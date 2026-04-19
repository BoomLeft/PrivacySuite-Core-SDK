//! Multi-tier privacy networking: `DoH`, OHTTP, and Tor.
//!
//! Three tiers of network privacy, each offering progressively stronger
//! anonymity guarantees:
//!
//! | Tier | Name | Transport | What the ISP sees |
//! |------|----------|-----------|--------------------------------------|
//! | 1 | Standard | `DoH` | TLS to `1.1.1.1` / `9.9.9.9`, no DNS queries |
//! | 2 | Enhanced | OHTTP | Relay IP only; relay sees neither query nor client IP |
//! | 3 | Maximum | Tor | Nothing — full geographic anonymization |
//!
//! ## Tier 3 design
//!
//! Tor connectivity uses a SOCKS5 proxy (via `tokio-socks`) that connects
//! through an external Tor daemon. This is the same architecture used by
//! Signal, Tor Browser, and other production privacy applications — the Tor
//! process runs as a separate daemon, and the SDK connects through its
//! SOCKS5 port (default `127.0.0.1:9050`).
//!
//! This approach avoids embedding the Arti Tor client (which pulls in
//! ~1,400 transitive crates including unmaintained packages), keeping the
//! supply chain auditable and free of security advisories.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Default Tor SOCKS5 proxy address (standard Tor daemon port).
const DEFAULT_TOR_SOCKS_ADDR: &str = "127.0.0.1:9050";

/// Errors arising from privacy-networking operations.
///
/// Variants are intentionally descriptive enough for callers to decide on a
/// retry strategy without leaking internal state.
#[derive(Debug)]
pub enum NetworkError {
    /// DNS resolution failed.
    DnsResolution(String),
    /// A TCP/TLS connection could not be established.
    Connection(String),
    /// The Tor SOCKS5 proxy is unreachable or rejected the connection.
    TorProxy(String),
    /// The caller supplied an invalid or unsupported configuration.
    InvalidConfiguration(String),
    /// The upstream response body exceeds the configured cap.
    ///
    /// Returned either before any body bytes are read (when the
    /// transport enforces the cap against the advertised
    /// `Content-Length`) or after reading (when the transport can only
    /// observe the actual delivered length). Callers can distinguish
    /// "cap too tight" from "misbehaving upstream" using `observed`
    /// and `cap`.
    ResponseTooLarge {
        /// Observed body length, in bytes. May be the `Content-Length`
        /// header value when the transport rejects pre-body.
        observed: u64,
        /// Configured cap, in bytes.
        cap: u64,
    },
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsResolution(msg) => write!(f, "DNS resolution failed: {msg}"),
            Self::Connection(msg) => write!(f, "connection failed: {msg}"),
            Self::TorProxy(msg) => write!(f, "Tor proxy error: {msg}"),
            Self::InvalidConfiguration(msg) => {
                write!(f, "invalid configuration: {msg}")
            }
            Self::ResponseTooLarge { observed, cap } => {
                write!(
                    f,
                    "response body too large: {observed} bytes exceeds cap of {cap}"
                )
            }
        }
    }
}

impl std::error::Error for NetworkError {}

/// Selects the network-privacy tier for a given operation.
///
/// Higher tiers provide stronger anonymity but incur additional latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyTier {
    /// Tier 1 — DNS-over-HTTPS via Cloudflare and Quad9.
    /// ISP cannot observe DNS queries.
    Standard,
    /// Tier 2 — Oblivious HTTP.
    /// The relay cannot correlate the client IP with the request content.
    Enhanced,
    /// Tier 3 — Tor via external SOCKS5 proxy.
    /// Full geographic anonymization through onion-routed circuits.
    Maximum,
}

/// A DNS resolver that sends all queries over HTTPS (`DoH`), preventing the
/// ISP from observing plaintext DNS traffic.
///
/// Upstream servers:
/// - Cloudflare (`1.1.1.1`)
/// - Quad9 (`9.9.9.9`)
///
/// # SSRF / private-IP filter
///
/// By default [`PrivacyDns::resolve`] strips addresses that are not
/// publicly routable — RFC 1918 (10/8, 172.16/12, 192.168/16), loopback,
/// link-local, CGNAT (100.64/10), IPv4 broadcast/multicast/documentation,
/// cloud metadata (`169.254.169.254`), IPv4-mapped-IPv6, and the IPv6
/// equivalents. A malicious DoH response (or a MITM on the DoH channel)
/// cannot steer a caller that blindly dials the first returned IP into
/// the user's `localhost`, internal LAN, or a cloud metadata endpoint.
///
/// Tests and local development that legitimately need to resolve
/// private targets should call [`PrivacyDns::resolve_raw`] (behaviour-
/// equivalent to the pre-filter version).
#[derive(Debug)]
pub struct PrivacyDns {
    resolver: TokioResolver,
}

impl PrivacyDns {
    /// Create a new `DoH` resolver backed by Cloudflare and Quad9.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::DnsResolution`] if the resolver cannot be
    /// constructed (e.g. TLS backend unavailable).
    pub fn new() -> Result<Self, NetworkError> {
        let mut cloudflare = NameServerConfig::new(
            "1.1.1.1:443".parse().map_err(|e| {
                NetworkError::DnsResolution(format!("bad Cloudflare address: {e}"))
            })?,
            Protocol::Https,
        );
        cloudflare.tls_dns_name = Some("cloudflare-dns.com".to_owned());

        let mut quad9 = NameServerConfig::new(
            "9.9.9.9:443".parse().map_err(|e| {
                NetworkError::DnsResolution(format!("bad Quad9 address: {e}"))
            })?,
            Protocol::Https,
        );
        quad9.tls_dns_name = Some("dns.quad9.net".to_owned());

        let mut config = ResolverConfig::new();
        config.add_name_server(cloudflare);
        config.add_name_server(quad9);

        let resolver = TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self { resolver })
    }

    /// Resolve `domain` to publicly-routable IP addresses via DNS-over-HTTPS.
    ///
    /// SSRF-guarded: private, loopback, link-local, CGNAT, broadcast,
    /// multicast, documentation, and IPv4-mapped-IPv6 addresses are
    /// filtered out of the returned list. Returns an empty `Vec` if
    /// every answer is rejected (intentional: the caller should treat
    /// that as a lookup failure rather than silently falling back).
    ///
    /// See [`PrivacyDns::resolve_raw`] if you need the unfiltered set
    /// (e.g. for local development).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::DnsResolution`] if the upstream `DoH` servers
    /// cannot resolve the domain.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, NetworkError> {
        let all = self.resolve_raw(domain).await?;
        Ok(all.into_iter().filter(|ip| is_public_unicast(ip)).collect())
    }

    /// Resolve `domain` without any SSRF / private-IP filtering.
    ///
    /// Use this only for local development, unit tests, or cases where
    /// the caller is explicitly allowed to dial private destinations.
    /// Production code must prefer [`PrivacyDns::resolve`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::DnsResolution`] if the upstream `DoH`
    /// servers cannot resolve the domain.
    pub async fn resolve_raw(&self, domain: &str) -> Result<Vec<IpAddr>, NetworkError> {
        let response = self
            .resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| NetworkError::DnsResolution(e.to_string()))?;

        Ok(response.iter().collect())
    }
}

/// Returns `true` for IP addresses that are safe to return from a
/// public-internet name lookup.
///
/// Rejects the full SSRF-class surface:
/// - IPv4: RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`),
///   loopback (`127/8`), link-local (`169.254/16`, including the cloud
///   metadata endpoint `169.254.169.254`), CGNAT (`100.64/10`),
///   `0.0.0.0/8` (unspecified), broadcast (`255.255.255.255`),
///   multicast (`224/4`), documentation ranges, and
///   benchmark (`198.18/15`).
/// - IPv6: loopback (`::1`), unspecified (`::`), unique-local
///   (`fc00::/7`, which includes `fd00::/8`), link-local (`fe80::/10`),
///   multicast (`ff00::/8`), documentation (`2001:db8::/32`), and
///   IPv4-mapped addresses (`::ffff:0:0/96`) if they embed a
///   non-public IPv4.
fn is_public_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

#[doc(hidden)]
pub(crate) fn is_public_v4(v4: &Ipv4Addr) -> bool {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_unspecified()
        || v4.is_documentation()
    {
        return false;
    }
    let [a, b, _, _] = v4.octets();
    // CGNAT 100.64.0.0/10 — not publicly routable though `is_private`
    // returns false for it on Rust stable.
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // RFC 2544 benchmark 198.18.0.0/15.
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 0.0.0.0/8 is source-only per RFC 1122 §3.2.1.3.
    if a == 0 {
        return false;
    }
    // Explicit cloud-metadata endpoints (link-local already caught these,
    // listed here for readability / defense-in-depth).
    if v4.octets() == [169, 254, 169, 254] {
        return false;
    }
    true
}

#[doc(hidden)]
pub(crate) fn is_public_v6(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    let segs = v6.segments();
    // Unique-local fc00::/7 (covers fd00::/8 private range).
    if segs[0] & 0xFE00 == 0xFC00 {
        return false;
    }
    // Link-local fe80::/10.
    if segs[0] & 0xFFC0 == 0xFE80 {
        return false;
    }
    // Documentation 2001:db8::/32.
    if segs[0] == 0x2001 && segs[1] == 0x0DB8 {
        return false;
    }
    // IPv4-mapped ::ffff:0:0/96 — recurse into the IPv4 guard.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_public_v4(&v4);
    }
    // Deprecated IPv4-compatible ::0:0/96 (all zeros prefix) — treat
    // as non-public.
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0
    {
        return false;
    }
    true
}

/// Oblivious HTTP (OHTTP) client — **Tier 2 privacy** via K-anonymous relay.
///
/// OHTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)) separates
/// knowledge of the client's IP address from knowledge of the request
/// content by introducing two non-colluding parties:
///
/// 1. **Relay** — sees the client IP but receives only an opaque,
///    encrypted capsule it cannot decrypt.
/// 2. **Gateway** — decrypts the capsule and forwards the inner HTTP
///    request to the target, but never learns the client IP.
///
/// This implementation uses X25519 for ephemeral key exchange and
/// XChaCha20-Poly1305 for authenticated encryption. The Gateway's
/// X25519 public key must be provisioned out-of-band.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "sync", derive(serde::Serialize, serde::Deserialize))]
pub struct OhttpConfig {
    /// URL of the Relay server (e.g. `"https://relay.boomleft.com/ohttp"`).
    pub relay_url: String,
    /// URL of the Gateway server (e.g. `"https://gateway.boomleft.com/ohttp"`).
    pub gateway_url: String,
    /// The Gateway's X25519 public key, base64-encoded (32 bytes).
    pub gateway_public_key_b64: String,
}

impl OhttpConfig {
    /// Returns true if all three configuration fields are non-empty.
    pub fn is_configured(&self) -> bool {
        !self.relay_url.is_empty()
            && !self.gateway_url.is_empty()
            && !self.gateway_public_key_b64.is_empty()
    }

    /// Decode the Gateway's X25519 public key from base64.
    ///
    /// # Security
    ///
    /// Rejects the 32-byte all-zero key outright — that value is a Curve25519
    /// low-order point whose use would force the OHTTP handshake to a
    /// completely predictable shared secret. Further low-order-point rejection
    /// happens during the ECDH itself in [`crate::crypto::pairing`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::InvalidConfiguration`] if the key is not valid
    /// base64, not exactly 32 bytes, or is the all-zero small-subgroup point.
    pub fn gateway_public_key(
        &self,
    ) -> Result<x25519_dalek::PublicKey, NetworkError> {
        use base64::Engine;

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.gateway_public_key_b64)
            .map_err(|e| NetworkError::InvalidConfiguration(
                format!("invalid base64 in gateway public key: {}", e)
            ))?;

        if bytes.len() != 32 {
            return Err(NetworkError::InvalidConfiguration(
                format!("gateway public key must be 32 bytes, got {}", bytes.len())
            ));
        }

        // SECURITY: Reject the all-zero point at config-parse time. This is
        // the most common low-order point and a clear indicator of a
        // misconfigured or malicious gateway config. ECDH performs full
        // low-order-point rejection per call site.
        if bytes.iter().all(|&b| b == 0) {
            return Err(NetworkError::InvalidConfiguration(
                "gateway public key must not be the zero point".to_string(),
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(x25519_dalek::PublicKey::from(arr))
    }
}

/// The response payload after decryption from OHTTP Gateway.
#[derive(Debug)]
#[cfg_attr(feature = "sync", derive(serde::Serialize, serde::Deserialize))]
pub struct OhttpResponsePayload {
    /// HTTP status code from the target server.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body (base64-encoded to survive JSON serialisation).
    pub body_b64: String,
}

impl OhttpResponsePayload {
    /// Decode the base64-encoded response body.
    pub fn decode_body(&self) -> Result<Vec<u8>, NetworkError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&self.body_b64)
            .map_err(|e| NetworkError::InvalidConfiguration(
                format!("invalid base64 in response body: {}", e)
            ))
    }
}

/// A Tor SOCKS5 proxy client providing full onion-routed anonymity (**Tier 3**).
///
/// Connects through an external Tor daemon's SOCKS5 port (default
/// `127.0.0.1:9050`). This is the standard production architecture used by
/// Signal, Tor Browser, and other privacy applications.
///
/// # Prerequisites
///
/// The Tor daemon must be running on the same machine. Install via:
/// - macOS: `brew install tor && brew services start tor`
/// - Linux: `apt install tor` / `systemctl start tor`
/// - Windows: Install the Tor Expert Bundle
#[derive(Debug, Clone)]
pub struct TorClient {
    socks_addr: String,
}

impl TorClient {
    /// Create a Tor client pointing at the default SOCKS5 proxy
    /// (`127.0.0.1:9050`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            socks_addr: DEFAULT_TOR_SOCKS_ADDR.to_owned(),
        }
    }

    /// Create a Tor client pointing at a custom SOCKS5 proxy address.
    #[must_use]
    pub fn with_socks_addr(addr: &str) -> Self {
        Self {
            socks_addr: addr.to_owned(),
        }
    }

    /// Open an anonymized TCP stream to `target` (e.g. `"example.com:443"`)
    /// through the Tor SOCKS5 proxy.
    ///
    /// The returned [`TcpStream`] can be used with TLS wrappers and HTTP
    /// libraries as a drop-in transport.
    ///
    /// # Security — error scrubbing
    ///
    /// Every failure mode — local Tor daemon not running, SOCKS5
    /// protocol error, target unreachable via the exit node — folds
    /// into the single opaque error string [`TOR_CONNECT_ERR_MSG`].
    /// The previous implementation preserved the raw `tokio_socks`
    /// error text, which distinguished "proxy down" from "target
    /// unreachable" and could be used to fingerprint the user's local
    /// network conditions or confirm target reachability if the
    /// caller logs errors. Callers that need to distinguish failure
    /// classes should probe the proxy's liveness separately.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::TorProxy`] with the opaque
    /// [`TOR_CONNECT_ERR_MSG`] on any failure.
    pub async fn connect(&self, target: &str) -> Result<TcpStream, NetworkError> {
        let stream = Socks5Stream::connect(&*self.socks_addr, target)
            .await
            .map_err(|_| NetworkError::TorProxy(TOR_CONNECT_ERR_MSG.to_owned()))?;

        Ok(stream.into_inner())
    }
}

/// Opaque error string returned for any failure in [`TorClient::connect`].
///
/// See the security note on that method for the rationale.
pub const TOR_CONNECT_ERR_MSG: &str = "Tor connection failed";

impl Default for TorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-exported from [`crate::crypto::pinning`] — available without the
/// `networking` feature via `privacysuite_core_sdk::crypto::pinning::CertificatePinner`.
pub use crate::crypto::pinning::CertificatePinner;

#[cfg(feature = "ohttp")]
pub mod ohttp;

#[cfg(feature = "ohttp")]
pub use ohttp::{OhttpClient, OhttpRequest, OhttpResponse, OhttpTransport};

#[cfg(feature = "http")]
pub mod privacy_client;

#[cfg(feature = "http")]
pub use privacy_client::{FetchSpec, PrivacyClient, PrivacyClientConfig, PrivacyResponse};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_tier_values_are_distinct() {
        assert_ne!(PrivacyTier::Standard, PrivacyTier::Enhanced);
        assert_ne!(PrivacyTier::Enhanced, PrivacyTier::Maximum);
        assert_ne!(PrivacyTier::Standard, PrivacyTier::Maximum);
    }

    #[test]
    fn privacy_tier_copy_and_clone() {
        let tier = PrivacyTier::Maximum;
        let cloned = tier;
        assert_eq!(tier, cloned);
    }

    #[test]
    fn privacy_tier_debug_format() {
        let dbg = format!("{:?}", PrivacyTier::Standard);
        assert!(!dbg.is_empty());
    }

    #[test]
    fn certificate_pinner_matches_known_pin() {
        let pin = [0xABu8; 32];
        let pinner = CertificatePinner::new(vec![pin]);
        assert!(pinner.verify(&pin));
    }

    #[test]
    fn certificate_pinner_rejects_unknown_pin() {
        let known = [0xABu8; 32];
        let unknown = [0xCDu8; 32];
        let pinner = CertificatePinner::new(vec![known]);
        assert!(!pinner.verify(&unknown));
    }

    #[test]
    fn certificate_pinner_empty_set_rejects_all() {
        let pinner = CertificatePinner::new(vec![]);
        assert!(!pinner.verify(&[0x00u8; 32]));
    }

    #[test]
    fn network_error_display() {
        let err = NetworkError::DnsResolution("timeout".into());
        assert!(err.to_string().contains("timeout"));

        let err = NetworkError::Connection("refused".into());
        assert!(err.to_string().contains("refused"));

        let err = NetworkError::TorProxy("no proxy".into());
        assert!(err.to_string().contains("no proxy"));

        let err = NetworkError::InvalidConfiguration("bad".into());
        assert!(err.to_string().contains("bad"));

        let err = NetworkError::ResponseTooLarge {
            observed: 209_715_201,
            cap: 209_715_200,
        };
        let msg = err.to_string();
        assert!(msg.contains("too large"), "{msg}");
        assert!(msg.contains("209715201"), "{msg}");
        assert!(msg.contains("209715200"), "{msg}");
    }

    #[test]
    fn network_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(NetworkError::Connection("test".into()));
        let _ = err.to_string();
    }

    #[test]
    fn ohttp_config_is_configured() {
        let empty = OhttpConfig {
            relay_url: String::new(),
            gateway_url: String::new(),
            gateway_public_key_b64: String::new(),
        };
        assert!(!empty.is_configured());

        let full = OhttpConfig {
            relay_url: "https://relay.example.com".to_string(),
            gateway_url: "https://gw.example.com".to_string(),
            gateway_public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        };
        assert!(full.is_configured());
    }

    #[test]
    fn ohttp_response_payload_decode_body() {
        use base64::Engine;
        let plain = b"hello, OHTTP!";
        let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
        let payload = OhttpResponsePayload {
            status: 200,
            headers: vec![],
            body_b64: encoded,
        };
        let decoded = payload.decode_body().unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn tor_client_default_socks_addr() {
        let client = TorClient::new();
        assert_eq!(client.socks_addr, DEFAULT_TOR_SOCKS_ADDR);
    }

    #[test]
    fn tor_client_custom_socks_addr() {
        let client = TorClient::with_socks_addr("127.0.0.1:9150");
        assert_eq!(client.socks_addr, "127.0.0.1:9150");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn privacy_dns_resolves_known_domain() {
        let dns = PrivacyDns::new().expect("failed to create DoH resolver");
        let addrs = dns
            .resolve("one.one.one.one")
            .await
            .expect("DNS resolution failed");
        assert!(!addrs.is_empty(), "expected at least one IP address");
    }

    #[tokio::test]
    #[ignore = "requires running Tor daemon on 127.0.0.1:9050"]
    async fn tor_client_can_connect() {
        let client = TorClient::new();
        let _stream = client
            .connect("example.com:80")
            .await
            .expect("Tor SOCKS5 connection failed");
    }

    // --- Finding #6: TorClient returns an opaque error ---

    #[tokio::test]
    async fn tor_connect_failure_is_opaque() {
        // Point at a port that almost certainly isn't running a SOCKS5
        // proxy. The error string must be the fixed opaque constant,
        // with no underlying tokio_socks / OS-level detail.
        let client = TorClient::with_socks_addr("127.0.0.1:1");
        let err = client
            .connect("example.com:443")
            .await
            .expect_err("must fail");
        match err {
            NetworkError::TorProxy(msg) => {
                assert_eq!(msg, TOR_CONNECT_ERR_MSG);
                // Defence in depth — ensure no socket-level noise leaks.
                assert!(!msg.contains("Connection refused"));
                assert!(!msg.contains("os error"));
                assert!(!msg.contains("SOCKS"));
            }
            other => panic!("expected TorProxy, got {other:?}"),
        }
    }

    // --- Finding #2: PrivacyDns filters private/loopback IPs ---

    #[test]
    fn private_v4_addresses_are_not_public() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata
            "169.254.1.1",
            "100.64.0.1",      // CGNAT
            "198.18.0.1",      // benchmark
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",       // multicast
            "192.0.2.1",       // documentation
        ] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert!(!is_public_v4(&ip), "{s} must not be public");
        }
    }

    #[test]
    fn public_v4_addresses_are_public() {
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.217.17.14"] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert!(is_public_v4(&ip), "{s} must be public");
        }
    }

    #[test]
    fn private_v6_addresses_are_not_public() {
        for s in [
            "::1",
            "::",
            "fe80::1",
            "fd00::1", // unique-local
            "fc00::1",
            "ff02::1", // multicast
            "2001:db8::1", // documentation
            "::ffff:127.0.0.1", // mapped loopback
            "::ffff:10.0.0.1",
        ] {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert!(!is_public_v6(&ip), "{s} must not be public");
        }
    }

    #[test]
    fn public_v6_addresses_are_public() {
        for s in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert!(is_public_v6(&ip), "{s} must be public");
        }
    }

    #[test]
    fn ipv4_mapped_public_v6_is_public() {
        let ip: Ipv6Addr = "::ffff:1.1.1.1".parse().unwrap();
        assert!(is_public_v6(&ip));
    }

    // --- Finding #14: NetworkError is Send + Sync ---

    #[test]
    fn network_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetworkError>();
    }
}
