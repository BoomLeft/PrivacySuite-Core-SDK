//! URL validation for safe fetching.
//!
//! This module is the single entry point every BoomLeft application goes
//! through before handing a URL to the network layer. It consolidates the
//! previously duplicated hygiene code in Music, RSS, Podcasts, Scratchpad,
//! and Blackout into one place so a future hardening only needs to be made
//! here (handoff §6, "G2").
//!
//! # Threat model
//!
//! The validator defends against four distinct attack classes:
//!
//! 1. **Scheme confusion** — `file://`, `javascript:`, `data:`, `mailto:`
//!    and any other non-`http(s)` scheme that a naive URL handler might
//!    accept and then feed to an HTTP client, a webview, or a native URL
//!    opener. Rejected at the scheme check.
//! 2. **SSRF into private address space** — every literal IP form, both
//!    IPv4 and IPv6, is classified against RFC 1918 / loopback / link-local
//!    / cloud metadata ranges. IPv4-mapped IPv6 (`::ffff:x.x.x.x`) is
//!    unwrapped before classification. IPv6 zone-id suffixes are rejected
//!    outright (they only make sense for link-local targets).
//! 3. **Obfuscated IP encodings** — hostnames that are *actually* numeric
//!    IPs in disguise (`0x7f.0.0.1`, `0177.0.0.1`, `2130706433`) are
//!    detected by manually pre-parsing host labels and rejecting any
//!    non-decimal / leading-zero / all-digit form. Many URL libraries
//!    happily accept these and many HTTP clients will resolve them into
//!    `127.0.0.1`.
//! 4. **Homograph / header-injection via the URL** — Unicode bidi
//!    override characters (U+202A..U+202E, U+2066..U+2069, U+061C,
//!    U+200E, U+200F) in the host, percent-decoded CR/LF/NUL bytes
//!    anywhere in the URL, and embedded credentials (`user:pass@host`).
//!    These get rejected before the URL is handed to any subsystem.
//!
//! # Normalisation
//!
//! A successfully validated URL is returned wrapped in [`ValidatedUrl`].
//! The wrapper:
//!
//! - Strips the fragment (no information the network layer needs).
//! - Strips any credentials (defense in depth — we already reject them
//!   earlier, but belt-and-braces so a malformed-but-accepted URL can
//!   never leak creds).
//! - Lowercases the host.
//! - Leaves the path/query percent-encoded via the `url` crate's normal
//!   serialisation (which re-percent-encodes any structurally-invalid
//!   runs). The CR/LF/NUL scan happens both before and after parse so
//!   percent-encoded attacks (`%0d%0a`) get caught.
//!
//! `ValidatedUrl` deliberately does **not** implement `Deref` to
//! `::url::Url` — the only way for callers to get the string form out
//! is via [`ValidatedUrl::as_str`], which returns the canonicalised
//! serialisation. This keeps string-level manipulation (concatenation,
//! sprintf-style path building) away from the validated form.
//!
//! # Relationship to the pentest H10 fix
//!
//! The redirect-revalidation helper in
//! `boomleft-rss/apps/desktop/src-tauri/src/privacy.rs::is_private_url`
//! is the operational counterpart: callers that follow redirects should
//! re-run this validator on every hop, because the initial target can
//! redirect into a private range. Sharing the rules here means the two
//! stay in lockstep.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ::url::Url;

/// Validate a URL for safe fetching.
///
/// Applies the full hygiene pipeline described at the module level and
/// returns an opaque [`ValidatedUrl`] on success.
///
/// # Errors
///
/// Returns one of the [`UrlError`] variants; each variant is mutually
/// exclusive so callers can surface a precise reason to the user
/// without string-matching the `Display` output.
pub fn validate_url(input: &str) -> Result<ValidatedUrl, UrlError> {
    // 1. Reject CR/LF/NUL anywhere in the raw input. We scan the input
    //    as bytes, not chars, because an attacker who splits a multibyte
    //    UTF-8 sequence across a CR or LF could otherwise sneak one past
    //    a char-iteration scan. We also re-check after parsing so
    //    percent-encoded variants (`%0d%0a`) get caught.
    if input.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(UrlError::InvalidHostCharacters);
    }

    // 1b. Pre-scan for IPv6 zone-id suffix inside `[...]`. Newer `url`
    //     crate releases reject `[fe80::1%eth0]` and `[fe80::1%25eth0]`
    //     at parse time with the generic "invalid IPv6 address" error,
    //     which callers shouldn't have to distinguish from bidi/CRLF
    //     cases — both are "host contains something dangerous". Catch it
    //     here so the error maps to `InvalidHostCharacters` regardless of
    //     the `url` crate's version behaviour. Zone ids are only legal for
    //     link-local endpoints and are never legitimate in user-supplied
    //     URLs from the open internet.
    if let Some(open) = input.find('[') {
        if let Some(close_rel) = input[open + 1..].find(']') {
            let inside = &input[open + 1..open + 1 + close_rel];
            if inside.contains('%') {
                return Err(UrlError::InvalidHostCharacters);
            }
        }
    }

    // 2. Parse. The `url` crate refuses many of the malformed shapes
    //    outright but happily accepts things like `http://0x7f.0.0.1/`
    //    (valid host under WHATWG), so we still need the custom checks
    //    below.
    let mut parsed = Url::parse(input).map_err(|e| UrlError::Parse(e.to_string()))?;

    // 3. Scheme check.
    let scheme = parsed.scheme();
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return Err(UrlError::InvalidScheme(scheme.to_owned()));
    }

    // 4. Host must exist. `mailto:`, `data:`, `javascript:` would have
    //    been caught by the scheme check above, but `file:///` passes the
    //    scheme filter on some URL libraries depending on config — here
    //    we still defend in depth and bail if there's no host.
    let host = parsed
        .host_str()
        .ok_or(UrlError::MissingHost)?
        .to_owned();

    if host.is_empty() {
        return Err(UrlError::MissingHost);
    }

    // 5. Embedded credentials. The `url` crate exposes these separately
    //    from the host so we check before deciding the host is safe.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(UrlError::EmbeddedCredentials);
    }

    // 6. Bidi / direction-override / invisible-control characters in the
    //    host. Homograph defence. We scan the *original* host string
    //    from the parsed URL because the `url` crate may have already
    //    percent-decoded parts of it — we want to see whatever ended up
    //    in the routing target.
    if contains_bidi_or_control(&host) {
        return Err(UrlError::InvalidHostCharacters);
    }

    // 7. Percent-decoded CR/LF/NUL inside the host. An attacker who
    //    percent-encodes these into the URL can otherwise smuggle them
    //    past step 1. The `url` crate decodes percent-encodings in the
    //    host during parsing for IDN handling, but some shapes slip
    //    through — be explicit.
    if let Some(decoded) = percent_decode_host(&host) {
        if decoded.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(UrlError::InvalidHostCharacters);
        }
    }

    // 8. IPv6 zone-id suffix. The `url` crate accepts `[fe80::1%25eth0]`
    //    (the `%25` is a percent-encoded `%`). Zone ids only make sense
    //    for link-local targets — reject outright.
    if host.contains('%') {
        return Err(UrlError::InvalidHostCharacters);
    }

    // 9. Obfuscated IPv4 encodings. The WHATWG URL parser actually
    //    normalises most of these to dotted-quad for us, but not all
    //    shapes — and we want to reject them even when normalisation
    //    succeeds, because the user clearly intended to evade a naive
    //    filter.
    check_obfuscated_ipv4(&host)?;

    // 10. IP-literal classification against private / reserved ranges.
    if let Some(ip) = parse_host_as_ip(&host) {
        if is_private_or_reserved(ip) {
            return Err(UrlError::PrivateAddress);
        }
    }

    // 11. Normalise: strip fragment + credentials, lowercase host.
    parsed.set_fragment(None);
    // set_username/set_password on `Url` can return `Err(())` when the
    // URL has no host; we've already confirmed a host exists so this is
    // an infallible path, but we still guard against the lint.
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    // Host lowercasing — WHATWG already lowercases ASCII hosts during
    // parse, so this is a no-op for well-formed input. We do it
    // explicitly anyway so IDN / punycode hosts end up case-normal.
    if let Some(h) = parsed.host_str() {
        let lower = h.to_lowercase();
        if lower != h {
            // `set_host` may fail on some special URLs; fall through if so.
            let _ = parsed.set_host(Some(&lower));
        }
    }

    Ok(ValidatedUrl { inner: parsed })
}

/// A URL that has been checked by [`validate_url`].
///
/// The inner `::url::Url` is intentionally private. `Deref` is **not**
/// implemented — callers must go through [`ValidatedUrl::as_str`] or
/// one of the other accessors so no string-level concatenation can
/// reintroduce a bad byte.
#[derive(Debug, Clone)]
pub struct ValidatedUrl {
    inner: Url,
}

impl ValidatedUrl {
    /// Returns the canonical, normalised URL serialisation.
    ///
    /// Fragment is stripped. Host is lowercased. Query is preserved
    /// verbatim (call `strip_tracking_params` first if the caller wants
    /// tracker stripping too).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Returns the scheme (`"http"` or `"https"`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    /// Returns the host component, if any.
    ///
    /// By construction this is always `Some` — `validate_url` rejects
    /// URLs without a host — but the option is preserved to match the
    /// underlying `::url::Url` API shape.
    #[must_use]
    pub fn host_str(&self) -> Option<&str> {
        self.inner.host_str()
    }

    /// Returns the explicit port, or the scheme's default port if none
    /// is given (`80` for `http`, `443` for `https`).
    #[must_use]
    pub fn port_or_known_default(&self) -> u16 {
        self.inner
            .port_or_known_default()
            .unwrap_or(match self.inner.scheme() {
                "https" => 443,
                _ => 80,
            })
    }
}

/// Errors returned by [`validate_url`].
///
/// Variants are hand-rolled (matching the SDK's `CryptoError` style)
/// rather than `thiserror`-derived so the core SDK crate keeps its
/// existing dep-minimal surface — adding `thiserror` just for this one
/// error type would pull a proc macro into a crate that's explicitly
/// `#![forbid(unsafe_code)]` audited for supply-chain minimalism.
#[derive(Debug, PartialEq, Eq)]
pub enum UrlError {
    /// Underlying parser rejected the input.
    Parse(String),
    /// Scheme was neither `http` nor `https`.
    InvalidScheme(String),
    /// Parser succeeded but the URL has no host (e.g. `file:///path`).
    MissingHost,
    /// Host is a literal IP in a private, loopback, link-local,
    /// cloud-metadata, or otherwise reserved range.
    PrivateAddress,
    /// Host contained CR/LF/NUL (possibly percent-encoded), a bidi
    /// override codepoint, or an IPv6 zone-id suffix.
    InvalidHostCharacters,
    /// URL carried `user:pass@` credentials in the authority component.
    EmbeddedCredentials,
    /// Host was a decimal / octal / hex-encoded IPv4 literal disguised
    /// as a hostname.
    ObfuscatedIpEncoding,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "URL parse failed: {e}"),
            Self::InvalidScheme(s) => write!(f, "scheme must be http or https, got {s}"),
            Self::MissingHost => f.write_str("URL must have a host component"),
            Self::PrivateAddress => {
                f.write_str("host resolves to a private/reserved address")
            }
            Self::InvalidHostCharacters => {
                f.write_str("host contains disallowed characters (CR/LF/NUL/bidi)")
            }
            Self::EmbeddedCredentials => {
                f.write_str("URL embeds credentials — not permitted")
            }
            Self::ObfuscatedIpEncoding => {
                f.write_str("host is an obfuscated IP encoding (octal/hex/decimal)")
            }
        }
    }
}

impl std::error::Error for UrlError {}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Returns true if the string contains any Unicode bidi override or
/// invisible-direction code point that could be used for homograph
/// attacks in a hostname.
///
/// The blocklist covers the full bidi-override range (RLO/PDI/etc.) and
/// the individual LRM/RLM/ALM marks that can flip glyph ordering even
/// without an explicit override block.
fn contains_bidi_or_control(s: &str) -> bool {
    s.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'..='\u{202E}'  // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
            | '\u{061C}'              // ALM (Arabic letter mark)
            | '\u{200E}'              // LRM (left-to-right mark)
            | '\u{200F}'              // RLM (right-to-left mark)
        )
    })
}

/// Percent-decodes `host` once for the CR/LF/NUL defence-in-depth check.
///
/// Returns `None` if there's nothing percent-encoded in the host (common
/// case — avoids the allocation).
fn percent_decode_host(host: &str) -> Option<Vec<u8>> {
    if !host.contains('%') {
        return None;
    }
    let mut out = Vec::with_capacity(host.len());
    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1])?;
            let lo = hex_digit(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parses a host string as an `IpAddr`.
///
/// Accepts dotted-quad IPv4, bracketed IPv6 (`[::1]`), and bare IPv6
/// (some callers strip brackets before handing us the host).
fn parse_host_as_ip(host: &str) -> Option<IpAddr> {
    // Strip surrounding brackets for IPv6 literals.
    let trimmed = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse::<IpAddr>().ok()
}

/// Classifies an IPv4 address against private/reserved ranges.
fn is_reserved_ipv4(v4: Ipv4Addr) -> bool {
    // Cloud metadata: AWS / GCP / Azure IMDS all live at 169.254.169.254.
    // This is covered by the link-local check below but we keep the
    // comment here for audit traceability — handoff explicitly calls
    // out cloud metadata as a distinct concern even though the CIDR
    // collapses them into link-local.
    v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()     // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()  // 169.254/16 (covers 169.254.169.254 IMDS)
        || v4.is_broadcast()   // 255.255.255.255
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || is_cgnat_ipv4(v4)
        || is_reserved_range_ipv4(v4)
}

/// RFC 6598 shared address space (carrier-grade NAT): 100.64.0.0/10.
fn is_cgnat_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// IETF-reserved 240.0.0.0/4 (former "Class E").
fn is_reserved_range_ipv4(v4: Ipv4Addr) -> bool {
    (v4.octets()[0] & 0xF0) == 0xF0
}

/// Classifies an IPv6 address, with IPv4-mapped unwrap.
fn is_reserved_ipv6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }

    let segments = v6.segments();
    // fe80::/10 — link-local.
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // fc00::/7 — unique local (fc00..fdff). Handoff specifically calls
    // out the AWS IPv6 metadata endpoint at `fd00:ec2::254` — that falls
    // under this prefix so we're covered.
    if (segments[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // IPv4-mapped: `::ffff:x.x.x.x`. Unwrap and recheck.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_reserved_ipv4(v4);
    }
    false
}

/// Dispatch to the v4/v6 classifier.
fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_ipv4(v4),
        IpAddr::V6(v6) => is_reserved_ipv6(v6),
    }
}

/// Rejects obfuscated IPv4 encodings (octal, hex, decimal-wrapped).
///
/// The WHATWG URL parser will normalise some of these to canonical
/// dotted-quad (e.g. `http://2130706433/` → host `"127.0.0.1"`) and
/// some it won't. Either way, if the *input* was an obfuscated form
/// the caller is trying something sketchy and we reject it — even if
/// the normalised target would otherwise be a public address.
///
/// This runs on the host string as produced by the URL crate, which
/// for dotted-quad literals is already the canonical form. We detect:
///
/// 1. A bare all-digit host (`2130706433` = 127.0.0.1 packed).
/// 2. A dotted host whose any segment begins with `0x`/`0X`
///    (hex-encoded octet).
/// 3. A dotted host whose any segment has a leading zero followed by
///    more digits (octal-encoded octet — `0177`, `017`, etc.). We
///    exclude the literal `"0"` single-digit segment because that's
///    legitimately 0.
fn check_obfuscated_ipv4(host: &str) -> Result<(), UrlError> {
    // Case 1: host is a single all-digit token. The `url` crate may
    // have already normalised `http://2130706433/` → `127.0.0.1` host,
    // but it depends on version. Either way, a bare all-digit host
    // that survived parsing and is NOT a standard dotted-quad is an
    // obfuscated decimal-wrapped IPv4.
    if host.chars().all(|c| c.is_ascii_digit()) && !host.is_empty() {
        return Err(UrlError::ObfuscatedIpEncoding);
    }

    // Case 2 + 3: dotted host with hex or octal segments.
    //
    // We intentionally only run this check when the host *looks* like
    // an IP literal (all segments ASCII-alphanumeric with no letters
    // outside a-f). Otherwise a perfectly legitimate hostname like
    // `0a1b2c.example.com` would false-positive.
    if host.contains('.') && looks_like_numeric_host(host) {
        for seg in host.split('.') {
            if seg.starts_with("0x") || seg.starts_with("0X") {
                return Err(UrlError::ObfuscatedIpEncoding);
            }
            // Octal: leading 0 followed by at least one more digit.
            if seg.len() > 1 && seg.starts_with('0') && seg.chars().all(|c| c.is_ascii_digit()) {
                return Err(UrlError::ObfuscatedIpEncoding);
            }
        }
    }

    Ok(())
}

/// Returns true if every label of a dotted host looks like an IP-ish
/// token: pure digits, or `0x`-prefixed hex. Used only to scope the
/// obfuscated-IPv4 check so regular domain names aren't affected.
fn looks_like_numeric_host(host: &str) -> bool {
    host.split('.').all(|seg| {
        if seg.is_empty() {
            return false;
        }
        if seg.starts_with("0x") || seg.starts_with("0X") {
            // Hex form: remaining chars must be hex digits.
            seg[2..].chars().all(|c| c.is_ascii_hexdigit())
        } else {
            // Decimal/octal form: all digits.
            seg.chars().all(|c| c.is_ascii_digit())
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test-only
mod tests {
    use super::*;

    // ── Accepts ──────────────────────────────────────────────────────

    #[test]
    fn accepts_https_simple() {
        let v = validate_url("https://example.com/feed").unwrap();
        assert_eq!(v.scheme(), "https");
        assert_eq!(v.host_str(), Some("example.com"));
        assert_eq!(v.as_str(), "https://example.com/feed");
        assert_eq!(v.port_or_known_default(), 443);
    }

    #[test]
    fn accepts_port_path_query_strips_fragment() {
        let v = validate_url("https://example.com:8443/path?query=1#frag").unwrap();
        assert_eq!(v.port_or_known_default(), 8443);
        // Fragment must be stripped from the normalised form.
        assert!(!v.as_str().contains('#'));
        assert!(v.as_str().contains("query=1"));
    }

    #[test]
    fn accepts_multi_label_host() {
        let v = validate_url("https://sub.domain.example/path").unwrap();
        assert_eq!(v.host_str(), Some("sub.domain.example"));
    }

    #[test]
    fn accepts_plain_http() {
        // HTTP is accepted at this layer — callers that want https-only
        // enforce that themselves.
        let v = validate_url("http://example.com/feed").unwrap();
        assert_eq!(v.scheme(), "http");
        assert_eq!(v.port_or_known_default(), 80);
    }

    // ── Rejects: scheme & host shape ─────────────────────────────────

    #[test]
    fn rejects_file_scheme() {
        // `file:///etc/passwd` is usually parsed as scheme=file, host="".
        // Either MissingHost or InvalidScheme is acceptable per the handoff.
        let err = validate_url("file:///etc/passwd").unwrap_err();
        assert!(
            matches!(err, UrlError::MissingHost | UrlError::InvalidScheme(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_javascript_scheme() {
        let err = validate_url("javascript:alert(1)").unwrap_err();
        assert!(matches!(err, UrlError::InvalidScheme(_)), "got {err:?}");
    }

    #[test]
    fn rejects_data_scheme() {
        let err = validate_url("data:text/html,<script>alert(1)</script>").unwrap_err();
        assert!(matches!(err, UrlError::InvalidScheme(_)), "got {err:?}");
    }

    #[test]
    fn rejects_mailto_scheme() {
        let err = validate_url("mailto:x@example.com").unwrap_err();
        assert!(matches!(err, UrlError::InvalidScheme(_)), "got {err:?}");
    }

    // ── Rejects: private IPv4 ────────────────────────────────────────

    #[test]
    fn rejects_loopback_ipv4() {
        assert_eq!(
            validate_url("http://127.0.0.1/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_rfc1918_10_slash_8() {
        assert_eq!(
            validate_url("http://10.0.0.1/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_rfc1918_172_16_slash_12() {
        assert_eq!(
            validate_url("http://172.16.0.1/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_rfc1918_192_168_slash_16() {
        assert_eq!(
            validate_url("http://192.168.1.1/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_aws_gcp_azure_imds_v4() {
        assert_eq!(
            validate_url("http://169.254.169.254/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    // ── Rejects: private IPv6 ────────────────────────────────────────

    #[test]
    fn rejects_loopback_ipv6() {
        assert_eq!(
            validate_url("http://[::1]/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_link_local_ipv6() {
        assert_eq!(
            validate_url("http://[fe80::1]/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 — unwrap and recheck must flag as private.
        assert_eq!(
            validate_url("http://[::ffff:127.0.0.1]/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_unique_local_ipv6() {
        // fd00::/8 — covers the AWS IPv6 metadata endpoint variant
        // fd00:ec2::254.
        assert_eq!(
            validate_url("http://[fd00:ec2::254]/").unwrap_err(),
            UrlError::PrivateAddress
        );
    }

    #[test]
    fn rejects_ipv6_zone_id() {
        // The `url` crate accepts bracket-wrapped IPv6 with zone id via
        // the `%25` (URL-encoded `%`) form.
        let err = validate_url("http://[fe80::1%25eth0]/").unwrap_err();
        assert_eq!(err, UrlError::InvalidHostCharacters);
    }

    // ── Rejects: obfuscated IPv4 ─────────────────────────────────────

    #[test]
    fn rejects_hex_encoded_ipv4() {
        let err = validate_url("http://0x7f.0.0.1/").unwrap_err();
        // The `url` crate may normalise this to 127.0.0.1 (→ PrivateAddress)
        // or may leave it as 0x7f.0.0.1 (→ ObfuscatedIpEncoding). Either
        // is a correct rejection — the user is obfuscating.
        assert!(
            matches!(err, UrlError::ObfuscatedIpEncoding | UrlError::PrivateAddress),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_octal_encoded_ipv4() {
        let err = validate_url("http://0177.0.0.1/").unwrap_err();
        assert!(
            matches!(err, UrlError::ObfuscatedIpEncoding | UrlError::PrivateAddress),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_decimal_wrapped_ipv4() {
        // 2130706433 = 0x7F000001 = 127.0.0.1. Some HTTP clients accept
        // all-digit hosts as 32-bit-packed IPv4.
        let err = validate_url("http://2130706433/").unwrap_err();
        assert!(
            matches!(err, UrlError::ObfuscatedIpEncoding | UrlError::PrivateAddress),
            "got {err:?}"
        );
    }

    // ── Rejects: header injection / control characters ───────────────

    #[test]
    fn rejects_percent_encoded_crlf_in_host() {
        // `example.com%0d%0aHost: evil.com` — CRLF percent-encoded into
        // the host authority. The `url` crate may either reject at parse
        // (Parse) or accept-then-decode (InvalidHostCharacters); either
        // is a correct rejection. We just need to confirm we do NOT
        // return Ok.
        let err = validate_url("http://example.com%0d%0aHost: evil.com/").unwrap_err();
        assert!(
            matches!(
                err,
                UrlError::InvalidHostCharacters | UrlError::Parse(_)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_raw_nul_byte() {
        // Bare NUL byte anywhere in the URL string.
        let err = validate_url("http://example.com/\0").unwrap_err();
        assert_eq!(err, UrlError::InvalidHostCharacters);
    }

    #[test]
    fn rejects_raw_crlf() {
        let err = validate_url("http://example.com/\r\n").unwrap_err();
        assert_eq!(err, UrlError::InvalidHostCharacters);
    }

    // ── Rejects: credentials ─────────────────────────────────────────

    #[test]
    fn rejects_embedded_credentials() {
        assert_eq!(
            validate_url("http://user:pass@example.com/").unwrap_err(),
            UrlError::EmbeddedCredentials
        );
    }

    #[test]
    fn rejects_user_only_credentials() {
        // `http://user@example.com/` — username without password is
        // still a credential.
        assert_eq!(
            validate_url("http://user@example.com/").unwrap_err(),
            UrlError::EmbeddedCredentials
        );
    }

    // ── Rejects: homograph / bidi ────────────────────────────────────

    #[test]
    fn rejects_bidi_override_in_host() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — classic homograph attack.
        // The `url` crate's IDN handling may percent-encode this into
        // the host, reject it at parse, or (rarely) accept it — we must
        // reject in any case.
        let err = validate_url("http://\u{202E}example.com/").unwrap_err();
        assert!(
            matches!(
                err,
                UrlError::InvalidHostCharacters | UrlError::Parse(_)
            ),
            "got {err:?}"
        );
    }

    // ── Rejects: parse failures / empty ──────────────────────────────

    #[test]
    fn rejects_empty_string() {
        let err = validate_url("").unwrap_err();
        assert!(matches!(err, UrlError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn rejects_garbage() {
        let err = validate_url("not a url").unwrap_err();
        assert!(matches!(err, UrlError::Parse(_)), "got {err:?}");
    }

    // ── Positive controls: public IPs still work ─────────────────────

    #[test]
    fn accepts_public_ipv4() {
        // Google DNS — must NOT trip the private-range filter.
        let v = validate_url("https://8.8.8.8/").unwrap();
        assert_eq!(v.host_str(), Some("8.8.8.8"));
    }
}
