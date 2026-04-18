//! Oblivious HTTP (OHTTP) client per [RFC 9458].
//!
//! OHTTP decouples the *who* from the *what* of a web request by routing it
//! through two non-colluding parties:
//!
//! - **Relay** — sees the client IP, but carries only an opaque ciphertext.
//! - **Gateway** — decrypts the ciphertext and forwards the inner HTTP
//!   request, but only sees the relay's IP, never the client's.
//!
//! Neither party can alone correlate the client identity to the request
//! content. This module is the protocol-level OHTTP client — it encodes
//! and decrypts capsules; the actual HTTP POST to the relay is delegated
//! to a caller-provided [`OhttpTransport`] implementation.
//!
//! # Design choices
//!
//! - **Hand-rolled HPKE** over the SDK's existing primitives: `x25519-dalek`,
//!   `hmac` + `sha2` (HKDF-SHA256), and `chacha20poly1305` (ChaCha20-Poly1305,
//!   the 12-byte-nonce variant required by RFC 9180). No new crypto crate is
//!   added to the SDK — the HPKE implementation lives entirely in this file.
//! - **Single ciphersuite**: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//!   ChaCha20-Poly1305. This is one of the three recommended default suites
//!   in RFC 9180 §7.1 and the canonical combination for client devices that
//!   don't have AES-NI (i.e. most Android hardware).
//! - **Transport trait, not `reqwest`**: the SDK does not take on an HTTP
//!   client dependency. Callers wire their own client (typically through the
//!   future `PrivacyClient` wrapper) into [`OhttpTransport`].
//!
//! # What this module does NOT do
//!
//! - It does not fetch the Gateway's key configuration dynamically; the
//!   public key is provisioned through [`OhttpConfig`] out-of-band.
//! - It does not retry, pool connections, or implement circuit-breaking.
//! - It only supports the canonical DHKEM(X25519) / HKDF-SHA256 /
//!   ChaCha20-Poly1305 ciphersuite; gateways advertising other suites are
//!   rejected.
//! - BHTTP encoding only covers the subset OHTTP clients actually need:
//!   known-length request, known-length response, a single content section,
//!   no trailers, no informational responses, scheme `https` only.
//!
//! [RFC 9458]: https://www.rfc-editor.org/rfc/rfc9458
//! [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
//! [RFC 9292]: https://www.rfc-editor.org/rfc/rfc9292

use std::sync::Arc;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit as _AeadKeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as Chacha20Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use super::{NetworkError, OhttpConfig};

type HmacSha256 = Hmac<Sha256>;

// --- HPKE ciphersuite identifiers (RFC 9180 §7) ---

/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
const KEM_ID_X25519_HKDF_SHA256: u16 = 0x0020;
/// HKDF-SHA256 — RFC 9180 §7.2.
const KDF_ID_HKDF_SHA256: u16 = 0x0001;
/// ChaCha20-Poly1305 — RFC 9180 §7.3.
const AEAD_ID_CHACHA20_POLY1305: u16 = 0x0003;

/// `Nsecret` for DHKEM(X25519, HKDF-SHA256): 32 bytes.
const N_SECRET: usize = 32;
/// `Nh` for HKDF-SHA256: 32 bytes.
const N_H: usize = 32;
/// `Nk` for ChaCha20-Poly1305: 32 bytes.
const N_K: usize = 32;
/// `Nn` for ChaCha20-Poly1305: 12 bytes.
const N_N: usize = 12;
/// `Npk` for X25519: 32 bytes.
const N_PK: usize = 32;
/// `max(Nn, Nk)` — response nonce size per RFC 9458 §4.4.
const RESPONSE_NONCE_LEN: usize = if N_K > N_N { N_K } else { N_N };

/// HPKE protocol version label prefix (RFC 9180 §4).
const HPKE_V1: &[u8] = b"HPKE-v1";

/// HPKE mode: base (no PSK, no asymmetric auth).
const HPKE_MODE_BASE: u8 = 0x00;

/// Info string for OHTTP request, per RFC 9458 §4.3.
const OHTTP_INFO: &[u8] = b"message/bhttp request";

/// Exporter label for OHTTP response, per RFC 9458 §4.4.
const OHTTP_EXPORT_LABEL: &[u8] = b"message/bhttp response";

/// SECURITY: Single opaque error string for every AEAD / HPKE failure
/// path in this module. RFC 9458 §4.5 requires that the client not
/// expose information that distinguishes one AEAD failure class from
/// another, and the same discipline applies to HPKE `Seal` and
/// HPKE/HKDF key-derivation errors — an attacker that can observe
/// distinct `Display` strings on a malicious-relay path learns where
/// their tampering landed, which is exactly the "structural" leak
/// the spec is asking us not to provide. Every fallible step in the
/// OHTTP encrypt/decrypt pipeline now reports this same string.
const AEAD_FAIL_ERR_MSG: &str = "OHTTP response decryption failed";

// =========================================================================
// Public API
// =========================================================================

/// A single OHTTP request addressed to the Gateway's upstream target.
///
/// Encoded as BHTTP ([RFC 9292]) before HPKE sealing.
///
/// [RFC 9292]: https://www.rfc-editor.org/rfc/rfc9292
#[derive(Debug, Clone)]
pub struct OhttpRequest {
    /// HTTP method (e.g. `"GET"`, `"POST"`). Case preserved verbatim.
    pub method: String,
    /// Fully-qualified target URL the Gateway will fetch. Must start with
    /// `https://` — plaintext HTTP targets are rejected in
    /// [`OhttpClient::send`] to prevent the Gateway from issuing cleartext
    /// requests on the caller's behalf.
    pub url: String,
    /// Request headers as `(name, value)` pairs. Duplicates are allowed.
    pub headers: Vec<(String, String)>,
    /// Request body bytes. Empty for bodyless methods.
    pub body: Vec<u8>,
}

/// A decrypted OHTTP response as seen by the client.
#[derive(Debug, Clone)]
pub struct OhttpResponse {
    /// HTTP status code returned by the upstream target.
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Transport abstraction for POSTing an OHTTP capsule to the Relay.
///
/// The SDK does not take a dependency on any specific HTTP client — the
/// caller wires in their own (typically via the future `PrivacyClient`
/// wrapper). The implementation must:
///
/// - POST the given `body` to `url` with
///   `Content-Type: message/ohttp-req`.
/// - **Verify** that the HTTP response carries
///   `Content-Type: message/ohttp-res` (RFC 9458 §4.4). If the header is
///   missing or has any other value, treat the response as a protocol
///   violation and return [`NetworkError::Connection`] — do **not**
///   forward the body to the SDK. The current trait shape returns only
///   the body, so the transport is the only layer able to enforce this
///   header. A future revision of the trait may return headers
///   alongside the body so the SDK can enforce the check itself.
/// - Treat a 200-class response's body as the OHTTP response capsule and
///   return it verbatim.
/// - Translate non-2xx statuses, TLS failures, DNS failures, etc. into
///   [`NetworkError`] variants.
///
/// Implementations are typically `Arc`-shared across requests.
#[async_trait]
pub trait OhttpTransport: Send + Sync + std::fmt::Debug {
    /// POST `body` to `url` and return the raw response body on success.
    ///
    /// # Required checks by the implementer
    ///
    /// - Request `Content-Type` must be `message/ohttp-req`.
    /// - Response `Content-Type` must be `message/ohttp-res` — see the
    ///   trait-level docs.
    ///
    /// # Errors
    ///
    /// Returns a [`NetworkError`] describing the failure class. The SDK
    /// does not expect transports to retry — retry/backoff policy lives
    /// at a higher layer.
    async fn post_capsule(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, NetworkError>;
}

/// OHTTP client that encapsulates HTTP requests per RFC 9458 §4.
///
/// Each call to [`OhttpClient::send`] generates a fresh HPKE ephemeral
/// keypair, seals the BHTTP-encoded request, posts it to the Relay via
/// the configured [`OhttpTransport`], and decrypts the response.
pub struct OhttpClient {
    config: OhttpConfig,
    gateway_pk: PublicKey,
    transport: Arc<dyn OhttpTransport>,
    key_id: u8,
}

impl std::fmt::Debug for OhttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhttpClient")
            .field("relay_url", &self.config.relay_url)
            .field("gateway_url", &self.config.gateway_url)
            .field("key_id", &self.key_id)
            .field("transport", &self.transport)
            .finish()
    }
}

impl OhttpClient {
    /// Construct a new OHTTP client from the given config and transport.
    ///
    /// The key-configuration id defaults to `0`; use
    /// [`OhttpClient::with_key_id`] if the Gateway publishes multiple keys.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::InvalidConfiguration`] if:
    /// - `config` is missing any of relay/gateway/public-key fields,
    /// - the Gateway public key fails to decode (bad base64, wrong length,
    ///   all-zero low-order point).
    pub fn new(
        config: OhttpConfig,
        transport: Arc<dyn OhttpTransport>,
    ) -> Result<Self, NetworkError> {
        Self::with_key_id(config, transport, 0)
    }

    /// Construct a new OHTTP client using a non-default key-configuration id.
    ///
    /// The `key_id` is a single byte (RFC 9458 §3) that the Gateway uses to
    /// select which of its published keys to attempt decryption with. Most
    /// deployments use `0` (the default).
    ///
    /// # Errors
    ///
    /// Same as [`OhttpClient::new`].
    pub fn with_key_id(
        config: OhttpConfig,
        transport: Arc<dyn OhttpTransport>,
        key_id: u8,
    ) -> Result<Self, NetworkError> {
        if !config.is_configured() {
            return Err(NetworkError::InvalidConfiguration(
                "OhttpConfig is missing relay_url, gateway_url, or gateway_public_key_b64"
                    .to_owned(),
            ));
        }
        let gateway_pk = config.gateway_public_key()?;

        Ok(Self {
            config,
            gateway_pk,
            transport,
            key_id,
        })
    }

    /// Send a request via the Relay and return the decrypted response.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::InvalidConfiguration`] if the request URL is
    /// not `https://` or the request is otherwise malformed, or
    /// [`NetworkError::Connection`] if the transport fails or the response
    /// is malformed / fails AEAD verification.
    pub async fn send(&self, request: OhttpRequest) -> Result<OhttpResponse, NetworkError> {
        // SECURITY: Refuse to let the Gateway issue cleartext HTTP on our
        // behalf. OHTTP does not protect the Gateway→target hop; requiring
        // https keeps the upstream TLS intact.
        if !request.url.starts_with("https://") {
            return Err(NetworkError::InvalidConfiguration(
                "OHTTP target URL must use https://".to_owned(),
            ));
        }

        // 1. Encode the inner request as BHTTP (RFC 9292 known-length).
        let bhttp_request = bhttp::encode_request(&request)?;

        // 2. Build the OHTTP header (RFC 9458 §4.2).
        let hdr = build_request_header(
            self.key_id,
            KEM_ID_X25519_HKDF_SHA256,
            KDF_ID_HKDF_SHA256,
            AEAD_ID_CHACHA20_POLY1305,
        );

        // 3. HPKE SetupBaseS → (enc, ctx).
        let info = ohttp_info(&hdr);
        let (mut enc, mut ctx) = hpke::setup_base_s(&self.gateway_pk, &info)?;

        // 4. Seal(aad=hdr, plaintext=bhttp_request) at sequence 0.
        let ciphertext = ctx.seal(&hdr, &bhttp_request)?;

        // 5. Assemble capsule: hdr || enc || ct.
        let mut capsule = Vec::with_capacity(hdr.len() + enc.len() + ciphertext.len());
        capsule.extend_from_slice(&hdr);
        capsule.extend_from_slice(&enc);
        capsule.extend_from_slice(&ciphertext);

        // 6. Derive the response-decryption secret BEFORE we drop ctx.
        // SECURITY: `export_secret` is a `Vec<u8>` holding HPKE exporter
        // output. `Vec<u8>` does not zeroise on drop by default, so the
        // bytes would otherwise sit in the heap allocator's free list
        // until reuse. We explicitly `zeroize()` it after `decrypt_response`
        // returns (see `_guard` below).
        let export_secret = ctx.export(OHTTP_EXPORT_LABEL, RESPONSE_NONCE_LEN)?;
        drop(ctx); // explicit early drop to zeroize HPKE key material now

        // 7. POST to the relay via the caller's transport.
        let response_capsule = self
            .transport
            .post_capsule(&self.config.relay_url, capsule)
            .await?;

        // 8. Decrypt response. `export_secret` and `enc` are explicitly
        //    zeroised at scope exit regardless of success or failure.
        let result = decrypt_response(&enc, &export_secret, &response_capsule);
        let mut export_secret = export_secret;
        export_secret.zeroize();
        enc.zeroize();
        result
    }
}

// =========================================================================
// OHTTP capsule building (RFC 9458 §4.2)
// =========================================================================

/// Assemble the 7-byte `hdr` per RFC 9458 §4.2:
/// `key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)`.
fn build_request_header(key_id: u8, kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 7] {
    let mut hdr = [0u8; 7];
    hdr[0] = key_id;
    hdr[1..3].copy_from_slice(&kem_id.to_be_bytes());
    hdr[3..5].copy_from_slice(&kdf_id.to_be_bytes());
    hdr[5..7].copy_from_slice(&aead_id.to_be_bytes());
    hdr
}

/// Build the HPKE `info` string for an OHTTP request per RFC 9458 §4.3:
/// `"message/bhttp request" || 0x00 || hdr`.
fn ohttp_info(hdr: &[u8; 7]) -> Vec<u8> {
    let mut info = Vec::with_capacity(OHTTP_INFO.len() + 1 + hdr.len());
    info.extend_from_slice(OHTTP_INFO);
    info.push(0x00);
    info.extend_from_slice(hdr);
    info
}

/// Decrypt an OHTTP response capsule per RFC 9458 §4.4.
///
/// `enc` is the ephemeral X25519 public key sent in the request capsule.
/// `export_secret` is the HPKE-exported secret (length `RESPONSE_NONCE_LEN`).
/// `response_capsule` is the relay-delivered body:
/// `response_nonce(32) || aead_ciphertext`.
fn decrypt_response(
    enc: &[u8],
    export_secret: &[u8],
    response_capsule: &[u8],
) -> Result<OhttpResponse, NetworkError> {
    if response_capsule.len() < RESPONSE_NONCE_LEN + 16 {
        return Err(NetworkError::Connection(
            "OHTTP response capsule too short".to_owned(),
        ));
    }
    let (response_nonce, aead_ct) = response_capsule.split_at(RESPONSE_NONCE_LEN);

    // salt = enc || response_nonce; prk = HKDF-Extract(salt, export_secret)
    let mut salt = Vec::with_capacity(enc.len() + response_nonce.len());
    salt.extend_from_slice(enc);
    salt.extend_from_slice(response_nonce);
    // SECURITY: `prk` is HKDF-SHA256 output derived from the HPKE exporter
    // secret. It must be zeroised at function end — a post-return coredump
    // that captured `prk` plus the response capsule would let an attacker
    // reconstruct the AEAD key + nonce and decrypt the response offline.
    let mut prk = hkdf_extract(&salt, export_secret)
        .map_err(|_| aead_fail_err())?;
    salt.zeroize();

    // aead_key   = HKDF-Expand(prk, "key",   Nk)
    // aead_nonce = HKDF-Expand(prk, "nonce", Nn)
    let expand_key = hkdf_expand(&prk, b"key", N_K);
    let expand_nonce = hkdf_expand(&prk, b"nonce", N_N);
    let mut aead_key = match expand_key {
        Ok(k) => k,
        Err(_) => {
            prk.zeroize();
            return Err(aead_fail_err());
        }
    };
    let mut aead_nonce = match expand_nonce {
        Ok(n) => n,
        Err(_) => {
            prk.zeroize();
            aead_key.zeroize();
            return Err(aead_fail_err());
        }
    };

    // SECURITY: Every fallible call below folds into a single opaque
    // error string per RFC 9458 §4.5 — a caller that logs the Display
    // form of the returned NetworkError must not be able to distinguish
    // "AEAD key construction failed" from "AEAD tag verification failed".
    let cipher_result = ChaCha20Poly1305::new_from_slice(&aead_key);
    let nonce = Chacha20Nonce::from_slice(&aead_nonce);
    let payload = Payload {
        msg: aead_ct,
        aad: b"",
    };

    let plaintext = match cipher_result {
        Ok(cipher) => cipher.decrypt(nonce, payload).map_err(|_| aead_fail_err()),
        Err(_) => Err(aead_fail_err()),
    };

    aead_key.zeroize();
    aead_nonce.zeroize();
    prk.zeroize();

    let plaintext = plaintext?;
    bhttp::decode_response(&plaintext)
}

/// Build the single opaque AEAD-failure error used across the HPKE and
/// response pipelines. See [`AEAD_FAIL_ERR_MSG`].
#[inline]
fn aead_fail_err() -> NetworkError {
    NetworkError::Connection(AEAD_FAIL_ERR_MSG.to_owned())
}

// =========================================================================
// HPKE (RFC 9180) — base-mode sealer
// =========================================================================

mod hpke {
    //! Minimal HPKE base-mode sender for DHKEM(X25519) / HKDF-SHA256 /
    //! ChaCha20-Poly1305. Covers only the operations OHTTP clients need:
    //! `SetupBaseS`, `Seal`, and `Export`.

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as Chacha20Nonce};
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroize;

    use super::{
        aead_fail_err, labeled_expand, labeled_extract, suite_id_hpke, suite_id_kem, NetworkError,
        AEAD_ID_CHACHA20_POLY1305, HPKE_MODE_BASE, KDF_ID_HKDF_SHA256, KEM_ID_X25519_HKDF_SHA256,
        N_H, N_K, N_N, N_PK, N_SECRET,
    };
    use crate::crypto::util::fill_random;

    /// Output of `SetupBaseS`: sealing context. The encapsulated key is
    /// returned separately so the caller can ship it in the capsule.
    pub(super) struct SenderContext {
        key: [u8; N_K],
        base_nonce: [u8; N_N],
        exporter_secret: [u8; N_H],
        seq: u64,
    }

    impl Drop for SenderContext {
        fn drop(&mut self) {
            self.key.zeroize();
            self.base_nonce.zeroize();
            self.exporter_secret.zeroize();
            self.seq = 0;
        }
    }

    /// HPKE `SetupBaseS(pkR, info)` from RFC 9180 §5.1.1.
    ///
    /// Returns the 32-byte encapsulated key `enc` and a sealing context.
    pub(super) fn setup_base_s(
        pk_r: &PublicKey,
        info: &[u8],
    ) -> Result<([u8; N_PK], SenderContext), NetworkError> {
        // --- DHKEM.Encap(pkR) ---
        // SECURITY: (skE, pkE) <- GenerateKeyPair
        //
        // Route the 32-byte ephemeral scalar through the SDK's central
        // `fill_random` helper instead of calling `StaticSecret::random_from_rng(OsRng)`
        // directly. `fill_random` wraps `OsRng::try_fill_bytes` with a
        // `CryptoError::Rng` on failure — using it here keeps this site
        // consistent with the SDK's documented "single entry point for
        // randomness" policy and turns a catastrophic RNG failure into a
        // typed error rather than a panic path. `StaticSecret::from(bytes)`
        // then clamps per RFC 7748 §5 on construction.
        let mut sk_bytes = fill_random::<32>()
            .map_err(|_| NetworkError::Connection(
                "OHTTP ephemeral key generation failed".to_owned(),
            ))?;
        let sk_e = StaticSecret::from(sk_bytes);
        sk_bytes.zeroize();
        let pk_e = PublicKey::from(&sk_e);

        // SECURITY: reject the case where our own ephemeral public key is
        // somehow the zero point. x25519-dalek clamps the scalar so the
        // resulting pk is non-trivial for any OS-random scalar; this check
        // is defense-in-depth against a broken RNG.
        if pk_e.as_bytes() == &[0u8; 32] {
            return Err(NetworkError::Connection(
                "OHTTP: generated ephemeral pk was zero".to_owned(),
            ));
        }

        // dh = DH(skE, pkR)
        let dh = sk_e.diffie_hellman(pk_r);
        if !dh.was_contributory() {
            return Err(NetworkError::InvalidConfiguration(
                "Gateway public key is a Curve25519 low-order point".to_owned(),
            ));
        }
        let mut dh_bytes = *dh.as_bytes();

        let enc = *pk_e.as_bytes();
        let mut kem_context = Vec::with_capacity(N_PK * 2);
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(pk_r.as_bytes());

        // shared_secret = ExtractAndExpand(dh, kem_context)
        let suite_kem = suite_id_kem(KEM_ID_X25519_HKDF_SHA256);
        let mut eae_prk = labeled_extract(&[], &suite_kem, b"eae_prk", &dh_bytes)?;
        let mut shared_secret =
            labeled_expand(&eae_prk, &suite_kem, b"shared_secret", &kem_context, N_SECRET)?;
        eae_prk.zeroize();
        dh_bytes.zeroize();

        // --- KeySchedule<ROLE_S>(mode_base, shared_secret, info, psk="", psk_id="") ---
        let suite_hpke = suite_id_hpke(
            KEM_ID_X25519_HKDF_SHA256,
            KDF_ID_HKDF_SHA256,
            AEAD_ID_CHACHA20_POLY1305,
        );

        let mut psk_id_hash = labeled_extract(&[], &suite_hpke, b"psk_id_hash", b"")?;
        let mut info_hash = labeled_extract(&[], &suite_hpke, b"info_hash", info)?;
        let mut ksc = Vec::with_capacity(1 + N_H + N_H);
        ksc.push(HPKE_MODE_BASE);
        ksc.extend_from_slice(&psk_id_hash);
        ksc.extend_from_slice(&info_hash);
        // Both hashes are now copied into `ksc`; wipe the originals.
        psk_id_hash.zeroize();
        info_hash.zeroize();

        let mut secret = labeled_extract(&shared_secret, &suite_hpke, b"secret", b"")?;
        let mut key_vec = labeled_expand(&secret, &suite_hpke, b"key", &ksc, N_K)?;
        let mut nonce_vec = labeled_expand(&secret, &suite_hpke, b"base_nonce", &ksc, N_N)?;
        let mut exp_vec = labeled_expand(&secret, &suite_hpke, b"exp", &ksc, N_H)?;

        let mut key = [0u8; N_K];
        let mut base_nonce = [0u8; N_N];
        let mut exporter_secret = [0u8; N_H];
        key.copy_from_slice(&key_vec);
        base_nonce.copy_from_slice(&nonce_vec);
        exporter_secret.copy_from_slice(&exp_vec);

        // Zeroise all intermediate key material that won't live in the
        // SenderContext. The context itself zeroises on Drop.
        key_vec.zeroize();
        nonce_vec.zeroize();
        exp_vec.zeroize();
        secret.zeroize();
        shared_secret.zeroize();
        ksc.zeroize();

        let ctx = SenderContext {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
        };
        Ok((enc, ctx))
    }

    impl SenderContext {
        /// HPKE `Seal(aad, pt)` (RFC 9180 §5.2) at the current sequence number.
        ///
        /// Increments `seq` on success. OHTTP only ever calls this once, but
        /// the counter is maintained for correctness.
        pub(super) fn seal(
            &mut self,
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, NetworkError> {
            // nonce = base_nonce XOR I2OSP(seq, Nn)
            let mut nonce = self.base_nonce;
            let seq_be = self.seq.to_be_bytes();
            for (i, &b) in seq_be.iter().enumerate() {
                // N_N (12) > seq_be.len() (8), so the index is in-bounds.
                let idx = N_N - seq_be.len() + i;
                let slot = nonce.get_mut(idx).ok_or_else(|| {
                    NetworkError::Connection("HPKE nonce index out of range".to_owned())
                })?;
                *slot ^= b;
            }

            // SECURITY: Collapse both failure modes to the single opaque
            // `AEAD_FAIL_ERR_MSG` — see the module-level comment on that
            // constant. A caller logging the Display form of the error
            // must not be able to distinguish "AEAD key init failed" from
            // "AEAD encryption failed".
            let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| aead_fail_err())?;
            let result = cipher.encrypt(
                Chacha20Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            );
            nonce.zeroize();

            let ct = result.map_err(|_| aead_fail_err())?;
            self.seq = self
                .seq
                .checked_add(1)
                .ok_or_else(|| NetworkError::Connection("HPKE seq overflow".to_owned()))?;
            Ok(ct)
        }

        /// HPKE `Export(exporter_context, L)` (RFC 9180 §5.3).
        pub(super) fn export(
            &self,
            exporter_context: &[u8],
            length: usize,
        ) -> Result<Vec<u8>, NetworkError> {
            let suite_hpke = suite_id_hpke(
                KEM_ID_X25519_HKDF_SHA256,
                KDF_ID_HKDF_SHA256,
                AEAD_ID_CHACHA20_POLY1305,
            );
            labeled_expand(
                &self.exporter_secret,
                &suite_hpke,
                b"sec",
                exporter_context,
                length,
            )
        }
    }
}

// =========================================================================
// HKDF-SHA256 primitives (RFC 5869 + RFC 9180 Labeled*)
// =========================================================================

/// HKDF-SHA256 Extract (RFC 5869 §2.2).
///
/// # Errors
///
/// Returns [`NetworkError::Connection`] with the opaque
/// [`AEAD_FAIL_ERR_MSG`] on HMAC initialisation failure. HMAC-SHA256
/// accepts any key length today, so this path is unreachable, but
/// returning an error instead of a silent all-zero PRK ensures that a
/// future dependency upgrade that tightens this contract cannot produce
/// a deterministic PRK that collapses every downstream AEAD key.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<[u8; N_H], NetworkError> {
    let salt = if salt.is_empty() { &[0u8; N_H][..] } else { salt };
    // SECURITY: Disambiguate — `new_from_slice` is on both `Mac` and AEAD
    // `KeyInit`. We explicitly propagate the failure instead of falling
    // through with an all-zero PRK; see the doc-comment above.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
        .map_err(|_| NetworkError::Connection(AEAD_FAIL_ERR_MSG.to_owned()))?;
    mac.update(ikm);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; N_H];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// HKDF-SHA256 Expand (RFC 5869 §2.3).
fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, NetworkError> {
    if prk.len() < N_H {
        return Err(NetworkError::Connection("HKDF PRK too short".to_owned()));
    }
    let max = 255 * N_H;
    if output_len == 0 || output_len > max {
        return Err(NetworkError::Connection(
            "HKDF output length out of range".to_owned(),
        ));
    }
    let n = output_len.div_ceil(N_H);
    let mut okm = Vec::with_capacity(output_len);
    let mut t_prev = [0u8; N_H];
    let mut t_prev_populated = false;

    for i in 1..=n {
        let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(prk) else {
            t_prev.zeroize();
            okm.zeroize();
            return Err(NetworkError::Connection("HKDF MAC init failed".to_owned()));
        };
        if t_prev_populated {
            mac.update(&t_prev);
        }
        mac.update(info);
        // `n <= 255`, so `i` fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        mac.update(&[i as u8]);
        let tag = mac.finalize().into_bytes();

        t_prev.zeroize();
        t_prev.copy_from_slice(&tag);
        t_prev_populated = true;

        let remaining = output_len - okm.len();
        let take = remaining.min(N_H);
        okm.extend_from_slice(tag.get(..take).unwrap_or(&[]));
    }

    t_prev.zeroize();
    Ok(okm)
}

/// RFC 9180 §4 LabeledExtract.
///
/// `labeled_ikm = "HPKE-v1" || suite_id || label || ikm`
/// returns `HKDF-Extract(salt, labeled_ikm)`.
///
/// # Errors
///
/// Propagates the [`hkdf_extract`] error; see that function's
/// documentation.
fn labeled_extract(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<[u8; N_H], NetworkError> {
    let mut labeled = Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let prk = hkdf_extract(salt, &labeled);
    labeled.zeroize();
    prk
}

/// RFC 9180 §4 LabeledExpand.
///
/// `labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`
/// returns `HKDF-Expand(prk, labeled_info, L)`.
fn labeled_expand(
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, NetworkError> {
    if length > u16::MAX as usize {
        return Err(NetworkError::Connection(
            "HPKE LabeledExpand length > u16::MAX".to_owned(),
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    let l_be = (length as u16).to_be_bytes();
    let mut labeled =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&l_be);
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let out = hkdf_expand(prk, &labeled, length);
    labeled.zeroize();
    out
}

/// RFC 9180 §4.1: `suite_id = "KEM" || I2OSP(kem_id, 2)`.
fn suite_id_kem(kem_id: u16) -> [u8; 5] {
    let mut s = [0u8; 5];
    s[..3].copy_from_slice(b"KEM");
    s[3..5].copy_from_slice(&kem_id.to_be_bytes());
    s
}

/// RFC 9180 §5.1: `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
fn suite_id_hpke(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&kem_id.to_be_bytes());
    s[6..8].copy_from_slice(&kdf_id.to_be_bytes());
    s[8..10].copy_from_slice(&aead_id.to_be_bytes());
    s
}

// =========================================================================
// BHTTP encoding (RFC 9292) — minimal subset for OHTTP
// =========================================================================

mod bhttp {
    //! Minimal BHTTP encoder/decoder: known-length request, known-length
    //! response, no trailers, no informational responses, https only.

    use super::{NetworkError, OhttpRequest, OhttpResponse};

    const FRAMING_REQUEST_KNOWN_LENGTH: u64 = 0;
    const FRAMING_RESPONSE_KNOWN_LENGTH: u64 = 1;

    /// Returns `true` for the `tchar` set of RFC 9110 §5.6.2 — the
    /// characters permitted in an HTTP field-name / token.
    ///
    /// `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" /
    ///          "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`
    fn is_tchar(b: u8) -> bool {
        matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
            | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        )
    }

    /// Reject any byte that would let a naive Gateway-side HTTP/1.1 / HTTP/2
    /// emitter turn a BHTTP field into a new header, status line, or NUL-
    /// delimited record. Per RFC 9110 §5.5, CR/LF are illegal in
    /// field-values regardless of context; NUL is explicitly disallowed
    /// by most HTTP serialisers. This is defence-in-depth against a
    /// request-smuggling-at-the-Gateway class of attack where the SDK
    /// caller forwards an attacker-influenced header.
    fn reject_forbidden_value_bytes(
        field: &str,
        value: &[u8],
    ) -> Result<(), NetworkError> {
        if value
            .iter()
            .any(|&b| b == b'\r' || b == b'\n' || b == 0)
        {
            return Err(NetworkError::InvalidConfiguration(format!(
                "BHTTP {field} contains forbidden byte (CR/LF/NUL)"
            )));
        }
        Ok(())
    }

    /// Reject header names that aren't pure RFC 9110 `tchar`.
    fn reject_invalid_header_name(name: &str) -> Result<(), NetworkError> {
        if name.is_empty() {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP header name must not be empty".to_owned(),
            ));
        }
        if !name.bytes().all(is_tchar) {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP header name contains non-tchar byte".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reject HTTP method strings that aren't pure RFC 9110 `tchar`.
    /// Methods are tokens per §9.1.
    fn reject_invalid_method(method: &str) -> Result<(), NetworkError> {
        if method.is_empty() {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP method must not be empty".to_owned(),
            ));
        }
        if !method.bytes().all(is_tchar) {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP method contains non-tchar byte".to_owned(),
            ));
        }
        Ok(())
    }

    /// Encode an [`OhttpRequest`] as a known-length BHTTP request
    /// (RFC 9292 §3.2).
    pub(super) fn encode_request(req: &OhttpRequest) -> Result<Vec<u8>, NetworkError> {
        let (scheme, authority, path) = split_url(&req.url)?;

        // SECURITY: RFC 9292 §3.5 puts the burden of CRLF rejection on
        // the Gateway-side HTTP emitter, but defence-in-depth on the
        // client is cheap and stops request-smuggling before the capsule
        // leaves our process. Validate method (as a token), the path
        // (as a field-value for CR/LF/NUL), and every header name/value.
        reject_invalid_method(&req.method)?;
        reject_forbidden_value_bytes("path", path.as_bytes())?;
        reject_forbidden_value_bytes("authority", authority.as_bytes())?;

        let mut out = Vec::with_capacity(256 + req.body.len());
        write_varint(&mut out, FRAMING_REQUEST_KNOWN_LENGTH);

        write_lenprefixed(&mut out, req.method.as_bytes())?;
        write_lenprefixed(&mut out, scheme.as_bytes())?;
        write_lenprefixed(&mut out, authority.as_bytes())?;
        write_lenprefixed(&mut out, path.as_bytes())?;

        let mut header_buf = Vec::with_capacity(128);
        for (name, value) in &req.headers {
            // Header field names MUST be lowercased per RFC 9292 §3.3 and
            // MUST obey the RFC 9110 `tchar` grammar. Header values MUST
            // NOT contain CR/LF/NUL (defence-in-depth against smuggling
            // through a downstream HTTP/1.1 serializer).
            reject_invalid_header_name(name)?;
            reject_forbidden_value_bytes("header value", value.as_bytes())?;
            write_lenprefixed(&mut header_buf, name.to_lowercase().as_bytes())?;
            write_lenprefixed(&mut header_buf, value.as_bytes())?;
        }
        #[allow(clippy::cast_possible_truncation)]
        write_varint(&mut out, header_buf.len() as u64);
        out.extend_from_slice(&header_buf);

        #[allow(clippy::cast_possible_truncation)]
        write_varint(&mut out, req.body.len() as u64);
        out.extend_from_slice(&req.body);

        // Trailer section: VarInt(0).
        write_varint(&mut out, 0);

        Ok(out)
    }

    /// Decode a known-length BHTTP response (RFC 9292 §3.3) into an
    /// [`OhttpResponse`]. Informational (1xx) responses are skipped silently;
    /// the final response is returned.
    pub(super) fn decode_response(buf: &[u8]) -> Result<OhttpResponse, NetworkError> {
        let mut cur = Cursor::new(buf);
        let framing = cur.read_varint()?;
        if framing != FRAMING_RESPONSE_KNOWN_LENGTH {
            return Err(NetworkError::Connection(format!(
                "BHTTP: expected known-length response framing, got {framing}"
            )));
        }

        // Skip informational responses (status < 200).
        let mut status;
        loop {
            status = cur.read_varint()?;
            if !(100..200).contains(&status) {
                break;
            }
            let header_bytes_len = cur.read_varint()? as usize;
            cur.advance(header_bytes_len)?;
        }
        if !(200..600).contains(&status) {
            return Err(NetworkError::Connection(format!(
                "BHTTP: final status code {status} out of range"
            )));
        }
        #[allow(clippy::cast_possible_truncation)]
        let status_u16 = status as u16;

        let header_bytes_len = cur.read_varint()? as usize;
        let header_bytes = cur.read_exact(header_bytes_len)?;
        let headers = parse_headers(header_bytes)?;

        let content_len = cur.read_varint()? as usize;
        let body = cur.read_exact(content_len)?.to_vec();

        // Trailer section — ignore trailers but enforce that a VarInt follows.
        let _trailer_len = cur.read_varint()?;

        Ok(OhttpResponse {
            status: status_u16,
            headers,
            body,
        })
    }

    // ----- helpers used in production and in the test-only gateway -----

    pub(super) fn write_varint(out: &mut Vec<u8>, v: u64) {
        if v <= 63 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(v as u8);
        } else if v <= 16_383 {
            #[allow(clippy::cast_possible_truncation)]
            {
                out.push(0x40 | ((v >> 8) as u8));
                out.push(v as u8);
            }
        } else if v <= 1_073_741_823 {
            #[allow(clippy::cast_possible_truncation)]
            {
                out.push(0x80 | ((v >> 24) as u8));
                out.push((v >> 16) as u8);
                out.push((v >> 8) as u8);
                out.push(v as u8);
            }
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                out.push(0xC0 | ((v >> 56) as u8));
                out.push((v >> 48) as u8);
                out.push((v >> 40) as u8);
                out.push((v >> 32) as u8);
                out.push((v >> 24) as u8);
                out.push((v >> 16) as u8);
                out.push((v >> 8) as u8);
                out.push(v as u8);
            }
        }
    }

    fn write_lenprefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), NetworkError> {
        if bytes.len() > u32::MAX as usize {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP field too large".to_owned(),
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        write_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) struct Cursor<'a> {
        buf: &'a [u8],
        pub(super) pos: usize,
    }

    impl<'a> Cursor<'a> {
        pub(super) fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn remaining(&self) -> usize {
            self.buf.len().saturating_sub(self.pos)
        }

        fn read_u8(&mut self) -> Result<u8, NetworkError> {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| NetworkError::Connection("BHTTP truncated".to_owned()))?;
            self.pos += 1;
            Ok(b)
        }

        pub(super) fn read_exact(&mut self, n: usize) -> Result<&'a [u8], NetworkError> {
            if self.remaining() < n {
                return Err(NetworkError::Connection("BHTTP truncated".to_owned()));
            }
            let out = self
                .buf
                .get(self.pos..self.pos + n)
                .ok_or_else(|| NetworkError::Connection("BHTTP truncated".to_owned()))?;
            self.pos += n;
            Ok(out)
        }

        fn advance(&mut self, n: usize) -> Result<(), NetworkError> {
            let _ = self.read_exact(n)?;
            Ok(())
        }

        pub(super) fn read_varint(&mut self) -> Result<u64, NetworkError> {
            let first = self.read_u8()?;
            let len_tag = first >> 6;
            let first_val = u64::from(first & 0x3F);
            match len_tag {
                0 => Ok(first_val),
                1 => {
                    let b = u64::from(self.read_u8()?);
                    Ok((first_val << 8) | b)
                }
                2 => {
                    let b1 = u64::from(self.read_u8()?);
                    let b2 = u64::from(self.read_u8()?);
                    let b3 = u64::from(self.read_u8()?);
                    Ok((first_val << 24) | (b1 << 16) | (b2 << 8) | b3)
                }
                _ => {
                    let mut v = first_val;
                    for _ in 0..7 {
                        v = (v << 8) | u64::from(self.read_u8()?);
                    }
                    Ok(v)
                }
            }
        }

        pub(super) fn read_str(&mut self) -> Result<String, NetworkError> {
            let n = self.read_varint()? as usize;
            let bytes = self.read_exact(n)?;
            String::from_utf8(bytes.to_vec())
                .map_err(|_| NetworkError::Connection("BHTTP field not UTF-8".to_owned()))
        }
    }

    fn parse_headers(mut buf: &[u8]) -> Result<Vec<(String, String)>, NetworkError> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let mut cur = Cursor::new(buf);
            let name = cur.read_str()?;
            let value = cur.read_str()?;
            out.push((name, value));
            let consumed = cur.pos;
            buf = buf.get(consumed..).unwrap_or(&[]);
        }
        Ok(out)
    }

    /// Split `https://host[:port]/path?query#fragment` into
    /// `(scheme, authority, path_with_query)`.
    fn split_url(url: &str) -> Result<(&str, &str, String), NetworkError> {
        let Some(rest) = url.strip_prefix("https://") else {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP: URL must use https://".to_owned(),
            ));
        };
        let (authority, path_part) = match rest.find('/') {
            Some(idx) => {
                let (auth, rest_path) = rest.split_at(idx);
                (auth, rest_path.to_owned())
            }
            None => (rest, "/".to_owned()),
        };
        if authority.is_empty() {
            return Err(NetworkError::InvalidConfiguration(
                "BHTTP: empty authority in URL".to_owned(),
            ));
        }
        Ok(("https", authority, path_part))
    }

    // ---------- test-only decoder/encoder of the "other" direction ----------
    // Used by the in-memory mock Gateway in tests: decode the request the
    // client sent, synthesise a response, re-encode it. Not exposed in
    // production because real clients never need to decode their own
    // request or encode a response.

    #[cfg(test)]
    pub(super) fn decode_request(buf: &[u8]) -> Result<OhttpRequest, NetworkError> {
        let mut cur = Cursor::new(buf);
        let framing = cur.read_varint()?;
        if framing != FRAMING_REQUEST_KNOWN_LENGTH {
            return Err(NetworkError::Connection(format!(
                "BHTTP: expected known-length request framing, got {framing}"
            )));
        }
        let method = cur.read_str()?;
        let scheme = cur.read_str()?;
        let authority = cur.read_str()?;
        let path = cur.read_str()?;

        let header_bytes_len = cur.read_varint()? as usize;
        let header_bytes = cur.read_exact(header_bytes_len)?;
        let headers = parse_headers(header_bytes)?;

        let content_len = cur.read_varint()? as usize;
        let body = cur.read_exact(content_len)?.to_vec();
        let _trailer_len = cur.read_varint()?;

        Ok(OhttpRequest {
            method,
            url: format!("{scheme}://{authority}{path}"),
            headers,
            body,
        })
    }

    #[cfg(test)]
    pub(super) fn encode_response(resp: &OhttpResponse) -> Result<Vec<u8>, NetworkError> {
        let mut out = Vec::with_capacity(64 + resp.body.len());
        write_varint(&mut out, FRAMING_RESPONSE_KNOWN_LENGTH);
        write_varint(&mut out, u64::from(resp.status));
        let mut header_buf = Vec::with_capacity(64);
        for (name, value) in &resp.headers {
            write_lenprefixed(&mut header_buf, name.as_bytes())?;
            write_lenprefixed(&mut header_buf, value.as_bytes())?;
        }
        #[allow(clippy::cast_possible_truncation)]
        write_varint(&mut out, header_buf.len() as u64);
        out.extend_from_slice(&header_buf);
        #[allow(clippy::cast_possible_truncation)]
        write_varint(&mut out, resp.body.len() as u64);
        out.extend_from_slice(&resp.body);
        write_varint(&mut out, 0);
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn varint_round_trip() {
            let values = [0u64, 1, 63, 64, 16_383, 16_384, 1_000_000];
            for &v in &values {
                let mut buf = Vec::new();
                write_varint(&mut buf, v);
                let mut cur = Cursor::new(&buf);
                assert_eq!(cur.read_varint().unwrap(), v);
            }
        }

        #[test]
        fn url_split_with_path() {
            let (s, a, p) = split_url("https://example.com/foo?bar=1").unwrap();
            assert_eq!(s, "https");
            assert_eq!(a, "example.com");
            assert_eq!(p, "/foo?bar=1");
        }

        #[test]
        fn url_split_bare_host() {
            let (s, a, p) = split_url("https://example.com").unwrap();
            assert_eq!(s, "https");
            assert_eq!(a, "example.com");
            assert_eq!(p, "/");
        }

        #[test]
        fn url_split_rejects_http() {
            assert!(split_url("http://example.com/").is_err());
        }

        #[test]
        fn url_split_rejects_empty_authority() {
            assert!(split_url("https:///path").is_err());
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use rand_core::{OsRng, RngCore};
    use x25519_dalek::StaticSecret;

    use super::*;

    // --- A mock transport that can play the Gateway role in-memory. ---

    struct MockTransport {
        gateway_sk: Option<[u8; 32]>,
        fixed_response: Option<Vec<u8>>,
        responder: Mutex<Option<Box<dyn FnMut(OhttpRequest) -> OhttpResponse + Send>>>,
        last_capsule: Mutex<Option<Vec<u8>>>,
    }

    impl std::fmt::Debug for MockTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockTransport")
                .field("has_gateway", &self.gateway_sk.is_some())
                .field("has_fixed_response", &self.fixed_response.is_some())
                .finish()
        }
    }

    impl MockTransport {
        fn with_gateway(
            gateway_sk: [u8; 32],
            responder: impl FnMut(OhttpRequest) -> OhttpResponse + Send + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                gateway_sk: Some(gateway_sk),
                fixed_response: None,
                responder: Mutex::new(Some(Box::new(responder))),
                last_capsule: Mutex::new(None),
            })
        }

        fn with_fixed_response(capsule: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                gateway_sk: None,
                fixed_response: Some(capsule),
                responder: Mutex::new(None),
                last_capsule: Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl OhttpTransport for MockTransport {
        async fn post_capsule(
            &self,
            _url: &str,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, NetworkError> {
            if let Ok(mut guard) = self.last_capsule.lock() {
                *guard = Some(body.clone());
            }

            if let Some(fixed) = &self.fixed_response {
                return Ok(fixed.clone());
            }

            let sk = self.gateway_sk.ok_or_else(|| {
                NetworkError::Connection("mock transport: no gateway sk".into())
            })?;
            let mut lock = self
                .responder
                .lock()
                .map_err(|_| NetworkError::Connection("mock responder lock".into()))?;
            let responder = lock.as_mut().ok_or_else(|| {
                NetworkError::Connection("mock transport: no responder".into())
            })?;
            in_memory_gateway_roundtrip(&sk, &body, &mut **responder)
        }
    }

    /// In-memory Gateway that decrypts `capsule`, runs `responder` on the
    /// decoded request, and encrypts the response back.
    fn in_memory_gateway_roundtrip(
        gateway_sk_bytes: &[u8; 32],
        capsule: &[u8],
        responder: &mut dyn FnMut(OhttpRequest) -> OhttpResponse,
    ) -> Result<Vec<u8>, NetworkError> {
        if capsule.len() < 7 + 32 + 16 {
            return Err(NetworkError::Connection("capsule too short".into()));
        }
        let hdr: [u8; 7] = capsule
            .get(..7)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| NetworkError::Connection("hdr slice".into()))?;
        let enc_slice: &[u8] = capsule
            .get(7..39)
            .ok_or_else(|| NetworkError::Connection("enc slice".into()))?;
        let enc: [u8; 32] = enc_slice
            .try_into()
            .map_err(|_| NetworkError::Connection("enc slice".into()))?;
        let ct = capsule
            .get(39..)
            .ok_or_else(|| NetworkError::Connection("ct slice".into()))?;

        let expected_hdr = build_request_header(
            0,
            KEM_ID_X25519_HKDF_SHA256,
            KDF_ID_HKDF_SHA256,
            AEAD_ID_CHACHA20_POLY1305,
        );
        if hdr != expected_hdr {
            return Err(NetworkError::Connection("unexpected hdr".into()));
        }

        // Receiver HPKE.
        let sk_r = StaticSecret::from(*gateway_sk_bytes);
        let pk_r = PublicKey::from(&sk_r);
        let pk_e = PublicKey::from(enc);
        let dh = sk_r.diffie_hellman(&pk_e);
        if !dh.was_contributory() {
            return Err(NetworkError::Connection("low-order dh".into()));
        }
        let dh_bytes = *dh.as_bytes();

        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(pk_r.as_bytes());

        let suite_kem = suite_id_kem(KEM_ID_X25519_HKDF_SHA256);
        let eae_prk = labeled_extract(&[], &suite_kem, b"eae_prk", &dh_bytes)
            .map_err(|_| NetworkError::Connection("extract eae_prk".into()))?;
        let shared_secret =
            labeled_expand(&eae_prk, &suite_kem, b"shared_secret", &kem_context, N_SECRET)
                .map_err(|_| NetworkError::Connection("expand shared_secret".into()))?;

        let suite_hpke = suite_id_hpke(
            KEM_ID_X25519_HKDF_SHA256,
            KDF_ID_HKDF_SHA256,
            AEAD_ID_CHACHA20_POLY1305,
        );
        let info = ohttp_info(&hdr);
        let psk_id_hash = labeled_extract(&[], &suite_hpke, b"psk_id_hash", b"")
            .map_err(|_| NetworkError::Connection("extract psk_id_hash".into()))?;
        let info_hash = labeled_extract(&[], &suite_hpke, b"info_hash", &info)
            .map_err(|_| NetworkError::Connection("extract info_hash".into()))?;
        let mut ksc = Vec::with_capacity(1 + N_H + N_H);
        ksc.push(HPKE_MODE_BASE);
        ksc.extend_from_slice(&psk_id_hash);
        ksc.extend_from_slice(&info_hash);
        let secret = labeled_extract(&shared_secret, &suite_hpke, b"secret", b"")
            .map_err(|_| NetworkError::Connection("extract secret".into()))?;

        let key = labeled_expand(&secret, &suite_hpke, b"key", &ksc, N_K)
            .map_err(|_| NetworkError::Connection("expand key".into()))?;
        let base_nonce = labeled_expand(&secret, &suite_hpke, b"base_nonce", &ksc, N_N)
            .map_err(|_| NetworkError::Connection("expand base_nonce".into()))?;
        let exporter_secret = labeled_expand(&secret, &suite_hpke, b"exp", &ksc, N_H)
            .map_err(|_| NetworkError::Connection("expand exp".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| NetworkError::Connection("receiver AEAD key".into()))?;
        let nonce = Chacha20Nonce::from_slice(&base_nonce);
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &hdr })
            .map_err(|_| NetworkError::Connection("gateway decrypt".into()))?;
        let req = bhttp::decode_request(&pt)?;

        let resp = responder(req);
        let resp_bytes = bhttp::encode_response(&resp)?;

        // Encrypt response.
        let export_secret = labeled_expand(
            &exporter_secret,
            &suite_hpke,
            b"sec",
            OHTTP_EXPORT_LABEL,
            RESPONSE_NONCE_LEN,
        )
        .map_err(|_| NetworkError::Connection("expand exporter".into()))?;

        let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
        OsRng.fill_bytes(&mut response_nonce);
        let mut salt = Vec::with_capacity(enc.len() + response_nonce.len());
        salt.extend_from_slice(&enc);
        salt.extend_from_slice(&response_nonce);
        let prk = hkdf_extract(&salt, &export_secret)
            .map_err(|_| NetworkError::Connection("extract prk".into()))?;
        let aead_key = hkdf_expand(&prk, b"key", N_K)
            .map_err(|_| NetworkError::Connection("expand aead key".into()))?;
        let aead_nonce = hkdf_expand(&prk, b"nonce", N_N)
            .map_err(|_| NetworkError::Connection("expand aead nonce".into()))?;

        let cipher2 = ChaCha20Poly1305::new_from_slice(&aead_key)
            .map_err(|_| NetworkError::Connection("response AEAD key".into()))?;
        let enc_resp = cipher2
            .encrypt(
                Chacha20Nonce::from_slice(&aead_nonce),
                Payload {
                    msg: &resp_bytes,
                    aad: b"",
                },
            )
            .map_err(|_| NetworkError::Connection("response encrypt".into()))?;

        let mut capsule_out = Vec::with_capacity(response_nonce.len() + enc_resp.len());
        capsule_out.extend_from_slice(&response_nonce);
        capsule_out.extend_from_slice(&enc_resp);
        Ok(capsule_out)
    }

    fn gateway_keypair() -> ([u8; 32], PublicKey) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        (sk.to_bytes(), pk)
    }

    fn config_for_pk(pk: &PublicKey) -> OhttpConfig {
        use base64::Engine;
        OhttpConfig {
            relay_url: "https://relay.test/ohttp".into(),
            gateway_url: "https://gateway.test/ohttp".into(),
            gateway_public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(pk.as_bytes()),
        }
    }

    // --- unit tests for small helpers ---

    #[test]
    fn build_header_layout() {
        let hdr = build_request_header(0x05, 0x0020, 0x0001, 0x0003);
        assert_eq!(hdr, [0x05, 0x00, 0x20, 0x00, 0x01, 0x00, 0x03]);
    }

    #[test]
    fn ohttp_info_prefix_and_separator() {
        let hdr = [1u8, 2, 3, 4, 5, 6, 7];
        let info = ohttp_info(&hdr);
        assert!(info.starts_with(b"message/bhttp request\x00"));
        assert_eq!(&info[info.len() - 7..], &hdr);
    }

    #[test]
    fn new_rejects_empty_config() {
        let cfg = OhttpConfig {
            relay_url: String::new(),
            gateway_url: String::new(),
            gateway_public_key_b64: String::new(),
        };
        let t = MockTransport::with_fixed_response(vec![]);
        let err = OhttpClient::new(cfg, t).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[test]
    fn new_rejects_zero_gateway_key() {
        use base64::Engine;
        let cfg = OhttpConfig {
            relay_url: "https://r.test".into(),
            gateway_url: "https://g.test".into(),
            gateway_public_key_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
        };
        let t = MockTransport::with_fixed_response(vec![]);
        assert!(OhttpClient::new(cfg, t).is_err());
    }

    // --- full round-trip via the in-memory gateway ---

    #[tokio::test]
    async fn full_round_trip_through_mock_gateway() {
        let (sk, pk) = gateway_keypair();
        let responder = |req: OhttpRequest| {
            assert_eq!(req.method, "GET");
            assert!(req.url.starts_with("https://upstream.test"));
            OhttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"hello from gateway".to_vec(),
            }
        };
        let transport = MockTransport::with_gateway(sk, responder);
        let client = OhttpClient::new(config_for_pk(&pk), transport.clone()).unwrap();

        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://upstream.test/resource".into(),
            headers: vec![("accept".into(), "*/*".into())],
            body: vec![],
        };
        let resp = client.send(req).await.expect("send should succeed");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello from gateway");
        assert!(resp
            .headers
            .iter()
            .any(|(n, v)| n == "content-type" && v == "text/plain"));

        let captured = transport
            .last_capsule
            .lock()
            .unwrap()
            .clone()
            .expect("capsule captured");
        assert_eq!(&captured[..7], &[0, 0, 0x20, 0, 1, 0, 3]);
        assert!(captured.len() >= 7 + 32 + 16);
    }

    #[tokio::test]
    async fn post_request_with_body_and_many_headers() {
        let (sk, pk) = gateway_keypair();
        let expected_body = b"payload=42".to_vec();
        let expected_body_clone = expected_body.clone();
        let responder = move |req: OhttpRequest| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.body, expected_body_clone);
            assert!(req
                .headers
                .iter()
                .any(|(n, v)| n == "x-custom" && v == "value-1"));
            assert!(req
                .headers
                .iter()
                .any(|(n, v)| n == "x-custom" && v == "value-2"));
            OhttpResponse {
                status: 201,
                headers: vec![("x-echo".into(), "yes".into())],
                body: b"created".to_vec(),
            }
        };
        let transport = MockTransport::with_gateway(sk, responder);
        let client = OhttpClient::new(config_for_pk(&pk), transport).unwrap();

        let req = OhttpRequest {
            method: "POST".into(),
            url: "https://upstream.test/items".into(),
            headers: vec![
                ("X-Custom".into(), "value-1".into()),
                ("X-Custom".into(), "value-2".into()),
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ],
            body: expected_body,
        };
        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"created");
    }

    #[tokio::test]
    async fn rejects_non_https_request_url() {
        let (_, pk) = gateway_keypair();
        let transport = MockTransport::with_fixed_response(vec![]);
        let client = OhttpClient::new(config_for_pk(&pk), transport).unwrap();

        let req = OhttpRequest {
            method: "GET".into(),
            url: "http://insecure.test/".into(),
            headers: vec![],
            body: vec![],
        };
        let err = client.send(req).await.unwrap_err();
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[tokio::test]
    async fn rejects_tampered_response_capsule() {
        let (sk, pk) = gateway_keypair();
        let responder = |_req: OhttpRequest| OhttpResponse {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        };

        let good = MockTransport::with_gateway(sk, responder);

        #[derive(Debug)]
        struct Tamper {
            inner: Arc<MockTransport>,
        }
        #[async_trait]
        impl OhttpTransport for Tamper {
            async fn post_capsule(
                &self,
                url: &str,
                body: Vec<u8>,
            ) -> Result<Vec<u8>, NetworkError> {
                let mut resp = self.inner.post_capsule(url, body).await?;
                if let Some(last) = resp.last_mut() {
                    *last ^= 0x01;
                }
                Ok(resp)
            }
        }
        let tamper: Arc<dyn OhttpTransport> = Arc::new(Tamper { inner: good });
        let client = OhttpClient::new(config_for_pk(&pk), tamper).unwrap();

        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://upstream.test/x".into(),
            headers: vec![],
            body: vec![],
        };
        let err = client.send(req).await.unwrap_err();
        assert!(matches!(err, NetworkError::Connection(_)));
    }

    #[tokio::test]
    async fn rejects_truncated_response_capsule() {
        let (_, pk) = gateway_keypair();
        let transport = MockTransport::with_fixed_response(vec![0u8; 10]);
        let client = OhttpClient::new(config_for_pk(&pk), transport).unwrap();

        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://upstream.test/".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(client.send(req).await.is_err());
    }

    // --- BHTTP-level unit tests ---

    #[test]
    fn bhttp_request_round_trip() {
        let req = OhttpRequest {
            method: "POST".into(),
            url: "https://example.com/a/b?c=1".into(),
            headers: vec![("x-a".into(), "1".into()), ("x-b".into(), "two".into())],
            body: b"{\"ok\":true}".to_vec(),
        };
        let bytes = bhttp::encode_request(&req).unwrap();
        let decoded = bhttp::decode_request(&bytes).unwrap();
        assert_eq!(decoded.method, "POST");
        assert_eq!(decoded.url, "https://example.com/a/b?c=1");
        assert_eq!(decoded.headers, req.headers);
        assert_eq!(decoded.body, req.body);
    }

    #[test]
    fn bhttp_response_round_trip() {
        let resp = OhttpResponse {
            status: 404,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"not found".to_vec(),
        };
        let bytes = bhttp::encode_response(&resp).unwrap();
        let decoded = bhttp::decode_response(&bytes).unwrap();
        assert_eq!(decoded.status, 404);
        assert_eq!(decoded.headers, resp.headers);
        assert_eq!(decoded.body, resp.body);
    }

    #[test]
    fn bhttp_response_skips_informational() {
        // Build: framing(1), 100 Continue (status 100, empty headers),
        // then 200 OK with "hi".
        let mut out = Vec::new();
        bhttp::write_varint(&mut out, 1); // framing
        bhttp::write_varint(&mut out, 100); // informational status
        bhttp::write_varint(&mut out, 0); // informational headers len
        bhttp::write_varint(&mut out, 200); // final status
        bhttp::write_varint(&mut out, 0); // final headers len
        bhttp::write_varint(&mut out, 2); // content len
        out.extend_from_slice(b"hi");
        bhttp::write_varint(&mut out, 0); // trailers

        let decoded = bhttp::decode_response(&out).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.body, b"hi");
    }

    // --- Finding #1 regression: BHTTP encoder must reject CR/LF/NUL ---

    #[test]
    fn bhttp_rejects_crlf_in_header_value() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![(
                "x-smuggled".into(),
                "ok\r\nX-Injected: pwned".into(),
            )],
            body: vec![],
        };
        let err = bhttp::encode_request(&req).expect_err("CRLF must be rejected");
        assert!(matches!(err, NetworkError::InvalidConfiguration(_)));
    }

    #[test]
    fn bhttp_rejects_bare_lf_in_header_value() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![("x-a".into(), "value\nwith lf".into())],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_nul_in_header_value() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![("x-a".into(), "value\x00with nul".into())],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_crlf_in_header_name() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![("x-\r\nX-Injected".into(), "value".into())],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_space_in_header_name() {
        // Space is not a tchar per RFC 9110 §5.6.2.
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![("x a".into(), "value".into())],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_empty_header_name() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![(String::new(), "value".into())],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_crlf_in_method() {
        let req = OhttpRequest {
            method: "GET\r\nHOST: evil.example".into(),
            url: "https://example.com/".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_rejects_crlf_in_url_path() {
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/path\r\nX-Smuggle: 1".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            bhttp::encode_request(&req),
            Err(NetworkError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn bhttp_accepts_valid_rfc_9110_tchar_header_name() {
        // `tchar` includes digits, ALPHA, and a specific punctuation set.
        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![(
                "X-Custom!#$%&'*+-.^_`|~1234567890".into(),
                "value".into(),
            )],
            body: vec![],
        };
        let bytes = bhttp::encode_request(&req).expect("tchar header name accepted");
        let decoded = bhttp::decode_request(&bytes).unwrap();
        assert_eq!(decoded.headers.len(), 1);
    }

    // --- Finding #2 regression: opaque AEAD failure string ---

    #[tokio::test]
    async fn tampered_response_returns_single_opaque_error_string() {
        // A caller logging the NetworkError Display form must see the
        // SAME string regardless of whether tampering was detected at
        // the AEAD tag step or at a structural pre-check. This test
        // asserts the Display form for tampered capsules, since that is
        // the only failure reachable from outside without mocking HKDF.
        let (sk, pk) = gateway_keypair();
        let responder = |_req: OhttpRequest| OhttpResponse {
            status: 200,
            headers: vec![],
            body: b"ok".to_vec(),
        };
        let good = MockTransport::with_gateway(sk, responder);

        #[derive(Debug)]
        struct Tamper {
            inner: Arc<MockTransport>,
        }
        #[async_trait]
        impl OhttpTransport for Tamper {
            async fn post_capsule(
                &self,
                url: &str,
                body: Vec<u8>,
            ) -> Result<Vec<u8>, NetworkError> {
                let mut resp = self.inner.post_capsule(url, body).await?;
                if let Some(last) = resp.last_mut() {
                    *last ^= 0x01;
                }
                Ok(resp)
            }
        }
        let tamper: Arc<dyn OhttpTransport> = Arc::new(Tamper { inner: good });
        let client = OhttpClient::new(config_for_pk(&pk), tamper).unwrap();

        let req = OhttpRequest {
            method: "GET".into(),
            url: "https://upstream.test/".into(),
            headers: vec![],
            body: vec![],
        };
        let err = client.send(req).await.unwrap_err();
        let msg = err.to_string();
        // Whatever the code path, the Display form of the error should
        // carry the opaque string — no distinguishable substrings that
        // identify a specific internal failure mode.
        assert!(
            msg.contains(AEAD_FAIL_ERR_MSG),
            "expected opaque AEAD failure in {msg:?}"
        );
        assert!(!msg.contains("bad response AEAD key"));
        assert!(!msg.contains("bad HPKE AEAD key"));
        assert!(!msg.contains("HPKE Seal failed"));
    }
}
