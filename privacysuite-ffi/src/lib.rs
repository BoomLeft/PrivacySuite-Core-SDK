//! UniFFI bindings for PrivacySuite Core SDK.
//!
//! This crate provides the FFI bridge between the pure-Rust core SDK and
//! foreign languages (Kotlin/Android, Swift/iOS, Python). All key material
//! is wrapped in opaque `Arc`-based handles so that **raw key bytes never
//! cross the JNI/FFI boundary** unless the caller explicitly requests them.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │  privacysuite-core-sdk          │  ← #![forbid(unsafe_code)]
//! │  (all crypto, storage, sync)    │     Zero unsafe, fully auditable
//! └──────────────┬──────────────────┘
//! │  privacysuite-ffi (this crate)  │  ← UniFFI scaffolding
//! │  Opaque handles, type mapping   │     Thin glue layer
//! └──────────────┬──────────────────┘
//! │  Generated Kotlin / Swift       │  ← Idiomatic foreign API
//! └─────────────────────────────────┘
//! ```
//!
//! # What is NOT exported here
//!
//! - **Streaming AEAD (G3 — `crypto::stream`).** The chunked
//!   `EncryptedFileWriter` / `EncryptedFileReader` API takes
//!   `std::io::Write` / `std::io::Read` handles, which do not cross the
//!   UniFFI boundary cleanly (no shared file-descriptor story across
//!   Kotlin/Swift/Rust). Streaming AEAD is therefore feature-gated to
//!   Rust consumers for now; Phase 2 will expose a chunked byte-array
//!   API that mobile can call in a loop (push plaintext bytes, pull
//!   ciphertext bytes, finalize).

use std::sync::Arc;

use privacysuite_core_sdk::crypto::{aead, hash, hkdf, kdf, keys, mnemonic, util};
use privacysuite_core_sdk::error::CryptoError;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// FFI-safe error type that maps all SDK errors to flat enum variants.
///
/// UniFFI maps this to Kotlin sealed classes / Swift enums / Python exceptions.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PrivacySuiteError {
    /// Key derivation failed (bad parameters or empty passphrase).
    #[error("key derivation failed")]
    KeyDerivation,
    /// AEAD encryption failed.
    #[error("encryption failed")]
    Encryption,
    /// AEAD decryption or authentication failed.
    #[error("decryption failed")]
    Decryption,
    /// OS entropy source unavailable.
    #[error("random number generation failed")]
    Rng,
    /// Invalid BIP39 mnemonic phrase.
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,
    /// Input has wrong length.
    #[error("invalid input length")]
    InvalidLength,
    /// Base64 decoding failed.
    #[error("base64 decoding failed")]
    Base64Decode,
    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// A key is cryptographically invalid (e.g., X25519 low-order point).
    #[error("invalid cryptographic key")]
    InvalidKey,
    /// OPAQUE protocol state machine error.
    #[error("OPAQUE protocol error")]
    AuthProtocol,
    /// Invalid OPAQUE wire message.
    #[error("invalid OPAQUE message")]
    AuthInvalidMessage,
    // ── URL validation (G2) ────────────────────────────────────────
    //
    // Distinct variants rather than a single `UrlInvalid` so Kotlin/Swift
    // callers can surface a precise reason to the user without string-
    // matching the `Display` output.
    /// URL failed to parse.
    #[error("URL parse failed")]
    UrlParse,
    /// URL scheme is not http/https.
    #[error("URL scheme must be http or https")]
    UrlInvalidScheme,
    /// URL has no host component.
    #[error("URL must have a host component")]
    UrlMissingHost,
    /// URL host is a private/reserved IP address.
    #[error("URL host resolves to a private/reserved address")]
    UrlPrivateAddress,
    /// URL contains CR/LF/NUL/bidi characters.
    #[error("URL host contains disallowed characters")]
    UrlInvalidHostCharacters,
    /// URL embeds user:pass@ credentials.
    #[error("URL embeds credentials")]
    UrlEmbeddedCredentials,
    /// URL host is an obfuscated IP encoding.
    #[error("URL host is an obfuscated IP encoding")]
    UrlObfuscatedIpEncoding,
}

impl From<CryptoError> for PrivacySuiteError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::KeyDerivation => Self::KeyDerivation,
            CryptoError::Encryption => Self::Encryption,
            CryptoError::Decryption => Self::Decryption,
            CryptoError::Rng => Self::Rng,
            CryptoError::InvalidMnemonic => Self::InvalidMnemonic,
            CryptoError::InvalidLength => Self::InvalidLength,
            CryptoError::Base64Decode => Self::Base64Decode,
            CryptoError::SignatureInvalid => Self::SignatureInvalid,
            CryptoError::InvalidKey => Self::InvalidKey,
            // G3 streaming AEAD is feature-gated to Rust consumers for
            // now; Phase 2 will expose a chunked byte-array API that
            // mobile can call in a loop. Until that lands, coalesce the
            // streaming-specific error variants onto the closest FFI-
            // visible sibling so existing Kotlin / Swift callers keep
            // compiling unchanged.
            CryptoError::StreamTruncated
            | CryptoError::StreamInvalidHeader
            | CryptoError::StreamChunkIndexMismatch => Self::Decryption,
            CryptoError::StreamAlreadyFinalized => Self::Encryption,
        }
    }
}

impl From<privacysuite_core_sdk::privacy_utils::url::UrlError> for PrivacySuiteError {
    fn from(e: privacysuite_core_sdk::privacy_utils::url::UrlError) -> Self {
        use privacysuite_core_sdk::privacy_utils::url::UrlError as U;
        match e {
            U::Parse(_) => Self::UrlParse,
            U::InvalidScheme(_) => Self::UrlInvalidScheme,
            U::MissingHost => Self::UrlMissingHost,
            U::PrivateAddress => Self::UrlPrivateAddress,
            U::InvalidHostCharacters => Self::UrlInvalidHostCharacters,
            U::EmbeddedCredentials => Self::UrlEmbeddedCredentials,
            U::ObfuscatedIpEncoding => Self::UrlObfuscatedIpEncoding,
        }
    }
}

#[cfg(feature = "auth")]
impl From<privacysuite_core_sdk::auth::AuthError> for PrivacySuiteError {
    fn from(e: privacysuite_core_sdk::auth::AuthError) -> Self {
        match e {
            privacysuite_core_sdk::auth::AuthError::Protocol => Self::AuthProtocol,
            privacysuite_core_sdk::auth::AuthError::InvalidMessage => Self::AuthInvalidMessage,
            privacysuite_core_sdk::auth::AuthError::Crypto(c) => Self::from(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Opaque key handles — raw key bytes NEVER cross FFI unless explicitly asked.
// ---------------------------------------------------------------------------

/// Opaque handle wrapping a VaultKey (256-bit encryption key).
///
/// Key material lives only on the Rust heap and is zeroized when the last
/// `Arc` reference is dropped (via VaultKey's ZeroizeOnDrop). Kotlin/Swift
/// callers hold a pointer to this Arc — they never touch raw bytes unless
/// they call `as_bytes()`.
#[derive(uniffi::Object)]
pub struct VaultKeyHandle {
    inner: keys::VaultKey,
}

#[uniffi::export]
impl VaultKeyHandle {
    /// Create a VaultKeyHandle from raw bytes (32 bytes required).
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, PrivacySuiteError> {
        // SECURITY: Validate input length at FFI boundary to prevent type confusion.
        if bytes.len() != keys::KEY_LEN {
            return Err(PrivacySuiteError::InvalidLength);
        }
        let mut arr = [0u8; keys::KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Arc::new(Self {
            inner: keys::VaultKey::from_bytes(arr),
        }))
    }

    /// Export the raw key bytes. Caller must zeroize when done.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

/// Opaque handle wrapping a 256-bit random salt.
#[derive(uniffi::Object)]
pub struct SaltHandle {
    inner: keys::Salt,
}

#[uniffi::export]
impl SaltHandle {
    /// Generate a fresh cryptographically random salt.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, PrivacySuiteError> {
        Ok(Arc::new(Self {
            inner: keys::Salt::generate()?,
        }))
    }

    /// Create a SaltHandle from existing bytes (32 bytes required).
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, PrivacySuiteError> {
        Ok(Arc::new(Self {
            inner: keys::Salt::from_slice(&bytes)?,
        }))
    }

    /// Export the raw salt bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

/// Opaque handle wrapping a 24-word BIP39 mnemonic.
#[derive(uniffi::Object)]
pub struct MnemonicHandle {
    inner: mnemonic::Mnemonic,
}

#[uniffi::export]
impl MnemonicHandle {
    /// Generate a new random 24-word mnemonic.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, PrivacySuiteError> {
        Ok(Arc::new(Self {
            inner: mnemonic::Mnemonic::generate()?,
        }))
    }

    /// Recover a mnemonic from a space-separated word phrase.
    #[uniffi::constructor]
    pub fn from_phrase(phrase: String) -> Result<Arc<Self>, PrivacySuiteError> {
        Ok(Arc::new(Self {
            inner: mnemonic::Mnemonic::from_phrase(&phrase)?,
        }))
    }

    /// Returns the 24 mnemonic words.
    pub fn words(&self) -> Vec<String> {
        self.inner.words()
    }

    /// Returns the mnemonic as a space-separated string.
    pub fn to_phrase(&self) -> String {
        self.inner.to_phrase()
    }

    /// Derives a VaultKey from this mnemonic via BIP39 seed derivation.
    pub fn derive_vault_key(&self, passphrase: String) -> Result<Arc<VaultKeyHandle>, PrivacySuiteError> {
        let key = self.inner.derive_vault_key(&passphrase)?;
        Ok(Arc::new(VaultKeyHandle { inner: key }))
    }
}

// ---------------------------------------------------------------------------
// Core crypto functions
// ---------------------------------------------------------------------------

/// Derives a VaultKey from a passphrase and salt using Argon2id.
///
/// Parameters are hardcoded: m=64 MB, t=3, p=4 (no downgrade possible).
#[uniffi::export]
pub fn derive_key(
    passphrase: Vec<u8>,
    salt: &SaltHandle,
) -> Result<Arc<VaultKeyHandle>, PrivacySuiteError> {
    let key = keys::derive_key(&passphrase, &salt.inner)?;
    Ok(Arc::new(VaultKeyHandle { inner: key }))
}

/// Derives a purpose-specific sub-key from a master key using BLAKE3.
///
/// The `context` string binds the derived key to a specific purpose.
/// Different contexts produce independent keys from the same master.
#[uniffi::export]
pub fn derive_subkey(
    master: &VaultKeyHandle,
    context: String,
) -> Result<Arc<VaultKeyHandle>, PrivacySuiteError> {
    let key = kdf::derive_subkey(&master.inner, &context)?;
    Ok(Arc::new(VaultKeyHandle { inner: key }))
}

/// Derives a VaultKey using Argon2id with custom parameters.
///
/// Parameters are validated: m >= 64 MiB, t >= 3, p in 1..=8.
#[uniffi::export]
pub fn derive_key_with_params(
    passphrase: Vec<u8>,
    salt: &SaltHandle,
    m_cost_mib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Arc<VaultKeyHandle>, PrivacySuiteError> {
    let params = keys::KdfParams::new(m_cost_mib, t_cost, p_cost)?;
    let key = keys::derive_key_with_params(&passphrase, &salt.inner, &params)?;
    Ok(Arc::new(VaultKeyHandle { inner: key }))
}

/// Computes a BLAKE3 hash of `data`, returning a 32-byte digest.
#[uniffi::export]
pub fn blake3_hash(data: Vec<u8>) -> Vec<u8> {
    hash::blake3(&data).to_vec()
}

/// Returns `true` if `data` hashes to the given BLAKE3 digest.
#[uniffi::export]
pub fn blake3_verify(data: Vec<u8>, expected: Vec<u8>) -> bool {
    if expected.len() != hash::BLAKE3_HASH_LEN {
        return false;
    }
    let mut arr = [0u8; hash::BLAKE3_HASH_LEN];
    arr.copy_from_slice(&expected);
    hash::blake3_verify(&data, &arr)
}

/// Encrypts plaintext using XChaCha20-Poly1305 with associated data.
///
/// Returns nonce || ciphertext || tag as a single byte array.
#[uniffi::export]
pub fn aead_encrypt(
    key: &VaultKeyHandle,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, PrivacySuiteError> {
    Ok(aead::encrypt(&key.inner, &plaintext, &aad)?)
}

/// Decrypts ciphertext produced by `aead_encrypt`.
///
/// Expects input format: nonce (24 bytes) || ciphertext || tag (16 bytes).
#[uniffi::export]
pub fn aead_decrypt(
    key: &VaultKeyHandle,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, PrivacySuiteError> {
    Ok(aead::decrypt(&key.inner, &ciphertext, &aad)?)
}

// ---------------------------------------------------------------------------
// Additional crypto utilities
// ---------------------------------------------------------------------------

/// Computes a keyed BLAKE3 MAC of `data`, returning a 32-byte digest.
///
/// The key must be exactly 32 bytes.
///
/// # Security
///
/// Returns `InvalidLength` error if key is not exactly 32 bytes (validated at FFI boundary).
#[uniffi::export]
pub fn blake3_keyed_hash(key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, PrivacySuiteError> {
    // SECURITY: Strict length validation at FFI boundary prevents key material confusion.
    if key.len() != hash::BLAKE3_HASH_LEN {
        return Err(PrivacySuiteError::InvalidLength);
    }
    let mut key_arr = [0u8; hash::BLAKE3_HASH_LEN];
    key_arr.copy_from_slice(&key);
    Ok(hash::blake3_keyed(&key_arr, &data).to_vec())
}

/// Verifies a keyed BLAKE3 MAC.
#[uniffi::export]
pub fn blake3_keyed_verify(key: Vec<u8>, data: Vec<u8>, expected: Vec<u8>) -> Result<bool, PrivacySuiteError> {
    if key.len() != hash::BLAKE3_HASH_LEN || expected.len() != hash::BLAKE3_HASH_LEN {
        return Err(PrivacySuiteError::InvalidLength);
    }
    let mut key_arr = [0u8; hash::BLAKE3_HASH_LEN];
    key_arr.copy_from_slice(&key);
    let mut exp_arr = [0u8; hash::BLAKE3_HASH_LEN];
    exp_arr.copy_from_slice(&expected);
    Ok(hash::blake3_keyed_verify(&key_arr, &data, &exp_arr))
}

/// HKDF-SHA256 Expand (RFC 5869 Section 2.3).
///
/// Expands a pseudorandom key into `output_len` bytes bound to `info`.
/// PRK must be at least 32 bytes. Max output: 8160 bytes.
///
/// # Security
///
/// Returns error if PRK < 32 bytes or output_len > 8160, preventing HKDF downgrade attacks.
#[uniffi::export]
pub fn hkdf_sha256_expand(
    prk: Vec<u8>,
    info: Vec<u8>,
    output_len: u32,
) -> Result<Vec<u8>, PrivacySuiteError> {
    // SECURITY: hkdf_expand validates PRK length and output length per RFC 5869.
    Ok(hkdf::hkdf_expand(&prk, &info, output_len as usize)?)
}

/// HKDF-SHA256 Extract (RFC 5869 Section 2.2).
///
/// Extracts a 32-byte pseudorandom key from input key material.
///
/// # Security
///
/// Returns an error if HMAC initialisation fails instead of producing
/// a zero PRK on the (unreachable-today) failure path, which would
/// otherwise collapse downstream keys to deterministic values.
#[uniffi::export]
pub fn hkdf_sha256_extract(salt: Vec<u8>, ikm: Vec<u8>) -> Result<Vec<u8>, PrivacySuiteError> {
    Ok(hkdf::hkdf_extract(&salt, &ikm)?.to_vec())
}

/// Generates cryptographically secure random bytes.
#[uniffi::export]
pub fn secure_random(len: u32) -> Result<Vec<u8>, PrivacySuiteError> {
    Ok(util::secure_random(len as usize)?)
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` only if both slices have identical length and contents.
#[uniffi::export]
pub fn constant_time_equals(a: Vec<u8>, b: Vec<u8>) -> bool {
    util::constant_time_eq(&a, &b)
}

// ---------------------------------------------------------------------------
// OPAQUE authentication (client-side)
// ---------------------------------------------------------------------------

/// Result of starting OPAQUE registration.
#[derive(uniffi::Record)]
pub struct RegistrationStartResult {
    /// Opaque state handle — pass to `registration_finish`.
    pub state: Arc<RegistrationStateHandle>,
    /// Serialized RegistrationRequest to send to the server.
    pub message: Vec<u8>,
}

/// Result of starting OPAQUE login.
#[derive(uniffi::Record)]
pub struct LoginStartResult {
    /// Opaque state handle — pass to `login_finish`.
    pub state: Arc<LoginStateHandle>,
    /// Serialized CredentialRequest to send to the server.
    pub message: Vec<u8>,
}

/// Opaque handle for OPAQUE client registration state.
///
/// This is a one-shot handle: `registration_finish` consumes the inner state.
#[derive(uniffi::Object)]
pub struct RegistrationStateHandle {
    #[cfg(feature = "auth")]
    inner: std::sync::Mutex<Option<privacysuite_core_sdk::auth::ClientRegistrationState>>,
    #[cfg(not(feature = "auth"))]
    _phantom: (),
}

/// Opaque handle for OPAQUE client login state.
///
/// This is a one-shot handle: `login_finish` consumes the inner state.
#[derive(uniffi::Object)]
pub struct LoginStateHandle {
    #[cfg(feature = "auth")]
    inner: std::sync::Mutex<Option<privacysuite_core_sdk::auth::ClientLoginState>>,
    #[cfg(not(feature = "auth"))]
    _phantom: (),
}

/// Begin OPAQUE registration. Returns state + message to send to server.
#[uniffi::export]
pub fn registration_start(password: Vec<u8>) -> Result<RegistrationStartResult, PrivacySuiteError> {
    #[cfg(feature = "auth")]
    {
        let (state, message) = privacysuite_core_sdk::auth::registration_start(&password)?;
        Ok(RegistrationStartResult {
            state: Arc::new(RegistrationStateHandle {
                inner: std::sync::Mutex::new(Some(state)),
            }),
            message,
        })
    }
    #[cfg(not(feature = "auth"))]
    {
        let _ = password;
        Err(PrivacySuiteError::AuthProtocol)
    }
}

/// Finish OPAQUE registration. Returns upload message to send to server.
#[uniffi::export]
pub fn registration_finish(
    state: &RegistrationStateHandle,
    server_response: Vec<u8>,
) -> Result<Vec<u8>, PrivacySuiteError> {
    #[cfg(feature = "auth")]
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| PrivacySuiteError::AuthProtocol)?
            .take()
            .ok_or(PrivacySuiteError::AuthProtocol)?;
        Ok(privacysuite_core_sdk::auth::registration_finish(inner, &server_response)?)
    }
    #[cfg(not(feature = "auth"))]
    {
        let _ = (state, server_response);
        Err(PrivacySuiteError::AuthProtocol)
    }
}

/// Begin OPAQUE login. Returns state + message to send to server.
#[uniffi::export]
pub fn login_start(password: Vec<u8>) -> Result<LoginStartResult, PrivacySuiteError> {
    #[cfg(feature = "auth")]
    {
        let (state, message) = privacysuite_core_sdk::auth::login_start(&password)?;
        Ok(LoginStartResult {
            state: Arc::new(LoginStateHandle {
                inner: std::sync::Mutex::new(Some(state)),
            }),
            message,
        })
    }
    #[cfg(not(feature = "auth"))]
    {
        let _ = password;
        Err(PrivacySuiteError::AuthProtocol)
    }
}

/// Finish OPAQUE login. Returns the authenticated session key bytes.
#[uniffi::export]
pub fn login_finish(
    state: &LoginStateHandle,
    server_response: Vec<u8>,
) -> Result<Vec<u8>, PrivacySuiteError> {
    #[cfg(feature = "auth")]
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| PrivacySuiteError::AuthProtocol)?
            .take()
            .ok_or(PrivacySuiteError::AuthProtocol)?;
        let session_key = privacysuite_core_sdk::auth::login_finish(inner, &server_response)?;
        Ok(session_key.as_bytes().to_vec())
    }
    #[cfg(not(feature = "auth"))]
    {
        let _ = (state, server_response);
        Err(PrivacySuiteError::AuthProtocol)
    }
}

// ---------------------------------------------------------------------------
// PIN lock (G6)
// ---------------------------------------------------------------------------
//
// Two of the three `auth::pin_lock` primitives lift cleanly across UniFFI:
//
//   * `pin_derive_key` — pure function; PIN bytes + salt handle ->
//     VaultKey handle. No callback, no persistent state.
//   * `pin_status`      — pure query over a plain-data state struct.
//
// `try_pin` is *not* exported here. It takes a `verify_fn` callback that
// decides whether a freshly-derived key is correct, and UniFFI 0.31's
// callback interfaces don't round-trip the `Arc<VaultKeyHandle>` argument
// ergonomically. Kotlin / Swift callers can assemble the equivalent flow
// at the higher layer with the primitives exported here:
//
//   1. call `pin_status`; if locked, show the countdown and return.
//   2. call `pin_derive_key(pin, salt)` -> VaultKey handle.
//   3. call `aead_decrypt` against the stored canary; on success, call
//      `pin_status` again after resetting state in their persistence
//      layer.
//
// A Phase-2 follow-up will add the callback-based `try_pin` export once
// we settle on a UniFFI pattern for "caller-supplied predicate over an
// opaque handle"; tracked in the G6 PR description.

/// PIN attempt counter + exponential lockout timer. Mirror of
/// [`privacysuite_core_sdk::auth::pin_lock::PinAttemptState`] flattened
/// into a UniFFI `Record` so Kotlin / Swift callers can round-trip it
/// through their own persistence without learning about opaque handles.
#[cfg(feature = "auth")]
#[derive(uniffi::Record)]
pub struct PinStateFfi {
    /// Consecutive wrong-PIN attempts recorded.
    pub attempt_count: u32,
    /// Wall-clock (Unix milliseconds) at which the current lockout
    /// expires. `0` means "not currently locked".
    pub lockout_until_unix_ms: u64,
    /// Wall-clock (Unix milliseconds) of the last PIN attempt.
    pub last_attempt_unix_ms: u64,
}

/// PIN lockout snapshot — what the UI needs to render. Derived from a
/// [`PinStateFfi`] + caller-supplied wall-clock by [`pin_status`].
#[cfg(feature = "auth")]
#[derive(uniffi::Record)]
pub struct PinStatusFfi {
    /// `true` while the user must wait out the current lockout.
    pub is_locked: bool,
    /// Seconds remaining on the current lockout. `0` when not locked.
    pub remaining_secs: u64,
    /// How many more wrong guesses fit inside the free-attempt budget
    /// before the next lockout tier activates.
    pub attempts_left_before_next_lockout: u32,
}

#[cfg(feature = "auth")]
impl From<privacysuite_core_sdk::auth::pin_lock::PinAttemptState> for PinStateFfi {
    fn from(s: privacysuite_core_sdk::auth::pin_lock::PinAttemptState) -> Self {
        Self {
            attempt_count: s.attempt_count,
            lockout_until_unix_ms: s.lockout_until_unix_ms,
            last_attempt_unix_ms: s.last_attempt_unix_ms,
        }
    }
}

#[cfg(feature = "auth")]
impl From<PinStateFfi> for privacysuite_core_sdk::auth::pin_lock::PinAttemptState {
    fn from(s: PinStateFfi) -> Self {
        Self {
            attempt_count: s.attempt_count,
            lockout_until_unix_ms: s.lockout_until_unix_ms,
            last_attempt_unix_ms: s.last_attempt_unix_ms,
        }
    }
}

/// Derive a VaultKey from a PIN attempt using the PIN-tuned Argon2id
/// parameters. Wraps [`privacysuite_core_sdk::auth::pin_lock::derive_key_from_pin`].
///
/// The caller tests the returned key against their canary to decide
/// whether the PIN was correct — the SDK never compares secret bytes
/// directly across the FFI boundary.
#[cfg(feature = "auth")]
#[uniffi::export]
pub fn pin_derive_key(
    pin: Vec<u8>,
    salt: &SaltHandle,
) -> Result<Arc<VaultKeyHandle>, PrivacySuiteError> {
    let key = privacysuite_core_sdk::auth::pin_lock::derive_key_from_pin(&pin, &salt.inner)?;
    Ok(Arc::new(VaultKeyHandle { inner: key }))
}

/// Snapshot the lockout posture of a persisted PIN attempt state.
#[cfg(feature = "auth")]
#[uniffi::export]
#[must_use]
pub fn pin_status(state: PinStateFfi, now_unix_ms: u64) -> PinStatusFfi {
    let native = privacysuite_core_sdk::auth::pin_lock::PinAttemptState::from(state);
    let status = privacysuite_core_sdk::auth::pin_lock::status(&native, now_unix_ms);
    PinStatusFfi {
        is_locked: status.is_locked,
        remaining_secs: status.remaining_secs,
        attempts_left_before_next_lockout: status.attempts_left_before_next_lockout,
    }
}

// ---------------------------------------------------------------------------
// URL validation (G2)
// ---------------------------------------------------------------------------

/// Validate and normalise a URL for safe fetching.
///
/// Returns the normalised URL string (fragment + credentials stripped,
/// host lowercased) on success, or a [`PrivacySuiteError`] variant
/// identifying the specific rejection class.
///
/// Returning the string rather than an opaque `ValidatedUrl` handle is a
/// deliberate simplification for the UniFFI boundary: `ValidatedUrl` is a
/// tiny wrapper whose only purpose is type-level proof that validation
/// occurred, and surfacing that across FFI would require an `Arc`-backed
/// object handle with no meaningful methods on the foreign side. Callers
/// in Kotlin/Swift that need the normalised string can call this function
/// and trust the output; callers that need to re-validate (e.g. redirect
/// hops) should pass the string back in for another check.
#[uniffi::export]
pub fn validate_url(input: String) -> Result<String, PrivacySuiteError> {
    let validated = privacysuite_core_sdk::privacy_utils::url::validate_url(&input)?;
    Ok(validated.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// G1: PrivacyClient (DEFERRED FOR FFI — Phase 2)
// ---------------------------------------------------------------------------
//
// `PrivacyClient` composes the DoH / OHTTP / Tor tiers behind one API. It is
// fully available to Rust callers today via the `http` feature of the core
// crate (`privacysuite_core_sdk::networking::PrivacyClient`). Exposing it
// across UniFFI is deferred to a follow-up release for the reasons below —
// a UniFFI shim in this crate would force significant shape changes to the
// Rust API and block the Phase-1 migration of Music, Podcasts, Weather,
// RSS, DarkGIFs, Blackout, Screenshots, and Telephoto.
//
// ## Why it's deferred
//
//  * UniFFI 0.31's async-method export has rough edges for complex return
//    types. `PrivacyResponse` contains `Vec<(String, String)>` for headers,
//    which is legal but requires extra scaffolding for both Kotlin and
//    Swift. Getting that wrong at the FFI boundary is much more expensive
//    than adding it in Phase 2.
//
//  * The first wave of consumers (Music / Podcasts / Weather / RSS /
//    DarkGIFs / Blackout / Screenshots / Telephoto) are all Tauri+Rust
//    backends on Android. They consume `privacysuite-core-sdk` as a Cargo
//    dependency directly, not through UniFFI, so the Rust API is enough
//    for all eight. Native-Kotlin consumers (Voice, Scanner, Scratchpad)
//    don't make network calls today and can be addressed in Phase 2 with a
//    properly-shaped async UniFFI export.
//
// ## Phase 2 shape (tracking)
//
// When the export lands it will look roughly like:
//
// ```ignore
// #[derive(uniffi::Object)]
// pub struct PrivacyClientHandle { inner: PrivacyClient }
//
// #[uniffi::export(async_runtime = "tokio")]
// impl PrivacyClientHandle {
//     #[uniffi::constructor]
//     pub fn new(config: PrivacyClientConfigFfi) -> Result<Arc<Self>, PrivacySuiteError>;
//     pub async fn fetch(
//         &self,
//         method: String, url: String,
//         headers: Vec<HttpHeader>, body: Vec<u8>,
//     ) -> Result<PrivacyResponseFfi, PrivacySuiteError>;
//     pub async fn fetch_with_decoys(
//         &self,
//         real: FetchSpecFfi, decoys: Vec<FetchSpecFfi>, k: u32,
//     ) -> Result<PrivacyResponseFfi, PrivacySuiteError>;
// }
// ```
//
// See `networking::privacy_client` in the core crate for the authoritative
// Rust-side API and behaviour.
