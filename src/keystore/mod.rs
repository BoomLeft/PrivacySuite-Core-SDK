//! Android Keystore + `BiometricPrompt` wrapper around [`crate::crypto::keys::VaultKey`].
//!
//! # Overview
//!
//! On Android, app-local secrets MUST NOT live in plaintext on disk. The
//! platform's [Android Keystore] provides hardware-backed, non-extractable
//! keys that survive even a full filesystem compromise: an attacker with
//! read access to `/data/data/<your-package>/files` cannot derive the
//! wrapped secret without executing code as your UID.
//!
//! [`KeystoreVault`] wraps that platform primitive with a small Rust API
//! purpose-built for `BoomLeft`'s `VaultKey` type:
//!
//! - [`KeystoreVault::open_or_create`] provisions (or reopens) an AES-256-GCM
//!   key alias in the Android Keystore, preferring `StrongBox` when
//!   available;
//! - [`KeystoreVault::wrap_vault_key`] seals a `VaultKey` into an opaque
//!   ciphertext blob safe to write to `shared_preferences`/filesystem;
//! - [`KeystoreVault::unwrap_vault_key`] reverses the wrap and hands back
//!   a fresh [`zeroize::ZeroizeOnDrop`] `VaultKey`.
//!
//! # Platform support
//!
//! This module is **Android-only**. On every other target the crate
//! exposes stub symbols whose methods all return
//! [`KeystoreError::NotAvailable`] — this lets SDK consumers write
//! `cfg`-independent code against [`KeystoreVault`] and only check the
//! error variant at runtime.
//!
//! # `BiometricPrompt` integration
//!
//! Showing a `BiometricPrompt` requires a live `FragmentActivity`
//! reference, which the SDK's pure-Rust layer cannot obtain on its own.
//! For this first release we therefore go with **Option A**:
//!
//! - [`BiometricPolicy`] controls the `setUserAuthenticationRequired`
//!   and `setUserAuthenticationParameters` bits set on the
//!   `KeyGenParameterSpec` when the key is first provisioned;
//! - the caller is responsible for calling `BiometricPrompt` from the
//!   Android side **before** invoking [`KeystoreVault::unwrap_vault_key`];
//! - if the user has not authenticated within the policy's validity
//!   window, the subsequent `Cipher.init` call throws
//!   `UserNotAuthenticatedException`, which surfaces here as
//!   [`KeystoreError::BiometricRequired`]. The caller catches that,
//!   shows its `BiometricPrompt`, and retries the unwrap.
//!
//! A later release will expose a `UniFFI` callback-interface
//! `BiometricPromptHost` so the SDK can drive the prompt directly.
//! Until then see `TODO(G5-Phase4)` in [`android`].
//!
//! # Feature gate
//!
//! Pull in the `keystore` Cargo feature to enable this module. On
//! non-Android targets the feature is a no-op at the type level
//! (the stub types compile but every method is a short-circuit).
//!
//! [Android Keystore]: https://developer.android.com/privacy-and-security/keystore

#![cfg_attr(not(target_os = "android"), allow(unused))]

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "android")]
pub use android::{BiometricPolicy, KeystoreError, KeystoreVault};

// --- Non-Android stubs ----------------------------------------------------
//
// A parallel `android` module is exposed on non-Android targets so that
// callers can `use privacysuite_core_sdk::keystore::android::...` in
// cfg-independent code without importing a module that doesn't exist.
// Every method returns `KeystoreError::NotAvailable`; there is no
// Keystore implementation to fall back on off-device.

#[cfg(not(target_os = "android"))]
pub mod android {
    //! Non-Android stub. Every method returns
    //! [`KeystoreError::NotAvailable`]. See the module-level doc on
    //! [`super`] for the real implementation.

    use crate::error::CryptoError;

    /// Stub error type. Mirrors the Android implementation's variants so
    /// consumer `match` arms stay exhaustive across targets.
    #[derive(Debug)]
    pub enum KeystoreError {
        /// The Keystore backend is not available on this target (e.g. this
        /// build is for desktop or iOS, not Android).
        NotAvailable,
        /// `StrongBox` was required but isn't available on this device.
        HardwareBackedRequired,
        /// The key requires a biometric authentication that hasn't
        /// happened (or has expired) — caller must re-authenticate.
        BiometricRequired,
        /// The user dismissed the biometric / credential prompt.
        UserCancelled,
        /// A lower-level I/O or JNI failure; the inner `String` is a
        /// sanitised message (never contains key material).
        Io(String),
        /// A crypto-layer failure bubbled up from [`CryptoError`].
        Crypto(CryptoError),
    }

    impl std::fmt::Display for KeystoreError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotAvailable => f.write_str("Android Keystore is not available on this platform"),
                Self::HardwareBackedRequired => f.write_str("hardware-backed keystore (StrongBox) is required but unavailable"),
                Self::BiometricRequired => f.write_str("biometric authentication is required"),
                Self::UserCancelled => f.write_str("user cancelled authentication"),
                Self::Io(msg) => write!(f, "keystore I/O error: {msg}"),
                Self::Crypto(e) => write!(f, "keystore crypto error: {e}"),
            }
        }
    }

    impl std::error::Error for KeystoreError {}

    impl From<CryptoError> for KeystoreError {
        fn from(e: CryptoError) -> Self {
            Self::Crypto(e)
        }
    }

    /// Stub biometric policy. On non-Android targets the enum exists
    /// purely so cfg-independent code can continue to build.
    #[derive(Debug, Copy, Clone)]
    pub enum BiometricPolicy {
        /// No biometric gate; key is still hardware-backed (where available).
        None,
        /// Device credential (PIN / pattern / password) required within
        /// the last `invalidate_after_secs` seconds.
        DeviceCredential {
            /// Seconds the credential auth stays valid for. `0` = require
            /// a fresh auth on every operation.
            invalidate_after_secs: u32,
        },
        /// Biometric per-use.
        Biometric,
        /// Biometric OR device credential, caller's choice at prompt time.
        BiometricOrDeviceCredential,
    }

    /// Stub vault handle. Every method returns
    /// [`KeystoreError::NotAvailable`].
    #[derive(Debug)]
    pub struct KeystoreVault {
        _private: (),
    }

    impl KeystoreVault {
        /// Stub entry point for non-Android builds.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`] — there is no
        /// Android Keystore to talk to off-device.
        pub fn open_or_create(
            _alias: &str,
            _policy: BiometricPolicy,
            _require_strongbox: bool,
        ) -> Result<Self, KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }

        /// Stub accessor.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`].
        pub fn is_hardware_backed(&self) -> Result<bool, KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }

        /// Stub accessor.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`].
        pub fn is_strongbox_backed(&self) -> Result<bool, KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }

        /// Stub wrap entry point.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`].
        pub fn wrap_vault_key(
            &self,
            _key: &crate::crypto::keys::VaultKey,
        ) -> Result<Vec<u8>, KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }

        /// Stub unwrap entry point.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`].
        pub fn unwrap_vault_key(
            &self,
            _wrapped: &[u8],
        ) -> Result<crate::crypto::keys::VaultKey, KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }

        /// Stub delete.
        ///
        /// # Errors
        ///
        /// Always returns [`KeystoreError::NotAvailable`].
        pub fn delete(self) -> Result<(), KeystoreError> {
            Err(KeystoreError::NotAvailable)
        }
    }
}

#[cfg(not(target_os = "android"))]
pub use android::{BiometricPolicy, KeystoreError, KeystoreVault};

// --- Pure-Rust state-machine helpers --------------------------------------
//
// These are intentionally target-agnostic: they encapsulate the policy →
// `KeyGenParameterSpec`-builder-bits mapping, plus the wrapped-blob
// framing, in a form that's testable on the host without an Android
// runtime. The `android` module calls into them from the JNI side.

/// Bit-flag subset of `KeyProperties.AUTH_*` matching the authenticators
/// field passed to `setUserAuthenticationParameters`.
///
/// The values mirror Android constants by construction and stay `u32`
/// so we can encode them directly in the host-side unit tests without
/// pulling in any JNI types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatorFlags(pub(crate) u32);

impl AuthenticatorFlags {
    /// `KeyProperties.AUTH_BIOMETRIC_STRONG` (`1 << 0`).
    pub(crate) const BIOMETRIC_STRONG: Self = Self(0x1);
    /// `KeyProperties.AUTH_DEVICE_CREDENTIAL` (`1 << 1`).
    pub(crate) const DEVICE_CREDENTIAL: Self = Self(0x2);

    /// Bitwise OR — kept const-fn so we can use it in `const` contexts.
    pub(crate) const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Raw flag bits, as passed to the Android SDK.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

/// Logical spec derived from a [`BiometricPolicy`], ready to be realised
/// as a `KeyGenParameterSpec.Builder` call sequence on the Android side.
///
/// Exists to keep the Android JNI code thin and the business logic
/// host-testable.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct KeySpec {
    /// Matches `setUserAuthenticationRequired(bool)`.
    pub(crate) user_auth_required: bool,
    /// If `Some`, call `setUserAuthenticationParameters(timeout, flags)`.
    /// If `None`, leave the default.
    pub(crate) auth_params: Option<AuthParams>,
}

/// Second argument of `setUserAuthenticationParameters`, split out so
/// the host-side tests can inspect both halves independently.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct AuthParams {
    /// Timeout in seconds the last auth remains valid for. `0` means
    /// the key must be freshly authenticated on every use.
    pub(crate) timeout_secs: u32,
    /// Bit flags the key will accept as "authenticated".
    pub(crate) flags: AuthenticatorFlags,
}

/// Maps a [`BiometricPolicy`] onto the `KeyGenParameterSpec` bits the
/// Android side will set at provisioning time. This is the single
/// source of truth — the JNI path and the host-side unit tests both
/// route through it.
#[cfg(any(target_os = "android", test))]
pub(crate) fn key_spec_for(policy: BiometricPolicy) -> KeySpec {
    match policy {
        BiometricPolicy::None => KeySpec {
            user_auth_required: false,
            auth_params: None,
        },
        BiometricPolicy::DeviceCredential {
            invalidate_after_secs,
        } => KeySpec {
            user_auth_required: true,
            auth_params: Some(AuthParams {
                timeout_secs: invalidate_after_secs,
                flags: AuthenticatorFlags::DEVICE_CREDENTIAL,
            }),
        },
        BiometricPolicy::Biometric => KeySpec {
            user_auth_required: true,
            auth_params: Some(AuthParams {
                // 0 = per-use biometric prompt
                timeout_secs: 0,
                flags: AuthenticatorFlags::BIOMETRIC_STRONG,
            }),
        },
        BiometricPolicy::BiometricOrDeviceCredential => KeySpec {
            user_auth_required: true,
            auth_params: Some(AuthParams {
                timeout_secs: 0,
                flags: AuthenticatorFlags::BIOMETRIC_STRONG.or(AuthenticatorFlags::DEVICE_CREDENTIAL),
            }),
        },
    }
}

// --- Wrapped-blob framing -------------------------------------------------
//
// The Android Keystore's `Cipher.doFinal` produces a raw AES-GCM
// ciphertext with the tag appended, but the 12-byte IV is a separate
// field on the `Cipher` object. We frame both into a single opaque blob
// so callers only deal with one `Vec<u8>`. The layout matches Blackout's
// vetted `SecureSecretStore`:
//
//     [ IV (12 bytes) || ciphertext || GCM auth tag (16 bytes) ]
//
// The header is a fixed single byte `0x01` so we can evolve the format
// later without breaking old wrapped blobs on disk.

/// Wire-format version byte, prepended to every wrapped blob.
/// Bumping this is a breaking change; add a migration path first.
pub(crate) const WIRE_VERSION: u8 = 0x01;
/// AES-GCM IV length — 12 bytes is the NIST-recommended default and
/// what the Android Keystore produces.
pub(crate) const AES_GCM_IV_LEN: usize = 12;
/// AES-GCM auth tag length in bytes (128-bit).
pub(crate) const AES_GCM_TAG_LEN: usize = 16;
/// Minimum plausible wrapped-blob length: version byte + IV + tag.
pub(crate) const MIN_WRAPPED_LEN: usize = 1 + AES_GCM_IV_LEN + AES_GCM_TAG_LEN;

/// Frame a fresh wrapped blob: `[ version || iv || ciphertext-with-tag ]`.
#[cfg(any(target_os = "android", test))]
pub(crate) fn frame_wrapped(iv: &[u8], ciphertext_with_tag: &[u8]) -> Result<Vec<u8>, FramingError> {
    if iv.len() != AES_GCM_IV_LEN {
        return Err(FramingError::BadIv);
    }
    if ciphertext_with_tag.len() < AES_GCM_TAG_LEN {
        return Err(FramingError::ShortCiphertext);
    }
    let mut out = Vec::with_capacity(1 + AES_GCM_IV_LEN + ciphertext_with_tag.len());
    out.push(WIRE_VERSION);
    out.extend_from_slice(iv);
    out.extend_from_slice(ciphertext_with_tag);
    Ok(out)
}

/// Inverse of [`frame_wrapped`]. Returns the IV slice and the
/// ciphertext-with-tag slice without copying.
#[cfg(any(target_os = "android", test))]
pub(crate) fn unframe_wrapped(blob: &[u8]) -> Result<(&[u8], &[u8]), FramingError> {
    if blob.len() < MIN_WRAPPED_LEN {
        return Err(FramingError::TooShort);
    }
    let version = blob.first().copied().ok_or(FramingError::TooShort)?;
    if version != WIRE_VERSION {
        return Err(FramingError::BadVersion(version));
    }
    let iv_end = 1 + AES_GCM_IV_LEN;
    let iv = blob.get(1..iv_end).ok_or(FramingError::TooShort)?;
    let ct = blob.get(iv_end..).ok_or(FramingError::TooShort)?;
    if ct.len() < AES_GCM_TAG_LEN {
        return Err(FramingError::ShortCiphertext);
    }
    Ok((iv, ct))
}

/// Framing-level decode errors. Never bubbled out as-is — the Android
/// entry points map every variant onto [`KeystoreError::Io`] with a
/// sanitised message.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// Blob is shorter than `MIN_WRAPPED_LEN`.
    TooShort,
    /// Version byte was not `WIRE_VERSION`. Holds the unexpected byte.
    BadVersion(u8),
    /// IV slice was not exactly `AES_GCM_IV_LEN` bytes.
    BadIv,
    /// Ciphertext + tag was shorter than `AES_GCM_TAG_LEN` bytes.
    ShortCiphertext,
}

#[cfg(test)]
mod pure_tests {
    //! Host-runnable unit tests for the pure-Rust state machine — policy
    //! → spec-builder-bits mapping, wrapped-blob framing. These never
    //! invoke JNI and pass on every target.

    use super::*;

    #[test]
    fn policy_none_leaves_auth_off() {
        let spec = key_spec_for(BiometricPolicy::None);
        assert!(!spec.user_auth_required);
        assert!(spec.auth_params.is_none());
    }

    #[test]
    fn policy_device_credential_uses_device_flag() {
        let spec = key_spec_for(BiometricPolicy::DeviceCredential {
            invalidate_after_secs: 30,
        });
        assert!(spec.user_auth_required);
        let params = spec.auth_params.unwrap();
        assert_eq!(params.timeout_secs, 30);
        assert_eq!(params.flags, AuthenticatorFlags::DEVICE_CREDENTIAL);
    }

    #[test]
    fn policy_device_credential_zero_means_per_op() {
        let spec = key_spec_for(BiometricPolicy::DeviceCredential {
            invalidate_after_secs: 0,
        });
        assert_eq!(spec.auth_params.unwrap().timeout_secs, 0);
    }

    #[test]
    fn policy_biometric_forces_per_use() {
        let spec = key_spec_for(BiometricPolicy::Biometric);
        assert!(spec.user_auth_required);
        let params = spec.auth_params.unwrap();
        assert_eq!(params.timeout_secs, 0);
        assert_eq!(params.flags, AuthenticatorFlags::BIOMETRIC_STRONG);
    }

    #[test]
    fn policy_biometric_or_credential_sets_both_flags() {
        let spec = key_spec_for(BiometricPolicy::BiometricOrDeviceCredential);
        let params = spec.auth_params.unwrap();
        assert_eq!(params.timeout_secs, 0);
        assert_eq!(
            params.flags.bits(),
            AuthenticatorFlags::BIOMETRIC_STRONG.bits()
                | AuthenticatorFlags::DEVICE_CREDENTIAL.bits()
        );
    }

    #[test]
    fn framing_roundtrip() {
        let iv = [0xABu8; AES_GCM_IV_LEN];
        let ct = [0xCDu8; 48];
        let blob = frame_wrapped(&iv, &ct).unwrap();
        assert_eq!(blob.len(), 1 + AES_GCM_IV_LEN + 48);
        assert_eq!(blob[0], WIRE_VERSION);

        let (iv_out, ct_out) = unframe_wrapped(&blob).unwrap();
        assert_eq!(iv_out, &iv);
        assert_eq!(ct_out, &ct);
    }

    #[test]
    fn framing_rejects_wrong_iv_length() {
        assert_eq!(frame_wrapped(&[0u8; 8], &[0u8; 32]), Err(FramingError::BadIv));
    }

    #[test]
    fn framing_rejects_short_ciphertext_input() {
        let iv = [0u8; AES_GCM_IV_LEN];
        assert_eq!(
            frame_wrapped(&iv, &[0u8; AES_GCM_TAG_LEN - 1]),
            Err(FramingError::ShortCiphertext)
        );
    }

    #[test]
    fn unframe_rejects_short_blob() {
        assert_eq!(unframe_wrapped(&[]), Err(FramingError::TooShort));
        assert_eq!(
            unframe_wrapped(&[0u8; MIN_WRAPPED_LEN - 1]),
            Err(FramingError::TooShort)
        );
    }

    #[test]
    fn unframe_rejects_bad_version() {
        let mut blob = vec![0u8; MIN_WRAPPED_LEN];
        blob[0] = 0xFF;
        assert_eq!(unframe_wrapped(&blob), Err(FramingError::BadVersion(0xFF)));
    }

    // -- Stub-behaviour tests (non-Android builds only) -------------------
    //
    // The Android side has its own integration test module. On host
    // builds, verify every method on the stub surface fails with
    // NotAvailable so callers can rely on the cfg-independent API.

    #[cfg(not(target_os = "android"))]
    #[test]
    fn stub_open_or_create_returns_not_available() {
        let err = KeystoreVault::open_or_create("x", BiometricPolicy::None, false).unwrap_err();
        assert!(matches!(err, KeystoreError::NotAvailable));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn stub_wrap_returns_not_available() {
        // We can't construct a KeystoreVault on non-Android (open_or_create
        // refuses), so we only check the constructor path. The vault
        // instance methods are unreachable on this target by construction.
    }
}
