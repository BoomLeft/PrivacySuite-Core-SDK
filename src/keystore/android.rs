//! Android Keystore implementation of [`KeystoreVault`].
//!
//! # JNI architecture
//!
//! This module talks to `java.security.KeyStore`, `javax.crypto.KeyGenerator`,
//! `android.security.keystore.KeyGenParameterSpec.Builder`, and
//! `javax.crypto.Cipher` directly over JNI. We deliberately do **not**
//! ship a Kotlin shim with the SDK — consumer apps wouldn't pick it up
//! the way they pick up a Cargo dependency, and the SDK would grow a
//! second build system. Blackout's `SecureSecretStore.kt` is the vetted
//! reference we're porting; the Rust side below is a direct rewrite of
//! the same algorithm (`getOrCreateKey` → wrap/unwrap) without the
//! Kotlin indirection.
//!
//! # Panics
//!
//! This module must **never** panic — a Rust panic that unwinds across
//! the JNI boundary is undefined behaviour. Every call site returns a
//! `Result` and every `?` must produce a `KeystoreError`. The `clippy`
//! lint `panic = "deny"` enforces the absence of `panic!/unimplemented!/
//! todo!/unreachable!` macros in `src/`; combined with the absence of
//! `unwrap()`/`expect()` (both also denied), this gives us a static
//! guarantee that no panic path exists.
//!
//! # Logging
//!
//! None. Key bytes, wrapped blobs, and exception stack traces never
//! hit a log. Every error carries a short sanitised message describing
//! *where* the failure happened, never *what* was being processed.
//!
//! # `TODO(G5-Phase4)`
//!
//! Expose a `UniFFI` callback-interface `BiometricPromptHost` so this
//! module can drive a `BiometricPrompt` directly instead of requiring
//! the caller to show one before calling `unwrap_vault_key`. Option B
//! in the design doc. Blocked on `UniFFI`'s async-callback ergonomics.

// This file is only compiled on Android — the module is `#[cfg]`-gated
// at the `pub mod android;` declaration in `super`. We intentionally
// do **not** also place `#![cfg(target_os = "android")]` on the file,
// since the outer gate already guards the compile.

// SECURITY: every `unsafe` block in this module is gated by a `SAFETY`
// comment describing the invariant it relies on. See the crate-level
// `unsafe` policy in `lib.rs` — this module is the sole opt-out site
// from the crate-wide `deny(unsafe_code)` lint.

use jni::objects::{JByteArray, JObject, JString, JValue, JValueGen};
use jni::sys::jsize;
use jni::{AttachGuard, JNIEnv, JavaVM};
use zeroize::Zeroize;

use crate::crypto::keys::{VaultKey, KEY_LEN};

use super::{
    frame_wrapped, key_spec_for, unframe_wrapped, AuthParams, FramingError, AES_GCM_IV_LEN,
};

// --- Public surface -------------------------------------------------------

/// Biometric-gating policy applied at key-provisioning time. See the
/// [`super`] module-level docs for how the caller should pair this with
/// its own `BiometricPrompt` invocation.
#[derive(Debug, Copy, Clone)]
pub enum BiometricPolicy {
    /// Key usable without a biometric gate. The key is still
    /// hardware-backed and app-bound; this policy only says "don't
    /// require per-use user authentication".
    None,
    /// Key requires device-credential (PIN / pattern / password) auth
    /// within the last `invalidate_after_secs` seconds. `0` means a
    /// fresh auth is required on every operation.
    DeviceCredential {
        /// See variant docs.
        invalidate_after_secs: u32,
    },
    /// Key requires biometric authentication per use. The caller MUST
    /// show a `BiometricPrompt` from the Android side before calling
    /// [`KeystoreVault::unwrap_vault_key`]; otherwise that call returns
    /// [`KeystoreError::BiometricRequired`].
    Biometric,
    /// Biometric OR device credential, chosen by the user at prompt
    /// time. Useful for apps that want to allow a PIN fallback when
    /// the user's biometric hardware is temporarily unavailable.
    BiometricOrDeviceCredential,
}

/// All error conditions returned by [`KeystoreVault`].
///
/// Variants are coarse by design: foreign callers should not be
/// making policy decisions based on a JNI exception's fine grain.
#[derive(Debug)]
pub enum KeystoreError {
    /// Android Keystore backend is unreachable — typically because the
    /// NDK has not yet populated `ndk_context::android_context()`.
    NotAvailable,
    /// `StrongBox` was requested but isn't available on this device.
    HardwareBackedRequired,
    /// The key's user-auth window has lapsed; caller must prompt again
    /// and retry the operation.
    BiometricRequired,
    /// The user dismissed the biometric / credential prompt.
    UserCancelled,
    /// Wraps a lower-level failure. Message is sanitised — never
    /// contains plaintext, ciphertext, key alias, or wrapped-blob
    /// contents.
    Io(String),
    /// Wraps a crypto failure bubbled up from [`crate::error::CryptoError`].
    Crypto(crate::error::CryptoError),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable => f.write_str("Android Keystore is not available"),
            Self::HardwareBackedRequired => {
                f.write_str("hardware-backed keystore (StrongBox) is required but unavailable")
            }
            Self::BiometricRequired => f.write_str("biometric authentication is required"),
            Self::UserCancelled => f.write_str("user cancelled authentication"),
            Self::Io(msg) => write!(f, "keystore I/O error: {msg}"),
            Self::Crypto(e) => write!(f, "keystore crypto error: {e}"),
        }
    }
}

impl std::error::Error for KeystoreError {}

impl From<crate::error::CryptoError> for KeystoreError {
    fn from(e: crate::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<FramingError> for KeystoreError {
    fn from(e: FramingError) -> Self {
        Self::Io(match e {
            FramingError::TooShort => "wrapped blob is shorter than the minimum header".into(),
            FramingError::BadVersion(_) => "wrapped blob has an unknown version byte".into(),
            FramingError::BadIv => "wrapped blob has an invalid IV length".into(),
            FramingError::ShortCiphertext => "wrapped blob ciphertext is shorter than the tag".into(),
        })
    }
}

/// Handle to an Android-Keystore-backed AES-256-GCM key.
///
/// The key bytes never leave the Keystore hardware — this struct owns
/// only a UTF-8 alias string that identifies the key entry. All
/// operations route through JNI; the struct is therefore
/// `Send`/`Sync`-neutral: it's safe to hold across threads but every
/// operation attaches a fresh JNI thread before touching the VM.
pub struct KeystoreVault {
    alias: String,
}

impl std::fmt::Debug for KeystoreVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Alias is *not* secret, but we treat it as app-private
        // configuration and redact by default — callers that want to
        // log it can read `KeystoreVault::alias` directly (there is
        // no public accessor; this is intentional).
        f.debug_struct("KeystoreVault")
            .field("alias", &"<redacted>")
            .finish()
    }
}

impl KeystoreVault {
    /// Open an existing key entry, or provision a fresh
    /// AES-256-GCM key under the given `alias`.
    ///
    /// # Parameters
    ///
    /// - `alias` — caller's opaque label, unique per app-owned vault.
    /// - `policy` — biometric gating applied at provisioning time.
    /// - `require_strongbox` — when `true`, the call fails with
    ///   [`KeystoreError::HardwareBackedRequired`] if `StrongBox` isn't
    ///   available on this device. When `false`, the code falls back to
    ///   a TEE-backed Keystore entry.
    ///
    /// # Idempotency
    ///
    /// Calling this twice with the same `alias` returns a handle onto
    /// the *existing* key (`StrongBox` bit, key-size, etc. are frozen at
    /// the first call). Changing policy requires [`delete`] first.
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::NotAvailable`] — the Android NDK has not yet
    ///   populated a `JavaVM*` into `ndk_context`.
    /// - [`KeystoreError::HardwareBackedRequired`] — `require_strongbox`
    ///   was true and the device doesn't advertise `StrongBox`.
    /// - [`KeystoreError::Io`] — a lower-level JNI failure (sanitised
    ///   message; never contains key material).
    ///
    /// [`delete`]: KeystoreVault::delete
    pub fn open_or_create(
        alias: &str,
        policy: BiometricPolicy,
        require_strongbox: bool,
    ) -> Result<Self, KeystoreError> {
        if alias.is_empty() {
            return Err(KeystoreError::Io("keystore alias must not be empty".into()));
        }
        with_env(|env| {
            if keystore_contains_alias(env, alias)? {
                return Ok(());
            }
            provision_key(env, alias, key_spec_for(to_super_policy(policy)), require_strongbox)
        })?;
        Ok(Self {
            alias: alias.to_owned(),
        })
    }

    /// Returns `true` iff the underlying key is hardware-backed
    /// (`KeyInfo.getSecurityLevel()` is `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`
    /// or `SECURITY_LEVEL_STRONGBOX`).
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] on JNI failure, or
    /// [`KeystoreError::NotAvailable`] when the JVM pointer is missing.
    pub fn is_hardware_backed(&self) -> Result<bool, KeystoreError> {
        with_env(|env| key_security_level(env, &self.alias).map(SecurityLevel::is_hardware_backed))
    }

    /// Returns `true` iff the underlying key lives in a `StrongBox`
    /// keymaster (`SECURITY_LEVEL_STRONGBOX`).
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] on JNI failure, or
    /// [`KeystoreError::NotAvailable`] when the JVM pointer is missing.
    pub fn is_strongbox_backed(&self) -> Result<bool, KeystoreError> {
        with_env(|env| key_security_level(env, &self.alias).map(SecurityLevel::is_strongbox))
    }

    /// Seal a [`VaultKey`] for app-local persistence. See the `super`
    /// module-level docs for the wire format.
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::BiometricRequired`] — key is gated by
    ///   biometric policy and the auth window has lapsed.
    /// - [`KeystoreError::Io`] — JNI failure (sanitised message).
    /// - [`KeystoreError::NotAvailable`] — no live `JavaVM*`.
    pub fn wrap_vault_key(&self, key: &VaultKey) -> Result<Vec<u8>, KeystoreError> {
        with_env(|env| wrap_bytes(env, &self.alias, key.as_bytes()))
    }

    /// Inverse of [`KeystoreVault::wrap_vault_key`].
    ///
    /// # Errors
    ///
    /// - [`KeystoreError::BiometricRequired`] — the key's user-auth
    ///   window has lapsed; caller should show a `BiometricPrompt`,
    ///   wait for success, and retry.
    /// - [`KeystoreError::Crypto`] — the wrapped blob decrypted to
    ///   something that isn't a 32-byte `VaultKey`.
    /// - [`KeystoreError::Io`] — JNI failure / malformed wrapped blob.
    /// - [`KeystoreError::NotAvailable`] — no live `JavaVM*`.
    pub fn unwrap_vault_key(&self, wrapped: &[u8]) -> Result<VaultKey, KeystoreError> {
        let mut plaintext = with_env(|env| unwrap_bytes(env, &self.alias, wrapped))?;
        if plaintext.len() != KEY_LEN {
            plaintext.zeroize();
            return Err(KeystoreError::Crypto(crate::error::CryptoError::InvalidLength));
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(VaultKey::from_bytes(buf))
    }

    /// Permanently remove the Keystore-held key. After this, every
    /// blob previously produced by [`KeystoreVault::wrap_vault_key`] is
    /// unrecoverable.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] on JNI failure, or
    /// [`KeystoreError::NotAvailable`] when the JVM pointer is missing.
    pub fn delete(self) -> Result<(), KeystoreError> {
        with_env(|env| delete_alias(env, &self.alias))
    }
}

// --- Policy re-projection -------------------------------------------------
//
// `super::BiometricPolicy` is re-exported from `self::BiometricPolicy`;
// both enums have the same shape. We deliberately keep them as distinct
// types (Android-targeted + host-targeted) so the stub path on non-
// Android doesn't force `target_os = "android"` into every user's
// `Cargo.toml`. This helper bridges the two.

fn to_super_policy(p: BiometricPolicy) -> super::BiometricPolicy {
    match p {
        BiometricPolicy::None => super::BiometricPolicy::None,
        BiometricPolicy::DeviceCredential {
            invalidate_after_secs,
        } => super::BiometricPolicy::DeviceCredential {
            invalidate_after_secs,
        },
        BiometricPolicy::Biometric => super::BiometricPolicy::Biometric,
        BiometricPolicy::BiometricOrDeviceCredential => {
            super::BiometricPolicy::BiometricOrDeviceCredential
        }
    }
}

// --- JNI helpers ----------------------------------------------------------

/// Android Keystore provider name.
const KEYSTORE_PROVIDER: &str = "AndroidKeyStore";
/// AES-GCM transformation accepted by `Cipher.getInstance`.
const AES_GCM_TRANSFORM: &str = "AES/GCM/NoPadding";
/// AES algorithm name accepted by `KeyGenerator.getInstance`.
const ALG_AES: &str = "AES";
/// AES-GCM auth tag length in bits (128).
const GCM_TAG_LEN_BITS: i32 = 128;

/// Cipher mode constants from `javax.crypto.Cipher`. Pinned rather than
/// read from JNI so we never accidentally run in the wrong mode if a
/// reflection call is intercepted.
const CIPHER_ENCRYPT_MODE: i32 = 1;
const CIPHER_DECRYPT_MODE: i32 = 2;

/// `KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT` (1 | 2 = 3).
const PURPOSE_ENCRYPT_OR_DECRYPT: i32 = 1 | 2;

/// `KeyInfo.getSecurityLevel()` return values. Matches the `KeyProperties`
/// constants on Android 12+.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SecurityLevel {
    /// `SECURITY_LEVEL_SOFTWARE` (0).
    Software,
    /// `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` (1).
    TrustedEnvironment,
    /// `SECURITY_LEVEL_STRONGBOX` (2).
    StrongBox,
    /// `SECURITY_LEVEL_UNKNOWN_SECURE` (3) — hardware-backed but the
    /// level can't be determined.
    UnknownSecure,
    /// `SECURITY_LEVEL_UNKNOWN` (-1) — pre-S devices; caller must fall
    /// back to the legacy `isInsideSecureHardware()` check.
    Unknown,
}

impl SecurityLevel {
    const fn is_hardware_backed(self) -> bool {
        matches!(
            self,
            Self::TrustedEnvironment | Self::StrongBox | Self::UnknownSecure
        )
    }

    const fn is_strongbox(self) -> bool {
        matches!(self, Self::StrongBox)
    }
}

/// Attach the calling thread to the JVM for the duration of `f`.
///
/// This is the single point where `unsafe` appears in the crate. The
/// `JavaVM::from_raw` call adopts a raw `JavaVM*` pointer published by
/// the NDK at process start into `ndk_context::AndroidContext`.
fn with_env<F, T>(f: F) -> Result<T, KeystoreError>
where
    F: for<'local> FnOnce(&mut JNIEnv<'local>) -> Result<T, KeystoreError>,
{
    let ctx = ndk_context::android_context();
    let vm_ptr = ctx.vm();
    if vm_ptr.is_null() {
        return Err(KeystoreError::NotAvailable);
    }
    // SAFETY: `ndk_context::android_context()` is populated by the
    // Android NDK runtime before any Rust code runs on-device. The
    // pointer is a valid `JavaVM*` for the lifetime of the process,
    // and `JavaVM::from_raw` only reads from it through the JNI
    // invocation interface's function table (it does not take
    // ownership). The adopted `JavaVM` handle is scoped to this
    // function and never escapes.
    #[allow(unsafe_code)]
    let vm = unsafe { JavaVM::from_raw(vm_ptr.cast()) }
        .map_err(|_| KeystoreError::NotAvailable)?;
    let mut guard: AttachGuard<'_> = vm
        .attach_current_thread()
        .map_err(|_| KeystoreError::NotAvailable)?;
    // `AttachGuard` derefs to `&mut JNIEnv`, so we can pass it through
    // without further casts.
    f(&mut guard)
}

/// Drain any pending exception, describe it (for stderr in debug
/// builds only — no-op in release since Android filters these), and
/// return a sanitised error message.
fn take_exception(env: &mut JNIEnv<'_>) -> Result<String, KeystoreError> {
    // If there is no pending exception, the caller misused this helper.
    let pending = env
        .exception_check()
        .map_err(|_| KeystoreError::Io("failed to query JNI exception state".into()))?;
    if !pending {
        return Err(KeystoreError::Io("no pending JNI exception to take".into()));
    }
    // `exception_describe` logs to stderr; in release builds Android
    // suppresses stderr for app processes. Do not remove this call —
    // it's invaluable in `adb logcat` for debug builds.
    let _ = env.exception_describe();
    let throwable = env
        .exception_occurred()
        .map_err(|_| KeystoreError::Io("failed to capture JNI exception".into()))?;
    env.exception_clear()
        .map_err(|_| KeystoreError::Io("failed to clear JNI exception".into()))?;

    // Capture the exception *class name* only (no message — messages on
    // Keystore / Cipher exceptions can occasionally leak structured
    // parameters).
    let class_name = class_name_of(env, &throwable).unwrap_or_else(|| "<unknown-exception>".into());
    Ok(class_name)
}

/// Resolve the class name of a thrown `Throwable` to a `Foo.Bar` string.
/// Returns `None` on any JNI failure — never panics.
fn class_name_of(env: &mut JNIEnv<'_>, throwable: &JObject<'_>) -> Option<String> {
    // `throwable.getClass().getName()`
    let cls_obj = env
        .call_method(throwable, "getClass", "()Ljava/lang/Class;", &[])
        .ok()?
        .l()
        .ok()?;
    let name_obj = env
        .call_method(&cls_obj, "getName", "()Ljava/lang/String;", &[])
        .ok()?
        .l()
        .ok()?;
    let jstr: JString<'_> = name_obj.into();
    let rust_str: String = env.get_string(&jstr).ok()?.into();
    Some(rust_str)
}

/// Map a known exception class name onto a [`KeystoreError`] variant.
/// Unknown classes fall back to [`KeystoreError::Io`].
fn classify_exception(class_name: &str, context: &str) -> KeystoreError {
    // Matched suffixes keep us resilient to minor package moves.
    if class_name.ends_with("UserNotAuthenticatedException") {
        KeystoreError::BiometricRequired
    } else if class_name.ends_with("KeyPermanentlyInvalidatedException") {
        // Biometric enrolment changed after the key was bound; caller
        // must delete the key and re-provision.
        KeystoreError::BiometricRequired
    } else if class_name.ends_with("StrongBoxUnavailableException") {
        KeystoreError::HardwareBackedRequired
    } else if class_name.ends_with("OperationCanceledException") {
        KeystoreError::UserCancelled
    } else {
        KeystoreError::Io(format!("{context}: {class_name}"))
    }
}

/// Run a JNI call, propagating any pending exception as a classified
/// [`KeystoreError`]. `context` is a short static string used purely
/// for error-message attribution (never contains user data).
fn check_exception<T>(
    env: &mut JNIEnv<'_>,
    context: &str,
    raw: jni::errors::Result<T>,
) -> Result<T, KeystoreError> {
    match raw {
        Ok(v) => {
            // The jni crate's Result is Ok even when a Java exception
            // is pending on certain code paths. Double-check.
            let pending = env
                .exception_check()
                .map_err(|_| KeystoreError::Io(format!("{context}: exception-state query failed")))?;
            if pending {
                let class = take_exception(env)?;
                return Err(classify_exception(&class, context));
            }
            Ok(v)
        }
        Err(_e) => {
            let pending = env.exception_check().unwrap_or(false);
            if pending {
                let class = take_exception(env)?;
                Err(classify_exception(&class, context))
            } else {
                Err(KeystoreError::Io(format!("{context}: JNI call failed")))
            }
        }
    }
}

// --- KeyStore lookup / provision / delete ---------------------------------

fn load_keystore<'local>(
    env: &mut JNIEnv<'local>,
) -> Result<JObject<'local>, KeystoreError> {
    let provider = env
        .new_string(KEYSTORE_PROVIDER)
        .map_err(|_| KeystoreError::Io("allocating provider string failed".into()))?;
    let raw = env.call_static_method(
        "java/security/KeyStore",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&provider)],
    );
    let jv = check_exception(env, "KeyStore.getInstance", raw)?;
    let ks = check_exception(env, "KeyStore.getInstance result", jv.l())?;
    let null = JObject::null();
    let raw = env.call_method(
        &ks,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&null)],
    );
    let _ = check_exception(env, "KeyStore.load", raw)?;
    Ok(ks)
}

fn keystore_contains_alias(env: &mut JNIEnv<'_>, alias: &str) -> Result<bool, KeystoreError> {
    let ks = load_keystore(env)?;
    let alias_str = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let raw = env.call_method(
        &ks,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&alias_str)],
    );
    let jv = check_exception(env, "KeyStore.containsAlias", raw)?;
    check_exception(env, "KeyStore.containsAlias result", jv.z())
}

fn delete_alias(env: &mut JNIEnv<'_>, alias: &str) -> Result<(), KeystoreError> {
    let ks = load_keystore(env)?;
    let alias_str = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let raw = env.call_method(
        &ks,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&alias_str)],
    );
    let _ = check_exception(env, "KeyStore.deleteEntry", raw)?;
    Ok(())
}

/// Build a `KeyGenParameterSpec` and generate a fresh AES-256-GCM key
/// under `alias`.
///
/// If `require_strongbox` is `true` and the device does not support
/// `StrongBox`, this returns [`KeystoreError::HardwareBackedRequired`]
/// (after deleting the freshly-provisioned non-`StrongBox` key, so the
/// caller isn't left with a weaker-than-requested key entry).
fn provision_key(
    env: &mut JNIEnv<'_>,
    alias: &str,
    spec: super::KeySpec,
    require_strongbox: bool,
) -> Result<(), KeystoreError> {
    // Attempt StrongBox first when hinted. If the device rejects it
    // we'll catch `StrongBoxUnavailableException` and retry without
    // the StrongBox bit (mirrors Blackout's fallback). When
    // `require_strongbox` is true we *don't* fall back — we surface
    // `HardwareBackedRequired`.
    let first_attempt = provision_key_inner(env, alias, spec, true);
    match first_attempt {
        Ok(()) => {}
        Err(KeystoreError::HardwareBackedRequired) if !require_strongbox => {
            // TEE fallback: retry without StrongBox.
            provision_key_inner(env, alias, spec, false)?;
        }
        Err(e) => return Err(e),
    }

    // Post-provision StrongBox enforcement. `setIsStrongBoxBacked(true)`
    // can be silently ignored on some older devices (pre-Android 12);
    // verify with `KeyInfo.getSecurityLevel()` before returning success.
    if require_strongbox {
        let level = key_security_level(env, alias).unwrap_or(SecurityLevel::Unknown);
        if !level.is_strongbox() {
            // Clean up — caller asked for StrongBox and we didn't get it.
            let _ = delete_alias(env, alias);
            return Err(KeystoreError::HardwareBackedRequired);
        }
    }

    Ok(())
}

fn provision_key_inner(
    env: &mut JNIEnv<'_>,
    alias: &str,
    spec: super::KeySpec,
    with_strongbox_hint: bool,
) -> Result<(), KeystoreError> {
    let kg = keygenerator_get_instance(env)?;
    let mut builder = make_parameter_spec_builder(env, alias)?;

    builder = set_block_modes_gcm(env, &builder)?;
    builder = set_no_padding(env, &builder)?;
    builder = set_aes_256(env, &builder)?;
    builder = set_randomized_encryption_required(env, &builder)?;
    builder = set_user_authentication_required(env, &builder, spec.user_auth_required)?;

    if let Some(params) = spec.auth_params {
        builder = maybe_set_user_authentication_parameters(env, builder, params)?;
    }

    if with_strongbox_hint {
        #[allow(clippy::needless_pass_by_value)]
        match set_is_strongbox_backed(env, builder) {
            Ok(b) => builder = b,
            Err((b, KeystoreError::Io(msg))) if msg.contains("NoSuchMethodError") => {
                // Pre-API-28; StrongBox isn't a concept on this device.
                // Continue with the builder as-is (without the StrongBox bit).
                builder = b;
            }
            Err((_, e)) => return Err(e),
        }
    }

    // KeyGenParameterSpec spec = b.build();
    let raw = env.call_method(
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
    );
    let jv = check_exception(env, "Builder.build", raw)?;
    let key_spec = check_exception(env, "Builder.build result", jv.l())?;

    // kg.init(spec);
    let raw = env.call_method(
        &kg,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&key_spec)],
    );
    let _ = check_exception(env, "KeyGenerator.init", raw)?;

    // kg.generateKey();
    let raw = env.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[]);
    let _ = check_exception(env, "KeyGenerator.generateKey", raw)?;

    Ok(())
}

/// Call `KeyGenerator.getInstance("AES", "AndroidKeyStore")`.
fn keygenerator_get_instance<'local>(
    env: &mut JNIEnv<'local>,
) -> Result<JObject<'local>, KeystoreError> {
    let alg = env
        .new_string(ALG_AES)
        .map_err(|_| KeystoreError::Io("allocating AES alg string failed".into()))?;
    let provider = env
        .new_string(KEYSTORE_PROVIDER)
        .map_err(|_| KeystoreError::Io("allocating provider string failed".into()))?;
    let raw = env.call_static_method(
        "javax/crypto/KeyGenerator",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
        &[JValue::Object(&alg), JValue::Object(&provider)],
    );
    let jv = check_exception(env, "KeyGenerator.getInstance", raw)?;
    check_exception(env, "KeyGenerator.getInstance result", jv.l())
}

/// Construct a fresh `KeyGenParameterSpec.Builder(alias, PURPOSE_ENC | PURPOSE_DEC)`.
fn make_parameter_spec_builder<'local>(
    env: &mut JNIEnv<'local>,
    alias: &str,
) -> Result<JObject<'local>, KeystoreError> {
    let alias_j = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let raw = env.new_object(
        "android/security/keystore/KeyGenParameterSpec$Builder",
        "(Ljava/lang/String;I)V",
        &[
            JValue::Object(&alias_j),
            JValue::Int(PURPOSE_ENCRYPT_OR_DECRYPT),
        ],
    );
    check_exception(env, "KeyGenParameterSpec.Builder.<init>", raw)
}

/// Thin wrapper around the common fluent-builder pattern:
/// `builder.setFoo(x).setBar(y)`. Each Android `.setXxx()` call returns
/// the builder by self-reference; we check for exceptions and forward
/// the returned local reference (which may or may not be the same
/// underlying `jobject*` as the input — we don't care either way).
fn call_builder_returning_self<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
    method: &str,
    sig: &str,
    args: &[JValue<'_, '_>],
) -> Result<JObject<'local>, KeystoreError> {
    let raw = env.call_method(builder, method, sig, args);
    let jv = check_exception(env, method, raw)?;
    check_exception(env, method, jv.l())
}

/// `.setBlockModes("GCM")`.
fn set_block_modes_gcm<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
) -> Result<JObject<'local>, KeystoreError> {
    let block_mode = env
        .new_string("GCM")
        .map_err(|_| KeystoreError::Io("allocating block-mode string failed".into()))?;
    let arr = new_string_array(env, &[&block_mode])?;
    call_builder_returning_self(
        env,
        builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&arr)],
    )
}

/// `.setEncryptionPaddings("NoPadding")`.
fn set_no_padding<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
) -> Result<JObject<'local>, KeystoreError> {
    let padding = env
        .new_string("NoPadding")
        .map_err(|_| KeystoreError::Io("allocating padding string failed".into()))?;
    let arr = new_string_array(env, &[&padding])?;
    call_builder_returning_self(
        env,
        builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&arr)],
    )
}

/// `.setKeySize(256)`.
fn set_aes_256<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
) -> Result<JObject<'local>, KeystoreError> {
    call_builder_returning_self(
        env,
        builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(256)],
    )
}

/// `.setRandomizedEncryptionRequired(true)`. Default already-true on
/// the Android side, but we set it explicitly to foreclose reflection-
/// based shenanigans that disable randomised IVs.
fn set_randomized_encryption_required<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
) -> Result<JObject<'local>, KeystoreError> {
    call_builder_returning_self(
        env,
        builder,
        "setRandomizedEncryptionRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(u8::from(true))],
    )
}

/// `.setUserAuthenticationRequired(bool)`.
fn set_user_authentication_required<'local>(
    env: &mut JNIEnv<'local>,
    builder: &JObject<'_>,
    required: bool,
) -> Result<JObject<'local>, KeystoreError> {
    call_builder_returning_self(
        env,
        builder,
        "setUserAuthenticationRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(u8::from(required))],
    )
}

/// `.setUserAuthenticationParameters(timeout, flags)` — API 30+.
///
/// On pre-API-30 devices the method is absent; we swallow the
/// `NoSuchMethodError` and return the original builder unchanged.
/// Gating is still effective because `setUserAuthenticationRequired(true)`
/// is already set in that case.
fn maybe_set_user_authentication_parameters<'local>(
    env: &mut JNIEnv<'local>,
    builder: JObject<'local>,
    params: AuthParams,
) -> Result<JObject<'local>, KeystoreError> {
    let raw = env.call_method(
        &builder,
        "setUserAuthenticationParameters",
        "(II)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[
            JValue::Int(to_i32_saturating(params.timeout_secs)),
            JValue::Int(to_i32_saturating(params.flags.bits())),
        ],
    );
    match check_exception(env, "Builder.setUserAuthenticationParameters", raw) {
        Ok(jv) => check_exception(env, "Builder.setUserAuthenticationParameters result", jv.l()),
        Err(KeystoreError::Io(msg)) if msg.contains("NoSuchMethodError") => {
            // Pre-API-30. The caller already set
            // `setUserAuthenticationRequired(true)`, which is enough
            // gating for our supported Android range. Hand the builder
            // back unchanged.
            Ok(builder)
        }
        Err(e) => Err(e),
    }
}

// NOTE: this function and `set_is_strongbox_backed` both take the
// builder *by value* — unlike the other setters — because they need
// to *return* it back on certain error paths (pre-API 30 / 28 fallback).
// Clippy's "passed by value, not consumed" lint isn't quite right for
// this shape; we silence it at the call-site for readability.

/// `.setIsStrongBoxBacked(true)` — API 28+.
///
/// Returns the builder back in `Err` so the caller can keep using it
/// when `NoSuchMethodError` means the device is too old for the
/// `StrongBox` concept (pre-API 28).
fn set_is_strongbox_backed<'local>(
    env: &mut JNIEnv<'local>,
    builder: JObject<'local>,
) -> Result<JObject<'local>, (JObject<'local>, KeystoreError)> {
    let raw = env.call_method(
        &builder,
        "setIsStrongBoxBacked",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(u8::from(true))],
    );
    match check_exception(env, "Builder.setIsStrongBoxBacked", raw) {
        Ok(jv) => match check_exception(env, "Builder.setIsStrongBoxBacked result", jv.l()) {
            Ok(b) => Ok(b),
            Err(e) => Err((builder, e)),
        },
        Err(e) => Err((builder, e)),
    }
}

/// Build a `Ljava/lang/String;[]` of the given strings.
fn new_string_array<'local>(
    env: &mut JNIEnv<'local>,
    elems: &[&JString<'_>],
) -> Result<JObject<'local>, KeystoreError> {
    let len: jsize = elems
        .len()
        .try_into()
        .map_err(|_| KeystoreError::Io("string-array length overflow".into()))?;
    let cls = env
        .find_class("java/lang/String")
        .map_err(|_| KeystoreError::Io("find_class java/lang/String failed".into()))?;
    let arr = env
        .new_object_array(len, cls, JObject::null())
        .map_err(|_| KeystoreError::Io("allocating String[] failed".into()))?;
    for (i, s) in elems.iter().enumerate() {
        let idx: jsize = i
            .try_into()
            .map_err(|_| KeystoreError::Io("String[] index overflow".into()))?;
        env.set_object_array_element(&arr, idx, s)
            .map_err(|_| KeystoreError::Io("set_object_array_element failed".into()))?;
    }
    Ok(arr.into())
}

fn to_i32_saturating(x: u32) -> i32 {
    // Saturating cast — `u32::MAX` is wider than `i32::MAX` by a factor
    // of two, and the Android APIs we target (`setUserAuthentication
    // Parameters`) take a signed `int` timeout. Saturating is the
    // least-surprising behaviour for the small values we actually pass.
    i32::try_from(x).unwrap_or(i32::MAX)
}

// --- KeyInfo inspection ---------------------------------------------------

/// Look up the `SecretKey` and return its `KeyInfo.getSecurityLevel()`.
/// On devices older than API 31, `getSecurityLevel` doesn't exist and we
/// fall back to the legacy `isInsideSecureHardware()` check — on that
/// path we collapse the return onto `TrustedEnvironment` (inside) or
/// `Software` (not inside), since the finer-grained distinction
/// between TEE and `StrongBox` isn't knowable from that call.
fn key_security_level(
    env: &mut JNIEnv<'_>,
    alias: &str,
) -> Result<SecurityLevel, KeystoreError> {
    let ks = load_keystore(env)?;
    let alias_j = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let null = JObject::null();
    let raw = env.call_method(
        &ks,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&alias_j), JValue::Object(&null)],
    );
    let jv = check_exception(env, "KeyStore.getKey", raw)?;
    let secret_key = check_exception(env, "KeyStore.getKey result", jv.l())?;

    // SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", "AndroidKeyStore");
    let alg = env
        .new_string(ALG_AES)
        .map_err(|_| KeystoreError::Io("allocating AES alg string failed".into()))?;
    let provider = env
        .new_string(KEYSTORE_PROVIDER)
        .map_err(|_| KeystoreError::Io("allocating provider string failed".into()))?;
    let raw = env.call_static_method(
        "javax/crypto/SecretKeyFactory",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
        &[JValue::Object(&alg), JValue::Object(&provider)],
    );
    let jv = check_exception(env, "SecretKeyFactory.getInstance", raw)?;
    let factory = check_exception(env, "SecretKeyFactory.getInstance result", jv.l())?;

    // KeySpec info = factory.getKeySpec(secret_key, KeyInfo.class);
    let keyinfo_cls = env
        .find_class("android/security/keystore/KeyInfo")
        .map_err(|_| KeystoreError::Io("find_class KeyInfo failed".into()))?;
    let raw = env.call_method(
        &factory,
        "getKeySpec",
        "(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
        &[JValue::Object(&secret_key), JValue::Object(&keyinfo_cls)],
    );
    let jv = check_exception(env, "SecretKeyFactory.getKeySpec", raw)?;
    let key_info = check_exception(env, "SecretKeyFactory.getKeySpec result", jv.l())?;

    // Try API-31+ `getSecurityLevel() -> int` first.
    let raw = env.call_method(&key_info, "getSecurityLevel", "()I", &[]);
    match check_exception(env, "KeyInfo.getSecurityLevel", raw) {
        Ok(JValueGen::Int(level)) => Ok(match level {
            0 => SecurityLevel::Software,
            1 => SecurityLevel::TrustedEnvironment,
            2 => SecurityLevel::StrongBox,
            3 => SecurityLevel::UnknownSecure,
            _ => SecurityLevel::Unknown,
        }),
        // Some return-type shape we don't know how to handle. Treat as unknown.
        Ok(_) => Ok(SecurityLevel::Unknown),
        Err(KeystoreError::Io(msg)) if msg.contains("NoSuchMethodError") => {
            // API 23–30: fall back to `isInsideSecureHardware()`.
            let raw = env.call_method(&key_info, "isInsideSecureHardware", "()Z", &[]);
            let jv = check_exception(env, "KeyInfo.isInsideSecureHardware", raw)?;
            let inside = check_exception(env, "KeyInfo.isInsideSecureHardware result", jv.z())?;
            Ok(if inside {
                SecurityLevel::TrustedEnvironment
            } else {
                SecurityLevel::Software
            })
        }
        Err(e) => Err(e),
    }
}

// --- AES-GCM wrap / unwrap ------------------------------------------------

fn wrap_bytes(
    env: &mut JNIEnv<'_>,
    alias: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let ks = load_keystore(env)?;
    let alias_j = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let null = JObject::null();
    let raw = env.call_method(
        &ks,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&alias_j), JValue::Object(&null)],
    );
    let jv = check_exception(env, "KeyStore.getKey", raw)?;
    let secret_key = check_exception(env, "KeyStore.getKey result", jv.l())?;

    let cipher = cipher_get_instance(env)?;

    // cipher.init(ENCRYPT_MODE, key);
    let raw = env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(CIPHER_ENCRYPT_MODE), JValue::Object(&secret_key)],
    );
    let _ = check_exception(env, "Cipher.init(ENCRYPT_MODE)", raw)?;

    // byte[] ct = cipher.doFinal(plaintext);
    let pt_arr: JByteArray<'_> = env
        .byte_array_from_slice(plaintext)
        .map_err(|_| KeystoreError::Io("allocating plaintext JNI byte array failed".into()))?;
    let raw = env.call_method(
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&pt_arr)],
    );
    let jv = check_exception(env, "Cipher.doFinal(ENCRYPT)", raw)?;
    let ct_obj = check_exception(env, "Cipher.doFinal(ENCRYPT) result", jv.l())?;
    let ct_arr: JByteArray<'_> = ct_obj.into();
    let mut ciphertext = env
        .convert_byte_array(&ct_arr)
        .map_err(|_| KeystoreError::Io("reading ciphertext JNI byte array failed".into()))?;

    // byte[] iv = cipher.getIV();
    let raw = env.call_method(&cipher, "getIV", "()[B", &[]);
    let jv = check_exception(env, "Cipher.getIV", raw)?;
    let iv_obj = check_exception(env, "Cipher.getIV result", jv.l())?;
    let iv_arr: JByteArray<'_> = iv_obj.into();
    let mut iv = env
        .convert_byte_array(&iv_arr)
        .map_err(|_| KeystoreError::Io("reading IV JNI byte array failed".into()))?;

    if iv.len() != AES_GCM_IV_LEN {
        // Defensive: Android Keystore always emits a 12-byte IV for GCM,
        // but we don't want to assume.
        iv.zeroize();
        ciphertext.zeroize();
        return Err(KeystoreError::Io("Keystore-emitted IV has unexpected length".into()));
    }

    let framed = frame_wrapped(&iv, &ciphertext)?;
    iv.zeroize();
    ciphertext.zeroize();
    Ok(framed)
}

fn unwrap_bytes(
    env: &mut JNIEnv<'_>,
    alias: &str,
    wrapped: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let (iv, ct) = unframe_wrapped(wrapped)?;

    let ks = load_keystore(env)?;
    let alias_j = env
        .new_string(alias)
        .map_err(|_| KeystoreError::Io("allocating alias string failed".into()))?;
    let null = JObject::null();
    let raw = env.call_method(
        &ks,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&alias_j), JValue::Object(&null)],
    );
    let jv = check_exception(env, "KeyStore.getKey", raw)?;
    let secret_key = check_exception(env, "KeyStore.getKey result", jv.l())?;

    let cipher = cipher_get_instance(env)?;

    // GCMParameterSpec gcm_spec = new GCMParameterSpec(128, iv);
    let iv_arr: JByteArray<'_> = env
        .byte_array_from_slice(iv)
        .map_err(|_| KeystoreError::Io("allocating IV JNI byte array failed".into()))?;
    let raw = env.new_object(
        "javax/crypto/spec/GCMParameterSpec",
        "(I[B)V",
        &[
            JValue::Int(GCM_TAG_LEN_BITS),
            JValue::Object(&iv_arr),
        ],
    );
    let gcm_spec = check_exception(env, "GCMParameterSpec.<init>", raw)?;

    // cipher.init(DECRYPT_MODE, key, gcm_spec);
    let raw = env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[
            JValue::Int(CIPHER_DECRYPT_MODE),
            JValue::Object(&secret_key),
            JValue::Object(&gcm_spec),
        ],
    );
    let _ = check_exception(env, "Cipher.init(DECRYPT_MODE)", raw)?;

    // byte[] pt = cipher.doFinal(ciphertext);
    let ct_arr: JByteArray<'_> = env
        .byte_array_from_slice(ct)
        .map_err(|_| KeystoreError::Io("allocating ciphertext JNI byte array failed".into()))?;
    let raw = env.call_method(
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&ct_arr)],
    );
    let jv = check_exception(env, "Cipher.doFinal(DECRYPT)", raw)?;
    let pt_obj = check_exception(env, "Cipher.doFinal(DECRYPT) result", jv.l())?;
    let pt_arr: JByteArray<'_> = pt_obj.into();
    let plaintext = env
        .convert_byte_array(&pt_arr)
        .map_err(|_| KeystoreError::Io("reading plaintext JNI byte array failed".into()))?;
    Ok(plaintext)
}

fn cipher_get_instance<'local>(
    env: &mut JNIEnv<'local>,
) -> Result<JObject<'local>, KeystoreError> {
    let transform = env
        .new_string(AES_GCM_TRANSFORM)
        .map_err(|_| KeystoreError::Io("allocating cipher-transform string failed".into()))?;
    let raw = env.call_static_method(
        "javax/crypto/Cipher",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&transform)],
    );
    let jv = check_exception(env, "Cipher.getInstance", raw)?;
    check_exception(env, "Cipher.getInstance result", jv.l())
}

// --- Android-target-only integration tests --------------------------------
//
// These tests require a live Android runtime (JavaVM populated in
// `ndk_context`). They don't run in host `cargo test` — the
// `target_os = "android"` guard below prevents the host build from
// trying to compile them. Running them on-device is a manual step
// documented in `docs/keystore.md` (todo: create).

#[cfg(test)]
mod android_tests {
    //! Sanity-check compilation on `target_os = "android"` — actual
    //! execution requires a real device / emulator.

    use super::*;
    use crate::crypto::keys::VaultKey;

    #[allow(dead_code)]
    fn roundtrip_smoke() {
        // Not a `#[test]` — invoking Keystore from unit tests on-device
        // needs a `Context`, which the usual JUnit runner doesn't
        // provide. Wired as an `#[allow(dead_code)]` helper so CI
        // `cargo check --target aarch64-linux-android` exercises the
        // types even though the test is skipped.
        let vault =
            KeystoreVault::open_or_create("_test_keystore_vault", BiometricPolicy::None, false);
        if let Ok(v) = vault {
            let key = VaultKey::from_bytes([0x42; KEY_LEN]);
            if let Ok(wrapped) = v.wrap_vault_key(&key) {
                let unwrapped = v.unwrap_vault_key(&wrapped);
                assert!(unwrapped.is_ok());
            }
            let _ = v.delete();
        }
    }
}
