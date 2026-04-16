//! Tauri command handlers wrapping `PrivacySuite` Core SDK.
//!
//! Each function here is intended to be registered as a `#[tauri::command]`.
//! When building inside a Tauri project, uncomment the `tauri` dependency
//! in `Cargo.toml` and add the `#[tauri::command]` attributes.
//!
//! All commands accept and return serializable types from [`super::models`].
//! Secret material (keys, mnemonics) is never sent over IPC — only opaque
//! handles or encrypted blobs cross the bridge.

use privacysuite_core_sdk::crypto::{aead, kdf, keys, mnemonic};
use privacysuite_core_sdk::error::CryptoError;

use crate::models::{EncryptedBlob, KeyHandle, MnemonicPhrase};

/// SECURITY: Minimum passphrase length enforced at the IPC boundary.
///
/// A zero-length or trivially short passphrase offers no cryptographic value
/// regardless of how strong Argon2id is. This guards against frontend bugs
/// that might accidentally invoke vault creation with an empty string.
const MIN_PASSPHRASE_BYTES: usize = 1;

/// Generate a new vault: salt + mnemonic.
///
/// The passphrase-derived key never leaves Rust. The frontend receives only
/// an opaque salt handle and the mnemonic words (for one-time display).
///
/// # Errors
///
/// Returns a serialised error string if input validation, key derivation, or
/// mnemonic generation fails.
pub fn vault_create(passphrase: &str) -> Result<(KeyHandle, MnemonicPhrase), String> {
    // SECURITY: Validate at the IPC boundary — never rely on the JS caller.
    if passphrase.as_bytes().len() < MIN_PASSPHRASE_BYTES {
        return Err("passphrase must not be empty".to_string());
    }

    let salt = keys::Salt::generate().map_err(|e| e.to_string())?;
    // Derive once to surface Argon2id errors early; the resulting key is
    // dropped immediately and its memory is scrubbed by ZeroizeOnDrop.
    let _key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let mnem = mnemonic::Mnemonic::generate().map_err(|e| e.to_string())?;
    let words = mnem.to_phrase();

    let handle = KeyHandle {
        salt: salt.as_bytes().to_vec(),
    };
    let phrase = MnemonicPhrase { words };

    Ok((handle, phrase))
}

/// Encrypt a plaintext blob using a passphrase-derived key, optionally
/// routed through a hardcoded sub-key derivation context.
///
/// When `subkey_context` is non-empty, the master key is derived from the
/// passphrase, then a purpose-specific sub-key is derived via BLAKE3 with
/// that context, and the plaintext is encrypted under the sub-key. This
/// lets a frontend perform purpose-separated encryption without ever
/// exposing raw key material over IPC.
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// encryption fails.
pub fn encrypt_blob(
    passphrase: &str,
    salt: &[u8],
    plaintext: &[u8],
    context: &str,
) -> Result<EncryptedBlob, String> {
    if passphrase.as_bytes().len() < MIN_PASSPHRASE_BYTES {
        return Err("passphrase must not be empty".to_string());
    }
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let ciphertext =
        aead::encrypt(&key, plaintext, context.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptedBlob { ciphertext })
}

/// Decrypt an encrypted blob.
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// decryption fails. All decryption failures produce the same error to
/// prevent oracle attacks.
pub fn decrypt_blob(
    passphrase: &str,
    salt: &[u8],
    blob: &EncryptedBlob,
    context: &str,
) -> Result<Vec<u8>, String> {
    if passphrase.as_bytes().len() < MIN_PASSPHRASE_BYTES {
        return Err("passphrase must not be empty".to_string());
    }
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    aead::decrypt(&key, &blob.ciphertext, context.as_bytes()).map_err(|e| e.to_string())
}

/// Encrypt a plaintext blob using a **purpose-specific sub-key** derived
/// from the passphrase-derived master and the caller-provided `subkey_context`.
///
/// This is the zero-knowledge-safe replacement for returning sub-key bytes
/// over IPC: raw key material stays inside Rust, and the frontend only sees
/// an opaque ciphertext.
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// encryption fails.
pub fn encrypt_blob_with_subkey(
    passphrase: &str,
    salt: &[u8],
    subkey_context: &str,
    plaintext: &[u8],
    aad: &str,
) -> Result<EncryptedBlob, String> {
    if passphrase.as_bytes().len() < MIN_PASSPHRASE_BYTES {
        return Err("passphrase must not be empty".to_string());
    }
    if subkey_context.is_empty() {
        return Err("subkey_context must not be empty".to_string());
    }
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let master = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let subkey = kdf::derive_subkey(&master, subkey_context).map_err(|e| e.to_string())?;
    let ciphertext =
        aead::encrypt(&subkey, plaintext, aad.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptedBlob { ciphertext })
}

/// Decrypt a blob produced by [`encrypt_blob_with_subkey`].
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// decryption fails.
pub fn decrypt_blob_with_subkey(
    passphrase: &str,
    salt: &[u8],
    subkey_context: &str,
    blob: &EncryptedBlob,
    aad: &str,
) -> Result<Vec<u8>, String> {
    if passphrase.as_bytes().len() < MIN_PASSPHRASE_BYTES {
        return Err("passphrase must not be empty".to_string());
    }
    if subkey_context.is_empty() {
        return Err("subkey_context must not be empty".to_string());
    }
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let master = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let subkey = kdf::derive_subkey(&master, subkey_context).map_err(|e| e.to_string())?;
    aead::decrypt(&subkey, &blob.ciphertext, aad.as_bytes()).map_err(|e| e.to_string())
}

/// Verify a mnemonic phrase is valid BIP39.
///
/// # Errors
///
/// Returns an error string if the phrase is invalid.
pub fn verify_mnemonic(phrase: &str) -> Result<(), String> {
    let _m = mnemonic::Mnemonic::from_phrase(phrase).map_err(|e: CryptoError| e.to_string())?;
    Ok(())
}

// SECURITY: The former `derive_subkey` IPC command has been removed.
//
// It returned raw BLAKE3-derived sub-key bytes inside an `EncryptedBlob`
// (which, despite the name, carried *plaintext* key material). Exporting
// raw key bytes to the JavaScript frontend:
//   1. Copies the key into JS heap memory that Rust cannot zeroize.
//   2. May flow through Tauri's IPC logging or devtools.
//   3. Makes a frontend XSS or supply-chain compromise equivalent to full
//      vault compromise.
//
// Use [`encrypt_blob_with_subkey`] / [`decrypt_blob_with_subkey`] instead:
// the sub-key is derived *and consumed* inside Rust for each operation,
// so raw key bytes never cross the IPC boundary.
