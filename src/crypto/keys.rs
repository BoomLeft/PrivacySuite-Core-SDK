//! Key types and Argon2id key derivation.
//!
//! All key material in this module implements [`Zeroize`] and [`ZeroizeOnDrop`]
//! to ensure secrets are scrubbed from memory when no longer needed.
//!
//! # Argon2id Parameters
//!
//! | Parameter   | Value | Rationale                          |
//! |-------------|-------|------------------------------------|
//! | Memory      | 64 MB | OWASP minimum for interactive login |
//! | Time        | 3     | Balances security vs. mobile UX    |
//! | Parallelism | 4     | Matches typical mobile core count  |
//! | Output      | 32 B  | 256-bit key for XChaCha20-Poly1305 |

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Argon2id memory cost in KiB (64 MB = 65536 KiB).
const ARGON2_M_COST_KIB: u32 = 64 * 1024;

/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 3;

/// Argon2id parallelism degree.
const ARGON2_P_COST: u32 = 4;

/// Derived key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Salt length in bytes (256 bits).
pub const SALT_LEN: usize = 32;

/// A 256-bit key derived from a user's passphrase via Argon2id.
///
/// The inner bytes are zeroized when this value is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey {
    bytes: [u8; KEY_LEN],
}

impl VaultKey {
    /// Returns a reference to the raw key bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Creates a `VaultKey` from a 32-byte array.
    ///
    /// The caller is responsible for ensuring the source bytes are
    /// cryptographically derived (e.g., from Argon2id or BIP39 seed).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(***)")
    }
}

/// A 256-bit random salt for Argon2id key derivation.
///
/// Does not implement `Clone` or `Copy` to prevent accidental duplication
/// that would leave unzeroized copies in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salt {
    bytes: [u8; SALT_LEN],
}

impl Salt {
    /// Generates a new cryptographically random salt.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; SALT_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CryptoError::Rng)?;
        Ok(Self { bytes })
    }

    /// Creates a `Salt` from an existing 32-byte array.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates a `Salt` from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] if the slice is not [`SALT_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SALT_LEN] =
            slice.try_into().map_err(|_| CryptoError::InvalidLength {
                context: "salt",
                expected: SALT_LEN,
                actual: slice.len(),
            })?;
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw salt bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salt(***)")
    }
}

/// Derives a [`VaultKey`] from a passphrase and salt using Argon2id.
///
/// Parameters: m=64 MB, t=3, p=4 (hardcoded — prevents downgrade attacks).
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if the passphrase is empty or
/// Argon2id fails internally.
///
/// # Example
///
/// ```
/// use privacysuite_core_sdk::crypto::keys::{Salt, derive_key};
///
/// let salt = Salt::generate().unwrap();
/// let key = derive_key(b"correct horse battery staple", &salt).unwrap();
/// assert_eq!(key.as_bytes().len(), 32);
/// ```
pub fn derive_key(passphrase: &[u8], salt: &Salt) -> Result<VaultKey, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::KeyDerivation);
    }

    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivation)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_LEN];
    if argon2
        .hash_password_into(passphrase, salt.as_bytes(), &mut key_bytes)
        .is_err()
    {
        key_bytes.zeroize();
        return Err(CryptoError::KeyDerivation);
    }

    Ok(VaultKey::from_bytes(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_produces_32_bytes() {
        let salt = Salt::generate().unwrap();
        let key = derive_key(b"test passphrase", &salt).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key1 = derive_key(b"same passphrase", &salt).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key2 = derive_key(b"same passphrase", &salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let salt1 = Salt::from_bytes([1u8; SALT_LEN]);
        let salt2 = Salt::from_bytes([2u8; SALT_LEN]);
        let key1 = derive_key(b"passphrase", &salt1).unwrap();
        let key2 = derive_key(b"passphrase", &salt2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_passphrases_produce_different_keys() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key1 = derive_key(b"passphrase one", &salt).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key2 = derive_key(b"passphrase two", &salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn salt_from_slice_rejects_wrong_length() {
        assert!(Salt::from_slice(&[0u8; 16]).is_err());
    }

    #[test]
    fn salt_from_slice_accepts_correct_length() {
        let bytes = [7u8; SALT_LEN];
        let salt = Salt::from_slice(&bytes).unwrap();
        assert_eq!(salt.as_bytes(), &bytes);
    }

    #[test]
    fn vault_key_debug_does_not_leak() {
        let key = VaultKey::from_bytes([0xAB; KEY_LEN]);
        let debug = format!("{key:?}");
        assert!(!debug.contains("AB"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn salt_debug_does_not_leak() {
        let salt = Salt::from_bytes([0xCD; SALT_LEN]);
        let debug = format!("{salt:?}");
        assert!(!debug.contains("CD"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn empty_passphrase_rejected() {
        let salt = Salt::generate().unwrap();
        assert!(derive_key(b"", &salt).is_err());
    }
}
