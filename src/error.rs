//! Unified error types for `PrivacySuite` Core SDK.
//!
//! - **Fail closed**: every operation returns an explicit error.
//! - **No information leakage**: error messages never include key material
//!   or internal state.
//! - **Opaque decryption errors**: wrong key and corrupted ciphertext
//!   produce the same error to prevent oracle attacks.

use std::fmt;

/// Errors from cryptographic operations.
///
/// Variants are intentionally coarse-grained. `PartialEq` is derived so
/// callers can match errors structurally instead of comparing `Display`
/// strings (which could introduce timing side-channels).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Key derivation failed (bad parameters or empty passphrase).
    KeyDerivation,
    /// AEAD encryption failed.
    Encryption,
    /// AEAD decryption or authentication failed.
    Decryption,
    /// OS entropy source unavailable.
    Rng,
    /// Invalid BIP39 mnemonic phrase.
    InvalidMnemonic,
    /// Input has wrong length.
    InvalidLength {
        /// What the input represents.
        context: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyDerivation => f.write_str("key derivation failed"),
            Self::Encryption => f.write_str("encryption failed"),
            Self::Decryption => f.write_str("decryption failed"),
            Self::Rng => f.write_str("random number generation failed"),
            Self::InvalidMnemonic => f.write_str("invalid mnemonic phrase"),
            Self::InvalidLength { context, expected, actual } => {
                write!(f, "invalid {context} length: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
