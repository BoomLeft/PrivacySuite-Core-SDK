//! Cryptographic utility functions.
//!
//! Provides common primitives that multiple BoomLeft applications need:
//! secure random byte generation and constant-time byte comparison.

use crate::error::CryptoError;

/// Generates `len` bytes of cryptographically secure random data.
///
/// Uses the OS entropy source (`OsRng`).
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable.
pub fn secure_random(len: usize) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if both slices have the same length and identical contents.
/// Runs in time proportional to the longer slice regardless of where the
/// first difference occurs, preventing timing side-channels.
///
/// # Security Note
///
/// The length check itself is NOT constant-time (length is not secret),
/// but once lengths match, byte-by-byte comparison is constant-time.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    // SECURITY: ct_eq runs in constant time for equal-length inputs.
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_random_produces_requested_length() {
        let bytes = secure_random(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn secure_random_produces_different_outputs() {
        let a = secure_random(32).unwrap();
        let b = secure_random(32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn secure_random_zero_length() {
        let bytes = secure_random(0).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }
}
