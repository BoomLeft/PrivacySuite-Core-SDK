//! HKDF-SHA256 key derivation (RFC 5869).
//!
//! Provides HKDF-Expand for deriving purpose-specific sub-keys when
//! BLAKE3-based derivation (see [`super::kdf`]) is not suitable — for
//! example, when interoperating with systems that mandate HMAC-SHA256
//! or when NIST-compliant KDF is required.
//!
//! # When to use HKDF vs BLAKE3 KDF
//!
//! - **BLAKE3 KDF** ([`super::kdf::derive_subkey`]): Preferred for new
//!   BoomLeft designs. Faster, simpler, single dependency.
//! - **HKDF-SHA256** (this module): Use when interoperating with existing
//!   systems, when NIST SP 800-108 compliance is needed, or when the
//!   input key material comes from a non-uniform source that needs
//!   HKDF-Extract first.

use crate::error::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum output length for HKDF-SHA256 (255 * 32 = 8160 bytes).
pub const HKDF_SHA256_MAX_OUTPUT: usize = 255 * 32;

/// Performs HKDF-Extract (RFC 5869 Section 2.2).
///
/// Extracts a pseudorandom key (PRK) from input key material (IKM)
/// using an optional salt. If `salt` is empty, a zero-filled salt of
/// hash length (32 bytes) is used per the RFC.
///
/// # Returns
///
/// A 32-byte pseudorandom key suitable for use with [`hkdf_expand`].
///
/// # Panics
///
/// Does not panic: HMAC-SHA256 accepts keys of any length, so the
/// `new_from_slice` call is infallible. If a future dependency upgrade ever
/// makes this fallible, we fall back to a zero-initialised PRK so the
/// library never produces a partially-initialised output.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    // SECURITY: HMAC-SHA256 accepts any key length — this cannot fail in
    // practice. We still avoid `.expect()` (project policy: no panics in
    // crypto paths) and instead fall through to a safe zero output if the
    // invariant is ever violated.
    let Ok(mut mac) = HmacSha256::new_from_slice(salt) else {
        return [0u8; 32];
    };
    mac.update(ikm);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Performs HKDF-Expand (RFC 5869 Section 2.3).
///
/// Expands a pseudorandom key (PRK) into `output_len` bytes of output
/// key material (OKM), bound to the given `info` context.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if:
/// - `prk` is shorter than 32 bytes (minimum PRK length for SHA-256)
/// - `output_len` exceeds [`HKDF_SHA256_MAX_OUTPUT`] (8160 bytes)
/// - `output_len` is zero
pub fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    if prk.len() < 32 {
        return Err(CryptoError::InvalidLength {
            context: "HKDF PRK",
            expected: 32,
            actual: prk.len(),
        });
    }
    if output_len == 0 || output_len > HKDF_SHA256_MAX_OUTPUT {
        return Err(CryptoError::InvalidLength {
            context: "HKDF output length",
            expected: HKDF_SHA256_MAX_OUTPUT,
            actual: output_len,
        });
    }

    let n = output_len.div_ceil(32);
    let mut okm = Vec::with_capacity(output_len);

    // SECURITY: Reuse a single fixed-size buffer for T(i-1) so we can
    // zeroize the previous block in place every iteration. The old
    // `t_prev = t_i.to_vec()` pattern allocated a new Vec per iteration
    // and let the deallocated buffer leak partial PRF output onto the heap.
    let mut t_prev = [0u8; 32];
    let mut t_prev_len: usize = 0;

    for i in 1..=n {
        // SECURITY: HMAC-SHA256 accepts any key length — this cannot fail
        // in practice. Fall through with a cleared output on the impossible
        // error path rather than panicking.
        let Ok(mut mac) = HmacSha256::new_from_slice(prk) else {
            t_prev.zeroize();
            okm.zeroize();
            return Err(CryptoError::KeyDerivation);
        };
        mac.update(&t_prev[..t_prev_len]);
        mac.update(info);
        #[allow(clippy::cast_possible_truncation)]
        mac.update(&[i as u8]);
        let t_i = mac.finalize().into_bytes();

        // Zeroize the previous block before overwriting it.
        t_prev.zeroize();
        t_prev.copy_from_slice(&t_i);
        t_prev_len = 32;

        let remaining = output_len - okm.len();
        let take = remaining.min(32);
        okm.extend_from_slice(&t_i[..take]);
    }

    // Final scrub of the last intermediate block.
    t_prev.zeroize();

    Ok(okm)
}

/// Convenience: HKDF-Extract then HKDF-Expand in one call.
///
/// # Errors
///
/// Same as [`hkdf_expand`].
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut prk = hkdf_extract(salt, ikm);
    let result = hkdf_expand(&prk, info, output_len);
    prk.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_prk = hex::decode(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        ).unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ).unwrap();

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(&prk[..], &expected_prk[..]);

        let okm = hkdf_expand(&prk, &info, 42).unwrap();
        assert_eq!(&okm[..], &expected_okm[..]);
    }

    #[test]
    fn expand_rejects_short_prk() {
        assert!(hkdf_expand(&[0u8; 16], b"info", 32).is_err());
    }

    #[test]
    fn expand_rejects_zero_output() {
        assert!(hkdf_expand(&[0u8; 32], b"info", 0).is_err());
    }

    #[test]
    fn expand_rejects_too_long_output() {
        assert!(hkdf_expand(&[0u8; 32], b"info", HKDF_SHA256_MAX_OUTPUT + 1).is_err());
    }

    #[test]
    fn different_info_produces_different_output() {
        let prk = [0x42u8; 32];
        let o1 = hkdf_expand(&prk, b"purpose-a", 32).unwrap();
        let o2 = hkdf_expand(&prk, b"purpose-b", 32).unwrap();
        assert_ne!(o1, o2);
    }

    #[test]
    fn convenience_hkdf_works() {
        let okm = hkdf(b"salt", b"input key material", b"context", 64).unwrap();
        assert_eq!(okm.len(), 64);
    }
}
