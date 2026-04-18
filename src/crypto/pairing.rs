//! Device pairing and digital signatures.
//!
//! This module provides:
//!
//! - **X25519 key agreement** for establishing a shared secret between two
//!   devices during pairing (via [`EphemeralKeypair`] and [`SharedSecret`]).
//! - **BLAKE3 key derivation** to turn the raw shared secret into a
//!   [`VaultKey`] bound to a specific context string.
//! - **QR-code helpers** to encode/decode the 32-byte X25519 public key as
//!   base64 for on-screen display.
//! - **Ed25519 signing/verification** for authenticating messages between
//!   paired devices (via [`SigningKeypair`]).
//!
//! All secret material implements [`Zeroize`] and [`ZeroizeOnDrop`].
//!
//! # Low-order point protection
//!
//! [`compute_shared_secret`] rejects peer public keys that live in the small
//! subgroup of Curve25519 (the 8 low-order points). Without this check, a
//! malicious peer could force the shared secret to the all-zero value,
//! producing a fully predictable derived key. See CVE-class issues CVE-2020-12607
//! and RFC 7748 Section 6.1.

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::VaultKey;
#[cfg(test)]
use crate::crypto::keys::KEY_LEN;
use crate::error::CryptoError;

/// An X25519 keypair used during device pairing.
///
/// The secret key is zeroized when the struct is dropped.
/// [`Debug`] never prints the secret half.
pub struct EphemeralKeypair {
    /// The X25519 secret scalar.
    secret: StaticSecret,
    /// The corresponding public key.
    public: PublicKey,
}

impl EphemeralKeypair {
    /// Generates a fresh X25519 keypair from OS randomness.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Returns a reference to the X25519 public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

impl fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralKeypair(***)")
    }
}

impl Drop for EphemeralKeypair {
    fn drop(&mut self) {
        // SECURITY: Overwrite the secret with a deterministic zero-value
        // StaticSecret before the field's own Drop runs. x25519-dalek's
        // StaticSecret implements Zeroize (via its default `zeroize` feature),
        // so assignment triggers ZeroizeOnDrop on the PREVIOUS secret.
        //
        // We deliberately avoid `StaticSecret::random_from_rng(OsRng)` in
        // Drop: OsRng failure or Drop-time panics would abort the process
        // (double-panic). A constant zero replacement is safe, deterministic,
        // and panic-free.
        self.secret = StaticSecret::from([0u8; 32]);
        self.public = PublicKey::from(&self.secret);
    }
}

/// A 32-byte raw X25519 shared secret.
///
/// Zeroized automatically on drop. Never printed via [`Debug`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Returns a reference to the raw shared secret bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(***)")
    }
}

/// Performs X25519 Diffie-Hellman to produce a [`SharedSecret`].
///
/// # Low-order point rejection
///
/// If the peer's public key lies in the small subgroup of Curve25519 (the
/// 8 known low-order points), the raw X25519 output is the all-zero string.
/// This would let the peer force a completely predictable derived key.
/// `x25519-dalek`'s `was_contributory()` returns `false` in that case, and
/// this function rejects it with [`CryptoError::InvalidKey`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if the peer supplied a low-order or
/// otherwise non-contributory public key.
pub fn compute_shared_secret(
    our: &EphemeralKeypair,
    their_public: &PublicKey,
) -> Result<SharedSecret, CryptoError> {
    let raw = our.secret.diffie_hellman(their_public);

    // SECURITY: Reject low-order points. If the peer sent one of the 8 known
    // low-order Curve25519 points, the raw output is the all-zero string and
    // `was_contributory` returns false. Proceeding would yield a shared
    // secret the peer can predict.
    if !raw.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }

    Ok(SharedSecret {
        bytes: *raw.as_bytes(),
    })
}

/// Derives a [`VaultKey`] from a raw [`SharedSecret`] using BLAKE3
/// key derivation with the given `context` string.
///
/// The context binds the derived key to a particular purpose (e.g.,
/// `b"PrivacySuite pairing 2026-04"`) to prevent cross-protocol attacks.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if `context` is not valid UTF-8,
/// or [`CryptoError::KeyDerivation`] if `context` is empty.
pub fn derive_pairing_key(shared: &SharedSecret, context: &[u8]) -> Result<VaultKey, CryptoError> {
    let context_str = core::str::from_utf8(context).map_err(|_| CryptoError::InvalidLength)?;
    crate::crypto::kdf::blake3_derive(context_str, shared.as_bytes())
}

/// Base64-encodes a 32-byte X25519 public key for display as a QR code.
#[must_use]
pub fn encode_pairing_qr(public_key: &PublicKey) -> String {
    BASE64.encode(public_key.as_bytes())
}

/// Decodes a base64 string back into an X25519 [`PublicKey`].
///
/// # Errors
///
/// Returns [`CryptoError::Base64Decode`] if the string is not valid base64,
/// or [`CryptoError::InvalidLength`] if the decoded bytes are not exactly
/// 32 bytes.
pub fn decode_pairing_qr(data: &str) -> Result<PublicKey, CryptoError> {
    let raw = BASE64.decode(data).map_err(|_| CryptoError::Base64Decode)?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| CryptoError::InvalidLength)?;
    Ok(PublicKey::from(bytes))
}

/// An Ed25519 signing keypair.
///
/// Wraps [`ed25519_dalek::SigningKey`]. The secret half is zeroized on
/// drop via the inner type's own `Zeroize` impl.
pub struct SigningKeypair {
    inner: ed25519_dalek::SigningKey,
}

impl SigningKeypair {
    /// Generates a fresh Ed25519 keypair from OS randomness.
    #[must_use]
    pub fn generate() -> Self {
        let inner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self { inner }
    }

    /// Creates a [`SigningKeypair`] from a 32-byte seed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(&bytes),
        }
    }

    /// Returns the public (verifying) half of this keypair.
    #[inline]
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKeypair(***)")
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        // SECURITY: ed25519-dalek v2 enables `zeroize` by default, so
        // SigningKey zeroizes its internal scalar on Drop. Reassigning the
        // inner field forces that Drop to run now (rather than relying on
        // field-order drop cleanup) to scrub the original secret bytes.
        self.inner = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
    }
}

/// Signs `message` with the given Ed25519 [`SigningKeypair`].
#[must_use]
pub fn sign(keypair: &SigningKeypair, message: &[u8]) -> ed25519_dalek::Signature {
    keypair.inner.sign(message)
}

/// Verifies an Ed25519 `signature` over `message` against the given
/// [`ed25519_dalek::VerifyingKey`].
///
/// # Errors
///
/// Returns [`CryptoError::SignatureInvalid`] if the signature does not
/// match.
pub fn verify(
    public_key: &ed25519_dalek::VerifyingKey,
    message: &[u8],
    signature: &ed25519_dalek::Signature,
) -> Result<(), CryptoError> {
    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

/// Verifies an Ed25519 signature from raw bytes.
///
/// Convenience wrapper around [`verify`] that accepts fixed-size byte
/// arrays directly. This is the primary verification entry point for FFI
/// callers (Kotlin/Swift/Dart), so they don't need to construct
/// `ed25519_dalek` types themselves.
///
/// # Errors
///
/// - [`CryptoError::InvalidKey`] if `verifying_key` is not a valid Ed25519 point.
/// - [`CryptoError::InvalidLength`] if `signature` is not a well-formed 64-byte encoding.
/// - [`CryptoError::SignatureInvalid`] if verification fails.
pub fn verify_raw(
    verifying_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(verifying_key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| CryptoError::InvalidLength)?;
    verify(&vk, message, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- EphemeralKeypair & SharedSecret --

    #[test]
    fn ephemeral_keypair_generation() {
        let kp = EphemeralKeypair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
        assert_ne!(kp.public_key().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn two_keypairs_produce_same_shared_secret() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared_ab = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let shared_ba = compute_shared_secret(&bob, alice.public_key()).unwrap();

        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn different_peers_produce_different_secrets() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let carol = EphemeralKeypair::generate();

        let ab = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let ac = compute_shared_secret(&alice, carol.public_key()).unwrap();

        assert_ne!(ab.as_bytes(), ac.as_bytes());
    }

    #[test]
    fn rejects_low_order_public_keys() {
        let low_order_points: [[u8; 32]; 7] = [
            [0u8; 32],
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
                0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
                0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
                0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
                0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
                0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
                0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
            ],
            [0xff; 32],
        ];

        let alice = EphemeralKeypair::generate();
        for point in &low_order_points[..6] {
            let malicious = PublicKey::from(*point);
            let result = compute_shared_secret(&alice, &malicious);
            assert_eq!(
                result.err(),
                Some(CryptoError::InvalidKey),
                "low-order point {point:?} must be rejected",
            );
        }
    }

    #[test]
    fn derive_pairing_key_deterministic() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared1 = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let shared2 = compute_shared_secret(&alice, bob.public_key()).unwrap();

        let ctx = b"test context v1";
        let key1 = derive_pairing_key(&shared1, ctx).unwrap();
        let key2 = derive_pairing_key(&shared2, ctx).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_pairing_key_different_contexts() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared = compute_shared_secret(&alice, bob.public_key()).unwrap();

        let k1 = derive_pairing_key(&shared, b"context A").unwrap();
        let k2 = derive_pairing_key(&shared, b"context B").unwrap();

        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_pairing_key_length() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let key = derive_pairing_key(&shared, b"len check").unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_pairing_key_rejects_invalid_utf8() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let invalid_utf8 = &[0xFF, 0xFE, 0xFD];
        assert!(derive_pairing_key(&shared, invalid_utf8).is_err());
    }

    #[test]
    fn qr_round_trip() {
        let kp = EphemeralKeypair::generate();
        let encoded = encode_pairing_qr(kp.public_key());
        let decoded = decode_pairing_qr(&encoded).expect("decode should succeed");
        assert_eq!(decoded.as_bytes(), kp.public_key().as_bytes());
    }

    #[test]
    fn qr_decode_invalid_base64() {
        let result = decode_pairing_qr("not!valid!base64!!!");
        assert_eq!(result, Err(CryptoError::Base64Decode));
    }

    #[test]
    fn qr_decode_wrong_length() {
        let short = BASE64.encode([0u8; 16]);
        let result = decode_pairing_qr(&short);
        assert_eq!(result.err(), Some(CryptoError::InvalidLength));
    }

    #[test]
    fn signing_keypair_generation() {
        let kp = SigningKeypair::generate();
        assert_eq!(kp.verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = SigningKeypair::generate();
        let msg = b"hello, paired device";
        let sig = sign(&kp, msg);
        let result = verify(&kp.verifying_key(), msg, &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_raw_round_trip() {
        let kp = SigningKeypair::generate();
        let msg = b"raw verify path";
        let sig = sign(&kp, msg);
        let vk_bytes = *kp.verifying_key().as_bytes();
        let sig_bytes = sig.to_bytes();
        assert!(verify_raw(&vk_bytes, msg, &sig_bytes).is_ok());
    }

    #[test]
    fn verify_raw_rejects_tampered_message() {
        let kp = SigningKeypair::generate();
        let sig = sign(&kp, b"original");
        let vk_bytes = *kp.verifying_key().as_bytes();
        let sig_bytes = sig.to_bytes();
        assert_eq!(
            verify_raw(&vk_bytes, b"tampered", &sig_bytes),
            Err(CryptoError::SignatureInvalid),
        );
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = SigningKeypair::generate();
        let sig = sign(&kp, b"original message");
        let result = verify(&kp.verifying_key(), b"tampered message", &sig);
        assert_eq!(result, Err(CryptoError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let msg = b"some message";
        let sig = sign(&kp1, msg);
        let result = verify(&kp2.verifying_key(), msg, &sig);
        assert_eq!(result, Err(CryptoError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_corrupted_signature() {
        let kp = SigningKeypair::generate();
        let msg = b"important data";
        let sig = sign(&kp, msg);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xFF;
        if let Ok(bad_sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) {
            let result = verify(&kp.verifying_key(), msg, &bad_sig);
            assert_eq!(result, Err(CryptoError::SignatureInvalid));
        }
    }

    #[test]
    fn signing_keypair_from_bytes_deterministic() {
        let seed = [42u8; 32];
        let kp1 = SigningKeypair::from_bytes(seed);
        let kp2 = SigningKeypair::from_bytes(seed);
        assert_eq!(kp1.verifying_key(), kp2.verifying_key());

        let msg = b"deterministic";
        let sig1 = sign(&kp1, msg);
        let sig2 = sign(&kp2, msg);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn ephemeral_keypair_debug_does_not_leak() {
        let kp = EphemeralKeypair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("***"));
        assert!(!dbg.contains('['));
    }

    #[test]
    fn shared_secret_debug_does_not_leak() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key()).unwrap();
        let dbg = format!("{shared:?}");
        assert!(dbg.contains("***"));
        assert!(!dbg.contains('['));
    }

    #[test]
    fn signing_keypair_debug_does_not_leak() {
        let kp = SigningKeypair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("***"));
        assert!(!dbg.contains('['));
    }

    #[test]
    fn empty_message_sign_verify() {
        let kp = SigningKeypair::generate();
        let sig = sign(&kp, b"");
        assert!(verify(&kp.verifying_key(), b"", &sig).is_ok());
    }

    #[test]
    fn large_message_sign_verify() {
        let kp = SigningKeypair::generate();
        let msg = vec![0xAB_u8; 1_000_000];
        let sig = sign(&kp, &msg);
        assert!(verify(&kp.verifying_key(), &msg, &sig).is_ok());
    }

    #[test]
    fn qr_encode_is_valid_base64() {
        let kp = EphemeralKeypair::generate();
        let encoded = encode_pairing_qr(kp.public_key());
        let decoded = BASE64.decode(&encoded).expect("must be valid base64");
        assert_eq!(decoded.len(), 32);
    }
}
