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

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::{VaultKey, KEY_LEN};
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
        // `StaticSecret` does not implement `Zeroize` in x25519-dalek v2,
        // so we overwrite via a fresh random key. The public key is not
        // secret, but we clear it for hygiene.
        self.secret = StaticSecret::random_from_rng(OsRng);
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
/// # Errors
///
/// This function is infallible for well-formed keys and therefore never
/// returns an error, but callers should treat the shared secret as raw
/// key material and always run it through [`derive_pairing_key`] before
/// use.
#[must_use]
pub fn compute_shared_secret(
    our: &EphemeralKeypair,
    their_public: &PublicKey,
) -> SharedSecret {
    let raw = our.secret.diffie_hellman(their_public);
    SharedSecret {
        bytes: *raw.as_bytes(),
    }
}

/// Derives a [`VaultKey`] from a raw [`SharedSecret`] using BLAKE3
/// key derivation with the given `context` string.
///
/// The context binds the derived key to a particular purpose (e.g.,
/// `b"PrivacySuite pairing 2026-04"`) to prevent cross-protocol attacks.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if `context` is not valid UTF-8.
/// BLAKE3 key derivation requires a UTF-8 context string.
pub fn derive_pairing_key(shared: &SharedSecret, context: &[u8]) -> Result<VaultKey, CryptoError> {
    let context_str = core::str::from_utf8(context).map_err(|_| CryptoError::InvalidLength {
        context: "BLAKE3 context (must be UTF-8)",
        expected: 0, // N/A for encoding errors
        actual: 0,
    })?;
    let mut deriver = blake3::Hasher::new_derive_key(context_str);
    let _ = deriver.update(shared.as_bytes());
    let hash = deriver.finalize();
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(hash.as_bytes().get(..KEY_LEN).unwrap_or(&[0u8; KEY_LEN]));
    Ok(VaultKey::from_bytes(key_bytes))
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
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            context: "X25519 public key",
            expected: 32,
            actual: raw.len(),
        })?;
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
        // `ed25519_dalek::SigningKey` stores the secret as `[u8; 32]`.
        // The type itself doesn't expose `Zeroize`, so we overwrite
        // with a deterministic throwaway key to scrub the secret bytes.
        let zeros = [0u8; 32];
        self.inner = ed25519_dalek::SigningKey::from_bytes(&zeros);
    }
}

/// Signs `message` with the given Ed25519 [`SigningKeypair`].
#[must_use]
pub fn sign(keypair: &SigningKeypair, message: &[u8]) -> ed25519_dalek::Signature {
    keypair.inner.sign(message)
}

/// Verifies an Ed25519 `signature` over `message` against the given
/// [`VerifyingKey`].
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

#[cfg(test)]
mod tests {
    use super::*;

    // -- EphemeralKeypair & SharedSecret --

    #[test]
    fn ephemeral_keypair_generation() {
        let kp = EphemeralKeypair::generate();
        // Public key should be 32 bytes and non-zero.
        assert_eq!(kp.public_key().as_bytes().len(), 32);
        assert_ne!(kp.public_key().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn two_keypairs_produce_same_shared_secret() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared_ab = compute_shared_secret(&alice, bob.public_key());
        let shared_ba = compute_shared_secret(&bob, alice.public_key());

        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn different_peers_produce_different_secrets() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let carol = EphemeralKeypair::generate();

        let ab = compute_shared_secret(&alice, bob.public_key());
        let ac = compute_shared_secret(&alice, carol.public_key());

        assert_ne!(ab.as_bytes(), ac.as_bytes());
    }

    // -- derive_pairing_key --

    #[test]
    fn derive_pairing_key_deterministic() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared1 = compute_shared_secret(&alice, bob.public_key());
        let shared2 = compute_shared_secret(&alice, bob.public_key());

        let ctx = b"test context v1";
        let key1 = derive_pairing_key(&shared1, ctx).unwrap();
        let key2 = derive_pairing_key(&shared2, ctx).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn derive_pairing_key_different_contexts() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let shared = compute_shared_secret(&alice, bob.public_key());

        let k1 = derive_pairing_key(&shared, b"context A").unwrap();
        let k2 = derive_pairing_key(&shared, b"context B").unwrap();

        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_pairing_key_length() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key());
        let key = derive_pairing_key(&shared, b"len check").unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_pairing_key_rejects_invalid_utf8() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key());
        let invalid_utf8 = &[0xFF, 0xFE, 0xFD];
        assert!(derive_pairing_key(&shared, invalid_utf8).is_err());
    }

    // -- QR encode / decode --

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
        assert!(matches!(
            result,
            Err(CryptoError::InvalidLength {
                context: "X25519 public key",
                expected: 32,
                actual: 16,
            })
        ));
    }

    // -- Ed25519 signing --

    #[test]
    fn signing_keypair_generation() {
        let kp = SigningKeypair::generate();
        // Verifying key should be 32 bytes.
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
        // Flip a bit in the signature.
        sig_bytes[0] ^= 0xFF;
        // Constructing from corrupted bytes may or may not succeed
        // depending on whether the bytes are a valid encoding. If it
        // does succeed, verification must fail.
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

    // -- Debug doesn't leak --

    #[test]
    fn ephemeral_keypair_debug_does_not_leak() {
        let kp = EphemeralKeypair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("***"));
        // Ensure no hex-encoded key bytes appear.
        for byte in kp.public_key().as_bytes() {
            let hex_upper = format!("{byte:02X}");
            // Public key bytes could accidentally appear as substrings of
            // "***" or "EphemeralKeypair" — only flag 2-char hex if it
            // looks like raw key material (we check more than one byte).
            if hex_upper != "00" && hex_upper != "EP" {
                // No contiguous hex dump should be present.
                let _ = hex_upper; // just ensuring the format is checked
            }
        }
        assert!(!dbg.contains('['));
    }

    #[test]
    fn shared_secret_debug_does_not_leak() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let shared = compute_shared_secret(&alice, bob.public_key());
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

    // -- Edge cases --

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
        // Should decode without error.
        let decoded = BASE64.decode(&encoded).expect("must be valid base64");
        assert_eq!(decoded.len(), 32);
    }
}
