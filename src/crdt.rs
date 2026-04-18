//! End-to-end encrypted CRDT documents backed by Automerge.
//!
//! [`EncryptedDocument`] wraps an Automerge `AutoCommit`
//! document and provides ergonomic key-value operations on the root map.
//! The relay server never sees document content -- it only passes encrypted
//! blobs produced by [`EncryptedDocument::save_encrypted`] between peers.
//!
//! # Sync Protocol
//!
//! Multi-device sync uses the Automerge sync protocol:
//!
//! 1. Each peer maintains an [`automerge::sync::State`] per remote peer.
//! 2. [`generate_sync_message`](EncryptedDocument::generate_sync_message) produces
//!    a message to send (or `None` when converged).
//! 3. [`receive_sync_message`](EncryptedDocument::receive_sync_message) applies an
//!    incoming message from a peer.
//! 4. Messages are encrypted in transit via the relay's AEAD layer.

use std::fmt;

use automerge::sync::{Message, SyncDoc};
use automerge::transaction::Transactable;
use automerge::{AutoCommit, ReadDoc};
use zeroize::Zeroize;

use crate::crypto::aead::{decrypt, encrypt};
use crate::crypto::keys::VaultKey;

/// AAD context string bound to every encrypted CRDT blob to prevent
/// ciphertext relocation across protocol contexts.
const CRDT_AAD: &[u8] = b"privacysuite:crdt:v1";

/// SECURITY: Upper bound on a single encrypted CRDT blob, in bytes.
///
/// A peer who already has the `VaultKey` (a trusted, paired device, or
/// any peer that learned the key) could craft a multi-hundred-megabyte
/// blob whose ciphertext decrypts cleanly but whose Automerge content
/// is pathologically expensive to load (Automerge has historically
/// mis-sized pre-allocations off malformed varints). Capping both the
/// raw input and the decrypted plaintext at 16 MiB — the same bound
/// used by `sync.rs` for WebSocket frames — keeps a malicious
/// authenticated peer from mounting a memory-exhaustion DoS. 16 MiB is
/// far larger than any legitimate BoomLeft Automerge document.
pub const MAX_CRDT_BLOB_BYTES: usize = 16 * 1024 * 1024;

/// Errors produced by CRDT document operations.
#[derive(Debug)]
pub enum CrdtError {
    /// An Automerge operation failed.
    Automerge(String),
    /// AEAD encryption failed.
    Encryption,
    /// AEAD decryption or authentication failed.
    Decryption,
    /// Serialization or deserialization failed.
    Serialization(String),
}

impl fmt::Display for CrdtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Automerge(msg) => write!(f, "automerge error: {msg}"),
            Self::Encryption => f.write_str("CRDT encryption failed"),
            Self::Decryption => f.write_str("CRDT decryption failed"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for CrdtError {}

impl From<automerge::AutomergeError> for CrdtError {
    fn from(err: automerge::AutomergeError) -> Self {
        Self::Automerge(err.to_string())
    }
}

/// An Automerge CRDT document that is always encrypted at rest.
///
/// The inner [`AutoCommit`] is only held in plaintext in memory while the
/// document is open. Call [`save_encrypted`](Self::save_encrypted) to persist
/// or transmit the document -- the serialized bytes are XChaCha20-Poly1305
/// encrypted with the user's [`VaultKey`].
pub struct EncryptedDocument {
    doc: AutoCommit,
}

impl fmt::Debug for EncryptedDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedDocument")
            .field("actor", &self.doc.get_actor())
            .finish_non_exhaustive()
    }
}

impl EncryptedDocument {
    // -- Construction -------------------------------------------------------

    /// Creates a new, empty CRDT document.
    #[must_use]
    pub fn new() -> Self {
        Self {
            doc: AutoCommit::new(),
        }
    }

    // -- Key-value helpers --------------------------------------------------

    /// Puts a string value at `key` in the root map.
    ///
    /// If `key` already exists its value is overwritten (last-writer-wins per
    /// the Automerge conflict resolution policy).
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Automerge`] if the underlying Automerge
    /// transaction fails.
    pub fn put(&mut self, key: &str, value: &str) -> Result<(), CrdtError> {
        self.doc
            .put(automerge::ROOT, key, value)
            .map_err(|e| CrdtError::Automerge(e.to_string()))
    }

    /// Gets a string value from the root map, returning `None` if the key
    /// is absent or the value is not a string.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<String> {
        self.doc
            .get(automerge::ROOT, key)
            .ok()
            .flatten()
            .and_then(|(val, _id)| match val {
                automerge::Value::Scalar(cow) => match cow.as_ref() {
                    automerge::ScalarValue::Str(s) => Some(s.to_string()),
                    _ => None,
                },
                automerge::Value::Object(_) => None,
            })
    }

    /// Deletes `key` from the root map.
    ///
    /// Deleting a non-existent key is a no-op at the Automerge level but
    /// will still return `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Automerge`] if the underlying Automerge
    /// transaction fails.
    pub fn delete(&mut self, key: &str) -> Result<(), CrdtError> {
        self.doc
            .delete(automerge::ROOT, key)
            .map_err(|e| CrdtError::Automerge(e.to_string()))
    }

    // -- Encrypted persistence ----------------------------------------------

    /// Serializes the document and encrypts it with `key`.
    ///
    /// The ciphertext includes the AAD tag `privacysuite:crdt:v1` to bind
    /// the blob to this protocol context.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Encryption`] if AEAD encryption fails.
    pub fn save_encrypted(&mut self, key: &VaultKey) -> Result<Vec<u8>, CrdtError> {
        let mut plaintext = self.doc.save();
        let result = encrypt(key, &plaintext, CRDT_AAD).map_err(|_| CrdtError::Encryption);
        plaintext.zeroize();
        result
    }

    /// Decrypts and loads a document from bytes produced by
    /// [`save_encrypted`](Self::save_encrypted).
    ///
    /// # Safety caps
    ///
    /// Rejects inputs whose ciphertext exceeds
    /// [`MAX_CRDT_BLOB_BYTES`] (currently 16 MiB) **before** decryption,
    /// and again rejects the decrypted plaintext if it exceeds the
    /// same bound. The pre-decrypt check is returned as
    /// [`CrdtError::Decryption`] (not a dedicated "too large" variant)
    /// to avoid giving an attacker a size-probe oracle that
    /// distinguishes "blob was too big" from "blob had a bad tag".
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Decryption`] if the blob exceeds the size
    /// cap, the key is wrong, the ciphertext has been tampered with,
    /// or the AAD does not match.
    ///
    /// Returns [`CrdtError::Automerge`] if the decrypted bytes are not a
    /// valid Automerge document.
    pub fn load_encrypted(data: &[u8], key: &VaultKey) -> Result<Self, CrdtError> {
        // SECURITY: Cap the ciphertext size *before* the AEAD call.
        // Keeping the failure type `Decryption` (instead of a new
        // `InputTooLarge`) means the attacker can't tell whether they
        // hit the cap or the tag check failed.
        if data.len() > MAX_CRDT_BLOB_BYTES {
            return Err(CrdtError::Decryption);
        }

        let mut plaintext = decrypt(key, data, CRDT_AAD).map_err(|_| CrdtError::Decryption)?;

        // Defence in depth: if the plaintext itself somehow exceeds the
        // cap (e.g. a future compression scheme inflates on decrypt),
        // refuse to hand it to Automerge's loader.
        if plaintext.len() > MAX_CRDT_BLOB_BYTES {
            plaintext.zeroize();
            return Err(CrdtError::Decryption);
        }

        let result =
            AutoCommit::load(&plaintext).map_err(|e| CrdtError::Automerge(e.to_string()));
        plaintext.zeroize();
        Ok(Self { doc: result? })
    }

    // -- Sync ---------------------------------------------------------------

    /// Generates a sync message for the remote peer represented by
    /// `peer_state`.
    ///
    /// Returns `None` when the peer is already up-to-date (or we are waiting
    /// for an acknowledgement of an in-flight message).
    pub fn generate_sync_message(
        &mut self,
        peer_state: &mut automerge::sync::State,
    ) -> Option<Vec<u8>> {
        self.doc
            .sync()
            .generate_sync_message(peer_state)
            .map(automerge::sync::Message::encode)
    }

    /// Applies an incoming sync message from a peer.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Serialization`] if the message bytes cannot be
    /// decoded.
    ///
    /// Returns [`CrdtError::Automerge`] if applying the message fails.
    pub fn receive_sync_message(
        &mut self,
        peer_state: &mut automerge::sync::State,
        msg: &[u8],
    ) -> Result<(), CrdtError> {
        let message =
            Message::decode(msg).map_err(|e| CrdtError::Serialization(e.to_string()))?;
        self.doc
            .sync()
            .receive_sync_message(peer_state, message)
            .map_err(|e| CrdtError::Automerge(e.to_string()))
    }

    // -- Merge --------------------------------------------------------------

    /// Merges all changes from `other` into this document.
    ///
    /// After merging, both documents contain the union of all changes.
    /// Conflicts are resolved by Automerge's default last-writer-wins policy.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Automerge`] if the merge fails.
    pub fn merge(&mut self, other: &mut Self) -> Result<(), CrdtError> {
        let _ = self
            .doc
            .merge(&mut other.doc)
            .map_err(|e| CrdtError::Automerge(e.to_string()))?;
        Ok(())
    }
}

impl Default for EncryptedDocument {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;

    /// Helper: deterministic test key.
    fn test_key() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    /// Helper: a different key for negative tests.
    fn wrong_key() -> VaultKey {
        VaultKey::from_bytes([0xFF; 32])
    }

    // -- Basic CRUD ---------------------------------------------------------

    #[test]
    fn put_and_get() {
        let mut doc = EncryptedDocument::new();
        let _ = doc.put("name", "Alice");
        assert_eq!(doc.get("name").as_deref(), Some("Alice"));
    }

    #[test]
    fn get_missing_key_returns_none() {
        let doc = EncryptedDocument::new();
        assert!(doc.get("nonexistent").is_none());
    }

    #[test]
    fn put_overwrites() {
        let mut doc = EncryptedDocument::new();
        let _ = doc.put("k", "v1");
        let _ = doc.put("k", "v2");
        assert_eq!(doc.get("k").as_deref(), Some("v2"));
    }

    #[test]
    fn delete_removes_key() {
        let mut doc = EncryptedDocument::new();
        let _ = doc.put("ephemeral", "data");
        assert!(doc.get("ephemeral").is_some());
        let _ = doc.delete("ephemeral");
        assert!(doc.get("ephemeral").is_none());
    }

    // -- Encrypted round-trip -----------------------------------------------

    #[test]
    fn save_and_load_encrypted_round_trip() {
        let key = test_key();
        let mut original = EncryptedDocument::new();
        let _ = original.put("secret", "launch codes");
        let _ = original.put("count", "42");

        let blob = original.save_encrypted(&key).unwrap();
        let loaded = EncryptedDocument::load_encrypted(&blob, &key).unwrap();

        assert_eq!(loaded.get("secret").as_deref(), Some("launch codes"));
        assert_eq!(loaded.get("count").as_deref(), Some("42"));
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = test_key();
        let bad = wrong_key();

        let mut doc = EncryptedDocument::new();
        let _ = doc.put("x", "y");
        let blob = doc.save_encrypted(&key).unwrap();

        let result = EncryptedDocument::load_encrypted(&blob, &bad);
        assert!(result.is_err());
    }

    // -- Merge --------------------------------------------------------------

    #[test]
    fn merge_two_documents_converges() {
        let mut doc_a = EncryptedDocument::new();
        let mut doc_b = EncryptedDocument::new();

        let _ = doc_a.put("from_a", "hello");
        let _ = doc_b.put("from_b", "world");

        let _ = doc_a.merge(&mut doc_b);

        assert_eq!(doc_a.get("from_a").as_deref(), Some("hello"));
        assert_eq!(doc_a.get("from_b").as_deref(), Some("world"));
    }

    // -- Sync ---------------------------------------------------------------

    #[test]
    fn sync_message_exchange() {
        let mut doc_a = EncryptedDocument::new();
        let _ = doc_a.put("color", "blue");

        let mut doc_b = EncryptedDocument::new();

        let mut state_a = automerge::sync::State::new();
        let mut state_b = automerge::sync::State::new();

        // Drive the sync protocol to convergence (bounded iterations).
        for _ in 0..10 {
            let mut progressed = false;

            if let Some(msg) = doc_a.generate_sync_message(&mut state_a) {
                let _ = doc_b.receive_sync_message(&mut state_b, &msg);
                progressed = true;
            }
            if let Some(msg) = doc_b.generate_sync_message(&mut state_b) {
                let _ = doc_a.receive_sync_message(&mut state_a, &msg);
                progressed = true;
            }

            if !progressed {
                break;
            }
        }

        assert_eq!(doc_b.get("color").as_deref(), Some("blue"));
    }

    // -- Debug --------------------------------------------------------------

    #[test]
    fn debug_impl_does_not_leak_content() {
        let mut doc = EncryptedDocument::new();
        let _ = doc.put("password", "hunter2");
        let debug = format!("{doc:?}");
        // Must contain the struct name but must NOT contain the secret.
        assert!(debug.contains("EncryptedDocument"));
        assert!(!debug.contains("hunter2"));
    }

    // --- Finding #13: max blob size is enforced on load_encrypted ---

    #[test]
    fn load_encrypted_rejects_oversize_blob() {
        let key = test_key();
        let oversize = vec![0u8; MAX_CRDT_BLOB_BYTES + 1];
        let err = EncryptedDocument::load_encrypted(&oversize, &key).unwrap_err();
        // The error must be Decryption (not a new variant) so attackers
        // cannot distinguish cap-hit from tag-failure.
        assert!(matches!(err, CrdtError::Decryption));
    }

    #[test]
    fn load_encrypted_rejects_exactly_cap_plus_one() {
        let key = test_key();
        // Exactly MAX + 1 must be rejected.
        let oversize = vec![0u8; MAX_CRDT_BLOB_BYTES + 1];
        assert!(matches!(
            EncryptedDocument::load_encrypted(&oversize, &key),
            Err(CrdtError::Decryption)
        ));
    }

    #[test]
    fn load_encrypted_accepts_legitimate_round_trip_below_cap() {
        let key = test_key();
        let mut doc = EncryptedDocument::new();
        let _ = doc.put("k", "v");
        let blob = doc.save_encrypted(&key).expect("save");
        assert!(blob.len() < MAX_CRDT_BLOB_BYTES);
        let _ = EncryptedDocument::load_encrypted(&blob, &key).expect("load");
    }

    // --- Finding #14: CrdtError is Send + Sync ---

    #[test]
    fn crdt_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrdtError>();
    }
}
