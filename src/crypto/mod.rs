//! Cryptographic primitives for `PrivacySuite`.
//!
//! - **[`keys`]** — Argon2id key derivation (default and configurable params), zeroizing key and salt types.
//! - **[`kdf`]** — BLAKE3-based sub-key derivation for key hierarchies.
//! - **[`aead`]** — XChaCha20-Poly1305 authenticated encryption.
//! - **[`stream`]** — Chunked streaming AEAD (STREAM construction) for files.
//! - **[`hash`]** — BLAKE3 content hashing for integrity and deduplication.
//! - **[`mnemonic`]** — BIP39 24-word recovery phrase generation and recovery.
//! - **[`pairing`]** — X25519 device pairing, BLAKE3 key derivation, Ed25519 signing.
//! - **[`pinning`]** — TLS certificate pinning (SHA-256 SPKI verification).
//! - **[`media`]** — Image metadata stripping + decompression-bomb defense
//!   (byte-in / byte-out; no codec invocation).
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::{keys, kdf, aead, mnemonic};
//!
//! // Generate a recovery mnemonic (show to user, store nowhere).
//! let m = mnemonic::Mnemonic::generate().unwrap();
//! println!("{}", m.to_phrase()); // 24 words
//!
//! // Derive a vault key from a passphrase.
//! let salt = keys::Salt::generate().unwrap();
//! let key = keys::derive_key(b"user passphrase", &salt).unwrap();
//!
//! // Derive purpose-specific sub-keys.
//! let db_key = kdf::derive_subkey(&key, "myapp 2026 database").unwrap();
//! let field_key = kdf::derive_subkey(&key, "myapp 2026 field encryption").unwrap();
//!
//! // Encrypt data at rest.
//! let ct = aead::encrypt(&db_key, b"private data", b"row-id:42").unwrap();
//! let pt = aead::decrypt(&db_key, &ct, b"row-id:42").unwrap();
//! assert_eq!(pt, b"private data");
//! ```

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod kdf;
pub mod keys;
pub mod media;
pub mod mnemonic;
pub mod pairing;
pub mod pinning;
pub mod stream;
pub mod util;
