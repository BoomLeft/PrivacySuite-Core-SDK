//! Cryptographic primitives for `PrivacySuite`.
//!
//! - **[`keys`]** — Argon2id key derivation, zeroizing key and salt types.
//! - **[`aead`]** — XChaCha20-Poly1305 authenticated encryption.
//! - **[`mnemonic`]** — BIP39 24-word recovery phrase generation and recovery.
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::{keys, aead, mnemonic};
//!
//! // Generate a recovery mnemonic (show to user, store nowhere).
//! let m = mnemonic::Mnemonic::generate().unwrap();
//! println!("{}", m.to_phrase()); // 24 words
//!
//! // Derive a vault key from a passphrase.
//! let salt = keys::Salt::generate().unwrap();
//! let key = keys::derive_key(b"user passphrase", &salt).unwrap();
//!
//! // Encrypt data at rest.
//! let ct = aead::encrypt(&key, b"private data", b"row-id:42").unwrap();
//! let pt = aead::decrypt(&key, &ct, b"row-id:42").unwrap();
//! assert_eq!(pt, b"private data");
//! ```

pub mod aead;
pub mod keys;
pub mod mnemonic;
