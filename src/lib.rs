//! # `PrivacySuite` Core SDK
//!
//! Zero-knowledge cryptographic foundation for every `BoomLeft` application.
//!
//! ## Privacy Guarantees
//!
//! This crate is the enforcement boundary for `BoomLeft`'s core promise:
//!
//! - **Zero user data collection** — no analytics, no crash reporting, no telemetry.
//! - **On-device first** — all data stays on the user's device unless explicitly
//!   E2EE-synced to another device the user controls.
//! - **Private by math, not policy** — even with full server access and a subpoena,
//!   no plaintext user data can be produced. Equivalent to Signal's disclosure posture.
//!
//! ## Modules
//!
//! - [`crypto`] — Key derivation (`Argon2id`), AEAD (`XChaCha20-Poly1305`),
//!   BIP39 mnemonic recovery, zeroization of all key material.
//! - [`error`] — Unified error types (fail-closed, no information leakage).

#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod crypto;
pub mod error;
