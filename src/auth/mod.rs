//! Authentication building blocks for `BoomLeft` applications.
//!
//! This module currently hosts two complementary primitives:
//!
//! - [`opaque`] — OPAQUE zero-knowledge password authentication (aPAKE)
//!   against a server. The public OPAQUE symbols (`AuthError`,
//!   `SessionKey`, `registration_start`, etc.) are re-exported at the
//!   `privacysuite_core_sdk::auth::*` path for backwards compatibility.
//!
//! - [`pin_lock`] — On-device short-PIN unlock: an Argon2id-backed PIN
//!   key derivation paired with an exponential-lockout attempt counter.
//!   PIN-lock is storage-agnostic: the caller persists the attempt-state
//!   and salt wherever makes sense for the application (shared-preferences,
//!   encrypted file, `SQLCipher` row, etc).

mod opaque;

pub mod pin_lock;

// ---------------------------------------------------------------------------
// Backwards-compatible OPAQUE re-exports.
//
// Downstream callers reference OPAQUE symbols through
// `privacysuite_core_sdk::auth::*` — keep that surface exactly as it was
// before the split into `auth/opaque.rs` + `auth/pin_lock.rs`.
// ---------------------------------------------------------------------------

pub use opaque::{
    login_finish, login_start, registration_finish, registration_start, AuthError,
    ClientLoginState, ClientRegistrationState, SessionKey,
};
