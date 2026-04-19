//! Argon2id-backed short-PIN unlock with exponential lockout.
//!
//! # Scope
//!
//! This module implements two composable primitives:
//!
//! 1. [`derive_key_from_pin`] — Argon2id key derivation tuned for the
//!    low-entropy / interactive-UX characteristics of a short PIN.
//! 2. [`try_pin`] — a thin state machine that wraps the derivation with
//!    an attempt counter and an exponential lockout timer.
//!
//! The SDK is **storage-agnostic**. The caller persists
//! [`PinAttemptState`] and the [`Salt`] somewhere durable
//! (shared-preferences, encrypted file, `SQLCipher` row, etc); the logic
//! here is pure and deterministic given a caller-supplied wall-clock.
//!
//! # Why PIN Argon2id uses different parameters than vault derivation
//!
//! [`crate::crypto::keys::derive_key`] targets an arbitrary-length
//! passphrase and therefore pins relatively aggressive Argon2id
//! parameters (m=64 MiB, t=3, p=4). A short PIN has structurally
//! different requirements:
//!
//! - **Low entropy.** A 4-8 digit PIN has at most ~26 bits of entropy.
//!   An offline attacker who captures the stored ciphertext + salt can
//!   precompute the full PIN space regardless of how costly Argon2id is
//!   — piling on CPU cost only buys ~2× seconds against an attacker
//!   already prepared to spend a GPU-hour. The real defence is
//!   hardware-backing + attempt-limit + exponential lockout.
//! - **Interactive.** The user is staring at the unlock screen. We
//!   target sub-second derivation so the UX doesn't fall apart on mid-
//!   range devices. 32 MiB / t=3 / p=1 hits that on a 2020-vintage phone.
//!
//! See `docs/security/audit-2.md` (Finding #11) for the full write-up.
//!
//! # Timing-attack discipline
//!
//! PIN *correctness* is decided by the caller-supplied `verify_fn`
//! predicate: the SDK never compares secret bytes directly. The
//! callback **MUST** perform a constant-time comparison internally —
//! typically by attempting an AEAD decryption of a known canary and
//! returning `true` on success — so the caller's "right key?" check
//! can't leak via variable-time byte compare. See [`try_pin`] for the
//! full contract.
//!
//! Lockout timing comparisons are deliberately non-constant-time: the
//! attacker already knows when they last guessed (they were there), so
//! there's no side-channel to protect.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::crypto::keys::{Salt, VaultKey, KEY_LEN};
use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Argon2id parameters (PIN-tuned)
// ---------------------------------------------------------------------------

/// Argon2id memory cost in MiB for PIN derivation.
///
/// Half the default vault-derivation memory. See the module-level doc for
/// why stretching harder doesn't meaningfully improve the PIN posture.
pub const PIN_M_COST_MIB: u32 = 32;

/// Argon2id time cost (iterations) for PIN derivation.
pub const PIN_T_COST: u32 = 3;

/// Argon2id parallelism degree for PIN derivation.
///
/// p=1 (single-threaded) keeps the derivation deterministic across
/// devices with different core counts and minimises latency on the
/// lower-end phones we care about (the 4-core tablet doesn't finish a
/// p=4 derivation any faster than the 8-core flagship does).
pub const PIN_P_COST: u32 = 1;

// ---------------------------------------------------------------------------
// Lockout schedule
// ---------------------------------------------------------------------------

/// Number of wrong attempts tolerated before the first lockout kicks in.
///
/// The first 4 wrong attempts (attempts 1-4) pass through without a
/// timer; the 5th wrong attempt activates the 30-second tier.
pub const MAX_FREE_ATTEMPTS: u32 = 4;

/// Exponential lockout schedule, matching Telephoto's PIN-lock behaviour.
///
/// Tuples are `(threshold, lockout_seconds)`. When the wrong-attempt
/// counter reaches an attempt index `N`, the lockout engaged is the
/// value associated with the first threshold `N <= threshold`. Attempts
/// past the last entry sustain at 24 hours.
///
/// | Attempt | Lockout   |
/// |---------|-----------|
/// | 1–4     | none      |
/// | 5       | 30 s      |
/// | 6       | 2 min     |
/// | 7       | 5 min     |
/// | 8       | 15 min    |
/// | 9       | 1 hour    |
/// | 10+     | 24 hours  |
const LOCKOUT_SCHEDULE_SECS: &[(u32, u64)] = &[
    (5, 30),
    (6, 120),
    (7, 300),
    (8, 900),
    (9, 3600),
    (10, 86_400),
];

/// Compute the lockout duration triggered by reaching `attempt` wrong
/// attempts (1-indexed: `attempt == 5` means "the user just failed for
/// the fifth time").
///
/// Returns `0` for attempts that do not trigger a lockout (attempts
/// 1-4). Attempts past the schedule sustain at 24 hours.
#[must_use]
fn lockout_secs_for_attempt(attempt: u32) -> u64 {
    // Attempts below the first schedule threshold don't engage a
    // lockout at all.
    let Some(&(first_threshold, _)) = LOCKOUT_SCHEDULE_SECS.first() else {
        return 0;
    };
    if attempt < first_threshold {
        return 0;
    }
    // Walk the table in order; the first entry whose threshold is >=
    // the current attempt wins. Attempts beyond the last threshold
    // sustain at the final tier.
    let mut last_secs = 0u64;
    for &(threshold, secs) in LOCKOUT_SCHEDULE_SECS {
        last_secs = secs;
        if attempt <= threshold {
            return secs;
        }
    }
    last_secs
}

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/// Attempt counter + lockout timer. The SDK does not own persistence —
/// the caller reads this out of storage before calling [`try_pin`] and
/// writes it back afterwards.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PinAttemptState {
    /// Number of consecutive wrong PIN attempts recorded. A successful
    /// [`try_pin`] resets this to zero.
    pub attempt_count: u32,
    /// Wall-clock time at which the current lockout expires, in Unix
    /// milliseconds. `0` means "not currently locked out".
    pub lockout_until_unix_ms: u64,
    /// Wall-clock time of the most recent attempt, in Unix milliseconds.
    /// Currently informational; reserved for future rate-limiting
    /// heuristics so callers can already persist the field.
    pub last_attempt_unix_ms: u64,
}

impl PinAttemptState {
    /// Create a fresh, un-locked state with zero attempts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Public lockout status. What the UI gets. Never leaks the PIN, the
/// derived key, or any material that wasn't already knowable to an
/// observer of the unlock screen.
#[derive(Debug, Copy, Clone)]
pub struct PinLockStatus {
    /// `true` if the user is currently locked out and must wait.
    pub is_locked: bool,
    /// Seconds remaining on the current lockout. `0` when not locked.
    pub remaining_secs: u64,
    /// How many more wrong attempts the user may make before the next
    /// lockout tier activates. Clamped at zero once the free-attempt
    /// budget is exhausted.
    pub attempts_left_before_next_lockout: u32,
}

/// Errors that can arise from the PIN-lock state machine.
#[derive(Debug)]
pub enum PinError {
    /// The supplied PIN derived a key that `verify_fn` rejected.
    WrongPin,
    /// The user is currently locked out. `remaining_secs` communicates
    /// how long the UI should wait before re-enabling the prompt.
    Locked {
        /// Seconds until the lockout lifts.
        remaining_secs: u64,
    },
    /// The PIN failed format validation (empty, shorter than 4 bytes,
    /// or longer than 32 bytes).
    InvalidPinFormat,
    /// An underlying Argon2id or RNG primitive failed.
    Crypto(CryptoError),
    /// The caller reported a storage-layer failure while persisting
    /// state. The SDK itself never writes storage; this variant exists
    /// so callers can fold their storage error into the FFI-visible
    /// error type without inventing a new one.
    Storage(String),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPin => f.write_str("incorrect PIN"),
            Self::Locked { remaining_secs } => {
                write!(f, "locked out for {remaining_secs}s")
            }
            Self::InvalidPinFormat => f.write_str("PIN format is invalid"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
        }
    }
}

impl std::error::Error for PinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CryptoError> for PinError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

// ---------------------------------------------------------------------------
// PIN format validation
// ---------------------------------------------------------------------------

/// Minimum accepted PIN length in bytes.
const MIN_PIN_LEN: usize = 4;
/// Maximum accepted PIN length in bytes.
const MAX_PIN_LEN: usize = 32;

/// Validates byte-length only — no character-class restriction. The
/// SDK doesn't care whether the PIN is digits, alphanumeric, or Unicode;
/// the caller's UI is responsible for whatever format policy their
/// users expect.
fn validate_pin_format(pin: &[u8]) -> Result<(), PinError> {
    if pin.is_empty() || pin.len() < MIN_PIN_LEN || pin.len() > MAX_PIN_LEN {
        return Err(PinError::InvalidPinFormat);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Argon2id primitive
// ---------------------------------------------------------------------------

/// Derive a [`VaultKey`] from a PIN attempt using the PIN-tuned Argon2id
/// parameters.
///
/// This is the *primitive*: the caller decides how to tell whether the
/// derived key is correct (typically by attempting to decrypt a known
/// canary ciphertext). Attempt-counter and lockout logic is layered on
/// top by [`try_pin`].
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if the PIN is empty (Argon2id
/// rejects zero-length inputs) or if the Argon2id primitive fails
/// internally.
pub fn derive_key_from_pin(pin: &[u8], salt: &Salt) -> Result<VaultKey, CryptoError> {
    if pin.is_empty() {
        return Err(CryptoError::KeyDerivation);
    }
    // PIN_M_COST_MIB is measured in MiB; the Argon2id crate wants KiB.
    let m_cost_kib = PIN_M_COST_MIB.saturating_mul(1024);
    let params = Params::new(m_cost_kib, PIN_T_COST, PIN_P_COST, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; KEY_LEN];
    if argon2
        .hash_password_into(pin, salt.as_bytes(), &mut key_bytes)
        .is_err()
    {
        // SECURITY: zeroise the output buffer before returning so that a
        // panicking caller doesn't leave half-derived key material on
        // the stack.
        key_bytes.zeroize();
        return Err(CryptoError::KeyDerivation);
    }
    Ok(VaultKey::from_bytes(key_bytes))
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Attempt to unlock with `pin`, enforcing exponential lockout.
///
/// # Flow
///
/// 1. Validate the PIN byte length (4 ≤ len ≤ 32).
/// 2. If the user is still inside an active lockout window, return
///    [`PinError::Locked`] **without** running Argon2id. The attempt
///    counter is *not* incremented — a locked-out user shouldn't be
///    able to burn through tiers by repeatedly hitting the API.
/// 3. Otherwise, derive a candidate [`VaultKey`] via
///    [`derive_key_from_pin`] and hand it to `verify_fn`.
/// 4. If `verify_fn` returns `true`, reset the counter to zero and
///    return the key.
/// 5. If `verify_fn` returns `false`, increment the counter, consult
///    [`LOCKOUT_SCHEDULE_SECS`] to decide whether a lockout should
///    activate, update `state`, and return [`PinError::WrongPin`].
///
/// # `verify_fn` contract (IMPORTANT)
///
/// `verify_fn` receives the derived candidate key and must return
/// `true` iff it is the correct key. Typical implementations:
///
/// - Attempt to decrypt a stored canary ciphertext; return `true` on
///   successful AEAD authentication. (AEAD tag verification is already
///   constant-time by construction.)
/// - Compare a BLAKE3 hash of the key against a stored digest using
///   [`crate::crypto::util::constant_time_eq`]. Never use `==` on raw
///   bytes — that's variable-time and leaks a side-channel oracle.
///
/// The callback is invoked exactly once per non-locked attempt.
///
/// # Errors
///
/// - [`PinError::InvalidPinFormat`] — PIN byte length fails validation.
/// - [`PinError::Locked`] — the lockout window is still active.
/// - [`PinError::WrongPin`] — the derived key failed `verify_fn`.
/// - [`PinError::Crypto`] — Argon2id / RNG failure.
///
/// After a wrong-PIN or success path, the caller **MUST** persist the
/// mutated `state` back to storage before the next call, otherwise
/// attackers can reset the counter by killing the process.
pub fn try_pin<F>(
    pin: &[u8],
    salt: &Salt,
    state: &mut PinAttemptState,
    now_unix_ms: u64,
    verify_fn: F,
) -> Result<VaultKey, PinError>
where
    F: FnOnce(&VaultKey) -> bool,
{
    validate_pin_format(pin)?;

    // Short-circuit when a lockout is still active. We deliberately
    // check *before* running Argon2id: a locked-out user running us
    // through the KDF is (a) a waste of ~100ms of CPU per call and
    // (b) a minor DoS amplifier.
    let remaining = remaining_lockout_secs(state, now_unix_ms);
    if remaining > 0 {
        return Err(PinError::Locked {
            remaining_secs: remaining,
        });
    }

    let candidate = derive_key_from_pin(pin, salt)?;

    // Record the attempt wall-clock regardless of outcome; this is the
    // value callers will surface in "last unlock attempted at ..." UIs.
    state.last_attempt_unix_ms = now_unix_ms;

    if verify_fn(&candidate) {
        // Success — clear the counter so the user walks into the next
        // session with a fresh budget.
        state.attempt_count = 0;
        state.lockout_until_unix_ms = 0;
        Ok(candidate)
    } else {
        // Wrong PIN. Increment the counter (saturating — attackers
        // shouldn't be able to wrap u32) and, if the new value triggers
        // a lockout tier, stamp the expiry.
        state.attempt_count = state.attempt_count.saturating_add(1);

        let lockout_secs = lockout_secs_for_attempt(state.attempt_count);
        if lockout_secs > 0 {
            // `* 1000` is safe: the largest schedule entry is 86_400
            // seconds, i.e. 86.4M ms, comfortably inside u64.
            state.lockout_until_unix_ms =
                now_unix_ms.saturating_add(lockout_secs.saturating_mul(1000));
        } else {
            // Below the threshold — no active lockout.
            state.lockout_until_unix_ms = 0;
        }

        Err(PinError::WrongPin)
    }
}

/// Snapshot the current lockout posture without mutating state.
///
/// This is the query the UI polls to decide whether to enable the PIN
/// prompt. Returns both the human-facing "how many seconds until I can
/// try again" figure and the "how many guesses before the next lockout
/// tier" figure for callers that want to display a warning banner.
#[must_use]
pub fn status(state: &PinAttemptState, now_unix_ms: u64) -> PinLockStatus {
    let remaining_secs = remaining_lockout_secs(state, now_unix_ms);
    let is_locked = remaining_secs > 0;
    let attempts_left_before_next_lockout = MAX_FREE_ATTEMPTS.saturating_sub(state.attempt_count);
    PinLockStatus {
        is_locked,
        remaining_secs,
        attempts_left_before_next_lockout,
    }
}

/// Reset the attempt counter and clear any active lockout. Call on
/// successful biometric unlock (where the PIN was bypassed) or on a
/// user-initiated "forget device" flow.
pub fn reset(state: &mut PinAttemptState) {
    state.attempt_count = 0;
    state.lockout_until_unix_ms = 0;
    state.last_attempt_unix_ms = 0;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Compute the remaining lockout in seconds. Returns `0` when the
/// lockout has either never been set or has expired.
fn remaining_lockout_secs(state: &PinAttemptState, now_unix_ms: u64) -> u64 {
    if state.lockout_until_unix_ms == 0 || state.lockout_until_unix_ms <= now_unix_ms {
        0
    } else {
        // Round up — a 500ms residual should still report as "1 second
        // remaining" rather than vanishing into a zero.
        let delta_ms = state.lockout_until_unix_ms - now_unix_ms;
        delta_ms.div_ceil(1000)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SALT_LEN;

    fn fixed_salt() -> Salt {
        Salt::from_bytes([7u8; SALT_LEN])
    }

    fn other_salt() -> Salt {
        Salt::from_bytes([9u8; SALT_LEN])
    }

    // ----- derive_key_from_pin --------------------------------------------

    #[test]
    fn derive_same_pin_same_salt_is_deterministic() {
        let salt = fixed_salt();
        let k1 = derive_key_from_pin(b"1234", &salt).unwrap();
        let salt2 = fixed_salt();
        let k2 = derive_key_from_pin(b"1234", &salt2).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_different_salt_diverges() {
        let k1 = derive_key_from_pin(b"1234", &fixed_salt()).unwrap();
        let k2 = derive_key_from_pin(b"1234", &other_salt()).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_empty_pin_rejected() {
        let err = derive_key_from_pin(b"", &fixed_salt()).unwrap_err();
        assert_eq!(err, CryptoError::KeyDerivation);
    }

    // ----- status ----------------------------------------------------------

    #[test]
    fn status_fresh_state_has_four_attempts_left() {
        let state = PinAttemptState::new();
        let s = status(&state, 1_000_000);
        assert!(!s.is_locked);
        assert_eq!(s.remaining_secs, 0);
        assert_eq!(s.attempts_left_before_next_lockout, 4);
    }

    #[test]
    fn status_during_active_lockout_reports_remaining() {
        let now = 1_000_000;
        let state = PinAttemptState {
            attempt_count: 5,
            lockout_until_unix_ms: now + 30_000, // +30s
            last_attempt_unix_ms: now,
        };
        let s = status(&state, now);
        assert!(s.is_locked);
        // div_ceil rounds 30_000ms to 30s exactly.
        assert_eq!(s.remaining_secs, 30);
        assert_eq!(s.attempts_left_before_next_lockout, 0);
    }

    #[test]
    fn status_after_lockout_expired() {
        let now = 1_000_000;
        let state = PinAttemptState {
            attempt_count: 5,
            lockout_until_unix_ms: now - 1,
            last_attempt_unix_ms: now - 30_000,
        };
        let s = status(&state, now);
        assert!(!s.is_locked);
        assert_eq!(s.remaining_secs, 0);
    }

    #[test]
    fn status_rounds_up_subsecond_residual() {
        let now = 1_000_000;
        let state = PinAttemptState {
            attempt_count: 5,
            // 500ms remaining should still read as "1 second" in the UI.
            lockout_until_unix_ms: now + 500,
            last_attempt_unix_ms: now,
        };
        let s = status(&state, now);
        assert!(s.is_locked);
        assert_eq!(s.remaining_secs, 1);
    }

    // ----- try_pin ---------------------------------------------------------

    #[test]
    fn try_pin_wrong_pin_increments_counter() {
        let salt = fixed_salt();
        let mut state = PinAttemptState::new();
        let now = 1_000_000;

        let err = try_pin(b"wrong", &salt, &mut state, now, |_| false).unwrap_err();
        assert!(matches!(err, PinError::WrongPin));
        assert_eq!(state.attempt_count, 1);
        assert_eq!(state.lockout_until_unix_ms, 0);
        assert_eq!(state.last_attempt_unix_ms, now);
    }

    #[test]
    fn try_pin_correct_pin_resets_counter() {
        let salt = fixed_salt();
        let mut state = PinAttemptState {
            attempt_count: 3,
            lockout_until_unix_ms: 0,
            last_attempt_unix_ms: 0,
        };
        let now = 2_000_000;

        let key = try_pin(b"1234", &salt, &mut state, now, |_| true).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
        assert_eq!(state.attempt_count, 0);
        assert_eq!(state.lockout_until_unix_ms, 0);
        assert_eq!(state.last_attempt_unix_ms, now);
    }

    #[test]
    fn try_pin_invalid_format_short() {
        let salt = fixed_salt();
        let mut state = PinAttemptState::new();
        let err = try_pin(b"12", &salt, &mut state, 0, |_| true).unwrap_err();
        assert!(matches!(err, PinError::InvalidPinFormat));
        // Counter stays put — format errors aren't attack attempts.
        assert_eq!(state.attempt_count, 0);
    }

    #[test]
    fn try_pin_invalid_format_empty() {
        let salt = fixed_salt();
        let mut state = PinAttemptState::new();
        let err = try_pin(b"", &salt, &mut state, 0, |_| true).unwrap_err();
        assert!(matches!(err, PinError::InvalidPinFormat));
    }

    #[test]
    fn try_pin_invalid_format_too_long() {
        let salt = fixed_salt();
        let mut state = PinAttemptState::new();
        let pin = vec![b'1'; 33];
        let err = try_pin(&pin, &salt, &mut state, 0, |_| true).unwrap_err();
        assert!(matches!(err, PinError::InvalidPinFormat));
    }

    #[test]
    fn try_pin_while_locked_does_not_run_argon2id() {
        let salt = fixed_salt();
        let now = 10_000_000;
        let mut state = PinAttemptState {
            attempt_count: 5,
            lockout_until_unix_ms: now + 15_000,
            last_attempt_unix_ms: now - 1000,
        };

        // If verify_fn is invoked the test fails: a locked-out attempt
        // should short-circuit *before* Argon2id runs.
        let err = try_pin(b"1234", &salt, &mut state, now, |_| {
            panic!("verify_fn must not be called while locked");
        })
        .unwrap_err();

        match err {
            PinError::Locked { remaining_secs } => assert_eq!(remaining_secs, 15),
            other => panic!("expected Locked, got {other:?}"),
        }
        // Counter is NOT incremented — attackers can't burn tiers by
        // spamming the API while the timer is counting down.
        assert_eq!(state.attempt_count, 5);
        // last_attempt_unix_ms is also untouched: the attempt was
        // refused before any "attempt" was recorded.
        assert_eq!(state.last_attempt_unix_ms, now - 1000);
    }

    #[test]
    fn try_pin_after_lockout_expiry_allows_new_attempt() {
        let salt = fixed_salt();
        let earlier = 1_000_000;
        let later = earlier + 35_000;
        let mut state = PinAttemptState {
            attempt_count: 5,
            lockout_until_unix_ms: earlier + 30_000, // expired by `later`
            last_attempt_unix_ms: earlier,
        };

        // `later` is past the previous lockout_until: derivation should
        // run, and verify_fn=false should escalate the counter to 6 and
        // activate the 2-minute tier.
        let err = try_pin(b"wrong", &salt, &mut state, later, |_| false).unwrap_err();
        assert!(matches!(err, PinError::WrongPin));
        assert_eq!(state.attempt_count, 6);
        assert_eq!(state.lockout_until_unix_ms, later + 120_000);
    }

    // ----- Full escalation sequence ----------------------------------------

    #[test]
    fn full_escalation_walks_the_schedule() {
        let salt = fixed_salt();
        let mut state = PinAttemptState::new();
        let mut now = 1_000_000u64;

        // Attempts 1-4: no lockout.
        for expected_count in 1..=4 {
            let err = try_pin(b"wrong", &salt, &mut state, now, |_| false).unwrap_err();
            assert!(matches!(err, PinError::WrongPin));
            assert_eq!(state.attempt_count, expected_count);
            assert_eq!(
                state.lockout_until_unix_ms, 0,
                "attempt {expected_count} must not trigger a lockout"
            );
            now += 10;
        }

        // Attempts 5 through 10 — each should land on its schedule entry.
        let expected = [
            (5, 30u64),
            (6, 120),
            (7, 300),
            (8, 900),
            (9, 3600),
            (10, 86_400),
        ];
        for (attempt, expected_secs) in expected {
            let before = now;
            let err = try_pin(b"wrong", &salt, &mut state, now, |_| false).unwrap_err();
            assert!(matches!(err, PinError::WrongPin));
            assert_eq!(state.attempt_count, attempt);
            assert_eq!(
                state.lockout_until_unix_ms,
                before + expected_secs * 1000,
                "attempt {attempt} should set lockout of {expected_secs}s"
            );

            // Advance past the lockout so the next call isn't refused.
            now = state.lockout_until_unix_ms + 1;
        }

        // Attempt 11+ sustains at 24 hours.
        let before = now;
        let err = try_pin(b"wrong", &salt, &mut state, now, |_| false).unwrap_err();
        assert!(matches!(err, PinError::WrongPin));
        assert_eq!(state.attempt_count, 11);
        assert_eq!(state.lockout_until_unix_ms, before + 86_400 * 1000);
    }

    // ----- reset -----------------------------------------------------------

    #[test]
    fn reset_clears_everything() {
        let mut state = PinAttemptState {
            attempt_count: 9,
            lockout_until_unix_ms: 123_456_789,
            last_attempt_unix_ms: 987_654_321,
        };
        reset(&mut state);
        assert_eq!(state.attempt_count, 0);
        assert_eq!(state.lockout_until_unix_ms, 0);
        assert_eq!(state.last_attempt_unix_ms, 0);
    }

    // ----- status + attempts_left interaction ------------------------------

    #[test]
    fn attempts_left_decrements_with_counter() {
        let mut state = PinAttemptState::new();
        assert_eq!(status(&state, 0).attempts_left_before_next_lockout, 4);
        state.attempt_count = 1;
        assert_eq!(status(&state, 0).attempts_left_before_next_lockout, 3);
        state.attempt_count = 4;
        assert_eq!(status(&state, 0).attempts_left_before_next_lockout, 0);
        state.attempt_count = 10;
        assert_eq!(status(&state, 0).attempts_left_before_next_lockout, 0);
    }
}
