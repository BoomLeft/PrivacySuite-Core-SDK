//! Background sync scheduling — platform-agnostic trait + schema (G7).
//!
//! # Motivation
//!
//! Multiple BoomLeft consumer apps (Podcasts, Weather, Music) need to run
//! privacy-preserving sync work in the background: refresh RSS feeds,
//! download new podcast episodes when Wi-Fi returns, refetch forecasts
//! for pinned locations. Each app currently carries its own ad-hoc
//! `WorkManager` configuration wrapper with slightly different constraint
//! shapes, backoff parameters, and job-id conventions.
//!
//! This module standardises the *schema* across the family while
//! deliberately leaving the *scheduling* to the app layer. The trait
//! defined here ([`BackgroundSyncHost`]) lets a Rust caller describe a
//! periodic or one-shot job in SDK-owned types, and the host
//! implementation (Kotlin `WorkManager`, iOS `BGTaskScheduler`, or a
//! desktop timer thread) translates that description into a native
//! scheduler primitive.
//!
//! # Why the SDK does not bind `WorkManager` directly
//!
//! `WorkManager` is a Kotlin/Java library, with no Rust equivalent and a
//! rich Android-lifecycle surface (application context, broadcast
//! receivers, JobScheduler integration, Doze-mode awareness). Binding it
//! from Rust would mean either (a) a large JNI surface duplicated across
//! consumer apps, or (b) shipping an opinionated default that apps would
//! end up overriding anyway. Instead, the SDK:
//!
//! * Defines [`SyncJob`] / [`SyncConstraints`] / [`BackoffPolicy`] —
//!   the shared vocabulary every app should speak.
//! * Defines [`BackgroundSyncHost`] — the callback trait the host
//!   implements (on Android, a small Kotlin class wrapping
//!   `WorkManager`; on iOS, a similar class wrapping
//!   `BGTaskScheduler`).
//! * Defines [`BackgroundSyncClient`] — a thin wrapper the rest of the
//!   SDK (or consumer Rust code) talks to.
//!
//! A reference Kotlin `WorkManagerBackgroundSyncHost` lives in
//! `privacysuite-ffi/android/ffi/src/main/kotlin/` and ships inside the
//! Android AAR. Apps can either consume that directly or write their
//! own host for custom scheduling behaviour.
//!
//! # UniFFI exposure
//!
//! The FFI shim in `privacysuite-ffi` wraps [`BackgroundSyncClient`] as
//! a UniFFI `Object` and [`BackgroundSyncHost`] as a UniFFI
//! `callback_interface`. This keeps the core SDK dependency-free (no
//! `uniffi` crate in the core graph) while still giving Kotlin / Swift
//! callers a first-class binding.
//!
//! # Example (Rust consumer)
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use std::collections::HashSet;
//! use privacysuite_core_sdk::sync::background::{
//!     BackgroundSyncClient, BackgroundSyncError, BackgroundSyncHost,
//!     BackoffPolicy, SyncConstraints, SyncJob,
//! };
//!
//! #[derive(Debug)]
//! struct InMemoryHost {
//!     scheduled: Mutex<HashSet<String>>,
//! }
//! impl BackgroundSyncHost for InMemoryHost {
//!     fn schedule(&self, job: SyncJob) -> Result<(), BackgroundSyncError> {
//!         self.scheduled
//!             .lock()
//!             .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?
//!             .insert(job.job_id);
//!         Ok(())
//!     }
//!     fn cancel(&self, job_id: String) -> Result<(), BackgroundSyncError> {
//!         self.scheduled
//!             .lock()
//!             .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?
//!             .remove(&job_id);
//!         Ok(())
//!     }
//!     fn is_scheduled(&self, job_id: String) -> Result<bool, BackgroundSyncError> {
//!         Ok(self
//!             .scheduled
//!             .lock()
//!             .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?
//!             .contains(&job_id))
//!     }
//! }
//!
//! let host = Arc::new(InMemoryHost {
//!     scheduled: Mutex::new(HashSet::new()),
//! });
//! let client = BackgroundSyncClient::new(host);
//! client
//!     .schedule(SyncJob {
//!         job_id: "refresh-feeds".into(),
//!         constraints: SyncConstraints {
//!             network_required: true,
//!             unmetered_network: true,
//!             ..SyncConstraints::none()
//!         },
//!         interval_secs: 1_800,
//!         backoff_policy: BackoffPolicy::Exponential { initial_secs: 30 },
//!     })
//!     .expect("schedule should succeed");
//! assert!(client.is_scheduled("refresh-feeds").expect("lookup ok"));
//! ```

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

/// A single unit of work the caller wants scheduled.
///
/// `job_id` is a caller-chosen stable identifier — common values include
/// `"refresh-feeds"`, `"refresh-podcast-downloads"`,
/// `"weather-pinned-locations"`. Hosts treat the id as an opaque primary
/// key: scheduling a job with an existing id replaces the previous
/// registration (platform-native behaviour for both
/// `WorkManager.enqueueUniquePeriodicWork` and
/// `BGTaskScheduler.submit`).
#[derive(Debug, Clone)]
pub struct SyncJob {
    /// Caller-chosen stable id. Scheduling twice with the same id
    /// replaces the earlier registration.
    pub job_id: String,
    /// Device-state constraints the platform must satisfy before
    /// running the job.
    pub constraints: SyncConstraints,
    /// Minimum repeat interval in seconds.
    ///
    /// `0` means a one-shot job (run once, do not repeat). Non-zero
    /// values request a periodic job; the platform may round up to its
    /// minimum supported interval (on Android `WorkManager` that is
    /// 15 minutes = 900 s).
    pub interval_secs: u32,
    /// Backoff policy applied when the job returns a retry result.
    pub backoff_policy: BackoffPolicy,
}

/// Device-state constraints that must hold for the job to run.
///
/// All fields are additive — a `true` value means the platform must
/// satisfy the constraint before starting the job. The default
/// ([`SyncConstraints::none`]) imposes no constraints.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SyncConstraints {
    /// Job requires a network connection of any kind.
    pub network_required: bool,
    /// Job requires a metered-traffic-free network (Wi-Fi style).
    ///
    /// Implies `network_required` at the platform layer — hosts MUST
    /// treat `unmetered_network = true` as if `network_required = true`
    /// even when the caller set the latter to `false`.
    pub unmetered_network: bool,
    /// Job only runs while the device is charging.
    pub charging_required: bool,
    /// Job only runs when the device battery is not low (platform
    /// decides the threshold; on Android this is `setRequiresBatteryNotLow`).
    pub battery_not_low: bool,
    /// Job only runs when the device is idle (screen off, no recent
    /// user activity). Maps to `setRequiresDeviceIdle` on Android.
    pub device_idle: bool,
}

impl SyncConstraints {
    /// Construct a constraint set with every field cleared.
    ///
    /// Prefer this + struct update syntax over `Default::default()` to
    /// make it visually obvious at a call site which constraints are
    /// being enabled.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            network_required: false,
            unmetered_network: false,
            charging_required: false,
            battery_not_low: false,
            device_idle: false,
        }
    }
}

impl Default for SyncConstraints {
    fn default() -> Self {
        Self::none()
    }
}

/// Retry-backoff policy when a job returns a retryable failure.
///
/// All `initial_secs` values are a lower bound; platforms may clamp
/// upward (Android `WorkManager` enforces a 10-second floor via
/// `MIN_BACKOFF_MILLIS`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BackoffPolicy {
    /// Linear backoff: retry delay = `initial_secs * attempt_count`.
    Linear {
        /// Base delay in seconds. The platform may round up.
        initial_secs: u32,
    },
    /// Exponential backoff: retry delay = `initial_secs * 2^attempt_count`.
    Exponential {
        /// Base delay in seconds. The platform may round up.
        initial_secs: u32,
    },
}

impl BackoffPolicy {
    /// Returns the base delay regardless of policy shape.
    #[must_use]
    pub const fn initial_secs(self) -> u32 {
        match self {
            Self::Linear { initial_secs } | Self::Exponential { initial_secs } => initial_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can surface from a [`BackgroundSyncHost`] or a
/// [`BackgroundSyncClient`] operation.
///
/// Named `BackgroundSyncError` rather than `SyncError` so it does not
/// shadow the existing wire-protocol [`super::SyncError`]; the two are
/// entirely unrelated concerns and fusing them would force the FFI layer
/// to distinguish between "couldn't schedule a job" and "the relay closed
/// my WebSocket" at consumer-code sites.
#[derive(Debug)]
pub enum BackgroundSyncError {
    /// The host platform does not support background scheduling (e.g.
    /// a desktop build without a running scheduler thread).
    NotSupported,
    /// The host rejected the job because it violated a platform or
    /// policy rule (e.g. interval below the platform minimum).
    ///
    /// The payload is a human-readable reason suitable for logging;
    /// callers should not pattern-match on its contents.
    PolicyRejected(String),
    /// A platform-level error. Wraps whatever the native scheduler
    /// surfaced verbatim. Never parsed; purely diagnostic.
    Platform(String),
}

impl fmt::Display for BackgroundSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => f.write_str("background sync not supported on this platform"),
            Self::PolicyRejected(msg) => write!(f, "background sync policy rejected: {msg}"),
            Self::Platform(msg) => write!(f, "background sync platform error: {msg}"),
        }
    }
}

impl std::error::Error for BackgroundSyncError {}

// ---------------------------------------------------------------------------
// Host trait + client wrapper
// ---------------------------------------------------------------------------

/// Platform-specific scheduler adapter.
///
/// Consumer apps implement this trait in whichever language their
/// scheduler natively lives in:
///
/// * **Android / Kotlin** — wrap `androidx.work.WorkManager` in a
///   class that implements this trait via UniFFI's callback-interface
///   mapping. A reference implementation ships in the
///   `privacysuite-ffi` AAR as `WorkManagerBackgroundSyncHost`.
/// * **iOS / Swift** — wrap `BGTaskScheduler` similarly once the iOS
///   FFI lands.
/// * **Desktop / Rust** — implement directly with `tokio::time` or a
///   background OS service.
///
/// All methods are synchronous from the SDK's perspective; platform
/// schedulers are free to defer the actual work. The trait is
/// `Send + Sync` so the enclosing [`BackgroundSyncClient`] can be
/// cloned into async tasks.
pub trait BackgroundSyncHost: Send + Sync + fmt::Debug {
    /// Register (or re-register) `job` with the platform scheduler.
    ///
    /// Idempotent on `job.job_id`: calling with the same id as an
    /// existing job replaces the earlier registration atomically from
    /// the caller's perspective.
    ///
    /// # Errors
    ///
    /// Returns [`BackgroundSyncError::PolicyRejected`] if the platform
    /// refused the job (invalid interval, forbidden constraint
    /// combination), or [`BackgroundSyncError::Platform`] for any
    /// other native failure.
    fn schedule(&self, job: SyncJob) -> Result<(), BackgroundSyncError>;

    /// Cancel the job registered under `job_id`, if any.
    ///
    /// Calling with an unknown id is NOT an error — the post-condition
    /// is "no job with this id is scheduled", which is already true.
    ///
    /// # Errors
    ///
    /// Returns [`BackgroundSyncError::Platform`] on native scheduler
    /// failure.
    fn cancel(&self, job_id: String) -> Result<(), BackgroundSyncError>;

    /// Returns `true` if a job is currently registered under `job_id`.
    ///
    /// The query is a best-effort snapshot — a concurrent scheduler
    /// callback may invalidate the result before the caller acts on it.
    ///
    /// # Errors
    ///
    /// Returns [`BackgroundSyncError::Platform`] on native scheduler
    /// failure.
    fn is_scheduled(&self, job_id: String) -> Result<bool, BackgroundSyncError>;
}

/// Thin wrapper over a [`BackgroundSyncHost`] implementation.
///
/// The SDK does not own scheduling — it takes a host from the caller
/// (on Android, this is the app's Kotlin `BackgroundSyncHost` impl
/// wrapping `WorkManager`) and delegates every method verbatim.
///
/// The wrapper exists so the Rust / UniFFI surface has a stable
/// concrete type to pin to; the trait is intentionally kept small and
/// stable across SDK versions.
#[derive(Debug, Clone)]
pub struct BackgroundSyncClient {
    host: Arc<dyn BackgroundSyncHost>,
}

impl BackgroundSyncClient {
    /// Construct a new client wrapping the given host.
    #[must_use]
    pub fn new(host: Arc<dyn BackgroundSyncHost>) -> Self {
        Self { host }
    }

    /// Register (or re-register) `job` with the underlying host.
    ///
    /// # Errors
    ///
    /// Propagates whatever error the host returned.
    pub fn schedule(&self, job: SyncJob) -> Result<(), BackgroundSyncError> {
        self.host.schedule(job)
    }

    /// Cancel the job registered under `job_id`, if any.
    ///
    /// # Errors
    ///
    /// Propagates whatever error the host returned.
    pub fn cancel(&self, job_id: &str) -> Result<(), BackgroundSyncError> {
        self.host.cancel(job_id.to_owned())
    }

    /// Returns `true` if a job is currently registered under `job_id`.
    ///
    /// # Errors
    ///
    /// Propagates whatever error the host returned.
    pub fn is_scheduled(&self, job_id: &str) -> Result<bool, BackgroundSyncError> {
        self.host.is_scheduled(job_id.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        BackgroundSyncClient, BackgroundSyncError, BackgroundSyncHost, BackoffPolicy,
        SyncConstraints, SyncJob,
    };
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// In-memory test host; keeps a set of scheduled job ids and an
    /// optional forced-error knob for propagation testing.
    #[derive(Debug)]
    struct MockHost {
        scheduled: Mutex<HashSet<String>>,
        /// When set, every call returns this error verbatim (cloned).
        force_error: Mutex<Option<BackgroundSyncError>>,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                scheduled: Mutex::new(HashSet::new()),
                force_error: Mutex::new(None),
            }
        }

        fn with_error(err: BackgroundSyncError) -> Self {
            Self {
                scheduled: Mutex::new(HashSet::new()),
                force_error: Mutex::new(Some(err)),
            }
        }

        fn take_forced(&self) -> Option<BackgroundSyncError> {
            self.force_error
                .lock()
                .ok()
                .and_then(|mut guard| guard.take())
        }
    }

    impl BackgroundSyncHost for MockHost {
        fn schedule(&self, job: SyncJob) -> Result<(), BackgroundSyncError> {
            if let Some(err) = self.take_forced() {
                return Err(err);
            }
            let mut guard = self
                .scheduled
                .lock()
                .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?;
            let _ = guard.insert(job.job_id);
            Ok(())
        }

        fn cancel(&self, job_id: String) -> Result<(), BackgroundSyncError> {
            if let Some(err) = self.take_forced() {
                return Err(err);
            }
            let mut guard = self
                .scheduled
                .lock()
                .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?;
            let _ = guard.remove(&job_id);
            Ok(())
        }

        fn is_scheduled(&self, job_id: String) -> Result<bool, BackgroundSyncError> {
            if let Some(err) = self.take_forced() {
                return Err(err);
            }
            let guard = self
                .scheduled
                .lock()
                .map_err(|_| BackgroundSyncError::Platform("poisoned".into()))?;
            Ok(guard.contains(&job_id))
        }
    }

    fn sample_job(id: &str) -> SyncJob {
        SyncJob {
            job_id: id.to_owned(),
            constraints: SyncConstraints {
                network_required: true,
                unmetered_network: true,
                ..SyncConstraints::none()
            },
            interval_secs: 1_800,
            backoff_policy: BackoffPolicy::Exponential { initial_secs: 30 },
        }
    }

    #[test]
    fn schedule_stores_job_id() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host.clone());

        client.schedule(sample_job("refresh-feeds")).expect("schedule ok");

        assert!(client
            .is_scheduled("refresh-feeds")
            .expect("lookup ok"));
    }

    #[test]
    fn schedule_is_idempotent_on_job_id() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host.clone());

        client.schedule(sample_job("refresh")).expect("schedule ok 1");
        client.schedule(sample_job("refresh")).expect("schedule ok 2");

        let set_len = host.scheduled.lock().expect("lock ok").len();
        assert_eq!(set_len, 1);
    }

    #[test]
    fn cancel_removes_job_id() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host);

        client.schedule(sample_job("refresh")).expect("schedule ok");
        assert!(client.is_scheduled("refresh").expect("lookup ok"));

        client.cancel("refresh").expect("cancel ok");

        assert!(!client.is_scheduled("refresh").expect("lookup ok"));
    }

    #[test]
    fn cancel_unknown_id_is_not_an_error() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host);

        // No prior schedule call — cancelling an unknown id should succeed.
        client.cancel("does-not-exist").expect("cancel ok");
    }

    #[test]
    fn is_scheduled_reflects_state() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host);

        assert!(!client
            .is_scheduled("refresh")
            .expect("lookup ok"));

        client.schedule(sample_job("refresh")).expect("schedule ok");
        assert!(client.is_scheduled("refresh").expect("lookup ok"));

        client.cancel("refresh").expect("cancel ok");
        assert!(!client.is_scheduled("refresh").expect("lookup ok"));
    }

    #[test]
    fn host_error_propagates_verbatim() {
        let host = Arc::new(MockHost::with_error(BackgroundSyncError::Platform(
            "workmanager not initialised".into(),
        )));
        let client = BackgroundSyncClient::new(host);

        let err = client
            .schedule(sample_job("refresh"))
            .expect_err("should propagate");

        match err {
            BackgroundSyncError::Platform(msg) => {
                assert_eq!(msg, "workmanager not initialised");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn policy_rejected_error_propagates() {
        let host = Arc::new(MockHost::with_error(BackgroundSyncError::PolicyRejected(
            "interval below 15-minute platform minimum".into(),
        )));
        let client = BackgroundSyncClient::new(host);

        let err = client
            .schedule(sample_job("refresh"))
            .expect_err("should propagate");

        match err {
            BackgroundSyncError::PolicyRejected(msg) => {
                assert!(msg.contains("15-minute"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn not_supported_error_propagates() {
        let host = Arc::new(MockHost::with_error(BackgroundSyncError::NotSupported));
        let client = BackgroundSyncClient::new(host);

        let err = client.cancel("refresh").expect_err("should propagate");

        assert!(matches!(err, BackgroundSyncError::NotSupported));
    }

    #[test]
    fn constraints_none_is_all_false() {
        let c = SyncConstraints::none();
        assert!(!c.network_required);
        assert!(!c.unmetered_network);
        assert!(!c.charging_required);
        assert!(!c.battery_not_low);
        assert!(!c.device_idle);
    }

    #[test]
    fn constraints_default_matches_none() {
        assert_eq!(SyncConstraints::default(), SyncConstraints::none());
    }

    #[test]
    fn backoff_policy_initial_secs_accessor() {
        assert_eq!(
            BackoffPolicy::Linear { initial_secs: 10 }.initial_secs(),
            10
        );
        assert_eq!(
            BackoffPolicy::Exponential { initial_secs: 45 }.initial_secs(),
            45
        );
    }

    #[test]
    fn error_display_does_not_leak_internal_state() {
        let e = BackgroundSyncError::NotSupported;
        assert!(format!("{e}").contains("not supported"));

        let e = BackgroundSyncError::PolicyRejected("bad interval".into());
        assert!(format!("{e}").contains("bad interval"));

        let e = BackgroundSyncError::Platform("native boom".into());
        assert!(format!("{e}").contains("native boom"));
    }

    #[test]
    fn client_is_cheaply_cloneable_across_threads() {
        let host = Arc::new(MockHost::new());
        let client = BackgroundSyncClient::new(host);
        let cloned = client.clone();

        let handle = std::thread::spawn(move || {
            cloned.schedule(sample_job("threaded")).expect("schedule ok");
        });
        handle.join().expect("thread join ok");

        assert!(client.is_scheduled("threaded").expect("lookup ok"));
    }
}
