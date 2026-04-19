//! Internal logging guidance for the `PrivacySuite` Core SDK.
//!
//! This module intentionally contains **no executable code** — it is a
//! documentation anchor for the SDK's logging posture. Consumer crates
//! can `use privacysuite_core_sdk::logging;` to land on this page from
//! `rustdoc` and read the rules below.
//!
//! ## Current posture: zero log traffic
//!
//! As of this writing the SDK **does not emit any log output**, from
//! any module, under any build profile. It does not depend on the
//! `log` or `tracing` façade, and it contains no `println!`,
//! `eprintln!`, `dbg!`, `log::*` or `tracing::*` call sites. The
//! clippy lints `print_stdout` and `print_stderr` are configured at
//! `deny` in this crate's `Cargo.toml` to keep it that way.
//!
//! This matches the SDK's privacy guarantee: *even with full
//! cooperation from the OS or stdout/stderr*, no user data can be
//! produced because the SDK never writes any. Consumer apps that
//! install a log sink (`env_logger`, `android_logger`, `tracing-
//! subscriber`, …) will observe only their own log calls — not
//! anything originating from this crate.
//!
//! ## Contract for adding a log call
//!
//! If a future change needs to emit a log message from the SDK
//! (e.g. a hard-to-diagnose field failure that a structured error
//! alone cannot communicate), the contributor MUST do **all** of the
//! following in the same PR:
//!
//! 1. **Add the façade as an exact-pinned dependency** with the
//!    compile-time-off feature:
//!
//!    ```toml
//!    # Preferred: the `log` crate (lighter, no async machinery).
//!    log = { version = "=0.4", features = ["release_max_level_off"] }
//!    # Alternative: `tracing` — use only if structured spans are
//!    # actually needed; otherwise prefer `log` for minimal supply-chain.
//!    # tracing = { version = "=0.1", features = ["release_max_level_off"] }
//!    ```
//!
//!    The `release_max_level_off` feature makes every `log::warn!` /
//!    `log::debug!` / `log::info!` / `log::trace!` / `log::error!`
//!    macro expand to **zero instructions** when the crate is
//!    compiled with `cfg(not(debug_assertions))`. Dev builds keep
//!    the full façade. No runtime flag is needed.
//!
//! 2. **Update `deny.toml`** to allow the new crate (both `log` and
//!    `tracing` are currently unlisted — there is an explicit ban on
//!    telemetry crates, so adding either requires a `deny.toml`
//!    review).
//!
//! 3. **Do not add a Cargo feature gate** for the logging. The
//!    compile-time strip via `release_max_level_off` already handles
//!    the release case. Forcing consumers to pick a logging feature
//!    would be unnecessary noise; this crate's feature matrix is
//!    already dense.
//!
//! 4. **Obey the privacy rules below**, and cite the rule number in
//!    the PR description for the reviewer.
//!
//! ## Privacy rules for SDK logging
//!
//! 1. **Never log plaintext key material.** `VaultKey`, `Salt`,
//!    `SessionKey`, `MnemonicHandle`, OPAQUE client/server state,
//!    passphrases, mnemonic phrases, PIN hashes, and any other
//!    secret-bearing type MUST NOT appear in a log message — even
//!    via `{:?}`. These types have redacted `Debug` impls, but log
//!    messages that *construct a `String` from their contents* (e.g.
//!    via `hex::encode(key.as_bytes())`) bypass the redaction and
//!    MUST NOT be written.
//!
//! 2. **Never log user-controlled content.** URLs, filenames,
//!    hostnames, podcast titles, message bodies, contact names, and
//!    any other value that originated from the user are "user data"
//!    under `BoomLeft`'s privacy policy and MUST NOT be logged. If a
//!    diagnostic absolutely needs the shape of such a value, log the
//!    *kind* (e.g. `"URL has non-HTTPS scheme"`) rather than the
//!    value itself.
//!
//! 3. **Never log ciphertext.** AEAD tags, IVs, ephemeral public
//!    keys, HPKE `enc` blobs, OHTTP request/response bodies, and
//!    WebSocket frames are all off-limits. Even a 32-byte prefix is
//!    enough to fingerprint a connection across logs.
//!
//! 4. **Prefer structured error types over free-form log messages.**
//!    A `CryptoError::Decryption` or `TorError::DaemonUnreachable`
//!    variant is itself a diagnostic signal. The caller — at the
//!    app boundary, not inside this crate — decides whether to emit
//!    a `log::debug!` with the variant name. The SDK's own modules
//!    should `return Err(...)` rather than log.
//!
//! 5. **Use stable short strings for any message that *does* fire.**
//!    `"AEAD tag mismatch"`, `"Tor daemon unreachable"`,
//!    `"OPAQUE envelope deserialisation failed"` — short, stable,
//!    and with no embedded user data. These help field debugging
//!    without leaking content.
//!
//! 6. **Never call `println!`, `eprintln!`, `dbg!`, `print!`, or
//!    `eprint!` from this crate.** The `print_stdout` and
//!    `print_stderr` clippy lints are configured at `deny` in
//!    `Cargo.toml` and enforce this automatically.
//!
//! ## Consumer policy
//!
//! Apps consuming the SDK are responsible for installing a log sink
//! (or not — since the SDK emits nothing, omitting a sink is a
//! valid choice and the SDK's default assumption). Sinks MUST
//! honour the same privacy rules: no PII, no ciphertext peek, no
//! plaintext user content, no analytics upload. `BoomLeft` apps
//! typically install `env_logger` for local development and ship
//! **no sink at all** in release builds.
//!
//! The FFI crate (`privacysuite-ffi`) is treated as a consumer for
//! the purposes of this policy: it does not log either, and the
//! UniFFI-generated Kotlin / Swift surfaces do not install platform
//! log sinks on the SDK's behalf. Platform apps may of course log
//! at their own layer, subject to their own privacy review.
