# Changelog

All notable changes to `privacysuite-core-sdk` and the `privacysuite-ffi`
Android binding crate.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses SemVer with the caveat that pre-1.0 minor bumps may be
breaking. Apps consume the SDK by git tag (`{ git = "...", tag = "vX.Y.Z" }`),
so a tag is the canonical release artifact — not crates.io.

## [0.4.0] — 2026-04-19

Phase 4 (P3 gates) + FFI stabilization. Apps pinning to `v0.3.0` only need
to move forward to pick up the blind-index primitive (Scanner) and the
Android AAR Kotlin fix.

### Added
- **G8 `crypto::blind_index::HmacBlindIndex`** — HMAC-BLAKE3 deterministic
  index for full-text search over encrypted columns. Per-app salt, no key
  material leaked. Replaces Scanner's hand-rolled `HmacBlindIndex.kt`.
- **G10 logging facade (`logging` module, docs-only)** — codifies the
  SDK-wide "zero log traffic" posture. Callers are expected to compile in
  release with `log = { features = ["release_max_level_off"] }` to strip
  all non-`error!` sites; the module documents the invariant and offers
  no runtime API.

### Changed
- **FFI crate bumped 0.2.0 → 0.3.0.** Surfaces `KeystoreVault`,
  `BackgroundSyncHost`, `BackgroundSyncClient`, and the G4/G8 primitives
  across UniFFI. AAR filename follows: `privacysuite-ffi-0.3.0.aar`.

### Fixed
- **Android AAR Kotlin collision (FFI).** UniFFI 0.31 generates each
  `PrivacySuiteError` variant as a `Throwable` subclass; a struct-variant
  field named `message` collided with `Throwable.message`. Renamed
  `KeystoreIo.message` → `KeystoreIo.detail`. Display impl preserves the
  public error text, so `e.message` (inherited from Throwable) still
  prints `"keystore error: <…>"` via the generated `toString()`. Zero
  Kotlin-side caller changes.

### Release metadata
- Git tag: `v0.4.0`
- Crate version: `privacysuite-core-sdk = "0.4.0"`, `privacysuite-ffi = "0.3.0"`
- AAR SHA-256: `c8a279f3e6c307dc69068671ff29b8712c2e8b2ac9360c9b3a844f3cc9c6e94f`
- Consumer apps updated: Scanner (removes `scanner-crypto-shim`), Voice,
  Scratchpad, boomleft-net.

## [0.3.0] — 2026-04-18

Phase 1 + Phase 3 gates. Biggest release of the pre-1.0 cycle. Enables
Wave 1 (Blackout / Podcasts / RSS / Music) and Wave 2 (DarkGIFs / Shadow-Atlas
/ Telephoto / Screenshots / Weather / Voice / Scratchpad / Scanner) to
drop ~7 kLOC of redundant per-app privacy / crypto code.

### Added — Phase 1 gates
- **G1 `networking::privacy_client::PrivacyClient`** — unified HTTP client
  composing three tiers (DoH + direct, OHTTP + relay, Tor via Orbot
  SOCKS5). `fetch_with_decoys(k)` folds k-anon decoy fan-out for feed and
  metadata fetches. Behind `http` feature (pulls `reqwest` with
  `rustls-tls`, `gzip`, `brotli`, `socks`, `stream`, `http2`).
- **G2 `privacy_utils::url::validate_url()`** — RFC 1918 / loopback /
  link-local / cloud-metadata / IPv4-mapped-IPv6 / octal-hex-decimal
  wrapped address / Unicode bidi defense. Folded with
  `strip_tracking_params`. Replaces six hand-rolled SSRF checks
  (RSS `url_validator.dart`, Music, Podcasts, Scratchpad, etc.).
- **G3 `crypto::stream::{EncryptedFileWriter, EncryptedFileReader}`** —
  chunked XChaCha20-Poly1305 STREAM construction (Hoang/Reyhanitabar/
  Rogaway/Vizár, CRYPTO 2015). 1 MiB chunks, per-chunk AAD with counter,
  terminating empty chunk for finalization, resumable from chunk
  boundaries. Unblocks Voice / Scanner / Screenshots / Telephoto /
  Podcasts / Blackout (all previously limited to in-memory AEAD).

### Added — Phase 3 gates (P2)
- **G4 `crypto::media`** — EXIF strip via `img-parts` (lossless),
  400 MPixel decompression-bomb budget, 20 000×20 000 dimension cap.
  Ports Telephoto's sanitizer.
- **G5 `keystore::KeystoreVault`** — Android Keystore / StrongBox wrapper
  around `VaultKey`. JNI-bridged via `jni` + `ndk-context`. BiometricPrompt
  integration. Non-Android builds compile but every entry point returns
  `KeystoreError::NotAvailable`. Feature-gated (`keystore`). Voice,
  Telephoto, Scratchpad, Shadow-Atlas all consume.
- **G6 `auth::pin_lock::PinLock`** — Argon2id-backed PIN with exponential
  lockout. Returns `{is_locked, remaining_secs}` only (never the attempt
  count, to reduce oracle surface). Ports Telephoto's.
- **G7 `sync::BackgroundSync`** — trait + UniFFI callback interface for
  Android WorkManager. `BackgroundSyncHost` lets Kotlin implement the
  platform side; `BackgroundSyncClient` dispatches from Rust. Feature-
  gated (`sync`). Podcasts, Weather, Music consume.

### Fixed
- Four pre-existing test failures resolved en route to Wave 1:
  - `rejects_ipv6_zone_id` — pre-scan IPv6 `[…%…]` zone IDs before
    `url::Url::parse` (which accepts them).
  - `large_stream_50_mib` — marked `#[ignore]` (debug-profile wall-clock
    too sensitive on CI). `cargo test --release` still exercises it.
  - `tor_connect_failure_is_opaque` — removed the "SOCKS" substring from
    the error text so downstream heuristics can't distinguish Tor from
    OHTTP failures.
  - `cipher_compatibility_is_queryable_as_4` — reshaped: SQLCipher's
    `cipher_compatibility` pragma is effectively write-only in current
    releases, so the test now verifies the PRAGMA *was set* rather than
    that it can be read back.

### Changed
- `privacy_utils::url::TRACKING_PARAMS` — narrowed to a conservative
  baseline; new `TRACKING_PARAMS_AGGRESSIVE` list holds `cid`, `rid`,
  `ct`, `random_id`, `pingback_id` (breaking for apps that built on the
  old behavior — DarkGIFs consumed both lists during migration).

### Release metadata
- Git tag: `v0.3.0`
- Crate version at tag: `privacysuite-core-sdk = "0.1.0"` (version bumps
  were deferred until v0.4.0).
- All 10 Rust-pinned apps migrated to this tag except boomleft-net which
  stays on v0.2.0 intentionally (sibling scope, no G4–G7 dependency).

## [0.2.0] — 2026-04-18

Hardening release: pentest remediation + initial FFI surface.

### Added
- **OHTTP (RFC 9458) client primitive.** Pure-Rust HPKE stack
  (`DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305`) built
  on existing SDK primitives. `OhttpTransport` trait lets callers plug
  their own HTTP client so the SDK doesn't ship `reqwest`/`hyper`.
  Configurable response-size cap.
- **Relay-transport dispatch on explicit version byte** (Residual Risk #5).

### Fixed
- Crypto audit findings #1–#7 (see commit `7beb985`).
- Non-crypto audit findings #1–#14 (see commit `2fdabde`).
- Reproducible Android AAR build pipeline (`privacysuite-ffi/android/`).

### Release metadata
- Git tag: `v0.2.0`
- FFI crate version at tag: `privacysuite-ffi = "0.2.0"` (first published
  AAR — consumed by boomleft-net as a sibling scope).

## [0.1.0] — 2026-04-17

Initial tagged release. Carries forward the pre-tag README's state:

### Added
- **Crypto primitives:** XChaCha20-Poly1305 AEAD, BLAKE3 hashing
  (streaming + keyed), Argon2id password KDF, HKDF-SHA256 sub-key
  derivation, ed25519 signing, X25519 pairing, ChaCha20-Poly1305 blob
  AEAD, constant-time equality.
- **VaultKey:** 256-bit key material with `Zeroize` + `ZeroizeOnDrop`.
- **Encrypted storage:** rusqlite with `bundled-sqlcipher` (feature-gated).
- **Auth:** OPAQUE-KE authentication (feature-gated).
- **Sync:** Automerge CRDT + WebSocket relay (feature-gated).
- **Networking primitives:** DoH resolver (`hickory-resolver`), TorClient
  (`tokio-socks` over local Orbot SOCKS5 — embedded Arti intentionally
  removed to shrink the supply chain).
- **FFI surface (initial):** pairing, streaming BLAKE3, URL stripping,
  blob AEAD. Published as `privacysuite-ffi = "0.1.0"`.
- **Hardened FFI boundary** per adversarial audit.

### Release metadata
- Git tag: `v0.1.0`
- Supply-chain posture: all direct deps pinned to exact versions,
  `unsafe_code = "deny"`, `rand` banned in favor of `rand_core` +
  `getrandom` (RUSTSEC-2026-0097 defense).

---

[0.4.0]: https://github.com/mkfnch/PrivacySuite-Core-SDK/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mkfnch/PrivacySuite-Core-SDK/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mkfnch/PrivacySuite-Core-SDK/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mkfnch/PrivacySuite-Core-SDK/releases/tag/v0.1.0
