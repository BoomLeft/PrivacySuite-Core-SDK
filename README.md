# PrivacySuite Core SDK

> The zero-knowledge cryptographic foundation for every BoomLeft application.

PrivacySuite Core SDK is the shared cryptographic and privacy infrastructure used by all BoomLeft applications. Its three-crate workspace makes it structurally impossible to store plaintext user data outside the user's device, and ships the same primitives — key derivation, AEAD encryption, encrypted SQLite, E2EE CRDT sync, multi-tier privacy networking, and OPAQUE authentication — to desktop (via the Tauri plugin) and mobile (via UniFFI bindings).

---

## Architecture

A pure-Rust core crate, with two thin wrappers for desktop and mobile:

```
privacysuite-core-sdk/      # Pure Rust core. NO Tauri / FFI / unsafe.
  src/lib.rs                #   #![forbid(unsafe_code)]  #![deny(warnings)]
  src/error.rs              # Unified, opaque CryptoError
  src/auth.rs               # OPAQUE aPAKE client                  (feature: auth)
  src/crdt.rs               # Automerge documents w/ E2EE persist  (feature: sync)
  src/sync.rs               # WebSocket relay transport            (feature: sync)
  src/storage.rs            # SQLCipher database wrapper           (feature: storage)
  src/networking.rs         # DoH, OHTTP, Tor SOCKS5               (feature: networking)
  src/privacy_utils.rs      # Tracking-parameter URL stripping
  src/crypto/
    aead.rs                 # XChaCha20-Poly1305 (AEAD)
    keys.rs                 # Argon2id KDF + VaultKey/Salt types
    kdf.rs                  # BLAKE3 sub-key derivation
    hkdf.rs                 # HKDF-SHA256 (RFC 5869)
    hash.rs                 # BLAKE3 content + keyed hashing
    mnemonic.rs             # BIP39 24-word recovery
    pairing.rs              # X25519 device pairing + Ed25519 sign
    pinning.rs              # SHA-256 SPKI certificate pinning
    util.rs                 # fill_random + constant-time compare

tauri-plugin-privacysuite/  # Tauri 2.x plugin wrapping core
  src/commands.rs           # IPC commands (raw key bytes never cross IPC)
  src/models.rs             # Serde IPC types (KeyHandle, EncryptedBlob, …)

privacysuite-ffi/           # UniFFI bindings for Android (Kotlin) + iOS (Swift)
  src/lib.rs                # Opaque Arc<Handle> types — keys stay on Rust heap
```

The core crate has zero Tauri or FFI dependencies, so the same audited code is used on every platform.

---

## Features

- **Vault initialisation** — Argon2id (m=64 MB, t=3, p=4) key derivation from user passphrase; 24-word BIP39 mnemonic recovery
- **XChaCha20-Poly1305 AEAD** — 192-bit random nonces eliminate collision concerns; AAD context binding prevents ciphertext relocation
- **SQLCipher integration** — Encrypted SQLite via `bundled-sqlcipher`; `cipher_memory_security = ON` enabled before keying so SQLCipher's own zeroization covers keying buffers
- **Automerge CRDT sync** — E2EE document sync over a WebSocket relay; the relay only forwards opaque ciphertext blobs, with a 16 MiB inbound message cap to prevent client OOM
- **Device pairing** — X25519 DH key exchange via QR code; low-order points are explicitly rejected (no zero shared secrets)
- **Multi-tier privacy networking**:
  - **Tier 1 (Default):** DNS-over-HTTPS via Cloudflare and Quad9 — ISP cannot observe DNS queries
  - **Tier 2 (Enhanced):** Oblivious HTTP (OHTTP, RFC 9458) — relay sees client IP but no request content; gateway sees content but no client IP
  - **Tier 3 (Maximum):** Tor via the standard external Tor SOCKS5 daemon — same architecture as Signal / Tor Browser
- **Certificate pinning** — SHA-256 SPKI pin verification with constant-time matching
- **OPAQUE authentication** — Zero-knowledge aPAKE (RFC 9807); server never sees passwords, even during registration
- **Forward secrecy** — Ephemeral X25519 / Ed25519 keys for pairing and signing
- **Tracking-parameter stripping** — Compile-in blocklist of 100+ known trackers (utm_*, fbclid, gclid, …); ASCII-case-insensitive match closes Unicode-lowercase bypasses
- **Zeroization everywhere** — Every secret type implements `Zeroize + ZeroizeOnDrop`; SQLCipher PRAGMA strings zeroized after use; HKDF intermediate blocks zeroized between iterations

## Tech Stack

| Layer | Technology |
|---|---|
| Workspace | Pure Rust, `#![forbid(unsafe_code)]`, `#![deny(warnings)]` |
| Tauri integration | tauri-plugin-privacysuite (Tauri 2.x) |
| Mobile bindings | privacysuite-ffi (UniFFI → Kotlin/Swift) |
| Key derivation | Argon2id (RustCrypto, m=64 MB, t=3, p=4) |
| Sub-key derivation | BLAKE3 derive_key + HKDF-SHA256 |
| AEAD | XChaCha20-Poly1305 (RustCrypto) |
| Database | SQLCipher via rusqlite (`bundled-sqlcipher`) |
| CRDT | Automerge |
| Sync transport | WebSocket via tokio-tungstenite |
| Networking | hickory-resolver (DoH), OHTTP, external Tor SOCKS5 (tokio-socks) |
| Authentication | OPAQUE / Ristretto255 / Triple-DH (RFC 9807) |
| Key exchange | X25519 (x25519-dalek) with low-order-point rejection |
| Signing | Ed25519 (ed25519-dalek) |
| Hashing | BLAKE3 (content + keyed MAC), SHA-256, SHA-512 |
| Mnemonic | BIP39 (24-word, constant-time wordlist lookup) |
| Randomness | OS entropy via `rand_core::OsRng` + `getrandom` |

## Getting Started

### Prerequisites

- Rust 1.88+ and Cargo (a `rust-toolchain.toml` pinning channel `1.93` ships in the repo)
- For mobile bindings: Android NDK + `cargo-ndk`, or Xcode for iOS
- For Tier 3 (Tor): an external Tor daemon listening on `127.0.0.1:9050`

### Add to your project

```toml
# Cargo.toml
[dependencies]
# Pure-Rust core. Pick the features you actually need; defaults to ["auth"].
privacysuite-core-sdk = { path = "../PrivacySuite-Core-SDK", default-features = false, features = ["full"] }

# Tauri 2.x desktop plugin.
tauri-plugin-privacysuite = { path = "../PrivacySuite-Core-SDK/tauri-plugin-privacysuite" }
```

```rust
// src-tauri/src/main.rs
.plugin(tauri_plugin_privacysuite::init())
```

For Android / iOS, depend on `privacysuite-ffi` and run `uniffi-bindgen` against the produced `.so` / `.dylib` to emit Kotlin / Swift bindings — raw key bytes never cross the JNI/FFI boundary.

### Cargo features

| Feature | Pulls in | Purpose |
|---|---|---|
| `auth` *(default)* | opaque-ke | OPAQUE client-side authentication |
| `storage` | rusqlite + bundled-sqlcipher | Encrypted on-device SQLite |
| `sync` | automerge, tokio, tokio-tungstenite, futures-util, serde, serde_json | E2EE CRDT documents + relay transport |
| `networking` | hickory-resolver, tokio-socks, tokio | DoH + OHTTP + Tor SOCKS5 |
| `full` | all of the above | Convenience grab-bag |

The base crate (no features) gives you AEAD, KDF, BIP39, device pairing, BLAKE3, HKDF, certificate pinning, and tracking-param stripping — everything that doesn't need network or DB.

### Development

```bash
git clone https://github.com/mkfnch/PrivacySuite-Core-SDK
cd PrivacySuite-Core-SDK
cargo build --all-features
cargo test --all-features

# Supply-chain audit (uses pinned advisory ignores documented in deny.toml + audit.toml):
cargo audit
```

## Security Design Principles

1. **Fail closed** — Every API returns an explicit error rather than silently degrading to a weaker algorithm.
2. **No browser crypto** — All cryptographic operations run in Rust; raw key bytes never cross the IPC / JNI / FFI boundary.
3. **RustCrypto only** — Pure Rust implementations preferred over `ring` (C/ASM) or `openssl` (FFI). `cargo-deny` blocks `openssl`/`openssl-sys` at the dependency level.
4. **Mobile-first parameters** — Argon2id parameters are validated on ARM mobile hardware.
5. **Transport-agnostic sync** — CRDT sync is trait-based; future transports (LAN P2P, Tor onion services) can drop in without protocol changes.
6. **Single audit point per primitive** — All randomness flows through `crypto::util::fill_random`; all BLAKE3 derivation through `crypto::kdf::blake3_derive`; all Argon2id derivation through one private helper. New crypto invariants land in one place.
7. **Supply-chain pinned** — Every direct dependency is `=`-pinned in `Cargo.toml`; `cargo-deny` enforces the policy in `deny.toml` and bans telemetry/analytics crates at the dependency level.

## Transparency Label

| Field | Value |
|---|---|
| Data to servers | None — the SDK is a local-only library. Apps may opt in to E2EE relay sync. |
| Telemetry | None. No analytics, no crash reporting, no metrics. `deny.toml` bans sentry/datadog/bugsnag/rollbar/opentelemetry/prometheus at the dependency level. |
| Encryption | XChaCha20-Poly1305 (AEAD with 192-bit nonces) |
| Key derivation | Argon2id (m=64 MB, t=3, p=4) |
| Authentication | OPAQUE (aPAKE, RFC 9807) |
| Zero knowledge | Full — structurally impossible to store plaintext on servers. The relay only sees opaque ciphertext blobs. |
| Subpoena disclosure | Nothing. The SDK is a local library; no data is stored or transmitted by the SDK itself. The relay holds only ciphertext it cannot decrypt. Equivalent to Signal's disclosure posture. |

## License

Proprietary. Used internally by all BoomLeft applications. See [boomleft.com](https://boomleft.com) for details.

---

*Built by [BoomLeft](https://boomleft.com)*
