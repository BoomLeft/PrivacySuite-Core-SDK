# PrivacySuite Core SDK

> The zero-knowledge cryptographic foundation for every BoomLeft application.

PrivacySuite Core SDK is the shared cryptographic and privacy infrastructure used by all BoomLeft applications. It provides a production-grade, dual-crate architecture that makes it structurally impossible to store plaintext user data outside the user's device — and packages the full stack of primitives (key derivation, AEAD encryption, encrypted SQLite, E2EE CRDT sync, multi-tier privacy networking) into a single Tauri plugin that any developer can drop into their project.

---

## Architecture

PrivacySuite uses a two-crate workspace to separate pure cryptographic logic from Tauri bindings:

```
privacysuite-core/          # Pure Rust — NO Tauri dependency
  src/crypto.rs             # Key derivation + AEAD (XChaCha20-Poly1305 + Argon2id)
  src/storage.rs            # SQLCipher database abstraction
  src/crdt.rs               # Automerge document management
  src/sync.rs               # P2P + relay sync protocol
  src/networking.rs         # DoH, OHTTP, Arti privacy tiers

tauri-plugin-privacysuite/  # Tauri plugin wrapping core
  src/commands.rs           # #[tauri::command] wrappers
  src/models.rs             # Serde-serializable IPC types
  guest-js/                 # TypeScript bindings (tauri-specta)
```

---

## Features

- **Vault initialization** — Argon2id key derivation from user passphrase; 24-word BIP39 mnemonic recovery; Stronghold secure storage
- **XChaCha20-Poly1305 encryption** — Encrypt arbitrary payloads at rest; 192-bit nonce eliminates nonce collision concerns
- **SQLCipher integration** — Encrypted SQLite with SDK-derived keys; no per-operation PBKDF2 overhead
- **Automerge CRDT sync** — E2EE document sync via relay; relay never reads document content; LAN P2P and WebSocket relay transports
- **Device pairing** — X25519 DH key exchange via QR code for adding new devices to sync
- **Multi-tier privacy networking**:
  - **Tier 1 (Default):** DNS-over-HTTPS via Cloudflare/Quad9 — ISP cannot see DNS queries
  - **Tier 2 (Enhanced):** Oblivious HTTP (OHTTP) — relay server cannot correlate IP and request content
  - **Tier 3 (Maximum):** Tor via embedded Arti client — geographic anonymization
- **Certificate pinning** — All BoomLeft API connections use pinned certificates
- **OPAQUE authentication** — Zero-knowledge passphrase authentication (aPAKE); server never sees passwords
- **Forward secrecy** — Ephemeral key exchange for all authenticated sessions
- **Zeroization** — All sensitive values implement `Zeroize + ZeroizeOnDrop`

## Tech Stack

| Layer | Technology |
|---|---|
| Core crate | Pure Rust (no Tauri dependency) |
| Tauri plugin | tauri-plugin-privacysuite (Tauri 2.x) |
| Frontend | SolidJS + TypeScript bindings (tauri-specta) |
| Key derivation | Argon2id (RustCrypto, m=64MB, t=3, p=4) |
| AEAD | XChaCha20-Poly1305 (RustCrypto / orion) |
| Database | SQLCipher via rusqlite |
| CRDT sync | Automerge |
| Secure storage | Tauri Stronghold |
| Networking | Tier 1: hickory-dns DoH; Tier 2: OHTTP; Tier 3: Arti (embedded Tor) |
| Authentication | OPAQUE (RFC 9807) |
| Key exchange | X25519 (x25519-dalek) |
| Signing | Ed25519 (ed25519-dalek) |
| Hashing | BLAKE3 |

## Getting Started

### Prerequisites

- Rust 1.75+ and Cargo
- Node.js 20+ and pnpm
- Tauri 2.x project

### Add to your project

```toml
# Cargo.toml
[dependencies]
privacysuite-core = { path = "../PrivacySuite-Core-SDK/privacysuite-core" }
tauri-plugin-privacysuite = { path = "../PrivacySuite-Core-SDK/tauri-plugin-privacysuite" }
```

```rust
// src-tauri/src/main.rs
.plugin(tauri_plugin_privacysuite::init())
```

### Development

```bash
git clone https://github.com/mkfnch/PrivacySuite-Core-SDK
cd PrivacySuite-Core-SDK
cargo build
cargo test
```

## Security Design Principles

1. **Fail closed** — Every API fails with an explicit error rather than silently degrading to a weaker algorithm
2. **No WebCrypto** — All cryptographic operations run in Rust; browser-side crypto is forbidden
3. **RustCrypto only** — Pure Rust implementations preferred over ring (C/ASM) or openssl (FFI)
4. **Mobile-first parameters** — All Argon2id parameters validated on ARM mobile hardware
5. **Transport-agnostic sync** — CRDT sync works identically over LAN P2P, WebSocket relay, and future transports

## Transparency Label

| Field | Value |
|---|---|
| Data to servers | None (SDK is a local-only library) |
| Telemetry | None |
| Encryption | XChaCha20-Poly1305 |
| Key derivation | Argon2id (m=64MB, t=3, p=4) |
| Authentication | OPAQUE (aPAKE, RFC 9807) |
| Zero knowledge | Full — structurally impossible to store plaintext on servers |
| Subpoena disclosure | Nothing. The SDK is a local library; no data is stored or transmitted by the SDK itself. |

## License

Proprietary. Used internally by all BoomLeft applications. See [boomleft.com](https://boomleft.com) for details.

---

*Built by [BoomLeft](https://boomleft.com)*
