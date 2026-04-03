# PrivacySuite-Core-SDK Adoption Audit

**Date:** 2026-04-03
**Scope:** Audit of SDK applicability across four planned BoomLeft projects
**SDK Version:** Current `main` (Rust 1.93, edition 2021)

---

## 1. SDK Capability Summary

The PrivacySuite-Core-SDK provides a zero-knowledge cryptographic foundation with the following modules:

| Module | Feature Flag | Core Capabilities |
|--------|-------------|-------------------|
| **Crypto (always on)** | — | XChaCha20-Poly1305 AEAD, Argon2id KDF, BIP39 mnemonic, X25519 DH, Ed25519 signing, BLAKE3 hashing |
| **Auth** | `auth` (default) | OPAQUE aPAKE (RFC 9807), zero-knowledge password authentication, session keys |
| **Storage** | `storage` | SQLCipher encrypted database, in-memory or file-backed |
| **CRDT Sync** | `sync` | Automerge E2EE documents, WebSocket relay transport, per-peer sync state |
| **Networking** | `networking` | DNS-over-HTTPS, Oblivious HTTP (stub), Tor via SOCKS5, certificate pinning |

**Integration paths:** Tauri 2.x plugin (IPC bridge), UniFFI (Android/iOS/Python), direct Rust dependency.

**Security posture:** `#![forbid(unsafe_code)]`, all secrets `Zeroize + ZeroizeOnDrop`, no telemetry (enforced via `deny.toml`), fail-closed error handling, constant-time comparisons, supply-chain auditing.

---

## 2. Repository Access Status

All four target repositories are **private or not yet created**. The `mkfnch` GitHub account has three public repos: `PrivacySuite-Core-SDK`, `boomleft-calculator`, and `SSC-MCP`. The audit below is based on inferred project scope from naming, platform targets, and the BoomLeft ecosystem context.

| Repository | Status | Inferred Purpose |
|-----------|--------|-----------------|
| `mkfnch/StaffMeeting` | Private / not created | Privacy-focused meeting or team collaboration tool |
| `mkfnch/ShroudKey` | Private / not created | Encrypted key or password manager |
| `mkfnch/Adaptor` | Private / not created | Privacy-preserving adapter or bridge between services/protocols |
| `mkfnch/boomleft-vault` | Private / not created | Terminal-based encrypted vault or secrets manager |

---

## 3. Per-Project SDK Adoption Analysis

### 3.1 StaffMeeting (Linux, macOS)

**Likely scope:** A privacy-first meeting management or collaboration tool -- potentially handling meeting notes, agendas, scheduling, or real-time communication for teams.

#### SDK modules applicable

| SDK Module | Relevance | Use Case |
|-----------|-----------|----------|
| **Crypto core** | **Critical** | Encrypt meeting notes, agendas, and attachments at rest |
| **Auth (OPAQUE)** | **Critical** | Zero-knowledge user authentication -- server never sees passwords |
| **Storage (SQLCipher)** | **Critical** | Local encrypted database for meeting data, participant lists, preferences |
| **CRDT Sync** | **Critical** | Real-time collaborative editing of shared meeting documents across devices |
| **Device Pairing** | **High** | Pair team members' devices for encrypted sync without a central server |
| **Networking (DoH/Tor)** | **Medium** | Private DNS resolution; optional Tor routing for sensitive organizations |
| **Mnemonic Recovery** | **Medium** | Account recovery for users who lose their passphrase |
| **Ed25519 Signing** | **High** | Authenticate meeting participants, sign minutes/action items |

**Adoption estimate: ~85-90% of SDK is directly usable.**

#### What the SDK currently lacks for StaffMeeting

- **Real-time presence / WebRTC signaling** -- The sync module handles CRDT document sync but not ephemeral presence indicators or live audio/video signaling.
- **Group key management** -- The SDK's pairing is 1:1 (device-to-device via X25519 DH). A meeting tool needs N-party key distribution (e.g., Sender Keys, MLS-like group ratchet).
- **Access control / permissions model** -- No concept of roles (organizer, participant, viewer) or per-document access policies.
- **Calendar/scheduling primitives** -- No time-based data structures or recurring event handling.

---

### 3.2 ShroudKey (Linux, macOS)

**Likely scope:** An encrypted password/key manager -- storing credentials, SSH keys, API tokens, TOTP secrets, and similar sensitive data behind a single vault passphrase.

#### SDK modules applicable

| SDK Module | Relevance | Use Case |
|-----------|-----------|----------|
| **Crypto core** | **Critical** | Encrypt every credential entry with XChaCha20-Poly1305; derive vault key via Argon2id |
| **Mnemonic Recovery** | **Critical** | 24-word BIP39 backup phrase for vault recovery |
| **Storage (SQLCipher)** | **Critical** | Encrypted local vault database |
| **Device Pairing** | **High** | Sync vault across user's devices via X25519 key agreement |
| **CRDT Sync** | **High** | Conflict-free merge when credentials are edited on multiple devices |
| **Auth (OPAQUE)** | **Medium** | If a relay/cloud sync service requires authentication |
| **Certificate Pinning** | **High** | Pin relay server certificates to prevent MITM during sync |
| **Networking (DoH/Tor)** | **Medium** | DNS privacy for relay connections; Tor for high-threat users |
| **Ed25519 Signing** | **Medium** | Sign vault snapshots to detect tampering |

**Adoption estimate: ~90-95% of SDK is directly usable.** This is the highest-affinity project.

#### What the SDK currently lacks for ShroudKey

- **TOTP/HOTP generation** -- No RFC 6238/4226 implementation for one-time password generation.
- **Clipboard management** -- No secure clipboard API (auto-clear after timeout).
- **Password generation** -- No configurable password/passphrase generator (length, character sets, diceware).
- **Blind index / encrypted search** -- The SDK has a research doc (`blind-index-api-ramifications.md`) but no implementation. A password manager needs to search entries without decrypting the entire vault.
- **Import/export formats** -- No parsers for KeePass (KDBX), 1Password, Bitwarden CSV/JSON, or other common vault export formats.
- **Browser extension bridge** -- No protocol for communicating with a browser extension for autofill.

---

### 3.3 Adaptor (Linux, macOS)

**Likely scope:** A privacy-preserving adapter or protocol bridge -- potentially translating between services, formats, or networks while maintaining zero-knowledge properties. Could be an integration layer between BoomLeft apps and external services.

#### SDK modules applicable

| SDK Module | Relevance | Use Case |
|-----------|-----------|----------|
| **Crypto core** | **Critical** | Encrypt data in transit between adapted services |
| **Networking (DoH/Tor)** | **Critical** | Route adapted traffic through privacy tiers; DNS privacy |
| **Certificate Pinning** | **Critical** | Pin certificates for all upstream/downstream connections |
| **Auth (OPAQUE)** | **High** | Authenticate to upstream services without exposing credentials to the adapter |
| **Storage (SQLCipher)** | **Medium** | Cache or queue encrypted payloads locally |
| **Ed25519 Signing** | **High** | Sign transformed payloads for integrity verification |
| **Device Pairing** | **Low-Medium** | If the adapter bridges between user devices |

**Adoption estimate: ~60-70% of SDK is directly usable.**

#### What the SDK currently lacks for Adaptor

- **Protocol adapters / codec framework** -- No abstraction for transforming between data formats (JSON, Protobuf, XML, etc.) or protocols (REST, gRPC, WebSocket, MQTT).
- **Proxy / relay server primitives** -- The SDK has a client-side `RelayTransport` but no server-side relay implementation.
- **Rate limiting / backpressure** -- No flow control primitives for bridging between services with different throughput characteristics.
- **OAuth2/OIDC client** -- No support for authenticating to external services via standard OAuth flows (the SDK only supports OPAQUE for its own auth).
- **Logging / audit trail** -- `clippy.toml` bans stdout/stderr; an adapter likely needs structured privacy-safe logging for debugging.

---

### 3.4 boomleft-vault (Terminal scripts)

**Likely scope:** A CLI/terminal-based encrypted vault for managing secrets, files, or configuration -- similar to `age`, `sops`, or `pass` but built on the BoomLeft privacy stack.

#### SDK modules applicable

| SDK Module | Relevance | Use Case |
|-----------|-----------|----------|
| **Crypto core** | **Critical** | Encrypt/decrypt files and secrets from the command line |
| **Mnemonic Recovery** | **Critical** | Initialize vault with 24-word recovery phrase |
| **Storage (SQLCipher)** | **High** | Encrypted local vault database for structured secrets |
| **AEAD (XChaCha20-Poly1305)** | **Critical** | Encrypt individual files with AAD context binding |
| **Argon2id KDF** | **Critical** | Derive vault key from passphrase |
| **Device Pairing** | **Medium** | Sync vault between terminal environments on different machines |
| **CRDT Sync** | **Medium** | Merge vault changes across machines |
| **Networking (Tor)** | **Low-Medium** | Optional Tor routing for remote vault sync |

**Adoption estimate: ~70-80% of SDK is directly usable.**

#### What the SDK currently lacks for boomleft-vault

- **CLI framework / argument parsing** -- The SDK is library-only with no CLI entry point, argument parsing, or terminal UI helpers.
- **File encryption API** -- The AEAD module encrypts byte slices, but there's no streaming file encryption (for large files that don't fit in memory).
- **Shell integration** -- No `eval`-able output format for injecting secrets into shell environments (like `vault exec` or `sops exec-env`).
- **Pipe/stdin support** -- No streaming encryption/decryption from stdin to stdout.
- **Age/GPG interop** -- No compatibility with existing file encryption standards.
- **Git integration** -- No git filter (clean/smudge) for transparent encryption in repos.

---

## 4. Cross-Project SDK Adoption Matrix

| SDK Capability | StaffMeeting | ShroudKey | Adaptor | boomleft-vault |
|---------------|:---:|:---:|:---:|:---:|
| XChaCha20-Poly1305 AEAD | Y | Y | Y | Y |
| Argon2id KDF | Y | Y | Y | Y |
| BIP39 Mnemonic | Y | Y | -- | Y |
| X25519 Device Pairing | Y | Y | -- | M |
| Ed25519 Signing | Y | M | Y | -- |
| OPAQUE Auth | Y | M | Y | -- |
| SQLCipher Storage | Y | Y | M | Y |
| Automerge CRDT Sync | Y | Y | -- | M |
| WebSocket Relay | Y | Y | -- | M |
| DNS-over-HTTPS | M | M | Y | -- |
| Tor/SOCKS5 | M | M | Y | M |
| Certificate Pinning | M | Y | Y | -- |
| Tauri Plugin Bridge | Y | Y | Y | -- |
| UniFFI Bindings | -- | -- | -- | -- |

**Y** = Yes, directly applicable | **M** = Maybe, depending on features | **--** = Not needed

---

## 5. Suggested SDK Updates (Gap Analysis)

The following gaps appeared across multiple projects and represent the highest-leverage additions to the SDK:

### 5.1 High Priority (benefits 3+ projects)

#### 1. Group Key Management
**Projects:** StaffMeeting, ShroudKey (shared vaults), boomleft-vault (team secrets)
**What:** Extend the 1:1 `X25519` pairing to support N-party key distribution. Consider Sender Keys (Signal-style) or a simplified MLS-like tree ratchet.
**Why:** Every multi-user or multi-device project needs to encrypt for a group, not just a pair.
**Suggested module:** `src/crypto/group.rs` behind `sync` feature flag.

#### 2. Streaming / File Encryption API
**Projects:** boomleft-vault, ShroudKey (attachments), Adaptor (payload transformation)
**What:** A streaming encryption wrapper around XChaCha20-Poly1305 that processes data in chunks with authenticated headers. Consider the `STREAM` construction (nonce + counter + last-block flag).
**Why:** The current `encrypt(key, plaintext, aad)` requires the entire plaintext in memory. Large files (vault backups, meeting recordings, adapted payloads) need streaming.
**Suggested module:** `src/crypto/stream.rs` behind a new `stream` feature flag.

#### 3. Blind Index / Encrypted Search
**Projects:** ShroudKey, StaffMeeting, boomleft-vault
**What:** Implement the blind index design already documented in `docs/research/blind-index-api-ramifications.md`. HMAC-based truncated index for exact-match queries on encrypted SQLCipher data.
**Why:** Searching encrypted data without full decryption is essential for any vault or document-based application. The research is already done -- it needs implementation.
**Suggested module:** `src/storage/blind_index.rs` behind `storage` feature flag.

#### 4. Password / Passphrase Generator
**Projects:** ShroudKey, boomleft-vault, StaffMeeting (meeting passcodes)
**What:** Cryptographically secure password generator with configurable length, character sets, and a diceware/EFF wordlist mode for passphrase generation.
**Why:** Any app that manages credentials or access codes needs to generate strong passwords. Reusing `OsRng` and the BIP39 wordlist infrastructure makes this low-effort.
**Suggested module:** `src/crypto/generate.rs` (always available, uses existing `rand` + `subtle`).

### 5.2 Medium Priority (benefits 2 projects)

#### 5. TOTP/HOTP One-Time Passwords
**Projects:** ShroudKey, StaffMeeting (meeting 2FA)
**What:** RFC 6238 (TOTP) and RFC 4226 (HOTP) implementation using existing `hmac` + `sha1`/`sha2` dependencies.
**Why:** A password manager without TOTP support is incomplete. The SDK already has HMAC -- this is a thin wrapper.
**Suggested module:** `src/crypto/otp.rs` behind a new `otp` feature flag.

#### 6. OAuth2/OIDC Client
**Projects:** Adaptor, StaffMeeting (calendar integrations)
**What:** A minimal OAuth2 authorization code + PKCE client that stores tokens in SQLCipher and refreshes them automatically.
**Why:** Connecting to external services (Google Calendar, Microsoft Teams, etc.) requires OAuth2. Without it, every app re-implements token management.
**Suggested module:** `src/auth/oauth.rs` behind a new `oauth` feature flag (requires `storage` + `networking`).

#### 7. CLI / Terminal Helpers
**Projects:** boomleft-vault, Adaptor (if CLI-based)
**What:** A thin CLI adapter layer: passphrase prompt with terminal echo suppression, progress bars for encryption, and `eval`-able secret output for shell integration.
**Why:** The SDK currently only has Tauri and UniFFI integration paths. Terminal apps need a third path.
**Suggested module:** `privacysuite-cli/` as a new workspace member, or a `cli` feature flag on the core crate.

#### 8. Structured Privacy-Safe Logging
**Projects:** Adaptor, StaffMeeting (server components)
**What:** A logging facade that redacts sensitive fields (keys, tokens, PII) before output. Compatible with `tracing` crate but with redaction filters enforced at the type level.
**Why:** `clippy.toml` correctly bans raw stdout/stderr, but server-side components need some form of operational logging. A privacy-safe logger bridges this gap.
**Suggested module:** `src/logging.rs` behind a new `logging` feature flag.

### 5.3 Lower Priority (benefits 1 project but high value)

#### 9. Relay Server Implementation
**Projects:** Adaptor (directly), all projects (indirectly as sync infrastructure)
**What:** A reference relay server implementation that complements the existing client-side `RelayTransport`. Accepts WebSocket connections, forwards opaque encrypted frames, and manages room/channel routing.
**Why:** Every app using CRDT sync needs a relay. Currently, each project must build its own. A reference server in the SDK workspace prevents duplication.
**Suggested location:** `privacysuite-relay/` as a new workspace member.

#### 10. LAN Discovery Implementation
**Projects:** StaffMeeting (local team sync), ShroudKey (local device sync)
**What:** Complete the `LanDiscovery` stub in `src/sync.rs` with mDNS/DNS-SD announcement and discovery via `mdns-sd` crate.
**Why:** Currently marked as placeholder. LAN P2P sync is a key differentiator for zero-server-trust architectures.

---

## 6. Priority Ranking Summary

| # | Suggested Addition | Benefiting Projects | Effort Estimate | Dependencies |
|---|-------------------|--------------------|----|-----|
| 1 | Group Key Management | 3 | High | `x25519-dalek`, new design |
| 2 | Streaming File Encryption | 3 | Medium | `chacha20poly1305` |
| 3 | Blind Index (implement research) | 3 | Medium | `storage` feature |
| 4 | Password Generator | 3 | Low | `rand`, existing infra |
| 5 | TOTP/HOTP | 2 | Low | `hmac`, `sha1` |
| 6 | OAuth2/OIDC Client | 2 | High | `networking` + `storage` |
| 7 | CLI Helpers | 2 | Medium | New workspace member |
| 8 | Privacy-Safe Logging | 2 | Medium | `tracing` crate |
| 9 | Relay Server | All (infra) | High | `tokio`, `tokio-tungstenite` |
| 10 | LAN Discovery | 2 | Medium | `mdns-sd` crate |

---

## 7. Recommendation

The SDK is exceptionally well-designed for its current scope. **ShroudKey** has the highest natural affinity (~90-95%) and should be the first project to fully adopt the SDK. **StaffMeeting** is close behind (~85-90%) but needs group key management before it can fully leverage E2EE collaboration.

The two highest-leverage SDK additions are:
1. **Group key management** -- unlocks multi-user encryption for every project
2. **Password generator** -- trivial to implement, immediately useful for ShroudKey and boomleft-vault

The blind index implementation should also be prioritized since the research document already exists and it unblocks encrypted search across all vault-style applications.
