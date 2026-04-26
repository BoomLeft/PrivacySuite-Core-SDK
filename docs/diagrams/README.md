# Architecture & Protocol Diagrams

Visual companions to the documentation in [`README.md`](../../README.md) and the
module-level rustdoc. Each diagram is a self-contained SVG — open it in a
browser, drop it into a slide, or render it from the file directly. They use
only inline styles and system font fallbacks, so nothing external is fetched
when they render.

| # | Diagram | What it shows | Source |
|---|---|---|---|
| 1 | Workspace architecture | The three-crate layout: pure-Rust core wrapped by `tauri-plugin-privacysuite` and `privacysuite-ffi`. Reach across desktop, Android, iOS. Raw key bytes never cross the IPC / JNI / FFI boundary. | [`01-architecture.svg`](01-architecture.svg) |
| 2 | Vault key derivation pipeline | Passphrase → Argon2id (m=64 MB, t=3, p=4) → 256-bit `VaultKey` → BLAKE3/HKDF context-bound sub-keys for AEAD, storage, sync, and CRDT. Includes the BIP39 recovery path. | [`02-key-derivation.svg`](02-key-derivation.svg) |
| 3 | Multi-tier privacy networking | Tier 1 (DoH), Tier 2 (OHTTP), Tier 3 (Tor SOCKS5) side-by-side, with a column-by-column view of what the ISP, relay, gateway, and target each see. | [`03-privacy-tiers.svg`](03-privacy-tiers.svg) |
| 4 | OPAQUE auth flow | Sequence-style view of OPAQUE registration and login (Ristretto255 OPRF + Triple-DH, RFC 9807). The server never observes the password — at registration or login. | [`04-opaque-flow.svg`](04-opaque-flow.svg) |
| 5 | OHTTP topology | Two non-colluding parties (relay vs. gateway). What each one knows about the request, the client IP, and the target. The capsule construction is shown alongside. | [`05-ohttp-topology.svg`](05-ohttp-topology.svg) |
| 6 | E2EE CRDT sync via blind relay | Two paired devices syncing an Automerge document over a relay that holds only ciphertext. Highlights the four invariants enforced by `EncryptedTransport`. | [`06-e2ee-crdt-sync.svg`](06-e2ee-crdt-sync.svg) |
| 7 | Sync v2 wire frame | Byte-level layout of the v2 sync frame (`version || session_id || counter || ciphertext`), the AAD construction, replay-rejection rules, and the version-byte dispatch decoder. | [`07-sync-v2-frame.svg`](07-sync-v2-frame.svg) |
| 8 | AEAD ciphertext layout | XChaCha20-Poly1305 layout returned by `crypto::aead::encrypt`: 24-byte nonce, ciphertext, 16-byte Poly1305 tag. Why a 192-bit nonce, why context-binding via AAD. | [`08-aead-layout.svg`](08-aead-layout.svg) |
| 9 | Device pairing (X25519) | Out-of-band public-key exchange via QR code, ECDH, BLAKE3 derivation to a shared `VaultKey`. Low-order-point rejection and Ed25519 follow-up channel. | [`09-device-pairing.svg`](09-device-pairing.svg) |
| 10 | Zero-knowledge data residency | Trust-boundary view: where plaintext is allowed (in-memory on the device), where it never lives (disk and the network), and what the relay would surrender under subpoena. | [`10-zero-knowledge-residency.svg`](10-zero-knowledge-residency.svg) |

## Conventions

- **Green** highlights trusted, device-side state.
- **Indigo** marks encrypted material in motion (frames, capsules, ciphertext).
- **Amber** marks key material and high-value identifiers.
- **Red** marks observers / surfaces that must be assumed hostile (relays,
  gateways, network adversaries).

## Embedding

The diagrams are plain SVG with no external dependencies. To embed in
Markdown:

```markdown
![Workspace architecture](docs/diagrams/01-architecture.svg)
```

Or download a single file with `curl`:

```bash
curl -O https://raw.githubusercontent.com/BoomLeft/PrivacySuite-Core-SDK/main/docs/diagrams/01-architecture.svg
```
