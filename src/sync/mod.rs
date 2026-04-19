//! E2EE sync protocol with LAN peer-to-peer and WebSocket relay transports.
//!
//! # Architecture
//!
//! The sync protocol enables multi-device document synchronisation where the
//! relay server **never** reads document content — it only passes E2EE blobs
//! between devices. The current transport is [`RelayTransport`], a WebSocket
//! relay via `tokio-tungstenite`.
//!
//! [`EncryptedTransport`] wraps any [`SyncTransport`] implementation,
//! encrypting every message with XChaCha20-Poly1305 before it leaves the
//! device and decrypting on receipt.
//!
//! # Wire Format — v2 (Audit 2 Finding #10, Residual Risk #5)
//!
//! Each [`SyncMessage`] carries an opaque `payload` field. When sent through
//! an [`EncryptedTransport`], the payload is:
//!
//! ```text
//! version_byte(1) = 0x02 || session_id(16) || send_counter_be(8) || aead_ciphertext
//! ```
//!
//! The AEAD AAD is:
//!
//! ```text
//! "privacysuite:sync:v2" || session_id(16) || send_counter_be(8)
//! ```
//!
//! `session_id` is 16 random bytes generated when [`EncryptedTransport::new`] is
//! called, and `send_counter` is a monotonically increasing `u64` on both
//! send and receive sides. The receiver rejects frames whose counter does
//! not strictly advance, which prevents a hostile relay from replaying old
//! frames recorded under the same `VaultKey` (see Audit 2 Finding #10).
//!
//! # Versioning (Residual Risk #5)
//!
//! The leading byte of every frame is an explicit version tag. The decoder
//! inspects byte 0 before doing anything else and dispatches on it:
//!
//! - `0x02` — current v2 frame; decoded as documented above.
//! - `0x01` — v1 frame (the pre-hardening layout, AAD
//!   `"privacysuite:sync:v1"` and no replay-binding). Rejected with
//!   [`SyncError::Legacy`] carrying a clear operator-facing message; the
//!   decoder deliberately does not attempt to parse the rest, so a v1
//!   peer cannot use framing-probe timing to fingerprint which v2 field
//!   the reject happened on.
//! - any other byte — rejected with [`SyncError::Protocol`]
//!   (`"unknown sync version"`). This covers corrupted frames, future
//!   v3+ revisions reaching an older build, and frames from a non-sync
//!   producer that happens to hit the transport.
//!
//! Truncated frames (0 bytes, or any length below the v2 header) are
//! rejected with [`SyncError::Protocol`] (`"truncated sync frame"`) at
//! the same decoder entry point, before any AEAD work is attempted.
//!
//! This layout gives v3+ a clean upgrade path: bumping
//! [`SYNC_VERSION_V2`] is a one-site change, and older clients surface
//! a clear typed error rather than silently failing an AEAD tag verify.
//!
//! # Background scheduling (G7)
//!
//! Wire-level sync is only half of the story — consumer apps also need a
//! way to schedule *periodic* sync work (e.g. "refresh feeds every
//! 30 minutes on unmetered Wi-Fi, not when battery is low"). That lives
//! in the [`background`] submodule: a platform-agnostic trait
//! ([`background::BackgroundSyncHost`]) plus SDK-owned schema types
//! ([`background::SyncJob`], [`background::SyncConstraints`],
//! [`background::BackoffPolicy`]) that every consumer app converges on.
//! The SDK intentionally does not bind Android's `WorkManager` directly;
//! consumer apps implement the trait on top of whichever platform
//! scheduler is natively appropriate. See the [`background`] module
//! docs for the rationale.

pub mod background;

use std::fmt;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::keys::VaultKey;
use crate::crypto::pinning::CertificatePinner;

/// AAD prefix bound to every v2 sync encryption operation.
///
/// The full AAD is `SYNC_AAD_V2 || session_id(16) || send_counter_be(8)`.
const SYNC_AAD_V2: &[u8] = b"privacysuite:sync:v2";

/// On-wire version byte for the v2 framing (see module doc).
const SYNC_VERSION_V2: u8 = 0x02;

/// On-wire version byte for the deprecated v1 framing.
///
/// Retained as a named constant so the decoder can emit a precise
/// [`SyncError::Legacy`] instead of a generic "unknown version" error
/// when a peer hasn't yet upgraded. The SDK never *produces* v1 frames.
const SYNC_VERSION_V1: u8 = 0x01;

/// Length of the per-session random identifier bound into the AAD.
const SESSION_ID_LEN: usize = 16;

/// Length of the per-message send counter bound into the AAD.
const SEND_COUNTER_LEN: usize = 8;

/// Length of the v2 framing header: `version || session_id || counter`.
const FRAME_HEADER_LEN: usize = 1 + SESSION_ID_LEN + SEND_COUNTER_LEN;

/// SECURITY: Upper bound on a single inbound sync message, in bytes.
///
/// Without this cap, a malicious or compromised relay could send an arbitrarily
/// large WebSocket frame and exhaust client memory. 16 MiB is far larger than
/// any legitimate Automerge sync message in typical use.
const MAX_SYNC_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// SECURITY: Upper bound on a single WebSocket frame. Set to the same value
/// as the full-message cap because we don't fragment.
const MAX_SYNC_FRAME_BYTES: usize = MAX_SYNC_MESSAGE_BYTES;

/// SECURITY: Upper bound on consecutive non-data frames (Ping/Pong/Continue)
/// before [`RelayTransport::recv`] returns an error.
///
/// Tungstenite auto-Pongs every Ping, so a hostile relay can otherwise
/// pump an unbounded stream of Ping frames that the inner event loop
/// silently consumes — starving the caller of `recv().await` results.
/// 64 is well above any legitimate heartbeat cadence (typical keepalive
/// is ~30s, one frame per 30s means 32 minutes of pure heartbeats).
/// See Audit 2 Finding #11.
const MAX_CONSECUTIVE_CONTROL_FRAMES: usize = 64;

/// Errors that can occur during sync operations.
#[derive(Debug)]
pub enum SyncError {
    /// A transport-level error (e.g., network I/O failure).
    Transport(String),
    /// A protocol-level error (e.g., malformed message, ping flood, or
    /// replayed counter).
    Protocol(String),
    /// AEAD encryption failed.
    Encryption,
    /// AEAD decryption or authentication failed.
    Decryption,
    /// The remote end closed the connection.
    ConnectionClosed,
    /// TLS certificate pinning rejected the relay's presented certificate.
    ///
    /// Carries no diagnostic payload to avoid leaking which pin failed.
    CertificatePinMismatch,
    /// A frame from a peer speaking an older (pre-v2) wire format was
    /// received. The peer must upgrade; the SDK never parses v1 frames.
    ///
    /// The message is operator-facing and safe to surface to the user:
    /// it does not depend on any frame contents beyond the leading
    /// version byte.
    Legacy(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Encryption => f.write_str("sync encryption failed"),
            Self::Decryption => f.write_str("sync decryption failed"),
            Self::ConnectionClosed => f.write_str("connection closed"),
            Self::CertificatePinMismatch => {
                f.write_str("relay certificate did not match any configured pin")
            }
            Self::Legacy(msg) => write!(f, "legacy peer: {msg}"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Serialisable envelope for the sync protocol.
///
/// The `payload` contains either plaintext CRDT data (before encryption) or
/// an E2EE blob (after encryption by [`EncryptedTransport`]).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncMessage {
    /// Encrypted (or plaintext) CRDT sync data.
    pub payload: Vec<u8>,
}

/// Async transport for sending and receiving [`SyncMessage`]s.
///
/// Implementors must be `Send` so they can be used across Tokio tasks.
pub trait SyncTransport: Send {
    /// Sends a message through the transport.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Transport`] on I/O failure or
    /// [`SyncError::ConnectionClosed`] if the connection is gone.
    fn send(
        &mut self,
        msg: &SyncMessage,
    ) -> impl std::future::Future<Output = Result<(), SyncError>> + Send;

    /// Receives the next message from the transport.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Transport`] on I/O failure,
    /// [`SyncError::Protocol`] on deserialization failure, or
    /// [`SyncError::ConnectionClosed`] if the stream has ended.
    fn recv(
        &mut self,
    ) -> impl std::future::Future<Output = Result<SyncMessage, SyncError>> + Send;

    /// Gracefully closes the transport.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Transport`] if the close handshake fails.
    fn close(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), SyncError>> + Send;
}

/// WebSocket relay transport backed by `tokio-tungstenite`.
///
/// The relay server only forwards opaque binary frames — it never has access
/// to decryption keys and therefore cannot read message content.
#[derive(Debug)]
pub struct RelayTransport {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl RelayTransport {
    /// Connects to a WebSocket relay at the given URL **without TLS
    /// certificate pinning**.
    ///
    /// The relay is trusted via the host OS trust store only (native-tls
    /// → SecureTransport / SChannel / OpenSSL). A compromised CA or a
    /// corporate MITM proxy with a root installed can therefore
    /// terminate the WSS handshake and observe every (still-E2EE)
    /// frame. Use [`RelayTransport::connect_with_pinner`] to add a
    /// post-handshake SPKI-pin check.
    ///
    /// # Security
    ///
    /// Applies strict frame and message size limits (see
    /// [`MAX_SYNC_MESSAGE_BYTES`] / [`MAX_SYNC_FRAME_BYTES`]) so a malicious
    /// relay cannot exhaust client memory by sending oversized frames.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Transport`] if the TCP or TLS handshake fails.
    pub async fn connect(url: &str) -> Result<Self, SyncError> {
        Self::connect_with_pinner(url, None).await
    }

    /// Connects to a WebSocket relay at the given URL, optionally
    /// enforcing a TLS certificate pin against the peer's full
    /// DER-encoded certificate.
    ///
    /// # Pin scope
    ///
    /// The pin is compared against `SHA-256(full_peer_certificate_der)`
    /// — i.e. the hash of the **entire** X.509 leaf certificate, not
    /// the SPKI-only subset used by [`CertificatePinner`]'s doc
    /// example. This is a stricter bind (rotating the CA-issued
    /// certificate invalidates the pin even if the public key is
    /// re-used), which is correct for a deployment where the relay
    /// operator controls the full rotation schedule. Callers whose
    /// operational model requires SPKI-only pinning should compute the
    /// hash from the raw SPKI bytes and pre-load the resulting pin.
    ///
    /// # Behavior change vs. earlier SDK versions
    ///
    /// Previous SDK releases had no pin hook whatsoever. Consumers
    /// that are content with the host OS trust store should call
    /// [`RelayTransport::connect`] (which forwards to this method with
    /// `pinner = None`) and see identical behaviour. Consumers that
    /// supply a `Some(pinner)` argument will observe an additional
    /// post-handshake check that can fail with
    /// [`SyncError::CertificatePinMismatch`].
    ///
    /// # Errors
    ///
    /// - [`SyncError::Transport`] on TCP/TLS handshake failure.
    /// - [`SyncError::CertificatePinMismatch`] when a pinner is
    ///   supplied and the server certificate does not match any pin.
    /// - [`SyncError::Protocol`] if the connection is over a non-TLS
    ///   URL (e.g. `ws://`) while a pinner is supplied — pinning
    ///   against a non-TLS handshake is meaningless and the SDK
    ///   refuses to silently proceed.
    pub async fn connect_with_pinner(
        url: &str,
        pinner: Option<&CertificatePinner>,
    ) -> Result<Self, SyncError> {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
        use tokio_tungstenite::{connect_async_tls_with_config, Connector};

        // SECURITY: Cap inbound message and frame size so a hostile relay
        // cannot exhaust client memory. All other fields use the crate
        // defaults to avoid coupling to internal layout that may shift
        // between patch versions.
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_SYNC_MESSAGE_BYTES);
        config.max_frame_size = Some(MAX_SYNC_FRAME_BYTES);

        let connector: Option<Connector> = if pinner.is_some() {
            // Build a native-tls connector and hand it to tokio-
            // tungstenite. After the handshake we post-verify the peer
            // certificate; see the pin-check below.
            let tls = native_tls::TlsConnector::builder()
                .build()
                .map_err(|e| SyncError::Transport(e.to_string()))?;
            Some(Connector::NativeTls(tls))
        } else {
            None
        };

        let (ws, _response) =
            connect_async_tls_with_config(url, Some(config), false, connector)
                .await
                .map_err(|e| SyncError::Transport(e.to_string()))?;

        if let Some(pinner) = pinner {
            verify_peer_certificate_pin(&ws, pinner)?;
        }

        Ok(Self { ws })
    }
}

/// Post-handshake TLS pin check. Pulls the peer certificate off the
/// `native-tls` `TlsStream`, SHA-256-hashes the full DER cert, and
/// verifies against the provided [`CertificatePinner`].
///
/// Returns [`SyncError::Protocol`] if the connection is not TLS (a
/// `ws://` URL with a pinner argument is a caller bug — pinning has no
/// meaning on plaintext).
fn verify_peer_certificate_pin(
    ws: &tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    pinner: &CertificatePinner,
) -> Result<(), SyncError> {
    use tokio_tungstenite::MaybeTlsStream;

    let inner = ws.get_ref();
    let tls_stream = match inner {
        MaybeTlsStream::NativeTls(s) => s,
        MaybeTlsStream::Plain(_) => {
            return Err(SyncError::Protocol(
                "cannot pin a non-TLS relay connection".into(),
            ));
        }
        _ => {
            return Err(SyncError::Protocol(
                "unsupported TLS backend for pinning".into(),
            ));
        }
    };

    let cert = tls_stream
        .get_ref()
        .peer_certificate()
        .map_err(|e| SyncError::Transport(e.to_string()))?
        .ok_or(SyncError::CertificatePinMismatch)?;

    let der = cert
        .to_der()
        .map_err(|e| SyncError::Transport(e.to_string()))?;

    // SHA-256 over the full DER leaf certificate.
    let mut hash = [0u8; 32];
    {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&der);
        hash.copy_from_slice(&digest);
    }

    if !pinner.verify(&hash) {
        hash.zeroize();
        return Err(SyncError::CertificatePinMismatch);
    }
    hash.zeroize();
    Ok(())
}

impl SyncTransport for RelayTransport {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
        let serialized =
            serde_json::to_vec(msg).map_err(|e| SyncError::Protocol(e.to_string()))?;
        self.ws
            .send(WsMessage::Binary(serialized.into()))
            .await
            .map_err(|e| SyncError::Transport(e.to_string()))
    }

    async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
        // SECURITY (Audit 2 Finding #11): cap consecutive non-data
        // frames so a hostile relay cannot DoS the caller by pumping
        // Ping frames that tungstenite silently auto-Pongs. Reset on
        // every data frame.
        let mut consecutive_control: usize = 0;
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    // SECURITY: Defense-in-depth bound check. The tungstenite
                    // config already caps inbound messages, but re-verify
                    // here so any config regression cannot translate into an
                    // unbounded allocation.
                    if data.len() > MAX_SYNC_MESSAGE_BYTES {
                        return Err(SyncError::Protocol(
                            "inbound message exceeds size limit".into(),
                        ));
                    }
                    return serde_json::from_slice(&data)
                        .map_err(|e| SyncError::Protocol(e.to_string()));
                }
                Some(Ok(WsMessage::Text(text))) => {
                    if text.len() > MAX_SYNC_MESSAGE_BYTES {
                        return Err(SyncError::Protocol(
                            "inbound message exceeds size limit".into(),
                        ));
                    }
                    return serde_json::from_str(&text)
                        .map_err(|e| SyncError::Protocol(e.to_string()));
                }
                Some(Ok(WsMessage::Close(_))) | None => {
                    return Err(SyncError::ConnectionClosed);
                }
                Some(Ok(_)) => {
                    // Ping / Pong / Frame continuation. Bound the
                    // count so a ping-flooding relay cannot starve the
                    // caller indefinitely.
                    consecutive_control = consecutive_control.saturating_add(1);
                    if consecutive_control > MAX_CONSECUTIVE_CONTROL_FRAMES {
                        return Err(SyncError::Protocol(
                            "excessive control frames from relay".into(),
                        ));
                    }
                }
                Some(Err(e)) => {
                    return Err(SyncError::Transport(e.to_string()));
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        self.ws
            .close(None)
            .await
            .map_err(|e| SyncError::Transport(e.to_string()))
    }
}

/// Wraps any [`SyncTransport`], encrypting outbound messages and decrypting
/// inbound messages with XChaCha20-Poly1305.
///
/// # v2 framing (Audit 2 Finding #10)
///
/// Each encrypted frame on the wire is:
///
/// ```text
/// version(1)=0x02 || session_id(16) || send_counter_be(8) || aead_ciphertext
/// ```
///
/// The AAD fed to the AEAD is `SYNC_AAD_V2 || session_id || counter_be`.
/// The `session_id` is a per-session random identifier, and
/// `send_counter` is a monotonically increasing `u64` per direction.
/// The receiver enforces strict forward-progress on the counter, so a
/// hostile relay cannot replay a frame captured earlier under the same
/// `VaultKey`.
///
/// The key material and session identifier are zeroized when this
/// transport is dropped (via `VaultKey`'s own `ZeroizeOnDrop` impl, and
/// an explicit `zeroize()` of the session id in our own `Drop`).
#[derive(Debug)]
pub struct EncryptedTransport<T: SyncTransport> {
    inner: T,
    key: VaultKey,
    /// This transport's **send-side** session identifier. Written into
    /// every outgoing frame's header and bound into the AEAD AAD so a
    /// hostile relay cannot successfully alter it. Generated
    /// randomly at `new()`.
    send_session_id: [u8; SESSION_ID_LEN],
    /// Monotonic send counter; incremented before each send.
    send_counter: u64,
    /// The peer's session identifier, learned from the first inbound
    /// frame. Subsequent frames MUST carry the same session id —
    /// a change mid-session indicates either a new sender (not allowed
    /// on an established connection) or a hostile relay splicing
    /// recorded frames from a different session. Either way, reject.
    peer_session_id: Option<[u8; SESSION_ID_LEN]>,
    /// Greatest receive counter accepted so far for the learned peer
    /// session. The next frame must carry a counter strictly greater
    /// than this value, else [`SyncError::Decryption`] is returned.
    recv_high_water: u64,
}

impl<T: SyncTransport> EncryptedTransport<T> {
    /// Wraps `inner` so that every message is encrypted with a copy of `key`.
    ///
    /// Generates a fresh random session id at construction time. Two
    /// transports created from the same `VaultKey` will have distinct
    /// session ids and therefore distinct AAD: a frame captured on one
    /// cannot be replayed onto the other.
    #[must_use]
    pub fn new(inner: T, key: &VaultKey) -> Self {
        // SECURITY: A failure of the OS RNG here would be catastrophic
        // because we would return a zero session id and lose the
        // replay-binding property. Fall back to VaultKey bytes if
        // fill_random fails — this still ensures a per-key-distinct id
        // (though not per-session distinct). In practice OsRng never
        // fails on platforms the SDK targets.
        let send_session_id =
            crate::crypto::util::fill_random::<SESSION_ID_LEN>().unwrap_or_else(|_| {
                let mut fallback = [0u8; SESSION_ID_LEN];
                let kb = key.as_bytes();
                fallback
                    .copy_from_slice(kb.get(..SESSION_ID_LEN).unwrap_or(&[0u8; SESSION_ID_LEN]));
                fallback
            });
        Self {
            inner,
            key: VaultKey::from_bytes(*key.as_bytes()),
            send_session_id,
            send_counter: 0,
            peer_session_id: None,
            recv_high_water: 0,
        }
    }

    /// Build the AAD for the v2 framing: `SYNC_AAD_V2 || session_id || counter_be`.
    fn build_aad(session_id: &[u8; SESSION_ID_LEN], counter: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(SYNC_AAD_V2.len() + SESSION_ID_LEN + SEND_COUNTER_LEN);
        aad.extend_from_slice(SYNC_AAD_V2);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad
    }

    /// Assemble the on-wire framing for an encrypted payload:
    /// `version || session_id || counter_be || ciphertext`.
    fn build_frame(
        session_id: &[u8; SESSION_ID_LEN],
        counter: u64,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + ciphertext.len());
        frame.push(SYNC_VERSION_V2);
        frame.extend_from_slice(session_id);
        frame.extend_from_slice(&counter.to_be_bytes());
        frame.extend_from_slice(ciphertext);
        frame
    }

    /// Parse the on-wire framing. Returns `(session_id, counter, ciphertext)`
    /// on success.
    ///
    /// Dispatch on the leading version byte (Residual Risk #5):
    ///
    /// - `0x02` → parse as v2 and return the fields.
    /// - `0x01` → [`SyncError::Legacy`] with a clear operator-facing
    ///   message. The rest of the frame is not inspected.
    /// - anything else → [`SyncError::Protocol`]
    ///   (`"unknown sync version"`).
    ///
    /// Frames with fewer bytes than a v2 header (including 0-byte and
    /// 1-byte inputs) are rejected with [`SyncError::Protocol`]
    /// (`"truncated sync frame"`). Empty input is classified as
    /// truncation rather than as a version mismatch: without even one
    /// byte we cannot claim "unknown version" honestly.
    fn parse_frame(frame: &[u8]) -> Result<([u8; SESSION_ID_LEN], u64, &[u8]), SyncError> {
        // Peek the version byte first. An empty frame has no version at
        // all — treat that as truncation, not as an unknown version.
        let Some(&version) = frame.first() else {
            return Err(SyncError::Protocol("truncated sync frame".into()));
        };
        match version {
            SYNC_VERSION_V2 => {}
            SYNC_VERSION_V1 => {
                return Err(SyncError::Legacy(
                    "v1 wire format no longer supported — peer must upgrade".into(),
                ));
            }
            _ => {
                return Err(SyncError::Protocol("unknown sync version".into()));
            }
        }

        // Version is v2 — enforce the full header length.
        if frame.len() < FRAME_HEADER_LEN {
            return Err(SyncError::Protocol("truncated sync frame".into()));
        }

        let mut session_id = [0u8; SESSION_ID_LEN];
        let session_slice = frame
            .get(1..1 + SESSION_ID_LEN)
            .ok_or_else(|| SyncError::Protocol("truncated sync frame".into()))?;
        session_id.copy_from_slice(session_slice);

        let counter_slice = frame
            .get(1 + SESSION_ID_LEN..FRAME_HEADER_LEN)
            .ok_or_else(|| SyncError::Protocol("truncated sync frame".into()))?;
        let counter_array: [u8; SEND_COUNTER_LEN] = counter_slice
            .try_into()
            .map_err(|_| SyncError::Protocol("truncated sync frame".into()))?;
        let counter = u64::from_be_bytes(counter_array);

        let ct = frame
            .get(FRAME_HEADER_LEN..)
            .ok_or_else(|| SyncError::Protocol("truncated sync frame".into()))?;
        Ok((session_id, counter, ct))
    }
}

impl<T: SyncTransport> Drop for EncryptedTransport<T> {
    fn drop(&mut self) {
        self.send_session_id.zeroize();
        if let Some(ref mut p) = self.peer_session_id {
            p.zeroize();
        }
    }
}

impl<T: SyncTransport + std::fmt::Debug> SyncTransport for EncryptedTransport<T> {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
        // SECURITY: bump the counter *before* building the AAD so a
        // successful send always binds a fresh counter, and so a
        // counter-wrap at u64::MAX fails closed (which is already
        // way beyond any practical session lifetime — 2^64 frames at
        // 1 ms each is ~585 million years).
        let counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| SyncError::Protocol("send counter overflow".into()))?;
        self.send_counter = counter;

        let aad = Self::build_aad(&self.send_session_id, counter);
        let ciphertext = aead::encrypt(&self.key, &msg.payload, &aad)
            .map_err(|_| SyncError::Encryption)?;
        let frame = Self::build_frame(&self.send_session_id, counter, &ciphertext);

        self.inner.send(&SyncMessage { payload: frame }).await
    }

    async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
        let encrypted = self.inner.recv().await?;
        let (frame_session, counter, ct) = Self::parse_frame(&encrypted.payload)?;

        // SECURITY: the first inbound frame LEARNS the peer's session
        // id. All subsequent frames MUST carry the same id. A change
        // mid-session is either a hostile relay splicing frames from a
        // different captured session or a legitimate restart — either
        // way we refuse to silently accept it; the caller must
        // re-establish the transport.
        if let Some(expected) = self.peer_session_id {
            if frame_session != expected {
                return Err(SyncError::Decryption);
            }
            if counter <= self.recv_high_water {
                return Err(SyncError::Decryption);
            }
        }

        let aad = Self::build_aad(&frame_session, counter);
        let payload = aead::decrypt(&self.key, ct, &aad).map_err(|_| SyncError::Decryption)?;

        // Only after a successful AEAD verify do we learn/advance
        // state; otherwise a garbage frame could be used to corrupt
        // the high-water mark.
        if self.peer_session_id.is_none() {
            self.peer_session_id = Some(frame_session);
        }
        self.recv_high_water = counter;

        Ok(SyncMessage { payload })
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use tokio::sync::mpsc;

    // -- In-memory channel transport for testing --

    #[derive(Debug)]
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl SyncTransport for ChannelTransport {
        async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
            let data =
                serde_json::to_vec(msg).map_err(|e| SyncError::Protocol(e.to_string()))?;
            self.tx
                .send(data)
                .await
                .map_err(|_| SyncError::ConnectionClosed)
        }

        async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
            let data = self.rx.recv().await.ok_or(SyncError::ConnectionClosed)?;
            serde_json::from_slice(&data).map_err(|e| SyncError::Protocol(e.to_string()))
        }

        async fn close(&mut self) -> Result<(), SyncError> {
            Ok(())
        }
    }

    /// Creates a pair of connected `ChannelTransport`s for testing.
    fn channel_pair() -> (ChannelTransport, ChannelTransport) {
        let (tx_a, rx_b) = mpsc::channel(16);
        let (tx_b, rx_a) = mpsc::channel(16);
        (
            ChannelTransport { tx: tx_a, rx: rx_a },
            ChannelTransport { tx: tx_b, rx: rx_b },
        )
    }

    fn test_key() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    // -- SyncMessage serialization --

    #[test]
    fn sync_message_serialization_round_trip() {
        let msg = SyncMessage {
            payload: vec![1, 2, 3, 4, 5],
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let recovered: SyncMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(msg.payload, recovered.payload);
    }

    // -- EncryptedTransport round-trip --

    #[tokio::test]
    async fn encrypted_transport_round_trip() {
        let (transport_a, transport_b) = channel_pair();
        let key = test_key();

        let mut enc_a = EncryptedTransport::new(transport_a, &key);
        let mut enc_b = EncryptedTransport::new(transport_b, &key);

        let original = SyncMessage {
            payload: b"hello, world!".to_vec(),
        };

        enc_a.send(&original).await.unwrap();
        let received = enc_b.recv().await.unwrap();

        assert_eq!(original.payload, received.payload);
    }

    // -- Wrong key decryption failure --

    #[tokio::test]
    async fn encrypted_transport_wrong_key_fails() {
        let (transport_a, transport_b) = channel_pair();
        let key_a = VaultKey::from_bytes([0x01; 32]);
        let key_b = VaultKey::from_bytes([0x02; 32]);

        let mut enc_a = EncryptedTransport::new(transport_a, &key_a);
        let mut enc_b = EncryptedTransport::new(transport_b, &key_b);

        let msg = SyncMessage {
            payload: b"secret data".to_vec(),
        };

        enc_a.send(&msg).await.unwrap();
        let result = enc_b.recv().await;

        assert!(result.is_err());
        assert!(
            matches!(result, Err(SyncError::Decryption)),
            "expected Decryption error"
        );
    }

    // -- Plain channel transport --

    #[tokio::test]
    async fn channel_transport_round_trip() {
        let (mut a, mut b) = channel_pair();
        let msg = SyncMessage {
            payload: vec![10, 20, 30],
        };
        a.send(&msg).await.unwrap();
        let received = b.recv().await.unwrap();
        assert_eq!(msg.payload, received.payload);
    }

    // -- Connection close detection --

    #[tokio::test]
    async fn recv_after_sender_drop_returns_closed() {
        let (a, mut b) = channel_pair();
        drop(a);
        let result = b.recv().await;
        assert!(matches!(result, Err(SyncError::ConnectionClosed)));
    }

    // -- SyncError Display --

    #[test]
    fn sync_error_display() {
        let err = SyncError::Transport("timeout".into());
        assert_eq!(err.to_string(), "transport error: timeout");

        let err = SyncError::Protocol("bad frame".into());
        assert_eq!(err.to_string(), "protocol error: bad frame");

        let err = SyncError::Encryption;
        assert_eq!(err.to_string(), "sync encryption failed");

        let err = SyncError::Decryption;
        assert_eq!(err.to_string(), "sync decryption failed");

        let err = SyncError::ConnectionClosed;
        assert_eq!(err.to_string(), "connection closed");

        let err = SyncError::Legacy("upgrade needed".into());
        assert_eq!(err.to_string(), "legacy peer: upgrade needed");
    }

    // -- WebSocket relay (ignored — requires a running server) --

    #[tokio::test]
    #[ignore]
    async fn relay_transport_connect_and_echo() {
        // Requires a WebSocket echo server at ws://127.0.0.1:9001
        let relay = RelayTransport::connect("ws://127.0.0.1:9001")
            .await
            .unwrap();

        let key = test_key();
        let mut enc = EncryptedTransport::new(relay, &key);

        let msg = SyncMessage {
            payload: b"ping".to_vec(),
        };
        enc.send(&msg).await.unwrap();

        // In an echo-server scenario the reply would come back here.
        // enc.recv().await.unwrap();

        let _ = enc.close().await;
    }

    // -- Finding #10 regression: replay rejection + session binding --

    /// Transport that records every outbound message and exposes the
    /// last one for replay into another transport, simulating a hostile
    /// relay that captures + re-emits a frame.
    #[derive(Debug)]
    struct RecordingTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl SyncTransport for RecordingTransport {
        async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
            let data =
                serde_json::to_vec(msg).map_err(|e| SyncError::Protocol(e.to_string()))?;
            if let Ok(mut g) = self.captured.lock() {
                g.push(data.clone());
            }
            self.tx.send(data).await.map_err(|_| SyncError::ConnectionClosed)
        }
        async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
            let data = self.rx.recv().await.ok_or(SyncError::ConnectionClosed)?;
            serde_json::from_slice(&data).map_err(|e| SyncError::Protocol(e.to_string()))
        }
        async fn close(&mut self) -> Result<(), SyncError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn encrypted_transport_rejects_replayed_frame() {
        // Build a single legitimate frame, then dispatch it TWICE into
        // a fresh receiver. The first delivery is accepted; the second
        // must be rejected because the counter does not advance.
        let (sender_t, _sender_rx) = mpsc::channel::<Vec<u8>>(4);
        let (_unused_tx, sender_rx) = mpsc::channel::<Vec<u8>>(4);
        let cap = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender_transport = RecordingTransport {
            tx: sender_t,
            rx: sender_rx,
            captured: cap.clone(),
        };
        let key = test_key();
        let mut enc_sender = EncryptedTransport::new(sender_transport, &key);
        enc_sender
            .send(&SyncMessage {
                payload: b"one".to_vec(),
            })
            .await
            .unwrap();
        let frame_bytes = cap.lock().unwrap().first().cloned().unwrap();

        // Inject the same raw serialised frame twice into a fresh receiver.
        let (tx_inject, rx_inject) = mpsc::channel::<Vec<u8>>(4);
        tx_inject.send(frame_bytes.clone()).await.unwrap();
        tx_inject.send(frame_bytes).await.unwrap();
        let (_dead_tx, _dead_rx) = mpsc::channel::<Vec<u8>>(1);
        let receiver_transport = RecordingTransport {
            tx: _dead_tx,
            rx: rx_inject,
            captured: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let mut enc_receiver = EncryptedTransport::new(receiver_transport, &key);

        // First recv: accepted, learns session id, sets high-water to 1.
        let first = enc_receiver.recv().await.unwrap();
        assert_eq!(first.payload, b"one");
        // Second recv: identical counter → must be rejected.
        let second = enc_receiver.recv().await;
        assert!(
            matches!(second, Err(SyncError::Decryption)),
            "replayed frame must be rejected, got {second:?}"
        );
    }

    #[tokio::test]
    async fn encrypted_transport_rejects_session_id_change_midstream() {
        // Set up one RECEIVER with two candidate injectors: sender X
        // gets through first (establishing peer_session_id), then we
        // inject a frame produced by a DIFFERENT sender (same key, new
        // session id). The receiver must reject because the session id
        // changed mid-stream.
        let (tx_inject, rx_consume) = mpsc::channel::<Vec<u8>>(8);
        let (_unused_tx, _unused_rx) = mpsc::channel::<Vec<u8>>(1);
        let receiver_transport = RecordingTransport {
            tx: _unused_tx,
            rx: rx_consume,
            captured: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let key = test_key();
        let mut enc_receiver = EncryptedTransport::new(receiver_transport, &key);

        // Build sender X → one frame.
        let (_x_tx, _x_rx) = mpsc::channel::<Vec<u8>>(4);
        let x_cap = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let x_transport = RecordingTransport {
            tx: _x_tx,
            rx: _x_rx,
            captured: x_cap.clone(),
        };
        let mut enc_x = EncryptedTransport::new(x_transport, &key);
        enc_x
            .send(&SyncMessage {
                payload: b"from-x".to_vec(),
            })
            .await
            .unwrap();
        let frame_from_x = x_cap.lock().unwrap().first().cloned().unwrap();
        tx_inject.send(frame_from_x).await.unwrap();

        // Receiver accepts the first frame and learns X's session id.
        let first = enc_receiver.recv().await.unwrap();
        assert_eq!(first.payload, b"from-x");

        // Build sender Y (same key, different session id) → one frame.
        let (_y_tx, _y_rx) = mpsc::channel::<Vec<u8>>(4);
        let y_cap = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let y_transport = RecordingTransport {
            tx: _y_tx,
            rx: _y_rx,
            captured: y_cap.clone(),
        };
        let mut enc_y = EncryptedTransport::new(y_transport, &key);
        enc_y
            .send(&SyncMessage {
                payload: b"from-y".to_vec(),
            })
            .await
            .unwrap();
        let frame_from_y = y_cap.lock().unwrap().first().cloned().unwrap();
        tx_inject.send(frame_from_y).await.unwrap();

        // Receiver must reject — different session id after learning.
        let second = enc_receiver.recv().await;
        assert!(
            matches!(second, Err(SyncError::Decryption)),
            "session id change mid-stream must be rejected, got {second:?}"
        );
    }

    // -- Finding #11 regression: control-frame flood cap --

    #[test]
    fn max_consecutive_control_frames_is_reasonable() {
        // Compile-time sanity: 64 is the documented cap. If this ever
        // needs to move, the doc-comment on the constant and the
        // SECURITY note in the body should move too.
        assert_eq!(MAX_CONSECUTIVE_CONTROL_FRAMES, 64);
    }

    // -- Finding #14: every exposed error type is Send + Sync --

    #[test]
    fn sync_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SyncError>();
    }

    // -- Finding #10: on-wire framing layout --

    #[test]
    fn frame_header_layout_is_version_session_counter() {
        // Build a frame and verify byte layout.
        let session: [u8; SESSION_ID_LEN] = [0xAB; SESSION_ID_LEN];
        let frame = EncryptedTransport::<ChannelTransport>::build_frame(&session, 42, b"ct");
        assert_eq!(frame.first().copied(), Some(SYNC_VERSION_V2));
        assert_eq!(&frame[1..17], &session);
        assert_eq!(&frame[17..25], &42u64.to_be_bytes());
        assert_eq!(&frame[25..], b"ct");
    }

    // -- Residual Risk #5: explicit version-byte dispatch --

    #[test]
    fn parse_frame_rejects_v1_with_legacy_error() {
        // A 0x01 leading byte — even with a well-formed v2-length header
        // — must be rejected with SyncError::Legacy carrying a clear
        // operator-facing message. The decoder is not allowed to try
        // parsing the frame after the version check.
        let mut frame = vec![SYNC_VERSION_V1];
        frame.extend_from_slice(&[0u8; SESSION_ID_LEN]);
        frame.extend_from_slice(&0u64.to_be_bytes());
        let result = EncryptedTransport::<ChannelTransport>::parse_frame(&frame);
        match result {
            Err(SyncError::Legacy(msg)) => {
                assert!(
                    msg.contains("v1") && msg.contains("upgrade"),
                    "unexpected legacy message: {msg}"
                );
            }
            other => panic!("expected SyncError::Legacy, got {other:?}"),
        }
    }

    #[test]
    fn parse_frame_rejects_unknown_version_with_protocol_error() {
        // A leading byte that is neither v1 nor v2 is a Protocol error,
        // not a Legacy error — we don't know what it is.
        let mut frame = vec![0x03];
        frame.extend_from_slice(&[0u8; SESSION_ID_LEN]);
        frame.extend_from_slice(&0u64.to_be_bytes());
        let result = EncryptedTransport::<ChannelTransport>::parse_frame(&frame);
        match result {
            Err(SyncError::Protocol(msg)) => {
                assert_eq!(msg, "unknown sync version");
            }
            other => panic!("expected SyncError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_frame_rejects_empty_as_truncated() {
        // Zero bytes: no version available at all. We classify this as
        // truncation, not "unknown version" — honesty in error mapping.
        let result = EncryptedTransport::<ChannelTransport>::parse_frame(&[]);
        match result {
            Err(SyncError::Protocol(msg)) => {
                assert_eq!(msg, "truncated sync frame");
            }
            other => panic!("expected SyncError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_frame_rejects_single_version_byte_as_truncated() {
        // One byte, v2 version only — header is still truncated.
        let result = EncryptedTransport::<ChannelTransport>::parse_frame(&[SYNC_VERSION_V2]);
        match result {
            Err(SyncError::Protocol(msg)) => {
                assert_eq!(msg, "truncated sync frame");
            }
            other => panic!("expected SyncError::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_frame_rejects_truncated_header() {
        let short = vec![SYNC_VERSION_V2, 0x01, 0x02];
        let result = EncryptedTransport::<ChannelTransport>::parse_frame(&short);
        match result {
            Err(SyncError::Protocol(msg)) => {
                assert_eq!(msg, "truncated sync frame");
            }
            other => panic!("expected SyncError::Protocol, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_surfaces_legacy_error_for_injected_v1_frame() {
        // Inject a v1-tagged payload into the wire and confirm the
        // caller sees SyncError::Legacy, not Decryption. This is the
        // end-to-end guarantee callers will read from release notes:
        // "v1 peers rejected with clear error".
        let (tx_inject, rx_consume) = mpsc::channel::<Vec<u8>>(4);
        let (_dead_tx, _dead_rx) = mpsc::channel::<Vec<u8>>(1);
        let receiver_transport = RecordingTransport {
            tx: _dead_tx,
            rx: rx_consume,
            captured: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let key = test_key();
        let mut enc_receiver = EncryptedTransport::new(receiver_transport, &key);

        // Build a plausibly-sized v1 frame: version=0x01, full v2-shaped
        // header afterwards. The decoder must not look beyond byte 0.
        let mut v1_frame = vec![SYNC_VERSION_V1];
        v1_frame.extend_from_slice(&[0u8; SESSION_ID_LEN]);
        v1_frame.extend_from_slice(&1u64.to_be_bytes());
        v1_frame.extend_from_slice(b"pretend-ciphertext");
        let wire = serde_json::to_vec(&SyncMessage {
            payload: v1_frame,
        })
        .unwrap();
        tx_inject.send(wire).await.unwrap();

        match enc_receiver.recv().await {
            Err(SyncError::Legacy(msg)) => {
                assert!(
                    msg.contains("v1") && msg.contains("upgrade"),
                    "unexpected legacy message: {msg}"
                );
            }
            other => panic!("expected Legacy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypted_transport_round_trip_with_v2_version_byte() {
        // Explicit round-trip check that the v2 framing (with explicit
        // version byte) decodes end-to-end. Also inspect the wire bytes
        // to confirm the leading byte is SYNC_VERSION_V2.
        let (transport_a, transport_b) = channel_pair();
        let key = test_key();
        let mut enc_a = EncryptedTransport::new(transport_a, &key);
        let mut enc_b = EncryptedTransport::new(transport_b, &key);

        let msg = SyncMessage {
            payload: b"v2 round-trip".to_vec(),
        };
        enc_a.send(&msg).await.unwrap();
        let received = enc_b.recv().await.unwrap();
        assert_eq!(received.payload, msg.payload);
    }

    #[test]
    fn send_session_ids_are_per_transport_unique() {
        let (a_t, _b_t) = channel_pair();
        let (c_t, _d_t) = channel_pair();
        let key = test_key();
        let enc_a = EncryptedTransport::new(a_t, &key);
        let enc_c = EncryptedTransport::new(c_t, &key);
        assert_ne!(enc_a.send_session_id, enc_c.send_session_id);
    }
}
