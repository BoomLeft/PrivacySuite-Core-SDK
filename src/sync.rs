//! E2EE sync protocol with LAN peer-to-peer and WebSocket relay transports.
//!
//! # Architecture
//!
//! The sync protocol enables multi-device document synchronisation where the
//! relay server **never** reads document content — it only passes E2EE blobs
//! between devices. Two transport backends are provided:
//!
//! - [`RelayTransport`] — WebSocket relay via `tokio-tungstenite`.
//! - [`LanDiscovery`] — placeholder for LAN peer-to-peer discovery.
//!
//! [`EncryptedTransport`] wraps any [`SyncTransport`] implementation,
//! encrypting every message with XChaCha20-Poly1305 before it leaves the
//! device and decrypting on receipt.
//!
//! # Wire Format
//!
//! Each [`SyncMessage`] carries an opaque `payload` field. When sent through
//! an [`EncryptedTransport`], the payload is replaced with the AEAD ciphertext
//! (nonce ‖ ciphertext ‖ tag). The associated data `"privacysuite:sync:v1"`
//! is bound to every encryption to prevent cross-protocol ciphertext reuse.

use std::fmt;
use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::keys::VaultKey;

/// Associated data bound to every sync encryption operation.
const SYNC_AAD: &[u8] = b"privacysuite:sync:v1";

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors that can occur during sync operations.
#[derive(Debug)]
pub enum SyncError {
    /// A transport-level error (e.g., network I/O failure).
    Transport(String),
    /// A protocol-level error (e.g., malformed message).
    Protocol(String),
    /// AEAD encryption failed.
    Encryption,
    /// AEAD decryption or authentication failed.
    Decryption,
    /// The remote end closed the connection.
    ConnectionClosed,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Encryption => f.write_str("sync encryption failed"),
            Self::Decryption => f.write_str("sync decryption failed"),
            Self::ConnectionClosed => f.write_str("connection closed"),
        }
    }
}

impl std::error::Error for SyncError {}

// ---------------------------------------------------------------------------
// SyncMessage
// ---------------------------------------------------------------------------

/// Serialisable envelope for the sync protocol.
///
/// The `payload` contains either plaintext CRDT data (before encryption) or
/// an E2EE blob (after encryption by [`EncryptedTransport`]).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SyncMessage {
    /// Encrypted (or plaintext) CRDT sync data.
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// SyncTransport trait
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// RelayTransport (WebSocket)
// ---------------------------------------------------------------------------

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
    /// Connects to a WebSocket relay at the given URL.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Transport`] if the TCP or TLS handshake fails.
    pub async fn connect(url: &str) -> Result<Self, SyncError> {
        let (ws, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| SyncError::Transport(e.to_string()))?;
        Ok(Self { ws })
    }
}

impl SyncTransport for RelayTransport {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
        let serialized =
            serde_json::to_vec(msg).map_err(|e| SyncError::Protocol(e.to_string()))?;
        self.ws
            .send(WsMessage::Binary(serialized))
            .await
            .map_err(|e| SyncError::Transport(e.to_string()))
    }

    async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return serde_json::from_slice(&data)
                        .map_err(|e| SyncError::Protocol(e.to_string()));
                }
                Some(Ok(WsMessage::Text(text))) => {
                    return serde_json::from_str(&text)
                        .map_err(|e| SyncError::Protocol(e.to_string()));
                }
                Some(Ok(WsMessage::Close(_))) | None => {
                    return Err(SyncError::ConnectionClosed);
                }
                Some(Ok(_)) => {
                    // Ping/Pong frames — keep looping.
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

// ---------------------------------------------------------------------------
// EncryptedTransport
// ---------------------------------------------------------------------------

/// Wraps any [`SyncTransport`], encrypting outbound messages and decrypting
/// inbound messages with XChaCha20-Poly1305.
///
/// The key material is zeroized when this transport is dropped.
#[derive(Debug)]
pub struct EncryptedTransport<T: SyncTransport> {
    inner: T,
    key_bytes: [u8; 32],
}

impl<T: SyncTransport> Drop for EncryptedTransport<T> {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl<T: SyncTransport> EncryptedTransport<T> {
    /// Wraps `inner` so that every message is encrypted with `key`.
    ///
    /// The key bytes are copied into the transport and zeroized on drop.
    #[must_use]
    pub fn new(inner: T, key: &VaultKey) -> Self {
        Self {
            inner,
            key_bytes: *key.as_bytes(),
        }
    }
}

impl<T: SyncTransport + std::fmt::Debug> SyncTransport for EncryptedTransport<T> {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), SyncError> {
        let key = VaultKey::from_bytes(self.key_bytes);
        let encrypted_payload =
            aead::encrypt(&key, &msg.payload, SYNC_AAD).map_err(|_| SyncError::Encryption)?;

        let encrypted_msg = SyncMessage {
            payload: encrypted_payload,
        };
        self.inner.send(&encrypted_msg).await
    }

    async fn recv(&mut self) -> Result<SyncMessage, SyncError> {
        let encrypted_msg = self.inner.recv().await?;
        let key = VaultKey::from_bytes(self.key_bytes);
        // PEN-03: Move plaintext directly into the message — no clone.
        // The caller is responsible for zeroizing the payload when done.
        let plaintext = aead::decrypt(&key, &encrypted_msg.payload, SYNC_AAD)
            .map_err(|_| SyncError::Decryption)?;

        Ok(SyncMessage { payload: plaintext })
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        self.inner.close().await
    }
}

// ---------------------------------------------------------------------------
// LanDiscovery
// ---------------------------------------------------------------------------

/// Placeholder for LAN peer discovery via mDNS / broadcast.
///
/// The LAN transport will allow devices on the same network to sync directly
/// without routing through the relay server. This is not yet implemented;
/// the WebSocket relay is the primary transport.
#[derive(Debug)]
pub struct LanDiscovery;

impl LanDiscovery {
    /// Creates a new `LanDiscovery` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Announces this device's sync service on the given port.
    ///
    /// # Errors
    ///
    /// Currently always returns [`SyncError::Transport`] — LAN discovery is
    /// not yet implemented.
    pub fn announce(&self, _port: u16) -> Result<(), SyncError> {
        Err(SyncError::Transport(
            "LAN discovery not yet implemented".into(),
        ))
    }

    /// Discovers peer devices on the local network.
    ///
    /// # Errors
    ///
    /// Currently always returns [`SyncError::Transport`] — LAN discovery is
    /// not yet implemented.
    pub fn discover(&self) -> Result<Vec<SocketAddr>, SyncError> {
        Err(SyncError::Transport(
            "LAN discovery not yet implemented".into(),
        ))
    }
}

impl Default for LanDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // -- LAN discovery placeholder --

    #[test]
    fn lan_discovery_returns_not_implemented() {
        let discovery = LanDiscovery::new();
        assert!(discovery.announce(8080).is_err());
        assert!(discovery.discover().is_err());
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
}
