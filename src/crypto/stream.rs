//! Chunked streaming AEAD on top of XChaCha20-Poly1305.
//!
//! # Construction
//!
//! Implements the STREAM construction from Hoang, Reyhanitabar, Rogaway, and
//! Vizár, *"Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance"* (CRYPTO 2015), adapted to XChaCha20-Poly1305.
//!
//! Each stream consists of an ordered sequence of AEAD chunks. Every chunk
//! is sealed under a unique nonce derived from:
//!
//! - a **20-byte per-stream random prefix** (`stream_id`), and
//! - a **4-byte chunk counter** encoded as little-endian, whose top bit is
//!   reused as the "last-chunk" flag.
//!
//! The chunk counter and the last-chunk flag are **also** bound via the
//! per-chunk AAD. That means:
//!
//! - Chunks cannot be reordered (each tag authenticates a distinct index).
//! - Chunks cannot be replayed (same index + different position still
//!   fails, because the AEAD output of a prior chunk is rejected after the
//!   reader has already advanced its counter).
//! - Truncation-at-chunk-boundary fails authentication: the stream is only
//!   considered complete when a chunk decrypts successfully with the
//!   last-chunk flag set, so the terminating empty chunk is the sole
//!   end-of-stream signal.
//! - Two streams encrypted under the same key never collide on a nonce,
//!   because the 160-bit random `stream_id` is distinct with overwhelming
//!   probability.
//!
//! # Wire format
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │ header: 20-byte stream_id │ 4 bytes reserved (zero)           │
//! ├───────────────────────────┼───────────────────────────────────┤
//! │ chunk 0: 4-byte big-endian LEN │ LEN bytes ciphertext+tag     │
//! │ chunk 1: 4-byte big-endian LEN │ LEN bytes ciphertext+tag     │
//! │ ...                                                           │
//! │ chunk N-1 (last): 4-byte LEN=16 │ 16-byte tag (empty plaintext)│
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Nonce derivation
//!
//! ```text
//! nonce[ 0..20] = stream_id                    (20 random bytes)
//! nonce[20..24] = chunk_index.to_le_bytes()    (u32 little-endian)
//! if is_last_chunk: nonce[23] |= 0x80          (top bit of MSB)
//! ```
//!
//! Reusing the high bit of the little-endian MSB for the last-chunk flag
//! is equivalent to stealing the high bit of the 32-bit counter. The
//! effective counter space is therefore 2^31 chunks, i.e. 2 TiB per
//! stream at the configured 1 MiB chunk size — far beyond any plausible
//! single-stream workload.
//!
//! # AAD per chunk
//!
//! ```text
//! aad = stream_id || chunk_index.to_le_bytes() || [is_last_byte]
//! ```
//!
//! where `is_last_byte` is `1` for the terminating chunk and `0` otherwise.
//! Tampering with the last-chunk flag on any chunk flips the AAD and the
//! nonce simultaneously, so the AEAD tag check fails deterministically.

use std::io::{Read, Write};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::crypto::keys::VaultKey;
use crate::crypto::util::fill_random;
use crate::error::CryptoError;

/// Plaintext chunk size (1 MiB).
///
/// Chosen to balance per-chunk authentication overhead against the memory
/// footprint of a single-chunk buffer on mobile devices.
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

/// Per-stream random prefix length in bytes (160 bits).
///
/// Combined with the 32-bit chunk counter this fills the 24-byte
/// XChaCha20-Poly1305 nonce exactly.
pub const STREAM_ID_LEN: usize = 20;

/// Size of the chunk-counter portion of the nonce (4 bytes).
const CHUNK_COUNTER_LEN: usize = 4;

/// Reserved bytes in the stream header (currently zero).
const HEADER_RESERVED_LEN: usize = 4;

/// Total stream header length on the wire.
const HEADER_LEN: usize = STREAM_ID_LEN + HEADER_RESERVED_LEN;

/// Per-chunk length-prefix width (big-endian u32).
const LEN_PREFIX_LEN: usize = 4;

/// Poly1305 authentication tag size (128 bits).
const TAG_LEN: usize = 16;

/// Maximum chunk ciphertext length accepted on the wire: one full plaintext
/// chunk plus tag. Anything larger is rejected as malformed, capping the
/// per-chunk allocation and shutting the door on resource-exhaustion.
const MAX_CHUNK_CIPHERTEXT_LEN: usize = STREAM_CHUNK_SIZE + TAG_LEN;

/// Bit mask applied to the high byte of the chunk counter to mark the
/// terminating chunk.
const LAST_CHUNK_FLAG: u8 = 0x80;

/// Upper bound on the chunk counter (top bit reserved for last-chunk flag).
const MAX_CHUNK_INDEX: u32 = 0x7FFF_FFFF;

/// Derives the 24-byte XChaCha20-Poly1305 nonce for chunk `chunk_index`
/// under the stream identified by `stream_id`.
///
/// See the module docs for the exact layout.
fn derive_nonce(stream_id: &[u8; STREAM_ID_LEN], chunk_index: u32, is_last: bool) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..STREAM_ID_LEN].copy_from_slice(stream_id);
    let counter = chunk_index.to_le_bytes();
    nonce[STREAM_ID_LEN..STREAM_ID_LEN + CHUNK_COUNTER_LEN].copy_from_slice(&counter);
    if is_last {
        // SECURITY: Setting the top bit of the MSB of the little-endian
        // counter makes the last chunk cryptographically distinguishable
        // from all non-last chunks (distinct nonce → distinct keystream).
        nonce[23] |= LAST_CHUNK_FLAG;
    }
    nonce
}

/// Builds the per-chunk AAD: `stream_id || chunk_index.to_le_bytes() || [is_last_byte]`.
fn build_aad(
    stream_id: &[u8; STREAM_ID_LEN],
    chunk_index: u32,
    is_last: bool,
) -> [u8; STREAM_ID_LEN + CHUNK_COUNTER_LEN + 1] {
    let mut aad = [0u8; STREAM_ID_LEN + CHUNK_COUNTER_LEN + 1];
    aad[..STREAM_ID_LEN].copy_from_slice(stream_id);
    let counter = chunk_index.to_le_bytes();
    aad[STREAM_ID_LEN..STREAM_ID_LEN + CHUNK_COUNTER_LEN].copy_from_slice(&counter);
    aad[STREAM_ID_LEN + CHUNK_COUNTER_LEN] = u8::from(is_last);
    aad
}

/// Writer-side STREAM encoder.
///
/// Buffers plaintext in 1 MiB chunks. Each full chunk is sealed and written
/// to the inner writer as `[4-byte BE LEN][LEN bytes ciphertext+tag]`.
///
/// Callers MUST invoke [`EncryptedFileWriter::finalize`] to emit the
/// terminating empty last-chunk. Dropping an unfinalized writer produces
/// an incomplete stream that will be rejected by the reader as
/// [`CryptoError::StreamTruncated`] — the safe failure mode.
#[derive(Debug)]
pub struct EncryptedFileWriter<W: Write> {
    inner: W,
    key: VaultKey,
    stream_id: [u8; STREAM_ID_LEN],
    buffer: Zeroizing<Vec<u8>>,
    chunk_index: u32,
    finalized: bool,
}

impl<W: Write> EncryptedFileWriter<W> {
    /// Creates a new encrypted writer.
    ///
    /// Generates a fresh 20-byte random `stream_id`, writes the 24-byte
    /// header (`stream_id || 4 bytes reserved = 0`) to `inner`, and
    /// prepares to accept plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] if OS entropy is unavailable, or
    /// [`CryptoError::Encryption`] if writing the header to `inner` fails.
    pub fn new(mut inner: W, key: &VaultKey) -> Result<Self, CryptoError> {
        let stream_id = fill_random::<STREAM_ID_LEN>()?;
        // Header: stream_id || 4 bytes reserved (zero).
        let mut header = [0u8; HEADER_LEN];
        header[..STREAM_ID_LEN].copy_from_slice(&stream_id);
        // Remaining HEADER_RESERVED_LEN bytes are already zero.
        inner.write_all(&header).map_err(|_| CryptoError::Encryption)?;

        Ok(Self {
            inner,
            key: VaultKey::from_bytes(*key.as_bytes()),
            stream_id,
            buffer: Zeroizing::new(Vec::with_capacity(STREAM_CHUNK_SIZE)),
            chunk_index: 0,
            finalized: false,
        })
    }

    /// Appends `buf` to the plaintext stream. Emits as many sealed chunks
    /// as required to keep the internal buffer at most `STREAM_CHUNK_SIZE`
    /// bytes.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::StreamAlreadyFinalized`] if called after
    ///   [`Self::finalize`] (guard; the move semantics of `finalize`
    ///   normally prevent this).
    /// - [`CryptoError::Encryption`] if AEAD sealing or the inner writer
    ///   fails, or the stream exceeds the 2^31-chunk counter budget.
    pub fn write(&mut self, buf: &[u8]) -> Result<(), CryptoError> {
        if self.finalized {
            return Err(CryptoError::StreamAlreadyFinalized);
        }
        let mut offset = 0;
        while offset < buf.len() {
            let room = STREAM_CHUNK_SIZE - self.buffer.len();
            let take = room.min(buf.len() - offset);
            self.buffer.extend_from_slice(&buf[offset..offset + take]);
            offset += take;
            if self.buffer.len() == STREAM_CHUNK_SIZE {
                self.flush_chunk(false)?;
            }
        }
        Ok(())
    }

    /// Seals the current buffer as a single chunk and writes it to `inner`
    /// with its 4-byte big-endian length prefix. Increments the chunk
    /// counter on success.
    fn flush_chunk(&mut self, is_last: bool) -> Result<(), CryptoError> {
        if self.chunk_index > MAX_CHUNK_INDEX {
            return Err(CryptoError::Encryption);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| CryptoError::Encryption)?;
        let nonce_bytes = derive_nonce(&self.stream_id, self.chunk_index, is_last);
        let aad = build_aad(&self.stream_id, self.chunk_index, is_last);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: &self.buffer, aad: &aad };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::Encryption)?;
        // Sanity: ciphertext length must fit in u32 (always true: <= 1 MiB + 16).
        let len_u32 = u32::try_from(ciphertext.len()).map_err(|_| CryptoError::Encryption)?;
        self.inner
            .write_all(&len_u32.to_be_bytes())
            .map_err(|_| CryptoError::Encryption)?;
        self.inner
            .write_all(&ciphertext)
            .map_err(|_| CryptoError::Encryption)?;
        self.buffer.clear();
        self.chunk_index = self.chunk_index.saturating_add(1);
        Ok(())
    }

    /// Seals any remaining buffered plaintext as a non-last chunk (if
    /// non-empty), then seals and emits the mandatory terminating empty
    /// chunk with the last-chunk flag set.
    ///
    /// Returns the inner writer so callers can flush / sync it.
    ///
    /// # Errors
    ///
    /// Same as [`Self::write`]. On any error the stream is left in an
    /// unfinalizable state; the inner writer is not returned.
    pub fn finalize(mut self) -> Result<W, CryptoError> {
        if self.finalized {
            return Err(CryptoError::StreamAlreadyFinalized);
        }
        // 1. If there is buffered plaintext, seal it as a non-last chunk.
        if !self.buffer.is_empty() {
            self.flush_chunk(false)?;
        }
        // 2. Emit the mandatory empty last-chunk.
        debug_assert!(self.buffer.is_empty());
        self.flush_chunk(true)?;
        self.finalized = true;
        Ok(self.inner)
    }
}

/// Reader-side STREAM decoder.
///
/// Yields plaintext only after authenticating each chunk's AEAD tag.
/// Returns `Ok(0)` **only** after observing a successfully-decrypted
/// chunk with the last-chunk flag set. If the inner reader hits EOF
/// before that, the call returns [`CryptoError::StreamTruncated`] so
/// truncated-stream attacks fail closed.
#[derive(Debug)]
pub struct EncryptedFileReader<R: Read> {
    inner: R,
    key: VaultKey,
    stream_id: [u8; STREAM_ID_LEN],
    read_buffer: Zeroizing<Vec<u8>>,
    read_cursor: usize,
    chunk_index: u32,
    eof_seen: bool,
}

impl<R: Read> EncryptedFileReader<R> {
    /// Parses the 24-byte stream header and prepares to decrypt.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::StreamInvalidHeader`] if the header cannot be read
    ///   in full (short input).
    pub fn new(mut inner: R, key: &VaultKey) -> Result<Self, CryptoError> {
        let mut header = [0u8; HEADER_LEN];
        inner
            .read_exact(&mut header)
            .map_err(|_| CryptoError::StreamInvalidHeader)?;
        let mut stream_id = [0u8; STREAM_ID_LEN];
        stream_id.copy_from_slice(&header[..STREAM_ID_LEN]);
        // The reserved region is currently ignored; future format
        // revisions may negotiate via it.
        Ok(Self {
            inner,
            key: VaultKey::from_bytes(*key.as_bytes()),
            stream_id,
            read_buffer: Zeroizing::new(Vec::new()),
            read_cursor: 0,
            chunk_index: 0,
            eof_seen: false,
        })
    }

    /// Opens a reader positioned to begin decrypting at chunk
    /// `chunk_index`. The preceding chunks are read and discarded without
    /// decryption.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::StreamInvalidHeader`] on a short or missing header.
    /// - [`CryptoError::StreamTruncated`] if the inner reader hits EOF
    ///   while skipping.
    /// - [`CryptoError::StreamChunkIndexMismatch`] if `chunk_index`
    ///   exceeds the usable counter range.
    pub fn resume_at(mut inner: R, key: &VaultKey, chunk_index: u32) -> Result<Self, CryptoError> {
        if chunk_index > MAX_CHUNK_INDEX {
            return Err(CryptoError::StreamChunkIndexMismatch);
        }
        // Parse header first.
        let mut header = [0u8; HEADER_LEN];
        inner
            .read_exact(&mut header)
            .map_err(|_| CryptoError::StreamInvalidHeader)?;
        let mut stream_id = [0u8; STREAM_ID_LEN];
        stream_id.copy_from_slice(&header[..STREAM_ID_LEN]);

        // Skip the first `chunk_index` chunks without decrypting.
        for _ in 0..chunk_index {
            let mut len_buf = [0u8; LEN_PREFIX_LEN];
            inner
                .read_exact(&mut len_buf)
                .map_err(|_| CryptoError::StreamTruncated)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_CHUNK_CIPHERTEXT_LEN {
                return Err(CryptoError::StreamTruncated);
            }
            // Discard `len` bytes. `std::io::copy` avoids a heap
            // allocation the size of the chunk.
            let mut discard = std::io::sink();
            let copied = std::io::copy(&mut (&mut inner).take(len as u64), &mut discard)
                .map_err(|_| CryptoError::StreamTruncated)?;
            if copied as usize != len {
                return Err(CryptoError::StreamTruncated);
            }
        }

        Ok(Self {
            inner,
            key: VaultKey::from_bytes(*key.as_bytes()),
            stream_id,
            read_buffer: Zeroizing::new(Vec::new()),
            read_cursor: 0,
            chunk_index,
            eof_seen: false,
        })
    }

    /// Reads decrypted plaintext into `buf`, returning the number of bytes
    /// written.
    ///
    /// Returns `Ok(0)` **only** after a chunk has decrypted successfully
    /// with the last-chunk flag set. If the underlying reader hits EOF
    /// before the terminating chunk is authenticated, returns
    /// [`CryptoError::StreamTruncated`].
    ///
    /// # Errors
    ///
    /// - [`CryptoError::StreamTruncated`] on premature EOF.
    /// - [`CryptoError::Decryption`] if any chunk fails the AEAD tag check
    ///   (wrong key, reorder, replay, tampering, last-chunk flag forgery).
    /// - [`CryptoError::StreamInvalidHeader`] if a chunk advertises a
    ///   malformed length.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, CryptoError> {
        // If we've already authenticated the last chunk AND drained its
        // plaintext (empty), further reads return Ok(0).
        if self.eof_seen && self.read_cursor >= self.read_buffer.len() {
            return Ok(0);
        }

        // Refill the decrypted plaintext buffer if we've drained it.
        if self.read_cursor >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_cursor = 0;
            self.decrypt_next_chunk()?;
            // After a successful last-chunk decrypt the buffer may be
            // empty — return Ok(0) to the caller.
            if self.eof_seen && self.read_buffer.is_empty() {
                return Ok(0);
            }
        }

        let remaining = self.read_buffer.len() - self.read_cursor;
        let take = remaining.min(buf.len());
        buf[..take].copy_from_slice(&self.read_buffer[self.read_cursor..self.read_cursor + take]);
        self.read_cursor += take;
        Ok(take)
    }

    /// Pulls the next chunk off the wire and decrypts it into
    /// `self.read_buffer`. Updates `self.chunk_index` and `self.eof_seen`.
    fn decrypt_next_chunk(&mut self) -> Result<(), CryptoError> {
        if self.chunk_index > MAX_CHUNK_INDEX {
            return Err(CryptoError::StreamChunkIndexMismatch);
        }

        let mut len_buf = [0u8; LEN_PREFIX_LEN];
        // A clean EOF here (before any chunk byte arrives) means the
        // stream was truncated — the sender never emitted the mandatory
        // terminating chunk.
        self.inner
            .read_exact(&mut len_buf)
            .map_err(|_| CryptoError::StreamTruncated)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len < TAG_LEN || len > MAX_CHUNK_CIPHERTEXT_LEN {
            return Err(CryptoError::StreamInvalidHeader);
        }

        let mut ciphertext = Zeroizing::new(vec![0u8; len]);
        self.inner
            .read_exact(&mut ciphertext)
            .map_err(|_| CryptoError::StreamTruncated)?;

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| CryptoError::Decryption)?;

        // Decide whether this chunk is the terminating one. A chunk that
        // carries only the 16-byte tag (LEN == TAG_LEN, i.e. zero-byte
        // plaintext) is interpreted as the last chunk — the writer never
        // emits zero-byte non-last chunks. Any other length is always
        // non-last, and any attempt to retag a non-last chunk as last
        // fails the AEAD check deterministically.
        let is_last_candidate = len == TAG_LEN;

        let nonce_bytes = derive_nonce(&self.stream_id, self.chunk_index, is_last_candidate);
        let aad = build_aad(&self.stream_id, self.chunk_index, is_last_candidate);
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: ciphertext.as_slice(), aad: &aad };
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::Decryption)?;

        self.read_buffer.extend_from_slice(&plaintext);
        // Drop the plaintext intermediate; Vec<u8> does not zeroize by
        // default, so scrub it manually before dropping.
        drop(Zeroizing::new(plaintext));

        if is_last_candidate {
            self.eof_seen = true;
        }
        self.chunk_index = self.chunk_index.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::secure_random;
    use std::io::Cursor;

    fn test_key(seed: u8) -> VaultKey {
        VaultKey::from_bytes([seed; 32])
    }

    /// Helper: encrypt `plaintext` under `key` and return the wire bytes.
    fn encrypt_to_vec(key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut w = EncryptedFileWriter::new(buf, key).expect("writer init");
        w.write(plaintext).expect("writer write");
        w.finalize().expect("writer finalize")
    }

    /// Helper: decrypt `wire` under `key` by draining the reader.
    fn decrypt_to_vec(key: &VaultKey, wire: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut r = EncryptedFileReader::new(Cursor::new(wire), key)?;
        let mut out: Vec<u8> = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            let n = r.read(&mut scratch)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&scratch[..n]);
        }
        Ok(out)
    }

    // ----- Test 1: Round-trip at several sizes ------------------------------

    #[test]
    fn round_trip_100_kib() {
        let key = test_key(1);
        let pt = secure_random(100 * 1024).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert_eq!(dec, pt);
    }

    #[test]
    fn round_trip_exactly_one_chunk() {
        let key = test_key(2);
        let pt = secure_random(STREAM_CHUNK_SIZE).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert_eq!(dec, pt);
    }

    #[test]
    fn round_trip_one_chunk_plus_one() {
        let key = test_key(3);
        let pt = secure_random(STREAM_CHUNK_SIZE + 1).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert_eq!(dec, pt);
    }

    #[test]
    fn round_trip_five_mib() {
        let key = test_key(4);
        let pt = secure_random(5 * STREAM_CHUNK_SIZE).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert_eq!(dec, pt);
    }

    // ----- Test 2: Empty plaintext ------------------------------------------

    #[test]
    fn empty_plaintext_round_trips() {
        let key = test_key(5);
        let wire = encrypt_to_vec(&key, &[]);
        // Should contain: 24-byte header + 4-byte LEN prefix + 16-byte tag.
        assert_eq!(wire.len(), HEADER_LEN + LEN_PREFIX_LEN + TAG_LEN);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert!(dec.is_empty());
    }

    // ----- Test 3: Truncation detection -------------------------------------

    #[test]
    fn truncated_stream_fails() {
        let key = test_key(6);
        let pt = secure_random(3 * STREAM_CHUNK_SIZE + 500).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);

        // Locate the last chunk's framing: walk the wire by LEN prefixes.
        let last_chunk_offset = find_last_chunk_offset(&wire);
        let truncated = &wire[..last_chunk_offset];
        let err = decrypt_to_vec(&key, truncated).expect_err("must fail");
        assert_eq!(err, CryptoError::StreamTruncated);
    }

    #[test]
    fn truncated_mid_chunk_fails() {
        let key = test_key(7);
        let pt = secure_random(2 * STREAM_CHUNK_SIZE).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        // Drop the trailing 10 bytes — clips into the middle of the last chunk.
        let truncated = &wire[..wire.len() - 10];
        let err = decrypt_to_vec(&key, truncated).expect_err("must fail");
        assert_eq!(err, CryptoError::StreamTruncated);
    }

    // ----- Test 4: Chunk reorder --------------------------------------------

    #[test]
    fn chunk_reorder_fails() {
        let key = test_key(8);
        // Need at least three non-last chunks; use 3 * 1 MiB + a remainder
        // so there are 4 chunks (3 non-last + last empty).
        let pt = secure_random(3 * STREAM_CHUNK_SIZE + 17).expect("rng");
        let mut wire = encrypt_to_vec(&key, &pt);

        // Swap chunks 1 and 2 (0-indexed after header).
        let offsets = enumerate_chunk_offsets(&wire);
        assert!(offsets.len() >= 4, "need at least 4 chunks");
        // Each chunk framing is [4-byte LEN][LEN bytes CT].
        let (a_start, a_end) = chunk_span(&wire, offsets[1]);
        let (b_start, b_end) = chunk_span(&wire, offsets[2]);
        assert_eq!(a_start, offsets[1]);
        assert_eq!(b_start, offsets[2]);
        let a = wire[a_start..a_end].to_vec();
        let b = wire[b_start..b_end].to_vec();
        // Rebuild: header..a_start || b || a || rest. The two chunks are
        // adjacent, so the swap is simply a.extend(b) reversed.
        assert_eq!(a_end, b_start);
        let _ = wire
            .splice(a_start..b_end, b.iter().chain(a.iter()).copied())
            .collect::<Vec<_>>();

        let err = decrypt_to_vec(&key, &wire).expect_err("must fail");
        assert_eq!(err, CryptoError::Decryption);
    }

    // ----- Test 5: Chunk replay ---------------------------------------------

    #[test]
    fn chunk_replay_fails() {
        let key = test_key(9);
        let pt = secure_random(2 * STREAM_CHUNK_SIZE + 32).expect("rng");
        let mut wire = encrypt_to_vec(&key, &pt);

        // Duplicate the first chunk so it appears twice in a row. Decrypt
        // must fail because the AAD at index 1 expects the second chunk's
        // tag, not a replay of chunk 0.
        let offsets = enumerate_chunk_offsets(&wire);
        assert!(offsets.len() >= 3);
        let (c0_start, c0_end) = chunk_span(&wire, offsets[0]);
        let c0 = wire[c0_start..c0_end].to_vec();
        // Insert a copy of c0 immediately after c0.
        let _ = wire
            .splice(c0_end..c0_end, c0.iter().copied())
            .collect::<Vec<_>>();

        let err = decrypt_to_vec(&key, &wire).expect_err("must fail");
        assert_eq!(err, CryptoError::Decryption);
    }

    // ----- Test 6: Last-chunk flag tampering --------------------------------

    #[test]
    fn last_chunk_flag_tamper_fails() {
        let key = test_key(10);
        // Two full chunks + small tail → three non-last chunks + one last.
        let pt = secure_random(2 * STREAM_CHUNK_SIZE + 8).expect("rng");
        let wire = encrypt_to_vec(&key, &pt);
        let offsets = enumerate_chunk_offsets(&wire);
        assert!(offsets.len() >= 4);

        // Craft a ciphertext where the attacker claims chunk 0 is the
        // empty terminator by rewriting its LEN prefix to TAG_LEN and
        // presenting only the first 16 bytes of its ciphertext. The
        // reader will verify with is_last=true (nonce top-bit set, AAD
        // last-byte = 1) but chunk 0 was originally sealed with
        // is_last=false, so the AEAD tag check must fail.
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&wire[..HEADER_LEN]);
        tampered.extend_from_slice(&(TAG_LEN as u32).to_be_bytes());
        let (c0_start, _c0_end) = chunk_span(&wire, offsets[0]);
        let ct_start = c0_start + LEN_PREFIX_LEN;
        tampered.extend_from_slice(&wire[ct_start..ct_start + TAG_LEN]);
        let err = decrypt_to_vec(&key, &tampered).expect_err("must fail");
        assert_eq!(err, CryptoError::Decryption);
    }

    // ----- Test 7: Cross-key ------------------------------------------------

    #[test]
    fn cross_key_fails() {
        let key_a = test_key(0xAA);
        let key_b = test_key(0xBB);
        let pt = b"classified payload".to_vec();
        let wire = encrypt_to_vec(&key_a, &pt);
        let err = decrypt_to_vec(&key_b, &wire).expect_err("must fail");
        assert_eq!(err, CryptoError::Decryption);
    }

    // ----- Test 8: Large stream ---------------------------------------------

    // 50 MiB round-trip is sensitive to build profile: release finishes in
    // well under 2 s, but dev-profile debug assertions + unoptimised
    // ChaCha20 routines push it past 40 s on hosts without SIMD. Mark as
    // ignored by default; run via `cargo test -- --ignored large_stream_50_mib`
    // or in CI's perf tier with `--release`.
    #[test]
    #[ignore = "timing assertion only meaningful in --release"]
    fn large_stream_50_mib() {
        use std::time::Instant;
        let key = test_key(0xCC);
        // 50 MiB. Using a deterministic pattern avoids the cost of
        // generating 50 MiB from OsRng; round-trip behaviour is what we
        // care about here, not entropy.
        let size = 50 * STREAM_CHUNK_SIZE;
        let mut pt = vec![0u8; size];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let start = Instant::now();
        let wire = encrypt_to_vec(&key, &pt);
        let dec = decrypt_to_vec(&key, &wire).expect("decrypt");
        let elapsed = start.elapsed();
        assert_eq!(dec, pt);
        assert!(
            elapsed.as_secs() < 10,
            "50 MiB round-trip took {elapsed:?} — suspiciously slow",
        );
    }

    // ----- Test 9: Resumable decrypt ----------------------------------------

    #[test]
    fn resume_at_matches_tail() {
        let key = test_key(0xDD);
        let size = 5 * STREAM_CHUNK_SIZE;
        let mut pt = vec![0u8; size];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x11);
        }
        let wire = encrypt_to_vec(&key, &pt);

        // Sanity-check: normal decrypt of the whole stream equals pt.
        let full = decrypt_to_vec(&key, &wire).expect("decrypt");
        assert_eq!(full, pt);

        // Resume at chunk 3 -> plaintext[3 MiB..5 MiB].
        let mut r =
            EncryptedFileReader::resume_at(Cursor::new(&wire), &key, 3).expect("resume");
        let mut resumed: Vec<u8> = Vec::new();
        let mut scratch = [0u8; 8192];
        loop {
            let n = r.read(&mut scratch).expect("resume read");
            if n == 0 {
                break;
            }
            resumed.extend_from_slice(&scratch[..n]);
        }
        assert_eq!(resumed, pt[3 * STREAM_CHUNK_SIZE..]);
    }

    // ----- Test 10: Hostile stream_id ---------------------------------------

    #[test]
    fn hostile_stream_id_collision_still_authenticates() {
        let key_a = test_key(0xE1);
        let key_b = test_key(0xE2);
        let pt_a = b"alpha payload, carried under key_a".to_vec();
        let pt_b = b"bravo payload, carried under key_b".to_vec();

        let wire_a = encrypt_to_vec(&key_a, &pt_a);
        let mut wire_b = encrypt_to_vec(&key_b, &pt_b);

        // Baseline: each stream decrypts correctly under its own header
        // + own key.
        let dec_a = decrypt_to_vec(&key_a, &wire_a).expect("decrypt A");
        assert_eq!(dec_a, pt_a);
        let dec_b = decrypt_to_vec(&key_b, &wire_b).expect("decrypt B");
        assert_eq!(dec_b, pt_b);

        // Hostile swap: copy A's stream_id into B's header, then attempt
        // to decrypt B with key_b. This MUST fail because the AAD binds
        // every tag to the original per-stream id — rewriting the header
        // flips the AAD used during verification and the tag check
        // rejects. That's the intended property: an attacker cannot
        // re-label a foreign stream to pass it off under someone else's
        // stream_id.
        wire_b[..STREAM_ID_LEN].copy_from_slice(&wire_a[..STREAM_ID_LEN]);
        let err = decrypt_to_vec(&key_b, &wire_b).expect_err("must fail");
        assert_eq!(err, CryptoError::Decryption);
    }

    // ----- Additional coverage: invalid header and nonce/AAD layout --------

    #[test]
    fn short_header_fails() {
        let key = test_key(0xFA);
        let short = vec![0u8; HEADER_LEN - 1];
        let err = EncryptedFileReader::new(Cursor::new(short), &key).expect_err("must fail");
        assert_eq!(err, CryptoError::StreamInvalidHeader);
    }

    #[test]
    fn nonce_layout_is_stable() {
        // Smoke-check the nonce bytes directly so any accidental
        // endianness drift is caught in CI. This exact layout MUST not
        // change without a major-version bump.
        let stream_id = [0x11u8; STREAM_ID_LEN];
        let n0 = derive_nonce(&stream_id, 0, false);
        let n0_last = derive_nonce(&stream_id, 0, true);
        let n1 = derive_nonce(&stream_id, 1, false);
        // Stream-id prefix identical for all three.
        assert_eq!(&n0[..STREAM_ID_LEN], &stream_id);
        // Counter at nonce[20..24] little-endian.
        assert_eq!(&n0[20..24], &[0, 0, 0, 0]);
        assert_eq!(&n1[20..24], &[1, 0, 0, 0]);
        // Last-chunk flag in top bit of nonce[23].
        assert_eq!(n0_last[23], 0x80);
        assert_ne!(n0_last, n0);
    }

    #[test]
    fn aad_layout_is_stable() {
        let stream_id = [0x22u8; STREAM_ID_LEN];
        let aad = build_aad(&stream_id, 5, true);
        assert_eq!(aad.len(), STREAM_ID_LEN + CHUNK_COUNTER_LEN + 1);
        assert_eq!(&aad[..STREAM_ID_LEN], &stream_id);
        assert_eq!(
            &aad[STREAM_ID_LEN..STREAM_ID_LEN + CHUNK_COUNTER_LEN],
            &[5, 0, 0, 0]
        );
        assert_eq!(aad[STREAM_ID_LEN + CHUNK_COUNTER_LEN], 1);
    }

    // ----- Internal helpers for the reorder/replay/tamper tests -------------

    /// Returns byte offsets (from stream start) of every chunk's LEN prefix.
    fn enumerate_chunk_offsets(wire: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut cursor = HEADER_LEN;
        while cursor + LEN_PREFIX_LEN <= wire.len() {
            offsets.push(cursor);
            let mut len_buf = [0u8; LEN_PREFIX_LEN];
            len_buf.copy_from_slice(&wire[cursor..cursor + LEN_PREFIX_LEN]);
            let len = u32::from_be_bytes(len_buf) as usize;
            cursor += LEN_PREFIX_LEN + len;
        }
        offsets
    }

    /// Returns the (start, end) byte range of the chunk whose LEN prefix
    /// starts at `offset`. The range covers both the LEN prefix and the
    /// ciphertext + tag.
    fn chunk_span(wire: &[u8], offset: usize) -> (usize, usize) {
        let mut len_buf = [0u8; LEN_PREFIX_LEN];
        len_buf.copy_from_slice(&wire[offset..offset + LEN_PREFIX_LEN]);
        let len = u32::from_be_bytes(len_buf) as usize;
        (offset, offset + LEN_PREFIX_LEN + len)
    }

    /// Returns the offset of the last chunk's LEN prefix.
    fn find_last_chunk_offset(wire: &[u8]) -> usize {
        let offsets = enumerate_chunk_offsets(wire);
        *offsets.last().expect("stream has at least one chunk")
    }
}
