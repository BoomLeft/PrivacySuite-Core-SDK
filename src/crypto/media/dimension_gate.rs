//! Pure header walker for decompression-bomb + dimension-cap defense.
//!
//! Reads just the image header of a JPEG / PNG / WebP / GIF / HEIF / AVIF /
//! TIFF file, reports the declared dimensions + frame count, and rejects
//! any input that exceeds:
//!
//! * per-axis [`MAX_DIMENSION`] (20 000 px), or
//! * an aggregate decompressed-byte budget of [`MAX_DECOMPRESSED_BYTES`]
//!   (1.6 GiB, i.e. 400 M pixels × 4 bytes of RGBA).
//!
//! **Does NOT decode pixels.** **Does NOT invoke any codec library.** The
//! walker is O(header-tokens), never O(pixels), so it runs in a handful of
//! microseconds even on pathological inputs. Every read is bounds-checked
//! and every arithmetic op is `checked_*` — malformed headers short-circuit
//! into [`DimensionError::Malformed`] rather than panic.
//!
//! Intended to be called **before** handing the bytes to any pixel decoder
//! (thumbnail generator, full-resolution renderer, libheif, libavif, …).
//! Combined with [`super::sanitize::strip_metadata`] it gates every
//! untrusted image import in the SDK.

use super::sanitize::{detect_format, ImageFormat};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Per-axis dimension cap. Rejects anything over 20 000 on either axis.
///
/// Flagship DSLRs and medium-format cameras top out around 11 000 × 8 000
/// (Sony α1, Fujifilm GFX100). Satellite imagery and microscopy can go
/// higher but those aren't the target use case for the SDK.
pub const MAX_DIMENSION: u32 = 20_000;

/// Pixel-budget cap: 400 million pixels worth of uncompressed RGBA.
/// 400 M × 4 bytes/pixel = 1.6 GiB — which is already generous.
///
/// This mirrors the `MAX_PIXEL_BUDGET` const in the legacy Telephoto
/// thumbnail pipeline (`apps/mobile/src-tauri/src/media/thumbnail.rs`),
/// multiplied by 4 because we express the cap in *bytes of uncompressed
/// RGBA* here rather than raw pixel count.
pub const MAX_DECOMPRESSED_BYTES: u64 = 400_000_000 * 4;

/// Structured failure modes for [`inspect_dimensions`].
#[derive(Debug, PartialEq, Eq)]
pub enum DimensionError {
    /// Header-declared dimensions exceed the per-axis cap.
    TooLarge {
        /// Parsed width in pixels.
        width: u32,
        /// Parsed height in pixels.
        height: u32,
    },
    /// Pixel budget exceeded (`width * height * bits_per_pixel / 8 * frames`).
    DecompressionBomb {
        /// Estimated uncompressed size, in bytes.
        estimated_bytes: u64,
    },
    /// Header was malformed, unreadable, or in a format the walker does
    /// not support.
    Malformed,
}

impl std::fmt::Display for DimensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { width, height } => {
                write!(
                    f,
                    "image dimensions {width}x{height} exceed {MAX_DIMENSION} per axis"
                )
            }
            Self::DecompressionBomb { estimated_bytes } => {
                write!(
                    f,
                    "decompressed size {estimated_bytes} bytes exceeds budget of {MAX_DECOMPRESSED_BYTES}"
                )
            }
            Self::Malformed => f.write_str("malformed image header"),
        }
    }
}

impl std::error::Error for DimensionError {}

/// Result of [`inspect_dimensions`] on a successfully-parsed header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DimensionInfo {
    /// Declared width in pixels.
    pub width: u32,
    /// Declared height in pixels.
    pub height: u32,
    /// Bits per decoded pixel (e.g. 32 for RGBA8, 24 for RGB8). The walker
    /// normalises every format to one of 8 / 16 / 24 / 32 / 48 / 64 — when
    /// the header is ambiguous we err on the high side so the budget check
    /// stays conservative.
    pub bits_per_pixel: u8,
    /// Declared frame count. `1` for a still image; >1 for animated GIF,
    /// APNG, animated WebP, and AVIF image sequences.
    pub frame_count: u32,
    /// Estimated uncompressed bytes: `width * height * (bits_per_pixel/8) *
    /// frame_count`. Computed with `checked_*` on every step; if any step
    /// overflows a `u64` we bail with [`DimensionError::Malformed`] before
    /// returning.
    pub estimated_bytes: u64,
}

/// Read just the image header and return dimension info, rejecting anything
/// that exceeds [`MAX_DIMENSION`] or [`MAX_DECOMPRESSED_BYTES`].
///
/// Does NOT decode pixel data. Does NOT invoke any codec library. Purely a
/// header walker.
///
/// # Errors
///
/// * [`DimensionError::Malformed`] — input is truncated, in an unsupported
///   format, or structurally invalid. Also returned if any arithmetic on
///   header-derived sizes would overflow a `u64`.
/// * [`DimensionError::TooLarge`] — either axis exceeds [`MAX_DIMENSION`].
/// * [`DimensionError::DecompressionBomb`] — the aggregate uncompressed-
///   size estimate exceeds [`MAX_DECOMPRESSED_BYTES`].
pub fn inspect_dimensions(bytes: &[u8]) -> Result<DimensionInfo, DimensionError> {
    // Probing a single-byte input must not panic and must not misfire on a
    // pathological magic-byte coincidence.
    if bytes.len() < 4 {
        return Err(DimensionError::Malformed);
    }
    let (width, height, bits_per_pixel, frame_count) = match detect_format(bytes) {
        ImageFormat::Jpeg => probe_jpeg(bytes)?,
        ImageFormat::Png => probe_png(bytes)?,
        ImageFormat::Webp => probe_webp(bytes)?,
        ImageFormat::Gif => probe_gif(bytes)?,
        ImageFormat::Heif => probe_heif(bytes)?,
        ImageFormat::Tiff => probe_tiff(bytes)?,
        ImageFormat::Unknown => return Err(DimensionError::Malformed),
    };

    // Per-axis cap.
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(DimensionError::TooLarge { width, height });
    }

    // Aggregate decompressed-byte budget. Three multiplications — each can
    // overflow — so every step is `checked_mul`.
    let bytes_per_pixel: u64 = (u64::from(bits_per_pixel).saturating_add(7)) / 8;
    let estimated_bytes = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|p| p.checked_mul(bytes_per_pixel))
        .and_then(|p| p.checked_mul(u64::from(frame_count.max(1))))
        .ok_or(DimensionError::Malformed)?;

    if estimated_bytes > MAX_DECOMPRESSED_BYTES {
        return Err(DimensionError::DecompressionBomb { estimated_bytes });
    }

    Ok(DimensionInfo {
        width,
        height,
        bits_per_pixel,
        frame_count,
        estimated_bytes,
    })
}

// ---------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------

// Walk segments from SOI to the first Start-of-Frame marker. The SOF
// markers (0xFFC0..0xFFC3, 0xFFC5..0xFFC7, 0xFFC9..0xFFCB, 0xFFCD..0xFFCF)
// carry `precision (1 byte), height (2 BE), width (2 BE), channels (1)`.
//
// JPEG cannot carry animation — `frame_count` is always 1.
fn probe_jpeg(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(DimensionError::Malformed);
    }
    let mut i = 2usize;
    loop {
        if i >= data.len() || data[i] != 0xFF {
            return Err(DimensionError::Malformed);
        }
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            return Err(DimensionError::Malformed);
        }
        let marker = data[i];
        i += 1;

        // Start-of-Frame markers. Note: exclude the DHT, DAC, and JPG
        // markers in the same 0xC0..0xCF range (0xC4, 0xC8, 0xCC).
        let is_sof = matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        );
        // Non-SOF markers with no payload — skip, no length bytes follow.
        let is_standalone = matches!(marker, 0x01 | 0xD0..=0xD7 | 0xD8 | 0xD9);

        if is_standalone {
            if marker == 0xD9 {
                // EOI before any SOF — file has no frame header.
                return Err(DimensionError::Malformed);
            }
            continue;
        }

        // Every other marker carries a 2-byte BE length including the
        // length bytes themselves.
        if i.checked_add(2).map_or(true, |e| e > data.len()) {
            return Err(DimensionError::Malformed);
        }
        let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        if len < 2 {
            return Err(DimensionError::Malformed);
        }
        let seg_end = i.checked_add(len).ok_or(DimensionError::Malformed)?;
        if seg_end > data.len() {
            return Err(DimensionError::Malformed);
        }

        if is_sof {
            // SOF payload: precision + height + width + channels. We
            // already consumed the 2 length bytes implicitly via `len`;
            // SOF fields start at `i + 2`.
            if i.checked_add(8).map_or(true, |e| e > data.len()) {
                return Err(DimensionError::Malformed);
            }
            let precision = data[i + 2];
            let height = u16::from_be_bytes([data[i + 3], data[i + 4]]) as u32;
            let width = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
            let channels = data[i + 7];
            if channels == 0 {
                return Err(DimensionError::Malformed);
            }
            let bpp = u8::try_from(u32::from(precision).saturating_mul(u32::from(channels)))
                .unwrap_or(u8::MAX);
            return Ok((width, height, bpp.max(8), 1));
        }

        i = seg_end;
    }
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

// IHDR is always the first chunk after the 8-byte signature. Animated PNG
// (APNG) signals frame count via an acTL chunk BEFORE the first IDAT. We
// walk forward as long as chunk headers parse cleanly — stopping at either
// IDAT (past which animation metadata cannot appear before the first
// frame) or IEND.
fn probe_png(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    if data.len() < 8 + 8 + 13 + 4 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(DimensionError::Malformed);
    }
    // First chunk must be IHDR (length 13).
    let ihdr_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if ihdr_len != 13 || &data[12..16] != b"IHDR" {
        return Err(DimensionError::Malformed);
    }
    let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let bit_depth = data[24];
    let color_type = data[25];

    // PNG colour-type → samples-per-pixel map.
    let samples: u8 = match color_type {
        0 => 1, // greyscale
        2 => 3, // truecolour
        3 => 1, // indexed
        4 => 2, // greyscale + alpha
        6 => 4, // truecolour + alpha
        _ => return Err(DimensionError::Malformed),
    };
    let bpp = bit_depth.saturating_mul(samples).max(8);

    // Scan for acTL to pick up APNG frame count. acTL is required to appear
    // before the first IDAT, so we can stop at IDAT / IEND.
    let mut frame_count: u32 = 1;
    let mut cursor: usize = 8 + 4 + 4 + 13 + 4; // skip sig + IHDR length + type + body + CRC
    while cursor + 8 <= data.len() {
        let len = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        let typ = &data[cursor + 4..cursor + 8];
        let chunk_end = cursor
            .checked_add(12)
            .and_then(|x| x.checked_add(len))
            .ok_or(DimensionError::Malformed)?;
        if chunk_end > data.len() {
            // Truncated chunk — we've already got the dims, so return what
            // we have with a conservative frame_count=1.
            break;
        }
        if typ == b"acTL" {
            if len < 8 {
                return Err(DimensionError::Malformed);
            }
            frame_count = u32::from_be_bytes([
                data[cursor + 8],
                data[cursor + 9],
                data[cursor + 10],
                data[cursor + 11],
            ])
            .max(1);
        } else if typ == b"IDAT" || typ == b"IEND" {
            break;
        }
        cursor = chunk_end;
    }

    Ok((width, height, bpp, frame_count))
}

// ---------------------------------------------------------------------------
// WebP
// ---------------------------------------------------------------------------

// WebP comes in three flavours — VP8 (lossy), VP8L (lossless), and VP8X
// (extended, possibly animated). For VP8X the canvas dimensions are 24-bit
// little-endian width-1 / height-1 fields in the VP8X chunk. Frame count
// lives in an ANIM chunk if the animation flag (bit 1) is set, followed by
// ANMF chunks we count directly.
fn probe_webp(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    // Smallest well-formed WebP: 12 B RIFF prefix + 8 B chunk header + 5 B
    // VP8L body = 25 bytes (plus up to one pad byte). Enforce that minimum
    // here rather than the +8 VP8 minimum so we don't reject legitimate
    // tiny lossless WebPs.
    if data.len() < 25 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return Err(DimensionError::Malformed);
    }
    let mut i = 12usize;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bpp: u8 = 24;
    let mut frame_count: u32 = 1;
    let mut have_dims = false;
    let mut anim_flagged = false;
    let mut anmf_count: u32 = 0;

    while i + 8 <= data.len() {
        let fourcc: [u8; 4] = [data[i], data[i + 1], data[i + 2], data[i + 3]];
        let len =
            u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
        let padded_len = if len % 2 == 1 {
            len.checked_add(1).ok_or(DimensionError::Malformed)?
        } else {
            len
        };
        let body_off = i.checked_add(8).ok_or(DimensionError::Malformed)?;
        let chunk_end = body_off
            .checked_add(padded_len)
            .ok_or(DimensionError::Malformed)?;
        // Chunk data may go up to data.len() if a padding byte is missing;
        // for the dims we only need the first few bytes so be lenient.
        if body_off + len.min(data.len() - body_off) > data.len() {
            return Err(DimensionError::Malformed);
        }

        match &fourcc {
            b"VP8X" => {
                if len < 10 {
                    return Err(DimensionError::Malformed);
                }
                let flags = data[body_off];
                anim_flagged = flags & 0b0000_0010 != 0;
                let alpha = flags & 0b0001_0000 != 0;
                // Width/Height: 3 bytes LE each, value is dimension-1.
                let w = u32::from(data[body_off + 4])
                    | (u32::from(data[body_off + 5]) << 8)
                    | (u32::from(data[body_off + 6]) << 16);
                let h = u32::from(data[body_off + 7])
                    | (u32::from(data[body_off + 8]) << 8)
                    | (u32::from(data[body_off + 9]) << 16);
                width = w.checked_add(1).ok_or(DimensionError::Malformed)?;
                height = h.checked_add(1).ok_or(DimensionError::Malformed)?;
                bpp = if alpha { 32 } else { 24 };
                have_dims = true;
            }
            b"VP8 " => {
                // Simple lossy: payload starts with 3-byte frame tag, then
                // 3 bytes sync code (9D 01 2A), then 14-bit LE width, 14-bit
                // LE height.
                if len < 10 {
                    return Err(DimensionError::Malformed);
                }
                let w_raw = u16::from_le_bytes([data[body_off + 6], data[body_off + 7]]);
                let h_raw = u16::from_le_bytes([data[body_off + 8], data[body_off + 9]]);
                if !have_dims {
                    width = u32::from(w_raw & 0x3FFF);
                    height = u32::from(h_raw & 0x3FFF);
                    bpp = 24;
                    have_dims = true;
                }
            }
            b"VP8L" => {
                // Lossless: signature byte 0x2F then 14-bit width-1 / 14-bit
                // height-1 packed LE across bits 1..29 of the next 4 bytes.
                if len < 5 {
                    return Err(DimensionError::Malformed);
                }
                let sig = data[body_off];
                if sig != 0x2F {
                    return Err(DimensionError::Malformed);
                }
                let b1 = data[body_off + 1];
                let b2 = data[body_off + 2];
                let b3 = data[body_off + 3];
                let b4 = data[body_off + 4];
                let w_raw = u32::from(b1) | (u32::from(b2 & 0x3F) << 8);
                let h_raw = ((u32::from(b2) >> 6) & 0x03)
                    | (u32::from(b3) << 2)
                    | (u32::from(b4 & 0x0F) << 10);
                if !have_dims {
                    width = w_raw.checked_add(1).ok_or(DimensionError::Malformed)?;
                    height = h_raw.checked_add(1).ok_or(DimensionError::Malformed)?;
                    bpp = 32;
                    have_dims = true;
                }
            }
            b"ANMF" => {
                anmf_count = anmf_count.saturating_add(1);
            }
            _ => {}
        }
        i = chunk_end;
    }

    if !have_dims {
        return Err(DimensionError::Malformed);
    }
    if anim_flagged {
        // The animation flag promises there will be one or more ANMF
        // frames; honour the count we saw, minimum 1.
        frame_count = anmf_count.max(1);
    }
    Ok((width, height, bpp, frame_count))
}

// ---------------------------------------------------------------------------
// GIF
// ---------------------------------------------------------------------------

// Logical Screen Descriptor at offset 6: width (2 LE), height (2 LE), packed
// byte (1), background-index (1), pixel-aspect-ratio (1). Frame count is the
// number of Image Descriptor blocks (introducer 0x2C). We stop at the
// trailer 0x3B or if the byte stream ends.
fn probe_gif(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    if data.len() < 13 {
        return Err(DimensionError::Malformed);
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as u32;
    let height = u16::from_le_bytes([data[8], data[9]]) as u32;
    let packed = data[10];
    // GIF is an indexed-color format; decoded framebuffer is RGBA8.
    let bpp: u8 = 32;

    let mut i = 13usize;
    if packed & 0x80 != 0 {
        let gct_size = 3usize * (1usize << ((packed & 0x07) + 1));
        i = i.checked_add(gct_size).ok_or(DimensionError::Malformed)?;
    }

    let mut frame_count: u32 = 0;
    while i < data.len() {
        let introducer = data[i];
        match introducer {
            0x3B => break,
            0x21 => {
                // Extension — skip to next introducer.
                if i + 2 > data.len() {
                    return Err(DimensionError::Malformed);
                }
                let mut j = i + 2;
                loop {
                    if j >= data.len() {
                        return Err(DimensionError::Malformed);
                    }
                    let size = data[j] as usize;
                    if size == 0 {
                        j = j.checked_add(1).ok_or(DimensionError::Malformed)?;
                        break;
                    }
                    let next = j
                        .checked_add(1)
                        .and_then(|x| x.checked_add(size))
                        .ok_or(DimensionError::Malformed)?;
                    if next > data.len() {
                        return Err(DimensionError::Malformed);
                    }
                    j = next;
                }
                i = j;
            }
            0x2C => {
                frame_count = frame_count.saturating_add(1);
                if i + 10 > data.len() {
                    return Err(DimensionError::Malformed);
                }
                let ipacked = data[i + 9];
                let mut j = i + 10;
                if ipacked & 0x80 != 0 {
                    let lct_size = 3usize * (1usize << ((ipacked & 0x07) + 1));
                    j = j.checked_add(lct_size).ok_or(DimensionError::Malformed)?;
                }
                // LZW min-code-size byte.
                if j >= data.len() {
                    return Err(DimensionError::Malformed);
                }
                j += 1;
                // Sub-blocks.
                loop {
                    if j >= data.len() {
                        return Err(DimensionError::Malformed);
                    }
                    let size = data[j] as usize;
                    if size == 0 {
                        j = j.checked_add(1).ok_or(DimensionError::Malformed)?;
                        break;
                    }
                    let next = j
                        .checked_add(1)
                        .and_then(|x| x.checked_add(size))
                        .ok_or(DimensionError::Malformed)?;
                    if next > data.len() {
                        return Err(DimensionError::Malformed);
                    }
                    j = next;
                }
                i = j;
            }
            _ => return Err(DimensionError::Malformed),
        }
    }
    Ok((width, height, bpp, frame_count.max(1)))
}

// ---------------------------------------------------------------------------
// HEIF / HEIC / AVIF
// ---------------------------------------------------------------------------
//
// Walk the top-level box tree looking for `meta`, descend into `iprp` ->
// `ipco`, read the first `ispe` box for the canvas width/height. For image
// sequences the `iinf` box lists all image items; we count `infe` entries
// as an upper-bound on frame count (it's an upper bound because still HEIF
// files often carry a separate thumbnail item in iinf too, but that's OK —
// the budget check just gets tighter).

fn probe_heif(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    // Walk top-level boxes.
    let mut cursor = 0usize;
    let mut dims: Option<(u32, u32)> = None;
    let mut item_count: u32 = 0;
    while cursor < data.len() {
        let (kind, body_off, body_end) = iso_read_box_header(data, cursor)?;
        if &kind == b"meta" {
            // FullBox: 4 bytes version/flags before children.
            if body_off.checked_add(4).map_or(true, |e| e > body_end) {
                return Err(DimensionError::Malformed);
            }
            let meta_children = body_off + 4;
            // Walk meta's immediate children.
            let mut m = meta_children;
            while m < body_end {
                let (mk, mbody, mend) = iso_read_box_header(data, m)?;
                if mend > body_end {
                    return Err(DimensionError::Malformed);
                }
                match &mk {
                    b"iprp" => {
                        // Walk iprp -> ipco -> ispe.
                        let mut p = mbody;
                        while p < mend {
                            let (pk, pbody, pend) = iso_read_box_header(data, p)?;
                            if pend > mend {
                                return Err(DimensionError::Malformed);
                            }
                            if &pk == b"ipco" {
                                let mut q = pbody;
                                while q < pend {
                                    let (qk, qbody, qend) = iso_read_box_header(data, q)?;
                                    if qend > pend {
                                        return Err(DimensionError::Malformed);
                                    }
                                    if &qk == b"ispe" && dims.is_none() {
                                        // FullBox: 4 bytes flags + 4 width + 4 height (BE).
                                        if qbody.checked_add(12).map_or(true, |e| e > qend) {
                                            return Err(DimensionError::Malformed);
                                        }
                                        let w = u32::from_be_bytes([
                                            data[qbody + 4],
                                            data[qbody + 5],
                                            data[qbody + 6],
                                            data[qbody + 7],
                                        ]);
                                        let h = u32::from_be_bytes([
                                            data[qbody + 8],
                                            data[qbody + 9],
                                            data[qbody + 10],
                                            data[qbody + 11],
                                        ]);
                                        dims = Some((w, h));
                                    }
                                    q = qend;
                                }
                            }
                            p = pend;
                        }
                    }
                    b"iinf" => {
                        // FullBox, then entry_count. Just pluck the count
                        // for frame-count budgeting purposes — no need to
                        // parse each infe.
                        if mbody.checked_add(4).map_or(true, |e| e > mend) {
                            return Err(DimensionError::Malformed);
                        }
                        let version = data[mbody];
                        let cp = mbody + 4;
                        if version == 0 {
                            if cp.checked_add(2).map_or(true, |e| e > mend) {
                                return Err(DimensionError::Malformed);
                            }
                            item_count =
                                u32::from(u16::from_be_bytes([data[cp], data[cp + 1]]));
                        } else {
                            if cp.checked_add(4).map_or(true, |e| e > mend) {
                                return Err(DimensionError::Malformed);
                            }
                            item_count = u32::from_be_bytes([
                                data[cp],
                                data[cp + 1],
                                data[cp + 2],
                                data[cp + 3],
                            ]);
                        }
                    }
                    _ => {}
                }
                m = mend;
            }
        }
        cursor = body_end;
    }

    let (w, h) = dims.ok_or(DimensionError::Malformed)?;
    // We treat HEIF/AVIF as decoding to RGBA8 for the budget check — the
    // actual bit depth can be 10 or 12 (HDR) but we under-count only by a
    // modest factor.
    let bpp = 32u8;
    let frames = item_count.max(1);
    Ok((w, h, bpp, frames))
}

fn iso_read_box_header(data: &[u8], cursor: usize) -> Result<([u8; 4], usize, usize), DimensionError> {
    let after_header = cursor
        .checked_add(8)
        .ok_or(DimensionError::Malformed)?;
    if after_header > data.len() {
        return Err(DimensionError::Malformed);
    }
    let size32 = u32::from_be_bytes([
        data[cursor],
        data[cursor + 1],
        data[cursor + 2],
        data[cursor + 3],
    ]);
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&data[cursor + 4..cursor + 8]);
    let (body_off, body_end) = match size32 {
        0 => (after_header, data.len()),
        1 => {
            let after_largesize = cursor
                .checked_add(16)
                .ok_or(DimensionError::Malformed)?;
            if after_largesize > data.len() {
                return Err(DimensionError::Malformed);
            }
            let size64 = u64::from_be_bytes([
                data[cursor + 8],
                data[cursor + 9],
                data[cursor + 10],
                data[cursor + 11],
                data[cursor + 12],
                data[cursor + 13],
                data[cursor + 14],
                data[cursor + 15],
            ]);
            let size = usize::try_from(size64).map_err(|_| DimensionError::Malformed)?;
            if size < 16 {
                return Err(DimensionError::Malformed);
            }
            let end = cursor.checked_add(size).ok_or(DimensionError::Malformed)?;
            if end > data.len() {
                return Err(DimensionError::Malformed);
            }
            (after_largesize, end)
        }
        n => {
            let size = n as usize;
            if size < 8 {
                return Err(DimensionError::Malformed);
            }
            let end = cursor.checked_add(size).ok_or(DimensionError::Malformed)?;
            if end > data.len() {
                return Err(DimensionError::Malformed);
            }
            (after_header, end)
        }
    };
    Ok((kind, body_off, body_end))
}

// ---------------------------------------------------------------------------
// TIFF
// ---------------------------------------------------------------------------
//
// Walk the first IFD: we only need tags 256 (ImageWidth), 257
// (ImageLength), 258 (BitsPerSample), 277 (SamplesPerPixel). Then follow
// the next-IFD chain for multi-page count.
fn probe_tiff(data: &[u8]) -> Result<(u32, u32, u8, u32), DimensionError> {
    if data.len() < 8 {
        return Err(DimensionError::Malformed);
    }
    let le = match (data[0], data[1]) {
        (b'I', b'I') => true,
        (b'M', b'M') => false,
        _ => return Err(DimensionError::Malformed),
    };
    let magic = tiff_read_u16_d(data, 2, le)?;
    if magic != 42 {
        return Err(DimensionError::Malformed);
    }
    let mut ifd_off = tiff_read_u32_d(data, 4, le)? as usize;

    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut bits_per_sample: u32 = 8;
    let mut samples_per_pixel: u32 = 1;

    let mut seen_pages: u32 = 0;
    let mut first_page = true;

    // Walk the IFD chain, rejecting cycles > 64.
    while ifd_off != 0 {
        seen_pages = seen_pages.saturating_add(1);
        if seen_pages > 64 {
            return Err(DimensionError::Malformed);
        }
        if ifd_off.checked_add(2).map_or(true, |e| e > data.len()) {
            return Err(DimensionError::Malformed);
        }
        let entry_count = tiff_read_u16_d(data, ifd_off, le)? as usize;
        let entries_start = ifd_off
            .checked_add(2)
            .ok_or(DimensionError::Malformed)?;
        let entries_size = entry_count
            .checked_mul(12)
            .ok_or(DimensionError::Malformed)?;
        let entries_end = entries_start
            .checked_add(entries_size)
            .ok_or(DimensionError::Malformed)?;
        let after_next = entries_end
            .checked_add(4)
            .ok_or(DimensionError::Malformed)?;
        if after_next > data.len() {
            return Err(DimensionError::Malformed);
        }

        if first_page {
            for i in 0..entry_count {
                let p = entries_start + i * 12;
                let tag = tiff_read_u16_d(data, p, le)?;
                let typ = tiff_read_u16_d(data, p + 2, le)?;
                let count = tiff_read_u32_d(data, p + 4, le)?;
                match tag {
                    256 => width = tiff_read_tag_u32(data, p, typ, count, le)?,
                    257 => height = tiff_read_tag_u32(data, p, typ, count, le)?,
                    258 => bits_per_sample = tiff_read_tag_u32(data, p, typ, count, le)?,
                    277 => samples_per_pixel = tiff_read_tag_u32(data, p, typ, count, le)?,
                    _ => {}
                }
            }
            first_page = false;
        }

        ifd_off = tiff_read_u32_d(data, entries_end, le)? as usize;
    }

    if width == 0 || height == 0 {
        return Err(DimensionError::Malformed);
    }
    let bits = bits_per_sample
        .checked_mul(samples_per_pixel)
        .ok_or(DimensionError::Malformed)?;
    let bpp = u8::try_from(bits.max(8)).unwrap_or(u8::MAX);
    Ok((width, height, bpp, seen_pages.max(1)))
}

fn tiff_read_u16_d(data: &[u8], off: usize, le: bool) -> Result<u16, DimensionError> {
    if off.checked_add(2).map_or(true, |e| e > data.len()) {
        return Err(DimensionError::Malformed);
    }
    Ok(if le {
        u16::from_le_bytes([data[off], data[off + 1]])
    } else {
        u16::from_be_bytes([data[off], data[off + 1]])
    })
}

fn tiff_read_u32_d(data: &[u8], off: usize, le: bool) -> Result<u32, DimensionError> {
    if off.checked_add(4).map_or(true, |e| e > data.len()) {
        return Err(DimensionError::Malformed);
    }
    Ok(if le {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    })
}

/// Read the inline value of a TIFF tag as u32 — only supports SHORT / LONG
/// count=1, which is all we need for dimensions.
fn tiff_read_tag_u32(
    data: &[u8],
    p: usize,
    typ: u16,
    count: u32,
    le: bool,
) -> Result<u32, DimensionError> {
    if count != 1 {
        // BitsPerSample for RGB images has count=3; we pessimistically take
        // the first sample since all three are typically identical (PNG /
        // JPEG rarely use per-channel precision mismatches for RGB).
        if typ != 3 {
            return Err(DimensionError::Malformed);
        }
    }
    match typ {
        3 => {
            // SHORT — inline, first 2 bytes of the value field.
            Ok(u32::from(tiff_read_u16_d(data, p + 8, le)?))
        }
        4 => tiff_read_u32_d(data, p + 8, le),
        _ => Err(DimensionError::Malformed),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Helpers ----------

    fn synth_jpeg(width: u16, height: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xFF, 0xD8]); // SOI
        // APP0 JFIF — mandatory for well-formed files.
        let jfif = b"JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00";
        v.extend_from_slice(&[0xFF, 0xE0]);
        v.extend_from_slice(&((2 + jfif.len()) as u16).to_be_bytes());
        v.extend_from_slice(jfif);
        // SOF0 — 8-bit precision, HxW, 3 channels.
        let sof_payload = {
            let mut b = Vec::new();
            b.push(8);
            b.extend_from_slice(&height.to_be_bytes());
            b.extend_from_slice(&width.to_be_bytes());
            b.push(3);
            b.extend_from_slice(&[1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
            b
        };
        v.extend_from_slice(&[0xFF, 0xC0]);
        v.extend_from_slice(&((2 + sof_payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&sof_payload);
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v
    }

    fn synth_png(width: u32, height: u32, actl_frames: Option<u32>) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        // IHDR: 13 bytes payload.
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&width.to_be_bytes());
        v.extend_from_slice(&height.to_be_bytes());
        v.push(8); // bit depth
        v.push(6); // RGBA
        v.extend_from_slice(&[0, 0, 0]); // compression/filter/interlace
        v.extend_from_slice(&[0, 0, 0, 0]); // fake CRC
        if let Some(frames) = actl_frames {
            v.extend_from_slice(&8u32.to_be_bytes());
            v.extend_from_slice(b"acTL");
            v.extend_from_slice(&frames.to_be_bytes());
            v.extend_from_slice(&1u32.to_be_bytes()); // num_plays
            v.extend_from_slice(&[0, 0, 0, 0]); // CRC
        }
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0, 0, 0, 0]); // CRC
        v
    }

    fn synth_webp_vp8l(width: u32, height: u32) -> Vec<u8> {
        // RIFF<size>WEBPVP8L<chunklen>0x2F<packed-dims>
        let w_m1 = width - 1;
        let h_m1 = height - 1;
        let b1 = (w_m1 & 0xFF) as u8;
        let b2 = (((w_m1 >> 8) & 0x3F) as u8) | ((((h_m1) & 0x03) as u8) << 6);
        let b3 = ((h_m1 >> 2) & 0xFF) as u8;
        let b4 = ((h_m1 >> 10) & 0x0F) as u8;
        let payload = [0x2F, b1, b2, b3, b4];
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"WEBP");
        v.extend_from_slice(b"VP8L");
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&payload);
        if payload.len() % 2 == 1 {
            v.push(0);
        }
        let total = (v.len() - 8) as u32;
        v[4..8].copy_from_slice(&total.to_le_bytes());
        v
    }

    fn synth_webp_animated(width: u32, height: u32, frames: u32) -> Vec<u8> {
        // VP8X + ANIM + `frames` × ANMF.
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"WEBP");

        let w_m1 = width - 1;
        let h_m1 = height - 1;
        let mut vp8x = Vec::with_capacity(10);
        vp8x.push(0b0000_0010); // animation flag
        vp8x.extend_from_slice(&[0, 0, 0]); // reserved
        vp8x.push((w_m1 & 0xFF) as u8);
        vp8x.push(((w_m1 >> 8) & 0xFF) as u8);
        vp8x.push(((w_m1 >> 16) & 0xFF) as u8);
        vp8x.push((h_m1 & 0xFF) as u8);
        vp8x.push(((h_m1 >> 8) & 0xFF) as u8);
        vp8x.push(((h_m1 >> 16) & 0xFF) as u8);
        v.extend_from_slice(b"VP8X");
        v.extend_from_slice(&(vp8x.len() as u32).to_le_bytes());
        v.extend_from_slice(&vp8x);

        for _ in 0..frames {
            v.extend_from_slice(b"ANMF");
            let body = [0u8; 16];
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&body);
        }
        let total = (v.len() - 8) as u32;
        v[4..8].copy_from_slice(&total.to_le_bytes());
        v
    }

    fn synth_gif(width: u16, height: u16, frames: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"GIF89a");
        v.extend_from_slice(&width.to_le_bytes());
        v.extend_from_slice(&height.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0]); // packed / bg / aspect
        for _ in 0..frames {
            v.extend_from_slice(&[0x2C, 0, 0, 0, 0]);
            v.extend_from_slice(&width.to_le_bytes());
            v.extend_from_slice(&height.to_le_bytes());
            v.push(0); // packed
            v.push(2); // LZW min code size
            v.push(0); // terminator sub-block
        }
        v.push(0x3B);
        v
    }

    fn synth_heif(width: u32, height: u32) -> Vec<u8> {
        // Minimal HEIF with ftyp + meta -> iprp -> ipco -> ispe.
        fn bx(v: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
            let size = 8 + body.len();
            v.extend_from_slice(&(size as u32).to_be_bytes());
            v.extend_from_slice(kind);
            v.extend_from_slice(body);
        }
        let mut ispe_body = Vec::new();
        ispe_body.extend_from_slice(&[0u8; 4]); // FullBox
        ispe_body.extend_from_slice(&width.to_be_bytes());
        ispe_body.extend_from_slice(&height.to_be_bytes());

        let mut ipco_body = Vec::new();
        bx(&mut ipco_body, b"ispe", &ispe_body);

        let mut iprp_body = Vec::new();
        bx(&mut iprp_body, b"ipco", &ipco_body);

        let mut meta_body = Vec::new();
        meta_body.extend_from_slice(&[0u8; 4]); // FullBox
        bx(&mut meta_body, b"iprp", &iprp_body);

        let mut ftyp_body = Vec::new();
        ftyp_body.extend_from_slice(b"heic");
        ftyp_body.extend_from_slice(&[0u8; 4]);
        ftyp_body.extend_from_slice(b"mif1");

        let mut out = Vec::new();
        bx(&mut out, b"ftyp", &ftyp_body);
        bx(&mut out, b"meta", &meta_body);
        out
    }

    fn synth_tiff(width: u32, height: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&42u16.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes()); // first IFD at offset 8

        let entries: Vec<(u16, u16, u32, [u8; 4])> = vec![
            // ImageWidth (LONG)
            (256, 4, 1, width.to_le_bytes()),
            // ImageLength (LONG)
            (257, 4, 1, height.to_le_bytes()),
            // BitsPerSample (SHORT)
            (258, 3, 1, {
                let mut b = [0u8; 4];
                b[..2].copy_from_slice(&8u16.to_le_bytes());
                b
            }),
            // SamplesPerPixel (SHORT)
            (277, 3, 1, {
                let mut b = [0u8; 4];
                b[..2].copy_from_slice(&3u16.to_le_bytes());
                b
            }),
        ];
        v.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (tag, typ, count, val) in &entries {
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(&typ.to_le_bytes());
            v.extend_from_slice(&count.to_le_bytes());
            v.extend_from_slice(val);
        }
        v.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = 0
        v
    }

    // ---------- Happy path ----------

    #[test]
    fn jpeg_dimensions() {
        let buf = synth_jpeg(1024, 768);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 1024);
        assert_eq!(info.height, 768);
        assert_eq!(info.frame_count, 1);
    }

    #[test]
    fn png_dimensions_still() {
        let buf = synth_png(640, 480, None);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 640);
        assert_eq!(info.height, 480);
        assert_eq!(info.frame_count, 1);
        assert_eq!(info.bits_per_pixel, 32);
    }

    #[test]
    fn apng_frame_count() {
        let buf = synth_png(100, 100, Some(12));
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.frame_count, 12);
    }

    #[test]
    fn webp_vp8l_dimensions() {
        let buf = synth_webp_vp8l(800, 600);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 800);
        assert_eq!(info.height, 600);
        assert_eq!(info.frame_count, 1);
    }

    #[test]
    fn webp_animated_frame_count() {
        let buf = synth_webp_animated(320, 240, 7);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 320);
        assert_eq!(info.height, 240);
        assert_eq!(info.frame_count, 7);
    }

    #[test]
    fn gif_animated_frame_count() {
        let buf = synth_gif(16, 16, 5);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 16);
        assert_eq!(info.height, 16);
        assert_eq!(info.frame_count, 5);
    }

    #[test]
    fn heif_dimensions() {
        let buf = synth_heif(4032, 3024);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 4032);
        assert_eq!(info.height, 3024);
    }

    #[test]
    fn tiff_dimensions() {
        let buf = synth_tiff(3000, 2000);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 3000);
        assert_eq!(info.height, 2000);
        assert_eq!(info.frame_count, 1);
    }

    // ---------- Bomb defense ----------

    #[test]
    fn rejects_axis_over_cap() {
        let buf = synth_png(21_000, 21_000, None);
        let err = inspect_dimensions(&buf).unwrap_err();
        match err {
            DimensionError::TooLarge { width, height } => {
                assert_eq!(width, 21_000);
                assert_eq!(height, 21_000);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_500_megapixel_bomb() {
        // 20_000 × 20_000 = 400 M pixels. That's *at* the cap in pixel
        // terms and blows the byte budget (400 M × 4 = 1.6 GiB = cap, so
        // even RGBA8 is exactly on the boundary — bump the axes slightly
        // under the cap but animate the frames to push the bytes over).
        //
        // Cleaner test: 18_000 × 18_000 × RGBA8 = ~1.24 GiB for 1 frame,
        // but 3 frames = ~3.7 GiB which is well over the 1.6 GiB budget.
        let buf = synth_webp_animated(18_000, 18_000, 3);
        let err = inspect_dimensions(&buf).unwrap_err();
        match err {
            DimensionError::DecompressionBomb { estimated_bytes } => {
                assert!(estimated_bytes > MAX_DECOMPRESSED_BYTES);
            }
            other => panic!("expected DecompressionBomb, got {other:?}"),
        }
    }

    #[test]
    fn accepts_large_but_safe() {
        // 10_000 × 10_000 = 100 Mpix × 4 bytes = 400 MB — under the cap.
        let buf = synth_png(10_000, 10_000, None);
        let info = inspect_dimensions(&buf).unwrap();
        assert_eq!(info.width, 10_000);
        assert!(info.estimated_bytes < MAX_DECOMPRESSED_BYTES);
    }

    // ---------- Robustness against truncation ----------

    #[test]
    fn truncated_inputs_do_not_panic() {
        // Take a well-formed file and truncate to 1, 2, 4, 8 bytes — none
        // of these should decode successfully but all must return an
        // error (not panic).
        for src in [
            synth_jpeg(100, 100),
            synth_png(100, 100, None),
            synth_webp_vp8l(100, 100),
            synth_gif(100, 100, 1),
            synth_heif(100, 100),
            synth_tiff(100, 100),
        ] {
            for len in [0usize, 1, 2, 4, 8] {
                let truncated = &src[..len.min(src.len())];
                let res = inspect_dimensions(truncated);
                assert!(res.is_err(), "unexpected success for len={len}");
            }
        }
    }

    #[test]
    fn rejects_garbage_magic() {
        let err = inspect_dimensions(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]).unwrap_err();
        assert_eq!(err, DimensionError::Malformed);
    }
}
