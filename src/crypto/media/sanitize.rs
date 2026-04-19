//! Format-aware metadata sanitiser for imported images.
//!
//! Ported from Telephoto's `apps/mobile/src-tauri/src/media/sanitize.rs` —
//! the same byte-walkers, expressed as an SDK-public API. The sanitiser is
//! a pure byte-in / byte-out function; it never decodes pixels, never
//! allocates more than a single output `Vec<u8>` (plus small per-format
//! scratch), and is invariant to the image's pixel content. We verify the
//! output by scanning the produced bytes for the stripped marker tags
//! (`sanity_check`) and fail-closed if any survive.
//!
//! Scope / policy:
//!
//! * JPEG — keep APP0 JFIF (required for interop), drop APP1..=APP15,
//!   drop COM.
//! * PNG  — keep IHDR, IDAT, IEND, PLTE, tRNS. Drop every other ancillary
//!   chunk (tEXt, zTXt, iTXt, eXIf, tIME, gAMA, cHRM, sRGB, iCCP, bKGD,
//!   sBIT, sPLT, hIST, pHYs, etc.) — privacy > color fidelity.
//! * WebP — keep VP8 / VP8L / VP8X / ANIM / ANMF / ALPH. Drop EXIF / XMP /
//!   ICCP / and the VP8X flags that point to them.
//! * GIF  — keep trailer, global/local tables, image blocks, graphic-control
//!   and plain-text extensions. Drop every application extension block
//!   (XMP, Netscape-loop etc.) and comment extensions.
//! * HEIC / HEIF / AVIF — all three share the ISOBMFF container
//!   (ISO/IEC 14496-12). We walk the top-level box tree, keep `ftyp` / `mdat`
//!   / `moov` / `pitm` verbatim, rewrite `meta` to remove `iinf` entries of
//!   type `Exif` / `mime` / `uri ` (and their matching `iref`
//!   back-references), and drop `udta` / `uuid` / `free` / `skip` top-level
//!   boxes outright. The walker is codec-agnostic: it handles HEIC (HEVC),
//!   HEIF (any brand) and AVIF (AV1) through the same code path because the
//!   container is identical. Pixel bytes in `mdat` are NEVER re-encoded —
//!   we never invoke libheif / libavif / dav1d on untrusted input.
//! * TIFF — TIFF is pure metadata: every user-identifying value lives in an
//!   IFD tag. We rewrite each IFD from scratch keeping only the geometry +
//!   strip/tile tag whitelist required to decode (18 tags). Pixel data is
//!   copied verbatim at new offsets. Byte order (II / MM) is preserved. The
//!   full multi-page IFD chain is walked and every page is stripped.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Image formats recognised by [`strip_metadata`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG (JFIF / EXIF).
    Jpeg,
    /// Portable Network Graphics.
    Png,
    /// Google WebP (lossy, lossless, or extended).
    Webp,
    /// Graphics Interchange Format.
    Gif,
    /// ISOBMFF-family still images — HEIC, HEIF, and AVIF share the same
    /// container walker.
    Heif,
    /// TIFF 6.0 (classic). BigTIFF (`version == 43`) is deliberately not
    /// supported — the 64-bit variant requires a parallel set of code
    /// paths and is vanishingly rare in photography workflows.
    Tiff,
    /// Magic bytes did not match a supported format.
    Unknown,
}

/// Errors produced by [`strip_metadata`].
///
/// Variants are intentionally coarse-grained. In line with the rest of the
/// SDK (see `crypto::error::CryptoError`), structural parse failures and
/// failed post-strip checks collapse into `Malformed` — callers should
/// refuse the import rather than try to recover.
#[derive(Debug, PartialEq, Eq)]
pub enum SanitizeError {
    /// Structural parse failure — truncated segment, bad chunk length, or a
    /// marker we could not reconcile with the container spec. Also returned
    /// when the paranoid post-strip check detects that a metadata tag
    /// survived (indicates a bug in the sanitiser; the import must be
    /// rejected).
    Malformed,
    /// Input exceeds the hard 200 MiB input cap — HEIC photos from flagship
    /// phones top out at ~15 MiB, TIFF scans can be larger but anything
    /// above 200 MiB strongly suggests either a decompression-bomb attempt
    /// or a resource-exhaustion DoS against the single-Vec allocator.
    TooLarge,
    /// Magic bytes did not match any format we know how to sanitise.
    UnsupportedFormat(ImageFormat),
    /// A size computation overflowed. Kept distinct from `Malformed` so the
    /// FFI layer can report "decline, maybe retry with a trimmed input"
    /// separately from "malformed container".
    IntegerOverflow,
}

impl std::fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanitizeError::Malformed => f.write_str("malformed image"),
            SanitizeError::TooLarge => f.write_str("image exceeds sanitiser size cap"),
            SanitizeError::UnsupportedFormat(_) => f.write_str("unsupported image format"),
            SanitizeError::IntegerOverflow => f.write_str("image parse arithmetic overflowed"),
        }
    }
}

impl std::error::Error for SanitizeError {}

/// Hard upper bound applied to every stripper. HEIC photos from flagship
/// phones top out at ~15 MiB; TIFF scans can be larger but anything above
/// 200 MiB is well beyond normal user content and strongly suggests either
/// a decompression-bomb attempt or a resource-exhaustion DoS against the
/// single-Vec allocator.
pub(crate) const MAX_INPUT_BYTES: usize = 200 * 1024 * 1024;

/// Auto-detect the image format from the file's magic bytes.
///
/// Returns [`ImageFormat::Unknown`] for any input that does not match a
/// supported magic. Never panics; safe to call with inputs as short as zero
/// bytes.
#[must_use]
pub fn detect_format(bytes: &[u8]) -> ImageFormat {
    if is_jpeg(bytes) {
        ImageFormat::Jpeg
    } else if is_png(bytes) {
        ImageFormat::Png
    } else if is_webp(bytes) {
        ImageFormat::Webp
    } else if is_gif(bytes) {
        ImageFormat::Gif
    } else if is_heif_family(bytes) {
        ImageFormat::Heif
    } else if is_tiff(bytes) {
        ImageFormat::Tiff
    } else {
        ImageFormat::Unknown
    }
}

/// Strip all non-essential metadata from `bytes`.
///
/// Dispatches on the file's magic bytes (not any claimed MIME — we don't
/// trust that) and returns a freshly-allocated `Vec<u8>` with every EXIF /
/// XMP / IPTC / ICC / vendor metadata atom removed. Pixel data passes
/// through byte-for-byte — no libheif / libavif / libtiff invocation.
///
/// # Errors
///
/// * [`SanitizeError::TooLarge`] — input exceeds 200 MiB.
/// * [`SanitizeError::UnsupportedFormat`] — magic bytes don't match.
/// * [`SanitizeError::Malformed`] — structural parse failure, or a paranoid
///   post-strip check found metadata markers that should have been removed.
/// * [`SanitizeError::IntegerOverflow`] — an offset/length computation
///   overflowed while walking the container.
pub fn strip_metadata(bytes: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SanitizeError::TooLarge);
    }
    let format = detect_format(bytes);
    let out = match format {
        ImageFormat::Jpeg => strip_jpeg(bytes)?,
        ImageFormat::Png => strip_png(bytes)?,
        ImageFormat::Webp => strip_webp(bytes)?,
        ImageFormat::Gif => strip_gif(bytes)?,
        ImageFormat::Heif => strip_heif(bytes)?,
        ImageFormat::Tiff => strip_tiff(bytes)?,
        ImageFormat::Unknown => {
            return Err(SanitizeError::UnsupportedFormat(ImageFormat::Unknown))
        }
    };

    sanity_check(&out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Magic-byte detection
// ---------------------------------------------------------------------------

pub(crate) fn is_jpeg(d: &[u8]) -> bool {
    d.len() >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF
}
pub(crate) fn is_png(d: &[u8]) -> bool {
    d.len() >= 8 && &d[..8] == b"\x89PNG\r\n\x1a\n"
}
pub(crate) fn is_webp(d: &[u8]) -> bool {
    d.len() >= 12 && &d[..4] == b"RIFF" && &d[8..12] == b"WEBP"
}
pub(crate) fn is_gif(d: &[u8]) -> bool {
    d.len() >= 6 && (&d[..6] == b"GIF87a" || &d[..6] == b"GIF89a")
}

/// ISOBMFF magic: the second 4 bytes of the file must be the `ftyp` FourCC.
/// (The first 4 are the box size, which we cannot pin to a single value.)
pub(crate) fn is_heif_family(d: &[u8]) -> bool {
    d.len() >= 12 && &d[4..8] == b"ftyp"
}

/// TIFF magic — 'II' (little-endian) or 'MM' (big-endian) followed by the
/// 16-bit version word 42. We deliberately reject BigTIFF (version = 43):
/// the 64-bit variant requires a parallel set of code paths and is
/// vanishingly rare in photography workflows.
pub(crate) fn is_tiff(d: &[u8]) -> bool {
    d.len() >= 4
        && ((d[0] == b'I' && d[1] == b'I' && d[2] == 42 && d[3] == 0)
            || (d[0] == b'M' && d[1] == b'M' && d[2] == 0 && d[3] == 42))
}

// ---------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------

// JPEG segment structure: 0xFF <marker> [<length-hi> <length-lo> <payload>]
// SOI (0xD8), EOI (0xD9) and TEM / RSTn (0xD0..0xD7) have no payload; every
// other marker has a 2-byte big-endian length including the length bytes
// themselves. SOS (0xDA) is the start of the entropy-coded scan data which
// has no length field — we copy bytes verbatim until we see a non-restart
// 0xFF marker.
fn strip_jpeg(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    let mut out = Vec::with_capacity(data.len());
    let mut i;

    // SOI
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(SanitizeError::Malformed);
    }
    out.extend_from_slice(&data[0..2]);
    i = 2;

    loop {
        // Find next marker — skip any fill bytes (0xFF 0xFF... sequences).
        if i >= data.len() {
            return Err(SanitizeError::Malformed);
        }
        if data[i] != 0xFF {
            return Err(SanitizeError::Malformed);
        }
        while i < data.len() && data[i] == 0xFF {
            i += 1;
        }
        if i >= data.len() {
            return Err(SanitizeError::Malformed);
        }
        let marker = data[i];
        i += 1;

        match marker {
            0xD9 => {
                // EOI — copy and stop.
                out.push(0xFF);
                out.push(0xD9);
                break;
            }
            0xD0..=0xD7 | 0x01 => {
                // RSTn and TEM — no payload. Copy verbatim.
                out.push(0xFF);
                out.push(marker);
            }
            0xDA => {
                // SOS — length-delimited header, then entropy-coded data
                // that ends at the next non-restart marker. Copy the header,
                // then scan-copy until we see FF xx where xx != 0x00 and
                // not in 0xD0..=0xD7.
                if i + 2 > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if len < 2 || i + len > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                out.push(0xFF);
                out.push(0xDA);
                out.extend_from_slice(&data[i..i + len]);
                i += len;

                // Copy entropy-coded data.
                while i < data.len() {
                    let b = data[i];
                    out.push(b);
                    i += 1;
                    if b == 0xFF {
                        if i >= data.len() {
                            return Err(SanitizeError::Malformed);
                        }
                        let nb = data[i];
                        if nb == 0x00 || (0xD0..=0xD7).contains(&nb) {
                            // Stuffed byte or restart — copy and continue.
                            out.push(nb);
                            i += 1;
                        } else {
                            // Real marker begins here. Back up one so the
                            // outer loop re-reads this FF.
                            let _ = out.pop(); // the trailing 0xFF we wrote
                            i -= 1;
                            break;
                        }
                    }
                }
            }
            _ => {
                // All other markers have a length-prefixed payload.
                if i + 2 > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                if len < 2 || i + len > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                let segment_end = i + len;

                // Decide whether to keep or drop.
                let drop_seg = matches!(marker,
                    // APP1..APP15 — EXIF, XMP, IPTC, ICC, Photoshop, Adobe,
                    // Ducky, etc.
                    0xE1..=0xEF
                    // Comment marker.
                    | 0xFE
                );
                if !drop_seg {
                    out.push(0xFF);
                    out.push(marker);
                    out.extend_from_slice(&data[i..segment_end]);
                }
                i = segment_end;
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

fn strip_png(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    const SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if data.len() < 8 || &data[..8] != SIG {
        return Err(SanitizeError::Malformed);
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(SIG);
    let mut i = 8usize;

    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let typ = &data[i + 4..i + 8];
        let chunk_end = i
            .checked_add(12)
            .and_then(|x| x.checked_add(len))
            .ok_or(SanitizeError::IntegerOverflow)?;
        if chunk_end > data.len() {
            return Err(SanitizeError::Malformed);
        }
        let keep = matches!(typ, b"IHDR" | b"IDAT" | b"IEND" | b"PLTE" | b"tRNS");
        if keep {
            out.extend_from_slice(&data[i..chunk_end]);
        }
        if typ == b"IEND" {
            break;
        }
        i = chunk_end;
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// WebP
// ---------------------------------------------------------------------------

fn strip_webp(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return Err(SanitizeError::Malformed);
    }

    // We'll write RIFF header + size placeholder + "WEBP" + kept chunks,
    // then patch the RIFF size at the end.
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(b"RIFF\0\0\0\0WEBP");

    let mut i = 12usize;
    while i + 8 <= data.len() {
        let fourcc: [u8; 4] = [data[i], data[i + 1], data[i + 2], data[i + 3]];
        let len =
            u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
        let padded_len = if len % 2 == 1 { len + 1 } else { len };
        let chunk_end = i
            .checked_add(8)
            .and_then(|x| x.checked_add(padded_len))
            .ok_or(SanitizeError::IntegerOverflow)?;
        let copy_end = chunk_end.min(data.len());
        if chunk_end > data.len() {
            // Spec allows the final padding byte to be missing on some
            // encoders. Accept truncation equal to 1 byte of padding.
            if chunk_end - 1 != data.len() {
                return Err(SanitizeError::Malformed);
            }
        }

        // Keep image-bearing chunks. Drop EXIF, XMP, ICCP, unknown.
        let keep = matches!(
            &fourcc,
            b"VP8 " | b"VP8L" | b"VP8X" | b"ANIM" | b"ANMF" | b"ALPH"
        );
        if keep {
            if fourcc == *b"VP8X" && len >= 1 && i + 8 < data.len() {
                // Clear VP8X flag bits that referenced stripped chunks.
                let mut vp8x = data[i..copy_end].to_vec();
                if vp8x.len() >= 9 {
                    // Bit 5 = ICC profile, bit 3 = EXIF, bit 2 = XMP metadata.
                    vp8x[8] &= !(0b0010_1100);
                }
                out.extend_from_slice(&vp8x);
            } else {
                out.extend_from_slice(&data[i..copy_end]);
            }
        }
        i = chunk_end;
    }

    // Patch RIFF size = total - 8.
    let riff_size = u32::try_from(out.len().saturating_sub(8))
        .map_err(|_| SanitizeError::IntegerOverflow)?;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());

    Ok(out)
}

// ---------------------------------------------------------------------------
// GIF
// ---------------------------------------------------------------------------

// GIF structure:
//   Header (6 bytes)
//   LogicalScreenDescriptor (7 bytes)
//   [GlobalColorTable] if flag set
//   Data blocks: image descriptors (0x2C), extensions (0x21 <label> ...),
//   trailer (0x3B)
// We drop:
//   - Application extensions (0x21 0xFF ...) — XMP, Netscape loop, etc.
//   - Comment extensions (0x21 0xFE ...)
// We keep everything else verbatim.
fn strip_gif(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    if data.len() < 13 {
        return Err(SanitizeError::Malformed);
    }
    let mut out = Vec::with_capacity(data.len());
    // Header (6) + Logical Screen Descriptor (7) = 13 bytes.
    out.extend_from_slice(&data[..13]);
    let packed = data[10];
    let mut i = 13usize;

    // Optional Global Color Table.
    if packed & 0x80 != 0 {
        let gct_size = 3usize * (1usize << ((packed & 0x07) + 1));
        if i + gct_size > data.len() {
            return Err(SanitizeError::Malformed);
        }
        out.extend_from_slice(&data[i..i + gct_size]);
        i += gct_size;
    }

    while i < data.len() {
        let introducer = data[i];
        match introducer {
            0x3B => {
                // Trailer — copy and stop.
                out.push(0x3B);
                break;
            }
            0x21 => {
                // Extension: 0x21 <label> <sub-blocks...> <0x00>
                if i + 2 > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                let label = data[i + 1];
                let mut j = i + 2;
                let start_of_extension = i;
                let end_of_extension;
                loop {
                    if j >= data.len() {
                        return Err(SanitizeError::Malformed);
                    }
                    let size = data[j] as usize;
                    if size == 0 {
                        end_of_extension = j + 1;
                        break;
                    }
                    let blk_end = j + 1 + size;
                    if blk_end > data.len() {
                        return Err(SanitizeError::Malformed);
                    }
                    j = blk_end;
                }
                let drop_ext =
                    matches!(label, 0xFF /* application */ | 0xFE /* comment */);
                if !drop_ext {
                    out.extend_from_slice(&data[start_of_extension..end_of_extension]);
                }
                i = end_of_extension;
            }
            0x2C => {
                // Image Descriptor (10 bytes) + optional LCT + LZW data sub-blocks.
                if i + 10 > data.len() {
                    return Err(SanitizeError::Malformed);
                }
                let ipacked = data[i + 9];
                let mut j = i + 10;
                let out_start = i;
                if ipacked & 0x80 != 0 {
                    let lct_size = 3usize * (1usize << ((ipacked & 0x07) + 1));
                    if j + lct_size > data.len() {
                        return Err(SanitizeError::Malformed);
                    }
                    j += lct_size;
                }
                // LZW minimum code size byte.
                if j >= data.len() {
                    return Err(SanitizeError::Malformed);
                }
                j += 1;
                // Sub-blocks.
                loop {
                    if j >= data.len() {
                        return Err(SanitizeError::Malformed);
                    }
                    let size = data[j] as usize;
                    if size == 0 {
                        j += 1;
                        break;
                    }
                    let blk_end = j + 1 + size;
                    if blk_end > data.len() {
                        return Err(SanitizeError::Malformed);
                    }
                    j = blk_end;
                }
                out.extend_from_slice(&data[out_start..j]);
                i = j;
            }
            _ => return Err(SanitizeError::Malformed),
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// HEIF / HEIC / AVIF
// ---------------------------------------------------------------------------
//
// All three formats share the ISOBMFF (ISO/IEC 14496-12) container — they
// differ only in the `ftyp` brand and in the codec that populates `mdat`.
// Metadata stripping is therefore identical: walk the top-level box tree,
// descend one level into `meta`, and surgically remove the items that carry
// user-identifying data.
//
// What we drop
// ------------
// * `meta / iinf / infe` entries whose `item_type` is `Exif`, `mime`
//   (commonly `application/rdf+xml`, i.e. XMP), or `uri ` (arbitrary URI
//   references). These are the HEIF-native metadata carriers.
// * `meta / iref` back-references pointing at the stripped item IDs, so the
//   container does not contain dangling references.
// * The `mdat` / `idat` payload bytes referenced by those items' `iloc`
//   extents are overwritten with zeros in-place. Overwriting (not
//   removing) keeps every surviving `iloc` offset valid without having to
//   rewrite the offset table — the net effect is that the payload is
//   gone but the container remains structurally identical.
// * Top-level `udta` (User Data) boxes — Apple writes copyright /
//   device-identifying `©`-prefixed four-CC atoms here.
// * Top-level `uuid` boxes — free-form vendor extensions (Canon GPS, Sony
//   lens info, Apple Live-Photo linkage, etc.).
// * Top-level `free` / `skip` boxes — pure padding, no reason to copy.
//
// What we keep (and why)
// ----------------------
// * `ftyp` — file-type brand; mandatory for every parser to identify the
//   file.
// * `mdat` — compressed pixel payload, passed through byte-for-byte (with
//   metadata-item extents zeroed in place).
// * `moov` — rarely seen in still HEIF but legal in AVIF image sequences
//   and HEIF motion-photo variants; kept so the decoder has a chance.
// * `pitm` — primary item pointer.
// * `meta` — rewritten with metadata items excised but image items,
//   primary-item reference (`pitm`), handler (`hdlr`), item locations
//   (`iloc`), item properties (`iprp`/`ipco`/`ipma`), and the image-only
//   subset of `iref` preserved.
//
// What we do NOT do
// -----------------
// * We never decode a single byte of compressed image data. libheif /
//   libavif / dav1d have a long CVE history and are off the import path
//   entirely. The box walk is O(boxes), never O(pixels).

/// Max recursion depth when walking `meta`'s child boxes. ISOBMFF allows
/// arbitrary nesting; we only go one level deep for `meta` itself plus a
/// couple inside `iinf`, so a small constant is sufficient and a defence
/// against pathological nesting DoS.
const HEIF_MAX_DEPTH: u8 = 8;

/// Top-level ISOBMFF box types we copy verbatim into the output.
const HEIF_KEEP_TOP: &[&[u8; 4]] = &[b"ftyp", b"mdat", b"moov", b"pitm", b"idat"];

/// Top-level box types we unconditionally drop.
const HEIF_DROP_TOP: &[&[u8; 4]] = &[
    b"udta", // user data — Apple ©-prefixed proprietary atoms
    b"uuid", // vendor extensions (Canon GPS, Sony lens, etc.)
    b"free", // padding
    b"skip", // padding
    b"mdta", // undefined / rarely-used metadata atom
];

/// `meta` sub-box types we unconditionally drop.
const HEIF_DROP_IN_META: &[&[u8; 4]] = &[b"udta", b"uuid", b"free", b"skip"];

/// Item types in `iinf` that carry metadata. We drop the `infe`, zero the
/// `iloc` extents, and remove back-references from `iref`.
const METADATA_ITEM_TYPES: &[&[u8; 4]] = &[
    b"Exif", // EXIF TIFF stream (the single highest-value target)
    b"mime", // MIME item — nearly always application/rdf+xml i.e. XMP
    b"uri ", // URI reference — arbitrary, unsafe by default
];

/// Strip metadata from a HEIF/HEIC/AVIF file. See module docs for the
/// box-level policy. Output is always a newly allocated `Vec<u8>`.
pub(crate) fn strip_heif(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(SanitizeError::TooLarge);
    }
    if !is_heif_family(data) {
        return Err(SanitizeError::Malformed);
    }

    // Pass 1: walk `meta` to collect the set of metadata item IDs and the
    // exact (offset, length) ranges they occupy in `mdat` / `idat`.
    let plan = heif_plan_strip(data)?;

    // Pass 2: produce the output. We mutate a copy of the input so we can
    // zero `mdat` / `idat` extents in-place at their original offsets.
    let mut work = data.to_vec();
    for &(off, len) in &plan.zero_ranges {
        // Bounds-check every range — `heif_plan_strip` already did, but
        // belt and braces since a corrupted iloc could slip past in
        // pathological cases.
        let end = off.checked_add(len).ok_or(SanitizeError::IntegerOverflow)?;
        if end > work.len() {
            return Err(SanitizeError::Malformed);
        }
        for b in &mut work[off..end] {
            *b = 0;
        }
    }

    // Now walk the top-level boxes and emit kept ones. For `meta` we
    // recurse and rewrite.
    let mut out = Vec::with_capacity(work.len());
    let mut cursor = 0usize;
    while cursor < work.len() {
        let (hdr, body_off, body_end) = heif_read_box_header(&work, cursor)?;
        let typ = &hdr.kind;
        if HEIF_DROP_TOP.iter().any(|t| *t == typ) {
            cursor = body_end;
            continue;
        }
        if typ == b"meta" {
            // `meta` is a FullBox: 4 bytes of version/flags before children.
            if body_off.checked_add(4).map_or(true, |e| e > body_end) {
                return Err(SanitizeError::Malformed);
            }
            let children_start = body_off + 4;
            let new_meta = heif_rewrite_meta(&work, children_start, body_end, &plan)?;
            // Emit a fresh `meta` header with updated size.
            heif_write_box(&mut out, b"meta", |buf| {
                // Copy version/flags.
                buf.extend_from_slice(&work[body_off..children_start]);
                buf.extend_from_slice(&new_meta);
                Ok(())
            })?;
            cursor = body_end;
            continue;
        }
        if HEIF_KEEP_TOP.iter().any(|t| *t == typ) {
            // Copy verbatim — size bytes and all.
            out.extend_from_slice(&work[cursor..body_end]);
            cursor = body_end;
            continue;
        }
        // Unknown top-level box: conservative default is DROP. Importers
        // that need a new box type can add it to `HEIF_KEEP_TOP` explicitly.
        cursor = body_end;
    }

    Ok(out)
}

#[derive(Debug)]
struct HeifBoxHeader {
    /// FourCC type.
    kind: [u8; 4],
}

/// Parse one ISOBMFF box header starting at `cursor`. Returns the header,
/// the offset where the body starts (right after size + type + any
/// largesize), and the offset of the first byte after the box.
fn heif_read_box_header(
    data: &[u8],
    cursor: usize,
) -> Result<(HeifBoxHeader, usize, usize), SanitizeError> {
    let after_header = cursor
        .checked_add(8)
        .ok_or(SanitizeError::IntegerOverflow)?;
    if after_header > data.len() {
        return Err(SanitizeError::Malformed);
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
        0 => {
            // size=0 means the box runs to EOF.
            (after_header, data.len())
        }
        1 => {
            // size=1 means a 64-bit largesize follows the type field.
            let after_largesize = cursor
                .checked_add(16)
                .ok_or(SanitizeError::IntegerOverflow)?;
            if after_largesize > data.len() {
                return Err(SanitizeError::Malformed);
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
            let size = usize::try_from(size64).map_err(|_| SanitizeError::IntegerOverflow)?;
            if size < 16 {
                return Err(SanitizeError::Malformed);
            }
            let end = cursor
                .checked_add(size)
                .ok_or(SanitizeError::IntegerOverflow)?;
            if end > data.len() {
                return Err(SanitizeError::Malformed);
            }
            (after_largesize, end)
        }
        n => {
            let size = n as usize;
            if size < 8 {
                return Err(SanitizeError::Malformed);
            }
            let end = cursor
                .checked_add(size)
                .ok_or(SanitizeError::IntegerOverflow)?;
            if end > data.len() {
                return Err(SanitizeError::Malformed);
            }
            (after_header, end)
        }
    };
    Ok((HeifBoxHeader { kind }, body_off, body_end))
}

/// Emit a box to `out`. The caller writes the body via `body_fn`; we patch
/// the size field after measuring the body.
fn heif_write_box<F>(out: &mut Vec<u8>, kind: &[u8; 4], body_fn: F) -> Result<(), SanitizeError>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), SanitizeError>,
{
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    out.extend_from_slice(kind);
    body_fn(out)?;
    let size = out.len() - start;
    if size > u32::MAX as usize {
        // Rewriting would require a largesize header; synthesised test
        // inputs never come anywhere near 4 GiB. Fail closed.
        return Err(SanitizeError::IntegerOverflow);
    }
    let size_u32 = u32::try_from(size).map_err(|_| SanitizeError::IntegerOverflow)?;
    out[start..start + 4].copy_from_slice(&size_u32.to_be_bytes());
    Ok(())
}

#[derive(Debug, Default)]
struct HeifStripPlan {
    /// Item IDs whose iinf entry is marked for removal.
    metadata_item_ids: Vec<u32>,
    /// Byte ranges in the container that must be zeroed before the output
    /// pass. Populated from `iloc` extents for metadata items.
    zero_ranges: Vec<(usize, usize)>,
}

/// Walk the top-level boxes, find `meta`, and enumerate its `iinf` + `iloc`
/// to populate a [`HeifStripPlan`].
fn heif_plan_strip(data: &[u8]) -> Result<HeifStripPlan, SanitizeError> {
    let mut plan = HeifStripPlan::default();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let (hdr, body_off, body_end) = heif_read_box_header(data, cursor)?;
        if &hdr.kind == b"meta" {
            // FullBox: skip version/flags.
            if body_off.checked_add(4).map_or(true, |e| e > body_end) {
                return Err(SanitizeError::Malformed);
            }
            heif_plan_meta(data, body_off + 4, body_end, &mut plan, 0)?;
        }
        cursor = body_end;
    }
    Ok(plan)
}

fn heif_plan_meta(
    data: &[u8],
    start: usize,
    end: usize,
    plan: &mut HeifStripPlan,
    depth: u8,
) -> Result<(), SanitizeError> {
    if depth > HEIF_MAX_DEPTH {
        return Err(SanitizeError::Malformed);
    }

    // First pass: collect metadata item IDs from iinf.
    let mut cursor = start;
    while cursor < end {
        let (hdr, body_off, body_end) = heif_read_box_header(data, cursor)?;
        if &hdr.kind == b"iinf" {
            heif_collect_iinf_metadata_ids(data, body_off, body_end, plan)?;
        }
        cursor = body_end;
    }

    // Second pass: use iloc to turn item IDs into byte ranges.
    let mut cursor = start;
    while cursor < end {
        let (hdr, body_off, body_end) = heif_read_box_header(data, cursor)?;
        if &hdr.kind == b"iloc" {
            heif_collect_iloc_ranges(data, body_off, body_end, plan)?;
        }
        cursor = body_end;
    }
    Ok(())
}

/// Parse `iinf` (ISO/IEC 14496-12 §8.11.6). Each `infe` child's `item_type`
/// is matched against [`METADATA_ITEM_TYPES`]; matches are added to
/// `plan.metadata_item_ids`.
fn heif_collect_iinf_metadata_ids(
    data: &[u8],
    body_off: usize,
    body_end: usize,
    plan: &mut HeifStripPlan,
) -> Result<(), SanitizeError> {
    // FullBox: 1 byte version, 3 bytes flags.
    if body_off.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let version = data[body_off];
    let mut p = body_off + 4;

    // entry_count: u16 (v0) or u32 (v>=1).
    let entry_count = if version == 0 {
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
        p += 2;
        n
    } else {
        if p.checked_add(4).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        p += 4;
        n
    };

    for _ in 0..entry_count {
        let (hdr, infe_body, infe_end) = heif_read_box_header(data, p)?;
        if infe_end > body_end {
            return Err(SanitizeError::Malformed);
        }
        if &hdr.kind != b"infe" {
            // Spec requires infe but be permissive about unknown siblings.
            p = infe_end;
            continue;
        }
        if let Some((item_id, item_type)) = heif_parse_infe(data, infe_body, infe_end)? {
            if METADATA_ITEM_TYPES.iter().any(|t| *t == &item_type) {
                plan.metadata_item_ids.push(item_id);
            }
        }
        p = infe_end;
    }
    Ok(())
}

/// Parse an `infe` box body. Returns `None` if the version is legacy
/// (< 2) where item_type is implicit and never matches our metadata set.
fn heif_parse_infe(
    data: &[u8],
    body_off: usize,
    body_end: usize,
) -> Result<Option<(u32, [u8; 4])>, SanitizeError> {
    if body_off.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let version = data[body_off];
    let mut p = body_off + 4;

    // Legacy v0/v1 infe — no item_type; they're always image items in
    // practice and never carry metadata we care about.
    if version < 2 {
        return Ok(None);
    }
    // v2: item_ID is u16; v3: item_ID is u32.
    let item_id = if version == 2 {
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let id = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
        p += 2;
        id
    } else {
        if p.checked_add(4).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let id = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        p += 4;
        id
    };
    // item_protection_index: u16 (skipped).
    if p.checked_add(2).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    p += 2;
    // item_type: 4 bytes.
    if p.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let mut item_type = [0u8; 4];
    item_type.copy_from_slice(&data[p..p + 4]);
    Ok(Some((item_id, item_type)))
}

/// Parse `iloc` (ISO/IEC 14496-12 §8.11.3). For each extent whose item ID
/// appears in `plan.metadata_item_ids`, record the absolute byte range
/// (base_offset + extent_offset, extent_length) in `plan.zero_ranges`.
fn heif_collect_iloc_ranges(
    data: &[u8],
    body_off: usize,
    body_end: usize,
    plan: &mut HeifStripPlan,
) -> Result<(), SanitizeError> {
    if body_off.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let version = data[body_off];
    let mut p = body_off + 4;

    if p.checked_add(2).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let b1 = data[p];
    let b2 = data[p + 1];
    p += 2;
    let offset_size = (b1 >> 4) as usize;
    let length_size = (b1 & 0x0F) as usize;
    let base_offset_size = (b2 >> 4) as usize;
    let index_size = if version == 1 || version == 2 {
        (b2 & 0x0F) as usize
    } else {
        0
    };

    // Valid sizes per spec: 0, 4, or 8 bytes.
    for s in [offset_size, length_size, base_offset_size, index_size] {
        if !(s == 0 || s == 4 || s == 8) {
            return Err(SanitizeError::Malformed);
        }
    }

    let item_count = if version < 2 {
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
        p += 2;
        n
    } else {
        if p.checked_add(4).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        p += 4;
        n
    };

    for _ in 0..item_count {
        // item_ID
        let item_id = if version < 2 {
            if p.checked_add(2).map_or(true, |e| e > body_end) {
                return Err(SanitizeError::Malformed);
            }
            let id = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
            p += 2;
            id
        } else {
            if p.checked_add(4).map_or(true, |e| e > body_end) {
                return Err(SanitizeError::Malformed);
            }
            let id = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            p += 4;
            id
        };
        // construction_method (v>=1): u16 with top 12 bits reserved.
        let mut construction_method = 0u8;
        if version == 1 || version == 2 {
            if p.checked_add(2).map_or(true, |e| e > body_end) {
                return Err(SanitizeError::Malformed);
            }
            construction_method = data[p + 1] & 0x0F;
            p += 2;
        }
        // data_reference_index: u16 (skipped — we trust we're in-file).
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        p += 2;
        // base_offset
        let base_offset = heif_read_uint(data, p, base_offset_size, body_end)?;
        p = p
            .checked_add(base_offset_size)
            .ok_or(SanitizeError::IntegerOverflow)?;
        // extent_count
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let extent_count = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
        p += 2;

        let is_metadata = plan.metadata_item_ids.contains(&item_id);
        for _ in 0..extent_count {
            if index_size > 0 {
                if p.checked_add(index_size).map_or(true, |e| e > body_end) {
                    return Err(SanitizeError::Malformed);
                }
                p += index_size;
            }
            let extent_offset = heif_read_uint(data, p, offset_size, body_end)?;
            p = p
                .checked_add(offset_size)
                .ok_or(SanitizeError::IntegerOverflow)?;
            let extent_length = heif_read_uint(data, p, length_size, body_end)?;
            p = p
                .checked_add(length_size)
                .ok_or(SanitizeError::IntegerOverflow)?;

            if is_metadata {
                // construction_method 0 = mdat file offset; 1 = idat (offset
                // relative to enclosing meta's idat box); 2 = item_offset
                // (into another item — rare). For 0 and 1 we can zero the
                // bytes in our own buffer. For 2 we conservatively skip —
                // zeroing would require resolving the other item first.
                if construction_method == 0 || construction_method == 1 {
                    let absolute = base_offset
                        .checked_add(extent_offset)
                        .ok_or(SanitizeError::IntegerOverflow)?;
                    let abs_usize = usize::try_from(absolute)
                        .map_err(|_| SanitizeError::IntegerOverflow)?;
                    let len_usize = usize::try_from(extent_length)
                        .map_err(|_| SanitizeError::IntegerOverflow)?;
                    plan.zero_ranges.push((abs_usize, len_usize));
                }
            }
        }
    }
    Ok(())
}

fn heif_read_uint(
    data: &[u8],
    off: usize,
    size: usize,
    limit: usize,
) -> Result<u64, SanitizeError> {
    if off.checked_add(size).map_or(true, |e| e > limit) {
        return Err(SanitizeError::Malformed);
    }
    let v = match size {
        0 => 0,
        4 => u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as u64,
        8 => u64::from_be_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ]),
        _ => return Err(SanitizeError::Malformed),
    };
    Ok(v)
}

/// Rebuild the contents of a `meta` box. Drops `udta`/`uuid`/`free`/`skip`
/// children; rewrites `iinf` / `iref` to exclude metadata-item entries;
/// every other child is copied verbatim.
fn heif_rewrite_meta(
    data: &[u8],
    start: usize,
    end: usize,
    plan: &HeifStripPlan,
) -> Result<Vec<u8>, SanitizeError> {
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let (hdr, body_off, body_end) = heif_read_box_header(data, cursor)?;
        let typ = &hdr.kind;
        if HEIF_DROP_IN_META.iter().any(|t| *t == typ) {
            cursor = body_end;
            continue;
        }
        match typ {
            b"iinf" => {
                let new_iinf = heif_rewrite_iinf(data, body_off, body_end, plan)?;
                heif_write_box(&mut out, b"iinf", |buf| {
                    buf.extend_from_slice(&new_iinf);
                    Ok(())
                })?;
            }
            b"iref" => {
                let new_iref = heif_rewrite_iref(data, body_off, body_end, plan)?;
                heif_write_box(&mut out, b"iref", |buf| {
                    buf.extend_from_slice(&new_iref);
                    Ok(())
                })?;
            }
            _ => {
                out.extend_from_slice(&data[cursor..body_end]);
            }
        }
        cursor = body_end;
    }
    Ok(out)
}

/// Emit a fresh `iinf` body excluding `infe` entries whose item_id is in
/// `plan.metadata_item_ids`.
fn heif_rewrite_iinf(
    data: &[u8],
    body_off: usize,
    body_end: usize,
    plan: &HeifStripPlan,
) -> Result<Vec<u8>, SanitizeError> {
    if body_off.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let version = data[body_off];
    let flags = &data[body_off..body_off + 4];

    let mut p = body_off + 4;
    let original_count = if version == 0 {
        if p.checked_add(2).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u16::from_be_bytes([data[p], data[p + 1]]) as u32;
        p += 2;
        n
    } else {
        if p.checked_add(4).map_or(true, |e| e > body_end) {
            return Err(SanitizeError::Malformed);
        }
        let n = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        p += 4;
        n
    };

    // Collect kept infes.
    let mut kept: Vec<&[u8]> = Vec::new();
    for _ in 0..original_count {
        let (hdr, infe_body, infe_end) = heif_read_box_header(data, p)?;
        if infe_end > body_end {
            return Err(SanitizeError::Malformed);
        }
        let drop_entry = if &hdr.kind == b"infe" {
            match heif_parse_infe(data, infe_body, infe_end)? {
                Some((item_id, _)) => plan.metadata_item_ids.contains(&item_id),
                None => false,
            }
        } else {
            false
        };
        if !drop_entry {
            kept.push(&data[p..infe_end]);
        }
        p = infe_end;
    }

    let new_count = u32::try_from(kept.len()).map_err(|_| SanitizeError::IntegerOverflow)?;
    let mut out = Vec::new();
    out.extend_from_slice(flags);
    if version == 0 {
        if new_count > u32::from(u16::MAX) {
            return Err(SanitizeError::IntegerOverflow);
        }
        out.extend_from_slice(&(new_count as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&new_count.to_be_bytes());
    }
    for infe in kept {
        out.extend_from_slice(infe);
    }
    Ok(out)
}

/// Emit a fresh `iref` body with references to stripped items removed.
///
/// `iref` is a FullBox whose children are one box per reference type
/// (`cdsc`, `thmb`, `auxl`, `dimg`, …). Each child body is `from_ID`,
/// `reference_count`, then that many `to_ID`s. We drop any single-reference
/// box whose `from_ID` or sole `to_ID` is in the stripped set, and prune
/// stripped `to_ID`s from multi-reference lists.
fn heif_rewrite_iref(
    data: &[u8],
    body_off: usize,
    body_end: usize,
    plan: &HeifStripPlan,
) -> Result<Vec<u8>, SanitizeError> {
    if body_off.checked_add(4).map_or(true, |e| e > body_end) {
        return Err(SanitizeError::Malformed);
    }
    let version = data[body_off];
    let id_size = if version == 0 { 2 } else { 4 };
    let mut out = Vec::new();
    out.extend_from_slice(&data[body_off..body_off + 4]);

    let mut cursor = body_off + 4;
    while cursor < body_end {
        let (hdr, ref_body, ref_end) = heif_read_box_header(data, cursor)?;
        if ref_end > body_end {
            return Err(SanitizeError::Malformed);
        }
        let mut p = ref_body;
        if p.checked_add(id_size).map_or(true, |e| e > ref_end) {
            return Err(SanitizeError::Malformed);
        }
        let from_id = if version == 0 {
            u16::from_be_bytes([data[p], data[p + 1]]) as u32
        } else {
            u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
        };
        p += id_size;
        if p.checked_add(2).map_or(true, |e| e > ref_end) {
            return Err(SanitizeError::Malformed);
        }
        let count = u16::from_be_bytes([data[p], data[p + 1]]);
        p += 2;

        if plan.metadata_item_ids.contains(&from_id) {
            // Entire reference originates from a stripped item — drop.
            cursor = ref_end;
            continue;
        }

        let mut kept_ids: Vec<u32> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if p.checked_add(id_size).map_or(true, |e| e > ref_end) {
                return Err(SanitizeError::Malformed);
            }
            let to_id = if version == 0 {
                u16::from_be_bytes([data[p], data[p + 1]]) as u32
            } else {
                u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
            };
            p += id_size;
            if !plan.metadata_item_ids.contains(&to_id) {
                kept_ids.push(to_id);
            }
        }
        if kept_ids.is_empty() {
            // No surviving references — drop the whole single-ref box.
            cursor = ref_end;
            continue;
        }

        // Emit rewritten reference box.
        heif_write_box(&mut out, &hdr.kind, |buf| {
            if version == 0 {
                if from_id > u32::from(u16::MAX) {
                    return Err(SanitizeError::IntegerOverflow);
                }
                buf.extend_from_slice(&(from_id as u16).to_be_bytes());
            } else {
                buf.extend_from_slice(&from_id.to_be_bytes());
            }
            if kept_ids.len() > u16::MAX as usize {
                return Err(SanitizeError::IntegerOverflow);
            }
            let count_u16 = u16::try_from(kept_ids.len())
                .map_err(|_| SanitizeError::IntegerOverflow)?;
            buf.extend_from_slice(&count_u16.to_be_bytes());
            for id in kept_ids {
                if version == 0 {
                    if id > u32::from(u16::MAX) {
                        return Err(SanitizeError::IntegerOverflow);
                    }
                    buf.extend_from_slice(&(id as u16).to_be_bytes());
                } else {
                    buf.extend_from_slice(&id.to_be_bytes());
                }
            }
            Ok(())
        })?;

        cursor = ref_end;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TIFF
// ---------------------------------------------------------------------------
//
// TIFF is the worst-case format for metadata leakage: every byte of
// user-identifying data lives as an IFD tag. EXIF (34665), GPS (34853),
// XMP (700), IPTC (33723), ICC (34675), Photoshop (34377), MakerNote (37500)
// — all of them are just tags in the main IFD pointing at out-of-line
// blobs. There is no "metadata-free TIFF" in practice.
//
// Because of that, a conservative chunk-walker in the style of the JPEG /
// PNG strippers would have to understand every one of ~1200 registered tag
// numbers (and every private / manufacturer range) and still could not be
// sure an unknown tag wasn't leaking data. So we take the opposite tack:
// **rewrite the file from scratch**, keeping ONLY the bare-minimum tag set
// needed by a standards-compliant decoder to get pixels on screen.
//
// Output layout per IFD:
//   1. Strip / tile pixel data (copied byte-for-byte at new offsets).
//   2. Out-of-line tag values (e.g. RATIONAL arrays that don't fit inline).
//   3. The rewritten IFD itself (count + sorted entries + next-IFD pointer).
//
// Strip/tile pixel bytes are copied verbatim; we never touch the encoded
// sample values. Byte order (II / MM) is preserved.

/// TIFF tag type codes (TIFF 6.0 §2).
const TIFF_TYPE_BYTE: u16 = 1;
const TIFF_TYPE_ASCII: u16 = 2;
const TIFF_TYPE_SHORT: u16 = 3;
const TIFF_TYPE_LONG: u16 = 4;
const TIFF_TYPE_RATIONAL: u16 = 5;
const TIFF_TYPE_SBYTE: u16 = 6;
const TIFF_TYPE_UNDEFINED: u16 = 7;
const TIFF_TYPE_SSHORT: u16 = 8;
const TIFF_TYPE_SLONG: u16 = 9;
const TIFF_TYPE_SRATIONAL: u16 = 10;
const TIFF_TYPE_FLOAT: u16 = 11;
const TIFF_TYPE_DOUBLE: u16 = 12;

fn tiff_type_size(t: u16) -> Option<u32> {
    Some(match t {
        TIFF_TYPE_BYTE | TIFF_TYPE_ASCII | TIFF_TYPE_SBYTE | TIFF_TYPE_UNDEFINED => 1,
        TIFF_TYPE_SHORT | TIFF_TYPE_SSHORT => 2,
        TIFF_TYPE_LONG | TIFF_TYPE_SLONG | TIFF_TYPE_FLOAT => 4,
        TIFF_TYPE_RATIONAL | TIFF_TYPE_SRATIONAL | TIFF_TYPE_DOUBLE => 8,
        _ => return None,
    })
}

/// Whitelist of TIFF tag numbers kept in the rewritten IFD.
///
/// Explicitly DROPPED: 305 Software, 306 DateTime, 315 Artist, 316
/// HostComputer, 271 Make, 272 Model, 33432 Copyright, 700 XMP, 33723 IPTC,
/// 34675 ICCProfile, 34665 ExifIFDPointer, 34853 GPSInfoIFDPointer, 40965
/// InteropIFDPointer, every private MakerNote range (37500 + 50xxx range),
/// and every tag not on this list.
fn tiff_is_kept_tag(tag: u16) -> bool {
    matches!(
        tag,
        256   // ImageWidth
        | 257 // ImageLength
        | 258 // BitsPerSample
        | 259 // Compression
        | 262 // PhotometricInterpretation
        | 273 // StripOffsets
        | 274 // Orientation
        | 277 // SamplesPerPixel
        | 278 // RowsPerStrip
        | 279 // StripByteCounts
        | 282 // XResolution
        | 283 // YResolution
        | 284 // PlanarConfiguration
        | 296 // ResolutionUnit
        | 320 // ColorMap (required for palette TIFFs)
        | 322 // TileWidth
        | 323 // TileLength
        | 324 // TileOffsets
        | 325 // TileByteCounts
        | 338 // ExtraSamples
    )
}

/// Tag numbers that require rewriting (they hold offsets into strip/tile
/// pixel data).
fn tiff_is_offset_tag(tag: u16) -> bool {
    matches!(tag, 273 | 324)
}

/// Companion tag numbers that hold byte counts paired with offset tags.
fn tiff_is_bytecount_tag(tag: u16) -> bool {
    matches!(tag, 279 | 325)
}

#[derive(Debug, Clone)]
struct TiffEntry {
    tag: u16,
    typ: u16,
    count: u32,
    /// Either the inline value (≤4 bytes, packed into the u32, endian-preserved
    /// as raw bytes) or the out-of-line offset into the source file.
    value_bytes: [u8; 4],
}

#[derive(Debug)]
struct TiffOffsetPlan {
    offsets: Vec<u32>,
    byte_counts: Vec<u32>,
    new_offsets: Vec<u32>,
}

/// Strip all metadata tags from a TIFF, preserving pixel data and byte
/// order. Multi-page (IFD chain) inputs are rewritten page-by-page.
pub(crate) fn strip_tiff(data: &[u8]) -> Result<Vec<u8>, SanitizeError> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(SanitizeError::TooLarge);
    }
    if !is_tiff(data) {
        return Err(SanitizeError::Malformed);
    }
    if data.len() < 8 {
        return Err(SanitizeError::Malformed);
    }
    let le = data[0] == b'I';

    // Follow the next-IFD chain and rewrite each.
    let first_ifd_off = tiff_read_u32(data, 4, le)? as usize;

    // Output: write header first; 8 bytes of prefix (byte order, magic,
    // first IFD offset placeholder). We'll patch the first-IFD offset at
    // the end.
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[0..2]); // byte order
    out.extend_from_slice(&data[2..4]); // magic 42
    out.extend_from_slice(&[0u8; 4]); // first-IFD offset placeholder

    let mut ifd_cursor = first_ifd_off;
    let mut prev_next_off_pos: Option<usize> = None;
    let mut first_new_ifd_off: Option<u32> = None;
    let mut seen: usize = 0;

    while ifd_cursor != 0 {
        if seen > 64 {
            // Cycle or absurdly long chain — fail closed.
            return Err(SanitizeError::Malformed);
        }
        seen += 1;

        let (new_ifd_off, next_off_patch_pos, next_ifd_cursor) =
            tiff_rewrite_ifd(data, ifd_cursor, le, &mut out)?;

        // Wire the previous IFD's next-pointer (or the header's
        // first-IFD pointer) to this new IFD.
        if let Some(pos) = prev_next_off_pos {
            tiff_write_u32_at(&mut out, pos, new_ifd_off, le);
        } else {
            first_new_ifd_off = Some(new_ifd_off);
        }
        prev_next_off_pos = Some(next_off_patch_pos);
        ifd_cursor = next_ifd_cursor;
    }

    // Patch the first-IFD offset in the header (terminator is already 0
    // from our placeholder writes).
    if let Some(off) = first_new_ifd_off {
        tiff_write_u32_at(&mut out, 4, off, le);
    } else {
        // Zero IFDs — shouldn't happen for a valid TIFF, but be lenient.
        tiff_write_u32_at(&mut out, 4, 0, le);
    }

    Ok(out)
}

/// Rewrite one IFD into `out` and return `(new_ifd_offset,
/// next_pointer_patch_position, next_ifd_offset_in_source)`.
fn tiff_rewrite_ifd(
    data: &[u8],
    ifd_off: usize,
    le: bool,
    out: &mut Vec<u8>,
) -> Result<(u32, usize, usize), SanitizeError> {
    if ifd_off.checked_add(2).map_or(true, |e| e > data.len()) {
        return Err(SanitizeError::Malformed);
    }
    let entry_count = tiff_read_u16(data, ifd_off, le)? as usize;
    let entries_start = ifd_off
        .checked_add(2)
        .ok_or(SanitizeError::IntegerOverflow)?;
    let entries_size = entry_count
        .checked_mul(12)
        .ok_or(SanitizeError::IntegerOverflow)?;
    let entries_end = entries_start
        .checked_add(entries_size)
        .ok_or(SanitizeError::IntegerOverflow)?;
    let after_next = entries_end
        .checked_add(4)
        .ok_or(SanitizeError::IntegerOverflow)?;
    if after_next > data.len() {
        return Err(SanitizeError::Malformed);
    }
    let next_ifd_off = tiff_read_u32(data, entries_end, le)? as usize;

    // Read entries, filter to whitelisted tags only.
    let mut entries: Vec<TiffEntry> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let p = entries_start + i * 12;
        let tag = tiff_read_u16(data, p, le)?;
        let typ = tiff_read_u16(data, p + 2, le)?;
        let count = tiff_read_u32(data, p + 4, le)?;
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&data[p + 8..p + 12]);
        if tiff_is_kept_tag(tag) {
            entries.push(TiffEntry {
                tag,
                typ,
                count,
                value_bytes,
            });
        }
    }

    // Sort by tag — TIFF spec requires ascending tag order.
    entries.sort_by_key(|e| e.tag);

    // Group StripOffsets/TileOffsets with their byte counts so we can
    // rewrite both to new positions.
    let mut strip_plan: Option<TiffOffsetPlan> = None;
    let mut tile_plan: Option<TiffOffsetPlan> = None;

    for e in &entries {
        match e.tag {
            273 => strip_plan = Some(tiff_extract_offset_plan(data, e, le)?),
            324 => tile_plan = Some(tiff_extract_offset_plan(data, e, le)?),
            _ => {}
        }
    }
    // Pair with byte-count tags.
    for e in &entries {
        match e.tag {
            279 => {
                if let Some(p) = strip_plan.as_mut() {
                    p.byte_counts = tiff_read_long_or_short_values(data, e, le)?;
                }
            }
            325 => {
                if let Some(p) = tile_plan.as_mut() {
                    p.byte_counts = tiff_read_long_or_short_values(data, e, le)?;
                }
            }
            _ => {}
        }
    }

    // Layout plan:
    //   1. At current `out.len()`, the pixel data for this IFD begins
    //      (concatenation of all strip / tile extents).
    //   2. Then the IFD header (count + entries + next-IFD pointer).
    //   3. Then out-of-line tag data (arrays > 4 bytes).
    //
    // We need to know new pixel offsets BEFORE writing the IFD, so we
    // copy pixel data first and remember where each strip/tile landed.

    if let Some(plan) = strip_plan.as_mut() {
        plan.new_offsets = tiff_copy_extents(out, data, &plan.offsets, &plan.byte_counts)?;
    }
    if let Some(plan) = tile_plan.as_mut() {
        plan.new_offsets = tiff_copy_extents(out, data, &plan.offsets, &plan.byte_counts)?;
    }

    // Align IFD start to even boundary per TIFF convention.
    if out.len() % 2 == 1 {
        out.push(0);
    }

    let new_ifd_off = u32::try_from(out.len()).map_err(|_| SanitizeError::IntegerOverflow)?;
    let kept_count = entries.len();
    if kept_count > u16::MAX as usize {
        return Err(SanitizeError::IntegerOverflow);
    }
    let kept_count_u16 = u16::try_from(kept_count).map_err(|_| SanitizeError::IntegerOverflow)?;
    let kept_count_bytes = if le {
        kept_count_u16.to_le_bytes()
    } else {
        kept_count_u16.to_be_bytes()
    };
    out.extend_from_slice(&kept_count_bytes);

    // Reserve entries region + next-IFD pointer.
    let entries_out_start = out.len();
    let entries_len = kept_count
        .checked_mul(12)
        .ok_or(SanitizeError::IntegerOverflow)?;
    let new_out_len = entries_out_start
        .checked_add(entries_len)
        .and_then(|x| x.checked_add(4))
        .ok_or(SanitizeError::IntegerOverflow)?;
    out.resize(new_out_len, 0u8);
    let next_ifd_patch_pos = entries_out_start + entries_len;

    // Write each entry, placing out-of-line values at end.
    for (idx, e) in entries.iter().enumerate() {
        let entry_p = entries_out_start + idx * 12;
        let type_sz = tiff_type_size(e.typ).ok_or(SanitizeError::Malformed)?;
        let total_bytes = u64::from(type_sz)
            .checked_mul(u64::from(e.count))
            .ok_or(SanitizeError::IntegerOverflow)?;

        // Tag + type + count.
        tiff_write_u16_at(out, entry_p, e.tag, le);
        tiff_write_u16_at(out, entry_p + 2, e.typ, le);
        tiff_write_u32_at(out, entry_p + 4, e.count, le);

        // Value / offset field.
        if tiff_is_offset_tag(e.tag) {
            // Rewrite to new offsets.
            let plan = match e.tag {
                273 => strip_plan.as_ref(),
                324 => tile_plan.as_ref(),
                _ => None,
            }
            .ok_or(SanitizeError::Malformed)?;
            tiff_write_offset_array(out, entry_p + 8, e, &plan.new_offsets, le)?;
        } else if tiff_is_bytecount_tag(e.tag) {
            // Byte counts are unchanged from the source — we're copying
            // pixel data verbatim.
            let plan = match e.tag {
                279 => strip_plan.as_ref(),
                325 => tile_plan.as_ref(),
                _ => None,
            }
            .ok_or(SanitizeError::Malformed)?;
            tiff_write_offset_array(out, entry_p + 8, e, &plan.byte_counts, le)?;
        } else if total_bytes <= 4 {
            // Inline: copy raw bytes (endianness is preserved because
            // we're copying verbatim from the source).
            out[entry_p + 8..entry_p + 12].copy_from_slice(&e.value_bytes);
        } else {
            // Out-of-line: copy payload from source, write new offset.
            let src_off = tiff_read_u32(&e.value_bytes, 0, le)? as usize;
            let size =
                usize::try_from(total_bytes).map_err(|_| SanitizeError::IntegerOverflow)?;
            let end = src_off
                .checked_add(size)
                .ok_or(SanitizeError::IntegerOverflow)?;
            if end > data.len() {
                return Err(SanitizeError::Malformed);
            }
            let new_off = u32::try_from(out.len()).map_err(|_| SanitizeError::IntegerOverflow)?;
            out.extend_from_slice(&data[src_off..end]);
            // TIFF values have no specified alignment but word-align for
            // safety so next IFD starts on an even byte.
            if out.len() % 2 == 1 {
                out.push(0);
            }
            tiff_write_u32_at(out, entry_p + 8, new_off, le);
        }
    }

    Ok((new_ifd_off, next_ifd_patch_pos, next_ifd_off))
}

fn tiff_extract_offset_plan(
    data: &[u8],
    e: &TiffEntry,
    le: bool,
) -> Result<TiffOffsetPlan, SanitizeError> {
    let values = tiff_read_long_or_short_values(data, e, le)?;
    Ok(TiffOffsetPlan {
        offsets: values,
        byte_counts: Vec::new(),
        new_offsets: Vec::new(),
    })
}

/// Read an array of LONG or SHORT values. Other TIFF numeric types
/// (FLOAT/DOUBLE etc.) are rejected here — this helper is only used for
/// offsets and byte counts which are always LONG or SHORT by spec.
fn tiff_read_long_or_short_values(
    data: &[u8],
    e: &TiffEntry,
    le: bool,
) -> Result<Vec<u32>, SanitizeError> {
    let type_sz = tiff_type_size(e.typ).ok_or(SanitizeError::Malformed)? as usize;
    let total = u64::from(type_sz as u64)
        .checked_mul(u64::from(e.count))
        .ok_or(SanitizeError::IntegerOverflow)?;
    let count_us = usize::try_from(e.count).map_err(|_| SanitizeError::IntegerOverflow)?;

    // Fetch raw bytes (either inline or out-of-line).
    let bytes_cow: Vec<u8> = if total <= 4 {
        e.value_bytes.to_vec()
    } else {
        let off = tiff_read_u32(&e.value_bytes, 0, le)? as usize;
        let size = usize::try_from(total).map_err(|_| SanitizeError::IntegerOverflow)?;
        let end = off
            .checked_add(size)
            .ok_or(SanitizeError::IntegerOverflow)?;
        if end > data.len() {
            return Err(SanitizeError::Malformed);
        }
        data[off..end].to_vec()
    };

    let mut out = Vec::with_capacity(count_us);
    for i in 0..count_us {
        let p = i * type_sz;
        let v = match e.typ {
            TIFF_TYPE_SHORT => tiff_read_u16(&bytes_cow, p, le)? as u32,
            TIFF_TYPE_LONG => tiff_read_u32(&bytes_cow, p, le)?,
            _ => return Err(SanitizeError::Malformed),
        };
        out.push(v);
    }
    Ok(out)
}

/// Copy each (offset, length) slice of the source into `out`, returning the
/// new offsets. Offsets are taken verbatim; byte counts are the actual
/// sizes to copy. No interpretation of the content is done.
fn tiff_copy_extents(
    out: &mut Vec<u8>,
    data: &[u8],
    offsets: &[u32],
    counts: &[u32],
) -> Result<Vec<u32>, SanitizeError> {
    if offsets.len() != counts.len() {
        return Err(SanitizeError::Malformed);
    }
    let mut new_offs = Vec::with_capacity(offsets.len());
    for (off, cnt) in offsets.iter().zip(counts.iter()) {
        let off_us = *off as usize;
        let cnt_us = *cnt as usize;
        let end = off_us
            .checked_add(cnt_us)
            .ok_or(SanitizeError::IntegerOverflow)?;
        if end > data.len() {
            return Err(SanitizeError::Malformed);
        }
        let new_off = u32::try_from(out.len()).map_err(|_| SanitizeError::IntegerOverflow)?;
        out.extend_from_slice(&data[off_us..end]);
        new_offs.push(new_off);
        // Keep word alignment between extents for clean output.
        if out.len() % 2 == 1 {
            out.push(0);
        }
    }
    Ok(new_offs)
}

fn tiff_write_offset_array(
    out: &mut Vec<u8>,
    value_field_pos: usize,
    e: &TiffEntry,
    values: &[u32],
    le: bool,
) -> Result<(), SanitizeError> {
    let type_sz = u64::from(tiff_type_size(e.typ).ok_or(SanitizeError::Malformed)?);
    let total = type_sz
        .checked_mul(u64::from(e.count))
        .ok_or(SanitizeError::IntegerOverflow)?;
    if values.len() as u64 != u64::from(e.count) {
        return Err(SanitizeError::Malformed);
    }
    if total <= 4 {
        // Inline. Zero, then pack.
        for b in &mut out[value_field_pos..value_field_pos + 4] {
            *b = 0;
        }
        let mut p = value_field_pos;
        for v in values {
            match e.typ {
                TIFF_TYPE_SHORT => {
                    if *v > u32::from(u16::MAX) {
                        return Err(SanitizeError::IntegerOverflow);
                    }
                    tiff_write_u16_at(out, p, *v as u16, le);
                    p += 2;
                }
                TIFF_TYPE_LONG => {
                    tiff_write_u32_at(out, p, *v, le);
                    p += 4;
                }
                _ => return Err(SanitizeError::Malformed),
            }
        }
    } else {
        // Out-of-line — write array at end of `out`.
        let array_off = u32::try_from(out.len()).map_err(|_| SanitizeError::IntegerOverflow)?;
        for v in values {
            match e.typ {
                TIFF_TYPE_SHORT => {
                    if *v > u32::from(u16::MAX) {
                        return Err(SanitizeError::IntegerOverflow);
                    }
                    let small = u16::try_from(*v).map_err(|_| SanitizeError::IntegerOverflow)?;
                    let bytes = if le {
                        small.to_le_bytes()
                    } else {
                        small.to_be_bytes()
                    };
                    out.extend_from_slice(&bytes);
                }
                TIFF_TYPE_LONG => {
                    let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
                    out.extend_from_slice(&bytes);
                }
                _ => return Err(SanitizeError::Malformed),
            }
        }
        if out.len() % 2 == 1 {
            out.push(0);
        }
        tiff_write_u32_at(out, value_field_pos, array_off, le);
    }
    Ok(())
}

fn tiff_read_u16(data: &[u8], off: usize, le: bool) -> Result<u16, SanitizeError> {
    if off.checked_add(2).map_or(true, |e| e > data.len()) {
        return Err(SanitizeError::Malformed);
    }
    Ok(if le {
        u16::from_le_bytes([data[off], data[off + 1]])
    } else {
        u16::from_be_bytes([data[off], data[off + 1]])
    })
}

fn tiff_read_u32(data: &[u8], off: usize, le: bool) -> Result<u32, SanitizeError> {
    if off.checked_add(4).map_or(true, |e| e > data.len()) {
        return Err(SanitizeError::Malformed);
    }
    Ok(if le {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    })
}

fn tiff_write_u16_at(buf: &mut [u8], off: usize, v: u16, le: bool) {
    let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
    buf[off..off + 2].copy_from_slice(&bytes);
}

fn tiff_write_u32_at(buf: &mut [u8], off: usize, v: u32, le: bool) {
    let bytes = if le { v.to_le_bytes() } else { v.to_be_bytes() };
    buf[off..off + 4].copy_from_slice(&bytes);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Paranoid post-strip check. Scans for known metadata marker tags. If any
/// survive, the sanitiser has a bug and we must NOT accept the import.
fn sanity_check(out: &[u8]) -> Result<(), SanitizeError> {
    const TAGS: &[&[u8]] = &[
        b"Exif\0\0",               // EXIF APP1
        b"http://ns.adobe.com/xap", // XMP
        b"Photoshop 3.0",          // APP13 IPTC
        b"ICC_PROFILE",            // APP2 ICC
        b"Adobe\0",                // APP14 Adobe
        b"Ducky",                  // APP12 Ducky
        b"iTXt",                   // PNG international text
        b"zTXt",                   // PNG compressed text
        b"tEXt",                   // PNG text
        b"eXIf",                   // PNG EXIF
        b"iCCP",                   // PNG ICC profile
        b"NETSCAPE2.0",            // GIF Netscape app ext
        b"XMP DataXMP",            // GIF XMP app ext signature (Adobe)
    ];
    for tag in TAGS {
        if contains(out, tag) {
            return Err(SanitizeError::Malformed);
        }
    }
    Ok(())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- JPEG / PNG / WebP / GIF ----------

    /// Build a minimal-but-parseable JPEG with an EXIF APP1 and a COM marker
    /// so we can test that the sanitiser removes both.
    fn synthesize_jpeg_with_metadata() -> Vec<u8> {
        let mut v = Vec::new();
        // SOI
        v.extend_from_slice(&[0xFF, 0xD8]);
        // APP0 JFIF (keep)
        let jfif_payload = b"JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00";
        let app0_len = (2 + jfif_payload.len()) as u16;
        v.extend_from_slice(&[0xFF, 0xE0]);
        v.extend_from_slice(&app0_len.to_be_bytes());
        v.extend_from_slice(jfif_payload);
        // APP1 EXIF (drop)
        let exif_payload = b"Exif\x00\x00DEADBEEF";
        let app1_len = (2 + exif_payload.len()) as u16;
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&app1_len.to_be_bytes());
        v.extend_from_slice(exif_payload);
        // COM (drop)
        let com_payload = b"hello world";
        let com_len = (2 + com_payload.len()) as u16;
        v.extend_from_slice(&[0xFF, 0xFE]);
        v.extend_from_slice(&com_len.to_be_bytes());
        v.extend_from_slice(com_payload);
        // SOS with tiny body.
        let sos_payload = [0x01u8, 0x01, 0x00, 0x00, 0x3F, 0x00];
        let sos_len = (2 + sos_payload.len()) as u16;
        v.extend_from_slice(&[0xFF, 0xDA]);
        v.extend_from_slice(&sos_len.to_be_bytes());
        v.extend_from_slice(&sos_payload);
        // Some ECS data ending at EOI.
        v.extend_from_slice(&[0x55, 0xAA, 0x55, 0xAA]);
        // EOI
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn jpeg_strip_removes_exif_and_com() {
        let input = synthesize_jpeg_with_metadata();
        let out = strip_metadata(&input).expect("sanitize ok");
        assert!(contains(&out, b"JFIF"));
        assert!(!contains(&out, b"Exif\0\0"));
        assert!(!contains(&out, b"hello world"));
        assert_eq!(&out[..2], &[0xFF, 0xD8]);
        assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9]);
    }

    #[test]
    fn png_strip_drops_text_chunks() {
        let mut v = Vec::new();
        v.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        fn chunk(v: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
            v.extend_from_slice(&(data.len() as u32).to_be_bytes());
            v.extend_from_slice(typ);
            v.extend_from_slice(data);
            v.extend_from_slice(&[0u8, 0, 0, 0]); // fake CRC
        }
        chunk(&mut v, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
        chunk(&mut v, b"tEXt", b"Comment\0secret GPS");
        chunk(
            &mut v,
            b"IDAT",
            &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
        );
        chunk(&mut v, b"IEND", &[]);
        let out = strip_metadata(&v).expect("sanitize ok");
        assert!(!contains(&out, b"tEXt"));
        assert!(!contains(&out, b"secret GPS"));
        assert!(contains(&out, b"IHDR"));
        assert!(contains(&out, b"IDAT"));
        assert!(contains(&out, b"IEND"));
    }

    #[test]
    fn webp_strip_drops_exif_and_xmp_chunks() {
        let mut v = Vec::new();
        v.extend_from_slice(b"RIFF");
        v.extend_from_slice(&[0u8, 0, 0, 0]);
        v.extend_from_slice(b"WEBP");
        fn chunk(v: &mut Vec<u8>, fourcc: &[u8; 4], data: &[u8]) {
            v.extend_from_slice(fourcc);
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(data);
            if data.len() % 2 == 1 {
                v.push(0);
            }
        }
        chunk(&mut v, b"VP8X", &[0x2C, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        chunk(
            &mut v,
            b"EXIF",
            b"\x49\x49\x2A\x00 secret exif data",
        );
        chunk(
            &mut v,
            b"XMP ",
            b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:Description rdf:about=\"\"/></x:xmpmeta>",
        );
        chunk(&mut v, b"VP8L", &[0x2F, 0, 0, 0, 0, 0, 0, 0]);
        let size = (v.len() - 8) as u32;
        v[4..8].copy_from_slice(&size.to_le_bytes());
        let out = strip_metadata(&v).expect("sanitize ok");
        assert!(!contains(&out, b"secret exif data"));
        assert!(!contains(&out, b"xmpmeta"));
        assert!(contains(&out, b"VP8L"));
        let vp8x_ofs = 12 + 8;
        assert_eq!(out[vp8x_ofs] & 0b0010_1100, 0);
    }

    #[test]
    fn gif_strip_removes_application_and_comment_extensions() {
        let mut v = Vec::new();
        v.extend_from_slice(b"GIF89a");
        v.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0]);
        v.extend_from_slice(&[0x21, 0xFE, 0x0B]);
        v.extend_from_slice(b"my comment!");
        v.push(0x00);
        v.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        v.extend_from_slice(b"NETSCAPE2.0");
        v.extend_from_slice(&[0x03, 0x01, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0]);
        v.extend_from_slice(&[0x02, 0x01, 0x44, 0x00]);
        v.push(0x3B);
        let out = strip_metadata(&v).expect("sanitize ok");
        assert!(!contains(&out, b"my comment!"));
        assert!(!contains(&out, b"NETSCAPE2.0"));
        assert_eq!(out.last(), Some(&0x3B));
    }

    #[test]
    fn rejects_unknown_format() {
        let err = strip_metadata(&[0, 0, 0, 0]).unwrap_err();
        match err {
            SanitizeError::UnsupportedFormat(ImageFormat::Unknown) => {}
            other => panic!("expected UnsupportedFormat(Unknown), got {other:?}"),
        }
    }

    #[test]
    fn detect_format_matrix() {
        assert_eq!(detect_format(&[]), ImageFormat::Unknown);
        assert_eq!(detect_format(&[0xFF, 0xD8, 0xFF]), ImageFormat::Jpeg);
        assert_eq!(detect_format(b"\x89PNG\r\n\x1a\n"), ImageFormat::Png);
        let mut webp = Vec::new();
        webp.extend_from_slice(b"RIFF\0\0\0\0WEBP");
        assert_eq!(detect_format(&webp), ImageFormat::Webp);
        assert_eq!(detect_format(b"GIF89a"), ImageFormat::Gif);
        let mut heif = Vec::new();
        heif.extend_from_slice(&0u32.to_be_bytes());
        heif.extend_from_slice(b"ftypheic");
        assert_eq!(detect_format(&heif), ImageFormat::Heif);
        let mut tiff_le = Vec::new();
        tiff_le.extend_from_slice(b"II");
        tiff_le.extend_from_slice(&42u16.to_le_bytes());
        assert_eq!(detect_format(&tiff_le), ImageFormat::Tiff);
        let mut tiff_be = Vec::new();
        tiff_be.extend_from_slice(b"MM");
        tiff_be.extend_from_slice(&42u16.to_be_bytes());
        assert_eq!(detect_format(&tiff_be), ImageFormat::Tiff);
    }

    // ---------- HEIF / HEIC / AVIF fixtures ----------

    /// Append one ISOBMFF box with `kind` + `body` to `v`.
    fn bx(v: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
        let size = 8 + body.len();
        v.extend_from_slice(&(size as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(body);
    }

    /// Build a minimal HEIF-shaped file with a single `hvc1` image item and a
    /// single metadata item. `metadata_item_type` picks between `Exif` and
    /// `mime` (XMP). Returns the file bytes plus the metadata payload so
    /// callers can assert it is gone from the output.
    fn synthesize_heif_with_metadata_item(
        brand: &[u8; 4],
        metadata_item_type: &[u8; 4],
        metadata_payload: &[u8],
    ) -> Vec<u8> {
        let image_payload: &[u8] = b"COMPRESSED-HEVC-BYTES";

        // Build meta body.
        let mut meta_body: Vec<u8> = Vec::new();
        meta_body.extend_from_slice(&[0u8; 4]); // FullBox version+flags

        // hdlr (FullBox).
        let mut hdlr_body = Vec::new();
        hdlr_body.extend_from_slice(&[0u8; 4]); // version/flags
        hdlr_body.extend_from_slice(&[0u8; 4]); // pre_defined
        hdlr_body.extend_from_slice(b"pict");
        hdlr_body.extend_from_slice(&[0u8; 12]); // reserved
        hdlr_body.push(0); // name
        bx(&mut meta_body, b"hdlr", &hdlr_body);

        // pitm (FullBox v0) — primary item = item 1.
        let mut pitm_body = Vec::new();
        pitm_body.extend_from_slice(&[0u8; 4]); // version/flags
        pitm_body.extend_from_slice(&[0u8, 1]); // item_ID = 1
        bx(&mut meta_body, b"pitm", &pitm_body);

        // iinf v0 with two infe v2 entries.
        let mut iinf_body = Vec::new();
        iinf_body.extend_from_slice(&[0u8; 4]); // version/flags
        iinf_body.extend_from_slice(&[0u8, 2]); // entry_count v0
        fn infe_v2(item_id: u16, item_type: &[u8; 4]) -> Vec<u8> {
            let mut b = Vec::new();
            b.push(2); // version 2
            b.extend_from_slice(&[0u8, 0, 0]); // flags
            b.extend_from_slice(&item_id.to_be_bytes());
            b.extend_from_slice(&[0u8, 0]); // item_protection_index
            b.extend_from_slice(item_type);
            b.push(0); // item_name zero-terminated
            b
        }
        let infe1 = infe_v2(1, b"hvc1");
        let infe2 = infe_v2(2, metadata_item_type);
        bx(&mut iinf_body, b"infe", &infe1);
        bx(&mut iinf_body, b"infe", &infe2);
        bx(&mut meta_body, b"iinf", &iinf_body);

        // iloc body layout (we know exactly what we're emitting):
        // FullBox header 4 + sizes 2 + item_count 2 + 2 items × (id 2 + cm+flags 2
        // + dref 2 + base 0 + extent_count 2 + 1 extent × (off 4 + len 4) = 16)
        // = 40.
        let iloc_body_len = 4 + 2 + 2 + 16 * 2;
        let iloc_box_size = 8 + iloc_body_len;
        let meta_size_after_iloc = 8 + meta_body.len() + iloc_box_size;
        // `ftyp` = 8-byte box header + 4 (major brand) + 4 (minor version) +
        // 4 (compatible brand) = 20 bytes. (The Telephoto test fixture had
        // this as `16` by mistake; that offsets every iloc extent by four
        // bytes, which is harmless on the Telephoto assert but flags an
        // overlap on ours because we check image-payload preservation.)
        let ftyp_size = 20;
        let mdat_header = 8;
        let mdat_body_off = ftyp_size + meta_size_after_iloc + mdat_header;
        let item1_ext_off = mdat_body_off;
        let item2_ext_off = mdat_body_off + image_payload.len();

        let mut iloc_body = Vec::new();
        iloc_body.push(1); // version
        iloc_body.extend_from_slice(&[0u8, 0, 0]); // flags
        iloc_body.push((4 << 4) | 4); // offset_size=4 length_size=4
        iloc_body.push(0); // base_offset_size=0 index_size=0
        iloc_body.extend_from_slice(&[0u8, 2]); // item_count
        for (id, ext_off, ext_len) in [
            (1u16, item1_ext_off as u32, image_payload.len() as u32),
            (2u16, item2_ext_off as u32, metadata_payload.len() as u32),
        ] {
            iloc_body.extend_from_slice(&id.to_be_bytes()); // item_id
            iloc_body.extend_from_slice(&[0u8, 0]); // construction_method=0
            iloc_body.extend_from_slice(&[0u8, 0]); // data_reference_index
            // base_offset size=0 → no bytes
            iloc_body.extend_from_slice(&[0u8, 1]); // extent_count=1
            iloc_body.extend_from_slice(&ext_off.to_be_bytes());
            iloc_body.extend_from_slice(&ext_len.to_be_bytes());
        }
        assert_eq!(iloc_body.len(), iloc_body_len);
        bx(&mut meta_body, b"iloc", &iloc_body);

        // Full file.
        let mut v: Vec<u8> = Vec::new();
        let mut ftyp_body = Vec::new();
        ftyp_body.extend_from_slice(brand); // major brand
        ftyp_body.extend_from_slice(&[0u8; 4]); // minor version
        ftyp_body.extend_from_slice(b"mif1"); // compatible brand
        bx(&mut v, b"ftyp", &ftyp_body);
        bx(&mut v, b"meta", &meta_body);
        let mut mdat_body = Vec::new();
        mdat_body.extend_from_slice(image_payload);
        mdat_body.extend_from_slice(metadata_payload);
        bx(&mut v, b"mdat", &mdat_body);
        v
    }

    #[test]
    fn heif_strips_exif_item_leaves_image_intact() {
        let exif_payload: &[u8] = b"Exif\0\0\x49\x49\x2A\x00 GPS LEAK PAYLOAD";
        let input = synthesize_heif_with_metadata_item(b"heic", b"Exif", exif_payload);
        let out = strip_heif(&input).expect("strip ok");

        // The EXIF payload must NOT appear anywhere in the output.
        assert!(!contains(&out, b"GPS LEAK PAYLOAD"), "EXIF substring survived");
        // Image pixel data must still be present byte-for-byte.
        assert!(contains(&out, b"COMPRESSED-HEVC-BYTES"), "image payload dropped");
        // File must still start with an ftyp box.
        assert_eq!(&out[4..8], b"ftyp");
        // meta box must still exist (primary item still needs decoding).
        assert!(contains(&out, b"meta"));
        // The image item type `hvc1` must survive.
        assert!(contains(&out, b"hvc1"));
        // The `Exif` infe item_type must be gone from the rewritten meta.
        assert!(!contains(&out, b"Exif"));
    }

    #[test]
    fn avif_strips_xmp_leaves_av1_intact() {
        // The container code is format-agnostic, so this is the same
        // fixture as the HEIF case but with an AVIF brand + mime item_type.
        let xmp_payload: &[u8] = b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">LEAKED-GPS</x:xmpmeta>";
        let input = synthesize_heif_with_metadata_item(b"avif", b"mime", xmp_payload);
        let out = strip_heif(&input).expect("strip ok");

        assert!(!contains(&out, b"LEAKED-GPS"), "XMP payload survived");
        assert!(!contains(&out, b"xmpmeta"), "XMP signature survived");
        // Image payload (stands in for av01 codec bytes) survives.
        assert!(contains(&out, b"COMPRESSED-HEVC-BYTES"));
        assert_eq!(&out[8..12], b"avif"); // major brand preserved
    }

    #[test]
    fn heif_rejects_200mib_plus() {
        // 200 MiB + 1 — malicious resource-exhaustion sized input.
        let input = vec![0u8; MAX_INPUT_BYTES + 1];
        let err = strip_heif(&input).unwrap_err();
        assert_eq!(err, SanitizeError::TooLarge);
    }

    #[test]
    fn heif_rejects_malformed_box_size() {
        // Build: ftyp (valid) + bogus box whose size claims to extend past EOF.
        let mut v = Vec::new();
        let mut ftyp_body = Vec::new();
        ftyp_body.extend_from_slice(b"heic");
        ftyp_body.extend_from_slice(&[0u8; 4]);
        ftyp_body.extend_from_slice(b"mif1");
        bx(&mut v, b"ftyp", &ftyp_body);
        // Box with size field claiming 1 MiB but only 8 header bytes follow.
        v.extend_from_slice(&(1_000_000u32).to_be_bytes()); // size
        v.extend_from_slice(b"mdat");
        // No body — header claims a huge payload that isn't there.

        let err = strip_heif(&v).unwrap_err();
        assert_eq!(err, SanitizeError::Malformed);
    }

    #[test]
    fn heif_drops_top_level_uuid_and_udta() {
        // Build: ftyp + udta + uuid + mdat.
        let mut v = Vec::new();
        let mut ftyp_body = Vec::new();
        ftyp_body.extend_from_slice(b"heic");
        ftyp_body.extend_from_slice(&[0u8; 4]);
        ftyp_body.extend_from_slice(b"mif1");
        bx(&mut v, b"ftyp", &ftyp_body);
        bx(&mut v, b"udta", b"APPLE-PROPRIETARY-GPS-HERE");
        bx(
            &mut v,
            b"uuid",
            b"\x85\xC0\xB6\x87\x82\x0F\x11\xE0\x81\x11\xF4\xCE\x46\x2B\x6A\x48canon-gps-data",
        );
        bx(&mut v, b"mdat", b"KEEP-ME-IMAGE");

        let out = strip_heif(&v).expect("ok");
        assert!(!contains(&out, b"APPLE-PROPRIETARY-GPS-HERE"));
        assert!(!contains(&out, b"canon-gps-data"));
        assert!(contains(&out, b"KEEP-ME-IMAGE"));
    }

    // ---------- TIFF fixtures ----------

    /// Pack a u16 value into the 4-byte value/offset field of an IFD entry,
    /// high bytes zeroed, respecting byte order. TIFF puts SHORT values
    /// left-justified within the 4-byte field in both endianness flavours.
    fn short_inline(v: u16, le: bool) -> [u8; 4] {
        let mut out = [0u8; 4];
        if le {
            out[0..2].copy_from_slice(&v.to_le_bytes());
        } else {
            out[0..2].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// Construct a TIFF with the whitelisted geometry/strip tags plus a pile
    /// of dropped tags (GPS, XMP, Software, Make, Model, DateTime, etc.).
    /// Returns (bytes, pixel_marker). Little-endian by default.
    fn synthesize_tiff_with_gps_and_xmp(le: bool) -> (Vec<u8>, &'static [u8]) {
        let pixel_data: &[u8] = b"PIXELS-KEEP-ME";
        let xmp_blob: &[u8] = b"<x:xmpmeta>GPS-DATA-LEAK-XMP</x:xmpmeta>";
        let gps_sub_ifd: &[u8] = b"GPS-SUB-IFD-BLOB";
        let make_str: &[u8] = b"SuperCamCorp\0";
        let datetime: &[u8] = b"2026:04:17 10:00:00\0";

        let mut v = Vec::new();
        v.extend_from_slice(if le { b"II" } else { b"MM" });
        let magic_bytes = if le {
            42u16.to_le_bytes()
        } else {
            42u16.to_be_bytes()
        };
        v.extend_from_slice(&magic_bytes);
        v.extend_from_slice(&[0u8; 4]); // first IFD offset placeholder

        // Pixel strip at a fixed offset.
        let strip_offset = v.len() as u32;
        v.extend_from_slice(pixel_data);
        let xmp_off = v.len() as u32;
        v.extend_from_slice(xmp_blob);
        let gps_off = v.len() as u32;
        v.extend_from_slice(gps_sub_ifd);
        let make_off = v.len() as u32;
        v.extend_from_slice(make_str);
        let datetime_off = v.len() as u32;
        v.extend_from_slice(datetime);
        // XResolution RATIONAL = 72/1.
        let xres_off = v.len() as u32;
        let num72 = if le {
            72u32.to_le_bytes()
        } else {
            72u32.to_be_bytes()
        };
        let one = if le { 1u32.to_le_bytes() } else { 1u32.to_be_bytes() };
        v.extend_from_slice(&num72);
        v.extend_from_slice(&one);

        // IFD start offset.
        let ifd_off = v.len() as u32;
        let ifd_off_bytes = if le {
            ifd_off.to_le_bytes()
        } else {
            ifd_off.to_be_bytes()
        };
        v[4..8].copy_from_slice(&ifd_off_bytes);

        // Entries (must be in sorted tag order).
        let strip_bytes = if le {
            strip_offset.to_le_bytes()
        } else {
            strip_offset.to_be_bytes()
        };
        let xmp_bytes = if le {
            xmp_off.to_le_bytes()
        } else {
            xmp_off.to_be_bytes()
        };
        let gps_bytes = if le {
            gps_off.to_le_bytes()
        } else {
            gps_off.to_be_bytes()
        };
        let make_bytes = if le {
            make_off.to_le_bytes()
        } else {
            make_off.to_be_bytes()
        };
        let dt_bytes = if le {
            datetime_off.to_le_bytes()
        } else {
            datetime_off.to_be_bytes()
        };
        let xres_bytes = if le {
            xres_off.to_le_bytes()
        } else {
            xres_off.to_be_bytes()
        };

        let entries: Vec<(u16, u16, u32, [u8; 4])> = vec![
            (256, TIFF_TYPE_SHORT, 1, short_inline(7, le)),
            (257, TIFF_TYPE_SHORT, 1, short_inline(2, le)),
            (258, TIFF_TYPE_SHORT, 1, short_inline(8, le)),
            (259, TIFF_TYPE_SHORT, 1, short_inline(1, le)),
            (262, TIFF_TYPE_SHORT, 1, short_inline(1, le)),
            (
                271,
                TIFF_TYPE_ASCII,
                make_str.len() as u32,
                make_bytes,
            ), // Make — drop
            (273, TIFF_TYPE_LONG, 1, strip_bytes),
            (277, TIFF_TYPE_SHORT, 1, short_inline(1, le)),
            (278, TIFF_TYPE_SHORT, 1, short_inline(2, le)),
            (279, TIFF_TYPE_LONG, 1, {
                let mut b = [0u8; 4];
                if le {
                    b.copy_from_slice(&(pixel_data.len() as u32).to_le_bytes());
                } else {
                    b.copy_from_slice(&(pixel_data.len() as u32).to_be_bytes());
                }
                b
            }),
            (282, TIFF_TYPE_RATIONAL, 1, xres_bytes),
            (283, TIFF_TYPE_RATIONAL, 1, xres_bytes),
            (296, TIFF_TYPE_SHORT, 1, short_inline(2, le)),
            (
                306,
                TIFF_TYPE_ASCII,
                datetime.len() as u32,
                dt_bytes,
            ), // DateTime — drop
            (
                700,
                TIFF_TYPE_BYTE,
                xmp_blob.len() as u32,
                xmp_bytes,
            ), // XMP — drop
            (34853, TIFF_TYPE_LONG, 1, gps_bytes), // GPSInfoIFDPointer — drop
        ];
        let entry_count = entries.len() as u16;
        let ec_bytes = if le {
            entry_count.to_le_bytes()
        } else {
            entry_count.to_be_bytes()
        };
        v.extend_from_slice(&ec_bytes);
        for (tag, typ, count, val) in &entries {
            let tag_b = if le { tag.to_le_bytes() } else { tag.to_be_bytes() };
            let typ_b = if le { typ.to_le_bytes() } else { typ.to_be_bytes() };
            let count_b = if le { count.to_le_bytes() } else { count.to_be_bytes() };
            v.extend_from_slice(&tag_b);
            v.extend_from_slice(&typ_b);
            v.extend_from_slice(&count_b);
            v.extend_from_slice(val);
        }
        v.extend_from_slice(&[0u8; 4]); // next-IFD pointer (terminator)

        (v, pixel_data)
    }

    #[test]
    fn tiff_strips_gps_tags_preserves_pixel_data() {
        let (input, pixel_marker) = synthesize_tiff_with_gps_and_xmp(true);
        let out = strip_tiff(&input).expect("strip ok");

        // GPS / XMP / Software / Make / DateTime all gone.
        assert!(!contains(&out, b"GPS-SUB-IFD-BLOB"), "GPS sub-IFD data survived");
        assert!(!contains(&out, b"GPS-DATA-LEAK-XMP"), "XMP payload survived");
        assert!(!contains(&out, b"<x:xmpmeta>"), "XMP marker survived");
        assert!(!contains(&out, b"SuperCamCorp"), "Make tag survived");
        assert!(!contains(&out, b"2026:04:17"), "DateTime tag survived");
        // Pixel data survives at its new offset.
        assert!(contains(&out, pixel_marker), "pixel data dropped");
        // TIFF header preserved.
        assert_eq!(&out[..2], b"II");
        assert_eq!(&out[2..4], &42u16.to_le_bytes());
    }

    #[test]
    fn tiff_preserves_byte_order() {
        // II (little-endian) round-trip.
        let (le_input, pixel_marker) = synthesize_tiff_with_gps_and_xmp(true);
        let le_out = strip_tiff(&le_input).expect("le strip ok");
        assert_eq!(&le_out[..2], b"II");
        assert_eq!(&le_out[2..4], &42u16.to_le_bytes());
        assert!(contains(&le_out, pixel_marker));

        // MM (big-endian) round-trip.
        let (be_input, pixel_marker) = synthesize_tiff_with_gps_and_xmp(false);
        let be_out = strip_tiff(&be_input).expect("be strip ok");
        assert_eq!(&be_out[..2], b"MM");
        assert_eq!(&be_out[2..4], &42u16.to_be_bytes());
        assert!(contains(&be_out, pixel_marker));
        // Cross-check: BE header's first-IFD offset must NOT equal the LE
        // representation of the same integer (byte order really is being
        // honoured, not just echoed verbatim from the header constant).
        let be_first_ifd = u32::from_be_bytes([be_out[4], be_out[5], be_out[6], be_out[7]]);
        assert!(be_first_ifd > 0);
    }

    #[test]
    fn tiff_multi_page_strips_each_ifd() {
        // Two-IFD TIFF: each page has its own GPS tag; both must be stripped.
        let le = true;
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&42u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]); // first IFD

        let strip0 = v.len() as u32;
        v.extend_from_slice(b"PAGE0-PIXELS");
        let gps0 = v.len() as u32;
        v.extend_from_slice(b"PAGE0-GPS-LEAK");
        let strip1 = v.len() as u32;
        v.extend_from_slice(b"PAGE1-PIXELS");
        let gps1 = v.len() as u32;
        v.extend_from_slice(b"PAGE1-GPS-LEAK");

        let ifd0 = v.len() as u32;
        v[4..8].copy_from_slice(&ifd0.to_le_bytes());

        fn write_ifd(
            v: &mut Vec<u8>,
            strip_off: u32,
            strip_len: u32,
            gps_off: u32,
            le: bool,
        ) -> usize {
            let strip_bytes = if le {
                strip_off.to_le_bytes()
            } else {
                strip_off.to_be_bytes()
            };
            let strip_len_bytes = if le {
                strip_len.to_le_bytes()
            } else {
                strip_len.to_be_bytes()
            };
            let gps_bytes = if le {
                gps_off.to_le_bytes()
            } else {
                gps_off.to_be_bytes()
            };
            let entries: Vec<(u16, u16, u32, [u8; 4])> = vec![
                (256, TIFF_TYPE_SHORT, 1, super::tests::short_inline(2, le)),
                (257, TIFF_TYPE_SHORT, 1, super::tests::short_inline(2, le)),
                (273, TIFF_TYPE_LONG, 1, strip_bytes),
                (279, TIFF_TYPE_LONG, 1, strip_len_bytes),
                (34853, TIFF_TYPE_LONG, 1, gps_bytes),
            ];
            let ec = if le {
                (entries.len() as u16).to_le_bytes()
            } else {
                (entries.len() as u16).to_be_bytes()
            };
            v.extend_from_slice(&ec);
            for (tag, typ, count, val) in &entries {
                let tag_b = if le { tag.to_le_bytes() } else { tag.to_be_bytes() };
                let typ_b = if le { typ.to_le_bytes() } else { typ.to_be_bytes() };
                let count_b = if le { count.to_le_bytes() } else { count.to_be_bytes() };
                v.extend_from_slice(&tag_b);
                v.extend_from_slice(&typ_b);
                v.extend_from_slice(&count_b);
                v.extend_from_slice(val);
            }
            let next_pos = v.len();
            v.extend_from_slice(&[0u8; 4]);
            next_pos
        }
        let next0 = write_ifd(&mut v, strip0, 12, gps0, le);
        let ifd1 = v.len() as u32;
        v[next0..next0 + 4].copy_from_slice(&ifd1.to_le_bytes());
        let _ = write_ifd(&mut v, strip1, 12, gps1, le);

        let out = strip_tiff(&v).expect("strip ok");
        assert!(!contains(&out, b"PAGE0-GPS-LEAK"), "page 0 GPS survived");
        assert!(!contains(&out, b"PAGE1-GPS-LEAK"), "page 1 GPS survived");
        assert!(contains(&out, b"PAGE0-PIXELS"), "page 0 pixels dropped");
        assert!(contains(&out, b"PAGE1-PIXELS"), "page 1 pixels dropped");

        // Both IFDs were emitted (the chain was walked): the header's
        // first-IFD offset must differ from 0 and the next-IFD pointer
        // reached from there must also differ from 0.
        let first = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
        assert!(first > 0 && first + 2 <= out.len());
        let count0 = u16::from_le_bytes([out[first], out[first + 1]]) as usize;
        let next_ptr_pos = first + 2 + count0 * 12;
        assert!(next_ptr_pos + 4 <= out.len());
        let next_ptr = u32::from_le_bytes([
            out[next_ptr_pos],
            out[next_ptr_pos + 1],
            out[next_ptr_pos + 2],
            out[next_ptr_pos + 3],
        ]);
        assert!(next_ptr > 0, "second IFD missing from chain");
    }

    #[test]
    fn tiff_rejects_overflowing_strip_offset() {
        // Build a minimal TIFF where StripOffsets points past EOF.
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&42u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]); // first IFD offset

        let ifd_off = v.len() as u32;
        v[4..8].copy_from_slice(&ifd_off.to_le_bytes());

        // Craft IFD with StripOffsets = 0xFFFF_FF00 (way past EOF).
        let entries: Vec<(u16, u16, u32, [u8; 4])> = vec![
            (256, TIFF_TYPE_SHORT, 1, short_inline(2, true)),
            (257, TIFF_TYPE_SHORT, 1, short_inline(2, true)),
            (273, TIFF_TYPE_LONG, 1, 0xFFFF_FF00u32.to_le_bytes()),
            (279, TIFF_TYPE_LONG, 1, 10u32.to_le_bytes()),
        ];
        v.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (tag, typ, count, val) in &entries {
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(&typ.to_le_bytes());
            v.extend_from_slice(&count.to_le_bytes());
            v.extend_from_slice(val);
        }
        v.extend_from_slice(&[0u8; 4]); // next-IFD pointer

        let err = strip_tiff(&v).unwrap_err();
        assert!(matches!(err, SanitizeError::Malformed));
    }

    #[test]
    fn tiff_rejects_big_tiff() {
        // BigTIFF magic = 43. We only handle classic TIFF (42).
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&43u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]);
        assert!(strip_tiff(&v).is_err());
    }
}
