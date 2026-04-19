//! Image metadata stripping and decompression-bomb defense.
//!
//! This module is the SDK entry point for importing untrusted image bytes.
//! It consolidates two previously-duplicated Telephoto primitives:
//!
//! * [`sanitize`] — format-aware metadata stripping. Auto-detects JPEG / PNG /
//!   WebP / GIF / HEIF / AVIF / TIFF from magic bytes, walks the container
//!   structure, and emits a fresh `Vec<u8>` with every EXIF / XMP / IPTC / ICC
//!   / vendor metadata atom removed. **Pixel data passes through
//!   byte-for-byte** — the sanitiser never invokes libheif, libavif, libtiff,
//!   or any other codec. That keeps the O(CVE) decoder surface entirely off
//!   the import path.
//!
//! * [`dimension_gate`] — decompression-bomb defense. Parses just the image
//!   header (no pixel decode) and rejects anything that exceeds the per-axis
//!   dimension cap or the total uncompressed-byte budget. Safe to call
//!   *before* invoking an image decoder in consumer code.
//!
//! # Typical pipeline
//!
//! ```no_run
//! use privacysuite_core_sdk::crypto::media::{inspect_dimensions, strip_metadata};
//!
//! fn import(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//!     // 1. Reject decompression bombs up-front so we never allocate /
//!     //    decode pixels for a pathological header.
//!     let _dims = inspect_dimensions(bytes)?;
//!     // 2. Strip metadata. Output is safe to persist.
//!     let clean = strip_metadata(bytes)?;
//!     Ok(clean)
//! }
//! ```
//!
//! Both functions are pure byte-in / byte-out and never touch disk, network,
//! or global state.

pub mod dimension_gate;
pub mod sanitize;

pub use dimension_gate::{inspect_dimensions, DimensionError, DimensionInfo};
pub use sanitize::{detect_format, strip_metadata, ImageFormat, SanitizeError};
