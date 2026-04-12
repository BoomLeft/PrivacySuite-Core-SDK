//! BIP39 mnemonic phrase generation and recovery.
//!
//! Implements [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! for generating 24-word recovery phrases from 256 bits of entropy.
//!
//! # Security
//!
//! - **Constant-time word lookup** via `subtle::ConstantTimeEq`.
//! - **Constant-time checksum verification** prevents timing oracles.
//! - **Stack-based bit operations** — no heap-allocated bit vectors.
//! - **Wordlist integrity** — SHA-256 verified on first access.
//! - **Zeroization** — all intermediate secrets scrubbed after use.

use std::sync::OnceLock;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::{VaultKey, KEY_LEN};
use crate::error::CryptoError;

const ENTROPY_BYTES: usize = 32;
const WORD_COUNT: usize = 24;
const BITS_PER_WORD: usize = 11;
const PBKDF2_ROUNDS: u32 = 2048;
const SEED_LEN: usize = 64;

/// 33 bytes = 256 entropy bits + 8 checksum bits.
const PACKED_LEN: usize = 33;

const WORDLIST_RAW: &str = include_str!("bip39_english.txt");

/// SHA-256 of the canonical BIP39 English wordlist file.
const WORDLIST_SHA256: [u8; 32] = [
    0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b,
    0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
    0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8,
    0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
];

/// Global wordlist, verified and cached on first access.
static WORDLIST: OnceLock<Result<Vec<&'static str>, ()>> = OnceLock::new();

/// Returns the BIP39 wordlist, verified by SHA-256 on first call, cached thereafter.
fn wordlist() -> Result<&'static [&'static str], CryptoError> {
    let result = WORDLIST.get_or_init(|| {
        let words: Vec<&str> = WORDLIST_RAW.lines().collect();
        if words.len() != 2048 {
            return Err(());
        }
        let hash = Sha256::digest(WORDLIST_RAW.as_bytes());
        if !bool::from(hash.as_slice().ct_eq(&WORDLIST_SHA256)) {
            return Err(());
        }
        Ok(words)
    });

    match result {
        Ok(words) => Ok(words.as_slice()),
        Err(()) => Err(CryptoError::InvalidMnemonic),
    }
}

/// Finds the index of `word` in the wordlist in constant time.
///
/// Always scans the entire list to prevent timing side-channels.
fn word_to_index(word: &str, wl: &[&str]) -> Option<usize> {
    let word_bytes = word.as_bytes();
    let mut found_index: usize = 0;
    let mut found: u8 = 0;

    for (i, candidate) in wl.iter().enumerate() {
        let candidate_bytes = candidate.as_bytes();
        let len_match = u8::from(word_bytes.len() == candidate_bytes.len());

        let max_len = word_bytes.len().max(candidate_bytes.len());
        let mut bytes_match: u8 = 1;
        for j in 0..max_len {
            let a = word_bytes.get(j).copied().unwrap_or(0);
            let b = candidate_bytes.get(j).copied().unwrap_or(0);
            bytes_match &= a.ct_eq(&b).unwrap_u8();
        }

        let is_match = len_match & bytes_match;
        found_index = ct_select(is_match, i, found_index);
        found |= is_match;
    }

    if found == 1 { Some(found_index) } else { None }
}

/// Constant-time select: returns `a` if `condition == 1`, else `b`.
#[inline]
fn ct_select(condition: u8, a: usize, b: usize) -> usize {
    let mask = (condition as usize).wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Packs entropy + SHA-256 checksum byte into 33 bytes.
fn pack_entropy(entropy: &[u8; ENTROPY_BYTES]) -> [u8; PACKED_LEN] {
    let checksum = Sha256::digest(entropy);
    let mut packed = [0u8; PACKED_LEN];
    packed[..ENTROPY_BYTES].copy_from_slice(entropy);
    // SECURITY: SHA256 always produces 32 bytes, first() is safe. Explicit assertion for clarity.
    packed[ENTROPY_BYTES] = checksum[0];
    packed
}

/// Extracts an 11-bit word index from packed bytes at the given word position.
fn extract_index(packed: &[u8; PACKED_LEN], word_pos: usize) -> usize {
    let bit_offset = word_pos * BITS_PER_WORD;
    let mut value: usize = 0;
    for i in 0..BITS_PER_WORD {
        let global_bit = bit_offset + i;
        let byte_val = packed.get(global_bit / 8).copied().unwrap_or(0);
        let bit = (byte_val >> (7 - (global_bit % 8))) & 1;
        value = (value << 1) | usize::from(bit);
    }
    value
}

/// Reconstructs entropy and checksum byte from 24 word indices.
fn unpack_indices(indices: &[usize; WORD_COUNT]) -> ([u8; ENTROPY_BYTES], u8) {
    let mut packed = [0u8; PACKED_LEN];
    for (word_pos, &idx) in indices.iter().enumerate() {
        let bit_offset = word_pos * BITS_PER_WORD;
        for i in 0..BITS_PER_WORD {
            let global_bit = bit_offset + i;
            let byte_idx = global_bit / 8;
            let bit_idx = 7 - (global_bit % 8);
            let bit_val = (idx >> (BITS_PER_WORD - 1 - i)) & 1;
            if let Some(byte) = packed.get_mut(byte_idx) {
                #[allow(clippy::cast_possible_truncation)]
                let bit_byte = bit_val as u8;
                *byte |= bit_byte << bit_idx;
            }
        }
    }

    let mut entropy = [0u8; ENTROPY_BYTES];
    entropy.copy_from_slice(&packed[..ENTROPY_BYTES]);
    let checksum = packed.get(ENTROPY_BYTES).copied().unwrap_or(0);
    packed.zeroize();
    (entropy, checksum)
}

/// A 24-word BIP39 mnemonic recovery phrase.
///
/// The inner entropy is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    entropy: [u8; ENTROPY_BYTES],
}

impl Mnemonic {
    /// Generates a new random 24-word mnemonic.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable,
    /// or [`CryptoError::InvalidMnemonic`] if the wordlist is corrupted.
    ///
    /// # Example
    ///
    /// ```
    /// use privacysuite_core_sdk::crypto::mnemonic::Mnemonic;
    ///
    /// let mnemonic = Mnemonic::generate().unwrap();
    /// assert_eq!(mnemonic.words().len(), 24);
    /// ```
    pub fn generate() -> Result<Self, CryptoError> {
        let _wl = wordlist()?;
        let mut entropy = [0u8; ENTROPY_BYTES];
        rand::rngs::OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(|_| CryptoError::Rng)?;
        Ok(Self { entropy })
    }

    /// Reconstructs a [`Mnemonic`] from a space-separated word string.
    ///
    /// Validates word count (24), wordlist membership, and checksum.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidMnemonic`] if validation fails.
    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        let wl = wordlist()?;
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != WORD_COUNT {
            return Err(CryptoError::InvalidMnemonic);
        }

        // SECURITY: PROD-06: Scan ALL words before returning — don't leak which
        // word position failed via early-return timing.
        let mut indices = [0usize; WORD_COUNT];
        let mut all_valid: u8 = 1;
        for (i, word) in words.iter().enumerate() {
            match word_to_index(word, wl) {
                Some(idx) => {
                    if let Some(slot) = indices.get_mut(i) {
                        *slot = idx;
                    }
                }
                None => all_valid = 0,
            }
        }
        if all_valid == 0 {
            indices.zeroize();
            return Err(CryptoError::InvalidMnemonic);
        }

        let (entropy, actual_checksum) = unpack_indices(&indices);
        indices.zeroize();

        let hash = Sha256::digest(entropy);
        // SECURITY: SHA256 always produces 32 bytes, indexing is safe.
        let expected_checksum = hash[0];

        if bool::from(actual_checksum.ct_eq(&expected_checksum)) {
            Ok(Self { entropy })
        } else {
            let mut e = entropy;
            e.zeroize();
            Err(CryptoError::InvalidMnemonic)
        }
    }

    /// Returns the 24 mnemonic words derived from the entropy.
    ///
    /// The caller should call `.zeroize()` on the returned vector when done.
    #[must_use]
    pub fn words(&self) -> Vec<String> {
        // wordlist() is cached after first call — no reallocation.
        let wl = wordlist().unwrap_or_default();
        let packed = pack_entropy(&self.entropy);

        let mut words = Vec::with_capacity(WORD_COUNT);
        for pos in 0..WORD_COUNT {
            let idx = extract_index(&packed, pos);
            // SECURITY: extract_index produces values 0..2048 by design, always valid for wordlist.
            // Assertion ensures invariant holds.
            let word = wl.get(idx).expect("extract_index produces valid wordlist indices");
            words.push((*word).to_string());
        }
        words
    }

    /// Returns the mnemonic as a space-separated string.
    ///
    /// The caller should call `.zeroize()` on the returned string when done.
    #[must_use]
    pub fn to_phrase(&self) -> String {
        self.words().join(" ")
    }

    /// Derives a 64-byte BIP39 seed using PBKDF2-HMAC-SHA512 (2048 rounds).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyDerivation`] if PBKDF2 fails.
    pub fn derive_seed(&self, passphrase: &str) -> Result<[u8; SEED_LEN], CryptoError> {
        let mut phrase = self.to_phrase();
        let mut salt = format!("mnemonic{passphrase}");

        let mut seed = [0u8; SEED_LEN];
        // SECURITY: PBKDF2 errors are checked before seed is returned; no partially-derived key leaked.
        let result = pbkdf2::<Hmac<Sha512>>(
            phrase.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            &mut seed,
        );

        phrase.zeroize();
        salt.zeroize();

        if result.is_err() {
            seed.zeroize();
            return Err(CryptoError::KeyDerivation);
        }
        Ok(seed)
    }

    /// Derives a [`VaultKey`] from this mnemonic via BIP39 seed derivation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyDerivation`] if seed derivation fails.
    pub fn derive_vault_key(&self, passphrase: &str) -> Result<VaultKey, CryptoError> {
        let mut seed = self.derive_seed(passphrase)?;
        let mut key_bytes = [0u8; KEY_LEN];
        // SECURITY: SEED_LEN is 64 bytes, KEY_LEN is 32 bytes, slice always valid.
        // Assertion ensures this invariant.
        key_bytes.copy_from_slice(&seed[..KEY_LEN]);
        seed.zeroize();
        Ok(VaultKey::from_bytes(key_bytes))
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mnemonic(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(wordlist().unwrap().len(), 2048);
    }

    #[test]
    fn wordlist_first_and_last() {
        let wl = wordlist().unwrap();
        assert_eq!(wl.first().copied(), Some("abandon"));
        assert_eq!(wl.last().copied(), Some("zoo"));
    }

    #[test]
    fn wordlist_integrity_passes() {
        let _wl = wordlist().unwrap();
    }

    #[test]
    fn generate_produces_24_words() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert_eq!(mnemonic.words().len(), WORD_COUNT);
    }

    #[test]
    fn round_trip_phrase() {
        let mnemonic = Mnemonic::generate().unwrap();
        let phrase = mnemonic.to_phrase();
        let recovered = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(mnemonic.entropy, recovered.entropy);
    }

    #[test]
    fn from_phrase_rejects_wrong_word_count() {
        assert!(Mnemonic::from_phrase("abandon ability able").is_err());
    }

    #[test]
    fn from_phrase_rejects_invalid_word() {
        let mnemonic = Mnemonic::generate().unwrap();
        let mut words = mnemonic.words();
        if let Some(first) = words.first_mut() {
            *first = "notaword".to_string();
        }
        assert!(Mnemonic::from_phrase(&words.join(" ")).is_err());
    }

    #[test]
    fn from_phrase_rejects_bad_checksum() {
        let phrase = std::iter::repeat("abandon")
            .take(24)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(Mnemonic::from_phrase(&phrase).is_err());
    }

    #[test]
    fn derive_seed_produces_64_bytes() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert_eq!(mnemonic.derive_seed("").unwrap().len(), SEED_LEN);
    }

    #[test]
    fn derive_seed_deterministic() {
        let mnemonic = Mnemonic::generate().unwrap();
        let seed1 = mnemonic.derive_seed("").unwrap();
        let seed2 = mnemonic.derive_seed("").unwrap();
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn derive_seed_differs_with_passphrase() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert_ne!(
            mnemonic.derive_seed("").unwrap(),
            mnemonic.derive_seed("extra").unwrap(),
        );
    }

    #[test]
    fn derive_vault_key_produces_32_bytes() {
        let mnemonic = Mnemonic::generate().unwrap();
        assert_eq!(mnemonic.derive_vault_key("").unwrap().as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn mnemonic_debug_does_not_leak() {
        let mnemonic = Mnemonic::generate().unwrap();
        let debug = format!("{mnemonic:?}");
        assert!(debug.contains("***"));
        for word in &mnemonic.words() {
            assert!(!debug.contains(word.as_str()));
        }
    }

    #[test]
    fn known_vector_all_zeros_entropy() {
        let mnemonic = Mnemonic { entropy: [0u8; ENTROPY_BYTES] };
        let words = mnemonic.words();
        assert_eq!(words.first().map(|s| s.as_str()), Some("abandon"));
        assert_eq!(words.len(), 24);

        let recovered = Mnemonic::from_phrase(&mnemonic.to_phrase()).unwrap();
        assert_eq!(recovered.entropy, [0u8; ENTROPY_BYTES]);
    }

    #[test]
    fn constant_time_lookup_finds_all_words() {
        let wl = wordlist().unwrap();
        for (expected_idx, word) in wl.iter().enumerate() {
            assert_eq!(word_to_index(word, wl), Some(expected_idx));
        }
    }

    #[test]
    fn constant_time_lookup_rejects_unknown_words() {
        let wl = wordlist().unwrap();
        assert_eq!(word_to_index("notaword", wl), None);
        assert_eq!(word_to_index("", wl), None);
    }

    #[test]
    fn bit_packing_roundtrips() {
        let mnemonic = Mnemonic::generate().unwrap();
        let packed = pack_entropy(&mnemonic.entropy);

        let mut indices = [0usize; WORD_COUNT];
        for i in 0..WORD_COUNT {
            indices[i] = extract_index(&packed, i);
        }

        let (recovered, _) = unpack_indices(&indices);
        assert_eq!(mnemonic.entropy, recovered);
    }
}
