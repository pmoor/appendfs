//! Optional per-record compression, applied before encryption.
//!
//! Compressing then encrypting is the only workable order - ciphertext does not compress -
//! and it is cheap here because a record is already the unit of I/O: an AEAD authenticates a
//! payload as a whole, so a read of any byte already fetches and processes the entire record.
//! Compression rides along inside that existing work rather than adding a new read cost.
//!
//! The trade is a side channel. An observer of a volume can already see record boundaries and
//! sizes; with compression they additionally learn how *compressible* each record was, which
//! distinguishes text from already-compressed media. Records hold one inode's bytes, so there
//! is no cross-file mixing of the kind CRIME exploits, but an attacker who can write chosen
//! bytes into the same file as a secret and watch record sizes learns something about it.

use serde::{Deserialize, Serialize};
use std::io;

/// Upper bound on a decompressed record, guarding against a corrupt or forged length.
///
/// On an encrypted volume the length lives inside the AEAD, so it cannot be forged without
/// the key; this bound is what protects an unencrypted volume, where nothing authenticates it.
pub const MAX_DECOMPRESSED_RECORD: usize = 256 * 1024 * 1024;

/// zstd level. Measured across source text, logs, sparse binary and incompressible data,
/// level 3 sits at near-peak ratio while compressing at 170-690 MB/s; level 6 buys a few
/// percent more for a collapse to 55 MB/s, which would throttle flushing.
const ZSTD_LEVEL: i32 = 3;

/// Minimum saving for a compressed record to be kept, as a fraction of the original.
///
/// Below this the space win does not justify decompressing on every future read, so the
/// record is stored as-is. Matches the ratio ZFS uses for the same decision.
const MIN_SAVING_NUMERATOR: usize = 1;
const MIN_SAVING_DENOMINATOR: usize = 8;

/// Tag byte leading every record payload, inside the encrypted envelope.
const TAG_STORED: u8 = 0;
const TAG_ZSTD: u8 = 1;

/// How a volume compresses newly written records.
///
/// This governs writes only. What a *reader* does is decided by the tag inside each record,
/// never by this field - the field sits in the plaintext volume header where nothing
/// authenticates it, so trusting it on the read path would let a flipped byte change how
/// stored bytes are interpreted. That is the mistake the old per-record `key_id` made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum Compression {
    #[default]
    None = 0,
    Zstd = 1,
}

impl Compression {
    pub fn is_enabled(self) -> bool {
        self != Compression::None
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Compression::None => "None",
            Compression::Zstd => "zstd",
        })
    }
}

/// Wraps `payload` in the envelope that gets encrypted and written.
///
/// Layout is `[tag][u32 original length, when compressed][bytes]`. The tag travels *inside*
/// the payload rather than in the record header precisely so that encryption authenticates
/// it: the record header is not covered by the payload checksum, so a tag stored there could
/// be flipped to make a reader feed ciphertext-shaped bytes to the decompressor.
pub fn pack(payload: &[u8], compression: Compression) -> Vec<u8> {
    if compression.is_enabled()
        && let Ok(compressed) = zstd::bulk::compress(payload, ZSTD_LEVEL)
    {
        // Keep it only if it saves enough to be worth decompressing on every read. The
        // check is cheap even when it fails: zstd rejects incompressible input at GB/s.
        let saved = payload.len().saturating_sub(compressed.len());
        if saved >= payload.len() / MIN_SAVING_DENOMINATOR * MIN_SAVING_NUMERATOR && !compressed.is_empty() {
            let mut out = Vec::with_capacity(1 + 4 + compressed.len());
            out.push(TAG_ZSTD);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&compressed);
            return out;
        }
    }

    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(TAG_STORED);
    out.extend_from_slice(payload);
    out
}

/// Reverses [`pack`], returning the original payload.
pub fn unpack(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "record payload is empty"))?;

    match tag {
        TAG_STORED => Ok(rest.to_vec()),
        TAG_ZSTD => {
            let len_bytes = rest
                .get(..4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "compressed record is missing its length"))?;
            let original_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;

            if original_len > MAX_DECOMPRESSED_RECORD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed record claims to expand to {} bytes, beyond the {} byte limit",
                        original_len, MAX_DECOMPRESSED_RECORD
                    ),
                ));
            }

            let decompressed = zstd::bulk::decompress(&rest[4..], original_len).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("record decompression failed: {}", e),
                )
            })?;

            // zstd's own frame header also carries a length; disagreement means the record
            // is not what it claims, so refuse rather than hand back a short buffer.
            if decompressed.len() != original_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed record declared {} bytes but expanded to {}",
                        original_len,
                        decompressed.len()
                    ),
                ));
            }
            Ok(decompressed)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown record payload tag {}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_compressible_and_not() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(500).into_bytes();
        let packed = pack(&text, Compression::Zstd);
        assert_eq!(packed[0], TAG_ZSTD, "repetitive text should compress");
        assert!(packed.len() < text.len() / 2);
        assert_eq!(unpack(&packed).unwrap(), text);

        // Incompressible input must be stored as-is rather than grown by a wrapper.
        let mut rnd = vec![0u8; 64 * 1024];
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for b in rnd.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let packed = pack(&rnd, Compression::Zstd);
        assert_eq!(packed[0], TAG_STORED, "random data must not be kept compressed");
        assert_eq!(packed.len(), rnd.len() + 1);
        assert_eq!(unpack(&packed).unwrap(), rnd);
    }

    #[test]
    fn test_disabled_compression_is_pass_through() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(100);
        let packed = pack(&data, Compression::None);
        assert_eq!(packed[0], TAG_STORED);
        assert_eq!(unpack(&packed).unwrap(), data);
    }

    #[test]
    fn test_empty_payload_round_trips() {
        for mode in [Compression::None, Compression::Zstd] {
            let packed = pack(&[], mode);
            assert_eq!(unpack(&packed).unwrap(), Vec::<u8>::new(), "{:?}", mode);
        }
    }

    #[test]
    fn test_corrupt_envelopes_are_rejected() {
        assert!(unpack(&[]).is_err(), "empty payload");
        assert!(unpack(&[9]).is_err(), "unknown tag");
        assert!(unpack(&[TAG_ZSTD, 1, 2]).is_err(), "truncated length");
        assert!(unpack(&[TAG_ZSTD, 0, 0, 0, 1, 0xFF]).is_err(), "not a zstd frame");

        // A forged expansion length must be refused before it sizes an allocation.
        let mut bomb = vec![TAG_ZSTD];
        bomb.extend_from_slice(&u32::MAX.to_be_bytes());
        bomb.extend_from_slice(&[0u8; 8]);
        let err = unpack(&bomb).unwrap_err();
        assert!(err.to_string().contains("beyond the"), "unexpected: {}", err);
    }
}
