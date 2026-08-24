//! The encoding used for everything appendfs persists.
//!
//! Wraps bincode with one fixed configuration so that on-disk bytes are produced the same way
//! everywhere, and so the choice is stated in one place rather than implied by whichever
//! bincode entry point a call site happened to use.

use serde::{Deserialize, Serialize};

/// Big-endian, fixed-width integers.
///
/// Big-endian to match the hand-written framing in the log and summary formats, so a file
/// does not mix byte orders depending on whether a field went through bincode or through
/// `to_be_bytes`.
///
/// `with_fixint_encoding` is not optional here. Bincode's `DefaultOptions` uses varint
/// encoding, so asking only for big-endian would quietly change integer *widths* as well as
/// their order - a `SummaryHeader` shrinks from 28 bytes to 13, and becomes variable-length
/// depending on the values it holds. Readers seek past that header by a fixed
/// `SUMMARY_HEADER_SIZE`, so a variable-length header would misalign every byte after it.
/// Fixint reproduces exactly what plain `bincode::serialize` produced, byte order aside.
fn options() -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new().with_fixint_encoding().with_big_endian()
}

/// Serializes `value` in the on-disk encoding.
pub fn serialize<T: ?Sized + Serialize>(value: &T) -> bincode::Result<Vec<u8>> {
    use bincode::Options;
    options().serialize(value)
}

/// Deserializes `bytes` written by [`serialize`].
pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
    use bincode::Options;
    options().deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Sample {
        magic: [u8; 4],
        version: u32,
        generation: u64,
    }

    fn sample() -> Sample {
        Sample {
            magic: *b"APPS",
            version: 9,
            generation: 258,
        }
    }

    #[test]
    fn test_integers_are_big_endian() {
        let bytes = serialize(&sample()).unwrap();
        // `version` follows the 4 magic bytes; big-endian puts its most significant byte
        // first, so a small value reads as leading zeroes rather than trailing ones.
        assert_eq!(&bytes[4..8], &9u32.to_be_bytes());
        assert_eq!(&bytes[8..16], &258u64.to_be_bytes());
    }

    #[test]
    fn test_widths_match_fixed_size_encoding() {
        // Varint encoding would make this shorter, and variable with the values it holds.
        // Anything that seeks past a serialized struct by a constant depends on this.
        let small = serialize(&sample()).unwrap();
        let large = serialize(&Sample {
            magic: *b"APPS",
            version: u32::MAX,
            generation: u64::MAX,
        })
        .unwrap();

        assert_eq!(small.len(), 4 + 4 + 8);
        assert_eq!(small.len(), large.len(), "encoded size must not depend on the values");
    }

    #[test]
    fn test_round_trip() {
        let value = sample();
        assert_eq!(deserialize::<Sample>(&serialize(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn test_little_endian_bytes_do_not_silently_decode() {
        // A file written by the previous little-endian encoding must not read back as a
        // plausible value. It cannot be detected here - both are valid byte strings - so the
        // check is that the *values* differ, which is what the format version gate exists to
        // catch before it matters.
        let le = bincode::serialize(&sample()).unwrap();
        let decoded: Sample = deserialize(&le).unwrap();
        assert_ne!(decoded, sample(), "byte order change must alter decoded values");
    }
}
