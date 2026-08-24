//! The single path between a record payload in memory and the bytes stored for it.
//!
//! Compression and encryption are always applied together and in one order - compress, then
//! encrypt - so they are exposed as one operation rather than two steps a caller composes.
//! When they were separate, three read paths each had to remember to unwrap the compression
//! envelope after decrypting, and one of them (the keyless branch of `dump`) did not, quietly
//! reporting every payload shifted by a byte. Pairing them here removes the chance to perform
//! half of the transformation.

use crate::compress::Compression;
use crate::crypto::VolumeKey;
use std::io;

/// The fields that identify a record for authentication.
///
/// Exactly what gets bound into the AEAD's associated data, so a payload cannot be
/// relabelled as a different record type or reattributed to another inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordId {
    pub generation: u64,
    pub tx_id: u64,
    pub op_code: u8,
    pub inode: u64,
}

/// Turns a payload into the bytes written to the log.
pub fn encode(key: &VolumeKey, compression: Compression, id: RecordId, payload: &[u8]) -> io::Result<Vec<u8>> {
    // Compress first: ciphertext does not compress, and the resulting tag ends up inside the
    // encrypted region where it is authenticated.
    let packed = crate::compress::pack(payload, compression);
    key.encrypt_record(id.generation, id.tx_id, id.op_code, id.inode, &packed)
        .map_err(io::Error::from)
}

/// Recovers the original payload from bytes read out of the log.
pub fn decode(key: &VolumeKey, id: RecordId, stored: &[u8]) -> io::Result<Vec<u8>> {
    let plain = key
        .decrypt_record(id.generation, id.tx_id, id.op_code, id.inode, stored)
        .map_err(io::Error::from)?;
    crate::compress::unpack(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeySource, MasterKey, VolumeHeader};

    const ID: RecordId = RecordId {
        generation: 3,
        tx_id: 77,
        op_code: 1,
        inode: 42,
    };

    fn payload() -> Vec<u8> {
        "log line that repeats and repeats and repeats. "
            .repeat(200)
            .into_bytes()
    }

    #[test]
    fn test_round_trip_across_every_volume_shape() {
        let master = MasterKey::new([0x21u8; 32]);
        let data = payload();

        for compression in [Compression::None, Compression::Zstd] {
            // Unencrypted volume.
            let plain_key = VolumeKey::plaintext();
            let stored = encode(&plain_key, compression, ID, &data).unwrap();
            assert_eq!(
                decode(&plain_key, ID, &stored).unwrap(),
                data,
                "plaintext/{}",
                compression
            );

            // Encrypted volume.
            let (_h, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile, compression).unwrap();
            let stored = encode(&key, compression, ID, &data).unwrap();
            assert_ne!(stored, data, "encrypted/{} left the payload readable", compression);
            assert_eq!(decode(&key, ID, &stored).unwrap(), data, "encrypted/{}", compression);
        }
    }

    #[test]
    fn test_compression_shrinks_the_stored_bytes() {
        let key = VolumeKey::plaintext();
        let data = payload();
        let plain = encode(&key, Compression::None, ID, &data).unwrap();
        let squeezed = encode(&key, Compression::Zstd, ID, &data).unwrap();
        assert!(
            squeezed.len() * 4 < plain.len(),
            "expected a large saving on repetitive data: {} -> {}",
            plain.len(),
            squeezed.len()
        );
    }

    #[test]
    fn test_decode_rejects_a_reattributed_record() {
        let master = MasterKey::new([0x21u8; 32]);
        let (_h, key) = VolumeHeader::new_encrypted(&master, [0u8; 16], KeySource::KeyFile, Compression::Zstd).unwrap();
        let stored = encode(&key, Compression::Zstd, ID, &payload()).unwrap();

        // The identity is bound into the AAD, so an intact record cannot be moved onto
        // another inode or relabelled as another record type.
        let other_inode = RecordId {
            inode: ID.inode + 1,
            ..ID
        };
        assert!(decode(&key, other_inode, &stored).is_err());
        let other_op = RecordId {
            op_code: ID.op_code + 1,
            ..ID
        };
        assert!(decode(&key, other_op, &stored).is_err());
    }
}
