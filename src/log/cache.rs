use crate::log::record::{FILE_HEADER_SIZE, FileHeader};
use crate::storage::{OsStorage, Storage, StorageReader};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe cache holding open log file reader handles to eliminate repeated open calls.
pub struct LogFileCache {
    storage: Arc<dyn Storage>,
    cache: Mutex<HashMap<u64, Arc<dyn StorageReader>>>,
}

impl LogFileCache {
    pub fn new(log_dir: impl AsRef<Path>) -> Self {
        let storage = Arc::new(OsStorage::new(log_dir));
        Self::with_storage(storage)
    }

    pub fn with_storage(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieves an open log reader handle, verifying the `FileHeader` on first open.
    pub fn get_or_open(&self, generation: u64) -> io::Result<Arc<dyn StorageReader>> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(reader) = guard.get(&generation) {
            return Ok(Arc::clone(reader));
        }

        let filename = format!("{:06}.log", generation);
        let reader = self.storage.open_reader(&filename)?;

        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;

        FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        guard.insert(generation, Arc::clone(&reader));
        Ok(reader)
    }

    /// Reads a slice from an extent stored on disk, decrypting if necessary.
    pub fn read_extent_payload(
        &self,
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        slice_offset: u32,
        dst_buf: &mut [u8],
        volume_key: &crate::crypto::VolumeKey,
    ) -> io::Result<usize> {
        let reader = self.get_or_open(generation)?;
        let mut header_buf = [0u8; crate::log::record::RECORD_HEADER_SIZE];
        reader.read_exact_at(record_log_offset, &mut header_buf)?;
        let header = crate::log::record::RecordHeader::from_bytes(&header_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Whether to decrypt is a property of the volume, so it cannot be influenced by
        // anything read out of the record. Records used to carry a `key_id` that this branch
        // consulted, which let anyone able to write to the storage clear one byte and have
        // this copy raw ciphertext straight into a read buffer, bypassing the AEAD.
        if !volume_key.cipher().is_encrypted() {
            // Unencrypted fast-path: direct seek and read
            let seek_pos = record_log_offset
                + crate::log::record::RECORD_HEADER_SIZE as u64
                + payload_offset as u64
                + slice_offset as u64;
            reader.read_exact_at(seek_pos, dst_buf)?;
            return Ok(dst_buf.len());
        }

        // Encrypted path: read ciphertext payload, decrypt, copy slice
        let mut raw_payload = vec![0u8; header.payload_len as usize];
        reader.read_exact_at(
            record_log_offset + crate::log::record::RECORD_HEADER_SIZE as u64,
            &mut raw_payload,
        )?;

        let decrypted = volume_key
            .decrypt_record(
                generation,
                header.tx_id,
                header.op_code as u8,
                header.inode,
                &raw_payload,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Fill the whole request or fail. The unencrypted path above uses `read_exact_at`,
        // so it already errors on a short extent; returning a partial count here instead
        // left `copy_extent_data` with an unfilled tail that lower layers then rendered as
        // zeros - silently substituting plausible data for the `EIO` that a Disk extent
        // disagreeing with its record actually warrants.
        let start = payload_offset as u64 + slice_offset as u64;
        let slice = usize::try_from(start)
            .ok()
            .zip(
                start
                    .checked_add(dst_buf.len() as u64)
                    .and_then(|end| usize::try_from(end).ok()),
            )
            .and_then(|(start, end)| decrypted.get(start..end))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extent in generation {} at record offset {} wants {} bytes from payload offset {}, \
                         but that record decrypts to only {} bytes",
                        generation,
                        record_log_offset,
                        dst_buf.len(),
                        start,
                        decrypted.len()
                    ),
                )
            })?;

        dst_buf.copy_from_slice(slice);
        Ok(dst_buf.len())
    }

    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::log::writer::LogWriter;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_file_cache_open_and_verify() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        writer.sync().unwrap();

        let cache = LogFileCache::with_storage(storage);

        // First access opens and verifies header
        let file1 = cache.get_or_open(1).unwrap();

        // Second access returns cached handle
        let file2 = cache.get_or_open(1).unwrap();
        assert!(Arc::ptr_eq(&file1, &file2));
    }
}
