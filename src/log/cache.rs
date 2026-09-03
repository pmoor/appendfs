use crate::log::record::{FILE_HEADER_SIZE, FileHeader};
use crate::remote::RemoteReadTarget;
use crate::remote::block_cache::{DEFAULT_DECRYPTED_CACHE_SIZE, DecryptedRecordCache, OnDiskBlockCache};
use crate::remote::tiered_reader::TieredStorageReader;
use crate::storage::{OsStorage, Storage, StorageReader};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

/// Thread-safe cache holding open log file reader handles to eliminate repeated open calls,
/// with two-tiered caching (in-memory decrypted payload LRU + on-disk raw block cache)
/// and sparse remote reading.
#[allow(clippy::type_complexity)]
pub struct LogFileCache {
    storage: Arc<dyn Storage>,
    cache: Mutex<HashMap<u64, Arc<dyn StorageReader>>>,
    pub decrypted_cache: Arc<DecryptedRecordCache>,
    pub block_cache: Option<Arc<OnDiskBlockCache>>,
    pub remotes: Arc<RwLock<Vec<RemoteReadTarget>>>,
    pub manifest: Option<Arc<RwLock<crate::log::LogManifest>>>,
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
            decrypted_cache: Arc::new(DecryptedRecordCache::new(DEFAULT_DECRYPTED_CACHE_SIZE)),
            block_cache: None,
            remotes: Arc::new(RwLock::new(Vec::new())),
            manifest: None,
        }
    }

    pub fn with_remote_support(
        storage: Arc<dyn Storage>,
        block_cache: Option<Arc<OnDiskBlockCache>>,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        manifest: Option<Arc<RwLock<crate::log::LogManifest>>>,
    ) -> Self {
        Self {
            storage,
            cache: Mutex::new(HashMap::new()),
            decrypted_cache: Arc::new(DecryptedRecordCache::new(DEFAULT_DECRYPTED_CACHE_SIZE)),
            block_cache,
            remotes: Arc::new(RwLock::new(remotes.into_iter().map(Into::into).collect())),
            manifest,
        }
    }

    /// Sets the byte capacity for the in-memory decrypted record cache.
    pub fn set_decrypted_cache_size(&self, max_bytes: usize) {
        self.decrypted_cache.set_max_bytes(max_bytes);
    }

    /// Retrieves an open log reader handle, verifying the `FileHeader` on first open.
    /// If the log file was pruned locally, falls back to `TieredStorageReader` over S3 range requests.
    pub fn get_or_open(&self, generation: u64) -> io::Result<Arc<dyn StorageReader>> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(reader) = guard.get(&generation) {
            return Ok(Arc::clone(reader));
        }

        let filename = format!("{:06}.log", generation);

        let (is_sealed, mut expected_len) = if let Some(ref m) = self.manifest {
            let man = m.read().unwrap();
            let is_sealed = generation < man.next_generation - 1;
            let expected_len = man.get_by_generation(generation).map(|l| l.total_bytes).unwrap_or(0);
            (is_sealed, expected_len)
        } else {
            (false, 0)
        };

        // If expected_len is not yet in manifest but local file exists:
        if is_sealed
            && expected_len == 0
            && let Ok(r) = self.storage.open_reader(&filename)
            && let Ok(l) = r.len()
        {
            expected_len = l;
        }

        // If generation is sealed and block_cache is enabled, use the unified TieredStorageReader!
        // This checks OnDiskBlockCache first, falling back to local storage (Tier 0) to pre-warm the cache,
        // and falling back to remotes if the local file was purged.
        if let Some(ref bc) = self.block_cache
            && is_sealed
            && expected_len > 0
        {
            let remotes = self.remotes.read().unwrap().clone();
            let reader: Arc<dyn StorageReader> = Arc::new(TieredStorageReader::with_local_storage(
                generation,
                filename,
                expected_len,
                Some(self.storage.clone()),
                remotes,
                Arc::clone(bc),
            ));
            guard.insert(generation, Arc::clone(&reader));
            return Ok(reader);
        }

        let open_res = self.storage.open_reader(&filename);

        let reader: Arc<dyn StorageReader> = match open_res {
            Ok(r) => {
                let mut header_buf = [0u8; FILE_HEADER_SIZE];
                r.read_exact_at(0, &mut header_buf)?;
                FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                r
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let remotes = self.remotes.read().unwrap().clone();
                if remotes.is_empty() {
                    return Err(e);
                }

                let block_cache = match self.block_cache {
                    Some(ref bc) => Arc::clone(bc),
                    None => return Err(e),
                };

                Arc::new(TieredStorageReader::with_local_storage(
                    generation,
                    filename,
                    expected_len,
                    Some(self.storage.clone()),
                    remotes,
                    block_cache,
                ))
            }
            Err(e) => return Err(e),
        };

        guard.insert(generation, Arc::clone(&reader));
        Ok(reader)
    }

    /// Reads a slice from an extent stored on disk or fetched via S3 range requests.
    ///
    /// If the decrypted record payload is already present in the in-memory LRU cache,
    /// it is copied directly with ZERO disk I/O and ZERO decryption overhead.
    pub fn read_extent_payload(
        &self,
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        slice_offset: u32,
        dst_buf: &mut [u8],
        volume_key: &crate::crypto::VolumeKey,
    ) -> io::Result<usize> {
        let decrypted: Arc<Vec<u8>> = if let Some(cached) = self.decrypted_cache.get(generation, record_log_offset) {
            cached
        } else {
            let reader = self.get_or_open(generation)?;
            let mut header_buf = [0u8; crate::log::record::RECORD_HEADER_SIZE];
            reader.read_exact_at(record_log_offset, &mut header_buf)?;
            let header = crate::log::record::RecordHeader::from_bytes(&header_buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let mut raw_payload = vec![0u8; header.payload_len as usize];
            reader.read_exact_at(
                record_log_offset + crate::log::record::RECORD_HEADER_SIZE as u64,
                &mut raw_payload,
            )?;

            let dec = crate::log::codec::decode(
                volume_key,
                crate::log::codec::RecordId {
                    generation,
                    tx_id: header.tx_id,
                    op_code: header.op_code as u8,
                    inode: header.inode,
                },
                &raw_payload,
            )?;

            let arc_dec = Arc::new(dec);
            self.decrypted_cache
                .insert(generation, record_log_offset, Arc::clone(&arc_dec));
            arc_dec
        };

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
                         but that record holds only {} bytes",
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

    #[test]
    fn test_log_file_cache_decrypted_lru_hit() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let key = VolumeKey::plaintext_arc();
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            key.clone(),
        )
        .unwrap();

        let payload = b"cached extent data 123456789";
        let (_, gen_num, offset) = writer
            .append_record(crate::log::record::OpCode::Data, 10, payload)
            .unwrap();
        writer.sync().unwrap();

        let cache = LogFileCache::with_storage(storage);

        // First read populates in-memory decrypted cache
        let mut buf1 = [0u8; 6];
        cache
            .read_extent_payload(gen_num, offset, 0, 0, &mut buf1, &key)
            .unwrap();
        assert_eq!(&buf1, b"cached");

        // Verify entry is in decrypted cache
        assert!(cache.decrypted_cache.get(gen_num, offset).is_some());

        // Second read hits in-memory cache directly
        let mut buf2 = [0u8; 6];
        cache
            .read_extent_payload(gen_num, offset, 7, 0, &mut buf2, &key)
            .unwrap();
        assert_eq!(&buf2, b"extent");
    }
}
