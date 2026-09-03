use crate::remote::RemoteReadTarget;
use crate::remote::block_cache::{BLOCK_SIZE, OnDiskBlockCache};
use crate::storage::{Storage, StorageReader};
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::Arc;

/// A `StorageReader` backed by local storage, remote S3/NFS stores, and a local on-disk block cache.
///
/// For sealed log files, `TieredStorageReader` provides a unified read path:
/// 1. Checks `OnDiskBlockCache` first (`.cache/`).
/// 2. On miss, reads from `local_storage` (if the file is still present on local disk before purge)
///    and saves the 1 MiB block into `OnDiskBlockCache` (pre-warming the cache).
/// 3. If the local file has been purged, fetches 1 MiB blocks from remote stores and caches them.
///    Remotes are queried by priority (lower numbers first). Equal-priority remotes are load-balanced
///    pseudo-randomly but deterministically via a hash of `(filename, block_idx)`.
pub struct TieredStorageReader {
    pub generation: u64,
    pub filename: String,
    pub expected_len: u64,
    pub local_storage: Option<Arc<dyn Storage>>,
    pub remotes: Vec<RemoteReadTarget>,
    pub block_cache: Arc<OnDiskBlockCache>,
    pub coalescer: Arc<crate::remote::RemoteReadCoalescer>,
}

impl TieredStorageReader {
    pub fn new(
        generation: u64,
        filename: impl Into<String>,
        expected_len: u64,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        block_cache: Arc<OnDiskBlockCache>,
    ) -> Self {
        Self::with_local_storage(generation, filename, expected_len, None, remotes, block_cache)
    }

    pub fn with_local_storage(
        generation: u64,
        filename: impl Into<String>,
        expected_len: u64,
        local_storage: Option<Arc<dyn Storage>>,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        block_cache: Arc<OnDiskBlockCache>,
    ) -> Self {
        let mut remotes: Vec<RemoteReadTarget> = remotes.into_iter().map(Into::into).collect();
        remotes.sort_by(|a, b| (a.priority, &a.name).cmp(&(b.priority, &b.name)));
        let coalescer = Arc::clone(block_cache.coalescer());
        Self {
            generation,
            filename: filename.into(),
            expected_len,
            local_storage,
            remotes,
            block_cache,
            coalescer,
        }
    }

    pub fn with_coalescer(mut self, coalescer: Arc<crate::remote::RemoteReadCoalescer>) -> Self {
        self.coalescer = coalescer;
        self
    }

    fn fetch_block_from_remotes(&self, block_idx: u64) -> io::Result<Vec<u8>> {
        let block_start = block_idx * BLOCK_SIZE;
        if block_start >= self.expected_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("block start {} exceeds file length {}", block_start, self.expected_len),
            ));
        }

        let block_len = BLOCK_SIZE.min(self.expected_len - block_start);

        // 1. Check local storage first (Tier 0: local file still present before purge)
        if let Some(ref storage) = self.local_storage
            && let Ok(reader) = storage.open_reader(&self.filename)
        {
            let mut buf = vec![0u8; block_len as usize];
            if reader.read_exact_at(block_start, &mut buf).is_ok() {
                let _ = self.block_cache.write_block(self.generation, block_idx, &buf);
                return Ok(buf);
            }
        }

        let mut last_err = None;

        // 2. Query remotes by priority tier (lower priority number first).
        // Within an equal-priority tier, distribute traffic pseudo-randomly but
        // deterministically based on hash(filename, block_idx).
        let mut idx = 0;
        while idx < self.remotes.len() {
            let priority = self.remotes[idx].priority;
            let group_start = idx;
            while idx < self.remotes.len() && self.remotes[idx].priority == priority {
                idx += 1;
            }
            let group = &self.remotes[group_start..idx];

            let start_offset = if group.len() > 1 {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                self.filename.hash(&mut hasher);
                block_idx.hash(&mut hasher);
                (hasher.finish() as usize) % group.len()
            } else {
                0
            };

            for i in 0..group.len() {
                let candidate = &group[(start_offset + i) % group.len()];
                let mut buf = Vec::with_capacity(block_len as usize);
                match candidate
                    .store
                    .get_object_range(&self.filename, block_start, block_len, &mut buf)
                {
                    Ok(bytes_read) => {
                        if bytes_read == block_len {
                            // Successfully fetched block!
                            let _ = self.block_cache.write_block(self.generation, block_idx, &buf);
                            return Ok(buf);
                        }
                        last_err = Some(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "remote '{}' returned short range read ({} of {} bytes)",
                                candidate.name, bytes_read, block_len
                            ),
                        ));
                    }
                    Err(e) => {
                        log::warn!(
                            "Tiered read failed for {} (gen {}, block {}) on remote '{}': {}. Trying next remote...",
                            self.filename,
                            self.generation,
                            block_idx,
                            candidate.name,
                            e
                        );
                        last_err = Some(e);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("No remotes available to fetch block {} of {}", block_idx, self.filename),
            )
        }))
    }

    fn get_or_fetch_block(&self, block_idx: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Ok(Some(cached)) = self.block_cache.read_block(self.generation, block_idx) {
            return Ok(Arc::new(cached));
        }

        self.coalescer.coalesce((self.generation, block_idx), || {
            // Re-check block cache inside leader closure in case a preceding fetch just populated it
            if let Ok(Some(cached)) = self.block_cache.read_block(self.generation, block_idx) {
                return Ok(Arc::new(cached));
            }
            let data = self.fetch_block_from_remotes(block_idx)?;
            Ok(Arc::new(data))
        })
    }
}

impl StorageReader for TieredStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.expected_len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read_exact_at range [{}, {}) exceeds file length {}",
                    offset,
                    offset + buf.len() as u64,
                    self.expected_len
                ),
            ));
        }

        let mut buf_offset = 0;
        let mut current_file_offset = offset;
        let mut remaining = buf.len();

        while remaining > 0 {
            let block_idx = current_file_offset / BLOCK_SIZE;
            let offset_in_block = (current_file_offset % BLOCK_SIZE) as usize;
            let block_data = self.get_or_fetch_block(block_idx)?;

            let bytes_in_this_block = (block_data.len().saturating_sub(offset_in_block)).min(remaining);
            if bytes_in_this_block == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("short block read at block index {}", block_idx),
                ));
            }

            buf[buf_offset..buf_offset + bytes_in_this_block]
                .copy_from_slice(&block_data[offset_in_block..offset_in_block + bytes_in_this_block]);

            buf_offset += bytes_in_this_block;
            current_file_offset += bytes_in_this_block as u64;
            remaining -= bytes_in_this_block;
        }

        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.expected_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;
    use crate::remote::{CountingRemoteStore, RemoteStore};

    #[test]
    fn test_tiered_reader_with_block_cache_and_failover() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(OnDiskBlockCache::new(dir.path(), 50 * 1024 * 1024).unwrap());

        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let payload = vec![0x42u8; 2 * 1024 * 1024]; // 2 MiB file across 2 blocks
        remote2
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        // Remote 1 is empty; Remote 2 has the file
        let remotes: Vec<(String, Arc<dyn RemoteStore>)> =
            vec![("remote1".to_string(), remote1), ("remote2".to_string(), remote2)];

        let reader = TieredStorageReader::new(1, "000001.log", payload.len() as u64, remotes, cache.clone());
        assert_eq!(reader.len().unwrap(), 2 * 1024 * 1024);

        // Read 100 bytes from block 0
        let mut slice = [0u8; 100];
        reader.read_exact_at(500, &mut slice).unwrap();
        assert_eq!(slice, [0x42u8; 100]);

        // Block 0 is now cached on disk
        assert!(cache.read_block(1, 0).unwrap().is_some());
        assert!(cache.read_block(1, 1).unwrap().is_none());

        // Read spanning across block 0 and block 1 boundary
        let cross_offset = BLOCK_SIZE - 50;
        let mut cross_buf = [0u8; 100];
        reader.read_exact_at(cross_offset, &mut cross_buf).unwrap();
        assert_eq!(cross_buf, [0x42u8; 100]);

        // Block 1 is now also cached
        assert!(cache.read_block(1, 1).unwrap().is_some());
    }

    #[test]
    fn test_tiered_reader_with_local_storage_tier0() {
        use crate::storage::{MemoryStorage, WriteMode};

        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(OnDiskBlockCache::new(dir.path(), 50 * 1024 * 1024).unwrap());

        let memory_storage = Arc::new(MemoryStorage::new());
        let payload = vec![0x99u8; 1024 * 1024]; // 1 MiB block
        {
            let mut writer = memory_storage.open_writer("000001.log", WriteMode::CreateNew).unwrap();
            writer.append(&payload).unwrap();
            writer.sync().unwrap();
        }

        // Remotes list is EMPTY - data exists solely in local memory_storage!
        let remotes: Vec<(String, Arc<dyn RemoteStore>)> = Vec::new();
        let reader = TieredStorageReader::with_local_storage(
            1,
            "000001.log",
            payload.len() as u64,
            Some(memory_storage.clone()),
            remotes,
            cache.clone(),
        );

        assert!(cache.read_block(1, 0).unwrap().is_none());

        // Read from reader: should read from local storage AND write to block cache!
        let mut slice = [0u8; 64];
        reader.read_exact_at(128, &mut slice).unwrap();
        assert_eq!(slice, [0x99u8; 64]);

        // Block 0 MUST now be pre-warmed in on-disk block cache!
        assert!(cache.read_block(1, 0).unwrap().is_some());

        // Now drop/truncate the local file to simulate local log purging!
        memory_storage.remove_file("000001.log").unwrap();
        assert!(!memory_storage.exists("000001.log"));

        // Subsequent read MUST still succeed directly from block cache!
        let mut slice2 = [0u8; 64];
        reader.read_exact_at(256, &mut slice2).unwrap();
        assert_eq!(slice2, [0x99u8; 64]);
    }

    #[test]
    fn test_tiered_reader_equal_priority_deterministic_distribution() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(OnDiskBlockCache::new(dir.path(), 50 * 1024 * 1024).unwrap());

        let store_a = Arc::new(MockRemoteStore::new());
        let store_b = Arc::new(MockRemoteStore::new());

        let total_blocks = 8;
        let payload = vec![0x77u8; (total_blocks * BLOCK_SIZE) as usize];
        store_a
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();
        store_b
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        // Wrap in CountingRemoteStore to monitor per-remote traffic
        let counting_a = Arc::new(CountingRemoteStore::new(store_a.clone()));
        let counting_b = Arc::new(CountingRemoteStore::new(store_b.clone()));

        // Both stores have equal priority 100
        let remotes = vec![
            RemoteReadTarget::new("store_a", counting_a.clone(), 100),
            RemoteReadTarget::new("store_b", counting_b.clone(), 100),
        ];

        let reader = TieredStorageReader::new(1, "000001.log", payload.len() as u64, remotes, cache.clone());

        // Fetch each block individually
        for b in 0..total_blocks {
            let offset = b * BLOCK_SIZE + 10;
            let mut slice = [0u8; 32];
            reader.read_exact_at(offset, &mut slice).unwrap();
            assert_eq!(slice, [0x77u8; 32]);
        }

        let reads_a = counting_a.range_reads();
        let reads_b = counting_b.range_reads();

        // Total reads must equal total_blocks
        assert_eq!(reads_a + reads_b, total_blocks as usize);
        // Traffic must be distributed to BOTH stores, not all to one!
        assert!(reads_a > 0, "store_a must receive read traffic, got {}", reads_a);
        assert!(reads_b > 0, "store_b must receive read traffic, got {}", reads_b);
    }
}
