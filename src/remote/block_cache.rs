use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// 1 MiB aligned block chunk size for remote over-fetching and on-disk caching.
pub const BLOCK_SIZE: u64 = 1024 * 1024;

/// Computes the block index for a given byte offset.
pub fn block_index(offset: u64) -> u64 {
    offset / BLOCK_SIZE
}

/// Computes the start byte offset of a block index.
pub fn block_start_offset(block_idx: u64) -> u64 {
    block_idx * BLOCK_SIZE
}

use std::sync::atomic::{AtomicUsize, Ordering};

/// Default in-memory decrypted record cache size (128 MiB).
pub const DEFAULT_DECRYPTED_CACHE_SIZE: usize = 128 * 1024 * 1024;

/// In-memory LRU cache storing decrypted record payloads to eliminate repeated AEAD decryptions,
/// bounded by total byte size.
#[derive(Debug)]
pub struct DecryptedRecordCache {
    max_bytes: AtomicUsize,
    entries: Mutex<DecryptedLruInner>,
}

#[derive(Debug)]
struct DecryptedLruInner {
    map: HashMap<(u64, u64), Arc<Vec<u8>>>,
    queue: VecDeque<(u64, u64)>,
    current_bytes: usize,
}

impl Default for DecryptedRecordCache {
    fn default() -> Self {
        Self::new(DEFAULT_DECRYPTED_CACHE_SIZE)
    }
}

impl DecryptedRecordCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes: AtomicUsize::new(max_bytes),
            entries: Mutex::new(DecryptedLruInner {
                map: HashMap::new(),
                queue: VecDeque::new(),
                current_bytes: 0,
            }),
        }
    }

    /// Maximum byte capacity of this cache.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes.load(Ordering::SeqCst)
    }

    /// Dynamically updates the maximum byte capacity, evicting oldest entries if necessary.
    pub fn set_max_bytes(&self, max_bytes: usize) {
        self.max_bytes.store(max_bytes, Ordering::SeqCst);
        let mut guard = self.entries.lock().unwrap();
        while guard.current_bytes > max_bytes && !guard.queue.is_empty() {
            if let Some(removed) = guard.queue.pop_front().and_then(|k| guard.map.remove(&k)) {
                guard.current_bytes = guard.current_bytes.saturating_sub(removed.len());
            }
        }
    }

    /// Current approximate byte memory consumed by cached payloads.
    pub fn current_bytes(&self) -> usize {
        self.entries.lock().unwrap().current_bytes
    }

    /// Number of cached record payloads.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().map.is_empty()
    }

    pub fn get(&self, generation: u64, record_log_offset: u64) -> Option<Arc<Vec<u8>>> {
        let mut guard = self.entries.lock().unwrap();
        if let Some(val) = guard.map.get(&(generation, record_log_offset)) {
            let res = Arc::clone(val);
            // Move key to back of queue (most recently used)
            if let Some(pos) = guard.queue.iter().position(|k| *k == (generation, record_log_offset)) {
                guard.queue.remove(pos);
                guard.queue.push_back((generation, record_log_offset));
            }
            Some(res)
        } else {
            None
        }
    }

    pub fn insert(&self, generation: u64, record_log_offset: u64, payload: Arc<Vec<u8>>) {
        let mut guard = self.entries.lock().unwrap();
        let key = (generation, record_log_offset);
        let new_len = payload.len();

        let max_b = self.max_bytes.load(Ordering::SeqCst);

        // If a single record exceeds max_bytes, don't cache it
        if new_len > max_b {
            return;
        }

        if let Some(old_len) = guard.map.get(&key).map(|p| p.len()) {
            guard.current_bytes = guard.current_bytes.saturating_sub(old_len) + new_len;
            guard.map.insert(key, payload);
            if let Some(pos) = guard.queue.iter().position(|k| *k == key) {
                guard.queue.remove(pos);
                guard.queue.push_back(key);
            }
            return;
        }

        while guard.current_bytes + new_len > max_b && !guard.queue.is_empty() {
            if let Some(removed) = guard.queue.pop_front().and_then(|k| guard.map.remove(&k)) {
                guard.current_bytes = guard.current_bytes.saturating_sub(removed.len());
            }
        }

        guard.current_bytes += new_len;
        guard.map.insert(key, payload);
        guard.queue.push_back(key);
    }

    pub fn clear(&self) {
        let mut guard = self.entries.lock().unwrap();
        guard.map.clear();
        guard.queue.clear();
        guard.current_bytes = 0;
    }
}

/// Persistent on-disk LRU block cache storing raw encrypted 1 MiB chunks in `<log_dir>/.cache/`.
#[derive(Debug)]
pub struct OnDiskBlockCache {
    cache_dir: PathBuf,
    max_bytes: u64,
    access_lock: Mutex<()>,
    coalescer: Arc<super::RemoteReadCoalescer>,
}

impl OnDiskBlockCache {
    pub fn new(cache_dir: impl AsRef<Path>, max_bytes: u64) -> io::Result<Self> {
        Self::with_coalescer(cache_dir, max_bytes, Arc::new(super::RemoteReadCoalescer::new()))
    }

    pub fn with_coalescer(
        cache_dir: impl AsRef<Path>,
        max_bytes: u64,
        coalescer: Arc<super::RemoteReadCoalescer>,
    ) -> io::Result<Self> {
        let p = cache_dir.as_ref().to_path_buf();
        fs::create_dir_all(&p)?;
        Ok(Self {
            cache_dir: p,
            max_bytes,
            access_lock: Mutex::new(()),
            coalescer,
        })
    }

    pub fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        &self.coalescer
    }

    fn block_path(&self, generation: u64, block_idx: u64) -> PathBuf {
        self.cache_dir.join(format!("{:06}_{:06}.bin", generation, block_idx))
    }

    pub fn read_block(&self, generation: u64, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        let path = self.block_path(generation, block_idx);
        if !path.exists() {
            return Ok(None);
        }

        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    pub fn write_block(&self, generation: u64, block_idx: u64, data: &[u8]) -> io::Result<()> {
        let _guard = self.access_lock.lock().unwrap();
        let target_path = self.block_path(generation, block_idx);
        let tmp_path = self
            .cache_dir
            .join(format!("{:06}_{:06}.tmp.{}", generation, block_idx, std::process::id()));

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(data)?;
            file.flush()?;
        }

        fs::rename(tmp_path, target_path)?;
        self.prune_if_needed()?;
        Ok(())
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        let mut entries = Vec::new();
        let mut total_size = 0u64;

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("bin")
                && let Ok(meta) = entry.metadata()
            {
                let len = meta.len();
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                total_size += len;
                entries.push((path, len, mtime));
            }
        }

        if total_size <= self.max_bytes {
            return Ok(());
        }

        // Sort oldest first
        entries.sort_by_key(|(_, _, mtime)| *mtime);

        for (path, len, _) in entries {
            if total_size <= self.max_bytes {
                break;
            }
            let _ = fs::remove_file(path);
            total_size = total_size.saturating_sub(len);
        }

        Ok(())
    }
}

/// Common interface for local 1 MiB raw block caches (on-disk or in-memory).
pub trait BlockCache: Send + Sync + std::fmt::Debug {
    /// Reads a 1 MiB block from cache if present.
    fn read_block(&self, generation: u64, block_idx: u64) -> io::Result<Option<Vec<u8>>>;
    /// Writes a 1 MiB block into cache, pruning oldest entries if capacity is exceeded.
    fn write_block(&self, generation: u64, block_idx: u64, data: &[u8]) -> io::Result<()>;
    /// Prunes excess cached blocks if capacity is exceeded.
    fn prune_if_needed(&self) -> io::Result<()>;
    /// Reference to the single-flight request coalescer associated with this block cache.
    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer>;
}

impl BlockCache for OnDiskBlockCache {
    fn read_block(&self, generation: u64, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        self.read_block(generation, block_idx)
    }

    fn write_block(&self, generation: u64, block_idx: u64, data: &[u8]) -> io::Result<()> {
        self.write_block(generation, block_idx, data)
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        self.prune_if_needed()
    }

    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        self.coalescer()
    }
}

/// In-memory LRU block cache storing raw encrypted 1 MiB chunks without touching local disk.
#[derive(Debug)]
pub struct MemoryBlockCache {
    entries: Mutex<HashMap<(u64, u64), Vec<u8>>>,
    max_bytes: usize,
    coalescer: Arc<super::RemoteReadCoalescer>,
}

impl MemoryBlockCache {
    pub fn new(max_bytes: usize) -> Self {
        Self::with_coalescer(max_bytes, Arc::new(super::RemoteReadCoalescer::new()))
    }

    pub fn with_coalescer(max_bytes: usize, coalescer: Arc<super::RemoteReadCoalescer>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_bytes,
            coalescer,
        }
    }
}

impl BlockCache for MemoryBlockCache {
    fn read_block(&self, generation: u64, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        let guard = self.entries.lock().unwrap();
        Ok(guard.get(&(generation, block_idx)).cloned())
    }

    fn write_block(&self, generation: u64, block_idx: u64, data: &[u8]) -> io::Result<()> {
        let mut guard = self.entries.lock().unwrap();
        guard.insert((generation, block_idx), data.to_vec());
        drop(guard);
        self.prune_if_needed()
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        let mut guard = self.entries.lock().unwrap();
        let mut current_bytes: usize = guard.values().map(|v| v.len()).sum();
        if current_bytes > self.max_bytes {
            let keys: Vec<(u64, u64)> = guard.keys().copied().collect();
            for k in keys {
                if current_bytes <= self.max_bytes {
                    break;
                }
                if let Some(removed) = guard.remove(&k) {
                    current_bytes = current_bytes.saturating_sub(removed.len());
                }
            }
        }
        Ok(())
    }

    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        &self.coalescer
    }
}

/// Unified two-tiered cache containing on-disk raw blocks and in-memory decrypted payloads.
#[derive(Debug)]
pub struct TieredCache {
    pub on_disk: OnDiskBlockCache,
    pub decrypted: DecryptedRecordCache,
}

impl TieredCache {
    pub fn new(cache_dir: impl AsRef<Path>, max_disk_bytes: u64, max_decrypted_bytes: usize) -> io::Result<Self> {
        let on_disk = OnDiskBlockCache::new(cache_dir, max_disk_bytes)?;
        let decrypted = DecryptedRecordCache::new(max_decrypted_bytes);
        Ok(Self { on_disk, decrypted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypted_lru_cache() {
        // 6 bytes limit: holds exactly two 3-byte records
        let cache = DecryptedRecordCache::new(6);
        assert!(cache.get(1, 100).is_none());
        assert_eq!(cache.current_bytes(), 0);

        cache.insert(1, 100, Arc::new(vec![1, 2, 3]));
        assert_eq!(cache.current_bytes(), 3);

        cache.insert(1, 200, Arc::new(vec![4, 5, 6]));
        assert_eq!(cache.current_bytes(), 6);

        assert_eq!(cache.get(1, 100).unwrap().as_slice(), &[1, 2, 3]);

        // Insert 3rd entry (3 bytes) evicts oldest (which is 200 because 100 was just accessed)
        cache.insert(1, 300, Arc::new(vec![7, 8, 9]));
        assert_eq!(cache.current_bytes(), 6);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 200).is_none());
        assert!(cache.get(1, 100).is_some());
        assert!(cache.get(1, 300).is_some());

        // Oversized payload (> 6 bytes) is rejected and not cached
        cache.insert(1, 400, Arc::new(vec![0u8; 10]));
        assert!(cache.get(1, 400).is_none());
        assert_eq!(cache.current_bytes(), 6);
    }

    #[test]
    fn test_decrypted_record_cache_dynamic_resizing() {
        let cache = DecryptedRecordCache::new(100);
        cache.insert(1, 1, Arc::new(vec![1; 30]));
        cache.insert(1, 2, Arc::new(vec![2; 30]));
        cache.insert(1, 3, Arc::new(vec![3; 30]));
        assert_eq!(cache.current_bytes(), 90);
        assert_eq!(cache.len(), 3);

        // Dynamically shrink limit to 50 bytes: must evict entry 1 and 2
        cache.set_max_bytes(50);
        assert_eq!(cache.max_bytes(), 50);
        assert!(cache.current_bytes() <= 50);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1, 1).is_none());
        assert!(cache.get(1, 2).is_none());
        assert!(cache.get(1, 3).is_some());
    }

    #[test]
    fn test_on_disk_block_cache_write_read_and_prune() {
        let dir = tempfile::tempdir().unwrap();
        let cache = OnDiskBlockCache::new(dir.path(), 2500).unwrap(); // max 2500 bytes

        assert_eq!(cache.read_block(1, 0).unwrap(), None);

        let data1 = vec![0xAA; 1000];
        cache.write_block(1, 0, &data1).unwrap();
        assert_eq!(cache.read_block(1, 0).unwrap().unwrap(), data1);

        let data2 = vec![0xBB; 1000];
        cache.write_block(1, 1, &data2).unwrap();

        // 3rd write causes prune
        let data3 = vec![0xCC; 1000];
        cache.write_block(1, 2, &data3).unwrap();

        // One of the older blocks was pruned to stay under 2500 bytes
        let remaining = [
            cache.read_block(1, 0).unwrap().is_some(),
            cache.read_block(1, 1).unwrap().is_some(),
            cache.read_block(1, 2).unwrap().is_some(),
        ];
        assert_eq!(remaining.iter().filter(|&&b| b).count(), 2);
    }

    #[test]
    fn test_memory_block_cache_write_read_and_prune() {
        let cache = MemoryBlockCache::new(2500);

        assert_eq!(cache.read_block(1, 0).unwrap(), None);

        let data1 = vec![0xAA; 1000];
        cache.write_block(1, 0, &data1).unwrap();
        assert_eq!(cache.read_block(1, 0).unwrap().unwrap(), data1);

        let data2 = vec![0xBB; 1000];
        cache.write_block(1, 1, &data2).unwrap();

        let data3 = vec![0xCC; 1000];
        cache.write_block(1, 2, &data3).unwrap();

        let remaining = [
            cache.read_block(1, 0).unwrap().is_some(),
            cache.read_block(1, 1).unwrap().is_some(),
            cache.read_block(1, 2).unwrap().is_some(),
        ];
        assert_eq!(remaining.iter().filter(|&&b| b).count(), 2);
    }
}
