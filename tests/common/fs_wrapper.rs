use appendfs::InMemoryFS;
use appendfs::clock::{Clock, SystemClock};
use appendfs::crypto::VolumeKey;
use appendfs::log::recover_fs;
use appendfs::shim::{FileAttr, FileType};
use appendfs::storage::{FaultStorage, OsStorage, Storage};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Per-inode snapshot entry produced by `TestFS::get_tree_snapshot` - built entirely
/// from the same core handlers real FUSE dispatch uses (`getattr_core`, `list_dir_core`,
/// `readlink_core`, `read_core`), never by reading `fs.inodes` directly.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SnapshotNode {
    Directory {
        attr: FileAttr,
        entries: Vec<(String, u64)>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    File {
        attr: FileAttr,
        content: Vec<u8>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Symlink {
        attr: FileAttr,
        target: String,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Special {
        attr: FileAttr,
        xattrs: HashMap<String, Vec<u8>>,
    },
}

/// Builds the active `LogWriter`, routing it through `fault` when this instance was
/// created with fault injection so a test can fail its writes on demand.
fn make_writer(
    log_dir: &Path,
    fault: Option<&Arc<FaultStorage>>,
    generation: u64,
    clock: &dyn Clock,
    max_log_size: u64,
    start_tx: u64,
) -> Arc<appendfs::LogWriter> {
    let storage: Arc<dyn Storage> = match fault {
        Some(f) => Arc::clone(f) as Arc<dyn Storage>,
        None => Arc::new(OsStorage::new(log_dir)),
    };
    Arc::new(
        appendfs::LogWriter::create(
            storage,
            generation,
            clock,
            max_log_size,
            start_tx,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    )
}

#[allow(dead_code)]
pub struct TestFS {
    pub fs: InMemoryFS,
    pub log_dir: PathBuf,
    /// Present only for instances built by `new_temp_with_fault_injection`; the handle
    /// used to inject and clear log write failures. Survives remount/crash so faults can
    /// be injected repeatedly across a run.
    pub fault: Option<Arc<FaultStorage>>,
    pub _temp_dir: Option<Arc<tempfile::TempDir>>,
    pub remotes: Vec<Arc<appendfs::FailingRemoteStore>>,
    pub latency_remotes: Vec<Arc<appendfs::LatencyRemoteStore>>,
    pub memory_remotes: Vec<Arc<appendfs::MemoryRemoteStore>>,
    pub remote_registry: Option<Arc<RwLock<appendfs::RemoteRegistry>>>,
    pub block_cache: Option<Arc<dyn appendfs::BlockCache>>,
}

#[allow(dead_code)]
impl TestFS {
    pub fn new_temp(max_log_size: Option<u64>) -> Self {
        Self::new_temp_with_clock(max_log_size, Arc::new(SystemClock))
    }

    pub fn new_temp_with_clock(max_log_size: Option<u64>, clock: Arc<dyn Clock>) -> Self {
        Self::new_temp_inner(max_log_size, clock, false)
    }

    /// Like `new_temp_with_clock`, but routes all log I/O through a `FaultStorage`, so a
    /// test can make flushes fail at chosen moments via `self.fault`.
    pub fn new_temp_with_fault_injection(max_log_size: Option<u64>, clock: Arc<dyn Clock>) -> Self {
        Self::new_temp_inner(max_log_size, clock, true)
    }

    fn new_temp_inner(max_log_size: Option<u64>, clock: Arc<dyn Clock>, inject_faults: bool) -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        let fault = inject_faults.then(|| Arc::new(FaultStorage::new(Arc::new(OsStorage::new(&log_dir)))));
        let writer = make_writer(
            &log_dir,
            fault.as_ref(),
            1,
            &*clock,
            max_log_size.unwrap_or(appendfs::cli::DEFAULT_MAX_LOG_SIZE),
            1,
        );

        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        match fault.as_ref() {
            Some(f) => fs.set_storage(Arc::clone(f) as Arc<dyn Storage>),
            None => fs.set_log_dir(&log_dir),
        }

        // Export initial 000000.summary snapshot to initialize volume at clock.now()
        let snapshot = fs.snapshot_all();
        let manifest = fs.manifest.read().unwrap().clone();
        let storage = fs.log_writer.as_ref().unwrap().storage();
        let _ = appendfs::log::export_summary(
            &appendfs::log::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &fs.volume_header,
                generation: 0,
                last_tx_id: 0,
                next_inode: 2,
                created_at: clock.now(),
            },
            storage.as_ref(),
            &fs.volume_key,
        );

        Self {
            fs,
            log_dir,
            fault,
            _temp_dir: Some(Arc::new(temp_dir)),
            remotes: Vec::new(),
            latency_remotes: Vec::new(),
            memory_remotes: Vec::new(),
            remote_registry: None,
            block_cache: None,
        }
    }

    pub fn new_temp_with_remotes(max_log_size: Option<u64>, clock: Arc<dyn Clock>, num_remotes: usize) -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        let writer = make_writer(
            &log_dir,
            None,
            1,
            &*clock,
            max_log_size.unwrap_or(appendfs::cli::DEFAULT_MAX_LOG_SIZE),
            1,
        );

        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        fs.set_log_dir(&log_dir);

        // Export initial 000000.summary snapshot
        let snapshot = fs.snapshot_all();
        let manifest = fs.manifest.read().unwrap().clone();
        let storage = fs.log_writer.as_ref().unwrap().storage();
        let _ = appendfs::log::export_summary(
            &appendfs::log::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &fs.volume_header,
                generation: 0,
                last_tx_id: 0,
                next_inode: 2,
                created_at: clock.now(),
            },
            storage.as_ref(),
            &fs.volume_key,
        );

        let block_cache: Arc<dyn appendfs::BlockCache> = Arc::new(appendfs::MemoryBlockCache::new(50 * 1024 * 1024));

        let mut memory_remotes = Vec::new();
        let mut latency_remotes = Vec::new();
        let mut failing_remotes = Vec::new();
        let mut remote_read_targets = Vec::new();

        let mut registry = appendfs::RemoteRegistry::new();
        registry.policy.min_synced_remotes = 1;
        registry.policy.local_retention_secs = Some(0); // aggressive local eviction once verified
        registry.policy.max_log_age_secs = 3600;
        registry.policy.active_sync_interval_secs = 0;

        for i in 0..num_remotes {
            let name = format!("remote{}", i);
            let mem = Arc::new(appendfs::MemoryRemoteStore::new());
            let lat = Arc::new(appendfs::LatencyRemoteStore::new(mem.clone()));
            let failing = Arc::new(appendfs::FailingRemoteStore::new(lat.clone()));

            memory_remotes.push(mem);
            latency_remotes.push(lat);
            failing_remotes.push(failing.clone());

            let mut cfg = appendfs::RemoteTargetConfig::new(format!("bucket-{}", i));
            cfg.read_priority = 10 + i as u32;
            registry.add_remote(&name, cfg);
            registry.set_store_override(&name, failing.clone());

            remote_read_targets.push(appendfs::RemoteReadTarget {
                name,
                store: failing,
                priority: 10 + i as u32,
            });
        }

        let log_cache = Arc::new(appendfs::LogFileCache::with_remote_support(
            storage.clone(),
            Some(block_cache.clone()),
            remote_read_targets,
            Some(Arc::clone(&fs.manifest)),
        ));
        fs.log_cache = Some(log_cache);

        let registry_arc = Arc::new(RwLock::new(registry));
        fs.set_remote_registry(Arc::clone(&registry_arc));

        Self {
            fs,
            log_dir,
            fault: None,
            _temp_dir: Some(Arc::new(temp_dir)),
            remotes: failing_remotes,
            latency_remotes,
            memory_remotes,
            remote_registry: Some(registry_arc),
            block_cache: Some(block_cache),
        }
    }

    /// Triggers an immediate, synchronous remote replication cycle across all remotes.
    pub fn sync_remotes(&self) {
        if let Some(ref reg) = self.remote_registry {
            let mut last_part_sync = SystemTime::UNIX_EPOCH;
            let mut uploaded_parts = HashMap::new();
            let _ = appendfs::RemoteReplicationWorker::run_cycle(
                &self.fs,
                reg,
                &self.log_dir,
                &mut last_part_sync,
                &mut uploaded_parts,
            );
        }
    }

    pub fn from_instance(fs: InMemoryFS, log_dir: &Path, temp_dir: Option<Arc<tempfile::TempDir>>) -> Self {
        Self {
            fs,
            log_dir: log_dir.to_path_buf(),
            fault: None,
            _temp_dir: temp_dir,
            remotes: Vec::new(),
            latency_remotes: Vec::new(),
            memory_remotes: Vec::new(),
            remote_registry: None,
            block_cache: None,
        }
    }

    pub fn allocate_inode(&self) -> u64 {
        self.fs.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    pub fn mkdir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::dir::mkdir_core(&self.fs, parent, name, mode, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn create(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::read_write::create_core(&self.fs, parent, name, mode, 0, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, i32> {
        appendfs::operations::read_write::write_core(&self.fs, ino, buf, offset as i64)
    }

    pub fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, i32> {
        appendfs::operations::read_write::read_core(&self.fs, ino, len, offset as i64)
    }

    pub fn punch(&self, ino: u64, offset: u64, len: u64) -> Result<(), i32> {
        appendfs::operations::read_write::punch_hole_core(&self.fs, ino, offset, len)
    }

    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::links::unlink_core(&self.fs, parent, name)
    }

    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::dir::rmdir_core(&self.fs, parent, name)
    }

    pub fn symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, i32> {
        appendfs::operations::links::symlink_core(&self.fs, parent, name, target, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), i32> {
        appendfs::operations::links::link_core(&self.fs, ino, newparent, newname).map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), i32> {
        use appendfs::operations::read_write::{
            FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME, FUSE_SET_ATTR_SIZE,
            FUSE_SET_ATTR_UID, setattr_core,
        };

        let mut to_set = 0u32;
        if mode.is_some() {
            to_set |= FUSE_SET_ATTR_MODE;
        }
        if uid.is_some() {
            to_set |= FUSE_SET_ATTR_UID;
        }
        if gid.is_some() {
            to_set |= FUSE_SET_ATTR_GID;
        }
        if size.is_some() {
            to_set |= FUSE_SET_ATTR_SIZE;
        }
        if atime.is_some() {
            to_set |= FUSE_SET_ATTR_ATIME;
        }
        if mtime.is_some() {
            to_set |= FUSE_SET_ATTR_MTIME;
        }

        setattr_core(
            &self.fs,
            ino,
            mode.unwrap_or(0),
            uid.unwrap_or(0),
            gid.unwrap_or(0),
            size.unwrap_or(0) as i64,
            atime.unwrap_or(std::time::UNIX_EPOCH),
            mtime.unwrap_or(std::time::UNIX_EPOCH),
            to_set,
        )
        .map(|_| ())
    }

    pub fn readlink(&self, ino: u64) -> Result<String, i32> {
        appendfs::operations::links::readlink_core(&self.fs, ino)
    }

    pub fn rename(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
        appendfs::operations::links::rename_core(&self.fs, parent, name, newparent, newname)
    }

    pub fn opendir(&self, ino: u64) -> Result<u64, i32> {
        appendfs::operations::dir::opendir_core(&self.fs, ino, 0)
    }

    pub fn releasedir(&self, ino: u64, fh: u64) -> Result<(), i32> {
        appendfs::operations::dir::releasedir_core(&self.fs, ino, fh)
    }

    pub fn open(&self, ino: u64, flags: u32) -> Result<u64, i32> {
        appendfs::operations::read_write::open_core(&self.fs, ino, flags)
    }

    pub fn release(&self, ino: u64, fh: u64) -> Result<(), i32> {
        appendfs::operations::read_write::release_core(&self.fs, ino, fh)
    }

    pub fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
        appendfs::operations::xattr::setxattr_core(&self.fs, ino, name, value, flags)
    }

    /// Runs the real two-phase getxattr protocol (query size, then fetch with that
    /// size) rather than just requesting a large fixed buffer, so this exercises the
    /// same size/ERANGE path a real xattr syscall would.
    pub fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, i32> {
        use appendfs::operations::xattr::GetxattrResult;
        match appendfs::operations::xattr::getxattr_core(&self.fs, ino, name, 0)? {
            // A 0-length value is indistinguishable from "just tell me the size" at
            // size 0 - same ambiguity a real getxattr(2) caller has - so short-circuit
            // instead of re-querying with size 0 and hitting that same branch again.
            GetxattrResult::Size(0) => Ok(Vec::new()),
            GetxattrResult::Size(size) => {
                match appendfs::operations::xattr::getxattr_core(&self.fs, ino, name, size)? {
                    GetxattrResult::Data(data) => Ok(data),
                    GetxattrResult::Size(_) => unreachable!("size query answered with another size"),
                }
            }
            GetxattrResult::Data(_) => unreachable!("size-0 query returned data"),
        }
    }

    pub fn removexattr(&self, ino: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::xattr::removexattr_core(&self.fs, ino, name)
    }

    /// Same two-phase size-then-data protocol as `getxattr`; returns the decoded,
    /// null-separated attribute names.
    pub fn listxattr(&self, ino: u64) -> Result<Vec<String>, i32> {
        use appendfs::operations::xattr::ListxattrResult;
        let buf = match appendfs::operations::xattr::listxattr_core(&self.fs, ino, 0)? {
            // See the same-value comment in `getxattr` - size 0 has no second call to make.
            ListxattrResult::Size(0) => Vec::new(),
            ListxattrResult::Size(size) => match appendfs::operations::xattr::listxattr_core(&self.fs, ino, size)? {
                ListxattrResult::Data(data) => data,
                ListxattrResult::Size(_) => unreachable!("size query answered with another size"),
            },
            ListxattrResult::Data(data) => data,
        };
        Ok(buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect())
    }

    /// Resolves the full set of an inode's xattrs (name -> value) for snapshot
    /// comparison, via the same public getxattr/listxattr path a real caller would use.
    fn xattr_snapshot(&self, ino: u64) -> HashMap<String, Vec<u8>> {
        let names = self.listxattr(ino).unwrap_or_default();
        names
            .into_iter()
            .filter_map(|name| {
                let value = self.getxattr(ino, &name).ok()?;
                Some((name, value))
            })
            .collect()
    }

    pub fn get_tree_snapshot(&self) -> HashMap<u64, SnapshotNode> {
        let mut snapshot = HashMap::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(1u64);
        visited.insert(1u64);

        while let Some(ino) = queue.pop_front() {
            let attr = match appendfs::operations::read_write::getattr_core(&self.fs, ino) {
                Ok(attr) => attr,
                Err(_) => continue,
            };

            let xattrs = self.xattr_snapshot(ino);
            match attr.file_type {
                FileType::Directory => {
                    let mut entries = appendfs::operations::dir::list_dir_core(&self.fs, ino).unwrap_or_default();
                    entries.retain(|(_, child_ino)| *child_ino < 0xFFFF_FFFF_0000_0000);
                    for (_, child_ino) in &entries {
                        if visited.insert(*child_ino) {
                            queue.push_back(*child_ino);
                        }
                    }
                    snapshot.insert(ino, SnapshotNode::Directory { attr, entries, xattrs });
                }
                FileType::RegularFile => {
                    let content = self.read(ino, 0, attr.size as usize).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::File { attr, content, xattrs });
                }
                FileType::Symlink => {
                    let target = appendfs::operations::links::readlink_core(&self.fs, ino).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::Symlink { attr, target, xattrs });
                }
                FileType::NamedPipe | FileType::CharDevice | FileType::BlockDevice | FileType::Socket => {
                    snapshot.insert(ino, SnapshotNode::Special { attr, xattrs });
                }
            }
        }

        snapshot
    }

    /// Overrides the data-extent cap, so a test can exercise record chunking without having
    /// to write megabytes. Carried across `clean_remount` / `unclean_crash`.
    pub fn set_max_extent_size(&mut self, size: usize) {
        self.fs.max_extent_size = size;
    }

    pub fn clean_remount(self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        let clock = self.fs.clock.clone();
        let fault = self.fault.clone();
        let max_extent_size = self.fs.max_extent_size;
        let _ = self.fs.sync_and_export_summary();
        drop(self);
        let mut rec = Self::recover_into(&log_dir, temp_dir, clock, fault);
        rec.fs.max_extent_size = max_extent_size;
        rec
    }

    pub fn unclean_crash(mut self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        let clock = self.fs.clock.clone();
        let fault = self.fault.clone();
        let next_inode = self.fs.next_inode.load(Ordering::SeqCst);
        let max_extent_size = self.fs.max_extent_size;
        let _ = self.fs.sync_log();
        self.fs.log_writer = None;
        drop(self);
        let mut rec = Self::recover_into(&log_dir, temp_dir, clock, fault);
        rec.fs.max_extent_size = max_extent_size;
        rec.fs.next_inode.store(
            rec.fs.next_inode.load(Ordering::SeqCst).max(next_inode),
            Ordering::SeqCst,
        );
        rec
    }

    /// Replays `log_dir` into a fresh instance and opens the next generation for writing.
    /// Recovery itself always reads through the real OS filesystem - the log files on disk
    /// are real either way - while `fault`, when present, is carried over so the new
    /// instance can keep having its writes failed on demand.
    fn recover_into(
        log_dir: &Path,
        temp_dir: Option<Arc<tempfile::TempDir>>,
        clock: Arc<dyn Clock>,
        fault: Option<Arc<FaultStorage>>,
    ) -> Self {
        let storage: Arc<dyn Storage> = match fault.as_ref() {
            Some(f) => Arc::clone(f) as Arc<dyn Storage>,
            None => Arc::new(OsStorage::new(log_dir)),
        };
        let mut recovered = recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
        let start_tx = recovered.last_tx_id.load(Ordering::SeqCst) + 1;
        recovered.log_writer = Some(make_writer(
            log_dir,
            fault.as_ref(),
            next_gen,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
        ));
        match fault.as_ref() {
            Some(f) => recovered.set_storage(Arc::clone(f) as Arc<dyn Storage>),
            None => recovered.set_log_dir(log_dir),
        }
        Self {
            fs: recovered,
            log_dir: log_dir.to_path_buf(),
            fault,
            _temp_dir: temp_dir,
            remotes: Vec::new(),
            latency_remotes: Vec::new(),
            memory_remotes: Vec::new(),
            remote_registry: None,
            block_cache: None,
        }
    }
}
