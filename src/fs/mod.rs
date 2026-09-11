//! In-memory filesystem state and the LSM delta overlay.
//!
//! The overlay is layered `base` <- `flushing` <- `live`; see [`InMemoryFS`] for how the
//! three relate. This module holds the shared types and the struct itself, with the
//! behavior split across focused submodules:
//!
//! - [`layers`] - [`InodeLayerStack`], the race-free snapshot/fold abstraction every
//!   layered read goes through.
//! - [`handles`] - POSIX file and directory handle tracking.
//! - [`overlay`] - staging mutations into `live` and resolving reads across all layers.
//! - [`flush`] - freezing `live`, synthesizing log records, and folding batches into `base`.

pub mod arena;
mod flush;
pub mod flusher;
mod handles;
mod layers;
mod overlay;
pub mod virtual_files;

pub use crate::operations::locks::{FlockState, FlockWaiter, LockManager, RangeLock, RangeLockWaiter};
pub use arena::WriteArena;
pub use flusher::*;
pub use layers::{InodeLayerStack, ReadPlan, ReadSlice, ReadSliceSource};
pub use virtual_files::{VIRTUAL_INO_BASE, VirtualFileRegistry};

use crate::clock::{Clock, SystemClock};
use crate::log::{FlushMotivation, LogFileCache, LogManifest, LogWriter};
use crate::node::{EntryDelta, Node};
use crate::storage::Storage;
use crate::sync::{ActionGuard, ActionMutex, OpTag, PostUnlockQueue};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::SystemTime;

pub type DirSnapshot = Arc<Vec<(String, u64)>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirHandle {
    pub ino: u64,
    pub flags: u32,
    pub entries: DirSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileHandle {
    Regular { ino: u64, flags: u32 },
    Virtual { ino: u64, flags: u32, data: Arc<Vec<u8>> },
}

impl FileHandle {
    #[inline]
    pub fn ino(&self) -> u64 {
        match self {
            FileHandle::Regular { ino, .. } | FileHandle::Virtual { ino, .. } => *ino,
        }
    }

    #[inline]
    pub fn flags(&self) -> u32 {
        match self {
            FileHandle::Regular { flags, .. } | FileHandle::Virtual { flags, .. } => *flags,
        }
    }

    #[inline]
    pub fn is_regular(&self) -> bool {
        matches!(self, FileHandle::Regular { .. })
    }

    #[inline]
    pub fn is_virtual(&self) -> bool {
        matches!(self, FileHandle::Virtual { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handle {
    File(FileHandle),
    Directory(DirHandle),
}

impl Handle {
    #[inline]
    pub fn ino(&self) -> u64 {
        match self {
            Handle::File(f) => f.ino(),
            Handle::Directory(d) => d.ino,
        }
    }

    #[inline]
    pub fn flags(&self) -> u32 {
        match self {
            Handle::File(f) => f.flags(),
            Handle::Directory(d) => d.flags,
        }
    }

    #[inline]
    pub fn is_file(&self) -> bool {
        matches!(self, Handle::File(_))
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        matches!(self, Handle::Directory(_))
    }

    #[inline]
    pub fn as_file(&self) -> Option<&FileHandle> {
        match self {
            Handle::File(f) => Some(f),
            Handle::Directory(_) => None,
        }
    }

    #[inline]
    pub fn as_dir(&self) -> Option<&DirHandle> {
        match self {
            Handle::Directory(d) => Some(d),
            Handle::File(_) => None,
        }
    }
}

impl From<FileHandle> for Handle {
    #[inline]
    fn from(f: FileHandle) -> Self {
        Handle::File(f)
    }
}

impl From<DirHandle> for Handle {
    #[inline]
    fn from(d: DirHandle) -> Self {
        Handle::Directory(d)
    }
}

pub type HandleMap = HashMap<u64, Handle>;

pub type BatchCallback = Box<dyn FnOnce(std::io::Result<()>) + Send + 'static>;

struct BatchCompletionInner {
    result: Option<std::io::Result<()>>,
    callbacks: Vec<BatchCallback>,
}

/// Thread-safe synchronization handle allowing one or more waiters (via non-blocking callbacks,
/// blocking wait, or async wait) to be notified when a specific `FlushBatch` has been committed and synced to disk.
#[derive(Clone)]
pub struct BatchCompletion {
    state: Arc<(Mutex<BatchCompletionInner>, Condvar)>,
}

impl Default for BatchCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BatchCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_done = self.is_completed();
        f.debug_struct("BatchCompletion")
            .field("is_completed", &is_done)
            .finish()
    }
}

impl BatchCompletion {
    pub fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(BatchCompletionInner {
                    result: None,
                    callbacks: Vec::new(),
                }),
                Condvar::new(),
            )),
        }
    }

    /// Registers an asynchronous callback to be invoked when this batch completes.
    /// If the batch has already finished, the callback runs immediately.
    pub fn add_callback(&self, callback: BatchCallback) {
        let (lock, _) = &*self.state;
        let mut guard = lock.lock().unwrap();
        if let Some(ref res) = guard.result {
            let res_clone = match res {
                Ok(()) => Ok(()),
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            };
            drop(guard);
            callback(res_clone);
        } else {
            guard.callbacks.push(callback);
        }
    }

    /// Marks the batch as completed with `result`, running all registered callbacks and waking any waiters.
    pub fn complete(&self, result: std::io::Result<()>) {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().unwrap();
        assert!(guard.result.is_none(), "batch has already been completed");
        guard.result = Some(match &result {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        });
        let callbacks = std::mem::take(&mut guard.callbacks);
        drop(guard);
        for cb in callbacks {
            let res = match &result {
                Ok(()) => Ok(()),
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            };
            cb(res);
        }
        cvar.notify_all();
    }

    /// Asynchronously waits until the batch completes and yields its result.
    pub async fn wait(&self) -> std::io::Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.add_callback(Box::new(move |res| {
            let _ = tx.send(res);
        }));
        rx.await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Interrupted, "batch cancelled"))?
    }

    /// Synchronously blocks the calling thread until the batch completes and yields its result.
    pub fn wait_blocking(&self) -> std::io::Result<()> {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().unwrap();
        while guard.result.is_none() {
            guard = cvar.wait(guard).unwrap();
        }
        match guard.result.as_ref().unwrap() {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        }
    }

    /// Returns true if this batch has already completed.
    pub fn is_completed(&self) -> bool {
        self.state.0.lock().unwrap().result.is_some()
    }
}

/// An immutable frozen batch of mutations being written to the log, holding its
/// corresponding write arena chunk buffers and batch statistics.
#[derive(Debug, Clone)]
pub struct FlushBatch {
    pub id: u64,
    pub entries: HashMap<u64, EntryDelta>,
    pub arena: WriteArena,
    pub bytes: usize,
    pub ops: usize,
    pub completion: BatchCompletion,
    pub motivation: FlushMotivation,
    pub created_at: SystemTime,
}

impl FlushBatch {
    pub fn new(
        id: u64,
        entries: HashMap<u64, EntryDelta>,
        arena: WriteArena,
        bytes: usize,
        ops: usize,
        motivation: FlushMotivation,
        created_at: SystemTime,
    ) -> Self {
        assert!(!entries.is_empty(), "FlushBatch must contain at least one entry");
        Self {
            id,
            entries,
            arena,
            bytes,
            ops,
            completion: BatchCompletion::new(),
            motivation,
            created_at,
        }
    }
}

/// Consolidated mutable filesystem state protected by `InMemoryFS::inner`.
pub struct FsInner {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over generations.
    pub base: HashMap<u64, Arc<Node>>,
    /// Ordered queue of immutable frozen snapshots waiting to be written/flushed to disk.
    pub flushing: VecDeque<FlushBatch>,
    /// Monotonically increasing ID generator for flushing batches.
    pub next_batch_id: u64,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: HashMap<u64, EntryDelta>,
    /// Active write arena staging extent payload allocations for `live`.
    pub live_arena: WriteArena,
    /// Active open handles (regular files, virtual files, and directories) keyed by allocated handle ID (`fh`).
    pub handles: HandleMap,
    /// Open descriptor reference count per inode for fast POSIX unlinking checks.
    pub open_counts: HashMap<u64, u32>,
    /// Monotonically increasing file handle descriptor ID generator.
    pub next_fh: u64,
    /// Timestamp of the latest recovered operation / summary snapshot (if recovered).
    pub recovered_time: Option<SystemTime>,

    /// Dirty write data bytes currently staged in `live` / `live_arena`.
    pub staged_bytes: usize,
    /// Mutating operations currently staged in `live`.
    pub staged_ops: usize,
    /// Total data bytes across all frozen batches in `flushing`.
    pub flushing_bytes: usize,
    /// Total mutating operations across all frozen batches in `flushing`.
    pub flushing_ops: usize,
    /// Condition variable notified whenever capacity opens up in the `flushing` queue.
    pub capacity_cvar: Arc<Condvar>,
}

impl FsInner {
    /// Pops the committed batch from the front of the flushing queue, asserting its ID matches `batch.id`,
    /// and notifies `capacity_cvar` with lock held.
    pub fn pop_flushed_batch(&mut self, batch: &FlushBatch) -> FlushBatch {
        let front = self.flushing.front().expect("flushing queue must not be empty");
        assert_eq!(
            front.id, batch.id,
            "front of flushing queue must match committed batch ID"
        );
        let popped = self.flushing.pop_front().unwrap();
        self.flushing_bytes -= popped.bytes;
        self.flushing_ops -= popped.ops;
        self.capacity_cvar.notify_all();
        popped
    }

    /// Pops the batch from the front of the flushing queue if its ID matches `batch_id`,
    /// updating flushing capacity counters and notifying `capacity_cvar`.
    pub fn pop_front_batch(&mut self, batch_id: u64) -> Option<FlushBatch> {
        if let Some(front) = self.flushing.front() {
            assert_eq!(
                front.id, batch_id,
                "front of flushing queue must match committed batch ID"
            );
            let popped = self.flushing.pop_front().unwrap();
            self.flushing_bytes -= popped.bytes;
            self.flushing_ops -= popped.ops;
            self.capacity_cvar.notify_all();
            Some(popped)
        } else {
            None
        }
    }

    /// Records a mutation of `additional_bytes` and increments staged operation count by 1.
    pub fn record_mutation(&mut self, additional_bytes: usize) {
        self.staged_bytes += additional_bytes;
        self.staged_ops += 1;
    }

    /// Freezes `live` into the `flushing` queue with an explicit `FlushMotivation` and timestamp,
    /// provided that capacity bounds are not exceeded.
    pub fn freeze_live(
        &mut self,
        max_flush_queue_depth: usize,
        max_flush_queue_bytes: usize,
        max_flush_queue_ops: usize,
        motivation: FlushMotivation,
        now: SystemTime,
    ) -> bool {
        if self.flushing.len() >= max_flush_queue_depth
            || self.flushing_bytes >= max_flush_queue_bytes
            || self.flushing_ops >= max_flush_queue_ops
        {
            return false;
        }
        if !self.live.is_empty() {
            let entries = std::mem::take(&mut self.live);
            let chunk_size = self.live_arena.chunk_size;
            let arena = std::mem::replace(&mut self.live_arena, WriteArena::with_chunk_size(chunk_size));
            let bytes = self.staged_bytes;
            let ops = self.staged_ops;
            self.staged_bytes = 0;
            self.staged_ops = 0;
            self.flushing_bytes += bytes;
            self.flushing_ops += ops;
            let id = self.next_batch_id;
            self.next_batch_id += 1;
            self.flushing
                .push_back(FlushBatch::new(id, entries, arena, bytes, ops, motivation, now));
            true
        } else {
            false
        }
    }

    /// Directly applies a batch of delta records into `base` without requiring a `FlushBatch` wrapper.
    pub fn apply_base_deltas(&mut self, entries: HashMap<u64, EntryDelta>) {
        self.apply_base_deltas_ref(&entries);
    }

    /// Directly applies a borrowed map of delta records into `base`.
    pub fn apply_base_deltas_ref(&mut self, entries: &HashMap<u64, EntryDelta>) {
        for (&ino, entry) in entries {
            match entry {
                EntryDelta::Tombstone => {
                    self.base.remove(&ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = self.base.get(&ino).cloned() {
                        let mut node_clone = (*existing_arc).clone();
                        delta.apply_to_node(&mut node_clone);
                        self.base.insert(ino, Arc::new(node_clone));
                    } else {
                        self.base.insert(ino, Arc::new(delta.to_node()));
                    }
                }
            }
        }
    }

    /// Merges a flushed batch into `base`.
    pub fn fold_flushed_batch(&mut self, flushed: FlushBatch) {
        self.apply_base_deltas_ref(&flushed.entries);
    }
}

impl FsInner {
    #[inline]
    pub fn allocate_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        fh
    }

    #[inline]
    pub fn get_file_handle(&self, ino: u64, fh: u64) -> Result<&FileHandle, i32> {
        let handle = self.handles.get(&fh).ok_or(libc::EBADF)?;
        if handle.ino() != ino {
            return Err(libc::EBADF);
        }
        match handle {
            Handle::File(f) => Ok(f),
            Handle::Directory(_) => Err(libc::EISDIR),
        }
    }

    #[inline]
    pub fn validate_file_handle(&self, ino: u64, fh: u64) -> Result<(), i32> {
        self.get_file_handle(ino, fh).map(|_| ())
    }

    #[inline]
    pub fn validate_regular_handle(&self, ino: u64, fh: u64) -> Result<(), i32> {
        match self.get_file_handle(ino, fh)? {
            FileHandle::Regular { .. } => Ok(()),
            FileHandle::Virtual { .. } => Err(libc::EBADF),
        }
    }

    #[inline]
    pub fn get_dir_handle(&self, ino: u64, fh: u64) -> Result<&DirHandle, i32> {
        let handle = self.handles.get(&fh).ok_or(libc::EBADF)?;
        if handle.ino() != ino {
            return Err(libc::EBADF);
        }
        match handle {
            Handle::Directory(d) => Ok(d),
            Handle::File(_) => Err(libc::ENOTDIR),
        }
    }

    #[inline]
    pub fn insert_file_handle(&mut self, fh: u64, file_handle: FileHandle) {
        let ino = file_handle.ino();
        self.handles.insert(fh, Handle::File(file_handle));
        *self.open_counts.entry(ino).or_insert(0) += 1;
    }

    #[inline]
    pub fn insert_dir_handle(&mut self, fh: u64, dir_handle: DirHandle) {
        self.handles.insert(fh, Handle::Directory(dir_handle));
    }

    #[inline]
    pub fn handle_counts(&self) -> (usize, usize, usize) {
        let mut regular = 0;
        let mut virtual_count = 0;
        let mut dir = 0;
        for h in self.handles.values() {
            match h {
                Handle::File(FileHandle::Regular { .. }) => regular += 1,
                Handle::File(FileHandle::Virtual { .. }) => virtual_count += 1,
                Handle::Directory(_) => dir += 1,
            }
        }
        (regular, virtual_count, dir)
    }
}

/// An RAII guard for the consolidated filesystem state returned by [`InMemoryFS::lock_inner`].
///
/// Tracks whether mutations occurred during the guard's lifetime. When dropped, if a mutation
/// occurred and staged thresholds (`max_buffer_size` or `max_staged_ops`) were reached, attempts
/// to freeze `live` into `flushing` (subject to `max_flush_queue_depth`) and defers waking up the
/// flusher until after the mutex is unlocked.
pub struct FsInnerGuard<'a> {
    guard: ActionGuard<'a, FsInner>,
    fs: &'a InMemoryFS,
    mutation_occurred: bool,
}

impl<'a> FsInnerGuard<'a> {
    /// Records a mutation of `additional_bytes`, increments staged operation count by 1,
    /// and flags that a mutation occurred in this lock session.
    pub fn record_mutation(&mut self, additional_bytes: usize) {
        self.guard.record_mutation(additional_bytes);
        self.mutation_occurred = true;
    }

    /// Parks a task to be executed immediately after the mutex lock is released.
    pub fn defer(&mut self, task: impl FnOnce() + 'a) {
        self.guard.defer(task);
    }

    /// Registers a hook to run right before unlocking (with the lock still held).
    pub fn before_unlock(&mut self, hook: impl for<'q> FnOnce(&mut FsInner, &mut PostUnlockQueue<'q, 'a>) + 'a) {
        self.guard.before_unlock(hook);
    }

    /// Returns the operation tag associated with this guard.
    pub fn tag(&self) -> OpTag {
        self.guard.tag()
    }

    /// Overrides the operation tag associated with this guard.
    pub fn set_tag(&mut self, tag: OpTag) {
        self.guard.set_tag(tag);
    }

    /// Returns whether any mutation was recorded during this lock session.
    pub fn mutation_occurred(&self) -> bool {
        self.mutation_occurred
    }
}

impl<'a> Deref for FsInnerGuard<'a> {
    type Target = FsInner;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<'a> DerefMut for FsInnerGuard<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<'a> Drop for FsInnerGuard<'a> {
    fn drop(&mut self) {
        if self.mutation_occurred {
            let max_buffer_size = self.fs.max_buffer_size;
            let max_staged_ops = self.fs.max_staged_ops;
            let max_flush_queue_depth = self.fs.max_flush_queue_depth;
            let max_flush_queue_bytes = self.fs.max_flush_queue_bytes;
            let max_flush_queue_ops = self.fs.max_flush_queue_ops;
            if self.guard.staged_bytes >= max_buffer_size || self.guard.staged_ops >= max_staged_ops {
                let now = self.fs.clock.now();
                let froze = self.guard.freeze_live(
                    max_flush_queue_depth,
                    max_flush_queue_bytes,
                    max_flush_queue_ops,
                    FlushMotivation::Threshold,
                    now,
                );
                if froze || !self.guard.flushing.is_empty() {
                    let fs = self.fs;
                    self.guard.defer(move || {
                        fs.notify_flush_trigger(true);
                    });
                }
            }
        }
    }
}

pub struct InMemoryFS {
    /// Consolidated critical section protecting all in-memory metadata, layer overlay,
    /// file/dir handles, open counts, and write arena buffers.
    pub inner: ActionMutex<FsInner>,
    /// Independent whole-file BSD flock and POSIX byte-range record lock manager.
    pub locks: LockManager,
    /// Authoritative manifest of all active log generations and lineage.
    pub manifest: Arc<RwLock<LogManifest>>,
    pub next_inode: AtomicU64,
    pub last_tx_id: AtomicU64,
    pub clock: Arc<dyn Clock>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub log_cache: Option<Arc<LogFileCache>>,
    pub max_buffer_size: usize,
    pub max_staged_ops: usize,
    /// Largest payload written as a single data record. Bounds how much must be read and
    /// decrypted to serve a read of any byte within it - see `DEFAULT_MAX_EXTENT_SIZE`.
    pub max_extent_size: usize,
    /// Maximum frozen batches allowed to queue up before auto-freezing is bounded.
    pub max_flush_queue_depth: usize,
    /// Maximum total bytes across all frozen flush batches allowed to queue up before auto-freezing is bounded.
    pub max_flush_queue_bytes: usize,
    /// Maximum total mutating operations across all frozen flush batches allowed to queue up before auto-freezing is bounded.
    pub max_flush_queue_ops: usize,
    pub flush_interval: AtomicU64,
    pub flusher: Arc<Flusher>,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to true.
    pub track_atime: bool,
    /// When true, filesystem is mounted strictly read-only (EROFS).
    pub read_only: std::sync::atomic::AtomicBool,
    /// Active VolumeHeader holding unlocked Data Encryption Keys.
    pub volume_key: Arc<crate::crypto::VolumeKey>,
    /// Volume identity and key-check material, carried alongside the key it belongs to.
    ///
    /// Deliberately not part of `LogManifest`: the manifest describes log generation
    /// lineage, and folding volume identity into it meant every encrypted summary stored
    /// the header twice - once as the plaintext blob a reader actually consults, and again
    /// inside the encrypted manifest where nothing read it. Two copies of a
    /// security-relevant fact with nothing checking they agree is the shape of bug this
    /// module has already paid for.
    pub volume_header: crate::crypto::VolumeHeader,
    /// Dynamic virtual files registered in the filesystem root (`/`).
    pub(crate) virtual_files: Arc<virtual_files::VirtualFileRegistry>,
    /// Optional live RemoteRegistry instance for remote status reporting.
    pub remote_registry: RwLock<Option<Arc<RwLock<crate::remote::RemoteRegistry>>>>,
    /// Live telemetry counters and synchronization state across all remotes.
    pub replication_telemetry: Arc<RwLock<crate::remote::worker::ReplicationTelemetry>>,
    /// Threshold in bytes of committed log data before automatically exporting an intermediate .summary file on log roll (0 to disable).
    pub summary_interval_bytes: AtomicU64,
    /// Threshold in rolled generations before automatically exporting an intermediate .summary file on log roll (0 to disable).
    pub summary_interval_generations: AtomicU64,
    /// Cumulative data bytes flushed to the log since the last summary was exported.
    pub bytes_since_last_summary: AtomicU64,
    /// Number of generations rolled since the last summary was exported.
    pub generations_since_last_summary: AtomicU64,
    /// Generation number of the last exported summary file.
    pub last_summary_generation: AtomicU64,
    /// Condition variable and flag to immediately notify the background replication worker of new logs/summaries.
    pub replication_notifier: Arc<(Mutex<bool>, Condvar)>,
    /// Tracks in-flight asynchronous operations (e.g. cold reads, async fsyncs) to ensure safe unmount without use-after-free.
    pub async_tracker: Arc<crate::async_runtime::AsyncTracker>,
    /// Optional fixed IV for exported summary files (used for deterministic golden fixture generation and testing).
    pub deterministic_summary_iv: Option<[u8; 12]>,
}

impl InMemoryFS {
    pub fn set_max_extent_size(&mut self, size: usize) {
        self.max_extent_size = size;
    }

    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_log(clock, None)
    }

    pub fn with_clock_and_uids(clock: Arc<dyn Clock>, uid: u32, gid: u32) -> Self {
        let fs = Self::with_clock(clock.clone());
        let now = clock.now();
        if let Some(root) = fs.inner.lock(OpTag::Other).unwrap().base.get_mut(&1) {
            *root = Arc::new(Node::new_dir(1, 0o755, uid, gid, now));
        }
        fs
    }

    pub fn with_log(log_writer: Arc<LogWriter>) -> Self {
        Self::with_clock_and_log(Arc::new(SystemClock), Some(log_writer))
    }

    pub fn with_clock_and_log(clock: Arc<dyn Clock>, log_writer: Option<Arc<LogWriter>>) -> Self {
        let mut map = HashMap::new();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let now = clock.now();

        // Start with only the root directory (Inode 1), which is empty, nlink is 2 (parent entry and '.' link)
        map.insert(1, Arc::new(Node::new_dir(1, 0o755, uid, gid, now)));

        let log_cache = log_writer
            .as_ref()
            .map(|w| Arc::new(LogFileCache::with_storage(w.storage().clone())));

        // The writer owns the volume's volume_key; without one this is a plaintext volume.
        let volume_key = log_writer
            .as_ref()
            .map(|w| Arc::clone(w.volume_key()))
            .unwrap_or_else(|| Arc::new(crate::crypto::VolumeKey::plaintext()));

        let start_gen = log_writer.as_ref().map_or(1, |w| w.generation());
        let manifest = Arc::new(RwLock::new(LogManifest::new_with_time(start_gen, now)));

        let virtual_files = Arc::new(virtual_files::VirtualFileRegistry::new());

        let inner = FsInner {
            base: map,
            flushing: VecDeque::new(),
            next_batch_id: 1,
            live: HashMap::new(),
            live_arena: WriteArena::new(),
            handles: HashMap::new(),
            open_counts: HashMap::new(),
            next_fh: 1,
            recovered_time: None,
            staged_bytes: 0,
            staged_ops: 0,
            flushing_bytes: 0,
            flushing_ops: 0,
            capacity_cvar: Arc::new(Condvar::new()),
        };

        let inner = ActionMutex::new(inner);
        let next_inode = AtomicU64::new(2);
        let flush_interval = AtomicU64::new(0);
        let summary_interval_bytes = AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_BYTES);
        let summary_interval_generations = AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_GENERATIONS);
        let bytes_since_last_summary = AtomicU64::new(0);
        let generations_since_last_summary = AtomicU64::new(0);
        let last_summary_generation = AtomicU64::new(0);
        let replication_notifier = Arc::new((Mutex::new(false), Condvar::new()));

        let fs = Self {
            inner,
            locks: LockManager::new(),
            manifest,
            next_inode,
            last_tx_id: AtomicU64::new(0),
            clock,
            log_writer,
            log_cache,
            max_buffer_size: 128 * 1024 * 1024,
            max_staged_ops: crate::cli::DEFAULT_MAX_BUFFER_OPS,
            max_extent_size: crate::cli::DEFAULT_MAX_EXTENT_SIZE,
            max_flush_queue_depth: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_DEPTH,
            max_flush_queue_bytes: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_BYTES,
            max_flush_queue_ops: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_OPS,
            flush_interval,
            flusher: Arc::new(Flusher::new()),
            track_atime: true,
            read_only: std::sync::atomic::AtomicBool::new(false),
            volume_key,
            volume_header: crate::crypto::VolumeHeader::plaintext(),
            virtual_files,
            remote_registry: RwLock::new(None),
            replication_telemetry: Arc::new(RwLock::new(crate::remote::worker::ReplicationTelemetry::new())),
            summary_interval_bytes,
            summary_interval_generations,
            bytes_since_last_summary,
            generations_since_last_summary,
            last_summary_generation,
            replication_notifier,
            async_tracker: Arc::new(crate::async_runtime::AsyncTracker::new()),
            deterministic_summary_iv: None,
        };
        fs.register_runtime_status();
        fs
    }

    /// Acquires the inner filesystem lock associated with `tag`.
    ///
    /// When the returned guard is dropped, if mutations occurred and staged byte or op
    /// thresholds were reached, freezes the active `live` layer into `flushing` (if queue depth
    /// allows) and schedules a deferred post-unlock flush trigger.
    pub fn lock_inner(&self, tag: OpTag) -> FsInnerGuard<'_> {
        FsInnerGuard {
            guard: self.inner.lock(tag).unwrap(),
            fs: self,
            mutation_occurred: false,
        }
    }

    /// Executes `f` within the scope of the inner filesystem lock tagged with `tag`.
    ///
    /// The lock is released and any deferred post-unlock tasks (such as background
    /// flusher wakeups) are guaranteed to run immediately when `f` returns.
    pub fn with_inner<R>(&self, tag: OpTag, f: impl FnOnce(&mut FsInnerGuard<'_>) -> R) -> R {
        let mut guard = self.lock_inner(tag);
        f(&mut guard)
    }

    /// Acquires the filesystem inner lock with [`OpTag::Test`].
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn lock_inner_for_tests(&self) -> FsInnerGuard<'_> {
        self.lock_inner(OpTag::Test)
    }

    /// Acquires the filesystem inner lock with [`OpTag::Test`] and executes `f`.
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_inner_for_tests<R>(&self, f: impl FnOnce(&mut FsInnerGuard<'_>) -> R) -> R {
        self.with_inner(OpTag::Test, f)
    }

    /// Number of dirty bytes currently staged in the active `live` layer.
    pub fn staged_bytes(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().staged_bytes
    }

    /// Number of mutating operations currently staged in the active `live` layer.
    pub fn staged_ops(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().staged_ops
    }

    /// Total data bytes across all frozen batches waiting in `flushing`.
    pub fn flushing_bytes(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().flushing_bytes
    }

    /// Total operations across all frozen batches waiting in `flushing`.
    pub fn flushing_ops(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().flushing_ops
    }

    /// Total dirty bytes currently in memory (staged in `live` + queued in `flushing`).
    pub fn total_dirty_bytes(&self) -> usize {
        let inner = self.inner.lock(OpTag::Stats).unwrap();
        inner.staged_bytes + inner.flushing_bytes
    }

    /// Total dirty operations currently in memory (staged in `live` + queued in `flushing`).
    pub fn total_dirty_ops(&self) -> usize {
        let inner = self.inner.lock(OpTag::Stats).unwrap();
        inner.staged_ops + inner.flushing_ops
    }

    /// Attaches an active `LogWriter` to the filesystem instance, registering its active generation in the manifest.
    pub fn attach_log_writer(&mut self, writer: Arc<LogWriter>) {
        let generation = writer.generation();
        let now = self.clock.now();
        {
            let mut manifest = self.manifest.write().unwrap();
            if manifest.get_by_generation(generation).is_none() {
                manifest.record_roll(generation, now, crate::log::record::FILE_HEADER_SIZE as u64);
            }
        }
        self.log_writer = Some(writer);
    }

    /// Wakes up the background replication worker thread immediately.
    pub fn notify_replication(&self) {
        let (lock, cvar) = &*self.replication_notifier;
        let mut pending = lock.lock().unwrap();
        *pending = true;
        cvar.notify_all();
    }

    pub fn set_summary_intervals(&self, bytes: u64, generations: u64) {
        self.summary_interval_bytes.store(bytes, Ordering::SeqCst);
        self.summary_interval_generations.store(generations, Ordering::SeqCst);
    }

    pub fn set_remote_registry(&self, registry: Arc<RwLock<crate::remote::RemoteRegistry>>) {
        *self.remote_registry.write().unwrap() = Some(registry);
        self.register_remote_status();
    }

    pub fn register_remote_status(&self) {
        self.virtual_files
            .register(".remotes", crate::remote::worker::format_remotes_status);
    }

    pub fn register_runtime_status(&self) {
        self.virtual_files
            .register(".status", crate::stats::format_runtime_status);
    }

    /// Returns true if `ino` is a synthesized virtual file.
    pub fn is_virtual_ino(&self, ino: u64) -> bool {
        self.virtual_files.is_virtual_ino(ino)
    }

    /// Returns all registered root directory virtual entries `(name, ino)`.
    pub fn list_virtual_entries(&self) -> Vec<(String, u64)> {
        self.virtual_files.list_entries()
    }

    pub fn with_clock_and_storage(clock: Arc<dyn Clock>, storage: Arc<dyn Storage>) -> Self {
        let mut fs = Self::with_clock(clock);
        fs.set_storage(storage);
        fs
    }

    pub fn with_clock_storage_and_volume_key(
        clock: Arc<dyn Clock>,
        storage: Arc<dyn Storage>,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> Self {
        let mut fs = Self::with_clock(clock);
        fs.set_storage(storage);
        fs.volume_key = volume_key;
        fs
    }

    /// Sets the volume's header and key together, rejecting a pair that disagrees.
    ///
    /// The two are separate fields but describe one volume, and only agreeing values are
    /// coherent: the header is written to the summary in plaintext while the key encrypts
    /// its body, so a mismatched pair produces a snapshot that announces itself as
    /// unencrypted yet cannot be reopened by the key that wrote it.
    pub fn set_volume(
        &mut self,
        volume_header: crate::crypto::VolumeHeader,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> std::io::Result<()> {
        if volume_header.cipher != volume_key.cipher() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "volume header describes a {} volume but the key is for {}",
                    volume_header.cipher,
                    volume_key.cipher()
                ),
            ));
        }
        self.volume_header = volume_header;
        self.volume_key = volume_key;
        Ok(())
    }

    pub fn set_read_only(&self, ro: bool) {
        self.read_only.store(ro, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn recovered_time(&self) -> Option<SystemTime> {
        self.inner.lock(OpTag::Stats).unwrap().recovered_time
    }

    pub fn set_recovered_time(&self, time: Option<SystemTime>) {
        self.inner.lock(OpTag::Other).unwrap().recovered_time = time;
    }

    pub fn set_storage(&mut self, storage: Arc<dyn Storage>) {
        self.log_cache = Some(Arc::new(LogFileCache::with_storage(storage)));
    }

    pub fn set_log_dir(&mut self, log_dir: impl AsRef<Path>) {
        self.set_storage(Arc::new(crate::storage::OsStorage::new(log_dir)));
    }

    /// Increments the in-flight asynchronous operation count and returns an RAII guard.
    pub fn begin_async_op(&self) -> crate::async_runtime::AsyncOpGuard {
        self.async_tracker.begin()
    }

    /// Returns the number of currently tracked in-flight asynchronous operations.
    pub fn in_flight_async_ops(&self) -> usize {
        self.async_tracker.in_flight()
    }

    /// Blocks until all tracked asynchronous operations complete and drop their guards.
    pub fn drain_async_ops(&self) {
        self.async_tracker.drain();
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }
}

impl Drop for InMemoryFS {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.flusher.stop_background();
            if !self.is_read_only() {
                let _ = self.sync_and_export_summary();
            }
            self.destroy();
        }
    }
}

impl Default for InMemoryFS {
    fn default() -> Self {
        Self::new()
    }
}

pub fn find_parent_inode(fs: &InMemoryFS, child_ino: u64) -> Option<u64> {
    fs.get_parent_dir_inode(child_ino)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_inner_guard_mutation_tracking() {
        let fs = InMemoryFS::new();
        {
            let guard = fs.lock_inner_for_tests();
            assert!(!guard.mutation_occurred());
            assert_eq!(guard.staged_bytes, 0);
            assert_eq!(guard.staged_ops, 0);
        }
        {
            let mut guard = fs.lock_inner_for_tests();
            assert!(!guard.mutation_occurred());
            guard.record_mutation(128);
            assert!(guard.mutation_occurred());
            assert_eq!(guard.staged_bytes, 128);
            assert_eq!(guard.staged_ops, 1);
        }
        // After guard drops, staged bytes/ops persist on FsInner, but new guard starts with mutation_occurred = false
        {
            let guard = fs.lock_inner_for_tests();
            assert!(!guard.mutation_occurred());
            assert_eq!(guard.staged_bytes, 128);
            assert_eq!(guard.staged_ops, 1);
        }
    }

    #[test]
    fn test_fs_inner_guard_drop_auto_freeze_on_threshold() {
        let mut fs = InMemoryFS::new();
        fs.max_buffer_size = 50;
        fs.max_staged_ops = 5;
        fs.flusher.stop_background();

        let file = crate::operations::read_write::create_core(&fs, 1, "test.bin", 0o644, 0, 1000, 1000).unwrap();
        // File creation recorded name.len() = 8
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.staged_bytes(), 8);
        assert_eq!(fs.staged_ops(), 1);

        // Perform write below threshold (20 bytes: staged_bytes = 28, staged_ops = 2)
        crate::operations::read_write::write_core(&fs, file.ino, &[0xAA; 20], 0).unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.staged_bytes(), 28);
        assert_eq!(fs.staged_ops(), 2);

        // Perform write that crosses max_buffer_size (30 bytes: 28 + 30 = 58 >= 50)
        crate::operations::read_write::write_core(&fs, file.ino, &[0xBB; 30], 20).unwrap();
        // Guard drop during write_core should have auto-frozen live into flushing queue
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);
        assert_eq!(fs.flushing_bytes(), 58);
        assert_eq!(fs.flushing_ops(), 3);
    }
}
