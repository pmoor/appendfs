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
pub mod async_tracker;
pub mod delayed_queue;
mod flush;
mod flusher;
mod handles;
mod layers;
mod overlay;
pub mod virtual_files;

pub use crate::operations::locks::{FlockState, FlockWaiter, LockManager, RangeLock, RangeLockWaiter};
pub use crate::operations::op::{ALL_FUSE_OPS, FUSE_OP_COUNT, FuseOp, FuseOpMetrics, OpTier, ThrottleDecision};
pub use arena::WriteArena;
pub use async_tracker::{AsyncOpGuard, AsyncTracker};
pub use delayed_queue::DelayedResponseQueue;
pub use layers::{InodeLayerStack, ReadPlan, ReadSlice, ReadSliceSource};
pub use overlay::{InnerStatsSnapshot, InodeCounts};
pub use virtual_files::{VIRTUAL_INO_BASE, VirtualFileRegistry, is_virtual_ino};

use crate::clock::{Clock, SystemClock};
use crate::error::FsError;
use crate::log::{LogFileCache, LogManifest, LogWriter};
use crate::node::{EntryDelta, Node};
use crate::shim::{DeferredResult, FuseResponse, Request};
use crate::storage::Storage;
use crate::sync::{ActionGuard, ActionMutex, OpTag, PostUnlockQueue};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime};

pub type DirSnapshot = Arc<Vec<(String, u64)>>;

/// Where a filesystem sits in its shutdown lifecycle, stored on [`FsInner`] so every handler
/// observes it inside the same critical section that performs its mutation - closing the race
/// where a write could pass a pre-lock read-only check and land in `live` after a concurrent
/// `shutdown()` already believed everything was drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownState {
    /// Normal operation: reads and writes both proceed.
    #[default]
    Running,
    /// Mutating operations are rejected (`EROFS`); reads still proceed. Set at the start of
    /// `InMemoryFS::destroy()`, before `live`/`flushing` are drained.
    ReadOnly,
    /// Every operation, including reads, is rejected (`EIO`). Set once `live`/`flushing` have
    /// been fully drained and exported, immediately before the flusher thread is stopped.
    Stopped,
}

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

/// Thread-safe synchronization handle allowing one or more waiters (via non-blocking callbacks
/// or async wait) to be notified when a specific `FlushBatch` has been committed and synced to disk.
#[derive(Clone)]
pub struct BatchCompletion {
    state: Arc<Mutex<BatchCompletionInner>>,
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
            state: Arc::new(Mutex::new(BatchCompletionInner {
                result: None,
                callbacks: Vec::new(),
            })),
        }
    }

    /// Registers an asynchronous callback to be invoked when this batch completes.
    /// If the batch has already finished, the callback runs immediately.
    pub fn add_callback(&self, callback: BatchCallback) {
        let mut guard = self.state.lock().unwrap();
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

    /// Marks the batch as completed with `result`, running all registered callbacks.
    pub fn complete(&self, result: std::io::Result<()>) {
        let mut guard = self.state.lock().unwrap();
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
    }

    /// Blocks until the batch completes and yields its result.
    pub fn wait(&self) -> std::io::Result<()> {
        let signal = Arc::new((Mutex::new(None::<std::io::Result<()>>), Condvar::new()));
        let signal_clone = Arc::clone(&signal);
        self.add_callback(Box::new(move |res| {
            let (lock, cvar) = &*signal_clone;
            *lock.lock().unwrap() = Some(res);
            cvar.notify_all();
        }));

        let (lock, cvar) = &*signal;
        let mut guard = lock.lock().unwrap();
        loop {
            if let Some(res) = guard.take() {
                return res;
            }
            guard = cvar.wait(guard).unwrap();
        }
    }

    /// Returns true if this batch has already completed.
    pub fn is_completed(&self) -> bool {
        self.state.lock().unwrap().result.is_some()
    }
}

/// Why a batch was frozen out of `live`.
///
/// Decided by whoever asked for the freeze, carried on the batch through to completion, so
/// a flush can always account for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushReason {
    /// Explicit POSIX file sync (`fsync`).
    Fsync,
    /// Explicit POSIX directory sync (`fsyncdir`).
    Fsyncdir,
    /// An explicit sync point: `quiesce`, and through it unmount, summary export, and the
    /// one-shot CLI tools.
    Quiesce,
    /// The flusher's inactivity tick, with nobody waiting.
    Inactivity,
    /// Staged bytes or ops in `live` reached the configured flush thresholds.
    Threshold,
}

impl FlushReason {
    /// Every reason, in the order they are reported.
    pub const ALL: [FlushReason; 5] = [
        FlushReason::Fsync,
        FlushReason::Fsyncdir,
        FlushReason::Quiesce,
        FlushReason::Inactivity,
        FlushReason::Threshold,
    ];

    /// Position in [`FlushReason::ALL`], for indexing per-reason counters.
    pub fn index(&self) -> usize {
        match self {
            FlushReason::Fsync => 0,
            FlushReason::Fsyncdir => 1,
            FlushReason::Quiesce => 2,
            FlushReason::Inactivity => 3,
            FlushReason::Threshold => 4,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FlushReason::Fsync => "fsync",
            FlushReason::Fsyncdir => "fsyncdir",
            FlushReason::Quiesce => "quiesce",
            FlushReason::Inactivity => "inactivity",
            FlushReason::Threshold => "threshold",
        }
    }
}

impl fmt::Display for FlushReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `pad`, not `write_str`: the latter silently ignores width and alignment, which
        // quietly breaks any `{:<11}` this is formatted into.
        f.pad(self.as_str())
    }
}

/// How many recent flushes `.status` keeps. Enough to show a pattern, small enough that the
/// history costs nothing to hold or copy.
pub const FLUSH_HISTORY_CAPACITY: usize = 16;

/// What one completed flush cost.
///
/// Both come from the injected clock: `started_at` from `Clock::now`, and `duration` from
/// `Clock::monotonic`, which measures elapsed time without the backwards steps a wall clock
/// can take. A mocked clock therefore reports reproducible durations - zero for a fixed
/// clock, exactly what was advanced for an advancing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRecord {
    /// Identifier of the batch this records.
    pub id: u64,
    /// Why the batch was frozen.
    pub reason: FlushReason,
    /// Staged data bytes the batch carried.
    pub bytes: usize,
    /// Physical bytes appended to the log on disk (headers, deltas, data, and commit trailer).
    pub disk_bytes: u64,
    /// Mutating operations the batch carried.
    pub ops: usize,
    /// When the flusher picked the batch up.
    pub started_at: SystemTime,
    /// Time spent writing the batch's records to the log and syncing the file.
    ///
    /// Separated from `fold` because the two say different things when the flusher falls
    /// behind: this one is the storage device, `fold` is contention on the inner lock and
    /// the cost of applying deltas to `base`.
    pub persist: Duration,
    /// Time spent popping the batch and applying its deltas to `base`.
    pub fold: Duration,
    /// Total, end to end. Exceeds `persist + fold` by whatever the freeze and queue check
    /// at the head of the cycle cost.
    pub duration: Duration,
}

/// Point-in-time copy of the flusher's counters and its recent history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushStats {
    /// Whether a background thread is running cycles.
    pub background: bool,
    /// Inactivity interval, or `None` when only explicit wake-ups drive the flusher.
    pub interval: Option<Duration>,
    /// Batches completed since mount.
    pub total_batches: u64,
    /// Staged data bytes flushed since mount.
    pub total_bytes: u64,
    /// Physical log bytes flushed to disk since mount.
    pub total_disk_bytes: u64,
    /// Mutating operations flushed since mount.
    pub total_ops: u64,
    /// Cumulative time spent writing and syncing batches since mount.
    pub total_persist: Duration,
    /// Cumulative time spent folding batches into `base` since mount.
    pub total_fold: Duration,
    /// Batches completed per reason, indexed by [`FlushReason::index`].
    pub by_reason: [u64; 5],
    /// The most recent completions, oldest first, capped at [`FLUSH_HISTORY_CAPACITY`].
    pub recent: Vec<FlushRecord>,
}

impl FlushStats {
    /// Batches completed for `reason` since mount.
    pub fn count_for(&self, reason: FlushReason) -> u64 {
        self.by_reason[reason.index()]
    }
}

/// An immutable frozen batch of mutations being written to the log, holding its
/// corresponding write arena chunk buffers and batch statistics.
///
/// Deliberately not `Clone`, and shared as `Arc<FlushBatch>`: once `live` has been frozen
/// into one, nothing may change it. The flusher rewrites staged extents into disk extents on
/// a copy of `entries` alone, which it then folds into `base`, so a reader resolving against
/// the queue always sees the staged form until the batch is popped.
///
/// `arena` and the `Extent::Staged` handles inside `entries` are `Arc`s to the same buffers;
/// the field is what keeps those chunks alive for as long as the batch is queued.
#[derive(Debug)]
pub struct FlushBatch {
    pub id: u64,
    pub entries: HashMap<u64, EntryDelta>,
    pub arena: WriteArena,
    pub bytes: usize,
    pub ops: usize,
    pub completion: BatchCompletion,
    /// Why this batch was frozen.
    pub reason: FlushReason,
}

impl FlushBatch {
    /// `completion` comes from the `live` layer these entries were frozen out of, so anyone
    /// who registered interest while they were still live is carried into this batch.
    pub fn new(
        id: u64,
        entries: HashMap<u64, EntryDelta>,
        arena: WriteArena,
        bytes: usize,
        ops: usize,
        completion: BatchCompletion,
        reason: FlushReason,
    ) -> Self {
        assert!(!entries.is_empty(), "FlushBatch must contain at least one entry");
        Self {
            id,
            entries,
            arena,
            bytes,
            ops,
            completion,
            reason,
        }
    }
}

/// Consolidated mutable filesystem state protected by `InMemoryFS::inner`.
pub struct FsInner {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over generations.
    pub base: HashMap<u64, Arc<Node>>,
    /// Ordered queue of immutable frozen snapshots waiting to be written/flushed to disk.
    ///
    /// `Arc` so the flusher can take the front batch out of the critical section in constant
    /// time and copy what it needs without holding the lock.
    pub flushing: VecDeque<Arc<FlushBatch>>,
    /// Monotonically increasing ID generator for flushing batches.
    pub next_batch_id: u64,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: HashMap<u64, EntryDelta>,
    /// Active write arena staging extent payload allocations for `live`.
    pub live_arena: WriteArena,
    /// Completion handle for whatever is currently in `live`, travelling with the data when
    /// it is frozen. Lets a waiter register before the batch it will belong to exists.
    pub live_completion: BatchCompletion,
    /// Set when someone needs `live` flushed regardless of how little is staged, recording
    /// why. Taken by the freeze that honors it, which stamps the reason onto the batch.
    ///
    /// First request wins: a second one arriving before the freeze does not relabel a
    /// caller that has already been waiting.
    pub freeze_requested: Option<FlushReason>,
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
    /// Whole-file BSD flock and POSIX byte-range record lock manager.
    pub locks: LockManager,
    /// Current phase of the shutdown lifecycle; see [`ShutdownState`].
    pub shutdown_state: ShutdownState,
}

impl FsInner {
    /// Returns an error if the current shutdown phase should reject this operation.
    ///
    /// Pass `mutating = true` for anything that stages a change in `live` (writes, metadata
    /// updates, new lock grants); pass `false` for pure reads. Call this as the first statement
    /// inside the `with_inner`/`lock_inner` closure that performs the operation, not before
    /// acquiring the lock, so it observes the state atomically with the mutation it guards.
    pub fn check_shutdown(&self, mutating: bool) -> Result<(), FsError> {
        match self.shutdown_state {
            ShutdownState::Running => Ok(()),
            ShutdownState::ReadOnly => {
                if mutating {
                    Err(FsError::EROFS)
                } else {
                    Ok(())
                }
            }
            ShutdownState::Stopped => Err(FsError::EIO),
        }
    }
}

impl FsInner {
    /// Pops the committed batch from the front of the flushing queue, asserting its ID matches `batch.id`.
    pub fn pop_flushed_batch(&mut self, batch_id: u64) -> Arc<FlushBatch> {
        let front = self.flushing.front().expect("flushing queue must not be empty");
        assert_eq!(
            front.id, batch_id,
            "front of flushing queue must match committed batch ID"
        );
        let popped = self.flushing.pop_front().unwrap();
        self.flushing_bytes -= popped.bytes;
        self.flushing_ops -= popped.ops;
        popped
    }

    /// Pops the front batch from the flushing queue.
    #[cfg(any(test, feature = "testing"))]
    pub fn pop_flushing_batch(&mut self) -> Option<Arc<FlushBatch>> {
        let batch = self.flushing.pop_front()?;
        self.flushing_bytes -= batch.bytes;
        self.flushing_ops -= batch.ops;
        Some(batch)
    }

    /// Records a mutation of `additional_bytes` and increments staged operation count by 1.
    pub fn record_mutation(&mut self, additional_bytes: usize) {
        self.staged_bytes += additional_bytes;
        self.staged_ops += 1;
    }

    /// Whether the `flushing` queue has reached any of its depth, byte, or op limits.
    pub fn flushing_at_capacity(
        &self,
        max_flush_queue_depth: usize,
        max_flush_queue_bytes: usize,
        max_flush_queue_ops: usize,
    ) -> bool {
        self.flushing.len() >= max_flush_queue_depth
            || self.flushing_bytes >= max_flush_queue_bytes
            || self.flushing_ops >= max_flush_queue_ops
    }

    /// Freezes `live` into the `flushing` queue and transfers staged byte/op counts,
    /// provided that the `flushing` queue depth does not exceed `max_flush_queue_depth`,
    /// `flushing_bytes` does not exceed `max_flush_queue_bytes`, and
    /// `flushing_ops` does not exceed `max_flush_queue_ops`.
    ///
    /// If queue depth, byte count, or op count reaches or exceeds capacity, this is a no-op
    /// that preserves `live` and staged byte/op counters, returning `false`.
    /// Returns `true` if a batch was frozen, or `false` if `live` was empty or `flushing` was full.
    pub fn freeze_live(
        &mut self,
        max_flush_queue_depth: usize,
        max_flush_queue_bytes: usize,
        max_flush_queue_ops: usize,
    ) -> bool {
        if self.flushing_at_capacity(max_flush_queue_depth, max_flush_queue_bytes, max_flush_queue_ops) {
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
            // Whoever registered on `live` while these entries were staged now waits on the
            // batch that carries them; `live` starts over with a fresh handle.
            let completion = std::mem::take(&mut self.live_completion);
            // An outstanding request names this batch even when a threshold is what finally
            // tripped the freeze - the requester's data is in here either way.
            let reason = self.freeze_requested.take().unwrap_or(FlushReason::Threshold);
            self.flushing.push_back(Arc::new(FlushBatch::new(
                id, entries, arena, bytes, ops, completion, reason,
            )));
            true
        } else {
            false
        }
    }

    /// Merges a set of committed deltas into `base`.
    pub fn fold_entries(&mut self, entries: HashMap<u64, EntryDelta>) {
        for (ino, entry) in entries {
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
}

impl FsInner {
    #[inline]
    pub fn allocate_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        fh
    }

    #[inline]
    pub fn get_file_handle(&self, ino: u64, fh: u64) -> Result<&FileHandle, FsError> {
        let handle = self.handles.get(&fh).ok_or(FsError::EBADF)?;
        if handle.ino() != ino {
            return Err(FsError::EBADF);
        }
        match handle {
            Handle::File(f) => Ok(f),
            Handle::Directory(_) => Err(FsError::EISDIR),
        }
    }

    #[inline]
    pub fn validate_file_handle(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        self.get_file_handle(ino, fh).map(|_| ())
    }

    #[inline]
    pub fn validate_regular_handle(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        match self.get_file_handle(ino, fh)? {
            FileHandle::Regular { .. } => Ok(()),
            FileHandle::Virtual { .. } => Err(FsError::EBADF),
        }
    }

    #[inline]
    pub fn get_dir_handle(&self, ino: u64, fh: u64) -> Result<&DirHandle, FsError> {
        let handle = self.handles.get(&fh).ok_or(FsError::EBADF)?;
        if handle.ino() != ino {
            return Err(FsError::EBADF);
        }
        match handle {
            Handle::Directory(d) => Ok(d),
            Handle::File(_) => Err(FsError::ENOTDIR),
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
        if !self.mutation_occurred {
            return;
        }
        if self.fs.staged_threshold_reached(&self.guard) {
            let froze = self.fs.freeze_now_locked(&mut self.guard);
            if froze || !self.guard.flushing.is_empty() {
                let fs = self.fs;
                self.guard.defer(move || fs.wake_flusher());
            }
        }
        self.fs.sync_pushback_saturation(&self.guard);
    }
}

pub struct InMemoryFS {
    /// Consolidated critical section protecting all in-memory metadata, layer overlay,
    /// file/dir handles, open counts, write arena buffers, and lock manager state.
    pub inner: ActionMutex<FsInner>,
    /// Authoritative manifest of all active log generations and lineage.
    pub manifest: Arc<RwLock<LogManifest>>,
    pub next_inode: AtomicU64,
    pub last_batch_id: AtomicU64,
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
    /// Maximum number of small flush batches to coalesce into a single on-disk flush cycle.
    pub max_coalesce_batches: usize,
    /// Maximum cumulative staged data bytes across coalesced flush batches before forcing a disk flush.
    pub max_coalesce_bytes: usize,
    /// Maximum cumulative mutation operations across coalesced flush batches before forcing a disk flush.
    pub max_coalesce_ops: usize,
    /// Maximum data bytes for an individual flush batch to be eligible for coalescing.
    pub small_batch_max_bytes: usize,
    pub flush_interval: AtomicU64,
    pub(crate) flusher: flusher::Flusher,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to false.
    pub track_atime: bool,
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
    pub async_tracker: Arc<AsyncTracker>,
    /// Cumulative FUSE operation telemetry tracking calls and execution latency.
    pub op_metrics: Arc<FuseOpMetrics>,
    /// Asynchronous queue delaying FUSE responses during buffer saturation.
    pub delayed_queue: Arc<DelayedResponseQueue>,
    /// Optional fixed IV for exported summary files (used for deterministic golden fixture generation and testing).
    pub deterministic_summary_iv: Option<[u8; 12]>,
}

impl InMemoryFS {
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

        let manifest = Arc::new(RwLock::new(LogManifest::new()));

        let virtual_files = Arc::new(virtual_files::VirtualFileRegistry::new());
        let async_tracker = Arc::new(AsyncTracker::new());
        let op_metrics = Arc::new(FuseOpMetrics::new());
        let delayed_queue = Arc::new(DelayedResponseQueue::new(clock.clone(), op_metrics.clone()));

        let inner = FsInner {
            base: map,
            flushing: VecDeque::new(),
            next_batch_id: 1,
            live: HashMap::new(),
            live_arena: WriteArena::new(),
            live_completion: BatchCompletion::new(),
            freeze_requested: None,
            handles: HashMap::new(),
            open_counts: HashMap::new(),
            next_fh: 1,
            recovered_time: None,
            staged_bytes: 0,
            staged_ops: 0,
            flushing_bytes: 0,
            flushing_ops: 0,
            locks: LockManager::new(),
            shutdown_state: ShutdownState::Running,
        };

        let fs = Self {
            inner: ActionMutex::new(inner),
            manifest,
            next_inode: AtomicU64::new(2),
            last_batch_id: AtomicU64::new(0),
            clock,
            log_writer,
            log_cache,
            max_buffer_size: 128 * 1024 * 1024,
            max_staged_ops: crate::cli::DEFAULT_MAX_BUFFER_OPS,
            max_extent_size: crate::cli::DEFAULT_MAX_EXTENT_SIZE,
            max_flush_queue_depth: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_DEPTH,
            max_flush_queue_bytes: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_BYTES,
            max_flush_queue_ops: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_OPS,
            max_coalesce_batches: crate::cli::DEFAULT_MAX_COALESCE_BATCHES,
            max_coalesce_bytes: crate::cli::DEFAULT_MAX_COALESCE_BYTES,
            max_coalesce_ops: crate::cli::DEFAULT_MAX_COALESCE_OPS,
            small_batch_max_bytes: crate::cli::DEFAULT_SMALL_BATCH_MAX_BYTES,
            flush_interval: AtomicU64::new(0),
            flusher: flusher::Flusher::new(),
            track_atime: false,
            volume_key,
            volume_header: crate::crypto::VolumeHeader::plaintext(),
            virtual_files,
            remote_registry: RwLock::new(None),
            replication_telemetry: Arc::new(RwLock::new(crate::remote::worker::ReplicationTelemetry::new())),
            summary_interval_bytes: AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_BYTES),
            summary_interval_generations: AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_GENERATIONS),
            bytes_since_last_summary: AtomicU64::new(0),
            generations_since_last_summary: AtomicU64::new(0),
            last_summary_generation: AtomicU64::new(0),
            replication_notifier: Arc::new((Mutex::new(false), Condvar::new())),
            async_tracker,
            op_metrics,
            delayed_queue,
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

    /// Attaches an active `LogWriter` to the filesystem instance.
    ///
    /// # Panics
    ///
    /// Panics if the filesystem is in read-only mode or stopped.
    pub fn attach_log_writer(&mut self, writer: Arc<LogWriter>) {
        assert!(
            !self.is_read_only(),
            "cannot attach a log writer to a read-only filesystem"
        );
        self.log_writer = Some(writer);
    }

    /// Returns the sequence number for the next log generation to be allocated.
    ///
    /// Computed dynamically considering all sealed logs in the manifest, the generation
    /// of the latest summary snapshot, and the active log writer (if any). If the active
    /// log writer is open, the next generation is `active + 1`. If the writer is lazy
    /// (unopened), the next generation reflects the unopened generation waiting to be created.
    pub fn next_generation(&self) -> u64 {
        let manifest_max = self
            .manifest
            .read()
            .unwrap()
            .logs
            .iter()
            .map(|l| l.generation)
            .max()
            .unwrap_or(0);
        let summary_gen = self.last_summary_generation.load(Ordering::SeqCst);
        let base_next = manifest_max.max(summary_gen) + 1;
        match self.log_writer.as_ref() {
            Some(w) if w.is_open() => base_next.max(w.generation() + 1),
            Some(w) => base_next.max(w.generation()),
            None => base_next,
        }
    }

    /// Returns the physical filename for the next log generation (e.g. "000002.log").
    pub fn next_filename(&self) -> String {
        crate::log::log_filename(self.next_generation())
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

    /// Marks the filesystem read-only, rejecting every subsequent mutation with `EROFS`.
    ///
    /// One-way: [`ShutdownState`] only ever advances, so this never resurrects a filesystem
    /// that is already `Stopped`, and there is no way back to `Running`. Nothing needs to
    /// un-mark a read-only mount - a mount is read-only for its whole life - and allowing it
    /// would mean a filesystem could start accepting writes again midway through the shutdown
    /// sequence, after `destroy()` had already marked it read-only to drain it.
    ///
    /// Backed by the same `FsInner` state every handler checks inside its own critical
    /// section, rather than a standalone flag, so the transition cannot race a mutation.
    pub fn set_read_only(&self) {
        self.with_inner(OpTag::Other, |inner| {
            if inner.shutdown_state == ShutdownState::Running {
                inner.shutdown_state = ShutdownState::ReadOnly;
            }
        });
    }

    /// True once the filesystem is read-only or fully stopped.
    pub fn is_read_only(&self) -> bool {
        self.with_inner(OpTag::Other, |inner| inner.shutdown_state != ShutdownState::Running)
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
    pub fn begin_async_op(&self) -> AsyncOpGuard {
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

    /// Synchronizes the cached pushback saturation status and ratio in the delayed queue.
    pub(crate) fn sync_pushback_saturation(&self, inner: &FsInner) {
        let saturated = inner.flushing_at_capacity(
            self.max_flush_queue_depth,
            self.max_flush_queue_bytes,
            self.max_flush_queue_ops,
        );
        let ratio = if !saturated || self.max_buffer_size == 0 || self.max_staged_ops == 0 {
            0.0
        } else {
            let byte_ratio = inner.staged_bytes as f64 / self.max_buffer_size as f64;
            let op_ratio = inner.staged_ops as f64 / self.max_staged_ops as f64;
            byte_ratio.max(op_ratio)
        };
        self.delayed_queue.update_saturation(saturated, ratio);
    }

    /// Synchronizes the cached pushback saturation status and ratio atomics from current inner state.
    #[cfg(any(test, feature = "testing"))]
    pub fn refresh_pushback_saturation(&self) {
        let inner = self.inner.lock(OpTag::Stats).unwrap();
        self.sync_pushback_saturation(&inner);
    }

    /// Calculates the throttle decision for an operation tier using cached lock-free saturation state.
    #[cfg(any(test, feature = "testing"))]
    #[inline]
    pub fn calculate_throttle_for_tier(&self, tier: OpTier) -> ThrottleDecision {
        self.delayed_queue.tier_decision(tier)
    }

    /// Calculates the throttle decision for an incoming FUSE operation.
    #[inline]
    pub fn calculate_throttle(&self, op: FuseOp) -> ThrottleDecision {
        self.delayed_queue.tier_decision(op.tier())
    }

    /// Dispatches a FUSE response with declarative operation categorization, pushback throttling, and latency tracking.
    #[inline]
    pub fn dispatch_reply(
        &self,
        req: Request,
        op: FuseOp,
        res: impl Into<DeferredResult<FuseResponse<'static>>>,
        start: Duration,
    ) {
        self.op_metrics.record_call(op);
        let decision = self.calculate_throttle(op);

        let res = res.into();
        match res {
            DeferredResult::Ready(ready) => {
                let duration = self.clock.elapsed_since(start);
                self.op_metrics.record_duration(op, duration);
                self.delayed_queue.delay_response(op, decision, req, ready);
            }
            DeferredResult::Deferred(completion) => {
                let op_metrics = self.op_metrics.clone();
                let clock = self.clock.clone();
                let delayed_queue = self.delayed_queue.clone();
                completion.on_complete(Box::new(move |final_res| {
                    let duration = clock.elapsed_since(start);
                    op_metrics.record_duration(op, duration);
                    delayed_queue.delay_response(op, decision, req, final_res);
                }));
            }
        }
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }
}

impl Drop for InMemoryFS {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            // `destroy()` already drains `live`/`flushing` and exports the final summary as
            // part of its shutdown sequence; a second call here would just re-export an
            // unchanged summary. Idempotent against `destroy()` having already run via FUSE's
            // `destroy` callback - every step it takes checks `ShutdownState` first.
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
    fn test_flush_reason_display_honors_width() {
        // `.status` formats these into fixed-width columns. A `Display` impl written with
        // `write_str` compiles and reads fine but silently ignores the width, shifting every
        // column after it.
        assert_eq!(format!("{:<11}|", FlushReason::Fsync), "fsync      |");
        assert_eq!(format!("{:>11}|", FlushReason::Quiesce), "    quiesce|");
        assert_eq!(format!("{}", FlushReason::Inactivity), "inactivity");
    }

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

    #[test]
    fn test_track_atime_default_off_and_explicit_on() {
        let clock = Arc::new(crate::clock::AdvancingClock::new(crate::clock::unix_to_system_time(
            1_700_000_000,
            0,
        )));
        let fs = InMemoryFS::with_clock(clock.clone());
        assert!(!fs.track_atime, "track_atime should default to false");

        let file = crate::operations::read_write::create_core(&fs, 1, "atime_test.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file.ino, b"data", 0).unwrap();

        let initial_attr = fs.get_attr(file.ino).unwrap();
        assert_eq!(initial_attr.atime, crate::clock::unix_to_system_time(1_700_000_000, 0));

        // Advance clock and read with default track_atime = false
        clock.advance(Duration::from_secs(1000));
        let fh = crate::operations::read_write::open_core(&fs, file.ino, libc::O_RDONLY as u32).unwrap();
        let _ = crate::operations::read_write::read_core(&fs, file.ino, fh, 0, 4).unwrap();
        crate::operations::read_write::release_core(&fs, file.ino, fh).unwrap();

        let after_read_attr = fs.get_attr(file.ino).unwrap();
        assert_eq!(
            after_read_attr.atime, initial_attr.atime,
            "atime should not change on read when track_atime is false"
        );

        // Now test with track_atime = true
        let mut fs_with_atime = InMemoryFS::with_clock(clock.clone());
        fs_with_atime.track_atime = true;
        let file2 =
            crate::operations::read_write::create_core(&fs_with_atime, 1, "atime2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs_with_atime, file2.ino, b"data", 0).unwrap();

        clock.advance(Duration::from_secs(1000));
        let expected_time = clock.now();
        let fh2 = crate::operations::read_write::open_core(&fs_with_atime, file2.ino, libc::O_RDONLY as u32).unwrap();
        let _ = crate::operations::read_write::read_core(&fs_with_atime, file2.ino, fh2, 0, 4).unwrap();
        crate::operations::read_write::release_core(&fs_with_atime, file2.ino, fh2).unwrap();

        let attr_after_enabled_read = fs_with_atime.get_attr(file2.ino).unwrap();
        assert_eq!(
            attr_after_enabled_read.atime, expected_time,
            "atime should update on read when track_atime is true"
        );
    }
}
