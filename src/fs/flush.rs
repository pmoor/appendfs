//! Freezing `live`, writing delta log records, and folding batches into `base`.
//!
//! A flush freezes `live` into the `flushing` queue, writes pending data payloads and
//! serialized `LogEntryDelta` records directly to the active log file, and emits a
//! trailing `FlushCommit` confirming atomic persistence. Recovery replays `LogEntryDelta`
//! records directly onto `base`, guaranteeing identical state transitions across crash recovery.

use super::{AppendFs, FlushReason, FsInner, ShutdownState};
use crate::error::FsError;
use crate::extent_map::{Extent, ExtentMap, StagedBuffer};
use crate::log::{BatchStart, GenerationLiveStats, LogEntryDelta, LogFileInfo, LogWriter, OpCode};
use crate::node::{EntryDelta, NodeDelta};
use crate::operations::locks::LockManager;
use crate::storage::Storage;
use crate::sync::OpTag;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

struct PendingBatch {
    batch: Arc<super::FlushBatch>,
    entries: HashMap<u64, EntryDelta>,
    flushed_data_bytes: u64,
    disk_bytes: u64,
    started_at: SystemTime,
    started_monotonic: Duration,
    serialize_duration: Duration,
    serialize_end: Duration,
}

struct StagedSlice {
    data: StagedBuffer,
    payload_offset: u32,
    length: u32,
}

struct StagedRun {
    file_offset: u64,
    slices: Vec<StagedSlice>,
    total_len: usize,
}

/// Collects staged extents from a file's range map into coalesced runs of at most
/// `max_extent_size` bytes each. Contiguous extents are merged together and split across
/// record boundaries so each returned `StagedRun` can be written as a single log record.
fn collect_staged_runs(extents: &ExtentMap, max_extent_size: usize) -> Vec<StagedRun> {
    let mut runs: Vec<StagedRun> = Vec::new();
    let mut current_run: Option<StagedRun> = None;

    for (&offset, entry) in extents.iter() {
        if let Extent::Staged {
            ref data,
            payload_offset,
            length,
        } = entry.extent
        {
            let mut rem_len = length;
            let mut off = payload_offset;
            let mut file_off = offset;

            while rem_len > 0 {
                let can_append = match &current_run {
                    Some(run) => run.file_offset + run.total_len as u64 == file_off && run.total_len < max_extent_size,
                    None => false,
                };

                if can_append {
                    let run = current_run.as_mut().unwrap();
                    let take = std::cmp::min(rem_len as usize, max_extent_size - run.total_len) as u32;
                    run.slices.push(StagedSlice {
                        data: Arc::clone(data),
                        payload_offset: off,
                        length: take,
                    });
                    run.total_len += take as usize;
                    off += take;
                    rem_len -= take;
                    file_off += take as u64;

                    if run.total_len >= max_extent_size {
                        runs.push(current_run.take().unwrap());
                    }
                } else {
                    if let Some(run) = current_run.take() {
                        runs.push(run);
                    }
                    let take = std::cmp::min(rem_len as usize, max_extent_size) as u32;
                    let new_run = StagedRun {
                        file_offset: file_off,
                        slices: vec![StagedSlice {
                            data: Arc::clone(data),
                            payload_offset: off,
                            length: take,
                        }],
                        total_len: take as usize,
                    };
                    off += take;
                    rem_len -= take;
                    file_off += take as u64;

                    if new_run.total_len >= max_extent_size {
                        runs.push(new_run);
                    } else {
                        current_run = Some(new_run);
                    }
                }
            }
        } else if let Some(run) = current_run.take() {
            runs.push(run);
        }
    }

    if let Some(run) = current_run {
        runs.push(run);
    }

    runs
}

impl AppendFs {
    // --- Flush & Fold Pipelines ---

    /// Whether staged mutations in `live` have reached `max_buffer_size` or `max_staged_ops`.
    ///
    /// The sole definition of "`live` is due for a flush"; every automatic freeze consults it.
    pub(crate) fn staged_threshold_reached(&self, inner: &FsInner) -> bool {
        inner.staged_bytes >= self.max_buffer_size || inner.staged_ops >= self.max_staged_ops
    }

    /// Freezes `live` into the `flushing` queue, subject to the queue capacity limits.
    ///
    /// The sole entry point for moving mutations out of `live`: capacity policy lives here and
    /// nowhere else. Returns `true` if a batch was frozen.
    pub(crate) fn freeze_now_locked(&self, inner: &mut FsInner) -> bool {
        let froze = inner.freeze_live(
            self.max_flush_queue_depth,
            self.max_flush_queue_bytes,
            self.max_flush_queue_ops,
            self.clock.monotonic(),
            self.clock.now(),
        );
        if froze {
            self.sync_pushback_saturation(inner);
        }
        froze
    }

    /// Freezes `live` if someone asked for it, or if staged mutations have reached the flush
    /// thresholds.
    ///
    /// The flusher's whole freezing policy: a request covers an fsync, a `quiesce`, or the
    /// inactivity tick, and the threshold covers mutations that piled up while it was busy.
    pub(crate) fn freeze_if_due_locked(&self, inner: &mut FsInner) -> bool {
        (inner.freeze_requested.is_some() || self.staged_threshold_reached(inner)) && self.freeze_now_locked(inner)
    }

    /// Freezes `live` into the `flushing` queue, acquiring the inner lock.
    #[cfg(test)]
    pub(crate) fn freeze_now(&self) -> bool {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        self.freeze_now_locked(&mut inner)
    }

    /// Pops the front batch from the flushing queue, if any.
    #[cfg(any(test, feature = "testing"))]
    pub fn pop_flushing_batch(&self) -> Option<Arc<super::FlushBatch>> {
        let (batch, had_batch) = {
            let mut inner = self.inner.lock(OpTag::Flush).unwrap();
            let batch = inner.pop_flushing_batch();
            let had_batch = batch.is_some();
            if had_batch {
                self.sync_pushback_saturation(&inner);
            }
            (batch, had_batch)
        };
        if had_batch {
            self.delayed_queue.notify_capacity();
        }
        batch
    }

    /// Folds every queued batch straight into `base`, bypassing the log entirely.
    ///
    /// For tests that exercise layer resolution or queue accounting on a filesystem with no
    /// log writer, where `quiesce` has nothing to write to. Real flushing goes through
    /// `run_flush_cycle`, which folds a batch only once its records are on disk.
    #[cfg(any(test, feature = "testing"))]
    pub fn fold_flushing_into_base(&self) {
        let mut inner = self.inner.lock(OpTag::Fold).unwrap();
        while let Some(batch) = inner.pop_flushing_batch() {
            // Sole owner once popped, unless a reader is mid-resolve against it.
            let entries = match Arc::try_unwrap(batch) {
                Ok(batch) => batch.entries,
                Err(shared) => shared.entries.clone(),
            };
            inner.fold_entries(entries);
        }
        self.sync_pushback_saturation(&inner);
    }

    /// Returns the completion that fires once everything currently staged or queued is
    /// durable, or `None` if there is nothing pending.
    ///
    /// If `fh != 0`, the file handle is validated against `ino` under the same lock.
    ///
    /// The handle comes from the `live` layer itself, so a caller can register interest
    /// before the batch it will belong to exists. This tries to freeze `live` immediately so
    /// the data goes out without waiting on a threshold; if the flushing queue is at capacity
    /// the freeze is refused, `freeze_requested` stays set, and the flusher picks `live` up -
    /// along with this handle - as soon as it has made room.
    pub fn rollover_for_fsync(
        &self,
        ino: u64,
        fh: u64,
        reason: FlushReason,
    ) -> Result<Option<super::BatchCompletion>, FsError> {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        if fh != 0 {
            inner.validate_regular_handle(ino, fh)?;
        }
        if self.log_writer.is_none() {
            return Ok(None);
        }
        Ok(self.pending_completion_locked(&mut inner, reason))
    }

    /// Registers interest in everything currently staged or queued reaching disk, asking for
    /// `live` to be frozen even if it is below the flush thresholds.
    pub(crate) fn pending_completion_locked(
        &self,
        inner: &mut FsInner,
        reason: FlushReason,
    ) -> Option<super::BatchCompletion> {
        if !inner.live.is_empty() {
            let completion = inner.live_completion.clone();
            inner.freeze_requested.get_or_insert(reason);
            self.freeze_now_locked(inner);
            return Some(completion);
        }
        // Nothing live: the newest queued batch is the last thing that has to land.
        inner.flushing.back().map(|b| b.completion.clone())
    }

    /// Merges a flushed batch into `base`. Used by recovery to replay committed log records;
    /// during normal operation only the flusher folds.
    pub fn fold_entries(&self, entries: std::collections::HashMap<u64, EntryDelta>) {
        self.inner.lock(OpTag::Fold).unwrap().fold_entries(entries);
    }

    /// Rolls the active generation if it has reached `max_log_size` or `max_log_age`, and
    /// applies the effects of a roll: records the sealed generation in the manifest, exports a
    /// periodic summary if one is due, and tells replication there is new work.
    ///
    /// Also runs during the shutdown drain, so a large backlog is still split across
    /// generations; the successor is left lazy, so the drain never leaves an empty one behind.
    fn roll_log(&self, writer: &LogWriter) -> std::io::Result<()> {
        let Some(sealed_info) = writer.roll_if_needed()? else {
            return Ok(());
        };
        let sealed_gen = sealed_info.generation;
        self.manifest.write().unwrap().record_sealed_log(sealed_info);

        self.generations_since_last_summary.fetch_add(1, Ordering::SeqCst);

        let bytes_interval = self.summary_interval_bytes.load(Ordering::SeqCst);
        let gen_interval = self.summary_interval_generations.load(Ordering::SeqCst);
        let bytes_since = self.bytes_since_last_summary.load(Ordering::SeqCst);
        let gens_since = self.generations_since_last_summary.load(Ordering::SeqCst);

        let should_emit_summary =
            (bytes_interval > 0 && bytes_since >= bytes_interval) || (gen_interval > 0 && gens_since >= gen_interval);

        if should_emit_summary {
            let storage = writer.storage();
            let last_batch_id = writer.last_batch_id();
            match self.export_summary_for_base(storage.as_ref(), sealed_gen, last_batch_id) {
                Ok(_) => {
                    self.bytes_since_last_summary.store(0, Ordering::SeqCst);
                    self.generations_since_last_summary.store(0, Ordering::SeqCst);
                    self.last_summary_generation.store(sealed_gen, Ordering::SeqCst);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to export periodic summary for sealed generation {}: {}",
                        sealed_gen,
                        e
                    );
                }
            }
        }
        self.notify_replication();
        Ok(())
    }

    /// Writes pending data extents and serialized `LogEntryDelta` records for a frozen batch,
    /// followed by the `FlushCommit` trailer that makes the batch replayable.
    ///
    /// On any write error the entire batch is rolled back to its starting offset.
    /// Writes pending data extents and serialized `LogEntryDelta` records for a frozen batch,
    /// followed by the `FlushCommit` trailer that makes the batch replayable.
    ///
    /// On any write error the entire batch is rolled back to its starting offset.
    fn synthesize_and_write_flushing_layer(
        &self,
        frozen: &mut HashMap<u64, EntryDelta>,
        commit_timestamp: SystemTime,
        writer: &LogWriter,
    ) -> std::io::Result<(u64, u64)> {
        debug_assert!(self.flusher.in_cycle(), "only the flusher may write batches to the log");
        // Clamped because extent lengths are u32, and because a zero would make the
        // chunking loop below never advance.
        let max_extent_size = self.max_extent_size.clamp(1, u32::MAX as usize);

        let batch_checkpoint = writer.checkpoint();
        let batch_start = BatchStart {
            generation: batch_checkpoint.generation,
            offset: batch_checkpoint.offset,
        };

        let write_res = (|| -> std::io::Result<(u64, u64)> {
            let mut written_count = 0u32;
            let mut flushed_data_bytes = 0u64;

            let mut inos: Vec<u64> = frozen.keys().cloned().collect();
            inos.sort();

            // 1. Flush raw file data chunks
            // Note: Sparse holes (`Extent::Zero`) carry no payload bytes and do not emit
            // `OpCode::Data` records. They remain in `f.extents` and are serialized into the
            // log in step 2 below within `OpCode::InodeDelta` records as `LogExtent::Zero`
            // entries.
            for &ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::File(f))) = frozen.get_mut(&ino) {
                    let staged_runs = collect_staged_runs(&f.extents, max_extent_size);
                    for run in staged_runs {
                        let guards: Vec<_> = run.slices.iter().map(|s| s.data.read().unwrap()).collect();
                        let slice_refs: Vec<&[u8]> = run
                            .slices
                            .iter()
                            .zip(&guards)
                            .map(|(s, guard)| &guard[s.payload_offset as usize..(s.payload_offset + s.length) as usize])
                            .collect();

                        let (generation, record_log_offset, record_size) =
                            writer.append_data_slices(ino, &slice_refs, run.total_len)?;
                        written_count += 1;
                        flushed_data_bytes += run.total_len as u64;

                        let disk_extent =
                            Extent::new_disk(generation, record_log_offset, record_size, 0, run.total_len as u32);
                        f.extents.insert(run.file_offset, disk_extent);
                    }
                }
            }

            // 2. Flush Inode Delta records
            for &ino in &inos {
                if let Some(entry_delta) = frozen.get(&ino) {
                    let log_entry = LogEntryDelta::encode(entry_delta, batch_start);
                    writer.append_serialized(OpCode::InodeDelta, ino, &log_entry)?;
                    written_count += 1;
                }
            }

            // 3. Emit FlushCommit trailer (physical sync deferred to batch coalescing boundary)
            writer.emit_flush_commit(written_count, flushed_data_bytes, commit_timestamp)?;

            let active_offset = writer.current_offset();
            let disk_bytes = active_offset.saturating_sub(batch_checkpoint.offset);
            Ok((flushed_data_bytes, disk_bytes))
        })();

        match write_res {
            Ok(res) => Ok(res),
            Err(e) => {
                let _ = writer.rollback_to(&batch_checkpoint);
                Err(e)
            }
        }
    }

    /// Writes every queued flush batch to the log and folds it into `base`.
    ///
    /// The one authoritative flush body: nothing else writes batches to `LogWriter` or
    /// mutates `base`. The background thread calls this, or - in inline mode - whichever
    /// thread asked for a cycle. `Flusher::run_locked` keeps the two from overlapping.
    pub(crate) fn run_flush_cycle(&self) -> std::io::Result<()> {
        let Some(ref writer) = self.log_writer else {
            return Ok(());
        };
        self.flusher.run_locked(|| {
            loop {
                // Inspect candidates in the flush queue upfront in a single lock acquisition:
                // decide right here and then how many to coalesce without re-locking while writing to disk.
                let candidates = {
                    let mut inner = self.inner.lock(OpTag::Flush).unwrap();
                    self.freeze_if_due_locked(&mut inner);
                    if inner.flushing.is_empty() {
                        Vec::new()
                    } else {
                        let mut list = Vec::new();
                        let mut cumulative_bytes: usize = 0;
                        let mut cumulative_ops: usize = 0;

                        for (idx, b) in inner.flushing.iter().enumerate() {
                            assert!(!b.entries.is_empty(), "flushing batch must contain at least one entry");
                            if !list.is_empty()
                                && (list.len() >= self.max_coalesce_batches
                                    || b.bytes > self.small_batch_max_bytes
                                    || cumulative_bytes + b.bytes > self.max_coalesce_bytes
                                    || cumulative_ops + b.ops > self.max_coalesce_ops)
                            {
                                break;
                            }
                            cumulative_bytes += b.bytes;
                            cumulative_ops += b.ops;

                            let mut entries = b.entries.clone();
                            inner.normalize_directory_deltas(&mut entries, idx);
                            list.push((Arc::clone(b), entries));
                        }
                        list
                    }
                };

                if candidates.is_empty() {
                    break;
                }

                // Lazily open the active log file using the injected clock if unopened.
                writer.open_if_unopened()?;

                self.flush_coalesced_group(writer, candidates)?;

                // Rolled after the group is synced and its waiters released, so they never pay
                // for sealing a generation or exporting a summary. This makes `max_log_size` a
                // soft limit: the group that crosses it lands in full, and the roll follows.
                self.roll_log(writer)?;
            }

            // Checked again at the end of every cycle, including idle ones: with nothing
            // written, the check above never runs, and `max_log_age` would never come due.
            self.roll_log(writer)?;
            Ok(())
        })
    }

    /// Commits one group of coalesced candidate batches to the log file in FIFO order
    /// followed by a single physical sync (`writer.flush()`), then folds them into `base`.
    fn flush_coalesced_group(
        &self,
        writer: &LogWriter,
        candidates: Vec<(Arc<super::FlushBatch>, HashMap<u64, EntryDelta>)>,
    ) -> std::io::Result<()> {
        let group_checkpoint = writer.checkpoint();

        let mut coalesced: Vec<PendingBatch> = Vec::with_capacity(candidates.len());
        let mut serialize_result = Ok(());

        for (batch, mut entries) in candidates {
            let started_at = self.clock.now();
            let started_monotonic = self.clock.monotonic();
            match self.synthesize_and_write_flushing_layer(&mut entries, batch.commit_timestamp, writer) {
                Ok((flushed_data_bytes, disk_bytes)) => {
                    let serialize_end = self.clock.monotonic();
                    let serialize_duration = serialize_end.saturating_sub(started_monotonic);
                    coalesced.push(PendingBatch {
                        batch,
                        entries,
                        flushed_data_bytes,
                        disk_bytes,
                        started_at,
                        started_monotonic,
                        serialize_duration,
                        serialize_end,
                    });
                }
                Err(err) => {
                    // The failed batch has already rolled its own partial write back, so the
                    // log ends exactly after `coalesced`. Stop here; the failed batch and
                    // everything behind it stay queued for the next cycle.
                    serialize_result = Err(err);
                    break;
                }
            }
        }

        // Sync and complete whatever serialized cleanly - the whole group, or the prefix
        // ahead of a failed batch - then report the serialization failure, if any.
        if !coalesced.is_empty() {
            let sync_start = self.clock.monotonic();
            if let Err(e) = writer.flush() {
                // Nothing in the group is durable; unwind all of it so a retry does not
                // duplicate records.
                let _ = writer.rollback_to(&group_checkpoint);
                return serialize_result.and(Err(e));
            }
            let flush_duration = self.clock.monotonic().saturating_sub(sync_start);
            self.complete_coalesced_group(coalesced, sync_start, flush_duration);
        }
        serialize_result
    }

    /// Folds a durable group of batches into `base` and completes pending batch promises.
    fn complete_coalesced_group(&self, coalesced: Vec<PendingBatch>, sync_start: Duration, flush_duration: Duration) {
        let is_coalesced = coalesced.len() > 1;
        if is_coalesced {
            log::debug!(
                "Coalesced {} flush batches into single on-disk sync ({:?})",
                coalesced.len(),
                flush_duration
            );
        }

        // Notify batch waiters immediately once physical disk sync succeeds.
        // Waiters do not need to wait for folding into base to unblock.
        for p in &coalesced {
            p.batch.completion.complete(Ok(()));
        }

        let fold_records = {
            let mut inner = self.inner.lock(OpTag::Fold).unwrap();
            let mut records = Vec::with_capacity(coalesced.len());
            for p in coalesced {
                self.bytes_since_last_summary
                    .fetch_add(p.flushed_data_bytes, Ordering::SeqCst);
                let batch_fold_start = self.clock.monotonic();
                let popped = inner.pop_flushed_batch(p.batch.id);
                inner.fold_entries(p.entries);
                let batch_fold_end = self.clock.monotonic();
                let fold_duration = batch_fold_end.saturating_sub(batch_fold_start);

                let wait_duration = if is_coalesced {
                    sync_start.saturating_sub(p.serialize_end)
                } else {
                    Duration::ZERO
                };
                records.push((
                    popped,
                    p.disk_bytes,
                    p.started_at,
                    p.started_monotonic,
                    p.serialize_duration,
                    wait_duration,
                    fold_duration,
                ));
            }
            self.sync_pushback_saturation(&inner);
            records
        };

        let finished = self.clock.monotonic();

        for (popped, disk_bytes, started_at, started_monotonic, serialize, wait, fold) in fold_records {
            self.delayed_queue.notify_capacity();
            let record = super::FlushRecord {
                id: popped.id,
                reason: popped.reason,
                bytes: popped.bytes,
                disk_bytes,
                ops: popped.ops,
                started_at,
                queued: started_monotonic.saturating_sub(popped.frozen_at),
                serialize,
                wait,
                flush: flush_duration,
                fold,
                duration: finished.saturating_sub(popped.frozen_at),
            };
            log::debug!(
                "Flushed batch {} ({}): {} staged bytes ({} on disk), {} ops in {:?} ({:?} queued, {:?} serialize, {:?} wait, {:?} flush, {:?} fold)",
                record.id,
                record.reason,
                record.bytes,
                record.disk_bytes,
                record.ops,
                record.duration,
                record.queued,
                record.serialize,
                record.wait,
                record.flush,
                record.fold
            );
            self.flusher.record_flush(record);
        }
    }

    /// Asks for a flush cycle: wakes the background thread, or runs one here in inline mode.
    ///
    /// Returns without waiting for the cycle to finish. Callers that need the queue drained
    /// want [`AppendFs::quiesce`].
    pub(crate) fn wake_flusher(&self) {
        if self.flusher.is_background() {
            self.flusher.notify();
        } else if let Err(e) = self.run_flush_cycle() {
            log::error!("Inline flush cycle failed: {}", e);
        }
    }

    /// Returns once everything staged or queued when this was called is on disk and synced.
    ///
    /// Waiters are released as soon as the log file is synced, before the flusher folds the
    /// batch into `base`. With a background flusher, `base` may therefore still lag behind
    /// when this returns: read through the overlay stack (`live`, `flushing`, `base`), never
    /// `base` alone.
    pub fn quiesce(&self) -> std::io::Result<()> {
        if self.log_writer.is_none() {
            return Ok(());
        }

        // Taken before the cycle runs, so it names exactly what was outstanding at entry -
        // mutations arriving afterwards belong to a later batch and are not waited on.
        let pending = {
            let mut inner = self.inner.lock(OpTag::Flush).unwrap();
            self.pending_completion_locked(&mut inner, FlushReason::Quiesce)
        };
        let Some(pending) = pending else {
            return Ok(());
        };

        if self.flusher.is_background() {
            self.flusher.notify();
        } else {
            // Surfaces the failure directly rather than leaving us waiting on a batch the
            // cycle could not write.
            self.run_flush_cycle()?;
        }
        pending.wait()
    }

    /// Rolls the active log generation, draining pending batches first.
    pub fn force_roll_active_log(&self) -> std::io::Result<Option<LogFileInfo>> {
        let Some(ref writer) = self.log_writer else {
            return Ok(None);
        };
        self.quiesce()?;

        // Excludes the flusher for the roll itself. C3 moves age-based rolling into the
        // flusher's idle tick, at which point this exclusion goes away with it.
        self.flusher.run_locked(|| {
            let Some(sealed_info) = writer.force_roll()? else {
                return Ok(None);
            };
            self.manifest.write().unwrap().record_sealed_log(sealed_info.clone());
            self.notify_replication();
            Ok(Some(sealed_info))
        })
    }

    /// Flush counters and recent history, for `.status` and diagnostics.
    pub fn flush_stats(&self) -> super::FlushStats {
        self.flusher.stats()
    }

    /// Number of frozen batches currently waiting to be written to the log.
    #[cfg(any(test, feature = "testing"))]
    pub fn flush_queue_depth(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().flushing.len()
    }

    /// Finishes mounting in the process that will serve the mount: claims the volume lock and
    /// starts the background threads. An error fails the mount, before anything has started.
    ///
    /// This is the earliest point in that process: FUSE calls it from the session loop, after
    /// a background mount's `fuse_daemonize` has forked. `fork` carries only the calling
    /// thread into the daemon, so a thread started any earlier silently stops existing, and
    /// joining it at unmount hangs forever. The lock, taken before the fork so that a second
    /// mount is refused on the terminal, still records the parent's pid until now.
    pub fn init(self: &Arc<Self>) -> std::io::Result<()> {
        if let Some(ref writer) = self.log_writer {
            writer.record_lock_holder()?;
        }
        self.delayed_queue.start();
        self.enable_read_pool();
        if self.is_read_only() {
            return Ok(());
        }
        let secs = self.flush_interval.load(Ordering::SeqCst);
        self.flusher.start(self, (secs > 0).then(|| Duration::from_secs(secs)));

        let registry = self.remote_registry.read().unwrap().clone();
        if let Some(log_dir) = &self.replication_log_dir
            && let Some(registry) = registry
        {
            let mut worker = self.replication_worker.lock().unwrap();
            if worker.is_none() {
                log::info!(
                    "Starting background replication worker for {} remote(s)",
                    registry.read().unwrap().remotes.len()
                );
                *worker = Some(crate::remote::RemoteReplicationWorker::start(
                    Arc::clone(self),
                    registry,
                    log_dir.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Formal shutdown sequence, run once per filesystem lifetime (idempotent against repeat
    /// calls from FUSE's `destroy` callback and `Drop` both firing): read-only, drain `live`
    /// and `flushing` to a final durable summary, stop accepting all requests including reads,
    /// then drain whatever background/lock work remains and stop replication once it has
    /// pushed that summary.
    pub fn destroy(&self) {
        let Some(mounted_read_only) = self.with_inner(OpTag::Other, |inner| match inner.shutdown_state {
            // Shutdown already ran to completion: `Drop` calling in after FUSE's `destroy`
            // callback already did the work, or a second explicit call. Nothing left to do,
            // and re-running would re-export an unchanged summary and re-notify replication.
            ShutdownState::Stopped => None,
            // Otherwise the entry state says *why* the filesystem is read-only, which the
            // export below depends on: `ReadOnly` means it was mounted that way, `Running`
            // means this shutdown is what just made it so.
            entry_state => {
                inner.shutdown_state = ShutdownState::ReadOnly;
                Some(entry_state == ShutdownState::ReadOnly)
            }
        }) else {
            return;
        };

        // `stop()` joins the flusher thread, so once it returns the background thread has
        // exited and cannot pick up another cycle. Stopping it here, before the drain rather
        // than after, is what lets `quiesce()` below run the remaining work inline through
        // `run_flush_cycle()` itself (`is_background()` is now false) instead of waiting on a
        // thread that has already been told to exit. That in turn is what makes the drain
        // safe to do unconditionally, replacing the old behavior of failing queued
        // completions with `Interrupted`.
        self.flusher.stop();

        // Drains `live`/`flushing` and exports the final summary before anything is torn
        // down, so unmount never strands a write the way discarding queued completions used
        // to.
        //
        // Skipped entirely for a filesystem that was mounted read-only (`mount_ro_arc`), since
        // such a mount may be pointed at a historical recovery target (`--at-time` /
        // `--batch-id`). Exporting from one would publish that historical state as the
        // volume's newest summary, and a later recovery picking it up would roll the volume
        // back. A read-only mount has nothing staged to drain anyway.
        if !mounted_read_only {
            let _ = self.sync_and_export_summary();
        }

        self.with_inner(OpTag::Other, |inner| {
            inner.shutdown_state = ShutdownState::Stopped;
            LockManager::cancel_all_waiters(inner);
        });

        // Drain the delayed response queue before drain_async_ops(): stalls have no timeout.
        self.delayed_queue.drain();
        self.drain_async_ops();
        if let Some(pool) = self.read_pool.write().unwrap().take() {
            pool.shutdown();
        }

        // Last, so the worker's final cycle replicates the summary exported above. Taking it
        // out of `self` also releases the worker's `Arc` back to this filesystem.
        let worker = self.replication_worker.lock().unwrap().take();
        if let Some(mut worker) = worker {
            worker.stop();
        }
    }

    /// Dynamically calculates live extent statistics across all active files and log generations.
    pub fn calculate_generation_live_stats(&self) -> Vec<GenerationLiveStats> {
        let manifest = self.manifest.read().unwrap().clone();
        let inner = self.inner.lock(OpTag::Stats).unwrap();
        crate::stats::calculate_generation_live_stats_from_nodes(inner.base.values().map(|a| a.as_ref()), &manifest)
    }

    /// Exports a single-file summary snapshot of the current in-memory filesystem state to `storage`.
    pub fn export_summary(&self, storage: &dyn Storage) -> std::io::Result<String> {
        self.export_summary_with_iv(storage, None)
    }

    /// Exports a single-file summary snapshot of the current in-memory filesystem state to `storage` with an optional explicit IV.
    pub fn export_summary_with_iv(
        &self,
        storage: &dyn Storage,
        explicit_iv: Option<[u8; 12]>,
    ) -> std::io::Result<String> {
        self.quiesce()?;

        // Seal the active generation before taking the summary snapshot
        if let Some(ref writer) = self.log_writer
            && let Some(sealed_info) = writer.seal_active()?
        {
            self.manifest.write().unwrap().record_sealed_log(sealed_info);
        }

        let snapshot = self.inner.lock(OpTag::Flush).unwrap().snapshot_all();
        let manifest = self.manifest.read().unwrap().clone();

        let generation = manifest.latest_generation().unwrap_or(0);
        let last_batch_id = self
            .log_writer
            .as_ref()
            .map_or_else(|| self.last_batch_id.load(Ordering::SeqCst), |w| w.last_batch_id());
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let now = self.clock.now();

        // The header goes into the summary in plaintext while the key encrypts its body, so
        // a pair that disagrees writes a snapshot nothing can reopen - it would advertise
        // itself as unencrypted to `resolve_volume_key` while holding an encrypted body.
        // Refuse rather than emit one. Both are public fields, so assigning one without the
        // other (rather than through `set_volume`) can still produce such a pair.
        if self.volume_header.cipher != self.volume_key.cipher() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to export an unreadable summary: volume header describes a {} volume \
                     but the key in use is for {}",
                    self.volume_header.cipher,
                    self.volume_key.cipher()
                ),
            ));
        }

        let explicit_iv = explicit_iv.or(self.deterministic_summary_iv);
        let result = crate::log::summary::export_summary_with_iv(
            &crate::log::summary::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &self.volume_header,
                generation,
                last_batch_id,
                next_inode,
                created_at: now,
            },
            storage,
            &self.volume_key,
            explicit_iv,
        );

        if result.is_ok() {
            self.bytes_since_last_summary.store(0, Ordering::SeqCst);
            self.generations_since_last_summary.store(0, Ordering::SeqCst);
            self.last_summary_generation.store(generation, Ordering::SeqCst);
        }

        result
    }

    /// Exports a single-file summary snapshot capturing the committed `base` layer for a sealed generation.
    pub fn export_summary_for_base(
        &self,
        storage: &dyn Storage,
        sealed_gen: u32,
        last_batch_id: u64,
    ) -> std::io::Result<String> {
        let snapshot = self.inner.lock(OpTag::Flush).unwrap().base.clone();
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let manifest = self.manifest.read().unwrap().clone();
        debug_assert!(
            manifest.logs.iter().all(|l| l.generation <= sealed_gen),
            "manifest must not contain generations beyond sealed_gen {}",
            sealed_gen
        );
        debug_assert!(
            manifest.logs.iter().any(|l| l.generation == sealed_gen),
            "manifest must contain sealed_gen {}",
            sealed_gen
        );
        let now = self.clock.now();

        if self.volume_header.cipher != self.volume_key.cipher() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to export an unreadable summary: volume header describes a {} volume \
                     but the key in use is for {}",
                    self.volume_header.cipher,
                    self.volume_key.cipher()
                ),
            ));
        }

        crate::log::summary::export_summary(
            &crate::log::summary::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &self.volume_header,
                generation: sealed_gen,
                last_batch_id,
                next_inode,
                created_at: now,
            },
            storage,
            &self.volume_key,
        )
    }

    pub fn sync_and_export_summary(&self) -> std::io::Result<Option<String>> {
        self.sync_and_export_summary_with_iv(self.deterministic_summary_iv)
    }

    pub fn sync_and_export_summary_with_iv(&self, explicit_iv: Option<[u8; 12]>) -> std::io::Result<Option<String>> {
        self.quiesce()?;
        if let Some(ref writer) = self.log_writer {
            if !writer.is_open() {
                // Read-only session where no log records were ever flushed or written
                return Ok(None);
            }
            let storage = writer.storage();
            match self.export_summary_with_iv(storage.as_ref(), explicit_iv) {
                Ok(filename) => {
                    self.notify_replication();
                    return Ok(Some(filename));
                }
                Err(e) => {
                    log::warn!("sync_and_export_summary error: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::extent_map::ExtentMap;
    use crate::node::{AttrDelta, FileDelta, InodeMeta, Node, NodeDelta, NodeKind};
    use crate::storage::Storage;
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use std::time::SystemTime;

    #[test]
    fn test_init_fails_before_starting_anything_if_it_cannot_claim_the_lock() {
        let t = TestFs::builder().fault_injection().build();
        let fault = t.fault.unwrap();
        let fs = Arc::new(t.fs);

        fault.fail_lock_records(true);
        assert!(fs.init().is_err(), "a mount that cannot claim its lock must fail");
        assert!(!fs.flusher.stop(), "nothing may be started by a failed init");

        fault.fail_lock_records(false);
        fs.init().unwrap();
        assert!(fs.flusher.stop(), "a successful init starts the flusher");
        fs.destroy();
    }

    #[test]
    fn test_collect_staged_runs_merging_and_splitting() {
        use std::sync::RwLock;

        let mut map = ExtentMap::new();
        let buf1 = Arc::new(RwLock::new(vec![1u8; 100]));
        let buf2 = Arc::new(RwLock::new(vec![2u8; 100]));
        let buf3 = Arc::new(RwLock::new(vec![3u8; 300]));

        // Insert contiguous extents: 0..100, 100..200
        map.insert(0, Extent::new_staged(buf1, 0, 100));
        map.insert(100, Extent::new_staged(buf2, 0, 100));
        // Insert a sparse hole from 200..300, and staged extent from 300..600
        map.insert(300, Extent::new_staged(buf3, 0, 300));

        // Test with max_extent_size = 150
        // Expected runs:
        // Run 1: offset 0, len 150 (slices: 0..100 from buf1, 0..50 from buf2)
        // Run 2: offset 150, len 50 (slice: 50..100 from buf2)
        // Run 3: offset 300, len 150 (slice: 0..150 from buf3)
        // Run 4: offset 450, len 150 (slice: 150..300 from buf3)
        let runs = collect_staged_runs(&map, 150);
        assert_eq!(runs.len(), 4);

        assert_eq!(runs[0].file_offset, 0);
        assert_eq!(runs[0].total_len, 150);
        assert_eq!(runs[0].slices.len(), 2);
        assert_eq!(runs[0].slices[0].payload_offset, 0);
        assert_eq!(runs[0].slices[0].length, 100);
        assert_eq!(runs[0].slices[1].payload_offset, 0);
        assert_eq!(runs[0].slices[1].length, 50);

        assert_eq!(runs[1].file_offset, 150);
        assert_eq!(runs[1].total_len, 50);
        assert_eq!(runs[1].slices.len(), 1);
        assert_eq!(runs[1].slices[0].payload_offset, 50);
        assert_eq!(runs[1].slices[0].length, 50);

        assert_eq!(runs[2].file_offset, 300);
        assert_eq!(runs[2].total_len, 150);
        assert_eq!(runs[2].slices.len(), 1);
        assert_eq!(runs[2].slices[0].payload_offset, 0);
        assert_eq!(runs[2].slices[0].length, 150);

        assert_eq!(runs[3].file_offset, 450);
        assert_eq!(runs[3].total_len, 150);
        assert_eq!(runs[3].slices.len(), 1);
        assert_eq!(runs[3].slices[0].payload_offset, 150);
        assert_eq!(runs[3].slices[0].length, 150);
    }

    #[test]
    fn test_flush_coalesces_micro_writes_into_single_base_range_entry() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage).build().fs;

        let ino = fs.allocate_inode();
        fs.with_inner_for_tests(|inner| {
            inner.insert_new_node(
                ino,
                NodeDelta::File(FileDelta {
                    attr_delta: AttrDelta {
                        mode: Some(0o644),
                        nlink: Some(1),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            );
            inner.add_dir_entry(1, "micro.txt", ino, std::time::SystemTime::now());
        });

        // Perform 50 sequential 1-byte writes in live
        for i in 0..50u64 {
            let byte = vec![(i % 256) as u8];
            fs.write_at(ino, &byte, i as i64).unwrap();
        }

        // Verify that live extent map coalesced the sequential writes in memory
        {
            let inner = fs.inner.lock_for_tests().unwrap();
            if let Some(EntryDelta::Node(NodeDelta::File(f))) = inner.live.get(&ino) {
                assert_eq!(f.extents.len(), 1);
            } else {
                panic!("File not found in live layer");
            }
        }

        // Flush to disk and fold into base
        fs.quiesce().unwrap();

        // Verify that base has exactly 1 consolidated extent of length 50
        {
            let inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get(&ino).expect("inode missing in base");
            let node = node_arc.as_ref();
            if let NodeKind::File { extent_map, size, .. } = &node.kind {
                assert_eq!(*size, 50);
                assert_eq!(
                    extent_map.len(),
                    1,
                    "Expected exactly 1 consolidated RangeEntry in base!"
                );
                let (start, entry) = extent_map.iter().next().unwrap();
                assert_eq!(*start, 0);
                assert_eq!(entry.length(), 50);
                assert!(matches!(entry.extent, Extent::Disk { length: 50, .. }));
            } else {
                panic!("Expected NodeKind::File in base");
            }
        }

        // Read back data to ensure integrity
        let data = fs.read_file_data(ino, 0, 50).unwrap();
        let expected: Vec<u8> = (0..50u8).collect();
        assert_eq!(data, expected);
    }

    /// A write far larger than `max_extent_size` must be emitted as several capped records
    /// rather than one huge one, so that reading any byte of it decrypts only its own chunk.
    /// Runs over both a plaintext and an encrypted volume: the cap is not conditional on
    /// encryption, and the read path differs between the two (direct seek vs decrypt).
    #[test]
    fn test_large_write_is_split_into_capped_extents() {
        const CAP: usize = 1024;
        // Deliberately not a multiple of CAP, so the final chunk is a partial one.
        const TOTAL: usize = 8 * CAP + 300;

        for encrypted in [false, true] {
            let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());

            let (volume_header, volume_key) = if encrypted {
                let master = crate::crypto::MasterKey::new([0x42u8; 32]);
                let (header, key) =
                    crate::crypto::VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();
                (header, Arc::new(key))
            } else {
                (
                    crate::crypto::VolumeHeader::plaintext(),
                    crate::crypto::VolumeKey::plaintext_arc(),
                )
            };

            let mut fs = TestFs::builder()
                .storage(Arc::clone(&storage))
                .volume(volume_header, Arc::clone(&volume_key))
                .build()
                .fs;
            fs.max_extent_size = CAP;

            let ino = fs.allocate_inode();
            fs.with_inner_for_tests(|inner| {
                inner.insert_new_node(
                    ino,
                    NodeDelta::File(FileDelta {
                        attr_delta: AttrDelta {
                            mode: Some(0o644),
                            nlink: Some(1),
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                );
                inner.add_dir_entry(1, "big.bin", ino, SystemTime::now());
            });

            // A single contiguous write many times larger than the cap.
            let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
            fs.write_at(ino, &payload, 0).unwrap();
            fs.quiesce().unwrap();

            {
                let inner = fs.inner.lock_for_tests().unwrap();
                let node = inner.base.get(&ino).expect("inode missing in base");
                if let NodeKind::File { extent_map, size, .. } = &node.kind {
                    assert_eq!(*size as usize, TOTAL);
                    assert_eq!(
                        extent_map.len(),
                        TOTAL.div_ceil(CAP),
                        "expected one extent per capped chunk (encrypted={})",
                        encrypted
                    );
                    for (_, entry) in extent_map.iter() {
                        assert!(
                            entry.length() as usize <= CAP,
                            "extent of {} bytes exceeds the {} byte cap (encrypted={})",
                            entry.length(),
                            CAP,
                            encrypted
                        );
                    }
                } else {
                    panic!("expected NodeKind::File in base");
                }
            }

            // Whole-file and sub-range reads, including ranges straddling chunk boundaries.
            assert_eq!(
                fs.read_file_data(ino, 0, TOTAL).unwrap(),
                payload,
                "encrypted={}",
                encrypted
            );
            for (off, len) in [(0usize, 10usize), (CAP - 5, 10), (CAP * 3 + 7, CAP), (TOTAL - 10, 10)] {
                assert_eq!(
                    fs.read_file_data(ino, off as u64, len).unwrap(),
                    payload[off..off + len],
                    "sub-range read at {}..{} (encrypted={})",
                    off,
                    off + len,
                    encrypted
                );
            }

            // The split must survive a full replay from the log.
            let recovered = crate::log::recover_fs(
                Arc::clone(&storage),
                crate::RecoveryTarget::Latest,
                Arc::new(SystemClock),
                volume_key,
            )
            .unwrap();
            assert_eq!(
                recovered.read_file_data(ino, 0, TOTAL).unwrap(),
                payload,
                "after recovery (encrypted={})",
                encrypted
            );
        }
    }

    /// The core property a hole has to have: once the data it covers is durable in `base`,
    /// a `Zero` extent in a *later* layer must mask it. Removing the range from the delta
    /// instead would leave that layer with no opinion, and the read would fall through and
    /// resurrect the punched bytes.
    #[test]
    fn test_punched_hole_masks_flushed_data_and_survives_recovery() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let ino = fs.create_file(1, "holey.bin", 0o644).unwrap();

        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251 + 1) as u8).collect();
        fs.write_at(ino, &payload, 0).unwrap();

        // Flush first, so the data is a durable `Disk` extent in `base` and the punch below
        // lands in a fresh, higher layer - the case that actually needs masking.
        fs.quiesce().unwrap();
        assert_eq!(fs.read_file_data(ino, 0, 1000).unwrap(), payload);

        fs.punch_hole(ino, 200, 300).unwrap();

        // Size is unchanged by a punch, and the hole reads as zeros while the data on
        // either side is untouched.
        let expect_holed = |buf: &[u8]| {
            assert_eq!(&buf[..200], &payload[..200], "before the hole");
            assert!(buf[200..500].iter().all(|&b| b == 0), "hole must read as zeros");
            assert_eq!(&buf[500..], &payload[500..], "after the hole");
        };
        assert_eq!(fs.get_attr(ino).unwrap().size, 1000);
        expect_holed(&fs.read_file_data(ino, 0, 1000).unwrap());

        // A read starting inside the hole must not fall through to base either.
        assert!(
            fs.read_file_data(ino, 250, 100).unwrap().iter().all(|&b| b == 0),
            "read starting inside the hole"
        );

        // Fold the punch into base, then confirm it did not become a data record: the only
        // payload ever written was the original 1000 bytes.
        fs.quiesce().unwrap();
        fs.force_roll_active_log().unwrap();
        expect_holed(&fs.read_file_data(ino, 0, 1000).unwrap());

        let stats = fs.calculate_generation_live_stats();
        let live_bytes: u64 = stats.iter().map(|s| s.live_bytes).sum();
        assert_eq!(
            live_bytes, 700,
            "punched bytes must stop counting as live, so compaction can reclaim them"
        );

        // And it has to survive replay - this is where a silently-dropped Zero extent would
        // show up, with the old data reappearing. Check both routes: replaying the `.log`
        // (LogExtent) and loading a `.summary` (SerializedExtent), which encode holes
        // independently of each other.
        let from_log = crate::log::recover_fs(
            Arc::clone(&storage),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert_eq!(from_log.get_attr(ino).unwrap().size, 1000);
        expect_holed(&from_log.read_file_data(ino, 0, 1000).unwrap());

        fs.sync_and_export_summary().unwrap();
        let from_summary = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert_eq!(from_summary.get_attr(ino).unwrap().size, 1000);
        expect_holed(&from_summary.read_file_data(ino, 0, 1000).unwrap());
    }

    /// Two truncations in a row, then a grow. The second truncate must not narrow the
    /// masked range down to the size the first one left behind: everything the file ever
    /// held above the final cut has to stay masked, or growing back re-exposes whatever is
    /// still sitting in `base` between the two cut points.
    #[test]
    fn test_successive_truncates_keep_masking_the_full_discarded_range() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let ino = fs.create_file(1, "t.bin", 0o644).unwrap();
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251 + 1) as u8).collect();
        fs.write_at(ino, &payload, 0).unwrap();

        // Flush so the data is durable in `base` and the truncates below land in a layer
        // above it - the case where masking actually has to do something.
        fs.quiesce().unwrap();

        let truncate_to = |size: u64| {
            let now = fs.clock.now();
            crate::operations::read_write::setattr_core(
                &fs,
                ino,
                0,
                0,
                0,
                size as i64,
                now,
                now,
                crate::operations::read_write::FUSE_SET_ATTR_SIZE,
            )
            .unwrap();
        };

        truncate_to(500);
        truncate_to(100);
        // Growing back must expose zeros, not the bytes base still holds in [100, 1000).
        truncate_to(1000);

        let data = fs.read_file_data(ino, 0, 1000).unwrap();
        assert_eq!(&data[..100], &payload[..100], "data below the final cut survives");
        assert!(
            data[100..].iter().all(|&b| b == 0),
            "everything above the final cut must read as zeros, including the range between \
             the two truncation points"
        );

        // And it must still hold once flushed and replayed.
        fs.quiesce().unwrap();
        let recovered = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let rec = recovered.read_file_data(ino, 0, 1000).unwrap();
        assert_eq!(&rec[..100], &payload[..100]);
        assert!(rec[100..].iter().all(|&b| b == 0), "after recovery");
    }

    /// A punch is clamped to EOF: it must never extend the file, and punching entirely
    /// past the end is a no-op.
    #[test]
    fn test_punch_hole_is_clamped_to_eof() {
        let fs = TestFs::builder().build().fs;
        let ino = fs.create_file(1, "short.bin", 0o644).unwrap();
        fs.write_at(ino, &[0xAB; 100], 0).unwrap();

        fs.punch_hole(ino, 4096, 4096).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 100, "punch past EOF must not extend");
        assert_eq!(fs.read_file_data(ino, 0, 100).unwrap(), vec![0xAB; 100]);

        // Straddling EOF punches only the part that exists.
        fs.punch_hole(ino, 50, 4096).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 100, "straddling punch must not extend");
        let data = fs.read_file_data(ino, 0, 100).unwrap();
        assert_eq!(&data[..50], &[0xAB; 50]);
        assert!(data[50..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_directory_parent_tracking_across_mkdir_rename_and_flush() {
        let clock = Arc::new(crate::clock::MockClock(SystemTime::UNIX_EPOCH));
        let fs = TestFs::builder().clock(clock).build().fs;

        // Root inode 1 parent is 1
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));

        // Create dir1 (child of root)
        let dir1 = fs.make_dir(1, "dir1", 0o755).unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));

        // Create dir2 (child of dir1)
        let dir2 = fs.make_dir(dir1, "dir2", 0o755).unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir1));

        // Create dir3 (child of root)
        let dir3 = fs.make_dir(1, "dir3", 0o755).unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));

        // Move dir2 from dir1 into dir3
        fs.rename_entry(dir1, "dir2", dir3, "dir2_moved").unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));

        // Fold live to base
        fs.freeze_now();
        fs.fold_flushing_into_base();

        // Verify parent relations are preserved in base after fold
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));
    }

    #[test]
    fn test_generation_live_stats_and_manifest_lifecycle() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        let ino1 = fs.allocate_inode();
        fs.inner.lock_for_tests().unwrap().base.insert(
            ino1,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, clock.now()),
                kind: NodeKind::File {
                    extent_map: ExtentMap::new(),
                    size: 0,
                },
            }),
        );
        fs.with_inner_for_tests(|inner| {
            inner.add_dir_entry(1, "file1.bin", ino1, clock.now());
        });

        // Write 100 bytes to file1 in gen 1
        let data1 = vec![0xAA; 100];
        fs.write_at(ino1, &data1, 0).unwrap();
        fs.quiesce().unwrap();

        // Overwrite 40 bytes of file1 (offset 0..40)
        let overwrite_data = vec![0xBB; 40];
        fs.write_at(ino1, &overwrite_data, 0).unwrap();
        fs.quiesce().unwrap();

        // Export summary snapshot (seals active gen 1 into manifest and leaves gen 2 unopened)
        let summary_file = fs.export_summary(storage.as_ref()).unwrap();
        assert!(storage.exists(&summary_file));

        // Now gen 1 is sealed in manifest with 60 live bytes (offset 40..100) and 140 total data bytes
        let stats = fs.calculate_generation_live_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].generation, 1);
        assert_eq!(stats[0].filename, "000001.log");
        assert_eq!(stats[0].total_data_bytes, 140);
        assert_eq!(stats[0].live_bytes, 100); // 60 from 1st write + 40 from 2nd write (both landed in gen 1)
        assert_eq!(stats[0].live_extents, 2);
        assert!((stats[0].live_ratio - (100.0 / 140.0)).abs() < 1e-6);

        // Recover filesystem and verify manifest is restored identically
        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            clock.clone(),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let recovered_stats = recovered.calculate_generation_live_stats();
        assert_eq!(recovered_stats.len(), 1);
        assert_eq!(recovered_stats[0].generation, 1);
        assert_eq!(recovered_stats[0].total_data_bytes, 140);
        assert_eq!(recovered_stats[0].live_bytes, 100);
        assert_eq!(recovered_stats[0].live_extents, 2);
    }

    #[test]
    fn test_rm_rf_directory_tree_emits_unlinks_for_all_children_and_recovers_cleanly() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        // 1. Create /Gletscher, /Gletscher/sub, and files
        let gletscher_ino = fs.make_dir(1, "Gletscher", 0o755).unwrap();

        let file1_ino = fs.create_file(gletscher_ino, "file1.txt", 0o644).unwrap();
        fs.write_at(file1_ino, &[1, 2, 3, 4], 0).unwrap();

        let file2_ino = fs.create_file(gletscher_ino, "file2.txt", 0o644).unwrap();
        fs.write_at(file2_ino, &[5, 6, 7, 8], 0).unwrap();

        let sub_ino = fs.make_dir(gletscher_ino, "sub", 0o755).unwrap();

        let file3_ino = fs.create_file(sub_ino, "file3.txt", 0o644).unwrap();
        fs.write_at(file3_ino, &[9, 10, 11, 12], 0).unwrap();

        // Flush creation to disk and seal active generation 1
        fs.quiesce().unwrap();
        fs.force_roll_active_log().unwrap();

        // Verify live stats show 3 files and 12 live bytes
        let stats_before = fs.calculate_generation_live_stats();
        assert_eq!(stats_before[0].live_bytes, 12);
        assert_eq!(stats_before[0].live_extents, 3);

        // 2. Perform rm -rf /Gletscher
        fs.remove_file(sub_ino, "file3.txt").unwrap();
        fs.remove_dir(gletscher_ino, "sub").unwrap();
        fs.remove_file(gletscher_ino, "file1.txt").unwrap();
        fs.remove_file(gletscher_ino, "file2.txt").unwrap();
        fs.remove_dir(1, "Gletscher").unwrap();

        // Flush deletion to disk
        fs.quiesce().unwrap();

        // Check live stats in memory
        let stats_after = fs.calculate_generation_live_stats();
        assert_eq!(stats_after[0].live_bytes, 0);
        assert_eq!(stats_after[0].live_extents, 0);

        // 3. Inspect the log dump to verify InodeDelta records were written
        let dump_text = crate::dump::dump_log_file(storage.as_ref(), "000002.log", 2, None).unwrap();
        assert!(dump_text.contains("InodeDelta"));

        // 4. Recover filesystem and verify no orphaned nodes remain
        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            clock.clone(),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let base = recovered.inner.lock_for_tests().unwrap().base.clone();
        assert_eq!(base.len(), 1); // ONLY root directory (inode 1) remains!
        assert!(base.contains_key(&1));

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 0);
        assert_eq!(rec_stats[0].live_extents, 0);
    }

    #[test]
    fn test_hardlink_survives_rm_rf_of_other_parent_directory() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        // 1. Create /keep and /Gletscher directories
        let keep_ino = fs.make_dir(1, "keep", 0o755).unwrap();
        let gletscher_ino = fs.make_dir(1, "Gletscher", 0o755).unwrap();

        // 2. Create /keep/shared.txt (inode N, nlink 1) and write data
        let file_ino = fs.create_file(keep_ino, "shared.txt", 0o644).unwrap();
        fs.write_at(file_ino, b"persistent shared content", 0).unwrap();

        // 3. Create hard link /Gletscher/shared_link.txt -> inode N (nlink becomes 2)
        fs.hard_link(file_ino, gletscher_ino, "shared_link.txt").unwrap();
        assert_eq!(fs.get_attr(file_ino).unwrap().nlink, 2);

        // Commit everything to disk and seal active generation 1
        fs.quiesce().unwrap();
        fs.force_roll_active_log().unwrap();

        let stats1 = fs.calculate_generation_live_stats();
        assert_eq!(stats1[0].live_bytes, 25);
        assert_eq!(stats1[0].live_extents, 1);

        // 4. Delete /Gletscher via rm -rf (/Gletscher/shared_link.txt unlinked, /Gletscher rmdir'd)
        fs.remove_file(gletscher_ino, "shared_link.txt").unwrap();
        fs.remove_dir(1, "Gletscher").unwrap();

        // Verify that /keep/shared.txt still has nlink 1 in memory
        let keep_file_attr = fs.get_attr(file_ino).unwrap();
        assert_eq!(keep_file_attr.nlink, 1);

        // Commit deletion to disk
        fs.quiesce().unwrap();

        // Check in-memory live stats: data is STILL alive because /keep/shared.txt exists!
        let stats2 = fs.calculate_generation_live_stats();
        assert_eq!(stats2[0].live_bytes, 25);
        assert_eq!(stats2[0].live_extents, 1);

        // 5. Crash-recovery: Recover filesystem and verify /keep/shared.txt survived with full data!
        let recovered = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let rec_file_attr = recovered.get_attr(file_ino).expect("shared.txt must survive recovery");
        assert_eq!(rec_file_attr.nlink, 1);

        let data = recovered.read_file_data(file_ino, 0, 25).unwrap();
        assert_eq!(&data, b"persistent shared content");

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 25);
        assert_eq!(rec_stats[0].live_extents, 1);
    }

    #[test]
    fn test_automatic_flush_triggers_on_staged_thresholds() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        fs.max_buffer_size = 1000;
        fs.max_staged_ops = 5; // Automatic flush after 5 operations

        // Perform 4 create operations - not flushed yet
        for i in 0..4 {
            let name = format!("file_{}.txt", i);
            fs.create_file(1, &name, 0o644).unwrap();
        }
        assert_eq!(fs.staged_ops(), 4);
        assert_eq!(fs.log_writer.as_ref().unwrap().record_count(), 0);

        // 5th operation reaches threshold and triggers automatic flush!
        fs.create_file(1, "file_4.txt", 0o644).unwrap();

        // Staged ops reset to 0 after automatic flush
        assert_eq!(fs.staged_ops(), 0);
        assert_eq!(fs.log_writer.as_ref().unwrap().record_count(), 7); // 5 files + 1 root dir + 1 FlushCommit
    }

    #[test]
    fn test_unlinked_open_file_does_not_resurrect_on_recovery() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        // Create a file, write data, then sync
        let f = fs.create_file(1, "unlinked.txt", 0o644).unwrap();
        let ino = f;
        fs.write_at(ino, b"unlinked content", 0).unwrap();
        fs.quiesce().unwrap();

        // Open the file so open_counts > 0
        let fh = fs.open_file(ino, libc::O_RDWR as u32).unwrap();

        // Unlink the file: removes directory entry, but node is kept in memory because open_count == 1
        fs.remove_file(1, "unlinked.txt").unwrap();

        // Write more data while unlinked, then sync log
        fs.write_at(ino, b" more content", 16).unwrap();
        fs.quiesce().unwrap();

        // Close the handle: drops open_count to 0 and tombstones the node in live
        fs.release_file(ino, fh).unwrap();
        fs.quiesce().unwrap();

        // Recover filesystem from log
        let recovered = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let base = recovered.inner.lock_for_tests().unwrap().base.clone();

        // Only root inode (1) should exist; NO resurrected /file_{ino} or phantom entries!
        assert_eq!(base.len(), 1, "Expected only root inode in base");
        assert!(base.contains_key(&1));
        assert!(!base.contains_key(&ino));

        let entries = recovered.list_directory(1).unwrap();
        assert!(entries.is_empty(), "Expected empty root directory, got: {:?}", entries);
    }

    #[test]
    fn test_truncate_down_then_extend_across_flush_boundary() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder().storage(storage).clock(clock.clone()).build().fs;

        // Create file and write 100 bytes (0xAA)
        let file_ino = fs.create_file(1, "data.bin", 0o644).unwrap();
        let ino = file_ino;
        fs.write_at(ino, &[0xAA; 100], 0).unwrap();

        // Truncate down to 20 bytes
        let now = clock.now();
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            20,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Flush down-truncation to disk (so base layer now holds the 20-byte state)
        fs.quiesce().unwrap();

        // Extend file size to 100 bytes in a NEW live delta layer without writing bytes
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            100,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Read all 100 bytes: [0..20] must be 0xAA, [20..100] must be zeroes (0x00), NOT stale data!
        let read_data = fs.read_file_data(ino, 0, 100).unwrap();
        assert_eq!(read_data.len(), 100);
        assert_eq!(&read_data[0..20], &[0xAA; 20]);
        assert_eq!(
            &read_data[20..100],
            &[0x00; 80],
            "Stale data must not survive truncate-down across flush!"
        );

        // Flush and verify reading again from base
        fs.quiesce().unwrap();
        let read_data_after_flush = fs.read_file_data(ino, 0, 100).unwrap();
        assert_eq!(&read_data_after_flush[0..20], &[0xAA; 20]);
        assert_eq!(&read_data_after_flush[20..100], &[0x00; 80]);
    }

    #[test]
    fn test_multi_batch_flushing_queue_and_layer_resolution() {
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder().clock(clock.clone()).build().fs;

        // 1. Create file in batch 1
        let f = fs.create_file(1, "test.txt", 0o644).unwrap();
        let ino = f;
        fs.write_at(ino, &[0x11; 50], 0).unwrap();

        // Freeze into flushing queue (batch 1)
        fs.freeze_now();
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 1);

        // 2. Overwrite in batch 2 (live layer)
        fs.write_at(ino, &[0x22; 20], 10).unwrap();

        // Freeze into flushing queue (batch 2)
        fs.freeze_now();
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 2);

        // 3. In live layer, truncate to 40 bytes
        let now = clock.now();
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            40,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Verify read across live -> batch 2 -> batch 1 -> base
        let data = fs.read_file_data(ino, 0, 50).unwrap();
        assert_eq!(data.len(), 40);
        assert_eq!(&data[0..10], &[0x11; 10]);
        assert_eq!(&data[10..30], &[0x22; 20]);
        assert_eq!(&data[30..40], &[0x11; 10]);

        // Drain flushing batches into base
        fs.fold_flushing_into_base();
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);

        // Read again after folding
        let data_after_fold = fs.read_file_data(ino, 0, 50).unwrap();
        assert_eq!(data_after_fold, data);
    }

    #[test]
    fn test_shutdown_drain_rolls_without_leaving_an_empty_generation() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock)
            .max_log_size(50 * 1024)
            .build()
            .fs;

        // Three queued batches, each too large to coalesce with another, and two of them
        // together past `max_log_size`: the drain has to roll between them.
        for name in ["a.bin", "b.bin", "c.bin"] {
            let file = fs.create_file(1, name, 0o644).unwrap();
            fs.write_at(file, &[7u8; 40 * 1024], 0).unwrap();
            assert!(fs.freeze_now());
        }

        fs.destroy();

        assert!(storage.exists("000001.log"));
        assert!(
            storage.exists("000002.log"),
            "the drain must roll once the backlog crosses max_log_size"
        );
        assert!(
            !storage.exists("000003.log"),
            "sealing the last generation must not leave an empty successor behind"
        );
    }

    #[test]
    fn test_flush_io_error_retries_and_does_not_wedge() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        // Set tiny max_log_size (50 bytes) so the next flush rolls to 000002.log
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .max_log_size(50)
            .build()
            .fs;

        // 1. First batch: write data to file1 and flush (populates gen 1 past header size)
        let f1 = fs.create_file(1, "file1.txt", 0o644).unwrap();
        fs.write_at(f1, b"initial payload", 0).unwrap();
        // Inject permission error on opening 000002.log to simulate I/O failure when rolling
        fault_storage.fail_on_file("000002.log", std::io::ErrorKind::PermissionDenied);
        let _ = fs.quiesce();

        // 2. Second batch: write data to file2
        let f2 = fs.create_file(1, "file2.txt", 0o644).unwrap();
        fs.write_at(f2, b"second payload", 0).unwrap();

        // 3. Attempt flush - should fail with I/O error on roll creation
        let flush_res = fs.quiesce();
        assert!(flush_res.is_err(), "Expected flush_log to fail on simulated I/O error");

        // Verify filesystem is NOT wedged: flushing queue still retains the batch, live mutations still work!
        assert_eq!(
            fs.inner.lock_for_tests().unwrap().flushing.len(),
            1,
            "Failed batch must remain in flushing queue"
        );

        // Live operations continue working smoothly
        let f3 = fs.create_file(1, "file3.txt", 0o644).unwrap();
        fs.write_at(f3, b"third payload", 0).unwrap();

        // 5. Restore normal write access by clearing injected fault
        fault_storage.clear_fail_on_file("000002.log");

        // 6. Retry flush - must succeed and drain ALL batches
        let retry_res = fs.quiesce();
        assert!(
            retry_res.is_ok(),
            "Retried flush must succeed once I/O is restored: {:?}",
            retry_res
        );
        assert_eq!(
            fs.inner.lock_for_tests().unwrap().flushing.len(),
            0,
            "Flushing queue must be completely drained"
        );

        // Verify all three files are intact in memory and base
        let d1 = fs.read_file_data(f1, 0, 15).unwrap();
        assert_eq!(&d1, b"initial payload");
        let d2 = fs.read_file_data(f2, 0, 14).unwrap();
        assert_eq!(&d2, b"second payload");
        let d3 = fs.read_file_data(f3, 0, 13).unwrap();
        assert_eq!(&d3, b"third payload");

        // 7. Crash-recovery: Recover filesystem and verify all files recovered cleanly
        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            clock.clone(),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered.get_attr(f1).is_some());
        assert!(recovered.get_attr(f2).is_some());
        assert!(recovered.get_attr(f3).is_some());
        let rec_d1 = recovered.read_file_data(f1, 0, 15).unwrap();
        assert_eq!(&rec_d1, b"initial payload");
        let rec_d2 = recovered.read_file_data(f2, 0, 14).unwrap();
        assert_eq!(&rec_d2, b"second payload");
        let rec_d3 = recovered.read_file_data(f3, 0, 13).unwrap();
        assert_eq!(&rec_d3, b"third payload");
    }

    #[test]
    fn test_flush_mid_batch_failure_rolls_back_and_retries_cleanly() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        // 1. Initial batch with 2 files flushed cleanly
        let mut initial_inos = Vec::new();
        for i in 1..=2 {
            let name = format!("init_{}.txt", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            fs.write_at(f, b"initial payload", 0).unwrap();
            initial_inos.push(f);
        }
        fs.quiesce().unwrap();

        let initial_offset = storage.file_len("000001.log").unwrap();

        // 2. Stage a second batch with 8 files
        let mut batch2_inos = Vec::new();
        for i in 1..=8 {
            let name = format!("batch2_file_{}.bin", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            let payload = vec![(i as u8) * 0x11; 128];
            fs.write_at(f, &payload, 0).unwrap();
            batch2_inos.push((f, payload));
        }

        // 3. Set fault threshold slightly larger than initial_offset to force simulated ENOSPC mid-batch with partial torn write
        fault_storage.fail_writes_after_bytes(initial_offset + 300, true);

        // 4. Attempt flush - MUST fail with simulated mid-record write error
        let flush_res = fs.quiesce();
        assert!(
            flush_res.is_err(),
            "Expected flush to fail with simulated mid-record write error"
        );

        // 5. Verify the file in storage was rolled back to initial_offset!
        let rolled_back_len = storage.file_len("000001.log").unwrap();
        assert_eq!(
            rolled_back_len, initial_offset,
            "Log file must be rolled back to batch_start_offset on mid-batch failure"
        );

        // 6. Clear fault injection
        fault_storage.clear_write_limit();

        // 7. Retry flush - MUST succeed cleanly
        let retry_res = fs.quiesce();
        assert!(retry_res.is_ok(), "Retried flush must succeed: {:?}", retry_res);
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);

        // 8. Recover filesystem and verify 100% data integrity without checksum mismatches!
        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            clock.clone(),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .expect("Recovery must succeed cleanly");
        for ino in initial_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = recovered.read_file_data(ino, 0, 15).unwrap();
            assert_eq!(&d, b"initial payload");
        }
        for (ino, payload) in batch2_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = recovered.read_file_data(ino, 0, payload.len()).unwrap();
            assert_eq!(d, payload);
        }

        let report = crate::check::check_volume(
            storage.clone(),
            &crate::check::CheckOptions::full_data(),
            crate::crypto::VolumeKey::plaintext_arc(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();
        assert!(report.is_clean(), "Integrity check must be clean: {:?}", report.issues);
    }

    /// A batch rewritten after a failed sync must be encrypted under fresh nonces.
    ///
    /// The rollback truncates the failed attempt away, but on a real disk its bytes can
    /// outlive the truncate. Any retried record that reused one of the failed attempt's nonces
    /// for a different plaintext would expose the XOR of the two plaintexts and the Poly1305
    /// one-time key, so every sequence number in the retry must lie past all of the failed
    /// attempt's.
    #[test]
    fn test_batch_retried_after_failed_sync_uses_fresh_nonces() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = crate::clock::AdvancingClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));

        let master = crate::crypto::MasterKey::new([0x42u8; 32]);
        let (header, key) =
            crate::crypto::VolumeHeader::new_encrypted(&master, crate::compress::Compression::Zstd).unwrap();
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(Arc::new(clock.clone()))
            .volume(header, Arc::new(key))
            .build()
            .fs;
        // Open the log file up front, so the injected sync failure hits the batch rather than
        // the new file's header.
        fs.log_writer.as_ref().unwrap().open_if_unopened().unwrap();

        for i in 0..3u8 {
            let name = format!("file_{}.bin", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            fs.write_at(f, &vec![i; 4096], 0).unwrap();
        }
        let dir = fs.make_dir(1, "dir", 0o755).unwrap();
        fs.create_file(dir, "inner.txt", 0o644).unwrap();

        fault_storage.fail_syncs(true);
        assert!(fs.quiesce().is_err(), "the flush must fail on the injected sync error");
        fault_storage.fail_syncs(false);

        let tails = fault_storage.truncated_tails();
        assert_eq!(tails.len(), 1, "the failed group must be rolled back exactly once");
        let failed = &tails[0];
        assert_eq!(failed.filename, "000001.log");

        fs.quiesce().unwrap();

        let log = storage.open_reader("000001.log").unwrap();
        let mut retried = vec![0u8; (log.len().unwrap() - failed.offset) as usize];
        log.read_exact_at(failed.offset, &mut retried).unwrap();

        let failed_sequences = record_sequences(&failed.bytes);
        let retried_sequences = record_sequences(&retried);
        assert_eq!(
            failed_sequences.len(),
            retried_sequences.len(),
            "the retry writes the same records as the failed attempt"
        );
        let last_failed = *failed_sequences.last().unwrap();
        assert!(
            retried_sequences.iter().all(|&s| s > last_failed),
            "the retry reused a sequence of the failed attempt: failed {:?}, retried {:?}",
            failed_sequences,
            retried_sequences
        );

        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(clock.clone()),
            fs.log_writer.as_ref().unwrap().volume_key().clone(),
        )
        .unwrap();
        assert!(recovered.lookup_child(dir, "inner.txt").is_some());
    }

    /// The sequence number of every record in `bytes`, a run of whole records.
    fn record_sequences(bytes: &[u8]) -> Vec<u64> {
        use crate::log::record::{RECORD_HEADER_SIZE, RecordHeader};
        let mut sequences = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let header = RecordHeader::from_bytes(bytes[pos..pos + RECORD_HEADER_SIZE].try_into().unwrap()).unwrap();
            sequences.push(header.sequence);
            pos += RECORD_HEADER_SIZE + header.payload_len as usize;
        }
        assert_eq!(pos, bytes.len(), "a truncated record");
        sequences
    }

    #[test]
    fn test_extent_map_hole_larger_than_32_bits() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        let ino = fs.create_file(1, "sparse_5g.bin", 0o644).unwrap();

        let start_data = vec![0xABu8; 100];
        fs.write_at(ino, &start_data, 0).unwrap();

        // 5 GiB hole length (> 32-bit: 5 * 1024 * 1024 * 1024 = 5,368,709,120 > 4,294,967,295)
        let hole_len: u64 = 5 * 1024 * 1024 * 1024;
        let end_offset: u64 = 100 + hole_len;

        let end_data = vec![0xCDu8; 100];
        fs.write_at(ino, &end_data, end_offset as i64).unwrap();

        fs.punch_hole(ino, 100, hole_len).unwrap();

        let total_size = (end_offset + 100) as i64;
        assert_eq!(fs.get_attr(ino).unwrap().size, total_size);

        assert_eq!(fs.read_file_data(ino, 0, 100).unwrap(), start_data);
        assert_eq!(fs.read_file_data(ino, end_offset, 100).unwrap(), end_data);
        assert!(fs.read_file_data(ino, 100, 50).unwrap().iter().all(|&b| b == 0));
        assert!(
            fs.read_file_data(ino, end_offset - 50, 50)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );

        // Flush delta to log
        fs.quiesce().unwrap();

        // Verify recovery from .log replay
        let from_log = crate::log::recover_fs(
            Arc::clone(&storage),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert_eq!(from_log.get_attr(ino).unwrap().size, total_size);
        assert_eq!(from_log.read_file_data(ino, 0, 100).unwrap(), start_data);
        assert_eq!(from_log.read_file_data(ino, end_offset, 100).unwrap(), end_data);
        assert!(from_log.read_file_data(ino, 100, 50).unwrap().iter().all(|&b| b == 0));
        assert!(
            from_log
                .read_file_data(ino, end_offset - 50, 50)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );

        {
            let inner = from_log.inner.lock_for_tests().unwrap();
            let node = inner.base.get(&ino).unwrap();
            if let crate::node::NodeKind::File { ref extent_map, .. } = node.kind {
                let hole_entry = extent_map
                    .iter()
                    .find(|(start, _)| **start == 100)
                    .expect("hole entry at offset 100")
                    .1;
                assert_eq!(hole_entry.length(), hole_len);
                assert!(matches!(hole_entry.extent, Extent::Zero { length } if length == hole_len));
            } else {
                panic!("Expected file node");
            }
        }

        // Export summary snapshot and verify recovery from summary snapshot
        fs.sync_and_export_summary().unwrap();
        let from_summary = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert_eq!(from_summary.get_attr(ino).unwrap().size, total_size);
        assert_eq!(from_summary.read_file_data(ino, 0, 100).unwrap(), start_data);
        assert_eq!(from_summary.read_file_data(ino, end_offset, 100).unwrap(), end_data);
        assert!(
            from_summary
                .read_file_data(ino, 100, 50)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );
        assert!(
            from_summary
                .read_file_data(ino, end_offset - 50, 50)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );

        {
            let inner = from_summary.inner.lock_for_tests().unwrap();
            let node = inner.base.get(&ino).unwrap();
            if let crate::node::NodeKind::File { ref extent_map, .. } = node.kind {
                let hole_entry = extent_map
                    .iter()
                    .find(|(start, _)| **start == 100)
                    .expect("hole entry at offset 100 in summary")
                    .1;
                assert_eq!(hole_entry.length(), hole_len);
                assert!(matches!(hole_entry.extent, Extent::Zero { length } if length == hole_len));
            } else {
                panic!("Expected file node");
            }
        }
    }

    #[test]
    fn test_appendfs_destroy_drains_async_ops() {
        let fs = Arc::new(TestFs::builder().build().fs);
        assert_eq!(fs.in_flight_async_ops(), 0);

        let guard = fs.begin_async_op();
        assert_eq!(fs.in_flight_async_ops(), 1);

        let fs_clone = Arc::clone(&fs);
        let destroyed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let destroyed_clone = Arc::clone(&destroyed);

        let handle = std::thread::spawn(move || {
            fs_clone.destroy();
            destroyed_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        std::thread::sleep(Duration::from_millis(50));
        assert!(!destroyed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(fs.in_flight_async_ops(), 1);

        drop(guard);
        handle.join().unwrap();
        assert!(destroyed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(fs.in_flight_async_ops(), 0);
    }

    #[test]
    fn test_appendfs_destroy_drains_read_only() {
        let fs = Arc::new(TestFs::builder().build().fs);
        fs.set_read_only();
        let guard = fs.begin_async_op();

        let fs_clone = Arc::clone(&fs);
        let destroyed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let destroyed_clone = Arc::clone(&destroyed);

        let handle = std::thread::spawn(move || {
            fs_clone.destroy();
            destroyed_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        std::thread::sleep(Duration::from_millis(50));
        assert!(!destroyed.load(std::sync::atomic::Ordering::SeqCst));

        drop(guard);
        handle.join().unwrap();
        assert!(destroyed.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A filesystem mounted read-only must not write a summary on unmount, even though
    /// shutdown's own first phase also puts the filesystem into `ShutdownState::ReadOnly`.
    ///
    /// This matters most for a time-travel read-only mount (`--at-time` / `--batch-id`), whose
    /// in-memory state is historical: exporting it would publish that older state as the
    /// volume's newest summary, and a later recovery preferring it would roll the volume back.
    #[test]
    fn test_destroy_on_read_only_mount_does_not_export_a_summary() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder().storage(storage.clone()).clock(clock).build().fs;

        // Staged and flushed before the mount goes read-only, so the writer is genuinely open -
        // the export path is reachable and only the read-only entry state suppresses it.
        fs.create_file(1, "before_ro.bin", 0o644).unwrap();
        fs.quiesce().unwrap();

        let summaries_before = summary_count(storage.as_ref());
        fs.set_read_only();
        fs.destroy();

        assert_eq!(
            summary_count(storage.as_ref()),
            summaries_before,
            "a read-only mount must not export a summary on unmount"
        );
    }

    /// The read-write counterpart of the test above: a normal mount must still export on
    /// unmount, so the guard above cannot be satisfied by simply never exporting.
    #[test]
    fn test_destroy_on_read_write_mount_exports_a_final_summary() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder().storage(storage.clone()).clock(clock).build().fs;
        fs.create_file(1, "rw.bin", 0o644).unwrap();

        let summaries_before = summary_count(storage.as_ref());
        fs.destroy();

        assert!(
            summary_count(storage.as_ref()) > summaries_before,
            "a read-write unmount must export a final summary"
        );
    }

    fn summary_count(storage: &dyn Storage) -> usize {
        storage
            .list_files()
            .unwrap()
            .iter()
            .filter(|f| f.ends_with(".summary"))
            .count()
    }

    #[test]
    fn test_staged_accounting_reset_on_begin_flush_prevents_spurious_batches() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        // Threshold: 100 bytes or 10 ops
        fs.max_buffer_size = 100;
        fs.max_staged_ops = 10;

        let file = fs.create_file(1, "test.bin", 0o644).unwrap();

        // 1. Write 100 bytes to hit max_buffer_size threshold
        fs.write_at(file, &[0xAA; 100], 0).unwrap();

        // Automatic threshold triggered begin_flush()!
        // In unmounted environment without background flusher, threshold trigger flushes inline,
        // so queue depth is 0 and staged counters are 0.
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Now simulate active background flusher with queued batch:
        // Populate live with 60 bytes
        fs.write_at(file, &[0xBB; 60], 100).unwrap();
        assert_eq!(fs.staged_bytes(), 60);
        assert_eq!(fs.staged_ops(), 1);

        // Freeze batch into queue manually (simulating begin_flush when flusher starts or when threshold hit)
        fs.freeze_now();
        assert_eq!(fs.flush_queue_depth(), 1);
        // Counters must be reset to 0 upon freezing into flushing queue, and moved to flushing counters
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Subsequent write arriving while batch 1 is in flushing queue
        fs.write_at(file, &[0xCC; 20], 160).unwrap();
        // Should NOT trigger another begin_flush()! Queue depth must remain 1
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.staged_bytes(), 20);
        assert_eq!(fs.staged_ops(), 1);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Another small write
        fs.write_at(file, &[0xDD; 20], 180).unwrap();
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.staged_bytes(), 40);
        assert_eq!(fs.staged_ops(), 2);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Now drain flushing batches
        fs.fold_flushing_into_base();

        // Live staged data is preserved and flushing counters are drained to 0
        assert_eq!(fs.staged_bytes(), 40);
        assert_eq!(fs.staged_ops(), 2);
        assert_eq!(fs.flushing_bytes(), 0);
        assert_eq!(fs.flushing_ops(), 0);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_depth() {
        let mut fs = TestFs::builder().build().fs;
        fs.max_flush_queue_depth = 2;

        let file = fs.create_file(1, "bounded.bin", 0o644).unwrap();

        // Populate batch 1
        fs.write_at(file, &[0x11; 30], 0).unwrap();
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 1);

        // Populate batch 2
        fs.write_at(file, &[0x22; 40], 30).unwrap();
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);

        // Queue is now full (len == max_flush_queue_depth == 2).
        // Populate live with batch 3 candidates
        fs.write_at(file, &[0x33; 50], 70).unwrap();
        assert_eq!(fs.staged_bytes(), 50);
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must be a no-op that returns false and leaves live and staged accounting untouched
        assert!(!fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 50);
        assert_eq!(fs.staged_ops(), 1);

        // Verify data in live is intact and readable across layers
        let read = fs.read_file_data(file, 0, 120).unwrap();
        assert_eq!(&read[0..30], &[0x11; 30]);
        assert_eq!(&read[30..70], &[0x22; 40]);
        assert_eq!(&read[70..120], &[0x33; 50]);

        // Pop one batch from flushing queue to make room
        let popped = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(popped.entries.clone());
        assert_eq!(fs.flush_queue_depth(), 1);

        // Now begin_flush should succeed in freezing the accumulated live mutations
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.fold_flushing_into_base();
        assert_eq!(fs.flush_queue_depth(), 0);
        let read_final = fs.read_file_data(file, 0, 120).unwrap();
        assert_eq!(&read_final[0..30], &[0x11; 30]);
        assert_eq!(&read_final[30..70], &[0x22; 40]);
        assert_eq!(&read_final[70..120], &[0x33; 50]);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_bytes() {
        let mut fs = TestFs::builder().build().fs;
        fs.max_flush_queue_depth = 10;
        fs.max_flush_queue_bytes = 100;

        let file = fs.create_file(1, "bytes_bounded.bin", 0o644).unwrap();
        assert!(fs.freeze_now());
        let init = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(init.entries.clone());
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_bytes(), 0);

        // Populate batch 1: 60 bytes
        fs.write_at(file, &[0x11; 60], 0).unwrap();
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_bytes(), 60);

        // Populate batch 2: 40 bytes (total 100 bytes == max_flush_queue_bytes)
        fs.write_at(file, &[0x22; 40], 60).unwrap();
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 100);

        // Queue is now saturated on byte capacity (100 >= 100).
        // Populate live with batch 3 candidates: 30 bytes
        fs.write_at(file, &[0x33; 30], 100).unwrap();
        assert_eq!(fs.staged_bytes(), 30);
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must return false because flushing_bytes >= max_flush_queue_bytes
        assert!(!fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 100);
        assert_eq!(fs.staged_bytes(), 30);
        assert_eq!(fs.staged_ops(), 1);

        // Verify layered read consistency
        let read = fs.read_file_data(file, 0, 130).unwrap();
        assert_eq!(&read[0..60], &[0x11; 60]);
        assert_eq!(&read[60..100], &[0x22; 40]);
        assert_eq!(&read[100..130], &[0x33; 30]);

        // Pop one batch (60 bytes) to free byte capacity
        let popped = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(popped.entries.clone());
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_bytes(), 40);

        // Now begin_flush should succeed
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 70);
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.fold_flushing_into_base();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_bytes(), 0);
        let read_final = fs.read_file_data(file, 0, 130).unwrap();
        assert_eq!(&read_final[0..60], &[0x11; 60]);
        assert_eq!(&read_final[60..100], &[0x22; 40]);
        assert_eq!(&read_final[100..130], &[0x33; 30]);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_ops() {
        let mut fs = TestFs::builder().build().fs;
        fs.max_flush_queue_depth = 10;
        fs.max_flush_queue_ops = 2;

        let file = fs.create_file(1, "ops_bounded.bin", 0o644).unwrap();
        assert!(fs.freeze_now());
        let init = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(init.entries.clone());
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_ops(), 0);

        // Populate batch 1: 1 op
        fs.write_at(file, &[0x11; 10], 0).unwrap();
        assert_eq!(fs.staged_ops(), 1);
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_ops(), 1);

        // Populate batch 2: 1 op -> total 2 ops == max_flush_queue_ops
        fs.write_at(file, &[0x22; 10], 10).unwrap();
        assert_eq!(fs.staged_ops(), 1);
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);

        // Queue is now saturated on op capacity (2 >= 2).
        // Populate live with batch 3 candidates: 1 op
        fs.write_at(file, &[0x33; 10], 20).unwrap();
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must return false because flushing_ops >= max_flush_queue_ops
        assert!(!fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);
        assert_eq!(fs.staged_ops(), 1);

        // Pop one batch (1 op) to free op capacity
        let popped = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(popped.entries.clone());
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_ops(), 1);

        // Now begin_flush should succeed
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.fold_flushing_into_base();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_ops(), 0);
        let read_final = fs.read_file_data(file, 0, 30).unwrap();
        assert_eq!(&read_final[0..10], &[0x11; 10]);
        assert_eq!(&read_final[10..20], &[0x22; 10]);
        assert_eq!(&read_final[20..30], &[0x33; 10]);
    }

    #[test]
    fn test_quiesce_folds_batches_and_mid_drain_freeze_is_threshold_gated() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        fs.max_buffer_size = 100;
        fs.max_staged_ops = 10;

        let file = fs.create_file(1, "test.bin", 0o644).unwrap();
        fs.write_at(file, &[0xAA; 50], 0).unwrap();

        // Perform flush
        fs.quiesce().unwrap();

        // Verify OpTag::Fold metric was recorded
        let stats = fs.inner.op_stats();
        let fold_stat = stats.iter().find(|s| s.tag == OpTag::Fold).unwrap();
        assert!(
            fold_stat.count >= 1,
            "OpTag::Fold must be recorded when folding batches into base"
        );

        // Populate live with 20 bytes (below threshold of 100 bytes / 10 ops)
        fs.write_at(file, &[0xBB; 20], 50).unwrap();
        assert_eq!(fs.staged_bytes(), 20);
        assert_eq!(fs.staged_ops(), 1);

        // The mid-drain re-freeze is threshold-gated: below it, `live` is left alone.
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            assert!(!fs.freeze_if_due_locked(&mut inner));
        }
        assert_eq!(fs.staged_bytes(), 20, "Mutations below threshold should remain in live");
        assert_eq!(fs.staged_ops(), 1);
        assert_eq!(fs.flush_queue_depth(), 0);

        // Record mutations exceeding max_buffer_size directly on inner
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.record_mutation(90, Duration::ZERO); // 20 + 90 = 110 >= 100
            assert!(fs.freeze_if_due_locked(&mut inner));
        }
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.flush_queue_depth(), 1);

        // quiesce drains whatever is queued, thresholds or not
        fs.quiesce().unwrap();
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.flush_queue_depth(), 0);
    }

    #[test]
    fn test_fsync_batch_completion_waiters_concurrent() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = Arc::new(
            TestFs::builder()
                .storage(storage.clone())
                .clock(clock.clone())
                .build()
                .fs,
        );

        let file = fs.create_file(1, "test_fsync.bin", 0o644).unwrap();
        fs.write_at(file, b"waiter data", 0).unwrap();

        // Rollover under lock
        let completion = fs
            .rollover_for_fsync(file, 0, FlushReason::Fsync)
            .unwrap()
            .expect("completion expected");
        assert!(!completion.is_completed());

        // Register 10 concurrent completion callbacks on this exact BatchCompletion
        let unblocked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..10 {
            let counter = Arc::clone(&unblocked);
            completion.add_callback(Box::new(move |res| {
                res.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
            }));
        }

        assert_eq!(
            unblocked.load(Ordering::SeqCst),
            0,
            "No callbacks should fire before flush"
        );

        // Execute flush - commits batch and completes BatchCompletion
        fs.quiesce().unwrap();

        assert_eq!(
            unblocked.load(Ordering::SeqCst),
            10,
            "All completion callbacks must have been invoked"
        );
        assert!(completion.is_completed());
    }

    #[test]
    fn test_every_trigger_stamps_its_own_reason_on_the_batch() {
        for (reason, trigger) in [
            (FlushReason::Fsync, "fsync"),
            (FlushReason::Fsyncdir, "fsyncdir"),
            (FlushReason::Quiesce, "quiesce"),
            (FlushReason::Periodic, "periodic"),
            (FlushReason::Threshold, "threshold"),
        ] {
            let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
            let clock = Arc::new(SystemClock);
            let mut fs = TestFs::builder().storage(storage).clock(clock.clone()).build().fs;
            // Only the threshold case should trip on its own.
            fs.max_buffer_size = if reason == FlushReason::Threshold {
                1
            } else {
                usize::MAX
            };
            let fs = Arc::new(fs);
            // Pose as mounted so nothing drains the batch before we can inspect it.
            fs.flusher.set_background_for_tests(true);

            let file = fs.create_file(1, "r.bin", 0o644).unwrap();
            fs.write_at(file, b"payload", 0).unwrap();

            match reason {
                // Reached through `fsync` and `fsyncdir` respectively, which differ only in
                // the reason they pass down.
                FlushReason::Fsync => {
                    fs.rollover_for_fsync(file, 0, FlushReason::Fsync).unwrap();
                }
                FlushReason::Fsyncdir => {
                    fs.rollover_for_fsync(0, 0, FlushReason::Fsyncdir).unwrap();
                }
                FlushReason::Quiesce => {
                    let mut inner = fs.inner.lock_for_tests().unwrap();
                    fs.pending_completion_locked(&mut inner, FlushReason::Quiesce);
                }
                FlushReason::Periodic => {
                    let mut inner = fs.inner.lock_for_tests().unwrap();
                    inner.freeze_requested.get_or_insert(FlushReason::Periodic);
                    assert!(fs.freeze_if_due_locked(&mut inner));
                }
                // Already frozen by the guard drop when the write crossed the threshold.
                FlushReason::Threshold => {}
            }

            let inner = fs.inner.lock_for_tests().unwrap();
            let batch = inner
                .flushing
                .front()
                .unwrap_or_else(|| panic!("{} must have frozen a batch", trigger));
            assert_eq!(
                batch.reason, reason,
                "batch frozen by {} carries the wrong reason",
                trigger
            );
            assert!(
                inner.freeze_requested.is_none(),
                "the freeze consumes the request that named it"
            );
        }
    }

    #[test]
    fn test_rollover_for_fsync_under_saturation_registers_without_blocking() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs_inst = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        fs_inst.max_flush_queue_depth = 2;
        let fs = Arc::new(fs_inst);

        // Pose as a mounted filesystem, so nothing drains the queue behind our backs.
        fs.flusher.set_background_for_tests(true);

        let file = fs.create_file(1, "saturate.bin", 0o644).unwrap();
        fs.write_at(file, b"batch 1", 0).unwrap();
        assert!(fs.freeze_now());
        fs.write_at(file, b"batch 2", 7).unwrap();
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 2, "queue is saturated at max depth 2");

        fs.write_at(file, b"live data", 14).unwrap();
        assert_eq!(fs.staged_bytes(), 9);

        // The completion belongs to `live`, so fsync can take it without a batch existing
        // yet. No waiting for queue capacity: the handle travels with the data.
        let completion = fs
            .rollover_for_fsync(file, 0, FlushReason::Fsync)
            .unwrap()
            .expect("completion expected");
        assert_eq!(fs.flush_queue_depth(), 2, "a saturated queue must refuse the freeze");
        assert_eq!(fs.staged_bytes(), 9, "the refused freeze leaves live untouched");
        assert_eq!(
            fs.inner.lock_for_tests().unwrap().freeze_requested,
            Some(FlushReason::Fsync),
            "the request outlives the refused freeze, so the flusher honors it later"
        );
        assert!(!completion.is_completed());

        // Free a slot, as the flusher would by writing a batch out.
        let popped = fs.pop_flushing_batch().unwrap();
        fs.fold_entries(popped.entries.clone());

        // The flusher now picks `live` up on the strength of the outstanding request alone -
        // 9 bytes is far below the staged thresholds - and carries the handle into the batch.
        fs.flusher.set_background_for_tests(false);
        fs.quiesce().unwrap();

        assert!(
            completion.is_completed(),
            "the live handle must complete with its batch"
        );
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.staged_bytes(), 0);
        assert!(fs.inner.lock_for_tests().unwrap().freeze_requested.is_none());

        // The data written before the fsync is readable from `base` after the fold.
        assert_eq!(&fs.read_file_data(file, 14, 9).unwrap(), b"live data");
    }

    #[test]
    fn test_flush_log_emits_normalized_directory_deltas() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;

        // Initial setup in batch 1: create file.txt
        let _ = fs.create_file(1, "file.txt", 0o644).unwrap();
        fs.quiesce().unwrap();

        // In batch 2:
        // 1. touch tmp.txt; rm tmp.txt
        let _ = fs.create_file(1, "tmp.txt", 0o644).unwrap();
        fs.remove_file(1, "tmp.txt").unwrap();
        // 2. rename file.txt -> ren.txt -> file.txt
        fs.rename_entry(1, "file.txt", 1, "ren.txt").unwrap();
        fs.rename_entry(1, "ren.txt", 1, "file.txt").unwrap();

        // Flush to disk
        fs.quiesce().unwrap();

        // Read records from the log file
        let log_file = crate::log::log_filename(1);
        let records =
            crate::log::LogReader::open(storage.as_ref(), &log_file, crate::crypto::VolumeKey::plaintext_arc())
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        // Find the InodeDelta record for directory 1 in batch 2
        let mut current_batch = 1;
        let mut dir_deltas_batch2 = Vec::new();
        for rec in &records {
            if rec.header.op_code == crate::log::record::OpCode::FlushCommit {
                let commit: crate::log::record::FlushCommitPayload = crate::wire::deserialize(&rec.payload).unwrap();
                current_batch = commit.batch_id + 1;
            } else if current_batch == 2
                && rec.header.inode == 1
                && rec.header.op_code == crate::log::record::OpCode::InodeDelta
            {
                let delta: crate::log::record::LogEntryDelta = crate::wire::deserialize(&rec.payload).unwrap();
                if let crate::log::record::LogEntryDelta::Node(crate::log::record::LogNodeDelta::Directory(d)) = delta {
                    dir_deltas_batch2.push(d);
                }
            }
        }

        assert_eq!(
            dir_deltas_batch2.len(),
            1,
            "batch 2 must emit exactly one directory delta for root"
        );
        let dir_delta = &dir_deltas_batch2[0];
        assert!(
            dir_delta.added.is_empty(),
            "emitted log delta must have empty added: {:?}",
            dir_delta.added
        );
        assert!(
            dir_delta.removed.is_empty(),
            "emitted log delta must have empty removed: {:?}",
            dir_delta.removed
        );

        // Crash recovery check: recover the filesystem and verify integrity
        let recovered_fs = crate::log::recovery::recover_fs(
            storage,
            crate::log::recovery::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert!(recovered_fs.lookup_child(1, "file.txt").is_some());
        assert!(recovered_fs.lookup_child(1, "tmp.txt").is_none());
        assert!(recovered_fs.lookup_child(1, "ren.txt").is_none());
    }

    #[test]
    fn test_flush_coalesces_multiple_queued_batches() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        fs.max_coalesce_batches = 3;

        // Stage 3 batches manually
        let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
        fs.write_at(f1, b"batch 1 data", 0).unwrap();
        fs.freeze_now();

        let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
        fs.write_at(f2, b"batch 2 data", 0).unwrap();
        fs.freeze_now();

        let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
        fs.write_at(f3, b"batch 3 data", 0).unwrap();
        fs.freeze_now();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 3);

        // Run flush cycle: all 3 should coalesce into 1 on-disk flush
        fs.run_flush_cycle().unwrap();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);
        assert!(fs.lookup_child(1, "f1.txt").is_some());
        assert!(fs.lookup_child(1, "f2.txt").is_some());
        assert!(fs.lookup_child(1, "f3.txt").is_some());

        // Verify log contains all 3 FlushCommit markers
        let records: Vec<_> = crate::log::LogReader::open(
            storage.as_ref(),
            "000001.log",
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

        let flush_commits: Vec<_> = records
            .iter()
            .filter(|r| r.header.op_code == OpCode::FlushCommit)
            .collect();
        assert_eq!(flush_commits.len(), 3);

        // Recovery check
        let recovered = crate::log::recovery::recover_fs(
            storage,
            crate::log::recovery::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert!(recovered.lookup_child(1, "f1.txt").is_some());
        assert!(recovered.lookup_child(1, "f2.txt").is_some());
        assert!(recovered.lookup_child(1, "f3.txt").is_some());
    }

    #[test]
    fn test_coalesce_flush_batches_group_sync_failure_full_rollback() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = Arc::new(crate::storage::FaultStorage::new(mem_storage.clone()));
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(fault_storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        let writer = fs.log_writer.clone().unwrap();
        writer.open_if_unopened().unwrap();
        let initial_offset = writer.current_offset();
        fs.max_coalesce_batches = 3;

        // Stage 3 batches manually
        let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
        fs.write_at(f1, b"batch 1 data", 0).unwrap();
        fs.freeze_now();

        let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
        fs.write_at(f2, b"batch 2 data", 0).unwrap();
        fs.freeze_now();

        let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
        fs.write_at(f3, b"batch 3 data", 0).unwrap();
        fs.freeze_now();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 3);

        // Fail writer.flush() on group sync
        fault_storage.fail_syncs(true);
        let err = fs.run_flush_cycle().unwrap_err();
        assert_eq!(err.to_string(), "simulated sync failure");

        // The entire coalesced group must be rolled back:
        // 1. All 3 batches must still remain in the flushing queue
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 3);
        // 2. Active log file must be truncated back to initial_offset
        assert_eq!(fs.log_writer.as_ref().unwrap().current_offset(), initial_offset);
        // 3. Batch ID counter must be restored
        assert_eq!(fs.log_writer.as_ref().unwrap().last_batch_id(), 0);

        // Clear fault and retry flush
        fault_storage.fail_syncs(false);
        fs.run_flush_cycle().unwrap();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);
        assert_eq!(fs.log_writer.as_ref().unwrap().last_batch_id(), 3);

        // Verify log contains exactly 3 FlushCommit markers without duplicates
        let records: Vec<_> = crate::log::LogReader::open(
            mem_storage.as_ref(),
            "000001.log",
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

        let flush_commits: Vec<_> = records
            .iter()
            .filter(|r| r.header.op_code == OpCode::FlushCommit)
            .collect();
        assert_eq!(flush_commits.len(), 3);

        // Verify recovery restores all 3 files
        let recovered = crate::log::recovery::recover_fs(
            mem_storage,
            crate::log::recovery::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert!(recovered.lookup_child(1, "f1.txt").is_some());
        assert!(recovered.lookup_child(1, "f2.txt").is_some());
        assert!(recovered.lookup_child(1, "f3.txt").is_some());
    }

    #[test]
    fn test_coalesce_flush_batches_partial_failure_prefix_commit_and_retry() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = Arc::new(crate::storage::FaultStorage::new(mem_storage.clone()));
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder()
            .storage(fault_storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        fs.max_coalesce_batches = 3;

        // Stage 3 batches manually
        let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
        fs.write_at(f1, b"batch 1 data", 0).unwrap();
        fs.freeze_now();

        let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
        fs.write_at(f2, b"batch 2 data", 0).unwrap();
        fs.freeze_now();

        let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
        fs.write_at(f3, &vec![0x42; 70 * 1024], 0).unwrap();
        fs.freeze_now();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 3);

        // Batches 1 and 2 write small records (~600 bytes total), which fits easily under 5000 bytes.
        // Batch 3 writes 70 KiB, exceeding the 64 KiB buffered writer capacity and pushing total
        // bytes well beyond the 5000 byte limit. This triggers an append failure specifically in batch 3.
        fault_storage.fail_writes_after_bytes(5000, false);

        let res = fs.run_flush_cycle();
        assert!(res.is_err(), "cycle should report error from failed batch 3");

        // Batches 1 and 2 should have been committed as a durable prefix, popped from flushing,
        // and folded into base. Only batch 3 remains in flushing.
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 1);
        assert_eq!(fs.log_writer.as_ref().unwrap().last_batch_id(), 2);
        assert!(fs.lookup_child(1, "f1.txt").is_some());
        assert!(fs.lookup_child(1, "f2.txt").is_some());

        // Clear faults and retry flush cycle
        fault_storage.clear_write_limit();
        fs.run_flush_cycle().unwrap();

        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);
        assert_eq!(fs.log_writer.as_ref().unwrap().last_batch_id(), 3);
        assert!(fs.lookup_child(1, "f3.txt").is_some());

        // Verify log contains exactly 3 FlushCommit markers with sequential IDs 1, 2, 3
        let records: Vec<_> = crate::log::LogReader::open(
            mem_storage.as_ref(),
            "000001.log",
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

        let flush_commits: Vec<_> = records
            .iter()
            .filter(|r| r.header.op_code == OpCode::FlushCommit)
            .collect();
        assert_eq!(flush_commits.len(), 3);

        // Verify recovery restores all 3 files
        let recovered = crate::log::recovery::recover_fs(
            mem_storage,
            crate::log::recovery::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert!(recovered.lookup_child(1, "f1.txt").is_some());
        assert!(recovered.lookup_child(1, "f2.txt").is_some());
        assert!(recovered.lookup_child(1, "f3.txt").is_some());
    }

    #[test]
    fn test_coalesce_batch_waiters_notified_on_sync_before_fold() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let mut fs = TestFs::builder().storage(storage).clock(clock).build().fs;
        fs.max_coalesce_batches = 2;
        let fs = Arc::new(fs);

        let f1 = fs.create_file(1, "test.bin", 0o644).unwrap();
        fs.write_at(f1, b"hello world", 0).unwrap();
        fs.freeze_now();

        // Retrieve the frozen batch's completion handle
        let completion = {
            let inner = fs.inner.lock_for_tests().unwrap();
            inner.flushing.front().unwrap().completion.clone()
        };

        // Attach callback that verifies batch is still in flushing and not yet folded into base
        let callback_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_ran_clone = callback_ran.clone();
        let fs_clone = fs.clone();
        let test_ino = f1;
        completion.add_callback(Box::new(move |res| {
            assert!(res.is_ok());
            callback_ran_clone.store(true, Ordering::SeqCst);
            let inner = fs_clone.inner.lock_for_tests().unwrap();
            // Waiter is notified right after physical disk sync:
            // 1. The batch has NOT yet been popped from flushing
            assert_eq!(inner.flushing.len(), 1);
            // 2. The new file has NOT yet been folded into base
            assert!(
                !inner.base.contains_key(&test_ino),
                "base must not have folded the inode yet"
            );
        }));

        assert!(!callback_ran.load(Ordering::SeqCst));
        fs.run_flush_cycle().unwrap();
        assert!(callback_ran.load(Ordering::SeqCst));

        // After run_flush_cycle completes, base has the folded file and flushing is empty
        let inner = fs.inner.lock_for_tests().unwrap();
        assert_eq!(inner.flushing.len(), 0);
        assert!(inner.base.contains_key(&f1), "base must now contain the folded inode");
    }
}
