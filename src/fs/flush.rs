//! Freezing `live`, writing delta log records, and folding batches into `base`.
//!
//! A flush freezes `live` into the `flushing` queue, writes pending data payloads and
//! serialized `LogEntryDelta` records directly to the active log file, and emits a
//! trailing `FlushCommit` confirming atomic persistence. Recovery replays `LogEntryDelta`
//! records directly onto `base`, guaranteeing identical state transitions across crash recovery.

#[cfg(any(test, feature = "testing"))]
use super::TestFlusher;
use super::{FlushBatch, FlushHost, FlushMotivation, FlushRecord, FsInner, InMemoryFS};
use crate::extent_map::Extent;
use crate::log::{GenerationLiveStats, LogEntryDelta, LogWriter, OpCode, RECORD_HEADER_SIZE};
use crate::node::{EntryDelta, NodeDelta, NodeKind};
use crate::storage::Storage;
use crate::sync::OpTag;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn sync_manifest_md5s_and_snapshot(
    manifest_lock: &Arc<RwLock<crate::log::LogManifest>>,
    storage: &dyn Storage,
    active_gen: u64,
) -> crate::log::LogManifest {
    let needed: Vec<(u64, String)> = {
        let m = manifest_lock.read().unwrap();
        m.logs
            .iter()
            .filter(|l| l.generation < active_gen && l.md5.is_none())
            .map(|l| (l.generation, l.filename.clone()))
            .collect()
    };

    let mut computed = Vec::new();
    for (generation_num, fname) in needed {
        if storage.exists(&fname)
            && let Ok(digest) = crate::log::manifest::compute_storage_file_md5(storage, &fname)
        {
            computed.push((generation_num, digest));
        }
    }

    let mut m = manifest_lock.write().unwrap();
    for (generation_num, digest) in computed {
        m.set_generation_md5(generation_num, digest);
    }
    m.clone()
}

impl FlushHost for InMemoryFS {
    fn get_next_flush_batch(&self) -> Option<FlushBatch> {
        let inner = self.inner.lock(OpTag::Flush).unwrap();
        inner.flushing.front().cloned()
    }

    fn persist_flush_batch(&self, batch: &mut FlushBatch) -> std::io::Result<u64> {
        let Some(ref writer) = self.log_writer else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ReadOnlyFilesystem,
                "cannot persist without log writer",
            ));
        };
        let max_extent_size = self.max_extent_size.clamp(1, u32::MAX as usize);
        let estimated_bytes = {
            let entries = batch.entries.read().unwrap();
            estimate_batch_bytes(&entries, max_extent_size)
        };
        self.roll_log_if_needed(writer, estimated_bytes)?;
        let mut entries = batch.entries.write().unwrap();
        self.synthesize_and_write_flushing_layer(&mut entries, writer)
    }

    fn fold_flush_batch(&self, batch: &FlushBatch) {
        let mut inner = self.inner.lock(OpTag::Fold).unwrap();
        let entries = batch.entries.read().unwrap();
        inner.apply_base_deltas_ref(&entries);
    }

    fn remove_front_flush_batch(&self, batch_id: u64) {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        let popped = inner.pop_front_batch(batch_id);

        if inner.live_completion.is_some()
            || inner.staged_bytes >= self.max_buffer_size
            || inner.staged_ops >= self.max_staged_ops
        {
            let motivation = if inner.live_completion.is_some() {
                FlushMotivation::Fsync
            } else {
                FlushMotivation::Threshold
            };
            inner.freeze_live(
                self.max_flush_queue_depth,
                self.max_flush_queue_bytes,
                self.max_flush_queue_ops,
                motivation,
                self.clock.now(),
            );
        }

        drop(inner);

        if let Some(batch) = popped {
            batch.completion.complete(Ok(()));
        }
    }

    fn freeze_idle(&self) {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        if !inner.live.is_empty() {
            inner.freeze_live(
                self.max_flush_queue_depth,
                self.max_flush_queue_bytes,
                self.max_flush_queue_ops,
                FlushMotivation::TimeBased,
                self.clock.now(),
            );
        }
    }
}

impl InMemoryFS {
    /// Starts or restarts the background flusher thread responsible for emptying the flushing queue.
    pub fn start_flusher(self: &Arc<Self>) {
        let interval_secs = self.flush_interval.load(Ordering::SeqCst);
        let interval = Duration::from_secs(interval_secs);
        let host = Arc::clone(self) as Arc<dyn FlushHost>;
        self.flusher.start(host, interval, Arc::clone(&self.clock));
    }

    fn roll_log_if_needed(&self, writer: &LogWriter, estimated_bytes: u64) -> std::io::Result<()> {
        if let Some((next_gen, sealed_md5)) = writer.roll_if_needed(estimated_bytes, &*self.clock)? {
            if let Some(md5) = sealed_md5 {
                let sealed_gen = next_gen - 1;
                {
                    let mut manifest = self.manifest.write().unwrap();
                    manifest.set_generation_md5(sealed_gen, md5);
                    manifest.record_roll(next_gen, self.clock.now(), crate::log::record::FILE_HEADER_SIZE as u64);
                }

                self.generations_since_last_summary.fetch_add(1, Ordering::SeqCst);

                let bytes_interval = self.summary_interval_bytes.load(Ordering::SeqCst);
                let gen_interval = self.summary_interval_generations.load(Ordering::SeqCst);
                let bytes_since = self.bytes_since_last_summary.load(Ordering::SeqCst);
                let gens_since = self.generations_since_last_summary.load(Ordering::SeqCst);

                let should_emit_summary = (bytes_interval > 0 && bytes_since >= bytes_interval)
                    || (gen_interval > 0 && gens_since >= gen_interval);

                if should_emit_summary {
                    let storage = writer.storage();
                    let last_tx_id = writer.last_tx_id();
                    match self.export_summary_for_base(storage.as_ref(), sealed_gen, last_tx_id) {
                        Ok(filename) => {
                            self.bytes_since_last_summary.store(0, Ordering::SeqCst);
                            self.generations_since_last_summary.store(0, Ordering::SeqCst);
                            self.last_summary_generation.store(sealed_gen, Ordering::SeqCst);
                            log::info!(
                                "Exported periodic summary snapshot {} for sealed generation {} (last_tx_id: {})",
                                filename,
                                sealed_gen,
                                last_tx_id
                            );
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
            } else {
                let mut manifest = self.manifest.write().unwrap();
                manifest.record_roll(next_gen, self.clock.now(), crate::log::record::FILE_HEADER_SIZE as u64);
            }
            self.notify_replication();
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn synthesize_and_write_flushing_layer(
        &self,
        frozen: &mut HashMap<u64, EntryDelta>,
        writer: &LogWriter,
    ) -> std::io::Result<u64> {
        let max_extent_size = self.max_extent_size.clamp(1, u32::MAX as usize);
        let batch_gen = writer.generation();
        let batch_start_offset = writer.current_offset();
        writer.checkpoint_batch_start();

        let mut original_extents: HashMap<u64, crate::extent_map::ExtentMap> = HashMap::new();

        let write_res = (|| -> std::io::Result<u64> {
            let mut written_count = 0u32;
            let mut flushed_data_bytes = 0u64;

            let mut inos: Vec<u64> = frozen.keys().cloned().collect();
            inos.sort();

            // 1. Flush raw file data chunks
            for &ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::File(f))) = frozen.get_mut(&ino) {
                    let staged_runs: Vec<(u64, u32, Vec<u8>)> = {
                        let mut runs: Vec<(u64, u32, Vec<u8>)> = Vec::new();
                        let mut current_run: Option<(u64, Vec<u8>)> = None;

                        for (&offset, entry) in f.extents.iter() {
                            if let Extent::Staged {
                                data,
                                payload_offset,
                                length,
                            } = &entry.extent
                            {
                                let guard = data.read().unwrap();
                                let slice = &guard[*payload_offset as usize..(*payload_offset + *length) as usize];
                                match current_run {
                                    Some((start_off, ref mut bytes)) if start_off + bytes.len() as u64 == offset => {
                                        bytes.extend_from_slice(slice);
                                    }
                                    Some((start_off, bytes)) => {
                                        runs.push((start_off, bytes.len() as u32, bytes));
                                        current_run = Some((offset, slice.to_vec()));
                                    }
                                    None => {
                                        current_run = Some((offset, slice.to_vec()));
                                    }
                                }
                            } else if let Some((start_off, bytes)) = current_run.take() {
                                runs.push((start_off, bytes.len() as u32, bytes));
                            }
                        }
                        if let Some((start_off, bytes)) = current_run {
                            runs.push((start_off, bytes.len() as u32, bytes));
                        }
                        runs
                    };

                    if !staged_runs.is_empty() {
                        original_extents.insert(ino, f.extents.clone());
                    }

                    // Emit each run as one or more records of at most `max_extent_size`. A
                    // record is the unit of decryption, so an uncapped run would make a read
                    // of any byte within it decrypt the entire coalesced write.
                    for (start_off, _length, data) in staged_runs {
                        let mut chunk_start = 0usize;
                        loop {
                            let chunk_len = std::cmp::min(max_extent_size, data.len() - chunk_start);
                            let chunk = &data[chunk_start..chunk_start + chunk_len];

                            let (_, generation, record_log_offset, record_size) =
                                writer.append_record(OpCode::Data, ino, chunk)?;
                            written_count += 1;
                            flushed_data_bytes += chunk_len as u64;

                            let disk_extent =
                                Extent::new_disk(generation, record_log_offset, record_size, 0, chunk_len as u32);
                            f.extents.insert(start_off + chunk_start as u64, disk_extent);

                            chunk_start += chunk_len;
                            if chunk_start >= data.len() {
                                break;
                            }
                        }
                    }
                }
            }

            // 2. Flush Inode Delta records
            for &ino in &inos {
                if let Some(entry_delta) = frozen.get(&ino) {
                    let log_entry = LogEntryDelta::from(entry_delta);
                    let payload = crate::wire::serialize(&log_entry)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    writer.append_record(OpCode::InodeDelta, ino, &payload)?;
                    written_count += 1;
                }
            }

            // 3. Emit FlushCommit trailer
            writer.emit_flush_commit(written_count, &*self.clock)?;
            writer.flush()?;

            let active_gen = writer.generation();
            let active_offset = writer.current_offset();
            {
                let mut manifest = self.manifest.write().unwrap();
                if manifest.get_by_generation(active_gen).is_none() {
                    manifest.record_roll(
                        active_gen,
                        self.clock.now(),
                        crate::log::record::FILE_HEADER_SIZE as u64,
                    );
                }
                if let Some(entry) = manifest.get_mut_by_generation(active_gen) {
                    entry.record_count += written_count + 1; // including FlushCommit
                    entry.total_data_bytes += flushed_data_bytes;
                    entry.total_bytes = active_offset;
                }
            }
            Ok(flushed_data_bytes)
        })();

        let flushed_data_bytes = match write_res {
            Ok(bytes) => bytes,
            Err(e) => {
                for (ino, orig) in original_extents {
                    if let Some(EntryDelta::Node(NodeDelta::File(f))) = frozen.get_mut(&ino) {
                        f.extents = orig;
                    }
                }
                let _ = writer.rollback_to(batch_gen, batch_start_offset);
                return Err(e);
            }
        };

        self.bytes_since_last_summary
            .fetch_add(flushed_data_bytes, Ordering::SeqCst);

        Ok(flushed_data_bytes)
    }

    // --- Flush & Fold Pipelines ---

    /// Freezes `live` into the `flushing` queue with an explicit `FlushMotivation`.
    pub fn begin_flush(&self, motivation: FlushMotivation) -> bool {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        self.begin_flush_locked(&mut inner, motivation)
    }

    /// Freezes `live` into the `flushing` queue with the inner lock already held and explicit `motivation`.
    pub fn begin_flush_locked(&self, inner: &mut FsInner, motivation: FlushMotivation) -> bool {
        inner.freeze_live(
            self.max_flush_queue_depth,
            self.max_flush_queue_bytes,
            self.max_flush_queue_ops,
            motivation,
            self.clock.now(),
        )
    }

    /// Freezes active `live` mutations into a `FlushBatch` with explicit `FlushMotivation`.
    ///
    /// If `fh != 0`, the file handle is validated against `ino` under the lock.
    pub fn rollover_for_sync(
        &self,
        ino: u64,
        fh: u64,
        motivation: FlushMotivation,
    ) -> Result<Option<super::BatchCompletion>, i32> {
        let mut inner = self.inner.lock(OpTag::Flush).unwrap();
        if fh != 0 {
            inner.validate_regular_handle(ino, fh)?;
        }
        if self.log_writer.is_none() {
            return Ok(None);
        }
        if !inner.live.is_empty() {
            let completion = inner
                .live_completion
                .get_or_insert_with(super::BatchCompletion::new)
                .clone();
            inner.live_motivation.get_or_insert(motivation);
            self.begin_flush_locked(&mut inner, motivation);
            let flusher = &self.flusher;
            inner.defer(move || {
                flusher.trigger();
            });
            return Ok(Some(completion));
        }

        // Live is empty. If there are batches in flight, wait on the latest one.
        if let Some(back) = inner.flushing.back() {
            let completion = back.completion.clone();
            let flusher = &self.flusher;
            inner.defer(move || {
                flusher.trigger();
            });
            return Ok(Some(completion));
        }

        // No live mutations and no flushing batches.
        Ok(None)
    }

    /// Directly applies replayed log deltas into `base` without requiring a `FlushBatch` wrapper.
    pub fn apply_delta_batch(&self, deltas: HashMap<u64, EntryDelta>) {
        let mut inner = self.inner.lock(OpTag::Fold).unwrap();
        inner.apply_base_deltas(deltas);
    }

    /// Steps a single batch from the `flushing` queue under the flusher lock.
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn step_flush(&self) -> std::io::Result<Option<FlushRecord>> {
        TestFlusher::with_flusher(self, &self.flusher, Arc::clone(&self.clock)).step()
    }

    /// Flushes all pending mutations and batches to disk via the flusher.
    pub fn flush_log(&self) -> std::io::Result<()> {
        if self.flusher.is_background_active() {
            self.flush_with_motivation(FlushMotivation::Manual).map(|_| ())
        } else {
            #[cfg(any(test, feature = "testing"))]
            {
                self.flush_to_base().map(|_| ())
            }
            #[cfg(not(any(test, feature = "testing")))]
            {
                Ok(())
            }
        }
    }

    /// Flushes mutations if threshold is reached and waits for flusher to drain.
    #[cfg(any(test, feature = "testing"))]
    pub fn flush_log_locked(&self, _writer: &LogWriter) -> std::io::Result<()> {
        let (froze, completion) = {
            let mut inner = self.inner.lock(OpTag::Flush).unwrap();
            let froze = if inner.staged_bytes >= self.max_buffer_size || inner.staged_ops >= self.max_staged_ops {
                self.begin_flush_locked(&mut inner, FlushMotivation::Threshold)
            } else {
                false
            };
            (froze, inner.flushing.back().map(|b| b.completion.clone()))
        };
        if froze {
            if !self.flusher.is_background_active() {
                let test_flusher = TestFlusher::with_flusher(self, &self.flusher, Arc::clone(&self.clock));
                test_flusher.drain()?;
            } else {
                self.trigger_flusher();
                if let Some(comp) = completion {
                    comp.wait_blocking()?;
                }
            }
        }
        Ok(())
    }

    /// Flushes all pending mutations and batches with an explicit `FlushMotivation`.
    pub fn flush_with_motivation(&self, motivation: FlushMotivation) -> std::io::Result<usize> {
        if !self.flusher.is_background_active() {
            #[cfg(any(test, feature = "testing"))]
            {
                let mut total_drained = 0;
                let test_flusher = TestFlusher::with_flusher(self, &self.flusher, Arc::clone(&self.clock));
                loop {
                    self.begin_flush(motivation);
                    let drained = test_flusher.drain()?;
                    total_drained += drained;
                    let inner = self.inner.lock(OpTag::Flush).unwrap();
                    if inner.live.is_empty() && inner.flushing.is_empty() {
                        break;
                    }
                }
                return Ok(total_drained);
            }
            #[cfg(not(any(test, feature = "testing")))]
            {
                return Ok(0);
            }
        }

        let (count, completion) = {
            let mut inner = self.inner.lock(OpTag::Flush).unwrap();
            let mut count = inner.flushing.len();
            if !inner.live.is_empty() {
                let comp = inner
                    .live_completion
                    .get_or_insert_with(super::BatchCompletion::new)
                    .clone();
                inner.live_motivation.get_or_insert(motivation);
                if self.begin_flush_locked(&mut inner, motivation) {
                    count += 1;
                }
                (count, Some(comp))
            } else {
                (count, inner.flushing.back().map(|b| b.completion.clone()))
            }
        };
        if count == 0 && completion.is_none() {
            return Ok(0);
        }
        self.flusher.trigger();
        if let Some(comp) = completion {
            comp.wait_blocking()?;
        }
        let _flush_guard = self.flusher.lock();
        Ok(count)
    }

    /// Freezes all pending mutations and folds all queued batches into `base`.
    #[cfg(any(test, feature = "testing"))]
    pub fn flush_to_base(&self) -> std::io::Result<usize> {
        self.flush_with_motivation(FlushMotivation::Manual)
    }

    /// Safely rolls the active log generation under the flush lock, draining pending batches first.
    pub fn force_roll_active_log(&self) -> std::io::Result<Option<(u64, [u8; 16])>> {
        let Some(ref writer) = self.log_writer else {
            return Ok(None);
        };

        // Drain pending batches first via the flusher so the current generation is cleanly flushed
        self.flush_log()?;

        let _flush_guard = self.flusher.lock();
        if let Some((next_gen, sealed_md5)) = writer.force_roll(&*self.clock)? {
            let sealed_gen = next_gen - 1;
            {
                let mut manifest = self.manifest.write().unwrap();
                manifest.set_generation_md5(sealed_gen, sealed_md5);
                manifest.record_roll(next_gen, self.clock.now(), crate::log::record::FILE_HEADER_SIZE as u64);
            }
            self.notify_replication();
            Ok(Some((next_gen, sealed_md5)))
        } else {
            Ok(None)
        }
    }

    /// Number of frozen batches currently waiting to be written to the log.
    #[cfg(any(test, feature = "testing"))]
    pub fn flush_queue_depth(&self) -> usize {
        self.inner.lock(OpTag::Stats).unwrap().flushing.len()
    }

    /// Returns a snapshot of the most recent flush operations recorded in the ring buffer.
    pub fn recent_flushes(&self) -> Vec<FlushRecord> {
        self.flusher.recent_flushes()
    }

    /// Clears all recorded flush operations from the ring buffer.
    pub fn clear_flush_records(&self) {
        self.flusher.clear_records();
    }

    /// Wakes up the background periodic flusher immediately to drain pending batches.
    /// Returns true if a background flusher is active and was notified, false otherwise.
    pub fn trigger_flusher(&self) -> bool {
        self.flusher.trigger()
    }

    /// Wakes up the background periodic flusher immediately if thresholds were reached.
    pub fn notify_flush_trigger(&self, should_trigger: bool) {
        if should_trigger {
            self.flusher.trigger();
            std::thread::yield_now();
        }
    }

    /// Initializes background services upon FUSE mount.
    pub fn init(self: &Arc<Self>) {
        if self.is_read_only() || self.log_writer.is_none() {
            self.flusher.stop_background();
            return;
        }
        self.start_flusher();
    }

    /// Cleanly stops background services and drains in-flight async operations upon FUSE unmount.
    pub fn destroy(&self) {
        self.flusher.stop_background();
        self.drain_async_ops();
    }

    pub fn sync_log(&self) -> std::io::Result<()> {
        self.flush_log()?;
        if let Some(ref writer) = self.log_writer {
            writer.sync()?;
        }
        Ok(())
    }

    /// Dynamically calculates live extent statistics across all active files and log generations.
    pub fn calculate_generation_live_stats(&self) -> Vec<GenerationLiveStats> {
        let manifest = self.manifest.read().unwrap().clone();
        let base = self.inner.lock(OpTag::Stats).unwrap().base.clone();

        let mut live_map: HashMap<u64, (u64, u32)> = HashMap::new();
        for node_arc in base.values() {
            let node = node_arc.as_ref();
            if let NodeKind::File { extent_map, .. } = &node.kind {
                for (_, entry) in extent_map.iter() {
                    if let Extent::Disk { generation, length, .. } = &entry.extent {
                        let stats = live_map.entry(*generation).or_insert((0, 0));
                        stats.0 += *length as u64;
                        stats.1 += 1;
                    }
                }
            }
        }

        let mut result = Vec::new();
        for log in &manifest.logs {
            let (live_bytes, live_extents) = live_map.get(&log.generation).copied().unwrap_or((0, 0));
            let live_ratio = if log.total_data_bytes > 0 {
                live_bytes as f64 / log.total_data_bytes as f64
            } else {
                0.0
            };
            result.push(GenerationLiveStats {
                generation: log.generation,
                filename: log.filename.clone(),
                record_count: log.record_count,
                total_bytes: log.total_bytes,
                total_data_bytes: log.total_data_bytes,
                live_bytes,
                live_extents,
                live_ratio,
            });
        }
        result
    }

    /// Performs a comprehensive, read-only integrity check of the filesystem state.
    pub fn check_integrity(&self, log_dir: Option<&Path>, verify_data: bool) -> crate::check::IntegrityReport {
        crate::check::check_fs_integrity(self, log_dir, verify_data)
    }

    fn sync_manifest_md5s_and_snapshot(&self, storage: &dyn Storage, active_gen: u64) -> crate::log::LogManifest {
        sync_manifest_md5s_and_snapshot(&self.manifest, storage, active_gen)
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
        if self.log_writer.is_some() {
            self.sync_log()?;
        }
        let snapshot = self.inner.lock(OpTag::Flush).unwrap().snapshot_all();
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self
            .log_writer
            .as_ref()
            .map_or_else(|| self.last_tx_id.load(Ordering::SeqCst), |w| w.last_tx_id());
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let manifest = self.sync_manifest_md5s_and_snapshot(storage, generation);
        let now = self.clock.now();

        // The header goes into the summary in plaintext while the key encrypts its body, so
        // a pair that disagrees writes a snapshot nothing can reopen - it would advertise
        // itself as unencrypted to `resolve_volume_key` while holding an encrypted body.
        // Refuse rather than emit one. `InMemoryFS::with_log` can produce such a pair, since
        // it adopts the writer's key while the header stays at its plaintext default.
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
        let res = crate::log::summary::export_summary_with_iv(
            &crate::log::summary::SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &self.volume_header,
                generation,
                last_tx_id,
                next_inode,
                created_at: now,
            },
            storage,
            &self.volume_key,
            explicit_iv,
        );

        if res.is_ok() {
            self.bytes_since_last_summary.store(0, Ordering::SeqCst);
            self.generations_since_last_summary.store(0, Ordering::SeqCst);
            self.last_summary_generation.store(generation, Ordering::SeqCst);
        }

        res
    }

    /// Exports a single-file summary snapshot capturing the committed `base` layer for a sealed generation.
    pub fn export_summary_for_base(
        &self,
        storage: &dyn Storage,
        sealed_gen: u64,
        last_tx_id: u64,
    ) -> std::io::Result<String> {
        let snapshot = self.inner.lock(OpTag::Flush).unwrap().base.clone();
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let manifest = sync_manifest_md5s_and_snapshot(&self.manifest, storage, sealed_gen + 1);
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
                last_tx_id,
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
        let Some(ref writer) = self.log_writer else {
            return Ok(None);
        };
        self.sync_log()?;
        if !writer.is_open() {
            // Read-only session where no log records were ever flushed or written
            return Ok(None);
        }
        let storage = writer.storage();
        match self.export_summary_with_iv(storage.as_ref(), explicit_iv) {
            Ok(filename) => {
                self.notify_replication();
                Ok(Some(filename))
            }
            Err(e) => {
                log::warn!("sync_and_export_summary error: {}", e);
                Err(e)
            }
        }
    }
}

/// Upper bound on the bytes this batch will append.
/// Upper bound on the bytes a frozen batch will occupy, used only to decide whether it fits
/// in the current generation before any of it is written.
///
/// Compression makes the bound looser - payloads shrink after this runs - but it stays an
/// upper bound, and the looseness costs at most one batch of slack at a generation boundary
/// rather than shrinking files generally. Feeding an observed ratio back here would trade
/// that for extra state on a hot path.
fn estimate_batch_bytes(frozen: &HashMap<u64, EntryDelta>, max_extent_size: usize) -> u64 {
    let mut estimated_bytes: u64 = RECORD_HEADER_SIZE as u64 + 64; // FlushCommit
    for entry in frozen.values() {
        match entry {
            EntryDelta::Node(NodeDelta::File(f)) => {
                for (_, entry) in f.extents.iter() {
                    if let Extent::Staged { length, .. } = &entry.extent {
                        // One header per emitted chunk. Coalescing can merge adjacent staged
                        // extents into fewer records than this, so it stays an upper bound.
                        let chunks = (*length as u64).div_ceil(max_extent_size as u64).max(1);
                        estimated_bytes += chunks * RECORD_HEADER_SIZE as u64 + *length as u64;
                    }
                }
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 256 + f.extents.len() as u64 * 24;
            }
            EntryDelta::Node(NodeDelta::Directory(d)) => {
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 256 + (d.added.len() + d.removed.len()) as u64 * 64;
            }
            EntryDelta::Node(NodeDelta::Symlink(s)) => {
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 256 + s.target.as_ref().map_or(0, |t| t.len() as u64);
            }
            EntryDelta::Node(_) => {
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 256;
            }
            EntryDelta::Tombstone => {
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
            }
        }
    }
    estimated_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::extent_map::ExtentMap;
    use crate::log::BackgroundFlusher;
    use crate::node::{AttrDelta, FileDelta, InodeMeta, Node, NodeDelta, NodeKind};
    use crate::operations::read_write::write_core;
    use crate::storage::Storage;
    use std::time::SystemTime;

    fn make_test_fs_with_log(clock: Arc<dyn Clock>) -> InMemoryFS {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        InMemoryFS::with_clock_and_log(clock, Some(writer))
    }

    #[test]
    fn test_flush_coalesces_micro_writes_into_single_base_range_entry() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = SystemClock;
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_log(writer);

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
            write_core(&fs, ino, &byte, i as i64).unwrap();
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
        fs.sync_log().unwrap();

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

            let volume_key = if encrypted {
                let master = crate::crypto::MasterKey::new([0x42u8; 32]);
                let (_, key) = crate::crypto::VolumeHeader::new_encrypted(
                    &master,
                    [0u8; 16],
                    crate::crypto::KeySource::KeyFile,
                    crate::compress::Compression::None,
                )
                .unwrap();
                Arc::new(key)
            } else {
                crate::crypto::VolumeKey::plaintext_arc()
            };

            let writer = Arc::new(
                LogWriter::create(
                    Arc::clone(&storage),
                    1,
                    &SystemClock,
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    Arc::clone(&volume_key),
                )
                .unwrap(),
            );
            let mut fs = InMemoryFS::with_log(writer);
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
            write_core(&fs, ino, &payload, 0).unwrap();
            fs.sync_log().unwrap();

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
        let writer = Arc::new(
            LogWriter::create(
                Arc::clone(&storage),
                1,
                &SystemClock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_log(writer);

        let attr = crate::operations::read_write::create_core(&fs, 1, "holey.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251 + 1) as u8).collect();
        write_core(&fs, ino, &payload, 0).unwrap();

        // Flush first, so the data is a durable `Disk` extent in `base` and the punch below
        // lands in a fresh, higher layer - the case that actually needs masking.
        fs.sync_log().unwrap();
        assert_eq!(fs.read_file_data(ino, 0, 1000).unwrap(), payload);

        crate::operations::read_write::punch_hole_core(&fs, ino, 200, 300).unwrap();

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
        fs.sync_log().unwrap();
        expect_holed(&fs.read_file_data(ino, 0, 1000).unwrap());

        let stats = fs.calculate_generation_live_stats();
        let live_bytes: u64 = stats.iter().map(|s| s.live_bytes).sum();
        assert_eq!(
            live_bytes, 700,
            "punched bytes must stop counting as live, so compaction can reclaim them"
        );

        // And it has to survive replay - this is where a silently-dropped Zero extent would
        // show up, with the old data reappearing. Check both routes: replaying the `.log`
        // (LogExtent) and loading a `.summary` (SerializedExtent), which encode the hole
        // sentinel independently of each other.
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
        let writer = Arc::new(
            LogWriter::create(
                Arc::clone(&storage),
                1,
                &SystemClock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_log(writer);

        let attr = crate::operations::read_write::create_core(&fs, 1, "t.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251 + 1) as u8).collect();
        write_core(&fs, ino, &payload, 0).unwrap();

        // Flush so the data is durable in `base` and the truncates below land in a layer
        // above it - the case where masking actually has to do something.
        fs.sync_log().unwrap();

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
        fs.sync_log().unwrap();
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
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "short.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;
        write_core(&fs, ino, &[0xAB; 100], 0).unwrap();

        crate::operations::read_write::punch_hole_core(&fs, ino, 4096, 4096).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 100, "punch past EOF must not extend");
        assert_eq!(fs.read_file_data(ino, 0, 100).unwrap(), vec![0xAB; 100]);

        // Straddling EOF punches only the part that exists.
        crate::operations::read_write::punch_hole_core(&fs, ino, 50, 4096).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 100, "straddling punch must not extend");
        let data = fs.read_file_data(ino, 0, 100).unwrap();
        assert_eq!(&data[..50], &[0xAB; 50]);
        assert!(data[50..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_directory_parent_tracking_across_mkdir_rename_and_flush() {
        let clock = Arc::new(crate::clock::MockClock(SystemTime::UNIX_EPOCH));
        let fs = make_test_fs_with_log(clock);

        // Root inode 1 parent is 1
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));

        // Create dir1 (child of root)
        let dir1 = crate::operations::dir::mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));

        // Create dir2 (child of dir1)
        let dir2 = crate::operations::dir::mkdir_core(&fs, dir1, "dir2", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir1));

        // Create dir3 (child of root)
        let dir3 = crate::operations::dir::mkdir_core(&fs, 1, "dir3", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));

        // Move dir2 from dir1 into dir3
        crate::operations::links::rename_core(&fs, dir1, "dir2", dir3, "dir2_moved").unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));

        // Fold live to base
        fs.flush_to_base().unwrap();

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
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

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
        crate::operations::read_write::write_core(&fs, ino1, &data1, 0).unwrap();
        fs.sync_log().unwrap();

        // Check manifest and stats after gen 1 write
        let stats = fs.calculate_generation_live_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].generation, 1);
        assert_eq!(stats[0].filename, "000001.log");
        assert_eq!(stats[0].total_data_bytes, 100);
        assert_eq!(stats[0].live_bytes, 100);
        assert_eq!(stats[0].live_extents, 1);
        assert!((stats[0].live_ratio - 1.0).abs() < 1e-6);

        // Overwrite 40 bytes of file1 (offset 0..40)
        let overwrite_data = vec![0xBB; 40];
        crate::operations::read_write::write_core(&fs, ino1, &overwrite_data, 0).unwrap();
        fs.sync_log().unwrap();

        // Now gen 1 only has 60 live bytes (offset 40..100) and gen 1 total data is 140 bytes
        let stats = fs.calculate_generation_live_stats();
        assert_eq!(stats[0].total_data_bytes, 140);
        assert_eq!(stats[0].live_bytes, 100); // 60 from 1st write + 40 from 2nd write (both landed in gen 1)
        assert_eq!(stats[0].live_extents, 2);
        assert!((stats[0].live_ratio - (100.0 / 140.0)).abs() < 1e-6);

        // Export summary snapshot
        let summary_file = fs.export_summary(storage.as_ref()).unwrap();
        assert!(storage.exists(&summary_file));

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
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Create /Gletscher, /Gletscher/sub, and files
        let gletscher_attr = crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();
        let gletscher_ino = gletscher_attr.ino;

        let file1_attr =
            crate::operations::read_write::create_core(&fs, gletscher_ino, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file1_attr.ino, &[1, 2, 3, 4], 0).unwrap();

        let file2_attr =
            crate::operations::read_write::create_core(&fs, gletscher_ino, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file2_attr.ino, &[5, 6, 7, 8], 0).unwrap();

        let sub_attr = crate::operations::dir::mkdir_core(&fs, gletscher_ino, "sub", 0o755, 1000, 1000).unwrap();
        let sub_ino = sub_attr.ino;

        let file3_attr =
            crate::operations::read_write::create_core(&fs, sub_ino, "file3.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file3_attr.ino, &[9, 10, 11, 12], 0).unwrap();

        // Flush creation to disk
        fs.sync_log().unwrap();

        // Verify live stats show 3 files and 12 live bytes
        let stats_before = fs.calculate_generation_live_stats();
        assert_eq!(stats_before[0].live_bytes, 12);
        assert_eq!(stats_before[0].live_extents, 3);

        // 2. Perform rm -rf /Gletscher
        crate::operations::links::unlink_core(&fs, sub_ino, "file3.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, gletscher_ino, "sub").unwrap();
        crate::operations::links::unlink_core(&fs, gletscher_ino, "file1.txt").unwrap();
        crate::operations::links::unlink_core(&fs, gletscher_ino, "file2.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, 1, "Gletscher").unwrap();

        // Flush deletion to disk
        fs.sync_log().unwrap();

        // Check live stats in memory
        let stats_after = fs.calculate_generation_live_stats();
        assert_eq!(stats_after[0].live_bytes, 0);
        assert_eq!(stats_after[0].live_extents, 0);

        // 3. Inspect the log dump to verify InodeDelta records were written
        let dump_text = crate::dump::dump_log_file(storage.as_ref(), "000001.log", 1, None).unwrap();
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
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Create /keep and /Gletscher directories
        let keep_attr = crate::operations::dir::mkdir_core(&fs, 1, "keep", 0o755, 1000, 1000).unwrap();
        let gletscher_attr = crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();

        // 2. Create /keep/shared.txt (inode N, nlink 1) and write data
        let file_attr =
            crate::operations::read_write::create_core(&fs, keep_attr.ino, "shared.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file_attr.ino, b"persistent shared content", 0).unwrap();

        // 3. Create hard link /Gletscher/shared_link.txt -> inode N (nlink becomes 2)
        let link_attr =
            crate::operations::links::link_core(&fs, file_attr.ino, gletscher_attr.ino, "shared_link.txt").unwrap();
        assert_eq!(link_attr.nlink, 2);

        // Commit everything to disk
        fs.sync_log().unwrap();

        let stats1 = fs.calculate_generation_live_stats();
        assert_eq!(stats1[0].live_bytes, 25);
        assert_eq!(stats1[0].live_extents, 1);

        // 4. Delete /Gletscher via rm -rf (/Gletscher/shared_link.txt unlinked, /Gletscher rmdir'd)
        crate::operations::links::unlink_core(&fs, gletscher_attr.ino, "shared_link.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, 1, "Gletscher").unwrap();

        // Verify that /keep/shared.txt still has nlink 1 in memory
        let keep_file_attr = fs.get_attr(file_attr.ino).unwrap();
        assert_eq!(keep_file_attr.nlink, 1);

        // Commit deletion to disk
        fs.sync_log().unwrap();

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
        let rec_file_attr = recovered
            .get_attr(file_attr.ino)
            .expect("shared.txt must survive recovery");
        assert_eq!(rec_file_attr.nlink, 1);

        let data = recovered.read_file_data(file_attr.ino, 0, 25).unwrap();
        assert_eq!(&data, b"persistent shared content");

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 25);
        assert_eq!(rec_stats[0].live_extents, 1);
    }

    #[test]
    fn test_automatic_flush_triggers_on_staged_thresholds() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        fs_inst.max_buffer_size = 1000;
        fs_inst.max_staged_ops = 5; // Automatic flush after 5 operations
        let fs = Arc::new(fs_inst);
        fs.start_flusher();

        // Perform 4 create operations - not flushed yet
        for i in 0..4 {
            let name = format!("file_{}.txt", i);
            crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
        }
        assert_eq!(fs.staged_ops(), 4);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 0);

        // 5th operation reaches threshold and triggers automatic flush!
        crate::operations::read_write::create_core(&fs, 1, "file_4.txt", 0o644, 0, 1000, 1000).unwrap();

        // Staged ops reset to 0 after automatic flush
        assert_eq!(fs.staged_ops(), 0);
        assert!(crate::test_utils::wait_until(
            || fs.manifest.read().unwrap().logs[0].record_count == 7,
            Duration::from_secs(2)
        ));
    }

    #[test]
    fn test_unlinked_open_file_does_not_resurrect_on_recovery() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // Create a file, write data, then sync
        let f = crate::operations::read_write::create_core(&fs, 1, "unlinked.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = f.ino;
        crate::operations::read_write::write_core(&fs, ino, b"unlinked content", 0).unwrap();
        fs.sync_log().unwrap();

        // Open the file so open_counts > 0
        let fh = crate::operations::read_write::open_core(&fs, ino, libc::O_RDWR as u32).unwrap();

        // Unlink the file: removes directory entry, but node is kept in memory because open_count == 1
        crate::operations::links::unlink_core(&fs, 1, "unlinked.txt").unwrap();

        // Write more data while unlinked, then sync log
        crate::operations::read_write::write_core(&fs, ino, b" more content", 16).unwrap();
        fs.sync_log().unwrap();

        // Close the handle: drops open_count to 0 and tombstones the node in live
        crate::operations::read_write::release_core(&fs, ino, fh).unwrap();
        fs.sync_log().unwrap();

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
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // Create file and write 100 bytes (0xAA)
        let file_attr = crate::operations::read_write::create_core(&fs, 1, "data.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = file_attr.ino;
        crate::operations::read_write::write_core(&fs, ino, &[0xAA; 100], 0).unwrap();

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
        fs.sync_log().unwrap();

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
        fs.sync_log().unwrap();
        let read_data_after_flush = fs.read_file_data(ino, 0, 100).unwrap();
        assert_eq!(&read_data_after_flush[0..20], &[0xAA; 20]);
        assert_eq!(&read_data_after_flush[20..100], &[0x00; 80]);
    }

    #[test]
    fn test_multi_batch_flushing_queue_and_layer_resolution() {
        let clock = Arc::new(SystemClock);
        let fs = make_test_fs_with_log(clock.clone());

        // 1. Create file in batch 1
        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = f.ino;
        crate::operations::read_write::write_core(&fs, ino, &[0x11; 50], 0).unwrap();

        // Freeze into flushing queue (batch 1)
        fs.begin_flush(FlushMotivation::Test);
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 1);

        // 2. Overwrite in batch 2 (live layer)
        crate::operations::read_write::write_core(&fs, ino, &[0x22; 20], 10).unwrap();

        // Freeze into flushing queue (batch 2)
        fs.begin_flush(FlushMotivation::Test);
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
        fs.flush_to_base().unwrap();
        assert_eq!(fs.inner.lock_for_tests().unwrap().flushing.len(), 0);

        // Read again after folding
        let data_after_fold = fs.read_file_data(ino, 0, 50).unwrap();
        assert_eq!(data_after_fold, data);
    }

    #[test]
    fn test_flush_io_error_retries_and_does_not_wedge() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());

        crate::log::init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let clock = Arc::new(SystemClock);
        // Set tiny max_log_size (50 bytes) so the next flush rolls to 000002.log
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                50,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage.clone());
        fs.log_writer = Some(writer);

        // 1. First batch: write data to file1 and flush (populates gen 1 past header size)
        let f1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"initial payload", 0).unwrap();
        fs.flush_log().unwrap();

        // 2. Second batch: write data to file2
        let f2 = crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"second payload", 0).unwrap();

        // 3. Inject permission error on opening 000002.log to simulate I/O failure when rolling
        fault_storage.fail_on_file("000002.log", std::io::ErrorKind::PermissionDenied);

        // 4. Attempt flush - should fail with I/O error on roll creation
        let flush_res = fs.flush_log();
        assert!(flush_res.is_err(), "Expected flush_log to fail on simulated I/O error");

        // Verify filesystem is NOT wedged: flushing queue still retains the batch, live mutations still work!
        assert_eq!(
            fs.inner.lock_for_tests().unwrap().flushing.len(),
            1,
            "Failed batch must remain in flushing queue"
        );

        // Live operations continue working smoothly
        let f3 = crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f3.ino, b"third payload", 0).unwrap();

        // 5. Restore normal write access by clearing injected fault
        fault_storage.clear_fail_on_file("000002.log");

        // 6. Retry flush - must succeed and drain ALL batches
        let retry_res = fs.flush_log();
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
        let d1 = fs.read_file_data(f1.ino, 0, 15).unwrap();
        assert_eq!(&d1, b"initial payload");
        let d2 = fs.read_file_data(f2.ino, 0, 14).unwrap();
        assert_eq!(&d2, b"second payload");
        let d3 = fs.read_file_data(f3.ino, 0, 13).unwrap();
        assert_eq!(&d3, b"third payload");

        // 7. Crash-recovery: Recover filesystem and verify all files recovered cleanly
        let recovered = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            clock.clone(),
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered.get_attr(f1.ino).is_some());
        assert!(recovered.get_attr(f2.ino).is_some());
        assert!(recovered.get_attr(f3.ino).is_some());
        let rec_d1 = recovered.read_file_data(f1.ino, 0, 15).unwrap();
        assert_eq!(&rec_d1, b"initial payload");
        let rec_d2 = recovered.read_file_data(f2.ino, 0, 14).unwrap();
        assert_eq!(&rec_d2, b"second payload");
        let rec_d3 = recovered.read_file_data(f3.ino, 0, 13).unwrap();
        assert_eq!(&rec_d3, b"third payload");
    }

    #[test]
    fn test_flush_mid_batch_failure_rolls_back_and_retries_cleanly() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Initial batch with 2 files flushed cleanly
        let mut initial_inos = Vec::new();
        for i in 1..=2 {
            let name = format!("init_{}.txt", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
            crate::operations::read_write::write_core(&fs, f.ino, b"initial payload", 0).unwrap();
            initial_inos.push(f.ino);
        }
        fs.flush_log().unwrap();

        let initial_offset = storage.file_len("000001.log").unwrap();

        // 2. Stage a second batch with 8 files
        let mut batch2_inos = Vec::new();
        for i in 1..=8 {
            let name = format!("batch2_file_{}.bin", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
            let payload = vec![(i as u8) * 0x11; 128];
            crate::operations::read_write::write_core(&fs, f.ino, &payload, 0).unwrap();
            batch2_inos.push((f.ino, payload));
        }

        // 3. Set fault threshold slightly larger than initial_offset to force simulated ENOSPC mid-batch with partial torn write
        fault_storage.fail_writes_after_bytes(initial_offset + 300, true);

        // 4. Attempt flush - MUST fail with simulated mid-record write error
        let flush_res = fs.flush_log();
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
        let retry_res = fs.flush_log();
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

        let report =
            crate::check::check_volume(storage.clone(), true, crate::crypto::VolumeKey::plaintext_arc()).unwrap();
        assert!(report.is_clean(), "Integrity check must be clean: {:?}", report.issues);
    }

    #[test]
    fn test_extent_map_hole_larger_than_32_bits() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let ino = crate::operations::read_write::create_core(&fs, 1, "sparse_5g.bin", 0o644, 0, 1000, 1000)
            .unwrap()
            .ino;

        let start_data = vec![0xABu8; 100];
        crate::operations::read_write::write_core(&fs, ino, &start_data, 0).unwrap();

        // 5 GiB hole length (> 32-bit: 5 * 1024 * 1024 * 1024 = 5,368,709,120 > 4,294,967,295)
        let hole_len: u64 = 5 * 1024 * 1024 * 1024;
        let end_offset: u64 = 100 + hole_len;

        let end_data = vec![0xCDu8; 100];
        crate::operations::read_write::write_core(&fs, ino, &end_data, end_offset as i64).unwrap();

        crate::operations::read_write::punch_hole_core(&fs, ino, 100, hole_len).unwrap();

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
        fs.sync_log().unwrap();

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
    fn test_in_memory_fs_destroy_drains_async_ops() {
        let fs = Arc::new(InMemoryFS::new());
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
    fn test_in_memory_fs_destroy_drains_read_only() {
        let fs = Arc::new(InMemoryFS::new());
        fs.set_read_only(true);
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

    #[test]
    fn test_staged_accounting_reset_on_begin_flush_prevents_spurious_batches() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        // Threshold: 100 bytes or 10 ops
        fs_inst.max_buffer_size = 100;
        fs_inst.max_staged_ops = 10;
        let fs = Arc::new(fs_inst);
        fs.start_flusher();

        let file = crate::operations::read_write::create_core(&fs, 1, "test.bin", 0o644, 0, 1000, 1000).unwrap();

        // 1. Write 100 bytes to hit max_buffer_size threshold
        crate::operations::read_write::write_core(&fs, file.ino, &[0xAA; 100], 0).unwrap();

        // Automatic threshold triggered begin_flush()!
        // Background flusher drains the threshold batch so queue depth returns to 0.
        assert!(crate::test_utils::wait_until(
            || fs.flush_queue_depth() == 0,
            Duration::from_secs(2)
        ));
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Now simulate active background flusher with queued batch:
        // Populate live with 60 bytes
        crate::operations::read_write::write_core(&fs, file.ino, &[0xBB; 60], 100).unwrap();
        assert_eq!(fs.staged_bytes(), 60);
        assert_eq!(fs.staged_ops(), 1);

        // Freeze batch into queue manually (simulating begin_flush when flusher starts or when threshold hit)
        fs.begin_flush(FlushMotivation::Test);
        assert_eq!(fs.flush_queue_depth(), 1);
        // Counters must be reset to 0 upon freezing into flushing queue, and moved to flushing counters
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Subsequent write arriving while batch 1 is in flushing queue
        crate::operations::read_write::write_core(&fs, file.ino, &[0xCC; 20], 160).unwrap();
        // Should NOT trigger another begin_flush()! Queue depth must remain 1
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.staged_bytes(), 20);
        assert_eq!(fs.staged_ops(), 1);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Another small write
        crate::operations::read_write::write_core(&fs, file.ino, &[0xDD; 20], 180).unwrap();
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.staged_bytes(), 40);
        assert_eq!(fs.staged_ops(), 2);
        assert_eq!(fs.flushing_bytes(), 60);
        assert_eq!(fs.flushing_ops(), 1);

        // Now drain flushing batches
        while fs.step_flush().unwrap().is_some() {}

        // Live staged data is preserved and flushing counters are drained to 0
        assert_eq!(fs.staged_bytes(), 40);
        assert_eq!(fs.staged_ops(), 2);
        assert_eq!(fs.flushing_bytes(), 0);
        assert_eq!(fs.flushing_ops(), 0);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_depth() {
        let clock = Arc::new(SystemClock);
        let mut fs = make_test_fs_with_log(clock);
        fs.max_flush_queue_depth = 2;

        let file = crate::operations::read_write::create_core(&fs, 1, "bounded.bin", 0o644, 0, 1000, 1000).unwrap();

        // Populate batch 1
        crate::operations::read_write::write_core(&fs, file.ino, &[0x11; 30], 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 1);

        // Populate batch 2
        crate::operations::read_write::write_core(&fs, file.ino, &[0x22; 40], 30).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);

        // Queue is now full (len == max_flush_queue_depth == 2).
        // Populate live with batch 3 candidates
        crate::operations::read_write::write_core(&fs, file.ino, &[0x33; 50], 70).unwrap();
        assert_eq!(fs.staged_bytes(), 50);
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must be a no-op that returns false and leaves live and staged accounting untouched
        assert!(!fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 50);
        assert_eq!(fs.staged_ops(), 1);

        // Verify data in live is intact and readable across layers
        let read = fs.read_file_data(file.ino, 0, 120).unwrap();
        assert_eq!(&read[0..30], &[0x11; 30]);
        assert_eq!(&read[30..70], &[0x22; 40]);
        assert_eq!(&read[70..120], &[0x33; 50]);

        // Step one batch from flushing queue to make room
        fs.step_flush().unwrap().expect("batch stepped");
        assert_eq!(fs.flush_queue_depth(), 1);

        // Now begin_flush should succeed in freezing the accumulated live mutations
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.flush_to_base().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        let read_final = fs.read_file_data(file.ino, 0, 120).unwrap();
        assert_eq!(&read_final[0..30], &[0x11; 30]);
        assert_eq!(&read_final[30..70], &[0x22; 40]);
        assert_eq!(&read_final[70..120], &[0x33; 50]);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_bytes() {
        let clock = Arc::new(SystemClock);
        let mut fs = make_test_fs_with_log(clock);
        fs.max_flush_queue_depth = 10;
        fs.max_flush_queue_bytes = 100;

        let file =
            crate::operations::read_write::create_core(&fs, 1, "bytes_bounded.bin", 0o644, 0, 1000, 1000).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        fs.flush_to_base().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_bytes(), 0);

        // Populate batch 1: 60 bytes
        crate::operations::read_write::write_core(&fs, file.ino, &[0x11; 60], 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_bytes(), 60);

        // Populate batch 2: 40 bytes (total 100 bytes == max_flush_queue_bytes)
        crate::operations::read_write::write_core(&fs, file.ino, &[0x22; 40], 60).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 100);

        // Queue is now saturated on byte capacity (100 >= 100).
        // Populate live with batch 3 candidates: 30 bytes
        crate::operations::read_write::write_core(&fs, file.ino, &[0x33; 30], 100).unwrap();
        assert_eq!(fs.staged_bytes(), 30);
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must return false because flushing_bytes >= max_flush_queue_bytes
        assert!(!fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 100);
        assert_eq!(fs.staged_bytes(), 30);
        assert_eq!(fs.staged_ops(), 1);

        // Verify layered read consistency
        let read = fs.read_file_data(file.ino, 0, 130).unwrap();
        assert_eq!(&read[0..60], &[0x11; 60]);
        assert_eq!(&read[60..100], &[0x22; 40]);
        assert_eq!(&read[100..130], &[0x33; 30]);

        // Step one batch (60 bytes) to free byte capacity
        fs.step_flush().unwrap().expect("batch stepped");
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_bytes(), 40);

        // Now begin_flush should succeed
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_bytes(), 70);
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.flush_to_base().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_bytes(), 0);
        let read_final = fs.read_file_data(file.ino, 0, 130).unwrap();
        assert_eq!(&read_final[0..60], &[0x11; 60]);
        assert_eq!(&read_final[60..100], &[0x22; 40]);
        assert_eq!(&read_final[100..130], &[0x33; 30]);
    }

    #[test]
    fn test_freeze_live_bounded_by_max_flush_queue_ops() {
        let clock = Arc::new(SystemClock);
        let mut fs = make_test_fs_with_log(clock);
        fs.max_flush_queue_depth = 10;
        fs.max_flush_queue_ops = 2;

        let file = crate::operations::read_write::create_core(&fs, 1, "ops_bounded.bin", 0o644, 0, 1000, 1000).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        fs.flush_to_base().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_ops(), 0);

        // Populate batch 1: 1 op
        crate::operations::read_write::write_core(&fs, file.ino, &[0x11; 10], 0).unwrap();
        assert_eq!(fs.staged_ops(), 1);
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_ops(), 1);

        // Populate batch 2: 1 op -> total 2 ops == max_flush_queue_ops
        crate::operations::read_write::write_core(&fs, file.ino, &[0x22; 10], 10).unwrap();
        assert_eq!(fs.staged_ops(), 1);
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);

        // Queue is now saturated on op capacity (2 >= 2).
        // Populate live with batch 3 candidates: 1 op
        crate::operations::read_write::write_core(&fs, file.ino, &[0x33; 10], 20).unwrap();
        assert_eq!(fs.staged_ops(), 1);

        // begin_flush must return false because flushing_ops >= max_flush_queue_ops
        assert!(!fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);
        assert_eq!(fs.staged_ops(), 1);

        // Step one batch (1 op) to free op capacity
        fs.step_flush().unwrap().expect("batch stepped");
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(fs.flushing_ops(), 1);

        // Now begin_flush should succeed
        assert!(fs.begin_flush(FlushMotivation::Test));
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.flushing_ops(), 2);
        assert_eq!(fs.staged_ops(), 0);

        // Drain remaining batches
        fs.flush_to_base().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.flushing_ops(), 0);
        let read_final = fs.read_file_data(file.ino, 0, 30).unwrap();
        assert_eq!(&read_final[0..10], &[0x11; 10]);
        assert_eq!(&read_final[10..20], &[0x22; 10]);
        assert_eq!(&read_final[20..30], &[0x33; 10]);
    }

    #[test]
    fn test_flush_log_dedicated_fold_tag_and_threshold_drain() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone()));
        fs.max_buffer_size = 100;
        fs.max_staged_ops = 10;

        let file = crate::operations::read_write::create_core(&fs, 1, "test.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file.ino, &[0xAA; 50], 0).unwrap();

        // Perform flush
        fs.flush_log().unwrap();

        // Verify OpTag::Fold metric was recorded
        let stats = fs.inner.op_stats();
        let fold_stat = stats.iter().find(|s| s.tag == OpTag::Fold).unwrap();
        assert!(
            fold_stat.count >= 1,
            "OpTag::Fold must be recorded when folding batches into base"
        );

        // Populate live with 20 bytes (below threshold of 100 bytes / 10 ops)
        crate::operations::read_write::write_core(&fs, file.ino, &[0xBB; 20], 50).unwrap();
        assert_eq!(fs.staged_bytes(), 20);
        assert_eq!(fs.staged_ops(), 1);

        // Direct call to flush_log_locked: should NOT freeze live because thresholds are not met
        fs.flush_log_locked(&writer).unwrap();
        assert_eq!(fs.staged_bytes(), 20, "Mutations below threshold should remain in live");
        assert_eq!(fs.staged_ops(), 1);
        assert_eq!(fs.flush_queue_depth(), 0);

        // Record mutations exceeding max_buffer_size directly on inner
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.record_mutation(90); // 20 + 90 = 110 >= 100
        }
        assert_eq!(fs.staged_bytes(), 110);
        assert_eq!(fs.flush_queue_depth(), 0);

        // flush_log_locked will detect the threshold is met, freeze it via begin_flush_locked, and drain it
        fs.flush_log_locked(&writer).unwrap();
        assert_eq!(fs.staged_bytes(), 0);
        assert_eq!(fs.flush_queue_depth(), 0);
    }

    #[test]
    fn test_fsync_batch_completion_waiters_concurrent() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = Arc::new(InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone())));

        let file = crate::operations::read_write::create_core(&fs, 1, "test_fsync.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file.ino, b"waiter data", 0).unwrap();

        // Rollover under lock
        let completion = fs
            .rollover_for_sync(file.ino, 0, FlushMotivation::Fsync)
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
        fs.flush_log().unwrap();

        assert_eq!(
            unblocked.load(Ordering::SeqCst),
            10,
            "All completion callbacks must have been invoked"
        );
        assert!(completion.is_completed());
    }

    #[test]
    fn test_rollover_for_fsync_queue_saturation_and_deferred_freeze() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone()));
        fs_inst.max_flush_queue_depth = 2;
        let fs = Arc::new(fs_inst);

        // Install a background flusher handle so trigger_flusher returns true
        {
            let mut flusher = fs.flusher.background.lock().unwrap();
            *flusher = Some(BackgroundFlusher::start(|| Ok(()), || {}, Duration::from_secs(60)));
        }

        let file = crate::operations::read_write::create_core(&fs, 1, "saturate.bin", 0o644, 0, 1000, 1000).unwrap();

        // Batch 1
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 1", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        // Batch 2
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 2", 7).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        // Queue is now saturated at max depth 2
        assert_eq!(fs.flush_queue_depth(), 2);

        // Stage live mutations
        crate::operations::read_write::write_core(&fs, file.ino, b"live data", 14).unwrap();
        assert_eq!(fs.staged_bytes(), 9);

        // Call rollover_for_sync when flushing queue is saturated.
        // It should return Some(completion) immediately without blocking or spinning.
        let completion = fs
            .rollover_for_sync(file.ino, 0, FlushMotivation::Fsync)
            .unwrap()
            .expect("completion expected");
        assert!(!completion.is_completed());

        // Queue depth is still 2 and staged bytes are still in live waiting for capacity
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 9);

        // Step one batch from flushing queue, freeing capacity.
        // In remove_front_flush_batch, since inner.live_completion.is_some(), freeze_live is triggered immediately!
        let stepped = fs.step_flush().unwrap().expect("batch expected");
        assert_eq!(stepped.id, 1);

        // Capacity was freed and live mutations were frozen into the queue immediately
        assert_eq!(fs.flush_queue_depth(), 2);
        assert_eq!(fs.staged_bytes(), 0);
        assert!(!completion.is_completed());

        // Step batch 2
        let stepped2 = fs.step_flush().unwrap().expect("batch expected");
        assert_eq!(stepped2.id, 2);
        assert_eq!(fs.flush_queue_depth(), 1);
        assert!(!completion.is_completed());

        // Step batch 3 (containing the live data)
        let stepped3 = fs.step_flush().unwrap().expect("batch expected");
        assert_eq!(stepped3.id, 3);
        assert_eq!(fs.flush_queue_depth(), 0);

        // Completion must now be completed
        assert!(completion.is_completed());
        assert!(completion.wait_blocking().is_ok());

        // Verify read back
        let read_back = fs.read_file_data(file.ino, 0, 23).unwrap();
        assert_eq!(&read_back[0..7], b"batch 1");
        assert_eq!(&read_back[7..14], b"batch 2");
        assert_eq!(&read_back[14..23], b"live data");
    }

    #[test]
    fn test_flush_motivation_recording_fsync_and_fdirsync() {
        crate::async_runtime::block_on(async {
            let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
            let clock = Arc::new(SystemClock);
            let writer = Arc::new(
                LogWriter::create(
                    storage.clone(),
                    1,
                    &*clock,
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    crate::crypto::VolumeKey::plaintext_arc(),
                )
                .unwrap(),
            );
            let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

            // Create file and write data
            let file =
                crate::operations::read_write::create_core(&fs, 1, "moti_file.txt", 0o644, 0, 1000, 1000).unwrap();
            let fh = crate::operations::read_write::open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
            crate::operations::read_write::write_core(&fs, file.ino, b"hello flusher", 0).unwrap();

            // Run async fsync_core
            crate::operations::read_write::fsync_core(&fs, file.ino, fh)
                .await
                .unwrap();

            let flushes = fs.recent_flushes();
            assert_eq!(flushes.len(), 1);
            assert_eq!(flushes[0].motivation, FlushMotivation::Fsync);
            assert!(flushes[0].data_bytes > 0);
            assert!(flushes[0].ops_count > 0);

            // Now run fsyncdir_core
            crate::operations::read_write::create_core(&fs, 1, "dir_child.txt", 0o644, 0, 1000, 1000).unwrap();
            crate::operations::dir::fsyncdir_core(&fs).await.unwrap();

            let flushes_after = fs.recent_flushes();
            assert_eq!(flushes_after.len(), 2);
            assert_eq!(flushes_after[0].motivation, FlushMotivation::Fsync);
            assert_eq!(flushes_after[1].motivation, FlushMotivation::Fdirsync);
        });
    }

    #[test]
    fn test_step_flush_and_flush_to_base_in_memory() {
        let clock = Arc::new(SystemClock);
        let fs = make_test_fs_with_log(clock);

        // Create 2 files across 2 separate batches
        let file1 = crate::operations::read_write::create_core(&fs, 1, "mem1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file1.ino, b"data1", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        let file2 = crate::operations::read_write::create_core(&fs, 1, "mem2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file2.ino, b"data2", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        assert_eq!(fs.flush_queue_depth(), 2);

        // Advance 1 batch using single-authority step_flush
        let step_record = fs.step_flush().unwrap().expect("record expected");
        assert_eq!(fs.flush_queue_depth(), 1);
        assert_eq!(step_record.ops_count, 2);
        assert_eq!(step_record.data_bytes, 5); // 5 bytes payload

        // Advance remaining batches using single-authority flush_to_base
        let flushed_count = fs.flush_to_base().unwrap();
        assert_eq!(flushed_count, 1);
        assert_eq!(fs.flush_queue_depth(), 0);

        let records = fs.recent_flushes();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, step_record.id);
    }

    #[test]
    fn test_persist_flush_batch_failure_leaves_completion_intact_for_retry() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let file = crate::operations::read_write::create_core(&fs, 1, "retry_test.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file.ino, b"retry test payload", 0).unwrap();

        let initial_offset = storage.file_len("000001.log").unwrap();

        // Rollover for sync to generate a FlushBatch with a Completion handle
        let completion = fs
            .rollover_for_sync(file.ino, 0, FlushMotivation::Fsync)
            .unwrap()
            .expect("completion expected");
        assert!(!completion.is_completed());
        assert_eq!(fs.flush_queue_depth(), 1);

        // Inject write failure on storage
        fault_storage.fail_writes_after_bytes(initial_offset, true);

        // Use TestFlusher to attempt stepping the batch
        let test_flusher = TestFlusher::with_flusher(&fs, &fs.flusher, clock.clone());
        let step_res = test_flusher.step();
        assert!(step_res.is_err(), "Step must fail on injected write error");

        // Contract verification:
        // 1. Batch remains in the queue for retry
        assert_eq!(fs.flush_queue_depth(), 1);
        // 2. Completion is NOT resolved/completed yet
        assert!(
            !completion.is_completed(),
            "Completion must not be resolved on persist failure"
        );

        // Clear the fault
        fault_storage.clear_write_limit();

        // Retry stepping the batch
        let retry_record = test_flusher
            .step()
            .expect("retry step must not error")
            .expect("record expected");
        assert_eq!(retry_record.motivation, FlushMotivation::Fsync);

        // Contract verification after successful retry:
        // 1. Batch popped from queue
        assert_eq!(fs.flush_queue_depth(), 0);
        // 2. Completion is now successfully completed with Ok(())
        assert!(completion.is_completed());
        assert!(completion.wait_blocking().is_ok());

        // Verify data was properly persisted and folded
        let read_back = fs.read_file_data(file.ino, 0, 18).unwrap();
        assert_eq!(&read_back, b"retry test payload");
    }

    #[test]
    fn test_lifecycle_flusher_stopped_and_joined_on_panic_drop() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = Arc::new(InMemoryFS::with_clock_and_log(clock, Some(writer)));
        fs.init();
        assert!(fs.flusher.is_background_active());

        let flusher = Arc::clone(&fs.flusher);

        // Simulate a panic in a thread holding the filesystem
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _fs_held = fs;
            panic!("intentional test panic to verify drop lifecycle");
        }));
        assert!(res.is_err(), "Expected thread to panic");

        // Even though drop occurred during panic unwind, the background worker thread
        // must be cleanly stopped and joined, ensuring FileSystem strictly outlives Flusher.
        assert!(
            !flusher.is_background_active(),
            "Flusher worker must be stopped and joined even on panic drop"
        );
    }

    #[test]
    fn test_persist_flush_batch_fails_without_log_writer() {
        let fs = InMemoryFS::new();
        let file = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file.ino, b"data", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        let step_res = fs.step_flush();
        assert!(step_res.is_err());
        let err = step_res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
        assert_eq!(err.to_string(), "cannot persist without log writer");
    }

    #[test]
    fn test_flush_with_motivation_queue_saturation_flushes_live() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone()));
        fs_inst.max_flush_queue_depth = 2;
        let fs = Arc::new(fs_inst);

        let file =
            crate::operations::read_write::create_core(&fs, 1, "saturate_manual.bin", 0o644, 0, 1000, 1000).unwrap();

        // Batch 1
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 1", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        // Batch 2
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 2", 7).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        // Queue is now saturated at max depth 2
        assert_eq!(fs.flush_queue_depth(), 2);

        // Stage live mutations
        crate::operations::read_write::write_core(&fs, file.ino, b"live data", 14).unwrap();
        assert_eq!(fs.staged_bytes(), 9);

        // Call flush_to_base
        fs.flush_to_base().unwrap();

        assert_eq!(fs.staged_bytes(), 0, "All staged bytes must be flushed to base");
        assert_eq!(fs.flush_queue_depth(), 0, "Flushing queue must be empty");
    }

    #[test]
    fn test_flush_log_with_background_active_under_queue_saturation_flushes_live() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone()));
        fs_inst.max_flush_queue_depth = 2;
        let fs = Arc::new(fs_inst);
        fs.start_flusher();

        let file = crate::operations::read_write::create_core(&fs, 1, "saturate_bg.bin", 0o644, 0, 1000, 1000).unwrap();

        // Saturate queue
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 1", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 2", 7).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        assert_eq!(fs.flush_queue_depth(), 2);

        // Stage live data
        crate::operations::read_write::write_core(&fs, file.ino, b"live data", 14).unwrap();
        assert_eq!(fs.staged_bytes(), 9);

        // Call flush_log
        fs.flush_log().unwrap();

        assert_eq!(fs.staged_bytes(), 0, "Live staged bytes must be flushed to disk");
    }

    #[test]
    fn test_rollover_for_fdirsync_queue_saturation_preserves_motivation() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs_inst = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer.clone()));
        fs_inst.max_flush_queue_depth = 2;
        let fs = Arc::new(fs_inst);

        let file = crate::operations::read_write::create_core(&fs, 1, "moti_sat.bin", 0o644, 0, 1000, 1000).unwrap();

        // Batch 1
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 1", 0).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        // Batch 2
        crate::operations::read_write::write_core(&fs, file.ino, b"batch 2", 7).unwrap();
        assert!(fs.begin_flush(FlushMotivation::Test));

        assert_eq!(fs.flush_queue_depth(), 2);

        // Stage live modification
        crate::operations::read_write::write_core(&fs, file.ino, b"dir update", 14).unwrap();

        // Rollover with Fdirsync motivation while saturated
        let comp = fs
            .rollover_for_sync(0, 0, FlushMotivation::Fdirsync)
            .unwrap()
            .expect("completion expected");

        // Drain batches using step_flush
        let step1 = fs.step_flush().unwrap().expect("batch 1");
        assert_eq!(step1.motivation, FlushMotivation::Test);

        let step2 = fs.step_flush().unwrap().expect("batch 2");
        assert_eq!(step2.motivation, FlushMotivation::Test);

        let step3 = fs.step_flush().unwrap().expect("batch 3");
        assert_eq!(
            step3.motivation,
            FlushMotivation::Fdirsync,
            "Preserved Fdirsync motivation on deferred freeze"
        );

        assert!(comp.is_completed());
    }
}
