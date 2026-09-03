//! Freezing `live`, writing delta log records, and folding batches into `base`.
//!
//! A flush freezes `live` into the `flushing` queue, writes pending data payloads and
//! serialized `LogEntryDelta` records directly to the active log file, and emits a
//! trailing `FlushCommit` confirming atomic persistence. Recovery replays `LogEntryDelta`
//! records directly onto `base`, guaranteeing identical state transitions across crash recovery.

use super::InMemoryFS;
use crate::log::{
    BackgroundFlusher, ExtentState, GenerationLiveStats, LogEntryDelta, LogWriter, OpCode, RECORD_HEADER_SIZE,
    SharedExtentState,
};
use crate::node::{EntryDelta, NodeDelta, NodeKind};
use crate::storage::Storage;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

impl InMemoryFS {
    // --- Flush & Fold Pipelines ---

    /// Freezes `live` into the `flushing` queue.
    pub fn begin_flush(&self) {
        let _dir_guard = self.dir_lock.lock().unwrap();
        let mut live_guard = self.live.write().unwrap();
        if !live_guard.is_empty() {
            let frozen = std::mem::take(&mut *live_guard);
            self.flushing.write().unwrap().push_back(frozen);
        }
    }

    pub fn current_flushing(&self) -> VecDeque<HashMap<u64, EntryDelta>> {
        self.flushing.read().unwrap().clone()
    }

    /// Merges a flushed batch into `base`.
    pub fn fold_flushed_batch(&self, flushed: HashMap<u64, EntryDelta>) {
        let mut base = self.base.write().unwrap();
        for (ino, entry) in flushed {
            match entry {
                EntryDelta::Tombstone => {
                    base.remove(&ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = base.get(&ino).cloned() {
                        let mut node_clone = (*existing_arc).clone();
                        delta.apply_to_node(&mut node_clone);
                        base.insert(ino, Arc::new(node_clone));
                    } else {
                        base.insert(ino, Arc::new(delta.to_node()));
                    }
                }
            }
        }
    }

    /// Writes pending data extents and serialized `LogEntryDelta` records for a frozen batch,
    /// followed by the `FlushCommit` trailer that makes the batch replayable.
    ///
    /// On any write error the entire batch is rolled back to its starting offset.
    fn synthesize_and_write_flushing_layer(
        &self,
        frozen: &mut HashMap<u64, EntryDelta>,
        writer: &LogWriter,
    ) -> std::io::Result<()> {
        // Clamped because extent lengths are u32, and because a zero would make the
        // chunking loop below never advance.
        let max_extent_size = self.max_extent_size.clamp(1, u32::MAX as usize);

        if let Some((next_gen, sealed_md5)) =
            writer.roll_if_needed(estimate_batch_bytes(frozen, max_extent_size), &*self.clock)?
        {
            if let Some(md5) = sealed_md5 {
                let sealed_gen = next_gen - 1;
                {
                    let mut manifest = self.manifest.write().unwrap();
                    manifest.set_generation_md5(sealed_gen, md5);
                    manifest.record_roll(
                        next_gen,
                        format!("{:06}.log", next_gen),
                        self.clock.now(),
                        crate::log::record::FILE_HEADER_SIZE as u64,
                    );
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
                manifest.record_roll(
                    next_gen,
                    format!("{:06}.log", next_gen),
                    self.clock.now(),
                    crate::log::record::FILE_HEADER_SIZE as u64,
                );
            }
            self.notify_replication();
        }

        let batch_gen = writer.generation();
        let batch_start_offset = writer.current_offset();
        writer.checkpoint_batch_start();

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
                            if let ExtentState::Staged {
                                data,
                                payload_offset,
                                length,
                            } = entry.value.read_state()
                            {
                                let slice = &data[payload_offset as usize..(payload_offset + length) as usize];
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

                    // Emit each run as one or more records of at most `max_extent_size`. A
                    // record is the unit of decryption, so an uncapped run would make a read
                    // of any byte within it decrypt the entire coalesced write.
                    for (start_off, _length, data) in staged_runs {
                        let mut chunk_start = 0usize;
                        loop {
                            let chunk_len = std::cmp::min(max_extent_size, data.len() - chunk_start);
                            let chunk = &data[chunk_start..chunk_start + chunk_len];

                            let (_, generation, record_log_offset) = writer.append_record(OpCode::Data, ino, chunk)?;
                            written_count += 1;
                            flushed_data_bytes += chunk_len as u64;

                            let disk_extent =
                                SharedExtentState::new_disk(generation, record_log_offset, 0, chunk_len as u32);
                            f.extents
                                .insert(start_off + chunk_start as u64, chunk_len as u64, disk_extent);

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
                let _ = writer.rollback_to(batch_gen, batch_start_offset);
                return Err(e);
            }
        };

        self.bytes_since_last_summary
            .fetch_add(flushed_data_bytes, Ordering::SeqCst);

        Ok(())
    }

    pub fn flush_log(&self) -> std::io::Result<()> {
        let _flush_guard = self.flush_lock.lock().unwrap();
        let Some(ref writer) = self.log_writer else {
            return Ok(());
        };

        // Freeze any active live mutations into the flushing queue
        self.begin_flush();

        // Drain flushing batches from the front of the queue
        loop {
            let mut batch = {
                let mut flushing_write = self.flushing.write().unwrap();
                match flushing_write.front_mut() {
                    Some(b) => {
                        if b.is_empty() {
                            flushing_write.pop_front();
                            continue;
                        }
                        b.clone()
                    }
                    None => break,
                }
            };

            // Attempt to write and commit this batch
            self.synthesize_and_write_flushing_layer(&mut batch, writer)?;

            // On success: fold into base and pop from flushing queue
            self.fold_flushed_batch(batch);
            self.flushing.write().unwrap().pop_front();
        }

        self.staged_bytes.store(0, Ordering::Relaxed);
        self.staged_ops.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Number of frozen batches currently waiting to be written to the log.
    pub fn flush_queue_depth(&self) -> usize {
        self.flushing.read().unwrap().len()
    }

    /// Admission control for mutating operations, called before any state is changed.
    pub fn check_flush_capacity(&self) -> Result<(), i32> {
        if self.log_writer.is_none() || self.flush_queue_depth() < self.max_flush_queue_depth {
            return Ok(());
        }
        self.flush_log().map_err(|e| {
            log::error!(
                "refusing mutation: {} flush batches queued and the log is not draining: {}",
                self.flush_queue_depth(),
                e
            );
            e.raw_os_error().unwrap_or(libc::EIO)
        })
    }

    /// Increments mutation counters (ops & bytes) and triggers an automatic flush if thresholds are reached.
    pub fn notify_mutation(&self, additional_bytes: usize) {
        let staged_b = if additional_bytes > 0 {
            self.staged_bytes.fetch_add(additional_bytes, Ordering::Relaxed) + additional_bytes
        } else {
            self.staged_bytes.load(Ordering::Relaxed)
        };
        let staged_o = self.staged_ops.fetch_add(1, Ordering::Relaxed) + 1;

        if staged_b >= self.max_buffer_size || staged_o >= self.max_staged_ops {
            let _ = self.flush_log();
        }
    }

    /// Initializes background services (e.g. periodic flusher) upon FUSE mount.
    pub fn init(self: &Arc<Self>) {
        if self.is_read_only() {
            return;
        }
        let interval_secs = self.flush_interval.load(Ordering::SeqCst);
        if interval_secs > 0 {
            let self_clone = Arc::clone(self);
            let mut flusher = self.flusher.lock().unwrap();
            *flusher = Some(BackgroundFlusher::start(
                move || self_clone.flush_log(),
                Duration::from_secs(interval_secs),
            ));
            log::info!(
                "Started background periodic log flusher (interval: {} seconds)",
                interval_secs
            );
        }
    }

    /// Cleanly stops background services upon FUSE unmount.
    pub fn destroy(&self) {
        if self.is_read_only() {
            return;
        }
        let mut flusher = self.flusher.lock().unwrap();
        if let Some(mut f) = flusher.take() {
            f.stop();
        }
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
        let base = self.base.read().unwrap();

        let mut live_map: HashMap<u64, (u64, u32)> = HashMap::new();
        for node_arc in base.values() {
            let node = node_arc.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                for (_, entry) in range_map.iter() {
                    if let ExtentState::Disk { generation, length, .. } = entry.value.read_state() {
                        let stats = live_map.entry(generation).or_insert((0, 0));
                        stats.0 += length as u64;
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

    /// Exports a single-file summary snapshot of the current in-memory filesystem state to `storage`.
    pub fn export_summary(&self, storage: &dyn Storage) -> std::io::Result<String> {
        self.sync_log()?;
        let snapshot = self.snapshot_all();
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self
            .log_writer
            .as_ref()
            .map_or_else(|| self.last_tx_id.load(Ordering::SeqCst), |w| w.last_tx_id());
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let mut manifest = self.manifest.read().unwrap().clone();
        manifest.populate_sealed_md5s(storage, generation);
        *self.manifest.write().unwrap() = manifest.clone();
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

        let result = crate::log::summary::export_summary(
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
        sealed_gen: u64,
        last_tx_id: u64,
    ) -> std::io::Result<String> {
        let snapshot = self.base.read().unwrap().clone();
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let mut manifest = self.manifest.read().unwrap().clone();
        manifest.populate_sealed_md5s(storage, sealed_gen + 1);
        *self.manifest.write().unwrap() = manifest.clone();
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
        self.sync_log()?;
        if let Some(ref writer) = self.log_writer {
            if !writer.is_open() {
                // Read-only session where no log records were ever flushed or written
                return Ok(None);
            }
            let storage = writer.storage();
            match self.export_summary(storage.as_ref()) {
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
                    if let ExtentState::Staged { length, .. } = entry.value.read_state() {
                        // One header per emitted chunk. Coalescing can merge adjacent staged
                        // extents into fewer records than this, so it stays an upper bound.
                        let chunks = (length as u64).div_ceil(max_extent_size as u64).max(1);
                        estimated_bytes += chunks * RECORD_HEADER_SIZE as u64 + length as u64;
                    }
                }
                estimated_bytes += RECORD_HEADER_SIZE as u64 + 256 + f.extents.len() as u64 * 32;
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
    use crate::node::{AttrDelta, FileDelta, InodeMeta, Node, NodeDelta, NodeKind};
    use crate::operations::read_write::write_core;
    use crate::range_map::RangeMap;
    use crate::storage::Storage;
    use std::time::SystemTime;

    #[test]
    fn test_flush_coalesces_micro_writes_into_single_base_range_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
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
        fs.insert_new_node(
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
        fs.add_dir_entry(1, "micro.txt", ino, std::time::SystemTime::now());

        // Perform 50 sequential 1-byte writes in live
        for i in 0..50u64 {
            let byte = vec![(i % 256) as u8];
            write_core(&fs, ino, &byte, i as i64).unwrap();
        }

        // Verify that live has 50 individual extent entries before flush
        {
            let live = fs.live.read().unwrap();
            if let Some(EntryDelta::Node(NodeDelta::File(f))) = live.get(&ino) {
                assert_eq!(f.extents.len(), 50);
            } else {
                panic!("File not found in live layer");
            }
        }

        // Flush to disk and fold into base
        fs.sync_log().unwrap();

        // Verify that base has exactly 1 consolidated extent of length 50
        {
            let base = fs.base.read().unwrap();
            let node_arc = base.get(&ino).expect("inode missing in base");
            let node = node_arc.as_ref();
            if let NodeKind::File { range_map, size, .. } = &node.kind {
                assert_eq!(*size, 50);
                assert_eq!(
                    range_map.len(),
                    1,
                    "Expected exactly 1 consolidated RangeEntry in base!"
                );
                let (start, entry) = range_map.iter().next().unwrap();
                assert_eq!(*start, 0);
                assert_eq!(entry.length, 50);
                assert!(matches!(
                    entry.value.read_state(),
                    crate::log::ExtentState::Disk { length: 50, .. }
                ));
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
            let temp_dir = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));

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
            fs.insert_new_node(
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
            fs.add_dir_entry(1, "big.bin", ino, SystemTime::now());

            // A single contiguous write many times larger than the cap.
            let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
            write_core(&fs, ino, &payload, 0).unwrap();
            fs.sync_log().unwrap();

            {
                let base = fs.base.read().unwrap();
                let node = base.get(&ino).expect("inode missing in base");
                if let NodeKind::File { range_map, size, .. } = &node.kind {
                    assert_eq!(*size as usize, TOTAL);
                    assert_eq!(
                        range_map.len(),
                        TOTAL.div_ceil(CAP),
                        "expected one extent per capped chunk (encrypted={})",
                        encrypted
                    );
                    for (_, entry) in range_map.iter() {
                        assert!(
                            entry.length as usize <= CAP,
                            "extent of {} bytes exceeds the {} byte cap (encrypted={})",
                            entry.length,
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
        let temp_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
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
        let temp_dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
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
        let fs = InMemoryFS::with_clock(clock);

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
        fs.begin_flush();
        while let Some(batch) = fs.flushing.write().unwrap().pop_front() {
            fs.fold_flushed_batch(batch);
        }

        // Verify parent relations are preserved in base after fold
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));
    }

    #[test]
    fn test_generation_live_stats_and_manifest_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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
        fs.base.write().unwrap().insert(
            ino1,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, clock.now()),
                kind: NodeKind::File {
                    range_map: RangeMap::new(),
                    size: 0,
                },
            }),
        );
        fs.add_dir_entry(1, "file1.bin", ino1, clock.now());

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
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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
        let base = recovered.base.read().unwrap();
        assert_eq!(base.len(), 1); // ONLY root directory (inode 1) remains!
        assert!(base.contains_key(&1));

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 0);
        assert_eq!(rec_stats[0].live_extents, 0);
    }

    #[test]
    fn test_hardlink_survives_rm_rf_of_other_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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

        let data = crate::operations::read_write::read_core(&recovered, file_attr.ino, 25, 0).unwrap();
        assert_eq!(&data, b"persistent shared content");

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 25);
        assert_eq!(rec_stats[0].live_extents, 1);
    }

    #[test]
    fn test_mutation_threshold_triggers_automatic_flush() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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
        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        // Set small operation threshold of 5 ops
        fs.max_staged_ops = 5;

        // Perform 4 create operations - not flushed yet
        for i in 0..4 {
            let name = format!("file_{}.txt", i);
            crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
        }
        assert_eq!(fs.staged_ops.load(Ordering::SeqCst), 4);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 0);

        // 5th operation reaches threshold and triggers automatic flush!
        crate::operations::read_write::create_core(&fs, 1, "file_4.txt", 0o644, 0, 1000, 1000).unwrap();

        // Staged ops reset to 0 after automatic flush
        assert_eq!(fs.staged_ops.load(Ordering::SeqCst), 0);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 7); // 5 files + 1 root dir + 1 FlushCommit
    }

    #[test]
    fn test_unlinked_open_file_does_not_resurrect_on_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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

        // Create a temp file
        let file_attr =
            crate::operations::read_write::create_core(&fs, 1, "temp_scratch.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = file_attr.ino;

        // Open handle (like a POSIX process keeping file open)
        let _fh = fs.open_file_handle(ino, 0);

        // Write data
        crate::operations::read_write::write_core(&fs, ino, &[0xCC; 128], 0).unwrap();

        // Unlink while open in same live batch
        crate::operations::links::unlink_core(&fs, 1, "temp_scratch.bin").unwrap();

        // Flush log to disk
        fs.sync_log().unwrap();

        // Recover filesystem from log
        let recovered = crate::log::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            clock,
            crate::crypto::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let base = recovered.base.read().unwrap();

        // Only root inode (1) should exist; NO resurrected /file_{ino} or phantom entries!
        assert_eq!(base.len(), 1, "Expected only root inode in base");
        assert!(base.contains_key(&1));
        assert!(!base.contains_key(&ino));

        let entries = recovered.list_directory(1).unwrap();
        assert!(entries.is_empty(), "Root directory must be completely empty");
    }

    #[test]
    fn test_truncate_down_then_extend_across_flush_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
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
        let read_data = crate::operations::read_write::read_core(&fs, ino, 100, 0).unwrap();
        assert_eq!(read_data.len(), 100);
        assert_eq!(&read_data[0..20], &[0xAA; 20]);
        assert_eq!(
            &read_data[20..100],
            &[0x00; 80],
            "Stale data must not survive truncate-down across flush!"
        );

        // Flush and verify reading again from base
        fs.sync_log().unwrap();
        let read_data_after_flush = crate::operations::read_write::read_core(&fs, ino, 100, 0).unwrap();
        assert_eq!(&read_data_after_flush[0..20], &[0xAA; 20]);
        assert_eq!(&read_data_after_flush[20..100], &[0x00; 80]);
    }

    #[test]
    fn test_multi_batch_flushing_queue_and_layer_resolution() {
        let clock = Arc::new(SystemClock);
        let fs = InMemoryFS::with_clock(clock.clone());

        // 1. Create file in batch 1
        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = f.ino;
        crate::operations::read_write::write_core(&fs, ino, &[0x11; 50], 0).unwrap();

        // Freeze into flushing queue (batch 1)
        fs.begin_flush();
        assert_eq!(fs.flushing.read().unwrap().len(), 1);

        // 2. Overwrite in batch 2 (live layer)
        crate::operations::read_write::write_core(&fs, ino, &[0x22; 20], 10).unwrap();

        // Freeze into flushing queue (batch 2)
        fs.begin_flush();
        assert_eq!(fs.flushing.read().unwrap().len(), 2);

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
        while let Some(batch) = fs.flushing.write().unwrap().pop_front() {
            fs.fold_flushed_batch(batch);
        }
        assert_eq!(fs.flushing.read().unwrap().len(), 0);

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
            Some("main"),
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
            fs.flushing.read().unwrap().len(),
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
            fs.flushing.read().unwrap().len(),
            0,
            "Flushing queue must be completely drained"
        );

        // Verify all three files are intact in memory and base
        let d1 = crate::operations::read_write::read_core(&fs, f1.ino, 15, 0).unwrap();
        assert_eq!(&d1, b"initial payload");
        let d2 = crate::operations::read_write::read_core(&fs, f2.ino, 14, 0).unwrap();
        assert_eq!(&d2, b"second payload");
        let d3 = crate::operations::read_write::read_core(&fs, f3.ino, 13, 0).unwrap();
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
        let rec_d1 = crate::operations::read_write::read_core(&recovered, f1.ino, 15, 0).unwrap();
        assert_eq!(&rec_d1, b"initial payload");
        let rec_d2 = crate::operations::read_write::read_core(&recovered, f2.ino, 14, 0).unwrap();
        assert_eq!(&rec_d2, b"second payload");
        let rec_d3 = crate::operations::read_write::read_core(&recovered, f3.ino, 13, 0).unwrap();
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
        assert_eq!(fs.flushing.read().unwrap().len(), 0);

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
            let d = crate::operations::read_write::read_core(&recovered, ino, 15, 0).unwrap();
            assert_eq!(&d, b"initial payload");
        }
        for (ino, payload) in batch2_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = crate::operations::read_write::read_core(&recovered, ino, payload.len(), 0).unwrap();
            assert_eq!(d, payload);
        }

        let report =
            crate::check::check_volume(storage.clone(), true, crate::crypto::VolumeKey::plaintext_arc()).unwrap();
        assert!(report.is_clean(), "Integrity check must be clean: {:?}", report.issues);
    }

    #[test]
    fn test_flush_queue_is_bounded_and_reports_failure_when_log_stops_draining() {
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
        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        fs.max_staged_ops = 1; // freeze a batch on every mutation
        fs.max_flush_queue_depth = 4;

        // 1. The disk fills up: nothing more can ever be appended to the log.
        fault_storage.fail_writes_after_bytes(crate::log::record::FILE_HEADER_SIZE as u64, false);

        // 2. Keep mutating well past the queue bound.
        let mut accepted = 0;
        let mut refused = 0;
        let mut last_errno = 0;
        for i in 0..50 {
            let name = format!("f{}.txt", i);
            match crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000) {
                Ok(_) => accepted += 1,
                Err(e) => {
                    refused += 1;
                    last_errno = e;
                }
            }
        }

        // 3. Userspace must be told, rather than every write silently "succeeding".
        assert!(refused > 0, "mutations must start failing once the log stops draining");
        assert_eq!(last_errno, libc::EIO, "failure must surface as an errno");
        assert!(
            accepted <= fs.max_flush_queue_depth,
            "only the batches that fit in the queue may be accepted, got {}",
            accepted
        );

        // 4. The backlog must stay bounded instead of growing with every mutation.
        assert!(
            fs.flush_queue_depth() <= fs.max_flush_queue_depth,
            "flush queue must stay bounded, got {}",
            fs.flush_queue_depth()
        );

        // 5. An explicit sync still reports the underlying failure.
        assert!(fs.sync_log().is_err());

        // 6. Once the disk recovers, the queued batches drain and mutations resume.
        fault_storage.clear_write_limit();
        fs.sync_log().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        crate::operations::read_write::create_core(&fs, 1, "after.txt", 0o644, 0, 1000, 1000)
            .expect("mutations must be accepted again once the log drains");
    }
}
