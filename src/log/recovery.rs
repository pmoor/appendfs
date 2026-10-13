use crate::clock::Clock;
use crate::crypto::VolumeKey;
use crate::fs::AppendFs;
use crate::log::manifest::{parse_log_filename, parse_summary_filename};
use crate::log::reader::{LogReader, LogRecord};
use crate::log::record::{DecodedPayload, FlushCommitPayload, OpCode, SealPayload};
use crate::log::summary::SummaryReader;
use crate::node::EntryDelta;
use crate::sync::OpTag;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

/// Target boundary for point-in-time recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTarget {
    /// Replay all available logs and summaries up to the latest state.
    Latest,
    /// Replay up to and including flush batch ID `batch_id`.
    BatchId(u64),
    /// Replay up to and including the given wall-clock timestamp.
    Timestamp(std::time::SystemTime),
    /// Replay up to and including log generation `generation`.
    Generation(u32),
}

/// Rebuilds complete in-memory filesystem state from summary files and `.log` files in `storage`
/// up to the specified `target` boundary, using `clock` for timestamp context.
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn recover_fs(
    storage: Arc<dyn crate::storage::Storage>,
    target: RecoveryTarget,
    clock: Arc<dyn Clock>,
    volume_key: Arc<VolumeKey>,
) -> io::Result<AppendFs> {
    let files = storage.list_files()?;

    // 1. Scan for eligible single-file .summary snapshots matching the target.
    // Collect all candidate summary files and sort them descending by (generation, revision)
    // so we can walk backwards from newest to oldest and only open/decompress the latest eligible one.
    let mut summary_candidates: Vec<(u32, u16, String)> = Vec::new();
    for file in &files {
        if let Some((gen_num, rev_num)) = parse_summary_filename(file) {
            summary_candidates.push((gen_num, rev_num, file.clone()));
        }
    }
    // Sort descending by generation, and descending by revision within generation:
    summary_candidates.sort_by_key(|&(generation, rev, _)| std::cmp::Reverse((generation, rev)));

    let mut latest_summary: Option<(u32, u16, SummaryReader)> = None;
    let mut unreadable: Vec<String> = Vec::new();

    for (gen_num, rev_num, file) in summary_candidates {
        // Fast-path eligibility check before opening or decompressing the full summary body:
        match target {
            RecoveryTarget::Generation(max_gen) => {
                if gen_num > max_gen {
                    continue;
                }
            }
            RecoveryTarget::BatchId(max_batch) => match SummaryReader::read_summary_header(storage.as_ref(), &file) {
                Ok(header) => {
                    if header.last_batch_id > max_batch {
                        continue;
                    }
                }
                Err(e) => {
                    log::warn!("Ignoring unreadable summary {}: {}", file, e);
                    unreadable.push(format!("{}: {}", file, e));
                    continue;
                }
            },
            RecoveryTarget::Timestamp(max_time) => match SummaryReader::read_summary_header(storage.as_ref(), &file) {
                Ok(header) => {
                    if header.created_at > max_time {
                        continue;
                    }
                }
                Err(e) => {
                    log::warn!("Ignoring unreadable summary {}: {}", file, e);
                    unreadable.push(format!("{}: {}", file, e));
                    continue;
                }
            },
            RecoveryTarget::Latest => {}
        }

        // We found the newest eligible candidate: attempt to open, decrypt, and decompress it.
        match SummaryReader::open(storage.as_ref(), &file, volume_key.clone()) {
            Ok(reader) => {
                latest_summary = Some((gen_num, rev_num, reader));
                break;
            }
            Err(e) => {
                log::warn!("Ignoring unreadable summary {}: {}", file, e);
                unreadable.push(format!("{}: {}", file, e));
            }
        }
    }

    // Skipping a bad summary is only safe while some other summary still describes the
    // volume. If every one of them failed, the volume's state is simply unknown, and
    // continuing would rebuild an empty filesystem and present it as healthy - which is what
    // a format change looks like from here, since older bytes stay a valid encoding of
    // different values. Refuse instead of inventing an answer.
    if latest_summary.is_none() && !unreadable.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "volume has {} summary file(s) but none could be read, so its state is unknown: {}",
                unreadable.len(),
                unreadable.join("; ")
            ),
        ));
    }

    let mut log_files_map: BTreeMap<u32, (u16, String)> = BTreeMap::new();
    for file in &files {
        if let Some((gen_num, rev_num)) = parse_log_filename(file) {
            match log_files_map.get(&gen_num) {
                Some((existing_rev, _)) if *existing_rev >= rev_num => {}
                _ => {
                    log_files_map.insert(gen_num, (rev_num, file.clone()));
                }
            }
        }
    }

    let log_files: Vec<(u32, String)> = log_files_map
        .into_iter()
        .map(|(gen_num, (_, file))| (gen_num, file))
        .collect();

    let mut fs_instance = AppendFs::with_clock_storage_and_volume_key(clock, storage.clone(), volume_key.clone());

    let mut last_op_time: Option<SystemTime> = None;
    if latest_summary.is_none()
        && let Some((_, oldest_file)) = log_files.first()
        && let Ok(oldest_reader) = LogReader::open(storage.as_ref(), oldest_file, volume_key.clone())
    {
        let created = oldest_reader.file_header().created_at;
        last_op_time = Some(created);
        if let Some(root_arc) = fs_instance.inner.lock(OpTag::Other).unwrap().base.get_mut(&1) {
            let root_node = Arc::make_mut(root_arc);
            root_node.meta.atime = created;
            root_node.meta.mtime = created;
            root_node.meta.ctime = created;
        }
    }

    let mut min_log_gen = 0u32;
    let mut last_batch_id = 0u64;
    let mut expected_batch_id: Option<u64> = None;

    // 2. Fast-recover from summary file if available
    if let Some((summary_gen, _rev, reader)) = latest_summary {
        log::info!(
            "Fast-recovering appendfs state from summary file (generation: {}, inodes: {}, last_batch_id: {})...",
            summary_gen,
            reader.footer.entry_count,
            reader.header.last_batch_id
        );
        let inodes_map = reader.read_all_inodes()?;
        let next_ino = reader.header.next_inode;
        last_batch_id = reader.header.last_batch_id;
        expected_batch_id = Some(last_batch_id + 1);
        last_op_time = Some(reader.header.created_at);

        fs_instance.inner.lock(OpTag::Other).unwrap().base = inodes_map;
        *fs_instance.manifest.write().unwrap() = reader.manifest.clone();
        // Carried from the summary's plaintext blob so a later export writes back the same
        // identity, rather than defaulting to plaintext and silently downgrading the volume.
        // `SummaryReader::open` has already required the header and the key to agree, so
        // this pair is coherent.
        fs_instance.set_volume(reader.volume_header.clone(), volume_key.clone())?;
        fs_instance.next_inode.store(next_ino, Ordering::SeqCst);
        fs_instance.last_summary_generation.store(summary_gen, Ordering::SeqCst);
        min_log_gen = summary_gen;
    }

    let mut max_inode = fs_instance.next_inode.load(Ordering::SeqCst).saturating_sub(1);

    let mut target_cutoff_reached = false;
    let mut total_recovered_data_bytes = 0u64;
    let mut max_replayed_generation = min_log_gen;

    let max_existing_generation = log_files.last().map(|(g, _)| *g).unwrap_or(0);

    // 3. Replay log files with generation > min_log_gen
    for (gen_num, filename) in log_files {
        if gen_num <= min_log_gen && min_log_gen > 0 {
            continue;
        }

        if let RecoveryTarget::Generation(max_gen) = target
            && gen_num > max_gen
        {
            break;
        }

        max_replayed_generation = max_replayed_generation.max(gen_num);

        let mut pending: Vec<LogRecord> = Vec::new();
        let mut committed_records_count = 0u32;
        let mut log_data_bytes = 0u64;
        let mut sealed_at: Option<SystemTime> = None;

        let mut reader = LogReader::open(storage.as_ref(), &filename, volume_key.clone())?;
        let log_version = reader.file_header().version;
        let log_created_at = reader.file_header().created_at;
        for record_res in &mut reader {
            let record = match record_res {
                Ok(r) => r,
                Err(e) => {
                    // Gracefully stop replay on power-loss file truncation
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    return Err(e);
                }
            };

            let header = record.header;

            if sealed_at.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extraneous record with OpCode {} found after Seal record in generation {}",
                        header.op_code, gen_num
                    ),
                ));
            }

            if header.op_code == OpCode::Seal {
                if !pending.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "found {} uncommitted record(s) before Seal record in generation {}",
                            pending.len(),
                            gen_num
                        ),
                    ));
                }

                let seal = crate::wire::deserialize::<SealPayload>(&record.payload).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed Seal payload in generation {}: {}", gen_num, e),
                    )
                })?;

                if seal.record_count != committed_records_count {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Seal record_count mismatch in generation {}: claimed {} but committed {}",
                            gen_num, seal.record_count, committed_records_count
                        ),
                    ));
                }

                sealed_at = Some(seal.timestamp);
                if let Some(op_time) = record.op_time() {
                    last_op_time = Some(op_time);
                }
            } else if header.op_code == OpCode::FlushCommit {
                let commit = crate::wire::deserialize::<FlushCommitPayload>(&record.payload).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed FlushCommit payload in generation {}: {}", gen_num, e),
                    )
                })?;

                if commit.record_count as usize != pending.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "FlushCommit record_count mismatch in generation {}: claimed {} but buffered {}",
                            gen_num,
                            commit.record_count,
                            pending.len()
                        ),
                    ));
                }

                if let Some(expected) = expected_batch_id {
                    if commit.batch_id != expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "gap detected in log stream: expected batch_id {}, got {}",
                                expected, commit.batch_id
                            ),
                        ));
                    }
                    expected_batch_id = Some(expected + 1);
                } else {
                    expected_batch_id = Some(commit.batch_id + 1);
                }

                if let RecoveryTarget::BatchId(max_batch) = target
                    && commit.batch_id > max_batch
                {
                    target_cutoff_reached = true;
                    break;
                }

                committed_records_count += commit.record_count + 1;

                let mut current_batch: HashMap<u64, EntryDelta> = HashMap::new();

                for buffered in pending.drain(..) {
                    // Check if this record exceeds point-in-time recovery target
                    if let RecoveryTarget::Timestamp(max_time) = target
                        && let Some(op_time) = buffered.op_time()
                        && op_time > max_time
                    {
                        target_cutoff_reached = true;
                        break;
                    }

                    let target_ino = buffered.header.inode;
                    if target_ino > max_inode {
                        max_inode = target_ino;
                    }

                    let decoded = match buffered.decode() {
                        Ok(d) => d,
                        Err(e) => {
                            log::warn!("Failed to decode record for inode {}: {}", target_ino, e);
                            continue;
                        }
                    };

                    match decoded {
                        DecodedPayload::Data(data) => {
                            log_data_bytes += data.len() as u64;
                        }
                        DecodedPayload::InodeDelta(log_delta) => {
                            if let Some(op_time) = log_delta.op_time() {
                                last_op_time = Some(op_time);
                            }
                            let entry_delta = log_delta.into_entry_delta(gen_num);
                            current_batch.insert(target_ino, entry_delta);
                        }
                        DecodedPayload::FlushCommit(_) | DecodedPayload::Seal(_) => {}
                    }
                }

                if !current_batch.is_empty() {
                    fs_instance.fold_entries(current_batch);
                }

                if target_cutoff_reached {
                    break;
                }

                last_batch_id = commit.batch_id;

                if let RecoveryTarget::BatchId(max_batch) = target
                    && commit.batch_id == max_batch
                {
                    target_cutoff_reached = true;
                    break;
                }
            } else {
                pending.push(record);
            }
        }

        if !pending.is_empty() && !target_cutoff_reached {
            log::warn!(
                "Discarding {} uncommitted record(s) at end of generation {} (crash mid-flush)",
                pending.len(),
                gen_num
            );
        }

        let is_active_log = gen_num == max_existing_generation;
        if is_active_log && sealed_at.is_none() {
            log::info!(
                "Active head log file '{}' (generation {}) is unsealed (diagnostic evidence of unclean crash)",
                filename,
                gen_num
            );
        } else if sealed_at.is_none() && !target_cutoff_reached {
            log::warn!(
                "Intermediate log file '{}' (generation {}) lacks a terminal Seal record (flagged as truncated or abnormally terminated)",
                filename,
                gen_num
            );
        }

        let log_file_len = storage.file_len(&filename).unwrap_or(0);
        let log_md5 = reader.finish_md5()?;
        let log_file_info = crate::log::LogFileInfo {
            version: log_version,
            generation: gen_num,
            revision: parse_log_filename(&filename).map(|(_, r)| r).unwrap_or(0),
            filename: filename.clone(),
            created_at: log_created_at,
            record_count: committed_records_count,
            total_bytes: log_file_len,
            total_data_bytes: log_data_bytes,
            md5: log_md5,
            sealed_at,
        };
        fs_instance.manifest.write().unwrap().record_sealed_log(log_file_info);

        total_recovered_data_bytes += log_data_bytes;

        if target_cutoff_reached {
            break;
        }
    }

    // A count of generations rather than a generation number, so it widens to the u64 counter.
    let gens_since_summary = u64::from(max_replayed_generation.saturating_sub(min_log_gen));
    fs_instance
        .generations_since_last_summary
        .store(gens_since_summary, Ordering::SeqCst);
    fs_instance
        .bytes_since_last_summary
        .store(total_recovered_data_bytes, Ordering::SeqCst);

    if max_inode >= fs_instance.next_inode.load(Ordering::SeqCst) {
        fs_instance.next_inode.store(max_inode + 1, Ordering::SeqCst);
    }
    fs_instance
        .inner
        .lock(OpTag::Other)
        .unwrap()
        .base
        .retain(|_ino, arc| arc.meta.nlink > 0 || arc.is_dir());
    fs_instance.last_batch_id.store(last_batch_id, Ordering::SeqCst);
    fs_instance.set_recovered_time(last_op_time);

    Ok(fs_instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{AdvancingClock, SystemClock};
    use crate::log::LogWriter;
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_recovery_to_specific_batch_id() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let mut fs = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        fs.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // Batch 1: Create dir "step1"
        let d1 = fs.make_dir(1, "step1", 0o755).unwrap();
        fs.quiesce().unwrap();
        let batch_after_step1 = fs.log_writer.as_ref().unwrap().last_batch_id();

        // Batch 2: Create file "file1.txt" inside "step1"
        let f1 = fs.create_file(d1, "file1.txt", 0o644).unwrap();
        fs.write_at(f1, b"version 1", 0).unwrap();
        fs.quiesce().unwrap();
        let batch_after_file1 = fs.log_writer.as_ref().unwrap().last_batch_id();

        // Batch 3: Create file "file2.txt" inside "step1"
        let f2 = fs.create_file(d1, "file2.txt", 0o644).unwrap();
        fs.write_at(f2, b"version 2", 0).unwrap();
        fs.quiesce().unwrap();

        // 1. Recover to Latest -> step1, file1.txt, file2.txt all exist
        let fs_latest = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(fs_latest.lookup_child(1, "step1").is_some());
        let d1_ino = fs_latest.lookup_child(1, "step1").unwrap();
        assert!(fs_latest.lookup_child(d1_ino, "file1.txt").is_some());
        assert!(fs_latest.lookup_child(d1_ino, "file2.txt").is_some());

        // 2. Recover to batch_after_step1 -> only step1 exists, no file1.txt or file2.txt
        let fs_b1 = recover_fs(
            storage.clone(),
            RecoveryTarget::BatchId(batch_after_step1),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(fs_b1.lookup_child(1, "step1").is_some());
        let d1_b1 = fs_b1.lookup_child(1, "step1").unwrap();
        assert!(fs_b1.lookup_child(d1_b1, "file1.txt").is_none());
        assert!(fs_b1.lookup_child(d1_b1, "file2.txt").is_none());

        // 3. Recover to batch_after_file1 -> step1 and file1.txt exist, but not file2.txt
        let fs_b2 = recover_fs(
            storage.clone(),
            RecoveryTarget::BatchId(batch_after_file1),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let d1_b2 = fs_b2.lookup_child(1, "step1").unwrap();
        assert!(fs_b2.lookup_child(d1_b2, "file1.txt").is_some());
        assert!(fs_b2.lookup_child(d1_b2, "file2.txt").is_none());
    }

    #[test]
    fn test_recovery_detects_batch_gap() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        // Writer 1 starts at batch 1 and writes batch 1
        let writer1 = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        writer1.append_data(1, b"batch1 data").unwrap();
        writer1
            .emit_flush_commit(1, b"batch1 data".len() as u64, clock.now())
            .unwrap();
        writer1.flush().unwrap();
        assert_eq!(writer1.last_batch_id(), 1);
        writer1.seal_active().unwrap();
        drop(writer1);

        // Writer 2 starts at batch 3 (simulating a dropped/missing batch 2)
        let writer2 = Arc::new(
            LogWriter::create(
                storage.clone(),
                2,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                3,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        writer2.append_data(1, b"batch3 data").unwrap();
        writer2
            .emit_flush_commit(1, b"batch3 data".len() as u64, clock.now())
            .unwrap();
        writer2.flush().unwrap();
        assert_eq!(writer2.last_batch_id(), 3);
        drop(writer2);

        // Recovery should fail due to detected gap (expected batch 2, got 3)
        let res = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        );
        assert!(res.is_err());
        let err_str = res.err().unwrap().to_string();
        assert!(err_str.contains("gap detected in log stream: expected batch_id 2, got 3"));
    }

    #[test]
    fn test_recovery_to_specific_timestamp() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let mut fs = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        fs.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // T = 1000: Create "early_dir"
        fs.make_dir(1, "early_dir", 0o755).unwrap();
        fs.quiesce().unwrap();

        // Advance clock to T = 2000
        clock.advance(Duration::from_secs(1000));
        fs.make_dir(1, "late_dir", 0o755).unwrap();
        fs.quiesce().unwrap();

        // Recover at T = 1500 -> early_dir exists, late_dir does not
        let fs_t1500 = recover_fs(
            storage.clone(),
            RecoveryTarget::Timestamp(UNIX_EPOCH + Duration::from_secs(1500)),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(fs_t1500.lookup_child(1, "early_dir").is_some());
        assert!(fs_t1500.lookup_child(1, "late_dir").is_none());

        // Recover at T = 2500 -> both exist
        let fs_t2500 = recover_fs(
            storage.clone(),
            RecoveryTarget::Timestamp(UNIX_EPOCH + Duration::from_secs(2500)),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(fs_t2500.lookup_child(1, "early_dir").is_some());
        assert!(fs_t2500.lookup_child(1, "late_dir").is_some());
    }

    #[test]
    fn test_recovery_computes_manifest_md5_on_the_fly() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let mut fs = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        fs.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // Create dir "step1" and quiesce (flushes and commits to 000001.log)
        fs.make_dir(1, "step1", 0o755).unwrap();
        fs.quiesce().unwrap();

        // 1. Recover without exporting summary - generation 1 should immediately have its MD5 populated in manifest
        let recovered = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        let expected_md5_1 = *md5::compute(mem_storage.get_file_bytes("000001.log").unwrap());
        let manifest = recovered.manifest.read().unwrap();
        let entry = manifest.get_by_generation(1).expect("generation 1 in manifest");
        assert_eq!(entry.md5, expected_md5_1);
        drop(manifest);
        drop(recovered);

        // 2. Append trailing torn bytes at EOF of 000001.log to simulate crash mid-write
        let mut bytes = mem_storage.get_file_bytes("000001.log").unwrap();
        bytes.extend_from_slice(b"trailing torn bytes");
        mem_storage.insert_file("000001.log", bytes);

        let recovered_torn = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        let expected_md5_torn = *md5::compute(mem_storage.get_file_bytes("000001.log").unwrap());
        let manifest = recovered_torn.manifest.read().unwrap();
        let entry = manifest.get_by_generation(1).expect("generation 1 in manifest");
        assert_eq!(entry.md5, expected_md5_torn);
    }

    #[test]
    fn test_recovery_verifies_rolled_log_is_sealed() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .root_owner(1000, 1000)
            .build()
            .fs;
        let writer = fs.log_writer.clone().unwrap();

        // Batch 1 into gen 1
        fs.make_dir(1, "dir1", 0o755).unwrap();
        fs.quiesce().unwrap();

        // Roll to generation 2 (this seals gen 1 with OpCode::Seal)
        let sealed = writer.force_roll().unwrap().unwrap();
        assert_eq!(sealed.generation, 1);
        fs.manifest.write().unwrap().record_sealed_log(sealed);

        // Batch 2 into gen 2
        fs.make_dir(1, "dir2", 0o755).unwrap();
        fs.quiesce().unwrap();

        // Verify recovery succeeds across rolled gen 1 (sealed) and active gen 2
        let recovered = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered.lookup_child(1, "dir1").is_some());
        assert!(recovered.lookup_child(1, "dir2").is_some());

        let manifest = recovered.manifest.read().unwrap();
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[0].version, crate::log::record::CURRENT_VERSION);
        assert_eq!(manifest.logs[1].version, crate::log::record::CURRENT_VERSION);
        assert!(manifest.logs[0].is_sealed(), "gen 1 was cleanly rolled and sealed");
        assert!(manifest.logs[0].sealed_at.is_some());
        assert!(
            !manifest.logs[1].is_sealed(),
            "active gen 2 ended without explicit seal"
        );
        assert_eq!(manifest.logs[1].sealed_at, None);
        assert!(!manifest.last_shutdown_clean());
    }

    #[test]
    fn test_recovery_handles_unsealed_intermediate_log_from_crash() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .root_owner(1000, 1000)
            .max_log_size(10_000)
            .build()
            .fs;
        let writer = fs.log_writer.clone().unwrap();

        fs.make_dir(1, "dir1", 0o755).unwrap();
        fs.quiesce().unwrap();
        fs.log_writer = None;
        drop(fs);
        drop(writer);

        // Now simulate gen 2 being created after crash recovery without sealing gen 1
        let writer2 =
            LogWriter::create(storage.clone(), 2, clock.clone(), 10_000, 2, VolumeKey::plaintext_arc()).unwrap();
        let mut fs2 = AppendFs::with_clock_and_uids(clock.clone(), 1000, 1000);
        fs2.log_writer = Some(Arc::new(writer2));
        fs2.set_storage(storage.clone());
        fs2.make_dir(1, "dir2", 0o755).unwrap();
        fs2.quiesce().unwrap();
        fs2.log_writer = None;
        drop(fs2);

        // Recovery must succeed and recover both dir1 and dir2
        let recovered = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered.lookup_child(1, "dir1").is_some());
        assert!(recovered.lookup_child(1, "dir2").is_some());

        let manifest = recovered.manifest.read().unwrap();
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[0].version, crate::log::record::CURRENT_VERSION);
        assert_eq!(manifest.logs[1].version, crate::log::record::CURRENT_VERSION);
        assert!(!manifest.logs[0].is_sealed(), "gen 1 crashed without seal");
        assert_eq!(manifest.logs[0].sealed_at, None);
        assert!(!manifest.logs[1].is_sealed(), "gen 2 crashed without seal");
        assert_eq!(manifest.logs[1].sealed_at, None);
        assert!(!manifest.last_shutdown_clean());
        assert!(!manifest.all_logs_sealed());
    }

    #[test]
    fn test_recovery_rejects_record_after_seal() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .root_owner(1000, 1000)
            .max_log_size(10_000)
            .build()
            .fs;
        let writer = fs.log_writer.clone().unwrap();

        fs.make_dir(1, "dir1", 0o755).unwrap();
        fs.quiesce().unwrap();
        writer.seal_active().unwrap();
        drop(fs);
        drop(writer);

        // Append an extraneous record after seal directly to 000001.log
        let mut log_bytes = mem_storage.get_file_bytes("000001.log").unwrap();
        let file_salt = crate::log::record::FileHeader::from_bytes(
            log_bytes[..crate::log::record::FILE_HEADER_SIZE].try_into().unwrap(),
        )
        .unwrap()
        .key_salt;
        let extra_payload = b"extraneous";
        let (_, cipher, tag) = crate::log::codec::encode(
            &VolumeKey::plaintext().log_file_key(&file_salt),
            crate::compress::Compression::None,
            crate::log::codec::RecordId {
                // Past every sequence the writer used in this generation.
                sequence: 1_000,
                op_code: OpCode::Data as u8,
                inode: 2,
            },
            extra_payload,
        )
        .unwrap();
        let extra_header = crate::log::record::RecordHeader {
            op_code: OpCode::Data,
            inode: 2,
            payload_len: cipher.len() as u32,
            sequence: 1_000,
            auth_tag: tag,
        };
        log_bytes.extend_from_slice(&extra_header.to_bytes());
        log_bytes.extend_from_slice(&cipher);
        mem_storage.insert_file("000001.log", log_bytes);

        let result = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        );
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected recovery to fail on record after seal"),
        };
        assert!(
            err_msg.contains("extraneous record with OpCode Data found after Seal record in generation 1"),
            "Expected extraneous record error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_recovery_rejects_seal_record_count_mismatch() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        let mut fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .root_owner(1000, 1000)
            .max_log_size(10_000)
            .build()
            .fs;
        let writer = fs.log_writer.clone().unwrap();

        fs.make_dir(1, "dir1", 0o755).unwrap();
        fs.quiesce().unwrap();

        // Seal gen 1 with record_count = 3 (1 dir delta + 1 attr delta + 1 FlushCommit)
        let _ = writer.seal_active().unwrap();
        fs.log_writer = None;
        drop(fs);
        drop(writer);

        // Forge a wrong Seal record by appending a bad Seal payload
        let bad_seal = SealPayload {
            timestamp: clock.now(),
            record_count: 999, // mismatch!
        };
        let bad_payload = crate::wire::serialize(&bad_seal).unwrap();

        // Replace 000001.log with one containing bad seal count
        let mut reader = LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc()).unwrap();
        let mut valid_records = Vec::new();
        for r in &mut reader {
            let rec = r.unwrap();
            if rec.header.op_code != OpCode::Seal {
                valid_records.push(rec);
            }
        }
        drop(reader);

        // Reconstruct 000001.log with valid records + bad seal
        // Keep the original header: it carries the salt the kept records are keyed by.
        let original = mem_storage.get_file_bytes("000001.log").unwrap();
        let file_header = crate::log::record::FileHeader::from_bytes(
            original[..crate::log::record::FILE_HEADER_SIZE].try_into().unwrap(),
        )
        .unwrap();
        let file_salt = file_header.key_salt;
        let mut new_bytes = file_header.to_bytes().to_vec();
        for rec in valid_records {
            let h = rec.header.to_bytes();
            new_bytes.extend_from_slice(&h);
            new_bytes.extend_from_slice(&rec.payload);
        }
        // Use encode to compute valid tag for bad seal
        let (_, cipher, tag) = crate::log::codec::encode(
            &VolumeKey::plaintext().log_file_key(&file_salt),
            crate::compress::Compression::None,
            crate::log::codec::RecordId {
                // Past every sequence the writer used in this generation.
                sequence: 1_000,
                op_code: OpCode::Seal as u8,
                inode: 0,
            },
            &bad_payload,
        )
        .unwrap();
        let tagged_header = crate::log::record::RecordHeader {
            op_code: OpCode::Seal,
            inode: 0,
            payload_len: cipher.len() as u32,
            sequence: 1_000,
            auth_tag: tag,
        };
        new_bytes.extend_from_slice(&tagged_header.to_bytes());
        new_bytes.extend_from_slice(&cipher);
        mem_storage.insert_file("000001.log", new_bytes);

        let result = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        );
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected recovery to fail on seal record count mismatch"),
        };
        assert!(
            err_msg.contains("Seal record_count mismatch in generation 1: claimed 999 but committed 3"),
            "Expected record count mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_recovery_walks_backwards_when_latest_summary_corrupted() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();

        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));

        // Phase 1: create fs with writer at gen 1, write file1, export summary
        {
            let fs = TestFs::builder()
                .storage(storage.clone())
                .clock(clock.clone())
                .root_owner(1000, 1000)
                .build()
                .fs;
            let writer = fs.log_writer.clone().unwrap();

            let f1 = fs.create_file(1, "file1.txt", 0o644).unwrap();
            fs.write_at(f1, b"data1", 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
            assert!(storage.exists("000001.summary"));

            let _ = writer.seal_active().unwrap();
        }

        // Phase 2: create fs at gen 2, write file2, export summary
        {
            let writer = Arc::new(
                LogWriter::create(
                    storage.clone(),
                    2,
                    clock.clone(),
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    2,
                    VolumeKey::plaintext_arc(),
                )
                .unwrap(),
            );
            let mut fs = AppendFs::with_clock_and_uids(clock.clone(), 1000, 1000);
            fs.log_writer = Some(writer.clone());
            fs.set_storage(storage.clone());

            let f2 = fs.create_file(1, "file2.txt", 0o644).unwrap();
            fs.write_at(f2, b"data2", 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
            assert!(storage.exists("000002.summary"));

            let _ = writer.seal_active().unwrap();
        }

        // Corrupt 000002.summary body
        let mut corrupt_bytes = mem_storage.get_file_bytes("000002.summary").unwrap();
        for b in &mut corrupt_bytes[crate::log::summary::SUMMARY_HEADER_SIZE..] {
            *b = 0xAA;
        }
        mem_storage.insert_file("000002.summary", corrupt_bytes);

        // Recover with Latest -> should ignore unreadable 000002.summary, fall back to 000001.summary,
        // replay log 000002.log, and have both file1.txt and file2.txt recovered!
        let recovered = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        assert!(recovered.lookup_child(1, "file1.txt").is_some());
        assert!(recovered.lookup_child(1, "file2.txt").is_some());
    }

    #[test]
    fn test_targeted_recovery_skips_unneeded_summary_decompression() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();

        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));

        // Gen 1: batch 1, time 1000
        let time_gen1 = clock.now();
        let batch_gen1;
        {
            let fs = TestFs::builder()
                .storage(storage.clone())
                .clock(clock.clone())
                .root_owner(1000, 1000)
                .build()
                .fs;
            let writer = fs.log_writer.clone().unwrap();

            let f1 = fs.create_file(1, "target.txt", 0o644).unwrap();
            fs.write_at(f1, b"data1", 0).unwrap();
            fs.quiesce().unwrap();
            batch_gen1 = fs.log_writer.as_ref().unwrap().last_batch_id();
            fs.export_summary(storage.as_ref()).unwrap();
            assert!(storage.exists("000001.summary"));
            let _ = writer.seal_active().unwrap();
        }

        // Gen 2: batch 2, time 2000
        clock.advance(Duration::from_secs(1000));
        {
            let writer = Arc::new(
                LogWriter::create(
                    storage.clone(),
                    2,
                    clock.clone(),
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    batch_gen1 + 1,
                    VolumeKey::plaintext_arc(),
                )
                .unwrap(),
            );
            let mut fs = AppendFs::with_clock_and_uids(clock.clone(), 1000, 1000);
            fs.log_writer = Some(writer.clone());
            fs.set_storage(storage.clone());

            let f2 = fs.create_file(1, "future.txt", 0o644).unwrap();
            fs.write_at(f2, b"data2", 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
            assert!(storage.exists("000002.summary"));
            let _ = writer.seal_active().unwrap();
        }

        // Keep 000002.summary's header intact (so read_header succeeds with last_batch_id > batch_gen1
        // and created_at > time_gen1), but corrupt its body so SummaryReader::open would fail with error.
        let mut corrupt_bytes = mem_storage.get_file_bytes("000002.summary").unwrap();
        for b in &mut corrupt_bytes[crate::log::summary::SUMMARY_HEADER_SIZE..] {
            *b = 0x55;
        }
        mem_storage.insert_file("000002.summary", corrupt_bytes);

        // Targeted recovery to batch_gen1:
        // Must inspect 000002.summary header, see last_batch_id > batch_gen1, and skip opening it.
        // Then inspect 000001.summary header, see last_batch_id <= batch_gen1, and open it.
        // It succeeds because 000002.summary body is NEVER opened!
        let recovered_batch = recover_fs(
            storage.clone(),
            RecoveryTarget::BatchId(batch_gen1),
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered_batch.lookup_child(1, "target.txt").is_some());
        assert!(recovered_batch.lookup_child(1, "future.txt").is_none());

        // Targeted recovery to time_gen1:
        // Must inspect 000002.summary header, see created_at > time_gen1, and skip opening it.
        let recovered_time = recover_fs(
            storage.clone(),
            RecoveryTarget::Timestamp(time_gen1),
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered_time.lookup_child(1, "target.txt").is_some());
        assert!(recovered_time.lookup_child(1, "future.txt").is_none());
    }

    #[test]
    fn test_recovery_walks_backwards_across_revisions() {
        let mem_storage = Arc::new(crate::storage::MemoryStorage::new());
        let storage: Arc<dyn crate::storage::Storage> = mem_storage.clone();

        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));

        // Phase 1: create fs with writer at gen 1, write rev0.txt, export rev 0 summary
        let rev0_summary_bytes;
        {
            let mut fs = TestFs::builder()
                .storage(storage.clone())
                .clock(clock.clone())
                .root_owner(1000, 1000)
                .build()
                .fs;
            let writer = fs.log_writer.clone().unwrap();

            let f1 = fs.create_file(1, "rev0.txt", 0o644).unwrap();
            fs.write_at(f1, b"data0", 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
            assert!(storage.exists("000001.summary"));
            rev0_summary_bytes = mem_storage.get_file_bytes("000001.summary").unwrap();

            // In the same session, write rev1.txt and export another summary
            let f2 = fs.create_file(1, "rev1.txt", 0o644).unwrap();
            fs.write_at(f2, b"data1", 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();

            // Take the new summary (which has rev0 + rev1) and make it 000001_r1.summary
            let mut r1_bytes = mem_storage.get_file_bytes("000001.summary").unwrap();
            r1_bytes[12..14].copy_from_slice(&1u16.to_be_bytes()); // revision: 1
            let footer_offset = r1_bytes.len() - crate::log::summary::SUMMARY_FOOTER_SIZE;
            let new_checksum = *blake3::hash(&r1_bytes[..footer_offset]).as_bytes();
            let len = r1_bytes.len();
            r1_bytes[len - 32..].copy_from_slice(&new_checksum);
            mem_storage.insert_file("000001_r1.summary", r1_bytes);

            let _ = writer.seal_active().unwrap();
            fs.log_writer = None;
        }

        // Restore 000001.summary after fs drops so destroy() does not overwrite it
        mem_storage.insert_file("000001.summary", rev0_summary_bytes);

        // Simulate log pruning so the filesystem relies strictly on summary contents
        storage.remove_file("000001.log").unwrap();

        // Case A: Both 000001.summary (rev 0) and 000001_r1.summary (rev 1) exist and are valid.
        // Recovery must sort by reverse revision within generation, choosing 000001_r1.summary first.
        {
            let recovered = recover_fs(
                storage.clone(),
                RecoveryTarget::Latest,
                clock.clone(),
                VolumeKey::plaintext_arc(),
            )
            .unwrap();
            assert!(recovered.lookup_child(1, "rev0.txt").is_some());
            assert!(recovered.lookup_child(1, "rev1.txt").is_some());
        }
        // Remove any files emitted when `recovered` dropped
        for f in storage.list_files().unwrap() {
            if f.starts_with("000002") {
                storage.remove_file(&f).unwrap();
            }
        }

        // Case B: 000001_r1.summary body is corrupted.
        // Recovery must fall back to 000001.summary (rev 0).
        let mut corrupt_r1 = mem_storage.get_file_bytes("000001_r1.summary").unwrap();
        for b in &mut corrupt_r1[crate::log::summary::SUMMARY_HEADER_SIZE..] {
            *b = 0xEE;
        }
        mem_storage.insert_file("000001_r1.summary", corrupt_r1);

        let recovered_fallback = recover_fs(
            storage.clone(),
            RecoveryTarget::Latest,
            clock.clone(),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(recovered_fallback.lookup_child(1, "rev0.txt").is_some());
        assert!(recovered_fallback.lookup_child(1, "rev1.txt").is_none());
    }
}
