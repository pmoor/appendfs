use crate::clock::Clock;
use crate::crypto::VolumeKey;
use crate::fs::InMemoryFS;
use crate::log::reader::{LogReader, LogRecord};
use crate::log::record::{DecodedPayload, FlushCommitPayload, OpCode};
use crate::log::summary::SummaryReader;
use crate::node::EntryDelta;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

/// Target boundary for point-in-time recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTarget {
    /// Replay all available logs and summaries up to the latest state.
    Latest,
    /// Replay up to and including transaction ID `tx_id`.
    TxId(u64),
    /// Replay up to and including the given wall-clock timestamp.
    Timestamp(std::time::SystemTime),
    /// Replay up to and including log generation `generation`.
    Generation(u64),
}

/// Rebuilds complete in-memory filesystem state from summary files and `.log` files in `storage`
/// up to the specified `target` boundary, using `clock` for timestamp context.
pub fn recover_fs(
    storage: Arc<dyn crate::storage::Storage>,
    target: RecoveryTarget,
    clock: Arc<dyn Clock>,
    volume_key: Arc<VolumeKey>,
) -> io::Result<InMemoryFS> {
    let files = storage.list_files()?;

    // 1. Scan for eligible single-file .summary snapshots matching the target
    let mut latest_summary: Option<(u64, SummaryReader)> = None;
    let mut unreadable: Vec<String> = Vec::new();
    for file in &files {
        if file.ends_with(".summary") {
            let stem = file.trim_end_matches(".summary");
            if let Ok(gen_num) = stem.parse::<u64>() {
                match SummaryReader::open(storage.as_ref(), file, volume_key.clone()) {
                    Ok(reader) => {
                        let eligible = match target {
                            RecoveryTarget::Latest => true,
                            RecoveryTarget::TxId(max_tx) => reader.header.last_tx_id <= max_tx,
                            RecoveryTarget::Timestamp(max_time) => reader.header.created_at <= max_time,
                            RecoveryTarget::Generation(max_gen) => gen_num <= max_gen,
                        };
                        if eligible && latest_summary.as_ref().is_none_or(|(g, _)| gen_num > *g) {
                            latest_summary = Some((gen_num, reader));
                        }
                    }
                    Err(e) => {
                        log::warn!("Ignoring unreadable summary {}: {}", file, e);
                        unreadable.push(format!("{}: {}", file, e));
                    }
                }
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

    let mut log_files = Vec::new();
    for file in &files {
        if file.ends_with(".log") {
            let stem = file.trim_end_matches(".log");
            if let Ok(gen_num) = stem.parse::<u64>() {
                log_files.push((gen_num, file.clone()));
            }
        }
    }

    log_files.sort_by_key(|(gen_num, _)| *gen_num);

    let mut fs_instance = InMemoryFS::with_clock_storage_and_volume_key(clock, storage.clone(), volume_key.clone());

    let mut last_op_time: Option<SystemTime> = None;
    if latest_summary.is_none()
        && let Some((_, oldest_file)) = log_files.first()
        && let Ok(oldest_reader) = LogReader::open(storage.as_ref(), oldest_file, volume_key.clone())
    {
        let created = oldest_reader.file_header().created_at;
        last_op_time = Some(created);
        if let Some(root_arc) = fs_instance.base.write().unwrap().get_mut(&1) {
            let root_node = Arc::make_mut(root_arc);
            root_node.meta.atime = created;
            root_node.meta.mtime = created;
            root_node.meta.ctime = created;
        }
    }

    let mut min_log_gen = 0u64;
    let mut last_tx_id = 0u64;

    // 2. Fast-recover from summary file if available
    if let Some((summary_gen, reader)) = latest_summary {
        log::info!(
            "Fast-recovering appendfs state from summary file (generation: {}, inodes: {}, last_tx_id: {})...",
            summary_gen,
            reader.footer.entry_count,
            reader.header.last_tx_id
        );
        let inodes_map = reader.read_all_inodes()?;
        let next_ino = reader.header.next_inode;
        last_tx_id = reader.header.last_tx_id;
        last_op_time = Some(reader.header.created_at);

        *fs_instance.base.write().unwrap() = inodes_map;
        *fs_instance.manifest.write().unwrap() = reader.manifest.clone();
        // Carried from the summary's plaintext blob so a later export writes back the same
        // identity, rather than defaulting to plaintext and silently downgrading the volume.
        // `SummaryReader::open` has already required the header and the key to agree, so
        // this pair is coherent.
        fs_instance.set_volume(reader.volume_header.clone(), volume_key.clone())?;
        fs_instance.next_inode.store(next_ino, Ordering::SeqCst);
        min_log_gen = summary_gen;
    }

    let mut max_inode = fs_instance.next_inode.load(Ordering::SeqCst).saturating_sub(1);

    let mut target_cutoff_reached = false;

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

        let mut pending: Vec<LogRecord> = Vec::new();
        let mut committed_records_count = 0u32;
        let mut log_data_bytes = 0u64;

        let reader = LogReader::open(storage.as_ref(), &filename, volume_key.clone())?;
        let log_created_at = reader.file_header().created_at;
        for record_res in reader {
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

            if header.op_code == OpCode::FlushCommit {
                if header.tx_id > last_tx_id {
                    last_tx_id = header.tx_id;
                }

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

                committed_records_count += commit.record_count + 1;

                let mut current_batch: HashMap<u64, EntryDelta> = HashMap::new();

                for buffered in pending.drain(..) {
                    // Check if this record exceeds point-in-time recovery target
                    match target {
                        RecoveryTarget::TxId(max_tx) => {
                            if buffered.header.tx_id > max_tx {
                                target_cutoff_reached = true;
                                break;
                            }
                        }
                        RecoveryTarget::Timestamp(max_time) => {
                            if let Some(op_time) = buffered.op_time()
                                && op_time > max_time
                            {
                                target_cutoff_reached = true;
                                break;
                            }
                        }
                        _ => {}
                    }

                    if buffered.header.tx_id > last_tx_id {
                        last_tx_id = buffered.header.tx_id;
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
                            let entry_delta = EntryDelta::from(log_delta);
                            current_batch.insert(target_ino, entry_delta);
                        }
                        DecodedPayload::FlushCommit(_) => {}
                    }
                }

                fs_instance.fold_flushed_batch(current_batch);

                if target_cutoff_reached {
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

        let log_file_len = storage.file_len(&filename).unwrap_or(0);
        {
            let mut manifest = fs_instance.manifest.write().unwrap();
            if manifest.get_by_generation(gen_num).is_none() {
                if manifest.logs.len() == 1 && manifest.logs[0].generation == 1 && min_log_gen == 0 && gen_num == 1 {
                    let entry = &mut manifest.logs[0];
                    entry.created_at = log_created_at;
                    entry.record_count = committed_records_count;
                    entry.total_data_bytes = log_data_bytes;
                    entry.total_bytes = log_file_len;
                } else {
                    manifest.record_roll(
                        gen_num,
                        format!("{:06}.log", gen_num),
                        log_created_at,
                        crate::log::record::FILE_HEADER_SIZE as u64,
                    );
                    if let Some(entry) = manifest.get_mut_by_generation(gen_num) {
                        entry.record_count = committed_records_count;
                        entry.total_data_bytes = log_data_bytes;
                        entry.total_bytes = log_file_len;
                    }
                }
            } else if let Some(entry) = manifest.get_mut_by_generation(gen_num) {
                entry.created_at = log_created_at;
                entry.record_count = committed_records_count;
                entry.total_data_bytes = log_data_bytes;
                entry.total_bytes = log_file_len;
            }
        }

        if target_cutoff_reached {
            break;
        }
    }

    if max_inode >= fs_instance.next_inode.load(Ordering::SeqCst) {
        fs_instance.next_inode.store(max_inode + 1, Ordering::SeqCst);
    }
    fs_instance
        .base
        .write()
        .unwrap()
        .retain(|_ino, arc| arc.meta.nlink > 0 || arc.is_dir());
    fs_instance.last_tx_id.store(last_tx_id, Ordering::SeqCst);
    fs_instance.set_recovered_time(last_op_time);

    Ok(fs_instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{AdvancingClock, SystemClock};
    use crate::log::LogWriter;
    use crate::storage::OsStorage;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_recovery_to_specific_tx_id() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // Tx 1-3: Create dir "step1"
        let d1 = crate::operations::dir::mkdir_core(&fs, 1, "step1", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();
        let tx_after_step1 = fs.log_writer.as_ref().unwrap().last_tx_id();

        // Tx 4-7: Create file "file1.txt" inside "step1"
        let f1 = crate::operations::read_write::create_core(&fs, d1.ino, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"version 1", 0).unwrap();
        fs.sync_log().unwrap();
        let tx_after_file1 = fs.log_writer.as_ref().unwrap().last_tx_id();

        // Tx 8-11: Create file "file2.txt" inside "step1"
        let f2 = crate::operations::read_write::create_core(&fs, d1.ino, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"version 2", 0).unwrap();
        fs.sync_log().unwrap();

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

        // 2. Recover to tx_after_step1 -> only step1 exists, no file1.txt or file2.txt
        let fs_tx1 = recover_fs(
            storage.clone(),
            RecoveryTarget::TxId(tx_after_step1),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        assert!(fs_tx1.lookup_child(1, "step1").is_some());
        let d1_tx1 = fs_tx1.lookup_child(1, "step1").unwrap();
        assert!(fs_tx1.lookup_child(d1_tx1, "file1.txt").is_none());
        assert!(fs_tx1.lookup_child(d1_tx1, "file2.txt").is_none());

        // 3. Recover to tx_after_file1 -> step1 and file1.txt exist, but not file2.txt
        let fs_tx6 = recover_fs(
            storage.clone(),
            RecoveryTarget::TxId(tx_after_file1),
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let d1_tx6 = fs_tx6.lookup_child(1, "step1").unwrap();
        assert!(fs_tx6.lookup_child(d1_tx6, "file1.txt").is_some());
        assert!(fs_tx6.lookup_child(d1_tx6, "file2.txt").is_none());
    }

    #[test]
    fn test_recovery_to_specific_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // T = 1000: Create "early_dir"
        crate::operations::dir::mkdir_core(&fs, 1, "early_dir", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

        // Advance clock to T = 2000
        clock.advance(Duration::from_secs(1000));
        crate::operations::dir::mkdir_core(&fs, 1, "late_dir", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

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
}
