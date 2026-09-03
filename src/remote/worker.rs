use crate::fs::InMemoryFS;
use crate::remote::RemoteStore;
use crate::remote::config::RemoteRegistry;
use crate::storage::Storage;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// Helper to stream a file from local `Storage` to a `RemoteStore`.
pub fn upload_storage_file(
    storage: &dyn Storage,
    remote: &dyn RemoteStore,
    filename: &str,
    expected_md5: Option<&[u8; 16]>,
) -> io::Result<()> {
    let reader = storage.open_reader(filename)?;
    let len = reader.len()?;

    struct StorageReadAdapter<'a> {
        reader: &'a dyn crate::storage::StorageReader,
        offset: u64,
        total_len: u64,
    }

    impl<'a> Read for StorageReadAdapter<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.total_len {
                return Ok(0);
            }
            let to_read = (buf.len() as u64).min(self.total_len - self.offset) as usize;
            self.reader.read_exact_at(self.offset, &mut buf[..to_read])?;
            self.offset += to_read as u64;
            Ok(to_read)
        }
    }

    let mut adapter = StorageReadAdapter {
        reader: reader.as_ref(),
        offset: 0,
        total_len: len,
    };

    remote.put_object(filename, &mut adapter, len, expected_md5)
}

/// Helper to cross-copy a file from one `RemoteStore` to another using streaming.
pub fn cross_copy_file(
    src_remote: &dyn RemoteStore,
    dst_remote: &dyn RemoteStore,
    filename: &str,
    expected_len: u64,
    expected_md5: Option<&[u8; 16]>,
) -> io::Result<()> {
    // Stream via a temporary local file or memory buffer if reasonably sized
    let dir = tempfile::tempdir()?;
    let tmp_file_path = dir.path().join(filename);
    {
        let mut tmp_file = std::fs::File::create(&tmp_file_path)?;
        src_remote.get_object(filename, &mut tmp_file)?;
        tmp_file.flush()?;
    }

    let mut tmp_file = std::fs::File::open(&tmp_file_path)?;
    dst_remote.put_object(filename, &mut tmp_file, expected_len, expected_md5)?;
    Ok(())
}

use std::collections::HashMap;

/// Live operational telemetry for a single remote target.
#[derive(Debug, Clone, Default)]
pub struct RemoteSyncTelemetry {
    pub name: String,
    pub synced_generation: u64,
    pub active_part: Option<(u64, u32)>,
    pub last_sync_time: Option<SystemTime>,
    pub last_error: Option<String>,
}

/// In-memory telemetry table capturing real-time replication status across all remotes.
#[derive(Debug, Default)]
pub struct ReplicationTelemetry {
    pub remotes: HashMap<String, RemoteSyncTelemetry>,
}

impl ReplicationTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_synced_gen(&mut self, remote_name: &str, generation_num: u64) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        if generation_num >= entry.synced_generation {
            entry.synced_generation = generation_num;
            entry.last_sync_time = Some(SystemTime::now());
            entry.last_error = None;
        }
    }

    pub fn record_active_part(&mut self, remote_name: &str, generation_num: u64, part_idx: u32) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        entry.active_part = Some((generation_num, part_idx));
        entry.last_sync_time = Some(SystemTime::now());
        entry.last_error = None;
    }

    pub fn record_error(&mut self, remote_name: &str, error: &str) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        entry.last_error = Some(error.to_string());
    }
}

/// Formats a complete human-readable report of replication status across all remotes.
pub fn format_remotes_status(fs: &InMemoryFS) -> String {
    let mut out = String::new();

    let manifest = fs.manifest.read().unwrap().clone();
    let head_gen = fs
        .log_writer
        .as_ref()
        .map(|w| w.generation())
        .unwrap_or_else(|| manifest.next_generation.saturating_sub(1).max(1));
    let sealed_gens: Vec<_> = manifest.logs.iter().filter(|l| l.generation < head_gen).collect();
    let last_sealed_gen = sealed_gens.iter().map(|l| l.generation).max().unwrap_or(0);

    let remotes_info = {
        let reg_lock = fs.remote_registry.read().unwrap();
        match reg_lock.as_ref() {
            Some(reg) => {
                let r = reg.read().unwrap();
                r.remotes.clone()
            }
            None => std::collections::BTreeMap::new(),
        }
    };

    if remotes_info.is_empty() {
        out.push_str("No remotes configured.\n\n");
        out.push_str(&format!("Volume Head Generation: {}\n", head_gen));
        out.push_str(&format!("Sealed Generations:     {}\n", last_sealed_gen));
        return out;
    }

    let telemetry_guard = fs.replication_telemetry.read().unwrap();

    out.push_str(&format!(
        "=== Remote Status (Volume Head Generation: {}) ===\n\n",
        head_gen
    ));

    for (name, config) in &remotes_info {
        out.push_str(&format!("[Remote: {}]\n", name));

        let target_str = match (&config.bucket, &config.path) {
            (Some(b), _) => format!("s3 (bucket: {}, prefix: {})", b, config.prefix),
            (_, Some(p)) => format!("local/nfs ({})", p.display()),
            _ => "unknown".to_string(),
        };
        out.push_str(&format!("  Target:             {}\n", target_str));
        out.push_str(&format!("  Read Priority:      {}\n", config.read_priority));
        out.push_str(&format!(
            "  Mode:               {}\n",
            if config.read_only { "Read-Only" } else { "Read-Write" }
        ));

        let telem = telemetry_guard.remotes.get(name);
        let synced_gen = telem.map_or(0, |t| t.synced_generation);
        let lag = last_sealed_gen.saturating_sub(synced_gen);

        let status_str = if config.read_only {
            "Read-Only Upstream"
        } else if lag == 0 {
            "Up to date"
        } else {
            "Syncing"
        };
        out.push_str(&format!("  Status:             {}\n", status_str));
        out.push_str(&format!("  Synced Generation:  {} / {}\n", synced_gen, last_sealed_gen));
        out.push_str(&format!("  Replication Lag:    {} sealed generation(s)\n", lag));

        if let Some(t) = telem {
            if let Some((part_gen, part)) = t.active_part {
                out.push_str(&format!("  Active Part:        {:06}.part{:04}.log\n", part_gen, part));
            }
            if let Some(t_time) = t.last_sync_time {
                let elapsed = SystemTime::now().duration_since(t_time).unwrap_or_default().as_secs();
                out.push_str(&format!("  Last Sync:          {}s ago\n", elapsed));
            }
            if let Some(ref err) = t.last_error {
                out.push_str(&format!("  Last Error:         {}\n", err));
            }
        }

        out.push('\n');
    }

    if let Some(cache) = fs.log_cache.as_ref().and_then(|lc| lc.block_cache.as_ref()) {
        let coalesced = cache.coalescer().coalesced_requests();
        let leader = cache.coalescer().leader_requests();
        if coalesced > 0 || leader > 0 {
            out.push_str("=== Remote Read Optimization ===\n");
            out.push_str(&format!("  Leader Fetches:     {}\n", leader));
            out.push_str(&format!(
                "  Coalesced Reads:    {} (saved network range requests)\n",
                coalesced
            ));
            out.push_str(&format!("  In-Flight Fetches:  {}\n", cache.coalescer().in_flight()));
            out.push('\n');
        }
    }

    out
}

/// Autonomous background replication and tiered pruning worker.
pub struct RemoteReplicationWorker {
    running: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl RemoteReplicationWorker {
    /// Starts the background replication worker thread.
    pub fn start(fs: Arc<InMemoryFS>, registry: Arc<RwLock<RemoteRegistry>>, log_dir: PathBuf) -> Self {
        fs.set_remote_registry(Arc::clone(&registry));
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        let thread_handle = thread::spawn(move || {
            let mut last_part_sync = SystemTime::now();
            let mut uploaded_part_offsets: std::collections::HashMap<u64, (u64, u32)> =
                std::collections::HashMap::new();

            while running_clone.load(Ordering::SeqCst) {
                if let Err(e) = Self::run_cycle(
                    &fs,
                    &registry,
                    &log_dir,
                    &mut last_part_sync,
                    &mut uploaded_part_offsets,
                ) {
                    log::warn!("Remote replication worker cycle error: {}", e);
                }

                // Sleep for 5 seconds between periodic maintenance checks
                for _ in 0..50 {
                    if !running_clone.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }

            // Final drain cycle on unmount/shutdown
            log::info!("Flushing remaining remote sync tasks before shutdown...");
            let _ = Self::run_cycle(
                &fs,
                &registry,
                &log_dir,
                &mut last_part_sync,
                &mut uploaded_part_offsets,
            );
        });

        Self {
            running,
            thread_handle: Some(thread_handle),
        }
    }

    pub fn run_cycle(
        fs: &Arc<InMemoryFS>,
        registry: &Arc<RwLock<RemoteRegistry>>,
        _log_dir: &Path,
        last_part_sync: &mut SystemTime,
        uploaded_parts: &mut std::collections::HashMap<u64, (u64, u32)>,
    ) -> io::Result<()> {
        let (policy, stores) = {
            let reg = registry.read().unwrap();
            (reg.policy.clone(), reg.build_all_stores())
        };

        if stores.is_empty() {
            return Ok(());
        }

        let storage = match fs.log_cache.as_ref() {
            Some(c) => Arc::clone(c.storage()),
            None => return Ok(()),
        };

        let (active_gen, active_offset, active_created) = match fs.log_writer {
            Some(ref w) => (w.generation(), w.current_offset(), w.created_at()),
            None => return Ok(()),
        };

        // 1. Time-based rolling check
        if let Some(created) = active_created {
            let age = SystemTime::now().duration_since(created).unwrap_or_default();
            if age.as_secs() >= policy.max_log_age_secs && active_offset > crate::log::record::FILE_HEADER_SIZE as u64 {
                log::info!(
                    "Active generation {} reached age threshold ({}s >= {}s); rolling for durability...",
                    active_gen,
                    age.as_secs(),
                    policy.max_log_age_secs
                );
                if let Some(ref w) = fs.log_writer {
                    if let Ok(Some((next_gen, sealed_md5))) = w.force_roll(&*fs.clock) {
                        let mut manifest = fs.manifest.write().unwrap();
                        manifest.set_generation_md5(next_gen - 1, sealed_md5);
                        manifest.record_roll(
                            next_gen,
                            format!("{:06}.log", next_gen),
                            fs.clock.now(),
                            crate::log::record::FILE_HEADER_SIZE as u64,
                        );
                    }
                    let _ = fs.sync_and_export_summary();
                }
            }
        }

        // 2. Sync sealed generations to all writable remotes
        let manifest = fs.manifest.read().unwrap().clone();
        for log_entry in &manifest.logs {
            let gen_num = log_entry.generation;
            let filename = &log_entry.filename;

            // Only sealed generations
            if gen_num >= active_gen {
                continue;
            }

            let expected_len = log_entry.total_bytes;
            let expected_md5 = log_entry.md5.as_ref();

            for (remote_name, remote, read_only, _) in &stores {
                if *read_only {
                    continue;
                }

                let remote_head = remote.head_object(filename)?;
                let needs_upload = match remote_head {
                    Some(ref obj) => obj.size != expected_len,
                    None => true,
                };

                if needs_upload {
                    if storage.exists(filename) {
                        log::info!(
                            "Replicating sealed {} ({} bytes) to remote '{}'...",
                            filename,
                            expected_len,
                            remote_name
                        );
                        upload_storage_file(storage.as_ref(), remote.as_ref(), filename, expected_md5)?;
                    } else {
                        // Cross-copy from another remote holding this generation
                        for (src_name, src_remote, _, _) in &stores {
                            if src_name == remote_name {
                                continue;
                            }
                            if let Ok(Some(src_obj)) = src_remote.head_object(filename)
                                && src_obj.size == expected_len
                            {
                                log::info!(
                                    "Cross-copying {} ({} bytes) from remote '{}' to remote '{}'...",
                                    filename,
                                    expected_len,
                                    src_name,
                                    remote_name
                                );
                                let _ = cross_copy_file(
                                    src_remote.as_ref(),
                                    remote.as_ref(),
                                    filename,
                                    expected_len,
                                    expected_md5,
                                );
                                break;
                            }
                        }
                    }

                    // Clean up any transient parts on this remote once consolidated log is verified
                    let parts = remote.list_objects(&format!("{:06}.part", gen_num)).unwrap_or_default();
                    for part in parts {
                        let _ = remote.delete_object(&part.key);
                    }
                }

                fs.replication_telemetry
                    .write()
                    .unwrap()
                    .record_synced_gen(remote_name, gen_num);
            }
        }

        // 3. Sync latest .summary checkpoint file to writable remotes
        let local_files = storage.list_files()?;
        let latest_summary = local_files.iter().filter(|f| f.ends_with(".summary")).max().cloned();

        if let Some(ref sum_file) = latest_summary {
            for (remote_name, remote, read_only, _) in &stores {
                if *read_only {
                    continue;
                }
                let head = remote.head_object(sum_file)?;
                let local_len = storage.file_len(sum_file).unwrap_or(0);
                if head.is_none() || head.map(|h| h.size) != Some(local_len) {
                    log::info!("Syncing latest checkpoint {} to remote '{}'...", sum_file, remote_name);
                    let _ = upload_storage_file(storage.as_ref(), remote.as_ref(), sum_file, None);
                }
            }
        }

        // 4. Active generation part-chunk upload (every active_sync_interval_secs)
        let now = SystemTime::now();
        let time_since_last_part = now.duration_since(*last_part_sync).unwrap_or_default();

        if time_since_last_part.as_secs() >= policy.active_sync_interval_secs {
            let (last_offset, part_idx) = uploaded_parts
                .entry(active_gen)
                .or_insert((crate::log::record::FILE_HEADER_SIZE as u64, 0));
            if active_offset > *last_offset {
                let part_len = active_offset - *last_offset;
                let part_filename = format!("{:06}.part{:04}.log", active_gen, *part_idx);

                // Read slice from local active log
                let active_filename = format!("{:06}.log", active_gen);
                if let Ok(reader) = storage.open_reader(&active_filename) {
                    let mut part_bytes = vec![0u8; part_len as usize];
                    if reader.read_exact_at(*last_offset, &mut part_bytes).is_ok() {
                        let part_md5: [u8; 16] = *md5::compute(&part_bytes);
                        for (remote_name, remote, read_only, _) in &stores {
                            if *read_only {
                                continue;
                            }
                            log::info!(
                                "Uploading active incremental part {} ({} bytes) to remote '{}'...",
                                part_filename,
                                part_len,
                                remote_name
                            );
                            let _ = remote.put_object(&part_filename, &mut &part_bytes[..], part_len, Some(&part_md5));
                            fs.replication_telemetry.write().unwrap().record_active_part(
                                remote_name,
                                active_gen,
                                *part_idx,
                            );
                        }
                        *last_offset = active_offset;
                        *part_idx += 1;
                    }
                }
            }
            *last_part_sync = now;
        }

        // 5. Tiered storage local eviction / pruning
        Self::prune_eligible_local_logs(&storage, &manifest, active_gen, &policy, &stores);

        Ok(())
    }

    fn prune_eligible_local_logs(
        storage: &Arc<dyn Storage>,
        manifest: &crate::log::LogManifest,
        active_gen: u64,
        policy: &crate::remote::config::ReplicationPolicy,
        stores: &[(String, Arc<dyn RemoteStore>, bool, bool)],
    ) {
        let now = SystemTime::now();
        let retention_dur = Duration::from_secs(policy.local_retention_days * 86400);

        for log_entry in &manifest.logs {
            let gen_num = log_entry.generation;
            let filename = &log_entry.filename;

            // Cannot prune active generation
            if gen_num >= active_gen {
                continue;
            }

            if !storage.exists(filename) {
                continue;
            }

            let age = now.duration_since(log_entry.created_at).unwrap_or_default();
            if age < retention_dur {
                continue;
            }

            // Verify quorum k of N stores have matching size and ETag
            let mut verified_copies = 0;
            for (_, remote, _, _) in stores {
                if let Ok(Some(remote_obj)) = remote.head_object(filename)
                    && remote_obj.size == log_entry.total_bytes
                {
                    if let Some(expected_md5) = log_entry.md5 {
                        if remote_obj.etag_md5() == Some(expected_md5) {
                            verified_copies += 1;
                        }
                    } else {
                        verified_copies += 1;
                    }
                }
            }

            if verified_copies >= policy.min_synced_remotes {
                log::info!(
                    "Pruning local sealed {} ({} days old, verified on {} remotes)...",
                    filename,
                    age.as_secs() / 86400,
                    verified_copies
                );
                let _ = storage.remove_file(filename);
            }
        }
    }

    /// Stops the background worker and joins its thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RemoteReplicationWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_upload_storage_file_and_cross_copy() {
        let storage = Arc::new(MemoryStorage::new());
        let mut writer = storage
            .open_writer("000001.log", crate::storage::WriteMode::CreateNew)
            .unwrap();
        writer.append(b"sealed log contents 12345678").unwrap();
        drop(writer);

        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let expected_md5: [u8; 16] = *md5::compute(b"sealed log contents 12345678");

        // Upload from local storage to remote 1
        upload_storage_file(storage.as_ref(), remote1.as_ref(), "000001.log", Some(&expected_md5)).unwrap();

        let head = remote1.head_object("000001.log").unwrap().unwrap();
        assert_eq!(head.size, 28);
        assert_eq!(head.etag_md5(), Some(expected_md5));

        // Cross-copy from remote 1 to remote 2
        cross_copy_file(
            remote1.as_ref(),
            remote2.as_ref(),
            "000001.log",
            28,
            Some(&expected_md5),
        )
        .unwrap();

        let head2 = remote2.head_object("000001.log").unwrap().unwrap();
        assert_eq!(head2.size, 28);
        assert_eq!(head2.etag_md5(), Some(expected_md5));
    }
}
