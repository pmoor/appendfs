use crate::fs::InMemoryFS;
use crate::log::manifest::GenerationLiveStats;
use crate::node::NodeKind;
use std::fmt::Write as FmtWrite;

/// Aggregate statistics and fragmentation status for an appendfs volume.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeStats {
    pub next_generation: u64,
    pub total_inodes: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub symlink_count: usize,
    pub total_logical_bytes: u64,
    pub total_disk_bytes: u64,
    pub total_data_bytes: u64,
    pub total_live_bytes: u64,
    pub overall_live_ratio: f64,
    pub generations: Vec<GenerationLiveStats>,
}

impl VolumeStats {
    /// Returns the physical filename for the next log generation (e.g. "000002.log").
    pub fn next_filename(&self) -> String {
        crate::log::log_filename(self.next_generation)
    }

    /// Collects volume statistics from an in-memory filesystem state.
    pub fn collect(fs: &InMemoryFS) -> Self {
        let manifest = fs.manifest.read().unwrap().clone();
        let base = fs.base.read().unwrap();
        let total_inodes = base.len();

        let mut directory_count = 0;
        let mut file_count = 0;
        let mut symlink_count = 0;
        let mut total_logical_bytes = 0;

        for node_arc in base.values() {
            let node = node_arc.as_ref();
            match &node.kind {
                NodeKind::Directory { .. } => directory_count += 1,
                NodeKind::File { size, .. } => {
                    file_count += 1;
                    total_logical_bytes += *size;
                }
                NodeKind::Symlink { .. } => symlink_count += 1,
                NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket => {}
            }
        }

        let generations = fs.calculate_generation_live_stats();
        let mut total_disk_bytes = 0;
        let mut total_data_bytes = 0;
        let mut total_live_bytes = 0;

        for g in &generations {
            total_disk_bytes += g.total_bytes;
            total_data_bytes += g.total_data_bytes;
            total_live_bytes += g.live_bytes;
        }

        let overall_live_ratio = if total_data_bytes > 0 {
            total_live_bytes as f64 / total_data_bytes as f64
        } else if generations.is_empty() {
            1.0
        } else {
            0.0
        };

        Self {
            next_generation: manifest.next_generation,
            total_inodes,
            directory_count,
            file_count,
            symlink_count,
            total_logical_bytes,
            total_disk_bytes,
            total_data_bytes,
            total_live_bytes,
            overall_live_ratio,
            generations,
        }
    }

    /// Formats stats into a clean, human-readable terminal table.
    pub fn display_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "=== appendfs Volume Statistics ===").unwrap();
        writeln!(
            out,
            "Next Generation:     {} ({})",
            self.next_generation,
            self.next_filename()
        )
        .unwrap();
        writeln!(
            out,
            "Total Inodes:        {} ({} directories, {} files, {} symlinks)",
            self.total_inodes, self.directory_count, self.file_count, self.symlink_count
        )
        .unwrap();
        writeln!(out, "Logical Data Size:   {}", format_bytes(self.total_logical_bytes)).unwrap();
        writeln!(out, "Physical Log Size:   {}", format_bytes(self.total_disk_bytes)).unwrap();
        if self.total_data_bytes > 0 {
            writeln!(out, "Overall Live Ratio:  {:.1}%", self.overall_live_ratio * 100.0).unwrap();
        } else {
            writeln!(out, "Overall Live Ratio:  N/A (no data payload)").unwrap();
        }
        writeln!(out).unwrap();

        if self.generations.is_empty() {
            writeln!(
                out,
                "No log generation files present (clean unmounted / fresh summary)."
            )
            .unwrap();
        } else {
            writeln!(
                out,
                "{:<14} {:>10} {:>12} {:>12} {:>12} {:>8} {:>12}  STATUS",
                "LOG FILE", "RECORDS", "LOG SIZE", "DATA SIZE", "LIVE DATA", "EXTENTS", "LIVE RATIO"
            )
            .unwrap();
            writeln!(
                out,
                "{:-<14} {:-<10} {:-<12} {:-<12} {:-<12} {:-<8} {:-<12}  {:-<24}",
                "", "", "", "", "", "", "", ""
            )
            .unwrap();

            for g in &self.generations {
                let (status, ratio_str) =
                    format_generation_status(g.total_data_bytes, g.live_bytes, g.live_ratio, g.record_count);

                writeln!(
                    out,
                    "{:<14} {:>10} {:>12} {:>12} {:>12} {:>8} {:>12}  {}",
                    g.filename,
                    g.record_count,
                    format_bytes(g.total_bytes),
                    format_bytes(g.total_data_bytes),
                    format_bytes(g.live_bytes),
                    g.live_extents,
                    ratio_str,
                    status,
                )
                .unwrap();
            }
        }

        out
    }
}

/// Determines the status label and live ratio display string for a log generation.
pub fn format_generation_status(
    total_data_bytes: u64,
    live_bytes: u64,
    live_ratio: f64,
    record_count: u32,
) -> (&'static str, String) {
    if total_data_bytes == 0 {
        let status = if record_count == 0 { "Empty" } else { "Metadata Only" };
        (status, "N/A".to_string())
    } else {
        let ratio_str = format!("{:.1}%", live_ratio * 100.0);
        let status = if live_bytes == 0 {
            "Dead (0% - Reclaimable)"
        } else if live_ratio < 0.30 {
            "Compaction Candidate"
        } else if live_ratio < 0.70 {
            "Fragmented"
        } else {
            "Healthy"
        };
        (status, ratio_str)
    }
}

/// Formats a byte size into a human-readable string (B, KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats a complete human-readable report of runtime filesystem statistics and health.
pub fn format_runtime_status(fs: &InMemoryFS) -> String {
    use std::sync::atomic::Ordering;

    let mut out = String::new();

    // 1. Volume & Manifest Info
    let (head_gen, next_gen, total_gens, total_disk_bytes) = {
        let manifest = fs.manifest.read().unwrap();
        let head = fs.log_writer.as_ref().map(|w| w.generation());
        let total_gens = manifest.logs.len();
        let total_disk: u64 = manifest.logs.iter().map(|l| l.total_bytes).sum();
        (head, manifest.next_generation, total_gens, total_disk)
    };

    let mode_str = if fs.is_read_only() { "Read-Only" } else { "Read-Write" };

    let cipher_str = format!("{:?}", fs.volume_header.cipher);
    let compression_str = format!("{:?}", fs.volume_header.compression);
    let key_source_str = format!("{}", fs.volume_header.key_source);
    let volume_id_hex = hex::encode(fs.volume_header.volume_id);

    let next_ino = fs.next_inode.load(Ordering::SeqCst);
    let last_tx = fs.last_tx_id.load(Ordering::SeqCst);

    let rec_time_str = {
        let guard = fs.recovered_time.read().unwrap();
        match *guard {
            Some(t) => {
                let elapsed = fs.clock.now().duration_since(t).unwrap_or_default().as_secs();
                format!("{}s ago", elapsed)
            }
            None => "N/A (fresh session)".to_string(),
        }
    };

    out.push_str("=== appendfs Runtime Status ===\n\n");

    out.push_str("[Volume]\n");
    out.push_str(&format!("  Access Mode:        {}\n", mode_str));
    out.push_str(&format!("  Volume ID:          {}\n", volume_id_hex));
    out.push_str(&format!("  Cipher Suite:       {}\n", cipher_str));
    out.push_str(&format!("  Key Source:         {}\n", key_source_str));
    out.push_str(&format!("  Compression:        {}\n", compression_str));
    if let Some(head) = head_gen {
        out.push_str(&format!(
            "  Active Generation:  {} ({})\n",
            head,
            crate::log::log_filename(head)
        ));
    } else {
        out.push_str("  Active Generation:  None (read-only / detached log writer)\n");
    }
    out.push_str(&format!(
        "  Next Generation:    {} ({})\n",
        next_gen,
        crate::log::log_filename(next_gen)
    ));
    out.push_str(&format!("  Total Generations:  {}\n", total_gens));
    out.push_str(&format!("  Physical Log Size:  {}\n", format_bytes(total_disk_bytes)));
    out.push_str(&format!("  Next Inode:         {}\n", next_ino));
    out.push_str(&format!("  Last Tx ID:         {}\n", last_tx));
    out.push_str(&format!("  Last Recovery:      {}\n", rec_time_str));
    out.push('\n');

    // 2. Inodes Across Layers
    let (total_active, dirs, files, symlinks, special, live_len, flushing_batches, base_len) = {
        fs.with_layers(|live, flushing, base| {
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            let mut dirs = 0;
            let mut files = 0;
            let mut symlinks = 0;
            let mut special = 0;

            for &ino in live
                .keys()
                .chain(flushing.iter().flat_map(|b| b.keys()))
                .chain(base.keys())
            {
                if !seen.insert(ino) {
                    continue;
                }
                let file_type = if let Some(delta) = live.get(&ino) {
                    match delta {
                        crate::node::EntryDelta::Tombstone => None,
                        crate::node::EntryDelta::Node(d) => Some(d.file_type()),
                    }
                } else if let Some(delta) = flushing.iter().rev().find_map(|b| b.get(&ino)) {
                    match delta {
                        crate::node::EntryDelta::Tombstone => None,
                        crate::node::EntryDelta::Node(d) => Some(d.file_type()),
                    }
                } else {
                    base.get(&ino).map(|n| n.file_type())
                };

                if let Some(ft) = file_type {
                    match ft {
                        crate::shim::FileType::Directory => dirs += 1,
                        crate::shim::FileType::RegularFile => files += 1,
                        crate::shim::FileType::Symlink => symlinks += 1,
                        _ => special += 1,
                    }
                }
            }
            let total = dirs + files + symlinks + special;
            (
                total,
                dirs,
                files,
                symlinks,
                special,
                live.len(),
                flushing.len(),
                base.len(),
            )
        })
    };

    out.push_str("[Inodes]\n");
    out.push_str(&format!(
        "  Active Inodes:      {} ({} directories, {} files, {} symlinks, {} special)\n",
        total_active, dirs, files, symlinks, special
    ));
    out.push_str(&format!("  Live Staged Inodes: {}\n", live_len));
    out.push_str(&format!("  Flushing Batches:   {}\n", flushing_batches));
    out.push_str(&format!("  Base Inodes:        {}\n", base_len));
    out.push('\n');

    // 3. Flush Layer Stats
    let staged_bytes = fs.staged_bytes.load(Ordering::SeqCst);
    let max_buffer_size = fs.max_buffer_size;
    let staged_ops = fs.staged_ops.load(Ordering::SeqCst);
    let max_staged_ops = fs.max_staged_ops;
    let max_extent_size = fs.max_extent_size;
    let max_flush_queue_depth = fs.max_flush_queue_depth;

    let bytes_since_summary = fs.bytes_since_last_summary.load(Ordering::SeqCst);
    let summary_interval_bytes = fs.summary_interval_bytes.load(Ordering::SeqCst);
    let gens_since_summary = fs.generations_since_last_summary.load(Ordering::SeqCst);
    let summary_interval_gens = fs.summary_interval_generations.load(Ordering::SeqCst);
    let last_summary_gen = fs.last_summary_generation.load(Ordering::SeqCst);

    let buffer_pct = if max_buffer_size > 0 {
        (staged_bytes as f64 / max_buffer_size as f64) * 100.0
    } else {
        0.0
    };

    out.push_str("[Flush Layer]\n");
    out.push_str(&format!(
        "  Staged Data:        {} / {} ({:.1}%)\n",
        format_bytes(staged_bytes as u64),
        format_bytes(max_buffer_size as u64),
        buffer_pct
    ));
    out.push_str(&format!("  Staged Operations:  {} / {}\n", staged_ops, max_staged_ops));
    out.push_str(&format!(
        "  Flushing Queue:     {} / {} batches\n",
        flushing_batches, max_flush_queue_depth
    ));
    out.push_str(&format!(
        "  Max Extent Size:    {}\n",
        format_bytes(max_extent_size as u64)
    ));
    out.push_str("  Summary Triggers:\n");
    if summary_interval_bytes > 0 {
        out.push_str(&format!(
            "    Flushed Data:     {} / {}\n",
            format_bytes(bytes_since_summary),
            format_bytes(summary_interval_bytes)
        ));
    } else {
        out.push_str(&format!(
            "    Flushed Data:     {} / Disabled\n",
            format_bytes(bytes_since_summary)
        ));
    }
    if summary_interval_gens > 0 {
        out.push_str(&format!(
            "    Rolled Gens:      {} / {}\n",
            gens_since_summary, summary_interval_gens
        ));
    } else {
        out.push_str(&format!("    Rolled Gens:      {} / Disabled\n", gens_since_summary));
    }
    out.push_str(&format!("    Last Summary Gen: {}\n", last_summary_gen));
    out.push('\n');

    // 4. Cache Stats
    out.push_str("[Cache]\n");
    if let Some(ref log_cache) = fs.log_cache {
        let cur_bytes = log_cache.decrypted_cache.current_bytes();
        let max_bytes = log_cache.decrypted_cache.max_bytes();
        let record_count = log_cache.decrypted_cache.len();
        let cache_pct = if max_bytes > 0 {
            (cur_bytes as f64 / max_bytes as f64) * 100.0
        } else {
            0.0
        };

        out.push_str(&format!(
            "  Decrypted Records:  {} / {} ({:.1}%, {} entries)\n",
            format_bytes(cur_bytes as u64),
            format_bytes(max_bytes as u64),
            cache_pct,
            record_count
        ));

        let block_summary = match &log_cache.block_cache {
            Some(bc) => bc.summary(),
            None => "Disabled".to_string(),
        };
        out.push_str(&format!("  Block Cache:        {}\n", block_summary));
        out.push_str(&format!("  Open Log Readers:   {}\n", log_cache.open_readers_count()));
    } else {
        out.push_str("  Decrypted Records:  Disabled (no log cache attached)\n");
        out.push_str("  Block Cache:        Disabled\n");
        out.push_str("  Open Log Readers:   0\n");
    }
    out.push('\n');

    // 5. Handles & Locks
    let file_handles_count = fs.file_handles.read().unwrap().len();
    let dir_handles_count = fs.dir_handles.read().unwrap().len();
    let virtual_handles_count = fs.virtual_handles.read().unwrap().len();
    let open_inodes_count = fs.open_counts.read().unwrap().len();
    let flock_count = fs.flock_table.lock().unwrap().len();
    let range_lock_count = fs.range_lock_table.lock().unwrap().len();

    out.push_str("[Handles & Locks]\n");
    out.push_str(&format!("  Open File Handles:  {}\n", file_handles_count));
    out.push_str(&format!("  Open Dir Handles:   {}\n", dir_handles_count));
    out.push_str(&format!("  Open Virtual FHs:   {}\n", virtual_handles_count));
    out.push_str(&format!("  Open Inodes:        {}\n", open_inodes_count));
    out.push_str(&format!("  Active File Locks:  {}\n", flock_count));
    out.push_str(&format!("  Active Range Locks: {}\n", range_lock_count));

    // 6. Replication Remotes (if configured)
    let remotes_count = fs
        .remote_registry
        .read()
        .unwrap()
        .as_ref()
        .map(|r| r.read().unwrap().remotes.len())
        .unwrap_or(0);
    if remotes_count > 0 {
        out.push('\n');
        out.push_str("[Replication]\n");
        out.push_str(&format!(
            "  Configured Remotes: {} (see .remotes for peer sync details)\n",
            remotes_count
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_stats_formatting() {
        let fs = InMemoryFS::new();
        let stats = VolumeStats::collect(&fs);
        assert_eq!(stats.total_inodes, 1);
        assert_eq!(stats.directory_count, 1);
        assert_eq!(stats.file_count, 0);

        let text = stats.display_text();
        assert!(text.contains("Total Inodes:        1"));
        assert!(text.contains("Overall Live Ratio:  N/A"));
    }

    #[test]
    fn test_format_generation_status() {
        // Zero data bytes
        assert_eq!(format_generation_status(0, 0, 0.0, 0), ("Empty", "N/A".to_string()));
        assert_eq!(
            format_generation_status(0, 0, 0.0, 10),
            ("Metadata Only", "N/A".to_string())
        );

        // Non-zero data bytes
        assert_eq!(
            format_generation_status(1000, 0, 0.0, 10),
            ("Dead (0% - Reclaimable)", "0.0%".to_string())
        );
        assert_eq!(
            format_generation_status(1000, 200, 0.20, 10),
            ("Compaction Candidate", "20.0%".to_string())
        );
        assert_eq!(
            format_generation_status(1000, 500, 0.50, 10),
            ("Fragmented", "50.0%".to_string())
        );
        assert_eq!(
            format_generation_status(1000, 950, 0.95, 10),
            ("Healthy", "95.0%".to_string())
        );
    }

    #[test]
    fn test_format_runtime_status_fresh_fs() {
        let fs = InMemoryFS::new();
        let status = format_runtime_status(&fs);

        assert!(status.contains("=== appendfs Runtime Status ==="));
        assert!(status.contains("[Volume]"));
        assert!(status.contains("Access Mode:        Read-Write"));
        assert!(status.contains("Active Generation:  None"));
        assert!(status.contains("Next Generation:    2"));

        assert!(status.contains("[Inodes]"));
        assert!(status.contains("Active Inodes:      1 (1 directories, 0 files, 0 symlinks, 0 special)"));
        assert!(status.contains("Live Staged Inodes: 0"));
        assert!(status.contains("Flushing Batches:   0"));
        assert!(status.contains("Base Inodes:        1"));

        assert!(status.contains("[Flush Layer]"));
        assert!(status.contains("Staged Data:        0 B"));
        assert!(status.contains("Staged Operations:  0"));

        assert!(status.contains("[Cache]"));
        assert!(status.contains("Decrypted Records:  Disabled"));
        assert!(status.contains("Block Cache:        Disabled"));

        assert!(status.contains("[Handles & Locks]"));
        assert!(status.contains("Open File Handles:  0"));
        assert!(status.contains("Open Dir Handles:   0"));
        assert!(status.contains("Active File Locks:  0"));
        assert!(status.contains("Active Range Locks: 0"));

        // Verify reading .status virtual file via handle
        let v_ino = fs.lookup_child(1, ".status").expect(".status must exist");
        let fh = fs.open_file_handle(v_ino, 0);
        assert_ne!(fh & crate::fs::VIRTUAL_FH_FLAG, 0);
        let content = fs.read_handle(v_ino, fh, 0, 1024).unwrap();
        let s = String::from_utf8(content).unwrap();
        assert!(s.contains("=== appendfs Runtime Status ==="));
        fs.release_file_handle(fh, v_ino).unwrap();
    }

    #[test]
    fn test_format_runtime_status_with_activity() {
        use crate::operations::dir::{mkdir_core, opendir_core, releasedir_core};
        use crate::operations::locks::{flock_core, setlk_core};
        use crate::operations::read_write::create_core;
        use crate::remote::block_cache::MemoryBlockCache;
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let clock = Arc::new(crate::clock::SystemClock);
        let mut fs = InMemoryFS::with_clock_and_storage(clock, storage.clone());

        // Attach LogFileCache with MemoryBlockCache
        let block_cache = Arc::new(MemoryBlockCache::new(10 * 1024 * 1024));
        let log_cache = Arc::new(crate::log::LogFileCache::with_remote_support(
            storage,
            Some(block_cache),
            Vec::<crate::remote::RemoteReadTarget>::new(),
            Some(Arc::clone(&fs.manifest)),
        ));
        log_cache.set_decrypted_cache_size(64 * 1024 * 1024);
        fs.log_cache = Some(log_cache.clone());

        // Populate decrypted cache with a dummy entry
        log_cache.decrypted_cache.insert(1, 100, Arc::new(vec![0u8; 4096]));

        // Create entries: 1 subfolder, 2 files, 1 symlink
        let dir = mkdir_core(&fs, 1, "sub", 0o755, 1000, 1000).unwrap();
        let f1 = create_core(&fs, 1, "f1.txt", 0o644, 0, 1000, 1000).unwrap();
        let f2 = create_core(&fs, dir.ino, "f2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::symlink_core(&fs, 1, "link.txt", "f1.txt", 1000, 1000).unwrap();

        // Write some staged data
        crate::operations::read_write::write_core(&fs, f1.ino, b"hello world staged data", 0).unwrap();

        // Open handles
        let fh_file1 = fs.open_file_handle(f1.ino, 0);
        let fh_file2 = fs.open_file_handle(f2.ino, 0);
        let dh = opendir_core(&fs, dir.ino, 0).unwrap();

        // Acquire locks
        flock_core(&fs, f1.ino, fh_file1, 1001, libc::LOCK_EX).unwrap();
        let rlock = crate::shim::ShimFlock {
            lock_type: libc::F_WRLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 100,
            pid: 100,
        };
        setlk_core(&fs, f2.ino, fh_file2, 1002, rlock, false).unwrap();

        // Inspect status
        let status = format_runtime_status(&fs);

        // 1 root + 1 subfolder = 2 directories, 2 files, 1 symlink = 5 active inodes
        assert!(status.contains("Active Inodes:      5 (2 directories, 2 files, 1 symlinks, 0 special)"));
        assert!(status.contains("Live Staged Inodes: 5")); // root, f1, f2, sub, link
        assert!(status.contains("Staged Data:        23 B"));
        assert!(status.contains("Open File Handles:  2"));
        assert!(status.contains("Open Dir Handles:   1"));
        assert!(status.contains("Active File Locks:  1"));
        assert!(status.contains("Active Range Locks: 1"));
        assert!(status.contains("Decrypted Records:  4.00 KiB / 64.00 MiB"));
        assert!(status.contains("Block Cache:        In-Memory (limit: 10.00 MiB)"));

        // Clean up handles
        fs.release_file_handle(fh_file1, f1.ino).unwrap();
        fs.release_file_handle(fh_file2, f2.ino).unwrap();
        releasedir_core(&fs, dir.ino, dh).unwrap();

        // Check read-only mode reporting
        fs.set_read_only(true);
        let ro_status = format_runtime_status(&fs);
        assert!(ro_status.contains("Access Mode:        Read-Only"));
    }
}
