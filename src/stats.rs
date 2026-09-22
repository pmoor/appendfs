use crate::extent_map::Extent;
use crate::fs::{InMemoryFS, InodeCounts};
use crate::log::LogManifest;
use crate::log::manifest::GenerationLiveStats;
use crate::node::{Node, NodeKind};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;

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

    /// Constructs VolumeStats from individual pre-computed parts.
    pub fn from_parts(next_generation: u64, counts: &InodeCounts, generations: Vec<GenerationLiveStats>) -> Self {
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
            next_generation,
            total_inodes: counts.total_active(),
            directory_count: counts.directories,
            file_count: counts.files,
            symlink_count: counts.symlinks,
            total_logical_bytes: counts.total_logical_bytes,
            total_disk_bytes,
            total_data_bytes,
            total_live_bytes,
            overall_live_ratio,
            generations,
        }
    }

    /// Collects volume statistics from an in-memory filesystem state.
    pub fn collect(fs: &InMemoryFS) -> Self {
        let counts = fs.inode_counts();
        let generations = fs.calculate_generation_live_stats();
        Self::from_parts(fs.next_generation(), &counts, generations)
    }

    /// Collects volume statistics directly from a snapshot's inodes and manifest.
    pub fn collect_from_snapshot(inodes: &HashMap<u64, Arc<Node>>, manifest: &LogManifest) -> Self {
        let counts = InodeCounts::from_nodes(inodes.values().map(|a| a.as_ref()));
        let generations = calculate_generation_live_stats_from_nodes(inodes.values().map(|a| a.as_ref()), manifest);
        let next_generation = manifest
            .logs
            .iter()
            .map(|l| l.generation)
            .max()
            .map_or(1, |max| max + 1);
        Self::from_parts(next_generation, &counts, generations)
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

        out.push_str(&format_generations_table(&self.generations));
        out
    }
}

/// Dynamically calculates live extent statistics across all active files and log generations from a node iterator.
pub fn calculate_generation_live_stats_from_nodes<'a, I>(nodes: I, manifest: &LogManifest) -> Vec<GenerationLiveStats>
where
    I: IntoIterator<Item = &'a Node>,
{
    let mut live_map: HashMap<u64, (u64, u32)> = HashMap::new();
    for node in nodes {
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

    let mut result = Vec::with_capacity(manifest.logs.len());
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
            sealed: log.sealed,
        });
    }
    result
}

/// Formats a table of log generations with records, sizes, live data, extents, live ratio, and status.
pub fn format_generations_table(generations: &[GenerationLiveStats]) -> String {
    let mut out = String::new();
    if generations.is_empty() {
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

        for g in generations {
            let (status, ratio_str) =
                format_generation_status(g.total_data_bytes, g.live_bytes, g.live_ratio, g.record_count);

            let display_status = if !g.sealed {
                format!("{status} (not sealed)")
            } else {
                status.to_string()
            };

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
                display_status,
            )
            .unwrap();
        }
    }
    out
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

/// Formats a duration into a human-readable string (ns, µs, ms, s).
pub fn format_duration(d: std::time::Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.2} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", d.as_secs_f64())
    }
}

/// Formats a complete human-readable report of runtime filesystem statistics and health.
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn format_runtime_status(fs: &InMemoryFS) -> String {
    use std::sync::atomic::Ordering;

    let snap = fs.stats_snapshot();
    let mut out = String::new();

    // 1. Volume & Manifest Info
    let (head_gen, next_gen, total_gens, total_disk_bytes) = {
        let manifest = fs.manifest.read().unwrap();
        let head = fs.log_writer.as_ref().filter(|w| w.is_open()).map(|w| w.generation());
        let total_gens = manifest.logs.len();
        let total_disk: u64 = manifest.logs.iter().map(|l| l.total_bytes).sum();
        (head, fs.next_generation(), total_gens, total_disk)
    };

    let mode_str = if fs.is_read_only() { "Read-Only" } else { "Read-Write" };

    let cipher_str = format!("{:?}", fs.volume_header.cipher);
    let compression_str = format!("{:?}", fs.volume_header.compression);
    let key_source_str = format!("{}", fs.volume_header.key_source);
    let volume_id_hex = hex::encode(fs.volume_header.volume_id);

    let next_ino = fs.next_inode.load(Ordering::SeqCst);
    let last_batch = fs.last_batch_id.load(Ordering::SeqCst);

    let rec_time_str = match snap.recovered_time {
        Some(t) => {
            let elapsed = fs.clock.now().duration_since(t).unwrap_or_default().as_secs();
            format!("{}s ago", elapsed)
        }
        None => "N/A (fresh session)".to_string(),
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
    } else if fs.log_writer.as_ref().is_some_and(|w| !w.is_open()) {
        out.push_str("  Active Generation:  None (lazy / unopened)\n");
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
    out.push_str(&format!("  Last Batch ID:      {}\n", last_batch));
    out.push_str(&format!("  Last Recovery:      {}\n", rec_time_str));
    out.push('\n');

    // 2. Inodes Across Layers
    out.push_str("[Inodes]\n");
    out.push_str(&format!(
        "  Active Inodes:      {} ({} directories, {} files, {} symlinks, {} special)\n",
        snap.inode_counts.total_active(),
        snap.inode_counts.directories,
        snap.inode_counts.files,
        snap.inode_counts.symlinks,
        snap.inode_counts.special()
    ));
    out.push_str(&format!("  Live Staged Inodes: {}\n", snap.live_len));
    out.push_str(&format!("  Flushing Batches:   {}\n", snap.flushing_batches));
    out.push_str(&format!("  Base Inodes:        {}\n", snap.base_len));
    out.push('\n');

    // 3. Flush Layer Stats
    let max_buffer_size = fs.max_buffer_size;
    let max_staged_ops = fs.max_staged_ops;
    let max_extent_size = fs.max_extent_size;
    let max_flush_queue_depth = fs.max_flush_queue_depth;
    let max_flush_queue_bytes = fs.max_flush_queue_bytes;
    let max_flush_queue_ops = fs.max_flush_queue_ops;

    let bytes_since_summary = fs.bytes_since_last_summary.load(Ordering::SeqCst);
    let summary_interval_bytes = fs.summary_interval_bytes.load(Ordering::SeqCst);
    let gens_since_summary = fs.generations_since_last_summary.load(Ordering::SeqCst);
    let summary_interval_gens = fs.summary_interval_generations.load(Ordering::SeqCst);
    let last_summary_gen = fs.last_summary_generation.load(Ordering::SeqCst);

    let buffer_pct = if max_buffer_size > 0 {
        (snap.staged_bytes as f64 / max_buffer_size as f64) * 100.0
    } else {
        0.0
    };

    out.push_str("[Flush Layer]\n");
    out.push_str(&format!(
        "  Staged Data:        {} / {} ({:.1}%)\n",
        format_bytes(snap.staged_bytes as u64),
        format_bytes(max_buffer_size as u64),
        buffer_pct
    ));
    out.push_str(&format!(
        "  Staged Operations:  {} / {}\n",
        snap.staged_ops, max_staged_ops
    ));
    out.push_str(&format!(
        "  Flushing Queue:     {} / {} batches ({} / {} data, {} / {} ops)\n",
        snap.flushing_batches,
        max_flush_queue_depth,
        format_bytes(snap.flushing_bytes as u64),
        format_bytes(max_flush_queue_bytes as u64),
        snap.flushing_ops,
        max_flush_queue_ops
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

    // 4. Flusher
    let flush = fs.flush_stats();
    out.push_str("[Flusher]\n");
    out.push_str(&format!(
        "  Mode:               {}\n",
        match (flush.background, flush.interval) {
            (true, Some(i)) => format!("background (flushes after {} idle)", format_duration(i)),
            (true, None) => "background (no inactivity flush)".to_string(),
            (false, _) => "inline (runs on the calling thread)".to_string(),
        }
    ));
    out.push_str(&format!(
        "  Batches Flushed:    {} ({} staged, {} on disk, {} ops)\n",
        flush.total_batches,
        format_bytes(flush.total_bytes),
        format_bytes(flush.total_disk_bytes),
        flush.total_ops
    ));
    out.push_str(&format!(
        "  Time Flushing:      {} serialize, {} wait, {} flush, {} folding into base\n",
        format_duration(flush.total_serialize),
        format_duration(flush.total_wait),
        format_duration(flush.total_flush),
        format_duration(flush.total_fold)
    ));
    let reasons: Vec<String> = crate::fs::FlushReason::ALL
        .iter()
        .filter(|r| flush.count_for(**r) > 0)
        .map(|r| format!("{} {}", r, flush.count_for(*r)))
        .collect();
    out.push_str(&format!(
        "  By Reason:          {}\n",
        if reasons.is_empty() {
            "None".to_string()
        } else {
            reasons.join(", ")
        }
    ));
    if flush.recent.is_empty() {
        out.push_str("  Recent Flushes:     None\n");
    } else {
        out.push_str("  Recent Flushes:\n");
        out.push_str(&format!(
            "    {:<7} {:<11} {:>10} {:>10} {:>7}  {:>10} {:>10} {:>10} {:>10} {:>10}  {}\n",
            "batch", "reason", "bytes", "on-disk", "ops", "serialize", "wait", "flush", "fold", "total", "age"
        ));
        let now = fs.clock.now();
        for record in flush.recent.iter().rev() {
            let age = now.duration_since(record.started_at).unwrap_or_default().as_secs();
            out.push_str(&format!(
                "    #{:<6} {:<11} {:>10} {:>10} {:>7}  {:>10} {:>10} {:>10} {:>10} {:>10}  {}s ago\n",
                record.id,
                record.reason,
                format_bytes(record.bytes as u64),
                format_bytes(record.disk_bytes),
                record.ops,
                format_duration(record.serialize),
                format_duration(record.wait),
                format_duration(record.flush),
                format_duration(record.fold),
                format_duration(record.duration),
                age
            ));
        }
    }
    out.push('\n');

    // 5. Cache Stats
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

    // 6. Handles & Locks
    let mutex_lock_count = fs.inner.lock_count();
    let mutex_busy_time = fs.inner.busy_time();
    let mutex_wait_time = fs.inner.wait_time();
    let avg_hold = if mutex_lock_count > 0 {
        mutex_busy_time / (mutex_lock_count as u32)
    } else {
        std::time::Duration::ZERO
    };

    out.push_str("[Handles & Locks]\n");
    out.push_str(&format!("  Open File Handles:  {}\n", snap.file_handles_count));
    out.push_str(&format!("  Open Virt Handles:  {}\n", snap.virt_handles_count));
    out.push_str(&format!("  Open Dir Handles:   {}\n", snap.dir_handles_count));
    out.push_str(&format!("  Open Inodes:        {}\n", snap.open_inodes_count));
    out.push_str(&format!("  Active File Locks:  {}\n", snap.flock_count));
    out.push_str(&format!("  Active Range Locks: {}\n", snap.range_lock_count));
    out.push_str(&format!("  Mutex Lock Count:   {}\n", mutex_lock_count));
    out.push_str(&format!(
        "  Mutex Busy Time:    {} (avg: {} / lock)\n",
        format_duration(mutex_busy_time),
        format_duration(avg_hold)
    ));
    out.push_str(&format!("  Mutex Wait Time:    {}\n", format_duration(mutex_wait_time)));

    let mut op_stats: Vec<_> = fs.inner.op_stats().into_iter().filter(|s| s.count > 0).collect();
    if !op_stats.is_empty() {
        op_stats.sort_by_key(|s| std::cmp::Reverse(s.busy_time));
        out.push('\n');
        out.push_str("[Mutex Contention by Operation]\n");
        out.push_str(&format!(
            "  {:<12} {:>8} {:>12} {:>12} {:>12} {:>12}\n",
            "OPERATION", "ACQUIRES", "TOTAL TIME", "AVG HOLD", "MAX HOLD", "WAIT TIME"
        ));
        out.push_str(&format!(
            "  {:-<12} {:-<8} {:-<12} {:-<12} {:-<12} {:-<12}\n",
            "", "", "", "", "", ""
        ));
        for s in op_stats {
            out.push_str(&format!(
                "  {:<12} {:>8} {:>12} {:>12} {:>12} {:>12}\n",
                s.tag.name(),
                s.count,
                format_duration(s.busy_time),
                format_duration(s.avg_hold_time()),
                format_duration(s.max_hold_time),
                format_duration(s.wait_time),
            ));
        }
    }

    // 7. Pushback Throttling (if active or throttled)
    let total_delayed = fs.op_metrics.total_delayed();
    let total_stalled = fs.op_metrics.total_stalled();
    let active_delayed = fs.op_metrics.total_active_delayed();
    if total_delayed > 0 || active_delayed > 0 {
        out.push('\n');
        out.push_str("[Pushback Throttling]\n");
        out.push_str(&format!("  Active Waiters:     {}\n", active_delayed));
        out.push_str(&format!("  Total Throttled:    {}\n", total_delayed));
        out.push_str(&format!("  Hard Stalled:       {}\n", total_stalled));
        out.push_str(&format!(
            "  Total Delay Time:   {}\n",
            format_duration(fs.op_metrics.total_delay_duration())
        ));
        out.push_str(&format!(
            "  Avg Delay / Waiter: {}\n",
            format_duration(fs.op_metrics.avg_delay_duration())
        ));
    }

    // 8. FUSE Operations
    let op_calls = fs.op_metrics.total_calls();
    if op_calls > 0 {
        out.push('\n');
        out.push_str("[FUSE Operations]\n");
        out.push_str(&format!(
            "  {:<12} {:>8} {:>8} {:>10} {:>14} {:>8} {:>12} {:>12}\n",
            "OPERATION", "ACTIVE", "CALLS", "THROTTLED", "AVG THROTTLED", "STALLED", "AVG LAT", "MAX LAT"
        ));
        out.push_str(&format!(
            "  {:-<12} {:-<8} {:-<8} {:-<10} {:-<14} {:-<8} {:-<12} {:-<12}\n",
            "", "", "", "", "", "", "", ""
        ));
        for op in &crate::operations::op::ALL_FUSE_OPS {
            let calls = fs.op_metrics.calls(*op);
            if calls > 0 {
                out.push_str(&format!(
                    "  {:<12} {:>8} {:>8} {:>10} {:>14} {:>8} {:>12} {:>12}\n",
                    op.as_str(),
                    fs.op_metrics.active(*op),
                    calls,
                    fs.op_metrics.throttled(*op),
                    format_duration(fs.op_metrics.avg_throttled_duration(*op)),
                    fs.op_metrics.stalled(*op),
                    format_duration(fs.op_metrics.avg_latency(*op)),
                    format_duration(fs.op_metrics.max_latency(*op)),
                ));
            }
        }
    }

    // 9. Replication Remotes (if configured)
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
    use crate::sync::OpTag;
    use std::sync::Arc;

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
    fn test_volume_stats_from_snapshot_matches_collect() {
        use crate::extent_map::{Extent, ExtentMap};
        use crate::log::LogFileInfo;
        use crate::node::{InodeMeta, Node, NodeKind};
        use std::time::SystemTime;

        let fs = InMemoryFS::new();
        let now = SystemTime::UNIX_EPOCH;

        let mut extent_map = ExtentMap::new();
        extent_map.insert(0, Extent::new_disk(1, 100, 4133, 20, 4096));

        let file_node = Arc::new(Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, now),
            kind: NodeKind::File { extent_map, size: 4096 },
        });

        let dir_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("data.bin".to_string(), 2)],
            },
        });

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(2, file_node);
            inner.base.insert(3, dir_node);
        }

        {
            let mut manifest = fs.manifest.write().unwrap();
            manifest.logs.push(LogFileInfo {
                generation: 1,
                revision: 0,
                filename: "000001.log".to_string(),
                created_at: now,
                record_count: 10,
                total_bytes: 8192,
                total_data_bytes: 4096,
                md5: [0u8; 16],
                sealed: true,
            });
        }

        let stats_fs = VolumeStats::collect(&fs);
        let snapshot = fs.snapshot_all();
        let manifest = fs.manifest.read().unwrap().clone();
        let stats_snapshot = VolumeStats::collect_from_snapshot(&snapshot, &manifest);

        assert_eq!(stats_fs, stats_snapshot);
        assert_eq!(stats_fs.display_text(), stats_snapshot.display_text());
        assert_eq!(stats_snapshot.total_inodes, 3);
        assert_eq!(stats_snapshot.file_count, 1);
        assert_eq!(stats_snapshot.directory_count, 2);
        assert_eq!(stats_snapshot.total_logical_bytes, 4096);
        assert_eq!(stats_snapshot.total_live_bytes, 4096);
        assert_eq!(stats_snapshot.overall_live_ratio, 1.0);
    }

    #[test]
    fn test_format_generations_table_sealed_and_unsealed() {
        let generations = vec![
            GenerationLiveStats {
                generation: 1,
                filename: "000001.log".to_string(),
                record_count: 10,
                total_bytes: 8192,
                total_data_bytes: 4096,
                live_bytes: 4096,
                live_extents: 1,
                live_ratio: 1.0,
                sealed: true,
            },
            GenerationLiveStats {
                generation: 2,
                filename: "000002.log".to_string(),
                record_count: 5,
                total_bytes: 4096,
                total_data_bytes: 2048,
                live_bytes: 2048,
                live_extents: 1,
                live_ratio: 1.0,
                sealed: false,
            },
        ];

        let table = format_generations_table(&generations);
        assert!(table.contains("000001.log"));
        assert!(table.contains("000002.log"));
        // Gen 1 is sealed, so shows Healthy without "(not sealed)"
        assert!(
            table.contains("Healthy\n")
                || table
                    .lines()
                    .any(|l| l.contains("000001.log") && l.ends_with("Healthy"))
        );
        // Gen 2 is unsealed, so shows Healthy (not sealed)
        assert!(
            table
                .lines()
                .any(|l| l.contains("000002.log") && l.ends_with("Healthy (not sealed)"))
        );

        // Empty table
        let empty_table = format_generations_table(&[]);
        assert!(empty_table.contains("No log generation files present"));
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
        assert!(status.contains("Next Generation:    1"));

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
        assert!(status.contains("Open Virt Handles:  0"));
        assert!(status.contains("Open Dir Handles:   0"));
        assert!(status.contains("Active File Locks:  0"));
        assert!(status.contains("Active Range Locks: 0"));
        assert!(status.contains("Mutex Lock Count:"));
        assert!(status.contains("Mutex Busy Time:"));
        assert!(status.contains("Mutex Wait Time:"));

        // Verify reading .status virtual file via handle
        let v_ino = fs.lookup_child(1, ".status").expect(".status must exist");
        let fh = fs.open_file_handle(v_ino, 0);
        assert!(fh > 0);
        // While open, runtime status query reports 1 open virt handle and 1 open inode
        let open_status = format_runtime_status(&fs);
        assert!(open_status.contains("Open Virt Handles:  1"));
        assert!(open_status.contains("Open Inodes:        1"));
        // The handle itself holds the snapshot taken at open time (before fh was recorded)
        let content = fs.read_handle(v_ino, fh, 0, 4096).unwrap();
        let s = String::from_utf8(content).unwrap();
        assert!(s.contains("=== appendfs Runtime Status ==="));
        assert!(s.contains("Open Virt Handles:  0"));
        fs.release_file_handle(fh, v_ino).unwrap();
        let closed_status = format_runtime_status(&fs);
        assert!(closed_status.contains("Open Virt Handles:  0"));
        assert!(closed_status.contains("Open Inodes:        0"));
    }

    #[test]
    fn test_format_runtime_status_with_active_writer() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::SystemClock);
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage.clone());
        let writer = Arc::new(
            crate::log::LogWriter::create(
                storage,
                5,
                clock.as_ref(),
                1024 * 1024,
                1,
                Arc::new(crate::crypto::VolumeKey::plaintext()),
            )
            .unwrap(),
        );
        fs.attach_log_writer(writer);
        let status = format_runtime_status(&fs);
        assert!(status.contains("Active Generation:  5 (000005.log)"));
        assert!(status.contains("Next Generation:    6 (000006.log)"));
    }

    #[test]
    fn test_format_runtime_status_with_lazy_writer() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::SystemClock);
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage.clone());
        let writer = Arc::new(
            crate::log::LogWriter::create_lazy(
                storage,
                1,
                1024 * 1024,
                1,
                Arc::new(crate::crypto::VolumeKey::plaintext()),
            )
            .unwrap(),
        );
        fs.attach_log_writer(writer);
        let status = format_runtime_status(&fs);
        assert!(status.contains("Active Generation:  None (lazy / unopened)"));
        assert!(status.contains("Next Generation:    1 (000001.log)"));

        // After writing and flushing, the generation file is opened and active
        crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();
        let status_after_write = format_runtime_status(&fs);
        assert!(status_after_write.contains("Active Generation:  1 (000001.log)"));
        assert!(status_after_write.contains("Next Generation:    2 (000002.log)"));
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
        log_cache.decrypted_cache.insert(1, 0, 100, Arc::new(vec![0u8; 4096]));

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
        assert!(status.contains("Staged Data:        52 B"));
        assert!(status.contains("Open File Handles:  2"));
        assert!(status.contains("Open Virt Handles:  0"));
        assert!(status.contains("Open Dir Handles:   1"));
        assert!(status.contains("Active File Locks:  1"));
        assert!(status.contains("Active Range Locks: 1"));
        assert!(status.contains("Decrypted Records:  4.00 KiB / 64.00 MiB"));
        assert!(status.contains("Block Cache:        In-Memory (limit: 10.00 MiB)"));
        assert!(status.contains("[Mutex Contention by Operation]"));
        assert!(status.contains("write"));
        assert!(status.contains("create"));
        assert!(status.contains("mkdir"));

        // Clean up handles
        fs.release_file_handle(fh_file1, f1.ino).unwrap();
        fs.release_file_handle(fh_file2, f2.ino).unwrap();
        releasedir_core(&fs, dir.ino, dh).unwrap();

        // Check read-only mode reporting
        fs.set_read_only();
        let ro_status = format_runtime_status(&fs);
        assert!(ro_status.contains("Access Mode:        Read-Only"));
    }

    #[test]
    fn test_format_runtime_status_single_lock_acquisition() {
        let fs = InMemoryFS::new();
        let before_stats_count = fs
            .inner
            .op_stats()
            .into_iter()
            .find(|s| s.tag == OpTag::Stats)
            .map(|s| s.count)
            .unwrap_or(0);

        let _ = format_runtime_status(&fs);

        let after_stats_count = fs
            .inner
            .op_stats()
            .into_iter()
            .find(|s| s.tag == OpTag::Stats)
            .map(|s| s.count)
            .unwrap_or(0);

        assert_eq!(
            after_stats_count - before_stats_count,
            1,
            "format_runtime_status must acquire the inner lock with OpTag::Stats exactly once"
        );
    }

    #[test]
    fn test_inode_counts_overlay_layers() {
        use crate::operations::dir::mkdir_core;
        use crate::operations::links::{symlink_core, unlink_core};
        use crate::operations::read_write::{create_core, write_core};

        let fs = InMemoryFS::new();
        // Base state: 1 root directory
        let counts = fs.inode_counts();
        assert_eq!(counts.total_active(), 1);
        assert_eq!(counts.directories, 1);
        assert_eq!(counts.total_logical_bytes, 0);

        // Add 2 files, 1 dir, 1 symlink in live
        let d1 = mkdir_core(&fs, 1, "d1", 0o755, 1000, 1000).unwrap();
        let f1 = create_core(&fs, 1, "f1.txt", 0o644, 0, 1000, 1000).unwrap();
        let f2 = create_core(&fs, d1.ino, "f2.txt", 0o644, 0, 1000, 1000).unwrap();
        write_core(&fs, f1.ino, &[0u8; 100], 0).unwrap();
        write_core(&fs, f2.ino, &[0u8; 50], 0).unwrap();
        symlink_core(&fs, 1, "s1.lnk", "f1.txt", 1000, 1000).unwrap();

        let counts_live = fs.inode_counts();
        assert_eq!(counts_live.directories, 2);
        assert_eq!(counts_live.files, 2);
        assert_eq!(counts_live.symlinks, 1);
        assert_eq!(counts_live.total_active(), 5);
        assert_eq!(counts_live.total_logical_bytes, 150);

        // Freeze live to flushing
        fs.freeze_now();
        let counts_flushing = fs.inode_counts();
        assert_eq!(counts_flushing.total_active(), 5);
        assert_eq!(counts_flushing.directories, 2);
        assert_eq!(counts_flushing.files, 2);
        assert_eq!(counts_flushing.symlinks, 1);
        assert_eq!(counts_flushing.total_logical_bytes, 150);

        // In live, unlink f2 and add f3
        unlink_core(&fs, d1.ino, "f2.txt").unwrap();
        let f3 = create_core(&fs, 1, "f3.txt", 0o644, 0, 1000, 1000).unwrap();
        write_core(&fs, f3.ino, &[0u8; 30], 0).unwrap();

        let counts_mixed = fs.inode_counts();
        assert_eq!(counts_mixed.directories, 2);
        assert_eq!(counts_mixed.files, 2); // f1 + f3 (f2 deleted)
        assert_eq!(counts_mixed.symlinks, 1);
        assert_eq!(counts_mixed.total_active(), 5);
        assert_eq!(counts_mixed.total_logical_bytes, 130);

        // Unlink f1 as well
        unlink_core(&fs, 1, "f1.txt").unwrap();
        let counts_after_del = fs.inode_counts();
        assert_eq!(counts_after_del.files, 1); // f3 only
        assert_eq!(counts_after_del.total_active(), 4);
        assert_eq!(counts_after_del.total_logical_bytes, 30);

        // Add special file types: FIFO, CharDevice, BlockDevice, Socket
        crate::operations::special::mknod_core(&fs, 1, "fifo", libc::S_IFIFO | 0o644, 0, 1000, 1000).unwrap();
        crate::operations::special::mknod_core(&fs, 1, "chr", libc::S_IFCHR | 0o660, 0x1234, 1000, 1000).unwrap();
        crate::operations::special::mknod_core(&fs, 1, "blk", libc::S_IFBLK | 0o660, 0x5678, 1000, 1000).unwrap();
        crate::operations::special::mknod_core(&fs, 1, "sock", libc::S_IFSOCK | 0o755, 0, 1000, 1000).unwrap();

        let counts_special = fs.inode_counts();
        assert_eq!(counts_special.named_pipes, 1);
        assert_eq!(counts_special.char_devices, 1);
        assert_eq!(counts_special.block_devices, 1);
        assert_eq!(counts_special.sockets, 1);
        assert_eq!(counts_special.special(), 4);
        assert_eq!(counts_special.total_active(), 8);
        assert_eq!(counts_special.total_logical_bytes, 30);
    }

    #[test]
    fn test_format_runtime_status_many_inodes_performance() {
        use crate::operations::read_write::create_core;

        let fs = InMemoryFS::new();
        for i in 0..1_000 {
            let name = format!("file_{}.dat", i);
            create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
        }

        let before_stats_count = fs
            .inner
            .op_stats()
            .into_iter()
            .find(|s| s.tag == OpTag::Stats)
            .map(|s| s.count)
            .unwrap_or(0);

        let status = format_runtime_status(&fs);

        let after_stats_count = fs
            .inner
            .op_stats()
            .into_iter()
            .find(|s| s.tag == OpTag::Stats)
            .map(|s| s.count)
            .unwrap_or(0);

        assert_eq!(after_stats_count - before_stats_count, 1);
        assert!(status.contains("Active Inodes:      1001 (1 directories, 1000 files, 0 symlinks, 0 special)"));
    }
}
