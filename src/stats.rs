use crate::clock::format_duration;
use crate::extent_map::Extent;
use crate::fs::{AppendFs, InodeCounts};
use crate::log::LogManifest;
use crate::log::manifest::GenerationLiveStats;
use crate::node::{Node, NodeKind};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;
use std::sync::Arc;

/// Default maximum number of top file extensions to display before grouping remaining extensions under `(other)`.
pub const TOP_EXTENSIONS_LIMIT: usize = 15;

/// Maximum average extent size (1 MiB) for a file to be considered fragmented in volume statistics.
pub const FRAGMENTED_AVG_EXTENT_THRESHOLD: u64 = 1024 * 1024;

/// Minimum number of extents (5) for a file to be considered fragmented in volume statistics.
pub const FRAGMENTED_MIN_EXTENTS: usize = 5;

/// File count and aggregate logical byte size for a specific file extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionStats {
    pub extension: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Generic histogram bucket for range categorization.
#[derive(Debug, Clone)]
pub struct HistogramBucket<T> {
    pub label: &'static str,
    pub min: T,
    pub max: T,
    pub count: usize,
    pub total_bytes: u64,
}

impl<T: PartialOrd + Copy> HistogramBucket<T> {
    pub const fn new(label: &'static str, min: T, max: T) -> Self {
        Self {
            label,
            min,
            max,
            count: 0,
            total_bytes: 0,
        }
    }

    pub fn matches(&self, val: T) -> bool {
        val >= self.min && val <= self.max
    }

    pub fn add(&mut self, bytes: u64) {
        self.count += 1;
        self.total_bytes += bytes;
    }
}

pub type ExtentsBucket = HistogramBucket<usize>;

/// File fragmentation information for top-N ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFragInfo {
    pub inode: u64,
    pub size: u64,
    pub extents: usize,
    pub path: String,
}

impl FileFragInfo {
    /// Computes the average extent size in bytes, or 0 if the file has no extents.
    pub fn avg_extent_size(&self) -> u64 {
        if self.extents > 0 {
            self.size / self.extents as u64
        } else {
            0
        }
    }
}

/// Builds a mapping from inode ID to its relative POSIX path by BFS traversal from root directory (inode 1).
pub fn build_path_map(inodes: &HashMap<u64, Arc<Node>>) -> HashMap<u64, String> {
    let mut path_map: HashMap<u64, String> = HashMap::new();
    path_map.insert(1, "/".to_string());
    let mut queue = VecDeque::new();
    queue.push_back(1u64);

    while let Some(dir_ino) = queue.pop_front() {
        let dir_path = path_map
            .get(&dir_ino)
            .cloned()
            .unwrap_or_else(|| format!("<inode {}>", dir_ino));
        if let Some(sync_node) = inodes.get(&dir_ino) {
            let node = sync_node.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind {
                for (name, child_ino) in entries {
                    let child_path = if dir_ino == 1 {
                        format!("/{}", name)
                    } else {
                        format!("{}/{}", dir_path, name)
                    };
                    path_map.insert(*child_ino, child_path);
                    if let Some(child_sync) = inodes.get(child_ino) {
                        let child_node = child_sync.as_ref();
                        if child_node.is_dir() {
                            queue.push_back(*child_ino);
                        }
                    }
                }
            }
        }
    }
    path_map
}

fn format_fragmentation_section(
    file_count: usize,
    total_file_extents: usize,
    max_file_extents: usize,
    extent_buckets: &[ExtentsBucket],
    file_frag_list: &[FileFragInfo],
) -> String {
    let mut out = String::new();
    writeln!(out, "--- File Extent & Fragmentation Statistics ---").unwrap();
    writeln!(out, "Total Regular Files: {}", file_count).unwrap();
    writeln!(out, "Total File Extents:  {}", total_file_extents).unwrap();
    let avg_extents = if file_count > 0 {
        total_file_extents as f64 / file_count as f64
    } else {
        0.0
    };
    writeln!(out, "Avg Extents / File:  {:.2}", avg_extents).unwrap();
    writeln!(out, "Max Extents in File: {}", max_file_extents).unwrap();
    writeln!(out).unwrap();

    if file_count > 0 {
        writeln!(out, "Extents / File Distribution:").unwrap();
        writeln!(
            out,
            "{:<24} {:>8} {:>12}   DISTRIBUTION",
            "EXTENTS RANGE", "FILES", "% OF FILES"
        )
        .unwrap();
        writeln!(out, "{:-<24} {:-<8} {:-<12}   {:-<20}", "", "", "", "").unwrap();

        for b in extent_buckets {
            let pct = (b.count as f64 / file_count as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            let pct_str = format!("{:.1}%", pct);
            writeln!(out, "{:<24} {:>8} {:>12}   {:<20}", b.label, b.count, pct_str, bar).unwrap();
        }
        writeln!(out).unwrap();

        let multi_extent_files: Vec<_> = file_frag_list.iter().filter(|f| f.extents > 1).take(5).collect();
        if !multi_extent_files.is_empty() {
            out.push_str(&format_file_frag_table(
                "Top Files by Extent Count",
                &multi_extent_files,
            ));
        }

        let fragmented_files: Vec<_> = file_frag_list
            .iter()
            .filter(|f| f.extents >= FRAGMENTED_MIN_EXTENTS && f.avg_extent_size() < FRAGMENTED_AVG_EXTENT_THRESHOLD)
            .take(5)
            .collect();
        if !fragmented_files.is_empty() {
            out.push_str(&format_file_frag_table(
                "Top Fragmented Files (< 1 MiB Avg Extent)",
                &fragmented_files,
            ));
        }
    }
    out
}

fn format_file_frag_table(title: &str, files: &[&FileFragInfo]) -> String {
    let mut out = String::new();
    writeln!(out, "--- {} ---", title).unwrap();
    writeln!(
        out,
        "{:<8} {:>12} {:>9} {:>16}   PATH",
        "INODE", "SIZE", "EXTENTS", "AVG EXTENT SIZE"
    )
    .unwrap();
    writeln!(out, "{:-<8} {:-<12} {:-<9} {:-<16}   {:-<30}", "", "", "", "", "").unwrap();
    for f in files {
        let avg_sz = f.avg_extent_size();
        writeln!(
            out,
            "{:<8} {:>12} {:>9} {:>16}   {}",
            f.inode,
            format_bytes(f.size),
            f.extents,
            format_bytes(avg_sz),
            f.path
        )
        .unwrap();
    }
    writeln!(out).unwrap();
    out
}

fn format_manifest_section(manifest: &LogManifest, inodes: &HashMap<u64, Arc<Node>>) -> String {
    let mut out = String::new();
    writeln!(out, "--- Tracked Log Generations Manifest ---").unwrap();
    if manifest.logs.is_empty() {
        writeln!(out, "Tracked Logs:        0 active log generation files").unwrap();
    } else {
        writeln!(out, "Tracked Logs:        {} log generation files", manifest.logs.len()).unwrap();
        writeln!(out).unwrap();

        let generations = calculate_generation_live_stats_from_nodes(inodes.values().map(|a| a.as_ref()), manifest);
        out.push_str(&format_generations_table(&generations));
    }
    out
}

/// Formats the canonical content report for an appendfs volume or summary file.
///
/// Contains Inode Breakdown, File Extension Breakdown, File Extents & Fragmentation Statistics,
/// and Tracked Log Generations Manifest.
pub fn format_volume_content_report(inodes: &HashMap<u64, Arc<Node>>, manifest: &LogManifest) -> String {
    let path_map = build_path_map(inodes);
    let mut extent_buckets = vec![
        ExtentsBucket::new("1 extent (contiguous)", 1, 1),
        ExtentsBucket::new("2 - 4 extents", 2, 4),
        ExtentsBucket::new("5 - 16 extents", 5, 16),
        ExtentsBucket::new("17 - 64 extents", 17, 64),
        ExtentsBucket::new("> 64 extents", 65, usize::MAX),
    ];
    let mut file_frag_list = Vec::new();

    let mut sorted_inodes: Vec<u64> = inodes.keys().copied().collect();
    sorted_inodes.sort_unstable();

    let mut dir_count = 0usize;
    let mut file_count = 0usize;
    let mut symlink_count = 0usize;
    let mut total_logical_bytes = 0u64;
    let mut total_file_extents = 0usize;
    let mut max_file_extents = 0usize;

    for &ino in &sorted_inodes {
        if let Some(sync_node) = inodes.get(&ino) {
            let node = sync_node.as_ref();
            match &node.kind {
                NodeKind::Directory { .. } => {
                    dir_count += 1;
                }
                NodeKind::Symlink { .. } => {
                    symlink_count += 1;
                }
                NodeKind::File { extent_map, size, .. } => {
                    file_count += 1;
                    total_logical_bytes += *size;
                    let num_extents = extent_map.len();
                    total_file_extents += num_extents;
                    if num_extents > max_file_extents {
                        max_file_extents = num_extents;
                    }
                    if num_extents > 0 {
                        for b in &mut extent_buckets {
                            if b.matches(num_extents) {
                                b.count += 1;
                                break;
                            }
                        }
                    }
                    let p = path_map
                        .get(&ino)
                        .cloned()
                        .unwrap_or_else(|| format!("<inode {}>", ino));
                    file_frag_list.push(FileFragInfo {
                        inode: ino,
                        size: *size,
                        extents: num_extents,
                        path: p,
                    });
                }
                NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket => {}
            }
        }
    }

    file_frag_list.sort_by(|a, b| b.extents.cmp(&a.extents).then_with(|| b.size.cmp(&a.size)));

    let mut out = String::new();
    writeln!(out, "--- Inode Breakdown ---").unwrap();
    writeln!(
        out,
        "Total Inodes:        {} ({} directories, {} regular files, {} symlinks)",
        sorted_inodes.len(),
        dir_count,
        file_count,
        symlink_count
    )
    .unwrap();
    writeln!(out, "Logical Data Size:   {}", format_bytes(total_logical_bytes)).unwrap();
    writeln!(out).unwrap();

    let extensions = calculate_extension_stats_from_nodes(inodes);
    let ext_table = format_extension_stats_table(&extensions, file_count, total_logical_bytes);
    if !ext_table.is_empty() {
        out.push_str(&ext_table);
        writeln!(out).unwrap();
    }

    out.push_str(&format_fragmentation_section(
        file_count,
        total_file_extents,
        max_file_extents,
        &extent_buckets,
        &file_frag_list,
    ));

    out.push_str(&format_manifest_section(manifest, inodes));
    out
}

/// Aggregate statistics and fragmentation status for an appendfs volume.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeStats {
    pub next_generation: u32,
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
    pub extensions: Vec<ExtensionStats>,
    pub content_report: String,
}

impl VolumeStats {
    /// Returns the physical filename for the next log generation (e.g. "000002.log").
    pub fn next_filename(&self) -> String {
        crate::log::log_filename(self.next_generation)
    }

    /// Constructs VolumeStats from individual pre-computed parts.
    pub fn from_parts(
        next_generation: u32,
        counts: &InodeCounts,
        generations: Vec<GenerationLiveStats>,
        extensions: Vec<ExtensionStats>,
        content_report: String,
    ) -> Self {
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
            extensions,
            content_report,
        }
    }

    /// Collects volume statistics from an in-memory filesystem state.
    pub fn collect(fs: &AppendFs) -> Self {
        let snapshot = fs.snapshot_all();
        let manifest = fs.manifest.read().unwrap();
        let counts = InodeCounts::from_nodes(snapshot.values().map(|a| a.as_ref()));
        let generations = calculate_generation_live_stats_from_nodes(snapshot.values().map(|a| a.as_ref()), &manifest);
        let extensions = calculate_extension_stats_from_nodes(&snapshot);
        let content_report = format_volume_content_report(&snapshot, &manifest);
        Self::from_parts(
            fs.next_generation_locked(&manifest),
            &counts,
            generations,
            extensions,
            content_report,
        )
    }

    /// Collects volume statistics directly from a snapshot's inodes and manifest.
    pub fn collect_from_snapshot(inodes: &HashMap<u64, Arc<Node>>, manifest: &LogManifest) -> Self {
        let counts = InodeCounts::from_nodes(inodes.values().map(|a| a.as_ref()));
        let generations = calculate_generation_live_stats_from_nodes(inodes.values().map(|a| a.as_ref()), manifest);
        let extensions = calculate_extension_stats_from_nodes(inodes);
        let content_report = format_volume_content_report(inodes, manifest);
        let next_generation = manifest.latest_generation().map_or(1, |max| max + 1);
        Self::from_parts(next_generation, &counts, generations, extensions, content_report)
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
        writeln!(out, "Physical Log Size:   {}", format_bytes(self.total_disk_bytes)).unwrap();
        if self.total_data_bytes > 0 {
            writeln!(out, "Overall Live Ratio:  {:.1}%", self.overall_live_ratio * 100.0).unwrap();
        } else {
            writeln!(out, "Overall Live Ratio:  N/A (no data payload)").unwrap();
        }
        writeln!(out).unwrap();

        out.push_str(&self.content_report);
        out
    }
}

/// Dynamically calculates live extent statistics across all active files and log generations from a node iterator.
pub fn calculate_generation_live_stats_from_nodes<'a, I>(nodes: I, manifest: &LogManifest) -> Vec<GenerationLiveStats>
where
    I: IntoIterator<Item = &'a Node>,
{
    // `copy_file_range` lets several extents - in one file or in many - reference the same
    // bytes of a record, so a record's live bytes are the union of the ranges referencing it,
    // not their sum.
    let mut referenced: HashMap<(u32, u64), Vec<(u64, u64)>> = HashMap::new();
    let mut live_map: HashMap<u32, (u64, u32)> = HashMap::new();
    for node in nodes {
        if let NodeKind::File { extent_map, .. } = &node.kind {
            for (_, entry) in extent_map.iter() {
                if let Extent::Disk {
                    generation,
                    record_log_offset,
                    payload_offset,
                    length,
                    ..
                } = &entry.extent
                {
                    let start = *payload_offset as u64;
                    referenced
                        .entry((*generation, *record_log_offset))
                        .or_default()
                        .push((start, start + *length as u64));
                    live_map.entry(*generation).or_insert((0, 0)).1 += 1;
                }
            }
        }
    }
    for ((generation, _), mut ranges) in referenced {
        ranges.sort_unstable();
        let mut live_bytes = 0;
        let mut covered_to = 0;
        for (start, end) in ranges {
            let start = start.max(covered_to);
            if end > start {
                live_bytes += end - start;
                covered_to = end;
            }
        }
        live_map.entry(generation).or_insert((0, 0)).0 += live_bytes;
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
            sealed: log.is_sealed(),
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

/// Extracts normalized file extension (e.g. `".txt"`, `".bin"`) or `"(no extension)"` if none.
pub fn extract_extension(filename: &str) -> String {
    let path = std::path::Path::new(filename);
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => format!(".{}", ext.to_lowercase()),
        _ => "(no extension)".to_string(),
    }
}

/// Traverses reachable directories from root and collects aggregate file counts and logical byte sizes per extension.
pub fn calculate_extension_stats_from_nodes(inodes: &HashMap<u64, Arc<Node>>) -> Vec<ExtensionStats> {
    let mut ino_to_name: HashMap<u64, String> = HashMap::new();
    let mut queue = VecDeque::new();
    let mut visited_dirs = HashSet::new();

    if inodes.contains_key(&1) {
        queue.push_back(1u64);
        visited_dirs.insert(1u64);
    }

    while let Some(dir_ino) = queue.pop_front() {
        if let Some(sync_node) = inodes.get(&dir_ino) {
            let node = sync_node.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind {
                let mut sorted_entries = entries.clone();
                sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));
                for (name, child_ino) in sorted_entries {
                    ino_to_name.entry(child_ino).or_insert_with(|| name.clone());
                    if let Some(child_sync) = inodes.get(&child_ino)
                        && child_sync.is_dir()
                        && visited_dirs.insert(child_ino)
                    {
                        queue.push_back(child_ino);
                    }
                }
            }
        }
    }

    let mut ext_map: HashMap<String, (usize, u64)> = HashMap::new();
    let mut sorted_inodes: Vec<u64> = inodes.keys().copied().collect();
    sorted_inodes.sort_unstable();

    for ino in sorted_inodes {
        if let Some(sync_node) = inodes.get(&ino) {
            let node = sync_node.as_ref();
            if let NodeKind::File { size, .. } = &node.kind {
                let name = ino_to_name.get(&ino).map(|s| s.as_str()).unwrap_or("");
                let ext = extract_extension(name);
                let entry = ext_map.entry(ext).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += *size;
            }
        }
    }

    let mut result: Vec<ExtensionStats> = ext_map
        .into_iter()
        .map(|(extension, (file_count, total_bytes))| ExtensionStats {
            extension,
            file_count,
            total_bytes,
        })
        .collect();

    result.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| b.file_count.cmp(&a.file_count))
            .then_with(|| a.extension.cmp(&b.extension))
    });

    result
}

/// Formats a table of file counts and logical byte sizes grouped by file extension.
pub fn format_extension_stats_table(extensions: &[ExtensionStats], total_files: usize, total_bytes: u64) -> String {
    let mut out = String::new();
    if extensions.is_empty() || total_files == 0 {
        return out;
    }

    writeln!(out, "--- File Extension Breakdown ---").unwrap();
    writeln!(
        out,
        "{:<24} {:>8} {:>12} {:>14} {:>12}",
        "EXTENSION", "FILES", "% OF FILES", "TOTAL BYTES", "% OF BYTES"
    )
    .unwrap();
    writeln!(out, "{:-<24} {:-<8} {:-<12} {:-<14} {:-<12}", "", "", "", "", "").unwrap();

    let (top, rest) = if extensions.len() > TOP_EXTENSIONS_LIMIT {
        extensions.split_at(TOP_EXTENSIONS_LIMIT)
    } else {
        (extensions, &[][..])
    };

    for ext in top {
        let file_pct = (ext.file_count as f64 / total_files as f64) * 100.0;
        let byte_pct = if total_bytes > 0 {
            (ext.total_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };
        writeln!(
            out,
            "{:<24} {:>8} {:>12} {:>14} {:>12}",
            ext.extension,
            ext.file_count,
            format!("{:.1}%", file_pct),
            format_bytes(ext.total_bytes),
            format!("{:.1}%", byte_pct)
        )
        .unwrap();
    }

    if !rest.is_empty() {
        let other_files: usize = rest.iter().map(|e| e.file_count).sum();
        let other_bytes: u64 = rest.iter().map(|e| e.total_bytes).sum();
        let file_pct = (other_files as f64 / total_files as f64) * 100.0;
        let byte_pct = if total_bytes > 0 {
            (other_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };
        writeln!(
            out,
            "{:<24} {:>8} {:>12} {:>14} {:>12}",
            "(other)",
            other_files,
            format!("{:.1}%", file_pct),
            format_bytes(other_bytes),
            format!("{:.1}%", byte_pct)
        )
        .unwrap();
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

/// Formats a latency or timing duration into a human-readable string (ns, µs, ms, s).
pub fn format_latency(d: std::time::Duration) -> String {
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
pub fn format_runtime_status(fs: &AppendFs) -> String {
    use std::sync::atomic::Ordering;

    let snap = fs.stats_snapshot();
    let mut out = String::new();

    // 1. Volume & Manifest Info
    let position = fs.log_writer.as_ref().map(|w| w.position());
    let (head_gen, next_gen, total_gens, total_disk_bytes) = {
        let manifest = fs.manifest.read().unwrap();
        let head = position.filter(|p| p.is_open).map(|p| p.generation);
        let total_gens = manifest.logs.len();
        let total_disk: u64 = manifest.logs.iter().map(|l| l.total_bytes).sum();
        let next_gen = fs.next_generation_locked(&manifest);
        (head, next_gen, total_gens, total_disk)
    };

    let mode_str = if fs.is_read_only() { "Read-Only" } else { "Read-Write" };

    let cipher_str = format!("{:?}", fs.volume_header.cipher);
    let compression_str = format!("{:?}", fs.volume_header.compression);
    let volume_id_hex = hex::encode(fs.volume_header.volume_id);

    let next_ino = fs.next_inode.load(Ordering::SeqCst);
    let last_batch = fs.last_batch_id.load(Ordering::SeqCst);

    let rec_time_str = match snap.recovered_time {
        Some(t) => {
            let elapsed = fs.clock.now().duration_since(t).unwrap_or_default().as_secs();
            format!("{} ago", format_duration(std::time::Duration::from_secs(elapsed)))
        }
        None => "N/A (fresh session)".to_string(),
    };

    out.push_str("=== appendfs Runtime Status ===\n\n");

    out.push_str("[Volume]\n");
    out.push_str(&format!("  Access Mode:        {}\n", mode_str));
    out.push_str(&format!("  Volume ID:          {}\n", volume_id_hex));
    out.push_str(&format!("  Cipher Suite:       {}\n", cipher_str));
    out.push_str(&format!("  Compression:        {}\n", compression_str));
    if let Some(head) = head_gen {
        out.push_str(&format!(
            "  Active Generation:  {} ({})\n",
            head,
            crate::log::log_filename(head)
        ));
    } else if position.is_some() {
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
            (true, Some(i)) => format!("background (periodic flush every {})", format_duration(i)),
            (true, None) => "background (no periodic flush)".to_string(),
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
        "  Time Flushing:      {} queued, {} serialize, {} wait, {} flush, {} folding into base\n",
        format_latency(flush.total_queued),
        format_latency(flush.total_serialize),
        format_latency(flush.total_wait),
        format_latency(flush.total_flush),
        format_latency(flush.total_fold)
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
            "    {:<7} {:<11} {:>10} {:>10} {:>7}  {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}  {}\n",
            "batch",
            "reason",
            "bytes",
            "on-disk",
            "ops",
            "queued",
            "serialize",
            "wait",
            "flush",
            "fold",
            "total",
            "age"
        ));
        let now = fs.clock.now();
        for record in flush.recent.iter().rev() {
            let age = now.duration_since(record.started_at).unwrap_or_default().as_secs();
            let age_str = format!("{} ago", format_duration(std::time::Duration::from_secs(age)));
            out.push_str(&format!(
                "    #{:<6} {:<11} {:>10} {:>10} {:>7}  {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}  {}\n",
                record.id,
                record.reason,
                format_bytes(record.bytes as u64),
                format_bytes(record.disk_bytes),
                record.ops,
                format_latency(record.queued),
                format_latency(record.serialize),
                format_latency(record.wait),
                format_latency(record.flush),
                format_latency(record.fold),
                format_latency(record.duration),
                age_str
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
        format_latency(mutex_busy_time),
        format_latency(avg_hold)
    ));
    out.push_str(&format!("  Mutex Wait Time:    {}\n", format_latency(mutex_wait_time)));

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
                format_latency(s.busy_time),
                format_latency(s.avg_hold_time()),
                format_latency(s.max_hold_time),
                format_latency(s.wait_time),
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
            format_latency(fs.op_metrics.total_delay_duration())
        ));
        out.push_str(&format!(
            "  Avg Delay / Waiter: {}\n",
            format_latency(fs.op_metrics.avg_delay_duration())
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
                    format_latency(fs.op_metrics.avg_throttled_duration(*op)),
                    fs.op_metrics.stalled(*op),
                    format_latency(fs.op_metrics.avg_latency(*op)),
                    format_latency(fs.op_metrics.max_latency(*op)),
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
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use std::sync::Arc;

    #[test]
    fn test_volume_stats_formatting() {
        let fs = TestFs::builder().build().fs;
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

        let fs = TestFs::builder().build().fs;
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

        let root_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 1, 1000, 1000, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("dir".to_string(), 3)],
            },
        });

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(1, root_node);
            inner.base.insert(2, file_node);
            inner.base.insert(3, dir_node);
        }

        {
            let mut manifest = fs.manifest.write().unwrap();
            manifest.logs.push(LogFileInfo {
                version: 1,
                generation: 1,
                revision: 0,
                filename: "000001.log".to_string(),
                created_at: now,
                record_count: 10,
                total_bytes: 8192,
                total_data_bytes: 4096,
                md5: [0u8; 16],
                sealed_at: Some(now),
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
        assert_eq!(stats_snapshot.extensions.len(), 1);
        assert_eq!(stats_snapshot.extensions[0].extension, ".bin");
        assert_eq!(stats_snapshot.extensions[0].file_count, 1);
        assert_eq!(stats_snapshot.extensions[0].total_bytes, 4096);
        assert!(
            stats_snapshot
                .display_text()
                .contains("--- File Extension Breakdown ---")
        );
        assert!(
            stats_snapshot
                .display_text()
                .contains(".bin                            1       100.0%       4.00 KiB       100.0%")
        );
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
        let fs = TestFs::builder().build().fs;
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
        assert!(status.contains("Decrypted Records:  0 B / "));
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
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::SystemClock);
        let fs = TestFs::builder().clock(clock.clone()).build().fs;
        fs.log_writer.as_ref().unwrap().open_if_unopened().unwrap();
        let status = format_runtime_status(&fs);
        assert!(status.contains("Active Generation:  1 (000001.log)"));
        assert!(status.contains("Next Generation:    2 (000002.log)"));
    }

    #[test]
    fn test_format_runtime_status_with_lazy_writer() {
        let fs = TestFs::builder().build().fs;
        let status = format_runtime_status(&fs);
        assert!(status.contains("Active Generation:  None (lazy / unopened)"));
        assert!(status.contains("Next Generation:    1 (000001.log)"));

        // After writing and flushing, the generation file is opened and active
        fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.quiesce().unwrap();
        let status_after_write = format_runtime_status(&fs);
        assert!(status_after_write.contains("Active Generation:  1 (000001.log)"));
        assert!(status_after_write.contains("Next Generation:    2 (000002.log)"));
    }

    #[test]
    fn test_format_runtime_status_with_activity() {
        use crate::operations::locks::{flock_core, setlk_core};

        use crate::remote::block_cache::MemoryBlockCache;
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let mut fs = TestFs::builder().storage(storage.clone()).build().fs;

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
        let dir = fs.make_dir(1, "sub", 0o755).unwrap();
        let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
        let f2 = fs.create_file(dir, "f2.txt", 0o644).unwrap();
        fs.make_symlink(1, "link.txt", "f1.txt").unwrap();

        // Write some staged data
        fs.write_at(f1, b"hello world staged data", 0).unwrap();

        // Open handles
        let fh_file1 = fs.open_file_handle(f1, 0);
        let fh_file2 = fs.open_file_handle(f2, 0);
        let dh = fs.open_dir(dir).unwrap();

        // Acquire locks
        flock_core(&fs, f1, fh_file1, 1001, libc::LOCK_EX).unwrap();
        let rlock = crate::shim::ShimFlock {
            lock_type: libc::F_WRLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 100,
            pid: 100,
        };
        setlk_core(&fs, f2, fh_file2, 1002, rlock, false).unwrap();

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
        fs.release_file_handle(fh_file1, f1).unwrap();
        fs.release_file_handle(fh_file2, f2).unwrap();
        fs.release_dir(dir, dh).unwrap();

        // Check read-only mode reporting
        fs.set_read_only();
        let ro_status = format_runtime_status(&fs);
        assert!(ro_status.contains("Access Mode:        Read-Only"));
    }

    #[test]
    fn test_format_runtime_status_single_lock_acquisition() {
        let fs = TestFs::builder().build().fs;
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
        let fs = TestFs::builder().build().fs;
        // Base state: 1 root directory
        let counts = fs.inode_counts();
        assert_eq!(counts.total_active(), 1);
        assert_eq!(counts.directories, 1);
        assert_eq!(counts.total_logical_bytes, 0);

        // Add 2 files, 1 dir, 1 symlink in live
        let d1 = fs.make_dir(1, "d1", 0o755).unwrap();
        let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
        let f2 = fs.create_file(d1, "f2.txt", 0o644).unwrap();
        fs.write_at(f1, &[0u8; 100], 0).unwrap();
        fs.write_at(f2, &[0u8; 50], 0).unwrap();
        fs.make_symlink(1, "s1.lnk", "f1.txt").unwrap();

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
        fs.remove_file(d1, "f2.txt").unwrap();
        let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
        fs.write_at(f3, &[0u8; 30], 0).unwrap();

        let counts_mixed = fs.inode_counts();
        assert_eq!(counts_mixed.directories, 2);
        assert_eq!(counts_mixed.files, 2); // f1 + f3 (f2 deleted)
        assert_eq!(counts_mixed.symlinks, 1);
        assert_eq!(counts_mixed.total_active(), 5);
        assert_eq!(counts_mixed.total_logical_bytes, 130);

        // Unlink f1 as well
        fs.remove_file(1, "f1.txt").unwrap();
        let counts_after_del = fs.inode_counts();
        assert_eq!(counts_after_del.files, 1); // f3 only
        assert_eq!(counts_after_del.total_active(), 4);
        assert_eq!(counts_after_del.total_logical_bytes, 30);

        // Add special file types: FIFO, CharDevice, BlockDevice, Socket
        fs.make_node(1, "fifo", libc::S_IFIFO | 0o644, 0).unwrap();
        fs.make_node(1, "chr", libc::S_IFCHR | 0o660, 0x1234).unwrap();
        fs.make_node(1, "blk", libc::S_IFBLK | 0o660, 0x5678).unwrap();
        fs.make_node(1, "sock", libc::S_IFSOCK | 0o755, 0).unwrap();

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
        let fs = TestFs::builder().build().fs;
        for i in 0..1_000 {
            let name = format!("file_{}.dat", i);
            fs.create_file(1, &name, 0o644).unwrap();
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

    #[test]
    fn test_format_runtime_status_concurrent_with_manifest_writer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let fs = Arc::new(TestFs::builder().build().fs);
        let stop = Arc::new(AtomicBool::new(false));
        let fs_writer = Arc::clone(&fs);
        let stop_writer = Arc::clone(&stop);

        let writer_handle = thread::spawn(move || {
            while !stop_writer.load(Ordering::Relaxed) {
                {
                    let manifest = fs_writer.manifest.write().unwrap();
                    let _ = manifest.logs.len();
                }
                thread::yield_now();
            }
        });

        for _ in 0..500 {
            let status = format_runtime_status(&fs);
            assert!(status.contains("=== appendfs Runtime Status ==="));
        }

        stop.store(true, Ordering::Relaxed);
        writer_handle.join().unwrap();
    }

    #[test]
    fn test_extract_extension() {
        assert_eq!(extract_extension("hello.txt"), ".txt");
        assert_eq!(extract_extension("photo.PNG"), ".png");
        assert_eq!(extract_extension("archive.tar.gz"), ".gz");
        assert_eq!(extract_extension("README"), "(no extension)");
        assert_eq!(extract_extension(".gitignore"), "(no extension)");
        assert_eq!(extract_extension(".env"), "(no extension)");
        assert_eq!(extract_extension(".vimrc.bak"), ".bak");
        assert_eq!(extract_extension("trailing."), "(no extension)");
        assert_eq!(extract_extension(""), "(no extension)");
        assert_eq!(extract_extension("manual.1"), ".1");
        assert_eq!(extract_extension("code.c++"), ".c++");
    }

    #[test]
    fn test_calculate_extension_stats_from_nodes() {
        use crate::extent_map::ExtentMap;
        use crate::node::{InodeMeta, Node, NodeKind};
        use std::time::SystemTime;

        let now = SystemTime::UNIX_EPOCH;
        let mut inodes = HashMap::new();

        // Inode 1: root dir
        inodes.insert(
            1,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 3, 0, 0, now),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: vec![
                        ("sub".to_string(), 2),
                        ("a.txt".to_string(), 3),
                        ("b.TXT".to_string(), 4),
                        ("no_ext".to_string(), 5),
                    ],
                },
            }),
        );

        // Inode 2: subdir
        inodes.insert(
            2,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 2, 0, 0, now),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: vec![
                        ("image.png".to_string(), 6),
                        ("hardlink_a.txt".to_string(), 3), // hardlink to inode 3
                    ],
                },
            }),
        );

        // Inode 3: a.txt (file, size 100) - hardlinked twice
        inodes.insert(
            3,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 2, 0, 0, now),
                kind: NodeKind::File {
                    extent_map: ExtentMap::new(),
                    size: 100,
                },
            }),
        );

        // Inode 4: b.TXT (file, size 200)
        inodes.insert(
            4,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 0, 0, now),
                kind: NodeKind::File {
                    extent_map: ExtentMap::new(),
                    size: 200,
                },
            }),
        );

        // Inode 5: no_ext (file, size 50)
        inodes.insert(
            5,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 0, 0, now),
                kind: NodeKind::File {
                    extent_map: ExtentMap::new(),
                    size: 50,
                },
            }),
        );

        // Inode 6: image.png (file, size 500)
        inodes.insert(
            6,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 0, 0, now),
                kind: NodeKind::File {
                    extent_map: ExtentMap::new(),
                    size: 500,
                },
            }),
        );

        let stats = calculate_extension_stats_from_nodes(&inodes);
        assert_eq!(stats.len(), 3);

        // Expected sorting: total_bytes desc, then file_count desc, then extension asc
        // 1. .png: 1 file, 500 bytes
        // 2. .txt: 2 files (inodes 3 and 4), 300 bytes (100 + 200)
        // 3. (no extension): 1 file, 50 bytes
        assert_eq!(stats[0].extension, ".png");
        assert_eq!(stats[0].file_count, 1);
        assert_eq!(stats[0].total_bytes, 500);

        assert_eq!(stats[1].extension, ".txt");
        assert_eq!(stats[1].file_count, 2);
        assert_eq!(stats[1].total_bytes, 300);

        assert_eq!(stats[2].extension, "(no extension)");
        assert_eq!(stats[2].file_count, 1);
        assert_eq!(stats[2].total_bytes, 50);
    }

    #[test]
    fn test_format_extension_stats_table_top_limit_and_other() {
        // Create 18 extensions to test the top 15 limit and (other) grouping
        let mut extensions = Vec::new();
        for i in 1..=18 {
            extensions.push(ExtensionStats {
                extension: format!(".ext{:02}", i),
                file_count: 10,
                total_bytes: (20 - i) as u64 * 1024,
            });
        }

        let total_files: usize = extensions.iter().map(|e| e.file_count).sum(); // 180 files
        let total_bytes: u64 = extensions.iter().map(|e| e.total_bytes).sum();

        let table = format_extension_stats_table(&extensions, total_files, total_bytes);
        assert!(table.contains("--- File Extension Breakdown ---"));
        assert!(table.contains("EXTENSION                   FILES   % OF FILES    TOTAL BYTES   % OF BYTES"));
        assert!(table.contains(".ext01"));
        assert!(table.contains(".ext15"));
        // .ext16, .ext17, .ext18 must be grouped under (other)
        assert!(!table.contains(".ext16"));
        assert!(!table.contains(".ext17"));
        assert!(!table.contains(".ext18"));
        assert!(table.contains("(other)"));

        let other_files: usize = extensions[15..].iter().map(|e| e.file_count).sum();
        let other_bytes: u64 = extensions[15..].iter().map(|e| e.total_bytes).sum();
        let other_file_pct = (other_files as f64 / total_files as f64) * 100.0;
        let other_byte_pct = (other_bytes as f64 / total_bytes as f64) * 100.0;

        assert!(table.contains(&format!(
            "{:<24} {:>8} {:>12} {:>14} {:>12}",
            "(other)",
            other_files,
            format!("{:.1}%", other_file_pct),
            format_bytes(other_bytes),
            format!("{:.1}%", other_byte_pct)
        )));
    }

    #[test]
    fn test_format_extension_stats_table_empty() {
        assert_eq!(format_extension_stats_table(&[], 0, 0), "");
        assert_eq!(format_extension_stats_table(&[], 5, 1000), "");
        let stats = vec![ExtensionStats {
            extension: ".txt".to_string(),
            file_count: 1,
            total_bytes: 10,
        }];
        assert_eq!(format_extension_stats_table(&stats, 0, 10), "");
    }

    #[test]
    fn test_file_frag_info_avg_extent_size() {
        let f0 = FileFragInfo {
            inode: 10,
            size: 100,
            extents: 0,
            path: "/empty".to_string(),
        };
        assert_eq!(f0.avg_extent_size(), 0);

        let f1 = FileFragInfo {
            inode: 11,
            size: 4096,
            extents: 2,
            path: "/file1".to_string(),
        };
        assert_eq!(f1.avg_extent_size(), 2048);
    }

    #[test]
    fn test_format_fragmentation_section_large_vs_small_extents() {
        let extent_buckets = vec![
            ExtentsBucket::new("1 extent (contiguous)", 1, 1),
            ExtentsBucket::new("2 - 4 extents", 2, 4),
            ExtentsBucket::new("> 64 extents", 65, usize::MAX),
        ];

        let files = vec![
            // Large sequential file (4 MiB avg extent size, 1000 extents)
            FileFragInfo {
                inode: 100,
                size: 4 * 1024 * 1024 * 1000,
                extents: 1000,
                path: "/backups/large.tar".to_string(),
            },
            // Truly fragmented file (4 KiB avg extent size, 50 extents >= 5)
            FileFragInfo {
                inode: 101,
                size: 200 * 1024,
                extents: 50,
                path: "/var/db/fragmented.sqlite".to_string(),
            },
            // Slightly fragmented file (3 extents < 5, small avg extent size 1 KiB)
            FileFragInfo {
                inode: 102,
                size: 3 * 1024,
                extents: 3,
                path: "/docs/few_extents.txt".to_string(),
            },
            // Contiguous file (1 extent, should not be in either table)
            FileFragInfo {
                inode: 103,
                size: 1024 * 1024,
                extents: 1,
                path: "/contiguous.bin".to_string(),
            },
        ];

        let report = format_fragmentation_section(4, 1054, 1000, &extent_buckets, &files);

        // "Top Files by Extent Count" should list all multi-extent files, starting with large.tar
        assert!(report.contains("--- Top Files by Extent Count ---"));
        let top_files_pos = report.find("--- Top Files by Extent Count ---").unwrap();
        let frag_files_pos = report
            .find("--- Top Fragmented Files (< 1 MiB Avg Extent) ---")
            .unwrap();
        assert!(top_files_pos < frag_files_pos);

        // Verify content within "Top Files by Extent Count"
        let top_section = &report[top_files_pos..frag_files_pos];
        assert!(top_section.contains("/backups/large.tar"));
        assert!(top_section.contains("/var/db/fragmented.sqlite"));
        assert!(top_section.contains("/docs/few_extents.txt"));
        assert!(!top_section.contains("/contiguous.bin"));

        // Verify content within "Top Fragmented Files (< 1 MiB Avg Extent)"
        let frag_section = &report[frag_files_pos..];
        assert!(!frag_section.contains("/backups/large.tar"));
        assert!(frag_section.contains("/var/db/fragmented.sqlite"));
        assert!(!frag_section.contains("/docs/few_extents.txt"));
        assert!(!frag_section.contains("/contiguous.bin"));
    }

    #[test]
    fn test_format_fragmentation_section_no_fragmented_files() {
        let extent_buckets = vec![
            ExtentsBucket::new("1 extent (contiguous)", 1, 1),
            ExtentsBucket::new("> 64 extents", 65, usize::MAX),
        ];

        let files = vec![FileFragInfo {
            inode: 100,
            size: 10 * 1024 * 1024 * 1024,
            extents: 2500, // 4 MiB avg extent size
            path: "/backups/backup.tar".to_string(),
        }];

        let report = format_fragmentation_section(1, 2500, 2500, &extent_buckets, &files);
        assert!(report.contains("--- Top Files by Extent Count ---"));
        assert!(report.contains("/backups/backup.tar"));
        // Since avg extent is 4 MiB, no files qualify as < 1 MiB avg extent
        assert!(!report.contains("--- Top Fragmented Files (< 1 MiB Avg Extent) ---"));
    }

    #[test]
    fn test_format_latency() {
        assert_eq!(format_latency(std::time::Duration::from_nanos(500)), "500 ns");
        assert_eq!(format_latency(std::time::Duration::from_micros(150)), "150.00 µs");
        assert_eq!(format_latency(std::time::Duration::from_millis(25)), "25.00 ms");
        assert_eq!(format_latency(std::time::Duration::from_millis(1500)), "1.50 s");
    }

    #[test]
    fn test_format_runtime_status_batch_and_recovery_duration() {
        use crate::clock::{AdvancingClock, Clock};

        let start_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let clock = Arc::new(AdvancingClock::new(start_time));
        let fs = TestFs::builder().clock(clock.clone()).build().fs;
        fs.set_recovered_time(Some(clock.now()));

        // Flush a batch
        fs.create_file(1, "test.bin", 0o644).unwrap();
        fs.quiesce().unwrap();

        // Immediately after flush: age is 0s
        let status_0s = format_runtime_status(&fs);
        assert!(status_0s.contains("Last Recovery:      0s ago"));
        assert!(status_0s.contains("0s ago\n"));

        // Advance by 106041 seconds (1d 5h 27m 21s)
        clock.advance(std::time::Duration::from_secs(106041));

        let status = format_runtime_status(&fs);
        assert!(
            status.contains("Last Recovery:      1d5h27m21s ago"),
            "Last Recovery must format broken up duration: {}",
            status
        );
        assert!(
            status.contains("1d5h27m21s ago\n"),
            "Recent Flushes age column must show 1d5h27m21s ago: {}",
            status
        );
    }
}
