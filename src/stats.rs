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

fn format_bytes(bytes: u64) -> String {
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
}
