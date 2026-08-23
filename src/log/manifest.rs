use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metadata and physical counters for an individual `.log` generation file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileInfo {
    /// Monotonic generation sequence number (e.g. 1 for 000001.log).
    pub generation: u64,
    /// Physical filename on disk (e.g. "000001.log" or "branch_a_000004.log").
    pub filename: String,
    /// Creation timestamp for this log generation.
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
    /// Total number of log records physically written into this file.
    pub record_count: u32,
    /// Total physical file size on disk (bytes).
    pub total_bytes: u64,
    /// Total uncompressed extent payload data bytes written.
    pub total_data_bytes: u64,
}

impl LogFileInfo {
    pub fn new(generation: u64, filename: impl Into<String>, created_at: SystemTime, initial_header_size: u64) -> Self {
        Self {
            generation,
            filename: filename.into(),
            created_at,
            record_count: 0,
            total_bytes: initial_header_size,
            total_data_bytes: 0,
        }
    }
}

/// Authoritative manifest of all active log generations and lineage for the filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogManifest {
    /// Active branch identifier (e.g. "main").
    pub branch: String,
    /// Ordered list of active log files that back the extents in this filesystem state.
    pub logs: Vec<LogFileInfo>,
    /// Next generation sequence number to allocate.
    pub next_generation: u64,
    /// Next generation log filename to create on roll (e.g. "000002.log").
    pub next_filename: String,
}

impl Default for LogManifest {
    fn default() -> Self {
        Self::new(1, "main")
    }
}

impl LogManifest {
    pub fn new(start_generation: u64, branch: impl Into<String>) -> Self {
        Self::new_with_time(start_generation, branch, SystemTime::now())
    }

    pub fn new_with_time(start_generation: u64, branch: impl Into<String>, created_at: SystemTime) -> Self {
        let branch = branch.into();
        let current_filename = format!("{:06}.log", start_generation);
        let next_generation = start_generation + 1;
        let next_filename = format!("{:06}.log", next_generation);

        Self {
            branch,
            logs: vec![LogFileInfo::new(
                start_generation,
                current_filename,
                created_at,
                crate::log::record::FILE_HEADER_SIZE as u64,
            )],
            next_generation,
            next_filename,
        }
    }

    /// Appends a new rolled log generation and advances `next_generation` / `next_filename`.
    pub fn record_roll(&mut self, next_gen: u64, next_file: String, created_at: SystemTime, initial_header_size: u64) {
        if self.logs.iter().any(|l| l.generation == next_gen) {
            return;
        }
        let entry = LogFileInfo::new(next_gen, next_file, created_at, initial_header_size);
        self.logs.push(entry);
        self.next_generation = next_gen + 1;
        self.next_filename = format!("{:06}.log", self.next_generation);
    }

    /// Finds a mutable reference to a log file entry by generation number.
    pub fn get_mut_by_generation(&mut self, generation: u64) -> Option<&mut LogFileInfo> {
        self.logs.iter_mut().find(|l| l.generation == generation)
    }

    /// Finds a reference to a log file entry by generation number.
    pub fn get_by_generation(&self, generation: u64) -> Option<&LogFileInfo> {
        self.logs.iter().find(|l| l.generation == generation)
    }
}

/// Dynamically computed live extent statistics for a single log generation.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationLiveStats {
    pub generation: u64,
    pub filename: String,
    pub record_count: u32,
    pub total_bytes: u64,
    pub total_data_bytes: u64,
    /// Total bytes still actively referenced by live file range maps.
    pub live_bytes: u64,
    /// Total number of active extent fragments referencing this generation.
    pub live_extents: u32,
    /// Ratio of live bytes to total data bytes written (0.0 to 1.0).
    pub live_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_manifest_creation_and_roll() {
        let mut manifest = LogManifest::new(1, "main");
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert_eq!(manifest.logs[0].filename, "000001.log");
        assert_eq!(manifest.next_generation, 2);
        assert_eq!(manifest.next_filename, "000002.log");

        manifest.record_roll(
            2,
            "000002.log".to_string(),
            SystemTime::now(),
            crate::log::record::FILE_HEADER_SIZE as u64,
        );
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[1].generation, 2);
        assert_eq!(manifest.next_generation, 3);
        assert_eq!(manifest.next_filename, "000003.log");

        let bytes = bincode::serialize(&manifest).unwrap();
        let deserialized: LogManifest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(manifest, deserialized);
    }
}
