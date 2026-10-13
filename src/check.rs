use crate::crypto::LogFileKey;
use crate::fs::AppendFs;
use crate::log::LogFileCache;
use crate::log::extent::ExtentState;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, OpCode, RECORD_HEADER_SIZE, RecordHeader};
use crate::node::NodeKind;
use crate::sync::OpTag;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// Options controlling filesystem integrity verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckOptions {
    /// Deep verify physical extent payloads and cryptographic checksums in `.log` files.
    pub verify_data: bool,
    /// Percentage of live data to sample and verify (0.0 < percent <= 100.0, default: 100.0).
    pub sample_percent: f64,
    /// Target remotes to verify (empty for local-only, "all", or specific remote names).
    pub remotes: Vec<String>,
    /// Seed for sampled block selection (if None, a random seed is generated).
    pub seed: Option<u64>,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            verify_data: false,
            sample_percent: 100.0,
            remotes: Vec::new(),
            seed: None,
        }
    }
}

impl CheckOptions {
    /// Creates a metadata-only verification option set (default).
    pub fn metadata_only() -> Self {
        Self::default()
    }

    /// Creates a full data verification option set (100% of live data).
    pub fn full_data() -> Self {
        Self {
            verify_data: true,
            sample_percent: 100.0,
            remotes: Vec::new(),
            seed: None,
        }
    }

    /// Creates a sampled data verification option set with a given percentage (0.0 < percent <= 100.0).
    pub fn sampled(sample_percent: f64, seed: Option<u64>) -> Self {
        Self {
            verify_data: true,
            sample_percent,
            remotes: Vec::new(),
            seed,
        }
    }
}

/// Severity level of an integrity issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IssueLevel {
    Info,
    Warning,
    Error,
}

impl fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueLevel::Info => write!(f, "INFO"),
            IssueLevel::Warning => write!(f, "WARN"),
            IssueLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// An individual integrity inconsistency or violation found during a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub level: IssueLevel,
    pub code: String,
    pub inode: Option<u64>,
    pub message: String,
}

impl IntegrityIssue {
    pub fn error(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Error,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }

    pub fn warning(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Warning,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }

    pub fn info(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Info,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub total_inodes: usize,
    pub directories: usize,
    pub regular_files: usize,
    pub symlinks: usize,
    pub total_extents: usize,
    pub total_data_bytes: u64,
    pub orphaned_inodes: Vec<u64>,
    pub issues: Vec<IntegrityIssue>,
    pub sampled_records: usize,
    pub sampled_data_bytes: u64,
    pub sampled_blocks: usize,
    pub sample_percent: Option<f64>,
    #[serde(default)]
    pub seed: Option<u64>,
    pub remotes_checked: Vec<String>,
    #[serde(default)]
    pub remote_files_verified: usize,
    #[serde(default)]
    pub remote_bytes_verified: u64,
}

impl IntegrityReport {
    /// Returns true if no Error-level issues were found.
    pub fn is_clean(&self) -> bool {
        !self.issues.iter().any(|i| i.level == IssueLevel::Error)
    }

    /// Returns the number of Error-level issues.
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.level == IssueLevel::Error).count()
    }

    /// Returns the number of Warning-level issues.
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.level == IssueLevel::Warning).count()
    }

    /// Merges another integrity report into this one.
    pub fn merge(&mut self, other: IntegrityReport) {
        if self.total_inodes == 0 {
            self.total_inodes = other.total_inodes;
            self.directories = other.directories;
            self.regular_files = other.regular_files;
            self.symlinks = other.symlinks;
            self.total_extents = other.total_extents;
            self.total_data_bytes = other.total_data_bytes;
        }
        self.orphaned_inodes.extend(other.orphaned_inodes);
        self.issues.extend(other.issues);
        self.sampled_records += other.sampled_records;
        self.sampled_data_bytes += other.sampled_data_bytes;
        self.sampled_blocks += other.sampled_blocks;
        if self.sample_percent.is_none() {
            self.sample_percent = other.sample_percent;
        }
        if self.seed.is_none() {
            self.seed = other.seed;
        }
        for r in other.remotes_checked {
            if !self.remotes_checked.contains(&r) {
                self.remotes_checked.push(r);
            }
        }
        self.remote_files_verified += other.remote_files_verified;
        self.remote_bytes_verified += other.remote_bytes_verified;
    }

    /// Formats the report as a clean, human-readable terminal output.
    // TODO(too-many-lines): extract this into smaller units.
    #[allow(clippy::too_many_lines)]
    pub fn format_report(&self, log_dir: Option<&Path>, verbose: bool) -> String {
        let mut out = String::new();
        out.push_str("=================================================================\n");
        out.push_str("               AppendFS Filesystem Integrity Check               \n");
        out.push_str("=================================================================\n\n");

        if let Some(dir) = log_dir {
            out.push_str(&format!("  Log Directory:     {}\n", dir.display()));
        }
        out.push_str(&format!(
            "  Total Inodes:      {} (Directories: {}, Files: {}, Symlinks: {})\n",
            self.total_inodes, self.directories, self.regular_files, self.symlinks
        ));
        out.push_str(&format!("  Total Extents:     {}\n", self.total_extents));
        out.push_str(&format!(
            "  Logical Data Size: {} bytes ({:.2} MiB)\n",
            self.total_data_bytes,
            self.total_data_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push('\n');

        let errors = self.error_count();
        let warnings = self.warning_count();

        out.push_str("------------------------- Check Summary -------------------------\n");
        if self.orphaned_inodes.is_empty() {
            out.push_str("  [PASS] Inode Reachability (0 orphaned inodes)\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Inode Reachability ({} orphaned inodes detected)\n",
                self.orphaned_inodes.len()
            ));
        }

        let nlink_issues = self.issues.iter().filter(|i| i.code == "NLINK_MISMATCH").count();
        if nlink_issues == 0 {
            out.push_str("  [PASS] Hardlink Reference Counts (nlink)\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Hardlink Reference Counts ({} nlink mismatches)\n",
                nlink_issues
            ));
        }

        let hierarchy_issues = self
            .issues
            .iter()
            .filter(|i| {
                i.code == "ROOT_MISSING"
                    || i.code == "ROOT_NOT_DIR"
                    || i.code == "ROOT_INVALID_PARENT"
                    || i.code == "DIR_CYCLE"
                    || i.code == "INVALID_PARENT"
                    || i.code == "DANGLING_ENTRY"
                    || i.code == "DUPLICATE_ENTRY"
                    || i.code == "INVALID_NAME"
            })
            .count();
        if hierarchy_issues == 0 {
            out.push_str("  [PASS] Directory Hierarchy & Tree Acyclicity\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Directory Hierarchy ({} structural issues)\n",
                hierarchy_issues
            ));
        }

        let extent_issues = self
            .issues
            .iter()
            .filter(|i| {
                i.code.starts_with("EXTENT_")
                    || i.code == "ZERO_LEN_EXTENT"
                    || i.code == "MISSING_LOG_FILE"
                    || i.code == "CORRUPT_LOG_RECORD"
                    || i.code == "LOG_FILE_READ_ERROR"
                    || i.code == "REMOTE_READ_FAILED"
                    || i.code == "REMOTE_CORRUPT_HEADER"
                    || i.code == "REMOTE_UNKNOWN"
                    || i.code == "REMOTE_WRITE_ONLY"
            })
            .count();
        if extent_issues == 0 {
            if let Some(pct) = self.sample_percent {
                let seed_suffix = if pct < 100.0 {
                    self.seed.map(|s| format!(", seed: 0x{:016x}", s)).unwrap_or_default()
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "  [PASS] File Extents & Log Record Consistency ({:.3}% sample{}, {} records, {:.2} MiB across {} blocks)\n",
                    pct,
                    seed_suffix,
                    self.sampled_records,
                    self.sampled_data_bytes as f64 / (1024.0 * 1024.0),
                    self.sampled_blocks
                ));
            } else {
                out.push_str("  [PASS] File Extents & Log Record Consistency\n");
            }
        } else {
            let seed_suffix = if let Some(s) = self.seed
                && self.sample_percent.map(|p| p < 100.0).unwrap_or(false)
            {
                format!(" [seed: 0x{:016x}]", s)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  [FAIL] File Extents ({} extent/data inconsistencies){}\n",
                extent_issues, seed_suffix
            ));
        }

        let manifest_issues = self
            .issues
            .iter()
            .filter(|i| i.code.starts_with("MANIFEST_") || i.code == "LOG_SIZE_MISMATCH")
            .count();
        if manifest_issues == 0 {
            out.push_str("  [PASS] Log Manifest & Physical Storage\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Log Manifest ({} manifest issues)\n",
                manifest_issues
            ));
        }

        if !self.remotes_checked.is_empty() {
            let remote_issues = self.issues.iter().filter(|i| i.code.starts_with("REMOTE_")).count();
            if remote_issues == 0 {
                if self.remote_files_verified > 0 {
                    out.push_str(&format!(
                        "  [PASS] Remote Stores & Manifest Consistency ({}) (verified on-disk MD5 for {} files, {:.2} MiB)\n",
                        self.remotes_checked.join(", "),
                        self.remote_files_verified,
                        self.remote_bytes_verified as f64 / (1024.0 * 1024.0)
                    ));
                } else {
                    out.push_str(&format!(
                        "  [PASS] Remote Stores & Manifest Consistency ({})\n",
                        self.remotes_checked.join(", ")
                    ));
                }
            } else {
                out.push_str(&format!(
                    "  [FAIL] Remote Stores ({} remote integrity issues across {})\n",
                    remote_issues,
                    self.remotes_checked.join(", ")
                ));
            }
        }

        out.push('\n');

        if !self.issues.is_empty() {
            out.push_str("------------------------- Issues Found --------------------------\n");
            for issue in &self.issues {
                if !verbose && issue.level == IssueLevel::Info {
                    continue;
                }
                let target = match issue.inode {
                    Some(ino) => format!(" (Inode {})", ino),
                    None => String::new(),
                };
                out.push_str(&format!(
                    "  [{}] {}{}: {}\n",
                    issue.level, issue.code, target, issue.message
                ));
            }
            out.push('\n');
        }

        out.push_str("=================================================================\n");
        if self.is_clean() {
            if warnings == 0 {
                out.push_str("  VERDICT: CLEAN - Volume is healthy with 0 errors.\n");
            } else {
                out.push_str(&format!(
                    "  VERDICT: CLEAN WITH WARNINGS (0 errors, {} warning(s)).\n",
                    warnings
                ));
            }
        } else {
            out.push_str(&format!(
                "  VERDICT: CORRUPT - Volume has {} error(s) and {} warning(s).\n",
                errors, warnings
            ));
        }
        out.push_str("=================================================================\n");

        out
    }
}

/// A candidate record from a live file extent for verification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LiveRecord {
    pub inode: u64,
    pub generation: u32,
    pub record_log_offset: u64,
    pub record_size: u32,
}

/// Pre-flight plan for sampled data verification.
#[derive(Debug, Clone)]
pub struct VerificationPlan {
    pub sample_percent: f64,
    pub seed: u64,
    pub total_live_records: usize,
    pub total_live_bytes: u64,
    pub sampled_records: Vec<LiveRecord>,
    pub sampled_record_bytes: u64,
    /// 1 MiB blocks to fetch locally per generation: generation -> set of block indices.
    pub local_blocks: BTreeMap<u32, BTreeSet<u64>>,
    /// 1 MiB blocks to fetch per remote: remote_name -> (generation -> set of block indices).
    pub remote_blocks: BTreeMap<String, BTreeMap<u32, BTreeSet<u64>>>,
    /// Which target (None = local, Some(remote_name) = remote) is assigned to verify each sampled record.
    pub record_targets: Vec<(LiveRecord, Option<String>)>,
    /// Requested remotes that were left out of data verification because they are write-only.
    pub write_only_remotes: Vec<String>,
}

impl VerificationPlan {
    pub fn total_blocks(&self) -> usize {
        let local: usize = self.local_blocks.values().map(|b| b.len()).sum();
        let remote: usize = self
            .remote_blocks
            .values()
            .flat_map(|m| m.values())
            .map(|b| b.len())
            .sum();
        local + remote
    }

    pub fn total_remote_egress_bytes(&self, manifest: &crate::log::LogManifest) -> u64 {
        let mut total = 0u64;
        for gen_map in self.remote_blocks.values() {
            for (&generation, blocks) in gen_map {
                let file_len = manifest
                    .get_by_generation(generation)
                    .map(|l| l.total_bytes)
                    .unwrap_or(0);
                for &b in blocks {
                    let start = b * crate::remote::block_cache::BLOCK_SIZE;
                    if start < file_len {
                        total += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                    }
                }
            }
        }
        total
    }

    pub fn total_remote_requests(&self) -> usize {
        self.remote_blocks
            .values()
            .map(|gen_map| gen_map.values().map(|b| b.len()).sum::<usize>())
            .sum()
    }

    pub fn display_summary(&self, manifest: &crate::log::LogManifest) -> String {
        let mut out = String::new();
        out.push_str("=================================================================\n");
        out.push_str("             AppendFS Sampled Data Verification Plan             \n");
        out.push_str("=================================================================\n");
        out.push_str(&format!(
            "  Sample Rate:         {:.3}% (Seed: 0x{:016x})\n",
            self.sample_percent, self.seed
        ));
        out.push_str(&format!(
            "  Live Records:        {} sampled out of {} (totaling {:.2} MiB)\n",
            self.sampled_records.len(),
            self.total_live_records,
            self.sampled_record_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push('\n');
        out.push_str("  Planned Read Traffic:\n");

        let mut local_bytes = 0u64;
        let mut local_blocks_count = 0usize;
        for (&generation, blocks) in &self.local_blocks {
            local_blocks_count += blocks.len();
            let file_len = manifest
                .get_by_generation(generation)
                .map(|l| l.total_bytes)
                .unwrap_or(0);
            for &b in blocks {
                let start = b * crate::remote::block_cache::BLOCK_SIZE;
                if start < file_len {
                    local_bytes += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                }
            }
        }

        if local_blocks_count > 0 || self.remote_blocks.is_empty() {
            out.push_str(&format!(
                "    Local Storage:     {:.2} MiB ({} 1 MiB blocks)\n",
                local_bytes as f64 / (1024.0 * 1024.0),
                local_blocks_count
            ));
        }

        let mut total_remote_bytes = 0u64;
        let mut total_remote_reqs = 0usize;

        for (remote_name, gen_map) in &self.remote_blocks {
            let mut rem_bytes = 0u64;
            let mut rem_reqs = 0usize;
            for (&generation, blocks) in gen_map {
                rem_reqs += blocks.len();
                let file_len = manifest
                    .get_by_generation(generation)
                    .map(|l| l.total_bytes)
                    .unwrap_or(0);
                for &b in blocks {
                    let start = b * crate::remote::block_cache::BLOCK_SIZE;
                    if start < file_len {
                        rem_bytes += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                    }
                }
            }
            total_remote_bytes += rem_bytes;
            total_remote_reqs += rem_reqs;
            out.push_str(&format!(
                "    Remote '{}':       {:.2} MiB ({} blocks / {} GET requests)\n",
                remote_name,
                rem_bytes as f64 / (1024.0 * 1024.0),
                rem_reqs,
                rem_reqs
            ));
        }

        if !self.remote_blocks.is_empty() {
            out.push_str("    -------------------------------------------------------------\n");
            out.push_str(&format!(
                "    Total Remote Egress: {:.2} MiB across {} GET range requests\n",
                total_remote_bytes as f64 / (1024.0 * 1024.0),
                total_remote_reqs
            ));
        }
        out.push_str("=================================================================\n");
        out
    }
}

fn verify_raw_record(
    raw_record: &[u8],
    record: &LiveRecord,
    file_key: &LogFileKey,
) -> Result<(), (&'static str, String)> {
    if raw_record.len() != record.record_size as usize {
        return Err((
            "CORRUPT_LOG_RECORD",
            format!(
                "Record at offset 0x{:x} in gen {} has incomplete length {} (expected {})",
                record.record_log_offset,
                record.generation,
                raw_record.len(),
                record.record_size
            ),
        ));
    }
    if raw_record.len() < RECORD_HEADER_SIZE {
        return Err((
            "CORRUPT_LOG_RECORD",
            format!(
                "Record at offset 0x{:x} in gen {} is smaller than header size {}",
                record.record_log_offset, record.generation, RECORD_HEADER_SIZE
            ),
        ));
    }

    let mut hdr_buf = [0u8; RECORD_HEADER_SIZE];
    hdr_buf.copy_from_slice(&raw_record[..RECORD_HEADER_SIZE]);
    let rec_header = RecordHeader::from_bytes(&hdr_buf).map_err(|e| {
        (
            "CORRUPT_LOG_RECORD",
            format!(
                "Invalid record header at offset 0x{:x} in gen {}: {}",
                record.record_log_offset, record.generation, e
            ),
        )
    })?;

    let opcode = rec_header.op_code as u8;
    if opcode != OpCode::Data as u8 && opcode != OpCode::DataZstd as u8 {
        return Err((
            "CORRUPT_LOG_RECORD",
            format!(
                "Record at offset 0x{:x} in gen {} has OpCode {} instead of OpCode::Data / OpCode::DataZstd",
                record.record_log_offset, record.generation, opcode
            ),
        ));
    }

    // The header names the inode that wrote the record, which need not be the one referencing
    // it: `copy_file_range` shares records between files. The tag still binds the record to
    // the inode in its header, so a relabelled record fails authentication below.
    let payload = &raw_record[RECORD_HEADER_SIZE..];
    file_key
        .decrypt_record(
            rec_header.sequence,
            opcode,
            rec_header.inode,
            payload,
            &rec_header.auth_tag,
        )
        .map_err(|e| {
            (
                "CORRUPT_LOG_RECORD",
                format!(
                    "Authentication tag mismatch for record at offset 0x{:x} in gen {}: {}",
                    record.record_log_offset, record.generation, e
                ),
            )
        })?;

    Ok(())
}

/// Builds a deterministic verification plan covering approximately `options.sample_percent`% of
/// 1 MiB blocks containing live data across the entire volume. Records crossing 1 MiB block boundaries
/// automatically expand the required fetch set to include the full span of blocks needed for complete decryption,
/// and all live extents completely covered by the resulting block set are verified.
#[allow(clippy::too_many_lines)]
pub fn plan_sampled_verification(fs: &AppendFs, options: &CheckOptions) -> VerificationPlan {
    let base_map = fs.inner.lock(OpTag::Stats).unwrap().base.clone();
    let manifest = fs.manifest.read().unwrap();
    const BLOCK_SIZE: u64 = crate::remote::block_cache::BLOCK_SIZE;

    // 1. Collect all unique live records from the inode tree, skipping invalid extents
    let mut unique_records: BTreeMap<(u32, u64), LiveRecord> = BTreeMap::new();
    for (&ino, node_arc) in &base_map {
        if let NodeKind::File { extent_map, .. } = &node_arc.as_ref().kind {
            for (_offset, entry) in extent_map.iter() {
                if let ExtentState::Disk {
                    generation,
                    record_log_offset,
                    record_size,
                    ..
                } = &entry.extent
                {
                    // Filter out corrupt extents: Pass 3 already flags them, and verifying
                    // them during data pass causes underflow / panic.
                    if (*record_size as usize) < RECORD_HEADER_SIZE {
                        continue;
                    }
                    if record_log_offset.checked_add(*record_size as u64).is_none() {
                        continue;
                    }
                    let max_allowed_bytes =
                        manifest
                            .get_by_generation(*generation)
                            .map(|l| l.total_bytes)
                            .or_else(|| {
                                fs.log_writer
                                    .as_ref()
                                    .filter(|w| w.generation() == *generation)
                                    .map(|w| w.current_offset())
                            });
                    if let Some(max_bytes) = max_allowed_bytes
                        && *record_log_offset + *record_size as u64 > max_bytes
                    {
                        continue;
                    }

                    // Several inodes can share a record; it is reported against the lowest, so
                    // the report does not depend on the order `base` is walked in.
                    let record = unique_records
                        .entry((*generation, *record_log_offset))
                        .or_insert(LiveRecord {
                            inode: ino,
                            generation: *generation,
                            record_log_offset: *record_log_offset,
                            record_size: *record_size,
                        });
                    record.inode = record.inode.min(ino);
                }
            }
        }
    }

    let total_live_records = unique_records.len();
    let total_live_bytes: u64 = unique_records.values().map(|r| r.record_size as u64).sum();

    // 2. Index live records by generation and by (generation, block_index)
    let mut records_by_gen: BTreeMap<u32, Vec<LiveRecord>> = BTreeMap::new();
    let mut records_by_gen_block: BTreeMap<(u32, u64), Vec<LiveRecord>> = BTreeMap::new();
    let mut all_live_blocks: Vec<(u32, u64)> = Vec::new();
    let mut seen_live_blocks: HashSet<(u32, u64)> = HashSet::new();

    for rec in unique_records.into_values() {
        let start_blk = rec.record_log_offset / BLOCK_SIZE;
        let end_blk = (rec.record_log_offset + rec.record_size as u64).saturating_sub(1) / BLOCK_SIZE;

        for blk in start_blk..=end_blk {
            if seen_live_blocks.insert((rec.generation, blk)) {
                all_live_blocks.push((rec.generation, blk));
            }
            records_by_gen_block
                .entry((rec.generation, blk))
                .or_default()
                .push(rec.clone());
        }
        records_by_gen.entry(rec.generation).or_default().push(rec);
    }

    for records in records_by_gen.values_mut() {
        records.sort_by_key(|r| r.record_log_offset);
    }

    // 3. Derive seed: deterministic random by default or explicit if specified
    let seed = options.seed.unwrap_or_else(rand::random);
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // 4. Resolve verification targets (None = local storage, Some(name) = remote). Write-only
    // remotes cannot be read back; they are recorded so the executor can report them rather than
    // silently verifying local storage in their place.
    let mut targets: BTreeSet<Option<String>> = BTreeSet::new();
    let mut write_only_remotes = Vec::new();
    let mut write_only_in_all = Vec::new();
    {
        let reg_opt = fs.remote_registry.read().unwrap().clone();
        let reg = reg_opt.as_ref().map(|r| r.read().unwrap());
        for r in &options.remotes {
            if r == "local" {
                targets.insert(None);
            } else if r == "all" {
                for (name, cfg) in reg.iter().flat_map(|reg| reg.remotes.iter()) {
                    if cfg.mode.is_readable() {
                        targets.insert(Some(name.clone()));
                    } else {
                        write_only_in_all.push(name.clone());
                    }
                }
            } else if let Some(cfg) = reg.as_ref().and_then(|reg| reg.get_remote(r))
                && !cfg.mode.is_readable()
            {
                write_only_remotes.push(r.clone());
            } else {
                // Unknown remotes are reported as REMOTE_UNKNOWN by the executor.
                targets.insert(Some(r.clone()));
            }
        }
    }
    // `all` quietly skips write-only remotes, unless that leaves nothing to verify.
    if targets.is_empty() {
        write_only_remotes.append(&mut write_only_in_all);
    }
    // No remotes requested (or `all` with no remotes configured) verifies local storage.
    if targets.is_empty() && write_only_remotes.is_empty() {
        targets.insert(None);
    }

    // 5. Sample blocks across the entire volume based on total block count
    let total_live_blocks = all_live_blocks.len();
    let selected_blocks = if total_live_blocks == 0 || options.sample_percent <= 0.0 {
        Vec::new()
    } else if options.sample_percent >= 100.0 {
        all_live_blocks.sort_unstable();
        all_live_blocks
    } else {
        let target_blocks = (((total_live_blocks as f64) * (options.sample_percent / 100.0)).ceil() as usize)
            .max(1)
            .min(total_live_blocks);
        all_live_blocks.shuffle(&mut rng);
        all_live_blocks.truncate(target_blocks);
        all_live_blocks.sort_unstable();
        all_live_blocks
    };

    // 6. Assign selected blocks to targets in contiguous ranges, expanding straddling records.
    //
    // The selected blocks (in volume order) are split into one contiguous range per target, so
    // that blocks are only fetched from two targets where adjacent ranges meet. The ranges are
    // rotated by a seeded offset, which varies both where the split points fall and which target
    // reads which part of the volume from one run to the next.
    let targets: Vec<Option<String>> = targets.into_iter().collect();
    let rotation = if selected_blocks.is_empty() {
        0
    } else {
        rng.gen_range(0..selected_blocks.len())
    };
    let mut local_blocks: BTreeMap<u32, BTreeSet<u64>> = BTreeMap::new();
    let mut remote_blocks: BTreeMap<String, BTreeMap<u32, BTreeSet<u64>>> = BTreeMap::new();

    let mut fetched_blocks: HashSet<(u32, u64)> = HashSet::new();

    for (i, &(generation, seed_blk)) in selected_blocks.iter().enumerate() {
        if fetched_blocks.contains(&(generation, seed_blk)) {
            continue;
        }

        // Local storage is skipped for generations already pruned locally, unless it is the only target.
        let local_eligible = targets.len() == 1 || {
            let log_filename = manifest
                .get_by_generation(generation)
                .map(|l| l.filename.clone())
                .unwrap_or_else(|| crate::log::log_filename(generation));
            fs.log_cache
                .as_ref()
                .is_none_or(|cache| cache.storage().exists(&log_filename))
        };
        // If the range's target is ineligible, the next target in order takes the block instead.
        let range = ((i + rotation) % selected_blocks.len()) * targets.len() / selected_blocks.len();
        let Some(chosen_target) = (0..targets.len())
            .map(|d| &targets[(range + d) % targets.len()])
            .find(|t| t.is_some() || local_eligible)
            .cloned()
        else {
            break;
        };

        // Every record touching the seed block must be fully readable from the chosen target. A
        // neighbouring block already assigned to a different target is fetched again here, since
        // a record split across two targets could otherwise never be assembled and verified.
        let assigned = match &chosen_target {
            None => local_blocks.get(&generation),
            Some(name) => remote_blocks.get(name).and_then(|m| m.get(&generation)),
        };
        let mut blocks_to_add = vec![seed_blk];
        if let Some(straddling_records) = records_by_gen_block.get(&(generation, seed_blk)) {
            for rec in straddling_records {
                let start_blk = rec.record_log_offset / BLOCK_SIZE;
                let end_blk = (rec.record_log_offset + rec.record_size as u64).saturating_sub(1) / BLOCK_SIZE;
                for blk in start_blk..=end_blk {
                    if !assigned.is_some_and(|a| a.contains(&blk)) && !blocks_to_add.contains(&blk) {
                        blocks_to_add.push(blk);
                    }
                }
            }
        }

        for &blk in &blocks_to_add {
            fetched_blocks.insert((generation, blk));
            match &chosen_target {
                None => {
                    local_blocks.entry(generation).or_default().insert(blk);
                }
                Some(remote_name) => {
                    remote_blocks
                        .entry(remote_name.clone())
                        .or_default()
                        .entry(generation)
                        .or_default()
                        .insert(blk);
                }
            }
        }
    }

    // 7. Find all records whose required blocks are completely covered by fetched blocks
    let mut sampled_records = Vec::new();
    let mut record_targets = Vec::new();
    let mut verified_records: HashSet<(u32, u64)> = HashSet::new();

    if !local_blocks.is_empty() {
        for (&generation, gen_records) in &records_by_gen {
            if let Some(fetched) = local_blocks.get(&generation) {
                for rec in gen_records {
                    let start_blk = rec.record_log_offset / BLOCK_SIZE;
                    let end_blk = (rec.record_log_offset + rec.record_size as u64).saturating_sub(1) / BLOCK_SIZE;
                    let fully_covered = (start_blk..=end_blk).all(|b| fetched.contains(&b));
                    if fully_covered && verified_records.insert((rec.generation, rec.record_log_offset)) {
                        sampled_records.push(rec.clone());
                        record_targets.push((rec.clone(), None));
                    }
                }
            }
        }
    }

    for (remote_name, gen_map) in &remote_blocks {
        for (&generation, gen_records) in &records_by_gen {
            if let Some(fetched) = gen_map.get(&generation) {
                for rec in gen_records {
                    let start_blk = rec.record_log_offset / BLOCK_SIZE;
                    let end_blk = (rec.record_log_offset + rec.record_size as u64).saturating_sub(1) / BLOCK_SIZE;
                    let fully_covered = (start_blk..=end_blk).all(|b| fetched.contains(&b));
                    if fully_covered && verified_records.insert((rec.generation, rec.record_log_offset)) {
                        sampled_records.push(rec.clone());
                        record_targets.push((rec.clone(), Some(remote_name.clone())));
                    }
                }
            }
        }
    }

    sampled_records.sort_by_key(|r| (r.generation, r.record_log_offset));
    record_targets.sort_by_key(|(r, _)| (r.generation, r.record_log_offset));
    let sampled_record_bytes: u64 = sampled_records.iter().map(|r| r.record_size as u64).sum();

    VerificationPlan {
        sample_percent: options.sample_percent,
        seed,
        total_live_records,
        total_live_bytes,
        sampled_records,
        sampled_record_bytes,
        local_blocks,
        remote_blocks,
        record_targets,
        write_only_remotes,
    }
}

/// Executes data verification for the sampled records in `plan`.
///
/// `progress`, if given, is called as data is read with `(bytes_read, bytes_total)`.
#[allow(clippy::too_many_lines)]
pub fn execute_sampled_verification(
    fs: &AppendFs,
    plan: &VerificationPlan,
    log_dir: Option<&Path>,
    report: &mut IntegrityReport,
    mut progress: Option<&mut dyn FnMut(u64, u64)>,
) {
    for remote_name in &plan.write_only_remotes {
        report.issues.push(IntegrityIssue::error(
            "REMOTE_WRITE_ONLY",
            None,
            format!(
                "Remote '{}' is configured as write-only and cannot be data verified",
                remote_name
            ),
        ));
    }

    if plan.sampled_records.is_empty() {
        report.sample_percent = Some(plan.sample_percent);
        report.seed = Some(plan.seed);
        return;
    }

    let manifest = fs.manifest.read().unwrap();
    const BLOCK_SIZE: u64 = crate::remote::block_cache::BLOCK_SIZE;

    let gen_len = |generation: u32| {
        manifest
            .get_by_generation(generation)
            .map(|l| l.total_bytes)
            .or_else(|| {
                fs.log_writer
                    .as_ref()
                    .filter(|w| w.generation() == generation)
                    .map(|w| w.current_offset())
            })
            .unwrap_or(0)
    };
    let blocks_bytes = |generation: u32, blocks: &BTreeSet<u64>| -> u64 {
        let file_len = gen_len(generation);
        blocks
            .iter()
            .map(|&b| file_len.saturating_sub(b * BLOCK_SIZE).min(BLOCK_SIZE))
            .sum()
    };

    // Progress counts remote block bytes fetched plus local record bytes read. Records skipped
    // on an error still count, so a run with errors finishes at 100% too.
    let total_bytes: u64 = plan
        .remote_blocks
        .values()
        .flat_map(|gen_map| gen_map.iter())
        .map(|(&generation, blocks)| blocks_bytes(generation, blocks))
        .sum::<u64>()
        + plan
            .record_targets
            .iter()
            .filter(|(_, target)| target.is_none())
            .map(|(rec, _)| rec.record_size as u64)
            .sum::<u64>();
    let mut done_bytes = 0u64;
    let mut advance = |bytes: u64| {
        done_bytes += bytes;
        if let Some(p) = progress.as_mut() {
            p(done_bytes, total_bytes);
        }
    };

    let mut verified_count = 0usize;
    let mut verified_bytes = 0u64;

    // Index records by (target, generation) for linear O(B + R) processing in deterministic order
    let mut remote_records_by_gen: BTreeMap<(&str, u32), Vec<&LiveRecord>> = BTreeMap::new();
    let mut local_records_by_gen: BTreeMap<u32, Vec<&LiveRecord>> = BTreeMap::new();

    for (rec, target) in &plan.record_targets {
        match target {
            Some(remote_name) => {
                remote_records_by_gen
                    .entry((remote_name.as_str(), rec.generation))
                    .or_default()
                    .push(rec);
            }
            None => {
                local_records_by_gen.entry(rec.generation).or_default().push(rec);
            }
        }
    }

    for records in remote_records_by_gen.values_mut() {
        records.sort_by_key(|r| r.record_log_offset);
    }
    for records in local_records_by_gen.values_mut() {
        records.sort_by_key(|r| r.record_log_offset);
    }

    // 1. Verify remote records by streaming block-by-block with sliding window
    if !plan.remote_blocks.is_empty() {
        let reg_opt = fs.remote_registry.read().unwrap().clone();
        let registry = if let Some(reg_arc) = reg_opt {
            reg_arc.read().unwrap().clone()
        } else if let Some(dir) = log_dir {
            crate::remote::RemoteRegistry::load_from_storage(&crate::storage::OsStorage::new(dir)).unwrap_or_default()
        } else if let Some(ref cache) = fs.log_cache {
            crate::remote::RemoteRegistry::load_from_storage(cache.storage().as_ref()).unwrap_or_default()
        } else {
            crate::remote::RemoteRegistry::default()
        };

        for (remote_name, gen_map) in &plan.remote_blocks {
            let store = match registry.store_overrides.get(remote_name) {
                Some(s) => s.clone(),
                None => match registry.get_remote(remote_name) {
                    Some(cfg) => cfg.build_store(),
                    None => {
                        report.issues.push(IntegrityIssue::error(
                            "REMOTE_UNKNOWN",
                            None,
                            format!("Remote '{}' is not configured in remotes.toml", remote_name),
                        ));
                        advance(gen_map.iter().map(|(&g, blocks)| blocks_bytes(g, blocks)).sum());
                        continue;
                    }
                },
            };

            for (&generation, blocks) in gen_map {
                let filename = manifest
                    .get_by_generation(generation)
                    .map(|l| l.filename.clone())
                    .unwrap_or_else(|| crate::log::log_filename(generation));

                // Fetch 42-byte FileHeader to derive LogFileKey
                let mut hdr_bytes = Vec::with_capacity(FILE_HEADER_SIZE);
                if let Err(e) = store.get_object_range(&filename, 0, FILE_HEADER_SIZE as u64, &mut hdr_bytes) {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_READ_FAILED",
                        None,
                        format!(
                            "Failed to read header from remote '{}' for {}: {}",
                            remote_name, filename, e
                        ),
                    ));
                    advance(blocks_bytes(generation, blocks));
                    continue;
                }
                let Ok(hdr_array): Result<[u8; FILE_HEADER_SIZE], _> = hdr_bytes.try_into() else {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_CORRUPT_HEADER",
                        None,
                        format!("Invalid header length in {} on remote '{}'", filename, remote_name),
                    ));
                    advance(blocks_bytes(generation, blocks));
                    continue;
                };
                let file_header = match FileHeader::from_bytes(&hdr_array) {
                    Ok(h) => h,
                    Err(e) => {
                        report.issues.push(IntegrityIssue::error(
                            "REMOTE_CORRUPT_HEADER",
                            None,
                            format!("Invalid header in {} on remote '{}': {}", filename, remote_name, e),
                        ));
                        advance(blocks_bytes(generation, blocks));
                        continue;
                    }
                };
                let file_key = Arc::new(fs.volume_key.log_file_key(&file_header.key_salt));

                let manifest_len = gen_len(generation);

                let records = remote_records_by_gen
                    .get(&(remote_name.as_str(), generation))
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);

                let mut window: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
                let mut rec_idx = 0;

                for &b in blocks {
                    let start_offset = b * BLOCK_SIZE;
                    if start_offset < manifest_len {
                        let len = (manifest_len - start_offset).min(BLOCK_SIZE);
                        let mut block_buf = Vec::with_capacity(len as usize);
                        if let Err(e) = store.get_object_range(&filename, start_offset, len, &mut block_buf) {
                            report.issues.push(IntegrityIssue::error(
                                "REMOTE_READ_FAILED",
                                None,
                                format!(
                                    "Failed to fetch block {} of {} from remote '{}': {}",
                                    b, filename, remote_name, e
                                ),
                            ));
                        } else {
                            window.insert(b, block_buf);
                        }
                        advance(len);
                    }

                    // Process all records whose required blocks end on or before block `b`
                    while rec_idx < records.len() {
                        let rec = records[rec_idx];
                        let start_blk = rec.record_log_offset / BLOCK_SIZE;
                        let end_blk = (rec.record_log_offset + rec.record_size as u64).saturating_sub(1) / BLOCK_SIZE;

                        if b < end_blk {
                            break;
                        }

                        let fully_loaded = (start_blk..=end_blk).all(|k| window.contains_key(&k));
                        if fully_loaded {
                            let mut raw_record = Vec::with_capacity(rec.record_size as usize);
                            let mut cur_offset = rec.record_log_offset;
                            let end_offset = rec.record_log_offset + rec.record_size as u64;
                            while cur_offset < end_offset {
                                let blk = cur_offset / BLOCK_SIZE;
                                let blk_start = blk * BLOCK_SIZE;
                                let offset_in_blk = (cur_offset - blk_start) as usize;
                                let blk_bytes = &window[&blk];
                                let avail = blk_bytes.len().saturating_sub(offset_in_blk);
                                let remaining = (end_offset - cur_offset) as usize;
                                let take = avail.min(remaining);
                                if take == 0 {
                                    break;
                                }
                                raw_record.extend_from_slice(&blk_bytes[offset_in_blk..offset_in_blk + take]);
                                cur_offset += take as u64;
                            }

                            match verify_raw_record(&raw_record, rec, &file_key) {
                                Ok(()) => {
                                    verified_count += 1;
                                    verified_bytes += rec.record_size as u64;
                                }
                                Err((code, msg)) => {
                                    report.issues.push(IntegrityIssue::error(
                                        code,
                                        Some(rec.inode),
                                        format!("{} (remote '{}')", msg, remote_name),
                                    ));
                                }
                            }
                        } else {
                            report.issues.push(IntegrityIssue::error(
                                "CORRUPT_LOG_RECORD",
                                Some(rec.inode),
                                format!(
                                    "Record at offset 0x{:x} in generation {} could not be assembled from remote '{}'",
                                    rec.record_log_offset, rec.generation, remote_name
                                ),
                            ));
                        }
                        rec_idx += 1;
                    }

                    // Slide the window forward by purging blocks no longer needed by any remaining record
                    let min_needed_blk = if rec_idx < records.len() {
                        records[rec_idx].record_log_offset / BLOCK_SIZE
                    } else {
                        u64::MAX
                    };
                    window.retain(|&k, _| k >= min_needed_blk);
                }
            }
        }
    }

    // 2. Verify local records
    let local_cache = fs
        .log_cache
        .clone()
        .or_else(|| log_dir.map(|d| Arc::new(LogFileCache::new(d))));

    for (&generation, records) in &local_records_by_gen {
        let records_bytes: u64 = records.iter().map(|r| r.record_size as u64).sum();
        if let Some(ref c) = local_cache {
            let log_filename = manifest
                .get_by_generation(generation)
                .map(|l| l.filename.clone())
                .unwrap_or_else(|| crate::log::log_filename(generation));
            if !c.storage().exists(&log_filename) {
                for rec in records {
                    report.issues.push(IntegrityIssue::error(
                        "MISSING_LOG_FILE",
                        Some(rec.inode),
                        format!(
                            "File inode {} extent references generation {} ('{}'), which does not exist in storage",
                            rec.inode, rec.generation, log_filename
                        ),
                    ));
                }
                advance(records_bytes);
                continue;
            }

            let file_len = match c.storage().file_len(&log_filename) {
                Ok(len) => len,
                Err(e) => {
                    for rec in records {
                        report.issues.push(IntegrityIssue::error(
                            "LOG_FILE_READ_ERROR",
                            Some(rec.inode),
                            format!("Failed to read file size for {}: {}", log_filename, e),
                        ));
                    }
                    advance(records_bytes);
                    continue;
                }
            };

            let open = match c.get_or_open(generation, &fs.volume_key) {
                Ok(open) => open,
                Err(e) => {
                    for rec in records {
                        report.issues.push(IntegrityIssue::error(
                            "LOG_FILE_READ_ERROR",
                            Some(rec.inode),
                            format!("Failed to open log file {}: {}", log_filename, e),
                        ));
                    }
                    advance(records_bytes);
                    continue;
                }
            };

            for rec in records {
                advance(rec.record_size as u64);
                if file_len < rec.record_log_offset + rec.record_size as u64 {
                    report.issues.push(IntegrityIssue::error(
                        "EXTENT_PAST_LOG_EOF",
                        Some(rec.inode),
                        format!(
                            "File inode {} record at offset 0x{:x} in {} declares {} bytes, which runs past {} byte file",
                            rec.inode, rec.record_log_offset, log_filename, rec.record_size, file_len
                        ),
                    ));
                    continue;
                }

                let mut raw_record = vec![0u8; rec.record_size as usize];
                if let Err(e) = open.reader.read_exact_at(rec.record_log_offset, &mut raw_record) {
                    report.issues.push(IntegrityIssue::error(
                        "CORRUPT_LOG_RECORD",
                        Some(rec.inode),
                        format!(
                            "Failed to read record at offset 0x{:x} in {}: {}",
                            rec.record_log_offset, log_filename, e
                        ),
                    ));
                    continue;
                }

                match verify_raw_record(&raw_record, rec, &open.file_key) {
                    Ok(()) => {
                        verified_count += 1;
                        verified_bytes += rec.record_size as u64;
                    }
                    Err((code, msg)) => {
                        report.issues.push(IntegrityIssue::error(
                            code,
                            Some(rec.inode),
                            format!("{} ({})", msg, log_filename),
                        ));
                    }
                }
            }
        } else {
            advance(records_bytes);
        }
    }

    report.sampled_records += verified_count;
    report.sampled_data_bytes += verified_bytes;
    report.sampled_blocks += plan.total_blocks();
    report.sample_percent = Some(plan.sample_percent);
    report.seed = Some(plan.seed);
}

/// Runs a read-only filesystem integrity check on the provided `AppendFs`.
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn check_fs_integrity(
    fs: &AppendFs,
    log_dir: Option<&Path>,
    options: &CheckOptions,
    plan: Option<&VerificationPlan>,
    progress: Option<&mut dyn FnMut(u64, u64)>,
) -> IntegrityReport {
    let mut report = IntegrityReport::default();

    // 0. Extract manifest and base snapshot
    let manifest = fs.manifest.read().unwrap().clone();

    let base_map = fs.inner.lock(OpTag::Stats).unwrap().base.clone();
    report.total_inodes = base_map.len();

    for (&_ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        match &node.kind {
            NodeKind::Directory { .. } => report.directories += 1,
            NodeKind::File { extent_map, size, .. } => {
                report.regular_files += 1;
                report.total_extents += extent_map.len();
                report.total_data_bytes += size;
            }
            NodeKind::Symlink { .. } => report.symlinks += 1,
            NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket => {}
        }
    }

    // Pass 1: Root Inode & Directory Hierarchy Traversal
    let mut reachable = HashSet::new();
    let mut ref_counts: HashMap<u64, u32> = HashMap::new();
    let mut subdirs_count: HashMap<u64, u32> = HashMap::new();

    let root_opt = base_map.get(&1);
    match root_opt {
        None => {
            report.issues.push(IntegrityIssue::error(
                "ROOT_MISSING",
                Some(1),
                "Root directory (inode 1) is missing from filesystem",
            ));
        }
        Some(root_arc) => {
            let root_node = root_arc.as_ref();
            match &root_node.kind {
                NodeKind::Directory { parent, .. } => {
                    if *parent != 1 {
                        report.issues.push(IntegrityIssue::error(
                            "ROOT_INVALID_PARENT",
                            Some(1),
                            format!("Root inode 1 has parent {}, expected 1", parent),
                        ));
                    }
                    reachable.insert(1);

                    // BFS Directory Traversal
                    let mut queue = VecDeque::new();
                    let mut active_path = HashSet::new();
                    active_path.insert(1);
                    queue.push_back((1u64, active_path));

                    while let Some((curr_dir_ino, current_ancestors)) = queue.pop_front() {
                        let curr_arc = match base_map.get(&curr_dir_ino) {
                            Some(a) => a,
                            None => continue,
                        };
                        let curr_node = curr_arc.as_ref();
                        let entries = match &curr_node.kind {
                            NodeKind::Directory { entries, .. } => entries,
                            _ => continue,
                        };

                        let mut seen_in_dir = HashSet::new();

                        for (name, child_ino) in entries {
                            let child_ino = *child_ino;
                            // Validate entry name
                            if name.is_empty() {
                                report.issues.push(IntegrityIssue::error(
                                    "INVALID_NAME",
                                    Some(curr_dir_ino),
                                    "Directory contains an entry with an empty filename",
                                ));
                            } else if name.len() > 255 {
                                report.issues.push(IntegrityIssue::error(
                                    "NAME_TOO_LONG",
                                    Some(curr_dir_ino),
                                    format!("Directory contains entry '{}' exceeding 255 bytes", name),
                                ));
                            } else if name.contains('/') || name.contains('\0') {
                                report.issues.push(IntegrityIssue::error(
                                    "INVALID_NAME",
                                    Some(curr_dir_ino),
                                    format!("Directory entry '{}' contains illegal characters ('/' or '\\0')", name),
                                ));
                            }

                            if !seen_in_dir.insert(name) {
                                report.issues.push(IntegrityIssue::error(
                                    "DUPLICATE_ENTRY",
                                    Some(curr_dir_ino),
                                    format!(
                                        "Directory inode {} contains duplicate entry name '{}'",
                                        curr_dir_ino, name
                                    ),
                                ));
                            }

                            // Check child existence
                            let child_arc = match base_map.get(&child_ino) {
                                Some(a) => a,
                                None => {
                                    report.issues.push(IntegrityIssue::error(
                                        "DANGLING_ENTRY",
                                        Some(curr_dir_ino),
                                        format!(
                                            "Directory entry '{}' in inode {} points to non-existent inode {}",
                                            name, curr_dir_ino, child_ino
                                        ),
                                    ));
                                    continue;
                                }
                            };

                            *ref_counts.entry(child_ino).or_default() += 1;

                            let child_node = child_arc.as_ref();
                            match &child_node.kind {
                                NodeKind::Directory { parent, .. } => {
                                    if child_ino == 1 {
                                        report.issues.push(IntegrityIssue::error(
                                            "ROOT_IN_SUBDIR",
                                            Some(curr_dir_ino),
                                            format!(
                                                "Directory inode {} contains entry '{}' pointing back to root (inode 1)",
                                                curr_dir_ino, name
                                            ),
                                        ));
                                        continue;
                                    }

                                    if current_ancestors.contains(&child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "DIR_CYCLE",
                                            Some(child_ino),
                                            format!(
                                                "Directory cycle detected: inode {} appears in its own directory ancestry",
                                                child_ino
                                            ),
                                        ));
                                        continue;
                                    }

                                    if *parent != curr_dir_ino {
                                        report.issues.push(IntegrityIssue::error(
                                            "INVALID_PARENT",
                                            Some(child_ino),
                                            format!(
                                                "Directory inode {} has parent field {}, but is contained in directory {}",
                                                child_ino, parent, curr_dir_ino
                                            ),
                                        ));
                                    }

                                    if reachable.contains(&child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "MULTIPLE_DIR_HARDLINKS",
                                            Some(child_ino),
                                            format!(
                                                "Directory inode {} has multiple directory entries pointing to it",
                                                child_ino
                                            ),
                                        ));
                                    }

                                    *subdirs_count.entry(curr_dir_ino).or_default() += 1;
                                    reachable.insert(child_ino);

                                    let mut next_ancestors = current_ancestors.clone();
                                    next_ancestors.insert(child_ino);
                                    queue.push_back((child_ino, next_ancestors));
                                }
                                NodeKind::File { .. }
                                | NodeKind::Symlink { .. }
                                | NodeKind::Fifo
                                | NodeKind::CharDevice { .. }
                                | NodeKind::BlockDevice { .. }
                                | NodeKind::Socket => {
                                    reachable.insert(child_ino);
                                }
                            }
                        }
                    }
                }
                _ => {
                    report.issues.push(IntegrityIssue::error(
                        "ROOT_NOT_DIR",
                        Some(1),
                        "Root inode 1 is not a directory",
                    ));
                }
            }
        }
    }

    // Pass 1.1: Orphan Inode Identification
    for (&ino, node_arc) in base_map.iter() {
        if !reachable.contains(&ino) {
            report.orphaned_inodes.push(ino);
            let node = node_arc.as_ref();
            let type_str = match &node.kind {
                NodeKind::Directory { entries, .. } => {
                    format!("Directory with {} entries", entries.len())
                }
                NodeKind::File { size, .. } => format!("RegularFile with {} bytes", size),
                NodeKind::Symlink { target, .. } => format!("Symlink -> '{}'", target),
                NodeKind::Fifo => "FIFO".to_string(),
                NodeKind::CharDevice { rdev } => format!("CharDevice (rdev=0x{:x})", rdev),
                NodeKind::BlockDevice { rdev } => format!("BlockDevice (rdev=0x{:x})", rdev),
                NodeKind::Socket => "Socket".to_string(),
            };
            report.issues.push(IntegrityIssue::error(
                "ORPHAN_INODE",
                Some(ino),
                format!(
                    "Orphaned inode {} ({}) exists in storage but is not reachable from root",
                    ino, type_str
                ),
            ));
        }
    }
    report.orphaned_inodes.sort();

    // Pass 2: Hardlink (nlink) Validation
    for (&ino, node_arc) in base_map.iter() {
        if !reachable.contains(&ino) {
            continue;
        }
        let node = node_arc.as_ref();
        if node.is_dir() {
            let expected_nlink = 2 + subdirs_count.get(&ino).copied().unwrap_or(0);
            if node.meta.nlink != expected_nlink {
                report.issues.push(IntegrityIssue::error(
                    "NLINK_MISMATCH",
                    Some(ino),
                    format!(
                        "Directory inode {} has nlink {}, expected {} (2 + {} subdirectories)",
                        ino,
                        node.meta.nlink,
                        expected_nlink,
                        subdirs_count.get(&ino).copied().unwrap_or(0)
                    ),
                ));
            }
        } else {
            let expected_nlink = ref_counts.get(&ino).copied().unwrap_or(0);
            if node.meta.nlink != expected_nlink {
                let kind_str = if node.is_file() { "File" } else { "Symlink" };
                report.issues.push(IntegrityIssue::error(
                    "NLINK_MISMATCH",
                    Some(ino),
                    format!(
                        "{} inode {} has nlink {}, expected {} (referenced by {} directory entries)",
                        kind_str, ino, node.meta.nlink, expected_nlink, expected_nlink
                    ),
                ));
            }
        }
    }

    // Pass 3: File Extent & ExtentMap Validation
    let mut active_generations: HashSet<u32> = manifest.logs.iter().map(|l| l.generation).collect();
    if let Some(ref w) = fs.log_writer {
        active_generations.insert(w.generation());
    }
    let cache = fs
        .log_cache
        .clone()
        .or_else(|| log_dir.map(|d| Arc::new(LogFileCache::new(d))));

    for (&ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        if let NodeKind::File { extent_map, size, .. } = &node.kind {
            for (offset, entry) in extent_map.iter() {
                let file_offset = *offset;
                let extent_len = entry.length();

                if extent_len == 0 {
                    report.issues.push(IntegrityIssue::error(
                        "ZERO_LEN_EXTENT",
                        Some(ino),
                        format!("File inode {} has 0-length extent at offset {}", ino, file_offset),
                    ));
                }

                if file_offset + extent_len > *size {
                    report.issues.push(IntegrityIssue::error(
                        "EXTENT_PAST_EOF",
                        Some(ino),
                        format!(
                            "File inode {} has extent [{}..{}] exceeding file size {}",
                            ino,
                            file_offset,
                            file_offset + extent_len,
                            size
                        ),
                    ));
                }

                // `length` is deliberately ignored: it is the extent's logical size, and the
                // bytes a record occupies on disk are derived from the record header's
                // `payload_len` instead. Treating the logical length as a physical bound is
                // what made healthy compressed volumes look corrupt.
                if let ExtentState::Disk {
                    generation,
                    record_log_offset,
                    record_size,
                    payload_offset: _,
                    length: _,
                } = &entry.extent
                {
                    let generation = *generation;
                    let record_log_offset = *record_log_offset;
                    let record_size = *record_size;
                    if !active_generations.contains(&generation) {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_UNKNOWN_GENERATION",
                            Some(ino),
                            format!(
                                "File inode {} extent [{}..{}] references unknown log generation {}",
                                ino,
                                file_offset,
                                file_offset + extent_len,
                                generation
                            ),
                        ));
                    }

                    if (record_size as usize) < RECORD_HEADER_SIZE {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_INVALID_RECORD_SIZE",
                            Some(ino),
                            format!(
                                "File inode {} extent record at offset 0x{:x} declares record_size {} bytes, smaller than header size {}",
                                ino, record_log_offset, record_size, RECORD_HEADER_SIZE
                            ),
                        ));
                    }

                    let max_allowed_bytes =
                        manifest
                            .get_by_generation(generation)
                            .map(|l| l.total_bytes)
                            .or_else(|| {
                                fs.log_writer
                                    .as_ref()
                                    .filter(|w| w.generation() == generation)
                                    .map(|w| w.current_offset())
                            });

                    if let Some(max_bytes) = max_allowed_bytes
                        && record_log_offset + record_size as u64 > max_bytes
                    {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_PAST_MANIFEST_EOF",
                            Some(ino),
                            format!(
                                "File inode {} extent record [0x{:x}..0x{:x}) in generation {} exceeds total bytes {}",
                                ino,
                                record_log_offset,
                                record_log_offset + record_size as u64,
                                generation,
                                max_bytes
                            ),
                        ));
                    }
                }
            }
        }
    }

    if options.verify_data {
        if let Some(p) = plan {
            execute_sampled_verification(fs, p, log_dir, &mut report, progress);
        } else {
            let p = plan_sampled_verification(fs, options);
            execute_sampled_verification(fs, &p, log_dir, &mut report, progress);
        }
    }

    // Pass 4: Manifest & Physical File Consistency
    let mut prev_gen = 0u32;
    for info in &manifest.logs {
        if info.generation == 0 {
            report.issues.push(IntegrityIssue::error(
                "MANIFEST_INVALID_GEN",
                None,
                format!("Log generation in manifest cannot be 0: {}", info.filename),
            ));
        } else if info.generation <= prev_gen {
            report.issues.push(IntegrityIssue::error(
                "MANIFEST_OUT_OF_ORDER",
                None,
                format!(
                    "Log generation {} in manifest is not strictly greater than previous generation {}",
                    info.generation, prev_gen
                ),
            ));
        }
        prev_gen = info.generation;

        if let Some(ref c) = cache
            && c.storage().exists(&info.filename)
            && let Ok(file_len) = c.storage().file_len(&info.filename)
            && file_len < info.total_bytes
        {
            report.issues.push(IntegrityIssue::warning(
                "LOG_SIZE_MISMATCH",
                None,
                format!(
                    "Physical log file '{}' in storage ({} bytes) is smaller than recorded in manifest ({} bytes)",
                    info.filename, file_len, info.total_bytes
                ),
            ));
        }
    }

    report
}

/// Helper function to recover a volume using Storage in read-only mode and run integrity checks.
pub fn check_volume(
    storage: Arc<dyn crate::storage::Storage>,
    options: &CheckOptions,
    volume_key: Arc<crate::crypto::VolumeKey>,
    clock: Arc<dyn crate::clock::Clock>,
) -> std::io::Result<IntegrityReport> {
    let fs = crate::log::recover_fs(storage, crate::log::RecoveryTarget::Latest, clock, volume_key)?;
    Ok(check_fs_integrity(&fs, None, options, None, None))
}

#[derive(Debug, Clone)]
struct RemoteFileCandidate {
    filename: String,
    total_bytes: u64,
    expected_md5: [u8; 16],
    sidecar_md5: Option<[u8; 16]>,
}

/// Streams `key` from `remote` and computes its MD5, calling `on_read` with the size of each chunk read.
fn compute_remote_object_md5(
    remote: &dyn crate::remote::RemoteStore,
    key: &str,
    on_read: &mut dyn FnMut(u64),
) -> std::io::Result<[u8; 16]> {
    let mut hasher = md5::Context::new();
    struct Md5Writer<'a>(&'a mut md5::Context, &'a mut dyn FnMut(u64));
    impl<'a> std::io::Write for Md5Writer<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.consume(buf);
            (self.1)(buf.len() as u64);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    remote.get_object(key, &mut Md5Writer(&mut hasher, on_read))?;
    Ok(hasher.compute().0)
}

/// Picks the remote objects to download for MD5 verification, weighted by size so that the
/// selection covers `options.sample_percent` of the bytes.
fn select_remote_md5_candidates<'a>(
    candidates: &'a [RemoteFileCandidate],
    options: &CheckOptions,
) -> Vec<&'a RemoteFileCandidate> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let total_bytes: u64 = candidates.iter().map(|c| c.total_bytes).sum();
    let sample_pct = options.sample_percent.clamp(0.0, 100.0);
    let target_bytes = if sample_pct >= 100.0 {
        total_bytes
    } else {
        let tb = ((total_bytes as f64) * (sample_pct / 100.0)).ceil() as u64;
        if sample_pct > 0.0 { tb.max(1) } else { 0 }
    };

    if target_bytes == 0 {
        return Vec::new();
    }

    if sample_pct >= 100.0 {
        candidates.iter().collect()
    } else {
        let seed = options.seed.unwrap_or_else(rand::random::<u64>);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut scored: Vec<(f64, &RemoteFileCandidate)> = candidates
            .iter()
            .map(|c| {
                let weight = (c.total_bytes as f64).max(1.0);
                let u: f64 = rng.gen_range(0.0f64..1.0f64).max(1e-12);
                let score = -u.ln() / weight;
                (score, c)
            })
            .collect();
        scored.sort_by(|a, b| {
            a.0.partial_cmp(&b.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.filename.cmp(&b.1.filename))
        });

        let mut picked = Vec::new();
        let mut accumulated = 0u64;
        for (_score, candidate) in scored {
            picked.push(candidate);
            accumulated += candidate.total_bytes;
            if accumulated >= target_bytes {
                break;
            }
        }
        picked
    }
}

fn verify_remote_sidecar_files_md5(
    remote: &dyn crate::remote::RemoteStore,
    remote_name: &str,
    candidates: &[RemoteFileCandidate],
    options: &CheckOptions,
    report: &mut IntegrityReport,
    mut progress: Option<&mut dyn FnMut(u64, u64)>,
) {
    let selected = select_remote_md5_candidates(candidates, options);
    let selected_bytes: u64 = selected.iter().map(|c| c.total_bytes).sum();
    let mut done_bytes = 0u64;

    for candidate in selected {
        let sidecar_md5 = candidate.sidecar_md5.or_else(|| {
            remote
                .head_object(&candidate.filename)
                .ok()
                .flatten()
                .and_then(|o| o.etag_md5())
        });

        let file_start = done_bytes;
        let md5 = compute_remote_object_md5(remote, &candidate.filename, &mut |n| {
            done_bytes += n;
            if let Some(p) = progress.as_mut() {
                p(done_bytes, selected_bytes);
            }
        });
        // A failed or short read still accounts for the whole object, so progress ends at 100%.
        done_bytes = file_start + candidate.total_bytes;
        if let Some(p) = progress.as_mut() {
            p(done_bytes, selected_bytes);
        }
        match md5 {
            Ok(computed_md5) => {
                if computed_md5 != candidate.expected_md5 {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_FILE_MD5_MISMATCH",
                        None,
                        format!(
                            "Remote '{}' object {} on-disk data MD5 mismatch: expected manifest MD5 {}, computed {}",
                            remote_name,
                            candidate.filename,
                            hex::encode(candidate.expected_md5),
                            hex::encode(computed_md5)
                        ),
                    ));
                } else if let Some(sidecar_md5) = sidecar_md5
                    && sidecar_md5 != computed_md5
                {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_SIDECAR_CORRUPT",
                        None,
                        format!(
                            "Remote '{}' object {} sidecar .md5 mismatch: on-disk data MD5 is {}, but sidecar specifies {}",
                            remote_name,
                            candidate.filename,
                            hex::encode(computed_md5),
                            hex::encode(sidecar_md5)
                        ),
                    ));
                } else {
                    report.remote_files_verified += 1;
                    report.remote_bytes_verified += candidate.total_bytes;
                }
            }
            Err(e) => {
                report.issues.push(IntegrityIssue::error(
                    "REMOTE_FILE_READ_FAILED",
                    None,
                    format!(
                        "Remote '{}' failed to read object {} for on-disk MD5 verification: {}",
                        remote_name, candidate.filename, e
                    ),
                ));
            }
        }
    }
}

/// Verifies that objects on a remote store match the authenticated sizes and MD5 digests in the summary manifest.
///
/// When `options.verify_data` is true, each sampled object is downloaded and read in full to compute and verify
/// the on-disk MD5 digest against the manifest and sidecar file (intended for local-dir remotes like NAS shares).
pub fn check_remote_integrity(
    remote: &dyn crate::remote::RemoteStore,
    remote_name: &str,
    manifest: &crate::log::LogManifest,
    options: &CheckOptions,
    progress: Option<&mut dyn FnMut(u64, u64)>,
) -> IntegrityReport {
    let mut report = IntegrityReport::default();
    report.remotes_checked.push(remote_name.to_string());

    // Batch-list all objects from the remote store to compare sizes and ETags (MD5)
    // in O(1) listing requests rather than dispatching individual head_object requests per log.
    let listed_objects: BTreeMap<String, crate::remote::RemoteObject> = match remote.list_objects("") {
        Ok(objs) => objs.into_iter().map(|o| (o.key.clone(), o)).collect(),
        Err(e) => {
            report.issues.push(IntegrityIssue::error(
                "REMOTE_LIST_FAILED",
                None,
                format!("Failed to list objects on remote '{}': {}", remote_name, e),
            ));
            return report;
        }
    };

    let mut candidates: Vec<RemoteFileCandidate> = Vec::new();

    for log_entry in &manifest.logs {
        let expected_md5 = log_entry.md5;

        match listed_objects.get(&log_entry.filename) {
            Some(remote_obj) => {
                if remote_obj.size != log_entry.total_bytes {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_SIZE_MISMATCH",
                        None,
                        format!(
                            "Remote '{}' object {} size mismatch: expected {} bytes, found {}",
                            remote_name, log_entry.filename, log_entry.total_bytes, remote_obj.size
                        ),
                    ));
                }
                let sidecar_md5 = remote_obj.etag_md5();
                match sidecar_md5 {
                    Some(remote_md5) => {
                        if remote_md5 != expected_md5 {
                            report.issues.push(IntegrityIssue::error(
                                "REMOTE_MD5_MISMATCH",
                                None,
                                format!(
                                    "Remote '{}' object {} MD5 mismatch: expected {}, got {}",
                                    remote_name,
                                    log_entry.filename,
                                    hex::encode(expected_md5),
                                    hex::encode(remote_md5)
                                ),
                            ));
                        }
                    }
                    None => {
                        report.issues.push(IntegrityIssue::warning(
                            "REMOTE_ETAG_UNPARSABLE",
                            None,
                            format!(
                                "Remote '{}' object {} has non-standard ETag: {:?}",
                                remote_name, log_entry.filename, remote_obj.etag
                            ),
                        ));
                    }
                }

                candidates.push(RemoteFileCandidate {
                    filename: log_entry.filename.clone(),
                    total_bytes: remote_obj.size,
                    expected_md5,
                    sidecar_md5,
                });
            }
            None => {
                report.issues.push(IntegrityIssue::error(
                    "REMOTE_OBJECT_MISSING",
                    None,
                    format!("Remote '{}' is missing object {}", remote_name, log_entry.filename),
                ));
            }
        }
    }

    // Also include any summary files discovered on the remote if they have valid sidecar MD5s
    for (name, obj) in &listed_objects {
        if name.ends_with(".summary")
            && !candidates.iter().any(|c| &c.filename == name)
            && let Some(md5) = obj.etag_md5()
        {
            candidates.push(RemoteFileCandidate {
                filename: name.clone(),
                total_bytes: obj.size,
                expected_md5: md5,
                sidecar_md5: Some(md5),
            });
        }
    }

    candidates.sort_by(|a, b| a.filename.cmp(&b.filename));

    if options.verify_data {
        verify_remote_sidecar_files_md5(remote, remote_name, &candidates, options, &mut report, progress);
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::extent_map::ExtentMap;
    use crate::log::LogWriter;
    use crate::node::{InodeMeta, Node, NodeKind};
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use std::sync::Arc;

    #[test]
    fn test_clean_filesystem_integrity_passes() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        // Create dir, file, symlink, hardlink
        let d = fs.make_dir(1, "mydir", 0o755).unwrap();
        let f = fs.create_file(d, "file.txt", 0o644).unwrap();
        fs.write_at(f, b"hello integrity checker", 0).unwrap();
        let _s = fs.make_symlink(1, "link_to_file", "mydir/file.txt").unwrap();
        fs.hard_link(f, 1, "hardlink.txt").unwrap();

        fs.quiesce().unwrap();

        let report = check_volume(
            storage,
            &CheckOptions::full_data(),
            VolumeKey::plaintext_arc(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.orphaned_inodes.len(), 0);
        assert_eq!(report.directories, 2); // root + mydir
        assert_eq!(report.regular_files, 1);
        assert_eq!(report.symlinks, 1);
        assert_eq!(report.sampled_records, 1);
    }

    /// Asserts progress never goes backwards, always reports `expected_total`, and ends complete.
    fn assert_progress_completes(calls: &[(u64, u64)], expected_total: u64) {
        assert!(!calls.is_empty(), "Progress must be reported");
        assert!(
            calls.windows(2).all(|w| w[0].0 <= w[1].0),
            "Progress must not go backwards: {:?}",
            calls
        );
        assert!(calls.iter().all(|&(_, total)| total == expected_total), "{:?}", calls);
        assert_eq!(calls.last().unwrap().0, expected_total);
    }

    #[test]
    fn test_local_data_verification_reports_progress() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        for i in 0..3 {
            let f = fs.create_file(1, &format!("f{}", i), 0o644).unwrap();
            fs.write_at(f, &vec![b'x'; 1000 * (i + 1)], 0).unwrap();
        }
        fs.quiesce().unwrap();

        let mut calls = Vec::new();
        let report = check_fs_integrity(
            &fs,
            None,
            &CheckOptions::full_data(),
            None,
            Some(&mut |done, total| calls.push((done, total))),
        );
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.sampled_records, 3);
        assert_progress_completes(&calls, report.sampled_data_bytes);
    }

    #[test]
    fn test_orphan_inode_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        // Inject an orphan inode 999 not linked into directory tree
        let orphan_ino = 999;
        let orphan_node = Node {
            meta: InodeMeta::new(0o644, 0, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: ExtentMap::new(),
                size: 0,
            },
        };
        fs.inner
            .lock_for_tests()
            .unwrap()
            .base
            .insert(orphan_ino, Arc::new(orphan_node));

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        assert_eq!(report.orphaned_inodes, vec![999]);
        let orphan_issue = report.issues.iter().find(|i| i.code == "ORPHAN_INODE").unwrap();
        assert_eq!(orphan_issue.inode, Some(999));
    }

    #[test]
    fn test_nlink_mismatch_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let mut fs = TestFs::builder().storage(storage.clone()).build().fs;
        fs.set_storage(storage);

        let f = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.quiesce().unwrap();

        // Corrupt nlink on test.txt in base (set nlink to 5 instead of 1)
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f).unwrap();
            let mut node = (**node_arc).clone();
            node.meta.nlink = 5;
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "NLINK_MISMATCH").unwrap();
        assert_eq!(issue.inode, Some(f));
    }

    #[test]
    fn test_extent_past_eof_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Inject file with extent beyond its size
        let mut rm = crate::extent_map::ExtentMap::new();
        rm.insert(100, crate::extent_map::Extent::new_staged_buffer(vec![0; 50], 0, 50));
        let bad_file = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: rm,
                size: 120, // Extent ends at 150 > size 120!
            },
        };
        fs.inner.lock_for_tests().unwrap().base.insert(2, Arc::new(bad_file));
        // Link to root
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("bad.txt".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "EXTENT_PAST_EOF").unwrap();
        assert_eq!(issue.inode, Some(2));
    }

    #[test]
    fn test_extent_past_manifest_eof_zero_io_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let f = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.write_at(f, b"small payload", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Inject extent pointing past manifest total_bytes in log generation 1
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f).unwrap();
            let mut node = (**node_arc).clone();
            if let NodeKind::File { extent_map, size } = &mut node.kind {
                *size = 50_000_000;
                extent_map.insert(
                    0,
                    crate::extent_map::Extent::new_disk(
                        1,
                        999_999_999, // way past manifest total_bytes!
                        4096,
                        0,
                        4096,
                    ),
                );
            }
            *node_arc = Arc::new(node);
        }

        // Even with verify_data = false (pure metadata check), must catch EXTENT_PAST_MANIFEST_EOF
        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "EXTENT_PAST_MANIFEST_EOF");
        assert!(
            issue.is_some(),
            "Must report EXTENT_PAST_MANIFEST_EOF: {:?}",
            report.issues
        );
    }

    #[test]
    fn test_extent_invalid_record_size_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let mut fs = TestFs::builder().storage(storage.clone()).build().fs;
        fs.set_storage(storage);

        let f = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.write_at(f, b"small payload", 0).unwrap();
        fs.quiesce().unwrap();

        // Inject extent with record_size smaller than RECORD_HEADER_SIZE (32 bytes)
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f).unwrap();
            let mut node = (**node_arc).clone();
            if let NodeKind::File { extent_map, .. } = &mut node.kind {
                extent_map.insert(
                    0,
                    crate::extent_map::Extent::new_disk(
                        1, 128, 10, // record_size 10 < RECORD_HEADER_SIZE 32!
                        0, 10,
                    ),
                );
            }
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "EXTENT_INVALID_RECORD_SIZE"));

        // Must not panic when verify_data is enabled!
        let full_report = check_fs_integrity(&fs, None, &CheckOptions::full_data(), None, None);
        assert!(!full_report.is_clean());
        assert!(
            full_report
                .issues
                .iter()
                .any(|i| i.code == "EXTENT_INVALID_RECORD_SIZE")
        );
    }

    #[test]
    fn test_extent_zero_record_size_does_not_panic() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let mut fs = TestFs::builder().storage(storage.clone()).build().fs;
        fs.set_storage(storage);

        let f = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.write_at(f, b"small payload", 0).unwrap();
        fs.quiesce().unwrap();

        // Inject extent with record_size 0 at record_log_offset 0 (which previously caused underflow in planner)
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f).unwrap();
            let mut node = (**node_arc).clone();
            if let NodeKind::File { extent_map, .. } = &mut node.kind {
                extent_map.insert(0, crate::extent_map::Extent::new_disk(1, 0, 0, 0, 10));
            }
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::full_data(), None, None);
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "EXTENT_INVALID_RECORD_SIZE" || i.code == "ZERO_LEN_EXTENT")
        );
    }

    #[test]
    fn test_directory_cycle_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Create cycle: /a (ino 2) -> /a/b (ino 3) -> /a/b/a (ino 2)
        let dir_a = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("b".to_string(), 3)],
            },
        };
        let dir_b = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 2,
                entries: vec![("cycle_to_a".to_string(), 2)],
            },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(2, Arc::new(dir_a));
            inner.base.insert(3, Arc::new(dir_b));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("a".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        let cycle_issue = report.issues.iter().find(|i| i.code == "DIR_CYCLE");
        assert!(cycle_issue.is_some(), "Must report DIR_CYCLE: {:?}", report.issues);
    }

    #[test]
    fn test_dangling_entry_and_invalid_parent_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // 1. Root contains dangling entry to ino 404
        // 2. Dir 2 has parent field 999 instead of 1
        let dir_wrong_parent = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 999, // Mismatched parent!
                entries: vec![],
            },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(2, Arc::new(dir_wrong_parent));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("dangling".to_string(), 404));
                entries.push(("wrong_parent_dir".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "DANGLING_ENTRY"));
        assert!(report.issues.iter().any(|i| i.code == "INVALID_PARENT"));
    }

    #[test]
    fn test_corrupt_log_record_checksum_detected() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let f = fs.create_file(1, "data.txt", 0o644).unwrap();
        fs.write_at(f, b"original clean payload bytes", 0).unwrap();
        fs.quiesce().unwrap();

        // 1. Initial check must be clean
        let record_offset = {
            let inner = fs.inner.lock_for_tests().unwrap();
            let base = &inner.base;
            let node_arc = base.get(&f).unwrap();
            let node = node_arc.as_ref();
            if let NodeKind::File { extent_map, .. } = &node.kind {
                let entry = extent_map.iter().next().unwrap().1;
                if let ExtentState::Disk { record_log_offset, .. } = &entry.extent {
                    *record_log_offset
                } else {
                    panic!("Expected Disk extent");
                }
            } else {
                panic!("Expected File node");
            }
        };

        // 2. Corrupt a byte in 000001.log inside the Write record payload
        let mut bytes = storage.get_file_bytes("000001.log").unwrap();
        bytes[record_offset as usize + RECORD_HEADER_SIZE + 1] ^= 0xFF;
        storage.insert_file("000001.log", bytes);

        // 3. Re-check: must catch CORRUPT_LOG_RECORD
        let corrupt_report = check_fs_integrity(&fs, None, &CheckOptions::full_data(), None, None);
        assert!(!corrupt_report.is_clean());
        assert!(corrupt_report.issues.iter().any(|i| i.code == "CORRUPT_LOG_RECORD"));
    }

    #[test]
    fn test_directory_entry_name_too_long_detected() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Inject a directory entry exceeding 255 bytes into root node in base
        let long_name = "x".repeat(256);
        let mut root_node = (*fs.inner.lock_for_tests().unwrap().base.get(&1).unwrap())
            .as_ref()
            .clone();
        if let NodeKind::Directory { entries, .. } = &mut root_node.kind {
            entries.push((long_name, 2));
        }
        let child_node = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: ExtentMap::new(),
                size: 0,
            },
        };
        let mut inner = fs.inner.lock_for_tests().unwrap();
        inner.base.insert(1, Arc::new(root_node));
        inner.base.insert(2, Arc::new(child_node));
        drop(inner);

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only(), None, None);
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "NAME_TOO_LONG"));
    }

    #[test]
    fn test_sampled_verification_fractional_percentage() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        // Create 8 files of ~300 KiB each so data spans across ~3 distinct 1 MiB blocks
        for i in 0..8 {
            let name = format!("file_{}.txt", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            let payload = vec![(i as u8) + 1; 300_000];
            fs.write_at(f, &payload, 0).unwrap();
        }
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // 1. Sample at fractional percentage 0.05% with fixed seed (selects 1 block out of 3)
        let opts = CheckOptions::sampled(0.05, Some(42));
        let plan = plan_sampled_verification(&fs, &opts);
        let blocks = plan.local_blocks.get(&1).unwrap();
        assert!(!blocks.is_empty(), "Should sample at least 1 block");
        assert!(blocks.len() < 3, "Should sample a subset of blocks");

        let report = check_fs_integrity(&fs, None, &opts, None, None);
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.sampled_records, plan.sampled_records.len());
        assert_eq!(report.sample_percent, Some(0.05));
    }

    #[test]
    fn test_all_extents_in_fetched_block_are_verified() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        // In Block 0, create 4 small files (~10 KiB each)
        for i in 0..4 {
            let name = format!("blk0_file_{}.txt", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            fs.write_at(f, &vec![b'A' + i; 10_000], 0).unwrap();
        }
        // Write a 1.5 MiB file to advance into block 1 and block 2
        let filler = fs.create_file(1, "filler.bin", 0o644).unwrap();
        fs.write_at(filler, &vec![b'X'; 1_500_000], 0).unwrap();

        // In block 2, create 3 small files
        for i in 0..3 {
            let name = format!("blk2_file_{}.txt", i);
            let f = fs.create_file(1, &name, 0o644).unwrap();
            fs.write_at(f, &vec![b'B' + i; 10_000], 0).unwrap();
        }
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Sample 1 block (30% of 3 blocks = 1 block). With seed 42, find which block was sampled.
        let opts = CheckOptions::sampled(30.0, Some(42));
        let plan = plan_sampled_verification(&fs, &opts);
        let blocks = plan.local_blocks.get(&1).unwrap();
        assert!(!blocks.is_empty());

        // All live records whose required blocks were fetched must be in plan.sampled_records!
        assert!(!plan.sampled_records.is_empty());
        for rec in &plan.sampled_records {
            let start = rec.record_log_offset / crate::remote::block_cache::BLOCK_SIZE;
            let end = (rec.record_log_offset + rec.record_size as u64 - 1) / crate::remote::block_cache::BLOCK_SIZE;
            for b in start..=end {
                assert!(blocks.contains(&b), "Record block {} must be in fetched blocks", b);
            }
        }

        let report = check_fs_integrity(&fs, None, &opts, None, None);
        assert!(report.is_clean());
        assert_eq!(report.sampled_records, plan.sampled_records.len());
    }

    #[test]
    fn test_multi_block_boundary_expansion() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Manually inject a file whose extent record crosses from block 0 into block 1:
        // offset 1_048_500, record_size = 200 => end_offset = 1_048_699 (crosses 1_048_576)
        let f_ino = 2;
        let mut extent_map = ExtentMap::new();
        extent_map.insert(0, crate::extent_map::Extent::new_disk(1, 1_048_500, 200, 0, 100));
        let file_node = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File { extent_map, size: 100 },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(f_ino, Arc::new(file_node));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("spanning.bin".to_string(), f_ino));
            }
            *root_arc = Arc::new(root);
        }

        let opts = CheckOptions::full_data();
        let plan = plan_sampled_verification(&fs, &opts);
        assert_eq!(plan.sampled_records.len(), 1);
        let blocks = plan.local_blocks.get(&1).unwrap();
        // Record at 1_048_500 spanning 200 bytes must require both block 0 and block 1!
        assert!(blocks.contains(&0), "Must require block 0");
        assert!(blocks.contains(&1), "Must require block 1 (boundary expansion)");
    }

    #[test]
    fn test_sampled_verification_remote_stores_and_corruption() {
        use crate::remote::mock::MockRemoteStore;
        use crate::remote::{RemoteMode, RemoteRegistry, RemoteStore, RemoteTargetConfig};

        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let f = fs.create_file(1, "cloud_file.txt", 0o644).unwrap();
        fs.write_at(f, b"cloud data content verification", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Set up two mock remotes: "backup1" and "backup2"
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        // Replicate 000001.log and summary to remotes
        let log_bytes = storage.get_file_bytes("000001.log").unwrap();
        remote1
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(log_bytes.clone()),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();
        remote2
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(log_bytes.clone()),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();

        let mut registry = RemoteRegistry::default();
        let mut cfg1 = RemoteTargetConfig::new("backup1");
        cfg1.mode = RemoteMode::ReadWrite;
        registry.add_remote("backup1", cfg1);
        registry.set_store_override("backup1", remote1.clone());

        let mut cfg2 = RemoteTargetConfig::new("backup2");
        cfg2.mode = RemoteMode::ReadWrite;
        registry.add_remote("backup2", cfg2);
        registry.set_store_override("backup2", remote2.clone());

        fs.set_remote_registry(Arc::new(std::sync::RwLock::new(registry)));

        // 1. Verification across remotes must pass initially
        let opts = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["backup1".to_string(), "backup2".to_string()],
            seed: Some(123),
        };
        let mut calls = Vec::new();
        let clean_report = check_fs_integrity(&fs, None, &opts, None, Some(&mut |d, t| calls.push((d, t))));
        assert!(clean_report.is_clean(), "Must be clean: {:?}", clean_report.issues);
        assert!(clean_report.sampled_records > 0);
        // A single 1 MiB block covers the whole log, so progress counts the whole file fetched.
        assert_progress_completes(&calls, log_bytes.len() as u64);

        // 2. Corrupt a byte in 000001.log on backup1
        let mut corrupted_log = log_bytes.clone();
        let rec_offset = FILE_HEADER_SIZE + RECORD_HEADER_SIZE + 2;
        corrupted_log[rec_offset] ^= 0xFF;
        remote1
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(corrupted_log),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();

        // 3. Verifying against backup1 must detect corruption with remote name
        let opts1 = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["backup1".to_string()],
            seed: Some(123),
        };
        let corrupt_report = check_fs_integrity(&fs, None, &opts1, None, None);
        assert!(!corrupt_report.is_clean());
        let issue = corrupt_report
            .issues
            .iter()
            .find(|i| i.code == "CORRUPT_LOG_RECORD")
            .unwrap();
        assert!(
            issue.message.contains("backup1"),
            "Issue message must mention corrupted remote: {}",
            issue.message
        );
    }

    #[test]
    fn test_sampled_verification_distributes_evenly_across_remotes_and_local() {
        use crate::remote::mock::MockRemoteStore;
        use crate::remote::{RemoteRegistry, RemoteTargetConfig};

        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        // 100 files of 300 KB each: ~29 blocks, with records straddling most block boundaries.
        for i in 0..100 {
            let f = fs.create_file(1, &format!("dist_{}.txt", i), 0o644).unwrap();
            fs.write_at(f, &vec![0xAA; 300_000], 0).unwrap();
        }
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        let mut registry = RemoteRegistry::default();
        registry.add_remote("r1", RemoteTargetConfig::new("r1"));
        registry.add_remote("r2", RemoteTargetConfig::new("r2"));
        registry.set_store_override("r1", Arc::new(MockRemoteStore::new()));
        registry.set_store_override("r2", Arc::new(MockRemoteStore::new()));
        fs.set_remote_registry(Arc::new(std::sync::RwLock::new(registry)));

        let empty = BTreeSet::new();
        for (remotes, a, b) in [
            (["r1", "r2"], Some("r1"), Some("r2")),
            (["local", "r1"], None, Some("r1")),
        ] {
            let blocks_of = |plan: &VerificationPlan, target: Option<&str>| -> BTreeSet<u64> {
                match target {
                    None => plan.local_blocks.get(&1).unwrap_or(&empty).clone(),
                    Some(name) => plan
                        .remote_blocks
                        .get(name)
                        .and_then(|m| m.get(&1))
                        .unwrap_or(&empty)
                        .clone(),
                }
            };

            let mut first_block_owners = BTreeSet::new();
            for seed in 0..16 {
                let opts = CheckOptions {
                    verify_data: true,
                    sample_percent: 100.0,
                    remotes: remotes.iter().map(|r| r.to_string()).collect(),
                    seed: Some(seed),
                };
                let plan = plan_sampled_verification(&fs, &opts);
                assert_eq!(
                    plan.sampled_records.len(),
                    plan.total_live_records,
                    "100% verification must cover every live record ({:?}, seed {})",
                    remotes,
                    seed
                );

                let (blocks_a, blocks_b) = (blocks_of(&plan, a), blocks_of(&plan, b));
                let unique = blocks_a.union(&blocks_b).count();
                let total = blocks_a.len() + blocks_b.len();
                // Each target reads one contiguous range (wrapping around the end of the volume),
                // so at most one shared block per range edge is read twice.
                assert!(
                    total - unique <= 2,
                    "{:?} seed {}: {} blocks read for {} unique",
                    remotes,
                    seed,
                    total,
                    unique
                );
                for blocks in [&blocks_a, &blocks_b] {
                    assert!(
                        blocks.len() * 3 >= unique,
                        "{:?} seed {}: unbalanced split {:?} / {:?}",
                        remotes,
                        seed,
                        blocks_a,
                        blocks_b
                    );
                }
                first_block_owners.insert(if blocks_a.contains(&0) { a } else { b });
            }
            assert_eq!(
                first_block_owners.len(),
                2,
                "{:?}: the seed must vary which target reads the start of the log",
                remotes
            );
        }
    }

    #[test]
    fn test_sampled_verification_random_seed_coverage_accumulation() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        // Create 20 files of 1 MiB each across 20 distinct blocks
        let chunk = vec![0x42u8; 1024 * 1024];
        for i in 1..=20 {
            let file = fs.create_file(1, &format!("file_{}.dat", i), 0o644).unwrap();
            fs.write_at(file, &chunk, 0).unwrap();
        }
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Sample with 5% (1 block out of 20) with random seed (seed: None)
        let mut cumulative_blocks: HashSet<u64> = HashSet::new();
        for _ in 0..30 {
            let opts = CheckOptions::sampled(5.0, None);
            let plan = plan_sampled_verification(&fs, &opts);
            if let Some(blocks) = plan.local_blocks.get(&1) {
                cumulative_blocks.extend(blocks);
            }
        }
        // With 30 trials picking 1 block out of 20 uniformly at random,
        // the probability of picking >= 5 distinct blocks is overwhelmingly high (> 1 - 10^-10).
        assert!(
            cumulative_blocks.len() >= 5,
            "Multiple runs with default random seed must accumulate coverage (found {} blocks)",
            cumulative_blocks.len()
        );
    }

    #[test]
    fn test_write_only_remote_rejected_for_data_verification() {
        use crate::remote::{RemoteMode, RemoteRegistry, RemoteTargetConfig};

        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let file = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.write_at(file, b"hello world data", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        let glacier_store = Arc::new(crate::remote::MockRemoteStore::new());
        let mut registry = RemoteRegistry::new();
        let mut glacier_cfg = RemoteTargetConfig::new("glacier-bucket");
        glacier_cfg.mode = RemoteMode::WriteOnly;
        registry.add_remote("glacier", glacier_cfg);
        registry.set_store_override("glacier", glacier_store);
        fs.set_remote_registry(Arc::new(std::sync::RwLock::new(registry)));

        // 1. Requesting a write-only remote for data verification is reported, and must not fall
        // back to verifying local storage instead.
        let opts = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["glacier".to_string()],
            seed: Some(42),
        };
        let plan = plan_sampled_verification(&fs, &opts);
        assert_eq!(plan.total_blocks(), 0, "Nothing may be verified in place of 'glacier'");
        assert!(plan.sampled_records.is_empty());
        assert_eq!(plan.write_only_remotes, vec!["glacier".to_string()]);
        let report = check_fs_integrity(&fs, None, &opts, None, None);
        assert!(
            report.issues.iter().any(|i| i.code == "REMOTE_WRITE_ONLY"),
            "Must contain REMOTE_WRITE_ONLY error, found: {:?}",
            report.issues
        );
        assert!(!report.is_clean());

        // `all` with only write-only remotes configured is reported the same way.
        let opts_all_write_only = CheckOptions {
            remotes: vec!["all".to_string()],
            ..opts.clone()
        };
        let plan = plan_sampled_verification(&fs, &opts_all_write_only);
        assert_eq!(plan.total_blocks(), 0);
        assert_eq!(plan.write_only_remotes, vec!["glacier".to_string()]);

        // 2. Metadata-only verification of write-only remote succeeds (checking manifest against bucket)
        let opts_meta = CheckOptions {
            verify_data: false,
            sample_percent: 100.0,
            remotes: vec!["glacier".to_string()],
            seed: None,
        };
        let report_meta = check_fs_integrity(&fs, None, &opts_meta, None, None);
        assert!(report_meta.is_clean());

        // 3. --remotes all with verify_data filters out write-only remotes from sampling targets
        let s3_store = Arc::new(crate::remote::MockRemoteStore::new());
        let mut s3_cfg = RemoteTargetConfig::new("s3-bucket");
        s3_cfg.mode = RemoteMode::ReadWrite;
        {
            let reg_opt = fs.remote_registry.read().unwrap();
            let mut reg = reg_opt.as_ref().unwrap().write().unwrap();
            reg.add_remote("s3", s3_cfg);
            reg.set_store_override("s3", s3_store);
        }

        let opts_all = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["all".to_string()],
            seed: Some(42),
        };
        let plan_all = plan_sampled_verification(&fs, &opts_all);
        assert!(
            plan_all.remote_blocks.contains_key("s3"),
            "Readable remote 's3' must be sampled"
        );
        assert!(
            !plan_all.remote_blocks.contains_key("glacier"),
            "Write-only remote 'glacier' must NOT be sampled"
        );
        assert!(
            plan_all.write_only_remotes.is_empty(),
            "`all` skips write-only remotes silently while a readable remote remains"
        );
    }

    #[test]
    fn test_local_dir_remote_md5_verification_catches_bitrot() {
        use crate::remote::{LocalDirRemoteStore, RemoteStore};

        let temp_dir = tempfile::tempdir().unwrap();
        let local_remote = Arc::new(LocalDirRemoteStore::new(temp_dir.path()));

        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let fs = TestFs::builder().storage(storage.clone()).build().fs;

        let file = fs.create_file(1, "test.txt", 0o644).unwrap();
        fs.write_at(file, b"crucial data that must not rot", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        let manifest = fs.manifest.read().unwrap().clone();
        assert!(!manifest.logs.is_empty(), "Manifest should have sealed 000001.log");

        // Replicate 000001.log to the local remote
        let reader = storage.open_reader("000001.log").unwrap();
        let log_data = reader.read_vec(0, reader.len().unwrap() as usize).unwrap();
        local_remote
            .put_object(
                "000001.log",
                &mut &log_data[..],
                log_data.len() as u64,
                Some(&manifest.logs[0].md5),
            )
            .unwrap();

        // 1. Clean verification: both metadata-only and verify_data pass
        let meta_report = check_remote_integrity(
            local_remote.as_ref(),
            "nas",
            &manifest,
            &CheckOptions::metadata_only(),
            None,
        );
        assert!(meta_report.is_clean(), "Metadata check must pass on clean replica");

        let mut calls = Vec::new();
        let data_report = check_remote_integrity(
            local_remote.as_ref(),
            "nas",
            &manifest,
            &CheckOptions::full_data(),
            Some(&mut |d, t| calls.push((d, t))),
        );
        assert!(
            data_report.is_clean(),
            "Data check must pass on clean replica: {:?}",
            data_report.issues
        );
        assert_eq!(data_report.remote_files_verified, 1);
        assert_eq!(data_report.remote_bytes_verified, log_data.len() as u64);
        assert_progress_completes(&calls, log_data.len() as u64);

        // 2. Simulate bit rot: corrupt a byte in 000001.log on disk, but leave 000001.log.md5 intact
        let file_path = temp_dir.path().join("000001.log");
        let mut on_disk_bytes = std::fs::read(&file_path).unwrap();
        on_disk_bytes[50] ^= 0xFF; // Flip bits in payload
        std::fs::write(&file_path, &on_disk_bytes).unwrap();

        // Metadata check reads .md5 sidecar, so it PASSES (the blind spot)
        let blind_spot_report = check_remote_integrity(
            local_remote.as_ref(),
            "nas",
            &manifest,
            &CheckOptions::metadata_only(),
            None,
        );
        assert!(
            blind_spot_report.is_clean(),
            "Metadata-only check misses on-disk bit rot because .md5 sidecar matches manifest"
        );

        // Data verification hashes the actual file on disk, so it FAILS with REMOTE_FILE_MD5_MISMATCH
        let detected_report = check_remote_integrity(
            local_remote.as_ref(),
            "nas",
            &manifest,
            &CheckOptions::full_data(),
            None,
        );
        assert!(
            !detected_report.is_clean(),
            "Data verification must detect on-disk bit rot"
        );
        assert!(
            detected_report
                .issues
                .iter()
                .any(|i| i.code == "REMOTE_FILE_MD5_MISMATCH"),
            "Expected REMOTE_FILE_MD5_MISMATCH, found: {:?}",
            detected_report.issues
        );

        // Formatted report reflects failure under Remote Stores
        let formatted = detected_report.format_report(None, false);
        assert!(formatted.contains("[FAIL] Remote Stores"));
    }

    #[test]
    fn test_local_dir_remote_md5_sampling_percentages() {
        use crate::remote::{LocalDirRemoteStore, RemoteStore};

        let temp_dir = tempfile::tempdir().unwrap();
        let local_remote = Arc::new(LocalDirRemoteStore::new(temp_dir.path()));

        // Create 4 log files with different sizes
        let mut manifest = crate::log::LogManifest::new();
        let mut total_bytes = 0u64;

        for i in 1..=4 {
            let filename = format!("{:06}.log", i);
            let size = i as u64 * 10_000;
            total_bytes += size;
            let data = vec![(i as u8) + 64; size as usize];
            let mut hasher = md5::Context::new();
            hasher.consume(&data);
            let md5 = hasher.compute().0;

            local_remote
                .put_object(&filename, &mut &data[..], size, Some(&md5))
                .unwrap();

            let log_info = crate::log::LogFileInfo {
                version: 1,
                generation: i,
                revision: 0,
                filename,
                created_at: std::time::SystemTime::UNIX_EPOCH,
                record_count: 10,
                total_bytes: size,
                total_data_bytes: size,
                md5,
                sealed_at: Some(std::time::SystemTime::UNIX_EPOCH),
            };
            manifest.record_sealed_log(log_info);
        }

        // 1. 100% data verification samples all 4 files
        let opts_100 = CheckOptions::full_data();
        let report_100 = check_remote_integrity(local_remote.as_ref(), "local-dir", &manifest, &opts_100, None);
        assert!(report_100.is_clean());
        assert_eq!(report_100.remote_files_verified, 4);
        assert_eq!(report_100.remote_bytes_verified, total_bytes);

        // 2. 25% data verification with seed samples a subset and is deterministically reproducible
        let opts_25 = CheckOptions::sampled(25.0, Some(42));
        let report_25 = check_remote_integrity(local_remote.as_ref(), "local-dir", &manifest, &opts_25, None);
        assert!(report_25.is_clean());
        assert!(report_25.remote_files_verified >= 1);
        assert!(report_25.remote_files_verified < 4);
        assert!(report_25.remote_bytes_verified >= total_bytes / 4);

        let report_25_repeat = check_remote_integrity(local_remote.as_ref(), "local-dir", &manifest, &opts_25, None);
        assert_eq!(report_25.remote_files_verified, report_25_repeat.remote_files_verified);
        assert_eq!(report_25.remote_bytes_verified, report_25_repeat.remote_bytes_verified);

        // 3. Output formatting includes verified on-disk MD5 stats
        let formatted = report_100.format_report(None, false);
        assert!(
            formatted.contains("verified on-disk MD5 for 4 files"),
            "Formatted report must contain remote on-disk stats: {}",
            formatted
        );
    }

    #[test]
    fn test_volume_wide_block_sampling_across_generations() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let mut fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);

        // Populate 5 separate generations, each with 2 distinct files in separate blocks
        for g in 1..=5 {
            let writer = Arc::new(
                LogWriter::create(
                    storage.clone(),
                    g,
                    clock.clone(),
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    g as u64 * 1000,
                    VolumeKey::plaintext_arc(),
                )
                .unwrap(),
            );
            fs.log_writer = Some(writer);
            fs.set_storage(storage.clone());

            let f1 = fs.create_file(1, &format!("gen{}_f1.bin", g), 0o644).unwrap();
            fs.write_at(f1, &vec![g as u8; 100_000], 0).unwrap();

            let f2 = fs.create_file(1, &format!("gen{}_f2.bin", g), 0o644).unwrap();
            // Advance offset into block 1 (> 1 MiB)
            fs.write_at(f2, &vec![g as u8 + 10; 1_200_000], 0).unwrap();

            fs.quiesce().unwrap();
            let file_len = storage.file_len(&crate::log::log_filename(g)).unwrap();
            let log_info = crate::log::LogFileInfo {
                version: 1,
                generation: g,
                revision: 0,
                filename: crate::log::log_filename(g),
                created_at: std::time::SystemTime::UNIX_EPOCH,
                record_count: 2,
                total_bytes: file_len,
                total_data_bytes: file_len,
                md5: [0u8; 16],
                sealed_at: Some(std::time::SystemTime::UNIX_EPOCH),
            };
            fs.manifest.write().unwrap().record_sealed_log(log_info);
            fs.log_writer = None;
        }
        fs.export_summary(storage.as_ref()).unwrap();

        // 10% sampling across volume: with 5 generations having 2 blocks each (10 blocks total),
        // volume-wide sampling should pick ~1-2 blocks (10% of 10 is 1), NOT 1 block per generation (5 blocks)!
        let opts = CheckOptions::sampled(10.0, Some(42));
        let plan = plan_sampled_verification(&fs, &opts);
        let total_sampled_blocks = plan.total_blocks();
        assert!(
            total_sampled_blocks <= 2,
            "10% sample of 10 blocks should fetch 1-2 blocks, fetched: {}",
            total_sampled_blocks
        );

        let report = check_fs_integrity(&fs, None, &opts, Some(&plan), None);
        assert!(report.is_clean(), "issues: {:?}", report.issues);
        assert_eq!(report.sampled_blocks, total_sampled_blocks);
    }
}
