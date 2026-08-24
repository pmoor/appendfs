use crate::fs::InMemoryFS;
use crate::log::LogFileCache;
use crate::log::extent::ExtentState;
use crate::log::record::{OpCode, RECORD_HEADER_SIZE, RecordHeader, checksum_payload};
use crate::node::NodeKind;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

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

/// Aggregated report produced by the filesystem integrity check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub branch: String,
    pub total_inodes: usize,
    pub directories: usize,
    pub regular_files: usize,
    pub symlinks: usize,
    pub total_extents: usize,
    pub total_data_bytes: u64,
    pub orphaned_inodes: Vec<u64>,
    pub issues: Vec<IntegrityIssue>,
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

    /// Formats the report as a clean, human-readable terminal output.
    pub fn format_report(&self, log_dir: Option<&Path>, verbose: bool) -> String {
        let mut out = String::new();
        out.push_str("=================================================================\n");
        out.push_str("               AppendFS Filesystem Integrity Check               \n");
        out.push_str("=================================================================\n\n");

        if let Some(dir) = log_dir {
            out.push_str(&format!("  Log Directory:     {}\n", dir.display()));
        }
        out.push_str(&format!("  Branch:            {}\n", self.branch));
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
            })
            .count();
        if extent_issues == 0 {
            out.push_str("  [PASS] File Extents & Log Record Consistency\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] File Extents ({} extent/data inconsistencies)\n",
                extent_issues
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

/// Runs a read-only filesystem integrity check on the provided `InMemoryFS`.
pub fn check_fs_integrity(fs: &InMemoryFS, log_dir: Option<&Path>, verify_data: bool) -> IntegrityReport {
    let mut report = IntegrityReport::default();

    // 0. Extract manifest and base snapshot
    let manifest = fs.manifest.read().unwrap().clone();
    report.branch = manifest.branch.clone();

    let base_map = fs.base.read().unwrap();
    report.total_inodes = base_map.len();

    for (&_ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        match &node.kind {
            NodeKind::Directory { .. } => report.directories += 1,
            NodeKind::File { range_map, size, .. } => {
                report.regular_files += 1;
                report.total_extents += range_map.len();
                report.total_data_bytes += *size;
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
                            let child_arc = match base_map.get(child_ino) {
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

                            *ref_counts.entry(*child_ino).or_default() += 1;

                            let child_node = child_arc.as_ref();
                            match &child_node.kind {
                                NodeKind::Directory { parent, .. } => {
                                    if *child_ino == 1 {
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

                                    if current_ancestors.contains(child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "DIR_CYCLE",
                                            Some(*child_ino),
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
                                            Some(*child_ino),
                                            format!(
                                                "Directory inode {} has parent field {}, but is contained in directory {}",
                                                child_ino, parent, curr_dir_ino
                                            ),
                                        ));
                                    }

                                    if reachable.contains(child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "MULTIPLE_DIR_HARDLINKS",
                                            Some(*child_ino),
                                            format!(
                                                "Directory inode {} has multiple directory entries pointing to it",
                                                child_ino
                                            ),
                                        ));
                                    }

                                    *subdirs_count.entry(curr_dir_ino).or_default() += 1;
                                    reachable.insert(*child_ino);

                                    let mut next_ancestors = current_ancestors.clone();
                                    next_ancestors.insert(*child_ino);
                                    queue.push_back((*child_ino, next_ancestors));
                                }
                                NodeKind::File { .. }
                                | NodeKind::Symlink { .. }
                                | NodeKind::Fifo
                                | NodeKind::CharDevice { .. }
                                | NodeKind::BlockDevice { .. }
                                | NodeKind::Socket => {
                                    reachable.insert(*child_ino);
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

    // Pass 3: File Extent & RangeMap Validation
    let active_generations: HashSet<u64> = manifest.logs.iter().map(|l| l.generation).collect();
    let cache = fs
        .log_cache
        .clone()
        .or_else(|| log_dir.map(|d| Arc::new(LogFileCache::new(d))));

    for (&ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        if let NodeKind::File { range_map, size, .. } = &node.kind {
            for (offset, entry) in range_map.iter() {
                let file_offset = *offset;
                let extent_len = entry.length;

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
                    payload_offset: _,
                    length: _,
                } = entry.value.read_state()
                {
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

                    if verify_data && let Some(ref c) = cache {
                        let log_filename = format!("{:06}.log", generation);
                        if !c.storage().exists(&log_filename) {
                            report.issues.push(IntegrityIssue::error(
                                    "MISSING_LOG_FILE",
                                    Some(ino),
                                    format!(
                                        "File inode {} extent references generation {} ('{}'), which does not exist in storage",
                                        ino, generation, log_filename
                                    ),
                                ));
                        } else if let Ok(file_len) = c.storage().file_len(&log_filename) {
                            // Only the header's position can be judged from the extent alone.
                            // `length` is the extent's *logical* size, which bears no fixed
                            // relation to the bytes on disk: encryption adds a tag, and
                            // compression can shrink a multi-megabyte extent to a few hundred
                            // bytes. Comparing `record_log_offset + length` against the file
                            // size therefore called every healthy compressed volume corrupt,
                            // and - because it gated the branch below - skipped the header and
                            // checksum verification that would have shown otherwise. The
                            // record's real extent is checked once `payload_len` is known.
                            if file_len < record_log_offset + RECORD_HEADER_SIZE as u64 {
                                report.issues.push(IntegrityIssue::error(
                                        "EXTENT_PAST_LOG_EOF",
                                        Some(ino),
                                        format!(
                                            "File inode {} extent references log generation {} at offset 0x{:x}, but file size is only {} bytes",
                                            ino, generation, record_log_offset, file_len
                                        ),
                                    ));
                            } else {
                                // Deep verification: Check record header & BLAKE3 checksum
                                match c.get_or_open(generation) {
                                    Ok(reader) => {
                                        let mut hdr_buf = [0u8; RECORD_HEADER_SIZE];
                                        if let Err(e) = reader.read_exact_at(record_log_offset, &mut hdr_buf) {
                                            report.issues.push(IntegrityIssue::error(
                                                "CORRUPT_LOG_RECORD",
                                                Some(ino),
                                                format!(
                                                    "Failed to read record header at offset 0x{:x} in {}: {}",
                                                    record_log_offset, log_filename, e
                                                ),
                                            ));
                                        } else {
                                            match RecordHeader::from_bytes(&hdr_buf) {
                                                Err(e) => {
                                                    report.issues.push(IntegrityIssue::error(
                                                        "CORRUPT_LOG_RECORD",
                                                        Some(ino),
                                                        format!(
                                                            "Invalid record header at offset 0x{:x} in {}: {}",
                                                            record_log_offset, log_filename, e
                                                        ),
                                                    ));
                                                }
                                                Ok(rec_header) => {
                                                    let opcode = rec_header.op_code as u8;
                                                    let rec_ino = rec_header.inode;
                                                    let payload_len = rec_header.payload_len as usize;
                                                    let stored_checksum = rec_header.checksum;

                                                    if opcode != OpCode::Data as u8 {
                                                        report.issues.push(IntegrityIssue::error(
                                                            "CORRUPT_LOG_RECORD",
                                                            Some(ino),
                                                            format!("Record at offset 0x{:x} in {} has OpCode {} instead of OpCode::Data", record_log_offset, log_filename, opcode),
                                                        ));
                                                    } else if rec_ino != ino {
                                                        report.issues.push(IntegrityIssue::error(
                                                            "CORRUPT_LOG_RECORD",
                                                            Some(ino),
                                                            format!("Record at offset 0x{:x} in {} belongs to inode {}, expected inode {}", record_log_offset, log_filename, rec_ino, ino),
                                                        ));
                                                    } else if file_len
                                                        < record_log_offset
                                                            + RECORD_HEADER_SIZE as u64
                                                            + payload_len as u64
                                                    {
                                                        report.issues.push(IntegrityIssue::error(
                                                            "EXTENT_PAST_LOG_EOF",
                                                            Some(ino),
                                                            format!(
                                                                "File inode {} record at offset 0x{:x} in {} declares a {} byte payload, which runs past the {} byte file",
                                                                ino, record_log_offset, log_filename, payload_len, file_len
                                                            ),
                                                        ));
                                                    } else {
                                                        let mut payload = vec![0u8; payload_len];
                                                        if let Err(e) = reader.read_exact_at(
                                                            record_log_offset + RECORD_HEADER_SIZE as u64,
                                                            &mut payload,
                                                        ) {
                                                            report.issues.push(IntegrityIssue::error(
                                                                "CORRUPT_LOG_RECORD",
                                                                Some(ino),
                                                                format!(
                                                                    "Failed to read payload at offset 0x{:x} in {}: {}",
                                                                    record_log_offset, log_filename, e
                                                                ),
                                                            ));
                                                        } else {
                                                            let computed = checksum_payload(&payload);
                                                            if computed[..] != stored_checksum {
                                                                report.issues.push(IntegrityIssue::error(
                                                                    "CORRUPT_LOG_RECORD",
                                                                    Some(ino),
                                                                    format!("BLAKE3 checksum mismatch for record at offset 0x{:x} in {}", record_log_offset, log_filename),
                                                                ));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        report.issues.push(IntegrityIssue::error(
                                            "LOG_FILE_READ_ERROR",
                                            Some(ino),
                                            format!("Failed to open log file {}: {}", log_filename, e),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Pass 4: Manifest & Physical File Consistency
    if manifest.branch.trim().is_empty() {
        report.issues.push(IntegrityIssue::error(
            "MANIFEST_EMPTY_BRANCH",
            None,
            "Manifest branch name is empty",
        ));
    }
    if manifest.next_generation == 0 {
        report.issues.push(IntegrityIssue::error(
            "MANIFEST_INVALID_NEXT_GEN",
            None,
            "Manifest next_generation cannot be 0",
        ));
    }

    for info in &manifest.logs {
        if info.generation >= manifest.next_generation {
            report.issues.push(IntegrityIssue::error(
                "MANIFEST_GEN_EXCEEDS_NEXT",
                None,
                format!(
                    "Log generation {} is >= manifest next_generation {}",
                    info.generation, manifest.next_generation
                ),
            ));
        }

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
    verify_data: bool,
    volume_key: Arc<crate::crypto::VolumeKey>,
) -> std::io::Result<IntegrityReport> {
    let fs = crate::log::recover_fs(
        storage,
        crate::log::RecoveryTarget::Latest,
        std::sync::Arc::new(crate::clock::SystemClock),
        volume_key,
    )?;
    Ok(check_fs_integrity(&fs, None, verify_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::log::{LogWriter, SharedExtentState};
    use crate::node::{InodeMeta, Node, NodeKind};
    use crate::range_map::RangeMap;
    use std::sync::Arc;

    #[test]
    fn test_clean_filesystem_integrity_passes() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
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

        // Create dir, file, symlink, hardlink
        let d = crate::operations::dir::mkdir_core(&fs, 1, "mydir", 0o755, 1000, 1000).unwrap();
        let f = crate::operations::read_write::create_core(&fs, d.ino, "file.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"hello integrity checker", 0).unwrap();
        let _s = crate::operations::links::symlink_core(&fs, 1, "link_to_file", "mydir/file.txt", 1000, 1000).unwrap();
        let _h = crate::operations::links::link_core(&fs, f.ino, 1, "hardlink.txt").unwrap();

        fs.sync_log().unwrap();

        let report = check_volume(storage, true, VolumeKey::plaintext_arc()).unwrap();
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.orphaned_inodes.len(), 0);
        assert_eq!(report.directories, 2); // root + mydir
        assert_eq!(report.regular_files, 1);
        assert_eq!(report.symlinks, 1);
    }

    #[test]
    fn test_orphan_inode_detection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
                range_map: RangeMap::new(),
                size: 0,
            },
        };
        fs.base.write().unwrap().insert(orphan_ino, Arc::new(orphan_node));

        let report = check_fs_integrity(&fs, Some(dir.path()), false);
        assert!(!report.is_clean());
        assert_eq!(report.orphaned_inodes, vec![999]);
        let orphan_issue = report.issues.iter().find(|i| i.code == "ORPHAN_INODE").unwrap();
        assert_eq!(orphan_issue.inode, Some(999));
    }

    #[test]
    fn test_nlink_mismatch_detection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(dir.path());

        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

        // Corrupt nlink on test.txt in base (set nlink to 5 instead of 1)
        {
            let mut base = fs.base.write().unwrap();
            let node_arc = base.get_mut(&f.ino).unwrap();
            let mut node = (**node_arc).clone();
            node.meta.nlink = 5;
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, Some(dir.path()), false);
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "NLINK_MISMATCH").unwrap();
        assert_eq!(issue.inode, Some(f.ino));
    }

    #[test]
    fn test_extent_past_eof_detection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
        let mut rm = RangeMap::new();
        rm.insert(100, 50, SharedExtentState::new_staged(Arc::new(vec![0; 50]), 0, 50));
        let bad_file = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                range_map: rm,
                size: 120, // Extent ends at 150 > size 120!
            },
        };
        fs.base.write().unwrap().insert(2, Arc::new(bad_file));
        // Link to root
        {
            let mut base = fs.base.write().unwrap();
            let root_arc = base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("bad.txt".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, Some(dir.path()), false);
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "EXTENT_PAST_EOF").unwrap();
        assert_eq!(issue.inode, Some(2));
    }

    #[test]
    fn test_directory_cycle_detection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
            let mut base = fs.base.write().unwrap();
            base.insert(2, Arc::new(dir_a));
            base.insert(3, Arc::new(dir_b));
            let root_arc = base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("a".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, Some(dir.path()), false);
        assert!(!report.is_clean());
        let cycle_issue = report.issues.iter().find(|i| i.code == "DIR_CYCLE");
        assert!(cycle_issue.is_some(), "Must report DIR_CYCLE: {:?}", report.issues);
    }

    #[test]
    fn test_dangling_entry_and_invalid_parent_detection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        crate::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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
            let mut base = fs.base.write().unwrap();
            base.insert(2, Arc::new(dir_wrong_parent));
            let root_arc = base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("dangling".to_string(), 404));
                entries.push(("wrong_parent_dir".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, Some(dir.path()), false);
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "DANGLING_ENTRY"));
        assert!(report.issues.iter().any(|i| i.code == "INVALID_PARENT"));
    }

    #[test]
    fn test_corrupt_log_record_checksum_detected() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            Some("main"),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
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

        let f = crate::operations::read_write::create_core(&fs, 1, "data.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"original clean payload bytes", 0).unwrap();
        fs.sync_log().unwrap();

        // 1. Initial check must be clean
        let record_offset = {
            let base = fs.base.read().unwrap();
            let node_arc = base.get(&f.ino).unwrap();
            let node = node_arc.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                let entry = range_map.iter().next().unwrap().1;
                if let ExtentState::Disk { record_log_offset, .. } = entry.value.read_state() {
                    record_log_offset
                } else {
                    panic!("Expected Disk extent");
                }
            } else {
                panic!("Expected File node");
            }
        };

        // 2. Corrupt a byte in 000001.log inside the Write record payload
        let mut bytes = storage.get_file_bytes("000001.log").unwrap();
        bytes[(record_offset + 30) as usize] ^= 0xFF;
        storage.insert_file("000001.log", bytes);

        // 3. Re-check: must catch CORRUPT_LOG_RECORD
        let corrupt_report = check_fs_integrity(&fs, None, true);
        assert!(!corrupt_report.is_clean());
        assert!(corrupt_report.issues.iter().any(|i| i.code == "CORRUPT_LOG_RECORD"));
    }
}
