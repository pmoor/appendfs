use crate::crypto::VolumeKey;
use crate::log::ExtentState;
use crate::log::record::{
    FILE_HEADER_SIZE, FileHeader, LogAttrDelta, LogEntryDelta, LogExtent, LogNodeDelta, OpCode, RECORD_HEADER_SIZE,
    RecordHeader,
};
use crate::log::summary::{SUMMARY_MAGIC, SummaryReader};
use crate::node::NodeKind;
use crate::storage::{Storage, StorageReader};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::io;
use std::sync::Arc;
use std::time::SystemTime;

/// Dispatches dumping from a `Storage` instance based on magic bytes or extension.
pub fn dump_file(
    storage: &dyn Storage,
    filename: &str,
    verbosity: u8,
    volume_key: Option<&VolumeKey>,
) -> io::Result<String> {
    let reader = storage.open_reader(filename)?;
    let mut magic = [0u8; 4];
    if reader.len()? < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("File {:?} is too small ({} bytes)", filename, reader.len()?),
        ));
    }
    reader.read_exact_at(0, &mut magic)?;

    if magic == crate::log::record::FILE_MAGIC || filename.ends_with(".log") {
        dump_log_reader_with_path(reader.as_ref(), Some(filename), verbosity, volume_key)
    } else if &magic == SUMMARY_MAGIC || filename.ends_with(".summary") {
        dump_summary_file(storage, filename, verbosity, volume_key)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unrecognized file format for {:?} (expected .log with APPF magic or .summary with APPS magic)",
                filename
            ),
        ))
    }
}

/// Generic bucket for histogram distributions (e.g. write payload sizes, extents per file).
#[derive(Debug, Clone)]
pub struct HistogramBucket<T> {
    pub label: &'static str,
    pub min: T,
    pub max: T,
    pub count: usize,
    pub total_bytes: u64,
}

impl<T: PartialOrd + Copy> HistogramBucket<T> {
    pub fn new(label: &'static str, min: T, max: T) -> Self {
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
pub type WriteBucket = HistogramBucket<u64>;

/// Represents the status of a single decoded record or EOF anomaly.
#[derive(Debug, Clone)]
pub enum DumpRecordEntry {
    Valid {
        offset: u64,
        header: RecordHeader,
        payload: Vec<u8>,
        uncompressed_len: Option<u64>,
        is_committed: bool,
    },
    TornRecord {
        offset: u64,
        reason: String,
        partial_bytes: Vec<u8>,
    },
}

/// Statistics collected for a single OpCode.
#[derive(Debug, Default, Clone)]
pub struct OpCodeStats {
    pub count: usize,
    pub payload_bytes: u64,
    pub uncompressed_bytes: u64,
    pub decompressed_count: usize,
}

/// Reads and analyzes a single `.log` generation file, formatting the output based on `verbosity`:
/// - `verbosity == 0`: File header, summary statistics, whole-file checksum, operations histogram, payload sizes histogram.
/// - `verbosity == 1`: Summary + complete record list (op, inode, offsets, payloads).
/// - `verbosity >= 2`: Summary + all records + full hex/ASCII data dumps for writes.
pub fn dump_log_file(
    storage: &dyn Storage,
    filename: &str,
    verbosity: u8,
    volume_key: Option<&VolumeKey>,
) -> io::Result<String> {
    let reader = storage.open_reader(filename)?;
    dump_log_reader_with_path(reader.as_ref(), Some(filename), verbosity, volume_key)
}

/// Reads and analyzes a `.log` file from a `StorageReader`.
pub fn dump_log_reader(reader: &dyn StorageReader, verbosity: u8) -> io::Result<String> {
    dump_log_reader_with_path(reader, None, verbosity, None)
}

// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn dump_log_reader_with_path(
    reader: &dyn StorageReader,
    display_path: Option<&str>,
    verbosity: u8,
    volume_key: Option<&VolumeKey>,
) -> io::Result<String> {
    let file_len = reader.len()?;

    if file_len < FILE_HEADER_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "Log file {:?} is smaller than the {}-byte FileHeader ({} bytes)",
                display_path.unwrap_or("<log>"),
                FILE_HEADER_SIZE,
                file_len
            ),
        ));
    }

    let mut header_buf = [0u8; FILE_HEADER_SIZE];
    reader.read_exact_at(0, &mut header_buf)?;
    let file_header = FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut records: Vec<DumpRecordEntry> = Vec::new();
    let mut current_offset = FILE_HEADER_SIZE as u64;

    let mut op_counts: [OpCodeStats; 6] = Default::default();
    let mut write_buckets = vec![
        WriteBucket::new("< 64 B", 0, 63),
        WriteBucket::new("64 B .. 511 B", 64, 511),
        WriteBucket::new("512 B .. 4 KiB", 512, 4095),
        WriteBucket::new("4 KiB .. 64 KiB", 4096, 65535),
        WriteBucket::new("64 KiB .. 1 MiB", 65536, 1048575),
        WriteBucket::new("> 1 MiB", 1048576, u64::MAX),
    ];

    let mut total_flush_batches = 0usize;
    let mut total_data_bytes = 0u64;
    let mut uncommitted_records_count = 0usize;

    // First pass: Read all records and detect batch commit boundaries
    let mut last_commit_idx: Option<usize> = None;

    while current_offset < file_len {
        let remaining_file_bytes = file_len - current_offset;
        if remaining_file_bytes < RECORD_HEADER_SIZE as u64 {
            let mut partial = vec![0u8; remaining_file_bytes as usize];
            let _ = reader.read_exact_at(current_offset, &mut partial);
            records.push(DumpRecordEntry::TornRecord {
                offset: current_offset,
                reason: format!(
                    "Truncated record header ({} of {} bytes present at EOF)",
                    remaining_file_bytes, RECORD_HEADER_SIZE
                ),
                partial_bytes: partial,
            });
            break;
        }

        let record_offset = current_offset;
        let mut rec_hdr_buf = [0u8; RECORD_HEADER_SIZE];
        if let Err(e) = reader.read_exact_at(record_offset, &mut rec_hdr_buf) {
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!("Failed reading record header: {}", e),
                partial_bytes: Vec::new(),
            });
            break;
        }

        let header = match RecordHeader::from_bytes(&rec_hdr_buf) {
            Ok(h) => h,
            Err(e) => {
                records.push(DumpRecordEntry::TornRecord {
                    offset: record_offset,
                    reason: format!("Corrupted record header: {}", e),
                    partial_bytes: rec_hdr_buf.to_vec(),
                });
                break;
            }
        };

        let available_payload = file_len.saturating_sub(record_offset + RECORD_HEADER_SIZE as u64);
        if available_payload < header.payload_len as u64 {
            let mut partial = vec![0u8; available_payload as usize];
            let _ = reader.read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut partial);
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!(
                    "Truncated record payload ({} of {} bytes present at EOF)",
                    available_payload, header.payload_len
                ),
                partial_bytes: partial,
            });
            break;
        }

        let mut raw_payload = vec![0u8; header.payload_len as usize];
        if let Err(e) = reader.read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut raw_payload) {
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!("Failed reading full payload: {}", e),
                partial_bytes: Vec::new(),
            });
            break;
        }

        let decrypted = if let Some(key) = volume_key {
            match key.decrypt_record(
                file_header.generation,
                file_header.revision,
                record_offset,
                header.op_code as u8,
                header.inode,
                &raw_payload,
                &header.auth_tag,
            ) {
                Ok(plain) => Some(plain),
                Err(e) => {
                    records.push(DumpRecordEntry::TornRecord {
                        offset: record_offset,
                        reason: format!("Payload authentication failed (corrupted / bitrot): {}", e),
                        partial_bytes: raw_payload,
                    });
                    break;
                }
            }
        } else {
            None
        };

        let mut uncompressed_len = None;
        let payload = match header.op_code {
            OpCode::DataZstd => {
                let zstd_slice: &[u8] = if let Some(ref plain) = decrypted {
                    plain
                } else {
                    &raw_payload
                };
                if let Ok(sz) = crate::compress::zstd_frame_content_size(zstd_slice) {
                    uncompressed_len = Some(sz as u64);
                }
                if verbosity >= 2 {
                    if uncompressed_len.is_some() {
                        crate::compress::decompress_zstd(zstd_slice).unwrap_or(raw_payload)
                    } else {
                        raw_payload
                    }
                } else {
                    Vec::new()
                }
            }
            OpCode::Data => {
                uncompressed_len = Some(header.payload_len as u64);
                if verbosity >= 2 {
                    decrypted.unwrap_or(raw_payload)
                } else {
                    Vec::new()
                }
            }
            _ => decrypted.unwrap_or(raw_payload),
        };

        let is_commit = header.op_code == OpCode::FlushCommit;
        let is_seal = header.op_code == OpCode::Seal;
        let rec_idx = records.len();
        records.push(DumpRecordEntry::Valid {
            offset: record_offset,
            header,
            payload,
            uncompressed_len,
            is_committed: false, // will update below
        });

        current_offset += RECORD_HEADER_SIZE as u64 + header.payload_len as u64;

        let op_idx = header.op_code as usize;
        if op_idx < op_counts.len() {
            op_counts[op_idx].count += 1;
            op_counts[op_idx].payload_bytes += header.payload_len as u64;
            if header.op_code == OpCode::DataZstd {
                if let Some(uncompressed) = uncompressed_len {
                    op_counts[op_idx].uncompressed_bytes += uncompressed;
                    op_counts[op_idx].decompressed_count += 1;
                }
            } else {
                op_counts[op_idx].uncompressed_bytes += header.payload_len as u64;
            }
        }

        if header.op_code == OpCode::Data || header.op_code == OpCode::DataZstd {
            let data_len = uncompressed_len.unwrap_or(header.payload_len as u64);
            for b in &mut write_buckets {
                if b.matches(data_len) {
                    b.add(data_len);
                    break;
                }
            }
            total_data_bytes += data_len;
        }

        if is_commit {
            total_flush_batches += 1;
            // Mark all preceding records up to this commit as committed
            let start = last_commit_idx.map_or(0, |i| i + 1);
            for r in &mut records[start..=rec_idx] {
                if let DumpRecordEntry::Valid { is_committed, .. } = r {
                    *is_committed = true;
                }
            }
            last_commit_idx = Some(rec_idx);
        } else if is_seal {
            if let DumpRecordEntry::Valid { is_committed, .. } = &mut records[rec_idx] {
                *is_committed = true;
            }
            last_commit_idx = Some(rec_idx);
        }
    }

    // Count uncommitted trailing records
    let start_uncommitted = last_commit_idx.map_or(0, |i| i + 1);
    for r in &records[start_uncommitted..] {
        if matches!(r, DumpRecordEntry::Valid { .. }) {
            uncommitted_records_count += 1;
        }
    }

    let mut out = String::new();
    writeln!(out, "=== appendfs Log File Dump ===").unwrap();
    if let Some(p) = display_path {
        writeln!(out, "File:                {:?}", p).unwrap();
    } else {
        writeln!(out, "File:                <in-memory>").unwrap();
    }
    writeln!(out, "Generation:          {}", file_header.generation).unwrap();
    writeln!(out, "Revision:            {}", file_header.revision).unwrap();
    writeln!(out, "Format Version:      {}", file_header.version).unwrap();
    writeln!(
        out,
        "Created At:          {}",
        format_system_time(file_header.created_at)
    )
    .unwrap();
    writeln!(out, "File Size:           {}", format_bytes(file_len)).unwrap();
    writeln!(
        out,
        "Total Valid Records: {}",
        records
            .iter()
            .filter(|r| matches!(r, DumpRecordEntry::Valid { .. }))
            .count()
    )
    .unwrap();
    writeln!(out, "Total Data Payload:  {}", format_bytes(total_data_bytes)).unwrap();
    writeln!(out).unwrap();

    // Flush batch statistics
    writeln!(out, "--- Flush Batch Statistics ---").unwrap();
    writeln!(out, "Committed Flushes:   {}", total_flush_batches).unwrap();
    if total_flush_batches > 0 {
        let avg_records = (records.len().saturating_sub(uncommitted_records_count)) as f64 / total_flush_batches as f64;
        let avg_data = total_data_bytes as f64 / total_flush_batches as f64;
        writeln!(out, "Avg Records / Flush: {:.1}", avg_records).unwrap();
        writeln!(out, "Avg Data / Flush:    {}", format_bytes(avg_data as u64)).unwrap();
    }
    if uncommitted_records_count > 0 {
        writeln!(
            out,
            "Trailing Batch:      {} UNCOMMITTED records (interrupted flush before FlushCommit)",
            uncommitted_records_count
        )
        .unwrap();
    } else {
        writeln!(out, "Trailing Batch:      None (cleanly committed at EOF)").unwrap();
    }
    writeln!(out).unwrap();

    // OpCode breakdown table
    writeln!(out, "--- Record Breakdown by OpCode ---").unwrap();
    writeln!(
        out,
        "{:<14} {:>10} {:>14} {:>12}",
        "OP CODE", "COUNT", "TOTAL BYTES", "% OF RECORDS"
    )
    .unwrap();
    writeln!(out, "{:-<14} {:-<10} {:-<14} {:-<12}", "", "", "", "").unwrap();

    let total_valid = records
        .iter()
        .filter(|r| matches!(r, DumpRecordEntry::Valid { .. }))
        .count();

    for code in 1..=5u8 {
        if let Ok(opcode) = OpCode::try_from(code) {
            let stats = &op_counts[code as usize];
            let pct = if total_valid > 0 {
                stats.count as f64 / total_valid as f64 * 100.0
            } else {
                0.0
            };
            let pct_str = format!("{:.1}%", pct);
            writeln!(
                out,
                "{:<14} {:>10} {:>14} {:>12}",
                opcode,
                stats.count,
                format_bytes(stats.payload_bytes),
                pct_str
            )
            .unwrap();
        }
    }

    let zstd_stats = &op_counts[OpCode::DataZstd as usize];
    if zstd_stats.count > 0 {
        writeln!(out).unwrap();
        if zstd_stats.decompressed_count == zstd_stats.count {
            let uncompressed = zstd_stats.uncompressed_bytes;
            let compressed = zstd_stats.payload_bytes;
            let saved = uncompressed.saturating_sub(compressed);
            let pct = if uncompressed > 0 {
                (saved as f64 / uncompressed as f64) * 100.0
            } else {
                0.0
            };
            let ratio = if compressed > 0 {
                uncompressed as f64 / compressed as f64
            } else {
                0.0
            };
            writeln!(
                out,
                "DataZstd Compression: {} -> {}, saved {} / {:.1}%, {:.2}x",
                format_bytes(uncompressed),
                format_bytes(compressed),
                format_bytes(saved),
                pct,
                ratio
            )
            .unwrap();
        } else if zstd_stats.decompressed_count > 0 {
            let uncompressed = zstd_stats.uncompressed_bytes;
            let compressed = zstd_stats.payload_bytes;
            let saved = uncompressed.saturating_sub(compressed);
            let pct = if uncompressed > 0 {
                (saved as f64 / uncompressed as f64) * 100.0
            } else {
                0.0
            };
            let ratio = if compressed > 0 {
                uncompressed as f64 / compressed as f64
            } else {
                0.0
            };
            writeln!(
                out,
                "DataZstd Compression ({} of {} records decompressed): {} -> {}, saved {} / {:.1}%, {:.2}x",
                zstd_stats.decompressed_count,
                zstd_stats.count,
                format_bytes(uncompressed),
                format_bytes(compressed),
                format_bytes(saved),
                pct,
                ratio
            )
            .unwrap();
        } else {
            writeln!(
                out,
                "DataZstd Compression: {} records encrypted (unlock with volume key to view savings)",
                zstd_stats.count
            )
            .unwrap();
        }
    }
    writeln!(out).unwrap();

    // Write size histogram
    let total_writes = op_counts[OpCode::Data as usize].count + op_counts[OpCode::DataZstd as usize].count;
    if total_writes > 0 {
        writeln!(out, "--- Write Payload Size Histogram ---").unwrap();
        writeln!(
            out,
            "{:<18} {:>8} {:>14}   DISTRIBUTION",
            "SIZE RANGE", "COUNT", "TOTAL BYTES"
        )
        .unwrap();
        writeln!(out, "{:-<18} {:-<8} {:-<14}   {:-<20}", "", "", "", "").unwrap();

        for b in &write_buckets {
            let pct = (b.count as f64 / total_writes as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            writeln!(
                out,
                "{:<18} {:>8} {:>14}   {:<20} ({:.1}%)",
                b.label,
                b.count,
                format_bytes(b.total_bytes),
                bar,
                pct
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // Detail record stream for verbosity >= 1
    if verbosity >= 1 {
        writeln!(out, "=== Sequential Record Stream ===").unwrap();
        for (i, entry) in records.iter().enumerate() {
            match entry {
                DumpRecordEntry::Valid {
                    offset,
                    header,
                    payload,
                    uncompressed_len,
                    is_committed,
                } => {
                    let commit_tag = if *is_committed {
                        "[COMMITTED]"
                    } else {
                        "[UNCOMMITTED TRAILING BATCH]"
                    };

                    writeln!(
                        out,
                        "#{:<5} [0x{:08x} / {:<8}] {:<14} inode {:<5} len {:<8} tag {:02x}{:02x}{:02x}{:02x} {}",
                        i + 1,
                        offset,
                        offset,
                        header.op_code,
                        header.inode,
                        format_bytes(header.payload_len as u64),
                        header.auth_tag[0],
                        header.auth_tag[1],
                        header.auth_tag[2],
                        header.auth_tag[3],
                        commit_tag,
                    )
                    .unwrap();

                    // Decode payload details
                    format_payload_details(
                        &mut out,
                        header.op_code,
                        header.payload_len,
                        *uncompressed_len,
                        payload,
                        verbosity >= 2,
                    );
                }
                DumpRecordEntry::TornRecord {
                    offset,
                    reason,
                    partial_bytes,
                } => {
                    writeln!(
                        out,
                        "#{:<5} [0x{:08x} / {:<8}] *** TORN RECORD / ANOMALY AT EOF ***",
                        i + 1,
                        offset,
                        offset
                    )
                    .unwrap();
                    writeln!(out, "      Error: {}", reason).unwrap();
                    if !partial_bytes.is_empty() && verbosity >= 2 {
                        writeln!(out, "      Partial Bytes ({} bytes):", partial_bytes.len()).unwrap();
                        out.push_str(&format_hexdump(partial_bytes, 256));
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Reads and analyzes a single `.summary` snapshot file, formatting the output based on `verbosity`:
/// - `verbosity == 0`: Summary metadata, whole-file checksum, inode breakdown, extent fragmentation stats, histogram, top fragmented files, manifest table.
/// - `verbosity == 1`: Summary + complete inode listing / directory tree.
/// - `verbosity >= 2`: Summary + complete inode listing + detailed physical extent range mappings for all files.
pub fn dump_summary_file(
    storage: &dyn Storage,
    filename: &str,
    verbosity: u8,
    volume_key: Option<&VolumeKey>,
) -> io::Result<String> {
    // An encrypted summary opened without a key cannot have its body read, but the parts
    // that live in plaintext still describe the volume. Report those rather than refusing:
    // inspecting on-disk structure without credentials is exactly what this tool is for.
    if volume_key.is_none() {
        let header = SummaryReader::read_volume_header(storage, filename)?;
        if header.cipher.is_encrypted() {
            return dump_encrypted_summary_without_key(storage, filename, &header);
        }
    }

    let kr = volume_key.cloned().unwrap_or_else(VolumeKey::plaintext);
    let reader = SummaryReader::open(storage, filename, Arc::new(kr))?;
    dump_summary_reader_with_path(&reader, Some(filename), verbosity)
}

/// Formats the plaintext-visible structure of an encrypted summary: everything outside the
/// encrypted body.
fn dump_encrypted_summary_without_key(
    storage: &dyn Storage,
    filename: &str,
    volume_header: &crate::crypto::VolumeHeader,
) -> io::Result<String> {
    use crate::log::summary::{SUMMARY_FOOTER_SIZE, SUMMARY_HEADER_SIZE, SummaryFooter, SummaryHeader};

    let reader = storage.open_reader(filename)?;
    let file_len = reader.len()?;
    if file_len < (SUMMARY_HEADER_SIZE + SUMMARY_FOOTER_SIZE) as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("summary file {} is too short ({} bytes)", filename, file_len),
        ));
    }

    let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
    reader.read_exact_at(0, &mut header_buf)?;
    let header = SummaryHeader::from_bytes(&header_buf)?;

    let mut footer_buf = [0u8; SUMMARY_FOOTER_SIZE];
    reader.read_exact_at(file_len - SUMMARY_FOOTER_SIZE as u64, &mut footer_buf)?;
    let footer = SummaryFooter::from_bytes(&footer_buf)?;

    let mut out = String::new();
    writeln!(out, "=== appendfs Summary File Dump ===").unwrap();
    writeln!(out, "File:                {:?}", filename).unwrap();
    writeln!(out, "Generation:          {}", header.generation).unwrap();
    writeln!(out, "Revision:            {}", header.revision).unwrap();
    writeln!(out, "Format Version:      {}", header.version).unwrap();
    writeln!(out, "Last Batch ID:       {}", header.last_batch_id).unwrap();
    writeln!(out, "Next Inode:          {}", header.next_inode).unwrap();
    writeln!(out, "File Size:           {}", format_bytes(file_len)).unwrap();
    writeln!(out, "Encryption:          {}", volume_header.cipher).unwrap();
    writeln!(out, "Unlocked by:         {}", volume_header.key_source).unwrap();
    writeln!(
        out,
        "Volume ID:           {}",
        volume_header
            .volume_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    )
    .unwrap();
    writeln!(out, "Inode Count:         {}", footer.entry_count).unwrap();
    writeln!(
        out,
        "Encrypted Body:      {} at offset {}",
        format_bytes(
            file_len - SUMMARY_FOOTER_SIZE as u64 - SUMMARY_HEADER_SIZE as u64 - header.volume_header_len as u64
        ),
        SUMMARY_HEADER_SIZE as u64 + header.volume_header_len as u64
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "No key supplied: the inode table and manifest live in the").unwrap();
    writeln!(out, "encrypted body and cannot be shown. Pass --key-file to read them.").unwrap();

    Ok(out)
}
/// Reads and analyzes a `.summary` snapshot from an existing `SummaryReader`.
pub fn dump_summary_reader(reader: &SummaryReader, verbosity: u8) -> io::Result<String> {
    dump_summary_reader_with_path(reader, None, verbosity)
}

// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn dump_summary_reader_with_path(
    reader: &SummaryReader,
    display_path: Option<&str>,
    verbosity: u8,
) -> io::Result<String> {
    let file_len = reader.reader().len()?;

    let inodes = reader.read_all_inodes()?;

    // Sort inodes ascending
    let mut sorted_inodes: Vec<u64> = inodes.keys().copied().collect();
    sorted_inodes.sort_unstable();

    // Inode type counters
    let mut dir_count = 0usize;
    let mut file_count = 0usize;
    let mut symlink_count = 0usize;
    let mut total_logical_bytes = 0u64;

    let mut total_file_extents = 0usize;
    let mut max_file_extents = 0usize;

    // Extents per file buckets
    let mut extent_buckets = vec![
        ExtentsBucket::new("1 extent (contiguous)", 1, 1),
        ExtentsBucket::new("2 - 4 extents", 2, 4),
        ExtentsBucket::new("5 - 16 extents", 5, 16),
        ExtentsBucket::new("17 - 64 extents", 17, 64),
        ExtentsBucket::new("> 64 extents", 65, usize::MAX),
    ];

    // File fragmentation list for top-N ranking
    struct FileFragInfo {
        inode: u64,
        size: u64,
        extents: usize,
        path: String,
    }
    let mut file_frag_list: Vec<FileFragInfo> = Vec::new();

    // Build path map by BFS traversal from root directory (inode 1)
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

    // Sort top fragmented files
    file_frag_list.sort_by(|a, b| b.extents.cmp(&a.extents).then_with(|| b.size.cmp(&a.size)));

    let mut out = String::new();
    writeln!(out, "=== appendfs Summary File Dump ===").unwrap();
    if let Some(p) = display_path {
        writeln!(out, "File:                {:?}", p).unwrap();
    } else {
        writeln!(out, "File:                <in-memory>").unwrap();
    }
    writeln!(out, "Generation:          {}", reader.header.generation).unwrap();
    writeln!(out, "Format Version:      {}", reader.header.version).unwrap();
    writeln!(out, "Last Batch ID:       {}", reader.header.last_batch_id).unwrap();
    writeln!(out, "Next Inode:          {}", reader.header.next_inode).unwrap();
    writeln!(out, "File Size:           {}", format_bytes(file_len)).unwrap();
    writeln!(out, "Encryption:          {}", reader.volume_header.cipher).unwrap();
    if reader.volume_header.cipher.is_encrypted() {
        writeln!(out, "Unlocked by:         {}", reader.volume_header.key_source).unwrap();
    }

    // Checksum display
    let checksum_hex = reader
        .footer
        .checksum
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    writeln!(out, "Checksum (BLAKE3):   {} (VERIFIED)", checksum_hex).unwrap();
    writeln!(out).unwrap();

    // Inode Breakdown
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

    // File Extents & Fragmentation Stats
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

        for b in &extent_buckets {
            let pct = (b.count as f64 / file_count as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            let pct_str = format!("{:.1}%", pct);
            writeln!(out, "{:<24} {:>8} {:>12}   {:<20}", b.label, b.count, pct_str, bar).unwrap();
        }
        writeln!(out).unwrap();

        // Top fragmented files (if any have > 1 extent)
        let multi_extent_files: Vec<_> = file_frag_list.iter().filter(|f| f.extents > 1).take(5).collect();
        if !multi_extent_files.is_empty() {
            writeln!(out, "--- Top Fragmented Files ---").unwrap();
            writeln!(
                out,
                "{:<8} {:>12} {:>9} {:>16}   PATH",
                "INODE", "SIZE", "EXTENTS", "AVG EXTENT SIZE"
            )
            .unwrap();
            writeln!(out, "{:-<8} {:-<12} {:-<9} {:-<16}   {:-<30}", "", "", "", "", "").unwrap();
            for f in multi_extent_files {
                let avg_sz = if f.extents > 0 { f.size / f.extents as u64 } else { 0 };
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
        }
    }

    // Log Manifest Section
    writeln!(out, "--- Tracked Log Generations Manifest ---").unwrap();
    if reader.manifest.logs.is_empty() {
        writeln!(out, "Tracked Logs:        0 active log generation files").unwrap();
    } else {
        writeln!(
            out,
            "Tracked Logs:        {} log generation files",
            reader.manifest.logs.len()
        )
        .unwrap();
        writeln!(out).unwrap();

        let generations = crate::stats::calculate_generation_live_stats_from_nodes(
            inodes.values().map(|a| a.as_ref()),
            &reader.manifest,
        );
        out.push_str(&crate::stats::format_generations_table(&generations));
    }
    writeln!(out).unwrap();

    // Verbose Level 1: Inode Tree / Details
    if verbosity >= 1 {
        writeln!(out, "=== Summary Inode Records ===").unwrap();
        for (i, &ino) in sorted_inodes.iter().enumerate() {
            if let Some(sync_node) = inodes.get(&ino) {
                let node = sync_node.as_ref();
                let path_str = path_map.get(&ino).map(|p| p.as_str()).unwrap_or("");
                match &node.kind {
                    NodeKind::Directory { entries, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Directory  {:?} (mode 0o{:o}, uid {}, gid {}, entries: {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            entries.len(),
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                        if !entries.is_empty() {
                            let mut sorted_entries = entries.clone();
                            sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));
                            let entry_strs: Vec<String> = sorted_entries
                                .iter()
                                .map(|(name, child_ino)| format!("{:?} -> Inode {}", name, child_ino))
                                .collect();
                            writeln!(out, "      entries: [{}]", entry_strs.join(", ")).unwrap();
                        }
                    }
                    NodeKind::Symlink { target, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Symlink    {:?} -> {:?} (uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            target,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::File { extent_map, size, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] RegularFile {:?} (size {}, extents {}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            format_bytes(*size),
                            extent_map.len(),
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();

                        // Verbose Level 2: Physical Extents Dump
                        if verbosity >= 2 {
                            if extent_map.is_empty() {
                                writeln!(out, "      extents: (empty / 0 bytes)").unwrap();
                            } else {
                                writeln!(out, "      extents ({}):", extent_map.len()).unwrap();
                                for (ext_idx, (&start, entry)) in extent_map.iter().enumerate() {
                                    let state_desc = match &entry.extent {
                                        ExtentState::Disk {
                                            generation,
                                            record_log_offset,
                                            record_size,
                                            payload_offset,
                                            length,
                                        } => {
                                            format!(
                                                "{} [record offset 0x{:08x} / {:<8}, rec_size {}, payload offset {:<4}, len {}]",
                                                crate::log::log_filename(*generation),
                                                record_log_offset,
                                                record_log_offset,
                                                format_bytes(*record_size as u64),
                                                payload_offset,
                                                format_bytes(*length as u64)
                                            )
                                        }
                                        ExtentState::Staged {
                                            data,
                                            payload_offset,
                                            length,
                                        } => {
                                            format!(
                                                "Staged Memory Buffer [payload offset {}, len {}, data buf {}]",
                                                payload_offset,
                                                format_bytes(*length as u64),
                                                format_bytes(data.read().map(|g| g.len() as u64).unwrap_or(0))
                                            )
                                        }
                                        ExtentState::Zero { length } => {
                                            format!("hole (reads as zeros) [len {}]", format_bytes(*length))
                                        }
                                    };
                                    writeln!(
                                        out,
                                        "        [{:>2}] [0x{:08x} .. 0x{:08x}] ({:>10}) -> {}",
                                        ext_idx + 1,
                                        start,
                                        start + entry.length(),
                                        format_bytes(entry.length()),
                                        state_desc
                                    )
                                    .unwrap();
                                }
                            }
                        }
                    }
                    NodeKind::Fifo => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] FIFO       {:?} (mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::CharDevice { rdev } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] CharDev    {:?} (rdev 0x{:x}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            rdev,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::BlockDevice { rdev } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] BlockDev   {:?} (rdev 0x{:x}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            rdev,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::Socket => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Socket     {:?} (mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                }
                if let Some(ref xattrs) = node.meta.xattrs {
                    let mut xattr_strs = Vec::new();
                    for (k, v) in xattrs.iter() {
                        xattr_strs.push(format!("{:?} ({} bytes)", k, v.len()));
                    }
                    writeln!(out, "      xattrs: [{}]", xattr_strs.join(", ")).unwrap();
                }
            }
        }
    }

    Ok(out)
}

fn format_data_payload(
    out: &mut String,
    opcode: OpCode,
    stored_len: u32,
    uncompressed_len: Option<u64>,
    payload: &[u8],
    dump_data_hex: bool,
) {
    if opcode == OpCode::DataZstd {
        if let Some(uncompressed) = uncompressed_len {
            if uncompressed > stored_len as u64 {
                let compressed = stored_len as u64;
                let saved = uncompressed - compressed;
                let pct = (saved as f64 / uncompressed as f64) * 100.0;
                writeln!(
                    out,
                    "      data_len: {} (saved {} / {:.1}%)",
                    format_bytes(uncompressed),
                    format_bytes(saved),
                    pct
                )
                .unwrap();
            } else {
                writeln!(out, "      data_len: {}", format_bytes(uncompressed)).unwrap();
            }
        } else {
            writeln!(out, "      data_len: {}", format_bytes(stored_len as u64)).unwrap();
        }
    } else {
        writeln!(out, "      data_len: {}", format_bytes(stored_len as u64)).unwrap();
    }

    if dump_data_hex && !payload.is_empty() {
        out.push_str(&format_hexdump(payload, 256));
    }
}

fn format_record_payload(out: &mut String, opcode: OpCode, payload: &[u8]) {
    match opcode {
        OpCode::InodeDelta => match crate::wire::deserialize::<crate::log::record::LogEntryDelta>(payload) {
            Ok(delta) => writeln!(out, "      delta: {}", format_log_entry_delta(&delta)).unwrap(),
            Err(_) => writeln!(out, "      [Failed to deserialize InodeDeltaPayload]").unwrap(),
        },
        OpCode::FlushCommit => match crate::wire::deserialize::<crate::log::record::FlushCommitPayload>(payload) {
            Ok(b) => writeln!(
                out,
                "      batch_id: {}, batch_record_count: {}, commit_timestamp: {}",
                b.batch_id,
                b.record_count,
                format_system_time(b.timestamp)
            )
            .unwrap(),
            Err(_) => writeln!(out, "      [Failed to deserialize FlushCommitPayload]").unwrap(),
        },
        OpCode::Seal => match crate::wire::deserialize::<crate::log::record::SealPayload>(payload) {
            Ok(s) => writeln!(
                out,
                "      sealed_record_count: {}, seal_timestamp: {}",
                s.record_count,
                format_system_time(s.timestamp)
            )
            .unwrap(),
            Err(_) => writeln!(out, "      [Failed to deserialize SealPayload]").unwrap(),
        },
        _ => {}
    }
}

fn format_payload_details(
    out: &mut String,
    opcode: OpCode,
    stored_len: u32,
    uncompressed_len: Option<u64>,
    payload: &[u8],
    dump_data_hex: bool,
) {
    match opcode {
        OpCode::Data | OpCode::DataZstd => {
            format_data_payload(out, opcode, stored_len, uncompressed_len, payload, dump_data_hex);
        }
        OpCode::InodeDelta | OpCode::FlushCommit | OpCode::Seal => {
            format_record_payload(out, opcode, payload);
        }
    }
}

/// Formats a byte slice into standard 16-bytes-per-line hex and ASCII dump.
pub fn format_hexdump(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let display_len = std::cmp::min(data.len(), max_bytes);
    for chunk_offset in (0..display_len).step_by(16) {
        let chunk_end = std::cmp::min(chunk_offset + 16, display_len);
        let chunk = &data[chunk_offset..chunk_end];

        let _ = write!(out, "      {:08x}  ", chunk_offset);

        for i in 0..16 {
            if i == 8 {
                out.push(' ');
            }
            if let Some(&b) = chunk.get(i) {
                let _ = write!(out, "{:02x} ", b);
            } else {
                out.push_str("   ");
            }
        }

        out.push_str(" |");
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    if data.len() > max_bytes {
        let _ = writeln!(out, "      ... [{} more data bytes omitted]", data.len() - max_bytes);
    }
    out
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

fn format_system_time(time: SystemTime) -> String {
    crate::clock::format_utc_civil_time(time)
}

fn push_attr_delta_fields(attr: &LogAttrDelta, fields: &mut Vec<String>) {
    if let Some(mode) = attr.mode {
        fields.push(format!("mode: 0o{:o}", mode));
    }
    if let Some(uid) = attr.uid {
        fields.push(format!("uid: {}", uid));
    }
    if let Some(gid) = attr.gid {
        fields.push(format!("gid: {}", gid));
    }
    if let Some(nlink) = attr.nlink {
        fields.push(format!("nlink: {}", nlink));
    }
    if let Some(atime) = attr.atime {
        fields.push(format!("atime: {}", format_system_time(atime)));
    }
    if let Some(mtime) = attr.mtime {
        fields.push(format!("mtime: {}", format_system_time(mtime)));
    }
    if let Some(ctime) = attr.ctime {
        fields.push(format!("ctime: {}", format_system_time(ctime)));
    }
    if let Some(created_at) = attr.created_at {
        fields.push(format!("created_at: {}", format_system_time(created_at)));
    }
    if let Some(ref xattrs) = attr.xattrs {
        if xattrs.is_empty() {
            fields.push("xattrs: []".to_string());
        } else {
            let xattr_strs: Vec<String> = xattrs
                .iter()
                .map(|(k, v)| match v {
                    Some(val) => format!("set {:?} ({} B)", k, val.len()),
                    None => format!("remove {:?}", k),
                })
                .collect();
            fields.push(format!("xattrs: [{}]", xattr_strs.join(", ")));
        }
    }
}

fn format_log_extent(ext: &LogExtent) -> String {
    let end = ext.file_offset.saturating_add(ext.length);
    if ext.record_log_offset == 0 {
        format!(
            "[0x{:x}..0x{:x} ({}) -> hole]",
            ext.file_offset,
            end,
            format_bytes(ext.length)
        )
    } else {
        format!(
            "[0x{:x}..0x{:x} ({}) -> log offset 0x{:08x}]",
            ext.file_offset,
            end,
            format_bytes(ext.length),
            ext.record_log_offset
        )
    }
}

fn format_fields(kind: &str, fields: &[String]) -> String {
    if fields.is_empty() {
        format!("{} {{}}", kind)
    } else {
        format!("{} {{ {} }}", kind, fields.join(", "))
    }
}

/// Formats a `LogNodeDelta` into a human-readable sparse string where only modified fields are displayed.
pub fn format_log_node_delta(node: &LogNodeDelta) -> String {
    match node {
        LogNodeDelta::Directory(d) => {
            let mut fields = Vec::new();
            if let Some(parent) = d.parent {
                fields.push(format!("parent: {}", parent));
            }
            if !d.added.is_empty() {
                let added_strs: Vec<String> = d
                    .added
                    .iter()
                    .map(|(name, ino)| format!("{:?} -> Inode {}", name, ino))
                    .collect();
                fields.push(format!("added: [{}]", added_strs.join(", ")));
            }
            if !d.removed.is_empty() {
                let removed_strs: Vec<String> = d.removed.iter().map(|name| format!("{:?}", name)).collect();
                fields.push(format!("removed: [{}]", removed_strs.join(", ")));
            }
            push_attr_delta_fields(&d.attr_delta, &mut fields);
            format_fields("Directory", &fields)
        }
        LogNodeDelta::File(f) => {
            let mut fields = Vec::new();
            if !f.extents.is_empty() {
                let ext_strs: Vec<String> = f.extents.iter().map(format_log_extent).collect();
                fields.push(format!("extents: [{}]", ext_strs.join(", ")));
            }
            if let Some(size) = f.size {
                if size >= 1024 {
                    fields.push(format!("size: {} ({})", size, format_bytes(size)));
                } else {
                    fields.push(format!("size: {} B", size));
                }
            }
            push_attr_delta_fields(&f.attr_delta, &mut fields);
            format_fields("File", &fields)
        }
        LogNodeDelta::Symlink(s) => {
            let mut fields = Vec::new();
            if let Some(ref target) = s.target {
                fields.push(format!("target: {:?}", target));
            }
            push_attr_delta_fields(&s.attr_delta, &mut fields);
            format_fields("Symlink", &fields)
        }
        LogNodeDelta::Fifo(s) => {
            let mut fields = Vec::new();
            if s.rdev != 0 {
                fields.push(format!("rdev: 0x{:x}", s.rdev));
            }
            push_attr_delta_fields(&s.attr_delta, &mut fields);
            format_fields("Fifo", &fields)
        }
        LogNodeDelta::CharDevice(s) => {
            let mut fields = Vec::new();
            fields.push(format!("rdev: 0x{:x}", s.rdev));
            push_attr_delta_fields(&s.attr_delta, &mut fields);
            format_fields("CharDevice", &fields)
        }
        LogNodeDelta::BlockDevice(s) => {
            let mut fields = Vec::new();
            fields.push(format!("rdev: 0x{:x}", s.rdev));
            push_attr_delta_fields(&s.attr_delta, &mut fields);
            format_fields("BlockDevice", &fields)
        }
        LogNodeDelta::Socket(s) => {
            let mut fields = Vec::new();
            if s.rdev != 0 {
                fields.push(format!("rdev: 0x{:x}", s.rdev));
            }
            push_attr_delta_fields(&s.attr_delta, &mut fields);
            format_fields("Socket", &fields)
        }
    }
}

/// Formats a `LogEntryDelta` into a human-readable sparse string where only modified fields are displayed.
pub fn format_log_entry_delta(delta: &LogEntryDelta) -> String {
    match delta {
        LogEntryDelta::Tombstone => "Tombstone".to_string(),
        LogEntryDelta::Node(node) => format_log_node_delta(node),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::log::LogWriter;
    use crate::storage::OsStorage;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_dump_log_file_summary_and_verbosity() {
        use crate::log::record::{LogAttrDelta, LogDirectoryDelta, LogEntryDelta, LogNodeDelta};

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Write InodeDelta record
        let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
            parent: Some(1),
            added: vec![("test.txt".to_string(), 2)],
            removed: vec![],
            attr_delta: LogAttrDelta {
                mode: Some(0o755),
                ..Default::default()
            },
        }));
        let delta_bytes = crate::wire::serialize(&dir_delta).unwrap();
        writer.append_record(OpCode::InodeDelta, 1, &delta_bytes).unwrap();

        // Write Data record with 100 bytes
        let data_bytes = vec![0x42; 100];
        writer.append_record(OpCode::Data, 2, &data_bytes).unwrap();

        // Commit batch
        writer.emit_flush_commit(2, 100, &clock).unwrap();
        writer.flush().unwrap();
        drop(writer);

        assert!(storage.exists("000001.log"));

        // Level 0: Summary
        let summary_dump = dump_log_file(storage.as_ref(), "000001.log", 0, None).unwrap();
        assert!(summary_dump.contains("Total Valid Records: 3"));
        assert!(summary_dump.contains("Committed Flushes:   1"));
        assert!(summary_dump.contains("Trailing Batch:      None"));
        assert!(summary_dump.contains("Data"));
        assert!(summary_dump.contains("64 B .. 511 B"));

        // Level 1: Records
        let v1_dump = dump_log_file(storage.as_ref(), "000001.log", 1, None).unwrap();
        assert!(v1_dump.contains("Sequential Record Stream"));
        assert!(v1_dump.contains("InodeDelta"));
        assert!(v1_dump.contains("delta: Directory { parent: 1, added: [\"test.txt\" -> Inode 2], mode: 0o755 }"));
        assert!(v1_dump.contains("Data"));
        assert!(v1_dump.contains("FlushCommit"));
        assert!(v1_dump.contains("[COMMITTED]"));

        // Level 2: Full Hex
        let v2_dump = dump_log_file(storage.as_ref(), "000001.log", 2, None).unwrap();
        assert!(v2_dump.contains("42 42 42 42"));
    }

    #[test]
    fn test_dump_log_file_detects_interrupted_flush_trailing_records() {
        use crate::log::record::{LogAttrDelta, LogDirectoryDelta, LogEntryDelta, LogNodeDelta};

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
            parent: Some(1),
            added: vec![("uncommitted.txt".to_string(), 2)],
            removed: vec![],
            attr_delta: LogAttrDelta {
                mode: Some(0o755),
                ..Default::default()
            },
        }));
        let delta_bytes = crate::wire::serialize(&dir_delta).unwrap();
        writer.append_record(OpCode::InodeDelta, 1, &delta_bytes).unwrap();
        drop(writer);

        let dump = dump_log_file(storage.as_ref(), "000001.log", 1, None).unwrap();
        assert!(dump.contains("Trailing Batch:      1 UNCOMMITTED records"));
        assert!(dump.contains("[UNCOMMITTED TRAILING BATCH]"));
    }

    #[test]
    fn test_dump_summary_file_summary_and_verbosity_levels() {
        use crate::extent_map::{Extent, ExtentMap};
        use crate::fs::InMemoryFS;
        use crate::log::LogManifest;
        use crate::log::summary::{SummarySnapshot, export_summary, init_volume};
        use crate::node::{InodeMeta, Node, NodeKind};
        use std::sync::Arc;

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        assert!(storage.exists("000000.summary"));

        // Level 0: Summary
        let dump_v0 = dump_file(storage.as_ref(), "000000.summary", 0, None).unwrap();
        assert!(dump_v0.contains("=== appendfs Summary File Dump ==="));
        assert!(dump_v0.contains("Total Inodes:        1 (1 directories, 0 regular files, 0 symlinks)"));
        assert!(dump_v0.contains("Checksum (BLAKE3):"));
        assert!(dump_v0.contains("VERIFIED"));

        // Create an InMemoryFS with fragmented files
        let fs = InMemoryFS::new();
        let now = SystemClock.now();

        // Create directory /docs (inode 2)
        let dir_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("fragmented.bin".to_string(), 3)],
            },
        });

        // Create fragmented file (inode 3) with 2 extents
        let mut rmap = ExtentMap::new();
        rmap.insert(0, Extent::new_disk(1, 100, 4133, 20, 4096));
        rmap.insert(4096, Extent::new_disk(2, 200, 4133, 20, 4096));

        let file_node = Arc::new(Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, now),
            kind: NodeKind::File {
                extent_map: rmap,
                size: 8192,
            },
        });

        // Root directory (inode 1)
        let root_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 2, 0, 0, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("docs".to_string(), 2)],
            },
        });

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(1, root_node);
            inner.base.insert(2, dir_node);
            inner.base.insert(3, file_node);
        }

        let snapshot = fs.snapshot_all();
        let manifest = LogManifest {
            logs: vec![
                crate::log::LogFileInfo {
                    generation: 1,
                    revision: 0,
                    filename: "000001.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                    md5: [1u8; 16],
                    sealed: true,
                },
                crate::log::LogFileInfo {
                    generation: 2,
                    revision: 0,
                    filename: "000002.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                    md5: [2u8; 16],
                    sealed: false,
                },
            ],
        };

        export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                last_batch_id: 100,
                next_inode: 4,
                created_at: std::time::SystemTime::now(),
            },
            storage.as_ref(),
            &crate::crypto::VolumeKey::plaintext(),
        )
        .unwrap();
        assert!(storage.exists("000001.summary"));

        // Level 0: Fragmentation Stats & Top Fragmented Files
        let dump_snap_v0 = dump_file(storage.as_ref(), "000001.summary", 0, None).unwrap();
        assert!(dump_snap_v0.contains("Total Regular Files: 1"));
        assert!(dump_snap_v0.contains("Total File Extents:  2"));
        assert!(dump_snap_v0.contains("Avg Extents / File:  2.00"));
        assert!(dump_snap_v0.contains("Max Extents in File: 2"));
        assert!(dump_snap_v0.contains("2 - 4 extents"));
        assert!(dump_snap_v0.contains("Top Fragmented Files"));
        assert!(dump_snap_v0.contains("/docs/fragmented.bin"));
        assert!(dump_snap_v0.contains("000001.log"));
        assert!(dump_snap_v0.contains("000002.log"));
        assert!(dump_snap_v0.contains("(not sealed)"));
        assert!(
            dump_snap_v0
                .lines()
                .any(|l| l.contains("000001.log") && l.ends_with("Healthy"))
        );
        assert!(
            dump_snap_v0
                .lines()
                .any(|l| l.contains("000002.log") && l.ends_with("Healthy (not sealed)"))
        );

        // Level 1: Inode Tree Listing
        let dump_snap_v1 = dump_file(storage.as_ref(), "000001.summary", 1, None).unwrap();
        assert!(dump_snap_v1.contains("Summary Inode Records"));
        assert!(dump_snap_v1.contains("Directory  \"/\""));
        assert!(dump_snap_v1.contains("Directory  \"/docs\""));
        assert!(dump_snap_v1.contains("RegularFile \"/docs/fragmented.bin\""));

        // Level 2: Full Physical Extent Mappings
        let dump_snap_v2 = dump_file(storage.as_ref(), "000001.summary", 2, None).unwrap();
        assert!(dump_snap_v2.contains("extents (2):"));
        assert!(dump_snap_v2.contains("000001.log [record offset 0x00000064 / 100"));
        assert!(dump_snap_v2.contains("000002.log [record offset 0x000000c8 / 200"));
    }

    #[test]
    fn test_format_log_entry_delta_sparse_file_only_atime() {
        use crate::clock::unix_to_system_time;
        use crate::log::record::{LogAttrDelta, LogEntryDelta, LogFileDelta, LogNodeDelta};

        let atime = unix_to_system_time(1789074226, 459059828);
        let delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta {
            extents: vec![],
            size: None,
            attr_delta: LogAttrDelta {
                atime: Some(atime),
                ..Default::default()
            },
        }));

        let formatted = format_log_entry_delta(&delta);
        assert!(formatted.starts_with("File { atime: 1789074226.459059828s"));
        assert!(formatted.ends_with(" }"));
        assert!(!formatted.contains("extents"));
        assert!(!formatted.contains("size"));
        assert!(!formatted.contains("mode"));
        assert!(!formatted.contains("uid"));
        assert!(!formatted.contains("gid"));
        assert!(!formatted.contains("nlink"));
        assert!(!formatted.contains("mtime"));
        assert!(!formatted.contains("ctime"));
        assert!(!formatted.contains("created_at"));
        assert!(!formatted.contains("xattrs"));
        assert!(!formatted.contains("None"));
    }

    #[test]
    fn test_format_log_entry_delta_file_extents_and_size() {
        use crate::log::record::{LogAttrDelta, LogEntryDelta, LogExtent, LogFileDelta, LogNodeDelta};

        let delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta {
            extents: vec![
                LogExtent {
                    file_offset: 0,
                    record_log_offset: 28,
                    record_size: 4124,
                    length: 4096,
                },
                LogExtent {
                    file_offset: 4096,
                    record_log_offset: 0,
                    record_size: 0,
                    length: 8192,
                },
            ],
            size: Some(12288),
            attr_delta: LogAttrDelta::default(),
        }));

        let formatted = format_log_entry_delta(&delta);
        assert_eq!(
            formatted,
            "File { extents: [[0x0..0x1000 (4.00 KiB) -> log offset 0x0000001c], [0x1000..0x3000 (8.00 KiB) -> hole]], size: 12288 (12.00 KiB) }"
        );

        let small_size_delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta {
            extents: vec![],
            size: Some(100),
            attr_delta: LogAttrDelta::default(),
        }));
        assert_eq!(format_log_entry_delta(&small_size_delta), "File { size: 100 B }");
    }

    #[test]
    fn test_format_log_entry_delta_directory_and_symlink() {
        use crate::log::record::{LogAttrDelta, LogDirectoryDelta, LogEntryDelta, LogNodeDelta, LogSymlinkDelta};

        let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
            parent: Some(1),
            added: vec![("hello.txt".to_string(), 2)],
            removed: vec!["old.txt".to_string()],
            attr_delta: LogAttrDelta {
                mode: Some(0o755),
                uid: Some(1000),
                gid: Some(1000),
                nlink: Some(2),
                ..Default::default()
            },
        }));
        assert_eq!(
            format_log_entry_delta(&dir_delta),
            "Directory { parent: 1, added: [\"hello.txt\" -> Inode 2], removed: [\"old.txt\"], mode: 0o755, uid: 1000, gid: 1000, nlink: 2 }"
        );

        let symlink_delta = LogEntryDelta::Node(LogNodeDelta::Symlink(LogSymlinkDelta {
            target: Some("/target/path".to_string()),
            attr_delta: LogAttrDelta {
                mode: Some(0o777),
                ..Default::default()
            },
        }));
        assert_eq!(
            format_log_entry_delta(&symlink_delta),
            "Symlink { target: \"/target/path\", mode: 0o777 }"
        );
    }

    #[test]
    fn test_format_log_entry_delta_special_nodes_and_xattrs() {
        use crate::log::record::{LogAttrDelta, LogEntryDelta, LogNodeDelta, LogSpecialDelta};

        let fifo_delta = LogEntryDelta::Node(LogNodeDelta::Fifo(LogSpecialDelta {
            rdev: 0,
            attr_delta: LogAttrDelta {
                mode: Some(0o644),
                ..Default::default()
            },
        }));
        assert_eq!(format_log_entry_delta(&fifo_delta), "Fifo { mode: 0o644 }");

        let char_delta = LogEntryDelta::Node(LogNodeDelta::CharDevice(LogSpecialDelta {
            rdev: 0x105,
            attr_delta: LogAttrDelta {
                mode: Some(0o660),
                xattrs: Some(vec![
                    ("user.test".to_string(), Some(vec![1, 2, 3])),
                    ("user.old".to_string(), None),
                ]),
                ..Default::default()
            },
        }));
        assert_eq!(
            format_log_entry_delta(&char_delta),
            "CharDevice { rdev: 0x105, mode: 0o660, xattrs: [set \"user.test\" (3 B), remove \"user.old\"] }"
        );

        let tombstone = LogEntryDelta::Tombstone;
        assert_eq!(format_log_entry_delta(&tombstone), "Tombstone");

        let empty_file = LogEntryDelta::Node(LogNodeDelta::File(Default::default()));
        assert_eq!(format_log_entry_delta(&empty_file), "File {}");
    }

    #[test]
    fn test_dump_log_file_compression_savings_display() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .with_compression(crate::compress::Compression::Zstd);

        // Highly compressible payload: 16 KiB of repeating text
        let compressible_data = "Hello compression savings test! ".repeat(512).into_bytes();
        let uncompressed_len = compressible_data.len() as u64;
        writer.append_record(OpCode::Data, 2, &compressible_data).unwrap();

        // Small / incompressible payload that stays OpCode::Data
        let small_data = vec![0x42; 8];
        writer.append_record(OpCode::Data, 3, &small_data).unwrap();

        writer.emit_flush_commit(2, uncompressed_len + 8, &clock).unwrap();
        writer.flush().unwrap();
        drop(writer);

        // Level 0: verify summary table and dedicated compression line
        let v0_dump = dump_log_file(storage.as_ref(), "000001.log", 0, None).unwrap();
        assert!(v0_dump.contains("--- Record Breakdown by OpCode ---"));
        assert!(v0_dump.contains("DataZstd"));
        assert!(v0_dump.contains("DataZstd Compression:"));
        assert!(v0_dump.contains("saved"));

        // Level 1: verify sequential stream has per-record savings for DataZstd
        let v1_dump = dump_log_file(storage.as_ref(), "000001.log", 1, None).unwrap();
        assert!(v1_dump.contains("DataZstd"));
        assert!(v1_dump.contains("(saved "));
        // Data record should not show (saved ...)
        assert!(v1_dump.contains("data_len: 8 B\n"));

        // Level 2: verify sequential stream with hex dump has decompressed data
        let v2_dump = dump_log_file(storage.as_ref(), "000001.log", 2, None).unwrap();
        assert!(v2_dump.contains("Hello compressio"));
    }

    #[test]
    fn test_dump_log_file_compression_encrypted_without_key() {
        use crate::crypto::{KeySource, MasterKey, VolumeHeader};

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;

        let master = MasterKey::new([0x33u8; 32]);
        let (_header, vol_key) = VolumeHeader::new_encrypted(
            &master,
            [0x11u8; 16],
            KeySource::KeyFile,
            crate::compress::Compression::Zstd,
        )
        .unwrap();

        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            Arc::new(vol_key.clone()),
        )
        .unwrap()
        .with_compression(crate::compress::Compression::Zstd);

        let compressible_data = "Repeating encrypted log data line. ".repeat(300).into_bytes();
        writer.append_record(OpCode::Data, 2, &compressible_data).unwrap();
        writer
            .emit_flush_commit(1, compressible_data.len() as u64, &clock)
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        // Keyless dump: should recognize encrypted DataZstd and report key needed for savings
        let keyless_dump = dump_log_file(storage.as_ref(), "000001.log", 0, None).unwrap();
        assert!(
            keyless_dump.contains("DataZstd Compression: 1 records encrypted (unlock with volume key to view savings)")
        );

        // Dump with key: should show actual savings
        let unlocked_dump = dump_log_file(storage.as_ref(), "000001.log", 0, Some(&vol_key)).unwrap();
        assert!(unlocked_dump.contains("DataZstd Compression:"));
        assert!(unlocked_dump.contains("saved"));
        assert!(!unlocked_dump.contains("encrypted (unlock with volume key"));

        // Level 2 dump with key: should decrypt, decompress, and hex dump
        let v2_unlocked = dump_log_file(storage.as_ref(), "000001.log", 2, Some(&vol_key)).unwrap();
        assert!(v2_unlocked.contains("Repeating encryp"));
    }
}
