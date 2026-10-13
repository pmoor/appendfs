use crate::crypto::VolumeKey;
use crate::log::ExtentState;
use crate::log::record::{
    FILE_HEADER_SIZE, FileHeader, LogAttrDelta, LogEntryDelta, LogExtent, LogNodeDelta, OpCode, RECORD_HEADER_SIZE,
    RecordHeader,
};
use crate::log::summary::{SUMMARY_MAGIC, SummaryReader};
use crate::node::NodeKind;
use crate::storage::{Storage, StorageReader};
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

pub use crate::stats::{ExtentsBucket, HistogramBucket};
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
        WriteBucket::new("[0, 64 B]", 0, 64),
        WriteBucket::new("(64 B, 512 B]", 65, 512),
        WriteBucket::new("(512 B, 4 KiB]", 513, 4096),
        WriteBucket::new("(4 KiB, 16 KiB]", 4097, 16384),
        WriteBucket::new("(16 KiB, 64 KiB]", 16385, 65536),
        WriteBucket::new("(64 KiB, 256 KiB]", 65537, 262144),
        WriteBucket::new("(256 KiB, 512 KiB]", 262145, 524288),
        WriteBucket::new("(512 KiB, 1 MiB]", 524289, 1048576),
        WriteBucket::new("(1 MiB, 2 MiB]", 1048577, 2097152),
        WriteBucket::new("(2 MiB, 3 MiB]", 2097153, 3145728),
        WriteBucket::new("(3 MiB, 4 MiB]", 3145729, 4194304),
        WriteBucket::new("> 4 MiB", 4194305, u64::MAX),
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
            match key.log_file_key(&file_header.key_salt).decrypt_record(
                header.sequence,
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
    writeln!(out, "Key Salt:            {}", hex::encode(file_header.key_salt)).unwrap();
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
        "{:<14} {:>10} {:>12} {:>14} {:>12}",
        "OP CODE", "COUNT", "% OF RECORDS", "TOTAL BYTES", "% OF BYTES"
    )
    .unwrap();
    writeln!(out, "{:-<14} {:-<10} {:-<12} {:-<14} {:-<12}", "", "", "", "", "").unwrap();

    let total_valid = records
        .iter()
        .filter(|r| matches!(r, DumpRecordEntry::Valid { .. }))
        .count();
    let total_payload_bytes: u64 = op_counts.iter().map(|s| s.payload_bytes).sum();

    for code in 1..=5u8 {
        if let Ok(opcode) = OpCode::try_from(code) {
            let stats = &op_counts[code as usize];
            let rec_pct = if total_valid > 0 {
                stats.count as f64 / total_valid as f64 * 100.0
            } else {
                0.0
            };
            let byte_pct = if total_payload_bytes > 0 {
                stats.payload_bytes as f64 / total_payload_bytes as f64 * 100.0
            } else {
                0.0
            };
            let rec_pct_str = format!("{:.1}%", rec_pct);
            let byte_pct_str = format!("{:.1}%", byte_pct);
            writeln!(
                out,
                "{:<14} {:>10} {:>12} {:>14} {:>12}",
                opcode,
                stats.count,
                rec_pct_str,
                format_bytes(stats.payload_bytes),
                byte_pct_str
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
            "{:<20} {:>8} {:>14}   DISTRIBUTION",
            "SIZE RANGE", "COUNT", "TOTAL BYTES"
        )
        .unwrap();
        writeln!(out, "{:-<20} {:-<8} {:-<14}   {:-<20}", "", "", "", "").unwrap();

        for b in &write_buckets {
            let pct = (b.count as f64 / total_writes as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            writeln!(
                out,
                "{:<20} {:>8} {:>14}   {:<20} ({:.1}%)",
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
                        "#{:<5} [0x{:08x} / {:<8}] {:<14} inode {:<5} seq {:<5} len {:<8} tag {:02x}{:02x}{:02x}{:02x} {}",
                        i + 1,
                        offset,
                        offset,
                        header.op_code,
                        header.inode,
                        header.sequence,
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
/// - `verbosity == 0`: Summary metadata, whole-file checksum, inode breakdown, extent fragmentation stats, histogram, top files by extent count, top fragmented files, manifest table.
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

    // Checksum display
    let checksum_hex = reader
        .footer
        .checksum
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    writeln!(out, "Checksum (BLAKE3):   {} (VERIFIED)", checksum_hex).unwrap();
    writeln!(out).unwrap();

    out.push_str(&crate::stats::format_volume_content_report(&inodes, &reader.manifest));

    // Verbose Level 1: Inode Tree / Details
    if verbosity >= 1 {
        let mut sorted_inodes: Vec<u64> = inodes.keys().copied().collect();
        sorted_inodes.sort_unstable();
        let path_map = crate::stats::build_path_map(&inodes);

        writeln!(out).unwrap();
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
    match *ext {
        LogExtent::Disk {
            file_offset,
            record_log_offset,
            length,
            ..
        } => format!(
            "[0x{:x}..0x{:x} ({}) -> log offset 0x{:08x}]",
            file_offset,
            file_offset.saturating_add(length as u64),
            format_bytes(length as u64),
            record_log_offset
        ),
        LogExtent::Zero { file_offset, length } => format!(
            "[0x{:x}..0x{:x} ({}) -> hole]",
            file_offset,
            file_offset.saturating_add(length),
            format_bytes(length)
        ),
        LogExtent::Ref {
            file_offset,
            generation,
            record_log_offset,
            payload_offset,
            length,
            ..
        } => format!(
            "[0x{:x}..0x{:x} ({}) -> gen {} log offset 0x{:08x} +0x{:x}]",
            file_offset,
            file_offset.saturating_add(length as u64),
            format_bytes(length as u64),
            generation,
            record_log_offset,
            payload_offset
        ),
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
    use crate::test_utils::TestFs;
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
            Arc::new(clock),
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
        writer.append_serialized(OpCode::InodeDelta, 1, &dir_delta).unwrap();

        // Write Data record with 100 bytes
        let data_bytes = vec![0x42; 100];
        writer.append_data(2, &data_bytes).unwrap();

        // Commit batch
        writer.emit_flush_commit(2, 100, clock.now()).unwrap();
        writer.flush().unwrap();
        drop(writer);

        assert!(storage.exists("000001.log"));

        // Level 0: Summary
        let summary_dump = dump_log_file(storage.as_ref(), "000001.log", 0, None).unwrap();
        assert!(summary_dump.contains("Total Valid Records: 3"));
        assert!(summary_dump.contains("Committed Flushes:   1"));
        assert!(summary_dump.contains("Trailing Batch:      None"));
        assert!(summary_dump.contains("Data"));
        assert!(summary_dump.contains("(64 B, 512 B]"));

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
            Arc::new(clock),
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
        writer.append_serialized(OpCode::InodeDelta, 1, &dir_delta).unwrap();
        drop(writer);

        let dump = dump_log_file(storage.as_ref(), "000001.log", 1, None).unwrap();
        assert!(dump.contains("Trailing Batch:      1 UNCOMMITTED records"));
        assert!(dump.contains("[UNCOMMITTED TRAILING BATCH]"));
    }

    #[test]
    fn test_dump_summary_file_summary_and_verbosity_levels() {
        use crate::extent_map::{Extent, ExtentMap};
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
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        assert!(storage.exists("000000.summary"));

        // Level 0: Summary
        let dump_v0 = dump_file(storage.as_ref(), "000000.summary", 0, None).unwrap();
        assert!(dump_v0.contains("=== appendfs Summary File Dump ==="));
        assert!(dump_v0.contains("Total Inodes:        1 (1 directories, 0 regular files, 0 symlinks)"));
        assert!(dump_v0.contains("Checksum (BLAKE3):"));
        assert!(dump_v0.contains("VERIFIED"));

        // Create an AppendFs with fragmented files
        let fs = TestFs::builder().build().fs;
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
                    version: 1,
                    generation: 1,
                    revision: 0,
                    filename: "000001.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                    md5: [1u8; 16],
                    sealed_at: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(10)),
                },
                crate::log::LogFileInfo {
                    version: 1,
                    generation: 2,
                    revision: 0,
                    filename: "000002.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                    md5: [2u8; 16],
                    sealed_at: None,
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
        assert!(dump_snap_v0.contains("--- File Extension Breakdown ---"));
        assert!(dump_snap_v0.contains(".bin                            1       100.0%       8.00 KiB       100.0%"));
        assert!(dump_snap_v0.contains("--- Top Files by Extent Count ---"));
        assert!(!dump_snap_v0.contains("--- Top Fragmented Files (< 1 MiB Avg Extent) ---"));
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
                LogExtent::Disk {
                    file_offset: 0,
                    record_log_offset: 28,
                    record_size: 4124,
                    length: 4096,
                },
                LogExtent::Zero {
                    file_offset: 4096,
                    length: 8192,
                },
                LogExtent::Ref {
                    file_offset: 12288,
                    generation: 3,
                    record_log_offset: 0x2a,
                    record_size: 4124,
                    payload_offset: 0x100,
                    length: 1024,
                },
            ],
            size: Some(13312),
            attr_delta: LogAttrDelta::default(),
        }));

        let formatted = format_log_entry_delta(&delta);
        assert_eq!(
            formatted,
            "File { extents: [[0x0..0x1000 (4.00 KiB) -> log offset 0x0000001c], [0x1000..0x3000 (8.00 KiB) -> hole], [0x3000..0x3400 (1.00 KiB) -> gen 3 log offset 0x0000002a +0x100]], size: 13312 (13.00 KiB) }"
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
            Arc::new(clock),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap()
        .with_compression(crate::compress::Compression::Zstd);

        // Highly compressible payload: 16 KiB of repeating text
        let compressible_data = "Hello compression savings test! ".repeat(512).into_bytes();
        let uncompressed_len = compressible_data.len() as u64;
        writer.append_data(2, &compressible_data).unwrap();

        // Small / incompressible payload that stays OpCode::Data
        let small_data = vec![0x42; 8];
        writer.append_data(3, &small_data).unwrap();

        writer.emit_flush_commit(2, uncompressed_len + 8, clock.now()).unwrap();
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
        use crate::crypto::{MasterKey, VolumeHeader};

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;

        let master = MasterKey::new([0x33u8; 32]);
        let (_header, vol_key) = VolumeHeader::new_encrypted(&master, crate::compress::Compression::Zstd).unwrap();

        let writer = LogWriter::create(
            storage.clone(),
            1,
            Arc::new(clock),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            Arc::new(vol_key.clone()),
        )
        .unwrap()
        .with_compression(crate::compress::Compression::Zstd);

        let compressible_data = "Repeating encrypted log data line. ".repeat(300).into_bytes();
        writer.append_data(2, &compressible_data).unwrap();
        writer
            .emit_flush_commit(1, compressible_data.len() as u64, clock.now())
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

    #[test]
    fn test_dump_log_file_breakdown_table_percentages() {
        use crate::log::record::{LogAttrDelta, LogDirectoryDelta, LogEntryDelta, LogNodeDelta};

        let dir = tempdir().unwrap();
        let storage = Arc::new(OsStorage::new(dir.path()));
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            Arc::new(clock),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
            parent: Some(1),
            added: vec![("a.txt".to_string(), 2)],
            removed: vec![],
            attr_delta: LogAttrDelta::default(),
        }));
        let (_, _, delta_rec_size) = writer.append_serialized(OpCode::InodeDelta, 1, &dir_delta).unwrap();
        let delta_len = (delta_rec_size - crate::log::record::RECORD_HEADER_SIZE as u32) as u64;

        let data_bytes = vec![0xAB; 200];
        writer.append_data(2, &data_bytes).unwrap();

        writer.emit_flush_commit(2, 200, clock.now()).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let dump = dump_log_file(storage.as_ref(), "000001.log", 0, None).unwrap();

        assert!(dump.contains("OP CODE             COUNT % OF RECORDS    TOTAL BYTES   % OF BYTES"));
        assert!(dump.contains("-------------- ---------- ------------ -------------- ------------"));

        let total_bytes = delta_len + 200 + 24;
        let data_byte_pct = (200.0 / total_bytes as f64) * 100.0;
        let delta_byte_pct = (delta_len as f64 / total_bytes as f64) * 100.0;
        let commit_byte_pct = (24.0 / total_bytes as f64) * 100.0;

        assert!(dump.contains(&format!(
            "{:<14} {:>10} {:>12} {:>14} {:>12}",
            "Data",
            1,
            "33.3%",
            "200 B",
            format!("{:.1}%", data_byte_pct)
        )));
        assert!(dump.contains(&format!(
            "{:<14} {:>10} {:>12} {:>14} {:>12}",
            "InodeDelta",
            1,
            "33.3%",
            format_bytes(delta_len),
            format!("{:.1}%", delta_byte_pct)
        )));
        assert!(dump.contains(&format!(
            "{:<14} {:>10} {:>12} {:>14} {:>12}",
            "FlushCommit",
            1,
            "33.3%",
            "24 B",
            format!("{:.1}%", commit_byte_pct)
        )));
        assert!(dump.contains(&format!(
            "{:<14} {:>10} {:>12} {:>14} {:>12}",
            "Seal", 0, "0.0%", "0 B", "0.0%"
        )));
    }

    #[test]
    fn test_write_payload_size_histogram_bucket_ranges() {
        let buckets = vec![
            WriteBucket::new("[0, 64 B]", 0, 64),
            WriteBucket::new("(64 B, 512 B]", 65, 512),
            WriteBucket::new("(512 B, 4 KiB]", 513, 4096),
            WriteBucket::new("(4 KiB, 16 KiB]", 4097, 16384),
            WriteBucket::new("(16 KiB, 64 KiB]", 16385, 65536),
            WriteBucket::new("(64 KiB, 256 KiB]", 65537, 262144),
            WriteBucket::new("(256 KiB, 512 KiB]", 262145, 524288),
            WriteBucket::new("(512 KiB, 1 MiB]", 524289, 1048576),
            WriteBucket::new("(1 MiB, 2 MiB]", 1048577, 2097152),
            WriteBucket::new("(2 MiB, 3 MiB]", 2097153, 3145728),
            WriteBucket::new("(3 MiB, 4 MiB]", 3145729, 4194304),
            WriteBucket::new("> 4 MiB", 4194305, u64::MAX),
        ];

        let find_bucket = |size: u64| -> &'static str { buckets.iter().find(|b| b.matches(size)).unwrap().label };

        assert_eq!(find_bucket(0), "[0, 64 B]");
        assert_eq!(find_bucket(64), "[0, 64 B]");
        assert_eq!(find_bucket(65), "(64 B, 512 B]");
        assert_eq!(find_bucket(512), "(64 B, 512 B]");
        assert_eq!(find_bucket(513), "(512 B, 4 KiB]");
        assert_eq!(find_bucket(4096), "(512 B, 4 KiB]");
        assert_eq!(find_bucket(4097), "(4 KiB, 16 KiB]");
        assert_eq!(find_bucket(16384), "(4 KiB, 16 KiB]");
        assert_eq!(find_bucket(16385), "(16 KiB, 64 KiB]");
        assert_eq!(find_bucket(65536), "(16 KiB, 64 KiB]");
        assert_eq!(find_bucket(65537), "(64 KiB, 256 KiB]");
        assert_eq!(find_bucket(262144), "(64 KiB, 256 KiB]");
        assert_eq!(find_bucket(262145), "(256 KiB, 512 KiB]");
        assert_eq!(find_bucket(524288), "(256 KiB, 512 KiB]");
        assert_eq!(find_bucket(524289), "(512 KiB, 1 MiB]");
        assert_eq!(find_bucket(1048576), "(512 KiB, 1 MiB]");
        assert_eq!(find_bucket(1048577), "(1 MiB, 2 MiB]");
        assert_eq!(find_bucket(2097152), "(1 MiB, 2 MiB]");
        assert_eq!(find_bucket(2097153), "(2 MiB, 3 MiB]");
        assert_eq!(find_bucket(3145728), "(2 MiB, 3 MiB]");
        assert_eq!(find_bucket(3145729), "(3 MiB, 4 MiB]");
        assert_eq!(find_bucket(4194304), "(3 MiB, 4 MiB]");
        assert_eq!(find_bucket(4194305), "> 4 MiB");
        assert_eq!(find_bucket(10 * 1024 * 1024), "> 4 MiB");
    }
}
