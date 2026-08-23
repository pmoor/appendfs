use crate::crypto::VolumeKey;
use crate::fs::InMemoryFS;
use crate::log::SharedExtentState;
use crate::node::{Node, NodeKind};
use crate::range_map::RangeMap;
use crate::storage::{Storage, StorageReader, WriteMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

// 28 bytes (manifest_offset + index_offset + entry_count + magic) + 32-byte BLAKE3 checksum.
pub const SUMMARY_FOOTER_SIZE: usize = 60;
pub const SUMMARY_INDEX_ENTRY_SIZE: usize = 16;
pub const SUMMARY_MAGIC: &[u8; 4] = b"APPS";
// Bumped to 8: SummaryHeader dropped its redundant `cipher` and `key_id` bytes (shrinking it
// from 62 to SUMMARY_HEADER_SIZE) and LogManifest no longer carries the volume header. Every
// one of these layouts deserializes from the others' bytes without erroring, so this version
// check is the only thing standing between an older volume and being silently misread.
pub const CURRENT_SUMMARY_VERSION: u32 = 8;
pub const SUMMARY_HEADER_SIZE: usize = 60;

/// Fixed-size header written at offset 0 of `{:06}.summary`, exactly `SUMMARY_HEADER_SIZE`
/// bytes - readers seek past it by that constant, so the two must agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u64,
    pub last_tx_id: u64,
    pub next_inode: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: std::time::SystemTime,
    /// IV for the encrypted body. Zero when `volume_header_len` is 0.
    pub iv: [u8; 12],
    /// Length of the plaintext VolumeHeader blob that follows this header; 0 means the
    /// volume is unencrypted. This is the sole in-file marker - the `cipher` and `key_id`
    /// bytes that used to sit here merely restated what the volume header already says, and
    /// every unauthenticated restatement is somewhere a reader might branch wrongly.
    pub volume_header_len: u32,
}

impl SummaryHeader {
    pub fn new(
        generation: u64,
        last_tx_id: u64,
        next_inode: u64,
        created_at: std::time::SystemTime,
        iv: [u8; 12],
        volume_header_len: u32,
    ) -> Self {
        Self {
            magic: *SUMMARY_MAGIC,
            version: CURRENT_SUMMARY_VERSION,
            generation,
            last_tx_id,
            next_inode,
            created_at,
            iv,
            volume_header_len,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryHeader serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let header: Self = bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if header.magic != *SUMMARY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not an appendfs summary file (bad magic {:?})", header.magic),
            ));
        }
        if header.version != CURRENT_SUMMARY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported summary format version {} (this build writes and reads version {})",
                    header.version, CURRENT_SUMMARY_VERSION
                ),
            ));
        }
        Ok(header)
    }
}

/// Footer written at EOF (last `SUMMARY_FOOTER_SIZE` bytes) of `{:06}.summary`.
///
/// `checksum` is a full (untruncated) BLAKE3 hash of everything in the file *before*
/// the footer - the header, every inode record, the manifest, and the index array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryFooter {
    pub manifest_offset: u64,
    pub index_offset: u64,
    pub entry_count: u64,
    pub magic: [u8; 4],
    pub checksum: [u8; 32],
}

impl SummaryFooter {
    pub fn new(manifest_offset: u64, index_offset: u64, entry_count: u64, checksum: [u8; 32]) -> Self {
        Self {
            manifest_offset,
            index_offset,
            entry_count,
            magic: *SUMMARY_MAGIC,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryFooter serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Fixed 16-byte index entry mapping `inode -> byte_offset` in the `.summary` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryIndexEntry {
    pub inode: u64,
    pub offset: u64,
}

impl SummaryIndexEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryIndexEntry serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Where a summary body accumulates while it is being built.
///
/// The two cases differ only in destination, not in content. An unencrypted body streams
/// straight to the file; an encrypted one has to be buffered, because ChaCha20-Poly1305
/// authenticates the body as a single message and its tag is not known until the last byte
/// is in. Reads do not gain from streaming that: `SummaryReader` materialises the whole
/// decrypted body anyway, since `read_inode` seeks into it by offset.
enum BodySink<'a> {
    /// Streams to the file, hashing as it goes. Offsets are absolute file positions, which
    /// is what the unencrypted reader seeks by.
    Direct {
        writer: &'a mut Box<dyn crate::storage::StorageWriter>,
        hasher: &'a mut blake3::Hasher,
        offset: u64,
    },
    /// Accumulates in memory to be sealed in one go. Offsets are relative to the body start,
    /// which is what the encrypted reader indexes the decrypted buffer by.
    Buffered(&'a mut Vec<u8>),
}

impl BodySink<'_> {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            BodySink::Direct { writer, hasher, offset } => {
                writer.append(bytes)?;
                hasher.update(bytes);
                *offset += bytes.len() as u64;
                Ok(())
            }
            BodySink::Buffered(buf) => {
                buf.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    /// The offset the next byte will occupy, in whichever coordinate space this sink's
    /// reader will later use.
    fn offset(&self) -> u64 {
        match self {
            BodySink::Direct { offset, .. } => *offset,
            BodySink::Buffered(buf) => buf.len() as u64,
        }
    }
}

/// Serializes every inode, then the manifest, then the index, into `sink`.
///
/// Returns `(manifest_offset, index_offset, entry_count)` for the footer.
fn write_summary_body(
    sink: &mut BodySink<'_>,
    inodes: &[(u64, Arc<Node>)],
    manifest: &crate::log::LogManifest,
) -> io::Result<(u64, u64, u64)> {
    let mut index_entries = Vec::with_capacity(inodes.len());

    for (inode, node_arc) in inodes {
        let mut node_to_serialize = node_arc.as_ref().clone();
        match node_to_serialize.kind {
            NodeKind::Directory { ref mut entries, .. } => entries.sort_by(|a, b| a.0.cmp(&b.0)),
            NodeKind::File { ref mut range_map, .. } => *range_map = coalesce_extents(range_map),
            _ => {}
        }

        let payload =
            bincode::serialize(&node_to_serialize).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        index_entries.push(SummaryIndexEntry {
            inode: *inode,
            offset: sink.offset(),
        });

        sink.append(&inode.to_le_bytes())?;
        sink.append(&(payload.len() as u32).to_le_bytes())?;
        sink.append(&payload)?;
    }

    let manifest_offset = sink.offset();
    let manifest_bytes = bincode::serialize(manifest).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    sink.append(&(manifest_bytes.len() as u32).to_le_bytes())?;
    sink.append(&manifest_bytes)?;

    index_entries.sort_by_key(|entry| entry.inode);
    let index_offset = sink.offset();
    for entry in &index_entries {
        sink.append(&entry.to_bytes())?;
    }

    Ok((manifest_offset, index_offset, index_entries.len() as u64))
}

/// Merges adjacent extents that are physically contiguous in the same log record, so a
/// sequential write reloads as one extent rather than one per flush chunk.
fn coalesce_extents(range_map: &RangeMap<SharedExtentState>) -> RangeMap<SharedExtentState> {
    let entries: Vec<(u64, u64, SharedExtentState)> = range_map
        .iter()
        .map(|(start, e)| (*start, e.length, e.value.clone()))
        .collect();

    let mut coalesced = RangeMap::new();
    let mut current: Option<(u64, u64, SharedExtentState)> = None;

    for (start, len, state) in entries {
        if let Some((cur_start, cur_len, cur_state)) = current.take() {
            let mut merged = false;
            if cur_start + cur_len == start
                && let (
                    crate::log::ExtentState::Disk {
                        generation: g1,
                        record_log_offset: r1,
                        payload_offset: p1,
                        length: _,
                    },
                    crate::log::ExtentState::Disk {
                        generation: g2,
                        record_log_offset: r2,
                        payload_offset: p2,
                        length: _,
                    },
                ) = (cur_state.read_state(), state.read_state())
                && g1 == g2
                && r1 == r2
                && p1 as u64 + cur_len == p2 as u64
            {
                current = Some((
                    cur_start,
                    cur_len + len,
                    SharedExtentState::new_disk(g1, r1, p1, (cur_len + len) as u32),
                ));
                merged = true;
            }
            if !merged {
                coalesced.insert(cur_start, cur_len, cur_state);
                current = Some((start, len, state));
            }
        } else {
            current = Some((start, len, state));
        }
    }

    if let Some((cur_start, cur_len, cur_state)) = current {
        coalesced.insert(cur_start, cur_len, cur_state);
    }

    coalesced
}

/// Everything that goes into one summary snapshot.
///
/// Grouped into a struct rather than passed positionally: the eight-argument version needed
/// `#[allow(clippy::too_many_arguments)]`, and suppressing that lint is what made squeezing
/// the volume header through the `LogManifest` look preferable to adding a ninth parameter.
pub struct SummarySnapshot<'a> {
    pub inodes: &'a HashMap<u64, Arc<Node>>,
    pub manifest: &'a crate::log::LogManifest,
    /// Volume identity and key-check material, written unencrypted ahead of the body.
    pub volume_header: &'a crate::crypto::VolumeHeader,
    pub generation: u64,
    pub last_tx_id: u64,
    pub next_inode: u64,
    pub created_at: std::time::SystemTime,
}

/// Exports a single-file summary snapshot to a `Storage` instance.
///
/// When `volume_key` carries a real cipher the inode body is written encrypted; a plaintext
/// key writes the body as-is. The volume header is always written unencrypted, ahead of the
/// body, so a reader can identify the volume and check a key before decrypting anything.
pub fn export_summary(
    snapshot: &SummarySnapshot<'_>,
    storage: &dyn Storage,
    volume_key: &VolumeKey,
) -> io::Result<String> {
    let SummarySnapshot {
        inodes,
        manifest,
        volume_header,
        generation,
        last_tx_id,
        next_inode,
        created_at,
    } = *snapshot;
    let mut inodes_snapshot: Vec<(u64, Arc<Node>)> = inodes.iter().map(|(ino, arc)| (*ino, Arc::clone(arc))).collect();
    // Sort by inode so physical serialization order is deterministic
    inodes_snapshot.sort_by_key(|(ino, _)| *ino);

    let filename = format!("{:06}.summary", generation);
    let tmp_filename = format!("{:06}.summary.tmp", generation);

    let mut writer = storage.open_writer(&tmp_filename, WriteMode::Overwrite)?;
    let mut hasher = blake3::Hasher::new();

    let is_encrypted = volume_key.cipher().is_encrypted();
    let iv = if is_encrypted {
        crate::crypto::generate_random_iv()
    } else {
        [0u8; 12]
    };
    let volume_header_bytes = if is_encrypted {
        bincode::serialize(volume_header).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    } else {
        Vec::new()
    };

    let header = SummaryHeader::new(
        generation,
        last_tx_id,
        next_inode,
        created_at,
        iv,
        volume_header_bytes.len() as u32,
    );
    let header_bytes = header.to_bytes();
    writer.append(&header_bytes)?;
    hasher.update(&header_bytes);

    if !volume_header_bytes.is_empty() {
        writer.append(&volume_header_bytes)?;
        hasher.update(&volume_header_bytes);
    }

    // One pass builds the body; where those bytes land is the only difference between an
    // encrypted and an unencrypted summary. Previously each case had its own copy of this
    // loop - 84% identical, including the whole extent-coalescing walk - so a fix to the
    // subtle part had to be made twice or silently applied to only one kind of volume.
    let mut buffered = is_encrypted.then(Vec::new);
    let body_base = (header_bytes.len() + volume_header_bytes.len()) as u64;

    let (manifest_offset, index_offset, entry_count) = {
        let mut sink = match buffered {
            Some(ref mut buf) => BodySink::Buffered(buf),
            None => BodySink::Direct {
                writer: &mut writer,
                hasher: &mut hasher,
                offset: body_base,
            },
        };
        write_summary_body(&mut sink, &inodes_snapshot, manifest)?
    };

    // An encrypted body is sealed as a single AEAD message, so it can only be written once
    // the last byte is known.
    if let Some(body) = buffered {
        let ciphertext = volume_key
            .encrypt_summary(&iv, &header_bytes, &body)
            .map_err(io::Error::other)?;
        writer.append(&ciphertext)?;
        hasher.update(&ciphertext);
    }

    let checksum: [u8; 32] = *hasher.finalize().as_bytes();
    let footer = SummaryFooter::new(manifest_offset, index_offset, entry_count, checksum);
    writer.append(&footer.to_bytes())?;

    writer.sync()?;
    drop(writer);

    storage.rename(&tmp_filename, &filename)?;

    log::info!(
        "Exported single-file summary snapshot {} (generation: {}, inodes: {}, last_tx_id: {})",
        filename,
        generation,
        inodes_snapshot.len(),
        last_tx_id
    );

    Ok(filename)
}

/// Initializes a fresh, empty appendfs volume on a `Storage` instance.
/// Creates `000000.summary` containing the root directory (inode 1) and an initial LogManifest.
pub fn init_volume(
    storage: Arc<dyn Storage>,
    branch: Option<&str>,
    volume_key: &VolumeKey,
    volume_header: crate::crypto::VolumeHeader,
) -> io::Result<String> {
    let files = storage.list_files()?;
    for file in files {
        if file.ends_with(".summary") || file.ends_with(".log") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Volume already initialized (found existing file {})", file),
            ));
        }
    }

    let fs = InMemoryFS::new();
    let snapshot = fs.snapshot_all();
    let branch_name = branch.unwrap_or("main");
    let manifest = crate::log::LogManifest {
        branch: branch_name.to_string(),
        logs: Vec::new(),
        next_generation: 1,
        next_filename: "000001.log".to_string(),
    };

    export_summary(
        &SummarySnapshot {
            inodes: &snapshot,
            manifest: &manifest,
            volume_header: &volume_header,
            generation: 0,
            last_tx_id: 0,
            next_inode: 2,
            created_at: std::time::SystemTime::now(),
        },
        storage.as_ref(),
        volume_key,
    )
}

/// Reader for single-file `{:06}.summary` snapshot files.
pub struct SummaryReader {
    reader: Arc<dyn StorageReader>,
    pub header: SummaryHeader,
    pub footer: SummaryFooter,
    pub manifest: crate::log::LogManifest,
    /// Parsed from the plaintext blob, so callers get volume identity without a second read.
    pub volume_header: crate::crypto::VolumeHeader,
    index_entries: Vec<SummaryIndexEntry>,
    decrypted_body: Option<Vec<u8>>,
    pub volume_key: Arc<VolumeKey>,
}

/// Slices `body`, returning a clean error rather than panicking when the range is out of
/// bounds.
///
/// Offsets in the footer are attacker-controllable: the footer's BLAKE3 checksum carries no
/// key, so anyone able to rewrite the file can recompute it. Indexing the decrypted body
/// with them directly turns a tampered summary into a panic instead of an error.
fn body_slice<'a>(body: &'a [u8], start: u64, len: u64, what: &str) -> io::Result<&'a [u8]> {
    let range = usize::try_from(start)
        .ok()
        .zip(start.checked_add(len).and_then(|end| usize::try_from(end).ok()))
        .and_then(|(start, end)| body.get(start..end));

    range.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary {} at {}..+{} lies outside the {}-byte body",
                what,
                start,
                len,
                body.len()
            ),
        )
    })
}

/// Reads the plaintext VolumeHeader blob that follows a summary header.
///
/// Shared by [`SummaryReader::read_volume_header`], which identifies a volume before any key
/// exists, and [`SummaryReader::open`], which needs the same value once one does.
fn parse_volume_header_blob(
    reader: &dyn StorageReader,
    header: &SummaryHeader,
) -> io::Result<crate::crypto::VolumeHeader> {
    if header.volume_header_len == 0 {
        return Ok(crate::crypto::VolumeHeader::plaintext());
    }

    // Bound the declared length by the file before allocating: this value is read straight
    // off disk, so a forged one would otherwise size a multi-gigabyte buffer that is only
    // discovered to be wrong once the read fails.
    let file_len = reader.len()?;
    if header.volume_header_len as u64 > file_len.saturating_sub(SUMMARY_HEADER_SIZE as u64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary declares a {}-byte volume header, more than its {} bytes can hold",
                header.volume_header_len, file_len
            ),
        ));
    }

    let mut buf = vec![0u8; header.volume_header_len as usize];
    reader.read_exact_at(SUMMARY_HEADER_SIZE as u64, &mut buf)?;
    bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl SummaryReader {
    /// Reads the VolumeHeader metadata from a summary file without requiring full body decryption.
    pub fn read_volume_header(storage: &dyn Storage, filename: &str) -> io::Result<crate::crypto::VolumeHeader> {
        let reader = storage.open_reader(filename)?;
        if reader.len()? < SUMMARY_HEADER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("summary file {} is too short", filename),
            ));
        }

        let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;
        let header = SummaryHeader::from_bytes(&header_buf)?;

        parse_volume_header_blob(reader.as_ref(), &header)
    }

    /// Opens a `.summary` file from a `Storage` instance.
    pub fn open(storage: &dyn Storage, filename: &str, volume_key: Arc<VolumeKey>) -> io::Result<Self> {
        let reader = storage.open_reader(filename)?;
        let file_len = reader.len()?;

        if file_len < (SUMMARY_HEADER_SIZE + SUMMARY_FOOTER_SIZE) as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("summary file {} is too short ({} bytes)", filename, file_len),
            ));
        }

        // 1. Read SummaryHeader at offset 0
        let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;
        let header = SummaryHeader::from_bytes(&header_buf)?;

        // 1b. Parse the plaintext volume header blob, if any.
        let volume_header = parse_volume_header_blob(reader.as_ref(), &header)?;

        // The volume says how it is encrypted and the caller supplies a key; if those
        // disagree, decide nothing and say so. Routing purely on the key would read an
        // encrypted body as plaintext (garbage, reported as corruption), and routing purely
        // on the file would trust an unauthenticated byte. Requiring agreement means a
        // flipped `cipher` is *detected* rather than either trusted or silently ignored.
        if volume_header.cipher != volume_key.cipher() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "summary file {} is a {} volume but the supplied key is for {}",
                    filename,
                    volume_header.cipher,
                    volume_key.cipher()
                ),
            ));
        }

        // 2. Read SummaryFooter at EOF
        let footer_offset = file_len - SUMMARY_FOOTER_SIZE as u64;
        let mut footer_buf = [0u8; SUMMARY_FOOTER_SIZE];
        reader.read_exact_at(footer_offset, &mut footer_buf)?;
        let footer = SummaryFooter::from_bytes(&footer_buf)?;

        // 3. Verify the whole-file checksum before trusting anything in this summary
        let content_len = file_len.saturating_sub(SUMMARY_FOOTER_SIZE as u64);
        let mut hasher = blake3::Hasher::new();
        let mut offset = 0u64;
        let mut buf = [0u8; 8192];
        while offset < content_len {
            let chunk = std::cmp::min(content_len - offset, buf.len() as u64) as usize;
            reader.read_exact_at(offset, &mut buf[..chunk])?;
            hasher.update(&buf[..chunk]);
            offset += chunk as u64;
        }

        if hasher.finalize().as_bytes() != &footer.checksum {
            panic!(
                "summary checksum mismatch in {}: this data has been corrupted (possible bitrot)",
                filename
            );
        }

        // `entry_count` also comes from the rewritable footer, and it sizes allocations on
        // both paths. Bound it by what the file could possibly hold before trusting it, or a
        // forged count aborts the process on an oversized allocation.
        footer
            .entry_count
            .checked_mul(SUMMARY_INDEX_ENTRY_SIZE as u64)
            .filter(|bytes| *bytes <= content_len)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "summary file {} claims {} index entries, more than its {} bytes can hold",
                        filename, footer.entry_count, content_len
                    ),
                )
            })?;

        // Which branch to take is decided by the key we hold, not by the summary's own
        // `cipher` byte. That byte is covered only by the footer's BLAKE3 checksum, which
        // carries no key and can simply be recomputed after an edit; the key's cipher comes
        // from the verified key check value. Trusting the file here would let a cleared
        // byte route an encrypted body down the plaintext path, skipping the AEAD.
        if !volume_key.cipher().is_encrypted() {
            // 4. Read LogManifest from manifest_offset
            let mut manifest_len_buf = [0u8; 4];
            reader.read_exact_at(footer.manifest_offset, &mut manifest_len_buf)?;
            let manifest_len = u32::from_le_bytes(manifest_len_buf) as usize;
            let mut manifest_buf = vec![0u8; manifest_len];
            reader.read_exact_at(footer.manifest_offset + 4, &mut manifest_buf)?;
            let manifest: crate::log::LogManifest =
                bincode::deserialize(&manifest_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // 5. Read index array from index_offset
            let mut index_entries = Vec::with_capacity(footer.entry_count as usize);
            let mut index_read_offset = footer.index_offset;
            for _ in 0..footer.entry_count {
                let mut entry_buf = [0u8; SUMMARY_INDEX_ENTRY_SIZE];
                reader.read_exact_at(index_read_offset, &mut entry_buf)?;
                index_entries.push(SummaryIndexEntry::from_bytes(&entry_buf)?);
                index_read_offset += SUMMARY_INDEX_ENTRY_SIZE as u64;
            }

            Ok(Self {
                reader,
                header,
                footer,
                manifest,
                volume_header,
                index_entries,
                decrypted_body: None,
                volume_key,
            })
        } else {
            // Encrypted summary body
            //
            // `volume_header_len` is read from the file, so an oversized value would push
            // `ciphertext_offset` past the footer and underflow this subtraction - a panic in
            // debug, and in release a wrapped length that requests a multi-terabyte
            // allocation.
            let ciphertext_offset = SUMMARY_HEADER_SIZE as u64 + header.volume_header_len as u64;
            let ciphertext_len = footer_offset.checked_sub(ciphertext_offset).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "summary file {} declares a {}-byte volume header, which overruns the file",
                        filename, header.volume_header_len
                    ),
                )
            })? as usize;
            let mut ciphertext = vec![0u8; ciphertext_len];
            reader.read_exact_at(ciphertext_offset, &mut ciphertext)?;

            let decrypted = volume_key
                .decrypt_summary(&header.iv, &header_buf, &ciphertext)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let len_bytes = body_slice(&decrypted, footer.manifest_offset, 4, "manifest length")?;
            let manifest_len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as u64;
            let manifest_bytes = body_slice(&decrypted, footer.manifest_offset + 4, manifest_len, "manifest")?;
            let manifest: crate::log::LogManifest =
                bincode::deserialize(manifest_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let mut index_entries = Vec::with_capacity(footer.entry_count as usize);
            let mut index_offset = footer.index_offset;
            for _ in 0..footer.entry_count {
                let entry_bytes = body_slice(&decrypted, index_offset, SUMMARY_INDEX_ENTRY_SIZE as u64, "index entry")?;
                index_entries.push(SummaryIndexEntry::from_bytes(entry_bytes)?);
                index_offset += SUMMARY_INDEX_ENTRY_SIZE as u64;
            }

            Ok(Self {
                reader,
                header,
                footer,
                manifest,
                volume_header,
                index_entries,
                decrypted_body: Some(decrypted),
                volume_key,
            })
        }
    }

    /// Returns the slice of all index entries in this summary file.
    pub fn index_entries(&self) -> &[SummaryIndexEntry] {
        &self.index_entries
    }

    /// Returns the underlying storage reader.
    pub fn reader(&self) -> &Arc<dyn StorageReader> {
        &self.reader
    }

    /// Performs binary search lookup on index array to get the byte offset of a target inode.
    pub fn lookup_offset(&self, inode: u64) -> Option<u64> {
        self.index_entries
            .binary_search_by_key(&inode, |entry| entry.inode)
            .ok()
            .map(|idx| self.index_entries[idx].offset)
    }

    /// Reads and deserializes a single `Node` for `inode` from this summary file.
    pub fn read_inode(&self, inode: u64) -> io::Result<Option<Node>> {
        let Some(offset) = self.lookup_offset(inode) else {
            return Ok(None);
        };

        if let Some(ref body) = self.decrypted_body {
            let off = offset as usize;
            if off + 12 > body.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "corrupted summary body"));
            }
            let read_inode = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
            if read_inode != inode {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("summary index mismatch: expected inode {}, found {}", inode, read_inode),
                ));
            }
            let payload_len = u32::from_le_bytes(body[off + 8..off + 12].try_into().unwrap()) as usize;
            if off + 12 + payload_len > body.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "corrupted summary body"));
            }
            let payload = &body[off + 12..off + 12 + payload_len];
            let node =
                bincode::deserialize::<Node>(payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(Some(node));
        }

        let mut meta_buf = [0u8; 12];
        self.reader.read_exact_at(offset, &mut meta_buf)?;
        let read_inode = u64::from_le_bytes(meta_buf[0..8].try_into().unwrap());
        if read_inode != inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("summary index mismatch: expected inode {}, found {}", inode, read_inode),
            ));
        }

        let payload_len = u32::from_le_bytes(meta_buf[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        self.reader.read_exact_at(offset + 12, &mut payload)?;

        let node = bincode::deserialize::<Node>(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(node))
    }

    /// Alias for `read_inode`.
    pub fn read_node(&self, inode: u64) -> io::Result<Option<Node>> {
        self.read_inode(inode)
    }

    /// Iterates through all `(inode, Node)` stored in this summary file in ascending inode order.
    pub fn iter_inodes(&self) -> impl Iterator<Item = io::Result<(u64, Node)>> + '_ {
        self.index_entries.iter().map(move |entry| {
            let node = self.read_inode(entry.inode)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("inode {} in index but not found in file", entry.inode),
                )
            })?;
            Ok((entry.inode, node))
        })
    }

    /// Reads all inodes into an in-memory HashMap.
    pub fn read_all_inodes(&self) -> io::Result<HashMap<u64, Arc<Node>>> {
        let mut map = HashMap::with_capacity(self.footer.entry_count as usize);
        for res in self.iter_inodes() {
            let (ino, node) = res?;
            map.insert(ino, Arc::new(node));
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::InodeMeta;
    use crate::storage::{FaultStorage, MemoryStorage};
    use std::time::SystemTime;

    #[test]
    fn test_summary_bincode_serialization() {
        let storage = Arc::new(MemoryStorage::new());
        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();

        let root_entries = vec![("hello.txt".to_string(), 2)];
        snapshot.insert(
            1,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 2, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: root_entries,
                },
            }),
        );

        let mut rmap = RangeMap::new();
        rmap.insert(0, 100, SharedExtentState::new_disk(1, 24, 0, 100));
        snapshot.insert(
            2,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::File {
                    range_map: rmap,
                    size: 100,
                },
            }),
        );

        let manifest = crate::log::LogManifest {
            branch: "main".to_string(),
            logs: Vec::new(),
            next_generation: 2,
            next_filename: "000002.log".to_string(),
        };

        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                last_tx_id: 42,
                next_inode: 3,
                created_at: SystemTime::now(),
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.header.last_tx_id, 42);
        assert_eq!(reader.header.next_inode, 3);
        assert_eq!(reader.manifest.branch, "main");
        assert_eq!(reader.footer.entry_count, 2);

        let node1 = reader.read_inode(1).unwrap().unwrap();
        match node1.kind {
            NodeKind::Directory { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "hello.txt");
            }
            _ => panic!("expected directory"),
        }

        let node2 = reader.read_inode(2).unwrap().unwrap();
        match node2.kind {
            NodeKind::File { range_map, .. } => {
                assert_eq!(range_map.len(), 1);
                let extent = range_map.query(0, 100);
                assert_eq!(extent.len(), 1);
                assert_eq!(extent[0].1, 100);
            }
            _ => panic!("expected file"),
        }

        assert!(reader.read_inode(999).unwrap().is_none());
    }

    #[test]
    fn test_summary_export_and_reader() {
        let storage = Arc::new(MemoryStorage::new());
        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();

        for i in 1..=50 {
            snapshot.insert(
                i,
                Arc::new(Node {
                    meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                    kind: NodeKind::File {
                        range_map: RangeMap::new(),
                        size: i * 10,
                    },
                }),
            );
        }

        let manifest = crate::log::LogManifest {
            branch: "test".to_string(),
            logs: Vec::new(),
            next_generation: 5,
            next_filename: "000005.log".to_string(),
        };

        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 4,
                last_tx_id: 999,
                next_inode: 51,
                created_at: SystemTime::now(),
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.footer.entry_count, 50);

        let all_inodes: Vec<u64> = reader.iter_inodes().map(|res| res.unwrap().0).collect();
        assert_eq!(all_inodes.len(), 50);
        for i in 1..=50 {
            assert_eq!(all_inodes[(i - 1) as usize], i);
        }
    }

    #[test]
    fn test_init_volume_creates_valid_summary_and_manifest() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            Some("dev"),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        assert!(storage.exists("000000.summary"));

        let reader = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 0);
        assert_eq!(reader.header.last_tx_id, 0);
        assert_eq!(reader.header.next_inode, 2);
        assert_eq!(reader.manifest.branch, "dev");
        assert_eq!(reader.manifest.next_generation, 1);
        assert_eq!(reader.manifest.next_filename, "000001.log");

        let root = reader.read_inode(1).unwrap().unwrap();
        match root.kind {
            NodeKind::Directory { entries, .. } => {
                assert!(entries.is_empty());
            }
            _ => panic!("expected directory root"),
        }
    }

    #[test]
    fn test_header_serializes_to_exactly_the_declared_size() {
        // Readers seek past the header by SUMMARY_HEADER_SIZE to reach the volume header
        // blob, so a field added or removed without updating the constant would silently
        // misalign every subsequent offset rather than fail loudly.
        let header = SummaryHeader::new(1, 2, 3, SystemTime::UNIX_EPOCH, [0u8; 12], 0);
        assert_eq!(header.to_bytes().len(), SUMMARY_HEADER_SIZE);
    }

    #[test]
    fn test_summary_from_a_different_format_version_is_rejected() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            None,
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        // Restamp the version field (bytes 4..8) as the previous format. The volume header
        // blob that follows would still deserialize into something plausible, so without
        // an explicit version check this would be misread rather than refused.
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[4..8].copy_from_slice(&(CURRENT_SUMMARY_VERSION - 1).to_le_bytes());
        storage.insert_file("000000.summary", bytes);

        let Err(err) = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()) else {
            panic!("summary from an older format version must not open");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unsupported summary format version"),
            "expected a version error, got: {}",
            err
        );
    }

    #[test]
    fn test_volume_header_is_readable_without_the_key() {
        let storage = Arc::new(MemoryStorage::new());
        let master = crate::crypto::MasterKey::new([0x5Au8; 32]);
        let (header, key) =
            crate::crypto::VolumeHeader::new_encrypted(&master, [0x77u8; 16], crate::crypto::KeySource::KeyFile)
                .unwrap();
        let expected_id = header.volume_id;

        init_volume(storage.clone(), Some("main"), &key, header).unwrap();

        // The point of keeping this blob in plaintext: identify the volume and validate a
        // key before any body decryption is attempted.
        let read_back = SummaryReader::read_volume_header(storage.as_ref(), "000000.summary").unwrap();
        assert_eq!(read_back.cipher, crate::crypto::CipherSuite::ChaCha20Poly1305);
        assert_eq!(read_back.volume_id, expected_id);
        assert!(read_back.unlock(&master).is_ok());

        let wrong = crate::crypto::MasterKey::new([0x00u8; 32]);
        assert_eq!(
            read_back.unlock(&wrong).unwrap_err(),
            crate::crypto::CryptoError::WrongKey
        );
    }

    #[test]
    #[should_panic(expected = "summary checksum mismatch")]
    fn test_bitrot_in_summary_body_is_detected() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            None,
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        // Mutate a byte in the middle of 000000.summary
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[20] ^= 0xFF;
        storage.insert_file("000000.summary", bytes);

        // Opening corrupted summary file must panic with bitrot detected
        let _ = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc());
    }

    #[test]
    fn test_stale_tmp_from_failed_export_does_not_corrupt_next_summary() {
        let mem = Arc::new(MemoryStorage::new());
        let storage = Arc::new(FaultStorage::new(mem.clone()));

        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();
        snapshot.insert(
            1,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 2, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: vec![("a.txt".to_string(), 2)],
                },
            }),
        );

        let manifest = crate::log::LogManifest {
            branch: "main".to_string(),
            logs: Vec::new(),
            next_generation: 2,
            next_filename: "000002.log".to_string(),
        };

        // A first export dies partway, leaving a partial 000001.summary.tmp behind.
        storage.fail_writes_after_bytes(16, true);
        let failed = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                last_tx_id: 42,
                next_inode: 3,
                created_at: SystemTime::UNIX_EPOCH,
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        );
        assert!(failed.is_err(), "injected write fault should fail the export");
        let stale = mem
            .get_file_bytes("000001.summary.tmp")
            .expect("failed export should leave a stale tmp");
        assert!(!stale.is_empty(), "stale tmp should hold the partial export");

        // Retrying on a healthy backend must not prefix the stale bytes to the new summary.
        storage.clear_write_limit();
        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                last_tx_id: 42,
                next_inode: 3,
                created_at: SystemTime::UNIX_EPOCH,
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.footer.entry_count, 1);
        match reader.read_inode(1).unwrap().unwrap().kind {
            NodeKind::Directory { entries, .. } => assert_eq!(entries[0].0, "a.txt"),
            _ => panic!("expected directory root"),
        }
    }
}
