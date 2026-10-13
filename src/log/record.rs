use crate::extent_map::{Extent, ExtentMap};
use crate::node::{AttrDelta, DirectoryDelta, EntryDelta, FileDelta, NodeDelta, SpecialDelta, SymlinkDelta};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const FILE_MAGIC: [u8; 4] = *b"APPF";
/// Version written into every new `.log` file. Version 2 added [`LogExtent::Ref`]; a version 1
/// file never holds one, so reading it needs nothing beyond what version 2 reads.
pub const CURRENT_VERSION: u32 = 2;
/// magic(4) + version(4) + generation(4) + revision(2) + created_at seconds(8) + nanoseconds(4)
/// + key_salt(16).
pub const FILE_HEADER_SIZE: usize = 42;
pub const RECORD_HEADER_SIZE: usize = 37;
pub const AUTH_TAG_SIZE: usize = 16;

/// Fixed-size header written at offset 0 of every `.log` file.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u32,
    pub revision: u16,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
    /// Random salt, drawn when the file is created, from which the key for this file's
    /// records is derived (see [`crate::crypto::VolumeKey::log_file_key`]). Stored in the
    /// clear: it is not secret, only unique.
    pub key_salt: [u8; 16],
}

impl FileHeader {
    pub fn new(generation: u32, created_at: SystemTime, key_salt: [u8; 16]) -> Self {
        Self {
            magic: FILE_MAGIC,
            version: CURRENT_VERSION,
            generation,
            revision: 0,
            created_at,
            key_salt,
        }
    }

    pub fn to_bytes(&self) -> [u8; FILE_HEADER_SIZE] {
        let mut buf = [0u8; FILE_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.version.to_be_bytes());
        buf[8..12].copy_from_slice(&self.generation.to_be_bytes());
        buf[12..14].copy_from_slice(&self.revision.to_be_bytes());
        // Seconds are stored as a full signed 64-bit count. Narrowing them to u32 - as this
        // header briefly did - silently wraps every timestamp past 2106 back to 1970 and
        // every pre-1970 one forward to ~2106, which corrupts the ordering that
        // `mount-ro --at-time` selects generations by.
        let (secs, nsecs) = crate::clock::system_time_to_unix(self.created_at);
        buf[14..22].copy_from_slice(&secs.to_be_bytes());
        buf[22..26].copy_from_slice(&nsecs.to_be_bytes());
        buf[26..42].copy_from_slice(&self.key_salt);
        buf
    }

    pub fn from_bytes(bytes: &[u8; FILE_HEADER_SIZE]) -> Result<Self, &'static str> {
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != FILE_MAGIC {
            return Err("invalid magic bytes");
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if version == 0 || version > CURRENT_VERSION {
            return Err("unsupported file version");
        }
        let generation = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let revision = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
        let secs = i64::from_be_bytes(bytes[14..22].try_into().unwrap());
        let nsecs = u32::from_be_bytes(bytes[22..26].try_into().unwrap());
        let created_at = crate::clock::unix_to_system_time(secs, nsecs);
        let key_salt = bytes[26..42].try_into().unwrap();
        Ok(Self {
            magic,
            version,
            generation,
            revision,
            created_at,
            key_salt,
        })
    }
}

/// Operation codes identifying log record types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// Uncompressed file data content written directly to log. Inode number in RecordHeader.
    Data = 1,
    /// Zstd-compressed file data content. Inode number in RecordHeader.
    DataZstd = 2,
    /// Serialized LogEntryDelta (LogNodeDelta or Tombstone) for the inode in RecordHeader.
    InodeDelta = 3,
    /// Trailer written once per flush batch confirming completion and consistency.
    FlushCommit = 4,
    /// Terminal record marking a cleanly rolled and closed log file.
    Seal = 5,
}

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OpCode::Data),
            2 => Ok(OpCode::DataZstd),
            3 => Ok(OpCode::InodeDelta),
            4 => Ok(OpCode::FlushCommit),
            5 => Ok(OpCode::Seal),
            _ => Err("Unknown operation code"),
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            OpCode::Data => "Data",
            OpCode::DataZstd => "DataZstd",
            OpCode::InodeDelta => "InodeDelta",
            OpCode::FlushCommit => "FlushCommit",
            OpCode::Seal => "Seal",
        };
        f.pad(name)
    }
}

/// Per-record header (37 bytes).
///
/// ```text
/// byte  0 | 1..9  | 9..13       | 13..21   | 21..37
///      op | inode | payload_len | sequence | auth_tag
/// ```
///
/// Deliberately carries no `key_id`: whether a payload is encrypted is a property of the
/// volume, recorded once in the volume header where the key check value vouches for it.
/// A per-record copy would be unauthenticated - this header is not covered by `auth_tag` -
/// and clearing it used to downgrade an encrypted read into a raw one.
///
/// The 16-byte `auth_tag` protects both header metadata (`op_code` and `inode` via the AAD,
/// `sequence` via the nonce) and payload bytes across both encrypted (Poly1305 detached tag)
/// and unencrypted (BLAKE3 16-byte hash) volumes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub op_code: OpCode,
    pub inode: u64,
    pub payload_len: u32,
    /// The record's position in its generation's nonce sequence; the low 64 bits of the
    /// record nonce (see [`crate::crypto::record_nonce`]). Strictly increasing within a
    /// generation file, though not contiguous: a rolled-back write leaves a gap.
    pub sequence: u64,
    /// 16-byte authentication tag (Poly1305 or BLAKE3) covering `AAD || payload`.
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl RecordHeader {
    pub fn to_bytes(&self) -> [u8; RECORD_HEADER_SIZE] {
        let mut buf = [0u8; RECORD_HEADER_SIZE];
        buf[0] = self.op_code as u8;
        buf[1..9].copy_from_slice(&self.inode.to_be_bytes());
        buf[9..13].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[13..21].copy_from_slice(&self.sequence.to_be_bytes());
        buf[21..37].copy_from_slice(&self.auth_tag);
        buf
    }

    pub fn from_bytes(bytes: &[u8; RECORD_HEADER_SIZE]) -> Result<Self, &'static str> {
        let op_code = OpCode::try_from(bytes[0])?;
        let inode = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[9..13].try_into().unwrap());
        let sequence = u64::from_be_bytes(bytes[13..21].try_into().unwrap());
        let auth_tag = bytes[21..37].try_into().unwrap();

        Ok(Self {
            op_code,
            inode,
            payload_len,
            sequence,
            auth_tag,
        })
    }
}

/// Payload for the `OpCode::FlushCommit` trailer written once per flush
/// batch, after all of that batch's other records.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushCommitPayload {
    pub batch_id: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub timestamp: SystemTime,
    pub record_count: u32,
}

/// Payload for the `OpCode::Seal` terminal record written at the end of a rolled log file.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealPayload {
    #[serde(with = "crate::clock::serde_system_time")]
    pub timestamp: SystemTime,
    pub record_count: u32,
}

/// Persisted on-disk representation of an attribute delta.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogAttrDelta {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub nlink: Option<u32>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub atime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub mtime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub ctime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub created_at: Option<SystemTime>,
    #[serde(default)]
    pub xattrs: Option<Vec<(String, Option<Vec<u8>>)>>,
}

impl From<&AttrDelta> for LogAttrDelta {
    fn from(a: &AttrDelta) -> Self {
        let xattrs = a.xattrs.as_ref().map(|map| {
            let mut entries: Vec<(String, Option<Vec<u8>>)> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|x, y| x.0.cmp(&y.0));
            entries
        });
        Self {
            mode: a.mode,
            uid: a.uid,
            gid: a.gid,
            nlink: a.nlink,
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
            created_at: a.created_at,
            xattrs,
        }
    }
}

impl From<LogAttrDelta> for AttrDelta {
    fn from(l: LogAttrDelta) -> Self {
        let xattrs = l.xattrs.map(|vec| vec.into_iter().collect());
        Self {
            mode: l.mode,
            uid: l.uid,
            gid: l.gid,
            nlink: l.nlink,
            atime: l.atime,
            mtime: l.mtime,
            ctime: l.ctime,
            created_at: l.created_at,
            xattrs,
        }
    }
}

/// Persisted on-disk representation of a directory delta.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogDirectoryDelta {
    pub parent: Option<u64>,
    pub added: Vec<(String, u64)>,
    pub removed: Vec<String>,
    pub attr_delta: LogAttrDelta,
}

impl From<&DirectoryDelta> for LogDirectoryDelta {
    fn from(d: &DirectoryDelta) -> Self {
        let mut added: Vec<(String, u64)> = d.added.iter().map(|(k, v)| (k.clone(), *v)).collect();
        added.sort_by(|a, b| a.0.cmp(&b.0));
        let mut removed: Vec<String> = d.removed.iter().cloned().collect();
        removed.sort();
        Self {
            parent: d.parent,
            added,
            removed,
            attr_delta: LogAttrDelta::from(&d.attr_delta),
        }
    }
}

impl From<LogDirectoryDelta> for DirectoryDelta {
    fn from(l: LogDirectoryDelta) -> Self {
        Self {
            parent: l.parent,
            added: l.added.into_iter().collect(),
            removed: l.removed.into_iter().collect(),
            attr_delta: AttrDelta::from(l.attr_delta),
        }
    }
}

/// Persisted on-disk descriptor for a single extent in a file delta record.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogExtent {
    /// `length` bytes held by the record at `record_log_offset` in the same `.log` file.
    /// `record_size` is that record's physical on-disk size (header + payload).
    ///
    /// Only ever names a data record written by the same flush batch for the same inode -
    /// which is what lets a replay that keeps one batch in memory, like `scripts/restore.py`,
    /// resolve it. Anything else is a [`LogExtent::Ref`].
    Disk {
        file_offset: u64,
        record_log_offset: u64,
        record_size: u32,
        length: u32,
    },
    /// A hole: `length` bytes that read as zeros. `u64` because a hole may exceed 4 GiB.
    Zero { file_offset: u64, length: u64 },
    /// `length` bytes starting `payload_offset` bytes into the payload of a data record
    /// written by an earlier batch: the record at `record_log_offset` in `generation`'s
    /// `.log` file, which is this file or an older one, and may belong to another inode.
    /// This is how `copy_file_range` shares data instead of copying it. Format version 2.
    Ref {
        file_offset: u64,
        generation: u32,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        length: u32,
    },
}

/// Where the flush batch being encoded began writing to the log.
///
/// Data records at or past this position were written by the batch itself; everything a
/// file delta references from before it is encoded as a [`LogExtent::Ref`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchStart {
    pub generation: u32,
    pub offset: u64,
}

/// Persisted on-disk representation of a regular file delta.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogFileDelta {
    pub extents: Vec<LogExtent>,
    pub size: Option<u64>,
    pub attr_delta: LogAttrDelta,
}

impl LogFileDelta {
    pub fn encode(f: &FileDelta, batch: BatchStart) -> Self {
        let mut extents = Vec::new();
        for (&start, entry) in f.extents.iter() {
            // Matched exhaustively on purpose: an `if let` here would silently drop any
            // state it did not name, which for a hole means losing the punch entirely and
            // resurrecting the data it masked at the next recovery.
            let log_extent = match &entry.extent {
                Extent::Disk {
                    generation,
                    record_log_offset,
                    record_size,
                    payload_offset,
                    length,
                } => {
                    let written_by_batch = *generation == batch.generation && *record_log_offset >= batch.offset;
                    if written_by_batch && *payload_offset == 0 {
                        LogExtent::Disk {
                            file_offset: start,
                            record_log_offset: *record_log_offset,
                            record_size: *record_size,
                            length: *length,
                        }
                    } else {
                        LogExtent::Ref {
                            file_offset: start,
                            generation: *generation,
                            record_log_offset: *record_log_offset,
                            record_size: *record_size,
                            payload_offset: *payload_offset,
                            length: *length,
                        }
                    }
                }
                Extent::Zero { length } => LogExtent::Zero {
                    file_offset: start,
                    length: *length,
                },
                // The flush that emits this record converts staged extents to `Disk`
                // first, so anything still staged is not durable yet and must not be
                // referenced from the log.
                Extent::Staged { .. } => continue,
            };
            extents.push(log_extent);
        }
        Self {
            extents,
            size: f.size,
            attr_delta: LogAttrDelta::from(&f.attr_delta),
        }
    }

    pub fn into_file_delta(self, generation: u32) -> FileDelta {
        let mut extents = ExtentMap::with_capacity(self.extents.len());
        for ext in self.extents {
            match ext {
                LogExtent::Disk {
                    file_offset,
                    record_log_offset,
                    record_size,
                    length,
                } => extents.insert(
                    file_offset,
                    Extent::new_disk(generation, record_log_offset, record_size, 0, length),
                ),
                LogExtent::Zero { file_offset, length } => extents.insert(file_offset, Extent::new_zero(length)),
                LogExtent::Ref {
                    file_offset,
                    generation,
                    record_log_offset,
                    record_size,
                    payload_offset,
                    length,
                } => extents.insert(
                    file_offset,
                    Extent::new_disk(generation, record_log_offset, record_size, payload_offset, length),
                ),
            }
        }
        FileDelta {
            extents,
            size: self.size,
            attr_delta: AttrDelta::from(self.attr_delta),
        }
    }
}

impl From<LogFileDelta> for FileDelta {
    fn from(l: LogFileDelta) -> Self {
        l.into_file_delta(0)
    }
}

/// Persisted on-disk representation of a symlink delta.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogSymlinkDelta {
    pub target: Option<String>,
    pub attr_delta: LogAttrDelta,
}

impl From<&SymlinkDelta> for LogSymlinkDelta {
    fn from(s: &SymlinkDelta) -> Self {
        Self {
            target: s.target.clone(),
            attr_delta: LogAttrDelta::from(&s.attr_delta),
        }
    }
}

impl From<LogSymlinkDelta> for SymlinkDelta {
    fn from(l: LogSymlinkDelta) -> Self {
        Self {
            target: l.target,
            attr_delta: AttrDelta::from(l.attr_delta),
        }
    }
}

/// Persisted on-disk representation of special file deltas (FIFO, Char/Block devices, Sockets).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogSpecialDelta {
    pub rdev: u32,
    pub attr_delta: LogAttrDelta,
}

impl From<&SpecialDelta> for LogSpecialDelta {
    fn from(s: &SpecialDelta) -> Self {
        Self {
            rdev: s.rdev,
            attr_delta: LogAttrDelta::from(&s.attr_delta),
        }
    }
}

impl From<LogSpecialDelta> for SpecialDelta {
    fn from(l: LogSpecialDelta) -> Self {
        Self {
            rdev: l.rdev,
            attr_delta: AttrDelta::from(l.attr_delta),
        }
    }
}

/// Persisted on-disk enum covering all node types.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LogNodeDelta {
    Directory(LogDirectoryDelta),
    File(LogFileDelta),
    Symlink(LogSymlinkDelta),
    Fifo(LogSpecialDelta),
    CharDevice(LogSpecialDelta),
    BlockDevice(LogSpecialDelta),
    Socket(LogSpecialDelta),
}

impl LogNodeDelta {
    pub fn encode(n: &NodeDelta, batch: BatchStart) -> Self {
        match n {
            NodeDelta::Directory(d) => LogNodeDelta::Directory(LogDirectoryDelta::from(d)),
            NodeDelta::File(f) => LogNodeDelta::File(LogFileDelta::encode(f, batch)),
            NodeDelta::Symlink(s) => LogNodeDelta::Symlink(LogSymlinkDelta::from(s)),
            NodeDelta::Fifo(s) => LogNodeDelta::Fifo(LogSpecialDelta::from(s)),
            NodeDelta::CharDevice(s) => LogNodeDelta::CharDevice(LogSpecialDelta::from(s)),
            NodeDelta::BlockDevice(s) => LogNodeDelta::BlockDevice(LogSpecialDelta::from(s)),
            NodeDelta::Socket(s) => LogNodeDelta::Socket(LogSpecialDelta::from(s)),
        }
    }
}

impl LogNodeDelta {
    pub fn into_node_delta(self, generation: u32) -> NodeDelta {
        match self {
            LogNodeDelta::Directory(d) => NodeDelta::Directory(DirectoryDelta::from(d)),
            LogNodeDelta::File(f) => NodeDelta::File(f.into_file_delta(generation)),
            LogNodeDelta::Symlink(s) => NodeDelta::Symlink(SymlinkDelta::from(s)),
            LogNodeDelta::Fifo(s) => NodeDelta::Fifo(SpecialDelta::from(s)),
            LogNodeDelta::CharDevice(s) => NodeDelta::CharDevice(SpecialDelta::from(s)),
            LogNodeDelta::BlockDevice(s) => NodeDelta::BlockDevice(SpecialDelta::from(s)),
            LogNodeDelta::Socket(s) => NodeDelta::Socket(SpecialDelta::from(s)),
        }
    }
}

impl From<LogNodeDelta> for NodeDelta {
    fn from(l: LogNodeDelta) -> Self {
        l.into_node_delta(0)
    }
}

impl std::fmt::Display for LogNodeDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::dump::format_log_node_delta(self))
    }
}

/// Persisted on-disk representation of an entry delta (Node delta or Tombstone).
/// Serialized with a single 1-byte discriminant tag (0 = Tombstone, 1..=7 = Node variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEntryDelta {
    Node(LogNodeDelta),
    Tombstone,
}

impl Serialize for LogEntryDelta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            LogEntryDelta::Tombstone => (0u8,).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::Directory(d)) => (1u8, d).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::File(f)) => (2u8, f).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::Symlink(s)) => (3u8, s).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::Fifo(s)) => (4u8, s).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::CharDevice(s)) => (5u8, s).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::BlockDevice(s)) => (6u8, s).serialize(serializer),
            LogEntryDelta::Node(LogNodeDelta::Socket(s)) => (7u8, s).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LogEntryDelta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = LogEntryDelta;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 1-byte tagged LogEntryDelta")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let tag: u8 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                match tag {
                    0 => Ok(LogEntryDelta::Tombstone),
                    1 => {
                        let d = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::Directory(d)))
                    }
                    2 => {
                        let f = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::File(f)))
                    }
                    3 => {
                        let s = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::Symlink(s)))
                    }
                    4 => {
                        let s = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::Fifo(s)))
                    }
                    5 => {
                        let s = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::CharDevice(s)))
                    }
                    6 => {
                        let s = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::BlockDevice(s)))
                    }
                    7 => {
                        let s = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(LogEntryDelta::Node(LogNodeDelta::Socket(s)))
                    }
                    other => Err(serde::de::Error::custom(format!(
                        "unknown LogEntryDelta tag: {}",
                        other
                    ))),
                }
            }
        }

        deserializer.deserialize_tuple(2, Visitor)
    }
}

impl LogEntryDelta {
    pub fn into_entry_delta(self, generation: u32) -> EntryDelta {
        match self {
            LogEntryDelta::Node(n) => EntryDelta::Node(n.into_node_delta(generation)),
            LogEntryDelta::Tombstone => EntryDelta::Tombstone,
        }
    }
}

impl std::fmt::Display for LogEntryDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::dump::format_log_entry_delta(self))
    }
}

impl LogEntryDelta {
    /// Encodes `e` for a record of the batch that began writing at `batch`.
    pub fn encode(e: &EntryDelta, batch: BatchStart) -> Self {
        match e {
            EntryDelta::Node(n) => LogEntryDelta::Node(LogNodeDelta::encode(n, batch)),
            EntryDelta::Tombstone => LogEntryDelta::Tombstone,
        }
    }
}

impl From<LogEntryDelta> for EntryDelta {
    fn from(l: LogEntryDelta) -> Self {
        l.into_entry_delta(0)
    }
}

impl LogEntryDelta {
    pub fn op_time(&self) -> Option<SystemTime> {
        match self {
            LogEntryDelta::Node(n) => {
                let attr = match n {
                    LogNodeDelta::Directory(d) => &d.attr_delta,
                    LogNodeDelta::File(f) => &f.attr_delta,
                    LogNodeDelta::Symlink(s) => &s.attr_delta,
                    LogNodeDelta::Fifo(s)
                    | LogNodeDelta::CharDevice(s)
                    | LogNodeDelta::BlockDevice(s)
                    | LogNodeDelta::Socket(s) => &s.attr_delta,
                };
                attr.created_at.or(attr.ctime).or(attr.mtime)
            }
            LogEntryDelta::Tombstone => None,
        }
    }
}

/// Unified typed representation of any decoded log record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload<'a> {
    Data(&'a [u8]),
    InodeDelta(LogEntryDelta),
    FlushCommit(FlushCommitPayload),
    Seal(SealPayload),
}

impl DecodedPayload<'_> {
    /// Extracts the timestamp associated with this operation (either creation time, operation time, or flush timestamp).
    pub fn op_time(&self) -> Option<SystemTime> {
        match self {
            DecodedPayload::Data(_) => None,
            DecodedPayload::InodeDelta(delta) => delta.op_time(),
            DecodedPayload::FlushCommit(p) => Some(p.timestamp),
            DecodedPayload::Seal(s) => Some(s.timestamp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_file_header_serialization() {
        let time = crate::clock::unix_to_system_time(1721838000, 0);
        let header = FileHeader::new(42, time, [0x5A; 16]);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), FILE_HEADER_SIZE);

        let deserialized = FileHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_file_header_timestamp_survives_the_u32_boundaries() {
        // Seconds were briefly stored as u32, which wrapped 2106 back to 1970 and pre-1970
        // forward to ~2106. `mount-ro --at-time` picks a generation by comparing these, so a
        // wrapped value silently selects the wrong point in history rather than failing.
        let cases = [
            ("epoch", 0i64),
            ("just inside u32", u32::MAX as i64 - 1),
            ("past the u32 ceiling (year 2106+)", u32::MAX as i64 + 1_000),
            ("far future", 1i64 << 40),
            ("before the epoch", -1),
            ("well before the epoch", -2_208_988_800),
        ];

        for (name, secs) in cases {
            let created_at = crate::clock::unix_to_system_time(secs, 123_456_789);
            let header = FileHeader::new(7, created_at, [0x5A; 16]);
            let round_tripped = FileHeader::from_bytes(&header.to_bytes()).unwrap();
            assert_eq!(round_tripped.created_at, created_at, "{} did not round-trip", name);
            assert_eq!(round_tripped.generation, 7, "{}", name);
        }
    }

    #[test]
    fn test_record_header_serialization() {
        let header = RecordHeader {
            op_code: OpCode::Data,
            inode: 5,
            payload_len: 4096,
            sequence: 0x0102_0304_0506_0708,
            auth_tag: [0xAA; AUTH_TAG_SIZE],
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), RECORD_HEADER_SIZE);
        assert_eq!(&bytes[13..21], &[1, 2, 3, 4, 5, 6, 7, 8]);

        let deserialized = RecordHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_log_entry_delta_1_byte_tag_overhead() {
        // Tombstone must serialize to exactly 1 byte (the 0u8 tag).
        let tombstone = LogEntryDelta::Tombstone;
        let tomb_bytes = crate::wire::serialize(&tombstone).unwrap();
        assert_eq!(tomb_bytes.len(), 1);
        assert_eq!(tomb_bytes[0], 0);
        assert_eq!(
            crate::wire::deserialize::<LogEntryDelta>(&tomb_bytes).unwrap(),
            LogEntryDelta::Tombstone
        );

        // Directory delta must start with tag 1u8.
        let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta::default()));
        let dir_bytes = crate::wire::serialize(&dir_delta).unwrap();
        assert_eq!(dir_bytes[0], 1);
        assert_eq!(
            crate::wire::deserialize::<LogEntryDelta>(&dir_bytes).unwrap(),
            dir_delta
        );

        // File delta must start with tag 2u8.
        let file_delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta::default()));
        let file_bytes = crate::wire::serialize(&file_delta).unwrap();
        assert_eq!(file_bytes[0], 2);
        assert_eq!(
            crate::wire::deserialize::<LogEntryDelta>(&file_bytes).unwrap(),
            file_delta
        );
    }

    /// Pins the byte layout `scripts/restore.py` parses: a big-endian `u32` variant tag, then
    /// the variant's fields.
    #[test]
    fn test_log_extent_wire_layout() {
        let disk = LogExtent::Disk {
            file_offset: 1,
            record_log_offset: 2,
            record_size: 3,
            length: 4,
        };
        let bytes = crate::wire::serialize(&disk).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u32.to_be_bytes());
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&4u32.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(crate::wire::deserialize::<LogExtent>(&bytes).unwrap(), disk);

        // A truncation's hole runs to u64::MAX, well past what a u32 length could hold.
        let hole = LogExtent::Zero {
            file_offset: 5,
            length: u64::MAX - 5,
        };
        let bytes = crate::wire::serialize(&hole).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&5u64.to_be_bytes());
        expected.extend_from_slice(&(u64::MAX - 5).to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(crate::wire::deserialize::<LogExtent>(&bytes).unwrap(), hole);

        let shared = LogExtent::Ref {
            file_offset: 6,
            generation: 7,
            record_log_offset: 8,
            record_size: 9,
            payload_offset: 10,
            length: 11,
        };
        let bytes = crate::wire::serialize(&shared).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&2u32.to_be_bytes());
        expected.extend_from_slice(&6u64.to_be_bytes());
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&9u32.to_be_bytes());
        expected.extend_from_slice(&10u32.to_be_bytes());
        expected.extend_from_slice(&11u32.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(crate::wire::deserialize::<LogExtent>(&bytes).unwrap(), shared);

        let mut unknown = bytes;
        unknown[..4].copy_from_slice(&3u32.to_be_bytes());
        assert!(crate::wire::deserialize::<LogExtent>(&unknown).is_err());
    }

    /// Only a whole record the batch wrote itself may use the compact same-file form; every
    /// other extent must carry its own generation and payload offset, or replay would read it
    /// from the wrong file or the wrong place in the record.
    #[test]
    fn test_file_delta_encodes_extents_not_written_by_the_batch_as_refs() {
        let batch = BatchStart {
            generation: 3,
            offset: 1000,
        };
        let mut extents = ExtentMap::new();
        // Written by this batch.
        extents.insert(0, Extent::new_disk(3, 1000, 140, 0, 100));
        // Same generation, but written before the batch began.
        extents.insert(100, Extent::new_disk(3, 500, 140, 0, 100));
        // An older generation.
        extents.insert(200, Extent::new_disk(1, 2000, 140, 0, 100));
        // Written by this batch, but only the tail of the record.
        extents.insert(300, Extent::new_disk(3, 1200, 140, 40, 60));
        let delta = FileDelta {
            extents,
            size: Some(360),
            attr_delta: AttrDelta::default(),
        };

        let encoded = LogFileDelta::encode(&delta, batch);
        assert_eq!(
            encoded.extents,
            vec![
                LogExtent::Disk {
                    file_offset: 0,
                    record_log_offset: 1000,
                    record_size: 140,
                    length: 100,
                },
                LogExtent::Ref {
                    file_offset: 100,
                    generation: 3,
                    record_log_offset: 500,
                    record_size: 140,
                    payload_offset: 0,
                    length: 100,
                },
                LogExtent::Ref {
                    file_offset: 200,
                    generation: 1,
                    record_log_offset: 2000,
                    record_size: 140,
                    payload_offset: 0,
                    length: 100,
                },
                LogExtent::Ref {
                    file_offset: 300,
                    generation: 3,
                    record_log_offset: 1200,
                    record_size: 140,
                    payload_offset: 40,
                    length: 60,
                },
            ]
        );

        let decoded = encoded.into_file_delta(batch.generation);
        assert_eq!(decoded.extents, delta.extents);
    }

    #[test]
    fn test_log_entry_delta_serialization_round_trip() {
        let mut added = HashMap::new();
        added.insert("child.txt".to_string(), 10);
        let mut removed = HashSet::new();
        removed.insert("old.txt".to_string());
        let dir_delta = EntryDelta::Node(NodeDelta::Directory(DirectoryDelta {
            parent: Some(1),
            added,
            removed,
            attr_delta: AttrDelta {
                mode: Some(0o755),
                uid: Some(1000),
                gid: Some(1000),
                nlink: Some(3),
                ..Default::default()
            },
        }));

        let batch = BatchStart {
            generation: 1,
            offset: 0,
        };
        let log_delta = LogEntryDelta::encode(&dir_delta, batch);
        let serialized = crate::wire::serialize(&log_delta).unwrap();
        let deserialized: LogEntryDelta = crate::wire::deserialize(&serialized).unwrap();
        let reconstructed = EntryDelta::from(deserialized);

        match (dir_delta, reconstructed) {
            (EntryDelta::Node(NodeDelta::Directory(d1)), EntryDelta::Node(NodeDelta::Directory(d2))) => {
                assert_eq!(d1.parent, d2.parent);
                assert_eq!(d1.added, d2.added);
                assert_eq!(d1.removed, d2.removed);
                assert_eq!(d1.attr_delta.mode, d2.attr_delta.mode);
                assert_eq!(d1.attr_delta.uid, d2.attr_delta.uid);
                assert_eq!(d1.attr_delta.gid, d2.attr_delta.gid);
                assert_eq!(d1.attr_delta.nlink, d2.attr_delta.nlink);
            }
            _ => panic!("Type mismatch in round trip"),
        }
    }
}
