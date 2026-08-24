use crate::log::{ExtentState, SharedExtentState, ZERO_EXTENT_GENERATION, zero_extent_fields, zero_extent_len};
use crate::node::{AttrDelta, DirectoryDelta, EntryDelta, FileDelta, NodeDelta, SpecialDelta, SymlinkDelta};
use crate::range_map::RangeMap;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const FILE_MAGIC: [u8; 4] = *b"APPF";
// Bumped for RecordHeader's new key_id field - a breaking format change, so old logs
// are cleanly rejected (FileHeader::from_bytes) rather than silently misparsed.
// Bumped to 7: every record payload now carries a one-byte compression envelope inside the
// encrypted region, so a v6 payload read as v7 would lose its first byte and gain a bogus
// tag. Version 6 had removed RecordHeader's `key_id` (25 bytes rather than 26) and widened
// FileHeader's timestamp to a full i64 of seconds. The header is validated on open, so an
// older file is refused rather than read with the wrong layout.
pub const CURRENT_VERSION: u32 = 7;
/// magic(4) + version(4) + generation(8) + created_at seconds(8) + nanoseconds(4).
pub const FILE_HEADER_SIZE: usize = 28;
pub const RECORD_HEADER_SIZE: usize = 25;
pub const RECORD_CHECKSUM_SIZE: usize = 4;

/// Computes the truncated-BLAKE3 checksum stored in a record's header, over that
/// record's payload bytes. 4 bytes (1-in-4-billion false-negative rate) is far more
/// than needed to detect accidental bitrot/corruption - this is not a security
/// mechanism (an adversary who can modify the payload can trivially recompute a
/// matching checksum, since it's unkeyed), just a way for recovery to notice when a
/// record's content no longer matches what was actually written.
pub fn checksum_payload(payload: &[u8]) -> [u8; RECORD_CHECKSUM_SIZE] {
    let hash = blake3::hash(payload);
    let mut out = [0u8; RECORD_CHECKSUM_SIZE];
    out.copy_from_slice(&hash.as_bytes()[..RECORD_CHECKSUM_SIZE]);
    out
}

/// Fixed-size header written at offset 0 of every `.log` file.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
}

impl FileHeader {
    pub fn new(generation: u64, created_at: SystemTime) -> Self {
        Self {
            magic: FILE_MAGIC,
            version: CURRENT_VERSION,
            generation,
            created_at,
        }
    }

    pub fn to_bytes(&self) -> [u8; FILE_HEADER_SIZE] {
        let mut buf = [0u8; FILE_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.version.to_be_bytes());
        buf[8..16].copy_from_slice(&self.generation.to_be_bytes());
        // Seconds are stored as a full signed 64-bit count. Narrowing them to u32 - as this
        // header briefly did - silently wraps every timestamp past 2106 back to 1970 and
        // every pre-1970 one forward to ~2106, which corrupts the ordering that
        // `mount-ro --at-time` selects generations by.
        let (secs, nsecs) = crate::clock::system_time_to_unix(self.created_at);
        buf[16..24].copy_from_slice(&secs.to_be_bytes());
        buf[24..28].copy_from_slice(&nsecs.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; FILE_HEADER_SIZE]) -> Result<Self, &'static str> {
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != FILE_MAGIC {
            return Err("invalid magic bytes");
        }
        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if version != CURRENT_VERSION {
            return Err("unsupported file version");
        }
        let generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let secs = i64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let nsecs = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let created_at = crate::clock::unix_to_system_time(secs, nsecs);

        Ok(Self {
            magic,
            version,
            generation,
            created_at,
        })
    }
}

/// Operation codes identifying log record types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// File data content written directly to log. Inode number in RecordHeader.
    Data = 1,
    /// Serialized LogEntryDelta (LogNodeDelta or Tombstone) for the inode in RecordHeader.
    InodeDelta = 2,
    /// Trailer written once per flush batch confirming completion and consistency.
    FlushCommit = 3,
}

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OpCode::Data),
            2 => Ok(OpCode::InodeDelta),
            3 => Ok(OpCode::FlushCommit),
            _ => Err("Unknown operation code"),
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            OpCode::Data => "Data",
            OpCode::InodeDelta => "InodeDelta",
            OpCode::FlushCommit => "FlushCommit",
        };
        f.pad(name)
    }
}

/// Compact per-record header (25 bytes).
///
/// Deliberately carries no `key_id`: whether a payload is encrypted is a property of the
/// volume, recorded once in the volume header where the key check value vouches for it.
/// A per-record copy would be unauthenticated - this header is not covered by `checksum` -
/// and clearing it used to downgrade an encrypted read into a raw one.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub op_code: OpCode,
    pub tx_id: u64,
    pub inode: u64,
    pub payload_len: u32,
    /// Truncated BLAKE3 checksum of the payload - see `checksum_payload`.
    pub checksum: [u8; RECORD_CHECKSUM_SIZE],
}

impl RecordHeader {
    pub fn to_bytes(&self) -> [u8; RECORD_HEADER_SIZE] {
        let mut buf = [0u8; RECORD_HEADER_SIZE];
        buf[0] = self.op_code as u8;
        buf[1..9].copy_from_slice(&self.tx_id.to_be_bytes());
        buf[9..17].copy_from_slice(&self.inode.to_be_bytes());
        buf[17..21].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[21..25].copy_from_slice(&self.checksum);
        buf
    }

    pub fn from_bytes(bytes: &[u8; RECORD_HEADER_SIZE]) -> Result<Self, &'static str> {
        let op_code = OpCode::try_from(bytes[0])?;
        let tx_id = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let inode = u64::from_be_bytes(bytes[9..17].try_into().unwrap());
        let payload_len = u32::from_be_bytes(bytes[17..21].try_into().unwrap());
        let checksum = bytes[21..25].try_into().unwrap();

        Ok(Self {
            op_code,
            tx_id,
            inode,
            payload_len,
            checksum,
        })
    }
}

/// Payload for the `OpCode::FlushCommit` trailer written once per flush
/// batch, after all of that batch's other records.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushCommitPayload {
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

/// Persisted on-disk descriptor for a single data extent.
///
/// A `generation` of [`ZERO_EXTENT_GENERATION`] marks a hole rather than a reference into a
/// `.log` file; `record_log_offset` and `payload_offset` are then meaningless and written
/// as zero.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogExtent {
    pub file_offset: u64,
    pub generation: u64,
    pub record_log_offset: u64,
    pub payload_offset: u32,
    pub length: u32,
}

/// Persisted on-disk representation of a regular file delta.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct LogFileDelta {
    pub extents: Vec<LogExtent>,
    pub size: Option<u64>,
    pub attr_delta: LogAttrDelta,
}

impl From<&FileDelta> for LogFileDelta {
    fn from(f: &FileDelta) -> Self {
        let mut extents = Vec::new();
        for (&start, entry) in f.extents.iter() {
            // Matched exhaustively on purpose: an `if let` here would silently drop any
            // state it did not name, which for a hole means losing the punch entirely and
            // resurrecting the data it masked at the next recovery.
            let log_extent = match entry.value.read_state() {
                ExtentState::Disk {
                    generation,
                    record_log_offset,
                    payload_offset,
                    length,
                } => LogExtent {
                    file_offset: start,
                    generation,
                    record_log_offset,
                    payload_offset,
                    length,
                },
                ExtentState::Zero { length } => {
                    let (generation, record_log_offset, payload_offset, length) = zero_extent_fields(length);
                    LogExtent {
                        file_offset: start,
                        generation,
                        record_log_offset,
                        payload_offset,
                        length,
                    }
                }
                // The flush that emits this record converts staged extents to `Disk`
                // first, so anything still staged is not durable yet and must not be
                // referenced from the log.
                ExtentState::Staged { .. } => continue,
            };
            extents.push(log_extent);
        }
        Self {
            extents,
            size: f.size,
            attr_delta: LogAttrDelta::from(&f.attr_delta),
        }
    }
}

impl From<LogFileDelta> for FileDelta {
    fn from(l: LogFileDelta) -> Self {
        let mut extents = RangeMap::new();
        for ext in l.extents {
            // A hole carries its length in `record_log_offset`, so the range length has to
            // come from there too - `ext.length` is meaningless for one.
            let (range_len, state) = if ext.generation == ZERO_EXTENT_GENERATION {
                let len = zero_extent_len(ext.record_log_offset);
                (len, SharedExtentState::new_zero(len))
            } else {
                (
                    ext.length as u64,
                    SharedExtentState::new_disk(ext.generation, ext.record_log_offset, ext.payload_offset, ext.length),
                )
            };
            extents.insert(ext.file_offset, range_len, state);
        }
        Self {
            extents,
            size: l.size,
            attr_delta: AttrDelta::from(l.attr_delta),
        }
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

impl From<&NodeDelta> for LogNodeDelta {
    fn from(n: &NodeDelta) -> Self {
        match n {
            NodeDelta::Directory(d) => LogNodeDelta::Directory(LogDirectoryDelta::from(d)),
            NodeDelta::File(f) => LogNodeDelta::File(LogFileDelta::from(f)),
            NodeDelta::Symlink(s) => LogNodeDelta::Symlink(LogSymlinkDelta::from(s)),
            NodeDelta::Fifo(s) => LogNodeDelta::Fifo(LogSpecialDelta::from(s)),
            NodeDelta::CharDevice(s) => LogNodeDelta::CharDevice(LogSpecialDelta::from(s)),
            NodeDelta::BlockDevice(s) => LogNodeDelta::BlockDevice(LogSpecialDelta::from(s)),
            NodeDelta::Socket(s) => LogNodeDelta::Socket(LogSpecialDelta::from(s)),
        }
    }
}

impl From<LogNodeDelta> for NodeDelta {
    fn from(l: LogNodeDelta) -> Self {
        match l {
            LogNodeDelta::Directory(d) => NodeDelta::Directory(DirectoryDelta::from(d)),
            LogNodeDelta::File(f) => NodeDelta::File(FileDelta::from(f)),
            LogNodeDelta::Symlink(s) => NodeDelta::Symlink(SymlinkDelta::from(s)),
            LogNodeDelta::Fifo(s) => NodeDelta::Fifo(SpecialDelta::from(s)),
            LogNodeDelta::CharDevice(s) => NodeDelta::CharDevice(SpecialDelta::from(s)),
            LogNodeDelta::BlockDevice(s) => NodeDelta::BlockDevice(SpecialDelta::from(s)),
            LogNodeDelta::Socket(s) => NodeDelta::Socket(SpecialDelta::from(s)),
        }
    }
}

/// Persisted on-disk representation of an entry delta (Node delta or Tombstone).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LogEntryDelta {
    Node(LogNodeDelta),
    Tombstone,
}

impl From<&EntryDelta> for LogEntryDelta {
    fn from(e: &EntryDelta) -> Self {
        match e {
            EntryDelta::Node(n) => LogEntryDelta::Node(LogNodeDelta::from(n)),
            EntryDelta::Tombstone => LogEntryDelta::Tombstone,
        }
    }
}

impl From<LogEntryDelta> for EntryDelta {
    fn from(l: LogEntryDelta) -> Self {
        match l {
            LogEntryDelta::Node(n) => EntryDelta::Node(NodeDelta::from(n)),
            LogEntryDelta::Tombstone => EntryDelta::Tombstone,
        }
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
}

impl DecodedPayload<'_> {
    /// Extracts the timestamp associated with this operation (either creation time, operation time, or flush timestamp).
    pub fn op_time(&self) -> Option<SystemTime> {
        match self {
            DecodedPayload::Data(_) => None,
            DecodedPayload::InodeDelta(delta) => delta.op_time(),
            DecodedPayload::FlushCommit(p) => Some(p.timestamp),
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
        let header = FileHeader::new(42, time);
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
            let header = FileHeader::new(7, created_at);
            let round_tripped = FileHeader::from_bytes(&header.to_bytes()).unwrap();
            assert_eq!(round_tripped.created_at, created_at, "{} did not round-trip", name);
            assert_eq!(round_tripped.generation, 7, "{}", name);
        }
    }

    #[test]
    fn test_record_header_serialization() {
        let header = RecordHeader {
            op_code: OpCode::Data,
            tx_id: 1001,
            inode: 5,
            payload_len: 4096,
            checksum: [0xAA, 0xBB, 0xCC, 0xDD],
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), RECORD_HEADER_SIZE);

        let deserialized = RecordHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_checksum_payload_detects_bitflip() {
        let original = b"the quick brown fox".to_vec();
        let checksum = checksum_payload(&original);

        let mut corrupted = original.clone();
        corrupted[3] ^= 0x01; // flip one bit
        assert_ne!(checksum_payload(&corrupted), checksum);

        assert_eq!(checksum_payload(&original), checksum);
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

        let log_delta = LogEntryDelta::from(&dir_delta);
        let serialized = bincode::serialize(&log_delta).unwrap();
        let deserialized: LogEntryDelta = bincode::deserialize(&serialized).unwrap();
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
