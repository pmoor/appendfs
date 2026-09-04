use crate::log::SharedExtentState;
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Common POSIX metadata fields shared by all inode types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeMeta {
    pub perm: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(with = "crate::clock::serde_system_time")]
    pub atime: SystemTime,
    #[serde(with = "crate::clock::serde_system_time")]
    pub mtime: SystemTime,
    #[serde(with = "crate::clock::serde_system_time")]
    pub ctime: SystemTime,
    #[serde(default)]
    pub xattrs: Option<Arc<BTreeMap<String, Vec<u8>>>>,
}

impl InodeMeta {
    pub fn new(perm: u32, nlink: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            perm,
            nlink,
            uid,
            gid,
            atime: time,
            mtime: time,
            ctime: time,
            xattrs: None,
        }
    }

    pub fn apply_delta(&mut self, delta: &AttrDelta) {
        if let Some(mode) = delta.mode {
            self.perm = mode & 0o7777;
        }
        if let Some(uid) = delta.uid {
            self.uid = uid;
        }
        if let Some(gid) = delta.gid {
            self.gid = gid;
        }
        if let Some(nlink) = delta.nlink {
            self.nlink = nlink;
        }
        if let Some(atime) = delta.atime {
            self.atime = atime;
        }
        if let Some(mtime) = delta.mtime {
            self.mtime = mtime;
        }
        if let Some(ctime) = delta.ctime {
            self.ctime = ctime;
        }
        if let Some(ref xattr_changes) = delta.xattrs {
            let mut map = match self.xattrs.take() {
                Some(arc) => (*arc).clone(),
                None => BTreeMap::new(),
            };
            for (key, val_opt) in xattr_changes {
                match val_opt {
                    Some(val) => {
                        map.insert(key.clone(), val.clone());
                    }
                    None => {
                        map.remove(key);
                    }
                }
            }
            if map.is_empty() {
                self.xattrs = None;
            } else {
                self.xattrs = Some(Arc::new(map));
            }
        }
    }
}

/// Type-specific contents and payloads for inodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeKind {
    Directory {
        parent: u64,
        entries: Vec<(String, u64)>,
    },
    File {
        range_map: RangeMap<SharedExtentState>,
        size: u64,
    },
    Symlink {
        target: String,
    },
    Fifo,
    CharDevice {
        rdev: u32,
    },
    BlockDevice {
        rdev: u32,
    },
    Socket,
}

/// In-memory filesystem node with unified metadata and type-specific kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub meta: InodeMeta,
    pub kind: NodeKind,
}

impl Node {
    pub fn new_dir(parent: u64, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 2, uid, gid, time),
            kind: NodeKind::Directory {
                parent,
                entries: Vec::new(),
            },
        }
    }

    pub fn new_file(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::File {
                range_map: RangeMap::new(),
                size: 0,
            },
        }
    }

    pub fn new_symlink(target: String, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(0o777, 1, uid, gid, time),
            kind: NodeKind::Symlink { target },
        }
    }

    pub fn new_fifo(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::Fifo,
        }
    }

    pub fn new_char_device(rdev: u32, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::CharDevice { rdev },
        }
    }

    pub fn new_block_device(rdev: u32, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::BlockDevice { rdev },
        }
    }

    pub fn new_socket(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::Socket,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Directory { .. })
    }

    pub fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
    }

    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, NodeKind::Symlink { .. })
    }

    pub fn is_fifo(&self) -> bool {
        matches!(self.kind, NodeKind::Fifo)
    }

    pub fn is_char_device(&self) -> bool {
        matches!(self.kind, NodeKind::CharDevice { .. })
    }

    pub fn is_block_device(&self) -> bool {
        matches!(self.kind, NodeKind::BlockDevice { .. })
    }

    pub fn is_socket(&self) -> bool {
        matches!(self.kind, NodeKind::Socket)
    }

    pub fn is_special(&self) -> bool {
        matches!(
            self.kind,
            NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket
        )
    }

    pub fn rdev(&self) -> u32 {
        match self.kind {
            NodeKind::CharDevice { rdev } | NodeKind::BlockDevice { rdev } => rdev,
            _ => 0,
        }
    }

    pub fn file_type(&self) -> FileType {
        match self.kind {
            NodeKind::Directory { .. } => FileType::Directory,
            NodeKind::File { .. } => FileType::RegularFile,
            NodeKind::Symlink { .. } => FileType::Symlink,
            NodeKind::Fifo => FileType::NamedPipe,
            NodeKind::CharDevice { .. } => FileType::CharDevice,
            NodeKind::BlockDevice { .. } => FileType::BlockDevice,
            NodeKind::Socket => FileType::Socket,
        }
    }

    pub fn to_attr(&self, ino: u64) -> FileAttr {
        let (file_type, size, perm, rdev) = match &self.kind {
            NodeKind::Directory { .. } => (FileType::Directory, 0, self.meta.perm, 0),
            NodeKind::File { size, .. } => (FileType::RegularFile, *size as i64, self.meta.perm, 0),
            NodeKind::Symlink { target } => (FileType::Symlink, target.len() as i64, 0o777, 0),
            NodeKind::Fifo => (FileType::NamedPipe, 0, self.meta.perm, 0),
            NodeKind::CharDevice { rdev } => (FileType::CharDevice, 0, self.meta.perm, *rdev),
            NodeKind::BlockDevice { rdev } => (FileType::BlockDevice, 0, self.meta.perm, *rdev),
            NodeKind::Socket => (FileType::Socket, 0, self.meta.perm, 0),
        };
        FileAttr {
            ino,
            file_type,
            perm,
            nlink: self.meta.nlink,
            uid: self.meta.uid,
            gid: self.meta.gid,
            rdev,
            size,
            atime: self.meta.atime,
            mtime: self.meta.mtime,
            ctime: self.meta.ctime,
        }
    }

    pub fn apply_attr_delta(&mut self, delta: &AttrDelta) {
        self.meta.apply_delta(delta);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttrDelta {
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
    pub xattrs: Option<std::collections::HashMap<String, Option<Vec<u8>>>>,
}

impl AttrDelta {
    pub fn apply_to_attr(&self, attr: &mut FileAttr) {
        if let Some(m) = self.mode {
            attr.perm = m & 0o7777;
        }
        if let Some(u) = self.uid {
            attr.uid = u;
        }
        if let Some(g) = self.gid {
            attr.gid = g;
        }
        if let Some(n) = self.nlink {
            attr.nlink = n;
        }
        if let Some(a) = self.atime {
            attr.atime = a;
        }
        if let Some(m) = self.mtime {
            attr.mtime = m;
        }
        if let Some(c) = self.ctime {
            attr.ctime = c;
        }
    }

    pub fn merge_from(&mut self, incoming: &AttrDelta) {
        if incoming.mode.is_some() {
            self.mode = incoming.mode;
        }
        if incoming.uid.is_some() {
            self.uid = incoming.uid;
        }
        if incoming.gid.is_some() {
            self.gid = incoming.gid;
        }
        if incoming.nlink.is_some() {
            self.nlink = incoming.nlink;
        }
        if incoming.atime.is_some() {
            self.atime = incoming.atime;
        }
        if incoming.mtime.is_some() {
            self.mtime = incoming.mtime;
        }
        if incoming.ctime.is_some() {
            self.ctime = incoming.ctime;
        }
        if incoming.created_at.is_some() {
            self.created_at = incoming.created_at;
        }
        if let Some(ref inc_xattrs) = incoming.xattrs {
            let target_xattrs = self.xattrs.get_or_insert_with(HashMap::new);
            for (k, v) in inc_xattrs {
                target_xattrs.insert(k.clone(), v.clone());
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirectoryDelta {
    pub parent: Option<u64>,
    pub added: std::collections::HashMap<String, u64>,
    pub removed: std::collections::HashSet<String>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone, Default)]
pub struct FileDelta {
    pub extents: RangeMap<SharedExtentState>,
    pub size: Option<u64>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone)]
pub struct SymlinkDelta {
    pub target: Option<String>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone, Default)]
pub struct SpecialDelta {
    pub rdev: u32,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone)]
pub enum NodeDelta {
    Directory(DirectoryDelta),
    File(FileDelta),
    Symlink(SymlinkDelta),
    Fifo(SpecialDelta),
    CharDevice(SpecialDelta),
    BlockDevice(SpecialDelta),
    Socket(SpecialDelta),
}

impl NodeDelta {
    pub fn file_type(&self) -> FileType {
        match self {
            NodeDelta::Directory(_) => FileType::Directory,
            NodeDelta::File(_) => FileType::RegularFile,
            NodeDelta::Symlink(_) => FileType::Symlink,
            NodeDelta::Fifo(_) => FileType::NamedPipe,
            NodeDelta::CharDevice(_) => FileType::CharDevice,
            NodeDelta::BlockDevice(_) => FileType::BlockDevice,
            NodeDelta::Socket(_) => FileType::Socket,
        }
    }

    pub fn attr_delta(&self) -> &AttrDelta {
        match self {
            NodeDelta::Directory(d) => &d.attr_delta,
            NodeDelta::File(f) => &f.attr_delta,
            NodeDelta::Symlink(s) => &s.attr_delta,
            NodeDelta::Fifo(s) | NodeDelta::CharDevice(s) | NodeDelta::BlockDevice(s) | NodeDelta::Socket(s) => {
                &s.attr_delta
            }
        }
    }

    pub fn attr_delta_mut(&mut self) -> &mut AttrDelta {
        match self {
            NodeDelta::Directory(d) => &mut d.attr_delta,
            NodeDelta::File(f) => &mut f.attr_delta,
            NodeDelta::Symlink(s) => &mut s.attr_delta,
            NodeDelta::Fifo(s) | NodeDelta::CharDevice(s) | NodeDelta::BlockDevice(s) | NodeDelta::Socket(s) => {
                &mut s.attr_delta
            }
        }
    }

    pub fn initial_attr(&self, ino: u64) -> FileAttr {
        let (file_type, perm, nlink, rdev) = match self {
            NodeDelta::Directory(_) => (FileType::Directory, 0o755, 2, 0),
            NodeDelta::File(_) => (FileType::RegularFile, 0o644, 1, 0),
            NodeDelta::Symlink(_) => (FileType::Symlink, 0o777, 1, 0),
            NodeDelta::Fifo(_) => (FileType::NamedPipe, 0o644, 1, 0),
            NodeDelta::CharDevice(s) => (FileType::CharDevice, 0o660, 1, s.rdev),
            NodeDelta::BlockDevice(s) => (FileType::BlockDevice, 0o660, 1, s.rdev),
            NodeDelta::Socket(_) => (FileType::Socket, 0o777, 1, 0),
        };
        FileAttr {
            ino,
            file_type,
            perm,
            nlink,
            uid: 0,
            gid: 0,
            rdev,
            size: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn apply_to_attr(&self, attr: &mut FileAttr) {
        match self {
            NodeDelta::Directory(d) => d.attr_delta.apply_to_attr(attr),
            NodeDelta::File(f) => {
                if let Some(s) = f.size {
                    attr.size = s as i64;
                }
                f.attr_delta.apply_to_attr(attr);
            }
            NodeDelta::Symlink(s) => {
                if let Some(ref t) = s.target {
                    attr.size = t.len() as i64;
                }
                s.attr_delta.apply_to_attr(attr);
            }
            NodeDelta::Fifo(s) | NodeDelta::CharDevice(s) | NodeDelta::BlockDevice(s) | NodeDelta::Socket(s) => {
                s.attr_delta.apply_to_attr(attr);
            }
        }
    }

    pub fn apply_to_node(&self, node: &mut Node) {
        match (&mut node.kind, self) {
            (NodeKind::Directory { parent, entries }, NodeDelta::Directory(d)) => {
                if let Some(p) = d.parent {
                    *parent = p;
                }
                for rem in &d.removed {
                    entries.retain(|(name, _)| name != rem);
                }
                for (name, child_ino) in &d.added {
                    entries.retain(|(existing_name, _)| existing_name != name);
                    entries.push((name.clone(), *child_ino));
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                node.apply_attr_delta(&d.attr_delta);
            }
            (NodeKind::File { range_map, size }, NodeDelta::File(f)) => {
                for (start, entry) in f.extents.iter() {
                    range_map.insert(*start, entry.length, entry.value.clone());
                }
                if let Some(s) = f.size {
                    *size = s;
                }
                // Nothing above the file's size is readable, so drop it. This is what
                // compacts a truncation away: the `Zero` extent that masked the discarded
                // range has done its job by overwriting those entries on the way in, and
                // has no one left below it to mask once it reaches `base`.
                range_map.truncate(*size);
                node.apply_attr_delta(&f.attr_delta);
            }
            (NodeKind::Symlink { target }, NodeDelta::Symlink(s)) => {
                if let Some(ref t) = s.target {
                    *target = t.clone();
                }
                node.apply_attr_delta(&s.attr_delta);
            }
            (NodeKind::Fifo, NodeDelta::Fifo(s))
            | (NodeKind::CharDevice { .. }, NodeDelta::CharDevice(s))
            | (NodeKind::BlockDevice { .. }, NodeDelta::BlockDevice(s))
            | (NodeKind::Socket, NodeDelta::Socket(s)) => {
                node.apply_attr_delta(&s.attr_delta);
            }
            _ => {}
        }
    }

    pub fn to_node(&self) -> Node {
        let mut node = match self {
            NodeDelta::Directory(d) => Node::new_dir(d.parent.unwrap_or(1), 0o755, 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::File(_) => Node::new_file(0o644, 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::Symlink(_) => Node::new_symlink(String::new(), 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::Fifo(_) => Node::new_fifo(0o644, 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::CharDevice(s) => Node::new_char_device(s.rdev, 0o660, 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::BlockDevice(s) => Node::new_block_device(s.rdev, 0o660, 0, 0, SystemTime::UNIX_EPOCH),
            NodeDelta::Socket(_) => Node::new_socket(0o777, 0, 0, SystemTime::UNIX_EPOCH),
        };
        self.apply_to_node(&mut node);
        node
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EntryDelta {
    Node(NodeDelta),
    Tombstone,
}
