use crate::error::FsError;
use crate::fs::{AppendFs, FlushReason};
use crate::operations::dir::{fsyncdir_response, list_dir_core, mkdir_core, opendir_core, releasedir_core, rmdir_core};
use crate::operations::links::{link_core, readlink_core, rename_core, symlink_core, unlink_core};
use crate::operations::read_write::{
    FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME, FUSE_SET_ATTR_SIZE,
    FUSE_SET_ATTR_UID, copy_file_range_core, create_core, fsync_response, getattr_core, open_core, punch_hole_core,
    read_response, release_core, setattr_core, write_handle_core,
};
use crate::operations::special::mknod_core;
use crate::operations::xattr::{getxattr_core, listxattr_core, removexattr_core, setxattr_core};
use crate::shim::{FileAttr, FileType, FuseResponse};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shortcuts for driving an `AppendFs` from tests.
///
/// Production code reaches the filesystem through the FUSE entry points, which hand back
/// deferred replies, expect the caller to manage file handles, and take the caller's
/// identity with every request. Tests usually just want the outcome, so these wrap those
/// same entry points: they wait for the result, open and release handles around the call,
/// and act as the owner of the root directory - the user who mounted the volume.
///
/// Every operation a test needs goes through here, so tests share one calling pattern. The
/// names follow `std::fs` where it has one and avoid the [`Filesystem`](crate::Filesystem)
/// trait's, so importing both never makes a call ambiguous. Results a FUSE reply would carry
/// are reduced to what a test compares: an inode number, a handle, or `()`.
pub trait FsTestExt {
    /// Writes `buf` at `offset` through a read-write handle opened and released around the
    /// call, so the caller does not need one of its own.
    fn write_at(&self, ino: u64, buf: &[u8], offset: i64) -> Result<usize, FsError>;

    /// Runs `copy_file_range` from `ino_in` at `off_in` to `ino_out` at `off_out` through
    /// handles opened and released around the call, returning how many bytes it copied.
    fn copy_range(&self, ino_in: u64, off_in: i64, ino_out: u64, off_out: i64, len: u64) -> Result<usize, FsError>;

    /// Reads up to `size` bytes at `offset` through a read-only handle opened and released
    /// around the call.
    fn read_at(&self, ino: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError>;

    /// Reads up to `size` bytes at `offset` through the open handle `fh`, waiting for the
    /// reply if the read was deferred to the read pool.
    fn read_blocking(&self, ino: u64, fh: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError>;

    /// Reads the whole file in 64 KiB chunks through one read-only handle, stopping at the
    /// first short read.
    fn read_all(&self, ino: u64) -> Result<Vec<u8>, FsError>;

    /// Runs `fsync` on `fh` and waits for the flush it triggers to become durable.
    fn fsync_blocking(&self, ino: u64, fh: u64) -> Result<(), FsError>;

    /// Runs `fsyncdir` on `ino` and waits for the flush it triggers to become durable.
    fn fsyncdir_blocking(&self, ino: u64) -> Result<(), FsError>;

    /// Creates a regular file and returns its inode number.
    fn create_file(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError>;

    /// Creates a directory and returns its inode number.
    fn make_dir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError>;

    /// Creates a symlink to `target` and returns its inode number.
    fn make_symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, FsError>;

    /// Creates a special file (FIFO, socket or device, per `mode`) and returns its inode
    /// number.
    fn make_node(&self, parent: u64, name: &str, mode: u32, rdev: u32) -> Result<u64, FsError>;

    /// Removes the non-directory entry `name` from `parent`.
    fn remove_file(&self, parent: u64, name: &str) -> Result<(), FsError>;

    /// Removes the empty directory `name` from `parent`.
    fn remove_dir(&self, parent: u64, name: &str) -> Result<(), FsError>;

    /// Moves `parent/name` to `newparent/newname`, replacing what is there if allowed.
    fn rename_entry(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), FsError>;

    /// Adds `newparent/newname` as another name for `ino`.
    fn hard_link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), FsError>;

    /// Returns the target a symlink points to.
    fn symlink_target(&self, ino: u64) -> Result<String, FsError>;

    /// Opens a file handle with `flags`, as `open(2)` would, and returns it.
    fn open_file(&self, ino: u64, flags: u32) -> Result<u64, FsError>;

    /// Releases a handle returned by [`FsTestExt::open_file`].
    fn release_file(&self, ino: u64, fh: u64) -> Result<(), FsError>;

    /// Opens a directory handle and returns it.
    fn open_dir(&self, ino: u64) -> Result<u64, FsError>;

    /// Releases a handle returned by [`FsTestExt::open_dir`].
    fn release_dir(&self, ino: u64, fh: u64) -> Result<(), FsError>;

    /// Deallocates `len` bytes at `offset`, which then read back as zeros.
    fn punch_hole(&self, ino: u64, offset: u64, len: u64) -> Result<(), FsError>;

    /// Applies the attributes set in `changes`, leaving the rest untouched.
    fn set_attrs(&self, ino: u64, changes: AttrChanges) -> Result<(), FsError>;

    /// Sets an xattr; `flags` takes `XATTR_CREATE` / `XATTR_REPLACE` as `setxattr(2)` does.
    fn set_xattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<(), FsError>;

    /// Removes an xattr.
    fn remove_xattr(&self, ino: u64, name: &str) -> Result<(), FsError>;

    /// Reads an xattr's value through the real two-phase protocol (query the size, then
    /// fetch with that size), so it exercises the same size/ERANGE path a getxattr(2)
    /// caller does rather than asking for a large fixed buffer.
    fn xattr_value(&self, ino: u64, name: &str) -> Result<Vec<u8>, FsError>;

    /// Lists an inode's xattr names through the same two-phase protocol as
    /// [`FsTestExt::xattr_value`].
    fn xattr_names(&self, ino: u64) -> Result<Vec<String>, FsError>;

    /// Walks the tree from the root and captures every reachable inode, for comparing two
    /// filesystems. Built from the same handlers FUSE dispatch uses, never by reading the
    /// layer state directly. Virtual files are skipped.
    fn tree_snapshot(&self) -> HashMap<u64, SnapshotNode>;
}

/// The attributes [`FsTestExt::set_attrs`] changes; `None` leaves one as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttrChanges {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<SystemTime>,
    pub mtime: Option<SystemTime>,
}

/// One inode as captured by [`FsTestExt::tree_snapshot`].
#[derive(Debug, Clone)]
pub enum SnapshotNode {
    Directory {
        attr: FileAttr,
        entries: Vec<(String, u64)>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    File {
        attr: FileAttr,
        content: Vec<u8>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Symlink {
        attr: FileAttr,
        target: String,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Special {
        attr: FileAttr,
        xattrs: HashMap<String, Vec<u8>>,
    },
}

/// The identity new inodes are created with: the root directory's owner, as on a volume
/// mounted by that user. `TestFsBuilder::root_owner` sets it.
fn caller(fs: &AppendFs) -> Result<(u32, u32), FsError> {
    let root = getattr_core(fs, 1)?;
    Ok((root.uid, root.gid))
}

/// Runs a size query against an xattr handler, then the fetch with the size it reported.
fn two_phase_xattr(query: impl Fn(usize) -> Result<FuseResponse<'static>, FsError>) -> Result<Vec<u8>, FsError> {
    match query(0)? {
        // A 0-length value is indistinguishable from "just tell me the size" at size 0 -
        // the same ambiguity a real caller has - so there is no second call to make.
        FuseResponse::XattrSize(0) => Ok(Vec::new()),
        FuseResponse::XattrSize(size) => match query(size)? {
            FuseResponse::Buf(data) => Ok(data.to_vec()),
            FuseResponse::XattrSize(_) => unreachable!("size query answered with another size"),
            _ => unreachable!("unexpected xattr response"),
        },
        FuseResponse::Buf(_) => unreachable!("size query returned data"),
        _ => unreachable!("unexpected xattr response"),
    }
}

impl FsTestExt for AppendFs {
    fn write_at(&self, ino: u64, buf: &[u8], offset: i64) -> Result<usize, FsError> {
        let fh = open_core(self, ino, libc::O_RDWR as u32)?;
        let res = write_handle_core(self, ino, fh, buf, offset);
        let _ = release_core(self, ino, fh);
        res
    }

    fn copy_range(&self, ino_in: u64, off_in: i64, ino_out: u64, off_out: i64, len: u64) -> Result<usize, FsError> {
        let fh_in = open_core(self, ino_in, libc::O_RDONLY as u32)?;
        let res = open_core(self, ino_out, libc::O_WRONLY as u32).and_then(|fh_out| {
            let res = copy_file_range_core(self, ino_in, fh_in, off_in, ino_out, fh_out, off_out, len, 0);
            let _ = release_core(self, ino_out, fh_out);
            res
        });
        let _ = release_core(self, ino_in, fh_in);
        res
    }

    fn read_at(&self, ino: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError> {
        let fh = open_core(self, ino, libc::O_RDONLY as u32)?;
        let res = self.read_blocking(ino, fh, offset, size);
        let _ = release_core(self, ino, fh);
        res
    }

    fn read_blocking(&self, ino: u64, fh: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError> {
        let reply = read_response(self, ino, fh, offset, size).wait()?;
        Ok(reply.into_bytes().expect("read replied without a data buffer"))
    }

    fn read_all(&self, ino: u64) -> Result<Vec<u8>, FsError> {
        const CHUNK: usize = 64 * 1024;
        let fh = open_core(self, ino, libc::O_RDONLY as u32)?;
        let mut result = Vec::new();
        let res = loop {
            match self.read_blocking(ino, fh, result.len() as i64, CHUNK) {
                Ok(chunk) => {
                    let done = chunk.len() < CHUNK;
                    result.extend_from_slice(&chunk);
                    if done {
                        break Ok(result);
                    }
                }
                Err(err) => break Err(err),
            }
        };
        let _ = release_core(self, ino, fh);
        res
    }

    fn fsync_blocking(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        fsync_response(self, ino, fh, FlushReason::Fsync).wait().map(|_| ())
    }

    fn fsyncdir_blocking(&self, ino: u64) -> Result<(), FsError> {
        fsyncdir_response(self, ino, false).wait().map(|_| ())
    }

    fn create_file(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError> {
        let (uid, gid) = caller(self)?;
        create_core(self, parent, name, mode, 0, uid, gid).map(|attr| attr.ino)
    }

    fn make_dir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError> {
        let (uid, gid) = caller(self)?;
        mkdir_core(self, parent, name, mode, uid, gid).map(|attr| attr.ino)
    }

    fn make_symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, FsError> {
        let (uid, gid) = caller(self)?;
        symlink_core(self, parent, name, target, uid, gid).map(|attr| attr.ino)
    }

    fn make_node(&self, parent: u64, name: &str, mode: u32, rdev: u32) -> Result<u64, FsError> {
        let (uid, gid) = caller(self)?;
        mknod_core(self, parent, name, mode, rdev, uid, gid).map(|attr| attr.ino)
    }

    fn remove_file(&self, parent: u64, name: &str) -> Result<(), FsError> {
        unlink_core(self, parent, name)
    }

    fn remove_dir(&self, parent: u64, name: &str) -> Result<(), FsError> {
        rmdir_core(self, parent, name)
    }

    fn rename_entry(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), FsError> {
        rename_core(self, parent, name, newparent, newname)
    }

    fn hard_link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), FsError> {
        link_core(self, ino, newparent, newname).map(|_| ())
    }

    fn symlink_target(&self, ino: u64) -> Result<String, FsError> {
        readlink_core(self, ino)
    }

    fn open_file(&self, ino: u64, flags: u32) -> Result<u64, FsError> {
        open_core(self, ino, flags)
    }

    fn release_file(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        release_core(self, ino, fh)
    }

    fn open_dir(&self, ino: u64) -> Result<u64, FsError> {
        opendir_core(self, ino, 0)
    }

    fn release_dir(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        releasedir_core(self, ino, fh)
    }

    fn punch_hole(&self, ino: u64, offset: u64, len: u64) -> Result<(), FsError> {
        punch_hole_core(self, ino, offset, len)
    }

    fn set_xattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<(), FsError> {
        setxattr_core(self, ino, name, value, flags).map(|_| ())
    }

    fn remove_xattr(&self, ino: u64, name: &str) -> Result<(), FsError> {
        removexattr_core(self, ino, name).map(|_| ())
    }

    fn set_attrs(&self, ino: u64, changes: AttrChanges) -> Result<(), FsError> {
        let AttrChanges {
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
        } = changes;
        let to_set = [
            (mode.is_some(), FUSE_SET_ATTR_MODE),
            (uid.is_some(), FUSE_SET_ATTR_UID),
            (gid.is_some(), FUSE_SET_ATTR_GID),
            (size.is_some(), FUSE_SET_ATTR_SIZE),
            (atime.is_some(), FUSE_SET_ATTR_ATIME),
            (mtime.is_some(), FUSE_SET_ATTR_MTIME),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .fold(0, |mask, (_, bit)| mask | bit);
        setattr_core(
            self,
            ino,
            mode.unwrap_or(0),
            uid.unwrap_or(0),
            gid.unwrap_or(0),
            size.unwrap_or(0) as i64,
            atime.unwrap_or(UNIX_EPOCH),
            mtime.unwrap_or(UNIX_EPOCH),
            to_set,
        )
        .map(|_| ())
    }

    fn xattr_value(&self, ino: u64, name: &str) -> Result<Vec<u8>, FsError> {
        two_phase_xattr(|size| getxattr_core(self, ino, name, size))
    }

    fn xattr_names(&self, ino: u64) -> Result<Vec<String>, FsError> {
        let buf = two_phase_xattr(|size| listxattr_core(self, ino, size))?;
        Ok(buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect())
    }

    fn tree_snapshot(&self) -> HashMap<u64, SnapshotNode> {
        let mut snapshot = HashMap::new();
        let mut visited = HashSet::from([1u64]);
        let mut queue = VecDeque::from([1u64]);

        while let Some(ino) = queue.pop_front() {
            let Ok(attr) = getattr_core(self, ino) else {
                continue;
            };
            let xattrs = self
                .xattr_names(ino)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|name| {
                    let value = self.xattr_value(ino, &name).ok()?;
                    Some((name, value))
                })
                .collect();
            let node = match attr.file_type {
                FileType::Directory => {
                    let mut entries = list_dir_core(self, ino).unwrap_or_default();
                    entries.retain(|(_, child)| !crate::fs::is_virtual_ino(*child));
                    for (_, child) in &entries {
                        if visited.insert(*child) {
                            queue.push_back(*child);
                        }
                    }
                    SnapshotNode::Directory { attr, entries, xattrs }
                }
                FileType::RegularFile => {
                    let content = self.read_at(ino, 0, attr.size as usize).unwrap_or_default();
                    SnapshotNode::File { attr, content, xattrs }
                }
                FileType::Symlink => {
                    let target = readlink_core(self, ino).unwrap_or_default();
                    SnapshotNode::Symlink { attr, target, xattrs }
                }
                FileType::NamedPipe | FileType::CharDevice | FileType::BlockDevice | FileType::Socket => {
                    SnapshotNode::Special { attr, xattrs }
                }
            };
            snapshot.insert(ino, node);
        }

        snapshot
    }
}
