use crate::fs::InMemoryFS;
use crate::log::SharedExtentState;
use crate::node::{AttrDelta, EntryDelta, FileDelta, NodeDelta};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType, Request};
use std::sync::Arc;
use std::time::SystemTime;

pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;

pub fn getattr_core(fs: &InMemoryFS, ino: u64) -> Result<FileAttr, i32> {
    log::trace!("getattr(ino={})", ino);
    fs.get_attr(ino).ok_or(libc::ENOENT)
}

pub fn getattr(fs: &InMemoryFS, req: Request, ino: u64) {
    match getattr_core(fs, ino) {
        Ok(attr) => req.reply_attr(&attr, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn read_core(fs: &InMemoryFS, ino: u64, size: usize, offset: i64) -> Result<Vec<u8>, i32> {
    log::trace!("read(ino={}, size={}, offset={})", ino, size, offset);
    if offset < 0 {
        return Err(libc::EINVAL);
    }
    if fs.virtual_files.is_virtual_ino(ino) {
        if let Some(content) = fs.virtual_files.generate_content(ino, fs) {
            let bytes = content.into_bytes();
            let start = (offset as usize).min(bytes.len());
            let end = (start + size).min(bytes.len());
            return Ok(bytes[start..end].to_vec());
        }
        return Err(libc::ENOENT);
    }
    fs.read_file_data(ino, offset as u64, size)
}

pub fn read(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("read(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    if (fh & crate::fs::VIRTUAL_FH_FLAG) != 0 {
        let handles = fs.virtual_handles.read().unwrap();
        if let Some(buf) = handles.get(&fh) {
            if offset < 0 {
                req.reply_err(libc::EINVAL);
                return;
            }
            let start = (offset as usize).min(buf.len());
            let end = (start + size).min(buf.len());
            req.reply_buf(&buf[start..end]);
            return;
        } else {
            req.reply_err(libc::EBADF);
            return;
        }
    }

    let handle = match fs.get_file_handle(fh) {
        Some(h) => h,
        None => {
            req.reply_err(libc::EBADF);
            return;
        }
    };
    if handle.ino != ino {
        req.reply_err(libc::EBADF);
        return;
    }
    match read_core(fs, ino, size, offset) {
        Ok(buf) => req.reply_buf(&buf),
        Err(e) => req.reply_err(e),
    }
}

pub fn open_core(fs: &InMemoryFS, ino: u64, flags: u32) -> Result<u64, i32> {
    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    if fs.is_read_only() && (flags as i32 & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND)) != 0 {
        return Err(libc::EROFS);
    }

    let fh = fs.open_file_handle(ino, flags);

    if (flags & libc::O_TRUNC as u32) != 0 {
        let now = fs.clock.now();
        let _ = setattr_core(fs, ino, 0, 0, 0, 0, now, now, FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_MTIME);
    }
    Ok(fh)
}

pub fn open(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("open(ino={}, flags=0x{:x})", ino, flags);
    match open_core(fs, ino, flags) {
        Ok(fh) => req.reply_open(fh),
        Err(e) => req.reply_err(e),
    }
}

pub fn write_core(fs: &InMemoryFS, ino: u64, buf: &[u8], offset: i64) -> Result<usize, i32> {
    log::trace!("write(ino={}, len={}, offset={})", ino, buf.len(), offset);
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.virtual_files.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }
    fs.check_flush_capacity()?;

    if offset < 0 {
        return Err(libc::EINVAL);
    }

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    let now = fs.clock.now();
    let file_offset = offset as u64;
    let write_len = buf.len() as u64;

    let data = Arc::new(buf.to_vec());
    let shared_state = SharedExtentState::new_staged(Arc::clone(&data), 0, buf.len() as u32);

    {
        let mut live = fs.live.write().unwrap();
        // The `get_attr` check above happened before this lock was taken, so the file may
        // have been unlinked in between. If its tombstone has already been frozen out of
        // `live`, inserting a delta here would resurrect the inode at the next fold.
        if !live.contains_key(&ino) && !fs.exists_below_live(ino) {
            return Err(libc::ENOENT);
        }
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            f.extents.insert(file_offset, write_len, shared_state.clone());
            // `f.size` is only `Some` here if an earlier op in this same live batch
            // already touched this file - otherwise this delta was just freshly
            // inserted above, possibly because a flush froze the previous one out from
            // under us in the window between the unlocked `get_attr` above and this
            // lock. In that case `attr.size` (read before the lock) can be stale - e.g.
            // a concurrent truncate that landed in that flush - so re-resolve the
            // current size from below `live` instead of trusting it.
            let current_size = f
                .size
                .or_else(|| fs.attr_below_live(ino).map(|a| a.size as u64))
                .unwrap_or(attr.size as u64);
            f.size = Some(std::cmp::max(current_size, file_offset + write_len));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }

    fs.notify_mutation(write_len as usize);

    Ok(buf.len())
}

pub fn write(fs: &InMemoryFS, req: Request, ino: u64, buf: &[u8], offset: i64, fh: u64) {
    log::trace!("write(ino={}, len={}, offset={}, fh={})", ino, buf.len(), offset, fh);
    let handle = match fs.get_file_handle(fh) {
        Some(h) => h,
        None => {
            req.reply_err(libc::EBADF);
            return;
        }
    };
    if handle.ino != ino {
        req.reply_err(libc::EBADF);
        return;
    }
    match write_core(fs, ino, buf, offset) {
        Ok(count) => req.reply_write(count),
        Err(e) => req.reply_err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_core(
    fs: &InMemoryFS,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FileAttr, i32> {
    log::trace!(
        "setattr(ino={}, mode=0o{:o}, uid={}, gid={}, size={}, to_set=0x{:x})",
        ino,
        mode,
        uid,
        gid,
        size,
        to_set
    );

    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.virtual_files.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }
    fs.check_flush_capacity()?;

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    let now = fs.clock.now();

    let mut attr_delta = AttrDelta::default();

    if (to_set & FUSE_SET_ATTR_MODE) != 0 {
        attr_delta.mode = Some(mode & 0o7777);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_UID) != 0 {
        attr_delta.uid = Some(uid);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_GID) != 0 {
        attr_delta.gid = Some(gid);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_ATIME) != 0 {
        attr_delta.atime = Some(atime);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_MTIME) != 0 {
        attr_delta.mtime = Some(mtime);
        attr_delta.ctime = Some(now);
    }

    if (to_set & FUSE_SET_ATTR_SIZE) != 0 && attr.file_type == FileType::RegularFile {
        log::trace!("truncating file to {}", size);
        let new_size = size as u64;
        let mut live = fs.live.write().unwrap();
        // The `get_attr` check above happened before this lock was taken, so the file may
        // have been unlinked in between. If its tombstone has already been frozen out of
        // `live`, inserting a delta here would resurrect the inode at the next fold.
        if !live.contains_key(&ino) && !fs.exists_below_live(ino) {
            return Err(libc::ENOENT);
        }
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            // One unbounded hole from the cut upwards. It does both jobs at once: it
            // replaces this delta's own extents above `new_size`, and it masks the layers
            // below, so a later grow re-exposes zeros rather than whatever `base` still
            // holds there. The size clamp in `read_file_data` hides that only for as long
            // as the file stays short.
            //
            // Unbounded rather than sized to the current file length, because a later
            // truncate overwrites this hole: sizing the replacement by the size the
            // *previous* truncate left behind would stop short of what that one had
            // masked, and the range between the two cuts would come back to life on the
            // next grow. This is exactly the reach the scalar `truncate_mask` used to
            // have.
            let mask_len = u64::MAX - new_size;
            f.extents
                .insert(new_size, mask_len, SharedExtentState::new_zero(mask_len));
            f.size = Some(new_size);
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }

    fs.update_attr_delta(ino, attr_delta);

    fs.notify_mutation(0);

    let updated_attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    Ok(updated_attr)
}

/// Deallocates `[offset, offset + len)`, leaving it reading as zeros without changing the
/// file size - the core of `fallocate(FALLOC_FL_PUNCH_HOLE)`.
///
/// This is truncate's interior-range sibling, and works the same way: rather than removing
/// the range from the live delta's extent map - which would leave the layer with no opinion
/// and let the read fall through to `base`, resurrecting the punched data - it inserts an
/// explicit `ExtentState::Zero` that masks whatever lies below.
pub fn punch_hole_core(fs: &InMemoryFS, ino: u64, offset: u64, len: u64) -> Result<(), i32> {
    log::trace!("punch_hole(ino={}, offset={}, len={})", ino, offset, len);
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    // Past EOF there is nothing to deallocate: those bytes already read as zeros, and a
    // punch must not extend the file.
    let file_size = attr.size as u64;
    let end = std::cmp::min(offset.saturating_add(len), file_size);
    if len == 0 || offset >= end {
        return Ok(());
    }

    let now = fs.clock.now();
    {
        let mut live = fs.live.write().unwrap();
        // As in `write_core`: `get_attr` ran before this lock, so the inode may have been
        // unlinked and its tombstone frozen out of `live` in between. Inserting a delta
        // then would resurrect it at the next fold.
        if !live.contains_key(&ino) && !fs.exists_below_live(ino) {
            return Err(libc::ENOENT);
        }
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            f.extents
                .insert(offset, end - offset, SharedExtentState::new_zero(end - offset));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }

    fs.notify_mutation(0);
    Ok(())
}

/// Raises a file's recorded size to `new_size`, without writing anything.
///
/// The gap needs no extents: reads zero-fill anything the extent map does not cover, so
/// growing the size alone is enough to make the new range read as zeros.
fn grow_size_to(fs: &InMemoryFS, ino: u64, new_size: u64) -> Result<(), i32> {
    let now = fs.clock.now();
    {
        let mut live = fs.live.write().unwrap();
        if !live.contains_key(&ino) && !fs.exists_below_live(ino) {
            return Err(libc::ENOENT);
        }
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            // As in `write_core`: only trust `f.size` if this delta already touched the
            // file, otherwise re-resolve from below `live`, since a flush may have frozen
            // the previous delta out from under us.
            let current = f
                .size
                .or_else(|| fs.attr_below_live(ino).map(|a| a.size as u64))
                .unwrap_or(0);
            if new_size > current {
                f.size = Some(new_size);
                f.attr_delta.mtime = Some(now);
                f.attr_delta.ctime = Some(now);
            }
        }
    }

    fs.notify_mutation(0);
    Ok(())
}

/// `fallocate(2)`.
///
/// Hole punching and zeroing are the modes that carry real weight here: they are how a
/// caller tells a log-structured filesystem that data is dead, which is what lets
/// compaction reclaim it.
///
/// Plain allocation cannot be honoured literally - there is no space to reserve in an
/// append-only log - so it only extends the file. That is a partial lie, but the honest
/// alternative is worse: glibc's `posix_fallocate` responds to `EOPNOTSUPP` by writing
/// zeros over the whole range by hand, so refusing a 1 GiB preallocation would push 1 GiB
/// of zeros through the write path.
pub fn fallocate_core(fs: &InMemoryFS, ino: u64, mode: i32, offset: i64, length: i64) -> Result<(), i32> {
    log::trace!(
        "fallocate(ino={}, mode=0x{:x}, offset={}, length={})",
        ino,
        mode,
        offset,
        length
    );
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.virtual_files.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }
    if offset < 0 || length <= 0 {
        return Err(libc::EINVAL);
    }

    const SUPPORTED: i32 = libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE;
    if mode & !SUPPORTED != 0 {
        // Notably COLLAPSE_RANGE and INSERT_RANGE, which shift every byte above the range
        // and would mean re-keying every extent above `offset` in every layer - including
        // expressing that shift in a delta relative to `base`. Refusing is spec-legal.
        return Err(libc::EOPNOTSUPP);
    }

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    let start = offset as u64;
    let len = length as u64;
    let end = start.saturating_add(len);

    if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 {
        // The kernel requires the pairing, and enforcing it keeps callers from assuming a
        // punch might extend the file.
        if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
            return Err(libc::EINVAL);
        }
        return punch_hole_core(fs, ino, start, len);
    }

    if mode & libc::FALLOC_FL_ZERO_RANGE != 0 {
        punch_hole_core(fs, ino, start, len)?;
        // Unlike a punch, zeroing past EOF grows the file unless KEEP_SIZE says otherwise.
        if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
            grow_size_to(fs, ino, end)?;
        }
        return Ok(());
    }

    if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
        // Nothing to reserve and nothing to resize.
        return Ok(());
    }
    grow_size_to(fs, ino, end)
}

pub fn fallocate(fs: &InMemoryFS, req: Request, ino: u64, mode: i32, offset: i64, length: i64, _fh: u64) {
    match fallocate_core(fs, ino, mode, offset, length) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setattr(
    fs: &InMemoryFS,
    req: Request,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) {
    match setattr_core(fs, ino, mode, uid, gid, size, atime, mtime, to_set) {
        Ok(attr) => req.reply_attr(&attr, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn create_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    let attr = {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!(
            "create(parent={}, name={}, mode=0o{:o}, flags=0x{:x}, uid={}, gid={})",
            parent,
            name,
            mode,
            flags,
            uid,
            gid
        );

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child(parent, name).is_some() {
            return Err(libc::EEXIST);
        }

        let new_ino = fs.allocate_inode();
        let new_delta = NodeDelta::File(FileDelta {
            extents: RangeMap::new(),
            size: Some(0),
            attr_delta: AttrDelta {
                mode: Some(mode & 0o7777),
                nlink: Some(1),
                uid: Some(uid),
                gid: Some(gid),
                atime: Some(now),
                mtime: Some(now),
                ctime: Some(now),
                created_at: Some(now),
                xattrs: None,
            },
        });

        fs.insert_new_node(new_ino, new_delta);
        fs.add_dir_entry(parent, name, new_ino, now);

        FileAttr {
            ino: new_ino,
            file_type: FileType::RegularFile,
            perm: mode & 0o7777,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    };

    fs.notify_mutation(0);

    Ok(attr)
}

pub fn create(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match create_core(fs, parent, name, mode, flags, uid, gid) {
        Ok(attr) => {
            let fh = fs.open_file_handle(attr.ino, flags);
            req.reply_create(&attr, 1.0, 1.0, fh);
        }
        Err(e) => req.reply_err(e),
    }
}

pub fn fsync(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool, fh: u64) {
    log::trace!("fsync(ino={}, datasync={}, fh={})", ino, datasync, fh);
    if fh != 0 {
        match fs.get_file_handle(fh) {
            Some(h) if h.ino == ino => {}
            _ => {
                req.reply_err(libc::EBADF);
                return;
            }
        }
    }
    let _ = fs.sync_log();
    req.reply_err(0);
}

pub fn release_core(fs: &InMemoryFS, ino: u64, fh: u64) -> Result<(), i32> {
    fs.release_file_handle(fh, ino)
}

pub fn release(fs: &InMemoryFS, req: Request, ino: u64, fh: u64) {
    log::trace!("release(ino={}, fh={})", ino, fh);
    match release_core(fs, ino, fh) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFS;

    fn file_with(fs: &InMemoryFS, contents: &[u8]) -> u64 {
        let attr = create_core(fs, 1, "f.bin", 0o644, 0, 1000, 1000).unwrap();
        write_core(fs, attr.ino, contents, 0).unwrap();
        attr.ino
    }

    #[test]
    fn test_fallocate_mode_dispatch() {
        let fs = InMemoryFS::new();
        let ino = file_with(&fs, &[0xAB; 512]);

        // Modes that shift file contents are refused outright. Silently ignoring the flag
        // and allocating instead would leave the caller's data at the wrong offsets.
        for mode in [libc::FALLOC_FL_COLLAPSE_RANGE, libc::FALLOC_FL_INSERT_RANGE] {
            assert_eq!(fallocate_core(&fs, ino, mode, 0, 128), Err(libc::EOPNOTSUPP));
        }

        // `vfs_fallocate` screens this pairing before FUSE sees it, but the check still has
        // to hold for direct callers.
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE, 0, 128),
            Err(libc::EINVAL)
        );

        assert_eq!(fallocate_core(&fs, ino, 0, -1, 128), Err(libc::EINVAL));
        assert_eq!(fallocate_core(&fs, ino, 0, 0, 0), Err(libc::EINVAL));

        // KEEP_SIZE alone has nothing to reserve, so it must leave the file untouched.
        assert_eq!(fallocate_core(&fs, ino, libc::FALLOC_FL_KEEP_SIZE, 0, 4096), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 512);

        // Plain allocation extends, and the new range reads as zeros.
        assert_eq!(fallocate_core(&fs, ino, 0, 512, 512), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 1024);
        let data = fs.read_file_data(ino, 0, 1024).unwrap();
        assert_eq!(&data[..512], &[0xAB; 512]);
        assert!(data[512..].iter().all(|&b| b == 0));

        // ...but allocating within the existing size must never shrink it.
        assert_eq!(fallocate_core(&fs, ino, 0, 0, 16), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 1024);
    }

    #[test]
    fn test_fallocate_zero_range_honours_keep_size() {
        // Without KEEP_SIZE, zeroing past EOF grows the file.
        let fs = InMemoryFS::new();
        let ino = file_with(&fs, &[0xCD; 512]);
        fallocate_core(&fs, ino, libc::FALLOC_FL_ZERO_RANGE, 256, 512).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 768);
        let data = fs.read_file_data(ino, 0, 768).unwrap();
        assert_eq!(&data[..256], &[0xCD; 256]);
        assert!(data[256..].iter().all(|&b| b == 0));

        // With KEEP_SIZE it zeroes the live part without extending.
        let fs2 = InMemoryFS::new();
        let ino2 = file_with(&fs2, &[0xCD; 512]);
        fallocate_core(
            &fs2,
            ino2,
            libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
            256,
            512,
        )
        .unwrap();
        assert_eq!(
            fs2.get_attr(ino2).unwrap().size,
            512,
            "KEEP_SIZE must suppress the extension"
        );
        let data2 = fs2.read_file_data(ino2, 0, 512).unwrap();
        assert_eq!(&data2[..256], &[0xCD; 256]);
        assert!(data2[256..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fallocate_rejected_on_read_only_mount() {
        let fs = InMemoryFS::new();
        let ino = file_with(&fs, &[0xEF; 128]);
        fs.set_read_only(true);
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, 0, 64),
            Err(libc::EROFS)
        );
        assert_eq!(punch_hole_core(&fs, ino, 0, 64), Err(libc::EROFS));
    }
}
