use crate::extent_map::{Extent, ExtentMap};
use crate::fs::{FileHandle, FsInner, InMemoryFS};
use crate::node::{AttrDelta, EntryDelta, FileDelta, NodeDelta};
use crate::shim::{FileAttr, FileType, Request};
use crate::sync::OpTag;
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

pub fn read_core(fs: &InMemoryFS, ino: u64, fh: u64, offset: i64, size: usize) -> Result<Vec<u8>, i32> {
    log::trace!("read(ino={}, fh={}, size={}, offset={})", ino, fh, size, offset);
    if offset < 0 {
        return Err(libc::EINVAL);
    }
    fs.read_handle(ino, fh, offset as u64, size)
}

pub fn read(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("read(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    if offset < 0 {
        req.reply_err(libc::EINVAL);
        return;
    }

    let plan = match fs.plan_read_handle(ino, fh, offset as u64, size) {
        Ok(p) => p,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    // Zero-copy fast path: single in-memory/cache slice or empty/zero read
    if plan.is_single_borrowable_slice() {
        plan.execute_single_slice(|buf| req.reply_buf(buf));
        return;
    }

    // Fast path: small in-memory read (<= 128 KiB) with zero cold disk slices
    const MAX_INLINE_READ_BYTES: usize = 128 * 1024;
    if !plan.has_cold_slices && plan.total_len <= MAX_INLINE_READ_BYTES {
        match fs.execute_read_plan_sync(plan) {
            Ok(buf) => req.reply_buf(&buf),
            Err(e) => req.reply_err(e),
        }
        return;
    }

    // Async offload: cold disk/remote read or large in-memory read
    let log_cache = fs.log_cache.clone();
    let volume_key = fs.volume_key.clone();
    let guard = fs.begin_async_op();
    crate::async_runtime::spawn(async move {
        let _guard = guard;
        match InMemoryFS::execute_read_plan_async(plan, log_cache, volume_key).await {
            Ok(buf) => req.reply_buf(&buf),
            Err(e) => req.reply_err(e),
        }
    });
}

pub fn open_core(fs: &InMemoryFS, ino: u64, flags: u32) -> Result<u64, i32> {
    let write_requested = (flags as i32 & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND)) != 0;
    if write_requested && fs.is_read_only() {
        return Err(libc::EROFS);
    }

    if fs.is_virtual_ino(ino) {
        if write_requested {
            return Err(libc::EACCES);
        }
        // Virtual files generate content outside the inner lock to prevent lock-ordering inversions
        // or self-deadlocks (since status generators query filesystem layer state).
        let content = fs.virtual_files.generate_content(ino, fs).unwrap_or_default();
        fs.with_inner(OpTag::Open, |inner| {
            let attr = fs.get_attr_locked(inner, ino).ok_or(libc::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(libc::EISDIR);
            }
            let fh = inner.allocate_fh();
            inner.insert_file_handle(
                fh,
                FileHandle::Virtual {
                    ino,
                    flags,
                    data: Arc::new(content.into_bytes()),
                },
            );
            Ok(fh)
        })
    } else {
        // Regular files: validate, open, and optionally truncate in a single critical section!
        let now = fs.clock.now();
        let trunc = (flags & libc::O_TRUNC as u32) != 0;
        fs.with_inner(OpTag::Open, |inner| {
            let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(libc::EISDIR);
            }
            let fh = inner.allocate_fh();
            inner.insert_file_handle(fh, FileHandle::Regular { ino, flags });
            if trunc {
                let entry = inner
                    .live
                    .entry(ino)
                    .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
                if let EntryDelta::Node(NodeDelta::File(f)) = entry {
                    let mask_len = u64::MAX;
                    f.extents.insert(0, Extent::new_zero(mask_len));
                    f.size = Some(0);
                    f.attr_delta.mtime = Some(now);
                    f.attr_delta.ctime = Some(now);
                }
                inner.record_mutation(0);
            }
            Ok(fh)
        })
    }
}

pub fn open(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("open(ino={}, flags=0x{:x})", ino, flags);
    match open_core(fs, ino, flags) {
        Ok(fh) => req.reply_open(fh, fs.is_virtual_ino(ino)),
        Err(e) => req.reply_err(e),
    }
}

pub fn write_handle_core(fs: &InMemoryFS, ino: u64, fh: u64, buf: &[u8], offset: i64) -> Result<usize, i32> {
    log::trace!("write(ino={}, fh={}, len={}, offset={})", ino, fh, buf.len(), offset);
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }

    if offset < 0 {
        return Err(libc::EINVAL);
    }

    let now = fs.clock.now();
    let file_offset = offset as u64;
    let write_len = buf.len() as u64;

    fs.with_inner(OpTag::Write, |inner| {
        inner.validate_regular_handle(ino, fh)?;
        let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(libc::EBADF);
        }

        if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
            return Err(libc::ENOENT);
        }

        let slices = inner.live_arena.append(buf);

        let entry = inner
            .live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            let mut cur_offset = file_offset;
            for (chunk_data, payload_offset, slice_len) in slices {
                let extent = Extent::new_staged(chunk_data, payload_offset, slice_len);
                f.extents.insert(cur_offset, extent);
                cur_offset += slice_len as u64;
            }
            let current_size = f.size.unwrap_or(attr.size as u64);
            f.size = Some(std::cmp::max(current_size, file_offset + write_len));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
        inner.record_mutation(write_len as usize);
        Ok(buf.len())
    })
}

#[cfg(any(test, feature = "testing"))]
pub fn write_core(fs: &InMemoryFS, ino: u64, buf: &[u8], offset: i64) -> Result<usize, i32> {
    if fs.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }
    let fh = open_core(fs, ino, libc::O_RDWR as u32)?;
    let res = write_handle_core(fs, ino, fh, buf, offset);
    let _ = release_core(fs, ino, fh);
    res
}

pub fn write(fs: &InMemoryFS, req: Request, ino: u64, buf: &[u8], offset: i64, fh: u64) {
    log::trace!("write(ino={}, len={}, offset={}, fh={})", ino, buf.len(), offset, fh);
    match write_handle_core(fs, ino, fh, buf, offset) {
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
    if fs.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }

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

    fs.with_inner(OpTag::SetAttr, |inner| {
        let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;

        if (to_set & FUSE_SET_ATTR_SIZE) != 0 && attr.file_type == FileType::RegularFile {
            log::trace!("truncating file to {}", size);
            let new_size = size as u64;
            let entry = inner
                .live
                .entry(ino)
                .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
            if let EntryDelta::Node(NodeDelta::File(f)) = entry {
                let mask_len = u64::MAX - new_size;
                f.extents.insert(new_size, Extent::new_zero(mask_len));
                f.size = Some(new_size);
                f.attr_delta.mtime = Some(now);
                f.attr_delta.ctime = Some(now);
            }
        }

        inner.update_attr_delta(ino, attr_delta);
        inner.record_mutation(0);
        inner.get_attr(ino).ok_or(libc::ENOENT)
    })
}

/// Internal helper: punches a zero hole in `[offset, offset + len)` within an already-locked `FsInner`.
fn punch_hole_locked(inner: &mut FsInner, ino: u64, offset: u64, len: u64, now: SystemTime) -> Result<(), i32> {
    let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    let file_size = attr.size as u64;
    let end = std::cmp::min(offset.saturating_add(len), file_size);
    if len == 0 || offset >= end {
        return Ok(());
    }

    if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
        return Err(libc::ENOENT);
    }
    let entry = inner
        .live
        .entry(ino)
        .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
    if let EntryDelta::Node(NodeDelta::File(f)) = entry {
        f.extents.insert(offset, Extent::new_zero(end - offset));
        f.attr_delta.mtime = Some(now);
        f.attr_delta.ctime = Some(now);
    }
    inner.record_mutation(0);
    Ok(())
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
    let now = fs.clock.now();
    fs.with_inner(OpTag::Fallocate, |inner| {
        punch_hole_locked(inner, ino, offset, len, now)
    })
}

/// Internal helper: raises a file's recorded size to `new_size` within an already-locked `FsInner`.
fn grow_size_locked(inner: &mut FsInner, ino: u64, new_size: u64, now: SystemTime) -> Result<(), i32> {
    let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
    let entry = inner
        .live
        .entry(ino)
        .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
    if let EntryDelta::Node(NodeDelta::File(f)) = entry {
        let current = f.size.unwrap_or(attr.size as u64);
        if new_size > current {
            f.size = Some(new_size);
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }
    inner.record_mutation(0);
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
    if fs.is_virtual_ino(ino) {
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

    if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 && mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
        return Err(libc::EINVAL);
    }

    let start = offset as u64;
    let len = length as u64;
    let end = start.saturating_add(len);
    let now = fs.clock.now();

    fs.with_inner(OpTag::Fallocate, |inner| {
        let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(libc::EISDIR);
        }

        if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 {
            return punch_hole_locked(inner, ino, start, len, now);
        }

        if mode & libc::FALLOC_FL_ZERO_RANGE != 0 {
            punch_hole_locked(inner, ino, start, len, now)?;
            if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
                grow_size_locked(inner, ino, end, now)?;
            }
            return Ok(());
        }

        if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
            return Ok(());
        }

        grow_size_locked(inner, ino, end, now)
    })
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
#[allow(clippy::too_many_arguments)]
fn create_internal(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
    open_handle: bool,
) -> Result<(FileAttr, Option<u64>), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Create, |inner| {
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

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, parent, name).is_some() {
            return Err(libc::EEXIST);
        }

        let new_ino = fs.allocate_inode();
        let new_delta = NodeDelta::File(FileDelta {
            extents: ExtentMap::new(),
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

        inner.insert_new_node(new_ino, new_delta);
        inner.add_dir_entry(parent, name, new_ino, now);
        inner.record_mutation(name.len());

        let fh = if open_handle {
            let fh = inner.allocate_fh();
            inner.insert_file_handle(fh, FileHandle::Regular { ino: new_ino, flags });
            Some(fh)
        } else {
            None
        };

        Ok((
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
            },
            fh,
        ))
    })
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
    create_internal(fs, parent, name, mode, flags, uid, gid, false).map(|(attr, _)| attr)
}

pub fn create(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match create_internal(fs, parent, name, mode, flags, uid, gid, true) {
        Ok((attr, fh)) => {
            req.reply_create(&attr, 1.0, 1.0, fh.unwrap());
        }
        Err(e) => req.reply_err(e),
    }
}

#[cfg(any(test, feature = "testing"))]
pub async fn fsync_core(fs: &InMemoryFS, ino: u64, fh: u64) -> Result<(), i32> {
    let completion = fs.rollover_for_fsync(ino, fh)?;
    let Some(completion) = completion else {
        if let Some(ref writer) = fs.log_writer {
            let writer_clone = Arc::clone(writer);
            tokio::task::spawn_blocking(move || writer_clone.sync())
                .await
                .map_err(|_| libc::EIO)?
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }
        return Ok(());
    };

    if !fs.trigger_flusher_with_motivation(crate::log::FlushMotivation::Fsync) {
        let _ = fs.flush_with_motivation(crate::log::FlushMotivation::Fsync);
    }
    completion
        .wait()
        .await
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

pub fn fsync(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool, fh: u64) {
    log::trace!("fsync(ino={}, datasync={}, fh={})", ino, datasync, fh);
    let completion = match fs.rollover_for_fsync(ino, fh) {
        Ok(c) => c,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    let Some(completion) = completion else {
        if let Some(ref writer) = fs.log_writer {
            let guard = fs.begin_async_op();
            let writer_clone = Arc::clone(writer);
            crate::async_runtime::spawn(async move {
                let _guard = guard;
                let res = tokio::task::spawn_blocking(move || writer_clone.sync()).await;
                match res {
                    Ok(Ok(())) => req.reply_err(0),
                    Ok(Err(e)) => req.reply_err(e.raw_os_error().unwrap_or(libc::EIO)),
                    Err(_) => req.reply_err(libc::EIO),
                }
            });
            return;
        }
        req.reply_err(0);
        return;
    };

    if !fs.trigger_flusher_with_motivation(crate::log::FlushMotivation::Fsync) {
        let _ = fs.flush_with_motivation(crate::log::FlushMotivation::Fsync);
    }
    let guard = fs.begin_async_op();
    crate::async_runtime::spawn(async move {
        let _guard = guard;
        match completion.wait().await {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    });
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
    use crate::{LogWriter, Storage, SystemClock};

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

    #[test]
    fn test_setattr_and_fallocate_single_lock_acquisition() {
        let fs = InMemoryFS::new();
        let ino = file_with(&fs, &[0xAA; 1024]);

        // 1. setattr_core: mode and size change
        let pre_stats = fs.inner.op_stats();
        let pre_setattr = pre_stats.iter().find(|s| s.tag == OpTag::SetAttr).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let updated = setattr_core(
            &fs,
            ino,
            0o755,
            1001,
            1002,
            512,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
            FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_SIZE,
        )
        .unwrap();
        assert_eq!(updated.size, 512);
        assert_eq!(updated.perm, 0o755);

        let post_stats = fs.inner.op_stats();
        let post_setattr = post_stats.iter().find(|s| s.tag == OpTag::SetAttr).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition tagged OpTag::SetAttr, 0 GetAttr
        assert_eq!(post_setattr - pre_setattr, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);

        // 2. punch_hole_core
        let pre_stats = fs.inner.op_stats();
        let pre_fallocate = pre_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let pre_total = fs.inner.lock_count();

        punch_hole_core(&fs, ino, 100, 50).unwrap();

        let post_stats = fs.inner.op_stats();
        let post_fallocate = post_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_fallocate - pre_fallocate, 1);
        assert_eq!(post_total - pre_total, 1);

        // 3. fallocate_core with ZERO_RANGE (zeroing + extending file)
        let pre_stats = fs.inner.op_stats();
        let pre_fallocate = pre_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let pre_total = fs.inner.lock_count();

        fallocate_core(&fs, ino, libc::FALLOC_FL_ZERO_RANGE, 400, 300).unwrap();

        let post_stats = fs.inner.op_stats();
        let post_fallocate = post_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition tagged OpTag::Fallocate
        assert_eq!(post_fallocate - pre_fallocate, 1);
        assert_eq!(post_total - pre_total, 1);
        assert_eq!(fs.get_attr(ino).unwrap().size, 700);
    }

    #[test]
    fn test_fsync_single_lock_acquisition() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        let file = create_core(&fs, 1, "fsync_lock.bin", 0o644, 0, 1000, 1000).unwrap();
        let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
        write_core(&fs, file.ino, b"test", 0).unwrap();

        let pre_total = fs.inner.lock_count();
        let pre_stats = fs.inner.op_stats();
        let pre_flush = pre_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Call fsync_core rollover with open file handle fh
        let res = fs.rollover_for_fsync(file.ino, fh);
        assert!(res.is_ok());

        let post_total = fs.inner.lock_count();
        let post_stats = fs.inner.op_stats();
        let post_flush = post_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Exactly 1 lock acquisition performed for both handle validation and live rollover
        assert_eq!(post_total - pre_total, 1);
        assert_eq!(post_flush - pre_flush, 1);
    }

    #[test]
    fn test_fsync_and_fsyncdir_core_async() {
        crate::async_runtime::block_on(async {
            let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
            let clock = Arc::new(SystemClock);
            let writer = Arc::new(
                LogWriter::create(
                    storage.clone(),
                    1,
                    &*clock,
                    crate::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    crate::crypto::VolumeKey::plaintext_arc(),
                )
                .unwrap(),
            );
            let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
            let file = create_core(&fs, 1, "fsync_core.bin", 0o644, 0, 1000, 1000).unwrap();
            let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
            write_core(&fs, file.ino, b"async fsync test", 0).unwrap();

            let res = fsync_core(&fs, file.ino, fh).await;
            assert_eq!(res, Ok(()));

            let dir_res = crate::operations::dir::fsyncdir_core(&fs).await;
            assert_eq!(dir_res, Ok(()));
        });
    }
}
