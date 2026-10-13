use crate::error::FsError;
use crate::extent_map::{Extent, ExtentMap};
use crate::fs::{AppendFs, FileHandle, FlushReason, FsInnerGuard, execute_read_plan, is_virtual_ino};
use crate::node::{AttrDelta, EntryDelta, FileDelta, NodeDelta};
use crate::shim::{
    DeferredCompletion, DeferredResult, DeferredToken, FileAttr, FileType, FuseResponse, RequestContext,
};
use crate::sync::OpTag;
use std::sync::Arc;
use std::time::SystemTime;

pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;

pub fn getattr_core(fs: &AppendFs, ino: u64) -> Result<FileAttr, FsError> {
    log::trace!("getattr(ino={})", ino);
    fs.with_inner(OpTag::GetAttr, |inner| {
        inner.check_shutdown(false)?;
        fs.get_attr_locked(inner, ino).ok_or(FsError::ENOENT)
    })
}

pub fn getattr_response(fs: &AppendFs, ino: u64) -> Result<FuseResponse<'static>, FsError> {
    getattr_core(fs, ino).map(FuseResponse::attr)
}

pub fn read_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    offset: i64,
    size: usize,
) -> DeferredResult<FuseResponse<'static>> {
    log::trace!("read(ino={}, fh={}, size={}, offset={})", ino, fh, size, offset);
    if offset < 0 {
        return DeferredResult::err(FsError::EINVAL);
    }

    let plan = match fs.plan_read_handle(ino, fh, offset as u64, size) {
        Ok(p) => p,
        Err(e) => return DeferredResult::err(e),
    };

    if !plan.has_cold_slices {
        // Fast path: 100% in-memory (zeros, staged buffers, or decrypted record cache hits)
        return DeferredResult::ready(
            execute_read_plan(plan, fs.log_cache.as_deref(), &fs.volume_key).map(FuseResponse::buf),
        );
    }

    let pool = fs.read_pool.read().unwrap().clone();
    let Some(pool) = pool else {
        // Without an active read threadpool (e.g. in unit tests or standalone tools),
        // execute synchronously on the caller thread.
        return DeferredResult::ready(
            execute_read_plan(plan, fs.log_cache.as_deref(), &fs.volume_key).map(FuseResponse::buf),
        );
    };

    // Cold read offload: dispatch to the dedicated read threadpool
    let (token, receiver) = DeferredToken::new();
    let guard = fs.begin_async_op();
    let log_cache = fs.log_cache.clone();
    let volume_key = fs.volume_key.clone();

    if let Err(e) = pool.spawn(move || {
        let _guard = guard;
        let res = execute_read_plan(plan, log_cache.as_deref(), &volume_key);
        token.complete(res.map(FuseResponse::buf));
    }) {
        return DeferredResult::err(e);
    }

    DeferredResult::deferred(receiver)
}

pub fn open_core(fs: &AppendFs, ino: u64, flags: u32) -> Result<u64, FsError> {
    let write_requested = (flags as i32 & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND)) != 0;

    if is_virtual_ino(ino) {
        if write_requested {
            return Err(FsError::EACCES);
        }
        // Virtual files generate content outside the inner lock to prevent lock-ordering inversions
        // or self-deadlocks (since status generators query filesystem layer state).
        let content = fs.virtual_files.generate_content(ino, fs).unwrap_or_default();
        fs.with_inner(OpTag::Open, |inner| {
            inner.check_shutdown(write_requested)?;
            let attr = fs.get_attr_locked(inner, ino).ok_or(FsError::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(FsError::EISDIR);
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
            inner.check_shutdown(write_requested)?;
            let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(FsError::EISDIR);
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

pub fn open_response(fs: &AppendFs, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError> {
    let is_virtual = is_virtual_ino(ino);
    open_core(fs, ino, flags).map(|fh| {
        FuseResponse::open(
            fh,
            /* direct_io = */ is_virtual,
            /* keep_cache = */ !is_virtual,
        )
    })
}

pub fn write_handle_core(fs: &AppendFs, ino: u64, fh: u64, buf: &[u8], offset: i64) -> Result<usize, FsError> {
    log::trace!("write(ino={}, fh={}, len={}, offset={})", ino, fh, buf.len(), offset);
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }

    if offset < 0 {
        return Err(FsError::EINVAL);
    }

    let now = fs.clock.now();
    let file_offset = offset as u64;
    let write_len = buf.len() as u64;

    fs.with_inner(OpTag::Write, |inner| {
        inner.check_shutdown(true)?;
        inner.validate_regular_handle(ino, fh)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(FsError::EBADF);
        }

        if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
            return Err(FsError::ENOENT);
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

pub fn write_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    buf: &[u8],
    offset: i64,
) -> Result<FuseResponse<'static>, FsError> {
    write_handle_core(fs, ino, fh, buf, offset).map(FuseResponse::write)
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_core(
    fs: &AppendFs,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FileAttr, FsError> {
    log::trace!(
        "setattr(ino={}, mode=0o{:o}, uid={}, gid={}, size={}, to_set=0x{:x})",
        ino,
        mode,
        uid,
        gid,
        size,
        to_set
    );

    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
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
        inner.check_shutdown(true)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;

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
        inner.get_attr(ino).ok_or(FsError::ENOENT)
    })
}

/// Internal helper: punches a zero hole in `[offset, offset + len)` within an already-locked `FsInner`.
fn punch_hole_locked(
    inner: &mut FsInnerGuard<'_>,
    ino: u64,
    offset: u64,
    len: u64,
    now: SystemTime,
) -> Result<(), FsError> {
    let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(FsError::EISDIR);
    }

    let file_size = attr.size as u64;
    let end = std::cmp::min(offset.saturating_add(len), file_size);
    if len == 0 || offset >= end {
        return Ok(());
    }

    if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
        return Err(FsError::ENOENT);
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
pub fn punch_hole_core(fs: &AppendFs, ino: u64, offset: u64, len: u64) -> Result<(), FsError> {
    log::trace!("punch_hole(ino={}, offset={}, len={})", ino, offset, len);
    let now = fs.clock.now();
    fs.with_inner(OpTag::Fallocate, |inner| {
        inner.check_shutdown(true)?;
        punch_hole_locked(inner, ino, offset, len, now)
    })
}

/// Internal helper: raises a file's recorded size to `new_size` within an already-locked `FsInner`.
fn grow_size_locked(inner: &mut FsInnerGuard<'_>, ino: u64, new_size: u64, now: SystemTime) -> Result<(), FsError> {
    let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
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
pub fn fallocate_core(fs: &AppendFs, ino: u64, mode: i32, offset: i64, length: i64) -> Result<(), FsError> {
    log::trace!(
        "fallocate(ino={}, mode=0x{:x}, offset={}, length={})",
        ino,
        mode,
        offset,
        length
    );
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }
    if offset < 0 || length <= 0 {
        return Err(FsError::EINVAL);
    }

    const SUPPORTED: i32 = libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE;
    if mode & !SUPPORTED != 0 {
        // Notably COLLAPSE_RANGE and INSERT_RANGE, which shift every byte above the range
        // and would mean re-keying every extent above `offset` in every layer - including
        // expressing that shift in a delta relative to `base`. Refusing is spec-legal.
        return Err(FsError::EOPNOTSUPP);
    }

    if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 && mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
        return Err(FsError::EINVAL);
    }

    let start = offset as u64;
    let len = length as u64;
    let end = start.saturating_add(len);
    let now = fs.clock.now();

    fs.with_inner(OpTag::Fallocate, |inner| {
        inner.check_shutdown(true)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(FsError::EISDIR);
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

/// Most bytes one `copy_file_range` call copies: the kernel's `MAX_RW_COUNT`. The FUSE reply
/// carries the count in 32 bits, and a short copy is legal - callers loop until done.
const MAX_COPY_LEN: u64 = i32::MAX as u64 & !0xfff;

/// `copy_file_range(2)`: makes `[off_out, off_out + len)` of `ino_out` read as
/// `[off_in, off_in + len)` of `ino_in` reads now, without copying a byte.
///
/// The destination takes the source's extents themselves. Flushed data is shared: the
/// destination's delta records reference the source's log records, wherever and in whichever
/// generation they are. Data still staged is shared in memory and written out once more with
/// the destination, since it has no record to reference yet. Holes stay holes.
///
/// Returns how many bytes were copied, which is short of `len` when the source ends first.
#[allow(clippy::too_many_arguments)]
pub fn copy_file_range_core(
    fs: &AppendFs,
    ino_in: u64,
    fh_in: u64,
    off_in: i64,
    ino_out: u64,
    fh_out: u64,
    off_out: i64,
    len: u64,
    flags: u32,
) -> Result<usize, FsError> {
    log::trace!(
        "copy_file_range(ino_in={}, off_in={}, ino_out={}, off_out={}, len={})",
        ino_in,
        off_in,
        ino_out,
        off_out,
        len
    );
    if is_virtual_ino(ino_in) || is_virtual_ino(ino_out) {
        // Not refused outright: the kernel answers this by copying through read and write,
        // which serve virtual files - or refuse them - the way they always do.
        return Err(FsError::EOPNOTSUPP);
    }
    if flags != 0 || off_in < 0 || off_out < 0 {
        return Err(FsError::EINVAL);
    }

    let now = fs.clock.now();
    let (off_in, off_out) = (off_in as u64, off_out as u64);

    fs.with_inner(OpTag::CopyFileRange, |inner| {
        inner.check_shutdown(true)?;
        inner.validate_regular_handle(ino_in, fh_in)?;
        inner.validate_regular_handle(ino_out, fh_out)?;
        let src_attr = inner.get_attr(ino_in).ok_or(FsError::ENOENT)?;
        let dst_attr = inner.get_attr(ino_out).ok_or(FsError::ENOENT)?;
        if src_attr.file_type != FileType::RegularFile || dst_attr.file_type != FileType::RegularFile {
            return Err(FsError::EINVAL);
        }

        let src_size = src_attr.size as u64;
        if off_in >= src_size {
            return Ok(0);
        }
        let len = len.min(src_size - off_in).min(MAX_COPY_LEN);
        if len == 0 {
            return Ok(0);
        }
        let end_out = off_out.checked_add(len).filter(|&end| end <= i64::MAX as u64);
        let Some(end_out) = end_out else {
            return Err(FsError::EFBIG);
        };
        if ino_in == ino_out && off_in < end_out && off_out < off_in + len {
            return Err(FsError::EINVAL);
        }

        let extents = inner.with_inode_layers(ino_in, |layers| layers.resolve_extents(off_in, len));
        let staged_bytes: u64 = extents
            .iter()
            .filter(|(_, extent)| extent.is_staged())
            .map(|(_, extent)| extent.length())
            .sum();

        let entry = inner
            .live
            .entry(ino_out)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            for (start, extent) in extents {
                f.extents.insert(start - off_in + off_out, extent);
            }
            let current_size = f.size.unwrap_or(dst_attr.size as u64);
            f.size = Some(current_size.max(end_out));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
        inner.record_mutation(staged_bytes as usize);
        Ok(len as usize)
    })
}

#[allow(clippy::too_many_arguments)]
pub fn copy_file_range_response(
    fs: &AppendFs,
    ino_in: u64,
    fh_in: u64,
    off_in: i64,
    ino_out: u64,
    fh_out: u64,
    off_out: i64,
    len: u64,
    flags: u32,
) -> Result<FuseResponse<'static>, FsError> {
    copy_file_range_core(fs, ino_in, fh_in, off_in, ino_out, fh_out, off_out, len, flags).map(FuseResponse::write)
}

pub fn fallocate_response(
    fs: &AppendFs,
    ino: u64,
    mode: i32,
    offset: i64,
    length: i64,
) -> Result<FuseResponse<'static>, FsError> {
    fallocate_core(fs, ino, mode, offset, length).map(|()| FuseResponse::ok())
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_response(
    fs: &AppendFs,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FuseResponse<'static>, FsError> {
    setattr_core(fs, ino, mode, uid, gid, size, atime, mtime, to_set).map(FuseResponse::attr)
}
#[allow(clippy::too_many_arguments)]
fn create_internal(
    fs: &AppendFs,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
    open_handle: bool,
) -> Result<(FileAttr, Option<u64>), FsError> {
    fs.with_inner(OpTag::Create, |inner| {
        inner.check_shutdown(true)?;
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
            return Err(FsError::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(FsError::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(FsError::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, parent, name).is_some() {
            return Err(FsError::EEXIST);
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
    fs: &AppendFs,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, FsError> {
    create_internal(fs, parent, name, mode, flags, uid, gid, false).map(|(attr, _)| attr)
}

pub fn create_response(
    fs: &AppendFs,
    ctx: RequestContext,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
) -> Result<FuseResponse<'static>, FsError> {
    create_internal(fs, parent, name, mode, flags, ctx.uid, ctx.gid, true)
        .map(|(attr, fh)| FuseResponse::create(attr, fh.unwrap()))
}

pub struct FsyncDeferred(pub crate::fs::BatchCompletion);

impl DeferredCompletion<FuseResponse<'static>> for FsyncDeferred {
    fn on_complete(
        self: Box<Self>,
        callback: Box<dyn FnOnce(Result<FuseResponse<'static>, FsError>) + Send + 'static>,
    ) {
        self.0.add_callback(Box::new(move |result| {
            let res = result.map(|()| FuseResponse::ok()).map_err(FsError::from);
            callback(res);
        }));
    }
}

pub fn fsync_response(fs: &AppendFs, ino: u64, fh: u64, reason: FlushReason) -> DeferredResult<FuseResponse<'static>> {
    let completion = match fs.rollover_for_fsync(ino, fh, reason) {
        Ok(c) => c,
        Err(e) => return DeferredResult::err(e),
    };

    let Some(completion) = completion else {
        return DeferredResult::ok_void();
    };

    fs.wake_flusher();
    DeferredResult::deferred(FsyncDeferred(completion))
}

pub fn release_core(fs: &AppendFs, ino: u64, fh: u64) -> Result<(), FsError> {
    fs.release_file_handle(fh, ino)
}

pub fn release_response(fs: &AppendFs, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
    release_core(fs, ino, fh).map(|()| FuseResponse::ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::AppendFs;
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use crate::{Storage, SystemClock};

    fn file_with(fs: &AppendFs, contents: &[u8]) -> u64 {
        let ino = fs.create_file(1, "f.bin", 0o644).unwrap();
        fs.write_at(ino, contents, 0).unwrap();
        ino
    }

    #[test]
    fn test_fallocate_mode_dispatch() {
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xAB; 512]);

        // Modes that shift file contents are refused outright. Silently ignoring the flag
        // and allocating instead would leave the caller's data at the wrong offsets.
        for mode in [libc::FALLOC_FL_COLLAPSE_RANGE, libc::FALLOC_FL_INSERT_RANGE] {
            assert_eq!(fallocate_core(&fs, ino, mode, 0, 128), Err(FsError::EOPNOTSUPP));
        }

        // `vfs_fallocate` screens this pairing before FUSE sees it, but the check still has
        // to hold for direct callers.
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE, 0, 128),
            Err(FsError::EINVAL)
        );

        assert_eq!(fallocate_core(&fs, ino, 0, -1, 128), Err(FsError::EINVAL));
        assert_eq!(fallocate_core(&fs, ino, 0, 0, 0), Err(FsError::EINVAL));

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
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xCD; 512]);
        fallocate_core(&fs, ino, libc::FALLOC_FL_ZERO_RANGE, 256, 512).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 768);
        let data = fs.read_file_data(ino, 0, 768).unwrap();
        assert_eq!(&data[..256], &[0xCD; 256]);
        assert!(data[256..].iter().all(|&b| b == 0));

        // With KEEP_SIZE it zeroes the live part without extending.
        let fs2 = TestFs::builder().build().fs;
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
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xEF; 128]);
        fs.set_read_only();
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, 0, 64),
            Err(FsError::EROFS)
        );
        assert_eq!(punch_hole_core(&fs, ino, 0, 64), Err(FsError::EROFS));
    }

    #[test]
    fn test_setattr_and_fallocate_single_lock_acquisition() {
        let fs = TestFs::builder().build().fs;
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
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        let file = fs.create_file(1, "fsync_lock.bin", 0o644).unwrap();
        let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
        fs.write_at(file, b"test", 0).unwrap();

        let pre_total = fs.inner.lock_count();
        let pre_stats = fs.inner.op_stats();
        let pre_flush = pre_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Call the fsync rollover with open file handle fh
        let res = fs.rollover_for_fsync(file, fh, FlushReason::Fsync);
        assert!(res.is_ok());

        let post_total = fs.inner.lock_count();
        let post_stats = fs.inner.op_stats();
        let post_flush = post_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Exactly 1 lock acquisition performed for both handle validation and live rollover
        assert_eq!(post_total - pre_total, 1);
        assert_eq!(post_flush - pre_flush, 1);
    }

    #[test]
    fn test_fsync_and_fsyncdir() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        let file = fs.create_file(1, "fsync.bin", 0o644).unwrap();
        let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
        fs.write_at(file, b"fsync test", 0).unwrap();

        let res = fs.fsync_blocking(file, fh);
        assert_eq!(res, Ok(()));

        let dir_res = fs.fsyncdir_blocking(1);
        assert_eq!(dir_res, Ok(()));
    }

    #[test]
    fn test_file_create_name_length_boundaries() {
        let fs = TestFs::builder().build().fs;

        // 255-byte name should succeed for create
        let name_255 = "f".repeat(255);
        let attr_255 = create_core(&fs, 1, &name_255, 0o644, 0, 1000, 1000).unwrap();
        assert_eq!(attr_255.file_type, FileType::RegularFile);

        // 256-byte name should fail with ENAMETOOLONG
        let name_256 = "f".repeat(256);
        assert_eq!(fs.create_file(1, &name_256, 0o644), Err(FsError::ENAMETOOLONG));
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn test_copy_file_range_references_records_of_an_older_generation() {
        let mut tfs = TestFs::builder().build();
        // 64-byte records, so the copy below spans three and starts and ends inside one.
        tfs.set_max_extent_size(64);
        let src_data = pattern(200);
        let src = tfs.fs.create_file(1, "src.bin", 0o644).unwrap();
        tfs.fs.write_at(src, &src_data, 0).unwrap();
        tfs.fs.quiesce().unwrap();
        tfs.fs.force_roll_active_log().unwrap();

        let dst = tfs.fs.create_file(1, "dst.bin", 0o644).unwrap();
        tfs.fs.write_at(dst, &[0xEE; 300], 0).unwrap();
        tfs.fs.quiesce().unwrap();
        let data_bytes_before = tfs.fs.log_writer.as_ref().unwrap().total_data_bytes();

        assert_eq!(tfs.fs.copy_range(src, 50, dst, 10, 100), Ok(100));
        let mut expected = vec![0xEE; 300];
        expected[10..110].copy_from_slice(&src_data[50..150]);
        assert_eq!(tfs.fs.read_all(dst).unwrap(), expected);

        tfs.fs.quiesce().unwrap();
        assert_eq!(
            tfs.fs.log_writer.as_ref().unwrap().total_data_bytes(),
            data_bytes_before,
            "the copy must not write any data"
        );
        let stats = tfs.fs.calculate_generation_live_stats();
        let gen1 = stats.iter().find(|g| g.generation == 1).unwrap();
        assert_eq!(gen1.live_bytes, 200, "bytes referenced twice are live once");

        let tfs = tfs.unclean_crash();
        assert_eq!(tfs.fs.read_all(dst).unwrap(), expected, "replayed from the log");
        let tfs = tfs.clean_remount();
        assert_eq!(tfs.fs.read_all(dst).unwrap(), expected, "loaded from the summary");
        assert_eq!(tfs.fs.read_all(src).unwrap(), src_data);
    }

    #[test]
    fn test_copy_file_range_of_unflushed_data_and_holes_is_a_snapshot() {
        let tfs = TestFs::builder().build();
        let fs = &tfs.fs;
        // The destination's flushed bytes must be masked wherever the source has a hole.
        let dst = fs.create_file(1, "dst.bin", 0o644).unwrap();
        fs.write_at(dst, &[0xEE; 500], 0).unwrap();
        fs.quiesce().unwrap();

        // Staged data with a punched hole, then an implicit one: [300, 400) was never written.
        let src = fs.create_file(1, "src.bin", 0o644).unwrap();
        fs.write_at(src, &[0xAA; 300], 0).unwrap();
        fs.write_at(src, &[0xCC; 10], 400).unwrap();
        fs.punch_hole(src, 100, 50).unwrap();

        assert_eq!(
            fs.copy_range(src, 0, dst, 0, 1000),
            Ok(410),
            "stops at the source's EOF"
        );
        let mut expected = vec![0xAA; 300];
        expected[100..150].fill(0);
        expected.extend_from_slice(&[0; 100]);
        expected.extend_from_slice(&[0xCC; 10]);
        expected.extend_from_slice(&[0xEE; 90]);

        // Writes to the source after the copy do not reach it, flushed or not.
        fs.write_at(src, &[0xBB; 410], 0).unwrap();
        assert_eq!(fs.read_all(dst).unwrap(), expected);
        fs.quiesce().unwrap();
        assert_eq!(fs.read_all(dst).unwrap(), expected);

        let tfs = tfs.unclean_crash();
        assert_eq!(tfs.fs.read_all(dst).unwrap(), expected);
        assert_eq!(tfs.fs.read_all(src).unwrap(), vec![0xBB; 410]);
    }

    #[test]
    fn test_copy_file_range_bounds_and_refusals() {
        let tfs = TestFs::builder().build();
        let fs = &tfs.fs;
        let src = file_with(fs, &[0x11; 100]);
        let dst = fs.create_file(1, "dst.bin", 0o644).unwrap();

        // Nothing to copy at or past the source's EOF.
        assert_eq!(fs.copy_range(src, 100, dst, 0, 10), Ok(0));
        assert_eq!(fs.copy_range(src, 500, dst, 0, 10), Ok(0));
        assert_eq!(fs.get_attr(dst).unwrap().size, 0);

        // Copying past the destination's EOF grows it, leaving a hole.
        assert_eq!(fs.copy_range(src, 90, dst, 1000, 50), Ok(10));
        assert_eq!(fs.get_attr(dst).unwrap().size, 1010);
        let data = fs.read_all(dst).unwrap();
        assert!(data[..1000].iter().all(|&b| b == 0));
        assert_eq!(&data[1000..], &[0x11; 10]);

        // Within one file, disjoint ranges copy and overlapping ones are refused.
        assert_eq!(fs.copy_range(src, 0, src, 100, 50), Ok(50));
        assert_eq!(fs.get_attr(src).unwrap().size, 150);
        assert_eq!(fs.copy_range(src, 0, src, 20, 50), Err(FsError::EINVAL));

        assert_eq!(fs.copy_range(src, -1, dst, 0, 10), Err(FsError::EINVAL));
        assert_eq!(fs.copy_range(src, 0, dst, -1, 10), Err(FsError::EINVAL));
        assert_eq!(fs.copy_range(src, 0, dst, i64::MAX - 5, 10), Err(FsError::EFBIG));

        let fh_in = open_core(fs, src, libc::O_RDONLY as u32).unwrap();
        let fh_out = open_core(fs, dst, libc::O_WRONLY as u32).unwrap();
        assert_eq!(
            copy_file_range_core(fs, src, fh_in, 0, dst, fh_out, 0, 10, 1),
            Err(FsError::EINVAL),
            "no flags are defined"
        );
        // Left to the kernel's read/write fallback, which handles virtual files.
        assert_eq!(
            copy_file_range_core(fs, crate::fs::VIRTUAL_INO_BASE, 0, 0, dst, fh_out, 0, 10, 0),
            Err(FsError::EOPNOTSUPP)
        );
        fs.set_read_only();
        assert_eq!(
            copy_file_range_core(fs, src, fh_in, 0, dst, fh_out, 0, 10, 0),
            Err(FsError::EROFS)
        );
    }
}
