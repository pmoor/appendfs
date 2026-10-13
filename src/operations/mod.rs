pub mod dir;
pub mod links;
pub mod locks;
pub mod op;
pub mod read_write;
pub mod special;
pub mod statfs;
pub mod xattr;

use crate::error::FsError;
use crate::fs::AppendFs;
use crate::shim::{DeferredResult, Filesystem, FuseResponse, RequestContext, ShimFlock};
use std::time::SystemTime;

impl Filesystem for AppendFs {
    fn lookup(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
        dir::lookup_response(self, parent, name)
    }

    fn getattr(&self, ino: u64) -> Result<FuseResponse<'static>, FsError> {
        read_write::getattr_response(self, ino)
    }

    fn opendir(&self, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError> {
        dir::opendir_response(self, ino, flags)
    }

    fn readdir(&self, ino: u64, size: usize, offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
        dir::readdir_response(self, ino, size, offset, fh)
    }

    fn readdirplus(&self, ino: u64, size: usize, offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
        dir::readdirplus_response(self, ino, size, offset, fh)
    }

    fn read(&self, ino: u64, size: usize, offset: i64, fh: u64) -> DeferredResult<FuseResponse<'static>> {
        read_write::read_response(self, ino, fh, offset, size)
    }

    fn open(&self, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError> {
        read_write::open_response(self, ino, flags)
    }

    fn write(&self, ino: u64, buf: &[u8], offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
        read_write::write_response(self, ino, fh, buf, offset)
    }

    fn setattr(
        &self,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        size: i64,
        atime: SystemTime,
        mtime: SystemTime,
        to_set: u32,
    ) -> Result<FuseResponse<'static>, FsError> {
        read_write::setattr_response(self, ino, mode, uid, gid, size, atime, mtime, to_set)
    }

    fn create(
        &self,
        ctx: RequestContext,
        parent: u64,
        name: &str,
        mode: u32,
        flags: u32,
    ) -> Result<FuseResponse<'static>, FsError> {
        read_write::create_response(self, ctx, parent, name, mode, flags)
    }

    fn mknod(
        &self,
        ctx: RequestContext,
        parent: u64,
        name: &str,
        mode: u32,
        rdev: u32,
    ) -> Result<FuseResponse<'static>, FsError> {
        special::mknod_response(self, ctx, parent, name, mode, rdev)
    }

    fn unlink(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
        links::unlink_response(self, parent, name)
    }

    fn mkdir(&self, ctx: RequestContext, parent: u64, name: &str, mode: u32) -> Result<FuseResponse<'static>, FsError> {
        dir::mkdir_response(self, ctx, parent, name, mode)
    }

    fn rmdir(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
        dir::rmdir_response(self, parent, name)
    }

    fn symlink(
        &self,
        ctx: RequestContext,
        link: &str,
        parent: u64,
        name: &str,
    ) -> Result<FuseResponse<'static>, FsError> {
        links::symlink_response(self, ctx, link, parent, name)
    }

    fn readlink(&self, ino: u64) -> Result<FuseResponse<'static>, FsError> {
        links::readlink_response(self, ino)
    }

    fn rename(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<FuseResponse<'static>, FsError> {
        links::rename_response(self, parent, name, newparent, newname)
    }

    fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<FuseResponse<'static>, FsError> {
        links::link_response(self, ino, newparent, newname)
    }

    fn fsync(&self, ino: u64, datasync: bool, fh: u64) -> DeferredResult<FuseResponse<'static>> {
        let _ = datasync;
        read_write::fsync_response(self, ino, fh, crate::fs::FlushReason::Fsync)
    }

    fn fallocate(
        &self,
        ino: u64,
        mode: i32,
        offset: i64,
        length: i64,
        fh: u64,
    ) -> Result<FuseResponse<'static>, FsError> {
        let _ = fh;
        read_write::fallocate_response(self, ino, mode, offset, length)
    }

    fn release(&self, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
        read_write::release_response(self, ino, fh)
    }

    fn releasedir(&self, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
        dir::releasedir_response(self, ino, fh)
    }

    fn fsyncdir(&self, ino: u64, datasync: bool) -> DeferredResult<FuseResponse<'static>> {
        dir::fsyncdir_response(self, ino, datasync)
    }

    fn statfs(&self, ino: u64) -> Result<FuseResponse<'static>, FsError> {
        statfs::statfs_response(self, ino)
    }

    fn flock(&self, ino: u64, fh: u64, lock_owner: u64, op: i32) -> DeferredResult<FuseResponse<'static>> {
        locks::flock_response(self, ino, fh, lock_owner, op)
    }

    fn getlk(&self, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) -> Result<FuseResponse<'static>, FsError> {
        locks::getlk_response(self, ino, fh, lock_owner, lock)
    }

    fn setlk(
        &self,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        lock: ShimFlock,
        sleep: bool,
    ) -> DeferredResult<FuseResponse<'static>> {
        locks::setlk_response(self, ino, fh, lock_owner, lock, sleep)
    }

    fn getxattr(&self, ino: u64, name: &str, size: usize) -> Result<FuseResponse<'static>, FsError> {
        xattr::getxattr_core(self, ino, name, size)
    }

    fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<FuseResponse<'static>, FsError> {
        xattr::setxattr_core(self, ino, name, value, flags)
    }

    fn listxattr(&self, ino: u64, size: usize) -> Result<FuseResponse<'static>, FsError> {
        xattr::listxattr_core(self, ino, size)
    }

    fn removexattr(&self, ino: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
        xattr::removexattr_core(self, ino, name)
    }

    fn copy_file_range(
        &self,
        ino_in: u64,
        fh_in: u64,
        off_in: i64,
        ino_out: u64,
        fh_out: u64,
        off_out: i64,
        len: u64,
        flags: u32,
    ) -> Result<FuseResponse<'static>, FsError> {
        read_write::copy_file_range_response(self, ino_in, fh_in, off_in, ino_out, fh_out, off_out, len, flags)
    }
}
