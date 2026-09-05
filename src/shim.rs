use crate::clock::system_time_to_unix;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::raw::c_void;
use std::time::SystemTime;

// High-level safe representation of file types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileType {
    Directory,
    RegularFile,
    Symlink,
    NamedPipe,
    CharDevice,
    BlockDevice,
    Socket,
}

// High-level safe representation of file attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAttr {
    pub ino: u64,
    pub file_type: FileType,
    pub perm: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: i64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

// High-level safe representation of filesystem statistics
pub struct StatfsAttr {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
}

// Custom layout-stable representation for FFI communication
#[repr(C)]
struct ShimFileAttr {
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    size: i64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
}

#[repr(C)]
struct ShimStatfsAttr {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
}

#[allow(non_camel_case_types)]
type shim_req_t = *mut c_void;

type ShimSetattrCallback = extern "C" fn(
    req: shim_req_t,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    to_set: u32,
    userdata: *mut c_void,
);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimFlock {
    pub lock_type: i16,
    pub whence: i16,
    pub start: i64,
    pub len: i64,
    pub pid: i32,
}

#[repr(C)]
struct RustLowlevelOps {
    lookup: Option<extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void)>,
    getattr: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    opendir: Option<extern "C" fn(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void)>,
    readdir: Option<extern "C" fn(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void)>,
    readdirplus:
        Option<extern "C" fn(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void)>,
    read: Option<extern "C" fn(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void)>,
    open: Option<extern "C" fn(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void)>,
    write: Option<
        extern "C" fn(req: shim_req_t, ino: u64, buf: *const u8, size: usize, off: i64, fh: u64, userdata: *mut c_void),
    >,
    setattr: Option<ShimSetattrCallback>,
    create: Option<
        extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, mode: u32, flags: u32, userdata: *mut c_void),
    >,
    mknod: Option<
        extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, mode: u32, rdev: u32, userdata: *mut c_void),
    >,
    unlink: Option<extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void)>,
    mkdir: Option<extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, mode: u32, userdata: *mut c_void)>,
    rmdir: Option<extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void)>,
    symlink: Option<
        extern "C" fn(req: shim_req_t, link: *const c_char, parent: u64, name: *const c_char, userdata: *mut c_void),
    >,
    readlink: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    rename: Option<
        extern "C" fn(
            req: shim_req_t,
            parent: u64,
            name: *const c_char,
            newparent: u64,
            newname: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    link:
        Option<extern "C" fn(req: shim_req_t, ino: u64, newparent: u64, newname: *const c_char, userdata: *mut c_void)>,
    fsync: Option<extern "C" fn(req: shim_req_t, ino: u64, datasync: c_int, fh: u64, userdata: *mut c_void)>,
    fallocate: Option<
        extern "C" fn(req: shim_req_t, ino: u64, mode: i32, offset: i64, length: i64, fh: u64, userdata: *mut c_void),
    >,
    release: Option<extern "C" fn(req: shim_req_t, ino: u64, fh: u64, userdata: *mut c_void)>,
    releasedir: Option<extern "C" fn(req: shim_req_t, ino: u64, fh: u64, userdata: *mut c_void)>,
    fsyncdir: Option<extern "C" fn(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void)>,
    statfs: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    flock: Option<extern "C" fn(req: shim_req_t, ino: u64, fh: u64, lock_owner: u64, op: c_int, userdata: *mut c_void)>,
    getlk: Option<
        extern "C" fn(req: shim_req_t, ino: u64, fh: u64, lock_owner: u64, lock: *mut ShimFlock, userdata: *mut c_void),
    >,
    setlk: Option<
        extern "C" fn(
            req: shim_req_t,
            ino: u64,
            fh: u64,
            lock_owner: u64,
            lock: *const ShimFlock,
            sleep: c_int,
            userdata: *mut c_void,
        ),
    >,
    getxattr: Option<extern "C" fn(req: shim_req_t, ino: u64, name: *const c_char, size: usize, userdata: *mut c_void)>,
    setxattr: Option<
        extern "C" fn(
            req: shim_req_t,
            ino: u64,
            name: *const c_char,
            value: *const u8,
            size: usize,
            flags: c_int,
            userdata: *mut c_void,
        ),
    >,
    listxattr: Option<extern "C" fn(req: shim_req_t, ino: u64, size: usize, userdata: *mut c_void)>,
    removexattr: Option<extern "C" fn(req: shim_req_t, ino: u64, name: *const c_char, userdata: *mut c_void)>,
    init: Option<extern "C" fn(userdata: *mut c_void)>,
    destroy: Option<extern "C" fn(userdata: *mut c_void)>,
}

unsafe extern "C" {
    fn run_fuse_ll(
        argc: c_int,
        argv: *const *const c_char,
        ops: *const RustLowlevelOps,
        userdata: *mut c_void,
    ) -> c_int;

    fn shim_reply_err(req: shim_req_t, err: c_int) -> c_int;
    fn shim_reply_entry(req: shim_req_t, attr: *const ShimFileAttr, attr_timeout: f64, entry_timeout: f64) -> c_int;
    fn shim_reply_attr(req: shim_req_t, attr: *const ShimFileAttr, attr_timeout: f64) -> c_int;
    fn shim_reply_buf(req: shim_req_t, buf: *const u8, size: usize) -> c_int;
    fn shim_reply_open(req: shim_req_t, fh: u64) -> c_int;
    fn shim_reply_write(req: shim_req_t, count: usize) -> c_int;
    fn shim_reply_create(
        req: shim_req_t,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        fh: u64,
    ) -> c_int;
    fn shim_reply_readlink(req: shim_req_t, link: *const c_char) -> c_int;
    fn shim_reply_statfs(req: shim_req_t, attr: *const ShimStatfsAttr) -> c_int;
    fn shim_reply_lock(req: shim_req_t, lock: *const ShimFlock) -> c_int;
    fn shim_reply_xattr(req: shim_req_t, count: usize) -> c_int;

    fn shim_add_direntry(
        req: shim_req_t,
        buf: *mut c_char,
        bufsize: usize,
        name: *const c_char,
        ino: u64,
        mode: u32,
        off: i64,
    ) -> usize;
    fn shim_add_direntry_plus(
        req: shim_req_t,
        buf: *mut c_char,
        bufsize: usize,
        name: *const c_char,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        off: i64,
    ) -> usize;
}

fn convert_file_attr(attr: &FileAttr) -> ShimFileAttr {
    let (atime_sec, atime_nsec) = system_time_to_unix(attr.atime);
    let (mtime_sec, mtime_nsec) = system_time_to_unix(attr.mtime);
    let (ctime_sec, ctime_nsec) = system_time_to_unix(attr.ctime);

    let mode = match attr.file_type {
        FileType::Directory => libc::S_IFDIR | attr.perm,
        FileType::RegularFile => libc::S_IFREG | attr.perm,
        FileType::Symlink => libc::S_IFLNK | attr.perm,
        FileType::NamedPipe => libc::S_IFIFO | attr.perm,
        FileType::CharDevice => libc::S_IFCHR | attr.perm,
        FileType::BlockDevice => libc::S_IFBLK | attr.perm,
        FileType::Socket => libc::S_IFSOCK | attr.perm,
    };

    ShimFileAttr {
        ino: attr.ino,
        mode,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        size: attr.size,
        atime_sec,
        atime_nsec,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
    }
}

pub struct Request {
    req: shim_req_t,
}

unsafe impl Send for Request {}

impl Request {
    pub fn reply_err(self, err: i32) {
        unsafe {
            shim_reply_err(self.req, err);
        }
    }

    pub fn reply_entry(self, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64) {
        let shim_attr = convert_file_attr(attr);
        unsafe {
            shim_reply_entry(self.req, &shim_attr, attr_timeout, entry_timeout);
        }
    }

    pub fn reply_attr(self, attr: &FileAttr, attr_timeout: f64) {
        let shim_attr = convert_file_attr(attr);
        unsafe {
            shim_reply_attr(self.req, &shim_attr, attr_timeout);
        }
    }

    pub fn reply_buf(self, buf: &[u8]) {
        unsafe {
            shim_reply_buf(self.req, buf.as_ptr(), buf.len());
        }
    }

    pub fn reply_open(self, fh: u64) {
        unsafe {
            shim_reply_open(self.req, fh);
        }
    }

    pub fn reply_write(self, count: usize) {
        unsafe {
            shim_reply_write(self.req, count);
        }
    }

    pub fn reply_create(self, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64, fh: u64) {
        let shim_attr = convert_file_attr(attr);
        unsafe {
            shim_reply_create(self.req, &shim_attr, attr_timeout, entry_timeout, fh);
        }
    }

    pub fn reply_readlink(self, link: &str) {
        let c_link = match CString::new(link) {
            Ok(c) => c,
            Err(_) => {
                self.reply_err(libc::EIO);
                return;
            }
        };
        unsafe {
            shim_reply_readlink(self.req, c_link.as_ptr());
        }
    }

    pub fn reply_statfs(self, attr: &StatfsAttr) {
        let shim_attr = ShimStatfsAttr {
            blocks: attr.blocks,
            bfree: attr.bfree,
            bavail: attr.bavail,
            files: attr.files,
            ffree: attr.ffree,
            bsize: attr.bsize,
            namelen: attr.namelen,
        };
        unsafe {
            shim_reply_statfs(self.req, &shim_attr);
        }
    }

    pub fn reply_lock(self, lock: &ShimFlock) {
        unsafe {
            shim_reply_lock(self.req, lock);
        }
    }

    pub fn reply_xattr(self, count: usize) {
        unsafe {
            shim_reply_xattr(self.req, count);
        }
    }

    pub fn uid(&self) -> u32 {
        unsafe {
            let fuse_req = self.req as *mut c_void;
            let ctx = fuse_req_ctx_shim(fuse_req);
            ctx.uid
        }
    }

    pub fn gid(&self) -> u32 {
        unsafe {
            let fuse_req = self.req as *mut c_void;
            let ctx = fuse_req_ctx_shim(fuse_req);
            ctx.gid
        }
    }
}

#[repr(C)]
struct FuseCtx {
    uid: u32,
    gid: u32,
    pid: i32,
    umask: u32,
}

unsafe extern "C" {
    fn fuse_req_ctx_shim(req: shim_req_t) -> FuseCtx;
}

struct DirBufCore {
    req: Request,
    buf: Vec<u8>,
    max_size: usize,
    full: bool,
}

impl DirBufCore {
    fn new(req: Request, max_size: usize) -> Self {
        Self {
            req,
            buf: Vec::with_capacity(max_size),
            max_size,
            full: false,
        }
    }

    fn is_full(&self) -> bool {
        self.full
    }

    fn fill<F>(&mut self, name: &str, ffi_fill: F) -> bool
    where
        F: FnOnce(shim_req_t, *mut c_char, usize, *const c_char) -> usize,
    {
        if self.full {
            return false;
        }
        let c_name = match CString::new(name) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let current_len = self.buf.len();
        let remaining = self.max_size.saturating_sub(current_len);
        if remaining == 0 {
            self.full = true;
            return false;
        }

        self.buf.resize(self.max_size, 0);

        let needed = ffi_fill(
            self.req.req,
            self.buf[current_len..].as_mut_ptr() as *mut c_char,
            remaining,
            c_name.as_ptr(),
        );

        if needed <= remaining {
            self.buf.truncate(current_len + needed);
            true
        } else {
            self.buf.truncate(current_len);
            self.full = true;
            false
        }
    }

    fn reply(self) {
        self.req.reply_buf(&self.buf);
    }
}

pub struct DirectoryBuffer(DirBufCore);

impl DirectoryBuffer {
    pub fn new(req: Request, max_size: usize) -> Self {
        Self(DirBufCore::new(req, max_size))
    }

    pub fn is_full(&self) -> bool {
        self.0.is_full()
    }

    pub fn add(&mut self, name: &str, ino: u64, file_type: FileType, next_off: i64) -> bool {
        let mode = match file_type {
            FileType::Directory => libc::S_IFDIR,
            FileType::RegularFile => libc::S_IFREG,
            FileType::Symlink => libc::S_IFLNK,
            FileType::NamedPipe => libc::S_IFIFO,
            FileType::CharDevice => libc::S_IFCHR,
            FileType::BlockDevice => libc::S_IFBLK,
            FileType::Socket => libc::S_IFSOCK,
        };

        self.0.fill(name, |req, buf_ptr, remaining, c_name_ptr| unsafe {
            shim_add_direntry(req, buf_ptr, remaining, c_name_ptr, ino, mode, next_off)
        })
    }

    pub fn reply(self) {
        self.0.reply();
    }
}

pub struct DirectoryBufferPlus(DirBufCore);

impl DirectoryBufferPlus {
    pub fn new(req: Request, max_size: usize) -> Self {
        Self(DirBufCore::new(req, max_size))
    }

    pub fn is_full(&self) -> bool {
        self.0.is_full()
    }

    pub fn add(&mut self, name: &str, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64, next_off: i64) -> bool {
        let shim_attr = convert_file_attr(attr);
        self.0.fill(name, |req, buf_ptr, remaining, c_name_ptr| unsafe {
            shim_add_direntry_plus(
                req,
                buf_ptr,
                remaining,
                c_name_ptr,
                &shim_attr,
                attr_timeout,
                entry_timeout,
                next_off,
            )
        })
    }

    pub fn reply(self) {
        self.0.reply();
    }
}

pub trait Filesystem {
    fn lookup(&self, req: Request, parent: u64, name: &str);
    fn getattr(&self, req: Request, ino: u64);
    fn opendir(&self, req: Request, ino: u64, flags: u32);
    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64);
    fn readdirplus(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64);
    fn read(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64);
    fn open(&self, req: Request, ino: u64, flags: u32);
    fn write(&self, req: Request, ino: u64, buf: &[u8], offset: i64, fh: u64);
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: Request,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        size: i64,
        atime: SystemTime,
        mtime: SystemTime,
        to_set: u32,
    );
    fn create(&self, req: Request, parent: u64, name: &str, mode: u32, flags: u32);
    fn mknod(&self, req: Request, parent: u64, name: &str, mode: u32, rdev: u32);
    fn unlink(&self, req: Request, parent: u64, name: &str);
    fn mkdir(&self, req: Request, parent: u64, name: &str, mode: u32);
    fn rmdir(&self, req: Request, parent: u64, name: &str);
    fn symlink(&self, req: Request, link: &str, parent: u64, name: &str);
    fn readlink(&self, req: Request, ino: u64);
    fn rename(&self, req: Request, parent: u64, name: &str, newparent: u64, newname: &str);
    fn link(&self, req: Request, ino: u64, newparent: u64, newname: &str);
    fn fsync(&self, req: Request, ino: u64, datasync: bool, fh: u64);
    fn fallocate(&self, req: Request, ino: u64, mode: i32, offset: i64, length: i64, fh: u64);
    fn release(&self, req: Request, ino: u64, fh: u64);
    fn releasedir(&self, req: Request, ino: u64, fh: u64);
    fn fsyncdir(&self, req: Request, ino: u64, datasync: bool);
    fn statfs(&self, req: Request, ino: u64);
    fn flock(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, op: i32);
    fn getlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock);
    fn setlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock, sleep: bool);
    fn getxattr(&self, req: Request, ino: u64, name: &str, size: usize);
    fn setxattr(&self, req: Request, ino: u64, name: &str, value: &[u8], flags: i32);
    fn listxattr(&self, req: Request, ino: u64, size: usize);
    fn removexattr(&self, req: Request, ino: u64, name: &str);
}

// Lowlevel C callback bridges
extern "C" fn lookup_bridge(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::ENOENT);
            return;
        }
    };
    fs.lookup(Request { req }, parent, name_str);
}

extern "C" fn getattr_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.getattr(Request { req }, ino);
}

extern "C" fn opendir_bridge(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.opendir(Request { req }, ino, flags);
}

extern "C" fn readdir_bridge(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.readdir(Request { req }, ino, size, off, fh);
}

extern "C" fn readdirplus_bridge(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.readdirplus(Request { req }, ino, size, off, fh);
}

extern "C" fn read_bridge(req: shim_req_t, ino: u64, size: usize, off: i64, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.read(Request { req }, ino, size, off, fh);
}

extern "C" fn open_bridge(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.open(Request { req }, ino, flags);
}

extern "C" fn write_bridge(
    req: shim_req_t,
    ino: u64,
    buf: *const u8,
    size: usize,
    off: i64,
    fh: u64,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let buf_slice = unsafe { std::slice::from_raw_parts(buf, size) };
    fs.write(Request { req }, ino, buf_slice, off, fh);
}

extern "C" fn setattr_bridge(
    req: shim_req_t,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    to_set: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let atime = crate::clock::unix_to_system_time(atime_sec, atime_nsec);
    let mtime = crate::clock::unix_to_system_time(mtime_sec, mtime_nsec);
    fs.setattr(Request { req }, ino, mode, uid, gid, size, atime, mtime, to_set);
}

extern "C" fn create_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    mode: u32,
    flags: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.create(Request { req }, parent, name_str, mode, flags);
}

extern "C" fn mknod_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    mode: u32,
    rdev: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.mknod(Request { req }, parent, name_str, mode, rdev);
}

extern "C" fn unlink_bridge(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::ENOENT);
            return;
        }
    };
    fs.unlink(Request { req }, parent, name_str);
}

extern "C" fn mkdir_bridge(req: shim_req_t, parent: u64, name: *const c_char, mode: u32, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.mkdir(Request { req }, parent, name_str, mode);
}

extern "C" fn rmdir_bridge(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::ENOENT);
            return;
        }
    };
    fs.rmdir(Request { req }, parent, name_str);
}

extern "C" fn symlink_bridge(
    req: shim_req_t,
    link: *const c_char,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let link_str = match unsafe { CStr::from_ptr(link) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.symlink(Request { req }, link_str, parent, name_str);
}

extern "C" fn readlink_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.readlink(Request { req }, ino);
}

extern "C" fn rename_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    newparent: u64,
    newname: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::ENOENT);
            return;
        }
    };
    let newname_str = match unsafe { CStr::from_ptr(newname) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.rename(Request { req }, parent, name_str, newparent, newname_str);
}

extern "C" fn link_bridge(req: shim_req_t, ino: u64, newparent: u64, newname: *const c_char, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let newname_str = match unsafe { CStr::from_ptr(newname) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.link(Request { req }, ino, newparent, newname_str);
}

extern "C" fn fsync_bridge(req: shim_req_t, ino: u64, datasync: c_int, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.fsync(Request { req }, ino, datasync != 0, fh);
}

extern "C" fn fallocate_bridge(
    req: shim_req_t,
    ino: u64,
    mode: i32,
    offset: i64,
    length: i64,
    fh: u64,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.fallocate(Request { req }, ino, mode, offset, length, fh);
}

extern "C" fn release_bridge(req: shim_req_t, ino: u64, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.release(Request { req }, ino, fh);
}

extern "C" fn releasedir_bridge(req: shim_req_t, ino: u64, fh: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.releasedir(Request { req }, ino, fh);
}

extern "C" fn fsyncdir_bridge(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.fsyncdir(Request { req }, ino, datasync != 0);
}

extern "C" fn statfs_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.statfs(Request { req }, ino);
}

extern "C" fn flock_bridge(req: shim_req_t, ino: u64, fh: u64, lock_owner: u64, op: c_int, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.flock(Request { req }, ino, fh, lock_owner, op);
}

extern "C" fn getlk_bridge(
    req: shim_req_t,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: *mut ShimFlock,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let sh_lock = unsafe { *lock };
    fs.getlk(Request { req }, ino, fh, lock_owner, sh_lock);
}

extern "C" fn setlk_bridge(
    req: shim_req_t,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: *const ShimFlock,
    sleep: c_int,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let sh_lock = unsafe { *lock };
    fs.setlk(Request { req }, ino, fh, lock_owner, sh_lock, sleep != 0);
}

extern "C" fn getxattr_bridge(req: shim_req_t, ino: u64, name: *const c_char, size: usize, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.getxattr(Request { req }, ino, name_str, size);
}

extern "C" fn setxattr_bridge(
    req: shim_req_t,
    ino: u64,
    name: *const c_char,
    value: *const u8,
    size: usize,
    flags: c_int,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    let val_slice = if size > 0 && !value.is_null() {
        unsafe { std::slice::from_raw_parts(value, size) }
    } else {
        &[]
    };
    fs.setxattr(Request { req }, ino, name_str, val_slice, flags);
}

extern "C" fn listxattr_bridge(req: shim_req_t, ino: u64, size: usize, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.listxattr(Request { req }, ino, size);
}

extern "C" fn removexattr_bridge(req: shim_req_t, ino: u64, name: *const c_char, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request { req }.reply_err(libc::EINVAL);
            return;
        }
    };
    fs.removexattr(Request { req }, ino, name_str);
}

extern "C" fn init_bridge(userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.init();
}

extern "C" fn destroy_bridge(userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.destroy();
}

pub fn mount(args: Vec<String>, fs: crate::fs::InMemoryFS) -> Result<(), i32> {
    mount_arc(args, std::sync::Arc::new(fs))
}

pub fn mount_ro(args: Vec<String>, fs: crate::fs::InMemoryFS) -> Result<(), i32> {
    mount_ro_arc(args, std::sync::Arc::new(fs))
}

pub fn mount_ro_arc(mut args: Vec<String>, fs: std::sync::Arc<crate::fs::InMemoryFS>) -> Result<(), i32> {
    fs.set_read_only(true);
    // Injects kernel-level read-only mount option
    args.push("-o".to_string());
    args.push("ro".to_string());
    mount_arc(args, fs)
}

pub fn mount_arc(args: Vec<String>, fs: std::sync::Arc<crate::fs::InMemoryFS>) -> Result<(), i32> {
    let c_args_owners: Vec<CString> = args.into_iter().map(|arg| CString::new(arg).unwrap()).collect();

    let c_args: Vec<*const c_char> = c_args_owners.iter().map(|arg| arg.as_ptr()).collect();

    let ops = RustLowlevelOps {
        lookup: Some(lookup_bridge),
        getattr: Some(getattr_bridge),
        opendir: Some(opendir_bridge),
        readdir: Some(readdir_bridge),
        readdirplus: Some(readdirplus_bridge),
        read: Some(read_bridge),
        open: Some(open_bridge),
        write: Some(write_bridge),
        setattr: Some(setattr_bridge),
        create: Some(create_bridge),
        mknod: Some(mknod_bridge),
        unlink: Some(unlink_bridge),
        mkdir: Some(mkdir_bridge),
        rmdir: Some(rmdir_bridge),
        symlink: Some(symlink_bridge),
        readlink: Some(readlink_bridge),
        rename: Some(rename_bridge),
        link: Some(link_bridge),
        fsync: Some(fsync_bridge),
        fallocate: Some(fallocate_bridge),
        release: Some(release_bridge),
        releasedir: Some(releasedir_bridge),
        fsyncdir: Some(fsyncdir_bridge),
        statfs: Some(statfs_bridge),
        flock: Some(flock_bridge),
        getlk: Some(getlk_bridge),
        setlk: Some(setlk_bridge),
        getxattr: Some(getxattr_bridge),
        setxattr: Some(setxattr_bridge),
        listxattr: Some(listxattr_bridge),
        removexattr: Some(removexattr_bridge),
        init: Some(init_bridge),
        destroy: Some(destroy_bridge),
    };

    let raw_userdata = Box::into_raw(Box::new(fs)) as *mut c_void;

    let code = unsafe { run_fuse_ll(c_args.len() as c_int, c_args.as_ptr(), &ops, raw_userdata) };

    // Clean up heap allocation and execute unmount flush/sync (only on read-write mounts)
    unsafe {
        let arc_fs = Box::from_raw(raw_userdata as *mut std::sync::Arc<crate::fs::InMemoryFS>);
        if !arc_fs.is_read_only() {
            let _ = arc_fs.sync_and_export_summary();
        }
    }

    if code == 0 { Ok(()) } else { Err(code) }
}
