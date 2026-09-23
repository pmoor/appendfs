use crate::clock::system_time_to_unix;
use crate::operations::op::FuseOp;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub use crate::error::FsError;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

type ShimSetattrCallback = extern "C" fn(
    req: Request,
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
    lookup: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char)>,
    getattr: Option<extern "C" fn(req: Request, ino: u64)>,
    opendir: Option<extern "C" fn(req: Request, ino: u64, flags: u32)>,
    readdir: Option<extern "C" fn(req: Request, ino: u64, size: usize, off: i64, fh: u64)>,
    readdirplus: Option<extern "C" fn(req: Request, ino: u64, size: usize, off: i64, fh: u64)>,
    read: Option<extern "C" fn(req: Request, ino: u64, size: usize, off: i64, fh: u64)>,
    open: Option<extern "C" fn(req: Request, ino: u64, flags: u32)>,
    write: Option<extern "C" fn(req: Request, ino: u64, buf: *const u8, size: usize, off: i64, fh: u64)>,
    setattr: Option<ShimSetattrCallback>,
    create: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char, mode: u32, flags: u32)>,
    mknod: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char, mode: u32, rdev: u32)>,
    unlink: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char)>,
    mkdir: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char, mode: u32)>,
    rmdir: Option<extern "C" fn(req: Request, parent: u64, name: *const c_char)>,
    symlink: Option<extern "C" fn(req: Request, link: *const c_char, parent: u64, name: *const c_char)>,
    readlink: Option<extern "C" fn(req: Request, ino: u64)>,
    rename:
        Option<extern "C" fn(req: Request, parent: u64, name: *const c_char, newparent: u64, newname: *const c_char)>,
    link: Option<extern "C" fn(req: Request, ino: u64, newparent: u64, newname: *const c_char)>,
    fsync: Option<extern "C" fn(req: Request, ino: u64, datasync: c_int, fh: u64)>,
    fallocate: Option<extern "C" fn(req: Request, ino: u64, mode: i32, offset: i64, length: i64, fh: u64)>,
    release: Option<extern "C" fn(req: Request, ino: u64, fh: u64)>,
    releasedir: Option<extern "C" fn(req: Request, ino: u64, fh: u64)>,
    fsyncdir: Option<extern "C" fn(req: Request, ino: u64, datasync: c_int)>,
    statfs: Option<extern "C" fn(req: Request, ino: u64)>,
    flock: Option<extern "C" fn(req: Request, ino: u64, fh: u64, lock_owner: u64, op: c_int)>,
    getlk: Option<extern "C" fn(req: Request, ino: u64, fh: u64, lock_owner: u64, lock: *mut ShimFlock)>,
    setlk:
        Option<extern "C" fn(req: Request, ino: u64, fh: u64, lock_owner: u64, lock: *const ShimFlock, sleep: c_int)>,
    getxattr: Option<extern "C" fn(req: Request, ino: u64, name: *const c_char, size: usize)>,
    setxattr:
        Option<extern "C" fn(req: Request, ino: u64, name: *const c_char, value: *const u8, size: usize, flags: c_int)>,
    listxattr: Option<extern "C" fn(req: Request, ino: u64, size: usize)>,
    removexattr: Option<extern "C" fn(req: Request, ino: u64, name: *const c_char)>,
    init: Option<extern "C" fn(userdata: *mut c_void)>,
    destroy: Option<extern "C" fn(userdata: *mut c_void)>,
}

#[repr(C)]
struct FuseCtx {
    uid: u32,
    gid: u32,
    pid: libc::pid_t,
    umask: libc::mode_t,
}

/// Opaque handle to underlying FUSE request.
#[repr(C)]
pub struct FuseReq {
    _private: [u8; 0],
}
pub type FuseReqT = *mut FuseReq;

unsafe extern "C" {
    fn fuse_req_ctx_shim(req: FuseReqT) -> FuseCtx;
    fn run_fuse_ll(
        argc: c_int,
        argv: *const *const c_char,
        ops: *const RustLowlevelOps,
        userdata: *mut c_void,
    ) -> c_int;

    fn shim_reply_err(req: FuseReqT, err: c_int) -> c_int;
    fn shim_reply_entry(req: FuseReqT, attr: *const ShimFileAttr, attr_timeout: f64, entry_timeout: f64) -> c_int;
    fn shim_reply_attr(req: FuseReqT, attr: *const ShimFileAttr, attr_timeout: f64) -> c_int;
    fn shim_reply_buf(req: FuseReqT, buf: *const u8, size: usize) -> c_int;
    fn shim_reply_open(req: FuseReqT, fh: u64, direct_io: bool, keep_cache: bool) -> c_int;
    fn shim_reply_write(req: FuseReqT, count: usize) -> c_int;
    fn shim_reply_create(
        req: FuseReqT,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        fh: u64,
    ) -> c_int;
    fn shim_reply_readlink(req: FuseReqT, link: *const c_char) -> c_int;
    fn shim_reply_statfs(req: FuseReqT, attr: *const ShimStatfsAttr) -> c_int;
    fn shim_reply_lock(req: FuseReqT, lock: *const ShimFlock) -> c_int;
    fn shim_reply_xattr(req: FuseReqT, count: usize) -> c_int;

    fn shim_add_direntry(
        req: FuseReqT,
        buf: *mut c_char,
        bufsize: usize,
        name: *const c_char,
        ino: u64,
        mode: u32,
        off: i64,
    ) -> usize;
    fn shim_add_direntry_plus(
        req: FuseReqT,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Request {
    pub req: FuseReqT,
    pub userdata: *mut c_void,
}

unsafe impl Send for Request {}

impl Request {
    #[cfg(any(test, feature = "testing"))]
    pub fn new_mock() -> Self {
        Self {
            req: std::ptr::null_mut(),
            userdata: std::ptr::null_mut(),
        }
    }

    #[inline]
    pub(crate) fn fs(&self) -> &crate::fs::InMemoryFS {
        unsafe { &*(self.userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) }
    }

    pub(crate) fn reply_err(self, err: FsError) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_err(self.req, err.raw());
        }
    }

    pub(crate) fn reply_ok(self) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_err(self.req, 0);
        }
    }

    pub(crate) fn reply_entry(self, attr: &FileAttr) {
        if self.req.is_null() {
            return;
        }
        let shim_attr = convert_file_attr(attr);
        let timeout = FuseResponse::timeout_for_ino(attr.ino);
        unsafe {
            shim_reply_entry(self.req, &shim_attr, timeout, timeout);
        }
    }

    pub(crate) fn reply_attr(self, attr: &FileAttr) {
        if self.req.is_null() {
            return;
        }
        let shim_attr = convert_file_attr(attr);
        let timeout = FuseResponse::timeout_for_ino(attr.ino);
        unsafe {
            shim_reply_attr(self.req, &shim_attr, timeout);
        }
    }

    pub(crate) fn reply_buf(self, buf: &[u8]) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_buf(self.req, buf.as_ptr(), buf.len());
        }
    }

    pub(crate) fn reply_open(self, fh: u64, direct_io: bool, keep_cache: bool) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_open(self.req, fh, direct_io, keep_cache);
        }
    }

    pub(crate) fn reply_write(self, count: usize) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_write(self.req, count);
        }
    }

    pub(crate) fn reply_create(self, attr: &FileAttr, fh: u64) {
        if self.req.is_null() {
            return;
        }
        let shim_attr = convert_file_attr(attr);
        let timeout = FuseResponse::timeout_for_ino(attr.ino);
        unsafe {
            shim_reply_create(self.req, &shim_attr, timeout, timeout, fh);
        }
    }

    pub(crate) fn reply_readlink(self, link: &str) {
        if self.req.is_null() {
            return;
        }
        let c_link = match CString::new(link) {
            Ok(c) => c,
            Err(_) => {
                self.reply_err(FsError::EIO);
                return;
            }
        };
        unsafe {
            shim_reply_readlink(self.req, c_link.as_ptr());
        }
    }

    pub(crate) fn reply_statfs(self, attr: &StatfsAttr) {
        if self.req.is_null() {
            return;
        }
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

    pub(crate) fn reply_lock(self, lock: &ShimFlock) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_lock(self.req, lock);
        }
    }

    pub(crate) fn reply_xattr(self, count: usize) {
        if self.req.is_null() {
            return;
        }
        unsafe {
            shim_reply_xattr(self.req, count);
        }
    }

    pub(crate) fn context(&self) -> RequestContext {
        if self.req.is_null() {
            return RequestContext::default();
        }
        unsafe {
            let ctx = fuse_req_ctx_shim(self.req);
            RequestContext {
                uid: ctx.uid,
                gid: ctx.gid,
                pid: ctx.pid as u32,
            }
        }
    }
}

/// Caller context extracted from a FUSE request (uid, gid, pid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl RequestContext {
    pub const fn new(uid: u32, gid: u32, pid: u32) -> Self {
        Self { uid, gid, pid }
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            uid: 1000,
            gid: 1000,
            pid: 0,
        }
    }
}

/// Buffer data payload for a FUSE reply, supporting both zero-copy borrowed slices
/// and heap-allocated byte vectors.
#[derive(Debug, Clone, Eq)]
pub enum ReplyData<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a, 'b> PartialEq<ReplyData<'b>> for ReplyData<'a> {
    fn eq(&self, other: &ReplyData<'b>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<'a> ReplyData<'a> {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            ReplyData::Borrowed(s) => s,
            ReplyData::Owned(v) => v.as_slice(),
        }
    }

    #[inline]
    pub fn to_owned(&self) -> ReplyData<'static> {
        match self {
            ReplyData::Borrowed(b) => ReplyData::Owned(b.to_vec()),
            ReplyData::Owned(v) => ReplyData::Owned(v.clone()),
        }
    }
}

impl<'a> From<&'a [u8]> for ReplyData<'a> {
    #[inline]
    fn from(s: &'a [u8]) -> Self {
        ReplyData::Borrowed(s)
    }
}

impl<'a> From<Vec<u8>> for ReplyData<'a> {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        ReplyData::Owned(v)
    }
}

impl<'a> std::ops::Deref for ReplyData<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> AsRef<[u8]> for ReplyData<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// High-level typed representation of a successful response sent back to the FUSE kernel.
///
/// Handlers can return `Result<FuseResponse<'a>, FsError>` without directly interacting with
/// `Request` or raw FFI pointers.
#[derive(Debug, Clone, PartialEq)]
pub enum FuseResponse<'a> {
    /// Void success (maps to `fuse_reply_err(req, 0)`).
    Ok,
    /// Directory entry with attributes (using default cache timeout).
    Entry(FileAttr),
    /// File attributes (using default cache timeout).
    Attr(FileAttr),
    /// File or directory handle allocation with direct_io and keep_cache flags.
    Open { fh: u64, direct_io: bool, keep_cache: bool },
    /// Number of bytes written.
    Write(usize),
    /// Atomic create reply: entry attributes and allocated file handle (using default cache timeout).
    Create { attr: FileAttr, fh: u64 },
    /// Raw buffer payload (e.g. read data, xattr value).
    Buf(ReplyData<'a>),
    /// Symbolic link target string.
    Readlink(String),
    /// Filesystem capacity and allocation statistics.
    Statfs(StatfsAttr),
    /// POSIX file lock information.
    Lock(ShimFlock),
    /// Extended attribute size query response.
    XattrSize(usize),
    /// Directory stream entries for readdir.
    Readdir { entries: Vec<DirEntry>, max_size: usize },
    /// Directory stream entries for readdirplus.
    ReaddirPlus {
        entries: Vec<DirEntryPlus>,
        max_size: usize,
    },
}

impl<'a> FuseResponse<'a> {
    pub const DEFAULT_TIMEOUT: f64 = 3600.0;

    #[inline]
    pub fn timeout_for_ino(ino: u64) -> f64 {
        if crate::fs::is_virtual_ino(ino) {
            0.0
        } else {
            Self::DEFAULT_TIMEOUT
        }
    }

    #[inline]
    pub fn ok() -> Self {
        FuseResponse::Ok
    }

    #[inline]
    pub fn entry(attr: FileAttr) -> Self {
        FuseResponse::Entry(attr)
    }

    #[inline]
    pub fn attr(attr: FileAttr) -> Self {
        FuseResponse::Attr(attr)
    }

    #[inline]
    pub fn open(fh: u64, direct_io: bool, keep_cache: bool) -> Self {
        FuseResponse::Open {
            fh,
            direct_io,
            keep_cache,
        }
    }

    #[inline]
    pub fn write(count: usize) -> Self {
        FuseResponse::Write(count)
    }

    #[inline]
    pub fn create(attr: FileAttr, fh: u64) -> Self {
        FuseResponse::Create { attr, fh }
    }

    #[inline]
    pub fn buf<T: Into<ReplyData<'a>>>(data: T) -> Self {
        FuseResponse::Buf(data.into())
    }

    #[inline]
    pub fn readlink(link: impl Into<String>) -> Self {
        FuseResponse::Readlink(link.into())
    }

    #[inline]
    pub fn statfs(stat: StatfsAttr) -> Self {
        FuseResponse::Statfs(stat)
    }

    #[inline]
    pub fn lock(lock: ShimFlock) -> Self {
        FuseResponse::Lock(lock)
    }

    #[inline]
    pub fn xattr_size(size: usize) -> Self {
        FuseResponse::XattrSize(size)
    }

    #[inline]
    pub fn readdir(entries: Vec<DirEntry>, max_size: usize) -> Self {
        FuseResponse::Readdir { entries, max_size }
    }

    #[inline]
    pub fn readdirplus(entries: Vec<DirEntryPlus>, max_size: usize) -> Self {
        FuseResponse::ReaddirPlus { entries, max_size }
    }

    #[inline]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FuseResponse::Buf(buf) => Some(buf.as_slice()),
            _ => None,
        }
    }

    #[inline]
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            FuseResponse::Buf(ReplyData::Borrowed(b)) => Some(b.to_vec()),
            FuseResponse::Buf(ReplyData::Owned(v)) => Some(v),
            _ => None,
        }
    }

    #[inline]
    pub fn xattr_size_value(&self) -> Option<usize> {
        match self {
            FuseResponse::XattrSize(sz) => Some(*sz),
            _ => None,
        }
    }

    /// Converts this response into an owned `'static` response that can be safely sent across
    /// threads or queued in asynchronous runtimes.
    pub fn to_static(&self) -> FuseResponse<'static> {
        match self {
            FuseResponse::Ok => FuseResponse::Ok,
            FuseResponse::Entry(a) => FuseResponse::Entry(*a),
            FuseResponse::Attr(a) => FuseResponse::Attr(*a),
            FuseResponse::Open {
                fh,
                direct_io,
                keep_cache,
            } => FuseResponse::Open {
                fh: *fh,
                direct_io: *direct_io,
                keep_cache: *keep_cache,
            },
            FuseResponse::Write(c) => FuseResponse::Write(*c),
            FuseResponse::Create { attr, fh } => FuseResponse::Create { attr: *attr, fh: *fh },
            FuseResponse::Buf(b) => FuseResponse::Buf(b.to_owned()),
            FuseResponse::Readlink(s) => FuseResponse::Readlink(s.clone()),
            FuseResponse::Statfs(s) => FuseResponse::Statfs(*s),
            FuseResponse::Lock(l) => FuseResponse::Lock(*l),
            FuseResponse::XattrSize(s) => FuseResponse::XattrSize(*s),
            FuseResponse::Readdir { entries, max_size } => FuseResponse::Readdir {
                entries: entries.clone(),
                max_size: *max_size,
            },
            FuseResponse::ReaddirPlus { entries, max_size } => FuseResponse::ReaddirPlus {
                entries: entries.clone(),
                max_size: *max_size,
            },
        }
    }

    /// Sends this response over the FUSE request handle.
    pub(crate) fn send(self, req: Request) {
        match self {
            FuseResponse::Ok => req.reply_ok(),
            FuseResponse::Entry(attr) => req.reply_entry(&attr),
            FuseResponse::Attr(attr) => req.reply_attr(&attr),
            FuseResponse::Open {
                fh,
                direct_io,
                keep_cache,
            } => req.reply_open(fh, direct_io, keep_cache),
            FuseResponse::Write(count) => req.reply_write(count),
            FuseResponse::Create { attr, fh } => req.reply_create(&attr, fh),
            FuseResponse::Buf(buf) => req.reply_buf(buf.as_slice()),
            FuseResponse::Readlink(link) => req.reply_readlink(&link),
            FuseResponse::Statfs(stat) => req.reply_statfs(&stat),
            FuseResponse::Lock(lock) => req.reply_lock(&lock),
            FuseResponse::XattrSize(size) => req.reply_xattr(size),
            FuseResponse::Readdir { entries, max_size } => {
                let mut db = DirectoryBuffer::new(req, max_size);
                for entry in entries {
                    if !db.add(&entry.name, entry.ino, entry.file_type, entry.offset) {
                        break;
                    }
                }
                db.reply();
            }
            FuseResponse::ReaddirPlus { entries, max_size } => {
                let mut db = DirectoryBufferPlus::new(req, max_size);
                for entry in entries {
                    if !db.add(&entry.name, &entry.attr, entry.offset) {
                        break;
                    }
                }
                db.reply();
            }
        }
    }
}

/// Helper to dispatch a `Result<FuseResponse, FsError>` to a FUSE request.
#[inline]
pub(crate) fn reply_result<'a>(req: Request, result: Result<FuseResponse<'a>, FsError>) {
    match result {
        Ok(resp) => resp.send(req),
        Err(err) => req.reply_err(err),
    }
}

/// Trait implemented by deferred async completions (e.g. batch flushes, lock acquisitions).
pub type DeferredCallback<T> = Box<dyn FnOnce(Result<T, FsError>) + Send + 'static>;

pub trait DeferredCompletion<T>: Send + 'static {
    fn on_complete(self: Box<Self>, callback: DeferredCallback<T>);
}

impl<T> std::fmt::Debug for dyn DeferredCompletion<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeferredCompletion")
    }
}

/// Rich result type representing an operation that either completed immediately or was deferred.
pub enum DeferredResult<T = FuseResponse<'static>> {
    /// The operation completed immediately (e.g. uncontended lock, cached read).
    Ready(Result<T, FsError>),
    /// The operation is pending an external event (batch disk sync, lock waiter wake).
    Deferred(Box<dyn DeferredCompletion<T>>),
}

impl<T: std::fmt::Debug> std::fmt::Debug for DeferredResult<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeferredResult::Ready(r) => f.debug_tuple("Ready").field(r).finish(),
            DeferredResult::Deferred(_) => f.debug_tuple("Deferred").finish(),
        }
    }
}

impl<T: Send + 'static> DeferredResult<T> {
    pub fn ready(res: Result<T, FsError>) -> Self {
        DeferredResult::Ready(res)
    }

    pub fn ok(val: T) -> Self {
        DeferredResult::Ready(Ok(val))
    }

    pub fn err(err: FsError) -> Self {
        DeferredResult::Ready(Err(err))
    }

    pub fn deferred(completion: impl DeferredCompletion<T> + 'static) -> Self {
        DeferredResult::Deferred(Box::new(completion))
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, DeferredResult::Ready(_))
    }

    pub fn is_deferred(&self) -> bool {
        matches!(self, DeferredResult::Deferred(_))
    }

    pub fn into_ready(self) -> Option<Result<T, FsError>> {
        match self {
            DeferredResult::Ready(r) => Some(r),
            DeferredResult::Deferred(_) => None,
        }
    }

    pub fn on_complete(self, callback: impl FnOnce(Result<T, FsError>) + Send + 'static) {
        match self {
            DeferredResult::Ready(res) => callback(res),
            DeferredResult::Deferred(completion) => completion.on_complete(Box::new(callback)),
        }
    }

    pub fn wait(self) -> Result<T, FsError> {
        match self {
            DeferredResult::Ready(res) => res,
            DeferredResult::Deferred(completion) => {
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                completion.on_complete(Box::new(move |res| {
                    let _ = tx.send(res);
                }));
                rx.recv().unwrap_or(Err(FsError::EIO))
            }
        }
    }
}

impl DeferredResult<FuseResponse<'static>> {
    pub fn ok_void() -> Self {
        DeferredResult::Ready(Ok(FuseResponse::ok()))
    }
}

impl<T> From<Result<T, FsError>> for DeferredResult<T> {
    fn from(res: Result<T, FsError>) -> Self {
        DeferredResult::Ready(res)
    }
}

struct DeferredTokenInner<T> {
    result: Option<Result<T, FsError>>,
    callback: Option<DeferredCallback<T>>,
}

/// Producer token held by waiter queues to signal completion of an async request.
pub struct DeferredToken<T> {
    state: Arc<Mutex<DeferredTokenInner<T>>>,
}

/// Consumer handle returned to the caller to receive completion of an async request.
pub struct DeferredReceiver<T> {
    state: Arc<Mutex<DeferredTokenInner<T>>>,
}

impl<T: Send + 'static> DeferredToken<T> {
    pub fn new() -> (Self, DeferredReceiver<T>) {
        let state = Arc::new(Mutex::new(DeferredTokenInner {
            result: None,
            callback: None,
        }));
        (Self { state: state.clone() }, DeferredReceiver { state })
    }

    pub fn complete(self, result: Result<T, FsError>) {
        let mut guard = self.state.lock().unwrap();
        if let Some(cb) = guard.callback.take() {
            drop(guard);
            cb(result);
        } else {
            guard.result = Some(result);
        }
    }
}

impl<T: Send + 'static> DeferredCompletion<T> for DeferredReceiver<T> {
    fn on_complete(self: Box<Self>, callback: DeferredCallback<T>) {
        let mut guard = self.state.lock().unwrap();
        if let Some(res) = guard.result.take() {
            drop(guard);
            callback(res);
        } else {
            guard.callback = Some(callback);
        }
    }
}

impl<T> Drop for DeferredToken<T> {
    fn drop(&mut self) {
        let mut guard = self.state.lock().unwrap();
        if guard.result.is_none() {
            guard.result = Some(Err(FsError::ECANCELED));
            if let Some(cb) = guard.callback.take() {
                drop(guard);
                cb(Err(FsError::ECANCELED));
            }
        }
    }
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
            buf: Vec::new(),
            max_size,
            full: false,
        }
    }

    fn fill<F>(&mut self, name: &str, fill_fn: F) -> bool
    where
        F: FnOnce(FuseReqT, *mut c_char, usize, *const c_char) -> usize,
    {
        if self.full {
            return false;
        }

        let c_name = match CString::new(name) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if self.req.req.is_null() {
            return true;
        }

        let old_len = self.buf.len();
        self.buf.resize(self.max_size, 0);

        let remaining = self.max_size.saturating_sub(old_len);
        let entry_size = fill_fn(
            self.req.req,
            unsafe { self.buf.as_mut_ptr().add(old_len) as *mut c_char },
            remaining,
            c_name.as_ptr(),
        );

        if entry_size <= remaining {
            self.buf.truncate(old_len + entry_size);
            true
        } else {
            self.buf.truncate(old_len);
            self.full = true;
            false
        }
    }

    fn reply(self) {
        self.req.reply_buf(&self.buf);
    }
}

pub(crate) struct DirectoryBuffer(DirBufCore);

impl DirectoryBuffer {
    pub(crate) fn new(req: Request, max_size: usize) -> Self {
        Self(DirBufCore::new(req, max_size))
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

pub(crate) struct DirectoryBufferPlus(DirBufCore);

impl DirectoryBufferPlus {
    pub(crate) fn new(req: Request, max_size: usize) -> Self {
        Self(DirBufCore::new(req, max_size))
    }

    pub fn add(&mut self, name: &str, attr: &FileAttr, next_off: i64) -> bool {
        let shim_attr = convert_file_attr(attr);
        let timeout = FuseResponse::timeout_for_ino(attr.ino);
        self.0.fill(name, |req, buf_ptr, remaining, c_name_ptr| unsafe {
            shim_add_direntry_plus(
                req, buf_ptr, remaining, c_name_ptr, &shim_attr, timeout, timeout, next_off,
            )
        })
    }

    pub fn reply(self) {
        self.0.reply();
    }
}

/// Single directory entry item yielded by directory enumerations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub name: String,
    pub file_type: FileType,
    pub offset: i64,
}

impl DirEntry {
    pub fn new(ino: u64, name: impl Into<String>, file_type: FileType, offset: i64) -> Self {
        Self {
            ino,
            name: name.into(),
            file_type,
            offset,
        }
    }
}

/// Directory entry item with full attributes yielded by `readdirplus`.
#[derive(Debug, Clone, PartialEq)]
pub struct DirEntryPlus {
    pub ino: u64,
    pub name: String,
    pub attr: FileAttr,
    pub offset: i64,
}

impl DirEntryPlus {
    pub fn new(name: impl Into<String>, attr: FileAttr, offset: i64) -> Self {
        Self {
            ino: attr.ino,
            name: name.into(),
            attr,
            offset,
        }
    }
}

pub trait Filesystem {
    fn init(&self) {}
    fn destroy(&self) {}
    fn lookup(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError>;
    fn getattr(&self, ino: u64) -> Result<FuseResponse<'static>, FsError>;
    fn opendir(&self, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError>;
    fn readdir(&self, ino: u64, size: usize, offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    fn readdirplus(&self, ino: u64, size: usize, offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    fn read(&self, ino: u64, size: usize, offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    fn open(&self, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError>;
    fn write(&self, ino: u64, buf: &[u8], offset: i64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<FuseResponse<'static>, FsError>;
    fn create(
        &self,
        ctx: RequestContext,
        parent: u64,
        name: &str,
        mode: u32,
        flags: u32,
    ) -> Result<FuseResponse<'static>, FsError>;
    fn mknod(
        &self,
        ctx: RequestContext,
        parent: u64,
        name: &str,
        mode: u32,
        rdev: u32,
    ) -> Result<FuseResponse<'static>, FsError>;
    fn unlink(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError>;
    fn mkdir(&self, ctx: RequestContext, parent: u64, name: &str, mode: u32) -> Result<FuseResponse<'static>, FsError>;
    fn rmdir(&self, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError>;
    fn symlink(
        &self,
        ctx: RequestContext,
        link: &str,
        parent: u64,
        name: &str,
    ) -> Result<FuseResponse<'static>, FsError>;
    fn readlink(&self, ino: u64) -> Result<FuseResponse<'static>, FsError>;
    fn rename(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<FuseResponse<'static>, FsError>;
    fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<FuseResponse<'static>, FsError>;
    fn fsync(&self, ino: u64, datasync: bool, fh: u64) -> DeferredResult<FuseResponse<'static>>;
    fn fallocate(
        &self,
        ino: u64,
        mode: i32,
        offset: i64,
        length: i64,
        fh: u64,
    ) -> Result<FuseResponse<'static>, FsError>;
    fn release(&self, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    fn releasedir(&self, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError>;
    fn fsyncdir(&self, ino: u64, datasync: bool) -> DeferredResult<FuseResponse<'static>>;
    fn statfs(&self, ino: u64) -> Result<FuseResponse<'static>, FsError>;
    fn flock(&self, ino: u64, fh: u64, lock_owner: u64, op: i32) -> DeferredResult<FuseResponse<'static>>;
    fn getlk(&self, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) -> Result<FuseResponse<'static>, FsError>;
    fn setlk(
        &self,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        lock: ShimFlock,
        sleep: bool,
    ) -> DeferredResult<FuseResponse<'static>>;
    fn getxattr(&self, ino: u64, name: &str, size: usize) -> Result<FuseResponse<'static>, FsError>;
    fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<FuseResponse<'static>, FsError>;
    fn listxattr(&self, ino: u64, size: usize) -> Result<FuseResponse<'static>, FsError>;
    fn removexattr(&self, ino: u64, name: &str) -> Result<FuseResponse<'static>, FsError>;
}

#[inline]
fn c_str_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn handle_op<R>(req: Request, op: FuseOp, f: impl FnOnce(&crate::fs::InMemoryFS) -> R)
where
    R: Into<DeferredResult<FuseResponse<'static>>>,
{
    let fs = req.fs();
    let start = fs.clock.monotonic();
    let res = f(fs);
    fs.dispatch_reply(req, op, res, start);
}

// Lowlevel C callback bridges
extern "C" fn lookup_bridge(req: Request, parent: u64, name: *const c_char) {
    handle_op(req, FuseOp::Lookup, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::ENOENT)?;
        fs.lookup(parent, name_str)
    });
}

extern "C" fn getattr_bridge(req: Request, ino: u64) {
    handle_op(req, FuseOp::Getattr, |fs| fs.getattr(ino));
}

extern "C" fn opendir_bridge(req: Request, ino: u64, flags: u32) {
    handle_op(req, FuseOp::Opendir, |fs| fs.opendir(ino, flags));
}

extern "C" fn readdir_bridge(req: Request, ino: u64, size: usize, off: i64, fh: u64) {
    handle_op(req, FuseOp::Readdir, |fs| fs.readdir(ino, size, off, fh));
}

extern "C" fn readdirplus_bridge(req: Request, ino: u64, size: usize, off: i64, fh: u64) {
    handle_op(req, FuseOp::Readdirplus, |fs| fs.readdirplus(ino, size, off, fh));
}

extern "C" fn read_bridge(req: Request, ino: u64, size: usize, off: i64, fh: u64) {
    handle_op(req, FuseOp::Read, |fs| fs.read(ino, size, off, fh));
}

extern "C" fn open_bridge(req: Request, ino: u64, flags: u32) {
    handle_op(req, FuseOp::Open, |fs| fs.open(ino, flags));
}

extern "C" fn write_bridge(req: Request, ino: u64, buf: *const u8, size: usize, off: i64, fh: u64) {
    handle_op(req, FuseOp::Write, |fs| {
        let buf_slice = if size > 0 && !buf.is_null() {
            unsafe { std::slice::from_raw_parts(buf, size) }
        } else {
            &[]
        };
        fs.write(ino, buf_slice, off, fh)
    });
}

extern "C" fn setattr_bridge(
    req: Request,
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
) {
    handle_op(req, FuseOp::Setattr, |fs| {
        let atime = crate::clock::unix_to_system_time(atime_sec, atime_nsec);
        let mtime = crate::clock::unix_to_system_time(mtime_sec, mtime_nsec);
        fs.setattr(ino, mode, uid, gid, size, atime, mtime, to_set)
    });
}

extern "C" fn create_bridge(req: Request, parent: u64, name: *const c_char, mode: u32, flags: u32) {
    handle_op(req, FuseOp::Create, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.create(req.context(), parent, name_str, mode, flags)
    });
}

extern "C" fn mknod_bridge(req: Request, parent: u64, name: *const c_char, mode: u32, rdev: u32) {
    handle_op(req, FuseOp::Mknod, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.mknod(req.context(), parent, name_str, mode, rdev)
    });
}

extern "C" fn unlink_bridge(req: Request, parent: u64, name: *const c_char) {
    handle_op(req, FuseOp::Unlink, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::ENOENT)?;
        fs.unlink(parent, name_str)
    });
}

extern "C" fn mkdir_bridge(req: Request, parent: u64, name: *const c_char, mode: u32) {
    handle_op(req, FuseOp::Mkdir, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.mkdir(req.context(), parent, name_str, mode)
    });
}

extern "C" fn rmdir_bridge(req: Request, parent: u64, name: *const c_char) {
    handle_op(req, FuseOp::Rmdir, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::ENOENT)?;
        fs.rmdir(parent, name_str)
    });
}

extern "C" fn symlink_bridge(req: Request, link: *const c_char, parent: u64, name: *const c_char) {
    handle_op(req, FuseOp::Symlink, |fs| {
        let link_str = c_str_to_str(link).ok_or(FsError::EINVAL)?;
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.symlink(req.context(), link_str, parent, name_str)
    });
}

extern "C" fn readlink_bridge(req: Request, ino: u64) {
    handle_op(req, FuseOp::Readlink, |fs| fs.readlink(ino));
}

extern "C" fn rename_bridge(req: Request, parent: u64, name: *const c_char, newparent: u64, newname: *const c_char) {
    handle_op(req, FuseOp::Rename, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::ENOENT)?;
        let newname_str = c_str_to_str(newname).ok_or(FsError::EINVAL)?;
        fs.rename(parent, name_str, newparent, newname_str)
    });
}

extern "C" fn link_bridge(req: Request, ino: u64, newparent: u64, newname: *const c_char) {
    handle_op(req, FuseOp::Link, |fs| {
        let newname_str = c_str_to_str(newname).ok_or(FsError::EINVAL)?;
        fs.link(ino, newparent, newname_str)
    });
}

extern "C" fn fsync_bridge(req: Request, ino: u64, datasync: c_int, fh: u64) {
    handle_op(req, FuseOp::Fsync, |fs| fs.fsync(ino, datasync != 0, fh));
}

extern "C" fn fallocate_bridge(req: Request, ino: u64, mode: i32, offset: i64, length: i64, fh: u64) {
    handle_op(req, FuseOp::Fallocate, |fs| fs.fallocate(ino, mode, offset, length, fh));
}

extern "C" fn release_bridge(req: Request, ino: u64, fh: u64) {
    handle_op(req, FuseOp::Release, |fs| fs.release(ino, fh));
}

extern "C" fn releasedir_bridge(req: Request, ino: u64, fh: u64) {
    handle_op(req, FuseOp::Releasedir, |fs| fs.releasedir(ino, fh));
}

extern "C" fn fsyncdir_bridge(req: Request, ino: u64, datasync: c_int) {
    handle_op(req, FuseOp::Fsyncdir, |fs| fs.fsyncdir(ino, datasync != 0));
}

extern "C" fn statfs_bridge(req: Request, ino: u64) {
    handle_op(req, FuseOp::Statfs, |fs| fs.statfs(ino));
}

extern "C" fn flock_bridge(req: Request, ino: u64, fh: u64, lock_owner: u64, op: c_int) {
    handle_op(req, FuseOp::Flock, |fs| fs.flock(ino, fh, lock_owner, op));
}

extern "C" fn getlk_bridge(req: Request, ino: u64, fh: u64, lock_owner: u64, lock: *mut ShimFlock) {
    handle_op(req, FuseOp::Getlk, |fs| {
        if lock.is_null() {
            return Err(FsError::EINVAL);
        }
        let sh_lock = unsafe { *lock };
        fs.getlk(ino, fh, lock_owner, sh_lock)
    });
}

extern "C" fn setlk_bridge(req: Request, ino: u64, fh: u64, lock_owner: u64, lock: *const ShimFlock, sleep: c_int) {
    handle_op(req, FuseOp::Setlk, |fs| {
        if lock.is_null() {
            return DeferredResult::err(FsError::EINVAL);
        }
        let sh_lock = unsafe { *lock };
        fs.setlk(ino, fh, lock_owner, sh_lock, sleep != 0)
    });
}

extern "C" fn getxattr_bridge(req: Request, ino: u64, name: *const c_char, size: usize) {
    handle_op(req, FuseOp::Getxattr, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.getxattr(ino, name_str, size)
    });
}

extern "C" fn setxattr_bridge(
    req: Request,
    ino: u64,
    name: *const c_char,
    value: *const u8,
    size: usize,
    flags: c_int,
) {
    let val_slice = if size > 0 && !value.is_null() {
        unsafe { std::slice::from_raw_parts(value, size) }
    } else {
        &[]
    };
    handle_op(req, FuseOp::Setxattr, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.setxattr(ino, name_str, val_slice, flags)
    });
}

extern "C" fn listxattr_bridge(req: Request, ino: u64, size: usize) {
    handle_op(req, FuseOp::Listxattr, |fs| fs.listxattr(ino, size));
}

extern "C" fn removexattr_bridge(req: Request, ino: u64, name: *const c_char) {
    handle_op(req, FuseOp::Removexattr, |fs| {
        let name_str = c_str_to_str(name).ok_or(FsError::EINVAL)?;
        fs.removexattr(ino, name_str)
    });
}

extern "C" fn init_bridge(userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    // FUSE_INIT arrives after `fuse_daemonize`, so this is the process that will serve the
    // mount: for a backgrounded mount, the daemon rather than the parent that forked it and
    // exited. The run log and the volume lock name their process, so both claim this one.
    crate::logging::open_deferred();
    if let Some(ref writer) = fs.log_writer
        && let Err(e) = writer.record_lock_holder()
    {
        log::warn!("Failed to record this process as the volume lock holder: {}", e);
    }
    fs.init();
}

extern "C" fn destroy_bridge(userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const std::sync::Arc<crate::fs::InMemoryFS>) };
    fs.destroy();
}

pub fn mount(args: Vec<String>, fs: crate::fs::InMemoryFS) -> Result<(), FsError> {
    mount_arc(args, std::sync::Arc::new(fs))
}

pub fn mount_ro(args: Vec<String>, fs: crate::fs::InMemoryFS) -> Result<(), FsError> {
    mount_ro_arc(args, std::sync::Arc::new(fs))
}

pub fn mount_ro_arc(mut args: Vec<String>, fs: std::sync::Arc<crate::fs::InMemoryFS>) -> Result<(), FsError> {
    fs.set_read_only();
    // Injects kernel-level read-only mount option
    args.push("-o".to_string());
    args.push("ro".to_string());
    mount_arc(args, fs)
}

pub fn mount_arc(args: Vec<String>, fs: std::sync::Arc<crate::fs::InMemoryFS>) -> Result<(), FsError> {
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

    // Reclaims the heap allocation handed to the C bridge. The unmount flush/sync already
    // happened inside `destroy_bridge` (`fs.destroy()`), which fires from within
    // `run_fuse_ll` before it returns here - so there's nothing left to flush, just this
    // `Box` to drop.
    unsafe {
        drop(Box::from_raw(
            raw_userdata as *mut std::sync::Arc<crate::fs::InMemoryFS>,
        ));
    }

    if code == 0 { Ok(()) } else { Err(FsError(code)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_data_borrowed_and_owned() {
        let raw = b"hello world";
        let borrowed: ReplyData = raw.as_slice().into();
        assert_eq!(borrowed.as_slice(), b"hello world");

        let owned: ReplyData = vec![1, 2, 3, 4].into();
        assert_eq!(owned.as_slice(), &[1, 2, 3, 4]);

        let static_data = borrowed.to_owned();
        assert_eq!(static_data.as_slice(), b"hello world");
        assert!(matches!(static_data, ReplyData::Owned(_)));
    }

    #[test]
    fn test_fuse_response_constructors_and_to_static() {
        assert_eq!(FuseResponse::ok(), FuseResponse::Ok);
        assert_eq!(FuseResponse::write(42), FuseResponse::Write(42));
        assert_eq!(
            FuseResponse::open(10, /* direct_io = */ false, /* keep_cache = */ true),
            FuseResponse::Open {
                fh: 10,
                direct_io: false,
                keep_cache: true,
            }
        );
        assert_eq!(
            FuseResponse::readlink("target"),
            FuseResponse::Readlink("target".to_string())
        );
        assert_eq!(FuseResponse::xattr_size(100), FuseResponse::XattrSize(100));

        let buf_resp = FuseResponse::buf(b"test data".as_slice());
        assert_eq!(buf_resp.to_static(), FuseResponse::buf(b"test data".to_vec()));

        // Check timeout_for_ino
        assert_eq!(FuseResponse::DEFAULT_TIMEOUT, 3600.0);
        assert_eq!(FuseResponse::timeout_for_ino(1), 3600.0);
        assert_eq!(FuseResponse::timeout_for_ino(crate::fs::VIRTUAL_INO_BASE), 0.0);
        assert_eq!(FuseResponse::timeout_for_ino(crate::fs::VIRTUAL_INO_BASE + 5), 0.0);
    }

    #[test]
    fn test_reply_result_with_mock_request() {
        let req = Request::new_mock();
        reply_result(req, Ok(FuseResponse::ok()));
        reply_result(req, Ok(FuseResponse::write(10)));
        reply_result(
            req,
            Ok(FuseResponse::open(
                1, /* direct_io = */ false, /* keep_cache = */ true,
            )),
        );
        reply_result(req, Ok(FuseResponse::readlink("dest")));
        reply_result(req, Ok(FuseResponse::buf(b"abc".as_slice())));
        reply_result(req, Ok(FuseResponse::xattr_size(10)));
        reply_result(req, Err(FsError::ENOENT));
    }
}
