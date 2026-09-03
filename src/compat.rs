use crate::clock::Clock;
use crate::fs::InMemoryFS;
use crate::log::{LogWriter, init_volume_with_clock_and_uids};
use crate::operations::dir::mkdir_core;
use crate::operations::links::{link_core, readlink_core, symlink_core};
use crate::operations::read_write::{
    FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME, FUSE_SET_ATTR_UID, create_core,
    read_core, setattr_core, write_core,
};
use crate::operations::special::mknod_core;
use crate::operations::xattr::setxattr_core;
use crate::shim::FileType;
use crate::storage::{OsStorage, Storage};
use crate::{VolumeHeader, VolumeKey};

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed base timestamp used for all canonical v1 compatibility fixtures:
/// 2023-11-14 22:13:20 UTC (1,700,000,000 seconds since UNIX epoch).
pub const COMPAT_BASE_TIMESTAMP_SECS: u64 = 1_700_000_000;

/// Root owner pinned into the canonical fixtures.
///
/// Fixture bytes are checked in and compared for equality, so the root directory's owner
/// cannot come from whoever happens to run the generator. Real volumes take it from the
/// invoking user instead - see `init_volume_with_clock_and_uids`.
pub const COMPAT_UID: u32 = 1000;
pub const COMPAT_GID: u32 = 1000;

pub fn compat_time(offset_secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(COMPAT_BASE_TIMESTAMP_SECS + offset_secs)
}

/// Deterministic, advancing mock clock for reproducible fixture generation.
#[derive(Debug, Clone)]
pub struct CompatClock {
    current: Arc<AtomicU64>,
}

impl CompatClock {
    pub fn new() -> Self {
        Self {
            current: Arc::new(AtomicU64::new(COMPAT_BASE_TIMESTAMP_SECS)),
        }
    }

    pub fn set_offset(&self, offset_secs: u64) {
        self.current
            .store(COMPAT_BASE_TIMESTAMP_SECS + offset_secs, Ordering::SeqCst);
    }
}

impl Default for CompatClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for CompatClock {
    fn now(&self) -> SystemTime {
        let secs = self.current.load(Ordering::SeqCst);
        UNIX_EPOCH + Duration::from_secs(secs)
    }
}

/// Patterned binary data for `/dir_a/subdir_1/data.bin` (1024 bytes).
pub fn compat_data_bin() -> Vec<u8> {
    (0..1024).map(|i| ((i * 7 + 13) % 256) as u8).collect()
}

/// Patterned binary data for first 16 KiB of `/dir_b/multi_extent.dat`.
pub fn compat_multi_extent_part1() -> Vec<u8> {
    (0..16384).map(|i| (i % 251) as u8).collect()
}

/// Patterned binary data for second 16 KiB of `/dir_b/multi_extent.dat`.
pub fn compat_multi_extent_part2() -> Vec<u8> {
    (16384..32768).map(|i| (i % 251) as u8).collect()
}

/// Full 32 KiB binary data for `/dir_b/multi_extent.dat`.
pub fn compat_multi_extent_full() -> Vec<u8> {
    let mut data = compat_multi_extent_part1();
    data.extend_from_slice(&compat_multi_extent_part2());
    data
}

/// Populates the canonical compatibility filesystem tree on `fs` across 3 distinct flush cycles.
pub fn populate_compat_tree(fs: &InMemoryFS, clock: &CompatClock) -> Result<(), i32> {
    // --- BATCH 1: Initial directories, partial file write, and initial xattr ---
    clock.set_offset(10);
    let dir_empty = mkdir_core(fs, 1, "dir_empty", 0o755, 1000, 1000)?;
    setattr_core(
        fs,
        dir_empty.ino,
        0o755,
        1000,
        1000,
        0,
        compat_time(10),
        compat_time(20),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(30);
    let dir_a = mkdir_core(fs, 1, "dir_a", 0o755, 1001, 1001)?;
    setattr_core(
        fs,
        dir_a.ino,
        0o755,
        1001,
        1001,
        0,
        compat_time(30),
        compat_time(40),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setxattr_core(fs, dir_a.ino, "user.dir_attr", b"dir_value_v1", 0)?;

    clock.set_offset(50);
    let hello_file = create_core(fs, 1, "hello.txt", 0o644, 0, 1001, 1001)?;
    write_core(fs, hello_file.ino, b"Hello, AppendFS ", 0)?;
    setxattr_core(fs, hello_file.ino, "user.test_attr", b"compat_v1", 0)?;

    // Commit Batch 1 to log
    fs.flush_log().map_err(|_| libc::EIO)?;

    // --- BATCH 2: Subdirectories, empty file, binary payload, multi-extent part 1 ---
    clock.set_offset(60);
    let subdir_1 = mkdir_core(fs, dir_a.ino, "subdir_1", 0o700, 1001, 1001)?;
    setattr_core(
        fs,
        subdir_1.ino,
        0o700,
        1001,
        1001,
        0,
        compat_time(50),
        compat_time(60),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(70);
    let deep = mkdir_core(fs, subdir_1.ino, "deep", 0o750, 1002, 1002)?;
    setattr_core(
        fs,
        deep.ino,
        0o750,
        1002,
        1002,
        0,
        compat_time(70),
        compat_time(80),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(90);
    let dir_b = mkdir_core(fs, 1, "dir_b", 0o750, 1003, 1003)?;
    setattr_core(
        fs,
        dir_b.ino,
        0o750,
        1003,
        1003,
        0,
        compat_time(90),
        compat_time(100),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Complete /hello.txt write
    clock.set_offset(110);
    write_core(fs, hello_file.ino, b"v1 compatibility world!\n", 16)?;

    let empty_file = create_core(fs, dir_a.ino, "empty_file.txt", 0o640, 0, 1001, 1001)?;
    setattr_core(
        fs,
        empty_file.ino,
        0o640,
        1001,
        1001,
        0,
        compat_time(130),
        compat_time(140),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    let data_bin = create_core(fs, subdir_1.ino, "data.bin", 0o600, 0, 1002, 1002)?;
    let bin_data = compat_data_bin();
    write_core(fs, data_bin.ino, &bin_data, 0)?;
    setattr_core(
        fs,
        data_bin.ino,
        0o600,
        1002,
        1002,
        bin_data.len() as i64,
        compat_time(150),
        compat_time(160),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    let multi_extent = create_core(fs, dir_b.ino, "multi_extent.dat", 0o644, 0, 1003, 1003)?;
    let p1 = compat_multi_extent_part1();
    write_core(fs, multi_extent.ino, &p1, 0)?;

    // Commit Batch 2 to log
    fs.flush_log().map_err(|_| libc::EIO)?;

    // --- BATCH 3: Multi-extent part 2, sparse file, hardlink, symlinks, special files, and attrs ---
    clock.set_offset(170);
    let p2 = compat_multi_extent_part2();
    write_core(fs, multi_extent.ino, &p2, 16384)?;
    setattr_core(
        fs,
        multi_extent.ino,
        0o644,
        1003,
        1003,
        32768,
        compat_time(170),
        compat_time(180),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Finalize /hello.txt timestamps and second xattr
    setattr_core(
        fs,
        hello_file.ino,
        0o644,
        1001,
        1001,
        40,
        compat_time(110),
        compat_time(120),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setxattr_core(fs, hello_file.ino, "user.second_attr", b"verified", 0)?;

    // Sparse file: 4096-byte hole, 100 bytes of 0xAA at offset 4096
    clock.set_offset(190);
    let sparse_file = create_core(fs, 1, "sparse_file.bin", 0o644, 0, 1001, 1001)?;
    write_core(fs, sparse_file.ino, &[0xAA; 100], 4096)?;
    setattr_core(
        fs,
        sparse_file.ino,
        0o644,
        1001,
        1001,
        4196,
        compat_time(190),
        compat_time(200),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Hard link in /dir_b pointing to /hello.txt
    link_core(fs, hello_file.ino, dir_b.ino, "hello_hardlink.txt")?;

    // Symlinks
    clock.set_offset(210);
    let sym_rel = symlink_core(fs, 1, "symlink_rel", "hello.txt", 1001, 1001)?;
    setattr_core(
        fs,
        sym_rel.ino,
        0o777,
        1001,
        1001,
        0,
        compat_time(210),
        compat_time(220),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(230);
    let sym_abs = symlink_core(fs, dir_a.ino, "symlink_abs", "/dir_b/multi_extent.dat", 1001, 1001)?;
    setattr_core(
        fs,
        sym_abs.ino,
        0o777,
        1001,
        1001,
        0,
        compat_time(230),
        compat_time(240),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(250);
    let sym_dir = symlink_core(fs, dir_a.ino, "symlink_dir", "/dir_a/subdir_1", 1001, 1001)?;
    setattr_core(
        fs,
        sym_dir.ino,
        0o777,
        1001,
        1001,
        0,
        compat_time(250),
        compat_time(260),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Special files via mknod
    clock.set_offset(270);
    let spec_fifo = mknod_core(fs, 1, "special_fifo", libc::S_IFIFO | 0o644, 0, 1000, 1000)?;
    setattr_core(
        fs,
        spec_fifo.ino,
        0o644,
        1000,
        1000,
        0,
        compat_time(270),
        compat_time(280),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(290);
    let spec_chr = mknod_core(fs, 1, "special_chr", libc::S_IFCHR | 0o660, 0x1234, 1000, 1000)?;
    setattr_core(
        fs,
        spec_chr.ino,
        0o660,
        1000,
        1000,
        0,
        compat_time(290),
        compat_time(300),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(310);
    let spec_blk = mknod_core(fs, 1, "special_blk", libc::S_IFBLK | 0o660, 0x5678, 1000, 1000)?;
    setattr_core(
        fs,
        spec_blk.ino,
        0o660,
        1000,
        1000,
        0,
        compat_time(310),
        compat_time(320),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    clock.set_offset(330);
    let spec_sock = mknod_core(fs, 1, "special_sock", libc::S_IFSOCK | 0o755, 0, 1000, 1000)?;
    setattr_core(
        fs,
        spec_sock.ino,
        0o755,
        1000,
        1000,
        0,
        compat_time(330),
        compat_time(340),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Set final explicit mtimes/atimes on directories now that all children have been added
    setattr_core(
        fs,
        dir_empty.ino,
        0o755,
        1000,
        1000,
        0,
        compat_time(10),
        compat_time(20),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setattr_core(
        fs,
        dir_a.ino,
        0o755,
        1001,
        1001,
        0,
        compat_time(30),
        compat_time(40),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setattr_core(
        fs,
        subdir_1.ino,
        0o700,
        1001,
        1001,
        0,
        compat_time(50),
        compat_time(60),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setattr_core(
        fs,
        deep.ino,
        0o750,
        1002,
        1002,
        0,
        compat_time(70),
        compat_time(80),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;
    setattr_core(
        fs,
        dir_b.ino,
        0o750,
        1003,
        1003,
        0,
        compat_time(90),
        compat_time(100),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Commit Batch 3 to log
    fs.flush_log().map_err(|_| libc::EIO)?;

    Ok(())
}

/// Generates the canonical compatibility volume into `out_dir`, writing `000000.summary`,
/// `000001.log`, and `000001.summary`.
pub fn create_canonical_compat_volume(out_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(out_dir)?;

    // Clean existing files in out_dir so init_volume starts with a fresh empty volume
    if let Ok(entries) = fs::read_dir(out_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = fs::remove_file(path);
            }
        }
    }

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(out_dir));
    let clock = Arc::new(CompatClock::new());

    // 1. Initialize volume -> writes 000000.summary with deterministic clock.
    // The root owner is pinned rather than taken from the invoking user, because these
    // bytes are checked in and must reproduce on any machine. Matches the uid/gid the rest
    // of the canonical tree is built with below.
    init_volume_with_clock_and_uids(
        storage.clone(),
        Some("main"),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        COMPAT_UID,
        COMPAT_GID,
    )?;

    // 2. Open log writer for generation 1 with deterministic clock
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(io::Error::other)?,
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), COMPAT_UID, COMPAT_GID);
    fs.log_writer = Some(writer);
    fs.set_log_dir(out_dir);

    // 3. Populate canonical tree across 3 flushes
    populate_compat_tree(&fs, &clock).map_err(io::Error::from_raw_os_error)?;

    // 4. Export final summary snapshot -> writes 000001.summary
    clock.set_offset(500);
    fs.sync_and_export_summary()?;

    // Drop fs to flush writer and release file descriptors
    drop(fs);

    let _ = fs::remove_file(out_dir.join(".lock"));

    Ok(())
}

/// Helper to navigate and locate an inode by relative POSIX path.
pub fn lookup_path(fs: &InMemoryFS, path: &str) -> Option<u64> {
    let mut current = 1u64; // Inode 1 is root directory
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        current = fs.lookup_child(current, seg)?;
    }
    Some(current)
}

/// Asserts that `fs` exactly matches the canonical compatibility specification.
/// Validates directory hierarchy, file contents, sparse holes, symlinks, special files,
/// permissions (`mode`), ownership (`uid`/`gid`), timestamps (`mtime`/`atime`), and xattrs.
pub fn verify_compat_tree(fs: &InMemoryFS) {
    // 1. Root directory (Inode 1)
    let root_attr = fs.get_attr(1).expect("root directory must exist");
    assert_eq!(root_attr.file_type, FileType::Directory);

    // 2. /dir_empty
    let ino_dir_empty = lookup_path(fs, "/dir_empty").expect("/dir_empty must exist");
    let attr = fs.get_attr(ino_dir_empty).unwrap();
    assert_eq!(attr.file_type, FileType::Directory);
    assert_eq!(attr.perm & 0o777, 0o755);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.atime, compat_time(10));
    assert_eq!(attr.mtime, compat_time(20));

    // 3. /dir_a
    let ino_dir_a = lookup_path(fs, "/dir_a").expect("/dir_a must exist");
    let attr = fs.get_attr(ino_dir_a).unwrap();
    assert_eq!(attr.file_type, FileType::Directory);
    assert_eq!(attr.perm & 0o777, 0o755);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(30));
    assert_eq!(attr.mtime, compat_time(40));
    assert_eq!(fs.get_xattr(ino_dir_a, "user.dir_attr"), Some(b"dir_value_v1".to_vec()));

    // 4. /dir_a/subdir_1
    let ino_subdir_1 = lookup_path(fs, "/dir_a/subdir_1").expect("/dir_a/subdir_1 must exist");
    let attr = fs.get_attr(ino_subdir_1).unwrap();
    assert_eq!(attr.file_type, FileType::Directory);
    assert_eq!(attr.perm & 0o777, 0o700);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(50));
    assert_eq!(attr.mtime, compat_time(60));

    // 5. /dir_a/subdir_1/deep
    let ino_deep = lookup_path(fs, "/dir_a/subdir_1/deep").expect("/dir_a/subdir_1/deep must exist");
    let attr = fs.get_attr(ino_deep).unwrap();
    assert_eq!(attr.file_type, FileType::Directory);
    assert_eq!(attr.perm & 0o777, 0o750);
    assert_eq!(attr.uid, 1002);
    assert_eq!(attr.gid, 1002);
    assert_eq!(attr.atime, compat_time(70));
    assert_eq!(attr.mtime, compat_time(80));

    // 6. /dir_b
    let ino_dir_b = lookup_path(fs, "/dir_b").expect("/dir_b must exist");
    let attr = fs.get_attr(ino_dir_b).unwrap();
    assert_eq!(attr.file_type, FileType::Directory);
    assert_eq!(attr.perm & 0o777, 0o750);
    assert_eq!(attr.uid, 1003);
    assert_eq!(attr.gid, 1003);
    assert_eq!(attr.atime, compat_time(90));
    assert_eq!(attr.mtime, compat_time(100));

    // 7. /hello.txt
    let ino_hello = lookup_path(fs, "/hello.txt").expect("/hello.txt must exist");
    let attr = fs.get_attr(ino_hello).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 40);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(110));
    assert_eq!(attr.mtime, compat_time(120));
    assert_eq!(attr.nlink, 2, "must be linked twice (hello.txt and hello_hardlink.txt)");
    let hello_bytes = read_core(fs, ino_hello, 40, 0).expect("read /hello.txt");
    assert_eq!(hello_bytes, b"Hello, AppendFS v1 compatibility world!\n");
    assert_eq!(fs.get_xattr(ino_hello, "user.test_attr"), Some(b"compat_v1".to_vec()));
    assert_eq!(fs.get_xattr(ino_hello, "user.second_attr"), Some(b"verified".to_vec()));

    // 8. /dir_b/hello_hardlink.txt
    let ino_hardlink = lookup_path(fs, "/dir_b/hello_hardlink.txt").expect("/dir_b/hello_hardlink.txt must exist");
    assert_eq!(ino_hardlink, ino_hello, "hardlink must share exact same inode");

    // 9. /dir_a/empty_file.txt
    let ino_empty = lookup_path(fs, "/dir_a/empty_file.txt").expect("/dir_a/empty_file.txt must exist");
    let attr = fs.get_attr(ino_empty).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 0);
    assert_eq!(attr.perm & 0o777, 0o640);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(130));
    assert_eq!(attr.mtime, compat_time(140));

    // 10. /dir_a/subdir_1/data.bin
    let ino_data_bin = lookup_path(fs, "/dir_a/subdir_1/data.bin").expect("/dir_a/subdir_1/data.bin must exist");
    let attr = fs.get_attr(ino_data_bin).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 1024);
    assert_eq!(attr.perm & 0o777, 0o600);
    assert_eq!(attr.uid, 1002);
    assert_eq!(attr.gid, 1002);
    assert_eq!(attr.atime, compat_time(150));
    assert_eq!(attr.mtime, compat_time(160));
    let bin_read = read_core(fs, ino_data_bin, 1024, 0).expect("read data.bin");
    assert_eq!(bin_read, compat_data_bin());

    // 11. /dir_b/multi_extent.dat
    let ino_multi = lookup_path(fs, "/dir_b/multi_extent.dat").expect("/dir_b/multi_extent.dat must exist");
    let attr = fs.get_attr(ino_multi).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 32768);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1003);
    assert_eq!(attr.gid, 1003);
    assert_eq!(attr.atime, compat_time(170));
    assert_eq!(attr.mtime, compat_time(180));
    let multi_read = read_core(fs, ino_multi, 32768, 0).expect("read multi_extent.dat");
    assert_eq!(multi_read, compat_multi_extent_full());

    // 12. /sparse_file.bin (hole 0..4096, data 4096..4196)
    let ino_sparse = lookup_path(fs, "/sparse_file.bin").expect("/sparse_file.bin must exist");
    let attr = fs.get_attr(ino_sparse).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 4196);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(190));
    assert_eq!(attr.mtime, compat_time(200));
    // Verify hole returns zeroed bytes
    let hole_read = read_core(fs, ino_sparse, 4096, 0).expect("read sparse hole");
    assert_eq!(hole_read, vec![0u8; 4096]);
    // Verify data portion
    let data_read = read_core(fs, ino_sparse, 100, 4096).expect("read sparse data");
    assert_eq!(data_read, vec![0xAAu8; 100]);

    // 13. Symlinks
    let ino_sym_rel = lookup_path(fs, "/symlink_rel").expect("/symlink_rel must exist");
    let attr = fs.get_attr(ino_sym_rel).unwrap();
    assert_eq!(attr.file_type, FileType::Symlink);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(210));
    assert_eq!(attr.mtime, compat_time(220));
    assert_eq!(readlink_core(fs, ino_sym_rel).unwrap(), "hello.txt");

    let ino_sym_abs = lookup_path(fs, "/dir_a/symlink_abs").expect("/dir_a/symlink_abs must exist");
    let attr = fs.get_attr(ino_sym_abs).unwrap();
    assert_eq!(attr.file_type, FileType::Symlink);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(230));
    assert_eq!(attr.mtime, compat_time(240));
    assert_eq!(readlink_core(fs, ino_sym_abs).unwrap(), "/dir_b/multi_extent.dat");

    let ino_sym_dir = lookup_path(fs, "/dir_a/symlink_dir").expect("/dir_a/symlink_dir must exist");
    let attr = fs.get_attr(ino_sym_dir).unwrap();
    assert_eq!(attr.file_type, FileType::Symlink);
    assert_eq!(attr.uid, 1001);
    assert_eq!(attr.gid, 1001);
    assert_eq!(attr.atime, compat_time(250));
    assert_eq!(attr.mtime, compat_time(260));
    assert_eq!(readlink_core(fs, ino_sym_dir).unwrap(), "/dir_a/subdir_1");

    // 14. Special files
    let ino_fifo = lookup_path(fs, "/special_fifo").expect("/special_fifo must exist");
    let attr = fs.get_attr(ino_fifo).unwrap();
    assert_eq!(attr.file_type, FileType::NamedPipe);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.atime, compat_time(270));
    assert_eq!(attr.mtime, compat_time(280));

    let ino_chr = lookup_path(fs, "/special_chr").expect("/special_chr must exist");
    let attr = fs.get_attr(ino_chr).unwrap();
    assert_eq!(attr.file_type, FileType::CharDevice);
    assert_eq!(attr.rdev, 0x1234);
    assert_eq!(attr.perm & 0o777, 0o660);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.atime, compat_time(290));
    assert_eq!(attr.mtime, compat_time(300));

    let ino_blk = lookup_path(fs, "/special_blk").expect("/special_blk must exist");
    let attr = fs.get_attr(ino_blk).unwrap();
    assert_eq!(attr.file_type, FileType::BlockDevice);
    assert_eq!(attr.rdev, 0x5678);
    assert_eq!(attr.perm & 0o777, 0o660);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.atime, compat_time(310));
    assert_eq!(attr.mtime, compat_time(320));

    let ino_sock = lookup_path(fs, "/special_sock").expect("/special_sock must exist");
    let attr = fs.get_attr(ino_sock).unwrap();
    assert_eq!(attr.file_type, FileType::Socket);
    assert_eq!(attr.perm & 0o777, 0o755);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, 1000);
    assert_eq!(attr.atime, compat_time(330));
    assert_eq!(attr.mtime, compat_time(340));
}
