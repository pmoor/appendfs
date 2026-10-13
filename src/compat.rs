use crate::clock::Clock;
use crate::error::FsError;
use crate::fs::AppendFs;
use crate::log::{LogWriter, init_volume_with_clock_and_uids};
use crate::operations::dir::mkdir_core;
#[cfg(any(test, feature = "testing"))]
use crate::operations::links::readlink_core;
use crate::operations::links::{link_core, symlink_core};
use crate::operations::read_write::{
    FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME, FUSE_SET_ATTR_SIZE,
    FUSE_SET_ATTR_UID, copy_file_range_core, create_core, open_core, punch_hole_core, release_core, setattr_core,
    write_handle_core,
};
use crate::operations::special::mknod_core;
use crate::operations::xattr::setxattr_core;
#[cfg(any(test, feature = "testing"))]
use crate::shim::FileType;
use crate::storage::{OsStorage, Storage};
#[cfg(any(test, feature = "testing"))]
use crate::test_utils::FsTestExt;
use crate::{VolumeHeader, VolumeKey};

fn compat_write(fs: &AppendFs, ino: u64, buf: &[u8], offset: i64) -> Result<usize, FsError> {
    let fh = open_core(fs, ino, libc::O_RDWR as u32)?;
    let res = write_handle_core(fs, ino, fh, buf, offset);
    let _ = release_core(fs, ino, fh);
    res
}

fn compat_copy(
    fs: &AppendFs,
    ino_in: u64,
    off_in: i64,
    ino_out: u64,
    off_out: i64,
    len: u64,
) -> Result<usize, FsError> {
    let fh_in = open_core(fs, ino_in, libc::O_RDONLY as u32)?;
    let fh_out = open_core(fs, ino_out, libc::O_WRONLY as u32)?;
    let res = copy_file_range_core(fs, ino_in, fh_in, off_in, ino_out, fh_out, off_out, len, 0);
    let _ = release_core(fs, ino_out, fh_out);
    let _ = release_core(fs, ino_in, fh_in);
    res
}

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed base timestamp used for all canonical compatibility fixtures:
/// 2023-11-14 22:13:20 UTC (1,700,000,000 seconds since UNIX epoch).
pub const COMPAT_BASE_TIMESTAMP_SECS: u64 = 1_700_000_000;

/// Root owner pinned into the canonical fixtures.
///
/// Fixture bytes are checked in and compared for equality, so the root directory's owner
/// cannot come from whoever happens to run the generator. Real volumes take it from the
/// invoking user instead - see `init_volume_with_clock_and_uids`.
pub const COMPAT_UID: u32 = 1000;
pub const COMPAT_GID: u32 = 1000;

/// Name of the key file in each encrypted fixture directory.
pub const COMPAT_KEY_FILENAME: &str = "key.pem";

/// Passphrase protecting the key files of the fixtures that have an encrypted one.
pub const COMPAT_KEY_PASSPHRASE: &str = "passphrase";

/// Key of the generated key-file fixtures, written into their key file unprotected so the
/// generator stays deterministic.
pub const COMPAT_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fixture configurations the generator can produce.
///
/// `v1_passphrase_compressed` and `v1_secret_key_passphrase_compressed` are not among them:
/// they were created under credential modes that no longer exist, so nothing can create
/// such a volume any more. They remain as frozen recovery fixtures, unlocked by a key file
/// holding the key those modes derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatFixtureConfig {
    /// Baseline plaintext volume with uncompressed log records.
    UnencryptedUncompressed,
    /// ChaCha20-Poly1305 encrypted volume unlocked by a key file, with Zstd log compression.
    KeyFileCompressed,
}

impl CompatFixtureConfig {
    pub const ALL: [Self; 2] = [Self::UnencryptedUncompressed, Self::KeyFileCompressed];

    /// The fixture directory for this configuration in the current format version, such as
    /// `v2` or `v2_key_file_compressed`.
    pub fn default_dir_name(self) -> String {
        let version = crate::log::record::CURRENT_VERSION;
        match self {
            Self::UnencryptedUncompressed => format!("v{}", version),
            Self::KeyFileCompressed => format!("v{}_key_file_compressed", version),
        }
    }

    /// Maps a fixture directory of the current format version, such as `v2` or
    /// `v2_key_file_compressed`, to its configuration. Any other name is `None` - including
    /// every fixture of an older version, which is frozen: the generator only writes the
    /// current format, so regenerating one would silently replace it with a newer one.
    pub fn from_dir_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        let suffix = name.strip_prefix(&format!("v{}", crate::log::record::CURRENT_VERSION))?;
        match suffix {
            "" => Some(Self::UnencryptedUncompressed),
            "_key_file_compressed" => Some(Self::KeyFileCompressed),
            _ => None,
        }
    }

    pub fn is_encrypted(self) -> bool {
        self == Self::KeyFileCompressed
    }

    pub fn compression(self) -> crate::compress::Compression {
        match self {
            Self::UnencryptedUncompressed => crate::compress::Compression::None,
            Self::KeyFileCompressed => crate::compress::Compression::Zstd,
        }
    }
}

/// Fixed 16-byte volume ID for canonical encrypted compatibility fixtures.
pub const COMPAT_ENCRYPTED_VOLUME_ID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Fixed 12-byte KCV IV for canonical encrypted compatibility fixtures.
pub const COMPAT_ENCRYPTED_KCV_IV: [u8; 12] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac];

/// Fixed 12-byte IV for generation 0 summary snapshot in canonical encrypted compatibility fixtures.
pub const COMPAT_SUMMARY_0_IV: [u8; 12] = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc];

/// Fixed 12-byte IV for generation 1 summary snapshot in canonical encrypted compatibility fixtures.
pub const COMPAT_SUMMARY_1_IV: [u8; 12] = [0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc];

/// Fixed key salt for each log generation in compatibility fixtures, in place of the random
/// one a real volume draws, so the fixtures come out byte-identical on every run.
pub fn compat_key_salt(generation: u32) -> [u8; 16] {
    let mut salt = *b"appendfs-compat-";
    salt[12..].copy_from_slice(&generation.to_be_bytes());
    salt
}

/// Canonical list of fixture volume file basenames.
pub const COMPAT_FIXTURE_FILES: &[&str] = &["000000.summary", "000001.log", "000001.summary"];

/// Canonical list of golden fixture dump file basenames.
pub const COMPAT_FIXTURE_DUMP_FILES: &[&str] = &[
    "000000.summary-dump.txt",
    "000001.log-dump.txt",
    "000001.summary-dump.txt",
];

/// Canonical golden fsck report filename.
pub const COMPAT_FSCK_REPORT_FILENAME: &str = "fsck-report.txt";

/// Resolves the volume key required to open `fixture_dir`, unlocking encrypted fixtures
/// with the key file stored alongside them.
pub fn resolve_fixture_volume_key(fixture_dir: &Path) -> Arc<VolumeKey> {
    let storage = OsStorage::new(fixture_dir);
    let volume_header =
        crate::log::SummaryReader::read_volume_header(&storage, "000000.summary").expect("read fixture volume header");
    if !volume_header.cipher.is_encrypted() {
        return VolumeKey::plaintext_arc();
    }

    let key_file = fixture_dir.join(COMPAT_KEY_FILENAME);
    let master = crate::crypto::KeyFile::read(&key_file)
        .and_then(|file| file.unlock(|| Ok(zeroize::Zeroizing::new(COMPAT_KEY_PASSPHRASE.to_string()))))
        .unwrap_or_else(|e| {
            panic!(
                "Failed to load key file '{}' for encrypted fixture '{}': {}",
                key_file.display(),
                fixture_dir.display(),
                e
            )
        });
    Arc::new(volume_header.unlock(&master).expect("unlock encrypted fixture volume"))
}

/// Generates golden `-dump.txt` files for the canonical volume files in `dir`.
pub fn generate_compat_dump_files(dir: &Path, volume_key: Option<&VolumeKey>) -> io::Result<()> {
    let storage = OsStorage::new(dir);
    for name in COMPAT_FIXTURE_FILES {
        let dump_text = crate::dump::dump_file(&storage, name, 1, volume_key)?;
        fs::write(dir.join(format!("{}-dump.txt", name)), dump_text)?;
    }
    Ok(())
}

/// Generates golden `fsck-report.txt` file for the canonical volume in `dir`.
pub fn generate_compat_fsck_report(dir: &Path, volume_key: Arc<VolumeKey>) -> io::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(dir));
    let report = crate::check::check_volume(
        storage,
        &crate::check::CheckOptions::full_data(),
        volume_key,
        Arc::new(CompatClock::new()),
    )
    .map_err(io::Error::other)?;
    let report_text = report.format_report(None, false);
    fs::write(dir.join(COMPAT_FSCK_REPORT_FILENAME), report_text)?;
    Ok(())
}

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

/// Final contents of `/dir_b/regrown.bin`.
/// Expected contents of `/dir_b/cloned.bin`: bytes 256..768 of data.bin, then hello.txt's
/// first 16 bytes.
pub fn compat_cloned_full() -> Vec<u8> {
    let mut v = compat_data_bin()[256..768].to_vec();
    v.extend_from_slice(b"Hello, AppendFS ");
    v
}

pub fn compat_regrown_full() -> Vec<u8> {
    let mut data = vec![0xBB; 4096];
    data.resize(8192, 0);
    data.extend_from_slice(&[0xCC; 100]);
    data
}

/// Populates the canonical compatibility filesystem tree on `fs` across 3 distinct flush cycles.
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn populate_compat_tree(fs: &AppendFs, clock: &CompatClock) -> Result<(), FsError> {
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
    compat_write(fs, hello_file.ino, b"Hello, AppendFS ", 0)?;
    setxattr_core(fs, hello_file.ino, "user.test_attr", b"compat_v1", 0)?;

    // Commit Batch 1 to log
    fs.quiesce()?;

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
    compat_write(fs, hello_file.ino, b"v1 compatibility world!\n", 16)?;

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
    compat_write(fs, data_bin.ino, &bin_data, 0)?;
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
    compat_write(fs, multi_extent.ino, &p1, 0)?;

    // Written in full here; batch 3 truncates it to half and writes past the old end.
    let regrown = create_core(fs, dir_b.ino, "regrown.bin", 0o644, 0, 1003, 1003)?;
    compat_write(fs, regrown.ino, &[0xBB; 8192], 0)?;

    // Commit Batch 2 to log
    fs.quiesce()?;

    // --- BATCH 3: Multi-extent part 2, sparse file, hardlink, symlinks, special files, and attrs ---
    clock.set_offset(170);
    let p2 = compat_multi_extent_part2();
    compat_write(fs, multi_extent.ino, &p2, 16384)?;
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

    // Sparse file: 4096-byte hole, 100 bytes of 0xAA at offset 4096. The hole is punched
    // over written data rather than left unwritten, so it is persisted as an explicit hole
    // extent in both the log and the summary.
    clock.set_offset(190);
    let sparse_file = create_core(fs, 1, "sparse_file.bin", 0o644, 0, 1001, 1001)?;
    compat_write(fs, sparse_file.ino, &[0xAA; 4196], 0)?;
    punch_hole_core(fs, sparse_file.ino, 0, 4096)?;
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

    // Truncate /dir_b/regrown.bin to half, then write at its old end. The log carries the
    // cut-off half as a hole over data flushed in batch 2, and the truncation's own hole
    // running from the new tail to u64::MAX.
    clock.set_offset(350);
    setattr_core(
        fs,
        regrown.ino,
        0,
        0,
        0,
        4096,
        UNIX_EPOCH,
        UNIX_EPOCH,
        FUSE_SET_ATTR_SIZE,
    )?;
    compat_write(fs, regrown.ino, &[0xCC; 100], 8192)?;
    setattr_core(
        fs,
        regrown.ino,
        0o644,
        1003,
        1003,
        0,
        compat_time(350),
        compat_time(360),
        FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME,
    )?;

    // Format v2: a file assembled by `copy_file_range` from records flushed by earlier
    // batches - the middle of data.bin, then the head of hello.txt - so the log carries `Ref`
    // extents into other inodes' records, one of them starting partway into its record.
    clock.set_offset(370);
    let cloned = create_core(fs, dir_b.ino, "cloned.bin", 0o644, 0, 1003, 1003)?;
    compat_copy(fs, data_bin.ino, 256, cloned.ino, 0, 512)?;
    compat_copy(fs, hello_file.ino, 0, cloned.ino, 512, 16)?;
    setattr_core(
        fs,
        cloned.ino,
        0o644,
        1003,
        1003,
        0,
        compat_time(370),
        compat_time(380),
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
    fs.quiesce()?;

    Ok(())
}

fn create_canonical_encrypted_compat_volume(out_dir: &Path, config: CompatFixtureConfig) -> io::Result<()> {
    let master_key = crate::crypto::MasterKey::new(COMPAT_KEY);
    fs::write(
        out_dir.join(COMPAT_KEY_FILENAME),
        crate::crypto::format_plain_key_file(&master_key).as_bytes(),
    )?;

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(out_dir));
    let clock = Arc::new(CompatClock::new());

    let (volume_header, volume_key) = crate::crypto::VolumeHeader::new_encrypted_with_params(
        &master_key,
        COMPAT_ENCRYPTED_VOLUME_ID,
        COMPAT_ENCRYPTED_KCV_IV,
        config.compression(),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let volume_key_arc = Arc::new(volume_key);

    // 1. Initialize volume -> writes 000000.summary with deterministic clock & explicit IV
    crate::log::summary::init_volume_with_clock_uids_and_iv(
        storage.clone(),
        &volume_key_arc,
        volume_header.clone(),
        clock.clone(),
        COMPAT_UID,
        COMPAT_GID,
        Some(COMPAT_SUMMARY_0_IV),
    )?;

    // 2. Open log writer for generation 1 with deterministic clock, volume encryption key, and compression
    // Lazy, so the fixed key salts are in place before the first file is created.
    let writer = Arc::new(
        LogWriter::create_lazy(
            storage.clone(),
            1,
            clock.clone(),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            volume_key_arc.clone(),
        )
        .map_err(io::Error::other)?
        .with_first_created_at(clock.now())
        .with_key_salts(compat_key_salt)
        .with_compression(config.compression()),
    );

    let mut fs = AppendFs::with_clock_and_uids(clock.clone(), COMPAT_UID, COMPAT_GID);
    fs.volume_header = volume_header;
    fs.volume_key = volume_key_arc.clone();
    fs.deterministic_summary_iv = Some(COMPAT_SUMMARY_1_IV);
    fs.log_writer = Some(writer);
    fs.set_log_dir(out_dir);

    // 3. Populate canonical tree across 3 flushes
    populate_compat_tree(&fs, &clock).map_err(io::Error::from)?;

    // 4. Export final summary snapshot -> writes 000001.summary with explicit IV
    clock.set_offset(500);
    fs.sync_and_export_summary_with_iv(Some(COMPAT_SUMMARY_1_IV))?;

    drop(fs);
    let _ = fs::remove_file(out_dir.join(".lock"));

    // 5. Generate golden dumps
    generate_compat_dump_files(out_dir, Some(&volume_key_arc))?;

    // 6. Generate golden fsck report
    generate_compat_fsck_report(out_dir, volume_key_arc)?;

    Ok(())
}

fn create_canonical_plaintext_compat_volume(out_dir: &Path, config: CompatFixtureConfig) -> io::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(out_dir));
    let clock = Arc::new(CompatClock::new());

    let volume_header = VolumeHeader::deterministic_plaintext(config.compression());
    let volume_key = VolumeKey::plaintext();
    let volume_key_arc = VolumeKey::plaintext_arc();

    // 1. Initialize volume -> writes 000000.summary with deterministic clock.
    init_volume_with_clock_and_uids(
        storage.clone(),
        &volume_key,
        volume_header.clone(),
        clock.clone(),
        COMPAT_UID,
        COMPAT_GID,
    )?;

    // 2. Open log writer for generation 1 with deterministic clock and compression
    // Lazy, so the fixed key salts are in place before the first file is created.
    let writer = Arc::new(
        LogWriter::create_lazy(
            storage.clone(),
            1,
            clock.clone(),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            volume_key_arc.clone(),
        )
        .map_err(io::Error::other)?
        .with_first_created_at(clock.now())
        .with_key_salts(compat_key_salt)
        .with_compression(config.compression()),
    );

    let mut fs = AppendFs::with_clock_and_uids(clock.clone(), COMPAT_UID, COMPAT_GID);
    fs.volume_header = volume_header;
    fs.log_writer = Some(writer);
    fs.set_log_dir(out_dir);

    // 3. Populate canonical tree across 3 flushes
    populate_compat_tree(&fs, &clock).map_err(io::Error::from)?;

    // 4. Export final summary snapshot -> writes 000001.summary
    clock.set_offset(500);
    fs.sync_and_export_summary()?;

    drop(fs);
    let _ = fs::remove_file(out_dir.join(".lock"));

    // 5. Generate golden dumps
    generate_compat_dump_files(out_dir, None)?;

    // 6. Generate golden fsck report
    generate_compat_fsck_report(out_dir, volume_key_arc)?;

    Ok(())
}

/// Generates the canonical compatibility volume into `out_dir` matching `config`.
pub fn create_canonical_compat_volume(out_dir: &Path, config: CompatFixtureConfig) -> io::Result<()> {
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

    if config.is_encrypted() {
        create_canonical_encrypted_compat_volume(out_dir, config)
    } else {
        create_canonical_plaintext_compat_volume(out_dir, config)
    }
}

/// Helper to navigate and locate an inode by relative POSIX path.
pub fn lookup_path(fs: &AppendFs, path: &str) -> Option<u64> {
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
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
#[cfg(any(test, feature = "testing"))]
pub fn verify_compat_tree(fs: &AppendFs, format_version: u32) {
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
    let hello_bytes = fs.read_at(ino_hello, 0, 40).expect("read compat file");
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
    let bin_read = fs.read_at(ino_data_bin, 0, 1024).expect("read compat file");
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
    let multi_read = fs.read_at(ino_multi, 0, 32768).expect("read compat file");
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
    let hole_read = fs.read_at(ino_sparse, 0, 4096).expect("read compat file");
    assert_eq!(hole_read, vec![0u8; 4096]);
    // Verify data portion
    let data_read = fs.read_at(ino_sparse, 4096, 100).expect("read compat file");
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

    // /dir_b/regrown.bin (data 0..4096, hole 4096..8192, data 8192..8292)
    let ino_regrown = lookup_path(fs, "/dir_b/regrown.bin").expect("/dir_b/regrown.bin must exist");
    let attr = fs.get_attr(ino_regrown).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 8292);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1003);
    assert_eq!(attr.gid, 1003);
    assert_eq!(attr.atime, compat_time(350));
    assert_eq!(attr.mtime, compat_time(360));
    assert_eq!(
        fs.read_at(ino_regrown, 0, 8292).expect("read compat file"),
        compat_regrown_full()
    );

    // /dir_b/cloned.bin, assembled by copy_file_range from format v2 on
    let cloned = lookup_path(fs, "/dir_b/cloned.bin");
    if format_version < 2 {
        assert_eq!(cloned, None, "copy_file_range arrived with format v2");
        return;
    }
    let ino_cloned = cloned.expect("/dir_b/cloned.bin must exist");
    let attr = fs.get_attr(ino_cloned).unwrap();
    assert_eq!(attr.file_type, FileType::RegularFile);
    assert_eq!(attr.size, 528);
    assert_eq!(attr.perm & 0o777, 0o644);
    assert_eq!(attr.uid, 1003);
    assert_eq!(attr.gid, 1003);
    assert_eq!(attr.atime, compat_time(370));
    assert_eq!(attr.mtime, compat_time(380));
    assert_eq!(fs.read_all(ino_cloned).expect("read compat file"), compat_cloned_full());
}

/// The log format version `fixture_dir` was written in, from its log file's header.
pub fn fixture_format_version(fixture_dir: &Path) -> u32 {
    let bytes = fs::read(fixture_dir.join("000001.log")).expect("read fixture log");
    let header: &[u8; crate::log::FILE_HEADER_SIZE] = bytes[..crate::log::FILE_HEADER_SIZE]
        .try_into()
        .expect("fixture log shorter than its header");
    crate::log::FileHeader::from_bytes(header)
        .expect("parse fixture log header")
        .version
}
