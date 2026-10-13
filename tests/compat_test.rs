//! Compatibility tests verifying that earlier on-disk storage format versions can be
//! reliably recovered, loaded, and written to by the current codebase.
//!
//! # Generating Golden Fixtures
//! The generator writes fixtures for the current format version only; those of older
//! versions are frozen.
//! ```bash
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```
//!
//! Any subdirectories placed into `tests/fixtures/` are automatically discovered
//! and tested by `test_all_fixture_versions`.

use appendfs::FsTestExt;
use appendfs::compat::{
    COMPAT_FSCK_REPORT_FILENAME, COMPAT_KEY_FILENAME, CompatFixtureConfig, create_canonical_compat_volume,
    fixture_format_version, verify_compat_tree,
};
use appendfs::storage::OsStorage;
use appendfs::{AppendFs, RecoveryTarget, Storage, SummaryReader, recover_fs};

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn fixture_v1_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

pub use appendfs::compat::resolve_fixture_volume_key;

/// Tests recovery when the latest summary file is missing, forcing full log replay and
/// reconstruction from the earliest summary and all subsequent log records.
pub fn verify_recovery_with_latest_summary_missing(fixture_dir: &Path) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path();

    // Copy 000000.summary and 000001.log, explicitly omitting 000001.summary.
    // This forces recovery to replay 000001.log from scratch across all 3 flush batches.
    fs::copy(fixture_dir.join("000000.summary"), temp_path.join("000000.summary")).expect("copy 000000.summary");
    fs::copy(fixture_dir.join("000001.log"), temp_path.join("000001.log")).expect("copy 000001.log");

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(temp_path));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);
    let volume_key = resolve_fixture_volume_key(fixture_dir);

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .expect("recovery from 000000.summary + 000001.log must succeed");

    // 1. Verify reconstructed filesystem tree, files, symlinks, special files, and xattrs
    verify_compat_tree(&fs, fixture_format_version(fixture_dir));

    // 2. Verify forward mutability on top of the reconstructed volume
    let writer = fs
        .next_log_writer(storage.clone(), appendfs::cli::DEFAULT_MAX_LOG_SIZE)
        .unwrap();
    fs.attach_log_writer(Arc::new(writer));
    fs.set_log_dir(temp_path);

    let new_file = fs
        .create_file(1, "new_after_reconstruction.txt", 0o644)
        .expect("create file after reconstruction");
    fs.write_at(new_file, b"reconstruction test forward write works!", 0)
        .expect("write after reconstruction");
    fs.quiesce().expect("flush after reconstruction");

    let read_back = fs.read_at(new_file, 0, 40).expect("read file");
    assert_eq!(read_back, b"reconstruction test forward write works!");
}

/// Tests recovery directly from the latest exported summary snapshot file.
pub fn verify_recovery_from_latest_summary_snapshot(fixture_dir: &Path) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path();

    // Copy all files in fixture_dir (e.g. 000000.summary, 000001.log, and 000001.summary)
    for entry in fs::read_dir(fixture_dir).unwrap().flatten() {
        if entry.path().is_file() {
            fs::copy(entry.path(), temp_path.join(entry.file_name())).unwrap();
        }
    }

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(temp_path));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);
    let volume_key = resolve_fixture_volume_key(fixture_dir);

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .expect("recovery from latest summary snapshot must succeed");

    // 1. Verify filesystem state loaded directly from the summary snapshot
    verify_compat_tree(&fs, fixture_format_version(fixture_dir));

    // 2. Verify forward mutability
    let writer = fs
        .next_log_writer(storage.clone(), appendfs::cli::DEFAULT_MAX_LOG_SIZE)
        .unwrap();
    fs.attach_log_writer(Arc::new(writer));
    fs.set_log_dir(temp_path);

    let new_file = fs
        .create_file(1, "new_after_summary.txt", 0o644)
        .expect("create file after summary");
    fs.write_at(new_file, b"summary test forward write works!", 0)
        .expect("write after summary");
    fs.quiesce().expect("flush after summary");

    let read_back = fs.read_at(new_file, 0, 33).expect("read file");
    assert_eq!(read_back, b"summary test forward write works!");
}

#[test]
fn test_v1_log_reconstruction_with_latest_summary_missing() {
    verify_recovery_with_latest_summary_missing(&fixture_v1_dir());
}

#[test]
fn test_v1_recovery_from_latest_summary_snapshot() {
    verify_recovery_from_latest_summary_snapshot(&fixture_v1_dir());
}

#[test]
fn test_v1_stats_matches_latest_summary_dump() {
    verify_stats_matches_latest_summary_dump(&fixture_v1_dir());
}

#[test]
fn test_v1_fsck_matches_golden() {
    verify_fsck_matches_golden(&fixture_v1_dir());
}

/// Every configuration the generator knows must reproduce its checked-in fixture byte for
/// byte, which is what proves the write path has not drifted from the format on disk.
///
/// The legacy passphrase fixtures are not among them: nothing can create such a volume any
/// more, so they are covered by recovery alone, in `test_all_fixture_versions`.
#[test]
fn test_generated_fixtures_reproduce_byte_for_byte() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for config in CompatFixtureConfig::ALL {
        let temp = tempfile::tempdir().unwrap();
        create_canonical_compat_volume(temp.path(), config).expect("create canonical compat volume");

        let fixture_dir = fixtures_dir.join(config.default_dir_name());
        let key_file = config.is_encrypted().then_some(COMPAT_KEY_FILENAME);
        for name in appendfs::compat::COMPAT_FIXTURE_FILES
            .iter()
            .chain(appendfs::compat::COMPAT_FIXTURE_DUMP_FILES.iter())
            .chain([COMPAT_FSCK_REPORT_FILENAME].iter())
            .chain(key_file.iter())
        {
            let actual_bytes = fs::read(temp.path().join(name)).expect("read generated file");
            let expected_bytes = fs::read(fixture_dir.join(name)).expect("read fixture file");
            assert_eq!(
                actual_bytes,
                expected_bytes,
                "Generated file {} differs from checked-in fixture in {}",
                name,
                fixture_dir.display()
            );
        }
    }
}

/// Shortest byte string worth searching for.
///
/// A match on fewer bytes than this says nothing: three bytes recur by chance roughly once
/// per 16 MiB of ciphertext, so a hit would be noise rather than a leak. Fixture bytes are
/// checked in and deterministic, so this threshold cannot make the test flaky either way.
const MIN_NEEDLE_BYTES: usize = 4;

/// Every byte string the fixture volume holds that a reader without the key must not see.
///
/// Collected by walking the recovered filesystem rather than by listing literals, so
/// anything added to `create_canonical_compat_volume` later is covered without this test
/// being touched. Each entry is `(what it is, the bytes)`.
fn collect_secret_plaintext(fs: &AppendFs) -> Vec<(String, Vec<u8>)> {
    let mut secrets: Vec<(String, Vec<u8>)> = Vec::new();
    // Paths carry no trailing slash, so the root is the empty string and is displayed as "/".
    let mut pending = vec![(String::new(), 1u64)];

    while let Some((path, ino)) = pending.pop() {
        let display = if path.is_empty() { "/" } else { path.as_str() };

        for name in fs.list_xattrs(ino).unwrap_or_default() {
            if let Some(value) = fs.get_xattr(ino, &name) {
                secrets.push((format!("xattr value of {} on {}", name, display), value));
            }
            secrets.push((format!("xattr name on {}", display), name.into_bytes()));
        }

        let Some(attr) = fs.get_attr(ino) else { continue };
        match attr.file_type {
            appendfs::FileType::Directory => {
                for (name, child) in fs.list_directory(ino).unwrap_or_default() {
                    let child_path = format!("{}/{}", path, name);
                    secrets.push((format!("name of {}", child_path), name.into_bytes()));
                    // Hard links revisit an inode, which only duplicates needles; directories
                    // cannot be hard-linked, so the walk terminates.
                    pending.push((child_path, child));
                }
            }
            appendfs::FileType::Symlink => {
                if let Some(target) = fs.read_link(ino) {
                    secrets.push((format!("symlink target of {}", display), target.into_bytes()));
                }
            }
            appendfs::FileType::RegularFile if attr.size > 0 => {
                let data = fs
                    .read_file_data(ino, 0, attr.size as usize)
                    .unwrap_or_else(|e| panic!("read {} for the plaintext scan: {:?}", display, e));
                secrets.push((format!("contents of {}", display), data));
            }
            _ => {}
        }
    }

    secrets.retain(|(_, bytes)| bytes.len() >= MIN_NEEDLE_BYTES);
    assert!(
        secrets.len() > 10,
        "the plaintext scan collected only {} needles, so it is not testing much",
        secrets.len()
    );
    secrets
}

/// Verifies that no name, file content, symlink target, or xattr of an encrypted fixture
/// appears in its checked-in volume files, or in anything the read path writes to disk
/// while serving them.
///
/// The byte-for-byte reproducibility tests prove the *format* has not moved; this proves
/// what the format is for. It runs against the committed bytes rather than a freshly
/// generated volume, so a regression that starts leaking plaintext is caught the moment
/// fixtures are regenerated, not merely when the encoding changes.
///
/// Two directories are scanned:
///
/// - the fixture itself, for what the *write* path produced; and
/// - the on-disk block cache, for what the *read* path spills. That cache is the one place
///   a read can put volume bytes back on disk. With `--disk-cache-local-reads`, reading a
///   sealed generation pre-warms it from local storage - no remote and no pruning required,
///   which is the whole point of pre-warming: blocks that were read once stay readable after
///   the log is purged. It must hold the encrypted 1 MiB blocks it read, never the decrypted
///   records derived from them.
///
/// The `-dump.txt` goldens beside the fixture are excluded: they are decrypted renderings
/// produced *with* the fixture key, and contain plaintext by design.
pub fn verify_no_plaintext_in_encrypted_fixture(fixture_dir: &Path) {
    let Some(config) = CompatFixtureConfig::from_dir_path(fixture_dir) else {
        return;
    };
    if !config.is_encrypted() {
        return;
    }

    // Recovered from a copy, scanned on the originals: nothing here may touch the fixtures.
    let temp = tempfile::tempdir().unwrap();
    for name in appendfs::compat::COMPAT_FIXTURE_FILES {
        fs::copy(fixture_dir.join(name), temp.path().join(name)).expect("copy fixture file");
    }
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(temp.path()));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);
    let mut fs_recovered = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        resolve_fixture_volume_key(fixture_dir),
    )
    .expect("recover encrypted fixture");

    // No remotes, nothing pruned: with local reads cached, reading a sealed generation
    // pre-warms the block cache straight from local storage.
    let cache_dir = temp.path().join(".cache");
    let block_cache = Arc::new(
        appendfs::remote::OnDiskBlockCache::new(&cache_dir, 64 * 1024 * 1024, clock.clone())
            .expect("create on-disk block cache"),
    );
    fs_recovered.log_cache = Some(Arc::new(
        appendfs::log::LogFileCache::with_remote_support(
            storage.clone(),
            Some(block_cache.clone()),
            Vec::<appendfs::remote::RemoteReadTarget>::new(),
            Some(Arc::clone(&fs_recovered.manifest)),
        )
        .with_cache_local_reads(true),
    ));

    // Reads every file, which both gathers the needles and fills the block cache.
    let secrets = collect_secret_plaintext(&fs_recovered);

    let volume_files: Vec<PathBuf> = appendfs::compat::COMPAT_FIXTURE_FILES
        .iter()
        .map(|name| fixture_dir.join(name))
        .collect();
    let cached_blocks: Vec<PathBuf> = fs::read_dir(&cache_dir)
        .expect("read block cache dir")
        .map(|e| e.expect("cache dir entry").path())
        .filter(|p| p.is_file())
        .collect();
    assert!(
        !cached_blocks.is_empty(),
        "no blocks were cached, so the read path was never exercised: {}",
        cache_dir.display()
    );

    for path in volume_files.iter().chain(cached_blocks.iter()) {
        let bytes = fs::read(path).expect("read file to scan");
        for (what, needle) in &secrets {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                "plaintext leak: the {} appears in {} ({} bytes: {:?})",
                what,
                path.display(),
                needle.len(),
                String::from_utf8_lossy(&needle[..needle.len().min(64)])
            );
        }
    }
}

/// Verifies that dump output for all canonical volume files in `fixture_dir` matches
/// the checked-in golden `-dump.txt` files.
pub fn verify_fixture_dumps(fixture_dir: &Path) {
    let storage = OsStorage::new(fixture_dir);
    let volume_key = resolve_fixture_volume_key(fixture_dir);

    for name in appendfs::compat::COMPAT_FIXTURE_FILES {
        let dump_filename = format!("{}-dump.txt", name);
        let golden_path = fixture_dir.join(&dump_filename);
        assert!(
            golden_path.is_file(),
            "Missing golden dump file {} in fixture {}",
            dump_filename,
            fixture_dir.display()
        );
        let actual_dump = appendfs::dump_file(&storage, name, 1, Some(volume_key.as_ref()))
            .unwrap_or_else(|e| panic!("Failed to dump {} in {}: {}", name, fixture_dir.display(), e));
        let expected_dump = fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("Failed to read golden dump {}: {}", golden_path.display(), e));
        assert_eq!(
            actual_dump,
            expected_dump,
            "Dump of {} in {} differs from golden fixture {}",
            name,
            fixture_dir.display(),
            golden_path.display()
        );
    }
}

/// Verifies that `appendfs stats` output is identical to `appendfs dump` on the latest summary file
/// starting from the canonical "--- Inode Breakdown ---" report header.
pub fn verify_stats_matches_latest_summary_dump(fixture_dir: &Path) {
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(fixture_dir));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);
    let volume_key = resolve_fixture_volume_key(fixture_dir);

    // 1. Locate the latest summary file in fixture_dir
    let mut latest_summary: Option<((u32, u16), String)> = None;
    for file in storage.list_files().expect("list fixture files") {
        if let Some((generation, rev)) = appendfs::log::parse_summary_filename(&file)
            && latest_summary.as_ref().is_none_or(|(gr, _)| (generation, rev) > *gr)
        {
            latest_summary = Some(((generation, rev), file));
        }
    }
    let (_, latest_summary_file) = latest_summary.expect("fixture must have at least one summary file");

    // 2. Dump latest summary file at verbosity 0
    let dump_output =
        appendfs::dump_file(&storage, &latest_summary_file, 0, Some(volume_key.as_ref())).unwrap_or_else(|e| {
            panic!(
                "Failed to dump {} in {}: {}",
                latest_summary_file,
                fixture_dir.display(),
                e
            )
        });

    // 3. Recover filesystem to latest state and collect VolumeStats
    let fs = recover_fs(storage, RecoveryTarget::Latest, clock, volume_key)
        .unwrap_or_else(|e| panic!("Recovery failed in {}: {}", fixture_dir.display(), e));
    let stats = appendfs::VolumeStats::collect(&fs);
    let stats_output = stats.display_text();

    // 4. Assert that the report starting from "--- Inode Breakdown ---" matches identically
    let dump_idx = dump_output
        .find("--- Inode Breakdown ---")
        .expect("dump must contain '--- Inode Breakdown ---'");
    let stats_idx = stats_output
        .find("--- Inode Breakdown ---")
        .expect("stats must contain '--- Inode Breakdown ---'");

    assert_eq!(
        &dump_output[dump_idx..],
        &stats_output[stats_idx..],
        "Stats report does not match latest summary dump in {}",
        fixture_dir.display()
    );
}

/// Verifies that running fsck in full data verification mode against the canonical volume
/// in `fixture_dir` produces an output identical to the checked-in golden `fsck-report.txt`.
pub fn verify_fsck_matches_golden(fixture_dir: &Path) {
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(fixture_dir));
    let volume_key = resolve_fixture_volume_key(fixture_dir);
    let golden_path = fixture_dir.join(COMPAT_FSCK_REPORT_FILENAME);
    assert!(
        golden_path.is_file(),
        "Missing golden fsck report file {} in fixture {}",
        COMPAT_FSCK_REPORT_FILENAME,
        fixture_dir.display()
    );

    let report = appendfs::check::check_volume(
        storage,
        &appendfs::check::CheckOptions::full_data(),
        volume_key,
        std::sync::Arc::new(appendfs::SystemClock),
    )
    .unwrap_or_else(|e| panic!("fsck failed on fixture {}: {}", fixture_dir.display(), e));
    let actual_report = report.format_report(None, false);
    let expected_report = fs::read_to_string(&golden_path)
        .unwrap_or_else(|e| panic!("Failed to read golden fsck report {}: {}", golden_path.display(), e));

    assert_eq!(
        actual_report,
        expected_report,
        "fsck report in {} differs from golden fixture {}",
        fixture_dir.display(),
        golden_path.display()
    );
}

#[test]
fn test_all_fixture_versions() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    assert!(fixtures_dir.is_dir(), "tests/fixtures directory must exist");

    let mut versions: Vec<PathBuf> = fs::read_dir(&fixtures_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    versions.sort();

    assert!(
        !versions.is_empty(),
        "at least one fixture version directory must exist"
    );

    for version_dir in &versions {
        let version_name = version_dir.file_name().unwrap().to_string_lossy();
        println!("Running compatibility checks on fixture: {}", version_name);
        verify_recovery_with_latest_summary_missing(version_dir);
        verify_recovery_from_latest_summary_snapshot(version_dir);
        verify_no_plaintext_in_encrypted_fixture(version_dir);
        verify_fixture_dumps(version_dir);
        verify_stats_matches_latest_summary_dump(version_dir);
        verify_fsck_matches_golden(version_dir);
        verify_python_restore_script(version_dir);
    }
}

/// Verifies that the standalone Python restore script (scripts/restore.py) can successfully
/// replay all log batches from the golden fixture and reconstruct identical file data.
pub fn verify_python_restore_script(fixture_dir: &Path) {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let dest_path = temp.path();

    let storage = OsStorage::new(fixture_dir);
    let is_encrypted = SummaryReader::read_volume_header(&storage, "000000.summary")
        .map(|h| h.cipher.is_encrypted())
        .unwrap_or(false);

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&script_path).arg(fixture_dir).arg(dest_path);
    if is_encrypted {
        cmd.arg("--key-file").arg(fixture_dir.join(COMPAT_KEY_FILENAME));
    }
    // Answers the key file's passphrase prompt, if it has one. A script that never reads it
    // may already have exited, so a failed write is not an error.
    cmd.stdin(std::process::Stdio::piped());
    let mut child = cmd
        .spawn()
        .expect("failed to execute python3; python3 must be installed and in PATH");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("open stdin");
        let _ = writeln!(stdin, "{}", appendfs::compat::COMPAT_KEY_PASSPHRASE);
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait on python3 child process");

    assert!(
        output.status.success(),
        "scripts/restore.py failed on {}:\nstdout:\n{}\nstderr:\n{}",
        fixture_dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify key files restored by scripts/restore.py
    let hello = fs::read(dest_path.join("hello.txt")).expect("read hello.txt");
    assert_eq!(hello, b"Hello, AppendFS v1 compatibility world!\n");

    let data_bin = fs::read(dest_path.join("dir_a/subdir_1/data.bin")).expect("read data.bin");
    assert_eq!(data_bin, appendfs::compat::compat_data_bin());

    let multi = fs::read(dest_path.join("dir_b/multi_extent.dat")).expect("read multi_extent.dat");
    assert_eq!(multi, appendfs::compat::compat_multi_extent_full());

    let sparse = fs::read(dest_path.join("sparse_file.bin")).expect("read sparse_file.bin");
    assert_eq!(sparse.len(), 4196);
    assert_eq!(&sparse[..4096], &[0u8; 4096]);
    assert_eq!(&sparse[4096..], &[0xAA; 100]);

    let regrown = fs::read(dest_path.join("dir_b/regrown.bin")).expect("read regrown.bin");
    assert_eq!(regrown, appendfs::compat::compat_regrown_full());

    if fixture_format_version(fixture_dir) >= 2 {
        let cloned = fs::read(dest_path.join("dir_b/cloned.bin")).expect("read cloned.bin");
        assert_eq!(cloned, appendfs::compat::compat_cloned_full());
    }

    assert!(dest_path.join("dir_empty").is_dir());
    assert!(dest_path.join("dir_a/subdir_1/deep").is_dir());
    assert_eq!(
        fs::read_link(dest_path.join("symlink_rel")).unwrap(),
        Path::new("hello.txt")
    );
}
