//! Compatibility tests verifying that earlier on-disk storage format versions can be
//! reliably recovered, loaded, and written to by the current codebase.
//!
//! # Generating Golden Fixtures
//! To generate or regenerate golden fixtures for any version:
//! ```bash
//! # For v1:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1
//!
//! # For a new format version (e.g. v2):
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```
//!
//! Any subdirectories placed into `tests/fixtures/` are automatically discovered
//! and tested by `test_all_fixture_versions`.

use appendfs::compat::{create_canonical_compat_volume, verify_compat_tree};
use appendfs::operations::read_write::{create_core, open_core, read_core, release_core, write_core};
use appendfs::storage::OsStorage;
use appendfs::{InMemoryFS, LogWriter, RecoveryTarget, Storage, VolumeKey, recover_fs};

fn read_test(fs: &InMemoryFS, ino: u64, size: usize, offset: i64) -> Vec<u8> {
    let fh = open_core(fs, ino, libc::O_RDONLY as u32).expect("open file");
    let data = read_core(fs, ino, fh, offset, size).expect("read file");
    release_core(fs, ino, fh).expect("release file");
    data
}

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn fixture_v1_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

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

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        VolumeKey::plaintext_arc(),
    )
    .expect("recovery from 000000.summary + 000001.log must succeed");

    // 1. Verify reconstructed filesystem tree, files, symlinks, special files, and xattrs
    verify_compat_tree(&fs);

    // 2. Verify forward mutability on top of the reconstructed volume
    let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
    let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            next_gen,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(temp_path);

    let new_file = create_core(&fs, 1, "new_after_reconstruction.txt", 0o644, 0, 1000, 1000)
        .expect("create file after reconstruction");
    write_core(&fs, new_file.ino, b"reconstruction test forward write works!", 0).expect("write after reconstruction");
    fs.flush_log().expect("flush after reconstruction");

    let read_back = read_test(&fs, new_file.ino, 40, 0);
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

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        VolumeKey::plaintext_arc(),
    )
    .expect("recovery from latest summary snapshot must succeed");

    // 1. Verify filesystem state loaded directly from the summary snapshot
    verify_compat_tree(&fs);

    // 2. Verify forward mutability
    let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
    let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            next_gen,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(temp_path);

    let new_file =
        create_core(&fs, 1, "new_after_summary.txt", 0o644, 0, 1000, 1000).expect("create file after summary");
    write_core(&fs, new_file.ino, b"summary test forward write works!", 0).expect("write after summary");
    fs.flush_log().expect("flush after summary");

    let read_back = read_test(&fs, new_file.ino, 33, 0);
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
fn test_v1_deterministic_reproducibility() {
    let temp = tempfile::tempdir().unwrap();
    create_canonical_compat_volume(temp.path()).expect("create canonical compat volume");

    let fixture_dir = fixture_v1_dir();
    for name in &["000000.summary", "000001.log", "000001.summary"] {
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
    }
}
