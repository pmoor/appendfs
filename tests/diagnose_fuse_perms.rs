//! TEMPORARY diagnostic. Not a real test - it asserts nothing and is meant to be reverted.
//!
//! Four integration tests fail on GitHub Actions with EACCES on the first write into a
//! mounted volume, while other tests that mount and write pass. Locally all of them pass.
//! `fuse_shim.cpp` forces `-odefault_permissions`, so the kernel checks the root inode's
//! uid/gid/mode against the caller - and a root owned by a foreign uid reproduces exactly
//! that EACCES locally. What is not known is why the runner ends up with a mismatch.
//!
//! This prints, for both the passing shape (a fresh `InMemoryFS`) and the failing shape (a
//! pristine volume put through `recover_fs`), what the in-memory root looks like and what
//! the kernel sees through the mount, then attempts the operation that fails on CI.

mod common;

use appendfs::crypto::{VolumeHeader, VolumeKey};
use appendfs::storage::OsStorage;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

fn report(label: &str, fs: appendfs::InMemoryFS) {
    let root = fs.base.read().unwrap().get(&1).cloned();
    match root {
        Some(node) => println!(
            "DIAG [{}] in-memory root: perm={:o} nlink={} uid={} gid={}",
            label, node.meta.perm, node.meta.nlink, node.meta.uid, node.meta.gid
        ),
        None => println!("DIAG [{}] in-memory root: MISSING from base map", label),
    }

    let log_dir = tempfile::Builder::new().prefix("diag_log_").tempdir().unwrap();
    let mnt = tempfile::Builder::new().prefix("diag_mnt_").tempdir().unwrap();
    let mut mount = common::TestMount::mount_custom(log_dir, mnt, fs, false);
    let path = mount.path().to_path_buf();

    match std::fs::metadata(&path) {
        Ok(m) => println!(
            "DIAG [{}] kernel sees:    mode={:o} uid={} gid={}",
            label,
            m.mode(),
            m.uid(),
            m.gid()
        ),
        Err(e) => println!("DIAG [{}] kernel stat failed: {:?}", label, e),
    }

    match std::fs::create_dir(path.join("diag_subdir")) {
        Ok(()) => println!("DIAG [{}] mkdir in root: OK", label),
        Err(e) => println!(
            "DIAG [{}] mkdir in root: {:?} errno={:?}",
            label,
            e.kind(),
            e.raw_os_error()
        ),
    }

    mount.unmount();
}

#[test]
fn diagnose_fuse_root_ownership() {
    println!(
        "DIAG process uid={} gid={} euid={} egid={}",
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() }
    );
    println!("DIAG TMPDIR={:?}", std::env::var("TMPDIR").ok());

    // The shape used by tests that PASS on CI.
    report("fresh", appendfs::InMemoryFS::new());

    // The shape used by all four tests that FAIL on CI: a pristine volume recovered from
    // the 000000.summary that init_volume just wrote.
    let dir = tempfile::Builder::new().prefix("diag_vol_").tempdir().unwrap();
    let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(OsStorage::new(dir.path()));
    appendfs::init_volume(
        storage.clone(),
        Some("main"),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
    )
    .unwrap();
    println!("DIAG volume files after init: {:?}", storage.list_files().unwrap());

    let recovered = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        VolumeKey::plaintext_arc(),
    )
    .unwrap();
    report("recovered", recovered);
}
