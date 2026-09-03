//! A fresh volume's root directory must belong to whoever created it.
//!
//! `init_volume` used to stamp the root as uid/gid 1000 unconditionally. Because the FUSE
//! shim always passes `-odefault_permissions`, the kernel enforces that recorded owner
//! against the caller - so on any machine whose user is not uid 1000, `appendfs init`
//! followed by `appendfs mount` produced a volume that mounted successfully and then
//! refused every write to its own root with EACCES. It went unnoticed because the first
//! user on a typical Linux install, and every developer who had run this, is uid 1000.

use appendfs::crypto::{VolumeHeader, VolumeKey};
use appendfs::storage::OsStorage;
use std::sync::Arc;

fn recovered_root_owner(dir: &std::path::Path) -> (u32, u32) {
    let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(OsStorage::new(dir));
    appendfs::init_volume(
        storage.clone(),
        Some("main"),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
    )
    .unwrap();

    let fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        VolumeKey::plaintext_arc(),
    )
    .unwrap();

    let base = fs.base.read().unwrap();
    let root = base.get(&1).expect("root inode must survive recovery");
    (root.meta.uid, root.meta.gid)
}

#[test]
fn test_fresh_volume_root_is_owned_by_the_invoking_user() {
    let dir = tempfile::tempdir().unwrap();
    let (uid, gid) = recovered_root_owner(dir.path());

    let expected_uid = unsafe { libc::getuid() };
    let expected_gid = unsafe { libc::getgid() };

    assert_eq!(
        uid, expected_uid,
        "root directory is owned by uid {} but this process runs as uid {}; the volume would \
         mount and then refuse every write to its own root",
        uid, expected_uid
    );
    assert_eq!(gid, expected_gid, "root gid must track the invoking user too");
}

/// Covers the escape hatch rather than the bug: the explicit-owner entry point must
/// actually reach the stored root, since the compat fixture generator depends on pinning it.
///
/// Note what this does *not* do. The test above only fails on a machine whose uid is not
/// 1000, and that is unavoidable - a hardcoded 1000 is indistinguishable from a correct
/// `getuid()` when you are uid 1000, which is precisely why the bug survived. CI runs as
/// uid 1001 and is what makes that assertion bite.
#[test]
fn test_root_owner_is_not_a_hardcoded_constant() {
    let dir_a = tempfile::tempdir().unwrap();
    let (uid, _) = recovered_root_owner(dir_a.path());

    // Generating with an explicit owner must produce a different one, proving the value is
    // plumbed through rather than baked in.
    let dir_b = tempfile::tempdir().unwrap();
    let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(OsStorage::new(dir_b.path()));
    let pinned_uid = uid.wrapping_add(7);
    let pinned_gid = uid.wrapping_add(9);
    appendfs::log::init_volume_with_clock_and_uids(
        storage.clone(),
        Some("main"),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        Arc::new(appendfs::SystemClock),
        pinned_uid,
        pinned_gid,
    )
    .unwrap();

    let fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let base = fs.base.read().unwrap();
    let root = base.get(&1).unwrap();

    assert_eq!(root.meta.uid, pinned_uid, "explicit owner must reach the stored root");
    assert_eq!(root.meta.gid, pinned_gid);
    assert_ne!(
        root.meta.uid, uid,
        "the two volumes must differ, otherwise the owner is not actually plumbed through"
    );
}
