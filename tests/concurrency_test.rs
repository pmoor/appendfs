// Threaded concurrency stress test. Unlike tests/fuzz_test.rs (which is deliberately
// single-threaded and deterministic, comparing independent FS instances step-by-step),
// this test hammers a *single shared* InMemoryFS from multiple real OS threads at once,
// directly through the same `*_core` functions real FUSE dispatch uses. The goal isn't
// reproducibility of a specific interleaving - it's shaking out races and lock misuse
// across the `live` -> `flushing` -> `base` overlay, including against a flusher thread
// freezing and folding batches underneath the workers, which a single-threaded fuzz test
// structurally cannot exercise.
mod common;
use appendfs::InMemoryFS;
use appendfs::LogWriter;
use appendfs::clock::{Clock, SystemClock};
use appendfs::log::record::DecodedPayload;
use appendfs::log::{LogReader, SummaryReader, recover_fs};
use appendfs::node::{Node, NodeKind};
use appendfs::operations::dir::{list_dir_core, mkdir_core, opendir_core, releasedir_core, rmdir_core};
use appendfs::operations::links::{link_core, readlink_core, rename_core, symlink_core, unlink_core};
use appendfs::operations::locks::{flock_core, getlk_core, setlk_core};
use appendfs::operations::read_write::{
    FUSE_SET_ATTR_SIZE, create_core, getattr_core, open_core, read_core, release_core, setattr_core, write_core,
};
use appendfs::operations::xattr::{getxattr_core, listxattr_core, removexattr_core, setxattr_core};
use appendfs::shim::{FileType, ShimFlock};
use common::TestRng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UID: u32 = 1000;
const GID: u32 = 1000;
const NUM_THREADS: usize = 8;
fn ops_per_thread() -> usize {
    common::fuzz_steps(400)
}
const DIR_NAMES: [&str; 4] = ["d0", "d1", "d2", "d3"];
const FILE_NAMES: [&str; 4] = ["f0", "f1", "f2", "f3"];
const XATTR_NAMES: [&str; 3] = ["user.a", "user.b", "user.c"];

fn pick_entry(fs: &InMemoryFS, dir_ino: u64, rng: &mut TestRng) -> Option<(String, u64)> {
    match list_dir_core(fs, dir_ino) {
        Ok(entries) if !entries.is_empty() => {
            let idx = rng.gen_range(0, entries.len() - 1);
            Some(entries[idx].clone())
        }
        _ => None,
    }
}

// Picks a directory to operate on: usually one of the top-level shared dirs, but
// sometimes a subdirectory discovered inside one of them, so nesting (and therefore
// multi-hop ancestor walks during directory rename's loop-prevention check) emerges
// organically as threads race to create/rename/remove entries.
fn pick_target_dir(fs: &InMemoryFS, shared: &[u64], rng: &mut TestRng) -> u64 {
    let base = shared[rng.gen_range(0, shared.len() - 1)];
    if rng.gen_range(0, 1) == 0 {
        return base;
    }
    if let Ok(entries) = list_dir_core(fs, base) {
        let dirs: Vec<u64> = entries
            .iter()
            .filter_map(|(_, ino)| match getattr_core(fs, *ino) {
                Ok(a) if a.file_type == FileType::Directory => Some(*ino),
                _ => None,
            })
            .collect();
        if !dirs.is_empty() {
            return dirs[rng.gen_range(0, dirs.len() - 1)];
        }
    }
    base
}

fn worker(fs: Arc<InMemoryFS>, shared_dirs: Arc<Vec<u64>>, seed: u64) {
    let mut rng = TestRng::new(seed);
    for _ in 0..ops_per_thread() {
        let dir_a = pick_target_dir(&fs, &shared_dirs, &mut rng);
        let dir_b = pick_target_dir(&fs, &shared_dirs, &mut rng);
        // Upper bound must stay >= the highest explicit arm below, with room left over
        // for the catch-all rename arm (`_`) to still be reachable - arms 9-11 were
        // silently dead code until this bound was widened alongside the new xattr arm,
        // since `gen_range(0, 8)` never produced anything past 8.
        match rng.gen_range(0, 13) {
            0 => {
                let name = DIR_NAMES[rng.gen_range(0, DIR_NAMES.len() - 1)];
                let _ = mkdir_core(&fs, dir_a, name, 0o755, UID, GID);
            }
            1 => {
                let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                if let Ok(attr) = create_core(&fs, dir_a, name, 0o644, 0, UID, GID) {
                    let data = vec![b'x'; rng.gen_range(1, 64)];
                    let _ = write_core(&fs, attr.ino, &data, 0);
                }
            }
            2 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let data = vec![b'y'; rng.gen_range(1, 64)];
                    let offset = rng.gen_range(0, 128) as i64;
                    let _ = write_core(&fs, ino, &data, offset);
                }
            }
            3 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng)
                    && let Ok(fh) = open_core(&fs, ino, 0)
                {
                    let _ = read_core(&fs, ino, fh, 0, 64);
                    let _ = release_core(&fs, ino, fh);
                }
            }
            4 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let size = rng.gen_range(0, 32) as i64;
                    let now = SystemTime::now();
                    let _ = setattr_core(&fs, ino, 0, UID, GID, size, now, now, FUSE_SET_ATTR_SIZE);
                }
            }
            5 => {
                let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                let _ = symlink_core(&fs, dir_a, name, "sometarget", UID, GID);
            }
            6 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                    let _ = link_core(&fs, ino, dir_b, name);
                }
            }
            7 => {
                if let Some((name, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    match getattr_core(&fs, ino) {
                        Ok(attr) if attr.file_type == FileType::Directory => {
                            let _ = rmdir_core(&fs, dir_a, &name);
                        }
                        Ok(_) => {
                            let _ = unlink_core(&fs, dir_a, &name);
                        }
                        Err(_) => {}
                    }
                }
            }
            8 => {
                // Exercise opendir snapshotting & releasedir concurrently with active mutations
                if let Ok(fh) = opendir_core(&fs, dir_a, 0) {
                    let _ = fs.get_dir_handle(fh);
                    let _ = releasedir_core(&fs, dir_a, fh);
                }
            }
            9 => {
                // Exercise open handle allocation, read, and release concurrently
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng)
                    && let Ok(fh) = open_core(&fs, ino, 0)
                {
                    let _ = read_core(&fs, ino, fh, 0, 64);
                    let _ = release_core(&fs, ino, fh);
                }
            }
            10 => {
                // Exercise BSD flock whole-file locking concurrently
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng)
                    && let Ok(fh) = open_core(&fs, ino, 0)
                {
                    let op = match rng.gen_range(0, 3) {
                        0 => libc::LOCK_SH,
                        1 => libc::LOCK_EX,
                        2 => libc::LOCK_SH | libc::LOCK_NB,
                        _ => libc::LOCK_UN,
                    };
                    let _ = flock_core(&fs, ino, fh, seed, op);
                    let _ = release_core(&fs, ino, fh);
                }
            }
            11 => {
                // Exercise POSIX fcntl range locking concurrently
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng)
                    && let Ok(fh) = open_core(&fs, ino, 0)
                {
                    let lock_type = match rng.gen_range(0, 2) {
                        0 => libc::F_RDLCK as i16,
                        1 => libc::F_WRLCK as i16,
                        _ => libc::F_UNLCK as i16,
                    };
                    let start = rng.gen_range(0, 64) as i64;
                    let len = rng.gen_range(0, 64) as i64;
                    let lock = ShimFlock {
                        lock_type,
                        whence: libc::SEEK_SET as i16,
                        start,
                        len,
                        pid: (seed % 10000) as i32,
                    };
                    let _ = setlk_core(&fs, ino, fh, seed, lock, false);
                    let _ = getlk_core(&fs, ino, fh, seed, lock);
                    let _ = release_core(&fs, ino, fh);
                }
            }
            12 => {
                // Exercise xattr set/get/list/remove concurrently, on either a
                // directory or a file/symlink inside it - this fs doesn't restrict
                // xattrs by node type. Small fixed name pool so concurrent
                // set/replace/remove races over the same name happen naturally,
                // matching DIR_NAMES/FILE_NAMES above.
                let target = if rng.gen_range(0, 1) == 0 {
                    Some(dir_a)
                } else {
                    pick_entry(&fs, dir_a, &mut rng).map(|(_, ino)| ino)
                };
                if let Some(ino) = target {
                    let name = XATTR_NAMES[rng.gen_range(0, XATTR_NAMES.len() - 1)];
                    match rng.gen_range(0, 3) {
                        0 => {
                            let value = vec![b'z'; rng.gen_range(0, 32)];
                            let flags = match rng.gen_range(0, 2) {
                                0 => 0,
                                1 => libc::XATTR_CREATE,
                                _ => libc::XATTR_REPLACE,
                            };
                            let _ = setxattr_core(&fs, ino, name, &value, flags);
                        }
                        1 => {
                            let _ = removexattr_core(&fs, ino, name);
                        }
                        2 => {
                            let _ = getxattr_core(&fs, ino, name, 0);
                        }
                        _ => {
                            let _ = listxattr_core(&fs, ino, 0);
                        }
                    }
                }
            }
            _ => {
                if let Some((name, _)) = pick_entry(&fs, dir_a, &mut rng) {
                    let newname = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                    let _ = rename_core(&fs, dir_a, &name, dir_b, newname);
                }
            }
        }
    }
}

/// Dedicated lock worker hammering BSD flock and POSIX range locks across files
fn lock_worker(fs: Arc<InMemoryFS>, shared_dirs: Arc<Vec<u64>>, seed: u64) {
    let mut rng = TestRng::new(seed);
    for _ in 0..ops_per_thread() {
        let dir = pick_target_dir(&fs, &shared_dirs, &mut rng);
        if let Some((_, ino)) = pick_entry(&fs, dir, &mut rng)
            && let Ok(fh) = open_core(&fs, ino, 0)
        {
            // Perform multiple lock operations on the open handle
            let op = if rng.gen_range(0, 1) == 0 {
                libc::LOCK_SH
            } else {
                libc::LOCK_EX
            };
            let _ = flock_core(&fs, ino, fh, seed, op);

            let lock = ShimFlock {
                lock_type: libc::F_RDLCK as i16,
                whence: libc::SEEK_SET as i16,
                start: rng.gen_range(0, 128) as i64,
                len: rng.gen_range(0, 64) as i64,
                pid: (seed % 10000) as i32,
            };
            let _ = setlk_core(&fs, ino, fh, seed, lock, false);
            let _ = getlk_core(&fs, ino, fh, seed, lock);

            let _ = release_core(&fs, ino, fh);
        }
    }
}

// Walks the entire tree from root using only the same core handlers real FUSE dispatch
// uses (never touching `fs.inodes` directly beyond a final orphan-count check), and
// asserts filesystem-wide invariants that must hold once all threads have quiesced:
//   - every reachable entry resolves (no dangling directory entries)
//   - every directory has nlink == 2 (this FS doesn't do POSIX subdir-nlink accounting,
//     so this is the invariant that actually holds - see mkdir_core/rmdir_core)
//   - every directory is reachable from exactly one parent (directories can't be
//     hardlinked - link_core rejects them with EPERM)
//   - every file/symlink's reported nlink matches the number of directory entries in
//     the final tree that actually point at it
//   - no inode exists in `fs.inodes` that isn't reachable from root (no leaks, and no
//     cycles disconnected from root - a cycle's members would all show up here as
//     simultaneously present-but-unreachable)
fn preserve_storage_for_repro(storage: &dyn Storage, seed: u64) {
    let preserved = std::path::PathBuf::from(format!("/tmp/appendfs_repro_seed_{}", seed));
    let _ = std::fs::remove_dir_all(&preserved);
    let _ = std::fs::create_dir_all(&preserved);
    for filename in storage.list_files().unwrap_or_default() {
        if let Ok(bytes) = storage
            .open_reader(&filename)
            .and_then(|r| r.read_vec(0, r.len().unwrap_or(0) as usize))
        {
            let _ = std::fs::write(preserved.join(&filename), bytes);
        }
    }
    eprintln!("  preserved log dir at {:?}", preserved);
}

// Passive diagnostic used only from a failure branch: scans every `.log` file in
// `storage` in generation order and prints every record touching `ino`, either as the
// record header's primary inode or (for Rename/Link) as a parent/dest reference, so a
// divergence at `ino` can be traced back to exactly which ops the log ever saw for it.
fn dump_log_records_for_inode(storage: &dyn Storage, ino: u64) {
    let mut log_files: Vec<String> = storage
        .list_files()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.ends_with(".log"))
        .collect();
    log_files.sort();
    for filename in log_files {
        let reader = match LogReader::open(storage, &filename, appendfs::VolumeKey::plaintext_arc()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("    (failed to open {:?}: {})", filename, e);
                continue;
            }
        };
        for rec in reader {
            let rec = match rec {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("    (read error in {:?}: {})", filename, e);
                    continue;
                }
            };
            let decoded = rec.decode().ok();
            let mentions = rec.header.inode == ino
                || match &decoded {
                    Some(DecodedPayload::InodeDelta(appendfs::log::LogEntryDelta::Node(
                        appendfs::log::LogNodeDelta::Directory(d),
                    ))) => d.added.iter().any(|(_, target_ino)| *target_ino == ino),
                    _ => false,
                };
            if mentions {
                eprintln!(
                    "    {:?} tx={} inode={} offset={} payload={:?}",
                    rec.header.op_code, rec.header.tx_id, rec.header.inode, rec.record_log_offset, decoded
                );
            }
        }
    }
}

// Traverses the live tree from root using only the public `*_core` query functions real VFS
// uses (never touching `fs.inodes` directly beyond a final orphan-count check), and
// asserts filesystem-wide invariants that must hold once all threads have quiesced:
//   - every reachable entry resolves (no dangling directory entries)
//   - every directory has nlink == 2 (this FS doesn't do POSIX subdir-nlink accounting,
//     so this is the invariant that actually holds - see mkdir_core/rmdir_core)
//   - every directory is reachable from exactly one parent (directories can't be
//     hardlinked - link_core rejects them with EPERM)
//   - every file/symlink's reported nlink matches the number of directory entries in
//     the final tree that actually point at it
//   - no inode exists in `fs.inodes` that isn't reachable from root (no leaks, and no
//     cycles disconnected from root - a cycle's members would all show up here as
//     simultaneously present-but-unreachable)
fn verify_tree_invariants(fs: &InMemoryFS, storage: &dyn Storage, seed: u64) {
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    visited.insert(1);
    queue.push_back(1);
    let mut link_counts: HashMap<u64, u32> = HashMap::new();

    while let Some(ino) = queue.pop_front() {
        let attr = getattr_core(fs, ino).unwrap_or_else(|e| panic!("getattr({}) failed: {}", ino, e));
        match attr.file_type {
            FileType::Directory => {
                let mut entries = list_dir_core(fs, ino).unwrap_or_else(|e| panic!("list_dir({}) failed: {}", ino, e));
                entries.retain(|(_, child_ino)| !fs.is_virtual_ino(*child_ino));
                let mut child_subdirs = 0;
                for (name, child_ino) in entries {
                    let child_attr = match getattr_core(fs, child_ino) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!(
                                "dangling entry {:?} -> inode {} in dir {}: getattr failed: {}",
                                name, child_ino, ino, e
                            );
                            dump_log_records_for_inode(storage, child_ino);
                            dump_log_records_for_inode(storage, ino);
                            preserve_storage_for_repro(storage, seed);
                            panic!(
                                "dangling entry {:?} -> inode {} in dir {}: getattr failed: {}",
                                name, child_ino, ino, e
                            );
                        }
                    };
                    if child_attr.file_type == FileType::Directory {
                        child_subdirs += 1;
                        assert!(
                            visited.insert(child_ino),
                            "directory inode {} reachable from more than one parent \
                             (topology corruption - directories cannot be hardlinked)",
                            child_ino
                        );
                        queue.push_back(child_ino);
                    } else {
                        *link_counts.entry(child_ino).or_insert(0) += 1;
                        visited.insert(child_ino);
                    }
                }
                assert_eq!(
                    attr.nlink,
                    2 + child_subdirs,
                    "directory inode {} has unexpected nlink {} (expected {})",
                    ino,
                    attr.nlink,
                    2 + child_subdirs
                );
            }
            FileType::Symlink => {
                readlink_core(fs, ino).unwrap_or_else(|e| panic!("readlink({}) failed: {}", ino, e));
            }
            FileType::RegularFile
            | FileType::NamedPipe
            | FileType::CharDevice
            | FileType::BlockDevice
            | FileType::Socket => {}
        }
    }

    for (ino, count) in &link_counts {
        let attr = getattr_core(fs, *ino).unwrap();
        if attr.nlink != *count {
            eprintln!(
                "nlink mismatch (seed {}) at inode {}: attr={:?} counted_entries={}",
                seed, ino, attr, count
            );
            dump_log_records_for_inode(storage, *ino);
            preserve_storage_for_repro(storage, seed);
        }
        assert_eq!(
            attr.nlink, *count,
            "inode {} nlink mismatch: attr reports {}, but {} directory entries point at it",
            ino, attr.nlink, count
        );
    }

    let snapshot = fs.snapshot_all();
    let total_inodes = snapshot.len();
    if visited.len() != total_inodes {
        let mut orphans: Vec<u64> = snapshot.keys().copied().filter(|k| !visited.contains(k)).collect();
        orphans.sort_unstable();
        eprintln!("orphaned/unreachable inodes: {:?}", orphans);
        for ino in &orphans {
            eprintln!("  node {}: {:?}", ino, snapshot.get(ino).map(|n| &**n));
            // Scan every directory's raw entries (not just what BFS reached) for any
            // dangling reference to this inode, to tell "nobody points at it" (a true
            // leak) apart from "something points at it but the tree walk never got
            // there" (a reachability bug elsewhere, e.g. a directory wrongly treated as
            // hardlinked so its subtree was skipped).
            let mut referrers = Vec::new();
            for (parent_ino, node) in &snapshot {
                if let NodeKind::Directory { entries, .. } = &node.kind {
                    for (name, child) in entries {
                        if child == ino {
                            referrers.push((*parent_ino, name.clone()));
                        }
                    }
                }
            }
            eprintln!("  referenced by: {:?}", referrers);
            dump_log_records_for_inode(storage, *ino);
        }
        preserve_storage_for_repro(storage, seed);
    }
    assert_eq!(
        visited.len(),
        total_inodes,
        "orphaned or leaked inodes: {} reachable from root, but fs.snapshot_all() holds {}",
        visited.len(),
        total_inodes
    );
}

// Root (inode 1) is created implicitly at `InMemoryFS` construction, never through a
// log record, so nothing in replay ever touches its timestamps - when recovering
// without a `.summary` file (as this test forces, to exercise a full log replay),
// `recovery.rs` approximates root's atime/mtime/ctime from the oldest log file's
// header, which only carries second precision (see the comment at
// `recover_fs_with_clock`'s call to `InMemoryFS::with_clock`). A real `SystemClock`
// live timestamp almost never lands on an exact second, so root's timestamps are
// expected to differ between live and replay - a known, pre-existing, and
// already-documented lossy-recovery approximation, unrelated to what this comparison
// is actually checking (whether concurrent directory-structure mutations replay in
// the same order they committed live). Every other inode is fully log-derived and
// compared exactly.
fn normalize_for_compare(ino: u64, mut node: Node) -> Node {
    if ino == 1 && node.is_dir() {
        node.meta.atime = UNIX_EPOCH;
        node.meta.mtime = UNIX_EPOCH;
        node.meta.ctime = UNIX_EPOCH;
    }
    node
}

use appendfs::storage::{MemoryStorage, OsStorage, Storage};

// After the concurrent stress run, replaying the log from scratch must reproduce
// byte-for-byte the same filesystem state that's live in memory. This is the property
// `InMemoryFS::dir_lock` exists to guarantee: every directory-structure mutation
// stages its log record while still holding that lock, so the log's record order
// always matches the order those mutations actually landed in memory - no concurrent
// interleaving between threads can produce a live state the log can't reconstruct.
// Mirrors tests/fuzz_test.rs's test_summary_export_is_deterministic, but against this
// test's genuinely concurrent log instead of a single-threaded one.
fn verify_log_replay_matches_live(fs: &InMemoryFS, storage: Arc<dyn Storage>, seed: u64) {
    let _generation = fs.log_writer.as_ref().unwrap().generation();
    let written_file = fs
        .export_summary(storage.as_ref())
        .unwrap_or_else(|e| panic!("export_summary failed on the live instance (seed {}): {}", seed, e));

    // Reprocess: copy only the raw .log files into a fresh in-memory storage (excluding the
    // .summary file just written), so recover_fs has no fast-path available and is
    // forced to fully replay from generation 1.
    let replay_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    for filename in storage.list_files().unwrap() {
        if filename.ends_with(".log") {
            let reader = storage.open_reader(&filename).unwrap();
            let len = reader.len().unwrap() as usize;
            let buf = reader.read_vec(0, len).unwrap();
            let mut writer = replay_storage
                .open_writer(&filename, appendfs::storage::WriteMode::CreateNew)
                .unwrap();
            writer.append(&buf).unwrap();
            writer.sync().unwrap();
        }
    }
    let mut replayed = recover_fs(
        replay_storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap_or_else(|e| panic!("recover_fs failed on replay (seed {}): {}", seed, e));
    replayed.track_atime = false;
    let regenerated_file = replayed
        .export_summary(replay_storage.as_ref())
        .unwrap_or_else(|e| panic!("export_summary failed on the replayed instance (seed {}): {}", seed, e));

    // Compare tree *content* (the inode map), not raw summary bytes - `next_inode` can
    // legitimately differ between the two: a failed create/mkdir/symlink (EEXIST,
    // common here since names are drawn from a small shared pool) still burns an inode
    // number live (`fs.allocate_inode()` runs unconditionally, before the name check),
    // but a failed call never stages a log record - so recovery, which derives
    // next_inode from the highest inode number that actually appears in some logged
    // record, has no way to see that gap. That never corrupts anything (the skipped
    // number was never live-assigned to any real node, so reusing it post-recovery
    // can't collide with one); it's excluded here deliberately, not overlooked.
    let written_reader =
        SummaryReader::open(storage.as_ref(), &written_file, appendfs::VolumeKey::plaintext_arc()).unwrap();
    let regenerated_reader = SummaryReader::open(
        replay_storage.as_ref(),
        &regenerated_file,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let written_inodes = written_reader.read_all_inodes().unwrap();
    let regenerated_inodes = regenerated_reader.read_all_inodes().unwrap();

    let mut written_keys: Vec<u64> = written_inodes.keys().copied().collect();
    let mut regenerated_keys: Vec<u64> = regenerated_inodes.keys().copied().collect();
    written_keys.sort_unstable();
    regenerated_keys.sort_unstable();
    if written_keys != regenerated_keys {
        let written_set: HashSet<u64> = written_keys.iter().copied().collect();
        let regenerated_set: HashSet<u64> = regenerated_keys.iter().copied().collect();
        let missing_from_replay: Vec<u64> = written_set.difference(&regenerated_set).copied().collect();
        let extra_in_replay: Vec<u64> = regenerated_set.difference(&written_set).copied().collect();
        eprintln!(
            "inode-set divergence (seed {}): missing_from_replay={:?} extra_in_replay={:?}",
            seed, missing_from_replay, extra_in_replay
        );
        for ino in missing_from_replay.iter().chain(extra_in_replay.iter()) {
            if let Some(node) = written_inodes.get(ino) {
                eprintln!("  live node {}: {:?}", ino, node);
            } else {
                eprintln!("  live node {}: <absent>", ino);
            }
            if let Some(node) = regenerated_inodes.get(ino) {
                eprintln!("  replayed node {}: {:?}", ino, node);
            } else {
                eprintln!("  replayed node {}: <absent>", ino);
            }
            dump_log_records_for_inode(storage.as_ref(), *ino);
        }
        preserve_storage_for_repro(storage.as_ref(), seed);
    }
    assert_eq!(
        written_keys, regenerated_keys,
        "log replay does not reproduce the live filesystem's inode set for seed {}",
        seed
    );

    for ino in written_keys {
        let live_node = (*written_inodes[&ino]).clone();
        let replayed_node = (*regenerated_inodes[&ino]).clone();
        let live_bytes = appendfs::wire::serialize(&normalize_for_compare(ino, live_node.clone())).unwrap();
        let replayed_bytes = appendfs::wire::serialize(&normalize_for_compare(ino, replayed_node.clone())).unwrap();
        if live_bytes != replayed_bytes {
            eprintln!("content divergence (seed {}) at inode {}:", seed, ino);
            eprintln!("  live:     {:?}", live_node);
            eprintln!("  replayed: {:?}", replayed_node);
            dump_log_records_for_inode(storage.as_ref(), ino);
            preserve_storage_for_repro(storage.as_ref(), seed);
        }
        assert_eq!(
            live_bytes, replayed_bytes,
            "log replay diverges from the live filesystem state at inode {} for seed {} \
             - the log's record order (or its replay semantics) diverged from what \
             actually landed in memory",
            ino, seed
        );
    }
}

// Not run by CI; invoke manually against a dir preserved by the inode-set-divergence
// diagnostic above (`/tmp/appendfs_repro_seed_<N>`) to inspect every record in log order.
#[test]
#[ignore]
fn dump_preserved_repro() {
    let dir = std::env::var("APPENDFS_REPRO_DIR").unwrap_or_else(|_| "/tmp/appendfs_repro_seed_28".to_string());
    let mut log_files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("log"))
        .collect();
    log_files.sort();
    for path in log_files {
        eprintln!("--- {:?} ---", path);
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let storage = OsStorage::new(parent);
        let reader = LogReader::open(&storage, filename, appendfs::VolumeKey::plaintext_arc()).unwrap();
        for rec in reader {
            let rec = rec.unwrap();
            let decoded = rec.decode().ok();
            eprintln!(
                "{:?} tx={} inode={} offset={} payload={:?}",
                rec.header.op_code, rec.header.tx_id, rec.header.inode, rec.record_log_offset, decoded
            );
        }
    }
}

fn run_concurrent_stress(seed: u64) {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let mut fs = InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs.set_storage(storage.clone());
    // Reads bump atime in memory but are never logged (logging every read would defeat
    // the point of an append-only log), so with atime tracking on, a live instance and
    // its log replay would legitimately differ on atime alone - disabling it here keeps
    // every field log-derived, which is what the replay comparison below needs.
    fs.track_atime = false;
    let fs = Arc::new(fs);

    let mut shared_dirs = Vec::new();
    for i in 0..4 {
        let attr = mkdir_core(&fs, 1, &format!("shared{}", i), 0o755, UID, GID).expect("setup mkdir failed");
        shared_dirs.push(attr.ino);
    }
    let shared_dirs = Arc::new(shared_dirs);

    let mut handles: Vec<_> = (0..NUM_THREADS)
        .map(|i| {
            let fs = Arc::clone(&fs);
            let shared_dirs = Arc::clone(&shared_dirs);
            let thread_seed = seed.wrapping_mul(1_000_003).wrapping_add(i as u64 + 1);
            thread::spawn(move || worker(fs, shared_dirs, thread_seed))
        })
        .collect();

    // Spawn 2 dedicated lock workers hammering flock and range locks
    for i in 0..2 {
        let fs = Arc::clone(&fs);
        let shared_dirs = Arc::clone(&shared_dirs);
        let thread_seed = seed.wrapping_mul(2_000_033).wrapping_add(i as u64 + 100);
        handles.push(thread::spawn(move || lock_worker(fs, shared_dirs, thread_seed)));
    }

    // Flush continuously while the workers mutate. Without this the whole run stays in
    // `live` and is written out by a single quiescent flush at the end, so the pipeline
    // that actually carries risk - freezing `live` into the queue, writing a batch, and
    // folding it into `base`, all while other threads are mutating and reading across
    // those same layers - never runs concurrently with anything.
    let stop_flusher = Arc::new(AtomicBool::new(false));
    let flush_count = Arc::new(AtomicU64::new(0));
    let flusher = {
        let fs = Arc::clone(&fs);
        let stop = Arc::clone(&stop_flusher);
        let count = Arc::clone(&flush_count);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                fs.flush_log()
                    .unwrap_or_else(|e| panic!("concurrent flush failed: {}", e));
                count.fetch_add(1, Ordering::Relaxed);
                thread::sleep(Duration::from_micros(100));
            }
        })
    };

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|_| panic!("worker thread {} panicked (seed {})", i, seed));
    }

    // Wait for the flusher to actually complete several passes before stopping it, rather
    // than stopping immediately and then asserting it happened to have been scheduled more
    // than once. On a busy two-core CI runner the workers can finish while the flusher is
    // still inside its first `flush_log`, which made this assertion fail on scheduling luck
    // rather than on anything the test is trying to catch.
    const MIN_FLUSHES: u64 = 2;
    let deadline = Instant::now() + Duration::from_secs(60);
    while flush_count.load(Ordering::Relaxed) < MIN_FLUSHES && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }

    stop_flusher.store(true, Ordering::Relaxed);
    flusher
        .join()
        .unwrap_or_else(|_| panic!("flusher thread panicked (seed {})", seed));

    // Still a real guard: it now fails only if the flusher genuinely cannot make progress,
    // not if it merely lost a scheduling race.
    let flushes = flush_count.load(Ordering::Relaxed);
    assert!(
        flushes >= MIN_FLUSHES,
        "flusher completed only {} pass(es) in 60s (seed {}); the run was effectively single-batch",
        flushes,
        seed
    );

    verify_tree_invariants(&fs, storage.as_ref(), seed);
    verify_log_replay_matches_live(&fs, storage.clone(), seed);

    assert!(
        fs.dir_handles.read().unwrap().is_empty(),
        "seed {}: leaked dir handles",
        seed
    );
    assert!(
        fs.file_handles.read().unwrap().is_empty(),
        "seed {}: leaked file handles",
        seed
    );
    assert!(
        fs.flock_table.lock().unwrap().is_empty(),
        "seed {}: leaked flock entries",
        seed
    );
    assert!(
        fs.range_lock_table.lock().unwrap().is_empty(),
        "seed {}: leaked range lock entries",
        seed
    );
    assert!(
        fs.open_counts.read().unwrap().is_empty(),
        "seed {}: leaked open_counts",
        seed
    );
}

#[test]
fn test_concurrent_stress() {
    // Default 5 seeds for fast CI/local runs; override with FUZZ_SEEDS=<n> for stress sweeps.
    let seeds = common::fuzz_seeds(5);
    for seed in 1..=seeds {
        run_concurrent_stress(seed);
    }
}
