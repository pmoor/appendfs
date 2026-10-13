mod common;
use appendfs::clock::{AdvancingClock, Clock, MockClock, SystemClock};
use appendfs::log::{LogAttrDelta, LogDirectoryDelta, LogEntryDelta, LogFileDelta, LogNodeDelta, OpCode, recover_fs};
use appendfs::node::NodeKind;
use appendfs::storage::{MemoryStorage, Storage};
use appendfs::test_utils::AttrChanges;
use appendfs::{FsTestExt, SnapshotNode, TestFs};
use appendfs::{LogWriter, RemoteStore};
use common::TestRng;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_differential_fuzzing_and_crash_recovery() {
    let seeds = common::fuzz_seeds(5);
    let steps = common::fuzz_steps(200);
    for seed in 1..=seeds {
        println!("=== RUNNING DIFFERENTIAL STRESS TEST WITH SEED {} ===", seed);
        let mut prng = TestRng::new(seed);

        // Shared, advanceable clock: all 4 instances (and, per clean_remount/
        // unclean_crash, their post-recovery selves) observe the exact same
        // simulated time, advanced once per step below - unlike a real wall clock,
        // this makes atime/mtime/ctime comparisons across instances exact rather
        // than flaky, so they can be checked at every checkpoint alongside content.
        let clock = AdvancingClock::new(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let fs_baseline = TestFs::builder().clock(Arc::new(clock.clone())).build();
        let mut fs_micro = TestFs::builder()
            .clock(Arc::new(clock.clone()))
            .max_log_size(256)
            .build();
        let mut fs_remount = TestFs::builder().clock(Arc::new(clock.clone())).build();
        // The crash instance routes its log through a FaultStorage, so each checkpoint can
        // force a mid-flush I/O failure before crashing. Every durability bug found so far
        // (the permanent wedge, mid-batch torn records, the unbounded flush queue) lived in
        // that seam and was invisible to a fuzzer that only ever saw a healthy disk.
        let mut fs_crash = TestFs::builder()
            .clock(Arc::new(clock.clone()))
            .fault_injection()
            .build();
        // The remote instance is backed by N=3 in-memory remotes with latency injection,
        // fault injection, aggressive local log pruning (local_retention = "0s"), and
        // spontaneous file deletion with single-survivor invariants.
        let mut fs_remote = TestFs::builder()
            .clock(Arc::new(clock.clone()))
            .max_log_size(256)
            .remotes(3)
            .build();

        // Split data records aggressively on every instance except the baseline, so extent
        // chunking is itself under differential test: the same content must come back no
        // matter how many records it was written as, and coalesced runs must be reassembled
        // at the right offsets. The sizes are small, odd and mutually unequal - writes below
        // are 16..256 bytes, so these split most of them, at varying boundaries. The
        // baseline keeps the default cap and so stays effectively unchunked.
        fs_micro.set_max_extent_size(37 + (seed as usize % 23));
        fs_remount.set_max_extent_size(64);
        fs_crash.set_max_extent_size(101);
        fs_remote.set_max_extent_size(83);

        let mut observed_flush_failures = 0usize;

        // Keep track of created subdirectories (inode IDs) to perform operations on
        let mut active_dirs = vec![1u64];
        let mut active_files = Vec::<u64>::new();

        struct FuzzDirHandle {
            ino: u64,
            fh1: u64,
            fh2: u64,
            fh3: u64,
            fh4: u64,
            fh5: u64,
            expected_snapshot: Vec<(String, u64)>,
        }

        struct FuzzFileHandle {
            ino: u64,
            fh1: u64,
            fh2: u64,
            fh3: u64,
            fh4: u64,
            fh5: u64,
        }

        let mut open_dir_handles: Vec<FuzzDirHandle> = Vec::new();
        let mut open_file_handles: Vec<FuzzFileHandle> = Vec::new();

        // Crash/remount checkpoints land at random steps rather than a fixed cadence,
        // so recovery gets exercised against varied in-flight-batch states (whatever
        // happened to be staged/flushed at that particular random moment) instead of
        // always the same handful of points every run. Drawn up front, before the step
        // loop's own op selection, so the two random streams don't interleave in a way
        // that's confusing to reason about. Step is always included at the end so the final
        // state is guaranteed to get validated even if no random draw lands there.
        let num_random_checkpoints = 3;
        let max_cp = steps.saturating_sub(1).max(1);
        let mut checkpoints: Vec<usize> = (0..num_random_checkpoints).map(|_| prng.gen_range(1, max_cp)).collect();
        checkpoints.push(steps);
        checkpoints.sort_unstable();
        checkpoints.dedup();
        println!("    checkpoints for seed {}: {:?}", seed, checkpoints);

        for step in 1..=steps {
            clock.advance(Duration::from_secs(1));
            let op_choice = prng.gen_range(0, 17);
            match op_choice {
                0 => {
                    // Create directory
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("dir_s{}_step{}", seed, step);
                    let res1 = fs_baseline.fs.make_dir(parent, &name, 0o755);
                    let res2 = fs_micro.fs.make_dir(parent, &name, 0o755);
                    let res3 = fs_remount.fs.make_dir(parent, &name, 0o755);
                    let res4 = fs_crash.fs.make_dir(parent, &name, 0o755);
                    let res5 = fs_remote.fs.make_dir(parent, &name, 0o755);

                    assert_eq!(res1, res2);
                    assert_eq!(res1, res3);
                    assert_eq!(res1, res4);
                    assert_eq!(res1, res5);

                    if let Ok(ino) = res1 {
                        active_dirs.push(ino);
                    }
                }
                1 => {
                    // Create file
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("file_s{}_step{}.txt", seed, step);
                    let res1 = fs_baseline.fs.create_file(parent, &name, 0o644);
                    let res2 = fs_micro.fs.create_file(parent, &name, 0o644);
                    let res3 = fs_remount.fs.create_file(parent, &name, 0o644);
                    let res4 = fs_crash.fs.create_file(parent, &name, 0o644);
                    let res5 = fs_remote.fs.create_file(parent, &name, 0o644);

                    assert_eq!(res1, res2);
                    assert_eq!(res1, res3);
                    assert_eq!(res1, res4);
                    assert_eq!(res1, res5);

                    if let Ok(ino) = res1 {
                        active_files.push(ino);
                    }
                }
                2 => {
                    // Write to file
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let offset = (prng.gen_range(0, 10) * 16) as u64;
                        let payload_len = prng.gen_range(16, 256);
                        let payload: Vec<u8> = (0..payload_len).map(|i| ((step + i) % 256) as u8).collect();

                        let res1 = fs_baseline.fs.write_at(ino, &payload, offset as i64);
                        let res2 = fs_micro.fs.write_at(ino, &payload, offset as i64);
                        let res3 = fs_remount.fs.write_at(ino, &payload, offset as i64);
                        let res4 = fs_crash.fs.write_at(ino, &payload, offset as i64);
                        let res5 = fs_remote.fs.write_at(ino, &payload, offset as i64);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);
                    }
                }
                3 => {
                    // Unlink file
                    if !active_files.is_empty() && prng.gen_range(0, 3) == 0 {
                        let idx = prng.gen_range(0, active_files.len() - 1);
                        let ino = active_files[idx];
                        // Unlink requires parent & name. Find name in root/dirs.
                        let (parent_to_unlink, name_to_unlink) = {
                            if let Some(p) = appendfs::fs::find_parent_inode(&fs_baseline.fs, ino) {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                let name = entries.into_iter().find(|(_, child)| *child == ino).map(|(n, _)| n);
                                (p, name)
                            } else {
                                (1u64, None)
                            }
                        };

                        if let Some(name) = name_to_unlink {
                            let res1 = fs_baseline.fs.remove_file(parent_to_unlink, &name);
                            let res2 = fs_micro.fs.remove_file(parent_to_unlink, &name);
                            let res3 = fs_remount.fs.remove_file(parent_to_unlink, &name);
                            let res4 = fs_crash.fs.remove_file(parent_to_unlink, &name);
                            let res5 = fs_remote.fs.remove_file(parent_to_unlink, &name);

                            assert_eq!(res1, res2);
                            assert_eq!(res1, res3);
                            assert_eq!(res1, res4);
                            assert_eq!(res1, res5);

                            if res1.is_ok() {
                                let still_alive = fs_baseline.fs.get_attr(ino).is_some();
                                if !still_alive {
                                    active_files.remove(idx);
                                }
                            }
                        }
                    }
                }
                4 => {
                    // Rename: move or overwrite between existing active files/dirs (excluding root).
                    // Biased towards colliding with an existing destination name so the
                    // overwrite-and-reclaim path (which crash recovery is known to replay
                    // incorrectly) gets exercised, not just plain moves.
                    let mut renameable: Vec<u64> = active_dirs.iter().cloned().filter(|&i| i != 1).collect();
                    renameable.extend(active_files.iter().cloned());

                    if !renameable.is_empty() {
                        let src_ino = renameable[prng.gen_range(0, renameable.len() - 1)];

                        let src_loc = {
                            if let Some(p) = appendfs::fs::find_parent_inode(&fs_baseline.fs, src_ino) {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                entries
                                    .into_iter()
                                    .find(|(_, child)| *child == src_ino)
                                    .map(|(n, _)| (p, n))
                            } else {
                                None
                            }
                        };

                        if let Some((src_parent, src_name)) = src_loc {
                            let dest_parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];

                            // Pick an existing entry in dest_parent to collide with. When
                            // dest_parent == src_parent and this picks the source's own entry,
                            // that exercises the literal self-rename (name == newname) no-op path.
                            let existing_name = {
                                let entries = fs_baseline.fs.list_directory(dest_parent).unwrap_or_default();
                                if entries.is_empty() {
                                    None
                                } else {
                                    let idx = prng.gen_range(0, entries.len() - 1);
                                    Some(entries[idx].0.clone())
                                }
                            };

                            let dest_name = if prng.gen_range(0, 1) == 0 {
                                existing_name.unwrap_or_else(|| format!("renamed_s{}_step{}", seed, step))
                            } else {
                                format!("renamed_s{}_step{}", seed, step)
                            };

                            let res1 = fs_baseline
                                .fs
                                .rename_entry(src_parent, &src_name, dest_parent, &dest_name);
                            let res2 = fs_micro.fs.rename_entry(src_parent, &src_name, dest_parent, &dest_name);
                            let res3 = fs_remount
                                .fs
                                .rename_entry(src_parent, &src_name, dest_parent, &dest_name);
                            let res4 = fs_crash.fs.rename_entry(src_parent, &src_name, dest_parent, &dest_name);
                            let res5 = fs_remote
                                .fs
                                .rename_entry(src_parent, &src_name, dest_parent, &dest_name);

                            assert_eq!(res1, res2, "rename result mismatch (baseline vs micro)");
                            assert_eq!(res1, res3, "rename result mismatch (baseline vs remount)");
                            assert_eq!(res1, res4, "rename result mismatch (baseline vs crash)");
                            assert_eq!(res1, res5, "rename result mismatch (baseline vs remote)");
                        }
                    }
                }
                5 => {
                    // Rmdir: pick a random non-root directory; ENOTEMPTY is a valid,
                    // consistently-reproduced outcome, not a skip condition.
                    let candidates: Vec<u64> = active_dirs.iter().cloned().filter(|&i| i != 1).collect();
                    if !candidates.is_empty() {
                        let idx = prng.gen_range(0, candidates.len() - 1);
                        let ino = candidates[idx];

                        let loc = {
                            if let Some(p) = appendfs::fs::find_parent_inode(&fs_baseline.fs, ino) {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                entries
                                    .into_iter()
                                    .find(|(_, child)| *child == ino)
                                    .map(|(n, _)| (p, n))
                            } else {
                                None
                            }
                        };

                        if let Some((parent, name)) = loc {
                            let res1 = fs_baseline.fs.remove_dir(parent, &name);
                            let res2 = fs_micro.fs.remove_dir(parent, &name);
                            let res3 = fs_remount.fs.remove_dir(parent, &name);
                            let res4 = fs_crash.fs.remove_dir(parent, &name);
                            let res5 = fs_remote.fs.remove_dir(parent, &name);

                            assert_eq!(res1, res2, "rmdir result mismatch (baseline vs micro)");
                            assert_eq!(res1, res3, "rmdir result mismatch (baseline vs remount)");
                            assert_eq!(res1, res4, "rmdir result mismatch (baseline vs crash)");
                            assert_eq!(res1, res5, "rmdir result mismatch (baseline vs remote)");

                            if res1.is_ok() {
                                active_dirs.retain(|&i| i != ino);
                            }
                        }
                    }
                }
                6 => {
                    // Symlink
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("symlink_s{}_step{}", seed, step);
                    let target = format!("target_s{}_step{}", seed, step);

                    let res1 = fs_baseline.fs.make_symlink(parent, &name, &target);
                    let res2 = fs_micro.fs.make_symlink(parent, &name, &target);
                    let res3 = fs_remount.fs.make_symlink(parent, &name, &target);
                    let res4 = fs_crash.fs.make_symlink(parent, &name, &target);
                    let res5 = fs_remote.fs.make_symlink(parent, &name, &target);

                    assert_eq!(res1, res2, "symlink result mismatch (baseline vs micro)");
                    assert_eq!(res1, res3, "symlink result mismatch (baseline vs remount)");
                    assert_eq!(res1, res4, "symlink result mismatch (baseline vs crash)");
                    assert_eq!(res1, res5, "symlink result mismatch (baseline vs remote)");

                    if let Ok(ino) = res1 {
                        active_files.push(ino);
                    }
                }
                7 => {
                    // Link: add a second name for an existing file/symlink.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let newparent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                        let newname = format!("hardlink_s{}_step{}", seed, step);

                        let res1 = fs_baseline.fs.hard_link(ino, newparent, &newname);
                        let res2 = fs_micro.fs.hard_link(ino, newparent, &newname);
                        let res3 = fs_remount.fs.hard_link(ino, newparent, &newname);
                        let res4 = fs_crash.fs.hard_link(ino, newparent, &newname);
                        let res5 = fs_remote.fs.hard_link(ino, newparent, &newname);

                        assert_eq!(res1, res2, "link result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "link result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "link result mismatch (baseline vs crash)");
                        assert_eq!(res1, res5, "link result mismatch (baseline vs remote)");
                    }
                }
                8 => {
                    // Setattr: mode/uid/gid/size in a random combination, matching
                    // real usage (a single call can set any subset). Size exercises
                    // both shrink and grow, including growing back past a size that
                    // was previously shrunk away. atime/mtime deliberately excluded
                    // here - exact-timestamp comparison across 4 independently-timed
                    // instances using a real wall clock is inherently flaky; see
                    // test_setattr_times_survive_crash_recovery for that path instead.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];

                        let mut mode = None;
                        let mut uid = None;
                        let mut gid = None;
                        let mut size = None;
                        if prng.gen_range(0, 1) == 0 {
                            let special = match prng.gen_range(0, 7) {
                                1 => 0o4000,
                                2 => 0o2000,
                                3 => 0o1000,
                                4 => 0o6000,
                                5 => 0o7000,
                                _ => 0,
                            };
                            mode = Some(special | (0o600 + prng.gen_range(0, 0o177) as u32));
                        }
                        if prng.gen_range(0, 1) == 0 {
                            uid = Some(prng.gen_range(1000, 2000) as u32);
                        }
                        if prng.gen_range(0, 1) == 0 {
                            gid = Some(prng.gen_range(1000, 2000) as u32);
                        }
                        if prng.gen_range(0, 1) == 0 {
                            size = Some(prng.gen_range(0, 300) as u64);
                        }
                        // Never let this degenerate into a pure no-op call.
                        if mode.is_none() && uid.is_none() && gid.is_none() && size.is_none() {
                            size = Some(prng.gen_range(0, 300) as u64);
                        }

                        let changes = AttrChanges {
                            mode,
                            uid,
                            gid,
                            size,
                            ..Default::default()
                        };
                        let res1 = fs_baseline.fs.set_attrs(ino, changes);
                        let res2 = fs_micro.fs.set_attrs(ino, changes);
                        let res3 = fs_remount.fs.set_attrs(ino, changes);
                        let res4 = fs_crash.fs.set_attrs(ino, changes);
                        let res5 = fs_remote.fs.set_attrs(ino, changes);

                        assert_eq!(res1, res2, "setattr result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "setattr result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "setattr result mismatch (baseline vs crash)");
                        assert_eq!(res1, res5, "setattr result mismatch (baseline vs remote)");
                    }
                }
                9 => {
                    // Readlink: non-symlink targets consistently return EINVAL across
                    // instances, which is still valid coverage, not just a skip.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];

                        let res1 = fs_baseline.fs.symlink_target(ino);
                        let res2 = fs_micro.fs.symlink_target(ino);
                        let res3 = fs_remount.fs.symlink_target(ino);
                        let res4 = fs_crash.fs.symlink_target(ino);
                        let res5 = fs_remote.fs.symlink_target(ino);

                        assert_eq!(res1, res2, "readlink result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "readlink result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "readlink result mismatch (baseline vs crash)");
                        assert_eq!(res1, res5, "readlink result mismatch (baseline vs remote)");
                    }
                }
                10 => {
                    // Read file & verify consistency across active instances
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let res1 = fs_baseline.fs.read_at(ino, 0, 4096);
                        let res2 = fs_micro.fs.read_at(ino, 0, 4096);
                        let res3 = fs_remount.fs.read_at(ino, 0, 4096);
                        let res4 = fs_crash.fs.read_at(ino, 0, 4096);
                        let res5 = fs_remote.fs.read_at(ino, 0, 4096);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);
                    }
                }
                11 => {
                    // Opendir: snapshot directory entries and hold open across mutations
                    let ino = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let res1 = fs_baseline.fs.open_dir(ino);
                    let res2 = fs_micro.fs.open_dir(ino);
                    let res3 = fs_remount.fs.open_dir(ino);
                    let res4 = fs_crash.fs.open_dir(ino);
                    let res5 = fs_remote.fs.open_dir(ino);

                    assert_eq!(res1.is_ok(), res2.is_ok());
                    assert_eq!(res1.is_ok(), res3.is_ok());
                    assert_eq!(res1.is_ok(), res4.is_ok());
                    assert_eq!(res1.is_ok(), res5.is_ok());

                    if let (Ok(fh1), Ok(fh2), Ok(fh3), Ok(fh4), Ok(fh5)) = (res1, res2, res3, res4, res5) {
                        let snap1 = fs_baseline
                            .fs
                            .extract_dir_handle(ino, fh1)
                            .expect("baseline dir handle")
                            .entries;
                        let snap2 = fs_micro
                            .fs
                            .extract_dir_handle(ino, fh2)
                            .expect("micro dir handle")
                            .entries;
                        let snap3 = fs_remount
                            .fs
                            .extract_dir_handle(ino, fh3)
                            .expect("remount dir handle")
                            .entries;
                        let snap4 = fs_crash
                            .fs
                            .extract_dir_handle(ino, fh4)
                            .expect("crash dir handle")
                            .entries;
                        let snap5 = fs_remote
                            .fs
                            .extract_dir_handle(ino, fh5)
                            .expect("remote dir handle")
                            .entries;
                        let snap5_filtered: Vec<(String, u64)> =
                            snap5.iter().filter(|(name, _)| name != ".remotes").cloned().collect();

                        assert_eq!(&*snap1, &*snap2, "opendir snapshot mismatch (baseline vs micro)");
                        assert_eq!(&*snap1, &*snap3, "opendir snapshot mismatch (baseline vs remount)");
                        assert_eq!(&*snap1, &*snap4, "opendir snapshot mismatch (baseline vs crash)");
                        assert_eq!(
                            &*snap1, &snap5_filtered,
                            "opendir snapshot mismatch (baseline vs remote)"
                        );

                        open_dir_handles.push(FuzzDirHandle {
                            ino,
                            fh1,
                            fh2,
                            fh3,
                            fh4,
                            fh5,
                            expected_snapshot: (*snap1).clone(),
                        });
                    }
                }
                12 => {
                    // Releasedir: verify that the open snapshot remained isolated from all
                    // intervening mutations, then release
                    if !open_dir_handles.is_empty() {
                        let idx = prng.gen_range(0, open_dir_handles.len() - 1);
                        let h = open_dir_handles.remove(idx);

                        let snap1 = fs_baseline
                            .fs
                            .extract_dir_handle(h.ino, h.fh1)
                            .expect("baseline handle")
                            .entries;
                        let snap2 = fs_micro
                            .fs
                            .extract_dir_handle(h.ino, h.fh2)
                            .expect("micro handle")
                            .entries;
                        let snap3 = fs_remount
                            .fs
                            .extract_dir_handle(h.ino, h.fh3)
                            .expect("remount handle")
                            .entries;
                        let snap4 = fs_crash
                            .fs
                            .extract_dir_handle(h.ino, h.fh4)
                            .expect("crash handle")
                            .entries;
                        let snap5 = fs_remote
                            .fs
                            .extract_dir_handle(h.ino, h.fh5)
                            .expect("remote handle")
                            .entries;
                        let snap5_filtered: Vec<(String, u64)> =
                            snap5.iter().filter(|(name, _)| name != ".remotes").cloned().collect();

                        assert_eq!(&*snap1, &h.expected_snapshot, "Snapshot isolation violated in baseline");
                        assert_eq!(&*snap2, &h.expected_snapshot, "Snapshot isolation violated in micro");
                        assert_eq!(&*snap3, &h.expected_snapshot, "Snapshot isolation violated in remount");
                        assert_eq!(&*snap4, &h.expected_snapshot, "Snapshot isolation violated in crash");
                        assert_eq!(
                            &snap5_filtered, &h.expected_snapshot,
                            "Snapshot isolation violated in remote"
                        );

                        let res1 = fs_baseline.fs.release_dir(h.ino, h.fh1);
                        let res2 = fs_micro.fs.release_dir(h.ino, h.fh2);
                        let res3 = fs_remount.fs.release_dir(h.ino, h.fh3);
                        let res4 = fs_crash.fs.release_dir(h.ino, h.fh4);
                        let res5 = fs_remote.fs.release_dir(h.ino, h.fh5);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);
                    }
                }
                13 => {
                    // Open file
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let res1 = fs_baseline.fs.open_file(ino, libc::O_RDWR as u32);
                        let res2 = fs_micro.fs.open_file(ino, libc::O_RDWR as u32);
                        let res3 = fs_remount.fs.open_file(ino, libc::O_RDWR as u32);
                        let res4 = fs_crash.fs.open_file(ino, libc::O_RDWR as u32);
                        let res5 = fs_remote.fs.open_file(ino, libc::O_RDWR as u32);

                        assert_eq!(res1.is_ok(), res2.is_ok());
                        assert_eq!(res1.is_ok(), res3.is_ok());
                        assert_eq!(res1.is_ok(), res4.is_ok());
                        assert_eq!(res1.is_ok(), res5.is_ok());

                        if let (Ok(fh1), Ok(fh2), Ok(fh3), Ok(fh4), Ok(fh5)) = (res1, res2, res3, res4, res5) {
                            open_file_handles.push(FuzzFileHandle {
                                ino,
                                fh1,
                                fh2,
                                fh3,
                                fh4,
                                fh5,
                            });
                        }
                    }
                }
                14 => {
                    // Xattr: setxattr/getxattr/listxattr/removexattr in a random
                    // combination, targeting either a file or a directory - this fs
                    // doesn't restrict xattrs by node type. Small fixed name pool so
                    // create/replace/remove races over the same name happen naturally,
                    // mirroring the name pools the create/mkdir cases above use.
                    let mut candidates = active_files.clone();
                    candidates.extend_from_slice(&active_dirs);
                    if !candidates.is_empty() {
                        let ino = candidates[prng.gen_range(0, candidates.len() - 1)];
                        let names = ["user.a", "user.b", "user.c"];
                        let name = names[prng.gen_range(0, names.len() - 1)];

                        match prng.gen_range(0, 3) {
                            0 => {
                                let value_len = prng.gen_range(0, 32);
                                let value: Vec<u8> = (0..value_len).map(|i| ((step + i) % 256) as u8).collect();
                                let flags = match prng.gen_range(0, 2) {
                                    0 => 0,
                                    1 => libc::XATTR_CREATE,
                                    _ => libc::XATTR_REPLACE,
                                };

                                let res1 = fs_baseline.fs.set_xattr(ino, name, &value, flags);
                                let res2 = fs_micro.fs.set_xattr(ino, name, &value, flags);
                                let res3 = fs_remount.fs.set_xattr(ino, name, &value, flags);
                                let res4 = fs_crash.fs.set_xattr(ino, name, &value, flags);
                                let res5 = fs_remote.fs.set_xattr(ino, name, &value, flags);

                                assert_eq!(res1, res2, "setxattr result mismatch (baseline vs micro)");
                                assert_eq!(res1, res3, "setxattr result mismatch (baseline vs remount)");
                                assert_eq!(res1, res4, "setxattr result mismatch (baseline vs crash)");
                                assert_eq!(res1, res5, "setxattr result mismatch (baseline vs remote)");
                            }
                            1 => {
                                let res1 = fs_baseline.fs.remove_xattr(ino, name);
                                let res2 = fs_micro.fs.remove_xattr(ino, name);
                                let res3 = fs_remount.fs.remove_xattr(ino, name);
                                let res4 = fs_crash.fs.remove_xattr(ino, name);
                                let res5 = fs_remote.fs.remove_xattr(ino, name);

                                assert_eq!(res1, res2, "removexattr result mismatch (baseline vs micro)");
                                assert_eq!(res1, res3, "removexattr result mismatch (baseline vs remount)");
                                assert_eq!(res1, res4, "removexattr result mismatch (baseline vs crash)");
                                assert_eq!(res1, res5, "removexattr result mismatch (baseline vs remote)");
                            }
                            2 => {
                                let res1 = fs_baseline.fs.xattr_value(ino, name);
                                let res2 = fs_micro.fs.xattr_value(ino, name);
                                let res3 = fs_remount.fs.xattr_value(ino, name);
                                let res4 = fs_crash.fs.xattr_value(ino, name);
                                let res5 = fs_remote.fs.xattr_value(ino, name);

                                assert_eq!(res1, res2, "getxattr result mismatch (baseline vs micro)");
                                assert_eq!(res1, res3, "getxattr result mismatch (baseline vs remount)");
                                assert_eq!(res1, res4, "getxattr result mismatch (baseline vs crash)");
                                assert_eq!(res1, res5, "getxattr result mismatch (baseline vs remote)");
                            }
                            _ => {
                                let res1 = fs_baseline.fs.xattr_names(ino);
                                let res2 = fs_micro.fs.xattr_names(ino);
                                let res3 = fs_remount.fs.xattr_names(ino);
                                let res4 = fs_crash.fs.xattr_names(ino);
                                let res5 = fs_remote.fs.xattr_names(ino);

                                assert_eq!(res1, res2, "listxattr result mismatch (baseline vs micro)");
                                assert_eq!(res1, res3, "listxattr result mismatch (baseline vs remount)");
                                assert_eq!(res1, res4, "listxattr result mismatch (baseline vs crash)");
                                assert_eq!(res1, res5, "listxattr result mismatch (baseline vs remote)");
                            }
                        }
                    }
                }
                15 => {
                    // Punch a hole. Offsets and lengths deliberately overlap the write
                    // case's range, so holes land inside, across and past the end of
                    // existing extents - and, once a checkpoint flushes, across extent
                    // boundaries in `base`, which is where a hole has to mask rather than
                    // fall through.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let offset = (prng.gen_range(0, 10) * 16) as u64;
                        let len = prng.gen_range(1, 200) as u64;

                        let res1 = fs_baseline.fs.punch_hole(ino, offset, len);
                        let res2 = fs_micro.fs.punch_hole(ino, offset, len);
                        let res3 = fs_remount.fs.punch_hole(ino, offset, len);
                        let res4 = fs_crash.fs.punch_hole(ino, offset, len);
                        let res5 = fs_remote.fs.punch_hole(ino, offset, len);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);
                    }
                }
                16 => {
                    // copy_file_range, between two files or within one. Sources have mostly
                    // been flushed by the time they are copied, so the destination comes to
                    // reference records from earlier batches - and on the small-log
                    // instances, from earlier generations, which the remote instance may
                    // since have pruned locally. Offsets reach past the writes' range, so
                    // copies also start past EOF, end in it, and open gaps in the target.
                    if !active_files.is_empty() {
                        let ino_in = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let ino_out = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let off_in = (prng.gen_range(0, 30) * 16) as i64;
                        let off_out = (prng.gen_range(0, 30) * 16) as i64;
                        let len = prng.gen_range(1, 300) as u64;

                        let source = fs_baseline.fs.read_at(ino_in, off_in, len as usize);
                        let res1 = fs_baseline.fs.copy_range(ino_in, off_in, ino_out, off_out, len);
                        let res2 = fs_micro.fs.copy_range(ino_in, off_in, ino_out, off_out, len);
                        let res3 = fs_remount.fs.copy_range(ino_in, off_in, ino_out, off_out, len);
                        let res4 = fs_crash.fs.copy_range(ino_in, off_in, ino_out, off_out, len);
                        let res5 = fs_remote.fs.copy_range(ino_in, off_in, ino_out, off_out, len);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);

                        // The other instances are held to the baseline at every checkpoint;
                        // this holds the baseline to what the copy promised.
                        if let Ok(copied) = res1 {
                            let source = source.expect("source read failed although the copy succeeded");
                            assert_eq!(copied, source.len(), "copy length must stop at the source's EOF");
                            let copy = fs_baseline.fs.read_at(ino_out, off_out, copied).unwrap();
                            assert_eq!(copy, source, "copied range must read back as the source did");
                        }
                    }
                }
                _ => {
                    // Release file
                    if !open_file_handles.is_empty() {
                        let idx = prng.gen_range(0, open_file_handles.len() - 1);
                        let h = open_file_handles.remove(idx);

                        let res1 = fs_baseline.fs.release_file(h.ino, h.fh1);
                        let res2 = fs_micro.fs.release_file(h.ino, h.fh2);
                        let res3 = fs_remount.fs.release_file(h.ino, h.fh3);
                        let res4 = fs_crash.fs.release_file(h.ino, h.fh4);
                        let res5 = fs_remote.fs.release_file(h.ino, h.fh5);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                        assert_eq!(res1, res5);
                    }
                }
            }

            // Inject periodic remote chaos:
            // 1. Injected transient faults on a single remote (so peer remotes remain healthy for failover)
            if step % 5 == 0 {
                let r_idx = prng.gen_range(0, fs_remote.remotes.len() - 1);
                fs_remote.remotes[r_idx].fail_next_n_requests(1);
            }
            // 2. Periodic sync cycle (progressing replication and local log pruning)
            if step % 30 == 0 {
                fs_remote.sync_remotes();
            }
            // 3. Spontaneous deletion with single-survivor invariant:
            // Hash of object key determines single keeper remote.
            // Only delete from non-keeper remotes IF keeper remote actually holds the object!
            if step % 7 == 0 {
                let n_remotes = fs_remote.memory_remotes.len();
                let mut all_keys = std::collections::HashSet::new();
                let mut remote_keys: Vec<std::collections::HashSet<String>> = Vec::with_capacity(n_remotes);
                for mem in &fs_remote.memory_remotes {
                    if let Ok(objs) = mem.list_objects("") {
                        let mut keys = std::collections::HashSet::with_capacity(objs.len());
                        for o in objs {
                            all_keys.insert(o.key.clone());
                            keys.insert(o.key);
                        }
                        remote_keys.push(keys);
                    } else {
                        remote_keys.push(std::collections::HashSet::new());
                    }
                }
                for key in all_keys {
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&key, &mut hasher);
                    let keeper = (std::hash::Hasher::finish(&hasher) as usize) % n_remotes;
                    let keeper_has_it = remote_keys.get(keeper).map(|keys| keys.contains(&key)).unwrap_or(false);
                    if keeper_has_it {
                        for (i, mem) in fs_remote.memory_remotes.iter().enumerate() {
                            if i != keeper && prng.gen_range(0, 100) < 50 {
                                let _ = mem.delete_object(&key);
                            }
                        }
                    }
                }
            }

            // At each randomly-drawn checkpoint step, simulate clean remount & unclean
            // crash recovery.
            if checkpoints.contains(&step) {
                // Drain open handles before remounting so all instances start recovery
                // cleanly without in-flight userspace descriptors
                for h in open_dir_handles.drain(..) {
                    let snap1 = fs_baseline
                        .fs
                        .extract_dir_handle(h.ino, h.fh1)
                        .expect("baseline handle")
                        .entries;
                    assert_eq!(
                        &*snap1, &h.expected_snapshot,
                        "Snapshot isolation violated before checkpoint"
                    );
                    let _ = fs_baseline.fs.release_dir(h.ino, h.fh1);
                    let _ = fs_micro.fs.release_dir(h.ino, h.fh2);
                    let _ = fs_remount.fs.release_dir(h.ino, h.fh3);
                    let _ = fs_crash.fs.release_dir(h.ino, h.fh4);
                    let _ = fs_remote.fs.release_dir(h.ino, h.fh5);
                }
                for h in open_file_handles.drain(..) {
                    let _ = fs_baseline.fs.release_file(h.ino, h.fh1);
                    let _ = fs_micro.fs.release_file(h.ino, h.fh2);
                    let _ = fs_remount.fs.release_file(h.ino, h.fh3);
                    let _ = fs_crash.fs.release_file(h.ino, h.fh4);
                    let _ = fs_remote.fs.release_file(h.ino, h.fh5);
                }

                // Fail a flush partway through writing this batch, then clear the fault.
                // The batch stays queued and is retried; if that retry ever leaves the log
                // in a state recovery can't read - a torn record, a duplicated one - the
                // crash comparison below turns it into a failure instead of silent
                // corruption nobody notices until a real disk fills up.
                if let Some(fault) = fs_crash.fault.clone() {
                    let offset = fs_crash.fs.log_writer.as_ref().map_or(0, |w| w.current_offset());
                    fault.fail_writes_after_bytes(offset + 200, true);
                    if fs_crash.fs.quiesce().is_err() {
                        observed_flush_failures += 1;
                    }
                    fault.clear_write_limit();
                }

                fs_remount = fs_remount.clean_remount();
                fs_crash = fs_crash.unclean_crash();

                // Quiesce and heal fs_remote
                let _ = fs_remote.fs.quiesce();
                for r in &fs_remote.remotes {
                    r.clear_faults();
                }
                for _ in 0..10 {
                    fs_remote.sync_remotes();
                }

                // Verify that cross-copying healed all remotes and all remotes agree on objects
                let r0_objs = fs_remote.memory_remotes[0].list_objects("").unwrap();
                for (i, mem) in fs_remote.memory_remotes.iter().enumerate().skip(1) {
                    let objs = mem.list_objects("").unwrap();
                    assert_eq!(
                        r0_objs.len(),
                        objs.len(),
                        "Remote {} object count mismatch with remote 0 at checkpoint (seed {}, step {})",
                        i,
                        seed,
                        step
                    );
                    for (o0, o_other) in r0_objs.iter().zip(objs.iter()) {
                        assert_eq!(o0.key, o_other.key);
                        assert_eq!(o0.size, o_other.size);
                        assert_eq!(o0.etag, o_other.etag);
                    }
                }

                // Exercise recovery on remote-backed instance with locally pruned logs
                fs_remote = fs_remote.clean_remount();

                // Assert complete tree & content parity across all 5 instances
                let snap_baseline = fs_baseline.fs.tree_snapshot();
                let snap_micro = fs_micro.fs.tree_snapshot();
                let snap_remount = fs_remount.fs.tree_snapshot();
                let snap_crash = fs_crash.fs.tree_snapshot();
                let snap_remote = fs_remote.fs.tree_snapshot();

                assert_eq!(snap_baseline.len(), snap_micro.len());
                assert_eq!(snap_baseline.len(), snap_remount.len());
                assert_eq!(snap_baseline.len(), snap_crash.len());
                assert_eq!(snap_baseline.len(), snap_remote.len());

                for (ino, snap) in &snap_baseline {
                    let micro_snap = snap_micro.get(ino).expect("inode missing in micro");
                    let remount_snap = snap_remount.get(ino).expect("inode missing in remount");
                    let crash_snap = snap_crash.get(ino).expect("inode missing in crash");
                    let remote_snap = snap_remote.get(ino).expect("inode missing in remote");

                    match (snap, micro_snap, remount_snap, crash_snap, remote_snap) {
                        (
                            SnapshotNode::Directory {
                                attr: a1,
                                entries: e1,
                                xattrs: x1,
                            },
                            SnapshotNode::Directory {
                                attr: a2,
                                entries: e2,
                                xattrs: x2,
                            },
                            SnapshotNode::Directory {
                                attr: a3,
                                entries: e3,
                                xattrs: x3,
                            },
                            SnapshotNode::Directory {
                                attr: a4,
                                entries: e4,
                                xattrs: x4,
                            },
                            SnapshotNode::Directory {
                                attr: a5,
                                entries: e5,
                                xattrs: x5,
                            },
                        ) => {
                            // Exact Vec order, not just set-equality: live rename does
                            // an in-place update for same-parent renames (preserving
                            // the entry's position), and recovery replay must
                            // reproduce that exactly, not just the resulting set of
                            // names - a real, once-actual bug (recovery used to
                            // unconditionally remove+push even for same-parent
                            // renames) was invisible to a sorted comparison and only
                            // surfaced via byte-for-byte .summary comparison - see
                            // test_summary_export_is_deterministic.
                            assert_eq!(
                                e1, e2,
                                "Directory entries mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                e1, e3,
                                "Directory entries mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                e1, e4,
                                "Directory entries mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                e1, e5,
                                "Directory entries mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "Directory atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "Directory atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a5.atime, a5.mtime, a5.ctime),
                                "Directory atime/mtime/ctime mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            // atime deliberately excluded here: reads bump atime in
                            // memory but are never logged (logging every read would
                            // defeat the point of an append-only log), so an
                            // atime-from-read is not crash-durable - only mtime/ctime,
                            // which are always backed by a logged op, are.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "Directory mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(x1, x2, "Directory xattrs mismatch at inode {} (baseline vs micro)", ino);
                            assert_eq!(
                                x1, x3,
                                "Directory xattrs mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(x1, x4, "Directory xattrs mismatch at inode {} (baseline vs crash)", ino);
                            assert_eq!(
                                x1, x5,
                                "Directory xattrs mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                        }
                        (
                            SnapshotNode::File {
                                attr: a1,
                                content: c1,
                                xattrs: x1,
                            },
                            SnapshotNode::File {
                                attr: a2,
                                content: c2,
                                xattrs: x2,
                            },
                            SnapshotNode::File {
                                attr: a3,
                                content: c3,
                                xattrs: x3,
                            },
                            SnapshotNode::File {
                                attr: a4,
                                content: c4,
                                xattrs: x4,
                            },
                            SnapshotNode::File {
                                attr: a5,
                                content: c5,
                                xattrs: x5,
                            },
                        ) => {
                            assert_eq!(c1, c2, "Content mismatch at inode {} (baseline vs micro)", ino);
                            assert_eq!(c1, c3, "Content mismatch at inode {} (baseline vs remount)", ino);
                            assert_eq!(c1, c4, "Content mismatch at inode {} (baseline vs crash)", ino);
                            assert_eq!(c1, c5, "Content mismatch at inode {} (baseline vs remote)", ino);
                            assert_eq!(
                                a1.size, a2.size,
                                "File size mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a3.size,
                                "File size mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a4.size,
                                "File size mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a5.size,
                                "File size mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a2.nlink,
                                "File nlink mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a3.nlink,
                                "File nlink mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a4.nlink,
                                "File nlink mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a5.nlink,
                                "File nlink mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a2.perm, a2.uid, a2.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a3.perm, a3.uid, a3.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a4.perm, a4.uid, a4.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a5.perm, a5.uid, a5.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "File atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "File atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a5.atime, a5.mtime, a5.ctime),
                                "File atime/mtime/ctime mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            // atime deliberately excluded - see the Directory arm's
                            // comment above.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "File mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(x1, x2, "File xattrs mismatch at inode {} (baseline vs micro)", ino);
                            assert_eq!(x1, x3, "File xattrs mismatch at inode {} (baseline vs remount)", ino);
                            assert_eq!(x1, x4, "File xattrs mismatch at inode {} (baseline vs crash)", ino);
                            assert_eq!(x1, x5, "File xattrs mismatch at inode {} (baseline vs remote)", ino);
                        }
                        (
                            SnapshotNode::Symlink {
                                attr: a1,
                                target: t1,
                                xattrs: x1,
                            },
                            SnapshotNode::Symlink {
                                attr: a2,
                                target: t2,
                                xattrs: x2,
                            },
                            SnapshotNode::Symlink {
                                attr: a3,
                                target: t3,
                                xattrs: x3,
                            },
                            SnapshotNode::Symlink {
                                attr: a4,
                                target: t4,
                                xattrs: x4,
                            },
                            SnapshotNode::Symlink {
                                attr: a5,
                                target: t5,
                                xattrs: x5,
                            },
                        ) => {
                            assert_eq!(t1, t2, "Symlink target mismatch at inode {} (baseline vs micro)", ino);
                            assert_eq!(t1, t3, "Symlink target mismatch at inode {} (baseline vs remount)", ino);
                            assert_eq!(t1, t4, "Symlink target mismatch at inode {} (baseline vs crash)", ino);
                            assert_eq!(t1, t5, "Symlink target mismatch at inode {} (baseline vs remote)", ino);
                            assert_eq!(
                                a1.nlink, a2.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a3.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a4.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a5.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a2.uid, a2.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a3.uid, a3.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a4.uid, a4.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a5.uid, a5.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "Symlink atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "Symlink atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a5.atime, a5.mtime, a5.ctime),
                                "Symlink atime/mtime/ctime mismatch at inode {} (baseline vs remote)",
                                ino
                            );
                            // atime deliberately excluded - see the Directory arm's
                            // comment above.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "Symlink mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(x1, x2, "Symlink xattrs mismatch at inode {} (baseline vs micro)", ino);
                            assert_eq!(x1, x3, "Symlink xattrs mismatch at inode {} (baseline vs remount)", ino);
                            assert_eq!(x1, x4, "Symlink xattrs mismatch at inode {} (baseline vs crash)", ino);
                            assert_eq!(x1, x5, "Symlink xattrs mismatch at inode {} (baseline vs remote)", ino);
                        }
                        _ => panic!("Node type mismatch for inode {}", ino),
                    }
                }
            }
        }

        {
            let inner = fs_baseline.fs.inner.lock_for_tests().unwrap();
            assert!(inner.handles.is_empty(), "seed {seed}: handle leak in baseline");
            assert!(
                inner.open_counts.is_empty(),
                "seed {seed}: open_counts leak in baseline"
            );
        }
        {
            let inner = fs_micro.fs.inner.lock_for_tests().unwrap();
            assert!(inner.handles.is_empty(), "seed {seed}: handle leak in micro");
            assert!(inner.open_counts.is_empty(), "seed {seed}: open_counts leak in micro");
        }
        {
            let inner = fs_remote.fs.inner.lock_for_tests().unwrap();
            assert!(inner.handles.is_empty(), "seed {seed}: handle leak in remote");
            assert!(inner.open_counts.is_empty(), "seed {seed}: open_counts leak in remote");
        }

        // The injection above is only worth anything if it actually fires. Without this,
        // a future change to batching or thresholds could quietly stop producing failures
        // and the run would still pass while testing nothing.
        assert!(
            observed_flush_failures > 0,
            "seed {}: no flush ever failed, so crash recovery was never exercised against \
             a failed-then-retried batch",
            seed
        );
    }
}

#[test]
fn test_crash_mid_flush_discards_uncommitted_trailing_batch() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = SystemClock;
    let writer = LogWriter::create(
        storage.clone(),
        1,
        Arc::new(clock),
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();

    // Batch 1: mkdir "committed_dir" under root (ino 1), properly committed with a
    // trailing FlushCommit - simulates a flush() call that completed successfully.
    let root_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
        parent: None,
        added: vec![("committed_dir".to_string(), 2)],
        removed: vec![],
        attr_delta: LogAttrDelta::default(),
    }));
    writer.append_serialized(OpCode::InodeDelta, 1, &root_delta).unwrap();

    let dir_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
        parent: Some(1),
        added: vec![],
        removed: vec![],
        attr_delta: LogAttrDelta {
            mode: Some(0o755),
            uid: Some(1000),
            gid: Some(1000),
            ..Default::default()
        },
    }));
    writer.append_serialized(OpCode::InodeDelta, 2, &dir_delta).unwrap();
    writer.emit_flush_commit(2, 0, clock.now()).unwrap();
    writer.flush().unwrap();

    // Batch 2: create "should_not_exist.txt" inside root, but WITHOUT ever writing its
    // FlushCommit trailer - simulates a crash exactly mid-flush, after the record was
    // physically appended but before the batch was confirmed complete.
    let uncommitted_delta = LogEntryDelta::Node(LogNodeDelta::Directory(LogDirectoryDelta {
        parent: None,
        added: vec![("should_not_exist.txt".to_string(), 3)],
        removed: vec![],
        attr_delta: LogAttrDelta::default(),
    }));
    writer
        .append_serialized(OpCode::InodeDelta, 1, &uncommitted_delta)
        .unwrap();
    // Deliberately no emit_flush_commit() call here - this is the crash point.

    writer.flush().unwrap();
    drop(writer);

    let recovered = recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let map = recovered.snapshot_all();

    let root = map.get(&1).unwrap();
    let entries = match &root.kind {
        NodeKind::Directory { entries, .. } => entries.clone(),
        _ => panic!("root is not a directory"),
    };

    assert!(
        entries.iter().any(|(name, _)| name == "committed_dir"),
        "committed batch's directory should have survived recovery"
    );
    assert!(
        !entries.iter().any(|(name, _)| name == "should_not_exist.txt"),
        "uncommitted trailing batch should have been discarded, not partially applied"
    );
    assert!(
        !map.contains_key(&3),
        "the uncommitted create's inode should not exist in recovered state at all"
    );
}

#[test]
fn test_crash_mid_flush_with_record_count_mismatch_fails_recovery() {
    // Exercises the defensive record_count cross-check: since every individual
    // record's own checksum already passed by the time recovery reaches a
    // FlushCommit, a record_count that still doesn't match what was actually
    // buffered can only mean a bug in the writer - not an expected crash-recovery
    // scenario - so this must hard-fail recovery entirely, not be silently discarded.
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = SystemClock;
    let writer = LogWriter::create(
        storage.clone(),
        1,
        Arc::new(clock),
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();

    let file_delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta {
        attr_delta: LogAttrDelta {
            mode: Some(0o644),
            uid: Some(1000),
            gid: Some(1000),
            ..Default::default()
        },
        ..Default::default()
    }));
    writer.append_serialized(OpCode::InodeDelta, 2, &file_delta).unwrap();
    // Claim 2 records preceded this trailer, when only 1 actually did.
    writer.emit_flush_commit(2, 0, clock.now()).unwrap();
    writer.flush().unwrap();
    drop(writer);

    let result = recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    );
    assert!(
        result.is_err(),
        "a FlushCommit with a mismatched record_count must fail recovery hard"
    );
}

#[test]
fn test_bitrot_in_committed_record_fails_recovery_hard() {
    // End-to-end: a fully committed, previously-valid batch whose payload bytes get
    // corrupted on disk afterwards (simulating real bitrot, not a torn write) must
    // cause recover_fs to refuse to mount, not silently reconstruct wrong state.
    let mem_storage = Arc::new(MemoryStorage::new());
    let storage: Arc<dyn Storage> = mem_storage.clone();
    let clock = SystemClock;
    let writer = LogWriter::create(
        storage.clone(),
        1,
        Arc::new(clock),
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();

    let file_delta = LogEntryDelta::Node(LogNodeDelta::File(LogFileDelta {
        attr_delta: LogAttrDelta {
            mode: Some(0o644),
            uid: Some(1000),
            gid: Some(1000),
            ..Default::default()
        },
        ..Default::default()
    }));
    writer.append_serialized(OpCode::InodeDelta, 2, &file_delta).unwrap();
    writer.emit_flush_commit(1, 0, clock.now()).unwrap();
    writer.flush().unwrap();
    let filename = writer.filename();
    drop(writer);

    // Sanity check: recovery succeeds and sees the file before any corruption.
    let recovered = recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    assert!(recovered.get_attr(2).is_some());
    drop(recovered);

    // header and this record's header - simulating a bitrotted byte in
    // otherwise-intact, previously-committed data.
    let mut file_bytes = mem_storage.get_file_bytes(&filename).unwrap();
    let corrupt_offset = appendfs::log::FILE_HEADER_SIZE + appendfs::log::RECORD_HEADER_SIZE + 2;
    file_bytes[corrupt_offset] ^= 0xFF;
    mem_storage.insert_file(&filename, file_bytes);

    let result = recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    );
    assert!(
        result.is_err(),
        "bitrot in a previously-committed record must be detected and hard-fail recovery, not be silently applied"
    );
}

// Sibling of test_truncate_shrink_then_grow_repro below, but for the *log* rather than
// the live read path. `apply_delta_to_node` folds a file delta as truncate(mask) ->
// extents -> size, so the synthesized records have to replay in that same order. A batch
// that shrinks and then grows back ends with a final size above the shrink point, and
// collapsing it into a single Setattr carrying only that final size loses the shrink -
// recovery then keeps the bytes past the truncation point that the live filesystem had
// already dropped. Needs a flush boundary before the truncate so the extent is in `base`.
#[test]
fn test_truncate_shrink_then_grow_within_one_batch_survives_crash_recovery() {
    let fs = TestFs::builder().build();
    let ino = fs.fs.create_file(1, "f.bin", 0o644).unwrap();
    fs.fs.write_at(ino, &[0xAA; 6], 0).unwrap();
    fs.fs.quiesce().unwrap();

    // Both of these land in one batch, whose final size (6) is above the shrink point (3).
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                size: Some(3),
                ..Default::default()
            },
        )
        .unwrap();
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                size: Some(6),
                ..Default::default()
            },
        )
        .unwrap();

    let live = fs.fs.read_at(ino, 0, 6).unwrap();
    assert_eq!(
        live,
        vec![0xAA, 0xAA, 0xAA, 0, 0, 0],
        "live must read the re-grown region as a hole"
    );

    let fs = fs.unclean_crash();
    assert_eq!(
        fs.fs.read_at(ino, 0, 6).unwrap(),
        live,
        "recovery must not resurrect bytes dropped by the truncate"
    );
}

// POSIX: "If the old argument and the new argument resolve to either the same existing
// directory entry or different directory entries for the same existing file, rename()
// shall return successfully and perform no other action." Treating the destination as a
// victim instead drops a link, and synthesis then emits a bare Rename whose replay does
// not reproduce that decrement, so live and the log disagree on nlink.
#[test]
fn test_rename_onto_own_hardlink_is_a_noop_and_survives_recovery() {
    let fs = TestFs::builder().build();
    let ino = fs.fs.create_file(1, "f0", 0o644).unwrap();
    fs.fs.write_at(ino, b"payload", 0).unwrap();
    fs.fs.hard_link(ino, 1, "f1").unwrap();
    // Flush so both names are in `base` when the rename resolves them.
    fs.fs.quiesce().unwrap();

    fs.fs.rename_entry(1, "f0", 1, "f1").unwrap();

    let names = |f: &TestFs| -> Vec<String> { f.fs.list_directory(1).unwrap().into_iter().map(|(n, _)| n).collect() };
    assert_eq!(names(&fs), vec!["f0", "f1"], "both hardlinks must survive");
    assert_eq!(
        fs.fs.get_attr(ino).unwrap().nlink,
        2,
        "renaming a file onto its own hardlink must not drop a link"
    );

    let fs = fs.unclean_crash();
    assert_eq!(names(&fs), vec!["f0", "f1"], "both names must survive recovery");
    assert_eq!(
        fs.fs.get_attr(ino).unwrap().nlink,
        2,
        "link count must survive recovery"
    );
    assert_eq!(fs.fs.read_at(ino, 0, 7).unwrap(), b"payload".to_vec());
}

// Synthesis reconstructs renames from a batch's net effect, so the order it emits them in
// has nothing to do with the order they happened. Replaying a rename while its destination
// is still occupied makes recovery treat the occupant as an overwrite victim, and for a
// directory that means deleting it outright along with everything under it.
#[test]
fn test_rename_into_a_name_freed_by_another_rename_in_the_same_batch() {
    let fs = TestFs::builder().build();
    let a = fs.fs.make_dir(1, "A", 0o755).unwrap();
    let b = fs.fs.make_dir(1, "B", 0o755).unwrap();
    let f = fs.fs.create_file(b, "payload.txt", 0o644).unwrap();
    fs.fs.write_at(f, b"important", 0).unwrap();
    fs.fs.quiesce().unwrap();

    // One batch: free the name "B" first, then move "A" into it.
    fs.fs.rename_entry(1, "B", 1, "C").unwrap();
    fs.fs.rename_entry(1, "A", 1, "B").unwrap();

    let live = fs.fs.list_directory(1).unwrap();
    assert_eq!(live, vec![("B".to_string(), a), ("C".to_string(), b)]);

    let fs = fs.unclean_crash();
    assert_eq!(
        fs.fs.list_directory(1).unwrap(),
        live,
        "replaying the renames out of order destroyed the displaced directory"
    );
    assert_eq!(fs.fs.read_at(f, 0, 9).unwrap(), b"important".to_vec());
}

// `add_dir_entry` clears the matching removal, so a name removed and put back inside one
// batch is recorded as a bare addition that merely restates what `base` already holds.
// Treating it as a real addition makes synthesis emit a Link, or pair it with an unrelated
// removal into a Rename, and replay then lands the entry twice.
#[test]
fn test_rename_away_and_back_within_one_batch_does_not_duplicate_the_entry() {
    let fs = TestFs::builder().build();
    let d = fs.fs.make_dir(1, "d", 0o755).unwrap();
    let f = fs.fs.create_file(d, "f", 0o644).unwrap();
    fs.fs.quiesce().unwrap();

    fs.fs.rename_entry(d, "f", 1, "moved").unwrap();
    fs.fs.rename_entry(1, "moved", d, "f").unwrap();

    let live = fs.fs.list_directory(d).unwrap();
    let live_nlink = fs.fs.get_attr(f).unwrap().nlink;
    assert_eq!(live, vec![("f".to_string(), f)]);

    let fs = fs.unclean_crash();
    assert_eq!(
        fs.fs.list_directory(d).unwrap(),
        live,
        "replay duplicated the directory entry"
    );
    assert_eq!(fs.fs.get_attr(f).unwrap().nlink, live_nlink);
}

#[test]
fn test_truncate_shrink_then_grow_repro() {
    // Targeted repro: write full content, shrink via truncate, write a small amount,
    // then grow back past the shrink point without covering it with a new write -
    // POSIX requires that newly-exposed region to read as zeros (a hole), not
    // whatever was physically there before the shrink.
    let fs = TestFs::builder().build();
    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.fs.write_at(ino, &full, 0).unwrap();
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                size: Some(50),
                ..Default::default()
            },
        )
        .unwrap();
    fs.fs.write_at(ino, b"XY", 0).unwrap();
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                size: Some(80),
                ..Default::default()
            },
        )
        .unwrap(); // grow back past the shrink point at 50

    let content = fs.fs.read_at(ino, 0, 80).unwrap();
    // Bytes [50..80) were "deleted" by the truncate to 50 and never rewritten -
    // POSIX says they must read as zero.
    assert!(
        content[50..80].iter().all(|&b| b == 0),
        "expected zeros in the newly-grown region [50,80), got {:?}",
        &content[50..80]
    );
}

#[test]
fn test_partial_overwrite_read_repro() {
    // Isolates write-overlap handling from truncate entirely: write 100 bytes, then
    // overwrite just the first 2, then verify the untouched tail [2,100) still reads
    // back as the original content.
    let fs = TestFs::builder().build();
    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.fs.write_at(ino, &full, 0).unwrap();
    fs.fs.write_at(ino, b"XY", 0).unwrap();

    let content = fs.fs.read_at(ino, 0, 100).unwrap();
    assert_eq!(&content[0..2], b"XY");
    assert_eq!(
        &content[2..100],
        &full[2..100],
        "tail bytes after partial overwrite changed unexpectedly"
    );
}

#[test]
fn test_partial_read_does_not_corrupt_subsequent_reads() {
    // RangeMap::query() is documented (and used throughout read()) as read-only, but
    // if it internally clones+trims via a value type whose clone() shares mutable
    // state (SharedExtentState), a PARTIAL read can permanently corrupt the stored
    // extent as a side effect - subsequent, unrelated reads would then see wrong data.
    let fs = TestFs::builder().build();
    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.fs.write_at(ino, &full, 0).unwrap();

    // A partial read, not touching the entry's own boundaries at either end.
    let partial = fs.fs.read_at(ino, 10, 20).unwrap();
    assert_eq!(&partial[..], &full[10..30]);

    // A subsequent FULL read must still return the original, untouched content -
    // the earlier partial read must not have mutated anything.
    let full_readback = fs.fs.read_at(ino, 0, 100).unwrap();
    assert_eq!(
        full_readback, full,
        "a prior partial read corrupted subsequent full-file reads"
    );
}

#[test]
fn test_setattr_times_survive_crash_recovery() {
    // setattr's atime/mtime handling used to update the live node but never populate
    // SetattrPayload - meaning those changes were never durably logged at all, and an
    // unclean crash (raw log replay, no summary) would silently lose them. Uses a
    // MockClock so timestamps compare exactly rather than fighting a real wall clock.
    let fixed_atime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let fixed_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_100);
    let clock: Arc<dyn Clock> = Arc::new(MockClock(fixed_atime));

    let fs = TestFs::builder().clock(clock).build();
    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap();
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                atime: Some(fixed_atime),
                mtime: Some(fixed_mtime),
                ..Default::default()
            },
        )
        .unwrap();

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(attr.atime, fixed_atime, "atime did not survive crash recovery");
    assert_eq!(attr.mtime, fixed_mtime, "mtime did not survive crash recovery");
}

#[test]
fn test_write_mtime_survives_crash_recovery() {
    // Isolates Write's op_time end-to-end: two writes, an intervening setattr that
    // touches only ctime, then an unclean crash - mtime must reflect the *last write*,
    // not the create time or the setattr's op_time.
    let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = AdvancingClock::new(start);
    let fs = TestFs::builder().clock(Arc::new(clock.clone())).build();

    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap(); // t=1_700_000_000
    clock.advance(Duration::from_secs(10));
    fs.fs.write_at(ino, b"hello", 0).unwrap(); // t=1_700_000_010
    clock.advance(Duration::from_secs(10));
    fs.fs.write_at(ino, b"world", 100).unwrap(); // t=1_700_000_020 - disjoint range, no elision
    clock.advance(Duration::from_secs(10));
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                mode: Some(0o600),
                ..Default::default()
            },
        )
        .unwrap(); // t=1_700_000_030 - ctime only

    let expected_mtime = start + Duration::from_secs(20);
    let expected_ctime = start + Duration::from_secs(30);

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(attr.mtime, expected_mtime, "mtime did not survive crash recovery");
    assert_eq!(attr.ctime, expected_ctime, "ctime did not survive crash recovery");
}

#[test]
fn test_setattr_size_change_updates_mtime_and_survives_crash_recovery() {
    // setattr's SIZE branch is the one to_set bit that (per POSIX truncate semantics)
    // touches mtime as well as ctime, unlike mode/uid/gid, which only ever touch
    // ctime. Recovery's replay used to apply op_time to ctime uniformly and never to
    // mtime at all, so a crash right after a truncate would resurrect the file with a
    // stale mtime from whenever it was created/last written, not from the truncate.
    let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = AdvancingClock::new(start);
    let fs = TestFs::builder().clock(Arc::new(clock.clone())).build();

    let ino = fs.fs.create_file(1, "f.txt", 0o644).unwrap(); // t=1_700_000_000
    clock.advance(Duration::from_secs(10));
    fs.fs.write_at(ino, b"hello world", 0).unwrap(); // t=1_700_000_010
    clock.advance(Duration::from_secs(10));
    // mode-only setattr: touches ctime, must NOT touch mtime.
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                mode: Some(0o600),
                ..Default::default()
            },
        )
        .unwrap(); // t=1_700_000_020
    clock.advance(Duration::from_secs(10));
    // size-only setattr (truncate): must touch BOTH mtime and ctime.
    fs.fs
        .set_attrs(
            ino,
            AttrChanges {
                size: Some(5),
                ..Default::default()
            },
        )
        .unwrap(); // t=1_700_000_030

    let expected_mtime = start + Duration::from_secs(30);
    let expected_ctime = start + Duration::from_secs(30);

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(attr.size, 5, "size did not survive crash recovery");
    assert_eq!(
        attr.mtime, expected_mtime,
        "mtime should reflect the truncate, not create/write time"
    );
    assert_eq!(attr.ctime, expected_ctime, "ctime did not survive crash recovery");
}

/// One tracked (parent, name, inode) entry, for `test_summary_export_is_deterministic`'s
/// own scratch bookkeeping - deliberately independent of `fs.inodes`, so the test picks
/// valid random targets without reaching into the filesystem's internals.
struct TrackedEntry {
    parent: u64,
    name: String,
    ino: u64,
    is_dir: bool,
}

#[test]
fn test_summary_export_is_deterministic() {
    // export_summary had two independent sources of nondeterminism: (1) its data
    // section iterated fs.inodes (a HashMap) directly instead of sorting like the index
    // section already did, so two summaries capturing identical filesystem state could
    // still land with inode records in a different physical order; (2) atime bumped by
    // plain reads is never logged, so a freshly-replayed instance has no way to
    // reconstruct it. This test builds a filesystem with atime tracking disabled (so
    // atime is fully log-derived, like every other field), exports its summary, then
    // reprocesses just the raw .log files from scratch (ignoring any summary shortcut)
    // and asserts the two summaries are byte-for-byte identical.
    let seeds = common::fuzz_seeds(5);
    let steps = common::fuzz_steps(150);
    for seed in 1..=seeds {
        let mut prng = TestRng::new(seed);
        let start = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = AdvancingClock::new(start);
        let mut fs = TestFs::builder().clock(Arc::new(clock.clone())).build();
        fs.fs.track_atime = false;

        let mut entries: Vec<TrackedEntry> = Vec::new();
        let mut dirs = vec![1u64];
        let mut files = Vec::<u64>::new(); // files and symlinks - anything read/write/link-able

        for step in 1..=steps {
            clock.advance(Duration::from_secs(1));
            match prng.gen_range(0, 8) {
                0 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("dir_{}_{}", seed, step);
                    if let Ok(ino) = fs.fs.make_dir(parent, &name, 0o755) {
                        dirs.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: true,
                        });
                    }
                }
                1 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("file_{}_{}.txt", seed, step);
                    if let Ok(ino) = fs.fs.create_file(parent, &name, 0o644) {
                        files.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: false,
                        });
                    }
                }
                2 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let offset = (prng.gen_range(0, 10) * 16) as u64;
                        let len = prng.gen_range(16, 128);
                        let payload: Vec<u8> = (0..len).map(|i| ((step + i) % 256) as u8).collect();
                        let _ = fs.fs.write_at(ino, &payload, offset as i64);
                    }
                }
                3 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let mode = (prng.gen_range(0, 1) == 0).then(|| {
                            let special = match prng.gen_range(0, 7) {
                                1 => 0o4000,
                                2 => 0o2000,
                                3 => 0o1000,
                                4 => 0o6000,
                                5 => 0o7000,
                                _ => 0,
                            };
                            special | (0o600 + prng.gen_range(0, 0o177) as u32)
                        });
                        let size = (prng.gen_range(0, 1) == 0).then(|| prng.gen_range(0, 200) as u64);
                        let _ = fs.fs.set_attrs(
                            ino,
                            AttrChanges {
                                mode,
                                size,
                                ..Default::default()
                            },
                        );
                    }
                }
                4 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("symlink_{}_{}", seed, step);
                    let target = format!("target_{}_{}", seed, step);
                    if let Ok(ino) = fs.fs.make_symlink(parent, &name, &target) {
                        files.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: false,
                        });
                    }
                }
                5 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let newparent = dirs[prng.gen_range(0, dirs.len() - 1)];
                        let newname = format!("hardlink_{}_{}", seed, step);
                        if fs.fs.hard_link(ino, newparent, &newname).is_ok() {
                            entries.push(TrackedEntry {
                                parent: newparent,
                                name: newname,
                                ino,
                                is_dir: false,
                            });
                        }
                    }
                }
                6 => {
                    let candidates: Vec<usize> = (0..entries.len()).filter(|&i| !entries[i].is_dir).collect();
                    if !candidates.is_empty() {
                        let idx = candidates[prng.gen_range(0, candidates.len() - 1)];
                        let e = entries.remove(idx);
                        let _ = fs.fs.remove_file(e.parent, &e.name);
                    }
                }
                7 => {
                    let candidates: Vec<usize> = (0..entries.len()).filter(|&i| entries[i].ino != 1).collect();
                    if !candidates.is_empty() {
                        let idx = candidates[prng.gen_range(0, candidates.len() - 1)];
                        let newparent = dirs[prng.gen_range(0, dirs.len() - 1)];
                        let newname = format!("renamed_{}_{}", seed, step);
                        let (parent, name) = (entries[idx].parent, entries[idx].name.clone());
                        if fs.fs.rename_entry(parent, &name, newparent, &newname).is_ok() {
                            entries[idx].parent = newparent;
                            entries[idx].name = newname;
                        }
                    }
                }
                _ => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let _ = fs.fs.read_at(ino, 0, 4096);
                    }
                }
            }
        }

        // Export a summary from the live instance - AppendFs::export_summary flushes
        // first, so every extent is guaranteed Disk-backed (SharedExtentState refuses to
        // serialize a still-Staged one) before either summary below gets written.
        let _generation = fs.fs.log_writer.as_ref().unwrap().generation();
        let live_storage = fs.storage.clone();
        let written_file = fs
            .fs
            .export_summary(live_storage.as_ref())
            .expect("export_summary failed on the live instance");

        // Reprocess: copy only the raw .log files and the volume's genesis summary into a
        // fresh in-memory storage, so recover_fs has no fast-path available and is forced
        // to fully replay from generation 1 - exactly the "reprocess all the logs" scenario
        // this test exists to check. `000000.summary` holds no data, only the empty root
        // `init_volume` created; every volume has it.
        let replay_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        for filename in live_storage.list_files().unwrap() {
            if filename.ends_with(".log") || filename == "000000.summary" {
                let reader = live_storage.open_reader(&filename).unwrap();
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
            Arc::new(clock.clone()),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .expect("recover_fs failed on replay");
        replayed.track_atime = false;
        replayed.next_inode.store(
            fs.fs.next_inode.load(std::sync::atomic::Ordering::SeqCst),
            std::sync::atomic::Ordering::SeqCst,
        );
        let regenerated_file = replayed
            .export_summary(replay_storage.as_ref())
            .expect("export_summary failed on the replayed instance");

        let live_reader = live_storage.open_reader(&written_file).unwrap();
        let written_bytes = live_reader.read_vec(0, live_reader.len().unwrap() as usize).unwrap();
        let replay_reader = replay_storage.open_reader(&regenerated_file).unwrap();
        let regenerated_bytes = replay_reader
            .read_vec(0, replay_reader.len().unwrap() as usize)
            .unwrap();
        assert_eq!(
            written_bytes,
            regenerated_bytes,
            "summary export is not byte-for-byte deterministic for seed {} \
             (written {} bytes, regenerated {} bytes)",
            seed,
            written_bytes.len(),
            regenerated_bytes.len()
        );
    }
}

#[test]
fn test_read_all_streaming_regular_large_and_virtual() {
    let fs = TestFs::builder().build();

    // 1. Empty file
    let empty_ino = fs.fs.create_file(1, "empty.txt", 0o644).unwrap();
    assert_eq!(fs.fs.read_all(empty_ino).unwrap(), Vec::<u8>::new());

    // 2. Small file (100 bytes)
    let small_ino = fs.fs.create_file(1, "small.txt", 0o644).unwrap();
    let small_payload = vec![0xABu8; 100];
    fs.fs.write_at(small_ino, &small_payload, 0).unwrap();
    assert_eq!(fs.fs.read_all(small_ino).unwrap(), small_payload);

    // 3. Large file spanning multiple 64KB chunks (150 KB)
    let large_ino = fs.fs.create_file(1, "large.txt", 0o644).unwrap();
    let large_payload: Vec<u8> = (0..(150 * 1024)).map(|i| (i % 251) as u8).collect();
    fs.fs.write_at(large_ino, &large_payload, 0).unwrap();
    assert_eq!(fs.fs.read_all(large_ino).unwrap(), large_payload);

    // 4. Virtual file (.remotes)
    fs.fs.register_remote_status();
    let remotes_ino = fs.fs.lookup_child(1, ".remotes").unwrap();
    let remotes_bytes = fs.fs.read_all(remotes_ino).unwrap();
    let remotes_str = String::from_utf8(remotes_bytes).unwrap();
    assert!(remotes_str.contains("No remotes configured"));

    // 5. Virtual file (.status)
    let status_ino = fs.fs.lookup_child(1, ".status").unwrap();
    let status_bytes = fs.fs.read_all(status_ino).unwrap();
    let status_str = String::from_utf8(status_bytes).unwrap();
    assert!(status_str.contains("=== appendfs Runtime Status ==="));
    assert!(status_str.contains("[Volume]"));
    assert!(status_str.contains("[Inodes]"));
    assert!(status_str.contains("[Flush Layer]"));
    assert!(status_str.contains("[Cache]"));
    assert!(status_str.contains("[Handles & Locks]"));
}
