use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_stats_on_empty_directory_fails() {
    let temp_dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs stats");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_fsck_on_empty_directory_fails() {
    let temp_dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("fsck")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs fsck");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_fails_on_directory_with_logs_but_no_summary() {
    let temp_dir = TempDir::new().unwrap();
    // Create an orphaned log file without any summary file
    std::fs::write(temp_dir.path().join("000001.log"), b"some log data").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs stats");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_init_plaintext_generates_random_volume_id() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    let output1 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(output1.status.success());
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    assert!(stdout1.contains("Volume ID:"));

    let output2 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir2.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout2.contains("Volume ID:"));

    // Extract Volume IDs
    let parse_vol_id = |text: &str| -> String {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("  Volume ID:") {
                return rest.trim().to_string();
            }
        }
        panic!("Volume ID not found in: {}", text);
    };

    let id1 = parse_vol_id(&stdout1);
    let id2 = parse_vol_id(&stdout2);

    assert_ne!(id1, "00000000000000000000000000000000");
    assert_ne!(id2, "00000000000000000000000000000000");
    assert_ne!(id1, id2);

    // `stats` reports volume identity as well as statistics, so the volume ID is visible
    // without a separate command.
    let stats_output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats");
    assert!(stats_output.status.success());
    let stats_stdout = String::from_utf8_lossy(&stats_output.stdout);
    assert!(stats_stdout.contains(&format!("Volume ID:     {}", id1)));

    // Verify passing --passphrase to stats on plaintext volume fails cleanly
    let pass_stats = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg("--passphrase")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats --passphrase");
    assert!(!pass_stats.status.success());
    let pass_stderr = String::from_utf8_lossy(&pass_stats.stderr);
    assert!(pass_stderr.contains("Volume is not encrypted; --passphrase does not apply to it"));

    // Verify passing --key-file to stats on plaintext volume fails cleanly
    let key_stats = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg("--key-file")
        .arg("/dev/null")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats --key-file");
    assert!(!key_stats.status.success());
    let key_stderr = String::from_utf8_lossy(&key_stats.stderr);
    assert!(key_stderr.contains("Volume is not encrypted; --key-file does not apply to it"));
}

#[test]
fn test_cli_remote_add_and_list_upload_partial_logs() {
    let temp_dir = TempDir::new().unwrap();
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(init_out.status.success());

    // 1. Add NFS remote (default upload_partial_logs = true)
    let nfs_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "nfs",
            "--path",
            "/mnt/nfs_backup",
        ])
        .output()
        .expect("failed to run remote add nfs");
    assert!(
        nfs_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&nfs_out.stderr)
    );

    // 2. Add S3 remote with --no-upload-partial-logs and --storage-class
    let s3_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "s3_backup",
            "--bucket",
            "my-appendfs-bucket",
            "--no-upload-partial-logs",
            "--storage-class",
            "INTELLIGENT_TIERING",
        ])
        .output()
        .expect("failed to run remote add s3_backup");
    assert!(
        s3_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&s3_out.stderr)
    );

    // 3. Verify `remote list` output shows partial_logs status and storage_class
    let list_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["remote", "list", temp_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run remote list");
    assert!(list_out.status.success());
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(stdout.contains("nfs: type='local/nfs'"));
    assert!(stdout.contains("partial_logs=Enabled"));
    assert!(stdout.contains("s3_backup: type='s3'"));
    assert!(stdout.contains("partial_logs=Disabled"));
    assert!(stdout.contains("storage_class='INTELLIGENT_TIERING'"));

    // 4. Verify remotes.toml was written correctly
    let storage = appendfs::storage::OsStorage::new(temp_dir.path());
    let registry = appendfs::remote::RemoteRegistry::load_from_storage(&storage).unwrap();
    assert!(registry.remotes["nfs"].upload_partial_logs);
    assert_eq!(registry.remotes["nfs"].storage_class, None);
    assert!(!registry.remotes["s3_backup"].upload_partial_logs);
    assert_eq!(
        registry.remotes["s3_backup"].storage_class.as_deref(),
        Some("INTELLIGENT_TIERING")
    );

    // 5. Verify passing both --upload-partial-logs and --no-upload-partial-logs fails
    let conflict_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "invalid_remote",
            "--bucket",
            "my-bucket",
            "--upload-partial-logs",
            "--no-upload-partial-logs",
        ])
        .output()
        .expect("failed to run remote add with conflicting flags");
    assert!(!conflict_out.status.success());
    let stderr = String::from_utf8_lossy(&conflict_out.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("Cannot specify both"),
        "expected conflict error, got: {}",
        stderr
    );
}

#[test]
fn test_cli_mount_args_flush_queue_bounds_defaults_and_overrides() {
    use appendfs::cli::{
        Cli, Commands, DEFAULT_MAX_FLUSH_QUEUE_BYTES, DEFAULT_MAX_FLUSH_QUEUE_DEPTH, DEFAULT_MAX_FLUSH_QUEUE_OPS,
    };
    use clap::Parser;

    // Test defaults
    let cli = Cli::try_parse_from(["appendfs", "mount", "/tmp/log", "/tmp/mnt"]).unwrap();
    match cli.command {
        Commands::Mount(args) => {
            assert_eq!(args.max_flush_queue_depth, DEFAULT_MAX_FLUSH_QUEUE_DEPTH);
            assert_eq!(args.max_flush_queue_depth, 16);
            assert_eq!(args.max_flush_queue_bytes, DEFAULT_MAX_FLUSH_QUEUE_BYTES);
            assert_eq!(args.max_flush_queue_ops, DEFAULT_MAX_FLUSH_QUEUE_OPS);
        }
        _ => panic!("expected Commands::Mount"),
    }

    // Test explicit flags
    let cli = Cli::try_parse_from([
        "appendfs",
        "mount",
        "/tmp/log",
        "/tmp/mnt",
        "--max-flush-queue-depth",
        "32",
        "--max-flush-queue-bytes",
        "67108864",
        "--max-flush-queue-ops",
        "5000",
    ])
    .unwrap();
    match cli.command {
        Commands::Mount(args) => {
            assert_eq!(args.max_flush_queue_depth, 32);
            assert_eq!(args.max_flush_queue_bytes, 67_108_864);
            assert_eq!(args.max_flush_queue_ops, 5000);
        }
        _ => panic!("expected Commands::Mount"),
    }
}

#[test]
fn test_cli_mount_foreground_unmounts_on_sigint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();

    let mut child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn appendfs mount");

    // Wait for FUSE mount to become ready
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("appendfs mount exited prematurely with: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    // Write a file to verify operational filesystem and persistent flush on unmount
    let test_file = mount_dir.path().join("before_interrupt.txt");
    std::fs::write(&test_file, b"data persisted across sigint").unwrap();
    assert_eq!(std::fs::read(&test_file).unwrap(), b"data persisted across sigint");

    // Send SIGINT (Ctrl+C) to foreground appendfs process
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    // Wait for child to exit cleanly
    let mut exited = false;
    let mut exit_status = None;
    for _ in 0..100 {
        if let Ok(Some(status)) = child.try_wait() {
            exited = true;
            exit_status = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child failed to exit after SIGINT");
    }

    let status = exit_status.unwrap();
    assert!(
        status.success(),
        "appendfs should exit successfully (0) on SIGINT unmount, got {:?}",
        status
    );

    // Verify mount point is cleanly unmounted and restored to underlying directory
    let after_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    assert_eq!(
        after_dev, initial_dev,
        "mount point device ID should be restored to initial underlying directory"
    );
    assert!(
        std::fs::read_dir(mount_dir.path()).unwrap().next().is_none(),
        "underlying directory should now be empty"
    );

    // Verify volume integrity and that written data was synced/exported
    let fsck_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["fsck", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run appendfs fsck");
    assert!(
        fsck_out.status.success(),
        "volume fsck failed: {}",
        String::from_utf8_lossy(&fsck_out.stderr)
    );

    // Remount to verify volume recovers and the file is accessible
    let mut remount_child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn remount child");

    let mut remounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            remounted = true;
            break;
        }
        if let Ok(Some(status)) = remount_child.try_wait() {
            panic!("remount child exited prematurely: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(remounted, "timed out waiting for remount");

    let read_back = std::fs::read(mount_dir.path().join("before_interrupt.txt")).unwrap();
    assert_eq!(read_back, b"data persisted across sigint");

    unsafe {
        libc::kill(remount_child.id() as libc::pid_t, libc::SIGINT);
    }
    assert!(remount_child.wait().unwrap().success());
}

#[test]
fn test_cli_mount_foreground_unmounts_on_sigint_when_busy() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();

    let mut child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn appendfs mount");

    // Wait for FUSE mount to become ready
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("appendfs mount exited prematurely with: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    let test_file = mount_dir.path().join("busy_file.txt");
    std::fs::write(&test_file, b"held open by external fd").unwrap();

    // Keep an open file descriptor in this test process to make the filesystem busy
    let open_file = std::fs::File::open(&test_file).unwrap();

    // Send SIGINT (Ctrl+C) to foreground appendfs process while filesystem is busy
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    // Wait for child to exit cleanly (lazy detach ensures unmount succeeds without blocking)
    let mut exited = false;
    let mut exit_status = None;
    for _ in 0..100 {
        if let Ok(Some(status)) = child.try_wait() {
            exited = true;
            exit_status = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child failed to exit after SIGINT while busy");
    }

    let status = exit_status.unwrap();
    assert!(
        status.success(),
        "appendfs should exit successfully (0) on SIGINT unmount even when busy, got {:?}",
        status
    );

    // Verify mount point is cleanly unmounted from VFS hierarchy
    let after_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    assert_eq!(
        after_dev, initial_dev,
        "mount point device ID should be detached and restored to underlying directory"
    );

    // Close the file descriptor now that unmount completed
    drop(open_file);
}

/// A backgrounded mount is the case that used to lose every log record: it redirects stderr
/// to /dev/null when it detaches from the terminal, and stderr was the only place logs went.
#[test]
fn test_cli_backgrounded_mount_writes_logs_into_the_volume_log_directory() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    let before = log_file_count(log_dir.path());

    // No `-f`: the process forks, and the parent exits once the daemon has mounted.
    let parent = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn appendfs mount");
    let parent_pid = parent.id();
    let out = parent.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The volume lock names the daemon serving the mount, not the parent that forked it and
    // exited - otherwise a second mount's "already locked by PID" points nowhere.
    let daemon_pid: u32 = std::fs::read_to_string(log_dir.path().join(".lock"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(daemon_pid, parent_pid, "the lock must not name the exited parent");
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", daemon_pid)).unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&cmdline).contains("mount"),
        "the lock must name the running mount daemon, PID {}",
        daemon_pid
    );

    // The operator is told where the logs went, since a daemonized mount leaves no other clue -
    // a file named for the daemon, too.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Logging to")
            && stdout.contains("logs/appendfs-")
            && stdout.contains(&format!("-{}.log", daemon_pid)),
        "startup must report the daemon's log location, got: {}",
        stdout
    );

    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    std::fs::write(mount_dir.path().join("payload.txt"), b"logged activity").unwrap();

    let unmounted = appendfs::wait_until(
        || {
            matches!(Command::new("fusermount3").arg("-u").arg(mount_dir.path()).status(),
                     Ok(s) if s.success())
        },
        Duration::from_secs(5),
    );
    assert!(unmounted, "failed to unmount");

    // One file for this run, named for when it started and which process it was.
    let logs_dir = log_dir.path().join("logs");
    assert!(
        appendfs::wait_until(
            || {
                std::fs::read_dir(&logs_dir)
                    .map(|entries| {
                        entries.flatten().any(|e| {
                            e.file_name().to_string_lossy().starts_with("appendfs-")
                                && e.metadata().map(|m| m.len() > 0).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            },
            Duration::from_secs(5)
        ),
        "a backgrounded mount must still leave logs in {}",
        logs_dir.display()
    );
    assert_eq!(
        log_file_count(log_dir.path()),
        before + 1,
        "the mount must leave exactly one log file of its own"
    );

    // The volume itself is unaffected: the log lives in a subdirectory, so nothing that
    // scans the log directory for generations or summaries can see it.
    let fsck = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["fsck", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run fsck");
    assert!(
        fsck.status.success(),
        "fsck must not be confused by the log directory: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
}

/// `--log-file /dev/null` is how logging is turned off; there is no separate flag for it.
#[test]
fn test_cli_log_file_dev_null_leaves_no_log_behind() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(["init", log_dir.path().to_str().unwrap()])
            .output()
            .expect("failed to init volume")
            .status
            .success()
    );

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    let before = log_file_count(log_dir.path());
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "--log-file",
            "/dev/null",
        ])
        .output()
        .expect("failed to spawn appendfs mount");
    assert!(
        out.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    std::fs::write(mount_dir.path().join("payload.txt"), b"no logs wanted").unwrap();
    assert!(
        appendfs::wait_until(
            || {
                matches!(Command::new("fusermount3").arg("-u").arg(mount_dir.path()).status(),
                         Ok(s) if s.success())
            },
            Duration::from_secs(5),
        ),
        "failed to unmount"
    );

    assert_eq!(
        log_file_count(log_dir.path()),
        before,
        "/dev/null must leave no log of its own behind"
    );
}

/// Every command logs, so a one-shot run leaves its own file in the volume alongside the
/// mounts, and each run's log says what that run was.
#[test]
fn test_cli_one_shot_commands_log_into_the_volume_with_their_command_line() {
    let log_dir = TempDir::new().unwrap();
    let logs = log_dir.path().join("logs");

    for args in [
        vec!["init", log_dir.path().to_str().unwrap()],
        vec!["stats", log_dir.path().to_str().unwrap()],
        vec!["fsck", log_dir.path().to_str().unwrap()],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {:?}: {}", args, e));
        assert!(
            out.status.success(),
            "{:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // One file per run, including the `init` that created the directory in the first place.
    let written: Vec<_> = std::fs::read_dir(&logs)
        .expect("every command must log into the volume")
        .flatten()
        .collect();
    assert_eq!(written.len(), 3, "each run gets its own file, got {:?}", written);

    // Each log opens with the command line that produced it.
    let mut commands: Vec<String> = written
        .iter()
        .map(|e| {
            std::fs::read_to_string(e.path())
                .unwrap()
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    commands.sort();
    assert!(
        commands.iter().any(|l| l.contains("init")),
        "a run's log must identify it: {:?}",
        commands
    );
    assert!(commands.iter().any(|l| l.contains("stats")), "{:?}", commands);
    assert!(commands.iter().any(|l| l.contains("fsck")), "{:?}", commands);
}

/// Credentials passed on the command line must not reach the log file.
#[test]
fn test_cli_does_not_log_credentials() {
    let log_dir = TempDir::new().unwrap();
    assert!(
        Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(["init", log_dir.path().to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            log_dir.path().to_str().unwrap(),
            "aws",
            "--bucket",
            "backups",
            "--access-key-id",
            "AKIAEXAMPLEKEYID",
            "--secret-access-key",
            "s3cr3t-must-not-be-logged",
        ])
        .output()
        .expect("failed to run remote add");
    assert!(
        out.status.success(),
        "remote add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for entry in std::fs::read_dir(log_dir.path().join("logs")).unwrap().flatten() {
        let contents = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
            !contents.contains("s3cr3t-must-not-be-logged"),
            "secret key leaked into {}",
            entry.path().display()
        );
        assert!(
            !contents.contains("AKIAEXAMPLEKEYID"),
            "access key id leaked into {}",
            entry.path().display()
        );
    }
}

/// A mistyped path must not scatter `logs/` directories across the filesystem.
#[test]
fn test_cli_does_not_create_a_volume_directory_that_does_not_exist() {
    let parent = TempDir::new().unwrap();
    let missing = parent.path().join("typo");

    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["stats", missing.to_str().unwrap()])
        .output()
        .expect("failed to run stats");
    assert!(!out.status.success(), "stats on a missing volume must fail");
    assert!(
        !missing.exists(),
        "a mistyped path must not be created just to log into"
    );
}

/// Number of log files currently in a volume's `logs/` directory.
fn log_file_count(log_dir: &std::path::Path) -> usize {
    std::fs::read_dir(log_dir.join("logs"))
        .map(|entries| entries.flatten().count())
        .unwrap_or(0)
}

#[test]
fn test_cli_mount_ro_batch_id_flag_and_no_tx_id_alias() {
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["mount-ro", "--help"])
        .output()
        .expect("failed to run mount-ro --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--batch-id"));
    assert!(!stdout.contains("--tx-id"));
}

/// SIGKILLs every other process holding `path` open, found by scanning `/proc/*/fd`.
fn kill_other_processes_holding(path: &std::path::Path) {
    for proc_entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = proc_entry.file_name().to_string_lossy().parse::<libc::pid_t>() else {
            continue;
        };
        if pid as u32 == std::process::id() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };
        if fds
            .flatten()
            .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|p| p == path))
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

/// A background mount (no `-f`) forks, and `fork` carries only the calling thread into the
/// daemon. Threads started before it - the delayed response queue's,
/// the replication worker's - used to vanish, so replication never ran and unmount hung
/// forever joining them, right after writing the final summary.
#[test]
fn test_cli_background_mount_exits_after_unmount_and_replicates() {
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    let log = log_dir.path().to_str().unwrap();
    let mount = mount_dir.path().to_str().unwrap();

    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "appendfs {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", log]);
    run(&[
        "remote",
        "add",
        log,
        "backup",
        "--path",
        remote_dir.path().to_str().unwrap(),
    ]);
    // Without `-f`, this returns once the daemon it forked has taken over the mount.
    run(&["mount", log, mount]);

    std::fs::write(mount_dir.path().join("hello.txt"), b"written through the daemon").unwrap();
    assert!(
        Command::new("fusermount3")
            .args(["-u", mount])
            .status()
            .unwrap()
            .success()
    );

    // The daemon holds the volume lock for as long as it runs.
    let lock_path = log_dir.path().join(".lock");
    let lock = std::fs::File::open(&lock_path).unwrap();
    let exited = appendfs::wait_until(
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        Duration::from_secs(10),
    );
    if !exited {
        kill_other_processes_holding(&lock_path);
    }
    assert!(exited, "background mount daemon did not exit after unmount");

    for name in ["000001.log", "000001.summary"] {
        assert!(
            remote_dir.path().join(name).exists(),
            "{} was not replicated to the remote",
            name
        );
    }
}

/// A backgrounded mount forks before it mounts, so a mount that fails has to be reported by
/// the daemon - on the terminal and in the exit status, as a foreground mount would.
#[test]
fn test_cli_backgrounded_mount_reports_failure_to_the_caller() {
    let log_dir = TempDir::new().unwrap();
    let missing_mount_point = log_dir.path().join("no-such-directory");

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            missing_mount_point.to_str().unwrap(),
        ])
        .output()
        .expect("failed to spawn appendfs mount");
    assert_eq!(out.status.code(), Some(1), "a failed mount must exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to mount"),
        "the failure must reach the caller's terminal, got: {}",
        stderr
    );
}
