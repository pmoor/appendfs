mod common;
use appendfs::Clock;
use appendfs::storage::{MemoryStorage, OsStorage, Storage};
use common::{TestMount, wait_until};
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_fuse_filesystem() {
    let log_dir = tempfile::Builder::new().prefix("appendfs_test_log_").tempdir().unwrap();
    let mount_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    // Perform directory listing verification (initially contains only virtual control files like .status)
    let entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert_eq!(entries, vec![".status".to_string()]);

    // Verify .status virtual file is directly readable through FUSE
    let status_str = fs::read_to_string(mount_path.join(".status")).unwrap();
    assert!(status_str.contains("=== appendfs Runtime Status ==="));

    // Verify statfs / statvfs reports root inode count (1)
    let path_c = std::ffi::CString::new(mount.path_str()).unwrap();
    let mut statvfs_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(path_c.as_ptr(), &mut statvfs_buf) };
    assert_eq!(res, 0);
    assert_eq!(statvfs_buf.f_files, 1);

    // Create a new file (hello.txt)
    let file_hello = mount_path.join("hello.txt");
    assert!(!file_hello.exists());

    let content = "Hello world from dynamic FUSE!\n";
    fs::write(&file_hello, content).unwrap();
    assert!(file_hello.exists());

    let read_content = fs::read_to_string(&file_hello).unwrap();
    assert_eq!(read_content, content);

    // Verify file ownership (UID/GID) and initial permissions
    let meta = fs::metadata(&file_hello).unwrap();
    assert_eq!(meta.uid(), unsafe { libc::getuid() });
    assert_eq!(meta.gid(), unsafe { libc::getgid() });
    assert_eq!(meta.permissions().mode() & 0o777, 0o644);

    // Verify chmod (setattr mode)
    fs::set_permissions(&file_hello, fs::Permissions::from_mode(0o600)).unwrap();
    let updated_meta = fs::metadata(&file_hello).unwrap();
    assert_eq!(updated_meta.permissions().mode() & 0o777, 0o600);

    // Verify initial timestamps and custom timestamp update (setattr mtime/atime)
    let mtime_1 = meta.modified().unwrap();
    assert!(mtime_1 >= std::time::UNIX_EPOCH);

    let custom_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let utimes_res = unsafe {
        let path_c = std::ffi::CString::new(file_hello.to_str().unwrap()).unwrap();
        let times = [
            libc::timeval {
                tv_sec: 1_700_000_000,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: 1_700_000_000,
                tv_usec: 0,
            },
        ];
        libc::utimes(path_c.as_ptr(), times.as_ptr())
    };
    assert_eq!(utimes_res, 0);

    let updated_meta_time = fs::metadata(&file_hello).unwrap();
    assert_eq!(updated_meta_time.modified().unwrap(), custom_time);

    // Verify truncate / write at offset
    let file = fs::OpenOptions::new().write(true).open(&file_hello).unwrap();
    file.set_len(5).unwrap();
    drop(file);
    assert_eq!(fs::metadata(&file_hello).unwrap().len(), 5);
    assert_eq!(fs::read_to_string(&file_hello).unwrap(), "Hello");

    // Write beyond current size (create a sparse gap)
    {
        use std::io::Seek;
        let mut file = fs::OpenOptions::new().write(true).open(&file_hello).unwrap();
        file.seek(std::io::SeekFrom::Start(10)).unwrap();
        file.write_all(b"world!").unwrap();
    }
    assert_eq!(fs::metadata(&file_hello).unwrap().len(), 16);
    let bytes = fs::read(&file_hello).unwrap();
    assert_eq!(&bytes[0..5], b"Hello");
    assert_eq!(&bytes[5..10], &[0, 0, 0, 0, 0]); // sparse zero-fill
    assert_eq!(&bytes[10..16], b"world!");

    // Create a directory (subdir)
    let sub_dir = mount_path.join("subdir");
    assert!(!sub_dir.exists());
    fs::create_dir(&sub_dir).unwrap();
    assert!(sub_dir.exists());
    assert!(sub_dir.is_dir());

    // Create nested file (subdir/nested.txt)
    let nested_file = sub_dir.join("nested.txt");
    fs::write(&nested_file, "nested content").unwrap();
    assert!(nested_file.exists());
    assert_eq!(fs::read_to_string(&nested_file).unwrap(), "nested content");

    // Test directory listing of root
    let root_entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(root_entries.contains(&"hello.txt".to_string()));
    assert!(root_entries.contains(&"subdir".to_string()));

    // Test directory listing of subdir
    let sub_entries: Vec<String> = fs::read_dir(&sub_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert_eq!(sub_entries, vec!["nested.txt".to_string()]);

    // Test rename (hello.txt -> hello_renamed.txt)
    let file_renamed = mount_path.join("hello_renamed.txt");
    fs::rename(&file_hello, &file_renamed).unwrap();
    assert!(!file_hello.exists());
    assert!(file_renamed.exists());
    assert_eq!(fs::read(&file_renamed).unwrap(), bytes);

    // Test moving across directories (hello_renamed.txt -> subdir/moved.txt)
    let file_moved = sub_dir.join("moved.txt");
    fs::rename(&file_renamed, &file_moved).unwrap();
    assert!(!file_renamed.exists());
    assert!(file_moved.exists());
    assert_eq!(fs::read(&file_moved).unwrap(), bytes);

    // Test symlink (subdir/sym -> moved.txt)
    let symlink_path = sub_dir.join("sym");
    std::os::unix::fs::symlink("moved.txt", &symlink_path).unwrap();
    assert!(symlink_path.exists());
    assert_eq!(
        fs::read_link(&symlink_path).unwrap(),
        std::path::PathBuf::from("moved.txt")
    );
    assert_eq!(fs::read(&symlink_path).unwrap(), bytes);

    // Test hard link (subdir/moved.txt -> hello_hard.txt in root)
    let file_hard = mount_path.join("hello_hard.txt");
    fs::hard_link(&file_moved, &file_hard).unwrap();
    assert!(file_hard.exists());
    let meta_moved = fs::metadata(&file_moved).unwrap();
    let meta_hard = fs::metadata(&file_hard).unwrap();
    assert_eq!(meta_moved.ino(), meta_hard.ino());
    assert_eq!(meta_moved.nlink(), 2);
    assert_eq!(meta_hard.nlink(), 2);

    // Write through hard link, read from original
    fs::write(&file_hard, "Modified via link!").unwrap();
    assert_eq!(fs::read_to_string(&file_moved).unwrap(), "Modified via link!");

    // Test unlink nested file
    fs::remove_file(&nested_file).unwrap();
    assert!(!nested_file.exists());

    // Test unlink symlink
    fs::remove_file(&symlink_path).unwrap();
    assert!(!symlink_path.exists());

    // Test rmdir failure on non-empty directory
    let rmdir_err = fs::remove_dir(&sub_dir);
    assert!(rmdir_err.is_err());

    // Remove moved.txt to make subdir empty
    fs::remove_file(&file_moved).unwrap();
    assert!(!file_moved.exists());

    // Test rmdir success on empty directory
    fs::remove_dir(&sub_dir).unwrap();
    assert!(!sub_dir.exists());

    // Assert hello.txt is gone
    assert!(!file_hello.exists());

    // Assert hello_hard.txt still exists, has nlink 1, and can be read/written
    assert!(file_hard.exists());
    let meta_hard = fs::metadata(&file_hard).unwrap();
    assert_eq!(meta_hard.nlink(), 1);
    assert_eq!(fs::read_to_string(&file_hard).unwrap(), "Modified via link!");

    // Verify fsync support by calling sync_all on a file handle
    {
        use std::fs::OpenOptions;
        let file = OpenOptions::new().write(true).open(&file_hard).unwrap();
        file.sync_data().unwrap();
        file.sync_all().unwrap();
    }

    // Verify fsyncdir support using opendir/dirfd/fsync (the only way to trigger FUSE fsyncdir)
    {
        use std::ffi::CString;
        let dir_path = CString::new(mount.path_str()).unwrap();
        unsafe {
            let dirp = libc::opendir(dir_path.as_ptr());
            assert!(!dirp.is_null(), "opendir failed");
            let fd = libc::dirfd(dirp);
            assert!(fd >= 0, "dirfd failed");
            let rc = libc::fsync(fd);
            assert_eq!(rc, 0, "fsync on dir fd failed: {}", std::io::Error::last_os_error());
            let rc = libc::fdatasync(fd);
            assert_eq!(rc, 0, "fdatasync on dir fd failed: {}", std::io::Error::last_os_error());
            libc::closedir(dirp);
        }
    }

    // Cleanup hello_hard.txt
    fs::remove_file(&file_hard).unwrap();
    assert!(!file_hard.exists());
    // Verify directory contains only virtual control files after deletion
    let entries_after: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert_eq!(entries_after, vec![".status".to_string()]);

    // Verify non-UTF8 filename lookup returns ENOENT without panicking
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let mut non_utf8_path = mount_path.as_os_str().as_bytes().to_vec();
        non_utf8_path.push(b'/');
        non_utf8_path.extend_from_slice(b"bad_\xff\xfe_file.txt");
        let c_path = CString::new(non_utf8_path).unwrap();
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let res = unsafe { libc::stat(c_path.as_ptr(), st.as_mut_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    mount.unmount();
}

#[test]
fn test_fuse_with_log_writer() {
    let log_dir = tempfile::Builder::new().prefix("appendfs_log_dir_").tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_dir.path()));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage,
            1,
            &appendfs::SystemClock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs = appendfs::InMemoryFS::with_log(Arc::clone(&writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_log_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs, false);
    let mount_path = mount.path().to_path_buf();

    // Perform operations on mounted filesystem
    let sub_dir = mount_path.join("docs");
    fs::create_dir(&sub_dir).unwrap();

    let file_path = sub_dir.join("logged_file.txt");
    let content = "Testing persistent appendfs logging engine!";
    fs::write(&file_path, content).unwrap();

    let read_back = fs::read_to_string(&file_path).unwrap();
    assert_eq!(read_back, content);

    // Call sync to trigger log flush to LogWriter disk file
    let file = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
    file.sync_data().unwrap();
    drop(file);

    // Verify .log file exists in log_dir and has size > FILE_HEADER_SIZE
    let log_file_path = mount.log_path.join("000001.log");
    assert!(log_file_path.exists());
    let log_size = fs::metadata(&log_file_path).unwrap().len();
    assert!(
        log_size > appendfs::log::record::FILE_HEADER_SIZE as u64,
        "Log file should contain logged record entries beyond header, size = {}",
        log_size
    );

    mount.unmount();
}

#[test]
fn test_recovery_after_remount() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    // Perform mutations
    let sub_dir = mount_path.join("photos");
    fs::create_dir(&sub_dir).unwrap();

    let photo1 = sub_dir.join("vacation.png");
    fs::write(&photo1, "RAW_PHOTO_DATA_123456789").unwrap();

    let symlink_path = mount_path.join("fav_photo.png");
    std::os::unix::fs::symlink("photos/vacation.png", &symlink_path).unwrap();

    // Flush and sync to disk
    let f = fs::OpenOptions::new().write(true).open(&photo1).unwrap();
    f.sync_data().unwrap();
    drop(f);

    // Remount generation 2
    mount.remount_rw();

    // Verify recovered filesystem contents
    let recovered_photo = mount.path().join("photos").join("vacation.png");
    assert!(recovered_photo.exists());
    let data = fs::read_to_string(&recovered_photo).unwrap();
    assert_eq!(data, "RAW_PHOTO_DATA_123456789");

    let recovered_symlink = mount.path().join("fav_photo.png");
    assert!(recovered_symlink.exists());
    let target = fs::read_link(&recovered_symlink).unwrap();
    assert_eq!(target.to_str().unwrap(), "photos/vacation.png");
}

#[test]
fn test_fuse_stress() {
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_stress_log_")
        .tempdir()
        .unwrap();
    let mount_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    // Create 4 subdirectories for the threads
    for i in 0..4 {
        let subdir = mount_path.join(format!("dir_{}", i));
        fs::create_dir(&subdir).unwrap();
        assert!(subdir.is_dir());
    }

    // Spawn 4 writer threads
    let mut threads = Vec::new();
    for thread_idx in 0..4 {
        let mount_path_clone = mount_path.clone();
        let writer = thread::spawn(move || {
            let subdir = mount_path_clone.join(format!("dir_{}", thread_idx));
            for iter_idx in 0..50 {
                let file_path = subdir.join(format!("file_{}.txt", iter_idx));
                let expected_content = format!("thread {} iteration {}", thread_idx, iter_idx);

                // Write the file
                fs::write(&file_path, &expected_content).unwrap();

                // Read and verify
                let read_content = fs::read_to_string(&file_path).unwrap();
                assert_eq!(read_content, expected_content);

                // Delete the file
                fs::remove_file(&file_path).unwrap();
                assert!(!file_path.exists());
            }
        });
        threads.push(writer);
    }

    // Spawn a 5th reader thread that lists directories concurrently
    let mount_path_clone = mount_path.clone();
    let reader = thread::spawn(move || {
        for iter_idx in 0..20 {
            thread::sleep(Duration::from_millis(10));
            // Read target thread dir
            let target_dir = mount_path_clone.join(format!("dir_{}", iter_idx % 4));
            if let Ok(entries) = fs::read_dir(&target_dir) {
                // Iterate over entries and concurrently read any existing files
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = fs::read(&path);
                    }
                }
            }
            // List root directory
            if let Ok(entries) = fs::read_dir(&mount_path_clone) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = fs::read(&path);
                    }
                }
            }
        }
    });
    threads.push(reader);

    // Wait for all threads to finish
    for t in threads {
        t.join().unwrap();
    }

    // Clean up: remove subdirectories and assert empty
    for i in 0..4 {
        let subdir = mount_path.join(format!("dir_{}", i));

        // Assert directory is empty
        let entries: Vec<String> = fs::read_dir(&subdir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect();
        assert!(
            entries.is_empty(),
            "Expected directory dir_{} to be empty, got: {:?}",
            i,
            entries
        );

        // Remove directory
        fs::remove_dir(&subdir).unwrap();
        assert!(!subdir.exists());
    }

    mount.unmount();
}

#[test]
fn test_log_rolling() {
    let clock: Arc<dyn appendfs::clock::Clock> = Arc::new(appendfs::clock::SystemClock);

    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_rolling_logs_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    // Create a LogWriter with a tiny max_log_size of 512 bytes to force rolling
    let writer = Arc::new(
        appendfs::LogWriter::create(storage, 1, &*clock, 512, 1, appendfs::VolumeKey::plaintext_arc()).unwrap(),
    );

    let mut fs_instance = appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_rolling_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Write enough data to force multiple generation rolls (512 bytes threshold).
    for i in 1..=5 {
        let file_path = mount_path.join(format!("chunk_{}.txt", i));
        let content = format!("LOG_ROLLING_PAYLOAD_{}_DATA_{}", i, "X".repeat(200));
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        (&file).write_all(content.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        // Read back data to verify read path across generations
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, content);
    }

    // Unmount initial filesystem to trigger unmount log sync
    mount.unmount();

    // Count generated .log files in log_path
    let mut log_files = Vec::new();
    for entry in fs::read_dir(&log_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("log") {
            log_files.push(path);
        }
    }

    assert!(
        log_files.len() > 1,
        "Expected log rolling to create multiple .log files, found: {}",
        log_files.len()
    );

    // Verify recovery across all rolled generation log files
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let mount_dir_rec = tempfile::Builder::new()
        .prefix("appendfs_rolling_rec_mount_")
        .tempdir()
        .unwrap();
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount_rec = TestMount::mount_custom(dummy_log, mount_dir_rec, recovered_fs, false);

    for i in 1..=5 {
        let file_path = mount_rec.path().join(format!("chunk_{}.txt", i));
        let expected_content = format!("LOG_ROLLING_PAYLOAD_{}_DATA_{}", i, "X".repeat(200));
        assert!(file_path.exists());
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, expected_content);
    }

    mount_rec.unmount();
}

#[test]
fn test_summary_single_file_export_and_recovery() {
    let clock: Arc<dyn appendfs::clock::Clock> = Arc::new(appendfs::clock::SystemClock);

    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_summary_logs_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );

    let mut fs_instance = appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_summary_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Populate filesystem with initial structure
    let docs_dir = mount_path.join("docs");
    fs::create_dir(&docs_dir).unwrap();

    let file1 = docs_dir.join("file1.txt");
    fs::write(&file1, "SNAPSHOT_FILE_1_CONTENT").unwrap();

    let file2 = docs_dir.join("file2.txt");
    fs::write(&file2, "SNAPSHOT_FILE_2_CONTENT").unwrap();

    // Unmount initial filesystem to flush log buffer to disk
    mount.unmount();

    // Recover filesystem state from log and export single-file summary snapshot (000001.summary)
    let fs_tmp = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let summary_file = fs_tmp.export_summary(storage.as_ref()).unwrap();
    let summary_path = log_path.join(&summary_file);

    assert!(summary_path.exists());
    assert_eq!(summary_file, "000001.summary");

    // Inspect summary snapshot using SummaryReader
    let reader =
        appendfs::SummaryReader::open(storage.as_ref(), &summary_file, appendfs::VolumeKey::plaintext_arc()).unwrap();
    assert_eq!(reader.header.generation, 1);
    assert_eq!(reader.footer.entry_count, 4); // root (1), docs dir (2), file1 (3), file2 (4)

    // Verify inodes can be read sequentially
    let all_nodes = reader.read_all_inodes().unwrap();
    assert_eq!(all_nodes.len(), 4);
    for ino in 1..=4 {
        assert!(all_nodes.contains_key(&ino));
    }

    // Verify recovery: recover_fs should fast-load state from 000001.summary
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();

    let mount_dir_rec = tempfile::Builder::new()
        .prefix("appendfs_summary_rec_mount_")
        .tempdir()
        .unwrap();
    let dummy_log_rec = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount_rec = TestMount::mount_custom(dummy_log_rec, mount_dir_rec, recovered_fs, false);

    let rec_file1 = mount_rec.path().join("docs").join("file1.txt");
    assert!(rec_file1.exists());
    assert_eq!(fs::read_to_string(&rec_file1).unwrap(), "SNAPSHOT_FILE_1_CONTENT");

    let rec_file2 = mount_rec.path().join("docs").join("file2.txt");
    assert!(rec_file2.exists());
    assert_eq!(fs::read_to_string(&rec_file2).unwrap(), "SNAPSHOT_FILE_2_CONTENT");

    mount_rec.unmount();
}

#[test]
fn test_large_directory_readdir_and_readdirplus() {
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_large_dir_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(dummy_log, temp_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    let large_dir = mount_path.join("large_dir");
    fs::create_dir(&large_dir).unwrap();

    let num_files = 1500;
    for i in 0..num_files {
        let file_path = large_dir.join(format!("file_{:05}.txt", i));
        fs::write(&file_path, format!("data_{}", i)).unwrap();
    }

    // Test readdir / readdirplus with standard Rust read_dir
    let mut read_entries = Vec::new();
    for entry in fs::read_dir(&large_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let meta = entry.metadata().unwrap();
        assert!(meta.is_file());
        read_entries.push(name);
    }
    read_entries.sort();
    assert_eq!(read_entries.len(), num_files);
    for (i, entry) in read_entries.iter().enumerate().take(num_files) {
        assert_eq!(entry, &format!("file_{:05}.txt", i));
    }

    // Test with command line `ls -la`
    let output = Command::new("ls").arg("-la").arg(&large_dir).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("file_00000.txt"));
    assert!(stdout.contains("file_01499.txt"));

    mount.unmount();
}

#[test]
fn test_manifest_and_live_stats_across_fuse_mount_and_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_manifest_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    // 1KB max log size to trigger rolling across writes
    let writer = Arc::new(
        appendfs::LogWriter::create(storage, 1, &*clock, 1000, 1, appendfs::VolumeKey::plaintext_arc()).unwrap(),
    );
    let fs = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_manifest_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, temp_dir, fs, false);
    let mount_path = mount.path().to_path_buf();

    // Helper function to write and fsync
    let write_and_sync = |path: &std::path::Path, data: &[u8]| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(data).unwrap();
        file.sync_all().unwrap();
        drop(file);
    };

    // Write file1 (1KB) in gen 1
    let file1 = mount_path.join("file1.bin");
    write_and_sync(&file1, &vec![0x11; 1000]);

    // Write file2 (1.5KB) -> forces rolling to generation 2
    let file2 = mount_path.join("file2.bin");
    write_and_sync(&file2, &vec![0x22; 1500]);

    // Write file3 (1.5KB) -> forces rolling to generation 3
    let file3 = mount_path.join("file3.bin");
    write_and_sync(&file3, &vec![0x33; 1500]);

    // Overwrite file1 completely with 500 bytes -> gen 1 now has 0 live bytes!
    write_and_sync(&file1, &vec![0x99; 500]);

    mount.unmount();

    // Recover filesystem
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let stats = recovered_fs.calculate_generation_live_stats();

    assert!(stats.len() >= 3, "Expected at least 3 generations");
    // Gen 1 file1 was overwritten in gen 3, so gen 1 live_bytes is 0!
    let gen1 = stats.iter().find(|s| s.generation == 1).unwrap();
    assert_eq!(gen1.live_bytes, 0);
    assert_eq!(gen1.live_ratio, 0.0);

    // Gen 2 (file2) is fully live
    let gen2 = stats.iter().find(|s| s.generation == 2).unwrap();
    assert_eq!(gen2.live_bytes, 1500);
    assert_eq!(gen2.live_extents, 1);
    assert!((gen2.live_ratio - 1.0).abs() < 1e-6);
}

#[test]
fn test_volume_init_mount_and_stats_flow() {
    let log_dir = tempfile::Builder::new().prefix("appendfs_init_vol_").tempdir().unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    // 1. Explicitly initialize empty volume
    let summary_filename = appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();
    let summary_path = log_path.join(&summary_filename);
    assert!(summary_path.exists());
    assert_eq!(summary_filename, "000000.summary");

    // 2. Mount initialized volume
    let mut fs_instance = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let next_gen = fs_instance.next_generation();
    assert_eq!(next_gen, 1);

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            next_gen,
            &appendfs::SystemClock,
            1024 * 1024,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs_instance.log_writer = Some(Arc::clone(&writer));
    fs_instance.set_log_dir(&log_path);

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_init_mount_")
        .tempdir()
        .unwrap();
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(dummy_log, temp_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Create a directory and file
    let docs = mount_path.join("docs");
    fs::create_dir(&docs).unwrap();
    let note = docs.join("note.txt");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&note)
            .unwrap();
        file.write_all(b"hello appendfs volume").unwrap();
        file.sync_all().unwrap();
    }

    // 3. Inspect volume with stats WHILE THE FUSE MOUNT IS ACTIVELY RUNNING
    {
        let live_storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));
        let live_recovered_fs = appendfs::recover_fs(
            live_storage,
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let live_stats = appendfs::VolumeStats::collect(&live_recovered_fs);
        assert_eq!(live_stats.total_inodes, 3);
        assert_eq!(live_stats.directory_count, 2);
        assert_eq!(live_stats.file_count, 1);
        assert_eq!(live_stats.total_logical_bytes, 21);
    }

    // Unmount
    mount.unmount();

    // 4. Inspect volume with stats after clean unmount
    let rec_storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));
    let recovered_fs = appendfs::recover_fs(
        rec_storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let stats = appendfs::VolumeStats::collect(&recovered_fs);

    assert_eq!(stats.total_inodes, 3); // root (1) + docs (2) + note.txt (3)
    assert_eq!(stats.directory_count, 2);
    assert_eq!(stats.file_count, 1);
    assert_eq!(stats.symlink_count, 0);
    assert_eq!(stats.total_logical_bytes, 21);

    let display = stats.display_text();
    assert!(display.contains("Total Inodes:        3 (2 directories, 1 files, 0 symlinks)"));
    assert!(display.contains("000001.log"));

    // 5. Test dump command on the generated 000001.log file
    let log_file = log_path.join("000001.log");
    assert!(log_file.exists());

    // Summary level (verbosity 0)
    let dump_v0 = appendfs::dump_log_file(rec_storage.as_ref(), "000001.log", 0, None).unwrap();
    assert!(dump_v0.contains("File Size:"));
    assert!(dump_v0.contains("Committed Flushes:"));
    assert!(dump_v0.contains("Trailing Batch:      None"));
    assert!(dump_v0.contains("Create"));
    assert!(dump_v0.contains("Write"));

    // Record stream level (verbosity 1)
    let dump_v1 = appendfs::dump_log_file(rec_storage.as_ref(), "000001.log", 1, None).unwrap();
    assert!(dump_v1.contains("Create"));
    assert!(dump_v1.contains("Write"));
    assert!(dump_v1.contains("note.txt"));
    assert!(dump_v1.contains("[COMMITTED]"));

    // Full hex payload level (verbosity 2)
    let dump_v2 = appendfs::dump_file(rec_storage.as_ref(), "000001.log", 2, None).unwrap();
    assert!(dump_v2.contains("hello appendfs v"));
    assert!(dump_v2.contains("olume"));

    // 6. Test dump command on the initial summary file 000000.summary
    let summary_file = log_path.join("000000.summary");
    assert!(summary_file.exists());
    let dump_sum_v0 = appendfs::dump_file(rec_storage.as_ref(), "000000.summary", 0, None).unwrap();
    assert!(dump_sum_v0.contains("=== appendfs Summary File Dump ==="));
    assert!(dump_sum_v0.contains("Total Inodes:        1"));
    assert!(dump_sum_v0.contains("Checksum (BLAKE3):"));
    assert!(dump_sum_v0.contains("VERIFIED"));

    let dump_sum_v1 = appendfs::dump_file(rec_storage.as_ref(), "000000.summary", 1, None).unwrap();
    assert!(dump_sum_v1.contains("Summary Inode Records"));
    assert!(dump_sum_v1.contains("Directory  \"/\""));
}

#[test]
fn test_lazy_log_creation_and_clean_read_only_unmount() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_path));

    // 1. Initialize volume
    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    // Verify only 000000.summary exists
    let files: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(files, vec!["000000.summary"]);

    // 2. Simulate Mount 1: Read-only mount session
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(
                storage.clone(),
                1,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                appendfs::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(log_path);

        // Perform read-only operations
        let root_entries = fs.list_directory(1).unwrap();
        assert_eq!(root_entries.len(), 0);

        // Drop fs (simulating unmount)
    }

    // Assert that the log directory remains 100% clean and untouched (ignoring .lock)!
    let mut files_after_ro: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|f| f != ".lock")
        .collect();
    files_after_ro.sort();
    assert_eq!(files_after_ro, vec!["000000.summary"]);

    // 3. Simulate Mount 2: Mutation session
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(
                storage.clone(),
                1,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                appendfs::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(log_path);

        // Create directory and file
        let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "testdir", 0o755, 1000, 1000).unwrap();
        let file_attr =
            appendfs::operations::read_write::create_core(&fs, dir_attr.ino, "data.txt", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, file_attr.ino, b"hello lazy log", 0).unwrap();

        // Flush & unmount
        fs.quiesce().unwrap();
    }

    // Assert that 000001.log and 000001.summary were created cleanly
    let mut files_after_write: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|f| f != ".lock")
        .collect();
    files_after_write.sort();
    assert_eq!(
        files_after_write,
        vec!["000000.summary", "000001.log", "000001.summary"]
    );

    // 4. Verify recovery restores the written state
    let recovered = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let root_entries = recovered.list_directory(1).unwrap();
    assert_eq!(root_entries.len(), 1);
    assert_eq!(root_entries[0].0, "testdir");
}

#[test]
fn test_bulk_metadata_rm_rf_triggers_automatic_flush() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_path));

    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(
            storage,
            1,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);
    // Set threshold to 10 operations
    fs.max_staged_ops = 10;

    // 1. Create a tree with 1 directory and 15 files
    let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "bigdir", 0o755, 1000, 1000).unwrap();
    let mut file_names = Vec::new();
    for i in 0..15 {
        let name = format!("f_{}.txt", i);
        appendfs::operations::read_write::create_core(&fs, dir_attr.ino, &name, 0o644, 0, 1000, 1000).unwrap();
        file_names.push(name);
    }

    // 2. Perform rm -rf (15 unlinks + 1 rmdir)
    for name in &file_names {
        appendfs::operations::links::unlink_core(&fs, dir_attr.ino, name).unwrap();
    }
    appendfs::operations::dir::rmdir_core(&fs, 1, "bigdir").unwrap();

    // Verify that the active log writer records flushes triggered automatically by operation count!
    let writer = fs.log_writer.as_ref().unwrap();
    assert!(
        writer.record_count() > 0,
        "metadata unlinks must have been automatically flushed to log"
    );
}

#[test]
fn test_background_flusher_in_mount_session() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_path));

    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(
            storage,
            1,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);
    // Set 1-second flush interval and high op threshold so automatic threshold does not trigger
    fs.max_staged_ops = 10_000;
    fs.flush_interval.store(1, std::sync::atomic::Ordering::SeqCst);

    let fs = std::sync::Arc::new(fs);
    fs.init();

    // Perform only 2 operations
    let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "periodic_dir", 0o755, 1000, 1000).unwrap();
    appendfs::operations::read_write::create_core(&fs, dir_attr.ino, "periodic_file.txt", 0o644, 0, 1000, 1000)
        .unwrap();

    // Staged ops should be 2 initially
    assert_eq!(fs.staged_ops(), 2);

    // Wait up to 5 seconds for the background flusher to flush dirty ops to disk
    assert!(
        wait_until(|| fs.total_dirty_ops() == 0, std::time::Duration::from_secs(5)),
        "Dirty ops ({}) must be flushed to 0 by the background flusher",
        fs.total_dirty_ops()
    );
    let writer = fs.log_writer.as_ref().unwrap();
    assert!(writer.record_count() > 0);

    fs.destroy();
}

#[test]
fn test_check_volume_identifies_clean_and_orphaned_volume() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_path));

    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(
            storage.clone(),
            1,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);

    // 1. Populate valid filesystem tree
    let d = appendfs::operations::dir::mkdir_core(&fs, 1, "sub", 0o755, 1000, 1000).unwrap();
    let f1 = appendfs::operations::read_write::create_core(&fs, d.ino, "hello.txt", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&fs, f1.ino, b"integrity test data", 0).unwrap();
    let _l = appendfs::operations::links::link_core(&fs, f1.ino, 1, "hardlink.txt").unwrap();

    fs.quiesce().unwrap();

    // 2. Check clean volume
    let report = appendfs::check_volume(storage, true, appendfs::VolumeKey::plaintext_arc()).unwrap();
    assert!(report.is_clean(), "Clean volume must pass check: {:?}", report.issues);
    assert_eq!(report.error_count(), 0);
    assert_eq!(report.orphaned_inodes.len(), 0);
    assert_eq!(report.directories, 2);
    assert_eq!(report.regular_files, 1);

    let output = report.format_report(Some(log_path), true);
    assert!(output.contains("VERDICT: CLEAN"));
    assert!(output.contains("[PASS] Inode Reachability"));

    // 3. Inject an orphaned inode into base and verify check detects it
    let orphan_ino = 888;
    let orphan_node = appendfs::Node {
        meta: appendfs::InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
        kind: appendfs::NodeKind::File {
            extent_map: appendfs::ExtentMap::new(),
            size: 256,
        },
    };
    fs.inner
        .lock_for_tests()
        .unwrap()
        .base
        .insert(orphan_ino, std::sync::Arc::new(orphan_node));

    let corrupted_report = appendfs::check_fs_integrity(&fs, Some(log_path), true);
    assert!(!corrupted_report.is_clean());
    assert_eq!(corrupted_report.orphaned_inodes, vec![888]);
    assert_eq!(corrupted_report.error_count(), 1);

    let corrupted_output = corrupted_report.format_report(Some(log_path), false);
    assert!(corrupted_output.contains("VERDICT: CORRUPT"));
    assert!(corrupted_output.contains("ORPHAN_INODE"));
    assert!(corrupted_output.contains("Inode 888"));
}

#[test]
fn test_mount_ro_rejects_mutations_and_enables_point_in_time_time_travel() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();
    let log_path = mount.log_path.clone();

    // 2. RW Mount: create directory and file (Tx 1 & 2)
    let step1_dir = mount_path.join("step1");
    fs::create_dir(&step1_dir).unwrap();
    let file1 = step1_dir.join("file1.txt");
    fs::write(&file1, "version 1 content").unwrap();

    // 3. RW Mount 2: append changes (Tx 3 & 4)
    mount.remount_rw();

    let step2_dir = mount.path().join("step2");
    fs::create_dir(&step2_dir).unwrap();
    let file2 = step2_dir.join("file2.txt");
    fs::write(&file2, "version 2 content").unwrap();

    mount.unmount();

    // Count summary and log files before RO mount
    let mut files_before_ro: Vec<String> = fs::read_dir(&log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files_before_ro.sort();

    // 4. RO Mount (Latest state)
    mount.remount_ro(appendfs::RecoveryTarget::Latest);

    // Read operations must succeed
    let file1 = mount.path().join("step1/file1.txt");
    assert_eq!(fs::read_to_string(&file1).unwrap(), "version 1 content");
    let file2 = mount.path().join("step2/file2.txt");
    assert_eq!(fs::read_to_string(&file2).unwrap(), "version 2 content");

    // Mutation operations must fail with EROFS / PermissionDenied
    assert!(fs::write(&file1, "tampered").is_err(), "Write on RO mount must fail");
    assert!(
        fs::create_dir(mount.path().join("forbidden_dir")).is_err(),
        "Mkdir on RO mount must fail"
    );
    assert!(fs::remove_file(&file1).is_err(), "Unlink on RO mount must fail");

    mount.unmount();

    // Verify RO mount never created/modified summary or log files
    let mut files_after_ro: Vec<String> = fs::read_dir(&log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files_after_ro.sort();
    assert_eq!(
        files_before_ro, files_after_ro,
        "RO mount must never write to disk files"
    );

    // 5. RO Mount with Point-in-Time Historical Recovery (BatchId cutoff before step2)
    mount.remount_ro(appendfs::RecoveryTarget::BatchId(1));

    // step1 exists
    let file1 = mount.path().join("step1/file1.txt");
    assert!(file1.exists(), "step1/file1.txt must exist at historical point-in-time");
    assert_eq!(fs::read_to_string(&file1).unwrap(), "version 1 content");

    // step2 does NOT exist at this historical point in time
    let step2 = mount.path().join("step2");
    assert!(!step2.exists(), "step2 must NOT exist at historical point-in-time");
}

#[test]
fn test_double_mount_rw_protection_and_concurrent_ro_mount() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_path));

    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    // 1. First RW Mount: acquires exclusive lock
    let mut fs1 = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let writer1 = appendfs::LogWriter::create_lazy(
        storage.clone(),
        1,
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("First RW mount must successfully acquire exclusive volume lock");
    fs1.log_writer = Some(std::sync::Arc::new(writer1));
    fs1.set_log_dir(log_path);

    // 2. Second concurrent RW Mount attempt: must fail with WouldBlock
    let err = appendfs::LogWriter::create_lazy(
        storage.clone(),
        1,
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "Second RW mount must fail with WouldBlock"
    );
    assert!(
        err.to_string().contains("already locked in read-write mode"),
        "Error message should clearly explain volume lock collision: {}",
        err
    );

    // 3. Concurrent RO Mount/Recovery: must succeed even while RW is actively mounted!
    let ro_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("RO recovery must succeed concurrently while RW mount is active");
    assert!(ro_fs.list_directory(1).is_some());

    // 4. Drop first RW mount (unmount / release lock)
    drop(fs1);

    // 5. Subsequent RW Mount: must now succeed cleanly
    let mut writer2_res = None;
    assert!(
        wait_until(
            || {
                let res = appendfs::LogWriter::create_lazy(
                    storage.clone(),
                    1,
                    appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    appendfs::VolumeKey::plaintext_arc(),
                );
                let ok = res.is_ok();
                writer2_res = Some(res);
                ok
            },
            std::time::Duration::from_secs(2)
        ),
        "Subsequent RW mount must succeed after previous RW mount is dropped"
    );
    let writer2 = writer2_res
        .unwrap()
        .expect("Subsequent RW mount must succeed after previous RW mount is dropped");
    drop(writer2);
}

#[test]
fn test_fuse_flock_and_posix_locks() {
    use std::os::unix::io::AsRawFd;

    let mount = common::TestMount::new_rw();
    let file_path = mount.path().join("lock_test.txt");
    std::fs::write(&file_path, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let f1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();
    let f2 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();

    // 1. Acquire shared lock on f1 and f2 concurrently
    let ret1 = unsafe { libc::flock(f1.as_raw_fd(), libc::LOCK_SH) };
    assert_eq!(ret1, 0, "flock(f1, LOCK_SH) should succeed");

    let ret2 = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_SH) };
    assert_eq!(ret2, 0, "flock(f2, LOCK_SH) should succeed concurrently");

    // 2. Attempt exclusive lock on f2 -> must fail with EWOULDBLOCK
    let ret_ex = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ret_ex, -1);
    let err = std::io::Error::last_os_error();
    assert!(
        err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN),
        "Expected EWOULDBLOCK/EAGAIN, got: {:?}",
        err
    );

    // 3. Unlock f1
    let ret_un1 = unsafe { libc::flock(f1.as_raw_fd(), libc::LOCK_UN) };
    assert_eq!(ret_un1, 0, "flock(f1, LOCK_UN) should succeed");

    // 4. Upgrade f2 to exclusive -> should now succeed!
    let ret_ex2 = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ret_ex2, 0, "flock(f2, LOCK_EX) should succeed after f1 unlocked");

    // 5. Unlock f2
    let ret_un2 = unsafe { libc::flock(f2.as_raw_fd(), libc::LOCK_UN) };
    assert_eq!(ret_un2, 0, "flock(f2, LOCK_UN) should succeed");

    // 6. Test POSIX fcntl range locking
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as i16;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = 0;
    fl.l_len = 10;

    let ret_fcntl = unsafe { libc::fcntl(f1.as_raw_fd(), libc::F_SETLK, &fl) };
    assert_eq!(ret_fcntl, 0, "fcntl(f1, F_SETLK, F_WRLCK) should succeed");

    // 7. Test blocking POSIX fcntl range locking across processes (F_SETLKW)
    let py_script = format!(
        r#"
import fcntl, sys
with open("{}", "r+") as f:
    fcntl.lockf(f, fcntl.LOCK_EX, 10, 0, 0)
"#,
        file_path.display()
    );

    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(&py_script)
        .spawn()
        .unwrap();

    // Verify child process is blocked while f1 holds write lock
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "Child process should be blocked on F_SETLKW"
    );

    // Unlock f1 -> child process should unblock and exit
    fl.l_type = libc::F_UNLCK as i16;
    let ret_fcntl_un = unsafe { libc::fcntl(f1.as_raw_fd(), libc::F_SETLK, &fl) };
    assert_eq!(ret_fcntl_un, 0, "fcntl(f1, F_SETLK, F_UNLCK) should succeed");

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "Child process should exit successfully after acquiring lock"
    );
}

#[test]
fn test_fuse_flock_and_posix_waiter_queue_parking() {
    use std::os::unix::io::AsRawFd;

    let mut mount = common::TestMount::new_rw();
    let file_path = mount.path().join("park_queue_test.txt");
    std::fs::write(&file_path, b"initial content").unwrap();

    let f1 = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();

    // 1. Parent process acquires exclusive lock on f1
    let ret_ex = unsafe { libc::flock(f1.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(ret_ex, 0, "flock(f1, LOCK_EX) should succeed");

    // 2. Child 1: Attempts blocking exclusive lock, will be parked in flock_waiters queue
    let py_child1 = format!(
        r#"
import fcntl, time
with open("{}", "r+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    f.write("child1_acquired\n")
    f.flush()
    time.sleep(0.1)
    fcntl.flock(f, fcntl.LOCK_UN)
"#,
        file_path.display()
    );

    let mut child1 = std::process::Command::new("python3")
        .arg("-c")
        .arg(&py_child1)
        .spawn()
        .unwrap();

    // Ensure child 1 has reached FUSE and is parked in the waiter queue
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        child1.try_wait().unwrap(),
        None,
        "Child 1 should be parked waiting for exclusive lock"
    );

    // 3. Child 2: Attempts blocking shared lock, will be parked behind child1 in the waiter queue
    let py_child2 = format!(
        r#"
import fcntl
with open("{}", "r") as f:
    fcntl.flock(f, fcntl.LOCK_SH)
    content = f.read()
    assert "child1_acquired" in content
    fcntl.flock(f, fcntl.LOCK_UN)
"#,
        file_path.display()
    );

    let mut child2 = std::process::Command::new("python3")
        .arg("-c")
        .arg(&py_child2)
        .spawn()
        .unwrap();

    // Verify both child1 and child2 are blocked and parked in the in-memory queue
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        child1.try_wait().unwrap(),
        None,
        "Child 1 should be parked waiting for exclusive lock"
    );
    assert_eq!(
        child2.try_wait().unwrap(),
        None,
        "Child 2 should be parked waiting behind Child 1"
    );

    // 4. Unlock f1 -> wakes child1 from queue -> child1 writes and unlocks -> wakes child2
    let ret_un = unsafe { libc::flock(f1.as_raw_fd(), libc::LOCK_UN) };
    assert_eq!(ret_un, 0, "flock(f1, LOCK_UN) should succeed");

    let status1 = child1.wait().unwrap();
    assert!(
        status1.success(),
        "Child 1 should acquire exclusive lock, write, and exit successfully"
    );

    let status2 = child2.wait().unwrap();
    assert!(
        status2.success(),
        "Child 2 should acquire shared lock and verify content written by Child 1"
    );

    // 5. Test POSIX byte range parking across non-overlapping and overlapping ranges
    let mut fl1: libc::flock = unsafe { std::mem::zeroed() };
    fl1.l_type = libc::F_WRLCK as i16;
    fl1.l_whence = libc::SEEK_SET as i16;
    fl1.l_start = 0;
    fl1.l_len = 100;

    let ret_p1 = unsafe { libc::fcntl(f1.as_raw_fd(), libc::F_SETLK, &fl1) };
    assert_eq!(ret_p1, 0, "Parent acquires write lock on [0..100)");

    // Child 3 locks non-overlapping range [200..300) -> should acquire immediately despite parent's lock
    let py_child3 = format!(
        r#"
import fcntl
with open("{}", "r+") as f:
    fcntl.lockf(f, fcntl.LOCK_EX, 100, 200, 0)
    fcntl.lockf(f, fcntl.LOCK_UN, 100, 200, 0)
"#,
        file_path.display()
    );
    let mut child3 = std::process::Command::new("python3")
        .arg("-c")
        .arg(&py_child3)
        .spawn()
        .unwrap();
    let status3 = child3.wait().unwrap();
    assert!(
        status3.success(),
        "Non-overlapping range lock should succeed immediately without waiting"
    );

    // Child 4 locks overlapping range [50..150) -> should be parked in range_lock_waiters
    let py_child4 = format!(
        r#"
import fcntl
with open("{}", "r+") as f:
    fcntl.lockf(f, fcntl.LOCK_EX, 100, 50, 0)
    fcntl.lockf(f, fcntl.LOCK_UN, 100, 50, 0)
"#,
        file_path.display()
    );
    let mut child4 = std::process::Command::new("python3")
        .arg("-c")
        .arg(&py_child4)
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        child4.try_wait().unwrap(),
        None,
        "Child 4 should be parked on overlapping range [50..150)"
    );

    // Parent unlocks [0..100) -> wakes Child 4
    fl1.l_type = libc::F_UNLCK as i16;
    let ret_un_p = unsafe { libc::fcntl(f1.as_raw_fd(), libc::F_SETLK, &fl1) };
    assert_eq!(ret_un_p, 0);

    let status4 = child4.wait().unwrap();
    assert!(
        status4.success(),
        "Child 4 should unblock and succeed after parent unlocks overlapping range"
    );

    drop(f1);
    mount.unmount();
}

#[test]
fn test_special_file_types_and_recovery() {
    use std::os::unix::net::UnixListener;

    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new().prefix("appendfs_spec_log_").tempdir().unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let mut fs_instance = appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new().prefix("appendfs_spec_mnt_").tempdir().unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // 1.1 Create FIFO via mkfifo
    let fifo_path = mount_path.join("test_fifo");
    let c_fifo = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
    let ret = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) };
    assert_eq!(ret, 0, "mkfifo should succeed");

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat = unsafe { libc::lstat(c_fifo.as_ptr(), &mut st) };
    assert_eq!(ret_stat, 0);
    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFIFO);
    assert_eq!(st.st_mode & 0o777, 0o644);
    assert_eq!(st.st_nlink, 1);
    assert_eq!(st.st_size, 0);

    // 1.2 Create UNIX Domain Socket via bind()
    let sock_path = mount_path.join("test_sock.sock");
    let listener = UnixListener::bind(&sock_path).expect("UnixListener::bind should succeed");
    drop(listener);

    let c_sock = std::ffi::CString::new(sock_path.to_str().unwrap()).unwrap();
    let mut st_sock: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat_sock = unsafe { libc::lstat(c_sock.as_ptr(), &mut st_sock) };
    assert_eq!(ret_stat_sock, 0);
    assert_eq!(st_sock.st_mode & libc::S_IFMT, libc::S_IFSOCK);
    assert_eq!(st_sock.st_nlink, 1);

    // 1.3 Hardlink FIFO
    let linked_fifo_path = mount_path.join("linked_fifo");
    fs::hard_link(&fifo_path, &linked_fifo_path).unwrap();

    let mut st_link: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat_link = unsafe { libc::lstat(c_fifo.as_ptr(), &mut st_link) };
    assert_eq!(ret_stat_link, 0);
    assert_eq!(st_link.st_nlink, 2);

    // 1.4 Rename socket
    let renamed_sock_path = mount_path.join("renamed_sock.sock");
    fs::rename(&sock_path, &renamed_sock_path).unwrap();
    assert!(!sock_path.exists());
    assert!(renamed_sock_path.exists());

    // 1.5 Flush and unmount
    mount.unmount();

    // 2. Recover filesystem and verify special nodes survived
    let recovered_fs = appendfs::log::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("recover_fs should succeed");
    let remount_dir = tempfile::Builder::new()
        .prefix("appendfs_spec_remount_")
        .tempdir()
        .unwrap();
    let log_dir_keep = tempfile::tempdir().unwrap();

    let remount = TestMount::mount_custom(log_dir_keep, remount_dir, recovered_fs, false);
    let remount_path = remount.path().to_path_buf();

    // Verify FIFO
    let fifo_path = remount_path.join("test_fifo");
    let c_fifo = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat = unsafe { libc::lstat(c_fifo.as_ptr(), &mut st) };
    assert_eq!(ret_stat, 0);
    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFIFO);
    assert_eq!(st.st_nlink, 2);

    // Verify linked FIFO
    let linked_fifo_path = remount_path.join("linked_fifo");
    let c_linked = std::ffi::CString::new(linked_fifo_path.to_str().unwrap()).unwrap();
    let mut st_l: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat_l = unsafe { libc::lstat(c_linked.as_ptr(), &mut st_l) };
    assert_eq!(ret_stat_l, 0);
    assert_eq!(st_l.st_ino, st.st_ino);

    // Verify renamed socket
    let renamed_sock_path = remount_path.join("renamed_sock.sock");
    let c_sock = std::ffi::CString::new(renamed_sock_path.to_str().unwrap()).unwrap();
    let mut st_s: libc::stat = unsafe { std::mem::zeroed() };
    let ret_stat_s = unsafe { libc::lstat(c_sock.as_ptr(), &mut st_s) };
    assert_eq!(ret_stat_s, 0);
    assert_eq!(st_s.st_mode & libc::S_IFMT, libc::S_IFSOCK);

    // Unlink one FIFO link and verify nlink decrements
    fs::remove_file(&fifo_path).unwrap();
    let mut st_after: libc::stat = unsafe { std::mem::zeroed() };
    let ret_after = unsafe { libc::lstat(c_linked.as_ptr(), &mut st_after) };
    assert_eq!(ret_after, 0);
    assert_eq!(st_after.st_nlink, 1);
}

fn sys_setxattr(path: &std::path::Path, name: &str, value: &[u8], flags: i32) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let c_name = std::ffi::CString::new(name).unwrap();
    let res = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            flags,
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn sys_getxattr(path: &std::path::Path, name: &str) -> std::io::Result<Vec<u8>> {
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let c_name = std::ffi::CString::new(name).unwrap();
    let sz = unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if sz < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u8; sz as usize];
    let res = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(res as usize);
    Ok(buf)
}

fn sys_listxattr(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let sz = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if sz < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if sz == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; sz as usize];
    let res = unsafe { libc::listxattr(c_path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(res as usize);
    let mut list = Vec::new();
    for chunk in buf.split(|&b| b == 0) {
        if !chunk.is_empty() {
            list.push(String::from_utf8_lossy(chunk).to_string());
        }
    }
    Ok(list)
}

fn sys_removexattr(path: &std::path::Path, name: &str) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let c_name = std::ffi::CString::new(name).unwrap();
    let res = unsafe { libc::removexattr(c_path.as_ptr(), c_name.as_ptr()) };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn test_xattr_fuse_crud_and_crash_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs_instance = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_mnt_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    let file_path = mount_path.join("doc.txt");
    fs::write(&file_path, b"document content").unwrap();

    // 1. Initial get / list on file with no xattrs
    assert_eq!(
        sys_getxattr(&file_path, "user.comment").unwrap_err().raw_os_error(),
        Some(libc::ENODATA)
    );
    assert_eq!(sys_listxattr(&file_path).unwrap(), Vec::<String>::new());

    // 2. Set multiple xattrs (string, binary)
    sys_setxattr(&file_path, "user.comment", b"hello appendfs", 0).unwrap();
    let binary_data = vec![0x00, 0xff, 0x42, 0x13, 0x37, 0xca, 0xfe];
    sys_setxattr(&file_path, "user.binary", &binary_data, 0).unwrap();
    sys_setxattr(&file_path, "user.author", b"antigravity", libc::XATTR_CREATE).unwrap();

    // 3. Flags validation: XATTR_CREATE on existing fails with EEXIST
    assert_eq!(
        sys_setxattr(&file_path, "user.author", b"duplicate", libc::XATTR_CREATE)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );

    // 4. Verify get and list
    assert_eq!(sys_getxattr(&file_path, "user.comment").unwrap(), b"hello appendfs");
    assert_eq!(sys_getxattr(&file_path, "user.binary").unwrap(), binary_data);
    assert_eq!(sys_getxattr(&file_path, "user.author").unwrap(), b"antigravity");

    let mut attrs = sys_listxattr(&file_path).unwrap();
    attrs.sort();
    assert_eq!(attrs, vec!["user.author", "user.binary", "user.comment"]);

    // 5. Update and remove
    sys_setxattr(&file_path, "user.comment", b"updated comment", libc::XATTR_REPLACE).unwrap();
    sys_removexattr(&file_path, "user.author").unwrap();

    assert_eq!(
        sys_getxattr(&file_path, "user.author").unwrap_err().raw_os_error(),
        Some(libc::ENODATA)
    );
    assert_eq!(sys_getxattr(&file_path, "user.comment").unwrap(), b"updated comment");

    // Unmount and flush to log
    mount.unmount();

    // 6. Recover filesystem from log files
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("recovery should succeed");
    let remount_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_remount_")
        .tempdir()
        .unwrap();
    let log_dir_keep = tempfile::tempdir().unwrap();
    let remount = TestMount::mount_custom(log_dir_keep, remount_dir, recovered_fs, false);
    let remount_path = remount.path().to_path_buf();

    let recovered_file = remount_path.join("doc.txt");
    assert_eq!(
        sys_getxattr(&recovered_file, "user.comment").unwrap(),
        b"updated comment"
    );
    assert_eq!(sys_getxattr(&recovered_file, "user.binary").unwrap(), binary_data);
    assert_eq!(
        sys_getxattr(&recovered_file, "user.author").unwrap_err().raw_os_error(),
        Some(libc::ENODATA)
    );

    let mut recovered_attrs = sys_listxattr(&recovered_file).unwrap();
    recovered_attrs.sort();
    assert_eq!(recovered_attrs, vec!["user.binary", "user.comment"]);
}

#[test]
fn test_xattr_on_directories_and_special_files() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_dir_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs_instance = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_dir_mnt_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // 1. Directory xattrs
    let dir_path = mount_path.join("test_dir");
    fs::create_dir(&dir_path).unwrap();

    sys_setxattr(&dir_path, "user.folder_tag", b"photos_2026", 0).unwrap();
    assert_eq!(sys_getxattr(&dir_path, "user.folder_tag").unwrap(), b"photos_2026");
    assert_eq!(sys_listxattr(&dir_path).unwrap(), vec!["user.folder_tag"]);

    // 2. Symlink creation & directory recovery
    let target_path = dir_path.join("target.txt");
    fs::write(&target_path, b"target file").unwrap();

    mount.unmount();

    // Recover and verify directory xattr persisted
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("recovery should succeed");
    let remount_dir = tempfile::Builder::new()
        .prefix("appendfs_xattr_dir_remount_")
        .tempdir()
        .unwrap();
    let log_dir_keep = tempfile::tempdir().unwrap();
    let remount = TestMount::mount_custom(log_dir_keep, remount_dir, recovered_fs, false);
    let remount_path = remount.path().to_path_buf();

    let rec_dir_path = remount_path.join("test_dir");
    assert_eq!(sys_getxattr(&rec_dir_path, "user.folder_tag").unwrap(), b"photos_2026");
}

#[test]
fn test_directory_nlink_tracking_and_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_dir_nlink_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs_instance = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_dir_nlink_mnt_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // 1. Initial root directory (st_nlink == 2)
    let root_meta = fs::metadata(&mount_path).unwrap();
    assert_eq!(root_meta.nlink(), 2);

    // 2. Create subdirectories in root
    let d1 = mount_path.join("d1");
    let d2 = mount_path.join("d2");
    fs::create_dir(&d1).unwrap();
    fs::create_dir(&d2).unwrap();

    // Root should now have nlink 4 (2 + 2 subdirs), d1 and d2 have nlink 2
    assert_eq!(fs::metadata(&mount_path).unwrap().nlink(), 4);
    assert_eq!(fs::metadata(&d1).unwrap().nlink(), 2);
    assert_eq!(fs::metadata(&d2).unwrap().nlink(), 2);

    // 3. Create nested subdirectory in d1
    let sub = d1.join("sub");
    fs::create_dir(&sub).unwrap();
    assert_eq!(fs::metadata(&d1).unwrap().nlink(), 3);

    // 4. Move sub to d2
    let sub_in_d2 = d2.join("sub");
    fs::rename(&sub, &sub_in_d2).unwrap();
    assert_eq!(fs::metadata(&d1).unwrap().nlink(), 2);
    assert_eq!(fs::metadata(&d2).unwrap().nlink(), 3);

    // 5. Unmount and recover
    mount.unmount();

    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .expect("recovery should succeed");
    let remount_dir = tempfile::Builder::new()
        .prefix("appendfs_dir_nlink_remount_")
        .tempdir()
        .unwrap();
    let log_dir_keep = tempfile::tempdir().unwrap();
    let remount = TestMount::mount_custom(log_dir_keep, remount_dir, recovered_fs, false);
    let remount_path = remount.path().to_path_buf();

    // Verify link counts on remount
    assert_eq!(fs::metadata(&remount_path).unwrap().nlink(), 4);
    assert_eq!(fs::metadata(remount_path.join("d1")).unwrap().nlink(), 2);
    assert_eq!(fs::metadata(remount_path.join("d2")).unwrap().nlink(), 3);
    assert_eq!(fs::metadata(remount_path.join("d2/sub")).unwrap().nlink(), 2);
}

#[test]
fn test_special_permission_bits_live_folded_and_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_perm_bits_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));
    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            1024 * 1024,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    // 1. Create file and directory
    let dir_ino = appendfs::operations::dir::mkdir_core(&fs, 1, "test_dir", 0o755, 1000, 1000)
        .unwrap()
        .ino;
    let file_ino = appendfs::operations::read_write::create_core(&fs, 1, "test_file.bin", 0o644, 0, 1000, 1000)
        .unwrap()
        .ino;

    // 2. chmod with setuid + setgid (0o6755) on file
    let attr1 = appendfs::operations::read_write::setattr_core(
        &fs,
        file_ino,
        0o6755,
        0,
        0,
        0,
        clock.now(),
        clock.now(),
        appendfs::operations::read_write::FUSE_SET_ATTR_MODE,
    )
    .unwrap();
    assert_eq!(
        attr1.perm, 0o6755,
        "Immediate setattr return must retain special permission bits"
    );

    // Check live get_attr (while delta is unfolded in live)
    let live_attr = fs.get_attr(file_ino).unwrap();
    assert_eq!(
        live_attr.perm, 0o6755,
        "Live get_attr before flush must retain special permission bits"
    );

    // Set sticky bit (0o1755) on directory
    let dir_attr1 = appendfs::operations::read_write::setattr_core(
        &fs,
        dir_ino,
        0o1755,
        0,
        0,
        0,
        clock.now(),
        clock.now(),
        appendfs::operations::read_write::FUSE_SET_ATTR_MODE,
    )
    .unwrap();
    assert_eq!(
        dir_attr1.perm, 0o1755,
        "Immediate directory setattr return must retain sticky bit"
    );
    assert_eq!(
        fs.get_attr(dir_ino).unwrap().perm,
        0o1755,
        "Live directory get_attr must retain sticky bit"
    );

    // 3. Flush log (folds delta into base)
    fs.quiesce().unwrap();

    let folded_file = fs.get_attr(file_ino).unwrap();
    let folded_dir = fs.get_attr(dir_ino).unwrap();
    assert_eq!(
        folded_file.perm, 0o6755,
        "Folded base file must retain special permission bits"
    );
    assert_eq!(folded_dir.perm, 0o1755, "Folded base directory must retain sticky bit");

    // 4. Recover from log and verify
    let recovered = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let rec_file = recovered.get_attr(file_ino).unwrap();
    let rec_dir = recovered.get_attr(dir_ino).unwrap();
    assert_eq!(
        rec_file.perm, 0o6755,
        "Recovered file must retain special permission bits"
    );
    assert_eq!(rec_dir.perm, 0o1755, "Recovered directory must retain sticky bit");

    // 5. Export summary snapshot and recover from summary
    let summary_dir = tempfile::tempdir().unwrap();
    let sum_storage: Arc<dyn Storage> = Arc::new(OsStorage::new(summary_dir.path()));
    let summary_file = recovered.export_summary(sum_storage.as_ref()).unwrap();
    let summary_path = summary_dir.path().join(&summary_file);
    assert!(summary_path.exists());

    let summary_recovered = appendfs::recover_fs(
        sum_storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let sum_file = summary_recovered.get_attr(file_ino).unwrap();
    let sum_dir = summary_recovered.get_attr(dir_ino).unwrap();
    assert_eq!(
        sum_file.perm, 0o6755,
        "Summary-recovered file must retain special permission bits"
    );
    assert_eq!(
        sum_dir.perm, 0o1755,
        "Summary-recovered directory must retain sticky bit"
    );
}

fn sys_fallocate(path: &std::path::Path, mode: i32, offset: i64, len: i64) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    let res = unsafe { libc::fallocate(file.as_raw_fd(), mode, offset, len) };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Drives `fallocate(2)` through a real mount: the punched range has to read back as zeros
/// with the surrounding data intact, the file size must not move, unsupported modes have to
/// be refused rather than silently misapplied, and the hole has to survive recovery.
#[test]
fn test_fallocate_punch_hole_zero_range_and_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_fallocate_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&log_path));

    let writer = Arc::new(
        appendfs::LogWriter::create(
            storage.clone(),
            1,
            &*clock,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    let fs_instance = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_fallocate_mnt_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    let file_path = mount_path.join("holey.bin");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251 + 1) as u8).collect();
    fs::write(&file_path, &payload).unwrap();
    assert_eq!(fs::metadata(&file_path).unwrap().len(), 4096);

    // 1. Punch a hole in the middle. Size must not move; the range reads as zeros.
    sys_fallocate(
        &file_path,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        1024,
        1024,
    )
    .unwrap();

    assert_eq!(
        fs::metadata(&file_path).unwrap().len(),
        4096,
        "punching must not change the file size"
    );
    let after_punch = fs::read(&file_path).unwrap();
    assert_eq!(&after_punch[..1024], &payload[..1024], "data before the hole");
    assert!(
        after_punch[1024..2048].iter().all(|&b| b == 0),
        "punched range must read as zeros"
    );
    assert_eq!(&after_punch[2048..], &payload[2048..], "data after the hole");

    // 2. PUNCH_HOLE without KEEP_SIZE must be refused rather than treated as a plain
    //    punch. `vfs_fallocate` screens this pairing before the request reaches FUSE and
    //    answers EOPNOTSUPP, so the filesystem's own EINVAL is only reachable by calling
    //    `fallocate_core` directly - covered by a unit test. Accept either here.
    let unpaired_err = sys_fallocate(&file_path, libc::FALLOC_FL_PUNCH_HOLE, 0, 512).unwrap_err();
    assert!(
        matches!(unpaired_err.raw_os_error(), Some(libc::EOPNOTSUPP) | Some(libc::EINVAL)),
        "PUNCH_HOLE without KEEP_SIZE should be refused, got {:?}",
        unpaired_err
    );

    // 3. COLLAPSE_RANGE shifts file contents, which this filesystem does not implement.
    //    Refusing is spec-legal; silently ignoring the flag would corrupt data.
    let collapse_err = sys_fallocate(&file_path, libc::FALLOC_FL_COLLAPSE_RANGE, 0, 512).unwrap_err();
    assert!(
        matches!(collapse_err.raw_os_error(), Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)),
        "COLLAPSE_RANGE should be refused, got {:?}",
        collapse_err
    );

    // 4. ZERO_RANGE over live data zeroes it, and past EOF it grows the file.
    sys_fallocate(&file_path, libc::FALLOC_FL_ZERO_RANGE, 3072, 2048).unwrap();
    assert_eq!(
        fs::metadata(&file_path).unwrap().len(),
        5120,
        "ZERO_RANGE past EOF must extend the file"
    );
    let after_zero = fs::read(&file_path).unwrap();
    assert!(
        after_zero[3072..5120].iter().all(|&b| b == 0),
        "zeroed range must read as zeros"
    );
    assert_eq!(
        &after_zero[2048..3072],
        &payload[2048..3072],
        "data before the zeroed range"
    );

    // 5. Plain allocation cannot reserve space here, but must still extend the file.
    sys_fallocate(&file_path, 0, 5120, 1024).unwrap();
    assert_eq!(fs::metadata(&file_path).unwrap().len(), 6144);

    let before_unmount = fs::read(&file_path).unwrap();
    mount.unmount();

    // 6. All of it has to survive replay - a dropped hole would resurrect the old bytes.
    let recovered_fs = appendfs::recover_fs(
        storage,
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    )
    .unwrap();
    let ino = recovered_fs.lookup_child(1, "holey.bin").expect("file must survive");
    let recovered = recovered_fs.read_file_data(ino, 0, 6144).unwrap();
    assert_eq!(recovered.len(), 6144);
    assert_eq!(recovered, before_unmount, "content must be identical after recovery");
}

/// A volume whose summaries all fail to open must be refused, not silently rebuilt empty.
///
/// Skipping a bad summary is only safe while another still describes the volume. When none
/// can be read the state is unknown, and continuing produces an empty filesystem that
/// `check` then pronounces healthy - which is exactly what an on-disk format change looks
/// like from here, since older bytes remain a valid encoding of different values.
#[test]
fn test_recovery_refuses_a_volume_with_no_readable_summary() {
    let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();

    // Truncate the only summary so it cannot be opened at all. Truncation is used rather
    // than a corrupted field because it fails the same way regardless of which fields a
    // given build validates - the guard under test is about there being no readable summary,
    // not about why any particular one failed.
    let bytes = storage.get_file_bytes("000000.summary").unwrap();
    storage.insert_file("000000.summary", bytes[..16].to_vec());

    let Err(err) = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        std::sync::Arc::new(appendfs::SystemClock),
        appendfs::VolumeKey::plaintext_arc(),
    ) else {
        panic!("recovery must refuse a volume it cannot describe");
    };
    assert!(
        err.to_string().contains("none could be read"),
        "unexpected error: {}",
        err
    );

    // A volume with no summaries at all is a different case and must still work: there is
    // nothing to contradict, so recovery legitimately starts from empty.
    let fresh_storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    assert!(
        appendfs::recover_fs(
            fresh_storage,
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .is_ok(),
        "an empty directory has no state to contradict"
    );
}

#[test]
fn test_encrypted_volume_lifecycle_and_raw_disk_verification() {
    let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    let master_key = appendfs::crypto::MasterKey::new([0x42u8; 32]);

    // 1. Initialize encrypted volume
    let (volume_header, volume_key) = appendfs::crypto::VolumeHeader::new_encrypted(
        &master_key,
        [0x11u8; 16],
        appendfs::crypto::KeySource::KeyFile,
        appendfs::compress::Compression::None,
    )
    .unwrap();
    appendfs::log::init_volume(storage.clone(), &volume_key, volume_header).unwrap();

    let unlocked_arc = std::sync::Arc::new(volume_key);

    // 2. Open writer and append sensitive data
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            unlocked_arc.clone(),
        )
        .unwrap();

        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(
                storage.clone(),
                1,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                unlocked_arc.clone(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);

        let file_attr =
            appendfs::operations::read_write::create_core(&fs, 1, "confidential.txt", 0o600, 0, 1000, 1000).unwrap();
        let secret = b"TOP_SECRET_CREDENTIALS_AND_PAYLOAD_987654321";
        appendfs::operations::read_write::write_core(&fs, file_attr.ino, secret, 0).unwrap();

        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();
    }

    // 3. Raw Disk Inspection: Verify zero plaintext leaks on disk!
    let raw_log = storage.get_file_bytes("000001.log").unwrap();
    let secret = b"TOP_SECRET_CREDENTIALS_AND_PAYLOAD_987654321";
    let filename = b"confidential.txt";
    assert!(
        !raw_log.windows(secret.len()).any(|w| w == secret),
        "Plaintext data leaked into raw log file!"
    );
    assert!(
        !raw_log.windows(filename.len()).any(|w| w == filename),
        "Plaintext metadata/filename leaked into raw log file!"
    );

    let raw_summary = storage.get_file_bytes("000001.summary").unwrap();
    assert!(
        !raw_summary.windows(secret.len()).any(|w| w == secret),
        "Plaintext data leaked into raw summary snapshot!"
    );

    // 4. Successful recovery using correct master key
    {
        let summary_kr = appendfs::log::SummaryReader::read_volume_header(storage.as_ref(), "000001.summary").unwrap();
        let unlocked_recovered = summary_kr.unlock(&master_key).unwrap();

        let recovered = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            std::sync::Arc::new(unlocked_recovered),
        )
        .unwrap();

        let entries = recovered.list_directory(1).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "confidential.txt");

        let content = recovered.read_file_data(entries[0].1, 0, secret.len()).unwrap();
        assert_eq!(content, secret);
    }

    // 5. A wrong master key is rejected up front, and is reported as a wrong key rather
    //    than as corruption - the volume on disk is perfectly intact.
    {
        let wrong_key = appendfs::crypto::MasterKey::new([0x99u8; 32]);
        let header = appendfs::log::SummaryReader::read_volume_header(storage.as_ref(), "000001.summary").unwrap();
        assert_eq!(
            header.unlock(&wrong_key).unwrap_err(),
            appendfs::crypto::CryptoError::WrongKey
        );

        // And it surfaces as PermissionDenied, not InvalidData, so callers that map errno
        // do not tell the user their data is damaged.
        let io_err: std::io::Error = header.unlock(&wrong_key).unwrap_err().into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}

/// Tampering with a record header must be caught, not served as data.
///
/// The header sits outside the payload checksum, so it reaches the reader unauthenticated.
/// `op_code` and `inode` are therefore bound into the record's associated data: an intact
/// ciphertext relabelled onto another inode must fail to authenticate rather than graft one
/// file's contents onto another. (Records no longer carry a `key_id` at all - a per-record
/// copy of a volume-level fact was itself the downgrade vector, so it was removed rather
/// than guarded.)
#[test]
fn test_tampered_record_header_is_rejected_not_served() {
    let master_key = appendfs::crypto::MasterKey::new([0x7Eu8; 32]);
    let secret = b"PLAINTEXT_THAT_MUST_NEVER_BE_SERVED";

    let (volume_header, volume_key) = appendfs::crypto::VolumeHeader::new_encrypted(
        &master_key,
        [0x0Au8; 16],
        appendfs::crypto::KeySource::KeyFile,
        appendfs::compress::Compression::None,
    )
    .unwrap();
    let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    appendfs::log::init_volume(storage.clone(), &volume_key, volume_header).unwrap();

    let volume_key = std::sync::Arc::new(volume_key);
    let ino = {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            volume_key.clone(),
        )
        .unwrap();
        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(
                storage.clone(),
                1,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                volume_key.clone(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);

        let attr = appendfs::operations::read_write::create_core(&fs, 1, "secret.txt", 0o600, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, attr.ino, secret, 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();
        attr.ino
    };

    // Sanity check: untouched, the file reads back correctly.
    {
        let fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            volume_key.clone(),
        )
        .unwrap();
        assert_eq!(fs.read_file_data(ino, 0, secret.len()).unwrap(), secret);
    }

    // Flip a bit in every record header's `inode` field, simulating an attacker with write
    // access but no key. Layout is op_code(1) inode(8) payload_len(4) auth_tag(16).
    let mut bytes = storage.get_file_bytes("000001.log").unwrap();
    let header_size = appendfs::log::record::RECORD_HEADER_SIZE;
    let mut off = appendfs::log::record::FILE_HEADER_SIZE;
    let mut tampered = 0;
    while off + header_size <= bytes.len() {
        let payload_len = u32::from_be_bytes(bytes[off + 9..off + 13].try_into().unwrap()) as usize;
        bytes[off + 1] ^= 0x01;
        tampered += 1;
        off += header_size + payload_len;
    }
    assert!(tampered > 0, "expected records to tamper with");
    storage.insert_file("000001.log", bytes);

    // Whether it surfaces during replay or at read time, the one outcome that must never
    // happen is the secret being returned as though nothing were wrong.
    let recovered = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        std::sync::Arc::new(appendfs::SystemClock),
        volume_key.clone(),
    );

    match recovered {
        Err(_) => {}
        Ok(fs) => match fs.read_file_data(ino, 0, secret.len()) {
            Err(_) => {}
            Ok(data) => {
                assert_ne!(data.as_slice(), secret.as_slice(), "tampering served the plaintext");
                panic!(
                    "tampered header was accepted, returning {} bytes instead of an error",
                    data.len()
                );
            }
        },
    }
}

/// A volume must record which credentials open it, so a mount asks for the right thing.
///
/// Without this the CLI can only infer the credential type from which flags were passed, and
/// a wrong guess is indistinguishable from a wrong credential - both just fail the key check.
#[test]
fn test_key_source_round_trips_through_the_volume_header() {
    use appendfs::crypto::KeySource;

    for (source, needs_file, needs_pass) in [
        (KeySource::Passphrase, false, true),
        (KeySource::KeyFile, true, false),
        (KeySource::KeyFileAndPassphrase, true, true),
    ] {
        let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
        let master = appendfs::crypto::MasterKey::new([0x5Cu8; 32]);

        let (header, key) = appendfs::crypto::VolumeHeader::new_encrypted(
            &master,
            [0x11u8; 16],
            source,
            appendfs::compress::Compression::None,
        )
        .unwrap();
        assert_eq!(header.key_source.needs_key_file(), needs_file, "{:?}", source);
        assert_eq!(header.key_source.needs_passphrase(), needs_pass, "{:?}", source);

        appendfs::log::init_volume(storage.clone(), &key, header).unwrap();

        // The mode must survive the round trip through the plaintext header blob, and be
        // readable without any credential at all - that is what lets a mount know what to
        // ask for before it can ask for it.
        let read_back = appendfs::log::SummaryReader::read_volume_header(storage.as_ref(), "000000.summary").unwrap();
        assert_eq!(read_back.key_source, source);
        assert!(read_back.unlock(&master).is_ok());
    }

    // A plaintext volume reports no credential at all.
    let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    appendfs::init_volume(
        storage.clone(),
        &appendfs::VolumeKey::plaintext(),
        appendfs::VolumeHeader::plaintext(),
    )
    .unwrap();
    let read_back = appendfs::log::SummaryReader::read_volume_header(storage.as_ref(), "000000.summary").unwrap();
    assert_eq!(read_back.key_source, KeySource::None);
    assert!(!read_back.key_source.needs_key_file());
    assert!(!read_back.key_source.needs_passphrase());
}

/// An encrypted volume may not describe itself as having no key source.
#[test]
fn test_encrypted_volume_rejects_none_key_source() {
    use appendfs::crypto::KeySource;
    let master = appendfs::crypto::MasterKey::new([0x01u8; 32]);
    assert!(
        appendfs::crypto::VolumeHeader::new_encrypted(
            &master,
            [0u8; 16],
            KeySource::None,
            appendfs::compress::Compression::None
        )
        .is_err()
    );
}

/// A rewritten summary footer must produce an error, never a panic or a huge allocation.
///
/// The footer's BLAKE3 checksum carries no key, so anyone able to modify the file can
/// recompute it; every offset and count it holds is therefore attacker-controlled and has to
/// be bounds-checked before it indexes the decrypted body or sizes a buffer.
#[test]
fn test_forged_summary_offsets_error_rather_than_panic() {
    use appendfs::crypto::{KeySource, MasterKey, VolumeHeader};

    /// Rewrites `000000.summary` via `edit`, restoring the whole-file checksum so the edit
    /// gets past the bitrot check and reaches the code under test.
    fn tamper(storage: &appendfs::storage::MemoryStorage, edit: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        edit(&mut bytes);
        let n = bytes.len();
        let digest = blake3::hash(&bytes[..n - 52]);
        bytes[n - 32..].copy_from_slice(digest.as_bytes());
        storage.insert_file("000000.summary", bytes);
    }

    for (name, edit) in [
        (
            "manifest_offset past the body",
            Box::new(|b: &mut Vec<u8>| {
                let n = b.len();
                b[n - 52..n - 44].copy_from_slice(&(1u64 << 40).to_le_bytes());
            }) as Box<dyn FnOnce(&mut Vec<u8>)>,
        ),
        (
            "absurd entry_count",
            Box::new(|b: &mut Vec<u8>| {
                let n = b.len();
                b[n - 44..n - 36].copy_from_slice(&u64::MAX.to_le_bytes());
            }),
        ),
        (
            "oversized volume_header_len",
            Box::new(|b: &mut Vec<u8>| {
                b[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
            }),
        ),
    ] {
        let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
        let master = MasterKey::new([0x33u8; 32]);
        let (header, key) = VolumeHeader::new_encrypted(
            &master,
            [0x44u8; 16],
            KeySource::KeyFile,
            appendfs::compress::Compression::None,
        )
        .unwrap();
        appendfs::log::init_volume(storage.clone(), &key, header).unwrap();

        tamper(&storage, edit);

        let opened = appendfs::log::SummaryReader::open(storage.as_ref(), "000000.summary", std::sync::Arc::new(key));
        assert!(opened.is_err(), "{}: forged summary opened successfully", name);
    }
}

/// A header/key pair that disagrees must be refused rather than written.
///
/// The header is stored in plaintext while the key encrypts the body, so a mismatched pair
/// yields a summary that advertises itself as unencrypted yet cannot be reopened by the key
/// that wrote it.
#[test]
fn test_export_refuses_a_mismatched_header_and_key() {
    use appendfs::crypto::{KeySource, MasterKey, VolumeHeader};

    let storage: std::sync::Arc<dyn appendfs::storage::Storage> =
        std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
    let master = MasterKey::new([0x55u8; 32]);
    let (_header, key) = VolumeHeader::new_encrypted(
        &master,
        [0u8; 16],
        KeySource::KeyFile,
        appendfs::compress::Compression::None,
    )
    .unwrap();

    // `with_log` adopts the writer's encrypted key while the header stays at its plaintext
    // default - the pairing this guard exists to catch.
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(
            storage.clone(),
            1,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            std::sync::Arc::new(key),
        )
        .unwrap(),
    );
    let fs = appendfs::InMemoryFS::with_log(writer);

    let err = fs.export_summary(storage.as_ref()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("refusing to export an unreadable summary"),
        "unexpected error: {}",
        err
    );
}

/// Compressed records must round-trip through a real write/recover/read cycle, and must
/// actually shrink the log.
#[test]
fn test_compressed_volume_round_trips_and_saves_space() {
    use appendfs::compress::Compression;
    use appendfs::crypto::{KeySource, MasterKey, VolumeHeader};

    // Same payload written to a compressed and an uncompressed volume, so the only
    // difference in log size is the compression.
    let payload: Vec<u8> = "the quick brown fox jumps over the lazy dog. "
        .repeat(4000)
        .into_bytes();

    let mut sizes = Vec::new();
    for compression in [Compression::None, Compression::Zstd] {
        let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
        let master = MasterKey::new([0x6Bu8; 32]);
        let (header, key) =
            VolumeHeader::new_encrypted(&master, [0x77u8; 16], KeySource::KeyFile, compression).unwrap();
        appendfs::log::init_volume(storage.clone(), &key, header.clone()).unwrap();

        let key = std::sync::Arc::new(key);
        let ino = {
            let mut fs = appendfs::recover_fs(
                storage.clone(),
                appendfs::RecoveryTarget::Latest,
                std::sync::Arc::new(appendfs::SystemClock),
                key.clone(),
            )
            .unwrap();
            let writer = std::sync::Arc::new(
                appendfs::LogWriter::create_lazy(
                    storage.clone(),
                    1,
                    appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    key.clone(),
                )
                .unwrap()
                .with_compression(compression),
            );
            fs.log_writer = Some(writer);

            let attr = appendfs::operations::read_write::create_core(&fs, 1, "text.log", 0o644, 0, 1000, 1000).unwrap();
            appendfs::operations::read_write::write_core(&fs, attr.ino, &payload, 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
            attr.ino
        };

        // The setting must survive the round trip through the volume header.
        let read_back = appendfs::log::SummaryReader::read_volume_header(storage.as_ref(), "000001.summary").unwrap();
        assert_eq!(read_back.compression, compression);

        // Recovering replays records through the reader; reading pulls them through the
        // extent cache. Both have to unwrap the envelope for this to match.
        let recovered = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            std::sync::Arc::new(appendfs::SystemClock),
            key.clone(),
        )
        .unwrap();
        assert_eq!(
            recovered.read_file_data(ino, 0, payload.len()).unwrap(),
            payload,
            "{:?} did not round-trip",
            compression
        );

        sizes.push(storage.get_file_bytes("000001.log").unwrap().len() as u64);
    }

    let (uncompressed, compressed) = (sizes[0], sizes[1]);
    assert!(
        compressed * 4 < uncompressed,
        "expected a large saving on highly repetitive data, got {} -> {} bytes",
        uncompressed,
        compressed
    );
}

/// `check --verify-data` must judge an extent by the record's physical size, not its logical
/// one.
///
/// An extent's `length` is its uncompressed size and bears no fixed relation to the bytes on
/// disk: encryption adds a tag, compression can shrink megabytes to hundreds of bytes.
/// Comparing that length against the log file size called every healthy compressed volume
/// corrupt - and skipped the header and checksum verification that would have shown otherwise.
#[test]
fn test_check_verifies_compressed_volumes_without_false_positives() {
    use appendfs::compress::Compression;
    use appendfs::crypto::{KeySource, MasterKey, VolumeHeader};

    for compression in [Compression::None, Compression::Zstd] {
        let storage = std::sync::Arc::new(appendfs::storage::MemoryStorage::new());
        let master = MasterKey::new([0x31u8; 32]);
        let (header, key) =
            VolumeHeader::new_encrypted(&master, [0x32u8; 16], KeySource::KeyFile, compression).unwrap();
        appendfs::log::init_volume(storage.clone(), &key, header).unwrap();
        let key = std::sync::Arc::new(key);

        // Highly compressible, and large enough that the compressed log is orders of
        // magnitude smaller than the logical extent lengths.
        let payload: Vec<u8> = "compressible payload ".repeat(300_000).into_bytes();
        {
            let mut fs = appendfs::recover_fs(
                storage.clone(),
                appendfs::RecoveryTarget::Latest,
                std::sync::Arc::new(appendfs::SystemClock),
                key.clone(),
            )
            .unwrap();
            let writer = std::sync::Arc::new(
                appendfs::LogWriter::create_lazy(
                    storage.clone(),
                    1,
                    appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                    1,
                    key.clone(),
                )
                .unwrap()
                .with_compression(compression),
            );
            fs.log_writer = Some(writer);
            let attr = appendfs::operations::read_write::create_core(&fs, 1, "big.txt", 0o644, 0, 1000, 1000).unwrap();
            appendfs::operations::read_write::write_core(&fs, attr.ino, &payload, 0).unwrap();
            fs.quiesce().unwrap();
            fs.export_summary(storage.as_ref()).unwrap();
        }

        let report = appendfs::check_volume(storage.clone(), true, key.clone()).unwrap();
        assert!(
            report.is_clean(),
            "{:?} volume reported {} errors: {:?}",
            compression,
            report.error_count(),
            report.issues
        );

        // The check must still catch a genuinely truncated log rather than having been
        // loosened into uselessness.
        let bytes = storage.get_file_bytes("000001.log").unwrap();
        let len = bytes.len();
        storage.insert_file("000001.log", bytes[..len / 2].to_vec());

        let truncated = appendfs::check_volume(storage, true, key).unwrap();
        assert!(
            !truncated.is_clean(),
            "{:?}: truncating the log must be detected",
            compression
        );
    }
}

#[test]
fn test_periodic_summary_generation_on_log_rolls() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let key = Arc::new(appendfs::crypto::VolumeKey::plaintext());

    // 1. Initialize empty volume (creates 000000.summary)
    appendfs::init_volume(
        storage.clone(),
        key.as_ref(),
        appendfs::crypto::VolumeHeader::plaintext(),
    )
    .unwrap();

    assert!(storage.exists("000000.summary"));
    assert!(!storage.exists("000001.summary"));
    assert!(!storage.exists("000002.summary"));

    // 2. Open filesystem with small max_log_size (1000 bytes) and summary_interval_generations = 2
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::clock::SystemClock),
            key.clone(),
        )
        .unwrap();

        let writer = Arc::new(
            appendfs::LogWriter::create_lazy(
                storage.clone(),
                1,
                1000, // 1000 bytes max log size forces rapid rolling
                0,
                key.clone(),
            )
            .unwrap(),
        );

        fs.log_writer = Some(writer);
        // Configure to emit summary every 2 rolled generations (and 0 byte trigger)
        fs.set_summary_intervals(0, 2);

        // Generation 1: write file1 (1000 bytes). Total log size becomes ~1100 bytes (>= 1000).
        let file1_data = vec![0x11u8; 1000];
        let a1 = appendfs::operations::read_write::create_core(&fs, 1, "file1.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a1.ino, &file1_data, 0).unwrap();
        fs.quiesce().unwrap();

        // Generation 2: write file2 (1000 bytes). Gen 1 reached limit, causing roll to gen 2!
        // Roll 1: gen 1 is sealed. generations_since_last_summary becomes 1 (< 2). No summary yet.
        let file2_data = vec![0x22u8; 1000];
        let a2 = appendfs::operations::read_write::create_core(&fs, 1, "file2.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a2.ino, &file2_data, 0).unwrap();
        fs.quiesce().unwrap();

        assert!(
            !storage.exists("000001.summary"),
            "Gen 1 roll should not emit summary yet (threshold is 2)"
        );

        // Generation 3: write file3 (1000 bytes). Gen 2 reached limit, causing roll to gen 3!
        // Roll 2: gen 2 is sealed. generations_since_last_summary becomes 2 (>= 2).
        // 000002.summary MUST be emitted!
        let file3_data = vec![0x33u8; 1000];
        let a3 = appendfs::operations::read_write::create_core(&fs, 1, "file3.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a3.ino, &file3_data, 0).unwrap();
        fs.quiesce().unwrap();

        assert!(
            storage.exists("000002.summary"),
            "Gen 2 roll must automatically emit 000002.summary while filesystem is mounted!"
        );

        // Generation 4: write file4 (1000 bytes) in gen 3.
        let file4_data = vec![0x44u8; 1000];
        let a4 = appendfs::operations::read_write::create_core(&fs, 1, "file4.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a4.ino, &file4_data, 0).unwrap();
        fs.quiesce().unwrap();

        // Simulate sudden crash: do NOT call sync_and_export_summary()!
        // 000003.summary must NOT exist.
        assert!(!storage.exists("000003.summary"));
    }

    // 3. Crash recovery: recover_fs should find 000002.summary, fast-recover base from it, and replay gen 3!
    let recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::clock::SystemClock),
        key.clone(),
    )
    .unwrap();

    // Verify all 4 files exist and have correct contents!
    let root_entries = recovered_fs.list_directory(1).unwrap();
    let names: Vec<String> = root_entries.into_iter().map(|e| e.0).collect();
    assert!(names.contains(&"file1.bin".to_string()));
    assert!(names.contains(&"file2.bin".to_string()));
    assert!(names.contains(&"file3.bin".to_string()));
    assert!(names.contains(&"file4.bin".to_string()));

    let f1_ino = recovered_fs.lookup_child(1, "file1.bin").unwrap();
    let fh1 = appendfs::operations::read_write::open_core(&recovered_fs, f1_ino, libc::O_RDONLY as u32).unwrap();
    let buf1 = appendfs::operations::read_write::read_core(&recovered_fs, f1_ino, fh1, 0, 1000)
        .unwrap()
        .into_bytes()
        .unwrap();
    appendfs::operations::read_write::release_core(&recovered_fs, f1_ino, fh1).unwrap();
    assert_eq!(buf1, vec![0x11u8; 1000]);

    let f4_ino = recovered_fs.lookup_child(1, "file4.bin").unwrap();
    let fh4 = appendfs::operations::read_write::open_core(&recovered_fs, f4_ino, libc::O_RDONLY as u32).unwrap();
    let buf4 = appendfs::operations::read_write::read_core(&recovered_fs, f4_ino, fh4, 0, 1000)
        .unwrap()
        .into_bytes()
        .unwrap();
    appendfs::operations::read_write::release_core(&recovered_fs, f4_ino, fh4).unwrap();
    assert_eq!(buf4, vec![0x44u8; 1000]);
}

#[test]
fn test_periodic_summary_generation_by_bytes() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let key = Arc::new(appendfs::crypto::VolumeKey::plaintext());

    appendfs::init_volume(
        storage.clone(),
        key.as_ref(),
        appendfs::crypto::VolumeHeader::plaintext(),
    )
    .unwrap();

    // Configure 2500 bytes threshold and 1000 max log size
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::clock::SystemClock),
            key.clone(),
        )
        .unwrap();

        let writer = Arc::new(appendfs::LogWriter::create_lazy(storage.clone(), 1, 1000, 0, key.clone()).unwrap());

        fs.log_writer = Some(writer);
        // Byte threshold = 2500, generations threshold = 0 (disabled)
        fs.set_summary_intervals(2500, 0);

        // 1. Write file1 (1000 bytes). Gen 1.
        let a1 = appendfs::operations::read_write::create_core(&fs, 1, "f1.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a1.ino, &vec![1u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();

        // 2. Write file2 (1000 bytes). Rolls to gen 2. bytes_since = 1000 (< 2500). No summary.
        let a2 = appendfs::operations::read_write::create_core(&fs, 1, "f2.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a2.ino, &vec![2u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();
        assert!(!storage.exists("000001.summary"));

        // 3. Write file3 (1000 bytes). Rolls to gen 3. bytes_since = 2000 (< 2500). No summary.
        let a3 = appendfs::operations::read_write::create_core(&fs, 1, "f3.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a3.ino, &vec![3u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();
        assert!(!storage.exists("000002.summary"));

        // 4. Write file4 (1000 bytes). Rolls to gen 4. bytes_since = 3000 (>= 2500).
        // 000003.summary must be emitted!
        let a4 = appendfs::operations::read_write::create_core(&fs, 1, "f4.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a4.ino, &vec![4u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();
        assert!(
            storage.exists("000003.summary"),
            "Gen 3 roll must automatically emit 000003.summary based on byte threshold!"
        );
    }

    let recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::clock::SystemClock),
        key.clone(),
    )
    .unwrap();

    let root_entries = recovered_fs.list_directory(1).unwrap();
    let names: Vec<String> = root_entries.into_iter().map(|e| e.0).collect();
    assert!(names.contains(&"f1.bin".to_string()));
    assert!(names.contains(&"f2.bin".to_string()));
    assert!(names.contains(&"f3.bin".to_string()));
    assert!(names.contains(&"f4.bin".to_string()));
}

#[test]
fn test_recovered_fs_restores_summary_counters_and_emits_early_summary() {
    use std::sync::atomic::Ordering;

    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let key = Arc::new(appendfs::crypto::VolumeKey::plaintext());

    appendfs::init_volume(
        storage.clone(),
        key.as_ref(),
        appendfs::crypto::VolumeHeader::plaintext(),
    )
    .unwrap();

    // 1. Session 1: configure max_log_size = 1000 bytes.
    // Write 1000 bytes in gen 1, export 000001.summary.
    // Then write 1000 bytes in gen 2 and 1000 bytes in gen 3 without exporting a summary.
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::clock::SystemClock),
            key.clone(),
        )
        .unwrap();

        let writer = Arc::new(appendfs::LogWriter::create_lazy(storage.clone(), 1, 1000, 0, key.clone()).unwrap());
        fs.log_writer = Some(writer);

        let a1 = appendfs::operations::read_write::create_core(&fs, 1, "f1.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a1.ino, &vec![1u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();

        // Export summary for gen 1
        fs.export_summary(storage.as_ref()).unwrap();
        assert!(storage.exists("000001.summary"));

        // Gen 2: write 1000 bytes in f2.bin, causing roll to gen 2
        let a2 = appendfs::operations::read_write::create_core(&fs, 1, "f2.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a2.ino, &vec![2u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();

        // Gen 3: write 1000 bytes in f3.bin, causing roll to gen 3
        let a3 = appendfs::operations::read_write::create_core(&fs, 1, "f3.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a3.ino, &vec![3u8; 1000], 0).unwrap();
        // Drop fs and writer to release lock, then remove 000003.summary (emitted on clean drop) to simulate crash
        drop(fs);
    }
    if storage.exists("000003.summary") {
        storage.remove_file("000003.summary").unwrap();
    }

    // At this point:
    // 000001.summary exists.
    // 000002.log has 1000 bytes of data.
    // 000003.log has 1000 bytes of data.
    // Neither 000002.summary nor 000003.summary exists.
    assert!(storage.exists("000001.summary"));
    assert!(!storage.exists("000002.summary"));
    assert!(!storage.exists("000003.summary"));

    // 2. Recover filesystem
    let mut recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::clock::SystemClock),
        key.clone(),
    )
    .unwrap();

    // Verify last_summary_generation is 1
    assert_eq!(recovered_fs.last_summary_generation.load(Ordering::SeqCst), 1);
    // Verify generations_since_last_summary is 2 (gens 2 and 3 replayed)
    assert_eq!(
        recovered_fs.generations_since_last_summary.load(Ordering::SeqCst),
        2,
        "generations_since_last_summary must be restored from replayed logs"
    );
    // Verify bytes_since_last_summary is 2000 (1000 bytes in gen 2 + 1000 bytes in gen 3)
    assert_eq!(
        recovered_fs.bytes_since_last_summary.load(Ordering::SeqCst),
        2000,
        "bytes_since_last_summary must be restored from replayed data"
    );

    // 3. Mount RW for Session 2 on generation 4 with summary_interval_bytes = 2500
    // Because 2000 bytes were already recovered from logs, writing 1000 bytes in gen 4
    // will push bytes_since to 3000 >= 2500, triggering an early summary on gen 4's roll!
    let next_gen = recovered_fs.next_generation();
    assert_eq!(next_gen, 4);

    let start_batch_id = recovered_fs.last_batch_id.load(Ordering::SeqCst) + 1;
    let writer2 = Arc::new(
        appendfs::LogWriter::create_lazy(storage.clone(), next_gen, 1000, start_batch_id, key.clone()).unwrap(),
    );
    recovered_fs.log_writer = Some(writer2);
    recovered_fs.set_summary_intervals(2500, 0);

    // Write file4 in gen 4 (1000 bytes). Gen 4 is opened and committed.
    let a4 = appendfs::operations::read_write::create_core(&recovered_fs, 1, "f4.bin", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&recovered_fs, a4.ino, &vec![4u8; 1000], 0).unwrap();
    recovered_fs.quiesce().unwrap();

    // Now write file5 in gen 5 (1000 bytes), which forces gen 4 to roll (gen 4 reached limit 1000).
    // On gen 4 roll:
    // bytes_since was 2000 (recovered) + 1000 (gen 4) = 3000 >= 2500!
    // 000004.summary MUST be emitted!
    let a5 = appendfs::operations::read_write::create_core(&recovered_fs, 1, "f5.bin", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&recovered_fs, a5.ino, &vec![5u8; 1000], 0).unwrap();
    recovered_fs.quiesce().unwrap();

    assert!(
        storage.exists("000004.summary"),
        "000004.summary must be emitted because recovered bytes (2000) + gen 4 (1000) = 3000 >= 2500"
    );
    assert_eq!(recovered_fs.last_summary_generation.load(Ordering::SeqCst), 4);
    assert_eq!(recovered_fs.bytes_since_last_summary.load(Ordering::SeqCst), 1000); // 1000 from f5.bin in gen 5
    drop(recovered_fs);
}

#[test]
fn test_recovered_fs_restores_generation_counter_and_emits_early_summary() {
    use std::sync::atomic::Ordering;

    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let key = Arc::new(appendfs::crypto::VolumeKey::plaintext());

    appendfs::init_volume(
        storage.clone(),
        key.as_ref(),
        appendfs::crypto::VolumeHeader::plaintext(),
    )
    .unwrap();

    // 1. Session 1: export 000001.summary, then roll to gen 2 and gen 3.
    {
        let mut fs = appendfs::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::clock::SystemClock),
            key.clone(),
        )
        .unwrap();

        let writer = Arc::new(appendfs::LogWriter::create_lazy(storage.clone(), 1, 1000, 0, key.clone()).unwrap());
        fs.log_writer = Some(writer);

        let a1 = appendfs::operations::read_write::create_core(&fs, 1, "f1.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a1.ino, &vec![1u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();

        fs.export_summary(storage.as_ref()).unwrap();
        assert!(storage.exists("000001.summary"));

        // Gen 2
        let a2 = appendfs::operations::read_write::create_core(&fs, 1, "f2.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a2.ino, &vec![2u8; 1000], 0).unwrap();
        fs.quiesce().unwrap();

        // Gen 3
        let a3 = appendfs::operations::read_write::create_core(&fs, 1, "f3.bin", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, a3.ino, &vec![3u8; 1000], 0).unwrap();

        drop(fs);
    }
    if storage.exists("000003.summary") {
        storage.remove_file("000003.summary").unwrap();
    }

    // 2. Recover filesystem
    let mut recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        Arc::new(appendfs::clock::SystemClock),
        key.clone(),
    )
    .unwrap();

    assert_eq!(recovered_fs.last_summary_generation.load(Ordering::SeqCst), 1);
    assert_eq!(
        recovered_fs.generations_since_last_summary.load(Ordering::SeqCst),
        2,
        "generations_since_last_summary must be 2 (gens 2 and 3 replayed)"
    );

    // 3. Mount Session 2 with summary_interval_generations = 3 (and 0 byte trigger)
    let next_gen = recovered_fs.next_generation();
    assert_eq!(next_gen, 4);

    let start_batch_id = recovered_fs.last_batch_id.load(Ordering::SeqCst) + 1;
    let writer2 = Arc::new(
        appendfs::LogWriter::create_lazy(storage.clone(), next_gen, 1000, start_batch_id, key.clone()).unwrap(),
    );
    recovered_fs.log_writer = Some(writer2);
    recovered_fs.set_summary_intervals(0, 3);

    // Write file4 in gen 4
    let a4 = appendfs::operations::read_write::create_core(&recovered_fs, 1, "f4.bin", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&recovered_fs, a4.ino, &vec![4u8; 1000], 0).unwrap();
    recovered_fs.quiesce().unwrap();

    // Write file5 in gen 5 (rolls gen 4). gens_since becomes 2 (recovered) + 1 (gen 4) = 3 >= 3!
    let a5 = appendfs::operations::read_write::create_core(&recovered_fs, 1, "f5.bin", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&recovered_fs, a5.ino, &vec![5u8; 1000], 0).unwrap();
    recovered_fs.quiesce().unwrap();

    assert!(
        storage.exists("000004.summary"),
        "000004.summary must be emitted because recovered gens (2) + gen 4 (1) = 3 >= 3"
    );
    assert_eq!(recovered_fs.last_summary_generation.load(Ordering::SeqCst), 4);
    assert_eq!(recovered_fs.generations_since_last_summary.load(Ordering::SeqCst), 1); // 1 from f5.bin rolling gen 5

    drop(recovered_fs);
}

#[test]
fn test_fuse_async_read_concurrency() {
    use std::io::{Read, Seek, SeekFrom};

    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    // 1. Prepare deterministic patterned test datasets exceeding 128 KiB (LARGE_READ_THRESHOLD)
    let pattern_256k: Vec<u8> = (0..(256 * 1024)).map(|i| ((i * 31 + 17) % 251) as u8).collect();
    let pattern_384k: Vec<u8> = (0..(384 * 1024)).map(|i| ((i * 37 + 19) % 251) as u8).collect();

    let path_256k = mount_path.join("large_256k.bin");
    let path_384k = mount_path.join("large_384k.bin");
    let path_sparse = mount_path.join("large_sparse.bin");

    // Write large files
    fs::write(&path_256k, &pattern_256k).unwrap();
    fs::write(&path_384k, &pattern_384k).unwrap();

    // Write sparse file (gap of 150 KiB followed by 64 KiB data = 214 KiB total, exceeding threshold)
    let sparse_data: Vec<u8> = (0..(64 * 1024)).map(|i| (i % 253) as u8).collect();
    {
        let mut sparse_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path_sparse)
            .unwrap();
        sparse_file.seek(SeekFrom::Start(150 * 1024)).unwrap();
        sparse_file.write_all(&sparse_data).unwrap();
        sparse_file.sync_all().unwrap();
    }

    // Sync all files to ensure persistence
    fs::File::open(&path_256k).unwrap().sync_all().unwrap();
    fs::File::open(&path_384k).unwrap().sync_all().unwrap();

    // 2. Concurrently read staged/live large files, sparse file, concurrent writers, and directory listings
    let mut threads = Vec::new();

    // Reader 1: Full 256 KiB reads (triggers LARGE_READ_THRESHOLD async offload)
    {
        let p = path_256k.clone();
        let expected = pattern_256k.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..15 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), expected.len());
                assert_eq!(data, expected);
            }
        }));
    }

    // Reader 2: Full 384 KiB reads
    {
        let p = path_384k.clone();
        let expected = pattern_384k.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..15 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), expected.len());
                assert_eq!(data, expected);
            }
        }));
    }

    // Reader 3: Chunked offset reads on 256 KiB file
    {
        let p = path_256k.clone();
        let expected = pattern_256k.clone();
        threads.push(thread::spawn(move || {
            let mut file = fs::File::open(&p).unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            for i in 0..20 {
                let offset = ((i * 13 * 1024) % (200 * 1024)) as u64;
                file.seek(SeekFrom::Start(offset)).unwrap();
                file.read_exact(&mut buf).unwrap();
                let start = offset as usize;
                let end = start + buf.len();
                assert_eq!(&buf[..], &expected[start..end]);
            }
        }));
    }

    // Reader 4: Read sparse file across the hole into the populated extent
    {
        let p = path_sparse.clone();
        let sparse_data_clone = sparse_data.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..15 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), (150 + 64) * 1024);
                // First 150 KiB must be all zeros
                assert!(data[..(150 * 1024)].iter().all(|&b| b == 0));
                // Remaining 64 KiB must match sparse_data
                assert_eq!(&data[(150 * 1024)..], &sparse_data_clone[..]);
            }
        }));
    }

    // Writer 1: Concurrent writes and removes in a subdirectory
    {
        let mount_p = mount_path.clone();
        threads.push(thread::spawn(move || {
            let sub = mount_p.join("writers_1");
            fs::create_dir_all(&sub).unwrap();
            let chunk = vec![0xABu8; 8 * 1024];
            for i in 0..15 {
                let file_p = sub.join(format!("scratch_{}.bin", i));
                fs::write(&file_p, &chunk).unwrap();
                let readback = fs::read(&file_p).unwrap();
                assert_eq!(readback, chunk);
                fs::remove_file(&file_p).unwrap();
            }
        }));
    }

    // Directory lister: Concurrent readdir and stat calls
    {
        let mount_p = mount_path.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..15 {
                thread::sleep(Duration::from_millis(5));
                if let Ok(entries) = fs::read_dir(&mount_p) {
                    for entry in entries.flatten() {
                        let _ = entry.metadata();
                    }
                }
            }
        }));
    }

    // Join all live-layer concurrent threads
    for t in threads {
        t.join().expect("Concurrent live-layer thread failed");
    }

    // 3. Remount filesystem cleanly to test the cold / storage read path
    mount.remount_rw();
    let mount_path = mount.path().to_path_buf();

    let path_256k = mount_path.join("large_256k.bin");
    let path_384k = mount_path.join("large_384k.bin");
    let path_sparse = mount_path.join("large_sparse.bin");

    // 4. Verify cold reads from flushed log extents via Tokio async offload
    let mut cold_threads = Vec::new();

    // Cold Reader 1: Full 256 KiB read from disk
    {
        let p = path_256k.clone();
        let expected = pattern_256k.clone();
        cold_threads.push(thread::spawn(move || {
            for _ in 0..10 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), expected.len());
                assert_eq!(data, expected);
            }
        }));
    }

    // Cold Reader 2: Full 384 KiB read from disk
    {
        let p = path_384k.clone();
        let expected = pattern_384k.clone();
        cold_threads.push(thread::spawn(move || {
            for _ in 0..10 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), expected.len());
                assert_eq!(data, expected);
            }
        }));
    }

    // Cold Reader 3: Sparse file cold read
    {
        let p = path_sparse.clone();
        let sparse_data_clone = sparse_data.clone();
        cold_threads.push(thread::spawn(move || {
            for _ in 0..10 {
                let data = fs::read(&p).unwrap();
                assert_eq!(data.len(), (150 + 64) * 1024);
                assert!(data[..(150 * 1024)].iter().all(|&b| b == 0));
                assert_eq!(&data[(150 * 1024)..], &sparse_data_clone[..]);
            }
        }));
    }

    // Cold Reader 4: Chunked seeks across disk blocks
    {
        let p = path_384k.clone();
        let expected = pattern_384k.clone();
        cold_threads.push(thread::spawn(move || {
            let mut file = fs::File::open(&p).unwrap();
            let mut buf = vec![0u8; 32 * 1024];
            for i in 0..15 {
                let offset = ((i * 23 * 1024) % (300 * 1024)) as u64;
                file.seek(SeekFrom::Start(offset)).unwrap();
                file.read_exact(&mut buf).unwrap();
                let start = offset as usize;
                let end = start + buf.len();
                assert_eq!(&buf[..], &expected[start..end]);
            }
        }));
    }

    for t in cold_threads {
        t.join().expect("Concurrent cold-layer read thread failed");
    }

    mount.unmount();
}

#[test]
fn test_fuse_async_fsync_and_singlethread_loop() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    let subdir = mount_path.join("syncdir");
    fs::create_dir(&subdir).unwrap();

    let mut threads = Vec::new();

    // Thread 1: Writer + fsync worker (repeatedly writes and fsyncs)
    {
        let p = mount_path.join("fsync_file.bin");
        threads.push(thread::spawn(move || {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&p)
                .unwrap();
            let chunk = vec![0x33u8; 16 * 1024];
            for _ in 0..20 {
                file.write_all(&chunk).unwrap();
                file.sync_all().unwrap(); // Triggers async fsync over FUSE
            }
        }));
    }

    // Thread 2: Directory fsync worker (creates files and fsyncs directory handle)
    {
        let sub = subdir.clone();
        threads.push(thread::spawn(move || {
            for i in 0..15 {
                let file_p = sub.join(format!("entry_{}.txt", i));
                fs::write(&file_p, format!("content {}", i)).unwrap();
                // Open directory and call sync_all (triggers FUSE fsyncdir)
                let dir_f = fs::File::open(&sub).unwrap();
                dir_f.sync_all().unwrap();
            }
        }));
    }

    // Thread 3: Large streaming writes that repeatedly trigger auto-flush thresholds
    {
        let p = mount_path.join("large_stream.bin");
        threads.push(thread::spawn(move || {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&p)
                .unwrap();
            // 64 KiB chunks * 16 = 1 MiB total data, triggering auto-flush thresholds
            let chunk = vec![0x77u8; 64 * 1024];
            for _ in 0..16 {
                file.write_all(&chunk).unwrap();
            }
            file.sync_all().unwrap();
        }));
    }

    // Thread 4: Concurrent reader verifying in-flight stability
    {
        let sub = subdir.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..25 {
                thread::sleep(Duration::from_millis(5));
                if let Ok(entries) = fs::read_dir(&sub) {
                    for entry in entries.flatten() {
                        let _ = fs::read_to_string(entry.path());
                    }
                }
            }
        }));
    }

    for t in threads {
        t.join().expect("Concurrent async fsync worker thread panicked");
    }

    // Remount volume to verify all fsynced data is durable on storage
    mount.remount_rw();
    let remount_path = mount.path().to_path_buf();

    // 1. Verify fsync_file.bin size (20 * 16 KiB = 320 KiB)
    let fsync_file = remount_path.join("fsync_file.bin");
    let fsync_data = fs::read(&fsync_file).unwrap();
    assert_eq!(fsync_data.len(), 20 * 16 * 1024);
    assert!(fsync_data.iter().all(|&b| b == 0x33));

    // 2. Verify syncdir entries
    let sub_remount = remount_path.join("syncdir");
    for i in 0..15 {
        let entry_p = sub_remount.join(format!("entry_{}.txt", i));
        let content = fs::read_to_string(&entry_p).unwrap();
        assert_eq!(content, format!("content {}", i));
    }

    // 3. Verify large_stream.bin (16 * 64 KiB = 1024 KiB)
    let stream_file = remount_path.join("large_stream.bin");
    let stream_data = fs::read(&stream_file).unwrap();
    assert_eq!(stream_data.len(), 16 * 64 * 1024);
    assert!(stream_data.iter().all(|&b| b == 0x77));

    mount.unmount();
}

#[test]
fn test_unmount_drains_in_flight_async_operations() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    // Prepare a large cold file on disk (512 KiB)
    let cold_file = mount_path.join("cold_file.bin");
    let initial_data = vec![0xABu8; 512 * 1024];
    fs::write(&cold_file, &initial_data).unwrap();

    // Flush and remount so it becomes cold disk extents
    mount.remount_rw();
    let remount_path = mount.path().to_path_buf();
    let cold_file = remount_path.join("cold_file.bin");

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut threads = Vec::new();

    // Spawn 4 concurrent readers requesting > 128 KiB chunks (triggers async offload on cold extents)
    for _ in 0..4 {
        let p = cold_file.clone();
        let stop_clone = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                // Read 512 KiB
                let _ = fs::read(&p);
            }
        }));
    }

    // Spawn 2 concurrent fsync / fsyncdir workers (triggers async fsync offload)
    for i in 0..2 {
        let p = remount_path.join(format!("fsync_work_{}.bin", i));
        let stop_clone = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            let chunk = vec![0xCDu8; 8192];
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&p) {
                    let _ = f.write_all(&chunk);
                    let _ = f.sync_all();
                }
            }
        }));
    }

    // Allow workers to run and establish continuous in-flight async operations
    thread::sleep(Duration::from_millis(150));

    // Signal workers to stop initiating new iterations so files close,
    // then immediately unmount while in-flight operations drain.
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    mount.unmount();
    for t in threads {
        let _ = t.join();
    }

    // Ensure volume remounts cleanly and data is intact
    mount.remount_rw();
    let recovered_path = mount.path().to_path_buf();
    let read_back = fs::read(recovered_path.join("cold_file.bin")).unwrap();
    assert_eq!(read_back, initial_data);

    mount.unmount();
}

#[test]
fn test_longest_allowed_file_and_directory_names() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    // 1. Verify statvfs f_namemax reports 255
    let path_c = std::ffi::CString::new(mount.path_str()).unwrap();
    let mut statvfs_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(path_c.as_ptr(), &mut statvfs_buf) };
    assert_eq!(res, 0);
    assert_eq!(statvfs_buf.f_namemax, 255);

    // 2. Prepare boundary names
    // 255 ASCII bytes (longest valid name)
    let file_name_255 = "f".repeat(255);
    // 256 ASCII bytes (first invalid name length)
    let file_name_256 = "f".repeat(256);
    // 300 ASCII bytes (well beyond limit)
    let file_name_300 = "f".repeat(300);

    let dir_name_255 = "d".repeat(255);
    let dir_name_256 = "d".repeat(256);

    let file_path_255 = mount_path.join(&file_name_255);
    let file_path_256 = mount_path.join(&file_name_256);
    let file_path_300 = mount_path.join(&file_name_300);

    let dir_path_255 = mount_path.join(&dir_name_255);
    let dir_path_256 = mount_path.join(&dir_name_256);

    // 3. Reject creating or looking up files exceeding 255 bytes with ENAMETOOLONG
    let err_create_256 = fs::write(&file_path_256, b"too long").unwrap_err();
    assert_eq!(err_create_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    let err_create_300 = fs::write(&file_path_300, b"much too long").unwrap_err();
    assert_eq!(err_create_300.raw_os_error(), Some(libc::ENAMETOOLONG));

    let err_stat_256 = fs::metadata(&file_path_256).unwrap_err();
    assert_eq!(err_stat_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // Reject deleting non-existent 256-byte name with ENAMETOOLONG
    let err_unlink_256 = fs::remove_file(&file_path_256).unwrap_err();
    assert_eq!(err_unlink_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 4. Create, write, read, and stat a 255-byte file name
    let file_content_255 = b"Contents of maximum allowed 255-byte file name";
    fs::write(&file_path_255, file_content_255).unwrap();
    assert!(file_path_255.exists());
    assert_eq!(fs::read(&file_path_255).unwrap(), file_content_255);

    let meta = fs::metadata(&file_path_255).unwrap();
    assert_eq!(meta.len(), file_content_255.len() as u64);

    // 5. Reject creating or removing directories exceeding 255 bytes
    let err_mkdir_256 = fs::create_dir(&dir_path_256).unwrap_err();
    assert_eq!(err_mkdir_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    let err_rmdir_256 = fs::remove_dir(&dir_path_256).unwrap_err();
    assert_eq!(err_rmdir_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 6. Create a 255-byte directory name
    fs::create_dir(&dir_path_255).unwrap();
    assert!(dir_path_255.is_dir());

    // 7. Create a 255-byte file inside the 255-byte directory (nested 255-byte components)
    let nested_name_255 = "n".repeat(255);
    let nested_file_path = dir_path_255.join(&nested_name_255);
    let nested_content = b"Nested inside 255-byte directory";
    fs::write(&nested_file_path, nested_content).unwrap();
    assert_eq!(fs::read(&nested_file_path).unwrap(), nested_content);

    // Reject 256-byte child in 255-byte directory
    let nested_path_256 = dir_path_255.join(&file_name_256);
    let err_nested_256 = fs::write(&nested_path_256, b"fail").unwrap_err();
    assert_eq!(err_nested_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 8. Multi-byte UTF-8 boundary checks:
    // '🦀' is 4 bytes. 63 * 4 + 3 ASCII bytes ('x') = 255 bytes.
    let utf8_name_255 = format!("{}{}", "🦀".repeat(63), "xxx");
    assert_eq!(utf8_name_255.len(), 255);
    let utf8_path_255 = mount_path.join(&utf8_name_255);
    let utf8_content = b"UTF-8 255-byte filename payload";
    fs::write(&utf8_path_255, utf8_content).unwrap();
    assert_eq!(fs::read(&utf8_path_255).unwrap(), utf8_content);

    // 64 * 4 = 256 bytes (only 64 characters, but 256 bytes!) -> must fail with ENAMETOOLONG
    let utf8_name_256 = "🦀".repeat(64);
    assert_eq!(utf8_name_256.len(), 256);
    let utf8_path_256 = mount_path.join(&utf8_name_256);
    let err_utf8_256 = fs::write(&utf8_path_256, b"too many bytes").unwrap_err();
    assert_eq!(err_utf8_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 9. Symlink: 255-byte name succeeds, 256-byte name fails with ENAMETOOLONG
    let symlink_name_255 = "s".repeat(255);
    let symlink_path_255 = mount_path.join(&symlink_name_255);
    std::os::unix::fs::symlink(&file_name_255, &symlink_path_255).unwrap();
    assert_eq!(
        fs::read_link(&symlink_path_255).unwrap().to_str().unwrap(),
        &file_name_255
    );
    assert_eq!(fs::read(&symlink_path_255).unwrap(), file_content_255);

    let symlink_path_256 = mount_path.join("s".repeat(256));
    let err_symlink_256 = std::os::unix::fs::symlink("target", &symlink_path_256).unwrap_err();
    assert_eq!(err_symlink_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 10. Hardlink: 255-byte name succeeds, 256-byte name fails with ENAMETOOLONG
    let hardlink_name_255 = "h".repeat(255);
    let hardlink_path_255 = mount_path.join(&hardlink_name_255);
    fs::hard_link(&file_path_255, &hardlink_path_255).unwrap();
    assert_eq!(fs::metadata(&file_path_255).unwrap().nlink(), 2);
    assert_eq!(fs::read(&hardlink_path_255).unwrap(), file_content_255);

    let hardlink_path_256 = mount_path.join("h".repeat(256));
    let err_hardlink_256 = fs::hard_link(&file_path_255, &hardlink_path_256).unwrap_err();
    assert_eq!(err_hardlink_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 11. FIFO via mkfifo: 255-byte succeeds, 256-byte fails with ENAMETOOLONG
    let fifo_name_255 = "p".repeat(255);
    let fifo_path_255 = mount_path.join(&fifo_name_255);
    let c_fifo_255 = std::ffi::CString::new(fifo_path_255.to_str().unwrap()).unwrap();
    let fifo_ret = unsafe { libc::mkfifo(c_fifo_255.as_ptr(), 0o644) };
    assert_eq!(fifo_ret, 0, "mkfifo with 255-byte name should succeed");

    let fifo_path_256 = mount_path.join("p".repeat(256));
    let c_fifo_256 = std::ffi::CString::new(fifo_path_256.to_str().unwrap()).unwrap();
    let fifo_err_ret = unsafe { libc::mkfifo(c_fifo_256.as_ptr(), 0o644) };
    assert_eq!(fifo_err_ret, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENAMETOOLONG));

    // 12. Renames:
    // Rename 255-byte hardlink to another 255-byte name
    let renamed_name_255 = "r".repeat(255);
    let renamed_path_255 = mount_path.join(&renamed_name_255);
    fs::rename(&hardlink_path_255, &renamed_path_255).unwrap();
    assert!(!hardlink_path_255.exists());
    assert!(renamed_path_255.exists());
    assert_eq!(fs::read(&renamed_path_255).unwrap(), file_content_255);

    // Target 256-byte name fails with ENAMETOOLONG
    let err_rename_dst_256 = fs::rename(&renamed_path_255, &file_path_256).unwrap_err();
    assert_eq!(err_rename_dst_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // Source 256-byte name fails with ENAMETOOLONG
    let err_rename_src_256 = fs::rename(&file_path_256, &renamed_path_255).unwrap_err();
    assert_eq!(err_rename_src_256.raw_os_error(), Some(libc::ENAMETOOLONG));

    // 13. Directory listing returns exact 255-byte names
    let root_entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(root_entries.contains(&file_name_255));
    assert!(root_entries.contains(&dir_name_255));
    assert!(root_entries.contains(&utf8_name_255));
    assert!(root_entries.contains(&symlink_name_255));
    assert!(root_entries.contains(&fifo_name_255));
    assert!(root_entries.contains(&renamed_name_255));

    // Ensure all data is synced to disk before remount
    let f1 = fs::OpenOptions::new().write(true).open(&file_path_255).unwrap();
    f1.sync_all().unwrap();
    drop(f1);

    let f2 = fs::OpenOptions::new().write(true).open(&nested_file_path).unwrap();
    f2.sync_all().unwrap();
    drop(f2);

    let f3 = fs::OpenOptions::new().write(true).open(&utf8_path_255).unwrap();
    f3.sync_all().unwrap();
    drop(f3);

    // 14. Persistence across remount & crash recovery
    mount.remount_rw();
    let remount_path = mount.path().to_path_buf();

    let remount_file_255 = remount_path.join(&file_name_255);
    let remount_dir_255 = remount_path.join(&dir_name_255);
    let remount_nested_file = remount_dir_255.join(&nested_name_255);
    let remount_utf8_255 = remount_path.join(&utf8_name_255);
    let remount_symlink_255 = remount_path.join(&symlink_name_255);
    let remount_renamed_255 = remount_path.join(&renamed_name_255);
    let remount_fifo_255 = remount_path.join(&fifo_name_255);

    assert!(remount_file_255.exists());
    assert_eq!(fs::read(&remount_file_255).unwrap(), file_content_255);

    assert!(remount_dir_255.is_dir());
    assert_eq!(fs::read(&remount_nested_file).unwrap(), nested_content);

    assert!(remount_utf8_255.exists());
    assert_eq!(fs::read(&remount_utf8_255).unwrap(), utf8_content);

    assert_eq!(
        fs::read_link(&remount_symlink_255).unwrap().to_str().unwrap(),
        &file_name_255
    );

    assert_eq!(fs::read(&remount_renamed_255).unwrap(), file_content_255);
    assert!(remount_fifo_255.exists());

    // 15. Clean deletion of 255-byte entities on remounted volume
    fs::remove_file(&remount_file_255).unwrap();
    fs::remove_file(&remount_nested_file).unwrap();
    fs::remove_dir(&remount_dir_255).unwrap();
    fs::remove_file(&remount_utf8_255).unwrap();
    fs::remove_file(&remount_symlink_255).unwrap();
    fs::remove_file(&remount_renamed_255).unwrap();
    fs::remove_file(&remount_fifo_255).unwrap();

    assert!(!remount_file_255.exists());
    assert!(!remount_dir_255.exists());

    mount.unmount();
}

#[test]
fn test_fuse_non_utf8_access_vectors() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_non_utf8_log_")
        .tempdir()
        .unwrap();
    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_non_utf8_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    let make_c_path = |name_bytes: &[u8]| -> CString {
        let mut p = mount_path.as_os_str().as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(name_bytes);
        CString::new(p).unwrap()
    };

    let c_bad_file = make_c_path(b"bad_\xff\xfe_file.txt");
    let c_bad_dir = make_c_path(b"bad_\xff\xfe_dir");
    let c_bad_fifo = make_c_path(b"bad_\xff\xfe_fifo");
    let c_bad_symlink = make_c_path(b"bad_\xff\xfe_symlink");
    let c_bad_hardlink = make_c_path(b"bad_\xff\xfe_hardlink");
    let c_bad_rename_dst = make_c_path(b"bad_\xff\xfe_renamed");

    // 1. Stat / lookup of non-UTF8 filename returns ENOENT
    {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let res = unsafe { libc::stat(c_bad_file.as_ptr(), st.as_mut_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    // 2. Open with O_CREAT (create) of non-UTF8 filename returns EINVAL
    {
        let fd = unsafe { libc::open(c_bad_file.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        assert_eq!(fd, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 3. Mkdir with non-UTF8 directory name returns EINVAL
    {
        let res = unsafe { libc::mkdir(c_bad_dir.as_ptr(), 0o755) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 4. Mknod / mkfifo with non-UTF8 name returns EINVAL
    {
        let res = unsafe { libc::mkfifo(c_bad_fifo.as_ptr(), 0o644) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 5. Symlink with non-UTF8 link name returns EINVAL
    {
        let c_valid_target = CString::new("target.txt").unwrap();
        let res = unsafe { libc::symlink(c_valid_target.as_ptr(), c_bad_symlink.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 6. Symlink with non-UTF8 target returns EINVAL
    {
        let c_bad_target = CString::new(b"target_\xff\xfe.txt".to_vec()).unwrap();
        let c_valid_symlink = make_c_path(b"valid_symlink");
        let res = unsafe { libc::symlink(c_bad_target.as_ptr(), c_valid_symlink.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // Create a valid file for hard link, rename, and xattr tests
    let valid_file = mount_path.join("valid.txt");
    fs::write(&valid_file, b"content for utf8 tests").unwrap();
    let c_valid_file = CString::new(valid_file.as_os_str().as_bytes().to_vec()).unwrap();

    // 7. Hard link with non-UTF8 destination name returns EINVAL
    {
        let res = unsafe { libc::link(c_valid_file.as_ptr(), c_bad_hardlink.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 8. Rename with non-UTF8 destination name returns EINVAL
    {
        let res = unsafe { libc::rename(c_valid_file.as_ptr(), c_bad_rename_dst.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 9. Rename with non-UTF8 source name returns ENOENT
    {
        let c_valid_rename_dst = make_c_path(b"renamed_target.txt");
        let res = unsafe { libc::rename(c_bad_file.as_ptr(), c_valid_rename_dst.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    // 10. Unlink with non-UTF8 filename returns ENOENT
    {
        let res = unsafe { libc::unlink(c_bad_file.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    // 11. Rmdir with non-UTF8 directory name returns ENOENT
    {
        let res = unsafe { libc::rmdir(c_bad_dir.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    // 12. Setxattr / getxattr / removexattr with non-UTF8 attribute name returns EINVAL
    {
        let c_bad_xattr = CString::new(b"user.bad_\xff\xfe".to_vec()).unwrap();
        let val = b"xattr_val";
        let res = unsafe {
            libc::setxattr(
                c_valid_file.as_ptr(),
                c_bad_xattr.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                val.len(),
                0,
            )
        };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));

        let res = unsafe { libc::getxattr(c_valid_file.as_ptr(), c_bad_xattr.as_ptr(), std::ptr::null_mut(), 0) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));

        let res = unsafe { libc::removexattr(c_valid_file.as_ptr(), c_bad_xattr.as_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    // 13. Verify filesystem state integrity after all rejected non-UTF8 attempts
    assert_eq!(fs::read(&valid_file).unwrap(), b"content for utf8 tests");

    let entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    // Only valid.txt and the virtual .status file should exist
    assert!(entries.contains(&"valid.txt".to_string()));
    assert!(entries.contains(&".status".to_string()));
    assert_eq!(entries.len(), 2);

    // Verify creating and reading another valid file succeeds normally
    let valid_file_2 = mount_path.join("valid_2.txt");
    fs::write(&valid_file_2, b"subsequent valid file").unwrap();
    assert_eq!(fs::read(&valid_file_2).unwrap(), b"subsequent valid file");

    fs::remove_file(&valid_file).unwrap();
    fs::remove_file(&valid_file_2).unwrap();

    mount.unmount();
}
