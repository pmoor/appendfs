use appendfs::InMemoryFS;
use appendfs::crypto::{VolumeHeader, VolumeKey};
use appendfs::log::RecoveryTarget;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub fn unmount_fuse(mount_path: &str) {
    for _ in 0..10 {
        let status = Command::new("fusermount3").arg("-u").arg(mount_path).status();
        if let Ok(s) = status
            && s.success()
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = Command::new("fusermount3").arg("-u").arg("-z").arg(mount_path).status();
}

#[allow(dead_code)]
pub struct TestMount {
    pub log_dir: tempfile::TempDir,
    pub mount_dir: tempfile::TempDir,
    pub mount_path: PathBuf,
    pub log_path: PathBuf,
    join_handle: Option<thread::JoinHandle<()>>,
    is_mounted: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl TestMount {
    /// Creates and mounts a new initialized volume with default in-memory filesystem in RW mode.
    pub fn new_rw() -> Self {
        let log_dir = tempfile::Builder::new().prefix("appendfs_log_").tempdir().unwrap();
        let log_path = log_dir.path().to_path_buf();
        let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(appendfs::storage::OsStorage::new(&log_path));
        appendfs::init_volume(storage.clone(), &VolumeKey::plaintext(), VolumeHeader::plaintext()).unwrap();

        let mount_dir = tempfile::Builder::new().prefix("appendfs_mnt_").tempdir().unwrap();
        let mount_path = mount_dir.path().to_path_buf();
        fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();

        let mut fs = appendfs::log::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let latest_gen = appendfs::find_latest_generation_in_storage(storage.as_ref());
        let next_gen = latest_gen + 1;
        let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
        let writer = Arc::new(
            appendfs::LogWriter::create_lazy(
                storage,
                next_gen,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(&log_path);

        Self::mount_custom(log_dir, mount_dir, fs, false)
    }

    /// Mounts an existing or custom `InMemoryFS` onto a new temporary mount point.
    pub fn mount_custom(
        log_dir: tempfile::TempDir,
        mount_dir: tempfile::TempDir,
        fs: InMemoryFS,
        read_only: bool,
    ) -> Self {
        let mount_path = mount_dir.path().to_path_buf();
        let log_path = log_dir.path().to_path_buf();
        fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();

        let initial_dev = fs::metadata(&mount_path).unwrap().dev();
        let mount_path_clone = mount_path.clone();

        let handle = thread::spawn(move || {
            let mut args = vec![
                "test_fs".to_string(),
                mount_path_clone.to_str().unwrap().to_string(),
                "-f".to_string(),
            ];
            if read_only {
                args.push("-o".to_string());
                args.push("ro".to_string());
            }
            if let Err(e) = appendfs::mount(args, fs) {
                eprintln!("FUSE mount error: {}", e);
            }
        });

        // Wait for FUSE mount ready
        let mut mounted = false;
        for _ in 0..200 {
            if let Ok(meta) = fs::metadata(&mount_path)
                && meta.dev() != initial_dev
            {
                mounted = true;
                break;
            }
            if handle.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(mounted, "FUSE mount timed out or device ID did not change");

        Self {
            log_dir,
            mount_dir,
            mount_path,
            log_path,
            join_handle: Some(handle),
            is_mounted: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Unmounts the active FUSE filesystem cleanly.
    pub fn unmount(&mut self) {
        if self.is_mounted.swap(false, Ordering::SeqCst) {
            unmount_fuse(self.mount_path.to_str().unwrap());
            if let Some(handle) = self.join_handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Remounts in RW mode on the same mount path.
    pub fn remount_rw(&mut self) {
        self.unmount();
        let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(appendfs::storage::OsStorage::new(&self.log_path));
        let mut fs = appendfs::log::recover_fs(
            storage.clone(),
            appendfs::RecoveryTarget::Latest,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
        let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
        let mut writer_res = appendfs::LogWriter::create_lazy(
            storage.clone(),
            next_gen,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
            VolumeKey::plaintext_arc(),
        );
        for _ in 0..20 {
            if writer_res.is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
            writer_res = appendfs::LogWriter::create_lazy(
                storage.clone(),
                next_gen,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
                VolumeKey::plaintext_arc(),
            );
        }
        let writer = Arc::new(writer_res.unwrap());
        fs.log_writer = Some(writer);
        fs.set_log_dir(&self.log_path);

        let initial_dev = fs::metadata(&self.mount_path).unwrap().dev();
        let mount_path_clone = self.mount_path.clone();

        let handle = thread::spawn(move || {
            let args = vec![
                "test_fs".to_string(),
                mount_path_clone.to_str().unwrap().to_string(),
                "-f".to_string(),
            ];
            if let Err(e) = appendfs::mount(args, fs) {
                eprintln!("FUSE mount error: {}", e);
            }
        });

        let mut mounted = false;
        for _ in 0..200 {
            if let Ok(meta) = fs::metadata(&self.mount_path)
                && meta.dev() != initial_dev
            {
                mounted = true;
                break;
            }
            if handle.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(mounted, "FUSE remount timed out");

        self.join_handle = Some(handle);
        self.is_mounted.store(true, Ordering::SeqCst);
    }

    /// Remounts in Read-Only mode with an optional Point-in-Time recovery target.
    pub fn remount_ro(&mut self, target: RecoveryTarget) {
        self.unmount();
        let storage: Arc<dyn appendfs::storage::Storage> = Arc::new(appendfs::storage::OsStorage::new(&self.log_path));
        let mut fs = appendfs::log::recover_fs(
            storage,
            target,
            Arc::new(appendfs::SystemClock),
            appendfs::VolumeKey::plaintext_arc(),
        )
        .unwrap();
        fs.set_log_dir(&self.log_path);
        fs.set_read_only(true);

        let initial_dev = fs::metadata(&self.mount_path).unwrap().dev();
        let mount_path_clone = self.mount_path.clone();

        let handle = thread::spawn(move || {
            let args = vec![
                "test_fs".to_string(),
                mount_path_clone.to_str().unwrap().to_string(),
                "-f".to_string(),
                "-o".to_string(),
                "ro".to_string(),
            ];
            if let Err(e) = appendfs::mount(args, fs) {
                eprintln!("FUSE mount-ro error: {}", e);
            }
        });

        let mut mounted = false;
        for _ in 0..200 {
            if let Ok(meta) = fs::metadata(&self.mount_path)
                && meta.dev() != initial_dev
            {
                mounted = true;
                break;
            }
            if handle.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(mounted, "FUSE remount-ro timed out");

        self.join_handle = Some(handle);
        self.is_mounted.store(true, Ordering::SeqCst);
    }

    pub fn path(&self) -> &Path {
        &self.mount_path
    }

    pub fn path_str(&self) -> &str {
        self.mount_path.to_str().unwrap()
    }
}

impl Drop for TestMount {
    fn drop(&mut self) {
        self.unmount();
    }
}
