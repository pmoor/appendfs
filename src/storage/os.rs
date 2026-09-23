use crate::storage::{Storage, StorageReader, StorageWriter, WriteMode};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// OS filesystem backed storage implementation rooted at a base directory.
#[derive(Debug, Clone)]
pub struct OsStorage {
    base_dir: PathBuf,
}

impl OsStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn full_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }
}

pub struct OsStorageReader {
    file: File,
}

impl StorageReader for OsStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

pub struct OsStorageWriter {
    file: File,
}

impl OsStorageWriter {
    pub fn new(file: File) -> Self {
        Self { file }
    }
}

impl StorageWriter for OsStorageWriter {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.seek(SeekFrom::Start(len))?;
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

impl Storage for OsStorage {
    fn list_files(&self) -> io::Result<Vec<String>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name != ".lock"
            {
                files.push(name.to_string());
            }
        }
        files.sort();
        Ok(files)
    }

    fn exists(&self, name: &str) -> bool {
        self.full_path(name).is_file()
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        let path = self.full_path(name);
        if path.exists() {
            std::fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        create_dir_all(&self.base_dir)?;
        std::fs::rename(self.full_path(from), self.full_path(to))
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        let file = File::open(self.full_path(name))?;
        Ok(Arc::new(OsStorageReader { file }))
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        create_dir_all(&self.base_dir)?;
        let path = self.full_path(name);
        let mut options = OpenOptions::new();
        options.write(true);
        match mode {
            WriteMode::CreateNew => options.create_new(true),
            WriteMode::Overwrite => options.create(true).truncate(true),
        };
        let file = options.open(&path)?;
        Ok(Box::new(OsStorageWriter::new(file)))
    }

    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn crate::storage::StorageLock>> {
        use std::io::Read;
        use std::os::unix::io::AsRawFd;

        create_dir_all(&self.base_dir)?;
        let lock_path = self.full_path(".lock");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
                let mut pid_buf = String::new();
                let _ = file.read_to_string(&mut pid_buf);
                let pid_str = pid_buf.trim();
                let msg = if !pid_str.is_empty() {
                    format!(
                        "Volume at '{}' is already locked in read-write mode by PID {}",
                        self.base_dir.display(),
                        pid_str
                    )
                } else {
                    format!(
                        "Volume at '{}' is already locked in read-write mode",
                        self.base_dir.display()
                    )
                };
                return Err(io::Error::new(io::ErrorKind::WouldBlock, msg));
            }
            return Err(err);
        }

        let lock = OsLock { file };
        // The pid is only there to name the holder in the error above, so failing to write
        // it is no reason to refuse a lock that is already held.
        let _ = crate::storage::StorageLock::record_holder(&lock);
        Ok(Box::new(lock))
    }
}

#[derive(Debug)]
pub struct OsLock {
    file: File,
}

impl crate::storage::StorageLock for OsLock {
    fn record_holder(&self) -> io::Result<()> {
        let mut file = &self.file;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", std::process::id())?;
        file.flush()
    }
}
