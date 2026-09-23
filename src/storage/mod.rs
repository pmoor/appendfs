use std::io;
use std::sync::Arc;

pub mod buffered;
pub mod fault;
pub mod memory;
pub mod os;
pub mod readonly;

pub use buffered::{BufferedStorageWriter, DEFAULT_STORAGE_BUFFER_CAPACITY};
pub use fault::FaultStorage;
pub use memory::MemoryStorage;
pub use os::{OsStorage, OsStorageReader, OsStorageWriter};
pub use readonly::ReadOnlyStorage;

/// Read-only access to a stored file. Completely stateless and thread-safe.
pub trait StorageReader: Send + Sync {
    /// Read exact buffer slice at the given byte offset (positional read / pread).
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Returns the total length of the file in bytes.
    fn len(&self) -> io::Result<u64>;

    /// Returns `true` if the file length is 0.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Convenience helper to read a new byte vector.
    fn read_vec(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Appendable write handle for an active log or summary file.
pub trait StorageWriter: Send + Sync {
    /// Appends data to the end of the file.
    fn append(&mut self, data: &[u8]) -> io::Result<()>;

    /// Truncates the file to `len` bytes (used for write rollback on error).
    fn truncate(&mut self, len: u64) -> io::Result<()>;

    /// Flushes any buffered data and ensures persistence.
    fn sync(&mut self) -> io::Result<()>;

    /// Returns the current length / write offset of the file.
    fn len(&self) -> io::Result<u64>;

    /// Returns `true` if the file length is 0.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

impl<W: StorageWriter + ?Sized> StorageWriter for Box<W> {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        (**self).append(data)
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        (**self).truncate(len)
    }

    fn sync(&mut self) -> io::Result<()> {
        (**self).sync()
    }

    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
}

/// How `Storage::open_writer` should treat a file that already exists.
///
/// Either way the returned writer starts from an empty file at offset 0 - there is no
/// append-to-existing mode, so a partial file left behind by a failed write can never be
/// silently prefixed to the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Fail with `AlreadyExists` if the file is already present. Use for files that must
    /// never be clobbered, such as a numbered log generation.
    CreateNew,
    /// Discard the contents of any existing file. Use for scratch files that are rewritten
    /// from scratch each time, such as `NNNNNN.summary.tmp`.
    Overwrite,
}

/// RAII guard representing an active exclusive lock on the storage volume.
///
/// Releasing or dropping this guard unlocks the storage volume.
pub trait StorageLock: Send + Sync + std::fmt::Debug {
    /// Records the calling process as the lock's holder, for the error a second mount gets.
    ///
    /// Done on acquiring the lock, and again once a backgrounded mount has forked: the lock
    /// passes to the daemon along with the open file, but the pid recorded is still that of
    /// the parent, which exits.
    fn record_holder(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Volume log storage container interface.
pub trait Storage: Send + Sync {
    /// Lists all file names in the volume (e.g. `["000001.log", "000001.summary"]`).
    fn list_files(&self) -> io::Result<Vec<String>>;

    /// Checks if a file exists.
    fn exists(&self, name: &str) -> bool;

    /// Returns the length of a file in bytes if it exists.
    fn file_len(&self, name: &str) -> io::Result<u64> {
        let reader = self.open_reader(name)?;
        reader.len()
    }

    /// Removes a file if it exists.
    fn remove_file(&self, name: &str) -> io::Result<()>;

    /// Atomically renames a file (e.g. `000001.summary.tmp` -> `000001.summary`).
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;

    /// Opens a file for reading.
    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>>;

    /// Opens a file for writing, starting from empty at offset 0. `mode` decides whether an
    /// existing file is an error or is discarded.
    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>>;

    /// Attempts to acquire an exclusive lock on this storage volume.
    ///
    /// Fails with `ErrorKind::WouldBlock` (or similar) if another process or writer already holds
    /// an exclusive lock on the volume.
    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn StorageLock>>;
}

impl<T: StorageReader + ?Sized> StorageReader for Arc<T> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }

    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
}

impl<T: Storage + ?Sized> Storage for Arc<T> {
    fn list_files(&self) -> io::Result<Vec<String>> {
        (**self).list_files()
    }

    fn exists(&self, name: &str) -> bool {
        (**self).exists(name)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        (**self).file_len(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        (**self).remove_file(name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        (**self).open_reader(name)
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        (**self).open_writer(name, mode)
    }

    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn StorageLock>> {
        (**self).acquire_exclusive_lock()
    }
}

impl<T: Storage + ?Sized> Storage for &T {
    fn list_files(&self) -> io::Result<Vec<String>> {
        (**self).list_files()
    }

    fn exists(&self, name: &str) -> bool {
        (**self).exists(name)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        (**self).file_len(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        (**self).remove_file(name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        (**self).open_reader(name)
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        (**self).open_writer(name, mode)
    }

    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn StorageLock>> {
        (**self).acquire_exclusive_lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_crud_and_truncation() {
        let storage = MemoryStorage::new();
        assert!(!storage.exists("test.log"));

        let mut writer = storage.open_writer("test.log", WriteMode::CreateNew).unwrap();
        writer.append(b"hello world").unwrap();
        assert_eq!(writer.len().unwrap(), 11);
        writer.truncate(5).unwrap();
        assert_eq!(writer.len().unwrap(), 5);
        writer.append(b" there!").unwrap();
        assert_eq!(writer.len().unwrap(), 12);
        drop(writer);

        let reader = storage.open_reader("test.log").unwrap();
        assert_eq!(reader.len().unwrap(), 12);
        let mut buf = [0u8; 12];
        reader.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello there!");

        let mut slice = [0u8; 6];
        reader.read_exact_at(6, &mut slice).unwrap();
        assert_eq!(&slice, b"there!");

        storage.rename("test.log", "test.renamed").unwrap();
        assert!(!storage.exists("test.log"));
        assert!(storage.exists("test.renamed"));

        let files = storage.list_files().unwrap();
        assert_eq!(files, vec!["test.renamed".to_string()]);

        storage.remove_file("test.renamed").unwrap();
        assert!(!storage.exists("test.renamed"));
    }

    #[test]
    fn test_os_storage_crud_and_positional_reads() {
        let dir = tempfile::tempdir().unwrap();
        let storage = OsStorage::new(dir.path());

        let mut writer = storage.open_writer("os_test.bin", WriteMode::CreateNew).unwrap();
        writer.append(b"0123456789ABCDEF").unwrap();
        writer.sync().unwrap();
        assert_eq!(writer.len().unwrap(), 16);
        writer.truncate(10).unwrap();
        assert_eq!(writer.len().unwrap(), 10);
        drop(writer);

        let reader = storage.open_reader("os_test.bin").unwrap();
        assert_eq!(reader.len().unwrap(), 10);
        let mut buf = [0u8; 4];
        reader.read_exact_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"6789");

        storage.rename("os_test.bin", "os_test_2.bin").unwrap();
        assert!(storage.exists("os_test_2.bin"));
        assert_eq!(storage.file_len("os_test_2.bin").unwrap(), 10);

        let files = storage.list_files().unwrap();
        assert_eq!(files, vec!["os_test_2.bin".to_string()]);
    }

    #[test]
    fn test_fault_storage_injection_and_bitflips() {
        let mem = Arc::new(MemoryStorage::new());
        let fault = FaultStorage::new(mem);

        // Fail open
        fault.fail_on_file("protected.log", io::ErrorKind::PermissionDenied);
        let err = match fault.open_writer("protected.log", WriteMode::CreateNew) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // Write limit with partial write
        let mut writer = fault.open_writer("data.log", WriteMode::CreateNew).unwrap();
        writer.append(b"initial 10").unwrap();
        assert_eq!(writer.len().unwrap(), 10);

        fault.fail_writes_after_bytes(15, true);
        let err = writer.append(b"1234567890").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        // Partial write succeeded up to 15 bytes total
        assert_eq!(writer.len().unwrap(), 15);
        drop(writer);

        // Inject bitflip at byte 0
        fault.inject_bitflip("data.log", 0, 0x01);
        let reader = fault.open_reader("data.log").unwrap();
        let mut first_byte = [0u8; 1];
        reader.read_exact_at(0, &mut first_byte).unwrap();
        assert_eq!(first_byte[0], b'i' ^ 0x01);
    }

    /// Both modes must hand back an empty file, so a partial write left by a failed
    /// operation can never be prefixed to the next one.
    fn assert_write_mode_contract(storage: &dyn Storage) {
        let mut writer = storage.open_writer("f.bin", WriteMode::CreateNew).unwrap();
        assert_eq!(writer.len().unwrap(), 0);
        writer.append(b"stale partial write").unwrap();
        writer.sync().unwrap();
        drop(writer);

        // CreateNew refuses to clobber an existing file.
        let err = match storage.open_writer("f.bin", WriteMode::CreateNew) {
            Err(e) => e,
            Ok(_) => panic!("CreateNew must reject an existing file"),
        };
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(storage.file_len("f.bin").unwrap(), 19, "must be untouched");

        // Overwrite discards the previous contents rather than appending to them.
        let mut writer = storage.open_writer("f.bin", WriteMode::Overwrite).unwrap();
        assert_eq!(writer.len().unwrap(), 0);
        writer.append(b"fresh").unwrap();
        writer.sync().unwrap();
        drop(writer);

        assert_eq!(storage.file_len("f.bin").unwrap(), 5);
        let reader = storage.open_reader("f.bin").unwrap();
        assert_eq!(reader.read_vec(0, 5).unwrap(), b"fresh");
    }

    #[test]
    fn test_write_mode_contract_holds_for_every_backend() {
        assert_write_mode_contract(&MemoryStorage::new());

        let dir = tempfile::tempdir().unwrap();
        assert_write_mode_contract(&OsStorage::new(dir.path()));

        let fault_dir = tempfile::tempdir().unwrap();
        assert_write_mode_contract(&FaultStorage::new(Arc::new(OsStorage::new(fault_dir.path()))));
    }

    #[test]
    fn test_exclusive_locking_for_every_backend() {
        // 1. MemoryStorage
        let mem = MemoryStorage::new();
        let lock1 = mem.acquire_exclusive_lock().unwrap();
        let err = mem.acquire_exclusive_lock().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(lock1);
        let lock2 = mem.acquire_exclusive_lock().unwrap();
        drop(lock2);

        // 2. OsStorage
        let dir = tempfile::tempdir().unwrap();
        let os1 = OsStorage::new(dir.path());
        let os2 = OsStorage::new(dir.path());
        let os_lock1 = os1.acquire_exclusive_lock().unwrap();
        let err = os2.acquire_exclusive_lock().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(os_lock1);
        let os_lock2 = os2.acquire_exclusive_lock().unwrap();
        drop(os_lock2);

        // 3. FaultStorage
        let fault_dir = tempfile::tempdir().unwrap();
        let fault = FaultStorage::new(Arc::new(OsStorage::new(fault_dir.path())));
        let f_lock1 = fault.acquire_exclusive_lock().unwrap();
        let err = fault.acquire_exclusive_lock().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(f_lock1);
        let f_lock2 = fault.acquire_exclusive_lock().unwrap();
        drop(f_lock2);
    }
}
