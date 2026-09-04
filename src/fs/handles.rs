//! POSIX file and directory handle tracking.
//!
//! File handles own the open-count bookkeeping that keeps an unlinked-but-open inode
//! alive, and releasing one also drops any BSD flock and POSIX range locks it held.
//! Directory handles hold an immutable snapshot of the listing taken at `opendir`, so a
//! paginated `readdir` is isolated from concurrent mutations.

use super::{FileHandle, FlockState, InMemoryFS};
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl InMemoryFS {
    // --- POSIX File Handle Tracking ---

    pub fn open_file_handle(&self, ino: u64, flags: u32) -> u64 {
        if self.virtual_files.is_virtual_ino(ino) {
            let content = self.virtual_files.generate_content(ino, self).unwrap_or_default();
            let fh = (self.allocate_fh() & !super::VIRTUAL_FH_FLAG) | super::VIRTUAL_FH_FLAG;
            self.virtual_handles.write().unwrap().insert(fh, content.into_bytes());
            return fh;
        }

        let fh = self.allocate_fh();
        self.file_handles.write().unwrap().insert(fh, FileHandle { ino, flags });
        *self.open_counts.write().unwrap().entry(ino).or_insert(0) += 1;
        fh
    }

    pub fn get_file_handle(&self, fh: u64) -> Option<FileHandle> {
        if (fh & super::VIRTUAL_FH_FLAG) != 0 {
            return None;
        }
        self.file_handles.read().unwrap().get(&fh).copied()
    }

    pub fn read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        if (fh & super::VIRTUAL_FH_FLAG) != 0 {
            let handles = self.virtual_handles.read().unwrap();
            let buf = handles.get(&fh).ok_or(libc::EBADF)?;
            let start = (offset as usize).min(buf.len());
            let end = (start + size).min(buf.len());
            return Ok(buf[start..end].to_vec());
        }

        let handle = self.get_file_handle(fh).ok_or(libc::EBADF)?;
        if handle.ino != ino {
            return Err(libc::EBADF);
        }
        self.read_file_data(ino, offset, size)
    }

    pub fn release_file_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        if (fh & super::VIRTUAL_FH_FLAG) != 0 {
            self.virtual_handles.write().unwrap().remove(&fh).ok_or(libc::EBADF)?;
            return Ok(());
        }

        let handle = self.file_handles.write().unwrap().remove(&fh).ok_or(libc::EBADF)?;
        if handle.ino != ino {
            return Err(libc::EBADF);
        }

        // Clean up any BSD flock held by this handle
        self.release_flock(ino, fh);

        let mut counts = self.open_counts.write().unwrap();
        if let Some(count) = counts.get_mut(&ino) {
            *count = count.saturating_sub(1);
        }
        if counts.get(&ino) == Some(&0) {
            counts.remove(&ino);
            // Clean up POSIX range locks if all handles on inode are closed
            self.range_lock_table.lock().unwrap().remove(&ino);
            self.range_lock_cond.notify_all();
        }
        let remaining = counts.get(&ino).copied().unwrap_or(0);
        if remaining == 0
            && let Some(attr) = self.get_attr(ino)
            && attr.nlink == 0
        {
            self.tombstone(ino);
        }
        Ok(())
    }

    pub fn release_flock(&self, ino: u64, fh: u64) {
        let mut table = self.flock_table.lock().unwrap();
        if let Some(state) = table.get_mut(&ino) {
            match state {
                FlockState::Shared(set) => {
                    set.remove(&fh);
                    if set.is_empty() {
                        table.remove(&ino);
                    }
                }
                FlockState::Exclusive(holder) => {
                    if *holder == fh {
                        table.remove(&ino);
                    }
                }
            }
            self.flock_cond.notify_all();
        }
    }

    pub fn open_count(&self, ino: u64) -> u32 {
        self.open_counts.read().unwrap().get(&ino).copied().unwrap_or(0)
    }

    // --- Directory Handle Snapshot Management ---

    pub fn allocate_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }

    pub fn open_dir_handle(&self, entries: Vec<(String, u64)>) -> u64 {
        let fh = self.allocate_fh();
        self.dir_handles.write().unwrap().insert(fh, Arc::new(entries));
        fh
    }

    pub fn get_dir_handle(&self, fh: u64) -> Option<Arc<Vec<(String, u64)>>> {
        self.dir_handles.read().unwrap().get(&fh).cloned()
    }

    pub fn release_dir_handle(&self, fh: u64) -> Result<(), i32> {
        self.dir_handles.write().unwrap().remove(&fh).ok_or(libc::EBADF)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_handle_snapshot_isolation_and_lifecycle() {
        let fs = InMemoryFS::new();
        let now = fs.clock.now();

        // 1. Create two files under root
        crate::operations::read_write::create_core(&fs, 1, "alpha.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::create_core(&fs, 1, "bravo.txt", 0o644, 0, 1000, 1000).unwrap();

        // 2. Open a directory handle on root
        let fh1 = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir_core must succeed on directory");
        assert!(fh1 > 0);

        let snap1 = fs.get_dir_handle(fh1).expect("Handle snapshot must exist");
        assert_eq!(snap1.len(), 2);
        assert_eq!(snap1[0].0, "alpha.txt");
        assert_eq!(snap1[1].0, "bravo.txt");

        // 3. Mutate directory: add charlie.txt, delete alpha.txt
        crate::operations::read_write::create_core(&fs, 1, "charlie.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.remove_dir_entry(1, "alpha.txt", now);

        // 4. fh1 MUST retain its original snapshot (alpha, bravo)
        let snap1_recheck = fs.get_dir_handle(fh1).expect("Handle snapshot must still exist");
        assert_eq!(snap1_recheck.len(), 2);
        assert_eq!(snap1_recheck[0].0, "alpha.txt");
        assert_eq!(snap1_recheck[1].0, "bravo.txt");

        // 5. A new directory handle on root gets the new snapshot (bravo, charlie)
        let fh2 = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir_core must succeed on directory");
        assert_ne!(fh1, fh2);
        let snap2 = fs.get_dir_handle(fh2).expect("Second handle snapshot must exist");
        assert_eq!(snap2.len(), 2);
        assert_eq!(snap2[0].0, "bravo.txt");
        assert_eq!(snap2[1].0, "charlie.txt");

        // 6. Release fh1
        assert_eq!(fs.release_dir_handle(fh1), Ok(()));
        assert!(fs.get_dir_handle(fh1).is_none());
        assert!(fs.get_dir_handle(fh2).is_some());
        assert_eq!(fs.release_dir_handle(fh1), Err(libc::EBADF));

        // 7. Release fh2
        assert_eq!(fs.release_dir_handle(fh2), Ok(()));
        assert!(fs.get_dir_handle(fh2).is_none());

        // 8. opendir_core on a non-directory returns ENOTDIR
        let alpha_ino = snap1[0].1;
        assert_eq!(
            crate::operations::dir::opendir_core(&fs, alpha_ino, 0),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn test_file_handle_lifecycle_and_unlinking() {
        let fs = InMemoryFS::new();

        // 1. Create a file
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // 2. Open two file handles
        let fh1 = fs.open_file_handle(ino, libc::O_RDONLY as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_WRONLY as u32);
        assert_ne!(fh1, fh2);
        assert_eq!(fs.open_count(ino), 2);
        assert_eq!(fs.get_file_handle(fh1).unwrap().ino, ino);
        assert_eq!(fs.get_file_handle(fh2).unwrap().ino, ino);

        // 3. Unlink the file while handles are still open
        crate::operations::links::unlink_core(&fs, 1, "test.txt").unwrap();

        // Inode must still exist (not tombstoned) because open_count is 2
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.get_attr(ino).unwrap().nlink, 0);

        // 4. Release first handle
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert!(fs.get_file_handle(fh1).is_none());
        assert!(fs.get_file_handle(fh2).is_some());
        assert_eq!(fs.open_count(ino), 1);
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.release_file_handle(fh1, ino), Err(libc::EBADF));

        // 5. Release second handle -> count drops to 0, inode gets tombstoned
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert!(fs.get_file_handle(fh2).is_none());
        assert_eq!(fs.open_count(ino), 0);
        assert!(
            fs.get_attr(ino).is_none(),
            "Unlinked file with 0 handles must be tombstoned"
        );
    }
}
