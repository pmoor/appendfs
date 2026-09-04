use crate::fs::InMemoryFS;
use crate::shim::{FileAttr, FileType};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Base inode for synthesized virtual files.
/// Inode space starts at `0xFFFF_FFFF_0000_0001` to guarantee complete separation
/// from on-disk persisted inodes.
pub const VIRTUAL_INO_BASE: u64 = 0xFFFF_FFFF_0000_0001;

/// High bit flag for virtual file handles.
/// Bit 63 is set so virtual handles are completely isolated from regular file handles.
pub const VIRTUAL_FH_FLAG: u64 = 1 << 63;

/// Dynamic content generator for a virtual file.
pub type VirtualFileGenerator = Arc<dyn Fn(&InMemoryFS) -> String + Send + Sync>;

/// Registration entry for a virtual file.
pub struct VirtualFileEntry {
    pub name: String,
    pub ino: u64,
    pub generator: VirtualFileGenerator,
}

/// Generic registry managing virtual control and telemetry files in the filesystem root (`/`).
#[derive(Default)]
pub struct VirtualFileRegistry {
    entries: RwLock<Vec<VirtualFileEntry>>,
    name_to_ino: RwLock<HashMap<String, u64>>,
    ino_to_idx: RwLock<HashMap<u64, usize>>,
    next_ino: AtomicU64,
}

impl VirtualFileRegistry {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            name_to_ino: RwLock::new(HashMap::new()),
            ino_to_idx: RwLock::new(HashMap::new()),
            next_ino: AtomicU64::new(VIRTUAL_INO_BASE),
        }
    }

    /// Registers a new virtual file in the root directory.
    pub fn register<F>(&self, name: impl Into<String>, generator: F) -> u64
    where
        F: Fn(&InMemoryFS) -> String + Send + Sync + 'static,
    {
        let name = name.into();
        let mut name_map = self.name_to_ino.write().unwrap();
        if let Some(&existing_ino) = name_map.get(&name) {
            // Update existing generator
            let ino_idx = self.ino_to_idx.read().unwrap();
            if let Some(&idx) = ino_idx.get(&existing_ino) {
                let mut entries = self.entries.write().unwrap();
                entries[idx].generator = Arc::new(generator);
                return existing_ino;
            }
        }

        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let mut entries = self.entries.write().unwrap();
        let idx = entries.len();

        entries.push(VirtualFileEntry {
            name: name.clone(),
            ino,
            generator: Arc::new(generator),
        });

        name_map.insert(name, ino);
        self.ino_to_idx.write().unwrap().insert(ino, idx);
        ino
    }

    /// Resolves an inode by name.
    pub fn get_ino_by_name(&self, name: &str) -> Option<u64> {
        self.name_to_ino.read().unwrap().get(name).copied()
    }

    /// Checks if an inode falls into the virtual inode range.
    pub fn is_virtual_ino(&self, ino: u64) -> bool {
        ino >= VIRTUAL_INO_BASE
    }

    /// Generates content for a virtual file by inode.
    pub fn generate_content(&self, ino: u64, fs: &InMemoryFS) -> Option<String> {
        let idx = *self.ino_to_idx.read().unwrap().get(&ino)?;
        let entries = self.entries.read().unwrap();
        let entry = entries.get(idx)?;
        Some((entry.generator)(fs))
    }

    /// Returns all registered root directory virtual entries `(name, ino)`.
    pub fn list_entries(&self) -> Vec<(String, u64)> {
        let entries = self.entries.read().unwrap();
        entries.iter().map(|e| (e.name.clone(), e.ino)).collect()
    }

    /// Builds a synthetic `FileAttr` for a virtual file.
    pub fn file_attr(&self, ino: u64, size: u64, now: SystemTime) -> FileAttr {
        FileAttr {
            ino,
            file_type: FileType::RegularFile,
            perm: 0o444, // read-only file
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: size as i64,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::dir::{iter_dir_entries, list_dir_core};
    use crate::operations::links::{rename_core, unlink_core};
    use crate::operations::read_write::{create_core, fallocate_core, read_core, setattr_core, write_core};

    #[test]
    fn test_virtual_file_registry_crud() {
        let registry = VirtualFileRegistry::new();
        let ino = registry.register(".status", |_| "status: ok\n".to_string());

        assert!(registry.is_virtual_ino(ino));
        assert_eq!(registry.get_ino_by_name(".status"), Some(ino));
        assert_eq!(registry.get_ino_by_name(".nonexistent"), None);

        let list = registry.list_entries();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], (".status".to_string(), ino));

        let fs = InMemoryFS::new();
        let content = registry.generate_content(ino, &fs).unwrap();
        assert_eq!(content, "status: ok\n");
    }

    #[test]
    fn test_virtual_file_handle_lifecycle_and_snapshot_isolation() {
        use std::sync::atomic::AtomicUsize;

        let fs = InMemoryFS::new();
        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&call_count);

        let v_ino = fs.virtual_files.register(".counter", move |_| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst);
            format!("counter: {}\n", n)
        });

        // 1. Open first handle: freezes counter = 0
        let fh1 = fs.open_file_handle(v_ino, 0);
        assert_ne!(fh1 & VIRTUAL_FH_FLAG, 0, "fh1 must have high bit flag set");

        // 2. Open second handle: freezes counter = 1
        let fh2 = fs.open_file_handle(v_ino, 0);
        assert_ne!(fh2 & VIRTUAL_FH_FLAG, 0, "fh2 must have high bit flag set");
        assert_ne!(fh1, fh2, "Handles must be distinct");

        // 3. Reading fh1 and fh2 via read_core yields their frozen snapshots
        let data1 = read_core(&fs, v_ino, fh1, 0, 100).unwrap();
        assert_eq!(data1, b"counter: 0\n");
        let data2 = read_core(&fs, v_ino, fh2, 0, 100).unwrap();
        assert_eq!(data2, b"counter: 1\n");

        // 4. Invalid handle returns EBADF
        assert_eq!(read_core(&fs, v_ino, 9999, 0, 100), Err(libc::EBADF));

        // 5. Open a third handle: freezes counter = 2
        let fh3 = fs.open_file_handle(v_ino, 0);
        let data3 = read_core(&fs, v_ino, fh3, 0, 100).unwrap();
        assert_eq!(data3, b"counter: 2\n");
        fs.release_file_handle(fh3, v_ino).unwrap();

        // 5. Release fh1: handle is freed and subsequent read returns EBADF
        fs.release_file_handle(fh1, v_ino).unwrap();
        assert_eq!(read_core(&fs, v_ino, fh1, 0, 100), Err(libc::EBADF));
        // fh2 remains untouched
        assert_eq!(read_core(&fs, v_ino, fh2, 0, 100).unwrap(), b"counter: 1\n");

        fs.release_file_handle(fh2, v_ino).unwrap();
        assert_eq!(read_core(&fs, v_ino, fh2, 0, 100), Err(libc::EBADF));
    }

    #[test]
    fn test_root_directory_pagination_with_virtual_files() {
        let fs = InMemoryFS::new();
        fs.register_remote_status();

        // Register two additional virtual files (along with default .remotes)
        let ino_v1 = fs.virtual_files.register(".virtual1", |_| "v1".to_string());
        let ino_v2 = fs.virtual_files.register(".virtual2", |_| "v2".to_string());

        // Create two regular files in root directory
        let f1 = create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        let f2 = create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();

        // Snapshot directory listing via list_dir_core
        let entries = list_dir_core(&fs, 1).unwrap();
        // Entries must contain: file1.txt, file2.txt, .remotes, .virtual1, .virtual2
        assert_eq!(entries.len(), 5);
        assert!(entries.iter().any(|(name, ino)| name == "file1.txt" && *ino == f1.ino));
        assert!(entries.iter().any(|(name, ino)| name == "file2.txt" && *ino == f2.ino));
        assert!(entries.iter().any(|(name, _)| name == ".remotes"));
        assert!(entries.iter().any(|(name, ino)| name == ".virtual1" && *ino == ino_v1));
        assert!(entries.iter().any(|(name, ino)| name == ".virtual2" && *ino == ino_v2));

        // Test pagination through iter_dir_entries
        // Page 1: offset 0
        let items_all: Vec<_> = iter_dir_entries(&fs, 1, &entries, 0).collect();
        // Dot (1) + DotDot (1) + 5 entries = 7 items
        assert_eq!(items_all.len(), 7);
        assert_eq!(items_all[0].name, ".");
        assert_eq!(items_all[0].next_offset, 1);
        assert_eq!(items_all[1].name, "..");
        assert_eq!(items_all[1].next_offset, 2);

        // Verify get_attrs_batch resolves all items including virtual files!
        let inos: Vec<u64> = items_all.iter().map(|item| item.ino).collect();
        let attrs = fs.get_attrs_batch(&inos);
        assert_eq!(attrs.len(), 6); // 1 (root) + 2 regular + 3 virtual

        // Page 2: simulate reading with offset = 2 (skip . and ..)
        let items_p2: Vec<_> = iter_dir_entries(&fs, 1, &entries, 2).collect();
        assert_eq!(items_p2.len(), 5);
        assert_eq!(items_p2[0].next_offset, 3);
        assert_eq!(items_p2[4].next_offset, 7);

        // Page 3: simulate reading with offset = 5 (middle of entries)
        let items_p3: Vec<_> = iter_dir_entries(&fs, 1, &entries, 5).collect();
        assert_eq!(items_p3.len(), 2);
        assert_eq!(items_p3[0].name, items_all[5].name);
        assert_eq!(items_p3[1].name, items_all[6].name);

        // Page 4: simulate end of directory offset = 7
        let items_end: Vec<_> = iter_dir_entries(&fs, 1, &entries, 7).collect();
        assert_eq!(items_end.len(), 0);
    }

    #[test]
    fn test_virtual_files_mutation_protection() {
        let fs = InMemoryFS::new();
        fs.register_remote_status();
        let v_ino = fs.virtual_files.get_ino_by_name(".remotes").unwrap();

        // 1. Writes are rejected with EPERM
        assert_eq!(write_core(&fs, v_ino, b"mutate", 0), Err(libc::EPERM));

        // 2. Setattr is rejected with EPERM
        assert_eq!(
            setattr_core(&fs, v_ino, 0o777, 0, 0, 0, fs.clock.now(), fs.clock.now(), 0x1),
            Err(libc::EPERM)
        );

        // 3. Fallocate is rejected with EPERM
        assert_eq!(
            fallocate_core(
                &fs,
                v_ino,
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                0,
                100
            ),
            Err(libc::EPERM)
        );

        // 4. Unlink is rejected with EPERM
        assert_eq!(unlink_core(&fs, 1, ".remotes"), Err(libc::EPERM));

        // 5. Rename is rejected with EPERM
        assert_eq!(rename_core(&fs, 1, ".remotes", 1, "renamed.txt"), Err(libc::EPERM));

        // 6. Creating over an existing virtual file returns EEXIST
        assert_eq!(create_core(&fs, 1, ".remotes", 0o644, 0, 1000, 1000), Err(libc::EEXIST));

        // 7. Hardlinking a virtual file is rejected with EPERM
        assert_eq!(
            crate::operations::links::link_core(&fs, v_ino, 1, "link.txt"),
            Err(libc::EPERM)
        );

        // 8. Xattr operations on virtual files are rejected / empty
        assert_eq!(
            crate::operations::xattr::setxattr_core(&fs, v_ino, "user.v", b"val", 0),
            Err(libc::EPERM)
        );
        assert_eq!(
            crate::operations::xattr::removexattr_core(&fs, v_ino, "user.v"),
            Err(libc::EPERM)
        );
        assert_eq!(
            crate::operations::xattr::getxattr_core(&fs, v_ino, "user.v", 0),
            Err(libc::ENODATA)
        );
        assert_eq!(
            crate::operations::xattr::listxattr_core(&fs, v_ino, 0),
            Ok(crate::operations::xattr::ListxattrResult::Size(0))
        );
    }

    #[test]
    fn test_remotes_virtual_file_formatting_and_telemetry() {
        let fs = InMemoryFS::new();
        fs.register_remote_status();

        let v_ino = fs.lookup_child(1, ".remotes").unwrap();

        // Check unconfigured default via read_core
        let fh1 = fs.open_file_handle(v_ino, 0);
        let initial_bytes = read_core(&fs, v_ino, fh1, 0, 4096).unwrap();
        let initial_status = String::from_utf8(initial_bytes).unwrap();
        fs.release_file_handle(fh1, v_ino).unwrap();
        assert!(initial_status.contains("No remotes configured."));
        assert!(initial_status.contains("Volume Head Generation: 1"));

        // Configure remotes
        let mut registry = crate::remote::config::RemoteRegistry::new();
        let mut nas_cfg = crate::remote::config::RemoteTargetConfig::new_path("/mnt/nas");
        nas_cfg.read_priority = 10;
        registry.add_remote("nas", nas_cfg);

        let mut s3_cfg = crate::remote::config::RemoteTargetConfig::new("backup-bucket");
        s3_cfg.read_priority = 100;
        s3_cfg.prefix = "logs/".to_string();
        registry.add_remote("s3", s3_cfg);

        fs.set_remote_registry(Arc::new(RwLock::new(registry)));

        // Record telemetry
        {
            let now = fs.clock.now();
            let mut telem = fs.replication_telemetry.write().unwrap();
            telem.record_synced_gen("nas", 1, now);
            telem.record_active_part("nas", 2, 3, now);
        }

        let fh2 = fs.open_file_handle(v_ino, 0);
        let updated_bytes = read_core(&fs, v_ino, fh2, 0, 4096).unwrap();
        let updated_status = String::from_utf8(updated_bytes).unwrap();
        fs.release_file_handle(fh2, v_ino).unwrap();

        assert!(updated_status.contains("=== Remote Status (Volume Head Generation: 1) ==="));
        assert!(updated_status.contains("[Remote: nas]"));
        assert!(updated_status.contains("Target:             local/nfs (/mnt/nas)"));
        assert!(updated_status.contains("Read Priority:      10"));
        assert!(updated_status.contains("Status:             Up to date"));
        assert!(updated_status.contains("Active Part:        000002.part0003.log"));

        assert!(updated_status.contains("[Remote: s3]"));
        assert!(updated_status.contains("Target:             s3 (bucket: backup-bucket, prefix: logs/)"));
        assert!(updated_status.contains("Read Priority:      100"));
    }
}
