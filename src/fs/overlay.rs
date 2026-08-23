//! Staging mutations into `live`, and resolving reads across the whole overlay.
//!
//! Mutations only ever touch `live`; the lower layers are immutable until a flush folds
//! into them. Reads go through [`InMemoryFS::with_layer_stack`], which takes all three
//! layer locks in a safe order - see [`super::layers`] for why the order matters.

use super::{InMemoryFS, InodeLayerStack};
use crate::node::{AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, SpecialDelta, SymlinkDelta};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

impl InMemoryFS {
    // --- In-Memory Delta Layer Mutations ---

    pub fn insert_new_node(&self, ino: u64, delta: NodeDelta) {
        self.live.write().unwrap().insert(ino, EntryDelta::Node(delta));
    }

    pub fn tombstone(&self, ino: u64) {
        self.live.write().unwrap().insert(ino, EntryDelta::Tombstone);
    }

    pub fn add_dir_entry(&self, parent: u64, name: &str, child_ino: u64, now: SystemTime) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.removed.remove(name);
            d.added.insert(name.to_string(), child_ino);
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn remove_dir_entry(&self, parent: u64, name: &str, now: SystemTime) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.added.remove(name);
            d.removed.insert(name.to_string());
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn update_dir_parent(&self, ino: u64, new_parent: u64) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.parent = Some(new_parent);
        }
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.with_inode_layers(ino, |layers| layers.parent_dir_inode())
    }

    pub fn update_attr_delta(&self, ino: u64, delta: AttrDelta) {
        let mut live = self.live.write().unwrap();
        match live.get_mut(&ino) {
            // Already deleted in this batch. The fallback below reconstructs a node delta
            // from the lower layers, which for a tombstoned inode would replace the
            // tombstone and bring the inode back from the dead - still carrying its old
            // link count, but with nothing referencing it.
            Some(EntryDelta::Tombstone) => return,
            Some(EntryDelta::Node(node_delta)) => {
                node_delta.attr_delta_mut().merge_from(&delta);
                return;
            }
            None => {}
        }

        // Inode not in live yet - query existing type from lower layers without re-acquiring live lock.
        let file_type = self.with_inode_layers_below_live(ino, |layers| layers.file_type());

        match file_type {
            Some(FileType::Directory) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Directory(DirectoryDelta {
                        parent: None,
                        added: HashMap::new(),
                        removed: HashSet::new(),
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::RegularFile) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::File(FileDelta {
                        extents: RangeMap::new(),
                        size: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Symlink) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Symlink(SymlinkDelta {
                        target: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::NamedPipe) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Fifo(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::CharDevice) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::CharDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::BlockDevice) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::BlockDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Socket) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Socket(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            None => {}
        }
    }

    // --- Overlay Query & Resolution Methods ---

    /// Acquires read locks across all three layers (`live`, `flushing`, `base`) atomically in
    /// consistent safe order and invokes `f` with the combined `InodeLayerStack` for `ino`.
    /// Zero-copy folding executes directly under the read locks.
    pub fn with_inode_layers<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let live = self.live.read().unwrap();
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();

        let base_entry = base.get(&ino);
        let mut deltas = Vec::with_capacity(flushing.len() + 1);
        for batch in flushing.iter() {
            if let Some(entry) = batch.get(&ino) {
                deltas.push(entry);
            }
        }
        if let Some(entry) = live.get(&ino) {
            deltas.push(entry);
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    /// Acquires read locks across `flushing` and `base` layers (skipping `live`) for callers
    /// that already hold `live.write()`.
    pub fn with_inode_layers_below_live<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();

        let base_entry = base.get(&ino);
        let mut deltas = Vec::with_capacity(flushing.len());
        for batch in flushing.iter() {
            if let Some(entry) = batch.get(&ino) {
                deltas.push(entry);
            }
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    /// Executes `f` while holding read locks on all three layers (`live`, `flushing`, `base`).
    pub fn with_layers<R>(
        &self,
        f: impl FnOnce(&HashMap<u64, EntryDelta>, &VecDeque<HashMap<u64, EntryDelta>>, &HashMap<u64, Arc<Node>>) -> R,
    ) -> R {
        let live = self.live.read().unwrap();
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();
        f(&live, &flushing, &base)
    }

    /// Validates whether an inode exists in the layers below `live` (flushing -> base).
    pub fn exists_below_live(&self, ino: u64) -> bool {
        self.with_inode_layers_below_live(ino, |layers| layers.exists())
    }

    /// Resolves full `FileAttr` for an inode across `flushing` -> `base`, skipping `live`.
    /// Used by mutators holding `live.write()`.
    pub fn attr_below_live(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers_below_live(ino, |layers| layers.attr())
    }

    /// Resolves full `FileAttr` for an inode across `live` -> `flushing` -> `base`.
    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers(ino, |layers| layers.attr())
    }

    /// Resolves full `FileAttr`s for a slice of inode IDs across `live` -> `flushing` -> `base`
    /// in a single atomic snapshot pass while holding all three layer read locks concurrently.
    pub fn get_attrs_batch(&self, inos: &[u64]) -> HashMap<u64, FileAttr> {
        self.with_layers(|live, flushing, base| {
            let mut result = HashMap::with_capacity(inos.len());
            for &ino in inos {
                let base_entry = base.get(&ino);
                let mut deltas = Vec::with_capacity(flushing.len() + 1);
                for batch in flushing.iter() {
                    if let Some(entry) = batch.get(&ino) {
                        deltas.push(entry);
                    }
                }
                if let Some(entry) = live.get(&ino) {
                    deltas.push(entry);
                }
                let stack = InodeLayerStack {
                    ino,
                    base: base_entry,
                    deltas,
                };
                if let Some(attr) = stack.attr() {
                    result.insert(ino, attr);
                }
            }
            result
        })
    }

    /// Looks up a child entry by `name` inside `parent` directory across layers.
    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.with_inode_layers(parent, |layers| layers.lookup_child(name))
    }

    /// Lists all consolidated entries of directory `parent` across layers in alphabetical order.
    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.with_inode_layers(parent, |layers| layers.list_directory())
    }

    /// Reads target of a symlink across layers.
    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.with_inode_layers(ino, |layers| layers.read_link())
    }

    /// Resolves an extended attribute value for an inode across live -> flushing -> base layers.
    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.with_inode_layers(ino, |layers| layers.get_xattr(name))
    }

    /// Lists all extended attribute names for an inode across all layers in alphabetical order.
    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.with_inode_layers(ino, |layers| layers.list_xattrs())
    }

    /// Stages a set/replace mutation for an extended attribute.
    pub fn set_xattr(&self, ino: u64, name: &str, value: Vec<u8>, now: SystemTime) {
        let mut xattrs = HashMap::new();
        xattrs.insert(name.to_string(), Some(value));
        let delta = AttrDelta {
            ctime: Some(now),
            xattrs: Some(xattrs),
            ..Default::default()
        };
        self.update_attr_delta(ino, delta);
    }

    /// Stages a removal mutation for an extended attribute.
    pub fn remove_xattr(&self, ino: u64, name: &str, now: SystemTime) {
        let mut xattrs = HashMap::new();
        xattrs.insert(name.to_string(), None);
        let delta = AttrDelta {
            ctime: Some(now),
            xattrs: Some(xattrs),
            ..Default::default()
        };
        self.update_attr_delta(ino, delta);
    }

    /// Reads file data at `[offset, offset + size)` resolving extents across layers.
    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let read_buf = self.with_inode_layers(ino, |layers| layers.read_file_data(offset, size, self))?;

        if self.track_atime {
            let now = self.clock.now();
            self.update_attr_delta(
                ino,
                AttrDelta {
                    atime: Some(now),
                    ..Default::default()
                },
            );
        }

        Ok(read_buf)
    }

    /// Merges all layers into a consolidated snapshot map atomically while holding all 3 layer guards.
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        self.with_layers(|live, flushing, base| {
            let mut result: HashMap<u64, Arc<Node>> = base.clone();

            for flushing_map in flushing.iter() {
                for (ino, entry) in flushing_map {
                    match entry {
                        EntryDelta::Tombstone => {
                            result.remove(ino);
                        }
                        EntryDelta::Node(delta) => {
                            if let Some(existing_arc) = result.get(ino).cloned() {
                                let mut node_clone = (*existing_arc).clone();
                                delta.apply_to_node(&mut node_clone);
                                result.insert(*ino, Arc::new(node_clone));
                            } else {
                                result.insert(*ino, Arc::new(delta.to_node()));
                            }
                        }
                    }
                }
            }

            for (ino, entry) in live.iter() {
                match entry {
                    EntryDelta::Tombstone => {
                        result.remove(ino);
                    }
                    EntryDelta::Node(delta) => {
                        if let Some(existing_arc) = result.get(ino).cloned() {
                            let mut node_clone = (*existing_arc).clone();
                            delta.apply_to_node(&mut node_clone);
                            result.insert(*ino, Arc::new(node_clone));
                        } else {
                            result.insert(*ino, Arc::new(delta.to_node()));
                        }
                    }
                }
            }

            result.retain(|_ino, arc| arc.meta.nlink > 0 || arc.is_dir());

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::log::LogWriter;
    use crate::storage::Storage;

    #[test]
    fn test_exists_below_live_sees_a_tombstone_frozen_out_of_live() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.sync_log().unwrap();
        assert!(fs.exists_below_live(attr.ino));

        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(
            fs.exists_below_live(attr.ino),
            "base still describes the inode until the tombstone's batch folds"
        );

        // Freeze the tombstone out of `live`. From here `live.entry(ino)` sees nothing, so
        // a writer that validated before taking the lock would insert a fresh delta and
        // resurrect the inode at the next fold - this predicate is what stops it.
        fs.begin_flush();
        assert!(!fs.live.read().unwrap().contains_key(&attr.ino));
        assert!(
            !fs.exists_below_live(attr.ino),
            "a tombstone frozen out of live must still report the inode as gone"
        );
    }

    #[test]
    fn test_attr_update_does_not_resurrect_a_tombstoned_inode() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::OsStorage::new(dir.path()));
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        // Fold it into `base`, so the lower layers still describe the inode after deletion.
        fs.sync_log().unwrap();
        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(fs.get_attr(attr.ino).is_none(), "unlinked file must be gone");

        // A late attribute update - an atime bump racing the unlink, say - must not rebuild
        // the node from `base` and bring it back carrying its old link count, unreferenced
        // by any directory.
        fs.update_attr_delta(
            attr.ino,
            AttrDelta {
                atime: Some(clock.now()),
                ..Default::default()
            },
        );
        assert!(
            fs.get_attr(attr.ino).is_none(),
            "attribute update resurrected a deleted inode"
        );
        assert!(
            !fs.snapshot_all().contains_key(&attr.ino),
            "resurrected inode leaked into the snapshot as an orphan"
        );
    }
}
