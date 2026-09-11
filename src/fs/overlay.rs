//! Staging mutations into `live`, and resolving reads across the whole overlay.
//!
//! Mutations only ever touch `live`; the lower layers are immutable until a flush folds
//! into them. Reads go through [`InMemoryFS::with_layer_stack`], which takes all three
//! layer locks in a safe order - see [`super::layers`] for why the order matters.

use super::{FlushBatch, FsInner, InMemoryFS, InodeLayerStack, ReadPlan};
use crate::extent_map::ExtentMap;
use crate::node::{AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, SpecialDelta, SymlinkDelta};
use crate::shim::{FileAttr, FileType};
use crate::sync::OpTag;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

impl FsInner {
    // --- In-Memory Delta Layer Mutations ---

    pub fn insert_new_node(&mut self, ino: u64, delta: NodeDelta) {
        self.live.insert(ino, EntryDelta::Node(delta));
    }

    pub fn tombstone(&mut self, ino: u64) {
        self.live.insert(ino, EntryDelta::Tombstone);
    }

    pub fn add_dir_entry(&mut self, parent: u64, name: &str, child_ino: u64, now: SystemTime) {
        let entry = self
            .live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.removed.remove(name);
            d.added.insert(name.to_string(), child_ino);
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn remove_dir_entry(&mut self, parent: u64, name: &str, now: SystemTime) {
        let entry = self
            .live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.added.remove(name);
            d.removed.insert(name.to_string());
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn update_dir_parent(&mut self, ino: u64, new_parent: u64) {
        let entry = self
            .live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.parent = Some(new_parent);
        }
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.with_inode_layers(ino, |layers| layers.parent_dir_inode())
    }

    pub fn update_attr_delta(&mut self, ino: u64, delta: AttrDelta) {
        match self.live.get_mut(&ino) {
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
                self.live.insert(
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
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::File(FileDelta {
                        extents: ExtentMap::new(),
                        size: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Symlink) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Symlink(SymlinkDelta {
                        target: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::NamedPipe) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Fifo(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::CharDevice) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::CharDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::BlockDevice) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::BlockDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Socket) => {
                self.live.insert(
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

    pub fn with_inode_layers<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let base_entry = self.base.get(&ino);
        let guards: Vec<_> = self.flushing.iter().map(|b| b.entries.read().unwrap()).collect();
        let mut deltas = Vec::with_capacity(guards.len() + 1);
        for guard in &guards {
            if let Some(entry) = guard.get(&ino) {
                deltas.push(entry);
            }
        }
        if let Some(entry) = self.live.get(&ino) {
            deltas.push(entry);
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    pub fn with_inode_layers_below_live<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let base_entry = self.base.get(&ino);
        let guards: Vec<_> = self.flushing.iter().map(|b| b.entries.read().unwrap()).collect();
        let mut deltas = Vec::with_capacity(guards.len());
        for guard in &guards {
            if let Some(entry) = guard.get(&ino) {
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

    pub fn exists_below_live(&self, ino: u64) -> bool {
        self.with_inode_layers_below_live(ino, |layers| layers.exists())
    }

    pub fn attr_below_live(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers_below_live(ino, |layers| layers.attr())
    }

    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers(ino, |layers| layers.attr())
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.with_inode_layers(parent, |layers| layers.lookup_child(name))
    }

    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.with_inode_layers(parent, |layers| layers.list_directory())
    }

    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.with_inode_layers(ino, |layers| layers.read_link())
    }

    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.with_inode_layers(ino, |layers| layers.get_xattr(name))
    }

    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.with_inode_layers(ino, |layers| layers.list_xattrs())
    }

    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        let mut result: HashMap<u64, Arc<Node>> = self.base.clone();

        for batch in self.flushing.iter() {
            let entries = batch.entries.read().unwrap();
            for (ino, entry) in entries.iter() {
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

        for (ino, entry) in self.live.iter() {
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
    }
}

impl InMemoryFS {
    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.inner.lock(OpTag::Lookup).unwrap().get_parent_dir_inode(ino)
    }

    // --- Overlay Query & Resolution Methods ---

    pub fn with_layers<R>(
        &self,
        tag: OpTag,
        f: impl FnOnce(&HashMap<u64, EntryDelta>, &VecDeque<FlushBatch>, &HashMap<u64, Arc<Node>>) -> R,
    ) -> R {
        let inner = self.inner.lock(tag).unwrap();
        f(&inner.live, &inner.flushing, &inner.base)
    }

    pub fn get_attr_locked(&self, inner: &FsInner, ino: u64) -> Option<FileAttr> {
        if self.virtual_files.is_virtual_ino(ino) {
            return Some(self.virtual_files.file_attr(ino, 0, self.clock.now()));
        }
        inner.get_attr(ino)
    }

    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.get_attr_locked(&self.inner.lock(OpTag::GetAttr).unwrap(), ino)
    }

    pub fn lookup_child_locked(&self, inner: &FsInner, parent: u64, name: &str) -> Option<u64> {
        if parent == 1
            && let Some(ino) = self.virtual_files.get_ino_by_name(name)
        {
            return Some(ino);
        }
        inner.lookup_child(parent, name)
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.lookup_child_locked(&self.inner.lock(OpTag::Lookup).unwrap(), parent, name)
    }

    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.inner.lock(OpTag::ReadDir).unwrap().list_directory(parent)
    }

    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.inner.lock(OpTag::ReadLink).unwrap().read_link(ino)
    }

    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.inner.lock(OpTag::Xattr).unwrap().get_xattr(ino, name)
    }

    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.inner.lock(OpTag::Xattr).unwrap().list_xattrs(ino)
    }

    pub fn plan_read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<ReadPlan, i32> {
        self.with_inner(OpTag::ReadPlan, |inner| {
            let plan = inner.with_inode_layers(ino, |layers| {
                layers.plan_read_file_data(offset, size, self.log_cache.as_deref())
            })?;

            if self.track_atime && plan.total_len > 0 {
                let now = self.clock.now();
                inner.update_attr_delta(
                    ino,
                    AttrDelta {
                        atime: Some(now),
                        ..Default::default()
                    },
                );
                inner.record_mutation(0);
            }

            Ok(plan)
        })
    }

    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let plan = self.plan_read_file_data(ino, offset, size)?;
        self.execute_read_plan_sync(plan)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        self.inner.lock_for_tests().unwrap().snapshot_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::log::{FlushMotivation, LogWriter};
    use crate::storage::Storage;

    #[test]
    fn test_exists_below_live_sees_a_tombstone_frozen_out_of_live() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
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
        let fs = InMemoryFS::with_clock_and_log(clock, Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.sync_log().unwrap();
        assert!(fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino));

        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(
            fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino),
            "base still describes the inode until the tombstone's batch folds"
        );

        // Freeze the tombstone out of `live`. From here `live.entry(ino)` sees nothing, so
        // a writer that validated before taking the lock would insert a fresh delta and
        // resurrect the inode at the next fold - this predicate is what stops it.
        fs.begin_flush(FlushMotivation::Test);
        assert!(!fs.inner.lock_for_tests().unwrap().live.contains_key(&attr.ino));
        assert!(
            !fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino),
            "a tombstone frozen out of live must still report the inode as gone"
        );
    }

    #[test]
    fn test_attr_update_does_not_resurrect_a_tombstoned_inode() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
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
        fs.with_inner_for_tests(|inner| {
            inner.update_attr_delta(
                attr.ino,
                AttrDelta {
                    atime: Some(clock.now()),
                    ..Default::default()
                },
            );
        });
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
