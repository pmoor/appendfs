//! Staging mutations into `live`, and resolving reads across the whole overlay.
//!
//! Mutations only ever touch `live`; the lower layers are immutable until a flush folds
//! into them. Reads go through [`InMemoryFS::with_layer_stack`], which takes all three
//! layer locks in a safe order - see [`super::layers`] for why the order matters.

use super::{FlushBatch, FsInner, InMemoryFS, InodeLayerStack, is_virtual_ino};
// Only the test-only by-inode read helpers at the bottom of this file return these.
#[cfg(any(test, feature = "testing"))]
use super::ReadPlan;
#[cfg(any(test, feature = "testing"))]
use crate::error::FsError;
use crate::extent_map::ExtentMap;
use crate::node::{
    AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, NodeKind, SpecialDelta, SymlinkDelta,
};
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
        let mut deltas = Vec::with_capacity(self.flushing.len() + 1);
        for batch in self.flushing.iter() {
            if let Some(entry) = batch.entries.get(&ino) {
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
        let mut deltas = Vec::with_capacity(self.flushing.len());
        for batch in self.flushing.iter() {
            if let Some(entry) = batch.entries.get(&ino) {
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

    /// Normalizes directory deltas across a batch about to be flushed against the folded `base`
    /// and any preceding flushing layers underneath it (`flushing[0..flushing_index]`).
    ///
    /// When self-canceling directory operations occur within the same flush batch (such as `mv a b; mv b a`,
    /// or `touch foo; rm foo`), or across coalesced batches in `flushing`, the in-memory `DirectoryDelta`
    /// accumulates redundant additions and phantom tombstones (e.g. `added: ["a" -> 123], removed: ["b"]`).
    ///
    /// Normalization inspects the underlying layer stack (`base` + `flushing[0..flushing_index]`):
    /// - Retains `added` entries only if the underlying layers do not already map `name` to the exact same `child_ino`.
    /// - Retains `removed` entries only if `name` actually existed in the underlying layers.
    ///
    /// This eliminates redundant additions and phantom tombstones from log batches with zero disk I/O,
    /// writing only genuinely modified directory entries or pure timestamp attribute deltas.
    pub fn normalize_directory_deltas(&self, entries: &mut HashMap<u64, EntryDelta>, flushing_index: usize) {
        for (&ino, entry) in entries.iter_mut() {
            if let EntryDelta::Node(NodeDelta::Directory(dir_delta)) = entry {
                let mut lower_deltas = Vec::with_capacity(flushing_index);
                for batch in self.flushing.iter().take(flushing_index) {
                    if let Some(e) = batch.entries.get(&ino) {
                        lower_deltas.push(e);
                    }
                }
                let stack = InodeLayerStack {
                    ino,
                    base: self.base.get(&ino),
                    deltas: lower_deltas,
                };

                if !stack.exists() || stack.file_type() != Some(FileType::Directory) {
                    dir_delta.removed.clear();
                } else {
                    dir_delta
                        .added
                        .retain(|name, &mut child_ino| stack.lookup_child(name) != Some(child_ino));
                    dir_delta.removed.retain(|name| stack.lookup_child(name).is_some());
                }
            }
        }
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
            for (ino, entry) in &batch.entries {
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

    /// Computes active inode counts and total logical byte size across all overlay layers in a single pass.
    pub fn inode_counts(&self) -> InodeCounts {
        let mut dirs = 0;
        let mut files = 0;
        let mut symlinks = 0;
        let mut named_pipes = 0;
        let mut char_devices = 0;
        let mut block_devices = 0;
        let mut sockets = 0;
        let mut total_logical_bytes = 0;

        let mut count_ft = |ft: FileType| match ft {
            FileType::Directory => dirs += 1,
            FileType::RegularFile => files += 1,
            FileType::Symlink => symlinks += 1,
            FileType::NamedPipe => named_pipes += 1,
            FileType::CharDevice => char_devices += 1,
            FileType::BlockDevice => block_devices += 1,
            FileType::Socket => sockets += 1,
        };

        let overlay_cap = self.live.len() + self.flushing.iter().map(|b| b.entries.len()).sum::<usize>();
        let mut seen_overlay = HashSet::with_capacity(overlay_cap);

        let mut process_node_delta = |ino: u64, d: &NodeDelta| {
            count_ft(d.file_type());
            if let NodeDelta::File(f) = d {
                let size = if let Some(s) = f.size {
                    s
                } else {
                    self.with_inode_layers(ino, |layers| layers.attr().map(|a| a.size as u64).unwrap_or(0))
                };
                total_logical_bytes += size;
            }
        };

        for (&ino, delta) in &self.live {
            seen_overlay.insert(ino);
            match delta {
                EntryDelta::Node(d) => process_node_delta(ino, d),
                EntryDelta::Tombstone => {}
            }
        }

        for batch in self.flushing.iter().rev() {
            for (&ino, delta) in &batch.entries {
                if seen_overlay.insert(ino) {
                    match delta {
                        EntryDelta::Node(d) => process_node_delta(ino, d),
                        EntryDelta::Tombstone => {}
                    }
                }
            }
        }

        for (&ino, node) in &self.base {
            if !seen_overlay.contains(&ino) {
                count_ft(node.file_type());
                if let NodeKind::File { size, .. } = &node.kind {
                    total_logical_bytes += size;
                }
            }
        }

        InodeCounts {
            directories: dirs,
            files,
            symlinks,
            named_pipes,
            char_devices,
            block_devices,
            sockets,
            total_logical_bytes,
        }
    }

    /// Captures a point-in-time snapshot of internal metrics while the lock is already held.
    pub fn stats_snapshot(&self) -> InnerStatsSnapshot {
        let (file_handles_count, virt_handles_count, dir_handles_count) = self.handle_counts();
        InnerStatsSnapshot {
            recovered_time: self.recovered_time,
            inode_counts: self.inode_counts(),
            live_len: self.live.len(),
            flushing_batches: self.flushing.len(),
            base_len: self.base.len(),
            staged_bytes: self.staged_bytes,
            staged_ops: self.staged_ops,
            flushing_bytes: self.flushing_bytes,
            flushing_ops: self.flushing_ops,
            file_handles_count,
            virt_handles_count,
            dir_handles_count,
            open_inodes_count: self.open_counts.len(),
            flock_count: self.locks.flock_count(),
            range_lock_count: self.locks.range_lock_count(),
        }
    }
}

/// Category breakdown of active inodes across all overlay layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InodeCounts {
    pub directories: usize,
    pub files: usize,
    pub symlinks: usize,
    pub named_pipes: usize,
    pub char_devices: usize,
    pub block_devices: usize,
    pub sockets: usize,
    pub total_logical_bytes: u64,
}

impl InodeCounts {
    /// Computes active inode counts and total logical byte size directly from an iterator of nodes.
    pub fn from_nodes<'a, I>(nodes: I) -> Self
    where
        I: IntoIterator<Item = &'a crate::node::Node>,
    {
        let mut counts = Self::default();
        for node in nodes {
            match &node.kind {
                crate::node::NodeKind::Directory { .. } => counts.directories += 1,
                crate::node::NodeKind::File { size, .. } => {
                    counts.files += 1;
                    counts.total_logical_bytes += *size;
                }
                crate::node::NodeKind::Symlink { .. } => counts.symlinks += 1,
                crate::node::NodeKind::Fifo => counts.named_pipes += 1,
                crate::node::NodeKind::CharDevice { .. } => counts.char_devices += 1,
                crate::node::NodeKind::BlockDevice { .. } => counts.block_devices += 1,
                crate::node::NodeKind::Socket => counts.sockets += 1,
            }
        }
        counts
    }

    /// Total number of active inodes across all types.
    pub fn total_active(&self) -> usize {
        self.directories + self.files + self.symlinks + self.special()
    }

    /// Total number of special files (named pipes, char devices, block devices, and sockets).
    pub fn special(&self) -> usize {
        self.named_pipes + self.char_devices + self.block_devices + self.sockets
    }
}

/// Point-in-time snapshot of internal mutable filesystem metrics collected under a single lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InnerStatsSnapshot {
    pub recovered_time: Option<SystemTime>,
    pub inode_counts: InodeCounts,
    pub live_len: usize,
    pub flushing_batches: usize,
    pub base_len: usize,
    pub staged_bytes: usize,
    pub staged_ops: usize,
    pub flushing_bytes: usize,
    pub flushing_ops: usize,
    pub file_handles_count: usize,
    pub virt_handles_count: usize,
    pub dir_handles_count: usize,
    pub open_inodes_count: usize,
    pub flock_count: usize,
    pub range_lock_count: usize,
}

impl InMemoryFS {
    /// Takes a point-in-time snapshot of internal filesystem metrics using a single mutex lock.
    pub fn stats_snapshot(&self) -> InnerStatsSnapshot {
        self.inner.lock(OpTag::Stats).unwrap().stats_snapshot()
    }

    /// Computes active inode counts across the overlay layers using a single mutex lock.
    pub fn inode_counts(&self) -> InodeCounts {
        self.inner.lock(OpTag::Stats).unwrap().inode_counts()
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.inner.lock(OpTag::Lookup).unwrap().get_parent_dir_inode(ino)
    }

    // --- Overlay Query & Resolution Methods ---

    pub fn with_layers<R>(
        &self,
        tag: OpTag,
        f: impl FnOnce(&HashMap<u64, EntryDelta>, &VecDeque<Arc<FlushBatch>>, &HashMap<u64, Arc<Node>>) -> R,
    ) -> R {
        let inner = self.inner.lock(tag).unwrap();
        f(&inner.live, &inner.flushing, &inner.base)
    }

    pub fn get_attr_locked(&self, inner: &FsInner, ino: u64) -> Option<FileAttr> {
        if is_virtual_ino(ino) {
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

    /// Plans a read by inode alone, without an open handle.
    ///
    /// Test-only. Real reads arrive with a file handle and go through
    /// [`InMemoryFS::plan_read_handle`], which additionally validates the handle and serves
    /// virtual files; this exists so tests can read an inode without opening it first.
    #[cfg(any(test, feature = "testing"))]
    pub fn plan_read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<ReadPlan, FsError> {
        self.with_inner(OpTag::ReadPlan, |inner| {
            inner.check_shutdown(false)?;
            let plan = inner.with_inode_layers(ino, |layers| {
                layers.plan_read_file_data(offset, size, self.log_cache.as_deref())
            })?;

            if self.track_atime && plan.total_len > 0 && inner.shutdown_state == super::ShutdownState::Running {
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

    /// Reads file contents by inode alone, without an open handle. Test-only; see
    /// [`InMemoryFS::plan_read_file_data`].
    #[cfg(any(test, feature = "testing"))]
    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, FsError> {
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
    use crate::log::LogWriter;
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
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();
        assert!(fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino));

        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(
            fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino),
            "base still describes the inode until the tombstone's batch folds"
        );

        // Freeze the tombstone out of `live`. From here `live.entry(ino)` sees nothing, so
        // a writer that validated before taking the lock would insert a fresh delta and
        // resurrect the inode at the next fold - this predicate is what stops it.
        fs.freeze_now();
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
        fs.quiesce().unwrap();
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

    #[test]
    fn test_normalize_directory_deltas_touch_and_rm_same_batch() {
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

        // Create and immediately unlink in the same batch
        let _attr = crate::operations::read_write::create_core(&fs, 1, "temp.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::unlink_core(&fs, 1, "temp.txt").unwrap();

        // Before freeze, live has a phantom tombstone in removed
        fs.with_inner_for_tests(|inner| {
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = inner.live.get(&1) {
                assert!(d.removed.contains("temp.txt"), "live must stage the removal");
                assert!(!d.added.contains_key("temp.txt"), "live must not retain added entry");
            } else {
                panic!("expected directory delta in live");
            }
        });

        // Freeze live into flushing
        assert!(fs.freeze_now());

        // Pre-flush normalization against base prunes the phantom tombstone
        fs.with_inner_for_tests(|inner| {
            let batch = inner.flushing.back().expect("batch must be in flushing");
            let mut entries = batch.entries.clone();
            inner.normalize_directory_deltas(&mut entries, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = entries.get(&1) {
                assert!(
                    d.removed.is_empty(),
                    "phantom tombstone must be pruned by normalization: {:?}",
                    d.removed
                );
                assert!(d.added.is_empty(), "added must remain empty");
                assert!(d.attr_delta.mtime.is_some(), "mtime update must be preserved");
                assert!(d.attr_delta.ctime.is_some(), "ctime update must be preserved");
            } else {
                panic!("expected directory delta in normalized entries");
            }
        });
    }

    #[test]
    fn test_normalize_directory_deltas_self_canceling_rename() {
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

        // Create file.txt and fold into base
        let attr = crate::operations::read_write::create_core(&fs, 1, "file.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();

        // Self-canceling rename: file.txt -> tmp.txt -> file.txt
        crate::operations::links::rename_core(&fs, 1, "file.txt", 1, "tmp.txt").unwrap();
        crate::operations::links::rename_core(&fs, 1, "tmp.txt", 1, "file.txt").unwrap();

        // Before freeze, live contains redundant added: "file.txt" and phantom removed: "tmp.txt"
        fs.with_inner_for_tests(|inner| {
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = inner.live.get(&1) {
                assert!(d.added.contains_key("file.txt"), "live has redundant addition");
                assert!(d.removed.contains("tmp.txt"), "live has phantom removal");
            } else {
                panic!("expected directory delta in live");
            }
        });

        // Freeze live into flushing
        assert!(fs.freeze_now());

        // Pre-flush normalization against base prunes both redundant addition and phantom tombstone
        fs.with_inner_for_tests(|inner| {
            let batch = inner.flushing.back().expect("batch must be in flushing");
            let mut entries = batch.entries.clone();
            inner.normalize_directory_deltas(&mut entries, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = entries.get(&1) {
                assert!(d.added.is_empty(), "redundant addition must be pruned: {:?}", d.added);
                assert!(
                    d.removed.is_empty(),
                    "phantom tombstone must be pruned: {:?}",
                    d.removed
                );
                assert!(d.attr_delta.mtime.is_some(), "mtime update must be preserved");
            } else {
                panic!("expected directory delta in normalized entries");
            }
        });

        // File remains fully accessible
        assert_eq!(fs.lookup_child(1, "file.txt"), Some(attr.ino));
        assert_eq!(fs.lookup_child(1, "tmp.txt"), None);
    }

    #[test]
    fn test_normalize_directory_deltas_chained_rename() {
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

        // Create a.txt and fold into base
        let attr = crate::operations::read_write::create_core(&fs, 1, "a.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();

        // Chained rename: a.txt -> b.txt -> c.txt in the same batch
        crate::operations::links::rename_core(&fs, 1, "a.txt", 1, "b.txt").unwrap();
        crate::operations::links::rename_core(&fs, 1, "b.txt", 1, "c.txt").unwrap();

        // Freeze live into flushing
        assert!(fs.freeze_now());

        fs.with_inner_for_tests(|inner| {
            let batch = inner.flushing.back().expect("batch must be in flushing");
            let mut entries = batch.entries.clone();
            inner.normalize_directory_deltas(&mut entries, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = entries.get(&1) {
                assert_eq!(d.added.get("c.txt"), Some(&attr.ino), "c.txt must be retained in added");
                assert!(
                    !d.added.contains_key("b.txt"),
                    "intermediate b.txt must not be in added"
                );
                assert!(d.removed.contains("a.txt"), "original a.txt must be in removed");
                assert!(
                    !d.removed.contains("b.txt"),
                    "intermediate phantom tombstone b.txt must be pruned"
                );
            } else {
                panic!("expected directory delta in normalized entries");
            }
        });
    }

    #[test]
    fn test_normalize_directory_deltas_across_flushing_batches() {
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

        // Batch 1: create file1.txt and flush (which folds into base)
        let _attr = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();

        // Batch 2: unlink file1.txt in live
        crate::operations::links::unlink_core(&fs, 1, "file1.txt").unwrap();
        assert!(fs.freeze_now());

        // Batch 2 must retain "file1.txt" in removed because it exists in folded base
        fs.with_inner_for_tests(|inner| {
            let batch2 = inner.flushing.back().expect("batch2 must be in flushing");
            let mut entries2 = batch2.entries.clone();
            inner.normalize_directory_deltas(&mut entries2, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = entries2.get(&1) {
                assert!(
                    d.removed.contains("file1.txt"),
                    "file1.txt must be retained in removed since it existed in base"
                );
            } else {
                panic!("expected directory delta in batch2");
            }
        });
    }

    #[test]
    fn test_normalize_directory_deltas_across_multiple_unflushed_batches() {
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

        // Initial setup in base: base has root (ino 1) containing "existing.txt"
        let existing_attr =
            crate::operations::read_write::create_core(&fs, 1, "existing.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();

        // Batch 0 (frozen, unflushed):
        // 1. Create file1.txt
        // 2. Hardlink existing.txt to keep inode alive, then unlink existing.txt
        let _f1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::link_core(&fs, existing_attr.ino, 1, "existing_link.txt").unwrap();
        crate::operations::links::unlink_core(&fs, 1, "existing.txt").unwrap();
        assert!(fs.freeze_now());

        // Batch 1 (frozen, unflushed):
        // 1. Unlink file1.txt (which was created in Batch 0, NOT in base!)
        // 2. Re-create existing.txt with the same inode (which was unlinked in Batch 0, but still in base!)
        crate::operations::links::unlink_core(&fs, 1, "file1.txt").unwrap();
        crate::operations::links::link_core(&fs, existing_attr.ino, 1, "existing.txt").unwrap();
        assert!(fs.freeze_now());

        fs.with_inner_for_tests(|inner| {
            assert_eq!(inner.flushing.len(), 2);

            // Test normalizing Batch 0 against base (index 0)
            let mut entries0 = inner.flushing[0].entries.clone();
            inner.normalize_directory_deltas(&mut entries0, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d0))) = entries0.get(&1) {
                assert!(d0.added.contains_key("file1.txt"));
                assert!(d0.removed.contains("existing.txt"));
            } else {
                panic!("expected directory delta in batch 0");
            }

            // Test normalizing Batch 1 against base + Batch 0 (index 1)
            let mut entries1 = inner.flushing[1].entries.clone();
            inner.normalize_directory_deltas(&mut entries1, 1);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d1))) = entries1.get(&1) {
                // file1.txt was created in Batch 0. Normalizing Batch 1 against Batch 0 MUST retain file1.txt in removed!
                assert!(
                    d1.removed.contains("file1.txt"),
                    "file1.txt must be retained in removed because it exists in flushing[0]"
                );
                // existing.txt was removed in Batch 0. Normalizing Batch 1 against Batch 0 MUST retain existing.txt in added!
                assert!(
                    d1.added.contains_key("existing.txt"),
                    "existing.txt must be retained in added because it was removed in flushing[0]"
                );
            } else {
                panic!("expected directory delta in batch 1");
            }

            // Verify that if we incorrectly normalized Batch 1 against index 0 (only base):
            // It would have wrongly dropped file1.txt from removed (since base didn't have it)
            // and wrongly dropped existing.txt from added (since base already had it with the same inode)!
            let mut entries1_buggy = inner.flushing[1].entries.clone();
            inner.normalize_directory_deltas(&mut entries1_buggy, 0);
            if let Some(EntryDelta::Node(NodeDelta::Directory(d1_buggy))) = entries1_buggy.get(&1) {
                assert!(
                    !d1_buggy.removed.contains("file1.txt"),
                    "demonstrating that index 0 would wrongly prune file1.txt"
                );
                assert!(
                    !d1_buggy.added.contains_key("existing.txt"),
                    "demonstrating that index 0 would wrongly prune existing.txt"
                );
            }
        });
    }
}
