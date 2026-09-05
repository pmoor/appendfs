//! Race-free layered reads over the `base` <- `flushing` <- `live` overlay.
//!
//! Every read that spans layers goes through [`InodeLayerStack`], which is constructed
//! while all the relevant layer read locks are held (see
//! [`InMemoryFS::with_layer_stack`](crate::fs::InMemoryFS::with_layer_stack)) and folds
//! oldest-to-newest without copying. Reading the layers one lock at a time instead is
//! unsound: a flush moves a batch strictly downward (`live` -> `flushing` -> `base`) in
//! two separate lock acquisitions, so a walk that reads an older layer before a newer
//! one can straddle that move and miss the batch entirely.

use super::InMemoryFS;
use crate::log::{ExtentState, SharedExtentState};
use crate::node::{EntryDelta, Node, NodeDelta, NodeKind};
use crate::shim::{FileAttr, FileType};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

// --- Layer Stack Snapshot & Fold Abstraction ---

/// Borrowed snapshot view of an inode's layer hierarchy (`base` plus chronological `deltas`).
/// Constructed while holding all necessary layer read locks, enabling race-free,
/// zero-copy folding directly under the locks.
pub struct InodeLayerStack<'a> {
    pub ino: u64,
    pub base: Option<&'a Arc<Node>>,
    /// Chronological list of entry deltas ordered from oldest to newest (`flushing[0]` ... `flushing[n]`, `[live]`).
    pub deltas: Vec<&'a EntryDelta>,
}

impl<'a> InodeLayerStack<'a> {
    /// Resolves full `FileAttr` across `base` and `deltas` (folded oldest to newest).
    pub fn attr(&self) -> Option<FileAttr> {
        let mut attr = self.base.map(|arc| arc.to_attr(self.ino));
        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    attr = None;
                }
                EntryDelta::Node(d) => {
                    let a = attr.get_or_insert_with(|| d.initial_attr(self.ino));
                    d.apply_to_attr(a);
                }
            }
        }
        attr
    }

    /// Checks if the inode exists (is not tombstoned and present in deltas or base).
    pub fn exists(&self) -> bool {
        if let Some(delta) = self.deltas.last() {
            return matches!(delta, EntryDelta::Node(_));
        }
        self.base.is_some()
    }

    /// Resolves the file type of the inode (checking newest deltas first).
    pub fn file_type(&self) -> Option<FileType> {
        if let Some(delta) = self.deltas.last() {
            return match delta {
                EntryDelta::Tombstone => None,
                EntryDelta::Node(d) => Some(d.file_type()),
            };
        }
        self.base.map(|arc| arc.file_type())
    }

    /// Looks up a child entry by `name` inside directory `self.ino`.
    pub fn lookup_child(&self, name: &str) -> Option<u64> {
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    if d.removed.contains(name) {
                        return None;
                    }
                    if let Some(&ino) = d.added.get(name) {
                        return Some(ino);
                    }
                }
                _ => return None,
            }
        }

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind
                && let Some((_, ino)) = entries.iter().find(|(entry_name, _)| entry_name == name)
            {
                return Some(*ino);
            }
        }

        None
    }

    /// Lists all consolidated directory entries across layers in alphabetical order.
    pub fn list_directory(&self) -> Option<Vec<(String, u64)>> {
        let attr = self.attr()?;
        if attr.file_type != FileType::Directory {
            return None;
        }

        let mut map: HashMap<String, u64> = HashMap::new();

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind {
                for (name, child_ino) in entries {
                    map.insert(name.clone(), *child_ino);
                }
            }
        }

        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    map.clear();
                }
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    for name in &d.removed {
                        map.remove(name);
                    }
                    for (name, child_ino) in &d.added {
                        map.insert(name.clone(), *child_ino);
                    }
                }
                _ => {}
            }
        }

        let mut list: Vec<(String, u64)> = map.into_iter().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        Some(list)
    }

    /// Reads target of a symlink across layers.
    pub fn read_link(&self) -> Option<String> {
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Symlink(s)) => {
                    if let Some(ref t) = s.target {
                        return Some(t.clone());
                    }
                }
                _ => return None,
            }
        }

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Symlink { target, .. } = &node.kind {
                return Some(target.clone());
            }
        }

        None
    }

    /// Returns the parent directory inode.
    pub fn parent_dir_inode(&self) -> Option<u64> {
        if self.ino == 1 {
            return Some(1);
        }

        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    if let Some(p) = d.parent {
                        return Some(p);
                    }
                }
                _ => return None,
            }
        }

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { parent, .. } = &node.kind {
                return Some(*parent);
            }
        }

        None
    }

    /// Resolves an extended attribute value by `name`.
    pub fn get_xattr(&self, name: &str) -> Option<Vec<u8>> {
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(d) => {
                    if let Some(ref xattrs) = d.attr_delta().xattrs
                        && let Some(val_opt) = xattrs.get(name)
                    {
                        return val_opt.clone();
                    }
                }
            }
        }

        if let Some(arc) = self.base
            && let Some(ref xattrs) = arc.meta.xattrs
        {
            return xattrs.get(name).cloned();
        }

        None
    }

    /// Lists all extended attribute names across layers in alphabetical order.
    pub fn list_xattrs(&self) -> Option<Vec<String>> {
        let _attr = self.attr()?;
        let mut names: BTreeSet<String> = BTreeSet::new();

        if let Some(arc) = self.base
            && let Some(ref xattrs) = arc.meta.xattrs
        {
            for k in xattrs.keys() {
                names.insert(k.clone());
            }
        }

        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    names.clear();
                }
                EntryDelta::Node(d) => {
                    if let Some(ref xattrs) = d.attr_delta().xattrs {
                        for (k, v) in xattrs {
                            if v.is_some() {
                                names.insert(k.clone());
                            } else {
                                names.remove(k);
                            }
                        }
                    }
                }
            }
        }

        Some(names.into_iter().collect())
    }

    /// Plans a read across layers, resolving extents into disjoint, ordered [`ReadSlice`] descriptors.
    ///
    /// For memory-resident chunks (staged extents or in-memory decrypted record cache hits),
    /// references to [`Arc<Vec<u8>>`] are cloned with zero byte-copying.
    ///
    /// If all requested bytes are covered by in-memory slices or holes, `has_cold_slices` will be false.
    pub fn plan_read_file_data(&self, offset: u64, size: usize, fs: &InMemoryFS) -> Result<ReadPlan, i32> {
        let attr = self.attr().ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(libc::EISDIR);
        }

        let file_size = attr.size as u64;
        if offset >= file_size {
            return Ok(ReadPlan::empty());
        }

        let read_len = std::cmp::min(size as u64, file_size - offset) as usize;
        let mut filled = vec![false; read_len];
        let mut raw_slices = Vec::new();

        let mut add_extent = |ext_start: u64, ext_len: u64, shared_state: &SharedExtentState| {
            let seg_start = std::cmp::max(offset, ext_start);
            let seg_end = std::cmp::min(offset + read_len as u64, ext_start + ext_len);
            if seg_start >= seg_end {
                return;
            }

            let dst_offset = (seg_start - offset) as usize;
            let seg_len = (seg_end - seg_start) as usize;
            let slice_inner_offset = (seg_start - ext_start) as usize;

            if filled[dst_offset..dst_offset + seg_len].iter().all(|&b| b) {
                return;
            }

            // Find all contiguous unfilled intervals within [dst_offset..dst_offset + seg_len]
            let mut idx = dst_offset;
            let end_idx = dst_offset + seg_len;
            while idx < end_idx {
                if filled[idx] {
                    idx += 1;
                    continue;
                }
                let sub_start = idx;
                while idx < end_idx && !filled[idx] {
                    filled[idx] = true;
                    idx += 1;
                }
                let sub_end = idx;
                let sub_len = sub_end - sub_start;
                let inner_offset = slice_inner_offset + (sub_start - dst_offset);

                let state = shared_state.read_state();
                let source = match state {
                    ExtentState::Zero { .. } => ReadSliceSource::Zero,
                    ExtentState::Staged {
                        data,
                        payload_offset,
                        length: _,
                    } => {
                        let src_offset = payload_offset as usize + inner_offset;
                        ReadSliceSource::Memory { data, src_offset }
                    }
                    ExtentState::Disk {
                        generation,
                        record_log_offset,
                        payload_offset,
                        length: _,
                    } => {
                        let cached = fs
                            .log_cache
                            .as_ref()
                            .and_then(|c| c.decrypted_cache.get(generation, record_log_offset));
                        if let Some(cached_data) = cached {
                            let src_offset = payload_offset as usize + inner_offset;
                            ReadSliceSource::Memory {
                                data: cached_data,
                                src_offset,
                            }
                        } else {
                            ReadSliceSource::Disk {
                                generation,
                                record_log_offset,
                                payload_offset,
                                slice_inner_offset: inner_offset as u32,
                            }
                        }
                    }
                };

                raw_slices.push(ReadSlice {
                    dst_offset: sub_start,
                    len: sub_len,
                    source,
                });
            }
        };

        let mut hit_tombstone = false;
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => {
                    hit_tombstone = true;
                    break;
                }
                EntryDelta::Node(NodeDelta::File(f)) => {
                    for (ext_start, ext_len, shared_state) in f.extents.query(offset, read_len as u64) {
                        add_extent(ext_start, ext_len, &shared_state);
                    }
                }
                _ => {}
            }
        }

        if !hit_tombstone && let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                for (ext_start, ext_len, shared_state) in range_map.query(offset, read_len as u64) {
                    add_extent(ext_start, ext_len, &shared_state);
                }
            }
        }

        // Any bytes never covered by any extent are holes (Zero)
        let mut idx = 0;
        while idx < read_len {
            if filled[idx] {
                idx += 1;
                continue;
            }
            let hole_start = idx;
            while idx < read_len && !filled[idx] {
                idx += 1;
            }
            raw_slices.push(ReadSlice {
                dst_offset: hole_start,
                len: idx - hole_start,
                source: ReadSliceSource::Zero,
            });
        }

        raw_slices.sort_by_key(|s| s.dst_offset);

        // Coalesce adjacent contiguous slices with matching source
        let mut coalesced: Vec<ReadSlice> = Vec::with_capacity(raw_slices.len());
        for slice in raw_slices {
            if let Some(prev) = coalesced.last_mut()
                && prev.dst_offset + prev.len == slice.dst_offset
            {
                match (&mut prev.source, &slice.source) {
                    (ReadSliceSource::Zero, ReadSliceSource::Zero) => {
                        prev.len += slice.len;
                        continue;
                    }
                    (
                        ReadSliceSource::Memory {
                            data: d1,
                            src_offset: s1,
                        },
                        ReadSliceSource::Memory {
                            data: d2,
                            src_offset: s2,
                        },
                    ) if Arc::ptr_eq(d1, d2) && *s1 + prev.len == *s2 => {
                        prev.len += slice.len;
                        continue;
                    }
                    (
                        ReadSliceSource::Disk {
                            generation: g1,
                            record_log_offset: r1,
                            payload_offset: p1,
                            slice_inner_offset: i1,
                        },
                        ReadSliceSource::Disk {
                            generation: g2,
                            record_log_offset: r2,
                            payload_offset: p2,
                            slice_inner_offset: i2,
                        },
                    ) if g1 == g2 && r1 == r2 && p1 == p2 && *i1 + prev.len as u32 == *i2 => {
                        prev.len += slice.len;
                        continue;
                    }
                    _ => {}
                }
            }
            coalesced.push(slice);
        }

        let has_cold_slices = coalesced
            .iter()
            .any(|s| matches!(s.source, ReadSliceSource::Disk { .. }));

        Ok(ReadPlan {
            total_len: read_len,
            has_cold_slices,
            slices: coalesced,
        })
    }

    /// Reads file data resolving extents across layers.
    pub fn read_file_data(&self, offset: u64, size: usize, fs: &InMemoryFS) -> Result<Vec<u8>, i32> {
        let plan = self.plan_read_file_data(offset, size, fs)?;
        fs.execute_read_plan_sync(&plan)
    }
}

/// Source of data for a specific byte segment within a read plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadSliceSource {
    /// Zero-filled (hole, punch-hole, or truncated region).
    Zero,
    /// In-memory: atomic pointer clone of `Arc<Vec<u8>>` (~10 ns).
    Memory { data: Arc<Vec<u8>>, src_offset: usize },
    /// Cold disk or remote S3 extent.
    Disk {
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        slice_inner_offset: u32,
    },
}

/// A contiguous segment of data within a read plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadSlice {
    pub dst_offset: usize,
    pub len: usize,
    pub source: ReadSliceSource,
}

/// A complete recipe for fulfilling a read request across layer boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    pub total_len: usize,
    pub has_cold_slices: bool,
    pub slices: Vec<ReadSlice>,
}

impl ReadPlan {
    pub fn empty() -> Self {
        Self {
            total_len: 0,
            has_cold_slices: false,
            slices: Vec::new(),
        }
    }
}

impl InMemoryFS {
    /// Executes a [`ReadPlan`] synchronously, reading any cold disk extents via [`LogFileCache`].
    pub fn execute_read_plan_sync(&self, plan: &ReadPlan) -> Result<Vec<u8>, i32> {
        execute_read_plan(plan, self.log_cache.as_deref(), &self.volume_key)
    }

    /// Executes a [`ReadPlan`] asynchronously, offloading cold disk I/O and large memory copies
    /// to the Tokio thread pool with zero locks on [`InMemoryFS`].
    pub async fn execute_read_plan_async(
        plan: ReadPlan,
        log_cache: Option<Arc<crate::log::LogFileCache>>,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> Result<Vec<u8>, i32> {
        tokio::task::spawn_blocking(move || execute_read_plan(&plan, log_cache.as_deref(), &volume_key))
            .await
            .map_err(|_| libc::EIO)?
    }
}

/// Core execution helper for [`ReadPlan`] completely decoupled from [`InMemoryFS`].
pub fn execute_read_plan(
    plan: &ReadPlan,
    log_cache: Option<&crate::log::LogFileCache>,
    volume_key: &crate::crypto::VolumeKey,
) -> Result<Vec<u8>, i32> {
    let mut dst_buf = vec![0u8; plan.total_len];
    for slice in &plan.slices {
        match &slice.source {
            ReadSliceSource::Zero => {}
            ReadSliceSource::Memory { data, src_offset } => {
                let src_start = *src_offset;
                let src_end = std::cmp::min(src_start + slice.len, data.len());
                let actual_len = std::cmp::min(slice.len, src_end.saturating_sub(src_start));
                if actual_len > 0 && src_start < data.len() {
                    dst_buf[slice.dst_offset..slice.dst_offset + actual_len]
                        .copy_from_slice(&data[src_start..src_start + actual_len]);
                }
            }
            ReadSliceSource::Disk {
                generation,
                record_log_offset,
                payload_offset,
                slice_inner_offset,
            } => {
                let cache = log_cache.ok_or(libc::EIO)?;
                match cache.read_extent_payload(
                    *generation,
                    *record_log_offset,
                    *payload_offset,
                    *slice_inner_offset,
                    &mut dst_buf[slice.dst_offset..slice.dst_offset + slice.len],
                    volume_key,
                ) {
                    Ok(_) => {}
                    Err(_) => return Err(libc::EIO),
                }
            }
        }
    }
    Ok(dst_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_attrs_batch_across_layers() {
        let fs = InMemoryFS::new();

        // 1. Create file1 in live -> freeze to flushing -> fold to base
        let attr1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.begin_flush();
        let batch = fs.flushing.write().unwrap().pop_front().unwrap();
        fs.fold_flushed_batch(batch);

        // 2. Create file2 in live -> freeze to flushing (stays in flushing)
        let attr2 = crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.begin_flush();

        // 3. Create file3 in live (stays in live)
        let attr3 = crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000).unwrap();

        // 4. Create and unlink file4 (tombstoned)
        let attr4 = crate::operations::read_write::create_core(&fs, 1, "file4.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::unlink_core(&fs, 1, "file4.txt").unwrap();

        // Inode 999 does not exist
        let inos = vec![1, attr1.ino, attr2.ino, attr3.ino, attr4.ino, 999];
        let batch_map = fs.get_attrs_batch(&inos);

        // Verify root, file1, file2, file3 are present with matching attributes
        assert!(batch_map.contains_key(&1));
        assert_eq!(batch_map.get(&1).unwrap(), &fs.get_attr(1).unwrap());

        assert!(batch_map.contains_key(&attr1.ino));
        assert_eq!(batch_map.get(&attr1.ino).unwrap(), &fs.get_attr(attr1.ino).unwrap());

        assert!(batch_map.contains_key(&attr2.ino));
        assert_eq!(batch_map.get(&attr2.ino).unwrap(), &fs.get_attr(attr2.ino).unwrap());

        assert!(batch_map.contains_key(&attr3.ino));
        assert_eq!(batch_map.get(&attr3.ino).unwrap(), &fs.get_attr(attr3.ino).unwrap());

        // Tombstoned inode 4 and non-existent inode 999 must NOT be present
        assert!(!batch_map.contains_key(&attr4.ino));
        assert!(!batch_map.contains_key(&999));
    }

    #[test]
    fn test_plan_read_file_data_staged_and_holes() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, attr.ino, &[0xAA; 100], 0).unwrap();
        crate::operations::read_write::fallocate_core(
            &fs,
            attr.ino,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            40,
            20,
        )
        .unwrap();

        let plan = fs.plan_read_file_data(attr.ino, 0, 100).unwrap();
        assert_eq!(plan.total_len, 100);
        assert!(!plan.has_cold_slices);
        assert_eq!(plan.slices.len(), 3);

        assert_eq!(plan.slices[0].dst_offset, 0);
        assert_eq!(plan.slices[0].len, 40);
        assert!(matches!(plan.slices[0].source, ReadSliceSource::Memory { .. }));

        assert_eq!(plan.slices[1].dst_offset, 40);
        assert_eq!(plan.slices[1].len, 20);
        assert_eq!(plan.slices[1].source, ReadSliceSource::Zero);

        assert_eq!(plan.slices[2].dst_offset, 60);
        assert_eq!(plan.slices[2].len, 40);
        assert!(matches!(plan.slices[2].source, ReadSliceSource::Memory { .. }));

        let read_buf = fs.execute_read_plan_sync(&plan).unwrap();
        assert_eq!(&read_buf[0..40], &[0xAA; 40]);
        assert_eq!(&read_buf[40..60], &[0x00; 20]);
        assert_eq!(&read_buf[60..100], &[0xAA; 40]);
    }

    #[test]
    fn test_plan_read_out_of_bounds() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "empty.bin", 0o644, 0, 1000, 1000).unwrap();
        let plan = fs.plan_read_file_data(attr.ino, 100, 50).unwrap();
        assert_eq!(plan.total_len, 0);
        assert!(!plan.has_cold_slices);
        assert!(plan.slices.is_empty());

        let res = fs.execute_read_plan_sync(&plan).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn test_plan_read_handle_virtual_file() {
        let fs = InMemoryFS::new();
        fs.register_runtime_status();

        let status_ino = crate::fs::VIRTUAL_INO_BASE;
        let fh = fs.open_file_handle(status_ino, libc::O_RDONLY as u32);
        assert_ne!(fh & crate::fs::VIRTUAL_FH_FLAG, 0);

        let plan = fs.plan_read_handle(status_ino, fh, 0, 50).unwrap();
        assert_eq!(plan.total_len, 50);
        assert!(!plan.has_cold_slices);
        assert_eq!(plan.slices.len(), 1);
        assert!(matches!(plan.slices[0].source, ReadSliceSource::Memory { .. }));

        let buf = fs.read_handle(status_ino, fh, 0, 50).unwrap();
        assert_eq!(buf.len(), 50);
        assert!(
            std::str::from_utf8(&buf)
                .unwrap()
                .starts_with("=== appendfs Runtime Status ===")
        );
    }

    #[test]
    fn test_plan_read_file_data_multi_layer_precedence() {
        use crate::node::{FileDelta, InodeMeta};
        use crate::range_map::RangeMap;
        use std::time::SystemTime;

        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "layers.bin", 0o644, 0, 1000, 1000).unwrap();

        // 1. Base layer: Disk extent at 0..100
        let shared_disk = SharedExtentState::new_disk(1, 1024, 0, 100);
        let mut base_range = RangeMap::new();
        base_range.insert(0, 100, shared_disk);
        let mut base_map = HashMap::new();
        base_map.insert(
            attr.ino,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::File {
                    range_map: base_range,
                    size: 100,
                },
            }),
        );
        *fs.base.write().unwrap() = base_map;

        // 2. Flushing layer: punch hole (Zero) at 20..40
        let mut flushing_batch = HashMap::new();
        let mut f_delta = FileDelta::default();
        f_delta.extents.insert(20, 20, SharedExtentState::new_zero(20));
        flushing_batch.insert(attr.ino, EntryDelta::Node(NodeDelta::File(f_delta)));
        fs.flushing.write().unwrap().push_back(flushing_batch);

        // 3. Live layer: Staged extent at 30..50
        let staged_data = Arc::new(vec![0xBB; 20]);
        let mut live_delta = FileDelta::default();
        live_delta
            .extents
            .insert(30, 20, SharedExtentState::new_staged(staged_data, 0, 20));
        fs.live
            .write()
            .unwrap()
            .insert(attr.ino, EntryDelta::Node(NodeDelta::File(live_delta)));

        // Now plan read from 0..100:
        // - 0..20: from Base (Disk)
        // - 20..30: from Flushing (Zero)
        // - 30..50: from Live (Memory)
        // - 50..100: from Base (Disk)
        let plan = fs.plan_read_file_data(attr.ino, 0, 100).unwrap();
        assert_eq!(plan.total_len, 100);
        assert!(plan.has_cold_slices);
        assert_eq!(plan.slices.len(), 4);

        assert_eq!(plan.slices[0].dst_offset, 0);
        assert_eq!(plan.slices[0].len, 20);
        assert!(matches!(
            plan.slices[0].source,
            ReadSliceSource::Disk {
                generation: 1,
                slice_inner_offset: 0,
                ..
            }
        ));

        assert_eq!(plan.slices[1].dst_offset, 20);
        assert_eq!(plan.slices[1].len, 10);
        assert_eq!(plan.slices[1].source, ReadSliceSource::Zero);

        assert_eq!(plan.slices[2].dst_offset, 30);
        assert_eq!(plan.slices[2].len, 20);
        assert!(matches!(
            plan.slices[2].source,
            ReadSliceSource::Memory { src_offset: 0, .. }
        ));

        assert_eq!(plan.slices[3].dst_offset, 50);
        assert_eq!(plan.slices[3].len, 50);
        assert!(matches!(
            plan.slices[3].source,
            ReadSliceSource::Disk {
                generation: 1,
                slice_inner_offset: 50,
                ..
            }
        ));
    }
}
