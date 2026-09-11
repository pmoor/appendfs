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
use crate::extent_map::Extent;
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
    // TODO(too-many-lines): extract this into smaller units.
    #[allow(clippy::too_many_lines)]
    pub fn plan_read_file_data(
        &self,
        offset: u64,
        size: usize,
        log_cache: Option<&crate::log::LogFileCache>,
    ) -> Result<ReadPlan, i32> {
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

        let mut add_extent = |ext_start: u64, ext_len: u64, extent: &Extent| {
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

                let source = match extent {
                    Extent::Zero { .. } => ReadSliceSource::Zero,
                    Extent::Staged {
                        data,
                        payload_offset,
                        length: _,
                    } => {
                        let src_offset = *payload_offset as usize + inner_offset;
                        ReadSliceSource::Memory {
                            data: data.clone(),
                            src_offset,
                        }
                    }
                    Extent::Disk {
                        generation,
                        record_log_offset,
                        record_size,
                        payload_offset,
                        length: _,
                    } => {
                        let cached = log_cache.and_then(|c| c.get_cached_record(*generation, *record_log_offset));
                        if let Some(cached_data) = cached {
                            let src_offset = *payload_offset as usize + inner_offset;
                            ReadSliceSource::Cache {
                                data: cached_data,
                                src_offset,
                            }
                        } else {
                            ReadSliceSource::Disk {
                                generation: *generation,
                                record_log_offset: *record_log_offset,
                                record_size: *record_size,
                                payload_offset: *payload_offset,
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
                    for (ext_start, ext_len, extent) in f.extents.query(offset, read_len as u64) {
                        add_extent(ext_start, ext_len, &extent);
                    }
                }
                _ => {}
            }
        }

        if !hit_tombstone && let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::File { extent_map, .. } = &node.kind {
                for (ext_start, ext_len, extent) in extent_map.query(offset, read_len as u64) {
                    add_extent(ext_start, ext_len, &extent);
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

        let has_cold_slices = raw_slices
            .iter()
            .any(|s| matches!(s.source, ReadSliceSource::Disk { .. }));

        Ok(ReadPlan {
            total_len: read_len,
            has_cold_slices,
            slices: raw_slices,
        })
    }

    /// Reads file data resolving extents across layers.
    pub fn read_file_data(&self, offset: u64, size: usize, fs: &InMemoryFS) -> Result<Vec<u8>, i32> {
        let plan = self.plan_read_file_data(offset, size, fs.log_cache.as_deref())?;
        fs.execute_read_plan_sync(plan)
    }
}

/// Source of data for a specific byte segment within a read plan.
#[derive(Debug, Clone)]
pub enum ReadSliceSource {
    /// Zero-filled (hole, punch-hole, or truncated region).
    Zero,
    /// In-memory: reference to staged write buffer slice.
    Memory {
        data: crate::log::extent::StagedBuffer,
        src_offset: usize,
    },
    /// In-memory: reference to decrypted record cache hit.
    Cache { data: Arc<Vec<u8>>, src_offset: usize },
    /// Cold disk or remote S3 extent.
    Disk {
        generation: u64,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        slice_inner_offset: u32,
    },
}

/// A contiguous segment of data within a read plan.
#[derive(Debug, Clone)]
pub struct ReadSlice {
    pub dst_offset: usize,
    pub len: usize,
    pub source: ReadSliceSource,
}

/// A complete recipe for fulfilling a read request across layer boundaries.
#[derive(Debug, Clone)]
pub struct ReadPlan {
    pub total_len: usize,
    pub has_cold_slices: bool,
    pub slices: Vec<ReadSlice>,
}

static STATIC_ZEROES: [u8; 128 * 1024] = [0u8; 128 * 1024];

impl ReadPlan {
    pub fn empty() -> Self {
        Self {
            total_len: 0,
            has_cold_slices: false,
            slices: Vec::new(),
        }
    }

    /// Returns true if the plan can be answered directly by borrowing a single slice
    /// with zero allocations and zero copies.
    pub fn is_single_borrowable_slice(&self) -> bool {
        if self.total_len == 0 || self.slices.is_empty() {
            return true;
        }
        if self.slices.len() != 1 || self.has_cold_slices {
            return false;
        }
        match &self.slices[0].source {
            ReadSliceSource::Zero => self.total_len <= STATIC_ZEROES.len(),
            ReadSliceSource::Memory { .. } | ReadSliceSource::Cache { .. } => true,
            ReadSliceSource::Disk { .. } => false,
        }
    }

    /// Executes the read plan by invoking `f` with a borrowed slice directly
    /// from memory, cache, or static zeroes with ZERO intermediate allocations and ZERO copies.
    ///
    /// # Panics
    /// Panics if `self.is_single_borrowable_slice()` is false.
    pub fn execute_single_slice<F: FnOnce(&[u8])>(&self, f: F) {
        if self.total_len == 0 || self.slices.is_empty() {
            f(&[]);
            return;
        }
        assert_eq!(self.slices.len(), 1, "expected exactly 1 slice in execute_single_slice");
        let slice = &self.slices[0];
        match &slice.source {
            ReadSliceSource::Zero => {
                assert!(
                    self.total_len <= STATIC_ZEROES.len(),
                    "zero slice exceeds static buffer"
                );
                f(&STATIC_ZEROES[..self.total_len]);
            }
            ReadSliceSource::Memory { data, src_offset } => {
                let guard = data.read().unwrap();
                let actual_len = std::cmp::min(slice.len, guard.len().saturating_sub(*src_offset));
                f(&guard[*src_offset..*src_offset + actual_len]);
            }
            ReadSliceSource::Cache { data, src_offset } => {
                let actual_len = std::cmp::min(slice.len, data.len().saturating_sub(*src_offset));
                f(&data[*src_offset..*src_offset + actual_len]);
            }
            ReadSliceSource::Disk { .. } => panic!("disk slice cannot be borrowed directly"),
        }
    }
}

impl InMemoryFS {
    /// Executes a [`ReadPlan`] synchronously, reading any cold disk extents via [`LogFileCache`].
    pub fn execute_read_plan_sync(&self, plan: ReadPlan) -> Result<Vec<u8>, i32> {
        execute_read_plan(plan, self.log_cache.as_deref(), &self.volume_key)
    }

    /// Executes a [`ReadPlan`] asynchronously, offloading cold disk I/O and large memory copies
    /// to the Tokio thread pool with zero locks on [`InMemoryFS`].
    ///
    /// Memory slices from live/flushing layers are copied out first into the destination buffer
    /// and their backing memory references dropped *before* any cold disk or remote I/O begins.
    pub async fn execute_read_plan_async(
        plan: ReadPlan,
        log_cache: Option<Arc<crate::log::LogFileCache>>,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> Result<Vec<u8>, i32> {
        tokio::task::spawn_blocking(move || execute_read_plan(plan, log_cache.as_deref(), &volume_key))
            .await
            .map_err(|_| libc::EIO)?
    }
}

/// Core execution helper for [`ReadPlan`] completely decoupled from [`InMemoryFS`].
///
/// Phase 1: Copies all in-memory slices into `dst_buf` and drops their backing buffers
/// immediately, allowing staged buffers to be freed before any disk I/O.
/// Phase 2: Resolves cold disk slices from cache or disk directly into `dst_buf`.
pub fn execute_read_plan(
    mut plan: ReadPlan,
    log_cache: Option<&crate::log::LogFileCache>,
    volume_key: &crate::crypto::VolumeKey,
) -> Result<Vec<u8>, i32> {
    if plan.total_len == 0 || plan.slices.is_empty() {
        return Ok(Vec::new());
    }

    let mut dst_buf = vec![0u8; plan.total_len];
    let mut cold_slices = Vec::new();

    // Phase 1: Pre-copy all in-memory slices into dst_buf and drop memory buffers immediately
    for slice in std::mem::take(&mut plan.slices) {
        match slice.source {
            ReadSliceSource::Zero => {}
            ReadSliceSource::Memory { data, src_offset } => {
                let guard = data.read().unwrap();
                let actual_len = std::cmp::min(slice.len, guard.len().saturating_sub(src_offset));
                if actual_len > 0 {
                    dst_buf[slice.dst_offset..slice.dst_offset + actual_len]
                        .copy_from_slice(&guard[src_offset..src_offset + actual_len]);
                }
                // Memory slice guard and StagedBuffer Arc are dropped at end of loop iteration!
            }
            ReadSliceSource::Cache { data, src_offset } => {
                let actual_len = std::cmp::min(slice.len, data.len().saturating_sub(src_offset));
                if actual_len > 0 {
                    dst_buf[slice.dst_offset..slice.dst_offset + actual_len]
                        .copy_from_slice(&data[src_offset..src_offset + actual_len]);
                }
                // Cache data Arc is dropped at end of loop iteration!
            }
            ReadSliceSource::Disk { .. } => {
                cold_slices.push(slice);
            }
        }
    }

    // Phase 2: All memory slice descriptors are now dropped!
    // Staged write buffers / arena chunks can be freed immediately, even if
    // disk or remote S3 reads below take significant time.
    if !cold_slices.is_empty() {
        let cache = log_cache.ok_or(libc::EIO)?;
        execute_cold_slices(cold_slices, &mut dst_buf, cache, volume_key)?;
    }

    Ok(dst_buf)
}

fn execute_cold_slices(
    cold_slices: Vec<ReadSlice>,
    dst_buf: &mut [u8],
    cache: &crate::log::LogFileCache,
    volume_key: &crate::crypto::VolumeKey,
) -> Result<(), i32> {
    if cold_slices.is_empty() {
        return Ok(());
    }

    struct ColdJob<'a> {
        slice: ReadSlice,
        target: &'a mut [u8],
    }

    let mut jobs = Vec::with_capacity(cold_slices.len());
    let mut remainder = dst_buf;
    let mut current_offset = 0;

    for slice in cold_slices {
        let (skip, tail) = remainder.split_at_mut(slice.dst_offset - current_offset);
        let _ = skip;
        let (target, next_remainder) = tail.split_at_mut(slice.len);
        current_offset = slice.dst_offset + slice.len;
        remainder = next_remainder;
        jobs.push(ColdJob { slice, target });
    }

    // Sort jobs by (generation, record_log_offset) so that slices referencing the same
    // record land in the same worker chunk to maximize decrypted_cache hits.
    jobs.sort_by_key(|job| match &job.slice.source {
        ReadSliceSource::Disk {
            generation,
            record_log_offset,
            ..
        } => (*generation, *record_log_offset),
        _ => (0, 0),
    });

    let num_workers = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .min(jobs.len())
        .clamp(1, 16);

    let chunk_size = jobs.len().div_ceil(num_workers);

    std::thread::scope(|s| -> Result<(), i32> {
        let mut handles = Vec::with_capacity(num_workers);

        for chunk in jobs.chunks_mut(chunk_size) {
            let handle = s.spawn(move || -> Result<(), i32> {
                for job in chunk {
                    match &job.slice.source {
                        ReadSliceSource::Disk {
                            generation,
                            record_log_offset,
                            record_size,
                            payload_offset,
                            slice_inner_offset,
                        } => {
                            cache
                                .read_extent_payload(
                                    *generation,
                                    *record_log_offset,
                                    *record_size,
                                    *payload_offset,
                                    *slice_inner_offset,
                                    &mut *job.target,
                                    volume_key,
                                )
                                .map_err(|_| libc::EIO)?;
                        }
                        _ => panic!("expected Disk slice in cold_slices"),
                    }
                }
                Ok(())
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().map_err(|_| libc::EIO)??;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent_map::{Extent, ExtentMap};
    use crate::fs::{FlushBatch, WriteArena};
    use crate::log::FlushMotivation;

    #[test]
    fn test_get_attr_across_layers() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(crate::clock::SystemClock);
        let writer = Arc::new(
            crate::log::LogWriter::create(
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

        // 1. Create file1 in live -> freeze to flushing -> fold to base
        let attr1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.flush_to_base().unwrap();

        // 2. Create file2 in live -> freeze to flushing (stays in flushing)
        let attr2 = crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.begin_flush(FlushMotivation::Test);

        // 3. Create file3 in live (stays in live)
        let attr3 = crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000).unwrap();

        // 4. Create and unlink file4 (tombstoned)
        let attr4 = crate::operations::read_write::create_core(&fs, 1, "file4.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::unlink_core(&fs, 1, "file4.txt").unwrap();

        // Verify root, file1, file2, file3 are present with matching attributes
        assert!(fs.get_attr(1).is_some());
        assert_eq!(fs.get_attr(attr1.ino).unwrap().ino, attr1.ino);
        assert_eq!(fs.get_attr(attr2.ino).unwrap().ino, attr2.ino);
        assert_eq!(fs.get_attr(attr3.ino).unwrap().ino, attr3.ino);

        // Tombstoned inode 4 and non-existent inode 999 must NOT be present
        assert!(fs.get_attr(attr4.ino).is_none());
        assert!(fs.get_attr(999).is_none());
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
        assert!(matches!(plan.slices[1].source, ReadSliceSource::Zero));

        assert_eq!(plan.slices[2].dst_offset, 60);
        assert_eq!(plan.slices[2].len, 40);
        assert!(matches!(plan.slices[2].source, ReadSliceSource::Memory { .. }));

        let read_buf = fs.execute_read_plan_sync(plan).unwrap();
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

        let res = fs.execute_read_plan_sync(plan).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn test_plan_read_handle_virtual_file() {
        let fs = InMemoryFS::new();
        fs.register_runtime_status();

        let status_ino = crate::fs::VIRTUAL_INO_BASE;
        let fh = fs.open_file_handle(status_ino, libc::O_RDONLY as u32);
        assert!(fh > 0);

        let plan = fs.plan_read_handle(status_ino, fh, 0, 50).unwrap();
        assert_eq!(plan.total_len, 50);
        assert!(!plan.has_cold_slices);
        assert_eq!(plan.slices.len(), 1);
        assert!(matches!(plan.slices[0].source, ReadSliceSource::Cache { .. }));

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
        use crate::extent_map::ExtentMap;
        use crate::node::{FileDelta, InodeMeta};
        use std::time::SystemTime;

        let fs = InMemoryFS::new();

        let attr = crate::operations::read_write::create_core(&fs, 1, "layers.bin", 0o644, 0, 1000, 1000).unwrap();

        // 1. Base layer: Disk extent at 0..100
        let shared_disk = Extent::new_disk(1, 1024, 137, 0, 100);
        let mut base_range = ExtentMap::new();
        base_range.insert(0, shared_disk);
        let mut base_map = HashMap::new();
        base_map.insert(
            attr.ino,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::File {
                    extent_map: base_range,
                    size: 100,
                },
            }),
        );
        fs.inner.lock_for_tests().unwrap().base = base_map;

        // 2. Flushing layer: punch hole (Zero) at 20..40
        let mut flushing_batch = HashMap::new();
        let mut f_delta = FileDelta::default();
        f_delta.extents.insert(20, Extent::new_zero(20));
        flushing_batch.insert(attr.ino, EntryDelta::Node(NodeDelta::File(f_delta)));
        fs.inner.lock_for_tests().unwrap().flushing.push_back(FlushBatch::new(
            1,
            flushing_batch,
            WriteArena::new(),
            0,
            0,
            crate::log::FlushMotivation::Manual,
            std::time::SystemTime::UNIX_EPOCH,
        ));

        // 3. Live layer: Staged extent at 30..50
        let mut live_delta = FileDelta::default();
        live_delta
            .extents
            .insert(30, Extent::new_staged_buffer(vec![0xBB; 20], 0, 20));
        fs.inner
            .lock_for_tests()
            .unwrap()
            .live
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
        assert!(matches!(plan.slices[1].source, ReadSliceSource::Zero));

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

    #[test]
    fn test_plan_read_file_data_decrypted_record_cache_hit() {
        use crate::node::InodeMeta;
        use std::time::SystemTime;

        let mut fs = InMemoryFS::new();
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        fs.log_cache = Some(Arc::new(crate::log::LogFileCache::with_storage(storage)));

        let attr = crate::operations::read_write::create_core(&fs, 1, "cached.bin", 0o644, 0, 1000, 1000).unwrap();

        let shared_disk = Extent::new_disk(1, 1024, 137, 0, 100);
        let mut base_range = ExtentMap::new();
        base_range.insert(0, shared_disk);
        let mut base_map = HashMap::new();
        base_map.insert(
            attr.ino,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::File {
                    extent_map: base_range,
                    size: 100,
                },
            }),
        );
        fs.inner.lock_for_tests().unwrap().base = base_map;
        fs.inner.lock_for_tests().unwrap().live.remove(&attr.ino);

        let cached_bytes = Arc::new(vec![0xCC; 100]);
        fs.log_cache
            .as_ref()
            .unwrap()
            .insert_cached_record(1, 1024, Arc::clone(&cached_bytes));

        let plan = fs.plan_read_file_data(attr.ino, 0, 100).unwrap();
        assert_eq!(plan.total_len, 100);
        assert!(!plan.has_cold_slices);
        assert_eq!(plan.slices.len(), 1);
        assert_eq!(plan.slices[0].dst_offset, 0);
        assert_eq!(plan.slices[0].len, 100);
        assert!(matches!(plan.slices[0].source, ReadSliceSource::Cache { .. }));

        let buf = fs.execute_read_plan_sync(plan).unwrap();
        assert_eq!(buf, vec![0xCC; 100]);
    }

    #[test]
    fn test_execute_read_plan_multi_extent_parallel() {
        use crate::crypto::{VolumeHeader, VolumeKey};
        use crate::log::RecoveryTarget;
        use crate::storage::MemoryStorage;

        let storage = Arc::new(MemoryStorage::new());
        let clock = Arc::new(crate::clock::SystemClock);
        let key = Arc::new(VolumeKey::plaintext());
        crate::log::init_volume(storage.clone(), &key, VolumeHeader::plaintext()).unwrap();
        let mut fs =
            crate::log::recover_fs(storage.clone(), RecoveryTarget::Latest, clock.clone(), key.clone()).unwrap();

        let writer = Arc::new(
            crate::log::LogWriter::create(
                storage.clone(),
                1,
                clock.as_ref(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                key.clone(),
            )
            .unwrap(),
        );
        fs.attach_log_writer(writer);

        let attr =
            crate::operations::read_write::create_core(&fs, 1, "multi_extent.bin", 0o644, 0, 1000, 1000).unwrap();

        // Write 4 separate extents, flushing between each so they land in distinct log batches/generations
        let data1 = vec![0x11u8; 200];
        let data2 = vec![0x22u8; 200];
        let data3 = vec![0x33u8; 200];
        let data4 = vec![0x44u8; 200];

        crate::operations::read_write::write_core(&fs, attr.ino, &data1, 0).unwrap();
        fs.flush_log().unwrap();

        crate::operations::read_write::write_core(&fs, attr.ino, &data2, 200).unwrap();
        fs.flush_log().unwrap();

        crate::operations::read_write::write_core(&fs, attr.ino, &data3, 400).unwrap();
        fs.flush_log().unwrap();

        crate::operations::read_write::write_core(&fs, attr.ino, &data4, 600).unwrap();
        fs.flush_log().unwrap();

        // Clear decrypted record cache to force actual cold disk decoding in parallel
        fs.log_cache.as_ref().unwrap().decrypted_cache.clear();

        let plan = fs.plan_read_file_data(attr.ino, 0, 800).unwrap();
        assert_eq!(plan.total_len, 800);
        assert!(plan.has_cold_slices);
        assert!(plan.slices.len() >= 4);

        // Execute synchronously (which dispatches parallel worker threads under the hood)
        let read_buf = fs.execute_read_plan_sync(plan.clone()).unwrap();
        assert_eq!(&read_buf[0..200], &data1[..]);
        assert_eq!(&read_buf[200..400], &data2[..]);
        assert_eq!(&read_buf[400..600], &data3[..]);
        assert_eq!(&read_buf[600..800], &data4[..]);

        // Also execute asynchronously via Tokio
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let async_buf = rt
            .block_on(InMemoryFS::execute_read_plan_async(
                plan,
                fs.log_cache.clone(),
                fs.volume_key.clone(),
            ))
            .unwrap();

        assert_eq!(&async_buf[0..200], &data1[..]);
        assert_eq!(&async_buf[200..400], &data2[..]);
        assert_eq!(&async_buf[400..600], &data3[..]);
        assert_eq!(&async_buf[600..800], &data4[..]);
    }

    #[test]
    fn test_read_plan_execute_single_slice_zero_copy() {
        // 1. Empty plan
        let empty_plan = ReadPlan::empty();
        assert!(empty_plan.is_single_borrowable_slice());
        let mut called = false;
        empty_plan.execute_single_slice(|slice| {
            assert!(slice.is_empty());
            called = true;
        });
        assert!(called);

        // 2. Zero plan
        let zero_plan = ReadPlan {
            total_len: 1024,
            has_cold_slices: false,
            slices: vec![ReadSlice {
                dst_offset: 0,
                len: 1024,
                source: ReadSliceSource::Zero,
            }],
        };
        assert!(zero_plan.is_single_borrowable_slice());
        called = false;
        zero_plan.execute_single_slice(|slice| {
            assert_eq!(slice.len(), 1024);
            assert!(slice.iter().all(|&b| b == 0));
            called = true;
        });
        assert!(called);

        // 3. Staged memory slice
        let staged_data = vec![0xABu8; 512];
        let memory_plan = ReadPlan {
            total_len: 256,
            has_cold_slices: false,
            slices: vec![ReadSlice {
                dst_offset: 0,
                len: 256,
                source: ReadSliceSource::Memory {
                    data: Arc::new(std::sync::RwLock::new(staged_data)),
                    src_offset: 20,
                },
            }],
        };
        assert!(memory_plan.is_single_borrowable_slice());
        called = false;
        memory_plan.execute_single_slice(|slice| {
            assert_eq!(slice.len(), 256);
            assert!(slice.iter().all(|&b| b == 0xAB));
            called = true;
        });
        assert!(called);

        // 4. Cache hit slice
        let cache_data = Arc::new(vec![0xCDu8; 128]);
        let cache_plan = ReadPlan {
            total_len: 64,
            has_cold_slices: false,
            slices: vec![ReadSlice {
                dst_offset: 0,
                len: 64,
                source: ReadSliceSource::Cache {
                    data: cache_data,
                    src_offset: 16,
                },
            }],
        };
        assert!(cache_plan.is_single_borrowable_slice());
        called = false;
        cache_plan.execute_single_slice(|slice| {
            assert_eq!(slice.len(), 64);
            assert!(slice.iter().all(|&b| b == 0xCD));
            called = true;
        });
        assert!(called);

        // 5. Multi-slice plan is not single borrowable
        let multi_plan = ReadPlan {
            total_len: 200,
            has_cold_slices: false,
            slices: vec![
                ReadSlice {
                    dst_offset: 0,
                    len: 100,
                    source: ReadSliceSource::Zero,
                },
                ReadSlice {
                    dst_offset: 100,
                    len: 100,
                    source: ReadSliceSource::Zero,
                },
            ],
        };
        assert!(!multi_plan.is_single_borrowable_slice());
    }

    #[test]
    fn test_execute_read_plan_single_cold_slice_direct() {
        use crate::crypto::{VolumeHeader, VolumeKey};
        use crate::log::RecoveryTarget;
        use crate::storage::MemoryStorage;

        let storage = Arc::new(MemoryStorage::new());
        let clock = Arc::new(crate::clock::SystemClock);
        let key = Arc::new(VolumeKey::plaintext());
        crate::log::init_volume(storage.clone(), &key, VolumeHeader::plaintext()).unwrap();
        let mut fs =
            crate::log::recover_fs(storage.clone(), RecoveryTarget::Latest, clock.clone(), key.clone()).unwrap();

        let writer = Arc::new(
            crate::log::LogWriter::create(
                storage.clone(),
                1,
                clock.as_ref(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                key.clone(),
            )
            .unwrap(),
        );
        fs.attach_log_writer(writer);

        let attr = crate::operations::read_write::create_core(&fs, 1, "single_cold.bin", 0o644, 0, 1000, 1000).unwrap();
        let payload = vec![0xEFu8; 1024];
        crate::operations::read_write::write_core(&fs, attr.ino, &payload, 0).unwrap();
        fs.flush_log().unwrap();

        // Evict from decrypted cache to force single cold disk direct read
        fs.log_cache.as_ref().unwrap().decrypted_cache.clear();

        let plan = fs.plan_read_file_data(attr.ino, 0, 1024).unwrap();
        assert_eq!(plan.slices.len(), 1);
        assert!(plan.has_cold_slices);

        let res = fs.execute_read_plan_sync(plan).unwrap();
        assert_eq!(res, payload);
    }
}
