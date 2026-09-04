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

    /// Reads file data resolving extents across layers.
    pub fn read_file_data(&self, offset: u64, size: usize, fs: &InMemoryFS) -> Result<Vec<u8>, i32> {
        let attr = self.attr().ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(libc::EISDIR);
        }

        let file_size = attr.size as u64;
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let read_len = std::cmp::min(size as u64, file_size - offset);
        let mut read_buf = vec![0u8; read_len as usize];
        let mut filled = vec![false; read_len as usize];

        // Newest layer first. Truncation and hole punching both leave `Zero` extents, which
        // claim their range in `filled` and so stop older layers contributing there - no
        // separate mask has to be threaded down the stack.
        let mut hit_tombstone = false;
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => {
                    hit_tombstone = true;
                    break;
                }
                EntryDelta::Node(NodeDelta::File(f)) => {
                    for (ext_start, ext_len, shared_state) in f.extents.query(offset, read_len) {
                        fs.copy_extent_data(
                            &mut read_buf,
                            &mut filled,
                            offset,
                            read_len,
                            ext_start,
                            ext_len,
                            &shared_state,
                        )?;
                    }
                }
                _ => {}
            }
        }

        if !hit_tombstone && let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                {
                    for (ext_start, ext_len, shared_state) in range_map.query(offset, read_len) {
                        fs.copy_extent_data(
                            &mut read_buf,
                            &mut filled,
                            offset,
                            read_len,
                            ext_start,
                            ext_len,
                            &shared_state,
                        )?;
                    }
                }
            }
        }

        Ok(read_buf)
    }
}

/// Extent payload resolution, used by [`InodeLayerStack::read_file_data`] to fill a read
/// buffer from whichever layer owns each byte range.
impl InMemoryFS {
    #[allow(clippy::too_many_arguments)]
    fn copy_extent_data(
        &self,
        dst_buf: &mut [u8],
        filled: &mut [bool],
        read_start: u64,
        read_len: u64,
        ext_start: u64,
        ext_len: u64,
        shared_state: &SharedExtentState,
    ) -> Result<(), i32> {
        let seg_start = std::cmp::max(read_start, ext_start);
        let seg_end = std::cmp::min(read_start + read_len, ext_start + ext_len);
        if seg_start >= seg_end {
            return Ok(());
        }

        let seg_len = (seg_end - seg_start) as usize;
        let dst_offset = (seg_start - read_start) as usize;
        let slice_inner_offset = (seg_start - ext_start) as usize;

        if filled[dst_offset..dst_offset + seg_len].iter().all(|&b| b) {
            return Ok(());
        }

        let mut temp_buf = vec![0u8; seg_len];
        let mut bytes_read = 0usize;

        let state = shared_state.read_state();
        match state {
            ExtentState::Staged {
                data,
                payload_offset,
                length: _,
            } => {
                let src_start = payload_offset as usize + slice_inner_offset;
                let src_end = std::cmp::min(src_start + seg_len, data.len());
                let actual_len = std::cmp::min(seg_len, src_end.saturating_sub(src_start));
                if actual_len > 0 && src_start < data.len() {
                    temp_buf[..actual_len].copy_from_slice(&data[src_start..src_start + actual_len]);
                    bytes_read = actual_len;
                }
            }
            // A hole contributes zeros, which `temp_buf` already holds. Claiming the
            // segment is the whole point: it marks these bytes `filled`, so lower layers
            // are not consulted and the punched-out data stays punched out.
            ExtentState::Zero { .. } => {
                bytes_read = seg_len;
            }
            ExtentState::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length: _,
            } => {
                if let Some(ref cache) = self.log_cache {
                    match cache.read_extent_payload(
                        generation,
                        record_log_offset,
                        payload_offset,
                        slice_inner_offset as u32,
                        &mut temp_buf[..seg_len],
                        &self.volume_key,
                    ) {
                        Ok(n) => bytes_read = n,
                        // A Disk extent is authoritative for these bytes. Swallowing the
                        // error would leave the segment unfilled, so the read falls through
                        // to lower layers and ultimately returns zeros - turning bitrot, a
                        // failed I/O, or a detected AEAD forgery into silent, plausible
                        // data. Report it instead.
                        Err(_) => return Err(libc::EIO),
                    }
                }
            }
        }

        for i in 0..bytes_read {
            if !filled[dst_offset + i] {
                dst_buf[dst_offset + i] = temp_buf[i];
                filled[dst_offset + i] = true;
            }
        }

        Ok(())
    }
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
}
