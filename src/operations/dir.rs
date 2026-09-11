#[cfg(any(test, feature = "testing"))]
use crate::fs::find_parent_inode;
use crate::fs::{DirHandle, InMemoryFS};
use crate::node::{AttrDelta, DirectoryDelta, NodeDelta};
use crate::shim::{self, FileAttr, FileType, Request};
use crate::sync::OpTag;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub fn lookup_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<FileAttr, i32> {
    log::trace!("lookup(parent={}, name={})", parent, name);
    if name.len() > 255 {
        return Err(libc::ENAMETOOLONG);
    }
    let inner = fs.inner.lock(OpTag::Lookup).unwrap();
    let parent_attr = fs.get_attr_locked(&inner, parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    if name == "." {
        return Ok(parent_attr);
    }
    if name == ".." {
        let dotdot_ino = if parent == 1 {
            1
        } else {
            inner.get_parent_dir_inode(parent).unwrap_or(1)
        };
        return fs.get_attr_locked(&inner, dotdot_ino).ok_or(libc::ENOENT);
    }

    let child_ino = fs.lookup_child_locked(&inner, parent, name).ok_or(libc::ENOENT)?;
    fs.get_attr_locked(&inner, child_ino).ok_or(libc::ENOENT)
}

pub fn lookup(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match lookup_core(fs, parent, name) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn list_dir_core(fs: &InMemoryFS, ino: u64) -> Result<Vec<(String, u64)>, i32> {
    let inner = fs.inner.lock(OpTag::ReadDir).unwrap();
    let attr = fs.get_attr_locked(&inner, ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }
    let mut entries = inner.list_directory(ino).ok_or(libc::ENOENT)?;
    drop(inner);
    if ino == 1 {
        let mut map: BTreeMap<String, u64> = entries.into_iter().collect();
        for (name, v_ino) in fs.list_virtual_entries() {
            map.entry(name).or_insert(v_ino);
        }
        entries = map.into_iter().collect();
    }
    Ok(entries)
}

fn iter_dir_items(
    ino: u64,
    dotdot_ino: u64,
    entries: &[(String, u64)],
    offset: i64,
) -> impl Iterator<Item = (&str, u64, i64)> {
    let offset = offset as usize;
    let dot = (offset == 0).then_some((".", ino, 1));
    let dotdot = (offset <= 1).then_some(("..", dotdot_ino, 2));
    let start_entry_idx = offset.saturating_sub(2);
    let rest = entries
        .iter()
        .enumerate()
        .skip(start_entry_idx)
        .map(|(idx, (name, child_ino))| (name.as_str(), *child_ino, (idx + 3) as i64));

    dot.into_iter().chain(dotdot).chain(rest)
}

#[cfg(any(test, feature = "testing"))]
pub struct DirItem<'a> {
    pub name: &'a str,
    pub ino: u64,
    pub next_offset: i64,
}

#[cfg(any(test, feature = "testing"))]
pub fn iter_dir_entries_with_parent<'a>(
    ino: u64,
    dotdot_ino: u64,
    entries: &'a [(String, u64)],
    offset: i64,
) -> impl Iterator<Item = DirItem<'a>> {
    iter_dir_items(ino, dotdot_ino, entries, offset).map(|(name, ino, next_offset)| DirItem { name, ino, next_offset })
}

#[cfg(any(test, feature = "testing"))]
pub fn iter_dir_entries<'a>(
    fs: &InMemoryFS,
    ino: u64,
    entries: &'a [(String, u64)],
    offset: i64,
) -> impl Iterator<Item = DirItem<'a>> {
    let dotdot_ino = if ino == 1 {
        1
    } else {
        find_parent_inode(fs, ino).unwrap_or(1)
    };
    iter_dir_entries_with_parent(ino, dotdot_ino, entries, offset)
}

pub fn opendir_core(fs: &InMemoryFS, ino: u64, flags: u32) -> Result<u64, i32> {
    fs.with_inner(OpTag::OpenDir, |inner| {
        let attr = fs.get_attr_locked(inner, ino).ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }
        let mut entries = inner.list_directory(ino).ok_or(libc::ENOENT)?;
        if ino == 1 {
            let mut map: BTreeMap<String, u64> = entries.into_iter().collect();
            for (name, v_ino) in fs.list_virtual_entries() {
                map.entry(name).or_insert(v_ino);
            }
            entries = map.into_iter().collect();
        }
        let fh = inner.allocate_fh();
        inner.insert_dir_handle(
            fh,
            DirHandle {
                ino,
                flags,
                entries: Arc::new(entries),
            },
        );
        Ok(fh)
    })
}

pub fn opendir(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("opendir(ino={}, flags=0x{:x})", ino, flags);
    match opendir_core(fs, ino, flags) {
        Ok(fh) => req.reply_open(fh, false),
        Err(e) => req.reply_err(e),
    }
}

pub fn readdir(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("readdir(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    let res = fs.with_inner(OpTag::ReadDir, |inner| {
        let dir = inner.get_dir_handle(ino, fh)?;
        let parent_ino = if ino == 1 {
            1
        } else {
            inner.get_parent_dir_inode(ino).unwrap_or(1)
        };
        let mut items = Vec::new();
        for (name, item_ino, next_offset) in iter_dir_items(ino, parent_ino, &dir.entries, offset) {
            if let Some(attr) = fs.get_attr_locked(inner, item_ino) {
                items.push((name.to_string(), item_ino, attr.file_type, next_offset));
            }
        }
        Ok(items)
    });

    let items = match res {
        Ok(items) => items,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    let mut db = shim::DirectoryBuffer::new(req, size);
    for (name, item_ino, file_type, next_offset) in items {
        if !db.add(&name, item_ino, file_type, next_offset) {
            break;
        }
    }
    db.reply();
}

pub fn readdirplus(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("readdirplus(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    let res = fs.with_inner(OpTag::ReadDir, |inner| {
        let dir = inner.get_dir_handle(ino, fh)?;
        let parent_ino = if ino == 1 {
            1
        } else {
            inner.get_parent_dir_inode(ino).unwrap_or(1)
        };
        let mut items = Vec::new();
        for (name, item_ino, next_offset) in iter_dir_items(ino, parent_ino, &dir.entries, offset) {
            if let Some(attr) = fs.get_attr_locked(inner, item_ino) {
                items.push((name.to_string(), attr, next_offset));
            }
        }
        Ok(items)
    });

    let items = match res {
        Ok(items) => items,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    let mut db = shim::DirectoryBufferPlus::new(req, size);
    for (name, attr, next_offset) in items {
        if !db.add(&name, &attr, 1.0, 1.0, next_offset) {
            break;
        }
    }
    db.reply();
}

pub fn mkdir_core(fs: &InMemoryFS, parent: u64, name: &str, mode: u32, uid: u32, gid: u32) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Mkdir, |inner| {
        let now = fs.clock.now();
        log::trace!(
            "mkdir(parent={}, name={}, mode=0o{:o}, uid={}, gid={})",
            parent,
            name,
            mode,
            uid,
            gid
        );

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, parent, name).is_some() {
            return Err(libc::EEXIST);
        }

        let new_ino = fs.allocate_inode();
        let new_delta = NodeDelta::Directory(DirectoryDelta {
            parent: Some(parent),
            added: HashMap::new(),
            removed: std::collections::HashSet::new(),
            attr_delta: AttrDelta {
                mode: Some(mode & 0o7777),
                nlink: Some(2),
                uid: Some(uid),
                gid: Some(gid),
                atime: Some(now),
                mtime: Some(now),
                ctime: Some(now),
                created_at: Some(now),
                xattrs: None,
            },
        });

        inner.insert_new_node(new_ino, new_delta);
        inner.add_dir_entry(parent, name, new_ino, now);
        inner.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink + 1),
                ctime: Some(now),
                ..Default::default()
            },
        );
        inner.record_mutation(name.len());

        Ok(FileAttr {
            ino: new_ino,
            file_type: FileType::Directory,
            perm: mode & 0o7777,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    })
}

pub fn mkdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match mkdir_core(fs, parent, name, mode, uid, gid) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn rmdir_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Rmdir, |inner| {
        let now = fs.clock.now();
        log::trace!("rmdir(parent={}, name={})", parent, name);

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let child_ino = fs.lookup_child_locked(inner, parent, name).ok_or(libc::ENOENT)?;
        let child_attr = fs.get_attr_locked(inner, child_ino).ok_or(libc::ENOENT)?;
        if child_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let entries = inner.list_directory(child_ino).ok_or(libc::ENOENT)?;
        if !entries.is_empty() {
            return Err(libc::ENOTEMPTY);
        }

        inner.remove_dir_entry(parent, name, now);
        inner.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink.saturating_sub(1)),
                ctime: Some(now),
                ..Default::default()
            },
        );
        inner.tombstone(child_ino);
        inner.record_mutation(name.len());
        Ok(())
    })
}

pub fn rmdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match rmdir_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn releasedir_core(fs: &InMemoryFS, ino: u64, fh: u64) -> Result<(), i32> {
    fs.release_dir_handle(fh, ino)
}

pub fn releasedir(fs: &InMemoryFS, req: Request, ino: u64, fh: u64) {
    log::trace!("releasedir(ino={}, fh={})", ino, fh);
    match releasedir_core(fs, ino, fh) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

#[cfg(any(test, feature = "testing"))]
pub async fn fsyncdir_core(fs: &InMemoryFS) -> Result<(), i32> {
    let completion = fs.rollover_for_sync(0, 0, crate::log::FlushMotivation::Fdirsync)?;
    let Some(completion) = completion else {
        if let Some(ref writer) = fs.log_writer {
            let writer_clone = Arc::clone(writer);
            tokio::task::spawn_blocking(move || writer_clone.sync())
                .await
                .map_err(|_| libc::EIO)?
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }
        return Ok(());
    };

    if !fs.flusher.is_background_active() {
        let clock = Arc::clone(&fs.clock);
        let test_flusher = crate::fs::flusher::TestFlusher::with_flusher(fs, &fs.flusher, clock);
        test_flusher
            .drain()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    }

    completion
        .wait()
        .await
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

pub fn fsyncdir(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    log::trace!("fsyncdir(ino={}, datasync={})", ino, datasync);
    let completion = match fs.rollover_for_sync(0, 0, crate::log::FlushMotivation::Fdirsync) {
        Ok(c) => c,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    let Some(completion) = completion else {
        if let Some(ref writer) = fs.log_writer {
            let guard = fs.begin_async_op();
            let writer_clone = Arc::clone(writer);
            crate::async_runtime::spawn(async move {
                let _guard = guard;
                let res = tokio::task::spawn_blocking(move || writer_clone.sync()).await;
                match res {
                    Ok(Ok(())) => req.reply_err(0),
                    Ok(Err(e)) => req.reply_err(e.raw_os_error().unwrap_or(libc::EIO)),
                    Err(_) => req.reply_err(libc::EIO),
                }
            });
            return;
        }
        req.reply_err(0);
        return;
    };

    let guard = fs.begin_async_op();
    crate::async_runtime::spawn(async move {
        let _guard = guard;
        match completion.wait().await {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_nlink_tracking_across_mkdir_rmdir_and_rename() {
        let fs = InMemoryFS::new();
        // Initial root (inode 1) starts with nlink 2
        assert_eq!(fs.get_attr(1).unwrap().nlink, 2);

        // 1. mkdir "d1" in root -> root nlink becomes 3, d1 has nlink 2
        let d1 = mkdir_core(&fs, 1, "d1", 0o755, 1000, 1000).unwrap();
        assert_eq!(d1.nlink, 2);
        assert_eq!(fs.get_attr(1).unwrap().nlink, 3);

        // 2. mkdir "d2" in root -> root nlink becomes 4, d2 has nlink 2
        let d2 = mkdir_core(&fs, 1, "d2", 0o755, 1000, 1000).unwrap();
        assert_eq!(d2.nlink, 2);
        assert_eq!(fs.get_attr(1).unwrap().nlink, 4);

        // 3. mkdir "sub" inside "d1" -> d1 nlink becomes 3, sub has nlink 2
        let sub = mkdir_core(&fs, d1.ino, "sub", 0o755, 1000, 1000).unwrap();
        assert_eq!(sub.nlink, 2);
        assert_eq!(fs.get_attr(d1.ino).unwrap().nlink, 3);

        // 4. Move "sub" from "d1" to "d2" -> d1 drops to 2, d2 increases to 3
        crate::operations::links::rename_core(&fs, d1.ino, "sub", d2.ino, "sub").unwrap();
        assert_eq!(fs.get_attr(d1.ino).unwrap().nlink, 2);
        assert_eq!(fs.get_attr(d2.ino).unwrap().nlink, 3);
        assert_eq!(fs.get_attr(sub.ino).unwrap().nlink, 2);

        // 5. rmdir "sub" from "d2" -> d2 drops back to 2
        rmdir_core(&fs, d2.ino, "sub").unwrap();
        assert_eq!(fs.get_attr(d2.ino).unwrap().nlink, 2);

        // 6. rmdir "d1" from root -> root drops to 3
        rmdir_core(&fs, 1, "d1").unwrap();
        assert_eq!(fs.get_attr(1).unwrap().nlink, 3);

        // 7. rmdir "d2" from root -> root drops to 2
        rmdir_core(&fs, 1, "d2").unwrap();
        assert_eq!(fs.get_attr(1).unwrap().nlink, 2);
    }

    #[test]
    fn test_lookup_core_single_lock_acquisition_tagged_lookup() {
        let fs = InMemoryFS::new();
        let file = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();

        let pre_stats = fs.inner.op_stats();
        let pre_lookup = pre_stats.iter().find(|s| s.tag == OpTag::Lookup).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let attr = lookup_core(&fs, 1, "test.txt").unwrap();
        assert_eq!(attr.ino, file.ino);

        let post_stats = fs.inner.op_stats();
        let post_lookup = post_stats.iter().find(|s| s.tag == OpTag::Lookup).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition, tagged OpTag::Lookup
        assert_eq!(post_lookup - pre_lookup, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);

        // Test "." and ".."
        let dot_attr = lookup_core(&fs, 1, ".").unwrap();
        assert_eq!(dot_attr.ino, 1);
        let dotdot_attr = lookup_core(&fs, 1, "..").unwrap();
        assert_eq!(dotdot_attr.ino, 1);

        // Test virtual file lookup
        let v_attr = lookup_core(&fs, 1, ".status").unwrap();
        assert_eq!(v_attr.ino, fs.lookup_child(1, ".status").unwrap());
    }

    #[test]
    fn test_list_dir_core_single_lock_acquisition_tagged_readdir() {
        let fs = InMemoryFS::new();
        let _ = mkdir_core(&fs, 1, "sub1", 0o755, 1000, 1000).unwrap();

        let pre_stats = fs.inner.op_stats();
        let pre_readdir = pre_stats.iter().find(|s| s.tag == OpTag::ReadDir).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let entries = list_dir_core(&fs, 1).unwrap();
        assert!(entries.iter().any(|(name, _)| name == "sub1"));
        assert!(entries.iter().any(|(name, _)| name == ".status"));

        let post_stats = fs.inner.op_stats();
        let post_readdir = post_stats.iter().find(|s| s.tag == OpTag::ReadDir).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition, tagged OpTag::ReadDir
        assert_eq!(post_readdir - pre_readdir, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);
    }
}
