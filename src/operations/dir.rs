use crate::fs::{InMemoryFS, find_parent_inode};
use crate::node::{AttrDelta, DirectoryDelta, NodeDelta};
use crate::shim::{self, FileAttr, FileType, Request};
use std::collections::{BTreeMap, HashMap};

pub fn lookup(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    log::trace!("lookup(parent={}, name={})", parent, name);
    if name.len() > 255 {
        req.reply_err(libc::ENAMETOOLONG);
        return;
    }
    let parent_attr = match fs.get_attr(parent) {
        Some(attr) => attr,
        None => {
            req.reply_err(libc::ENOENT);
            return;
        }
    };
    if parent_attr.file_type != FileType::Directory {
        req.reply_err(libc::ENOTDIR);
        return;
    }

    if name == "." {
        req.reply_entry(&parent_attr, 1.0, 1.0);
        return;
    }
    if name == ".." {
        let dotdot_ino = if parent == 1 {
            1
        } else {
            find_parent_inode(fs, parent).unwrap_or(1)
        };
        match fs.get_attr(dotdot_ino) {
            Some(attr) => req.reply_entry(&attr, 1.0, 1.0),
            None => req.reply_err(libc::ENOENT),
        }
        return;
    }

    let child_ino = match fs.lookup_child(parent, name) {
        Some(ino) => ino,
        None => {
            req.reply_err(libc::ENOENT);
            return;
        }
    };

    match fs.get_attr(child_ino) {
        Some(attr) => req.reply_entry(&attr, 1.0, 1.0),
        None => req.reply_err(libc::ENOENT),
    }
}

pub fn list_dir_core(fs: &InMemoryFS, ino: u64) -> Result<Vec<(String, u64)>, i32> {
    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }
    let mut entries = fs.list_directory(ino).ok_or(libc::ENOENT)?;
    if ino == 1 {
        let mut map: BTreeMap<String, u64> = entries.into_iter().collect();
        for (name, v_ino) in fs.virtual_files.list_entries() {
            map.entry(name).or_insert(v_ino);
        }
        entries = map.into_iter().collect();
    }
    Ok(entries)
}

pub struct DirItem<'a> {
    pub name: &'a str,
    pub ino: u64,
    pub next_offset: i64,
}

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

    let offset = offset as usize;
    let dot = (offset == 0).then_some(DirItem {
        name: ".",
        ino,
        next_offset: 1,
    });
    let dotdot = (offset <= 1).then_some(DirItem {
        name: "..",
        ino: dotdot_ino,
        next_offset: 2,
    });
    let start_entry_idx = offset.saturating_sub(2);
    let rest = entries
        .iter()
        .enumerate()
        .skip(start_entry_idx)
        .map(|(idx, (name, child_ino))| DirItem {
            name: name.as_str(),
            ino: *child_ino,
            next_offset: (idx + 3) as i64,
        });

    dot.into_iter().chain(dotdot).chain(rest)
}

pub fn opendir_core(fs: &InMemoryFS, ino: u64, _flags: u32) -> Result<u64, i32> {
    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }
    fs.open_dir_handle(ino).ok_or(libc::ENOENT)
}

pub fn opendir(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("opendir(ino={}, flags=0x{:x})", ino, flags);
    match opendir_core(fs, ino, flags) {
        Ok(fh) => req.reply_open(fh),
        Err(e) => req.reply_err(e),
    }
}

pub fn readdir(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("readdir(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    let entries = match fs.get_dir_handle(fh) {
        Some(entries) => entries,
        None => {
            req.reply_err(libc::EBADF);
            return;
        }
    };

    let items: Vec<DirItem> = iter_dir_entries(fs, ino, &entries, offset).collect();
    let inos: Vec<u64> = items.iter().map(|item| item.ino).collect();
    let attrs = fs.get_attrs_batch(&inos);

    let mut db = shim::DirectoryBuffer::new(req, size);
    for item in items {
        if let Some(attr) = attrs.get(&item.ino)
            && !db.add(item.name, item.ino, attr.file_type, item.next_offset)
        {
            break;
        }
    }
    db.reply();
}

pub fn readdirplus(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
    log::trace!("readdirplus(ino={}, size={}, offset={}, fh={})", ino, size, offset, fh);
    let entries = match fs.get_dir_handle(fh) {
        Some(entries) => entries,
        None => {
            req.reply_err(libc::EBADF);
            return;
        }
    };

    let items: Vec<DirItem> = iter_dir_entries(fs, ino, &entries, offset).collect();
    let inos: Vec<u64> = items.iter().map(|item| item.ino).collect();
    let attrs = fs.get_attrs_batch(&inos);

    let mut db = shim::DirectoryBufferPlus::new(req, size);
    for item in items {
        if let Some(attr) = attrs.get(&item.ino)
            && !db.add(item.name, attr, 1.0, 1.0, item.next_offset)
        {
            break;
        }
    }
    db.reply();
}

pub fn mkdir_core(fs: &InMemoryFS, parent: u64, name: &str, mode: u32, uid: u32, gid: u32) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    let attr = {
        let _dir_guard = fs.dir_lock.lock().unwrap();
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

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child(parent, name).is_some() {
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

        fs.insert_new_node(new_ino, new_delta);
        fs.add_dir_entry(parent, name, new_ino, now);
        fs.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink + 1),
                ctime: Some(now),
                ..Default::default()
            },
        );

        FileAttr {
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
        }
    };

    fs.notify_mutation(0);

    Ok(attr)
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
    fs.check_flush_capacity()?;

    {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!("rmdir(parent={}, name={})", parent, name);

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let child_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
        let child_attr = fs.get_attr(child_ino).ok_or(libc::ENOENT)?;
        if child_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let entries = fs.list_directory(child_ino).ok_or(libc::ENOENT)?;
        if !entries.is_empty() {
            return Err(libc::ENOTEMPTY);
        }

        fs.remove_dir_entry(parent, name, now);
        fs.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink.saturating_sub(1)),
                ctime: Some(now),
                ..Default::default()
            },
        );
        fs.tombstone(child_ino);
    }

    fs.notify_mutation(0);

    Ok(())
}

pub fn rmdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match rmdir_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn releasedir_core(fs: &InMemoryFS, _ino: u64, fh: u64) -> Result<(), i32> {
    fs.release_dir_handle(fh)
}

pub fn releasedir(fs: &InMemoryFS, req: Request, ino: u64, fh: u64) {
    log::trace!("releasedir(ino={}, fh={})", ino, fh);
    match releasedir_core(fs, ino, fh) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn fsyncdir(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    log::trace!("fsyncdir(ino={}, datasync={})", ino, datasync);
    let _ = fs.sync_log();
    req.reply_err(0);
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
}
