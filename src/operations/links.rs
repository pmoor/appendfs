use crate::fs::{InMemoryFS, find_parent_inode};
use crate::node::{AttrDelta, NodeDelta, SymlinkDelta};
use crate::shim::{FileAttr, FileType, Request};

pub fn unlink_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!("unlink(parent={}, name={})", parent, name);

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let child_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
        if fs.virtual_files.is_virtual_ino(child_ino) {
            return Err(libc::EPERM);
        }
        let child_attr = fs.get_attr(child_ino).ok_or(libc::ENOENT)?;

        if child_attr.file_type == FileType::Directory {
            return Err(libc::EISDIR);
        }

        fs.remove_dir_entry(parent, name, now);

        let new_nlink = child_attr.nlink.saturating_sub(1);
        fs.update_attr_delta(
            child_ino,
            AttrDelta {
                nlink: Some(new_nlink),
                ctime: Some(now),
                ..Default::default()
            },
        );

        if new_nlink == 0 && fs.open_count(child_ino) == 0 {
            fs.tombstone(child_ino);
        }
    }

    fs.notify_mutation(0);

    Ok(())
}

pub fn unlink(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match unlink_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn symlink_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    let attr = {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!(
            "symlink(parent={}, name={}, link={}, uid={}, gid={})",
            parent,
            name,
            target,
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
        let new_delta = NodeDelta::Symlink(SymlinkDelta {
            target: Some(target.to_string()),
            attr_delta: AttrDelta {
                mode: Some(0o777),
                nlink: Some(1),
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

        FileAttr {
            ino: new_ino,
            file_type: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: target.len() as i64,
            atime: now,
            mtime: now,
            ctime: now,
        }
    };

    fs.notify_mutation(0);

    Ok(attr)
}

pub fn symlink(fs: &InMemoryFS, req: Request, link: &str, parent: u64, name: &str) {
    let uid = req.uid();
    let gid = req.gid();
    match symlink_core(fs, parent, name, link, uid, gid) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn readlink_core(fs: &InMemoryFS, ino: u64) -> Result<String, i32> {
    log::trace!("readlink(ino={})", ino);
    fs.read_link(ino).ok_or(libc::EINVAL)
}

pub fn readlink(fs: &InMemoryFS, req: Request, ino: u64) {
    match readlink_core(fs, ino) {
        Ok(target) => req.reply_readlink(&target),
        Err(e) => req.reply_err(e),
    }
}

pub fn rename_core(fs: &InMemoryFS, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!(
            "rename(parent={}, name={}, newparent={}, newname={})",
            parent,
            name,
            newparent,
            newname
        );

        if name.len() > 255 || newname.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }
        let newparent_attr = fs.get_attr(newparent).ok_or(libc::ENOENT)?;
        if newparent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let source_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
        if fs.virtual_files.is_virtual_ino(source_ino) {
            return Err(libc::EPERM);
        }
        let source_attr = fs.get_attr(source_ino).ok_or(libc::ENOENT)?;

        if source_attr.file_type == FileType::Directory {
            let mut curr = newparent;
            while curr != 1 {
                if curr == source_ino {
                    return Err(libc::EINVAL);
                }
                if let Some(p) = find_parent_inode(fs, curr) {
                    curr = p;
                } else {
                    break;
                }
            }
        }

        if parent == newparent && name == newname {
            return Ok(());
        }

        let src_is_dir = source_attr.file_type == FileType::Directory;

        let mut dest_was_dir = false;
        if let Some(dest_ino) = fs.lookup_child(newparent, newname) {
            if fs.virtual_files.is_virtual_ino(dest_ino) {
                return Err(libc::EPERM);
            }
            // POSIX: when old and new resolve to different directory entries for the same
            // file - two hardlinks to one inode - rename succeeds and does nothing. Without
            // this the destination is treated as a victim and its link count is dropped,
            // which also desynchronizes the log: synthesis emits a bare Rename whose replay
            // does not reproduce that decrement.
            if dest_ino == source_ino {
                return Ok(());
            }

            let dest_attr = fs.get_attr(dest_ino).ok_or(libc::ENOENT)?;
            let dest_is_dir = dest_attr.file_type == FileType::Directory;

            if src_is_dir != dest_is_dir {
                return Err(if src_is_dir { libc::ENOTDIR } else { libc::EISDIR });
            }

            if dest_is_dir {
                let dest_entries = fs.list_directory(dest_ino).ok_or(libc::ENOENT)?;
                if !dest_entries.is_empty() {
                    return Err(libc::ENOTEMPTY);
                }
                dest_was_dir = true;
                fs.remove_dir_entry(newparent, newname, now);
                fs.tombstone(dest_ino);
            } else {
                fs.remove_dir_entry(newparent, newname, now);
                let new_dest_nlink = dest_attr.nlink.saturating_sub(1);
                fs.update_attr_delta(
                    dest_ino,
                    AttrDelta {
                        nlink: Some(new_dest_nlink),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
                if new_dest_nlink == 0 && fs.open_count(dest_ino) == 0 {
                    fs.tombstone(dest_ino);
                }
            }
        }

        fs.remove_dir_entry(parent, name, now);
        fs.add_dir_entry(newparent, newname, source_ino, now);
        if src_is_dir && parent != newparent {
            fs.update_dir_parent(source_ino, newparent);
        }
        if src_is_dir {
            // Two independent effects on subdirectory counts, composed rather than
            // handled as one combined case: moving to a different parent costs `parent`
            // a subdirectory and gains `newparent` one; clobbering an existing empty
            // directory at the destination costs `newparent` a subdirectory, regardless
            // of whether that's the same directory as `parent`. Handling them as a
            // single "cross-parent move, minus a same-parent-rename special case" (as
            // this used to) missed the case where they're `parent == newparent` *and*
            // dest_was_dir: renaming a directory onto an existing empty sibling in the
            // same parent removes a subdirectory (the clobbered sibling) without adding
            // one (the source was already counted), and nothing here applied that half
            // when the "cross-parent" condition gating the whole block was false.
            let mut parent_delta: i64 = 0;
            let mut newparent_delta: i64 = 0;
            if parent != newparent {
                parent_delta -= 1;
                newparent_delta += 1;
            }
            if dest_was_dir {
                newparent_delta -= 1;
            }
            if parent_delta != 0 {
                fs.update_attr_delta(
                    parent,
                    AttrDelta {
                        nlink: Some((parent_attr.nlink as i64 + parent_delta) as u32),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
            }
            if newparent_delta != 0 {
                fs.update_attr_delta(
                    newparent,
                    AttrDelta {
                        nlink: Some((newparent_attr.nlink as i64 + newparent_delta) as u32),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
            }
        }
    }

    fs.notify_mutation(0);

    Ok(())
}

pub fn rename(fs: &InMemoryFS, req: Request, parent: u64, name: &str, newparent: u64, newname: &str) {
    match rename_core(fs, parent, name, newparent, newname) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn link_core(fs: &InMemoryFS, ino: u64, newparent: u64, newname: &str) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    fs.check_flush_capacity()?;

    {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!("link(ino={}, newparent={}, newname={})", ino, newparent, newname);

        if newname.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let target_attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
        if target_attr.file_type == FileType::Directory {
            return Err(libc::EPERM);
        }
        if target_attr.nlink == 0 {
            return Err(libc::ENOENT);
        }

        let newparent_attr = fs.get_attr(newparent).ok_or(libc::ENOENT)?;
        if newparent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child(newparent, newname).is_some() {
            return Err(libc::EEXIST);
        }

        let new_nlink = target_attr.nlink + 1;
        fs.update_attr_delta(
            ino,
            AttrDelta {
                nlink: Some(new_nlink),
                ctime: Some(now),
                ..Default::default()
            },
        );

        fs.add_dir_entry(newparent, newname, ino, now);
    }

    fs.notify_mutation(0);

    fs.get_attr(ino).ok_or(libc::ENOENT)
}

pub fn link(fs: &InMemoryFS, req: Request, ino: u64, newparent: u64, newname: &str) {
    match link_core(fs, ino, newparent, newname) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}
