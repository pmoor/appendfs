use crate::fs::InMemoryFS;

pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;

#[derive(Debug, PartialEq, Eq)]
pub enum GetxattrResult {
    Size(usize),
    Data(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ListxattrResult {
    Size(usize),
    Data(Vec<u8>),
}

pub fn getxattr_core(fs: &InMemoryFS, ino: u64, name: &str, size: usize) -> Result<GetxattrResult, i32> {
    if fs.get_attr(ino).is_none() {
        return Err(libc::ENOENT);
    }
    if fs.is_virtual_ino(ino) {
        return Err(libc::ENODATA);
    }

    let val = fs.get_xattr(ino, name).ok_or(libc::ENODATA)?;
    if size == 0 {
        Ok(GetxattrResult::Size(val.len()))
    } else if size < val.len() {
        Err(libc::ERANGE)
    } else {
        Ok(GetxattrResult::Data(val))
    }
}

pub fn setxattr_core(fs: &InMemoryFS, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }

    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(libc::ERANGE);
    }

    if value.len() > XATTR_SIZE_MAX {
        return Err(libc::E2BIG);
    }

    if fs.get_attr(ino).is_none() {
        return Err(libc::ENOENT);
    }

    let exists = fs.get_xattr(ino, name).is_some();
    if (flags & libc::XATTR_CREATE) != 0 && exists {
        return Err(libc::EEXIST);
    }
    if (flags & libc::XATTR_REPLACE) != 0 && !exists {
        return Err(libc::ENODATA);
    }

    let now = fs.clock.now();
    fs.set_xattr(ino, name, value.to_vec(), now);
    fs.notify_mutation(name.len() + value.len());
    Ok(())
}

pub fn listxattr_core(fs: &InMemoryFS, ino: u64, size: usize) -> Result<ListxattrResult, i32> {
    if fs.get_attr(ino).is_none() {
        return Err(libc::ENOENT);
    }
    if fs.is_virtual_ino(ino) {
        return Ok(if size == 0 {
            ListxattrResult::Size(0)
        } else {
            ListxattrResult::Data(Vec::new())
        });
    }

    let keys = fs.list_xattrs(ino).ok_or(libc::ENOENT)?;
    let mut buf = Vec::new();
    for key in keys {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0); // null terminator
    }

    if size == 0 {
        Ok(ListxattrResult::Size(buf.len()))
    } else if size < buf.len() {
        Err(libc::ERANGE)
    } else {
        Ok(ListxattrResult::Data(buf))
    }
}

pub fn removexattr_core(fs: &InMemoryFS, ino: u64, name: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }
    if fs.is_virtual_ino(ino) {
        return Err(libc::EPERM);
    }

    if fs.get_attr(ino).is_none() {
        return Err(libc::ENOENT);
    }

    if fs.get_xattr(ino, name).is_none() {
        return Err(libc::ENODATA);
    }

    let now = fs.clock.now();
    fs.remove_xattr(ino, name, now);
    fs.notify_mutation(name.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xattr_basic_crud_and_size_query() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // 1. Missing attribute returns ENODATA
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 0), Err(libc::ENODATA));

        // 2. Set attribute
        assert_eq!(setxattr_core(&fs, ino, "user.comment", b"hello world", 0), Ok(()));

        // 3. Query size (size == 0)
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 0), Ok(GetxattrResult::Size(11)));

        // 4. Query with insufficient buffer -> ERANGE
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 5), Err(libc::ERANGE));

        // 5. Query with sufficient buffer -> Data
        assert_eq!(
            getxattr_core(&fs, ino, "user.comment", 20),
            Ok(GetxattrResult::Data(b"hello world".to_vec()))
        );

        // 6. List attributes
        match listxattr_core(&fs, ino, 0).unwrap() {
            ListxattrResult::Size(sz) => assert_eq!(sz, "user.comment\0".len()),
            _ => panic!("Expected Size result"),
        }

        match listxattr_core(&fs, ino, 64).unwrap() {
            ListxattrResult::Data(data) => assert_eq!(data, b"user.comment\0"),
            _ => panic!("Expected Data result"),
        }

        // 7. Remove attribute
        assert_eq!(removexattr_core(&fs, ino, "user.comment"), Ok(()));
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 0), Err(libc::ENODATA));
        assert_eq!(removexattr_core(&fs, ino, "user.comment"), Err(libc::ENODATA));
    }

    #[test]
    fn test_xattr_create_and_replace_flags() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "flags.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // REPLACE fails on nonexistent attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v1", libc::XATTR_REPLACE),
            Err(libc::ENODATA)
        );

        // CREATE succeeds on nonexistent attribute
        assert_eq!(setxattr_core(&fs, ino, "user.tag", b"v1", libc::XATTR_CREATE), Ok(()));

        // CREATE fails on existing attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v2", libc::XATTR_CREATE),
            Err(libc::EEXIST)
        );

        // REPLACE succeeds on existing attribute
        assert_eq!(setxattr_core(&fs, ino, "user.tag", b"v2", libc::XATTR_REPLACE), Ok(()));

        assert_eq!(
            getxattr_core(&fs, ino, "user.tag", 10),
            Ok(GetxattrResult::Data(b"v2".to_vec()))
        );
    }

    #[test]
    fn test_xattr_multiple_attributes_deterministic_order() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "multi.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        setxattr_core(&fs, ino, "user.zebra", b"1", 0).unwrap();
        setxattr_core(&fs, ino, "user.apple", b"2", 0).unwrap();
        setxattr_core(&fs, ino, "user.mango", b"3", 0).unwrap();

        match listxattr_core(&fs, ino, 100).unwrap() {
            ListxattrResult::Data(data) => {
                assert_eq!(data, b"user.apple\0user.mango\0user.zebra\0");
            }
            _ => panic!("Expected Data result"),
        }
    }
}
