use crate::remote::{RemoteObject, RemoteStore};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A `RemoteStore` implementation backed by a local directory (e.g. an NFS mount,
/// CIFS/Samba network share, or secondary storage drive).
///
/// Ensures atomic file creation via `.tmp` staging, and maintains sibling `<key>.md5`
/// sidecar files to provide instant ETag evaluation without reading large log files.
#[derive(Debug, Clone)]
pub struct LocalDirRemoteStore {
    root: PathBuf,
}

impl LocalDirRemoteStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl RemoteStore for LocalDirRemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }

        let mut objects = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|s| s.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Ignore internal staging and checksum sidecar files
            if filename.ends_with(".tmp") || filename.ends_with(".md5") || filename.starts_with('.') {
                continue;
            }

            if !filename.starts_with(prefix) {
                continue;
            }

            let meta = entry.metadata()?;
            let md5_path = self.root.join(format!("{}.md5", filename));
            let etag = if let Ok(content) = fs::read_to_string(&md5_path) {
                let trimmed = content.trim();
                if trimmed.len() == 32 {
                    Some(format!("\"{}\"", trimmed))
                } else {
                    None
                }
            } else {
                None
            };

            objects.push(RemoteObject::new(filename, meta.len(), etag, meta.modified().ok()));
        }

        objects.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(objects)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        let file_path = self.root.join(key);
        if !file_path.exists() {
            return Ok(None);
        }

        let meta = fs::metadata(&file_path)?;
        let md5_path = self.root.join(format!("{}.md5", key));
        let etag = if let Ok(content) = fs::read_to_string(&md5_path) {
            let trimmed = content.trim();
            if trimmed.len() == 32 {
                Some(format!("\"{}\"", trimmed))
            } else {
                None
            }
        } else {
            // Missing .md5 sidecar: treated as unverified without reading the entire file from disk
            None
        };

        Ok(Some(RemoteObject::new(key, meta.len(), etag, meta.modified().ok())))
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;

        let tmp_path = self.root.join(format!("{}.tmp", key));
        let final_path = self.root.join(key);
        let md5_path = self.root.join(format!("{}.md5", key));

        let mut file = File::create(&tmp_path)?;
        let mut hasher = md5::Context::new();
        let mut buf = [0u8; 64 * 1024];
        let mut remaining = len;

        while remaining > 0 {
            let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
            let n = reader.read(&mut buf[..to_read])?;
            if n == 0 {
                let _ = fs::remove_file(&tmp_path);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while streaming put_object to local remote",
                ));
            }
            file.write_all(&buf[..n])?;
            hasher.consume(&buf[..n]);
            remaining -= n as u64;
        }

        file.flush()?;
        file.sync_all()?;

        let computed_digest = hasher.compute().0;
        if let Some(expected_md5) = content_md5
            && computed_digest != *expected_md5
        {
            let _ = fs::remove_file(&tmp_path);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "BadDigest: expected {}, got {}",
                    hex::encode(expected_md5),
                    hex::encode(computed_digest)
                ),
            ));
        }

        // Write sibling .md5 checksum sidecar file
        fs::write(&md5_path, hex::encode(computed_digest))?;

        // Atomically commit staged data file
        fs::rename(&tmp_path, &final_path)?;

        Ok(())
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        let file_path = self.root.join(key);
        let mut file = File::open(&file_path)?;
        io::copy(&mut file, writer)
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        let file_path = self.root.join(key);
        let mut file = File::open(&file_path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut take = file.take(len);
        io::copy(&mut take, writer)
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        let file_path = self.root.join(key);
        let _ = fs::remove_file(&file_path);
        let md5_path = self.root.join(format!("{}.md5", key));
        let _ = fs::remove_file(&md5_path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_dir_remote_store_crud_and_md5() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalDirRemoteStore::new(dir.path());

        let data = b"Hello from local directory remote store with MD5 sidecars";
        let md5_digest = *md5::compute(data);

        // Put object with valid MD5
        store
            .put_object("000001.log", &mut &data[..], data.len() as u64, Some(&md5_digest))
            .unwrap();

        // Check head_object
        let obj = store.head_object("000001.log").unwrap().unwrap();
        assert_eq!(obj.size, data.len() as u64);
        assert_eq!(obj.etag_md5(), Some(md5_digest));

        // Check sibling file exists
        assert!(dir.path().join("000001.log.md5").exists());

        // Range read
        let mut range_buf = Vec::new();
        let bytes_copied = store.get_object_range("000001.log", 6, 4, &mut range_buf).unwrap();
        assert_eq!(bytes_copied, 4);
        assert_eq!(range_buf, b"from");

        // Full read
        let mut full_buf = Vec::new();
        store.get_object("000001.log", &mut full_buf).unwrap();
        assert_eq!(full_buf, data);

        // Put object with bad MD5 should fail
        let bad_md5 = [0xEE; 16];
        let err = store
            .put_object("bad.log", &mut &data[..], data.len() as u64, Some(&bad_md5))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!dir.path().join("bad.log").exists());
        assert!(!dir.path().join("bad.log.tmp").exists());

        // Missing .md5 leaves etag: None
        fs::remove_file(dir.path().join("000001.log.md5")).unwrap();
        let obj_no_md5 = store.head_object("000001.log").unwrap().unwrap();
        assert_eq!(obj_no_md5.etag, None);

        // Delete object
        store.delete_object("000001.log").unwrap();
        assert!(store.head_object("000001.log").unwrap().is_none());
    }
}
