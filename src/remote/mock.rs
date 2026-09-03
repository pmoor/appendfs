use crate::remote::{RemoteObject, RemoteStore};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::RwLock;
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct StoredObject {
    data: Vec<u8>,
    etag: String,
    last_modified: SystemTime,
}

/// Thread-safe in-memory implementation of `RemoteStore` for deterministic unit and integration tests.
#[derive(Debug, Default)]
pub struct MockRemoteStore {
    objects: RwLock<BTreeMap<String, StoredObject>>,
}

pub type MemoryRemoteStore = MockRemoteStore;

impl MockRemoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Directly checks if an object exists and returns its length.
    pub fn object_len(&self, key: &str) -> Option<u64> {
        let guard = self.objects.read().unwrap();
        guard.get(key).map(|o| o.data.len() as u64)
    }

    /// Returns a copy of raw object bytes (test helper).
    pub fn get_raw_bytes(&self, key: &str) -> Option<Vec<u8>> {
        let guard = self.objects.read().unwrap();
        guard.get(key).map(|o| o.data.clone())
    }
}

impl RemoteStore for MockRemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        let guard = self.objects.read().unwrap();
        let mut out = Vec::new();
        for (k, obj) in guard.iter() {
            if k.starts_with(prefix) {
                out.push(RemoteObject {
                    key: k.clone(),
                    size: obj.data.len() as u64,
                    etag: Some(obj.etag.clone()),
                    last_modified: Some(obj.last_modified),
                });
            }
        }
        Ok(out)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        let guard = self.objects.read().unwrap();
        Ok(guard.get(key).map(|obj| RemoteObject {
            key: key.to_string(),
            size: obj.data.len() as u64,
            etag: Some(obj.etag.clone()),
            last_modified: Some(obj.last_modified),
        }))
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        let mut buf = Vec::with_capacity(len as usize);
        reader.take(len).read_to_end(&mut buf)?;

        if buf.len() as u64 != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("put_object expected {} bytes, read {}", len, buf.len()),
            ));
        }

        let computed_md5: [u8; 16] = *md5::compute(&buf);
        if let Some(expected_md5) = content_md5
            && computed_md5 != *expected_md5
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "400 BadDigest: Content-MD5 mismatch (expected {}, got {})",
                    hex::encode(expected_md5),
                    hex::encode(computed_md5)
                ),
            ));
        }

        let etag = format!("\"{}\"", hex::encode(computed_md5));
        let mut guard = self.objects.write().unwrap();
        guard.insert(
            key.to_string(),
            StoredObject {
                data: buf,
                etag,
                last_modified: SystemTime::now(),
            },
        );
        Ok(())
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        let guard = self.objects.read().unwrap();
        let obj = guard
            .get(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("NoSuchKey: {}", key)))?;
        writer.write_all(&obj.data)?;
        Ok(obj.data.len() as u64)
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        let guard = self.objects.read().unwrap();
        let obj = guard
            .get(key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("NoSuchKey: {}", key)))?;

        let start = offset as usize;
        let end = (offset + len).min(obj.data.len() as u64) as usize;
        if start >= obj.data.len() {
            return Ok(0);
        }
        let slice = &obj.data[start..end];
        writer.write_all(slice)?;
        Ok(slice.len() as u64)
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        let mut guard = self.objects.write().unwrap();
        guard.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_remote_store_crud_and_md5() {
        let store = MockRemoteStore::new();
        assert_eq!(store.head_object("test.log").unwrap(), None);

        let data = b"hello world streaming S3 payload";
        let expected_md5: [u8; 16] = *md5::compute(data);

        // Put with valid MD5
        store
            .put_object(
                "logs/000001.log",
                &mut &data[..],
                data.len() as u64,
                Some(&expected_md5),
            )
            .unwrap();

        // Put with bad MD5 is rejected with BadDigest
        let bad_md5 = [0u8; 16];
        let err = store
            .put_object("logs/000002.log", &mut &data[..], data.len() as u64, Some(&bad_md5))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Head object returns ETag matching MD5
        let head = store.head_object("logs/000001.log").unwrap().unwrap();
        assert_eq!(head.size, data.len() as u64);
        assert_eq!(head.etag_md5(), Some(expected_md5));

        // Get object
        let mut downloaded = Vec::new();
        let bytes = store.get_object("logs/000001.log", &mut downloaded).unwrap();
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(&downloaded, data);

        // Range get
        let mut range_buf = Vec::new();
        let bytes = store.get_object_range("logs/000001.log", 6, 5, &mut range_buf).unwrap();
        assert_eq!(bytes, 5);
        assert_eq!(&range_buf, b"world");

        // List
        let list = store.list_objects("logs/").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, "logs/000001.log");

        // Delete
        store.delete_object("logs/000001.log").unwrap();
        assert_eq!(store.head_object("logs/000001.log").unwrap(), None);
    }
}
