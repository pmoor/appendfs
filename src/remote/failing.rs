use crate::remote::{RemoteObject, RemoteStore};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// A decorator wrapper around any `RemoteStore` capable of injecting fine-grained faults
/// (request countdown failures, method-specific errors, key-specific errors, and bitflips).
#[derive(Debug)]
pub struct FailingRemoteStore {
    inner: Arc<dyn RemoteStore>,
    fail_next_requests: AtomicUsize,
    error_kind: RwLock<io::ErrorKind>,
    error_message: RwLock<String>,
    fail_methods: RwLock<HashSet<String>>,
    fail_keys: RwLock<HashSet<String>>,
    bitflips: RwLock<Vec<(String, u64, u8)>>, // (key, byte_offset, bit_mask)
}

impl FailingRemoteStore {
    pub fn new(inner: Arc<dyn RemoteStore>) -> Self {
        Self {
            inner,
            fail_next_requests: AtomicUsize::new(0),
            error_kind: RwLock::new(io::ErrorKind::ConnectionReset),
            error_message: RwLock::new(
                "simulated remote store failure (503 Service Unavailable / ConnectionReset)".to_string(),
            ),
            fail_methods: RwLock::new(HashSet::new()),
            fail_keys: RwLock::new(HashSet::new()),
            bitflips: RwLock::new(Vec::new()),
        }
    }

    /// Access the wrapped inner store.
    pub fn inner(&self) -> &Arc<dyn RemoteStore> {
        &self.inner
    }

    /// Injects `n` consecutive failures for subsequent remote operations.
    pub fn fail_next_n_requests(&self, n: usize) {
        self.fail_next_requests.store(n, Ordering::SeqCst);
    }

    /// Configures the specific error kind and message returned on injected failure.
    pub fn set_error(&self, kind: io::ErrorKind, msg: impl Into<String>) {
        *self.error_kind.write().unwrap() = kind;
        *self.error_message.write().unwrap() = msg.into();
    }

    /// Injects an error for a specific method (e.g. "get_object_range", "put_object").
    pub fn fail_method(&self, method: &str) {
        self.fail_methods.write().unwrap().insert(method.to_string());
    }

    /// Clears any injected failure for a specific method.
    pub fn clear_fail_method(&self, method: &str) {
        self.fail_methods.write().unwrap().remove(method);
    }

    /// Injects an error for operations referencing a specific key.
    pub fn fail_key(&self, key: &str) {
        self.fail_keys.write().unwrap().insert(key.to_string());
    }

    /// Clears any injected failure for a specific key.
    pub fn clear_fail_key(&self, key: &str) {
        self.fail_keys.write().unwrap().remove(key);
    }

    /// Injects a bitflip into data returned by `get_object` or `get_object_range`.
    pub fn inject_bitflip(&self, key: &str, offset: u64, bit_mask: u8) {
        self.bitflips.write().unwrap().push((key.to_string(), offset, bit_mask));
    }

    /// Clears all injected faults (countdown, method/key filters, bitflips).
    pub fn clear_faults(&self) {
        self.fail_next_requests.store(0, Ordering::SeqCst);
        self.fail_methods.write().unwrap().clear();
        self.fail_keys.write().unwrap().clear();
        self.bitflips.write().unwrap().clear();
    }

    fn check_fault(&self, method: &str, key: Option<&str>) -> io::Result<()> {
        let remaining = self.fail_next_requests.load(Ordering::SeqCst);
        if remaining > 0 {
            self.fail_next_requests.fetch_sub(1, Ordering::SeqCst);
            let kind = *self.error_kind.read().unwrap();
            let msg = self.error_message.read().unwrap().clone();
            return Err(io::Error::new(kind, msg));
        }

        if self.fail_methods.read().unwrap().contains(method) {
            let kind = *self.error_kind.read().unwrap();
            let msg = self.error_message.read().unwrap().clone();
            return Err(io::Error::new(
                kind,
                format!("{} [injected for method {}]", msg, method),
            ));
        }

        if let Some(k) = key
            && self.fail_keys.read().unwrap().contains(k)
        {
            let kind = *self.error_kind.read().unwrap();
            let msg = self.error_message.read().unwrap().clone();
            return Err(io::Error::new(kind, format!("{} [injected for key {}]", msg, k)));
        }

        Ok(())
    }

    fn apply_bitflips(&self, key: &str, offset: u64, buf: &mut [u8]) {
        let flips = self.bitflips.read().unwrap();
        for (flip_key, flip_offset, mask) in flips.iter() {
            if flip_key == key && *flip_offset >= offset {
                let inner = (*flip_offset - offset) as usize;
                if inner < buf.len() {
                    buf[inner] ^= *mask;
                }
            }
        }
    }
}

impl RemoteStore for FailingRemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        self.check_fault("list_objects", None)?;
        self.inner.list_objects(prefix)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        self.check_fault("head_object", Some(key))?;
        self.inner.head_object(key)
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        self.check_fault("put_object", Some(key))?;
        self.inner.put_object(key, reader, len, content_md5)
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        self.check_fault("get_object", Some(key))?;
        let flips = self.bitflips.read().unwrap();
        let has_flips = flips.iter().any(|(k, _, _)| k == key);
        drop(flips);

        if has_flips {
            let mut buf = Vec::new();
            let n = self.inner.get_object(key, &mut buf)?;
            self.apply_bitflips(key, 0, &mut buf);
            writer.write_all(&buf)?;
            Ok(n)
        } else {
            self.inner.get_object(key, writer)
        }
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        self.check_fault("get_object_range", Some(key))?;
        let flips = self.bitflips.read().unwrap();
        let has_flips = flips.iter().any(|(k, _, _)| k == key);
        drop(flips);

        if has_flips {
            let mut buf = Vec::new();
            let n = self.inner.get_object_range(key, offset, len, &mut buf)?;
            self.apply_bitflips(key, offset, &mut buf);
            writer.write_all(&buf)?;
            Ok(n)
        } else {
            self.inner.get_object_range(key, offset, len, writer)
        }
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        self.check_fault("delete_object", Some(key))?;
        self.inner.delete_object(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;

    #[test]
    fn test_failing_store_countdown_and_recovery() {
        let mock = Arc::new(MockRemoteStore::new());
        let failing = FailingRemoteStore::new(mock.clone());

        failing.fail_next_n_requests(2);

        // 1st request fails
        assert!(failing.list_objects("").is_err());
        // 2nd request fails
        assert!(failing.head_object("test.log").is_err());
        // 3rd request succeeds
        assert!(failing.list_objects("").is_ok());
    }

    #[test]
    fn test_failing_store_method_and_key_filtering() {
        let mock = Arc::new(MockRemoteStore::new());
        let payload = b"Hello, AppendFS!";
        mock.put_object("file.txt", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        let failing = FailingRemoteStore::new(mock.clone());

        // Fail only get_object_range
        failing.fail_method("get_object_range");
        assert!(failing.head_object("file.txt").unwrap().is_some());

        let mut buf = Vec::new();
        assert!(failing.get_object_range("file.txt", 0, 5, &mut buf).is_err());

        // Clear method failure
        failing.clear_fail_method("get_object_range");
        buf.clear();
        assert_eq!(failing.get_object_range("file.txt", 0, 5, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"Hello");

        // Fail specific key
        failing.fail_key("file.txt");
        assert!(failing.head_object("file.txt").is_err());
        assert!(failing.head_object("other.txt").unwrap().is_none());
    }

    #[test]
    fn test_failing_store_bitflip_injection() {
        let mock = Arc::new(MockRemoteStore::new());
        let payload = [0xAA; 100];
        mock.put_object("data.bin", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        let failing = FailingRemoteStore::new(mock.clone());
        failing.inject_bitflip("data.bin", 5, 0x01);

        let mut out = Vec::new();
        failing.get_object("data.bin", &mut out).unwrap();
        assert_eq!(out[5], 0xAA ^ 0x01);
        assert_eq!(out[0], 0xAA);

        // Range read also applies bitflip correctly
        let mut range_out = Vec::new();
        failing.get_object_range("data.bin", 4, 10, &mut range_out).unwrap();
        assert_eq!(range_out[1], 0xAA ^ 0x01); // offset 5 is index 1 relative to offset 4
    }
}
