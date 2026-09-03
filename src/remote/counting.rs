use crate::remote::{RemoteObject, RemoteStore};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Telemetry metrics tracking operations and byte volume for a remote store.
#[derive(Debug, Default)]
pub struct RemoteStoreMetrics {
    pub list_objects: AtomicUsize,
    pub head_object: AtomicUsize,
    pub put_object: AtomicUsize,
    pub get_object: AtomicUsize,
    pub get_object_range: AtomicUsize,
    pub delete_object: AtomicUsize,
    pub bytes_uploaded: AtomicU64,
    pub bytes_downloaded: AtomicU64,
}

impl RemoteStoreMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of operations dispatched to the store across all methods.
    pub fn total_requests(&self) -> usize {
        self.list_objects.load(Ordering::SeqCst)
            + self.head_object.load(Ordering::SeqCst)
            + self.put_object.load(Ordering::SeqCst)
            + self.get_object.load(Ordering::SeqCst)
            + self.get_object_range.load(Ordering::SeqCst)
            + self.delete_object.load(Ordering::SeqCst)
    }

    /// Resets all counters to zero.
    pub fn reset(&self) {
        self.list_objects.store(0, Ordering::SeqCst);
        self.head_object.store(0, Ordering::SeqCst);
        self.put_object.store(0, Ordering::SeqCst);
        self.get_object.store(0, Ordering::SeqCst);
        self.get_object_range.store(0, Ordering::SeqCst);
        self.delete_object.store(0, Ordering::SeqCst);
        self.bytes_uploaded.store(0, Ordering::SeqCst);
        self.bytes_downloaded.store(0, Ordering::SeqCst);
    }
}

/// A decorator wrapper around any `RemoteStore` that collects operational metrics
/// and telemetry (requests per method, total requests, bytes transferred).
#[derive(Debug)]
pub struct CountingRemoteStore {
    inner: Arc<dyn RemoteStore>,
    metrics: Arc<RemoteStoreMetrics>,
}

impl CountingRemoteStore {
    pub fn new(inner: Arc<dyn RemoteStore>) -> Self {
        Self {
            inner,
            metrics: Arc::new(RemoteStoreMetrics::new()),
        }
    }

    pub fn with_shared_metrics(inner: Arc<dyn RemoteStore>, metrics: Arc<RemoteStoreMetrics>) -> Self {
        Self { inner, metrics }
    }

    /// Access the wrapped inner store.
    pub fn inner(&self) -> &Arc<dyn RemoteStore> {
        &self.inner
    }

    /// Access the collected metrics.
    pub fn metrics(&self) -> &Arc<RemoteStoreMetrics> {
        &self.metrics
    }

    /// Total requests dispatched through this store.
    pub fn total_requests(&self) -> usize {
        self.metrics.total_requests()
    }

    /// Total range reads dispatched (`get_object_range`).
    pub fn range_reads(&self) -> usize {
        self.metrics.get_object_range.load(Ordering::SeqCst)
    }

    /// Total full object gets dispatched (`get_object`).
    pub fn gets(&self) -> usize {
        self.metrics.get_object.load(Ordering::SeqCst)
    }

    /// Total object uploads dispatched (`put_object`).
    pub fn puts(&self) -> usize {
        self.metrics.put_object.load(Ordering::SeqCst)
    }

    /// Total metadata queries dispatched (`head_object`).
    pub fn heads(&self) -> usize {
        self.metrics.head_object.load(Ordering::SeqCst)
    }

    /// Total listing queries dispatched (`list_objects`).
    pub fn lists(&self) -> usize {
        self.metrics.list_objects.load(Ordering::SeqCst)
    }

    /// Total object deletions dispatched (`delete_object`).
    pub fn deletes(&self) -> usize {
        self.metrics.delete_object.load(Ordering::SeqCst)
    }

    /// Total bytes downloaded across `get_object` and `get_object_range`.
    pub fn bytes_downloaded(&self) -> u64 {
        self.metrics.bytes_downloaded.load(Ordering::SeqCst)
    }

    /// Total bytes uploaded through `put_object`.
    pub fn bytes_uploaded(&self) -> u64 {
        self.metrics.bytes_uploaded.load(Ordering::SeqCst)
    }

    /// Resets all counters to zero.
    pub fn reset(&self) {
        self.metrics.reset();
    }
}

impl RemoteStore for CountingRemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        self.metrics.list_objects.fetch_add(1, Ordering::SeqCst);
        self.inner.list_objects(prefix)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        self.metrics.head_object.fetch_add(1, Ordering::SeqCst);
        self.inner.head_object(key)
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        self.metrics.put_object.fetch_add(1, Ordering::SeqCst);
        self.metrics.bytes_uploaded.fetch_add(len, Ordering::SeqCst);
        self.inner.put_object(key, reader, len, content_md5)
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        self.metrics.get_object.fetch_add(1, Ordering::SeqCst);
        let bytes_read = self.inner.get_object(key, writer)?;
        self.metrics.bytes_downloaded.fetch_add(bytes_read, Ordering::SeqCst);
        Ok(bytes_read)
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        self.metrics.get_object_range.fetch_add(1, Ordering::SeqCst);
        let bytes_read = self.inner.get_object_range(key, offset, len, writer)?;
        self.metrics.bytes_downloaded.fetch_add(bytes_read, Ordering::SeqCst);
        Ok(bytes_read)
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        self.metrics.delete_object.fetch_add(1, Ordering::SeqCst);
        self.inner.delete_object(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;

    #[test]
    fn test_counting_remote_store_metrics() {
        let mock = Arc::new(MockRemoteStore::new());
        let counting = CountingRemoteStore::new(mock.clone());

        assert_eq!(counting.total_requests(), 0);

        let data = b"Hello, metrics!";
        counting
            .put_object("data.txt", &mut &data[..], data.len() as u64, None)
            .unwrap();

        assert_eq!(counting.puts(), 1);
        assert_eq!(counting.bytes_uploaded(), data.len() as u64);
        assert_eq!(counting.total_requests(), 1);

        assert!(counting.head_object("data.txt").unwrap().is_some());
        assert_eq!(counting.heads(), 1);
        assert_eq!(counting.total_requests(), 2);

        let mut buf = Vec::new();
        let n = counting.get_object_range("data.txt", 0, 5, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(counting.range_reads(), 1);
        assert_eq!(counting.bytes_downloaded(), 5);
        assert_eq!(counting.total_requests(), 3);

        counting.list_objects("").unwrap();
        assert_eq!(counting.lists(), 1);
        assert_eq!(counting.total_requests(), 4);

        counting.delete_object("data.txt").unwrap();
        assert_eq!(counting.deletes(), 1);
        assert_eq!(counting.total_requests(), 5);

        // Reset
        counting.reset();
        assert_eq!(counting.total_requests(), 0);
        assert_eq!(counting.bytes_uploaded(), 0);
        assert_eq!(counting.bytes_downloaded(), 0);
    }
}
