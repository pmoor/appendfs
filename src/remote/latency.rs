use crate::remote::{RemoteObject, RemoteStore};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// A decorator wrapper around any `RemoteStore` capable of injecting artificial delays
/// (fixed delays per call, method-specific delays, or simulated bandwidth throttling).
#[derive(Debug)]
pub struct LatencyRemoteStore {
    inner: Arc<dyn RemoteStore>,
    fixed_delay: RwLock<Option<Duration>>,
    method_delays: RwLock<HashMap<String, Duration>>,
    bytes_per_sec: RwLock<Option<u64>>,
}

impl LatencyRemoteStore {
    pub fn new(inner: Arc<dyn RemoteStore>) -> Self {
        Self {
            inner,
            fixed_delay: RwLock::new(None),
            method_delays: RwLock::new(HashMap::new()),
            bytes_per_sec: RwLock::new(None),
        }
    }

    /// Access the wrapped inner store.
    pub fn inner(&self) -> &Arc<dyn RemoteStore> {
        &self.inner
    }

    /// Injects a fixed delay on every remote store operation.
    pub fn set_fixed_delay(&self, delay: Duration) {
        *self.fixed_delay.write().unwrap() = Some(delay);
    }

    /// Clears any fixed delay.
    pub fn clear_fixed_delay(&self) {
        *self.fixed_delay.write().unwrap() = None;
    }

    /// Injects a delay for a specific method (e.g. "get_object_range", "put_object").
    pub fn set_method_delay(&self, method: &str, delay: Duration) {
        self.method_delays.write().unwrap().insert(method.to_string(), delay);
    }

    /// Clears any delay for a specific method.
    pub fn clear_method_delay(&self, method: &str) {
        self.method_delays.write().unwrap().remove(method);
    }

    /// Simulates bandwidth throttling by adding a transfer delay proportional to byte length.
    pub fn set_bandwidth_limit(&self, bytes_per_sec: u64) {
        *self.bytes_per_sec.write().unwrap() = Some(bytes_per_sec);
    }

    /// Clears simulated bandwidth limits.
    pub fn clear_bandwidth_limit(&self) {
        *self.bytes_per_sec.write().unwrap() = None;
    }

    /// Clears all configured delays and limits.
    pub fn clear_delays(&self) {
        *self.fixed_delay.write().unwrap() = None;
        self.method_delays.write().unwrap().clear();
        *self.bytes_per_sec.write().unwrap() = None;
    }

    fn apply_delay(&self, method: &str, payload_bytes: u64) {
        let mut total = Duration::ZERO;
        if let Some(d) = *self.fixed_delay.read().unwrap() {
            total += d;
        }
        if let Some(d) = self.method_delays.read().unwrap().get(method) {
            total += *d;
        }
        if let Some(bps) = *self.bytes_per_sec.read().unwrap()
            && bps > 0
            && payload_bytes > 0
        {
            let nanos = (payload_bytes as u128 * 1_000_000_000) / (bps as u128);
            total += Duration::from_nanos(nanos.min(u64::MAX as u128) as u64);
        }

        if total > Duration::ZERO {
            thread::sleep(total);
        }
    }
}

impl RemoteStore for LatencyRemoteStore {
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>> {
        self.apply_delay("list_objects", 0);
        self.inner.list_objects(prefix)
    }

    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>> {
        self.apply_delay("head_object", 0);
        self.inner.head_object(key)
    }

    fn put_object(&self, key: &str, reader: &mut dyn Read, len: u64, content_md5: Option<&[u8; 16]>) -> io::Result<()> {
        self.apply_delay("put_object", len);
        self.inner.put_object(key, reader, len, content_md5)
    }

    fn get_object(&self, key: &str, writer: &mut dyn Write) -> io::Result<u64> {
        let size = self.inner.head_object(key)?.map(|o| o.size).unwrap_or(0);
        self.apply_delay("get_object", size);
        self.inner.get_object(key, writer)
    }

    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> io::Result<u64> {
        self.apply_delay("get_object_range", len);
        self.inner.get_object_range(key, offset, len, writer)
    }

    fn delete_object(&self, key: &str) -> io::Result<()> {
        self.apply_delay("delete_object", 0);
        self.inner.delete_object(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;
    use std::time::Instant;

    #[test]
    fn test_latency_store_fixed_delay() {
        let mock = Arc::new(MockRemoteStore::new());
        let latency_store = LatencyRemoteStore::new(mock.clone());

        latency_store.set_fixed_delay(Duration::from_millis(15));

        let start = Instant::now();
        let _ = latency_store.list_objects("");
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(14), "elapsed was {:?}", elapsed);
    }

    #[test]
    fn test_latency_store_method_delay() {
        let mock = Arc::new(MockRemoteStore::new());
        let latency_store = LatencyRemoteStore::new(mock.clone());

        latency_store.set_method_delay("head_object", Duration::from_millis(20));

        let start1 = Instant::now();
        let _ = latency_store.list_objects("");
        let elapsed1 = start1.elapsed();
        // list_objects has no method delay, should be near instant
        assert!(elapsed1 < Duration::from_millis(10));

        let start2 = Instant::now();
        let _ = latency_store.head_object("nonexistent");
        let elapsed2 = start2.elapsed();
        assert!(elapsed2 >= Duration::from_millis(19));
    }
}
