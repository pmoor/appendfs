pub mod block_cache;
pub mod bootstrap;
pub mod coalesce;
pub mod config;
pub mod counting;
pub mod failing;
pub mod fs;
pub mod latency;
pub mod mock;
pub mod s3;
pub mod sigv4;
pub mod tiered_reader;
pub mod worker;

pub use crate::check::check_remote_integrity;
pub use block_cache::{BLOCK_SIZE, DEFAULT_DECRYPTED_CACHE_SIZE, DecryptedRecordCache, OnDiskBlockCache, TieredCache};
pub use bootstrap::bootstrap_from_remote;
pub use coalesce::{CoalesceError, RemoteReadCoalescer};
pub use config::{RemoteRegistry, RemoteTargetConfig, ReplicationPolicy};
pub use counting::{CountingRemoteStore, RemoteStoreMetrics};
pub use failing::FailingRemoteStore;
pub use fs::LocalDirRemoteStore;
pub use latency::LatencyRemoteStore;
pub use mock::{MemoryRemoteStore, MockRemoteStore};
pub use s3::S3RemoteStore;
pub use sigv4::SigV4Signer;
pub use tiered_reader::TieredStorageReader;
pub use worker::RemoteReplicationWorker;

use std::io;
use std::sync::Arc;
use std::time::SystemTime;

/// A remote target configured for tiered reading with priority.
#[derive(Clone, Debug)]
pub struct RemoteReadTarget {
    pub name: String,
    pub store: Arc<dyn RemoteStore>,
    pub priority: u32,
}

impl RemoteReadTarget {
    pub fn new(name: impl Into<String>, store: Arc<dyn RemoteStore>, priority: u32) -> Self {
        Self {
            name: name.into(),
            store,
            priority,
        }
    }
}

impl From<(String, Arc<dyn RemoteStore>)> for RemoteReadTarget {
    fn from((name, store): (String, Arc<dyn RemoteStore>)) -> Self {
        Self {
            name,
            store,
            priority: 100,
        }
    }
}

impl From<(String, Arc<dyn RemoteStore>, u32)> for RemoteReadTarget {
    fn from((name, store, priority): (String, Arc<dyn RemoteStore>, u32)) -> Self {
        Self { name, store, priority }
    }
}

impl From<(&str, Arc<dyn RemoteStore>)> for RemoteReadTarget {
    fn from((name, store): (&str, Arc<dyn RemoteStore>)) -> Self {
        Self {
            name: name.to_string(),
            store,
            priority: 100,
        }
    }
}

impl From<(&str, Arc<dyn RemoteStore>, u32)> for RemoteReadTarget {
    fn from((name, store, priority): (&str, Arc<dyn RemoteStore>, u32)) -> Self {
        Self {
            name: name.to_string(),
            store,
            priority,
        }
    }
}

/// Metadata for an object stored in a remote S3-compatible backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteObject {
    /// Object key relative to bucket root (includes prefix if any).
    pub key: String,
    /// Total object length in bytes.
    pub size: u64,
    /// Entity tag (in standard S3 single-part uploads, this is the hex-encoded MD5 digest).
    pub etag: Option<String>,
    /// Last modification timestamp from remote store.
    pub last_modified: Option<SystemTime>,
}

impl RemoteObject {
    pub fn new(key: impl Into<String>, size: u64, etag: Option<String>, last_modified: Option<SystemTime>) -> Self {
        Self {
            key: key.into(),
            size,
            etag,
            last_modified,
        }
    }

    /// Returns the raw MD5 byte array parsed from the ETag (if valid 32-character hex).
    pub fn etag_md5(&self) -> Option<[u8; 16]> {
        let etag_str = self.etag.as_deref()?.trim_matches('"');
        if etag_str.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&etag_str[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }
}

/// Abstract streaming interface to a remote object store (e.g. AWS S3, MinIO, Cloudflare R2, B2).
///
/// Designed to stream data without materializing entire large objects (such as 1 GiB log
/// generations) in heap memory.
pub trait RemoteStore: std::fmt::Debug + Send + Sync {
    /// Lists all objects under the specified prefix.
    fn list_objects(&self, prefix: &str) -> io::Result<Vec<RemoteObject>>;

    /// Returns metadata for the given object key, or `Ok(None)` if it does not exist (404).
    fn head_object(&self, key: &str) -> io::Result<Option<RemoteObject>>;

    /// Uploads an object by streaming from `reader` up to `len` bytes.
    ///
    /// If `content_md5` is provided, sends the `Content-MD5` header so the S3 backend
    /// enforces byte-for-byte correctness and returns HTTP 400 BadDigest on mismatch.
    fn put_object(
        &self,
        key: &str,
        reader: &mut dyn io::Read,
        len: u64,
        content_md5: Option<&[u8; 16]>,
    ) -> io::Result<()>;

    /// Streams the complete contents of `key` into `writer`.
    /// Returns the total number of bytes written.
    fn get_object(&self, key: &str, writer: &mut dyn io::Write) -> io::Result<u64>;

    /// Streams a specific byte range `[offset, offset + len)` of `key` into `writer`.
    /// Returns the total number of bytes written.
    fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn io::Write) -> io::Result<u64>;

    /// Deletes an object from the remote store.
    fn delete_object(&self, key: &str) -> io::Result<()>;
}
