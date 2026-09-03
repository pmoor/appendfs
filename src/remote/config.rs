use crate::remote::RemoteStore;
use crate::remote::s3::S3RemoteStore;
use crate::remote::sigv4::SigV4Signer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const DEFAULT_REMOTES_FILENAME: &str = "remotes.toml";

/// Configuration for a single remote target (e.g. AWS S3, Cloudflare R2, MinIO, or a local/NFS filesystem directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTargetConfig {
    /// Local filesystem path for local directory or NFS NAS share remotes
    pub path: Option<PathBuf>,
    /// S3 bucket name (for S3-compatible cloud object stores)
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub replicate_ancestors: bool,
    /// Read priority (lower numerical values are queried first during remote reads; default 10 for path/NFS, 100 for S3)
    #[serde(default = "default_read_priority")]
    pub read_priority: u32,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub access_key_id_env: Option<String>,
    pub secret_access_key_env: Option<String>,
    pub credentials_file: Option<PathBuf>,
    pub force_path_style: Option<bool>,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_read_priority() -> u32 {
    100
}

impl RemoteTargetConfig {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            path: None,
            bucket: Some(bucket.into()),
            region: default_region(),
            endpoint: None,
            prefix: String::new(),
            read_only: false,
            replicate_ancestors: false,
            read_priority: default_read_priority(),
            access_key_id: None,
            secret_access_key: None,
            access_key_id_env: None,
            secret_access_key_env: None,
            credentials_file: None,
            force_path_style: None,
        }
    }

    pub fn new_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            bucket: None,
            region: default_region(),
            endpoint: None,
            prefix: String::new(),
            read_only: false,
            replicate_ancestors: false,
            read_priority: 10,
            access_key_id: None,
            secret_access_key: None,
            access_key_id_env: None,
            secret_access_key_env: None,
            credentials_file: None,
            force_path_style: None,
        }
    }

    pub fn with_read_priority(mut self, priority: u32) -> Self {
        self.read_priority = priority;
        self
    }

    /// Resolves AWS credentials according to precedence:
    /// 1. Custom env var names (`access_key_id_env`, `secret_access_key_env`)
    /// 2. Credentials file (`credentials_file`)
    /// 3. Direct literal configuration (`access_key_id`, `secret_access_key`)
    /// 4. Standard AWS env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
    pub fn resolve_credentials(&self) -> Option<(String, String)> {
        // 1. Custom env vars
        if let (Some(key_var), Some(secret_var)) = (&self.access_key_id_env, &self.secret_access_key_env)
            && let (Ok(k), Ok(s)) = (std::env::var(key_var), std::env::var(secret_var))
        {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        // 2. Credentials file
        if let Some(ref path) = self.credentials_file
            && let Ok(content) = fs::read_to_string(path)
        {
            let mut lines = content.lines();
            if let (Some(k), Some(s)) = (lines.next(), lines.next()) {
                return Some((k.trim().to_string(), s.trim().to_string()));
            }
        }

        // 3. Direct literal keys
        if let (Some(k), Some(s)) = (&self.access_key_id, &self.secret_access_key) {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        // 4. Default AWS environment variables
        if let (Ok(k), Ok(s)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        None
    }

    /// Builds an `Arc<dyn RemoteStore>` client for this target.
    pub fn build_store(&self) -> Arc<dyn RemoteStore> {
        if let Some(ref path) = self.path {
            return Arc::new(crate::remote::LocalDirRemoteStore::new(path));
        }
        if let Some(ref ep) = self.endpoint
            && ep.starts_with("file://")
        {
            let local_path = ep.trim_start_matches("file://");
            return Arc::new(crate::remote::LocalDirRemoteStore::new(local_path));
        }

        let bucket = self.bucket.as_deref().unwrap_or("appendfs-bucket");
        let creds = self.resolve_credentials();
        let signer = creds.map(|(k, s)| SigV4Signer::new(k, s, &self.region));

        let force_path = self.force_path_style.unwrap_or_else(|| {
            // Default to path style if custom endpoint or IP address
            if let Some(ref ep) = self.endpoint {
                ep.contains("localhost") || ep.contains("127.0.0.1") || ep.contains(':')
            } else {
                false
            }
        });

        Arc::new(S3RemoteStore::new(
            bucket,
            &self.region,
            self.endpoint.clone(),
            &self.prefix,
            signer,
            force_path,
        ))
    }
}

/// Global volume replication and tiered retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Number of remotes $k$ that must confirm an immutable log generation before local eviction is permitted.
    #[serde(default = "default_min_synced")]
    pub min_synced_remotes: usize,
    /// Keep sealed log files locally for at least this many days before eviction.
    #[serde(default = "default_retention_days")]
    pub local_retention_days: u64,
    /// Optional fine-grained local retention duration in seconds (overrides local_retention_days if set).
    #[serde(default)]
    pub local_retention_secs: Option<u64>,
    /// Maximum disk footprint in GB of the local volume before LRU pruning.
    #[serde(default = "default_cache_max_gb")]
    pub local_cache_max_gb: u64,
    /// Maximum time an active log can stay open before rolling (default: 7200s / 2 hours).
    #[serde(default = "default_max_log_age")]
    pub max_log_age_secs: u64,
    /// Frequency of intermediate active log part uploads (default: 1800s / 30 minutes).
    #[serde(default = "default_active_sync_interval")]
    pub active_sync_interval_secs: u64,
    /// Frequency of full remote consistency and healing audits (default: 14400s / 4 hours).
    #[serde(default = "default_audit_interval")]
    pub audit_interval_secs: u64,
}

fn default_min_synced() -> usize {
    1
}
fn default_retention_days() -> u64 {
    30
}
fn default_cache_max_gb() -> u64 {
    50
}
fn default_max_log_age() -> u64 {
    7200
}
fn default_active_sync_interval() -> u64 {
    1800
}
fn default_audit_interval() -> u64 {
    14400 // 4 hours
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            min_synced_remotes: default_min_synced(),
            local_retention_days: default_retention_days(),
            local_retention_secs: None,
            local_cache_max_gb: default_cache_max_gb(),
            max_log_age_secs: default_max_log_age(),
            active_sync_interval_secs: default_active_sync_interval(),
            audit_interval_secs: default_audit_interval(),
        }
    }
}

/// Registry managing all configured remotes and policies for a volume (`remotes.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoteRegistry {
    #[serde(default)]
    pub policy: ReplicationPolicy,
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteTargetConfig>,
    #[serde(skip)]
    pub store_overrides: BTreeMap<String, Arc<dyn RemoteStore>>,
}

impl PartialEq for RemoteRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy && self.remotes == other.remotes
    }
}
impl Eq for RemoteRegistry {}

impl RemoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from `<log_dir>/remotes.toml`, or returns default if absent.
    pub fn load_from_dir(log_dir: &Path) -> io::Result<Self> {
        let config_path = log_dir.join(DEFAULT_REMOTES_FILENAME);
        if !config_path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&config_path)?;
        toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Persists configuration to `<log_dir>/remotes.toml`.
    pub fn save_to_dir(&self, log_dir: &Path) -> io::Result<()> {
        let config_path = log_dir.join(DEFAULT_REMOTES_FILENAME);
        let content = toml::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(config_path, content)
    }

    pub fn add_remote(&mut self, name: impl Into<String>, config: RemoteTargetConfig) {
        self.remotes.insert(name.into(), config);
    }

    pub fn remove_remote(&mut self, name: &str) -> bool {
        self.remotes.remove(name).is_some()
    }

    pub fn get_remote(&self, name: &str) -> Option<&RemoteTargetConfig> {
        self.remotes.get(name)
    }

    /// Sets an in-memory RemoteStore override for testing.
    pub fn set_store_override(&mut self, name: impl Into<String>, store: Arc<dyn RemoteStore>) {
        self.store_overrides.insert(name.into(), store);
    }

    /// Returns all configured stores as `(name, Arc<dyn RemoteStore>, is_read_only, replicate_ancestors)`,
    /// ordered by `read_priority` ascending (lower numerical priority tried first), breaking ties by name.
    pub fn build_all_stores(&self) -> Vec<(String, Arc<dyn RemoteStore>, bool, bool)> {
        let mut entries: Vec<_> = self
            .remotes
            .iter()
            .map(|(name, cfg)| {
                let store = self
                    .store_overrides
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| cfg.build_store());
                (
                    cfg.read_priority,
                    name.clone(),
                    store,
                    cfg.read_only,
                    cfg.replicate_ancestors,
                )
            })
            .collect();
        entries.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        entries
            .into_iter()
            .map(|(_, name, store, ro, ra)| (name, store, ro, ra))
            .collect()
    }

    /// Returns configured stores sorted by `read_priority` (ascending), breaking ties by name.
    pub fn build_read_stores(&self) -> Vec<crate::remote::RemoteReadTarget> {
        let mut entries: Vec<_> = self
            .remotes
            .iter()
            .map(|(name, cfg)| {
                let store = self
                    .store_overrides
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| cfg.build_store());
                crate::remote::RemoteReadTarget::new(name.clone(), store, cfg.read_priority)
            })
            .collect();
        entries.sort_by(|a, b| (a.priority, &a.name).cmp(&(b.priority, &b.name)));
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_registry_toml_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = RemoteRegistry::new();
        registry.policy.min_synced_remotes = 2;
        registry.policy.local_retention_days = 60;

        let mut r1 = RemoteTargetConfig::new("my-aws-bucket");
        r1.region = "us-west-2".to_string();
        r1.prefix = "vol1".to_string();
        r1.access_key_id = Some("AKIA123".to_string());
        r1.secret_access_key = Some("SECRET123".to_string());
        registry.add_remote("aws", r1);

        let mut r2 = RemoteTargetConfig::new("my-b2-bucket");
        r2.endpoint = Some("https://s3.us-west-002.backblazeb2.com".to_string());
        r2.read_only = true;
        r2.read_priority = 200;
        r2.access_key_id_env = Some("B2_KEY_ID".to_string());
        r2.secret_access_key_env = Some("B2_APP_KEY".to_string());
        registry.add_remote("b2", r2);

        let r3 = RemoteTargetConfig::new_path("/mnt/nfs_backup/appendfs_logs");
        registry.add_remote("nas", r3);

        registry.save_to_dir(dir.path()).unwrap();
        let loaded = RemoteRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(registry, loaded);

        assert_eq!(loaded.remotes.len(), 3);
        assert_eq!(loaded.remotes["aws"].bucket.as_deref(), Some("my-aws-bucket"));
        assert!(!loaded.remotes["aws"].read_only);
        assert!(loaded.remotes["b2"].read_only);
        assert_eq!(loaded.remotes["nas"].read_priority, 10);
        assert_eq!(loaded.remotes["aws"].read_priority, 100);
        assert_eq!(loaded.remotes["b2"].read_priority, 200);
        assert_eq!(
            loaded.remotes["nas"].path.as_deref(),
            Some(Path::new("/mnt/nfs_backup/appendfs_logs"))
        );

        // Verify build_read_stores sorts by read_priority (10 -> 100 -> 200)
        let stores = loaded.build_read_stores();
        let names: Vec<_> = stores.into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["nas", "aws", "b2"]);
    }
}
