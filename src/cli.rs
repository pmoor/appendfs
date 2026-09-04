use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

/// Default maximum log file size before rolling to next generation (1 GiB).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 1024 * 1024 * 1024;

/// Default maximum staged write data in memory before triggering a flush (128 MiB).
pub const DEFAULT_MAX_BUFFER_SIZE: usize = 128 * 1024 * 1024;

/// Default maximum size of a single data extent record (4 MiB).
///
/// A record is the unit of decryption: AEAD authenticates a payload as a whole, so reading
/// any byte of an encrypted record requires reading and decrypting all of it. Flushing
/// coalesces adjacent writes, so without a cap a large sequential write becomes one huge
/// record and every random read into it pays for the entire extent. Capping bounds that
/// amplification, at the cost of one record header (plus one AEAD tag when encrypting) per
/// chunk and one more entry in the file's extent map.
pub const DEFAULT_MAX_EXTENT_SIZE: usize = 4 * 1024 * 1024;

/// Default maximum staged mutation operations before triggering an automatic flush (10,000 ops).
pub const DEFAULT_MAX_BUFFER_OPS: usize = 10_000;

/// Default maximum number of frozen flush batches allowed to pile up before mutations are
/// refused with ENOSPC/EIO. Bounds worst-case unflushed memory at roughly this many times
/// `DEFAULT_MAX_BUFFER_SIZE` when the log is not draining.
pub const DEFAULT_MAX_FLUSH_QUEUE_DEPTH: usize = 4;

pub use crate::remote::block_cache::DEFAULT_DECRYPTED_CACHE_SIZE;

/// Default interval in bytes of committed log data before generating a new .summary snapshot file during log rolls (10 GiB).
pub const DEFAULT_SUMMARY_INTERVAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Default interval in rolled log generations before generating a new .summary snapshot file during log rolls (10 generations).
pub const DEFAULT_SUMMARY_INTERVAL_GENERATIONS: u64 = 10;

#[derive(Parser, Debug)]
#[command(
    name = "appendfs",
    author,
    version,
    about = "High-performance log-structured FUSE filesystem with append-only storage"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a fresh, empty appendfs volume
    Init(InitArgs),
    /// Mount an initialized appendfs volume as a FUSE filesystem
    Mount(MountArgs),
    /// Mount volume in read-only mode (with optional point-in-time time-travel recovery)
    #[command(name = "mount-ro")]
    MountRo(MountRoArgs),
    /// Alias for mount-ro (read-only mount)
    Mountro(MountRoArgs),
    /// Display volume statistics, inode breakdown, and log live extent ratios
    Stats(StatsArgs),
    /// Inspect and dump records from a single .log file
    Dump(DumpArgs),
    /// Check volume integrity and consistency (hierarchy, link counts, extents, manifests)
    Check(CheckArgs),
    /// Alias for check (filesystem consistency check)
    Fsck(CheckArgs),
    /// Show a volume's encryption state and identity (no key required)
    Key(KeyArgs),
    /// Manage remote S3-compatible replication targets
    Remote(RemoteSubcommandArgs),
}

#[derive(Args, Debug)]
pub struct RemoteSubcommandArgs {
    #[command(subcommand)]
    pub command: RemoteCommands,
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RemoteCommands {
    /// Add a new remote store target to remotes.toml
    Add(RemoteAddArgs),
    /// Remove a remote store target from remotes.toml
    Rm(RemoteRmArgs),
    /// List all configured remote store targets
    List(RemoteListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RemoteAddArgs {
    /// Volume log directory containing remotes.toml
    pub log_dir: PathBuf,

    /// Unique friendly name for this remote target (e.g. "aws", "b2", "r2")
    pub name: String,

    /// Local filesystem path for local directory or NFS NAS share remotes (e.g. "/mnt/nfs_backup/appendfs_logs")
    #[arg(long = "path")]
    pub path: Option<PathBuf>,

    /// S3 bucket name (required for S3 cloud remotes unless --path is specified)
    #[arg(long = "bucket")]
    pub bucket: Option<String>,

    /// S3 endpoint URL (e.g. "https://s3.us-west-002.backblazeb2.com")
    #[arg(long = "endpoint")]
    pub endpoint: Option<String>,

    /// S3 region (default: "us-east-1")
    #[arg(long = "region", default_value = "us-east-1")]
    pub region: String,

    /// Key prefix inside the bucket (e.g. "backups/vol1/")
    #[arg(long = "prefix", default_value = "")]
    pub prefix: String,

    /// Mark this remote as read-only (used for upstream volumes and zero-cost cloud forking)
    #[arg(long = "read-only", default_value_t = false)]
    pub read_only: bool,

    /// When forking from a read-only remote, replicate ancestor logs to this remote (default: false)
    #[arg(long = "replicate-ancestors", default_value_t = false)]
    pub replicate_ancestors: bool,

    /// Read priority (lower values are queried first during remote reads; default 10 for --path, 100 for S3)
    #[arg(long = "read-priority")]
    pub read_priority: Option<u32>,

    /// S3 Access Key ID (literal)
    #[arg(long = "access-key-id")]
    pub access_key_id: Option<String>,

    /// S3 Secret Access Key (literal)
    #[arg(long = "secret-access-key")]
    pub secret_access_key: Option<String>,

    /// Name of environment variable containing Access Key ID (e.g. "B2_KEY_ID")
    #[arg(long = "access-key-id-env")]
    pub access_key_id_env: Option<String>,

    /// Name of environment variable containing Secret Access Key (e.g. "B2_APPLICATION_KEY")
    #[arg(long = "secret-access-key-env")]
    pub secret_access_key_env: Option<String>,

    /// Path to file containing credentials (line 1: access key, line 2: secret key)
    #[arg(long = "credentials-file")]
    pub credentials_file: Option<PathBuf>,

    /// Force S3 path-style addressing (http://endpoint/bucket/key)
    #[arg(long = "path-style")]
    pub path_style: Option<bool>,
}

#[derive(Args, Debug, Clone)]
pub struct RemoteRmArgs {
    /// Volume log directory containing remotes.toml
    pub log_dir: PathBuf,

    /// Name of remote target to remove
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub struct RemoteListArgs {
    /// Volume log directory containing remotes.toml
    pub log_dir: PathBuf,
}

/// Arguments for `key`, which reports a volume's encryption state.
///
/// Whether a volume is encrypted is fixed at `init` and cannot be changed afterwards, so
/// there is nothing here to toggle - only to inspect.
#[derive(Args, Debug)]
pub struct KeyArgs {
    /// Volume log directory
    pub log_dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct DumpArgs {
    /// Path to the .log file to inspect
    pub file: PathBuf,

    /// Verbosity level (-v for record details, -vv for full hex/ASCII payload dumps)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Path to key file for decrypting records (64 hex characters)
    ///
    /// Without this (and without --passphrase) the raw on-disk bytes are shown, which is
    /// often what you want when inspecting structure.
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Prompt for the volume's passphrase in order to decrypt records
    ///
    /// Needed to read a passphrase-protected volume; combine with --key-file for a volume
    /// that requires both.
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Directory path where the appendfs volume log and summary files will be stored
    pub log_dir: PathBuf,

    /// Initial branch name (default: "main")
    #[arg(long = "branch", default_value = "main")]
    pub branch: String,

    /// Encrypt with ChaCha20-Poly1305, unlocked by a key file: 64 hex characters, e.g. from
    /// `openssl rand -hex 32`
    ///
    /// Add --passphrase to require both, so a stolen key file alone is useless.
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Encrypt with ChaCha20-Poly1305, unlocked by a passphrase prompted for interactively
    ///
    /// Combine with --key-file to require both.
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,

    /// Compress record payloads with zstd before storing them
    ///
    /// Records that do not compress by at least an eighth are stored as-is, so
    /// already-compressed data costs only the check. Fixed for the life of the volume.
    /// Note that compressed sizes reveal roughly how compressible each record was, which
    /// plain encryption does not.
    #[arg(long = "compress", default_value_t = false)]
    pub compress: bool,

    /// Bootstrap local volume by downloading latest checkpoint from this remote (e.g. "aws", "upstream")
    #[arg(long = "from-remote")]
    pub from_remote: Option<String>,

    /// S3 bucket name for bootstrap remote if configuring an S3 store on the fly
    #[arg(long = "remote-bucket")]
    pub remote_bucket: Option<String>,

    /// Local directory path for bootstrap remote if configuring a local/NFS share on the fly
    #[arg(long = "remote-path")]
    pub remote_path: Option<PathBuf>,

    /// S3 endpoint URL for bootstrap remote
    #[arg(long = "remote-endpoint")]
    pub remote_endpoint: Option<String>,

    /// S3 region for bootstrap remote (default: "us-east-1")
    #[arg(long = "remote-region", default_value = "us-east-1")]
    pub remote_region: String,

    /// Key prefix inside bucket for bootstrap remote
    #[arg(long = "remote-prefix", default_value = "")]
    pub remote_prefix: String,

    /// Mark bootstrap remote as read-only (for zero-cost CoW cloud forking)
    #[arg(long = "remote-read-only", default_value_t = false)]
    pub remote_read_only: bool,

    /// Access key ID for bootstrap remote credentials
    #[arg(long = "remote-access-key-id")]
    pub remote_access_key_id: Option<String>,

    /// Secret access key for bootstrap remote credentials
    #[arg(long = "remote-secret-access-key")]
    pub remote_secret_access_key: Option<String>,
}

impl InitArgs {
    /// Resolves the requested credential mode from the encryption flags.
    ///
    /// The two flags are orthogonal and between them name every mode, so there is no
    /// separate "encrypt" switch: naming a credential *is* the request to encrypt, and
    /// naming none leaves the volume plaintext. Whichever mode this picks is recorded in the
    /// volume and required at every mount thereafter; it cannot be changed later.
    pub fn key_source(&self) -> crate::crypto::KeySource {
        use crate::crypto::KeySource;
        match (self.key_file.is_some(), self.passphrase) {
            (true, true) => KeySource::KeyFileAndPassphrase,
            (true, false) => KeySource::KeyFile,
            (false, true) => KeySource::Passphrase,
            (false, false) => KeySource::None,
        }
    }

    /// The compression policy to record in the volume header. Also fixed at init.
    pub fn compression(&self) -> crate::compress::Compression {
        if self.compress {
            crate::compress::Compression::Zstd
        } else {
            crate::compress::Compression::None
        }
    }
}

/// Common arguments shared between read-write and read-only mounts.
#[derive(Args, Debug, Clone)]
pub struct MountCommonArgs {
    /// Directory path where appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Target mount point directory where the FUSE filesystem will be mounted
    pub mount_point: PathBuf,

    /// Run FUSE in foreground mode (do not daemonize)
    #[arg(short = 'f', long = "foreground", default_value_t = false)]
    pub foreground: bool,

    /// Additional raw FUSE options passed to libfuse (e.g. -o allow_other)
    #[arg(short = 'o', value_delimiter = ',')]
    pub fuse_options: Vec<String>,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Maximum size in bytes of in-memory decrypted record cache (default: 128 MiB)
    #[arg(long = "decrypted-cache-size", default_value_t = DEFAULT_DECRYPTED_CACHE_SIZE)]
    pub decrypted_cache_size: usize,
}

impl MountCommonArgs {
    /// Formats CLI arguments into libfuse-compatible C-style argv.
    pub fn to_fuse_args(&self) -> Vec<String> {
        let mut fuse_args = vec!["appendfs".to_string(), self.mount_point.to_str().unwrap().to_string()];
        if self.foreground {
            fuse_args.push("-f".to_string());
        }
        for opt in &self.fuse_options {
            fuse_args.push("-o".to_string());
            fuse_args.push(opt.clone());
        }
        fuse_args
    }
}

#[derive(Args, Debug)]
pub struct MountArgs {
    #[command(flatten)]
    pub common: MountCommonArgs,

    /// Interval in seconds for periodic background log flushing (default: 60, 0 to disable)
    #[arg(short = 'i', long = "flush-interval", default_value_t = 60)]
    pub flush_interval: u64,

    /// Threshold in bytes of dirty in-memory data before triggering an automatic flush (default: 128 MiB)
    #[arg(short = 't', long = "flush-threshold", default_value_t = DEFAULT_MAX_BUFFER_SIZE)]
    pub flush_threshold: usize,

    /// Threshold of staged dirty mutations (create/unlink/mkdir/etc) before triggering an automatic flush (default: 10000)
    #[arg(long = "flush-threshold-ops", default_value_t = DEFAULT_MAX_BUFFER_OPS)]
    pub flush_threshold_ops: usize,

    /// Maximum log file size in bytes before rolling to next generation (default: 1 GiB)
    #[arg(short = 's', long = "max-log-size", default_value_t = DEFAULT_MAX_LOG_SIZE)]
    pub max_log_size: u64,

    /// Maximum size in bytes of a single data extent record (default: 4 MiB)
    #[arg(long = "max-extent-size", default_value_t = DEFAULT_MAX_EXTENT_SIZE)]
    pub max_extent_size: usize,

    /// Disable autonomous background remote synchronization (default: sync is ON if remotes configured)
    #[arg(long = "no-sync", default_value_t = false)]
    pub no_sync: bool,

    /// Maximum age of active log file before rolling for cloud durability (e.g. "2h", "30m", default: "2h")
    #[arg(long = "max-log-age", default_value = "2h")]
    pub max_log_age: String,

    /// Interval in bytes of committed log data before generating a new .summary snapshot file during log rolls (default: 10 GiB, 0 to disable byte-based trigger)
    #[arg(long = "summary-interval-bytes", default_value_t = DEFAULT_SUMMARY_INTERVAL_BYTES)]
    pub summary_interval_bytes: u64,

    /// Interval in rolled log generations before generating a new .summary snapshot file during log rolls (default: 10, 0 to disable generation-based trigger)
    #[arg(long = "summary-interval-generations", default_value_t = DEFAULT_SUMMARY_INTERVAL_GENERATIONS)]
    pub summary_interval_generations: u64,
}

impl std::ops::Deref for MountArgs {
    type Target = MountCommonArgs;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl MountArgs {
    /// Formats CLI arguments into libfuse-compatible C-style argv.
    pub fn to_fuse_args(&self) -> Vec<String> {
        self.common.to_fuse_args()
    }
}

#[derive(Args, Debug)]
pub struct MountRoArgs {
    #[command(flatten)]
    pub common: MountCommonArgs,

    /// Target transaction ID for point-in-time historical recovery
    #[arg(long = "tx-id")]
    pub tx_id: Option<u64>,

    /// Target timestamp for point-in-time recovery (unix epoch secs or ISO 8601 string, e.g. "2026-08-17T10:00:00Z")
    #[arg(long = "at-time")]
    pub at_time: Option<String>,

    /// Target log generation for historical recovery
    #[arg(long = "generation")]
    pub generation: Option<u64>,
}

impl std::ops::Deref for MountRoArgs {
    type Target = MountCommonArgs;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl MountRoArgs {
    /// Formats CLI arguments into libfuse-compatible C-style argv.
    pub fn to_fuse_args(&self) -> Vec<String> {
        self.common.to_fuse_args()
    }
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    /// Directory path where the appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Directory path where the appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Deep verify physical extent payloads and BLAKE3 checksums in .log files on disk
    #[arg(long = "verify-data", default_value_t = true, action = clap::ArgAction::Set)]
    pub verify_data: bool,

    /// Verbosity level (-v for detailed integrity check report)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Verify remote objects on specified remote against summary manifest authenticated MD5s
    #[arg(long = "remote")]
    pub remote: Option<String>,
}

/// Helper parsing duration strings such as "2h", "30m", "120s".
pub fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    if let Some(rest) = s.strip_suffix('h') {
        let hours: u64 = rest.parse().map_err(|e| format!("{}", e))?;
        return Ok(std::time::Duration::from_secs(hours * 3600));
    }
    if let Some(rest) = s.strip_suffix('m') {
        let mins: u64 = rest.parse().map_err(|e| format!("{}", e))?;
        return Ok(std::time::Duration::from_secs(mins * 60));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let secs: u64 = rest.parse().map_err(|e| format!("{}", e))?;
        return Ok(std::time::Duration::from_secs(secs));
    }
    let secs: u64 = s.parse().map_err(|e| format!("{}", e))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Helper scanning `storage` for existing `.log` files to find the highest generation number.
pub fn find_latest_generation_in_storage(storage: &dyn crate::storage::Storage) -> u64 {
    let mut max_gen = 0u64;
    if let Ok(files) = storage.list_files() {
        for file in files {
            if file.ends_with(".log") {
                let stem = file.trim_end_matches(".log");
                if let Ok(gen_num) = stem.parse::<u64>()
                    && gen_num > max_gen
                {
                    max_gen = gen_num;
                }
            }
        }
    }
    max_gen
}

/// Helper scanning `log_dir` for existing `.log` files to find the highest generation number.
pub fn find_latest_generation(log_dir: impl AsRef<Path>) -> u64 {
    let storage = crate::storage::OsStorage::new(log_dir);
    find_latest_generation_in_storage(&storage)
}
