use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

/// Default maximum log file size before rolling to next generation (2 GiB).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 2 * 1024 * 1024 * 1024;

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

/// Default maximum staged mutation operations before triggering an automatic flush (16,384 ops / 2^14).
pub const DEFAULT_MAX_BUFFER_OPS: usize = 1 << 14;

/// Default maximum number of frozen flush batches allowed to queue up in memory before
/// auto-freezing is bounded (16 batches).
pub const DEFAULT_MAX_FLUSH_QUEUE_DEPTH: usize = 16;

/// Default maximum total bytes across all frozen flush batches queued in memory (256 MiB).
pub const DEFAULT_MAX_FLUSH_QUEUE_BYTES: usize = 2 * DEFAULT_MAX_BUFFER_SIZE;

/// Default maximum total mutating operations across all frozen flush batches queued in memory (32,768 ops).
pub const DEFAULT_MAX_FLUSH_QUEUE_OPS: usize = 2 * DEFAULT_MAX_BUFFER_OPS;

/// Default maximum number of small flush batches to coalesce into a single on-disk flush cycle (16 batches).
pub const DEFAULT_MAX_COALESCE_BATCHES: usize = 16;

/// Default maximum cumulative staged data bytes across coalesced flush batches before forcing a disk flush (128 KiB).
pub const DEFAULT_MAX_COALESCE_BYTES: usize = 128 * 1024;

/// Default maximum cumulative mutation operations across coalesced flush batches before forcing a disk flush (128 ops).
pub const DEFAULT_MAX_COALESCE_OPS: usize = 128;

/// Default maximum data bytes for an individual flush batch to be eligible for coalescing (32 KiB).
/// Batches larger than this are flushed independently to avoid delaying bulk writes.
pub const DEFAULT_SMALL_BATCH_MAX_BYTES: usize = 32 * 1024;

pub use crate::remote::block_cache::DEFAULT_DECRYPTED_CACHE_SIZE;

/// Default maximum size of the on-disk block cache (16 GiB).
pub const DEFAULT_DISK_CACHE_SIZE: u64 = 16 * 1024 * 1024 * 1024;

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

    /// Log verbosity: error, warn, info, debug, or trace (RUST_LOG overrides this)
    #[arg(long = "log-level", global = true, default_value = crate::logging::DEFAULT_LOG_LEVEL)]
    pub log_level: String,

    /// Where to write diagnostic logs. Mount commands default to
    /// <log-dir>/logs/appendfs-<date>-<time>-<pid>.log and other commands to nothing;
    /// `/dev/stderr` follows along on a terminal and `/dev/null` discards.
    #[arg(long = "log-file", global = true)]
    pub log_file: Option<PathBuf>,
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
    /// Display volume statistics, inode breakdown, and log live extent ratios
    Stats(StatsArgs),
    /// Inspect and dump records from a single .log file
    Dump(DumpArgs),
    /// Check volume integrity and consistency (hierarchy, link counts, extents, manifests)
    Fsck(FsckArgs),
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

    /// Upload incremental active log parts to this remote before generation seals (default: true)
    #[arg(
        long = "upload-partial-logs",
        num_args = 0..=1,
        default_missing_value = "true",
        conflicts_with = "no_upload_partial_logs"
    )]
    pub upload_partial_logs: Option<bool>,

    /// Disable uploading incremental active log parts to this remote (useful for write-only/append-only S3 targets)
    #[arg(long = "no-upload-partial-logs", conflicts_with = "upload_partial_logs")]
    pub no_upload_partial_logs: bool,

    /// S3 storage class for uploaded objects (e.g. "INTELLIGENT_TIERING", "STANDARD_IA", "GLACIER_IR")
    #[arg(long = "storage-class")]
    pub storage_class: Option<String>,
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

    /// Compress record payloads with zstd before storing them (default: true)
    ///
    /// Records that do not compress by at least an eighth are stored as-is, so
    /// already-compressed data costs only the check. Fixed for the life of the volume.
    /// Note that compressed sizes reveal roughly how compressible each record was, which
    /// plain encryption does not.
    #[arg(
        long = "compress",
        num_args = 0..=1,
        default_missing_value = "true",
        conflicts_with = "no_compress"
    )]
    pub compress: Option<bool>,

    /// Disable zstd compression for record payloads
    #[arg(long = "no-compress", conflicts_with = "compress")]
    pub no_compress: bool,

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
        if self.no_compress || self.compress == Some(false) {
            crate::compress::Compression::None
        } else {
            crate::compress::Compression::Zstd
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

    /// Prompt for the volume's passphrase in order to unlock volume
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,

    /// Maximum size in bytes of in-memory decrypted record cache (default: 128 MiB)
    #[arg(long = "decrypted-cache-size", default_value_t = DEFAULT_DECRYPTED_CACHE_SIZE)]
    pub decrypted_cache_size: usize,

    /// Directory for the on-disk block cache of sealed log blocks (default: `.cache` inside the log directory)
    #[arg(long = "disk-cache-dir")]
    pub disk_cache_dir: Option<PathBuf>,

    /// Maximum size in bytes of the on-disk block cache before the least recently used blocks are pruned (default: 16 GiB, 0 to disable)
    #[arg(long = "disk-cache-size", default_value_t = DEFAULT_DISK_CACHE_SIZE)]
    pub disk_cache_size: u64,

    /// Also cache blocks read from sealed logs still present in the log directory, so they stay readable after the local log is pruned (default: false, only blocks fetched from remotes are cached)
    #[arg(long = "disk-cache-local-reads", default_value_t = false)]
    pub disk_cache_local_reads: bool,
}

impl MountCommonArgs {
    /// Formats CLI arguments into libfuse-compatible C-style argv. `--foreground` is not
    /// among them: backgrounding is `appendfs::daemon`'s job, not libfuse's.
    pub fn to_fuse_args(&self) -> Vec<String> {
        let mut fuse_args = vec!["appendfs".to_string(), self.mount_point.to_str().unwrap().to_string()];
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

    /// Threshold of staged dirty mutations (create/unlink/mkdir/etc) before triggering an automatic flush (default: 16384)
    #[arg(long = "flush-threshold-ops", default_value_t = DEFAULT_MAX_BUFFER_OPS)]
    pub flush_threshold_ops: usize,

    /// Log file size in bytes at which to roll to the next generation; a soft limit, as the flush that crosses it is written in full first, overshooting by up to the flush threshold (or about twice that under a slow flush) (default: 2 GiB)
    #[arg(short = 's', long = "max-log-size", default_value_t = DEFAULT_MAX_LOG_SIZE)]
    pub max_log_size: u64,

    /// Maximum size in bytes of a single data extent record (default: 4 MiB)
    #[arg(long = "max-extent-size", default_value_t = DEFAULT_MAX_EXTENT_SIZE)]
    pub max_extent_size: usize,

    /// Disable autonomous background remote synchronization (default: sync is ON if remotes configured)
    #[arg(long = "no-sync", default_value_t = false)]
    pub no_sync: bool,

    /// Maximum age of active log file before rolling for cloud durability (e.g. "24h", "2h", default: "24h")
    #[arg(long = "max-log-age", default_value = "24h")]
    pub max_log_age: String,

    /// Interval in bytes of committed log data before generating a new .summary snapshot file during log rolls (default: 10 GiB, 0 to disable byte-based trigger)
    #[arg(long = "summary-interval-bytes", default_value_t = DEFAULT_SUMMARY_INTERVAL_BYTES)]
    pub summary_interval_bytes: u64,

    /// Interval in rolled log generations before generating a new .summary snapshot file during log rolls (default: 10, 0 to disable generation-based trigger)
    #[arg(long = "summary-interval-generations", default_value_t = DEFAULT_SUMMARY_INTERVAL_GENERATIONS)]
    pub summary_interval_generations: u64,

    /// Maximum number of frozen flush batches queued in memory before freezing is blocked (default: 16)
    #[arg(long = "max-flush-queue-depth", default_value_t = DEFAULT_MAX_FLUSH_QUEUE_DEPTH)]
    pub max_flush_queue_depth: usize,

    /// Maximum total bytes across all frozen flush batches queued in memory before freezing is blocked (default: 256 MiB)
    #[arg(long = "max-flush-queue-bytes", default_value_t = DEFAULT_MAX_FLUSH_QUEUE_BYTES)]
    pub max_flush_queue_bytes: usize,

    /// Maximum total mutating operations across all frozen flush batches queued in memory (default: 32768)
    #[arg(long = "max-flush-queue-ops", default_value_t = DEFAULT_MAX_FLUSH_QUEUE_OPS)]
    pub max_flush_queue_ops: usize,

    /// Track access time (atime) on reads (default: false, like noatime)
    #[arg(long = "track-atime", default_value_t = false)]
    pub track_atime: bool,

    /// Maximum number of small flush batches to coalesce into a single on-disk flush cycle (default: 16)
    #[arg(long = "max-coalesce-batches", default_value_t = DEFAULT_MAX_COALESCE_BATCHES)]
    pub max_coalesce_batches: usize,

    /// Maximum cumulative staged data bytes across coalesced flush batches before forcing a disk flush (default: 128 KiB)
    #[arg(long = "max-coalesce-bytes", default_value_t = DEFAULT_MAX_COALESCE_BYTES)]
    pub max_coalesce_bytes: usize,

    /// Maximum cumulative mutation operations across coalesced flush batches before forcing a disk flush (default: 128)
    #[arg(long = "max-coalesce-ops", default_value_t = DEFAULT_MAX_COALESCE_OPS)]
    pub max_coalesce_ops: usize,

    /// Maximum data bytes for an individual flush batch to be eligible for coalescing (default: 32 KiB)
    #[arg(long = "small-batch-max-bytes", default_value_t = DEFAULT_SMALL_BATCH_MAX_BYTES)]
    pub small_batch_max_bytes: usize,
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

    /// Target flush batch ID for point-in-time historical recovery
    #[arg(long = "batch-id")]
    pub batch_id: Option<u64>,

    /// Target timestamp for point-in-time recovery (unix epoch secs or ISO 8601 string, e.g. "2026-08-17T10:00:00Z")
    #[arg(long = "at-time")]
    pub at_time: Option<String>,

    /// Target log generation for historical recovery
    #[arg(long = "generation")]
    pub generation: Option<u32>,
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

    /// Prompt for the volume's passphrase in order to unlock volume
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,
}

#[derive(Args, Debug)]
pub struct FsckArgs {
    /// Directory path where the appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Deep verify physical extent payloads and BLAKE3 checksums in .log files on disk (default: false)
    #[arg(long = "verify-data", default_value_t = false)]
    pub verify_data: bool,

    /// Verbosity level (-v for detailed integrity check report)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Prompt for the volume's passphrase in order to unlock volume
    #[arg(long = "passphrase", default_value_t = false)]
    pub passphrase: bool,

    /// Verify remote objects on specified remote against summary manifest authenticated MD5s
    #[arg(long = "remote")]
    pub remote: Option<String>,
}

/// Helper scanning `storage` for existing `.log` files to find the highest generation number.
pub fn find_latest_generation_in_storage(storage: &dyn crate::storage::Storage) -> u32 {
    let mut max_gen = 0u32;
    if let Ok(files) = storage.list_files() {
        for file in files {
            if let Some((gen_num, _rev)) = crate::log::parse_log_filename(&file)
                && gen_num > max_gen
            {
                max_gen = gen_num;
            }
        }
    }
    max_gen
}

/// Helper scanning `log_dir` for existing `.log` files to find the highest generation number.
pub fn find_latest_generation(log_dir: impl AsRef<Path>) -> u32 {
    let storage = crate::storage::OsStorage::new(log_dir);
    find_latest_generation_in_storage(&storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_default_constants() {
        assert_eq!(DEFAULT_MAX_LOG_SIZE, 2 * 1024 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_BUFFER_OPS, 16_384);
        assert_eq!(DEFAULT_MAX_FLUSH_QUEUE_OPS, 32_768);
    }

    #[test]
    fn test_mount_args_defaults() {
        let cli = Cli::parse_from(["appendfs", "mount", "/path/to/log", "/path/to/mnt"]);
        let Commands::Mount(args) = cli.command else {
            panic!("expected Mount command");
        };
        assert_eq!(args.max_log_size, 2 * 1024 * 1024 * 1024);
        assert_eq!(args.flush_threshold_ops, 16_384);
        assert_eq!(args.max_flush_queue_ops, 32_768);
        assert_eq!(args.max_log_age, "24h");
        assert!(!args.track_atime);
    }

    #[test]
    fn test_init_args_compression_default_on() {
        let cli_default = Cli::parse_from(["appendfs", "init", "/path/to/log"]);
        let Commands::Init(args_default) = cli_default.command else {
            panic!("expected Init command");
        };
        assert_eq!(args_default.compression(), crate::compress::Compression::Zstd);

        let cli_no_comp = Cli::parse_from(["appendfs", "init", "--no-compress", "/path/to/log"]);
        let Commands::Init(args_no_comp) = cli_no_comp.command else {
            panic!("expected Init command");
        };
        assert_eq!(args_no_comp.compression(), crate::compress::Compression::None);

        let cli_comp_false = Cli::parse_from(["appendfs", "init", "--compress=false", "/path/to/log"]);
        let Commands::Init(args_comp_false) = cli_comp_false.command else {
            panic!("expected Init command");
        };
        assert_eq!(args_comp_false.compression(), crate::compress::Compression::None);
    }

    #[test]
    fn test_fsck_args_verify_data_default_off() {
        let cli_default = Cli::parse_from(["appendfs", "fsck", "/path/to/log"]);
        let Commands::Fsck(args_default) = cli_default.command else {
            panic!("expected Fsck command");
        };
        assert!(!args_default.verify_data);

        let cli_verified = Cli::parse_from(["appendfs", "fsck", "--verify-data", "/path/to/log"]);
        let Commands::Fsck(args_verified) = cli_verified.command else {
            panic!("expected Fsck command");
        };
        assert!(args_verified.verify_data);
    }
}
