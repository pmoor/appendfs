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
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,
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
}

#[derive(Args, Debug)]
pub struct MountArgs {
    /// Directory path where appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Target mount point directory where the FUSE filesystem will be mounted
    pub mount_point: PathBuf,

    /// Run FUSE in foreground mode (do not daemonize)
    #[arg(short = 'f', long = "foreground", default_value_t = false)]
    pub foreground: bool,

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

    /// Additional raw FUSE options passed to libfuse (e.g. -o allow_other)
    #[arg(short = 'o', value_delimiter = ',')]
    pub fuse_options: Vec<String>,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,
}

impl MountArgs {
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
pub struct MountRoArgs {
    /// Directory path where the appendfs volume log and summary files are stored
    pub log_dir: PathBuf,

    /// Directory where the read-only filesystem will be mounted
    pub mount_point: PathBuf,

    /// Target transaction ID for point-in-time historical recovery
    #[arg(long = "tx-id")]
    pub tx_id: Option<u64>,

    /// Target timestamp for point-in-time recovery (unix epoch secs or ISO 8601 string, e.g. "2026-08-17T10:00:00Z")
    #[arg(long = "at-time")]
    pub at_time: Option<String>,

    /// Target log generation for historical recovery
    #[arg(long = "generation")]
    pub generation: Option<u64>,

    /// Run filesystem in foreground (default: false / daemonize)
    #[arg(short = 'f', long = "foreground")]
    pub foreground: bool,

    /// Additional raw FUSE options passed to libfuse (e.g. -o allow_other)
    #[arg(short = 'o', value_delimiter = ',')]
    pub fuse_options: Vec<String>,

    /// Path to key file (64 hex characters; prompts for a passphrase if omitted)
    #[arg(long = "key-file")]
    pub key_file: Option<PathBuf>,
}

impl MountRoArgs {
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
