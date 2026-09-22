#![cfg_attr(not(test), deny(clippy::too_many_lines))]
use appendfs::cli::{
    Cli, Commands, DumpArgs, FsckArgs, InitArgs, MountArgs, MountRoArgs, RemoteAddArgs, RemoteCommands, RemoteListArgs,
    RemoteRmArgs, RemoteSubcommandArgs, StatsArgs,
};
use appendfs::clock::SystemClock;
use appendfs::crypto::{
    CipherSuite, KeySource, MasterKey, VolumeHeader, VolumeKey, generate_random_16, prompt_passphrase,
};
use appendfs::log::{LogWriter, SummaryReader};
use appendfs::storage::{OsStorage, Storage};
use appendfs::{VolumeStats, check_volume, dump_file, init_volume, recover_fs};

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

/// Finds the newest `{:06}.summary` in a volume directory.
///
/// The volume header lives in summary files, so this is the entry point for anything that
/// needs to identify a volume or verify a key.
fn latest_summary_file(storage: &dyn Storage) -> std::io::Result<Option<String>> {
    let mut latest: Option<((u64, u32), String)> = None;
    for file in storage.list_files()? {
        if let Some((generation, rev)) = appendfs::log::parse_summary_filename(&file)
            && latest.as_ref().is_none_or(|(gr, _)| (generation, rev) > *gr)
        {
            latest = Some(((generation, rev), file));
        }
    }
    Ok(latest.map(|(_, f)| f))
}

fn load_remote_registry(storage: &dyn Storage) -> appendfs::remote::RemoteRegistry {
    match appendfs::remote::RemoteRegistry::load_from_storage(storage) {
        Ok(reg) => reg,
        Err(e) => {
            eprintln!(
                "Error loading '{}': {}",
                appendfs::remote::config::DEFAULT_REMOTES_FILENAME,
                e
            );
            std::process::exit(1);
        }
    }
}

struct VolumeHeaderInfo {
    storage: Arc<dyn Storage>,
    header: VolumeHeader,
}

struct OpenVolumeStorage {
    storage: Arc<dyn Storage>,
    volume_key: Arc<VolumeKey>,
    volume_header: VolumeHeader,
}

struct OpenVolumeFS {
    fs: appendfs::InMemoryFS,
    storage: Arc<dyn Storage>,
    volume_key: Arc<VolumeKey>,
    volume_header: VolumeHeader,
}

/// Reads the volume header and validates that `log_dir` contains an initialized appendfs volume.
fn read_volume_header_info(log_dir: &Path) -> Result<VolumeHeaderInfo, String> {
    if !log_dir.exists() {
        return Err(format!(
            "Log directory '{}' does not exist.\nRun 'appendfs init {}' to create a new volume first.",
            log_dir.display(),
            log_dir.display()
        ));
    }

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_dir));
    let summary_file = latest_summary_file(storage.as_ref())
        .map_err(|e| format!("Error reading log directory '{}': {}", log_dir.display(), e))?;
    let summary_file = match summary_file {
        Some(sf) => sf,
        None => {
            return Err(format!(
                "No appendfs volume found in '{}' (directory contains no summary files).\nRun 'appendfs init {}' to create a new volume first.",
                log_dir.display(),
                log_dir.display()
            ));
        }
    };

    let header = SummaryReader::read_volume_header(storage.as_ref(), &summary_file).map_err(|e| e.to_string())?;

    Ok(VolumeHeaderInfo { storage, header })
}

/// Opens an appendfs volume's underlying storage and resolves/unlocks its volume key.
fn open_volume_storage(
    log_dir: &Path,
    key_file: Option<&Path>,
    passphrase_flag: bool,
) -> Result<OpenVolumeStorage, String> {
    let VolumeHeaderInfo {
        storage,
        header: volume_header,
    } = read_volume_header_info(log_dir)?;

    if volume_header.cipher == CipherSuite::None {
        if key_file.is_some() {
            return Err("Volume is not encrypted; --key-file does not apply to it".to_string());
        }
        if passphrase_flag {
            return Err("Volume is not encrypted; --passphrase does not apply to it".to_string());
        }
        return Ok(OpenVolumeStorage {
            storage,
            volume_key: Arc::new(VolumeKey::plaintext_with_volume_id(volume_header.volume_id)),
            volume_header,
        });
    }

    // Which credentials to collect comes from the volume, not from which flags happen to be
    // present. Guessing here would report a credential-type mismatch as a wrong key, which
    // sends the user hunting for the wrong problem.
    let source = volume_header.key_source;
    if key_file.is_some() && !source.needs_key_file() {
        return Err(format!(
            "Volume is unlocked by: {}. It does not use a key file, so --key-file does not apply.",
            source
        ));
    }
    if source.needs_key_file() && key_file.is_none() {
        return Err(format!(
            "Volume is unlocked by: {}. Pass --key-file to unlock it.",
            source
        ));
    }
    if passphrase_flag && !source.needs_passphrase() {
        return Err(format!(
            "Volume is unlocked by: {}. It does not use a passphrase, so --passphrase does not apply.",
            source
        ));
    }

    let passphrase = if source.needs_passphrase() {
        // Without a terminal this fails with a bare errno, which says nothing about *why* a
        // passphrase was wanted - the common case being a script mounting a two-factor
        // volume with only `--key-file`.
        // Wrapped so the passphrase is wiped when it goes out of scope rather than left in
        // freed heap memory for whatever allocates next.
        Some(Zeroizing::new(
            prompt_passphrase(&format!("Enter passphrase for volume '{}': ", log_dir.display())).map_err(|e| {
                format!(
                    "Volume is unlocked by: {}. Could not prompt for its passphrase: {}",
                    source, e
                )
            })?,
        ))
    } else {
        None
    };

    let master_key = match (key_file, passphrase.as_deref()) {
        (Some(kf), Some(pass)) => {
            MasterKey::from_file_and_passphrase(kf, pass, &volume_header.kdf_salt).map_err(|e| e.to_string())?
        }
        (Some(kf), None) => MasterKey::from_file(kf).map_err(|e| e.to_string())?,
        (None, Some(pass)) => MasterKey::from_passphrase(pass, &volume_header.kdf_salt)
            .map_err(|e| format!("Key derivation error: {}", e))?,
        (None, None) => {
            return Err(format!(
                "Volume is unlocked by: {}, but no credential was supplied.",
                source
            ));
        }
    };

    // The key check value is verified here, before recovery reads a single record. Without
    // it a wrong key would surface as an authentication failure mid-replay, which is
    // indistinguishable from bitrot and reads to the user like their volume is destroyed.
    let volume_key = volume_header.unlock(&master_key).map_err(|e| e.to_string())?;
    Ok(OpenVolumeStorage {
        storage,
        volume_key: Arc::new(volume_key),
        volume_header,
    })
}

/// Opens an appendfs volume and recovers an in-memory filesystem instance up to `target`.
fn open_volume_fs(
    log_dir: &Path,
    key_file: Option<&Path>,
    passphrase_flag: bool,
    target: appendfs::RecoveryTarget,
) -> Result<OpenVolumeFS, String> {
    let OpenVolumeStorage {
        storage,
        volume_key,
        volume_header,
    } = open_volume_storage(log_dir, key_file, passphrase_flag)?;
    let fs = recover_fs(storage.clone(), target, Arc::new(SystemClock), volume_key.clone())
        .map_err(|e| format!("Failed to recover volume from '{}': {}", log_dir.display(), e))?;
    Ok(OpenVolumeFS {
        fs,
        storage,
        volume_key,
        volume_header,
    })
}

/// Collects the credentials for a brand new volume, returning the key and the KDF salt to
/// record in its header.
///
/// Only `init` calls this, so passphrases are always confirmed and the salt is always freshly
/// minted; an existing volume's key is resolved by [`resolve_volume_key`] instead.
fn prompt_master_key(source: KeySource, key_file: Option<&Path>) -> Result<(MasterKey, [u8; 16]), String> {
    let passphrase = if source.needs_passphrase() {
        let ask =
            |prompt: &str| prompt_passphrase(prompt).map_err(|e| format!("Could not prompt for a passphrase: {}", e));
        let p1 = ask("Enter passphrase: ")?;
        let p2 = ask("Confirm passphrase: ")?;
        if p1 != p2 {
            return Err("Passphrases do not match".to_string());
        }
        if p1.is_empty() {
            return Err("Passphrase must not be empty".to_string());
        }
        Some(p1)
    } else {
        None
    };

    match (key_file, passphrase.as_deref()) {
        // A key file alone carries a full 256 bits, so there is nothing to stretch and the
        // salt stays zero and unused.
        (Some(kf), None) => Ok((MasterKey::from_file(kf).map_err(|e| e.to_string())?, [0u8; 16])),
        (Some(kf), Some(pass)) => {
            let salt = generate_random_16();
            let key = MasterKey::from_file_and_passphrase(kf, pass, &salt).map_err(|e| e.to_string())?;
            Ok((key, salt))
        }
        (None, Some(pass)) => {
            let salt = generate_random_16();
            let key = MasterKey::from_passphrase(pass, &salt).map_err(|e| format!("Key derivation error: {}", e))?;
            Ok((key, salt))
        }
        (None, None) => Err(format!(
            "Cannot initialize an encrypted volume with key source {}",
            source
        )),
    }
}

fn main() {
    let cli = Cli::parse();
    init_logging(&cli);

    match cli.command {
        Commands::Init(args) => cmd_init(args),
        Commands::Mount(args) => cmd_mount(args),
        Commands::MountRo(args) => cmd_mount_ro(args),
        Commands::Stats(args) => cmd_stats(args),
        Commands::Dump(args) => cmd_dump(args),
        Commands::Fsck(args) => cmd_fsck(args),
        Commands::Remote(subargs) => cmd_remote(subargs),
    }
}

/// Points logging at a file, and says where, since a backgrounded mount leaves no other
/// trace of it.
fn init_logging(cli: &Cli) {
    let Some(path) = cli.log_file.clone().or_else(|| default_volume_log(&cli.command)) else {
        return;
    };

    if let Some(path) = appendfs::logging::init(&path, &cli.log_level) {
        println!("Logging to '{}' (level: {})", path.display(), cli.log_level);
    }

    // First record of every run: what this invocation was, credentials redacted. Makes a log
    // self-identifying without having to correlate it against shell history.
    log::info!("{}", appendfs::logging::redacted_command_line());
}

/// Where a command logs by default: a per-run file in the volume it is operating on.
fn default_volume_log(command: &Commands) -> Option<PathBuf> {
    let (volume_dir, may_create) = match command {
        // `init` is the one command entitled to create the directory it was handed.
        Commands::Init(args) => (args.log_dir.clone(), true),
        Commands::Mount(args) => (args.log_dir.clone(), false),
        Commands::MountRo(args) => (args.log_dir.clone(), false),
        Commands::Stats(args) => (args.log_dir.clone(), false),
        Commands::Fsck(args) => (args.log_dir.clone(), false),
        // `dump` names a log file rather than a volume, so log beside it.
        Commands::Dump(args) => (args.file.parent()?.to_path_buf(), false),
        Commands::Remote(sub) => match sub.command {
            appendfs::cli::RemoteCommands::Add(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::Rm(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::List(ref a) => (a.log_dir.clone(), false),
        },
    };

    // A mistyped path should not scatter `logs/` directories across the filesystem.
    if !may_create && !volume_dir.exists() {
        return None;
    }
    Some(appendfs::logging::run_log_path(&volume_dir))
}

// TODO(too-many-lines): split the --from-remote bootstrap path out of this handler.
#[allow(clippy::too_many_lines)]
fn cmd_init(args: InitArgs) {
    if let Some(ref remote_name) = args.from_remote {
        println!(
            "Bootstrapping volume in '{}' from remote '{}'...",
            args.log_dir.display(),
            remote_name
        );
        std::fs::create_dir_all(&args.log_dir).unwrap_or_default();
        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        let registry = load_remote_registry(storage.as_ref());

        let remote_cfg = if let Some(cfg) = registry.get_remote(remote_name) {
            cfg.clone()
        } else if let Some(ref path) = args.remote_path {
            let mut cfg = appendfs::remote::RemoteTargetConfig::new_path(path);
            cfg.read_only = args.remote_read_only;
            cfg
        } else if let Some(ref bucket) = args.remote_bucket {
            let mut cfg = appendfs::remote::RemoteTargetConfig::new(bucket);
            cfg.endpoint = args.remote_endpoint.clone();
            cfg.region = args.remote_region.clone();
            cfg.prefix = args.remote_prefix.clone();
            cfg.read_only = args.remote_read_only;
            cfg.access_key_id = args.remote_access_key_id.clone();
            cfg.secret_access_key = args.remote_secret_access_key.clone();
            cfg
        } else {
            eprintln!(
                "Error: Remote '{}' not found in remotes.toml, and neither --remote-path nor --remote-bucket was specified.",
                remote_name
            );
            std::process::exit(1);
        };

        let store = remote_cfg.build_store();
        match appendfs::remote::bootstrap_from_remote(store.as_ref(), storage.as_ref(), remote_name, remote_cfg) {
            Ok(summary_file) => {
                println!("Successfully bootstrapped volume from remote '{}'!", remote_name);
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Latest Summary:  {}", summary_file);
                println!();
                println!(
                    "You can now mount this volume with 'appendfs mount {} <mountpoint>'",
                    args.log_dir.display()
                );
                return;
            }
            Err(e) => {
                eprintln!("Failed to bootstrap volume from remote: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!("Initializing appendfs volume at '{}'...", args.log_dir.display());

    let key_source = args.key_source();
    if key_source != KeySource::None {
        let (master_key, salt) = match prompt_master_key(key_source, args.key_file.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        let (volume_header, volume_key) =
            match VolumeHeader::new_encrypted(&master_key, salt, key_source, args.compression()) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("Failed to initialize volume encryption: {}", e);
                    std::process::exit(1);
                }
            };
        let volume_id = hex_string(&volume_header.volume_id);

        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        match init_volume(storage, &volume_key, volume_header) {
            Ok(summary_filename) => {
                println!("Initialized encrypted appendfs volume successfully!");
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Summary File:    {}", summary_filename);
                println!("  Cipher:          ChaCha20-Poly1305");
                println!("  Unlocked by:     {}", key_source);
                println!("  Compression:     {}", args.compression());
                println!("  Volume ID:       {}", volume_id);
                println!("  Root Inode:      1 (/)");
                println!("  Next Generation: 1 (000001.log)");
                println!();
                println!("Back up your credentials now: they are not stored in the volume");
                println!("and cannot be recovered. Losing them loses the volume, and this");
                println!("choice cannot be changed later.");
            }
            Err(e) => {
                eprintln!("Failed to initialize volume in '{}': {}", args.log_dir.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        // Compression is independent of encryption, so an unencrypted volume must
        // still honour --compress rather than silently dropping it.
        let mut volume_header = VolumeHeader::plaintext();
        volume_header.compression = args.compression();
        let volume_id = hex_string(&volume_header.volume_id);
        match init_volume(storage, &VolumeKey::plaintext(), volume_header) {
            Ok(summary_filename) => {
                println!("Initialized empty appendfs volume successfully!");
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Summary File:    {}", summary_filename);
                println!("  Cipher:          Plaintext (None)");
                println!("  Compression:     {}", args.compression());
                println!("  Volume ID:       {}", volume_id);
                println!("  Root Inode:      1 (/)");
                println!("  Next Generation: 1 (000001.log)");
            }
            Err(e) => {
                eprintln!("Failed to initialize volume in '{}': {}", args.log_dir.display(), e);
                std::process::exit(1);
            }
        }
    }
}

/// Starts the background replication worker, unless syncing is disabled or no remotes are
/// configured. The caller owns stopping it - see `cmd_mount`, where the ordering against
/// unmount matters.
fn start_replication_worker(
    args: &MountArgs,
    fs_instance: &Arc<appendfs::InMemoryFS>,
    registry_arc: &Arc<std::sync::RwLock<appendfs::remote::RemoteRegistry>>,
    log_dir: &std::path::Path,
) -> Option<appendfs::remote::RemoteReplicationWorker> {
    if args.no_sync || registry_arc.read().unwrap().remotes.is_empty() {
        return None;
    }
    println!(
        "Starting autonomous background replication worker for {} remote(s)...",
        registry_arc.read().unwrap().remotes.len()
    );
    Some(appendfs::remote::RemoteReplicationWorker::start(
        Arc::clone(fs_instance),
        Arc::clone(registry_arc),
        log_dir.to_path_buf(),
    ))
}

fn cmd_mount(args: MountArgs) {
    let log_dir = &args.log_dir;
    println!(
        "Recovering appendfs state from log directory '{}'...",
        log_dir.display()
    );

    let OpenVolumeFS {
        fs: mut fs_instance,
        storage,
        volume_key,
        volume_header,
    } = match open_volume_fs(
        log_dir,
        args.key_file.as_deref(),
        args.passphrase,
        appendfs::RecoveryTarget::Latest,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let next_gen = fs_instance.next_generation();

    let start_batch_id = fs_instance.last_batch_id.load(Ordering::SeqCst) + 1;

    // The volume header decides how writes are compressed; it was read back during
    // recovery, so a mount never has to be told separately.
    let compression = volume_header.compression;
    // The flusher checks `max_log_age` at the end of every cycle, so this one limit covers
    // both the CLI flag and the remote policy's `max_log_age_secs`; the tighter wins.
    let registry = load_remote_registry(storage.as_ref());
    let max_log_age = appendfs::clock::parse_duration(&args.max_log_age)
        .ok()
        .map(|cli| cli.min(std::time::Duration::from_secs(registry.policy.max_log_age_secs)));
    let writer = match LogWriter::create_lazy(storage.clone(), next_gen, args.max_log_size, start_batch_id, volume_key)
    {
        Ok(w) => Arc::new(w.with_compression(compression).with_max_log_age(max_log_age)),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    fs_instance.attach_log_writer(Arc::clone(&writer));
    fs_instance.max_buffer_size = args.flush_threshold;
    fs_instance.max_staged_ops = args.flush_threshold_ops;
    fs_instance.max_extent_size = args.max_extent_size;
    fs_instance.max_flush_queue_depth = args.max_flush_queue_depth;
    fs_instance.max_flush_queue_bytes = args.max_flush_queue_bytes;
    fs_instance.max_flush_queue_ops = args.max_flush_queue_ops;
    fs_instance.max_coalesce_batches = args.max_coalesce_batches;
    fs_instance.max_coalesce_bytes = args.max_coalesce_bytes;
    fs_instance.max_coalesce_ops = args.max_coalesce_ops;
    fs_instance.small_batch_max_bytes = args.small_batch_max_bytes;
    fs_instance.flush_interval.store(args.flush_interval, Ordering::SeqCst);
    fs_instance.set_summary_intervals(args.summary_interval_bytes, args.summary_interval_generations);
    fs_instance.track_atime = args.track_atime;

    let remote_stores = registry.build_read_stores();

    let cache_dir = log_dir.join(".cache");
    let block_cache = Arc::new(
        appendfs::remote::OnDiskBlockCache::new(
            &cache_dir,
            registry.policy.local_cache_max_gb * 1024 * 1024 * 1024,
            Arc::new(SystemClock),
        )
        .unwrap(),
    );

    let log_cache = Arc::new(appendfs::log::LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache),
        remote_stores,
        Some(Arc::clone(&fs_instance.manifest)),
    ));
    log_cache.set_decrypted_cache_size(args.decrypted_cache_size);
    fs_instance.log_cache = Some(log_cache);

    let fs_instance = Arc::new(fs_instance);

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_instance.set_remote_registry(Arc::clone(&registry_arc));

    let mut worker = start_replication_worker(&args, &fs_instance, &registry_arc, log_dir);

    println!(
        "Mounting appendfs at '{}' with log-dir '{}' (active generation: {}, flush-threshold: {} bytes, flush-ops: {}, flush-interval: {}s, max-log-size: {} bytes, max-extent-size: {} bytes, foreground: {})...",
        args.mount_point.display(),
        args.log_dir.display(),
        next_gen,
        args.flush_threshold,
        args.flush_threshold_ops,
        args.flush_interval,
        args.max_log_size,
        args.max_extent_size,
        args.foreground
    );

    let fuse_args = args.to_fuse_args();
    let result = appendfs::mount_arc(fuse_args, fs_instance);

    // By the time `mount_arc` returns, `fs.destroy()` has already run (from FUSE's `destroy`
    // callback, inside `run_fuse_ll`) and exported the final summary - so this final
    // replication cycle pushes the actual last state rather than racing it. Stopped
    // explicitly here, rather than left to drop at end of scope, so the ordering is
    // deliberate instead of an accident of `worker`'s lexical lifetime.
    if let Some(ref mut worker) = worker {
        worker.stop();
    }

    if let Err(err) = result {
        eprintln!("Failed to mount appendfs FUSE filesystem: {}", err);
        std::process::exit(1);
    }
}

fn cmd_mount_ro(args: MountRoArgs) {
    let log_dir = &args.log_dir;
    let target = if let Some(batch_id) = args.batch_id {
        appendfs::RecoveryTarget::BatchId(batch_id)
    } else if let Some(ref time_str) = args.at_time {
        match appendfs::parse_timestamp(time_str) {
            Ok(t) => appendfs::RecoveryTarget::Timestamp(t),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(target_gen) = args.generation {
        appendfs::RecoveryTarget::Generation(target_gen)
    } else {
        appendfs::RecoveryTarget::Latest
    };

    println!(
        "Recovering appendfs state (read-only, target: {:?}) from '{}'...",
        target,
        log_dir.display()
    );

    let OpenVolumeStorage {
        storage, volume_key, ..
    } = match open_volume_storage(log_dir, args.key_file.as_deref(), args.passphrase) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let registry = load_remote_registry(storage.as_ref());
    let remote_stores = registry.build_read_stores();

    if let Err(e) =
        appendfs::prepare_remote_recovery_for_target(storage.as_ref(), target, volume_key.clone(), &remote_stores)
    {
        log::warn!("Remote recovery preparation warning: {}", e);
    }

    let storage: Arc<dyn Storage> = Arc::new(appendfs::storage::ReadOnlyStorage::new(storage));

    let mut fs_instance = match recover_fs(storage.clone(), target, Arc::new(SystemClock), volume_key) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("Failed to recover volume from '{}': {}", log_dir.display(), e);
            std::process::exit(1);
        }
    };
    fs_instance.set_storage(storage.clone());
    fs_instance.set_read_only();

    let cache_dir = log_dir.join(".cache");
    let block_cache = Arc::new(
        appendfs::remote::OnDiskBlockCache::new(
            &cache_dir,
            registry.policy.local_cache_max_gb * 1024 * 1024 * 1024,
            Arc::new(SystemClock),
        )
        .unwrap(),
    );
    let log_cache = Arc::new(appendfs::log::LogFileCache::with_remote_support(
        storage,
        Some(block_cache),
        remote_stores,
        Some(Arc::clone(&fs_instance.manifest)),
    ));
    log_cache.set_decrypted_cache_size(args.decrypted_cache_size);
    fs_instance.log_cache = Some(log_cache);

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_instance.set_remote_registry(Arc::clone(&registry_arc));

    let effective_batch_id = fs_instance.last_batch_id.load(Ordering::SeqCst);
    let effective_gen = {
        let manifest = fs_instance.manifest.read().unwrap();
        manifest.logs.last().map(|l| l.generation).unwrap_or(1)
    };
    let effective_time_str = fs_instance
        .recovered_time()
        .map_or_else(|| "N/A".to_string(), appendfs::format_local_civil_time);

    println!(
        "Recovered appendfs state (read-only) -> Effective Version: generation {}, last batch_id: {}, timestamp: {}",
        effective_gen, effective_batch_id, effective_time_str
    );
    println!(
        "Mounting appendfs (read-only) at '{}' with log-dir '{}' (foreground: {})...",
        args.mount_point.display(),
        args.log_dir.display(),
        args.foreground
    );

    let fs_instance = Arc::new(fs_instance);
    let fuse_args = args.to_fuse_args();
    if let Err(err) = appendfs::mount_ro_arc(fuse_args, fs_instance) {
        eprintln!("Failed to mount read-only appendfs FUSE filesystem: {}", err);
        std::process::exit(1);
    }
}

fn cmd_stats(args: StatsArgs) {
    let VolumeHeaderInfo { header, .. } = match read_volume_header_info(&args.log_dir) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Printed before unlocking is attempted, so the credential a volume wants is visible
    // even when opening it fails - or before the passphrase prompt appears.
    print_volume_identity(&args.log_dir, &header);

    let OpenVolumeFS { fs, .. } = match open_volume_fs(
        &args.log_dir,
        args.key_file.as_deref(),
        args.passphrase,
        appendfs::RecoveryTarget::Latest,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_credential_help(&header);
            std::process::exit(1);
        }
    };

    let stats = VolumeStats::collect(&fs);
    print!("{}", stats.display_text());
}

fn cmd_dump(args: DumpArgs) {
    let file_path = &args.file;
    if !file_path.exists() {
        eprintln!("Error: File '{}' does not exist.", file_path.display());
        std::process::exit(1);
    }

    let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
    let filename = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    let storage = OsStorage::new(parent);

    // Asking for neither credential dumps the raw on-disk bytes, which is a valid way
    // to inspect structure. Asking for either resolves against the volume's summary -
    // not against the file being dumped, which is usually a .log and carries no
    // volume header - and fails loudly rather than quietly falling back to a
    // ciphertext dump the user did not ask for. A passphrase volume needs the
    // explicit flag, since prompting whenever a volume happens to be encrypted would
    // make scripted raw dumps hang waiting on a terminal.
    let volume_key = if args.key_file.is_some() || args.passphrase {
        match open_volume_storage(parent, args.key_file.as_deref(), args.passphrase) {
            Ok(res) => Some(res.volume_key),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    match dump_file(&storage, &filename, args.verbose, volume_key.as_deref()) {
        Ok(output) => print!("{}", output),
        Err(e) => {
            eprintln!("Error dumping file '{}': {}", file_path.display(), e);
            std::process::exit(1);
        }
    }
}

fn cmd_fsck(args: FsckArgs) {
    let log_dir = &args.log_dir;
    if let Some(ref remote_name) = args.remote {
        let OpenVolumeStorage {
            storage, volume_key, ..
        } = match open_volume_storage(log_dir, args.key_file.as_deref(), args.passphrase) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
        let registry = load_remote_registry(storage.as_ref());
        let remote_cfg = match registry.get_remote(remote_name) {
            Some(c) => c,
            None => {
                eprintln!("Error: Remote '{}' is not configured in remotes.toml.", remote_name);
                std::process::exit(1);
            }
        };
        let store = remote_cfg.build_store();
        let summary_file = match latest_summary_file(storage.as_ref()) {
            Ok(Some(f)) => f,
            _ => {
                eprintln!("Error: No summary files found in '{}'", log_dir.display());
                std::process::exit(1);
            }
        };
        let snapshot = match SummaryReader::open(storage.as_ref(), &summary_file, volume_key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read summary '{}': {}", summary_file, e);
                std::process::exit(1);
            }
        };
        let target_descr = if let Some(ref p) = remote_cfg.path {
            format!("path: '{}'", p.display())
        } else {
            format!("bucket: '{}'", remote_cfg.bucket.as_deref().unwrap_or(""))
        };
        println!(
            "Checking remote '{}' ({}) against summary manifest...",
            remote_name, target_descr
        );
        let report = appendfs::check_remote_integrity(store.as_ref(), remote_name, &snapshot.manifest);
        print!("{}", report.format_report(Some(log_dir), args.verbose > 0));
        if !report.is_clean() {
            std::process::exit(1);
        }
        return;
    }

    let OpenVolumeStorage {
        storage, volume_key, ..
    } = match open_volume_storage(log_dir, args.key_file.as_deref(), args.passphrase) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match check_volume(storage, args.verify_data, volume_key) {
        Ok(report) => {
            print!("{}", report.format_report(Some(log_dir), args.verbose > 0));
            if !report.is_clean() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to check volume integrity at '{}': {}", log_dir.display(), e);
            std::process::exit(1);
        }
    }
}

fn cmd_remote(subargs: RemoteSubcommandArgs) {
    match subargs.command {
        RemoteCommands::Add(add_args) => cmd_remote_add(add_args),
        RemoteCommands::Rm(rm_args) => cmd_remote_rm(rm_args),
        RemoteCommands::List(list_args) => cmd_remote_list(list_args),
    }
}

fn cmd_remote_add(add_args: RemoteAddArgs) {
    let storage = OsStorage::new(&add_args.log_dir);
    let mut registry = load_remote_registry(&storage);
    let mut cfg = if let Some(ref p) = add_args.path {
        appendfs::remote::RemoteTargetConfig::new_path(p)
    } else if let Some(ref b) = add_args.bucket {
        appendfs::remote::RemoteTargetConfig::new(b)
    } else {
        eprintln!("Error: Either --path or --bucket must be specified when adding a remote.");
        std::process::exit(1);
    };
    cfg.endpoint = add_args.endpoint;
    cfg.region = add_args.region;
    cfg.prefix = add_args.prefix;
    cfg.read_only = add_args.read_only;
    cfg.replicate_ancestors = add_args.replicate_ancestors;
    if let Some(prio) = add_args.read_priority {
        cfg.read_priority = prio;
    }
    cfg.access_key_id = add_args.access_key_id;
    cfg.secret_access_key = add_args.secret_access_key;
    cfg.access_key_id_env = add_args.access_key_id_env;
    cfg.secret_access_key_env = add_args.secret_access_key_env;
    cfg.credentials_file = add_args.credentials_file;
    cfg.force_path_style = add_args.path_style;
    cfg.storage_class = add_args.storage_class;
    if add_args.no_upload_partial_logs && add_args.upload_partial_logs.is_some() {
        eprintln!("Error: Cannot specify both --upload-partial-logs and --no-upload-partial-logs.");
        std::process::exit(1);
    }
    if add_args.no_upload_partial_logs {
        cfg.upload_partial_logs = false;
    } else if let Some(upl) = add_args.upload_partial_logs {
        cfg.upload_partial_logs = upl;
    }

    registry.add_remote(&add_args.name, cfg);
    if let Err(e) = registry.save_to_storage(&storage) {
        eprintln!("Failed to save remotes.toml in '{}': {}", add_args.log_dir.display(), e);
        std::process::exit(1);
    }
    println!(
        "Successfully added remote '{}' in '{}'",
        add_args.name,
        add_args.log_dir.display()
    );
}

fn cmd_remote_rm(rm_args: RemoteRmArgs) {
    let storage = OsStorage::new(&rm_args.log_dir);
    let mut registry = load_remote_registry(&storage);
    if registry.remove_remote(&rm_args.name) {
        if let Err(e) = registry.save_to_storage(&storage) {
            eprintln!("Failed to save remotes.toml in '{}': {}", rm_args.log_dir.display(), e);
            std::process::exit(1);
        }
        println!("Removed remote '{}' from '{}'", rm_args.name, rm_args.log_dir.display());
    } else {
        eprintln!("Error: Remote '{}' was not configured.", rm_args.name);
        std::process::exit(1);
    }
}

fn cmd_remote_list(list_args: RemoteListArgs) {
    let storage = OsStorage::new(&list_args.log_dir);
    let registry = load_remote_registry(&storage);
    if registry.remotes.is_empty() {
        println!("No remotes configured in '{}'.", list_args.log_dir.display());
    } else {
        println!("Configured remotes in '{}':", list_args.log_dir.display());
        let mut sorted_remotes: Vec<_> = registry.remotes.iter().collect();
        sorted_remotes.sort_by_key(|(name, cfg)| (cfg.read_priority, (*name).clone()));
        for (name, cfg) in sorted_remotes {
            if let Some(ref p) = cfg.path {
                println!(
                    "  - {}: type='local/nfs', path='{}', priority={}, mode='{}', partial_logs={}",
                    name,
                    p.display(),
                    cfg.read_priority,
                    if cfg.read_only { "ReadOnly (Fork)" } else { "ReadWrite" },
                    if cfg.upload_partial_logs { "Enabled" } else { "Disabled" },
                );
            } else {
                let sc_str = cfg
                    .storage_class
                    .as_deref()
                    .map(|sc| format!(", storage_class='{}'", sc))
                    .unwrap_or_default();
                println!(
                    "  - {}: type='s3', bucket='{}', priority={}, region='{}', mode='{}', partial_logs={}, endpoint={:?}, prefix='{}'{}",
                    name,
                    cfg.bucket.as_deref().unwrap_or(""),
                    cfg.read_priority,
                    cfg.region,
                    if cfg.read_only { "ReadOnly (Fork)" } else { "ReadWrite" },
                    if cfg.upload_partial_logs { "Enabled" } else { "Disabled" },
                    cfg.endpoint,
                    cfg.prefix,
                    sc_str
                );
            }
        }
    }
}

/// Prints a volume's identity: what it is and what unlocks it. Needs no credentials,
/// because the header sits in plaintext ahead of the encrypted summary body.
fn print_volume_identity(log_dir: &Path, header: &VolumeHeader) {
    println!("=== Volume ===");
    println!("Volume:        {}", log_dir.display());
    println!("Cipher Suite:  {}", header.cipher);
    println!("Compression:   {}", header.compression);
    println!("Volume ID:     {}", hex_string(&header.volume_id));
    if header.cipher.is_encrypted() {
        println!("Unlocked by:   {}", header.key_source);
    }
    println!();
}

/// Explains the credential situation. Only printed when the volume could not be opened,
/// which is exactly when someone needs to know what to supply.
fn print_credential_help(header: &VolumeHeader) {
    if header.cipher.is_encrypted() {
        eprintln!();
        eprintln!("Credentials are supplied per invocation and are not stored here.");
        eprintln!("Back them up: losing them loses the volume, and changing them means");
        eprintln!("re-encrypting into a fresh volume.");
        if header.compression.is_enabled() {
            eprintln!();
            eprintln!("Compressed records reveal roughly how compressible their contents");
            eprintln!("were, which encryption alone does not. Sizes leak; contents do not.");
        }
    } else {
        eprintln!();
        eprintln!("Volume is unencrypted, and cannot be encrypted in place.");
        eprintln!("Encryption is chosen at init time - 'appendfs init --key-file <file>'");
        eprintln!("and/or '--passphrase' - and fixed for the life of the volume.");
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
