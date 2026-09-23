//! Where diagnostic logs go.
//!
//! A backgrounded mount has no stderr: libfuse's `fuse_daemonize` redirects stdout and
//! stderr to `/dev/null`, so every `log::` record from a normal (non-`--foreground`) mount
//! was being discarded. Long-running mounts are exactly the ones worth having logs for, so
//! they write to a file inside the volume's own log directory instead.
//!
//! Each run gets its own file, named for the time it started and its pid. There is no
//! rotation to reason about, two mounts of the same volume cannot interleave their records,
//! and a crashed run's log stays exactly as it was left rather than being overwritten by the
//! restart. For a backgrounded mount that is the daemon's pid, not the parent's: the file is
//! only opened once `fuse_daemonize` has forked, and records logged before then are held in
//! memory until it is.
//!
//! A file is the only destination. Anything a user is meant to read is printed directly, so
//! logging has no reason to compete for the terminal - and `--log-file` reaches the terminal
//! anyway via `/dev/stderr`, or discards via `/dev/null`, which is why there is no separate
//! flag for either.
//!
//! Every run opens with its own command line, so a log identifies what it was for without
//! being cross-referenced against anything. Credential values are redacted first: several
//! flags take a secret key as an argument, and a log file is not the place for one.
//!
//! The files live in a `logs/` subdirectory rather than beside the `.log` and `.summary`
//! generation files. `Storage::list_files` is non-recursive and returns only files, so
//! nothing in a subdirectory can be mistaken for a volume file by recovery, replication, or
//! pruning - the same reasoning that puts the block cache in `.cache/`.
//!
//! Logging never takes the filesystem down: if the file cannot be opened or written, the
//! mount continues and the records are dropped.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

/// Subdirectory of the volume log directory holding diagnostic logs.
pub const LOG_SUBDIR: &str = "logs";

/// Default filter applied when neither `--log-level` nor `RUST_LOG` says otherwise.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// The directory a volume's diagnostic logs are written to.
pub fn log_directory(log_dir: &Path) -> PathBuf {
    log_dir.join(LOG_SUBDIR)
}

/// Names one run's log file: `appendfs-<YYYYMMDD>-<HHMMSS>-<pid>.log`.
///
/// The timestamp sorts chronologically and the pid disambiguates two mounts started within
/// the same second, so a name is never reused and no run can clobber another's log.
pub fn log_file_name(started: SystemTime, pid: u32) -> String {
    format!("appendfs-{}-{}.log", crate::clock::format_utc_compact(started), pid)
}

/// The log file for a run starting now.
pub fn log_file_path(log_dir: &Path, started: SystemTime, pid: u32) -> PathBuf {
    log_directory(log_dir).join(log_file_name(started, pid))
}

/// A log file that holds records until it is opened, and drops them rather than failing.
enum LogSink {
    /// No file yet. Records wait here, so nothing logged before the file is chosen is lost.
    Pending(Vec<u8>),
    Open(File),
    /// Opening or writing failed; records are dropped rather than propagated.
    Failed,
}

impl LogSink {
    /// Opens `path`, writing out whatever was recorded while pending.
    fn open(&mut self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // `append` rather than truncate: an explicit `--log-file` may name an existing file
        // - or a character device like `/dev/stderr` - and truncating would be wrong for both.
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        if let LogSink::Pending(pending) = self {
            file.write_all(pending)?;
        }
        *self = LogSink::Open(file);
        Ok(())
    }
}

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A logging failure must not surface as a filesystem error, so this reports success
        // either way and simply stops writing.
        match self {
            LogSink::Pending(pending) => pending.extend_from_slice(buf),
            LogSink::Open(file) => {
                if file.write_all(buf).is_err() {
                    *self = LogSink::Failed;
                }
            }
            LogSink::Failed => {}
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let LogSink::Open(file) = self {
            let _ = file.flush();
        }
        Ok(())
    }
}

/// The sink behind the installed logger. Global because `open_deferred` has to reach it
/// from the FUSE `init` callback, long after `main` handed the logger its target.
static SINK: Mutex<LogSink> = Mutex::new(LogSink::Pending(Vec::new()));

/// The run log `init_deferred` set aside for `open_deferred`: its directory and start time.
static DEFERRED: Mutex<Option<(PathBuf, SystemTime)>> = Mutex::new(None);

fn sink() -> MutexGuard<'static, LogSink> {
    SINK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The logger's target, writing through to `SINK`.
struct GlobalSink;

impl Write for GlobalSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        sink().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        sink().flush()
    }
}

fn install(level: &str) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .target(env_logger::Target::Pipe(Box::new(GlobalSink)))
        .init();
}

/// Points the sink at `path`, or reports why it could not - in which case records are
/// discarded and the command proceeds regardless, since a volume on read-only media is still
/// worth mounting.
fn open(path: &Path) {
    let mut sink = sink();
    if let Err(e) = sink.open(path) {
        *sink = LogSink::Failed;
        eprintln!(
            "Warning: could not open log file {}: {}; logging disabled",
            path.display(),
            e
        );
    }
}

/// Starts logging to `path`.
pub fn init(path: &Path, level: &str) {
    install(level);
    open(path);
}

/// Starts logging for a mount about to daemonize, into a run log under `log_dir` that is
/// only opened by `open_deferred`. Records until then are held in memory.
///
/// A run log is named for its process, and a backgrounded mount's process is the daemon
/// `fuse_daemonize` forks - which does not exist yet while recovery is already logging.
pub fn init_deferred(log_dir: &Path, level: &str) {
    *DEFERRED.lock().unwrap_or_else(PoisonError::into_inner) = Some((canonical_dir(log_dir), SystemTime::now()));
    install(level);
}

/// Opens the run log `init_deferred` set aside, named for the calling process. No-op
/// otherwise, including on every call after the first.
pub fn open_deferred() {
    let deferred = DEFERRED.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some((log_dir, started)) = deferred {
        open(&log_file_path(&log_dir, started, std::process::id()));
    }
}

/// Canonicalized because `fuse_daemonize` chdirs to `/`, and a backgrounded mount opens its
/// log only afterwards.
fn canonical_dir(log_dir: &Path) -> PathBuf {
    fs::canonicalize(log_dir).unwrap_or_else(|_| log_dir.to_path_buf())
}

/// The log file for this run under `log_dir`.
pub fn run_log_path(log_dir: &Path) -> PathBuf {
    log_file_path(&canonical_dir(log_dir), SystemTime::now(), std::process::id())
}

/// Whether a flag's value is a credential that must not reach a log file.
///
/// `--secret-access-key` and friends take the secret itself as an argument. The `-env` and
/// `-file` variants only name where to look, but they match too: over-redacting costs a log
/// line some detail, while under-redacting writes a key to disk.
fn is_secret_flag(arg: &str) -> bool {
    let name = arg.trim_start_matches('-');
    name.contains("secret") || name.contains("access-key")
}

/// This run's command line, with credential values replaced by `<redacted>`.
pub fn redacted_command_line() -> String {
    redact_args(std::env::args())
}

fn redact_args<I: IntoIterator<Item = String>>(args: I) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_value = false;

    for arg in args {
        if redact_value {
            out.push("<redacted>".to_string());
            redact_value = false;
            continue;
        }
        // `--flag=value` hides the secret inside a single argument.
        if arg.starts_with('-')
            && let Some((flag, _)) = arg.split_once('=')
            && is_secret_flag(flag)
        {
            out.push(format!("{}=<redacted>", flag));
            continue;
        }
        if arg.starts_with('-') && is_secret_flag(&arg) {
            redact_value = true;
        }
        out.push(arg);
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_log_file_name_identifies_the_run() {
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);
        assert_eq!(log_file_name(started, 4242), "appendfs-20251217-193320-4242.log");
    }

    #[test]
    fn test_concurrent_runs_never_share_a_file() {
        // Two mounts of the same volume starting in the same second must not interleave
        // their records, which is what the pid is for.
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);
        assert_ne!(log_file_name(started, 1), log_file_name(started, 2));

        // And a later run sorts after an earlier one.
        assert!(log_file_name(started, 9) < log_file_name(started + Duration::from_secs(1), 1));
    }

    #[test]
    fn test_command_line_redacts_credentials() {
        let args = [
            "appendfs",
            "remote",
            "add",
            "/srv/vol",
            "aws",
            "--bucket",
            "backups",
            "--access-key-id",
            "AKIAEXAMPLE",
            "--secret-access-key",
            "s3cr3t-do-not-log",
        ];
        let line = redact_args(args.iter().map(|s| s.to_string()));

        assert!(
            !line.contains("s3cr3t-do-not-log"),
            "secret leaked into the log: {}",
            line
        );
        assert!(!line.contains("AKIAEXAMPLE"), "key id leaked into the log: {}", line);
        assert!(
            line.contains("--secret-access-key <redacted>") && line.contains("--access-key-id <redacted>"),
            "the flags themselves should still be visible: {}",
            line
        );
        // Everything else survives, which is the point of logging the command line at all.
        assert!(line.contains("remote add /srv/vol aws --bucket backups"), "{}", line);
    }

    #[test]
    fn test_command_line_redacts_the_inline_form_too() {
        let args = ["appendfs", "init", "/srv/vol", "--remote-secret-access-key=s3cr3t"];
        let line = redact_args(args.iter().map(|s| s.to_string()));
        assert!(!line.contains("s3cr3t"), "inline secret leaked: {}", line);
        assert_eq!(line, "appendfs init /srv/vol --remote-secret-access-key=<redacted>");
    }

    #[test]
    fn test_command_line_keeps_non_secret_arguments() {
        // A path that merely mentions a key is not a secret, and over-redacting paths would
        // make the log useless for the case it exists for.
        let args = [
            "appendfs",
            "mount",
            "/srv/vol",
            "/mnt",
            "--key-file",
            "/etc/appendfs.key",
        ];
        let line = redact_args(args.iter().map(|s| s.to_string()));
        assert_eq!(line, "appendfs mount /srv/vol /mnt --key-file /etc/appendfs.key");
    }

    #[test]
    fn test_log_lives_where_storage_cannot_see_it() {
        // The guarantee that keeps a diagnostic log from ever being mistaken for a volume
        // file: `list_files` is non-recursive and file-only, so a subdirectory is invisible.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::OsStorage::new(dir.path());
        let path = log_file_path(dir.path(), SystemTime::now(), std::process::id());

        let mut sink = LogSink::Pending(Vec::new());
        sink.open(&path).unwrap();
        sink.write_all(b"a log record\n").unwrap();
        sink.flush().unwrap();

        assert!(path.exists());
        let listed = crate::storage::Storage::list_files(&storage).unwrap();
        assert!(
            listed.is_empty(),
            "the log directory must look empty to volume code, got {:?}",
            listed
        );
    }

    #[test]
    fn test_a_second_run_leaves_the_first_run_intact() {
        // A crashed run's log has to survive the restart that follows it.
        let dir = tempfile::tempdir().unwrap();
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);

        let first = log_file_path(dir.path(), started, 1);
        let mut sink = LogSink::Pending(Vec::new());
        sink.open(&first).unwrap();
        sink.write_all(b"from the first run\n").unwrap();
        sink.flush().unwrap();
        drop(sink);

        let second = log_file_path(dir.path(), started + Duration::from_secs(5), 2);
        let mut sink = LogSink::Pending(Vec::new());
        sink.open(&second).unwrap();
        sink.write_all(b"from the second run\n").unwrap();
        sink.flush().unwrap();

        assert_eq!(fs::read_to_string(&first).unwrap(), "from the first run\n");
        assert_eq!(fs::read_to_string(&second).unwrap(), "from the second run\n");
    }

    #[test]
    fn test_writes_keep_succeeding_after_the_file_is_lost() {
        // A filesystem must not fail because its log file did.
        let dir = tempfile::tempdir().unwrap();
        let path = log_file_path(dir.path(), SystemTime::now(), std::process::id());
        let mut sink = LogSink::Pending(Vec::new());
        sink.open(&path).unwrap();
        sink.write_all(b"before\n").unwrap();
        sink = LogSink::Failed;
        assert!(sink.write_all(b"after\n").is_ok(), "a lost log file must be survivable");
        assert!(sink.flush().is_ok());
    }

    #[test]
    fn test_records_before_the_file_opens_are_kept() {
        // A backgrounded mount logs all through recovery before it knows its file's name.
        let dir = tempfile::tempdir().unwrap();
        let path = log_file_path(dir.path(), SystemTime::now(), std::process::id());
        let mut sink = LogSink::Pending(Vec::new());
        sink.write_all(b"during recovery\n").unwrap();
        sink.open(&path).unwrap();
        sink.write_all(b"after daemonizing\n").unwrap();
        sink.flush().unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "during recovery\nafter daemonizing\n"
        );
    }
}
