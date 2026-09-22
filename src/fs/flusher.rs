//! Drives flush cycles.
//!
//! The flusher is the only component permitted to write flush batches to the log or fold
//! them into `base`. FUSE threads may append to `live` and freeze `live` into `flushing`;
//! everything past that point belongs here.
//!
//! Cycles run in one of two modes. A mounted filesystem starts a [`Flusher`] thread that
//! wakes on demand and after an interval of inactivity. Everything else - tests, one-shot
//! CLI tools, fixture generation - leaves it in the default inline mode, where a cycle runs
//! on the thread that asked for it. Both modes go through the same `wake` / `quiesce` calls,
//! so no caller has to know which one it is talking to.

use super::{FLUSH_HISTORY_CAPACITY, FlushRecord, FlushStats, InMemoryFS};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long the background thread waits before retrying a cycle that failed, rather than
/// sitting out the full inactivity interval while a transient error keeps the queue stalled.
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Counters and recent history, updated once per completed batch.
#[derive(Default)]
struct Telemetry {
    total_batches: u64,
    total_bytes: u64,
    total_disk_bytes: u64,
    total_ops: u64,
    total_serialize: Duration,
    total_wait: Duration,
    total_flush: Duration,
    total_fold: Duration,
    by_reason: [u64; 5],
    recent: VecDeque<FlushRecord>,
}

#[derive(Default)]
struct Wakeup {
    /// A cycle has been requested since the thread last ran one.
    wake: bool,
    /// The thread has been asked to exit.
    stop: bool,
}

/// Thread management and cycle serialization for [`InMemoryFS`] flushing.
pub(crate) struct Flusher {
    wakeup: Arc<(Mutex<Wakeup>, Condvar)>,
    /// `Some` once a background thread is running.
    thread: Mutex<Option<JoinHandle<()>>>,
    /// True while a background thread is running, so callers can pick between waking it and
    /// running the cycle themselves without locking `thread`.
    background: AtomicBool,
    /// Serializes flush cycles. Uncontended in background mode, where only one thread runs
    /// them; in inline mode it keeps concurrent callers from writing to the log at once.
    cycle_lock: Mutex<()>,
    /// Inactivity interval the thread was started with, kept for reporting.
    interval: Mutex<Option<Duration>>,
    /// Flush counters and history. Touched once per batch, never on a read path.
    telemetry: Mutex<Telemetry>,
    /// Whether a cycle is running, so debug builds can assert that nothing writes to the
    /// log from outside one.
    in_cycle: AtomicBool,
}

impl Default for Flusher {
    fn default() -> Self {
        Self::new()
    }
}

impl Flusher {
    pub(crate) fn new() -> Self {
        Self {
            wakeup: Arc::new((Mutex::new(Wakeup::default()), Condvar::new())),
            thread: Mutex::new(None),
            background: AtomicBool::new(false),
            cycle_lock: Mutex::new(()),
            in_cycle: AtomicBool::new(false),
            interval: Mutex::new(None),
            telemetry: Mutex::new(Telemetry::default()),
        }
    }

    /// Returns true once a background thread is running cycles.
    pub(crate) fn is_background(&self) -> bool {
        self.background.load(Ordering::SeqCst)
    }

    /// Starts the background thread, which runs a cycle whenever one is requested and, if
    /// `interval` is set, after that long without one. Idempotent.
    ///
    /// The thread holds only a `Weak` reference: an `Arc` here would form a cycle through
    /// `InMemoryFS::flusher` and keep the filesystem alive forever.
    pub(crate) fn start(&self, fs: &Arc<InMemoryFS>, interval: Option<Duration>) {
        let mut thread = self.thread.lock().unwrap();
        if thread.is_some() {
            return;
        }

        let weak = Arc::downgrade(fs);
        let wakeup = Arc::clone(&self.wakeup);
        let handle = std::thread::Builder::new()
            .name("appendfs-flusher".to_string())
            .spawn(move || run_background(&weak, &wakeup, interval))
            .expect("failed to spawn flusher thread");

        *thread = Some(handle);
        *self.interval.lock().unwrap() = interval;
        self.background.store(true, Ordering::SeqCst);
        log::info!(
            "Started flusher thread (inactivity interval: {})",
            interval.map_or_else(|| "disabled".to_string(), |i| format!("{}s", i.as_secs()))
        );
    }

    /// Poses as (or stops posing as) a mounted filesystem, without a thread behind it, so
    /// tests can exercise the paths that wait for a background flusher.
    #[cfg(test)]
    pub(crate) fn set_background_for_tests(&self, on: bool) {
        self.background.store(on, Ordering::SeqCst);
    }

    /// Requests a cycle from the background thread. No-op in inline mode, where the caller
    /// runs the cycle itself.
    pub(crate) fn notify(&self) {
        let (lock, cvar) = &*self.wakeup;
        let mut state = lock.lock().unwrap();
        state.wake = true;
        cvar.notify_one();
    }

    /// Signals the background thread to exit and joins it. Idempotent.
    ///
    /// Returns whether a thread was actually running, which tells `destroy` whether anything
    /// still queued has lost the thread that would have written it.
    pub(crate) fn stop(&self) -> bool {
        {
            let (lock, cvar) = &*self.wakeup;
            let mut state = lock.lock().unwrap();
            state.stop = true;
            cvar.notify_all();
        }
        let handle = self.thread.lock().unwrap().take();
        let was_running = handle.is_some();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.background.store(false, Ordering::SeqCst);
        was_running
    }

    /// Records a completed batch, evicting the oldest history entry once full.
    pub(crate) fn record_flush(&self, record: FlushRecord) {
        let mut telemetry = self.telemetry.lock().unwrap();
        telemetry.total_batches += 1;
        telemetry.total_bytes += record.bytes as u64;
        telemetry.total_disk_bytes += record.disk_bytes;
        telemetry.total_ops += record.ops as u64;
        telemetry.total_serialize += record.serialize;
        telemetry.total_wait += record.wait;
        telemetry.total_flush += record.flush;
        telemetry.total_fold += record.fold;
        telemetry.by_reason[record.reason.index()] += 1;
        if telemetry.recent.len() == FLUSH_HISTORY_CAPACITY {
            telemetry.recent.pop_front();
        }
        telemetry.recent.push_back(record);
    }

    /// Copies out the counters and history for reporting.
    pub(crate) fn stats(&self) -> FlushStats {
        let telemetry = self.telemetry.lock().unwrap();
        FlushStats {
            background: self.is_background(),
            interval: *self.interval.lock().unwrap(),
            total_batches: telemetry.total_batches,
            total_bytes: telemetry.total_bytes,
            total_disk_bytes: telemetry.total_disk_bytes,
            total_ops: telemetry.total_ops,
            total_serialize: telemetry.total_serialize,
            total_wait: telemetry.total_wait,
            total_flush: telemetry.total_flush,
            total_fold: telemetry.total_fold,
            by_reason: telemetry.by_reason,
            recent: telemetry.recent.iter().cloned().collect(),
        }
    }

    /// Runs `cycle` with the cycle lock held, so only one runs at a time.
    pub(crate) fn run_locked<T, F>(&self, cycle: F) -> std::io::Result<T>
    where
        F: FnOnce() -> std::io::Result<T>,
    {
        let _guard = self.cycle_lock.lock().unwrap();
        self.in_cycle.store(true, Ordering::SeqCst);
        let result = cycle();
        self.in_cycle.store(false, Ordering::SeqCst);
        result
    }

    /// Whether a flush cycle is currently running on some thread.
    pub(crate) fn in_cycle(&self) -> bool {
        self.in_cycle.load(Ordering::SeqCst)
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn run_background(weak: &Weak<InMemoryFS>, wakeup: &Arc<(Mutex<Wakeup>, Condvar)>, interval: Option<Duration>) {
    let (lock, cvar) = &**wakeup;
    let mut delay = interval;
    loop {
        let mut idle = false;
        {
            let mut state = lock.lock().unwrap();
            while !state.stop && !state.wake {
                match delay {
                    Some(d) => {
                        let (guard, timeout) = cvar.wait_timeout(state, d).unwrap();
                        state = guard;
                        if timeout.timed_out() {
                            idle = true;
                            break;
                        }
                    }
                    None => state = cvar.wait(state).unwrap(),
                }
            }
            if state.stop {
                return;
            }
            state.wake = false;
        }

        // Dropped between the wake-up and here: nothing left to flush into.
        let Some(fs) = weak.upgrade() else { return };
        // Nobody asked for this cycle, so nobody has frozen `live`. Ask on their behalf -
        // this is the inactivity flush.
        if idle {
            fs.request_freeze(crate::fs::FlushReason::Inactivity);
        }
        // Back off briefly rather than sitting out the whole interval, so a transient
        // failure does not strand committed mutations in the queue.
        delay = match fs.run_flush_cycle() {
            Ok(()) => interval,
            Err(e) => {
                log::error!("Flush cycle failed: {}", e);
                Some(RETRY_DELAY)
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::fs::InMemoryFS;
    use crate::log::LogWriter;
    use crate::operations::read_write::{create_core, write_core};
    use crate::storage::Storage;

    fn test_fs() -> Arc<InMemoryFS> {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = SystemClock;
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        Arc::new(InMemoryFS::with_log(writer))
    }

    fn stage_a_write(fs: &InMemoryFS, name: &str) {
        let file = create_core(fs, 1, name, 0o644, 0, 1000, 1000).unwrap();
        write_core(fs, file.ino, b"payload", 0).unwrap();
    }

    #[test]
    fn test_background_flusher_drains_queue_when_notified() {
        let fs = test_fs();
        // No inactivity interval: the only thing that can drain this queue is the notify.
        fs.flusher.start(&fs, None);

        stage_a_write(&fs, "notified.bin");
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 1);

        fs.flusher.notify();
        assert!(crate::wait_until(
            || fs.flush_queue_depth() == 0,
            Duration::from_secs(3)
        ));
        fs.destroy();
    }

    #[test]
    fn test_background_flusher_flushes_live_after_inactivity() {
        let fs = test_fs();
        fs.flusher.start(&fs, Some(Duration::from_millis(50)));

        // Left in `live`, well below any staged threshold, and never frozen by the writer:
        // only the inactivity tick can move it.
        stage_a_write(&fs, "idle.bin");
        assert!(fs.staged_bytes() > 0);

        assert!(crate::wait_until(
            || fs.staged_bytes() == 0 && fs.flush_queue_depth() == 0,
            Duration::from_secs(3)
        ));
        fs.destroy();
    }

    #[test]
    fn test_quiesce_waits_for_the_background_flusher_to_drain() {
        let fs = test_fs();
        fs.flusher.start(&fs, None);

        stage_a_write(&fs, "queued.bin");
        assert!(fs.freeze_now());
        stage_a_write(&fs, "still-live.bin");

        // Returns only once both the queued batch and the still-live write are on disk.
        fs.quiesce().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.staged_bytes(), 0);
        fs.destroy();
    }

    #[test]
    fn test_idle_cycle_rolls_the_generation_once_it_ages_out() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = crate::clock::AdvancingClock::new(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap()
            .with_max_log_age(Some(Duration::from_secs(3600))),
        );
        let fs = InMemoryFS::with_clock_and_log(Arc::new(clock.clone()), Some(writer.clone()));

        // A batch's worth of data, well under `max_log_size`: only age can roll this.
        stage_a_write(&fs, "aged.bin");
        fs.quiesce().unwrap();
        assert_eq!(writer.generation(), 1);
        assert!(writer.is_open());
        assert!(storage.exists("000001.log"));

        // Still inside the age limit. `quiesce` short-circuits with nothing pending, so drive
        // the cycle directly - this is what the inactivity tick does with an empty queue.
        clock.advance(Duration::from_secs(3599));
        fs.run_flush_cycle().unwrap();
        assert_eq!(writer.generation(), 1);

        // Past it: an idle cycle with nothing to write still seals the generation.
        clock.advance(Duration::from_secs(2));
        fs.run_flush_cycle().unwrap();
        assert_eq!(
            writer.generation(),
            2,
            "an aged-out generation must roll on an idle cycle"
        );
        assert!(
            fs.manifest.read().unwrap().logs.iter().any(|l| l.generation == 1),
            "the sealed generation must be recorded in the manifest"
        );
        assert!(
            !fs.manifest.read().unwrap().logs.iter().any(|l| l.generation == 2),
            "the unopened successor generation must not be recorded in the manifest yet"
        );
        assert!(
            !writer.is_open(),
            "the rolled log writer must be in lazy mode (unopened) on idle roll"
        );
        assert!(
            !storage.exists("000002.log"),
            "new generation log file must not be opened until new activity arrives"
        );

        // Filesystem receives no activity for a week: multiple idle cycles must NOT waste empty log files!
        for _ in 0..7 {
            clock.advance(Duration::from_secs(86400));
            fs.run_flush_cycle().unwrap();
            assert_eq!(writer.generation(), 2);
            assert!(!writer.is_open());
            assert!(!storage.exists("000002.log"));
            assert!(!storage.exists("000003.log"));
            assert!(!fs.manifest.read().unwrap().logs.iter().any(|l| l.generation == 2));
        }

        // New activity arrives: lazy log writer opens 000002.log
        stage_a_write(&fs, "after_idle.bin");
        fs.quiesce().unwrap();
        assert_eq!(writer.generation(), 2);
        assert!(writer.is_open());
        assert!(storage.exists("000002.log"));

        let manifest = fs.manifest.read().unwrap();
        assert!(
            !manifest.logs.iter().any(|l| l.generation == 2),
            "active generation 2 must remain in the log writer and not in the manifest until sealed"
        );
        drop(manifest);

        // Sealing/rolling generation 2 records it into the manifest with its creation time and md5
        let sealed2 = fs.force_roll_active_log().unwrap().unwrap();
        assert_eq!(sealed2.generation, 2);
        assert_eq!(
            sealed2.created_at,
            clock.now(),
            "creation time must match the time generation 2 was actually opened"
        );
        let manifest = fs.manifest.read().unwrap();
        let gen2 = manifest
            .logs
            .iter()
            .find(|l| l.generation == 2)
            .expect("generation 2 must be recorded in the manifest after being sealed");
        assert_eq!(gen2.created_at, clock.now());
        assert_ne!(gen2.md5, [0u8; 16]);
    }

    #[test]
    fn test_flush_stats_count_batches_bytes_and_reasons() {
        let fs = test_fs();

        // Fsync: freezes `live` itself, so the following quiesce finds nothing new to name.
        stage_a_write(&fs, "a.bin");
        fs.rollover_for_fsync(1, 0, crate::fs::FlushReason::Fsync).unwrap();
        fs.quiesce().unwrap();

        // Quiesce: nothing has frozen this one yet, so it names the batch.
        stage_a_write(&fs, "b.bin");
        fs.quiesce().unwrap();

        let stats = fs.flush_stats();
        assert_eq!(stats.total_batches, 2);
        assert_eq!(stats.count_for(crate::fs::FlushReason::Fsync), 1);
        assert_eq!(stats.count_for(crate::fs::FlushReason::Quiesce), 1);
        assert_eq!(stats.count_for(crate::fs::FlushReason::Threshold), 0);
        assert!(stats.total_bytes > 0);
        assert!(stats.total_disk_bytes > stats.total_bytes);
        assert_eq!(
            stats.total_disk_bytes,
            stats.recent.iter().map(|r| r.disk_bytes).sum::<u64>()
        );
        assert_eq!(
            stats.total_ops as usize,
            stats.recent.iter().map(|r| r.ops).sum::<usize>()
        );
        assert!(!stats.background, "an unstarted flusher reports inline");

        // The history agrees with the counters, oldest first.
        let reasons: Vec<_> = stats.recent.iter().map(|r| r.reason).collect();
        assert_eq!(
            reasons,
            vec![crate::fs::FlushReason::Fsync, crate::fs::FlushReason::Quiesce]
        );
    }

    #[test]
    fn test_flush_timings_come_from_the_injected_clock() {
        let fixed = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = crate::clock::MockClock(fixed);
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(Arc::new(clock), Some(writer));

        stage_a_write(&fs, "timed.bin");
        fs.quiesce().unwrap();

        let stats = fs.flush_stats();
        let record = stats.recent.first().expect("one batch");
        assert_eq!(record.started_at, fixed, "timestamps come from `Clock::now`");
        // The point of routing through `Clock::monotonic`: a fixed clock yields a
        // reproducible zero, where an `Instant` would report whatever the wall clock did.
        for (label, measured) in [
            ("total", record.duration),
            ("serialize", record.serialize),
            ("wait", record.wait),
            ("flush", record.flush),
            ("fold", record.fold),
        ] {
            assert_eq!(
                measured,
                Duration::ZERO,
                "{} comes from `Clock::monotonic`, not a real timer",
                label
            );
        }
    }

    #[test]
    fn test_flush_records_split_disk_time_from_fold_time() {
        let fs = test_fs();
        stage_a_write(&fs, "one.bin");
        fs.quiesce().unwrap();
        stage_a_write(&fs, "two.bin");
        fs.quiesce().unwrap();

        let stats = fs.flush_stats();
        assert_eq!(stats.recent.len(), 2);
        for record in &stats.recent {
            assert!(record.disk_bytes > 0, "disk_bytes must be non-zero");
            assert!(
                record.serialize > Duration::ZERO,
                "serializing the batch must be measured"
            );
            assert_eq!(
                record.wait,
                Duration::ZERO,
                "wait time must be zero for non-coalesced batch"
            );
            assert!(record.flush > Duration::ZERO, "flushing the batch must be measured");
            assert!(
                record.duration >= record.serialize + record.wait + record.flush + record.fold,
                "the total must cover all phases: {:?} < {:?} + {:?} + {:?} + {:?}",
                record.duration,
                record.serialize,
                record.wait,
                record.flush,
                record.fold
            );
        }

        assert_eq!(
            stats.total_disk_bytes,
            stats.recent.iter().map(|r| r.disk_bytes).sum::<u64>(),
            "cumulative disk bytes must agree with the history"
        );
        assert_eq!(
            stats.total_serialize,
            stats.recent.iter().map(|r| r.serialize).sum::<Duration>(),
            "cumulative serialize time must agree with the history"
        );
        assert_eq!(
            stats.total_wait,
            stats.recent.iter().map(|r| r.wait).sum::<Duration>(),
            "cumulative wait time must agree with the history"
        );
        assert_eq!(
            stats.total_flush,
            stats.recent.iter().map(|r| r.flush).sum::<Duration>(),
            "cumulative flush time must agree with the history"
        );
        assert_eq!(
            stats.total_fold,
            stats.recent.iter().map(|r| r.fold).sum::<Duration>(),
            "cumulative fold time must agree with the history"
        );
    }

    #[test]
    fn test_flush_record_disk_bytes_matches_storage_size() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = SystemClock;
        let writer = Arc::new(
            LogWriter::create(
                Arc::clone(&storage),
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_log(writer);

        stage_a_write(&fs, "disk_test.bin");
        fs.quiesce().unwrap();

        let stats = fs.flush_stats();
        assert_eq!(stats.total_batches, 1);
        let record = stats.recent.first().expect("one batch");

        // The log file starts with a 16-byte header, followed by the batch's data chunks,
        // inode deltas, and FlushCommit trailer.
        let file_len = storage.file_len("000001.log").unwrap();
        assert_eq!(
            file_len,
            crate::log::FILE_HEADER_SIZE as u64 + record.disk_bytes,
            "on-disk batch size must match bytes appended to the log file"
        );
        assert_eq!(stats.total_disk_bytes, record.disk_bytes);
        assert!(record.disk_bytes > record.bytes as u64);

        // A second metadata-only batch (e.g. chmod) has 0 staged payload bytes
        // but still takes on-disk space for its delta and commit trailer.
        crate::operations::read_write::setattr_core(
            &fs,
            1,
            0o750,
            0,
            0,
            0,
            std::time::SystemTime::UNIX_EPOCH,
            std::time::SystemTime::UNIX_EPOCH,
            crate::operations::read_write::FUSE_SET_ATTR_MODE,
        )
        .unwrap();
        fs.quiesce().unwrap();

        let stats2 = fs.flush_stats();
        assert_eq!(stats2.total_batches, 2);
        let record2 = stats2.recent.last().expect("second batch");
        assert_eq!(record2.bytes, 0, "metadata batch has 0 staged data bytes");
        assert!(record2.disk_bytes > 0, "metadata batch takes non-zero on-disk space");

        let updated_file_len = storage.file_len("000001.log").unwrap();
        assert_eq!(
            updated_file_len,
            file_len + record2.disk_bytes,
            "subsequent batch disk_bytes must match incremental file growth"
        );
        assert_eq!(
            stats2.total_disk_bytes,
            stats2.recent.iter().map(|r| r.disk_bytes).sum::<u64>()
        );
    }

    #[test]
    fn test_flush_history_is_capped_and_evicts_the_oldest() {
        let fs = test_fs();
        let total = crate::fs::FLUSH_HISTORY_CAPACITY + 4;
        for i in 0..total {
            stage_a_write(&fs, &format!("f{}.bin", i));
            fs.quiesce().unwrap();
        }

        let stats = fs.flush_stats();
        assert_eq!(
            stats.total_batches as usize, total,
            "counters keep counting past the cap"
        );
        assert_eq!(stats.recent.len(), crate::fs::FLUSH_HISTORY_CAPACITY);

        // What survives is the newest window, still in order.
        let ids: Vec<u64> = stats.recent.iter().map(|r| r.id).collect();
        let newest = *ids.last().unwrap();
        let expected: Vec<u64> = ((newest - (crate::fs::FLUSH_HISTORY_CAPACITY as u64 - 1))..=newest).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn test_status_reports_the_flusher_section() {
        let fs = test_fs();
        let empty = crate::stats::format_runtime_status(&fs);
        assert!(empty.contains("[Flusher]"));
        assert!(empty.contains("Recent Flushes:     None"));
        assert!(empty.contains("By Reason:          None"));

        stage_a_write(&fs, "status.bin");
        fs.quiesce().unwrap();

        let status = crate::stats::format_runtime_status(&fs);
        assert!(status.contains("Batches Flushed:    1"));
        assert!(
            status.contains("Time Flushing:"),
            "phase totals must be reported: {}",
            status
        );
        assert!(
            status.contains("serialize") && status.contains("flush") && status.contains("fold"),
            "recent flushes must break out serialize, flush and fold time: {}",
            status
        );
        assert!(
            status.contains("quiesce 1"),
            "per-reason counts must be reported: {}",
            status
        );
        assert!(
            status.contains("inline (runs on the calling thread)"),
            "mode must be reported: {}",
            status
        );
    }

    #[test]
    fn test_coalesce_flush_records_breakdown_serialize_wait_flush_fold() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage);
        fs.log_writer = Some(writer);
        fs.max_coalesce_batches = 3;

        // Stage batch 1
        let f1 = crate::operations::read_write::create_core(&fs, 1, "f1.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"batch 1", 0).unwrap();
        fs.freeze_now();

        // Stage batch 2
        let f2 = crate::operations::read_write::create_core(&fs, 1, "f2.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"batch 2", 0).unwrap();
        fs.freeze_now();

        // Stage batch 3
        let f3 = crate::operations::read_write::create_core(&fs, 1, "f3.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f3.ino, b"batch 3", 0).unwrap();
        fs.freeze_now();

        fs.run_flush_cycle().unwrap();

        let stats = fs.flush_stats();
        assert_eq!(stats.recent.len(), 3);
        let b1 = &stats.recent[0];
        let b2 = &stats.recent[1];
        let b3 = &stats.recent[2];

        // Every batch has serialize measured
        assert!(b1.serialize >= Duration::ZERO);
        assert!(b2.serialize >= Duration::ZERO);
        assert!(b3.serialize >= Duration::ZERO);

        // Batch 1 and 2 waited while subsequent batches were serialized
        assert!(b1.wait >= b2.wait);
        assert!(b2.wait >= b3.wait);

        // Every batch in the coalesced group shares the exact same flush (physical sync) duration
        assert_eq!(b1.flush, b2.flush);
        assert_eq!(b2.flush, b3.flush);

        // Totals match sums
        assert_eq!(
            stats.total_serialize,
            stats.recent.iter().map(|r| r.serialize).sum::<Duration>()
        );
        assert_eq!(stats.total_wait, stats.recent.iter().map(|r| r.wait).sum::<Duration>());
        assert_eq!(
            stats.total_flush,
            stats.recent.iter().map(|r| r.flush).sum::<Duration>()
        );
        assert_eq!(stats.total_fold, stats.recent.iter().map(|r| r.fold).sum::<Duration>());

        // In the non-coalescing case (1 batch), wait time must be strictly Duration::ZERO
        let f4 = crate::operations::read_write::create_core(&fs, 1, "f4.bin", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f4.ino, b"batch 4", 0).unwrap();
        fs.freeze_now();
        fs.run_flush_cycle().unwrap();

        let stats2 = fs.flush_stats();
        let b4 = stats2.recent.last().unwrap();
        assert_eq!(
            b4.wait,
            Duration::ZERO,
            "wait time must be strictly zero in the non-coalescing case"
        );
    }

    #[test]
    fn test_flusher_thread_does_not_keep_the_filesystem_alive() {
        let fs = test_fs();
        fs.flusher.start(&fs, Some(Duration::from_millis(20)));
        let weak = Arc::downgrade(&fs);

        // Joins the thread, so nothing holds an upgraded reference by the time we drop.
        fs.destroy();
        drop(fs);

        assert!(
            weak.upgrade().is_none(),
            "flusher thread must hold a Weak reference, not an Arc"
        );
    }
}
