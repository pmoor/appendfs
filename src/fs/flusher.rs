use super::FlushBatch;
use crate::log::{BackgroundFlusher, FlushMotivation};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

/// Interface defining host filesystem operations required by background and test flushers.
pub trait FlushHost: Send + Sync {
    /// Returns the batch at the front of the `flushing` queue, if any.
    /// Does not create batches or mutate queue state.
    fn get_next_flush_batch(&self) -> Option<FlushBatch>;

    /// Persists the batch's data payloads and delta records to disk.
    /// On failure, the host internally rolls back log offsets and manifest state,
    /// returning an Err. The batch remains in the queue for retry.
    fn persist_flush_batch(&self, batch: &mut FlushBatch) -> std::io::Result<u64>;

    /// Folds the flushed batch's deltas into the in-memory `base` layer.
    fn fold_flush_batch(&self, batch: &FlushBatch);

    /// Pops the batch from the front of the `flushing` queue and resolves its completion handle.
    /// If `live` is currently above staged byte/op thresholds, the host immediately
    /// transitions `live -> flushing` under the lock to keep the queue primed.
    fn remove_front_flush_batch(&self, batch_id: u64);

    /// Called when the idle timer expires to allow the host to
    /// transition `live -> flushing` with FlushMotivation::TimeBased if `live` is dirty.
    fn freeze_idle(&self);
}

/// Maximum number of recent flush operations preserved in the flusher ring buffer.
pub const FLUSH_RING_BUFFER_CAPACITY: usize = 16;

/// Detailed statistics recorded for a single completed flush operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRecord {
    /// Monotonically increasing flush batch identifier.
    pub id: u64,
    /// The motivation that triggered this flush operation.
    pub motivation: FlushMotivation,
    /// Total data extent payload bytes flushed to disk / consolidated into base.
    pub data_bytes: u64,
    /// Number of distinct mutating operations contained within the flushed batch.
    pub ops_count: usize,
    /// Injected clock timestamp when the batch write/consolidation started.
    pub started_at: SystemTime,
    /// Injected clock timestamp when the batch was folded into base and completion resolved.
    pub completed_at: SystemTime,
    /// Total elapsed duration for the flush operation.
    pub duration: Duration,
}

/// Fixed-capacity ring buffer recording recent flush operations for runtime diagnostics (`.status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRingBuffer {
    records: VecDeque<FlushRecord>,
    capacity: usize,
}

impl Default for FlushRingBuffer {
    fn default() -> Self {
        Self::new(FLUSH_RING_BUFFER_CAPACITY)
    }
}

impl FlushRingBuffer {
    /// Creates a new `FlushRingBuffer` with the specified maximum capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            records: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Appends a new flush record, evicting the oldest record if capacity is exceeded.
    pub fn push(&mut self, record: FlushRecord) {
        if self.records.len() >= self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }

    /// Returns a chronological snapshot of recorded flush operations (oldest to newest).
    pub fn entries(&self) -> Vec<FlushRecord> {
        self.records.iter().cloned().collect()
    }

    /// Number of flush records currently retained in the ring buffer.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no flush operations have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clears all retained flush records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

/// Consolidated authority and state manager for filesystem flush execution, background scheduling,
/// and runtime diagnostic telemetry.
pub struct Flusher {
    /// Background periodic flusher thread instance.
    pub(crate) background: Mutex<Option<BackgroundFlusher>>,
    /// Ring buffer of recent flush execution statistics.
    pub(crate) ring_buffer: Arc<Mutex<FlushRingBuffer>>,
    /// Mutex serializing flush operations to prevent concurrent log writes and interleaving.
    pub(crate) lock: Arc<Mutex<()>>,
}

impl Default for Flusher {
    fn default() -> Self {
        Self::new()
    }
}

impl Flusher {
    /// Creates a new `Flusher` with empty ring buffer and no active background thread.
    pub fn new() -> Self {
        Self {
            background: Mutex::new(None),
            ring_buffer: Arc::new(Mutex::new(FlushRingBuffer::new(FLUSH_RING_BUFFER_CAPACITY))),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Starts or restarts the background flusher worker thread driving `FlushHost`.
    pub fn start(&self, host: Arc<dyn FlushHost>, interval: Duration, clock: Arc<dyn crate::clock::Clock>) {
        self.stop_background();

        let weak_host = Arc::downgrade(&host);
        let weak_host_timeout = weak_host.clone();
        let ring_buffer = Arc::clone(&self.ring_buffer);
        let flusher_lock = Arc::clone(&self.lock);

        let bg = BackgroundFlusher::start(
            move || {
                let Some(host) = weak_host.upgrade() else {
                    return Ok(());
                };
                let _guard = flusher_lock.lock().unwrap();
                while let Some(mut batch) = host.get_next_flush_batch() {
                    let started_at = clock.now();
                    match host.persist_flush_batch(&mut batch) {
                        Ok(data_bytes) => {
                            host.fold_flush_batch(&batch);
                            host.remove_front_flush_batch(batch.id);
                            let completed_at = clock.now();
                            let duration = completed_at.duration_since(started_at).unwrap_or_default();
                            let record = FlushRecord {
                                id: batch.id,
                                motivation: batch.motivation,
                                data_bytes,
                                ops_count: batch.ops,
                                started_at,
                                completed_at,
                                duration,
                            };
                            ring_buffer.lock().unwrap().push(record);
                        }
                        Err(e) => {
                            log::error!("Background flusher failed to persist batch {}: {}", batch.id, e);
                            return Err(e);
                        }
                    }
                }
                Ok(())
            },
            move || {
                if let Some(host) = weak_host_timeout.upgrade() {
                    host.freeze_idle();
                }
            },
            interval,
        );

        *self.background.lock().unwrap() = Some(bg);
    }

    /// Returns a snapshot of the most recent flush operations recorded in the ring buffer.
    pub fn recent_flushes(&self) -> Vec<FlushRecord> {
        self.ring_buffer.lock().unwrap().entries()
    }

    /// Records a completed flush operation into the ring buffer.
    pub fn record_flush(&self, record: FlushRecord) {
        self.ring_buffer.lock().unwrap().push(record);
    }

    /// Clears all flush history from the ring buffer.
    pub fn clear_records(&self) {
        self.ring_buffer.lock().unwrap().clear();
    }

    /// Acquires the serialization lock for executing a flush operation.
    pub fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap()
    }

    /// Returns `true` if the periodic background flusher thread is currently active.
    pub fn is_background_active(&self) -> bool {
        self.background.lock().unwrap().is_some()
    }

    /// Wakes up the background flusher thread immediately to execute a flush cycle.
    /// Returns `true` if a background flusher thread is running and was notified.
    pub fn trigger(&self) -> bool {
        if let Some(ref bg) = *self.background.lock().unwrap() {
            bg.trigger();
            true
        } else {
            false
        }
    }

    /// Stops the background flusher thread and joins its worker handle.
    /// Returns `true` if a background flusher was active and stopped.
    pub fn stop_background(&self) -> bool {
        let mut bg = match self.background.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(mut f) = bg.take() {
            f.stop();
            true
        } else {
            false
        }
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        self.stop_background();
    }
}

/// Synchronous, threadless flusher driver for executing flushes in unit tests without background OS threads.
#[cfg(any(test, feature = "testing"))]
pub struct TestFlusher<'a> {
    host: &'a dyn FlushHost,
    flusher: Option<&'a Flusher>,
    clock: Arc<dyn crate::clock::Clock>,
}

#[cfg(any(test, feature = "testing"))]
impl<'a> TestFlusher<'a> {
    /// Creates a new `TestFlusher` wrapping the specified `host` with the system clock.
    pub fn new(host: &'a dyn FlushHost) -> Self {
        Self {
            host,
            flusher: None,
            clock: Arc::new(crate::clock::SystemClock),
        }
    }

    /// Creates a new `TestFlusher` wrapping the specified `host` and injected test clock.
    pub fn with_clock(host: &'a dyn FlushHost, clock: Arc<dyn crate::clock::Clock>) -> Self {
        Self {
            host,
            flusher: None,
            clock,
        }
    }

    /// Creates a new `TestFlusher` wrapping the specified `host`, `flusher` for ring buffer telemetry, and injected test clock.
    pub fn with_flusher(host: &'a dyn FlushHost, flusher: &'a Flusher, clock: Arc<dyn crate::clock::Clock>) -> Self {
        Self {
            host,
            flusher: Some(flusher),
            clock,
        }
    }

    /// Steps a single batch from the `flushing` queue:
    /// - Persists batch to disk via `host.persist_flush_batch`
    /// - Folds deltas into base via `host.fold_flush_batch`
    /// - Pops batch from queue and completes completion handle via `host.remove_front_flush_batch`
    /// - Records flush operation in `FlushRingBuffer` if flusher is configured
    pub fn step(&self) -> std::io::Result<Option<FlushRecord>> {
        let _guard = self.flusher.map(|f| f.lock());
        let mut batch = match self.host.get_next_flush_batch() {
            Some(b) => b,
            None => return Ok(None),
        };

        let started_at = self.clock.now();
        let flushed_bytes = self.host.persist_flush_batch(&mut batch)?;
        self.host.fold_flush_batch(&batch);
        self.host.remove_front_flush_batch(batch.id);

        let completed_at = self.clock.now();
        let duration = completed_at.duration_since(started_at).unwrap_or_default();
        let record = FlushRecord {
            id: batch.id,
            motivation: batch.motivation,
            data_bytes: flushed_bytes,
            ops_count: batch.ops,
            started_at,
            completed_at,
            duration,
        };

        if let Some(flusher) = self.flusher {
            flusher.record_flush(record.clone());
        }

        Ok(Some(record))
    }

    /// Drains all batches from the `flushing` queue until none remain.
    pub fn drain(&self) -> std::io::Result<usize> {
        let mut count = 0;
        while self.step()?.is_some() {
            count += 1;
        }
        Ok(count)
    }

    /// Convenience helper to step one batch from `host` with system clock.
    pub fn step_host(host: &dyn FlushHost) -> std::io::Result<Option<FlushRecord>> {
        TestFlusher::new(host).step()
    }

    /// Convenience helper to drain all batches from `host` with system clock.
    pub fn drain_host(host: &dyn FlushHost) -> std::io::Result<usize> {
        TestFlusher::new(host).drain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_ring_buffer_capacity_and_eviction() {
        let mut ring = FlushRingBuffer::new(3);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        let t0 = SystemTime::UNIX_EPOCH;
        ring.push(FlushRecord {
            id: 1,
            motivation: FlushMotivation::Manual,
            data_bytes: 100,
            ops_count: 1,
            started_at: t0,
            completed_at: t0 + Duration::from_millis(10),
            duration: Duration::from_millis(10),
        });
        ring.push(FlushRecord {
            id: 2,
            motivation: FlushMotivation::Fsync,
            data_bytes: 200,
            ops_count: 2,
            started_at: t0,
            completed_at: t0 + Duration::from_millis(20),
            duration: Duration::from_millis(20),
        });
        ring.push(FlushRecord {
            id: 3,
            motivation: FlushMotivation::Threshold,
            data_bytes: 300,
            ops_count: 3,
            started_at: t0,
            completed_at: t0 + Duration::from_millis(30),
            duration: Duration::from_millis(30),
        });

        assert_eq!(ring.len(), 3);
        let entries = ring.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[1].id, 2);
        assert_eq!(entries[2].id, 3);

        // Push 4th record - should evict record 1
        ring.push(FlushRecord {
            id: 4,
            motivation: FlushMotivation::TimeBased,
            data_bytes: 400,
            ops_count: 4,
            started_at: t0,
            completed_at: t0 + Duration::from_millis(40),
            duration: Duration::from_millis(40),
        });

        assert_eq!(ring.len(), 3);
        let entries = ring.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, 2);
        assert_eq!(entries[1].id, 3);
        assert_eq!(entries[2].id, 4);
        assert_eq!(entries[2].motivation, FlushMotivation::TimeBased);

        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn test_flush_ring_buffer_capacity_16_bound() {
        let mut ring = FlushRingBuffer::new(FLUSH_RING_BUFFER_CAPACITY);
        let t0 = SystemTime::UNIX_EPOCH;

        for i in 0..25usize {
            ring.push(FlushRecord {
                id: i as u64,
                motivation: FlushMotivation::Manual,
                data_bytes: (i * 10) as u64,
                ops_count: i,
                started_at: t0,
                completed_at: t0 + Duration::from_millis(i as u64),
                duration: Duration::from_millis(i as u64),
            });
        }

        assert_eq!(ring.len(), 16);
        let entries = ring.entries();
        assert_eq!(entries.len(), 16);
        // Evicted 0..9, keeping 9..25
        assert_eq!(entries[0].id, 9);
        assert_eq!(entries[15].id, 24);
    }

    #[test]
    fn test_flusher_encapsulation_methods() {
        let flusher = Flusher::new();
        assert!(!flusher.is_background_active());
        assert!(!flusher.trigger());
        assert!(!flusher.stop_background());

        let t0 = SystemTime::UNIX_EPOCH;
        flusher.record_flush(FlushRecord {
            id: 42,
            motivation: FlushMotivation::Fsync,
            data_bytes: 1024,
            ops_count: 5,
            started_at: t0,
            completed_at: t0 + Duration::from_millis(5),
            duration: Duration::from_millis(5),
        });

        let flushes = flusher.recent_flushes();
        assert_eq!(flushes.len(), 1);
        assert_eq!(flushes[0].id, 42);
        assert_eq!(flushes[0].motivation, FlushMotivation::Fsync);
        assert_eq!(flushes[0].data_bytes, 1024);
        assert_eq!(flushes[0].ops_count, 5);

        flusher.clear_records();
        assert!(flusher.recent_flushes().is_empty());
    }

    struct MockFlushHost {
        batches: Mutex<VecDeque<FlushBatch>>,
        folded: Mutex<Vec<u64>>,
        removed: Mutex<Vec<u64>>,
        idled: Mutex<bool>,
        fail_persist: Mutex<bool>,
    }

    impl FlushHost for MockFlushHost {
        fn get_next_flush_batch(&self) -> Option<FlushBatch> {
            self.batches.lock().unwrap().front().cloned()
        }

        fn persist_flush_batch(&self, batch: &mut FlushBatch) -> std::io::Result<u64> {
            if *self.fail_persist.lock().unwrap() {
                return Err(std::io::Error::other("mock persist error"));
            }
            Ok(batch.bytes as u64)
        }

        fn fold_flush_batch(&self, batch: &FlushBatch) {
            self.folded.lock().unwrap().push(batch.id);
        }

        fn remove_front_flush_batch(&self, batch_id: u64) {
            let mut batches = self.batches.lock().unwrap();
            if let Some(b) = batches.pop_front() {
                assert_eq!(b.id, batch_id);
                self.removed.lock().unwrap().push(batch_id);
                b.completion.complete(Ok(()));
            }
        }

        fn freeze_idle(&self) {
            *self.idled.lock().unwrap() = true;
        }
    }

    fn make_test_batch(id: u64, bytes: usize, ops: usize, motivation: FlushMotivation) -> FlushBatch {
        let mut entries = std::collections::HashMap::new();
        entries.insert(1, crate::node::EntryDelta::Tombstone);
        FlushBatch::new(
            id,
            entries,
            crate::fs::WriteArena::new(),
            bytes,
            ops,
            motivation,
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn test_test_flusher_step_and_drain() {
        let mut batches = VecDeque::new();
        let b1 = make_test_batch(1, 100, 2, FlushMotivation::Fsync);
        let b2 = make_test_batch(2, 200, 4, FlushMotivation::Threshold);
        let c1 = b1.completion.clone();
        let c2 = b2.completion.clone();
        batches.push_back(b1);
        batches.push_back(b2);

        let host = MockFlushHost {
            batches: Mutex::new(batches),
            folded: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
            idled: Mutex::new(false),
            fail_persist: Mutex::new(false),
        };

        let flusher = Flusher::new();
        let test_flusher = TestFlusher::with_flusher(&host, &flusher, Arc::new(crate::clock::SystemClock));

        // Step one batch
        let record1 = test_flusher.step().unwrap().expect("record for batch 1");
        assert_eq!(record1.id, 1);
        assert_eq!(record1.motivation, FlushMotivation::Fsync);
        assert_eq!(record1.data_bytes, 100);
        assert_eq!(record1.ops_count, 2);
        assert!(c1.is_completed());
        assert!(!c2.is_completed());
        assert_eq!(*host.folded.lock().unwrap(), vec![1]);
        assert_eq!(*host.removed.lock().unwrap(), vec![1]);
        assert_eq!(flusher.recent_flushes().len(), 1);

        // Drain remaining batches
        let drained_count = test_flusher.drain().unwrap();
        assert_eq!(drained_count, 1);
        assert!(c2.is_completed());
        assert_eq!(*host.folded.lock().unwrap(), vec![1, 2]);
        assert_eq!(*host.removed.lock().unwrap(), vec![1, 2]);
        assert_eq!(flusher.recent_flushes().len(), 2);
        assert!(host.get_next_flush_batch().is_none());

        // Drain empty host returns 0
        assert_eq!(test_flusher.drain().unwrap(), 0);
    }

    #[test]
    fn test_test_flusher_persist_failure_leaves_batch() {
        let mut batches = VecDeque::new();
        let b1 = make_test_batch(1, 100, 2, FlushMotivation::Manual);
        let c1 = b1.completion.clone();
        batches.push_back(b1);

        let host = MockFlushHost {
            batches: Mutex::new(batches),
            folded: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
            idled: Mutex::new(false),
            fail_persist: Mutex::new(true),
        };

        let test_flusher = TestFlusher::new(&host);
        let res = test_flusher.step();
        assert!(res.is_err());
        assert!(!c1.is_completed());
        assert!(host.folded.lock().unwrap().is_empty());
        assert!(host.removed.lock().unwrap().is_empty());
        assert_eq!(host.batches.lock().unwrap().len(), 1);

        // Clear error and retry
        *host.fail_persist.lock().unwrap() = false;
        let record = test_flusher.step().unwrap().expect("record expected");
        assert_eq!(record.id, 1);
        assert!(c1.is_completed());
        assert_eq!(*host.folded.lock().unwrap(), vec![1]);
    }

    #[test]
    fn test_production_flusher_background_worker_lifecycle() {
        let mut batches = VecDeque::new();
        let b1 = make_test_batch(10, 500, 3, FlushMotivation::TimeBased);
        let c1 = b1.completion.clone();
        batches.push_back(b1);

        let host = Arc::new(MockFlushHost {
            batches: Mutex::new(batches),
            folded: Mutex::new(Vec::new()),
            removed: Mutex::new(Vec::new()),
            idled: Mutex::new(false),
            fail_persist: Mutex::new(false),
        });

        let flusher = Flusher::new();
        flusher.start(
            host.clone(),
            Duration::from_millis(50),
            Arc::new(crate::clock::SystemClock),
        );
        assert!(flusher.is_background_active());

        // Trigger or wait for background flusher to process batch 10
        flusher.trigger();
        assert!(crate::wait_until(|| c1.is_completed(), Duration::from_secs(3)));

        assert_eq!(*host.folded.lock().unwrap(), vec![10]);
        assert_eq!(*host.removed.lock().unwrap(), vec![10]);
        assert_eq!(flusher.recent_flushes().len(), 1);
        assert_eq!(flusher.recent_flushes()[0].id, 10);

        // Stop flusher
        assert!(flusher.stop_background());
        assert!(!flusher.is_background_active());
    }
}
