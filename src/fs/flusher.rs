use crate::log::{BackgroundFlusher, FlushMotivation};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

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
    pub(crate) ring_buffer: Mutex<FlushRingBuffer>,
    /// Mutex serializing flush operations to prevent concurrent log writes and interleaving.
    pub(crate) lock: Mutex<()>,
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
            ring_buffer: Mutex::new(FlushRingBuffer::new(FLUSH_RING_BUFFER_CAPACITY)),
            lock: Mutex::new(()),
        }
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
        let mut bg = self.background.lock().unwrap();
        if let Some(mut f) = bg.take() {
            f.stop();
            true
        } else {
            false
        }
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
}
