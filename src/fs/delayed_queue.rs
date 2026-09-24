//! Delayed response queue for write pushback throttling and hard stalls.
//!
//! Provides two-phase pushback:
//! 1. Soft pushback: asymptotic delay formula ($r < 1.0$) scaling smoothly from `base_throttle_delay`
//!    to `max_throttle_delay` based on buffer saturation, racing against background flush commits and unmount.
//! 2. Hard stall: indefinite hold ($r \ge 1.0$) when buffer is at 100% capacity, waking immediately
//!    as soon as flush commits to disk or filesystem unmounts.
//!
//! Implemented with a mutex-protected priority queue (min-heap) and a dedicated worker thread
//! that sleeps and waits on a condition variable, eliminating asynchronous runtime overhead.

use crate::clock::Clock;
use crate::error::FsError;
use crate::operations::op::{FuseOp, FuseOpMetrics, OpTier};
use crate::shim::{FuseResponse, Request, reply_result};
use std::collections::{BinaryHeap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub use crate::operations::op::ThrottleDecision;

pub const DEFAULT_BASE_THROTTLE_DELAY: Duration = Duration::from_millis(10);
pub const DEFAULT_MAX_THROTTLE_DELAY: Duration = Duration::from_secs(10);

struct DelayedItem {
    op: FuseOp,
    deadline: Duration,
    id: u64,
    req: Request,
    res: Result<FuseResponse<'static>, FsError>,
    enqueued_at: Duration,
    is_stalled: bool,
}

impl PartialEq for DelayedItem {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}

impl Eq for DelayedItem {}

impl PartialOrd for DelayedItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DelayedItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering so that BinaryHeap acts as a min-heap (earliest deadline has highest priority)
        other.deadline.cmp(&self.deadline).then_with(|| other.id.cmp(&self.id))
    }
}

#[derive(Default)]
struct QueueState {
    next_id: u64,
    delayed: BinaryHeap<DelayedItem>,
    stalled: VecDeque<DelayedItem>,
    stopped: bool,
}

fn dispatch_item(item: DelayedItem, now: Duration, op_metrics: &FuseOpMetrics) {
    let elapsed = now.saturating_sub(item.enqueued_at);
    op_metrics.record_delayed_dispatch(item.op, item.is_stalled, elapsed);
    reply_result(item.req, item.res);
}

/// Priority-queued response manager that delays FUSE replies without blocking kernel worker threads.
pub struct DelayedResponseQueue {
    state: Arc<(Mutex<QueueState>, Condvar)>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    flushing_saturated: AtomicBool,
    cached_ratio_bits: AtomicU64,
    clock: Arc<dyn Clock>,
    op_metrics: Arc<FuseOpMetrics>,
    base_throttle_delay: Duration,
    max_throttle_delay: Duration,
}

impl std::fmt::Debug for DelayedResponseQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelayedResponseQueue")
            .field("flushing_saturated", &self.is_flushing_saturated())
            .field("cached_saturation_ratio", &self.cached_saturation_ratio())
            .field("base_throttle_delay", &self.base_throttle_delay)
            .field("max_throttle_delay", &self.max_throttle_delay)
            .finish()
    }
}

impl DelayedResponseQueue {
    /// Creates a new delayed response queue with default base (10ms) and max (10s) throttle delays.
    pub fn new(clock: Arc<dyn Clock>, op_metrics: Arc<FuseOpMetrics>) -> Self {
        Self::with_delays(
            clock,
            op_metrics,
            DEFAULT_BASE_THROTTLE_DELAY,
            DEFAULT_MAX_THROTTLE_DELAY,
        )
    }

    /// Creates a new delayed response queue with custom base and max throttle delays.
    pub fn with_delays(
        clock: Arc<dyn Clock>,
        op_metrics: Arc<FuseOpMetrics>,
        base_throttle_delay: Duration,
        max_throttle_delay: Duration,
    ) -> Self {
        Self {
            state: Arc::new((Mutex::new(QueueState::default()), Condvar::new())),
            thread: Mutex::new(None),
            flushing_saturated: AtomicBool::new(false),
            cached_ratio_bits: AtomicU64::new(0.0f64.to_bits()),
            clock,
            op_metrics,
            base_throttle_delay,
            max_throttle_delay,
        }
    }

    /// Starts the worker thread that dispatches delayed responses once their deadline passes.
    /// Idempotent. Until it runs, delayed responses only go out through `notify_capacity`,
    /// `drain`, or (in tests) `wake_expired`.
    ///
    /// Not done in the constructor, so that only a mounted filesystem runs the thread:
    /// `InMemoryFS::init` starts it and `drain` stops it.
    pub fn start(&self) {
        let mut thread = self.thread.lock().unwrap();
        if thread.is_some() {
            return;
        }
        let state = Arc::clone(&self.state);
        let clock = Arc::clone(&self.clock);
        let op_metrics = Arc::clone(&self.op_metrics);
        *thread = Some(
            std::thread::Builder::new()
                .name("appendfs-delayed-queue".to_string())
                .spawn(move || Self::worker_loop(state, clock, op_metrics))
                .expect("failed to spawn delayed response queue worker thread"),
        );
    }

    fn worker_loop(
        state_pair: Arc<(Mutex<QueueState>, Condvar)>,
        clock: Arc<dyn Clock>,
        op_metrics: Arc<FuseOpMetrics>,
    ) {
        let (lock, cvar) = &*state_pair;
        let mut state = lock.lock().unwrap();
        loop {
            if state.stopped {
                break;
            }

            let now = clock.monotonic();
            let mut to_reply = Vec::new();
            while let Some(top) = state.delayed.peek() {
                if top.deadline <= now {
                    to_reply.push(state.delayed.pop().unwrap());
                } else {
                    break;
                }
            }

            if !to_reply.is_empty() {
                drop(state);
                for item in to_reply {
                    dispatch_item(item, now, &op_metrics);
                }
                state = lock.lock().unwrap();
                continue;
            }

            let wait_timeout = state.delayed.peek().map(|item| item.deadline.saturating_sub(now));

            state = match wait_timeout {
                Some(timeout) => cvar.wait_timeout(state, timeout).unwrap().0,
                None => cvar.wait(state).unwrap(),
            };
        }
    }

    /// Base delay for soft backpressure formula.
    pub fn base_throttle_delay(&self) -> Duration {
        self.base_throttle_delay
    }

    /// Maximum delay for soft backpressure formula and timeout for stalls.
    pub fn max_throttle_delay(&self) -> Duration {
        self.max_throttle_delay
    }

    /// Computes the asymptotic delay for a given buffer/queue saturation ratio (0.0 to 1.0+).
    ///
    /// Formula:
    /// $$\text{delay} = \text{base\_delay} \times \frac{r^2}{1.0 - r}$$
    /// clamped to `max_throttle_delay`.
    pub fn compute_delay(&self, ratio: f64) -> Duration {
        if ratio <= 0.0 {
            return Duration::ZERO;
        }
        if ratio >= 1.0 {
            return self.max_throttle_delay;
        }
        let factor = (ratio * ratio) / (1.0 - ratio);
        let delay_nanos = (self.base_throttle_delay.as_nanos() as f64 * factor) as u128;
        Duration::from_nanos(delay_nanos as u64).min(self.max_throttle_delay)
    }

    /// Computes the throttling decision for an operation tier based on saturation ratio.
    pub fn calculate_tier_decision(&self, tier: OpTier, ratio: f64) -> ThrottleDecision {
        match tier {
            OpTier::ReadOnly => ThrottleDecision::NoDelay,
            OpTier::Write => {
                if ratio >= 1.0 {
                    ThrottleDecision::Stall
                } else {
                    let delay = self.compute_delay(ratio);
                    if delay.is_zero() {
                        ThrottleDecision::NoDelay
                    } else {
                        ThrottleDecision::Delay(delay)
                    }
                }
            }
            OpTier::Metadata => {
                const METADATA_THRESHOLD: f64 = 0.75;
                if ratio < METADATA_THRESHOLD {
                    ThrottleDecision::NoDelay
                } else if ratio >= 1.0 {
                    ThrottleDecision::Stall
                } else {
                    let normalized_r = (ratio - METADATA_THRESHOLD) / (1.0 - METADATA_THRESHOLD);
                    let delay = self.compute_delay(normalized_r);
                    if delay.is_zero() {
                        ThrottleDecision::NoDelay
                    } else {
                        ThrottleDecision::Delay(delay)
                    }
                }
            }
        }
    }

    /// Whether the flushing queue is currently saturated (at capacity).
    #[inline]
    pub fn is_flushing_saturated(&self) -> bool {
        self.flushing_saturated.load(Ordering::Relaxed)
    }

    /// The latest cached buffer/queue saturation ratio.
    #[inline]
    pub fn cached_saturation_ratio(&self) -> f64 {
        f64::from_bits(self.cached_ratio_bits.load(Ordering::Relaxed))
    }

    /// Updates the cached saturation status and ratio in a lock-free manner.
    pub fn update_saturation(&self, saturated: bool, ratio: f64) {
        self.cached_ratio_bits.store(ratio.to_bits(), Ordering::Relaxed);
        self.flushing_saturated.store(saturated, Ordering::Release);
    }

    /// Computes the throttling decision for an operation tier using cached saturation state without locks.
    #[inline]
    pub fn tier_decision(&self, tier: OpTier) -> ThrottleDecision {
        if tier == OpTier::ReadOnly || !self.flushing_saturated.load(Ordering::Acquire) {
            return ThrottleDecision::NoDelay;
        }
        let ratio = self.cached_saturation_ratio();
        self.calculate_tier_decision(tier, ratio)
    }

    /// Returns the metrics collector associated with this delayed response queue.
    pub fn op_metrics(&self) -> &Arc<FuseOpMetrics> {
        &self.op_metrics
    }

    /// Wakes up any operations waiting on capacity (e.g. after a batch is committed to disk).
    pub fn notify_capacity(&self) {
        let (lock, cvar) = &*self.state;
        let mut to_reply = Vec::new();
        {
            let mut state = lock.lock().unwrap();
            while let Some(item) = state.stalled.pop_front() {
                to_reply.push(item);
            }
            while let Some(item) = state.delayed.pop() {
                to_reply.push(item);
            }
            cvar.notify_all();
        }

        let now = self.clock.monotonic();
        for item in to_reply {
            dispatch_item(item, now, &self.op_metrics);
        }
    }

    /// Wakes and processes any delayed operations whose deadline has expired according to the clock.
    #[cfg(any(test, feature = "testing"))]
    pub fn wake_expired(&self) {
        let (lock, cvar) = &*self.state;
        let mut to_reply = Vec::new();
        let now = self.clock.monotonic();
        {
            let mut state = lock.lock().unwrap();
            while let Some(top) = state.delayed.peek() {
                if top.deadline <= now {
                    to_reply.push(state.delayed.pop().unwrap());
                } else {
                    break;
                }
            }
            cvar.notify_all();
        }
        for item in to_reply {
            dispatch_item(item, now, &self.op_metrics);
        }
    }

    /// Drains the queue immediately on unmount, waking all parked and delayed responses so they reply before exit.
    pub fn drain(&self) {
        let (lock, cvar) = &*self.state;
        let mut to_reply = Vec::new();
        {
            let mut state = lock.lock().unwrap();
            if state.stopped {
                return;
            }
            state.stopped = true;
            while let Some(item) = state.delayed.pop() {
                to_reply.push(item);
            }
            while let Some(item) = state.stalled.pop_front() {
                to_reply.push(item);
            }
            cvar.notify_all();
        }

        let now = self.clock.monotonic();
        for item in to_reply {
            dispatch_item(item, now, &self.op_metrics);
        }

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }

    /// Dispatches a FUSE response according to `decision`.
    ///
    /// - `ThrottleDecision::NoDelay` or zero duration: sent immediately.
    /// - `ThrottleDecision::Delay(d)`: delayed asynchronously, racing against capacity wakeup and unmount.
    /// - `ThrottleDecision::Stall`: stalled indefinitely, waking only when capacity is freed or unmount occurs.
    pub fn delay_response(
        &self,
        op: FuseOp,
        decision: ThrottleDecision,
        req: Request,
        res: Result<FuseResponse<'static>, FsError>,
    ) {
        match decision {
            ThrottleDecision::NoDelay => {
                reply_result(req, res);
            }
            ThrottleDecision::Delay(delay) if delay.is_zero() => {
                reply_result(req, res);
            }
            ThrottleDecision::Delay(delay) => {
                let (lock, cvar) = &*self.state;
                let mut state = lock.lock().unwrap();
                if state.stopped {
                    drop(state);
                    reply_result(req, res);
                    return;
                }
                let enqueued_at = self.clock.monotonic();
                let deadline = enqueued_at + delay;
                let id = state.next_id;
                state.next_id += 1;
                self.op_metrics.record_delayed_enqueue(op, decision);
                state.delayed.push(DelayedItem {
                    op,
                    deadline,
                    id,
                    req,
                    res,
                    enqueued_at,
                    is_stalled: false,
                });
                cvar.notify_one();
            }
            ThrottleDecision::Stall => {
                let (lock, _cvar) = &*self.state;
                let mut state = lock.lock().unwrap();
                if state.stopped {
                    drop(state);
                    reply_result(req, res);
                    return;
                }
                let enqueued_at = self.clock.monotonic();
                let id = state.next_id;
                state.next_id += 1;
                self.op_metrics.record_delayed_enqueue(op, decision);
                state.stalled.push_back(DelayedItem {
                    op,
                    deadline: Duration::MAX,
                    id,
                    req,
                    res,
                    enqueued_at,
                    is_stalled: true,
                });
            }
        }
    }
}

impl Drop for DelayedResponseQueue {
    fn drop(&mut self) {
        self.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asymptotic_delay_curve() {
        let clock = Arc::new(crate::clock::SystemClock);
        let metrics = Arc::new(FuseOpMetrics::new());
        let queue =
            DelayedResponseQueue::with_delays(clock, metrics, Duration::from_millis(10), Duration::from_secs(10));

        assert_eq!(queue.compute_delay(-0.1), Duration::ZERO);
        assert_eq!(queue.compute_delay(0.0), Duration::ZERO);
        assert_eq!(queue.compute_delay(0.5), Duration::from_millis(5));
        assert_eq!(queue.compute_delay(0.8), Duration::from_millis(32));
        assert_eq!(queue.compute_delay(1.0), Duration::from_secs(10));
        assert_eq!(queue.compute_delay(1.5), Duration::from_secs(10));
    }

    #[test]
    fn test_delayed_queue_drain_unblocks() {
        let clock = Arc::new(crate::clock::SystemClock);
        let metrics = Arc::new(FuseOpMetrics::new());
        let queue = DelayedResponseQueue::new(clock, metrics);

        assert_eq!(queue.op_metrics().total_active_delayed(), 0);
        assert_eq!(queue.op_metrics().total_delayed(), 0);

        queue.drain();
        assert_eq!(queue.op_metrics().total_active_delayed(), 0);
    }

    #[test]
    fn test_delayed_queue_dispatches_only_once_started() {
        let metrics = Arc::new(FuseOpMetrics::new());
        let queue = DelayedResponseQueue::new(Arc::new(crate::clock::SystemClock), metrics.clone());
        let delay = ThrottleDecision::Delay(Duration::from_millis(1));

        // No worker thread yet: an expired deadline stays queued.
        queue.delay_response(FuseOp::Write, delay, Request::new_mock(), Ok(FuseResponse::ok()));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(metrics.total_active_delayed(), 1);

        queue.start();
        assert!(
            crate::wait_until(|| metrics.total_active_delayed() == 0, Duration::from_secs(5)),
            "the started worker thread must dispatch the expired response"
        );

        queue.drain();
    }

    #[test]
    fn test_delayed_response_queue_drain_on_unmount() {
        let queue = DelayedResponseQueue::new(Arc::new(crate::clock::SystemClock), Arc::new(FuseOpMetrics::new()));

        let req = Request::new_mock();
        let response = Ok(FuseResponse::ok());
        // Schedule with Stall (hard indefinite wait)
        queue.delay_response(FuseOp::Write, ThrottleDecision::Stall, req, response);

        assert_eq!(queue.op_metrics().total_active_delayed(), 1);
        assert_eq!(queue.op_metrics().total_delayed(), 1);
        assert_eq!(queue.op_metrics().total_stalled(), 1);

        // Drain on unmount
        queue.drain();

        assert_eq!(queue.op_metrics().total_active_delayed(), 0);
    }

    #[test]
    fn test_delayed_queue_wake_stalled_waiter_on_batch_commit() {
        let mut fs = crate::fs::InMemoryFS::new();
        fs.max_buffer_size = 1000;
        fs.max_flush_queue_depth = 1;

        // Artificially set flushing_ops > 0 and staged_bytes >= max_staging_bytes
        {
            let mut inner = fs.inner.lock(crate::sync::OpTag::Other).unwrap();
            let completion = inner.live_completion.clone();
            inner.flushing.push_back(std::sync::Arc::new(crate::fs::FlushBatch {
                id: 1,
                entries: std::iter::once((
                    1,
                    crate::node::EntryDelta::Node(crate::node::NodeDelta::Directory(Default::default())),
                ))
                .collect(),
                arena: crate::fs::WriteArena::new(),
                bytes: 100,
                ops: 1,
                completion,
                reason: crate::fs::FlushReason::Threshold,
                frozen_at: std::time::Duration::ZERO,
                commit_timestamp: std::time::UNIX_EPOCH,
            }));
            inner.flushing_bytes = 100;
            inner.flushing_ops = 1;
            // Stage 1000 bytes -> hard stall
            inner.staged_bytes = 1000;
        }
        fs.refresh_pushback_saturation();

        let decision = fs.calculate_throttle(crate::operations::op::FuseOp::Write);
        assert_eq!(decision, ThrottleDecision::Stall);

        // Dispatch delayed response via dispatch_reply
        let req = Request::new_mock();
        let response = Ok(FuseResponse::write(100));
        let start = fs.clock.monotonic();
        fs.dispatch_reply(req, crate::operations::op::FuseOp::Write, response, start);

        // It should now be queued, active, and tracked in op_metrics
        assert_eq!(fs.op_metrics.total_active_delayed(), 1);
        assert_eq!(fs.op_metrics.total_delayed(), 1);
        assert_eq!(fs.op_metrics.total_stalled(), 1);
        assert_eq!(fs.op_metrics.calls(crate::operations::op::FuseOp::Write), 1);
        assert_eq!(fs.op_metrics.stalled(crate::operations::op::FuseOp::Write), 1);

        // Pop the batch -> this notifies capacity immediately
        let _ = fs.pop_flushing_batch();

        // Hard-stalled waiter should have been unblocked and finished immediately!
        assert_eq!(fs.op_metrics.total_active_delayed(), 0);
    }

    #[test]
    fn test_delayed_queue_aggregate_latency_and_runtime_status() {
        use crate::clock::AdvancingClock;
        use crate::stats::format_runtime_status;
        use std::time::SystemTime;

        let mock_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let adv_clock = Arc::new(AdvancingClock::new(mock_time));
        let mut fs = crate::fs::InMemoryFS::with_clock(adv_clock.clone());
        fs.max_buffer_size = 1000;
        fs.max_flush_queue_depth = 1;

        // Initially, zero delay
        assert_eq!(fs.op_metrics.total_delay_duration(), Duration::ZERO);
        assert_eq!(fs.op_metrics.avg_delay_duration(), Duration::ZERO);

        // Dispatch a normal request with start time to record op execution latency
        let req = Request::new_mock();
        let resp = Ok(FuseResponse::ok());
        let start = fs.clock.monotonic();
        adv_clock.advance(Duration::from_millis(5));

        fs.dispatch_reply(req, crate::operations::op::FuseOp::Write, resp, start);
        assert_eq!(fs.op_metrics.calls(crate::operations::op::FuseOp::Write), 1);
        assert_eq!(
            fs.op_metrics.avg_latency(crate::operations::op::FuseOp::Write),
            Duration::from_millis(5)
        );

        // Delay a response to verify aggregate backpressure delay tracking
        let req2 = Request::new_mock();
        let resp2 = Ok(FuseResponse::write(50));
        fs.delayed_queue.delay_response(
            crate::operations::op::FuseOp::Write,
            ThrottleDecision::Delay(Duration::from_millis(20)),
            req2,
            resp2,
        );
        assert_eq!(fs.op_metrics.total_active_delayed(), 1);
        assert_eq!(fs.op_metrics.total_delayed(), 1);

        // Advance mock clock to simulate the passage of delay time deterministically
        adv_clock.advance(Duration::from_millis(20));
        fs.delayed_queue.wake_expired();

        assert_eq!(fs.op_metrics.total_active_delayed(), 0);
        assert_eq!(fs.op_metrics.total_delay_duration(), Duration::from_millis(20));
        assert_eq!(fs.op_metrics.avg_delay_duration(), Duration::from_millis(20));
        assert_eq!(fs.op_metrics.throttled(crate::operations::op::FuseOp::Write), 1);
        assert_eq!(
            fs.op_metrics
                .avg_throttled_duration(crate::operations::op::FuseOp::Write),
            Duration::from_millis(20)
        );

        // Check runtime status text
        let status = format_runtime_status(&fs);
        assert!(status.contains("[Pushback Throttling]"));
        assert!(status.contains("Total Throttled:    1"));
        assert!(status.contains("Total Delay Time:"));
        assert!(status.contains("Avg Delay / Waiter:"));
        assert!(status.contains("[FUSE Operations]"));
        assert!(status.contains("AVG LAT"));
        assert!(status.contains("MAX LAT"));
        assert!(status.contains("AVG THROTTLED"));
    }

    #[test]
    fn test_delayed_queue_early_capacity_notification_records_actual_wait() {
        use crate::clock::AdvancingClock;
        use std::time::SystemTime;

        let mock_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = Arc::new(AdvancingClock::new(mock_time));
        let metrics = Arc::new(FuseOpMetrics::new());
        let queue = DelayedResponseQueue::new(clock.clone(), metrics.clone());

        let req = Request::new_mock();
        let resp = Ok(FuseResponse::write(42));

        // Decision was to sleep for 50ms (e.g. calculated delay)
        queue.delay_response(
            FuseOp::Write,
            ThrottleDecision::Delay(Duration::from_millis(50)),
            req,
            resp,
        );

        assert_eq!(metrics.total_active_delayed(), 1);

        // Advance clock only 10ms before a background flush commits and frees capacity
        clock.advance(Duration::from_millis(10));
        queue.notify_capacity();

        assert_eq!(metrics.total_active_delayed(), 0);
        // Verify actual time spent waiting (10ms) was captured, NOT the decided sleep time (50ms)
        assert_eq!(metrics.avg_throttled_duration(FuseOp::Write), Duration::from_millis(10));
        assert_eq!(metrics.total_delay_duration(), Duration::from_millis(10));
    }
}
