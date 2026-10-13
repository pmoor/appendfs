use appendfs::TestFs;
use appendfs::clock::MockClock;
use appendfs::fs::{DelayedResponseQueue, OpTier};
use appendfs::sync::OpTag;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn mock_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn test_asymptotic_delay_mathematics() {
    let clock = Arc::new(MockClock(mock_time()));
    let metrics = Arc::new(appendfs::operations::op::FuseOpMetrics::new());
    let queue = DelayedResponseQueue::with_delays(clock, metrics, Duration::from_millis(10), Duration::from_secs(10));
    let max = queue.max_throttle_delay();

    // Negative or 0 ratio: zero delay
    assert_eq!(queue.compute_delay(-0.5), Duration::ZERO);
    assert_eq!(queue.compute_delay(0.0), Duration::ZERO);

    // At ratio 0.5: delay = 10ms * (0.25 / 0.5) = 5ms
    assert_eq!(queue.compute_delay(0.5), Duration::from_millis(5));

    // At ratio 0.8: delay = 10ms * (0.64 / 0.2) = 32ms
    assert_eq!(queue.compute_delay(0.8), Duration::from_millis(32));

    // At ratio 0.9: delay = 10ms * (0.81 / 0.1) = 81ms
    assert_eq!(queue.compute_delay(0.9), Duration::from_millis(81));

    // At ratio 0.99: delay = 10ms * (0.9801 / 0.01) = 980.1ms
    let d99 = queue.compute_delay(0.99);
    assert!(d99 >= Duration::from_millis(970) && d99 <= Duration::from_millis(990));

    // At or above 1.0: clamped to max (10s)
    assert_eq!(queue.compute_delay(1.0), max);
    assert_eq!(queue.compute_delay(2.0), max);
}

#[test]
fn test_tier_throttling_decision_logic() {
    let clock = Arc::new(MockClock(mock_time()));
    let mut fs = TestFs::builder().clock(clock).build().fs;
    fs.max_buffer_size = 1000;
    fs.max_staged_ops = 100;
    fs.max_flush_queue_depth = 1;

    // 1. When flushing is not saturated: delay is always zero for all tiers
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::ReadOnly),
        appendfs::ThrottleDecision::NoDelay
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Metadata),
        appendfs::ThrottleDecision::NoDelay
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write),
        appendfs::ThrottleDecision::NoDelay
    );

    // 2. Artificially saturate flushing queue by pushing a dummy batch
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        let completion = inner.live_completion.clone();
        inner.flushing.push_back(Arc::new(appendfs::fs::FlushBatch {
            id: 1,
            entries: std::iter::once((
                1,
                appendfs::node::EntryDelta::Node(appendfs::node::NodeDelta::Directory(Default::default())),
            ))
            .collect(),
            arena: appendfs::fs::WriteArena::new(),
            bytes: 100,
            ops: 1,
            completion,
            reason: appendfs::fs::FlushReason::Threshold,
            frozen_at: std::time::Duration::ZERO,
            commit_timestamp: std::time::UNIX_EPOCH,
        }));
        inner.flushing_bytes = 100;
        inner.flushing_ops = 1;
    }
    fs.refresh_pushback_saturation();

    // Now flushing queue depth is 1 >= max_flush_queue_depth (saturated).
    // Staged bytes = 0, staged ops = 0.
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::ReadOnly),
        appendfs::ThrottleDecision::NoDelay
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Metadata),
        appendfs::ThrottleDecision::NoDelay
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write),
        appendfs::ThrottleDecision::NoDelay
    );

    // 3. Stage 500 bytes (ratio = 0.5)
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        inner.staged_bytes = 500;
        inner.staged_ops = 10;
    }
    fs.refresh_pushback_saturation();
    // Write tier should experience delay (r=0.5 -> 5ms)
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write),
        appendfs::ThrottleDecision::Delay(Duration::from_millis(5))
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write).delay(),
        Duration::from_millis(5)
    );
    // Metadata tier should be 0 because r < 0.75
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Metadata),
        appendfs::ThrottleDecision::NoDelay
    );
    // ReadOnly tier is always zero
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::ReadOnly),
        appendfs::ThrottleDecision::NoDelay
    );

    // 4. Stage 800 bytes (ratio = 0.8)
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        inner.staged_bytes = 800;
        inner.staged_ops = 20;
    }
    fs.refresh_pushback_saturation();
    // Write tier: r=0.8 -> 32ms
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write),
        appendfs::ThrottleDecision::Delay(Duration::from_millis(32))
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write).delay(),
        Duration::from_millis(32)
    );
    // Metadata tier: normalized_r = (0.8 - 0.75) / 0.25 = 0.2 -> delay > 0
    let meta_decision = fs.calculate_throttle_for_tier(OpTier::Metadata);
    assert!(meta_decision.is_throttled());
    assert!(meta_decision.delay() > Duration::ZERO);
    assert!(meta_decision.delay() < fs.calculate_throttle_for_tier(OpTier::Write).delay());

    // 5. Stage 1000 bytes (ratio = 1.0)
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        inner.staged_bytes = 1000;
    }
    fs.refresh_pushback_saturation();
    // Both Write and Metadata enter hard stall (Stall)
    assert_eq!(
        fs.calculate_throttle(appendfs::FuseOp::Write),
        appendfs::ThrottleDecision::Stall
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Write),
        appendfs::ThrottleDecision::Stall
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::Metadata),
        appendfs::ThrottleDecision::Stall
    );
    // ReadOnly tier is still zero / NoDelay
    assert_eq!(
        fs.calculate_throttle(appendfs::FuseOp::Read),
        appendfs::ThrottleDecision::NoDelay
    );
    assert_eq!(
        fs.calculate_throttle_for_tier(OpTier::ReadOnly),
        appendfs::ThrottleDecision::NoDelay
    );
}

#[test]
fn test_fuse_op_declarative_classification_and_metrics() {
    use appendfs::{ALL_FUSE_OPS, FUSE_OP_COUNT, FuseOp, FuseOpMetrics, ThrottleDecision};

    assert_eq!(ALL_FUSE_OPS.len(), FUSE_OP_COUNT);
    assert_eq!(FUSE_OP_COUNT, 32);

    // Verify tiers
    assert_eq!(FuseOp::Write.tier(), OpTier::Write);
    assert_eq!(FuseOp::Fallocate.tier(), OpTier::Write);
    assert!(FuseOp::Write.is_mutating());
    assert!(FuseOp::Fallocate.is_mutating());

    assert_eq!(FuseOp::Create.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Mkdir.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Unlink.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Rename.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Setattr.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Setxattr.tier(), OpTier::Metadata);
    assert!(FuseOp::Mkdir.is_mutating());

    assert_eq!(FuseOp::Read.tier(), OpTier::ReadOnly);
    assert_eq!(FuseOp::Lookup.tier(), OpTier::ReadOnly);
    assert_eq!(FuseOp::Getattr.tier(), OpTier::ReadOnly);
    assert_eq!(FuseOp::Readdir.tier(), OpTier::ReadOnly);
    assert!(!FuseOp::Read.is_mutating());
    assert!(FuseOp::Read.is_read());
    assert!(FuseOp::Readdir.is_read());
    assert!(FuseOp::Getattr.is_read());

    // Verify metrics recording
    let metrics = FuseOpMetrics::new();
    assert_eq!(metrics.total_calls(), 0);
    assert_eq!(metrics.total_throttled(), 0);
    assert_eq!(metrics.total_stalled(), 0);

    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::Delay(Duration::from_millis(15)));
    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::Stall);
    metrics.record_call(FuseOp::Read);
    metrics.record_throttle(FuseOp::Read, ThrottleDecision::NoDelay);

    assert_eq!(metrics.calls(FuseOp::Write), 2);
    assert_eq!(metrics.throttled(FuseOp::Write), 1);
    assert_eq!(metrics.stalled(FuseOp::Write), 1);

    assert_eq!(metrics.calls(FuseOp::Read), 1);
    assert_eq!(metrics.throttled(FuseOp::Read), 0);
    assert_eq!(metrics.stalled(FuseOp::Read), 0);

    assert_eq!(metrics.total_calls(), 3);
    assert_eq!(metrics.total_throttled(), 1);
    assert_eq!(metrics.total_stalled(), 1);
}

#[test]
fn test_delayed_response_queue_stall_calculation() {
    let clock = Arc::new(MockClock(mock_time()));
    let mut fs = TestFs::builder().clock(clock).build().fs;
    fs.max_buffer_size = 1000;
    fs.max_flush_queue_depth = 1;

    // Saturate flushing queue
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        let completion = inner.live_completion.clone();
        inner.flushing.push_back(Arc::new(appendfs::fs::FlushBatch {
            id: 1,
            entries: std::iter::once((
                1,
                appendfs::node::EntryDelta::Node(appendfs::node::NodeDelta::Directory(Default::default())),
            ))
            .collect(),
            arena: appendfs::fs::WriteArena::new(),
            bytes: 100,
            ops: 1,
            completion,
            reason: appendfs::fs::FlushReason::Threshold,
            frozen_at: std::time::Duration::ZERO,
            commit_timestamp: std::time::UNIX_EPOCH,
        }));
        inner.flushing_bytes = 100;
        inner.flushing_ops = 1;
        // Stage 1000 bytes -> hard stall
        inner.staged_bytes = 1000;
    }
    fs.refresh_pushback_saturation();

    let decision = fs.calculate_throttle(appendfs::FuseOp::Write);
    assert_eq!(decision, appendfs::ThrottleDecision::Stall);
}

#[test]
fn test_fuse_op_latency_metrics() {
    use appendfs::{FuseOp, FuseOpMetrics};

    let metrics = FuseOpMetrics::new();
    assert_eq!(metrics.avg_latency(FuseOp::Fsync), Duration::ZERO);
    assert_eq!(metrics.max_latency(FuseOp::Fsync), Duration::ZERO);
    assert_eq!(metrics.total_duration(), Duration::ZERO);

    metrics.record_call(FuseOp::Fsync);
    metrics.record_duration(FuseOp::Fsync, Duration::from_millis(10));
    metrics.record_call(FuseOp::Fsync);
    metrics.record_duration(FuseOp::Fsync, Duration::from_millis(30));

    assert_eq!(metrics.calls(FuseOp::Fsync), 2);
    assert_eq!(metrics.total_duration(), Duration::from_millis(40));
    assert_eq!(metrics.avg_latency(FuseOp::Fsync), Duration::from_millis(20));
    assert_eq!(metrics.max_latency(FuseOp::Fsync), Duration::from_millis(30));
}

#[test]
fn test_fuse_op_throttled_duration_metrics() {
    use appendfs::{FuseOp, FuseOpMetrics, ThrottleDecision};

    let metrics = FuseOpMetrics::new();
    assert_eq!(metrics.throttled(FuseOp::Write), 0);
    assert_eq!(metrics.throttled_duration(FuseOp::Write), Duration::ZERO);
    assert_eq!(metrics.avg_throttled_duration(FuseOp::Write), Duration::ZERO);
    assert_eq!(metrics.total_throttled_duration(), Duration::ZERO);

    // Record calls: 4 calls to Write, but only 2 were throttled
    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::NoDelay);
    metrics.record_duration(FuseOp::Write, Duration::from_millis(5));

    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::Delay(Duration::from_millis(50)));
    metrics.record_duration(FuseOp::Write, Duration::from_millis(5));
    metrics.record_throttled_duration(FuseOp::Write, Duration::from_millis(20));

    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::Delay(Duration::from_millis(80)));
    metrics.record_duration(FuseOp::Write, Duration::from_millis(5));
    metrics.record_throttled_duration(FuseOp::Write, Duration::from_millis(40));

    metrics.record_call(FuseOp::Write);
    metrics.record_throttle(FuseOp::Write, ThrottleDecision::NoDelay);
    metrics.record_duration(FuseOp::Write, Duration::from_millis(5));

    assert_eq!(metrics.calls(FuseOp::Write), 4);
    assert_eq!(metrics.throttled(FuseOp::Write), 2);
    assert_eq!(metrics.throttled_duration(FuseOp::Write), Duration::from_millis(60));
    // Average throttled duration when actually throttled: 60ms / 2 = 30ms (NOT 60ms / 4 = 15ms)
    assert_eq!(metrics.avg_throttled_duration(FuseOp::Write), Duration::from_millis(30));
    assert_eq!(metrics.total_throttled_duration(), Duration::from_millis(60));

    // Another op (Lookup) that had no throttles
    metrics.record_call(FuseOp::Lookup);
    metrics.record_throttle(FuseOp::Lookup, ThrottleDecision::NoDelay);
    assert_eq!(metrics.avg_throttled_duration(FuseOp::Lookup), Duration::ZERO);
}

#[test]
fn test_fs_destroy_drains_stalled_waiters_and_completes_cleanly() {
    let clock = Arc::new(MockClock(mock_time()));
    let mut fs = TestFs::builder().clock(clock).build().fs;
    fs.max_buffer_size = 1000;
    fs.max_flush_queue_depth = 1;

    // Saturate flushing queue and staged bytes -> hard stall
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        let completion = inner.live_completion.clone();
        inner.flushing.push_back(Arc::new(appendfs::fs::FlushBatch {
            id: 1,
            entries: std::iter::once((
                1,
                appendfs::node::EntryDelta::Node(appendfs::node::NodeDelta::Directory(Default::default())),
            ))
            .collect(),
            arena: appendfs::fs::WriteArena::new(),
            bytes: 100,
            ops: 1,
            completion,
            reason: appendfs::fs::FlushReason::Threshold,
            frozen_at: std::time::Duration::ZERO,
            commit_timestamp: std::time::UNIX_EPOCH,
        }));
        inner.flushing_bytes = 100;
        inner.flushing_ops = 1;
        inner.staged_bytes = 1000;
    }
    fs.refresh_pushback_saturation();

    let decision = fs.calculate_throttle(appendfs::FuseOp::Write);
    assert_eq!(decision, appendfs::ThrottleDecision::Stall);

    // Dispatch a stalled reply via dispatch_reply
    let req = appendfs::shim::Request::new_mock();
    let response = Ok(appendfs::shim::FuseResponse::write(100));
    let start = fs.clock.monotonic();
    fs.dispatch_reply(req, appendfs::FuseOp::Write, response, start);

    assert_eq!(fs.op_metrics.total_active_delayed(), 1);
    assert_eq!(fs.op_metrics.total_stalled(), 1);

    // destroy() must drain the delayed queue before drain_async_ops(),
    // allowing the stalled writer to complete rather than deadlocking unmount.
    fs.destroy();

    assert_eq!(fs.op_metrics.total_active_delayed(), 0);
}

#[test]
fn test_calculate_throttle_is_completely_lock_free() {
    let clock = Arc::new(MockClock(mock_time()));
    let mut fs = TestFs::builder().clock(clock).build().fs;
    fs.max_buffer_size = 1000;
    fs.max_flush_queue_depth = 1;

    // 1. In unsaturated state, verify 0 lock acquisitions on inner
    let lock_count_before = fs.inner.lock_count();
    for _ in 0..100 {
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::ReadOnly),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::Metadata),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::Write),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle(appendfs::FuseOp::Write),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle(appendfs::FuseOp::Read),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(fs.calculate_throttle(appendfs::FuseOp::Write).delay(), Duration::ZERO);
        assert!(!fs.delayed_queue.is_flushing_saturated());
        assert_eq!(fs.delayed_queue.cached_saturation_ratio(), 0.0);
    }
    assert_eq!(
        fs.inner.lock_count(),
        lock_count_before,
        "calculate_throttle queries in unsaturated state must be 100% lock-free"
    );

    // 2. Artificially saturate and stage data
    {
        let mut inner = fs.inner.lock(OpTag::Test).unwrap();
        let completion = inner.live_completion.clone();
        inner.flushing.push_back(Arc::new(appendfs::fs::FlushBatch {
            id: 1,
            entries: std::iter::once((
                1,
                appendfs::node::EntryDelta::Node(appendfs::node::NodeDelta::Directory(Default::default())),
            ))
            .collect(),
            arena: appendfs::fs::WriteArena::new(),
            bytes: 100,
            ops: 1,
            completion,
            reason: appendfs::fs::FlushReason::Threshold,
            frozen_at: std::time::Duration::ZERO,
            commit_timestamp: std::time::UNIX_EPOCH,
        }));
        inner.flushing_bytes = 100;
        inner.flushing_ops = 1;
        inner.staged_bytes = 500; // ratio = 0.5
    }
    fs.refresh_pushback_saturation();

    // 3. In saturated state, verify still 0 lock acquisitions on inner
    let lock_count_before = fs.inner.lock_count();
    for _ in 0..100 {
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::ReadOnly),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::Metadata),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle_for_tier(OpTier::Write),
            appendfs::ThrottleDecision::Delay(Duration::from_millis(5))
        );
        assert_eq!(
            fs.calculate_throttle(appendfs::FuseOp::Write),
            appendfs::ThrottleDecision::Delay(Duration::from_millis(5))
        );
        assert_eq!(
            fs.calculate_throttle(appendfs::FuseOp::Read),
            appendfs::ThrottleDecision::NoDelay
        );
        assert_eq!(
            fs.calculate_throttle(appendfs::FuseOp::Write).delay(),
            Duration::from_millis(5)
        );
        assert!(fs.delayed_queue.is_flushing_saturated());
        assert_eq!(fs.delayed_queue.cached_saturation_ratio(), 0.5);
    }
    assert_eq!(
        fs.inner.lock_count(),
        lock_count_before,
        "calculate_throttle queries in saturated state must be 100% lock-free"
    );
}
