//! Tests for FUSE operation categorization, latency tracking, and operational telemetry.

use appendfs::TestFs;
use appendfs::clock::{AdvancingClock, MockClock};
use appendfs::operations::op::{ALL_FUSE_OPS, FUSE_OP_COUNT, FuseOp, FuseOpMetrics, OpTier};
use appendfs::shim::{DeferredResult, DeferredToken, FuseResponse, Request};
use appendfs::stats::format_runtime_status;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn mock_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn test_fuse_op_exhaustive_properties() {
    assert_eq!(ALL_FUSE_OPS.len(), FUSE_OP_COUNT);
    assert_eq!(FUSE_OP_COUNT, 32);

    for (idx, op) in ALL_FUSE_OPS.iter().enumerate() {
        assert_eq!(op.index(), idx);
        assert!(!op.as_str().is_empty());
    }

    // Verify mutating classification
    assert!(FuseOp::Write.is_mutating());
    assert!(FuseOp::Create.is_mutating());
    assert!(FuseOp::Mkdir.is_mutating());
    assert!(FuseOp::Unlink.is_mutating());
    assert!(FuseOp::Rmdir.is_mutating());
    assert!(FuseOp::Rename.is_mutating());
    assert!(FuseOp::Symlink.is_mutating());
    assert!(FuseOp::Link.is_mutating());
    assert!(FuseOp::Setattr.is_mutating());
    assert!(FuseOp::Setxattr.is_mutating());
    assert!(FuseOp::Removexattr.is_mutating());
    assert!(FuseOp::Fallocate.is_mutating());
    assert!(FuseOp::CopyFileRange.is_mutating());

    // Verify read classification
    assert!(FuseOp::Read.is_read());
    assert!(FuseOp::Readdir.is_read());
    assert!(FuseOp::Readdirplus.is_read());
    assert!(FuseOp::Lookup.is_read());
    assert!(FuseOp::Getattr.is_read());
    assert!(FuseOp::Readlink.is_read());
    assert!(!FuseOp::Read.is_mutating());

    // Verify tier categorization
    assert_eq!(FuseOp::Write.tier(), OpTier::Write);
    assert_eq!(FuseOp::Fallocate.tier(), OpTier::Write);
    assert_eq!(FuseOp::CopyFileRange.tier(), OpTier::Write);
    assert_eq!(FuseOp::Create.tier(), OpTier::Metadata);
    assert_eq!(FuseOp::Read.tier(), OpTier::ReadOnly);
}

#[test]
fn test_fuse_op_metrics_latency_and_aggregation() {
    let metrics = FuseOpMetrics::new();
    assert_eq!(metrics.total_calls(), 0);
    assert_eq!(metrics.total_active(), 0);
    assert_eq!(metrics.total_duration(), Duration::ZERO);
    assert_eq!(metrics.calls(FuseOp::Lookup), 0);
    assert_eq!(metrics.active(FuseOp::Lookup), 0);
    assert_eq!(metrics.avg_latency(FuseOp::Lookup), Duration::ZERO);
    assert_eq!(metrics.max_latency(FuseOp::Lookup), Duration::ZERO);

    // Record calls and durations for Lookup
    metrics.record_call(FuseOp::Lookup);
    assert_eq!(metrics.active(FuseOp::Lookup), 1);
    assert_eq!(metrics.total_active(), 1);
    metrics.record_duration(FuseOp::Lookup, Duration::from_micros(20));
    assert_eq!(metrics.active(FuseOp::Lookup), 0);
    assert_eq!(metrics.total_active(), 0);

    metrics.record_call(FuseOp::Lookup);
    metrics.record_duration(FuseOp::Lookup, Duration::from_micros(60));

    assert_eq!(metrics.calls(FuseOp::Lookup), 2);
    assert_eq!(metrics.avg_latency(FuseOp::Lookup), Duration::from_micros(40));
    assert_eq!(metrics.max_latency(FuseOp::Lookup), Duration::from_micros(60));

    // Record for Write
    metrics.record_call(FuseOp::Write);
    assert_eq!(metrics.active(FuseOp::Write), 1);
    assert_eq!(metrics.total_active(), 1);
    metrics.record_duration(FuseOp::Write, Duration::from_micros(100));
    assert_eq!(metrics.active(FuseOp::Write), 0);
    assert_eq!(metrics.total_active(), 0);

    assert_eq!(metrics.calls(FuseOp::Write), 1);
    assert_eq!(metrics.avg_latency(FuseOp::Write), Duration::from_micros(100));
    assert_eq!(metrics.max_latency(FuseOp::Write), Duration::from_micros(100));

    assert_eq!(metrics.total_calls(), 3);
    assert_eq!(metrics.total_duration(), Duration::from_micros(180));
}

#[test]
fn test_dispatch_reply_synchronous_latency() {
    let clock = Arc::new(AdvancingClock::new(mock_time()));
    let fs = TestFs::builder().clock(clock.clone()).build().fs;

    let req = Request::new_mock();
    let start = fs.clock.monotonic();
    clock.advance(Duration::from_millis(12));

    fs.dispatch_reply(req, FuseOp::Getattr, Ok(FuseResponse::ok()), start);

    assert_eq!(fs.op_metrics.calls(FuseOp::Getattr), 1);
    assert_eq!(fs.op_metrics.active(FuseOp::Getattr), 0);
    assert_eq!(fs.op_metrics.avg_latency(FuseOp::Getattr), Duration::from_millis(12));
    assert_eq!(fs.op_metrics.max_latency(FuseOp::Getattr), Duration::from_millis(12));
}

#[test]
fn test_dispatch_reply_deferred_latency() {
    let clock = Arc::new(AdvancingClock::new(mock_time()));
    let fs = TestFs::builder().clock(clock.clone()).build().fs;

    let req = Request::new_mock();
    let (token, receiver) = DeferredToken::new();
    let start = fs.clock.monotonic();

    // Dispatch pending deferred operation
    fs.dispatch_reply(req, FuseOp::Fsync, DeferredResult::deferred(receiver), start);

    // Initial check before async completion: call counted and marked active, but duration not yet recorded
    assert_eq!(fs.op_metrics.calls(FuseOp::Fsync), 1);
    assert_eq!(fs.op_metrics.active(FuseOp::Fsync), 1);
    assert_eq!(fs.op_metrics.total_active(), 1);
    assert_eq!(fs.op_metrics.avg_latency(FuseOp::Fsync), Duration::ZERO);

    // Simulate async flush execution duration
    clock.advance(Duration::from_millis(25));
    token.complete(Ok(FuseResponse::ok()));

    // Now duration should be measured and recorded accurately, and active count decremented
    assert_eq!(fs.op_metrics.calls(FuseOp::Fsync), 1);
    assert_eq!(fs.op_metrics.active(FuseOp::Fsync), 0);
    assert_eq!(fs.op_metrics.total_active(), 0);
    assert_eq!(fs.op_metrics.avg_latency(FuseOp::Fsync), Duration::from_millis(25));
    assert_eq!(fs.op_metrics.max_latency(FuseOp::Fsync), Duration::from_millis(25));
}

#[test]
fn test_runtime_status_fuse_operations_formatting() {
    let clock = Arc::new(MockClock(mock_time()));
    let fs = TestFs::builder().clock(clock).build().fs;

    // Fresh FS has no op calls -> no [FUSE Operations] table
    let fresh_status = format_runtime_status(&fs);
    assert!(!fresh_status.contains("[FUSE Operations]"));

    // Record an op
    let req = Request::new_mock();
    fs.dispatch_reply(req, FuseOp::Lookup, Ok(FuseResponse::ok()), Duration::ZERO);

    let status = format_runtime_status(&fs);
    assert!(status.contains("[FUSE Operations]"));
    assert!(status.contains("OPERATION"));
    assert!(status.contains("ACTIVE"));
    assert!(status.contains("CALLS"));
    assert!(status.contains("AVG THROTTLED"));
    assert!(status.contains("AVG LAT"));
    assert!(status.contains("MAX LAT"));
    assert!(status.contains("lookup"));
}

#[test]
fn test_runtime_status_fuse_operations_throttled_formatting() {
    let clock = Arc::new(AdvancingClock::new(mock_time()));
    let fs = TestFs::builder().clock(clock.clone()).build().fs;

    // Record an unthrottled lookup
    let req1 = Request::new_mock();
    fs.dispatch_reply(req1, FuseOp::Lookup, Ok(FuseResponse::ok()), Duration::ZERO);

    // Record two writes, one of which was throttled
    let req2 = Request::new_mock();
    let start2 = fs.clock.monotonic();
    clock.advance(Duration::from_millis(5));
    fs.dispatch_reply(req2, FuseOp::Write, Ok(FuseResponse::write(10)), start2);

    let req3 = Request::new_mock();
    let start3 = fs.clock.monotonic();
    clock.advance(Duration::from_millis(5));
    // Delay via delayed_queue (which automatically records throttle and delay queue metrics)
    fs.op_metrics.record_call(FuseOp::Write);
    let dur3 = fs.clock.elapsed_since(start3);
    fs.op_metrics.record_duration(FuseOp::Write, dur3);
    fs.delayed_queue.delay_response(
        FuseOp::Write,
        appendfs::operations::op::ThrottleDecision::Delay(Duration::from_millis(15)),
        req3,
        Ok(FuseResponse::write(20)),
    );

    // Advance clock and wake expired
    clock.advance(Duration::from_millis(15));
    fs.delayed_queue.wake_expired();

    assert_eq!(fs.op_metrics.calls(FuseOp::Write), 2);
    assert_eq!(fs.op_metrics.throttled(FuseOp::Write), 1);
    assert_eq!(
        fs.op_metrics.avg_throttled_duration(FuseOp::Write),
        Duration::from_millis(15)
    );

    let status = format_runtime_status(&fs);
    assert!(status.contains("[FUSE Operations]"));
    assert!(status.contains("AVG THROTTLED"));
    // Verify 15.00 ms is in the formatted output for the throttled write
    assert!(status.contains("15.00 ms"));
}
