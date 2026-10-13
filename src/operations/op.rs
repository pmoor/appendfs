//! Exhaustive FUSE operation categorization, operational tiers, and runtime metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Exhaustive enum of all 32 FUSE operations implemented by AppendFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FuseOp {
    Lookup = 0,
    Getattr = 1,
    Opendir = 2,
    Readdir = 3,
    Readdirplus = 4,
    Read = 5,
    Open = 6,
    Write = 7,
    Setattr = 8,
    Create = 9,
    Mknod = 10,
    Unlink = 11,
    Mkdir = 12,
    Rmdir = 13,
    Symlink = 14,
    Readlink = 15,
    Rename = 16,
    Link = 17,
    Fsync = 18,
    Fallocate = 19,
    Release = 20,
    Releasedir = 21,
    Fsyncdir = 22,
    Statfs = 23,
    Flock = 24,
    Getlk = 25,
    Setlk = 26,
    Getxattr = 27,
    Setxattr = 28,
    Listxattr = 29,
    Removexattr = 30,
    CopyFileRange = 31,
}

pub const FUSE_OP_COUNT: usize = 32;

pub const ALL_FUSE_OPS: [FuseOp; FUSE_OP_COUNT] = [
    FuseOp::Lookup,
    FuseOp::Getattr,
    FuseOp::Opendir,
    FuseOp::Readdir,
    FuseOp::Readdirplus,
    FuseOp::Read,
    FuseOp::Open,
    FuseOp::Write,
    FuseOp::Setattr,
    FuseOp::Create,
    FuseOp::Mknod,
    FuseOp::Unlink,
    FuseOp::Mkdir,
    FuseOp::Rmdir,
    FuseOp::Symlink,
    FuseOp::Readlink,
    FuseOp::Rename,
    FuseOp::Link,
    FuseOp::Fsync,
    FuseOp::Fallocate,
    FuseOp::Release,
    FuseOp::Releasedir,
    FuseOp::Fsyncdir,
    FuseOp::Statfs,
    FuseOp::Flock,
    FuseOp::Getlk,
    FuseOp::Setlk,
    FuseOp::Getxattr,
    FuseOp::Setxattr,
    FuseOp::Listxattr,
    FuseOp::Removexattr,
    FuseOp::CopyFileRange,
];

impl FuseOp {
    /// Zero-based index of this FUSE operation.
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Operation name as a static string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Getattr => "getattr",
            Self::Opendir => "opendir",
            Self::Readdir => "readdir",
            Self::Readdirplus => "readdirplus",
            Self::Read => "read",
            Self::Open => "open",
            Self::Write => "write",
            Self::Setattr => "setattr",
            Self::Create => "create",
            Self::Mknod => "mknod",
            Self::Unlink => "unlink",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::Symlink => "symlink",
            Self::Readlink => "readlink",
            Self::Rename => "rename",
            Self::Link => "link",
            Self::Fsync => "fsync",
            Self::Fallocate => "fallocate",
            Self::Release => "release",
            Self::Releasedir => "releasedir",
            Self::Fsyncdir => "fsyncdir",
            Self::Statfs => "statfs",
            Self::Flock => "flock",
            Self::Getlk => "getlk",
            Self::Setlk => "setlk",
            Self::Getxattr => "getxattr",
            Self::Setxattr => "setxattr",
            Self::Listxattr => "listxattr",
            Self::Removexattr => "removexattr",
            Self::CopyFileRange => "copy_file_range",
        }
    }

    /// Classification into operational pushback throttling tier.
    #[inline]
    pub const fn tier(self) -> OpTier {
        match self {
            // Read-Only: Never delayed to prevent response queue deadlocks and starvation
            Self::Lookup
            | Self::Getattr
            | Self::Opendir
            | Self::Readdir
            | Self::Readdirplus
            | Self::Read
            | Self::Open
            | Self::Readlink
            | Self::Statfs
            | Self::Getxattr
            | Self::Listxattr => OpTier::ReadOnly,

            // Metadata: Delays only when staging is heavily saturated (ratio >= 0.75)
            Self::Setattr
            | Self::Create
            | Self::Mknod
            | Self::Unlink
            | Self::Mkdir
            | Self::Rmdir
            | Self::Symlink
            | Self::Rename
            | Self::Link
            | Self::Release
            | Self::Releasedir
            | Self::Flock
            | Self::Getlk
            | Self::Setlk
            | Self::Setxattr
            | Self::Removexattr => OpTier::Metadata,

            // Write: Delays as soon as flushing queues saturate; stalls at 100% capacity
            Self::Write | Self::Fsync | Self::Fallocate | Self::Fsyncdir | Self::CopyFileRange => OpTier::Write,
        }
    }

    /// Returns true if this operation modifies filesystem state.
    #[inline]
    pub const fn is_mutating(self) -> bool {
        !matches!(self.tier(), OpTier::ReadOnly)
    }

    /// Returns true if this operation is a pure read.
    #[inline]
    pub const fn is_read(self) -> bool {
        matches!(self.tier(), OpTier::ReadOnly)
    }
}

/// Operational tier for classifying FUSE operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpTier {
    /// Pure reads (e.g. read, readdir, lookup, getattr) that never modify state.
    ReadOnly,
    /// Light metadata mutations (e.g. mkdir, unlink, rename, setattr).
    Metadata,
    /// Heavy payload write mutations (write, fallocate, copy_file_range).
    Write,
}

/// Decision produced by operational pushback throttling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// No backpressure applied; response can be sent immediately.
    NoDelay,
    /// Soft delay calculated via asymptotic saturation formula.
    Delay(Duration),
    /// Hard stall: staged buffer has reached 100% capacity; caller is paused indefinitely
    /// until disk flush commits capacity or the filesystem unmounts.
    Stall,
}

impl ThrottleDecision {
    /// Returns true if this decision causes any form of backpressure (delay or stall).
    #[inline]
    pub const fn is_throttled(self) -> bool {
        !matches!(self, Self::NoDelay)
    }

    /// Returns true if this decision is a hard indefinite stall.
    #[inline]
    pub const fn is_stalled(self) -> bool {
        matches!(self, Self::Stall)
    }

    /// Expected maximum delay duration (or zero if unthrottled).
    #[inline]
    pub const fn delay(self) -> Duration {
        match self {
            Self::NoDelay => Duration::ZERO,
            Self::Delay(d) => d,
            Self::Stall => Duration::MAX,
        }
    }
}

/// Cumulative telemetry tracking invocations, active operations, throttling, and execution latency across all FUSE operations.
#[derive(Debug, Default)]
pub struct FuseOpMetrics {
    calls: [AtomicU64; FUSE_OP_COUNT],
    active: [AtomicU64; FUSE_OP_COUNT],
    throttled: [AtomicU64; FUSE_OP_COUNT],
    stalled: [AtomicU64; FUSE_OP_COUNT],
    active_delayed: [AtomicU64; FUSE_OP_COUNT],
    total_nanos: [AtomicU64; FUSE_OP_COUNT],
    max_nanos: [AtomicU64; FUSE_OP_COUNT],
    throttled_nanos: [AtomicU64; FUSE_OP_COUNT],
    stalled_nanos: [AtomicU64; FUSE_OP_COUNT],
}

impl FuseOpMetrics {
    /// Creates a fresh metrics collector with all counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an invocation of the given FUSE operation and increments the active count.
    #[inline]
    pub fn record_call(&self, op: FuseOp) {
        self.calls[op.index()].fetch_add(1, Ordering::Relaxed);
        self.active[op.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Records a throttle decision applied to the given FUSE operation.
    #[inline]
    pub fn record_throttle(&self, op: FuseOp, decision: ThrottleDecision) {
        match decision {
            ThrottleDecision::NoDelay => {}
            ThrottleDecision::Delay(_) => {
                self.throttled[op.index()].fetch_add(1, Ordering::Relaxed);
            }
            ThrottleDecision::Stall => {
                self.stalled[op.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records that an operation was enqueued into the delayed response queue with the given throttle decision.
    #[inline]
    pub fn record_delayed_enqueue(&self, op: FuseOp, decision: ThrottleDecision) {
        self.record_throttle(op, decision);
        self.active_delayed[op.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Records the dispatch of a delayed or stalled operation response and updates wait duration.
    #[inline]
    pub fn record_delayed_dispatch(&self, op: FuseOp, is_stalled: bool, elapsed: Duration) {
        self.active_delayed[op.index()].fetch_sub(1, Ordering::Relaxed);
        if is_stalled {
            self.record_stalled_duration(op, elapsed);
        } else {
            self.record_throttled_duration(op, elapsed);
        }
    }

    /// Records the elapsed execution duration for `op` and decrements the active count.
    #[inline]
    pub fn record_duration(&self, op: FuseOp, duration: Duration) {
        self.active[op.index()].fetch_sub(1, Ordering::Relaxed);
        let nanos = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.total_nanos[op.index()].fetch_add(nanos, Ordering::Relaxed);
        self.max_nanos[op.index()].fetch_max(nanos, Ordering::Relaxed);
    }

    /// Records the actual duration that `op` was throttled (waiting in pushback delay queue).
    #[inline]
    pub fn record_throttled_duration(&self, op: FuseOp, duration: Duration) {
        let nanos = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.throttled_nanos[op.index()].fetch_add(nanos, Ordering::Relaxed);
    }

    /// Records the actual duration that `op` was stalled (waiting in pushback stall queue).
    #[inline]
    pub fn record_stalled_duration(&self, op: FuseOp, duration: Duration) {
        let nanos = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.stalled_nanos[op.index()].fetch_add(nanos, Ordering::Relaxed);
    }

    /// Cumulative count of invocations for `op`.
    #[inline]
    pub fn calls(&self, op: FuseOp) -> u64 {
        self.calls[op.index()].load(Ordering::Relaxed)
    }

    /// Number of currently active (in-flight) invocations for `op`.
    #[inline]
    pub fn active(&self, op: FuseOp) -> u64 {
        self.active[op.index()].load(Ordering::Relaxed)
    }

    /// Number of currently active (queued) delayed/stalled operations for `op`.
    #[inline]
    pub fn active_delayed(&self, op: FuseOp) -> u64 {
        self.active_delayed[op.index()].load(Ordering::Relaxed)
    }

    /// Cumulative count of soft-throttled invocations for `op`.
    #[inline]
    pub fn throttled(&self, op: FuseOp) -> u64 {
        self.throttled[op.index()].load(Ordering::Relaxed)
    }

    /// Cumulative count of hard-stalled invocations for `op`.
    #[inline]
    pub fn stalled(&self, op: FuseOp) -> u64 {
        self.stalled[op.index()].load(Ordering::Relaxed)
    }

    /// Cumulative duration that `op` was soft-throttled.
    pub fn throttled_duration(&self, op: FuseOp) -> Duration {
        let nanos = self.throttled_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos)
    }

    /// Cumulative duration that `op` was hard-stalled.
    pub fn stalled_duration(&self, op: FuseOp) -> Duration {
        let nanos = self.stalled_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos)
    }

    /// Average throttled duration for `op` when the operation was actually throttled.
    pub fn avg_throttled_duration(&self, op: FuseOp) -> Duration {
        let throttled = self.throttled(op);
        if throttled == 0 {
            return Duration::ZERO;
        }
        let nanos = self.throttled_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos / throttled)
    }

    /// Average stalled duration for `op` when the operation encountered a hard stall.
    pub fn avg_stalled_duration(&self, op: FuseOp) -> Duration {
        let stalled = self.stalled(op);
        if stalled == 0 {
            return Duration::ZERO;
        }
        let nanos = self.stalled_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos / stalled)
    }

    /// Average execution latency for `op`.
    pub fn avg_latency(&self, op: FuseOp) -> Duration {
        let calls = self.calls(op);
        if calls == 0 {
            return Duration::ZERO;
        }
        let nanos = self.total_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos / calls)
    }

    /// Maximum execution latency for `op`.
    pub fn max_latency(&self, op: FuseOp) -> Duration {
        let nanos = self.max_nanos[op.index()].load(Ordering::Relaxed);
        Duration::from_nanos(nanos)
    }

    /// Sum of all invocations across all FUSE operations.
    pub fn total_calls(&self) -> u64 {
        self.calls.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Sum of all currently active (in-flight) operations across all FUSE operations.
    pub fn total_active(&self) -> u64 {
        self.active.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Sum of all currently active delayed/stalled operations across all FUSE operations.
    pub fn total_active_delayed(&self) -> u64 {
        self.active_delayed.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Sum of all soft-throttled operations across all FUSE operations.
    pub fn total_throttled(&self) -> u64 {
        self.throttled.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Sum of all hard-stalled operations across all FUSE operations.
    pub fn total_stalled(&self) -> u64 {
        self.stalled.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Total number of operations that encountered any form of pushback backpressure (delayed or stalled).
    pub fn total_delayed(&self) -> u64 {
        self.total_throttled() + self.total_stalled()
    }

    /// Total cumulative execution duration across all operations.
    pub fn total_duration(&self) -> Duration {
        let nanos: u64 = self.total_nanos.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        Duration::from_nanos(nanos)
    }

    /// Total cumulative soft-throttled duration across all operations.
    pub fn total_throttled_duration(&self) -> Duration {
        let nanos: u64 = self.throttled_nanos.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        Duration::from_nanos(nanos)
    }

    /// Total cumulative hard-stalled duration across all operations.
    pub fn total_stalled_duration(&self) -> Duration {
        let nanos: u64 = self.stalled_nanos.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        Duration::from_nanos(nanos)
    }

    /// Total cumulative pushback delay duration (soft delays + hard stalls) across all operations.
    pub fn total_delay_duration(&self) -> Duration {
        self.total_throttled_duration() + self.total_stalled_duration()
    }

    /// Average pushback delay duration per delayed/stalled operation across all operations.
    pub fn avg_delay_duration(&self) -> Duration {
        let total = self.total_delayed();
        if total == 0 {
            Duration::ZERO
        } else {
            let total_nanos = self.total_delay_duration().as_nanos();
            Duration::from_nanos((total_nanos / total as u128) as u64)
        }
    }
}
