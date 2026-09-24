#![cfg_attr(not(test), deny(clippy::too_many_lines))]
pub mod check;
pub mod cli;
pub mod clock;
pub mod compat;
pub mod compress;
pub mod crypto;
pub mod daemon;
pub mod dump;
pub mod error;
pub mod extent_map;
pub mod fs;
pub mod log;
pub mod logging;
pub mod node;
pub mod operations;
pub mod remote;
pub mod shim;
pub mod stats;
pub mod storage;
pub mod sync;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;
pub mod wire;

// Only the two types callers routinely name are lifted to the crate root; everything else
// crypto exposes stays reachable at its canonical `appendfs::crypto::` path.
pub use crypto::{VolumeHeader, VolumeKey};

pub use check::{
    IntegrityIssue, IntegrityReport, IssueLevel, check_fs_integrity, check_remote_integrity, check_volume,
};
pub use cli::{
    Cli, Commands, DumpArgs, FsckArgs, InitArgs, MountArgs, MountRoArgs, StatsArgs, find_latest_generation,
    find_latest_generation_in_storage,
};
pub use clock::{
    AdvancingClock, Clock, MockClock, SystemClock, format_duration, format_local_civil_time, format_utc_civil_time,
    format_utc_compact, parse_duration, parse_timestamp,
};
pub use dump::{dump_file, dump_log_file, dump_log_reader, dump_summary_file, dump_summary_reader};
pub use error::FsError;
pub use extent_map::{Extent, ExtentEntry, ExtentMap};
pub use fs::{
    AsyncOpGuard, AsyncTracker, BatchCompletion, DelayedResponseQueue, FLUSH_HISTORY_CAPACITY, FlushReason,
    FlushRecord, FlushStats, InMemoryFS, InnerStatsSnapshot, InodeCounts, OpTier, ThrottleDecision,
};
pub use log::{
    ExtentState, LogFileCache, LogReader, LogRecord, LogWriter, RecoveryTarget, SharedExtentState, SummaryFooter,
    SummaryHeader, SummaryReader, export_summary, init_volume, init_volume_with_clock, recover_fs,
};
pub use node::{InodeMeta, Node, NodeDelta, NodeKind, SpecialDelta};
pub use operations::op::{ALL_FUSE_OPS, FUSE_OP_COUNT, FuseOp, FuseOpMetrics};
pub use remote::{
    BLOCK_TOUCH_THROTTLE, BatchLeaderGuard, BlockCache, ConcurrencyLimiter, ConcurrencyPermit, ConfiguredRemote,
    DEFAULT_DECRYPTED_CACHE_SIZE, DecryptedRecordCache, FollowerBlock, MemoryBlockCache, OnDiskBlockCache,
    RemoteObject, RemoteReadCoalescer, RemoteReadTarget, RemoteRegistry, RemoteReplicationWorker, RemoteStore,
    RemoteTargetConfig, ReplicationPolicy, S3RemoteStore, TMP_FILE_MAX_AGE, TieredCache, TieredStorageReader,
    prepare_remote_recovery_for_target,
};
#[cfg(any(test, feature = "testing"))]
pub use remote::{CountingRemoteStore, FailingRemoteStore, LatencyRemoteStore, MockRemoteStore, RemoteStoreMetrics};
pub use shim::{
    DeferredCallback, DeferredCompletion, DeferredReceiver, DeferredResult, DeferredToken, DirEntry, DirEntryPlus,
    FileAttr, FileType, Filesystem, FuseResponse, ReplyData, Request, RequestContext, StatfsAttr,
};
pub use stats::{
    VolumeStats, calculate_generation_live_stats_from_nodes, format_generation_status, format_generations_table,
    format_runtime_status,
};
pub use storage::{
    BufferedStorageWriter, DEFAULT_STORAGE_BUFFER_CAPACITY, FaultStorage, MemoryStorage, OsStorage, OsStorageReader,
    OsStorageWriter, ReadOnlyStorage, Storage, StorageReader, StorageWriter, WriteMode,
};
pub use sync::{ActionGuard, ActionMutex, OpStatSnapshot, OpTag, PostUnlockQueue};
#[cfg(any(test, feature = "testing"))]
pub use test_utils::wait_until;

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), FsError> {
    shim::mount(args, fs)
}

pub fn mount_arc(
    args: Vec<String>,
    fs: std::sync::Arc<InMemoryFS>,
    ready: Option<daemon::Ready>,
) -> Result<(), FsError> {
    shim::mount_arc(args, fs, ready)
}

pub fn mount_ro(args: Vec<String>, fs: InMemoryFS) -> Result<(), FsError> {
    shim::mount_ro(args, fs)
}

pub fn mount_ro_arc(
    args: Vec<String>,
    fs: std::sync::Arc<InMemoryFS>,
    ready: Option<daemon::Ready>,
) -> Result<(), FsError> {
    shim::mount_ro_arc(args, fs, ready)
}
