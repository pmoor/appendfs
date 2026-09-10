#![cfg_attr(not(test), deny(clippy::too_many_lines))]
pub mod async_runtime;
pub mod check;
pub mod cli;
pub mod clock;
pub mod compat;
pub mod compress;
pub mod crypto;
pub mod dump;
pub mod extent_map;
pub mod fs;
pub mod log;
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
    CheckArgs, Cli, Commands, DumpArgs, InitArgs, MountArgs, MountRoArgs, StatsArgs, find_latest_generation,
    find_latest_generation_in_storage,
};
pub use clock::{AdvancingClock, Clock, MockClock, SystemClock, format_local_civil_time, parse_timestamp};
pub use dump::{dump_file, dump_log_file, dump_log_reader, dump_summary_file, dump_summary_reader};
pub use extent_map::{Extent, ExtentEntry, ExtentMap};
pub use fs::{BatchCompletion, FlushRecord, FlushRingBuffer, Flusher, InMemoryFS};
pub use log::{
    BackgroundFlusher, ExtentState, FlushMotivation, LogFileCache, LogReader, LogRecord, LogWriter, RecoveryTarget,
    SharedExtentState, SummaryFooter, SummaryHeader, SummaryReader, export_summary, init_volume,
    init_volume_with_clock, recover_fs,
};
pub use node::{InodeMeta, Node, NodeDelta, NodeKind, SpecialDelta};
pub use remote::{
    BatchLeaderGuard, BlockCache, ConcurrencyLimiter, ConcurrencyPermit, ConfiguredRemote,
    DEFAULT_DECRYPTED_CACHE_SIZE, DecryptedRecordCache, FollowerBlock, MemoryBlockCache, OnDiskBlockCache,
    RemoteObject, RemoteReadCoalescer, RemoteReadTarget, RemoteRegistry, RemoteReplicationWorker, RemoteStore,
    RemoteTargetConfig, ReplicationPolicy, S3RemoteStore, TieredCache, TieredStorageReader,
    prepare_remote_recovery_for_target,
};
#[cfg(any(test, feature = "testing"))]
pub use remote::{CountingRemoteStore, FailingRemoteStore, LatencyRemoteStore, MockRemoteStore, RemoteStoreMetrics};
pub use stats::VolumeStats;
pub use storage::{FaultStorage, MemoryStorage, OsStorage, Storage, StorageReader, StorageWriter, WriteMode};
pub use sync::{ActionGuard, ActionMutex, OpStatSnapshot, OpTag, PostUnlockQueue};
#[cfg(any(test, feature = "testing"))]
pub use test_utils::wait_until;

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount(args, fs)
}

pub fn mount_arc(args: Vec<String>, fs: std::sync::Arc<InMemoryFS>) -> Result<(), i32> {
    shim::mount_arc(args, fs)
}

pub fn mount_ro(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount_ro(args, fs)
}

pub fn mount_ro_arc(args: Vec<String>, fs: std::sync::Arc<InMemoryFS>) -> Result<(), i32> {
    shim::mount_ro_arc(args, fs)
}
