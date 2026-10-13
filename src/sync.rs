use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, LockResult, Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult};
use std::time::{Duration, Instant};

/// Tags identifying distinct filesystem operation categories for lock contention profiling.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpTag {
    Write = 0,
    ReadPlan = 1,
    Create = 2,
    Mknod = 3,
    Unlink = 4,
    Symlink = 5,
    Rename = 6,
    Link = 7,
    Mkdir = 8,
    Rmdir = 9,
    SetAttr = 10,
    Fallocate = 11,
    Xattr = 12,
    Handle = 13,
    Flush = 14,
    Fold = 15,
    Layer = 16,
    Open = 17,
    OpenDir = 18,
    ReadDir = 19,
    Lookup = 20,
    GetAttr = 21,
    ReadLink = 22,
    Stats = 23,
    Lock = 24,
    Other = 25,
    CopyFileRange = 26,
    #[cfg(any(test, feature = "testing"))]
    Test = 27,
}

#[cfg(not(any(test, feature = "testing")))]
pub const OP_TAG_COUNT: usize = 27;
#[cfg(any(test, feature = "testing"))]
pub const OP_TAG_COUNT: usize = 28;

pub const ALL_OP_TAGS: [OpTag; OP_TAG_COUNT] = [
    OpTag::Write,
    OpTag::ReadPlan,
    OpTag::Create,
    OpTag::Mknod,
    OpTag::Unlink,
    OpTag::Symlink,
    OpTag::Rename,
    OpTag::Link,
    OpTag::Mkdir,
    OpTag::Rmdir,
    OpTag::SetAttr,
    OpTag::Fallocate,
    OpTag::Xattr,
    OpTag::Handle,
    OpTag::Flush,
    OpTag::Fold,
    OpTag::Layer,
    OpTag::Open,
    OpTag::OpenDir,
    OpTag::ReadDir,
    OpTag::Lookup,
    OpTag::GetAttr,
    OpTag::ReadLink,
    OpTag::Stats,
    OpTag::Lock,
    OpTag::Other,
    OpTag::CopyFileRange,
    #[cfg(any(test, feature = "testing"))]
    OpTag::Test,
];

impl OpTag {
    pub const fn as_str(&self) -> &'static str {
        match self {
            OpTag::Write => "write",
            OpTag::ReadPlan => "read_plan",
            OpTag::Create => "create",
            OpTag::Mknod => "mknod",
            OpTag::Unlink => "unlink",
            OpTag::Symlink => "symlink",
            OpTag::Rename => "rename",
            OpTag::Link => "link",
            OpTag::Mkdir => "mkdir",
            OpTag::Rmdir => "rmdir",
            OpTag::SetAttr => "setattr",
            OpTag::Fallocate => "fallocate",
            OpTag::Xattr => "xattr",
            OpTag::Handle => "handle",
            OpTag::Flush => "flush",
            OpTag::Fold => "fold",
            OpTag::Layer => "layer",
            OpTag::Open => "open",
            OpTag::OpenDir => "opendir",
            OpTag::ReadDir => "readdir",
            OpTag::Lookup => "lookup",
            OpTag::GetAttr => "getattr",
            OpTag::ReadLink => "readlink",
            OpTag::Stats => "stats",
            OpTag::Lock => "lock",
            OpTag::Other => "other",
            OpTag::CopyFileRange => "copy_file_range",
            #[cfg(any(test, feature = "testing"))]
            OpTag::Test => "test",
        }
    }

    pub const fn name(&self) -> &'static str {
        self.as_str()
    }
}

/// Contention metrics recorded for an individual operation tag.
pub struct OpMetrics {
    pub count: AtomicU64,
    pub busy_nanos: AtomicU64,
    pub wait_nanos: AtomicU64,
    pub max_hold_nanos: AtomicU64,
}

impl OpMetrics {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            busy_nanos: AtomicU64::new(0),
            wait_nanos: AtomicU64::new(0),
            max_hold_nanos: AtomicU64::new(0),
        }
    }
}

impl Default for OpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

const fn new_op_metrics_array() -> [OpMetrics; OP_TAG_COUNT] {
    [const { OpMetrics::new() }; OP_TAG_COUNT]
}

/// Point-in-time snapshot of operation metrics for reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpStatSnapshot {
    pub tag: OpTag,
    pub count: u64,
    pub busy_time: Duration,
    pub wait_time: Duration,
    pub max_hold_time: Duration,
}

impl OpStatSnapshot {
    pub fn avg_hold_time(&self) -> Duration {
        if self.count > 0 {
            self.busy_time / (self.count as u32)
        } else {
            Duration::ZERO
        }
    }

    pub fn avg_wait_time(&self) -> Duration {
        if self.count > 0 {
            self.wait_time / (self.count as u32)
        } else {
            Duration::ZERO
        }
    }
}

/// A queue for deferred actions to be executed immediately after the lock is released.
pub struct PostUnlockQueue<'q, 'a> {
    tasks: &'q mut Vec<Box<dyn FnOnce() + 'a>>,
}

impl<'q, 'a> PostUnlockQueue<'q, 'a> {
    /// Enqueues an action to be executed right after the mutex lock is released.
    pub fn defer(&mut self, task: impl FnOnce() + 'a) {
        self.tasks.push(Box::new(task));
    }
}

/// A custom mutex that tracks contention metrics (cumulative busy time, wait time,
/// acquisition count, and per-operation statistics) and supports pre-unlock inspection and deferred post-unlock actions.
pub struct ActionMutex<T> {
    inner: Mutex<T>,
    busy_time_nanos: AtomicU64,
    wait_time_nanos: AtomicU64,
    lock_count: AtomicU64,
    op_metrics: [OpMetrics; OP_TAG_COUNT],
}

impl<T> ActionMutex<T> {
    /// Creates a new `ActionMutex` protecting `val`.
    pub const fn new(val: T) -> Self {
        Self {
            inner: Mutex::new(val),
            busy_time_nanos: AtomicU64::new(0),
            wait_time_nanos: AtomicU64::new(0),
            lock_count: AtomicU64::new(0),
            op_metrics: new_op_metrics_array(),
        }
    }

    /// Acquires the mutex with a specific operation tag, blocking until available.
    /// Tracks wait time and starts measuring busy time upon acquisition.
    pub fn lock(&self, tag: OpTag) -> LockResult<ActionGuard<'_, T>> {
        let wait_start = Instant::now();
        match self.inner.lock() {
            Ok(guard) => {
                let wait_dur = wait_start.elapsed();
                let wait_nanos = wait_dur.as_nanos() as u64;
                self.wait_time_nanos.fetch_add(wait_nanos, Ordering::Relaxed);
                self.op_metrics[tag as usize]
                    .wait_nanos
                    .fetch_add(wait_nanos, Ordering::Relaxed);
                Ok(ActionGuard::new(self, guard, tag))
            }
            Err(poisoned) => {
                let wait_dur = wait_start.elapsed();
                let wait_nanos = wait_dur.as_nanos() as u64;
                self.wait_time_nanos.fetch_add(wait_nanos, Ordering::Relaxed);
                self.op_metrics[tag as usize]
                    .wait_nanos
                    .fetch_add(wait_nanos, Ordering::Relaxed);
                Err(PoisonError::new(ActionGuard::new(self, poisoned.into_inner(), tag)))
            }
        }
    }

    /// Acquires the mutex with [`OpTag::Test`].
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn lock_for_tests(&self) -> LockResult<ActionGuard<'_, T>> {
        self.lock(OpTag::Test)
    }

    /// Attempts to acquire the mutex with a specific operation tag without blocking.
    pub fn try_lock(&self, tag: OpTag) -> TryLockResult<ActionGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(guard) => Ok(ActionGuard::new(self, guard, tag)),
            Err(TryLockError::Poisoned(poisoned)) => Err(TryLockError::Poisoned(PoisonError::new(ActionGuard::new(
                self,
                poisoned.into_inner(),
                tag,
            )))),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
        }
    }

    /// Attempts to acquire the mutex with [`OpTag::Test`] without blocking.
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn try_lock_for_tests(&self) -> TryLockResult<ActionGuard<'_, T>> {
        self.try_lock(OpTag::Test)
    }

    /// Acquires the mutex with [`OpTag::Test`] and executes `f` with a mutable reference to the [`ActionGuard`].
    ///
    /// Available only in tests or with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_lock_for_tests<R>(&self, f: impl FnOnce(&mut ActionGuard<'_, T>) -> R) -> R {
        self.with_lock(OpTag::Test, f)
    }

    /// Acquires the lock with `tag` and executes `f` with a mutable reference to the [`ActionGuard`].
    ///
    /// The lock is released and any deferred post-unlock tasks are guaranteed to execute
    /// immediately when `f` returns.
    pub fn with_lock<R>(&self, tag: OpTag, f: impl FnOnce(&mut ActionGuard<'_, T>) -> R) -> R {
        let mut guard = self.lock(tag).expect("ActionMutex poisoned");
        f(&mut guard)
    }

    /// Cumulative duration that threads have spent holding this mutex (busy time).
    pub fn busy_time(&self) -> Duration {
        Duration::from_nanos(self.busy_time_nanos.load(Ordering::Relaxed))
    }

    /// Cumulative duration that threads have spent waiting to acquire this mutex.
    pub fn wait_time(&self) -> Duration {
        Duration::from_nanos(self.wait_time_nanos.load(Ordering::Relaxed))
    }

    /// Total number of successful lock acquisitions.
    pub fn lock_count(&self) -> u64 {
        self.lock_count.load(Ordering::Relaxed)
    }

    /// Returns a snapshot of per-operation metrics.
    pub fn op_stats(&self) -> Vec<OpStatSnapshot> {
        let mut stats = Vec::with_capacity(OP_TAG_COUNT);
        for &tag in &ALL_OP_TAGS {
            let m = &self.op_metrics[tag as usize];
            let count = m.count.load(Ordering::Relaxed);
            let busy_time = Duration::from_nanos(m.busy_nanos.load(Ordering::Relaxed));
            let wait_time = Duration::from_nanos(m.wait_nanos.load(Ordering::Relaxed));
            let max_hold_time = Duration::from_nanos(m.max_hold_nanos.load(Ordering::Relaxed));
            stats.push(OpStatSnapshot {
                tag,
                count,
                busy_time,
                wait_time,
                max_hold_time,
            });
        }
        stats
    }

    /// Returns a mutable reference to the underlying data if we have exclusive access to the mutex.
    pub fn get_mut(&mut self) -> LockResult<&mut T> {
        self.inner.get_mut()
    }

    /// Consumes the mutex, returning the underlying data.
    pub fn into_inner(self) -> LockResult<T> {
        self.inner.into_inner()
    }
}

impl<T> From<T> for ActionMutex<T> {
    fn from(val: T) -> Self {
        Self::new(val)
    }
}

impl<T: fmt::Debug> fmt::Debug for ActionMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("ActionMutex");
        match self.inner.try_lock() {
            Ok(guard) => d.field("data", &&*guard),
            Err(_) => d.field("data", &"<locked>"),
        };
        d.field("busy_time", &self.busy_time())
            .field("wait_time", &self.wait_time())
            .field("lock_count", &self.lock_count())
            .finish()
    }
}

type PreUnlockHook<'a, T> = Box<dyn for<'q> FnOnce(&mut T, &mut PostUnlockQueue<'q, 'a>) + 'a>;
type PostUnlockTask<'a> = Box<dyn FnOnce() + 'a>;

/// An RAII guard for `ActionMutex`.
///
/// When dropped, runs registered pre-unlock hooks while holding the lock, releases
/// the lock (updating busy time and per-operation metrics), and then executes all deferred post-unlock tasks.
pub struct ActionGuard<'a, T> {
    mutex: &'a ActionMutex<T>,
    guard: Option<MutexGuard<'a, T>>,
    hold_start: Instant,
    tag: OpTag,
    pre_unlock_hooks: Vec<PreUnlockHook<'a, T>>,
    post_unlock_tasks: Vec<PostUnlockTask<'a>>,
}

impl<'a, T> ActionGuard<'a, T> {
    fn new(mutex: &'a ActionMutex<T>, guard: MutexGuard<'a, T>, tag: OpTag) -> Self {
        Self {
            mutex,
            guard: Some(guard),
            hold_start: Instant::now(),
            tag,
            pre_unlock_hooks: Vec::new(),
            post_unlock_tasks: Vec::new(),
        }
    }

    /// Returns the operation tag associated with this guard.
    pub fn tag(&self) -> OpTag {
        self.tag
    }

    /// Overrides the operation tag associated with this guard.
    pub fn set_tag(&mut self, tag: OpTag) {
        self.tag = tag;
    }

    /// Parks a task to be executed immediately after the mutex lock is released.
    pub fn defer(&mut self, task: impl FnOnce() + 'a) {
        self.post_unlock_tasks.push(Box::new(task));
    }

    /// Registers a hook to run right before unlocking (with the lock still held).
    /// The hook can inspect or mutate `&mut T` and enqueue further post-unlock tasks.
    pub fn before_unlock(&mut self, hook: impl for<'q> FnOnce(&mut T, &mut PostUnlockQueue<'q, 'a>) + 'a) {
        self.pre_unlock_hooks.push(Box::new(hook));
    }

    /// Returns the elapsed duration since this lock guard was acquired.
    pub fn hold_elapsed(&self) -> Duration {
        self.hold_start.elapsed()
    }

    /// Temporarily releases the lock and waits on `cvar`, re-acquiring the lock before returning.
    pub fn wait(mut self, cvar: &Condvar) -> Self {
        let elapsed = self.hold_start.elapsed();
        let elapsed_nanos = elapsed.as_nanos() as u64;
        self.mutex.busy_time_nanos.fetch_add(elapsed_nanos, Ordering::Relaxed);
        self.mutex.op_metrics[self.tag as usize]
            .busy_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);

        let raw_guard = self.guard.take().expect("guard not dropped");
        let new_guard = cvar.wait(raw_guard).expect("ActionMutex poisoned during wait");
        self.guard = Some(new_guard);
        self.hold_start = Instant::now();
        self
    }

    /// Temporarily releases the lock and waits on `cvar` for up to `dur`, re-acquiring the lock before returning.
    pub fn wait_timeout(mut self, cvar: &Condvar, dur: Duration) -> (Self, std::sync::WaitTimeoutResult) {
        let elapsed = self.hold_start.elapsed();
        let elapsed_nanos = elapsed.as_nanos() as u64;
        self.mutex.busy_time_nanos.fetch_add(elapsed_nanos, Ordering::Relaxed);
        self.mutex.op_metrics[self.tag as usize]
            .busy_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);

        let raw_guard = self.guard.take().expect("guard not dropped");
        let (new_guard, res) = cvar
            .wait_timeout(raw_guard, dur)
            .expect("ActionMutex poisoned during wait");
        self.guard = Some(new_guard);
        self.hold_start = Instant::now();
        (self, res)
    }
}

impl<'a, T> Deref for ActionGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().expect("guard not dropped").deref()
    }
}

impl<'a, T> DerefMut for ActionGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.as_mut().expect("guard not dropped").deref_mut()
    }
}

impl<'a, T> Drop for ActionGuard<'a, T> {
    fn drop(&mut self) {
        // 1. Run pre-unlock hooks while still holding the mutex lock.
        // If a hook panics, unwinding will still drop `self.guard` and release the lock.
        let hooks = std::mem::take(&mut self.pre_unlock_hooks);
        if let Some(ref mut inner) = self.guard {
            let mut queue = PostUnlockQueue {
                tasks: &mut self.post_unlock_tasks,
            };
            for hook in hooks {
                hook(inner, &mut queue);
            }
        }

        // 2. Explicitly drop the mutex guard to release the lock.
        drop(self.guard.take());
        let elapsed = self.hold_start.elapsed();
        let elapsed_nanos = elapsed.as_nanos() as u64;
        self.mutex.busy_time_nanos.fetch_add(elapsed_nanos, Ordering::Relaxed);
        self.mutex.lock_count.fetch_add(1, Ordering::Relaxed);

        let metric = &self.mutex.op_metrics[self.tag as usize];
        metric.count.fetch_add(1, Ordering::Relaxed);
        metric.busy_nanos.fetch_add(elapsed_nanos, Ordering::Relaxed);
        metric.max_hold_nanos.fetch_max(elapsed_nanos, Ordering::Relaxed);

        // 3. Run all post-unlock tasks without holding the lock.
        if !std::thread::panicking() {
            let tasks = std::mem::take(&mut self.post_unlock_tasks);
            for task in tasks {
                task();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    #[test]
    fn test_action_mutex_basic_and_busy_time() {
        let m = ActionMutex::new(42);
        assert_eq!(m.lock_count(), 0);
        assert_eq!(m.busy_time(), Duration::ZERO);

        {
            let mut guard = m.lock_for_tests().unwrap();
            assert_eq!(*guard, 42);
            *guard = 100;
            thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(m.lock_count(), 1);
        assert!(m.busy_time() >= Duration::from_millis(4));
        assert_eq!(*m.lock_for_tests().unwrap(), 100);
        assert_eq!(m.lock_count(), 2);
    }

    #[test]
    fn test_action_mutex_deferred_runs_after_unlock() {
        let m = Arc::new(ActionMutex::new(0));
        let m_clone = Arc::clone(&m);
        let executed = Arc::new(AtomicBool::new(false));
        let executed_clone = Arc::clone(&executed);

        {
            let mut guard = m.lock_for_tests().unwrap();
            *guard += 1;
            guard.defer(move || {
                // If the lock were still held, acquiring here would deadlock!
                let val = *m_clone.lock_for_tests().unwrap();
                assert_eq!(val, 1);
                executed_clone.store(true, Ordering::SeqCst);
            });
            // The task has not executed yet because the lock is still held
            assert!(!executed.load(Ordering::SeqCst));
        }

        // Lock is dropped, deferred task MUST have run
        assert!(executed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_action_mutex_before_unlock_hook() {
        let m = Arc::new(ActionMutex::new(10));
        let m_clone = Arc::clone(&m);
        let post_ran = Arc::new(AtomicBool::new(false));
        let post_ran_clone = Arc::clone(&post_ran);

        {
            let mut guard = m.lock_for_tests().unwrap();
            guard.before_unlock(move |data, queue| {
                // Inspect data under lock
                if *data == 10 {
                    *data = 20;
                    let m_sub = Arc::clone(&m_clone);
                    let p_sub = Arc::clone(&post_ran_clone);
                    queue.defer(move || {
                        assert_eq!(*m_sub.lock_for_tests().unwrap(), 20);
                        p_sub.store(true, Ordering::SeqCst);
                    });
                }
            });
            assert_eq!(*guard, 10);
            assert!(!post_ran.load(Ordering::SeqCst));
        }

        assert_eq!(*m.lock_for_tests().unwrap(), 20);
        assert!(post_ran.load(Ordering::SeqCst));
    }

    #[test]
    fn test_action_mutex_wait_time() {
        let m = Arc::new(ActionMutex::new(0));
        let m1 = Arc::clone(&m);
        let m2 = Arc::clone(&m);

        let t1 = thread::spawn(move || {
            let mut g = m1.lock_for_tests().unwrap();
            thread::sleep(Duration::from_millis(20));
            *g += 1;
        });

        thread::sleep(Duration::from_millis(5));

        let t2 = thread::spawn(move || {
            let mut g = m2.lock_for_tests().unwrap();
            *g += 1;
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(*m.lock_for_tests().unwrap(), 2);
        assert_eq!(m.lock_count(), 3);
        assert!(m.busy_time() >= Duration::from_millis(18));
        assert!(m.wait_time() >= Duration::from_millis(10));

        let test_stat = m.op_stats().into_iter().find(|s| s.tag == OpTag::Test).unwrap();
        assert_eq!(test_stat.count, 3);
        assert!(test_stat.wait_time >= Duration::from_millis(10));
        assert!(test_stat.avg_wait_time() >= Duration::from_millis(3));
    }

    #[test]
    fn test_action_mutex_try_lock() {
        let m = Arc::new(ActionMutex::new(10));
        let m_clone = Arc::clone(&m);

        let guard = m.lock_for_tests().unwrap();
        assert!(m_clone.try_lock_for_tests().is_err());
        drop(guard);

        let mut try_guard = m.try_lock_for_tests().unwrap();
        assert_eq!(*try_guard, 10);
        *try_guard = 20;
        drop(try_guard);

        assert_eq!(*m.lock_for_tests().unwrap(), 20);
        let stats = m.op_stats();
        let test_stat = stats.iter().find(|s| s.tag == OpTag::Test).unwrap();
        assert_eq!(test_stat.count, 3);
    }

    #[test]
    fn test_action_mutex_test_methods() {
        let m = Arc::new(ActionMutex::new(42));
        {
            let mut g = m.lock_for_tests().unwrap();
            assert_eq!(*g, 42);
            *g = 43;
        }
        assert_eq!(*m.lock_for_tests().unwrap(), 43);

        let try_res = m.try_lock_for_tests().unwrap();
        assert_eq!(*try_res, 43);
        drop(try_res);

        let with_res = m.with_lock_for_tests(|g| {
            **g = 100;
            **g * 2
        });
        assert_eq!(with_res, 200);
        assert_eq!(*m.lock_for_tests().unwrap(), 100);

        let stats = m.op_stats();
        let test_stat = stats.iter().find(|s| s.tag == OpTag::Test).unwrap();
        assert_eq!(test_stat.count, 5);
    }

    #[test]
    fn test_action_mutex_with_lock() {
        let m = Arc::new(ActionMutex::new(100));
        let m_clone = Arc::clone(&m);
        let deferred_ran = Arc::new(AtomicBool::new(false));
        let deferred_ran_clone = Arc::clone(&deferred_ran);

        let res = m.with_lock_for_tests(|guard| {
            **guard += 50;
            let m_sub = Arc::clone(&m_clone);
            let d_sub = Arc::clone(&deferred_ran_clone);
            guard.defer(move || {
                // Must be unlocked here so we can re-acquire without deadlock!
                assert_eq!(*m_sub.lock_for_tests().unwrap(), 150);
                d_sub.store(true, Ordering::SeqCst);
            });
            **guard * 2
        });

        assert_eq!(res, 300);
        assert!(deferred_ran.load(Ordering::SeqCst));
        assert_eq!(m.lock_count(), 2); // 1 for with_lock, 1 inside deferred task

        let stats = m.op_stats();
        let test_stat = stats.iter().find(|s| s.tag == OpTag::Test).unwrap();
        assert_eq!(test_stat.count, 2);
    }

    #[test]
    fn test_op_tags_coverage() {
        assert_eq!(ALL_OP_TAGS.len(), OP_TAG_COUNT);
        assert_eq!(OP_TAG_COUNT, 28);

        let m = ActionMutex::new(0);
        for &tag in &ALL_OP_TAGS {
            assert!(!tag.name().is_empty());
            assert_eq!(tag.name(), tag.as_str());
            let _guard = m.lock(tag).unwrap();
        }

        let stats = m.op_stats();
        assert_eq!(stats.len(), OP_TAG_COUNT);
        for &tag in &ALL_OP_TAGS {
            let stat = stats.iter().find(|s| s.tag == tag).unwrap();
            assert_eq!(stat.count, 1);
        }
    }
}
