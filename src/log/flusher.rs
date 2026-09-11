use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The underlying trigger or motivation for initiating a flush operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMotivation {
    /// Explicit POSIX file data/metadata sync (`fsync`).
    Fsync,
    /// Explicit POSIX directory sync (`fsyncdir`).
    Fdirsync,
    /// Periodic background flusher interval timeout.
    TimeBased,
    /// Live mutation staged bytes or operation count reached configured capacity thresholds.
    Threshold,
    /// Manual explicit flush invocation (e.g. CLI, tests, log rolls, summary exports).
    Manual,
    /// Filesystem shutdown or unmount flush.
    Shutdown,
}

impl FlushMotivation {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlushMotivation::Fsync => "fsync",
            FlushMotivation::Fdirsync => "fdirsync",
            FlushMotivation::TimeBased => "time-based",
            FlushMotivation::Threshold => "threshold",
            FlushMotivation::Manual => "manual",
            FlushMotivation::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for FlushMotivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Default)]
struct FlusherState {
    stop: bool,
    triggered: bool,
}

/// Background thread manager that periodically triggers a flush routine with motivation tracking.
pub struct BackgroundFlusher {
    state: Arc<(Mutex<FlusherState>, Condvar)>,
    thread_handle: Option<JoinHandle<()>>,
}

impl BackgroundFlusher {
    /// Starts a periodic background flusher thread that runs every `interval`.
    pub fn start<F>(flush_fn: F, interval: Duration) -> Self
    where
        F: Fn() -> std::io::Result<()> + Send + 'static,
    {
        let pair = Arc::new((Mutex::new(FlusherState::default()), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut state = lock.lock().unwrap();
            while !state.stop {
                if !state.triggered {
                    state = if interval.is_zero() {
                        cvar.wait(state).unwrap()
                    } else {
                        let result = cvar.wait_timeout(state, interval).unwrap();
                        result.0
                    };
                }
                let run_flush = state.triggered;
                state.triggered = false;
                if state.stop {
                    if run_flush {
                        drop(state);
                        if let Err(e) = flush_fn() {
                            log::error!("Background flush failed: {}", e);
                        }
                    }
                    break;
                }
                drop(state);
                if let Err(e) = flush_fn() {
                    log::error!("Background flush failed: {}", e);
                }
                state = lock.lock().unwrap();
            }
        });

        Self {
            state: pair,
            thread_handle: Some(handle),
        }
    }

    /// Starts a periodic background flusher thread observing a dynamic atomic `interval` in seconds.
    /// Runs `on_timeout` when the interval expires, followed by `flush_fn`.
    pub fn start_dynamic<F, T>(flush_fn: F, on_timeout: T, interval: Arc<std::sync::atomic::AtomicU64>) -> Self
    where
        F: Fn() -> std::io::Result<()> + Send + 'static,
        T: Fn() + Send + 'static,
    {
        let pair = Arc::new((Mutex::new(FlusherState::default()), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut state = lock.lock().unwrap();
            while !state.stop {
                let interval_secs = interval.load(std::sync::atomic::Ordering::Relaxed);
                let mut should_flush = state.triggered;
                let mut timed_out = false;
                if !should_flush {
                    if interval_secs == 0 {
                        let result = cvar.wait_timeout(state, Duration::from_millis(100)).unwrap();
                        state = result.0;
                        should_flush = state.triggered;
                    } else {
                        let result = cvar.wait_timeout(state, Duration::from_secs(interval_secs)).unwrap();
                        state = result.0;
                        timed_out = result.1.timed_out();
                        should_flush = timed_out || state.triggered;
                    }
                }
                state.triggered = false;
                if state.stop {
                    if should_flush {
                        drop(state);
                        if timed_out {
                            on_timeout();
                        }
                        if let Err(e) = flush_fn() {
                            log::error!("Background flush failed: {}", e);
                        }
                    }
                    break;
                }
                if !should_flush {
                    continue;
                }
                drop(state);
                if timed_out {
                    on_timeout();
                }
                if let Err(e) = flush_fn() {
                    log::error!("Background flush failed: {}", e);
                }
                state = lock.lock().unwrap();
            }
        });

        Self {
            state: pair,
            thread_handle: Some(handle),
        }
    }

    /// Wakes up the background flusher thread immediately to execute a flush cycle
    /// without waiting for the next periodic interval timeout.
    pub fn trigger(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.triggered = true;
        cvar.notify_one();
    }

    /// Signals the background flusher thread to exit immediately and joins it.
    pub fn stop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        if !state.stop {
            state.stop = true;
            cvar.notify_all();
        }
        drop(state);

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BackgroundFlusher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_background_flusher_periodic_trigger() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);

        let mut flusher = BackgroundFlusher::start(
            move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(50),
        );

        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) >= 2,
            Duration::from_secs(3)
        ));

        flusher.stop();
    }

    #[test]
    fn test_background_flusher_manual_trigger() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);

        // Long periodic interval (10 seconds)
        let mut flusher = BackgroundFlusher::start(
            move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(10),
        );

        assert_eq!(count.load(Ordering::SeqCst), 0);

        flusher.trigger();
        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) == 1,
            Duration::from_secs(3)
        ));

        flusher.stop();
    }
}
