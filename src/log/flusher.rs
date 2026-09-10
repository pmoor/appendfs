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

    /// Combines two motivations, giving higher priority to synchronous and high-importance triggers.
    pub fn combine(self, other: FlushMotivation) -> FlushMotivation {
        match (self, other) {
            (FlushMotivation::Shutdown, _) | (_, FlushMotivation::Shutdown) => FlushMotivation::Shutdown,
            (FlushMotivation::Fsync, _) | (_, FlushMotivation::Fsync) => FlushMotivation::Fsync,
            (FlushMotivation::Fdirsync, _) | (_, FlushMotivation::Fdirsync) => FlushMotivation::Fdirsync,
            (FlushMotivation::Threshold, _) | (_, FlushMotivation::Threshold) => FlushMotivation::Threshold,
            (FlushMotivation::Manual, _) | (_, FlushMotivation::Manual) => FlushMotivation::Manual,
            (FlushMotivation::TimeBased, other) => other,
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
    pending_motivation: Option<FlushMotivation>,
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
        F: Fn(FlushMotivation) -> std::io::Result<()> + Send + 'static,
    {
        let pair = Arc::new((Mutex::new(FlusherState::default()), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut state = lock.lock().unwrap();
            while !state.stop {
                if state.pending_motivation.is_none() {
                    let result = cvar.wait_timeout(state, interval).unwrap();
                    state = result.0;
                }
                if state.stop {
                    break;
                }
                let motivation = state.pending_motivation.take().unwrap_or(FlushMotivation::TimeBased);
                drop(state);
                if let Err(e) = flush_fn(motivation) {
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
    /// with the specified motivation without waiting for the next periodic interval timeout.
    pub fn trigger(&self, motivation: FlushMotivation) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.pending_motivation = Some(match state.pending_motivation {
            Some(existing) => existing.combine(motivation),
            None => motivation,
        });
        cvar.notify_one();
    }

    /// Wakes up the background flusher thread with `FlushMotivation::Manual`.
    pub fn trigger_default(&self) {
        self.trigger(FlushMotivation::Manual);
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
            move |motivation| {
                assert_eq!(motivation, FlushMotivation::TimeBased);
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
        let last_mot = Arc::new(Mutex::new(None));
        let last_mot_clone = Arc::clone(&last_mot);

        // Long periodic interval (10 seconds)
        let mut flusher = BackgroundFlusher::start(
            move |motivation| {
                *last_mot_clone.lock().unwrap() = Some(motivation);
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(10),
        );

        assert_eq!(count.load(Ordering::SeqCst), 0);

        // Trigger with Fsync
        flusher.trigger(FlushMotivation::Fsync);
        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) == 1,
            Duration::from_secs(3)
        ));
        assert_eq!(*last_mot.lock().unwrap(), Some(FlushMotivation::Fsync));

        // Trigger with Fdirsync
        flusher.trigger(FlushMotivation::Fdirsync);
        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) == 2,
            Duration::from_secs(3)
        ));
        assert_eq!(*last_mot.lock().unwrap(), Some(FlushMotivation::Fdirsync));

        flusher.stop();
    }

    #[test]
    fn test_flush_motivation_combine() {
        use FlushMotivation::*;

        // Shutdown takes highest priority
        assert_eq!(Shutdown.combine(Fsync), Shutdown);
        assert_eq!(Fsync.combine(Shutdown), Shutdown);
        assert_eq!(Shutdown.combine(Threshold), Shutdown);
        assert_eq!(Shutdown.combine(Manual), Shutdown);
        assert_eq!(Shutdown.combine(TimeBased), Shutdown);

        // Fsync takes priority over Fdirsync, Threshold, Manual, TimeBased
        assert_eq!(Fsync.combine(Fdirsync), Fsync);
        assert_eq!(Fdirsync.combine(Fsync), Fsync);
        assert_eq!(Fsync.combine(Threshold), Fsync);
        assert_eq!(Fsync.combine(Manual), Fsync);
        assert_eq!(Fsync.combine(TimeBased), Fsync);

        // Fdirsync takes priority over Threshold, Manual, TimeBased
        assert_eq!(Fdirsync.combine(Threshold), Fdirsync);
        assert_eq!(Fdirsync.combine(Manual), Fdirsync);
        assert_eq!(Fdirsync.combine(TimeBased), Fdirsync);

        // Threshold takes priority over Manual, TimeBased
        assert_eq!(Threshold.combine(Manual), Threshold);
        assert_eq!(Threshold.combine(TimeBased), Threshold);
        assert_eq!(TimeBased.combine(Threshold), Threshold);

        // Manual takes priority over TimeBased
        assert_eq!(Manual.combine(TimeBased), Manual);
        assert_eq!(TimeBased.combine(Manual), Manual);

        // TimeBased with TimeBased
        assert_eq!(TimeBased.combine(TimeBased), TimeBased);
    }
}
