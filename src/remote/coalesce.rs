use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Serializable error representation for sharing `io::Error`s across waiting follower threads.
#[derive(Clone, Debug)]
pub struct CoalesceError {
    pub kind: io::ErrorKind,
    pub message: String,
}

impl From<&io::Error> for CoalesceError {
    fn from(err: &io::Error) -> Self {
        Self {
            kind: err.kind(),
            message: err.to_string(),
        }
    }
}

impl From<CoalesceError> for io::Error {
    fn from(err: CoalesceError) -> Self {
        io::Error::new(err.kind, err.message)
    }
}

#[derive(Debug)]
enum CallState {
    InProgress,
    Done(Result<Arc<Vec<u8>>, CoalesceError>),
}

#[derive(Debug)]
struct InFlightCall {
    state: Mutex<CallState>,
    cond: Condvar,
}

impl InFlightCall {
    fn new() -> Self {
        Self {
            state: Mutex::new(CallState::InProgress),
            cond: Condvar::new(),
        }
    }
}

/// A panic-safe, synchronous single-flight deduplicator for concurrent remote reads.
///
/// When multiple concurrent threads request the same `(generation, block_idx)`, only the
/// first thread (the leader) issues the remote fetch. Concurrent follower threads wait on
/// a condition variable and share the resulting `Arc<Vec<u8>>` without issuing redundant
/// network requests or duplicate cache writes.
#[derive(Debug, Default)]
pub struct RemoteReadCoalescer {
    calls: Mutex<HashMap<(u64, u64), Arc<InFlightCall>>>,
    coalesced_requests: AtomicU64,
    leader_requests: AtomicU64,
    in_flight_count: AtomicUsize,
}

/// RAII guard ensuring that if a leader thread panics during the fetch closure,
/// waiting follower threads are promptly notified with an error rather than deadlocking.
struct LeaderGuard<'a> {
    coalescer: &'a RemoteReadCoalescer,
    key: (u64, u64),
    call: Arc<InFlightCall>,
    completed: bool,
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.call.state.lock().unwrap();
            *state = CallState::Done(Err(CoalesceError {
                kind: io::ErrorKind::Interrupted,
                message: "in-flight remote read aborted due to thread panic".to_string(),
            }));
            self.call.cond.notify_all();

            let mut calls = self.coalescer.calls.lock().unwrap();
            calls.remove(&self.key);
            self.coalescer.in_flight_count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl RemoteReadCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of concurrent requests deduplicated (joined an existing in-flight fetch).
    pub fn coalesced_requests(&self) -> u64 {
        self.coalesced_requests.load(Ordering::SeqCst)
    }

    /// Number of requests that acted as leaders (initiated an actual fetch).
    pub fn leader_requests(&self) -> u64 {
        self.leader_requests.load(Ordering::SeqCst)
    }

    /// Total number of requests processed by this coalescer.
    pub fn total_requests(&self) -> u64 {
        self.leader_requests() + self.coalesced_requests()
    }

    /// Current number of distinct block fetches in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight_count.load(Ordering::SeqCst)
    }

    /// Executes `fetch` for `key` if no fetch is currently in flight.
    /// If an identical fetch is already in flight, awaits its completion and shares the result.
    pub fn coalesce<F>(&self, key: (u64, u64), fetch: F) -> io::Result<Arc<Vec<u8>>>
    where
        F: FnOnce() -> io::Result<Arc<Vec<u8>>>,
    {
        let call = {
            let mut calls = self.calls.lock().unwrap();
            if let Some(existing) = calls.get(&key) {
                // Follower: join existing in-flight call
                self.coalesced_requests.fetch_add(1, Ordering::SeqCst);
                Arc::clone(existing)
            } else {
                // Leader: register new in-flight call
                self.leader_requests.fetch_add(1, Ordering::SeqCst);
                self.in_flight_count.fetch_add(1, Ordering::SeqCst);
                let call = Arc::new(InFlightCall::new());
                calls.insert(key, Arc::clone(&call));

                let mut guard = LeaderGuard {
                    coalescer: self,
                    key,
                    call: Arc::clone(&call),
                    completed: false,
                };

                // Drop map lock before initiating network/storage I/O
                drop(calls);

                let result = fetch();

                // Publish result to all waiting followers
                {
                    let mut state = guard.call.state.lock().unwrap();
                    match result {
                        Ok(ref data) => {
                            *state = CallState::Done(Ok(Arc::clone(data)));
                        }
                        Err(ref err) => {
                            *state = CallState::Done(Err(CoalesceError::from(err)));
                        }
                    }
                    guard.call.cond.notify_all();
                }

                // Remove from in-flight calls map
                {
                    let mut calls = guard.coalescer.calls.lock().unwrap();
                    calls.remove(&guard.key);
                    guard.coalescer.in_flight_count.fetch_sub(1, Ordering::SeqCst);
                }

                guard.completed = true;
                return result;
            }
        };

        // Follower: wait for leader to complete the fetch
        let mut state = call.state.lock().unwrap();
        loop {
            match *state {
                CallState::InProgress => {
                    state = call.cond.wait(state).unwrap();
                }
                CallState::Done(Ok(ref data)) => {
                    return Ok(Arc::clone(data));
                }
                CallState::Done(Err(ref err)) => {
                    return Err(io::Error::from(err.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_singleflight_coalescing_concurrent_identical_requests() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let invocations = Arc::new(AtomicUsize::new(0));

        let num_threads = 10;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let c = Arc::clone(&coalescer);
            let inv = Arc::clone(&invocations);
            handles.push(thread::spawn(move || {
                c.coalesce((1, 0), || {
                    inv.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(50));
                    Ok(Arc::new(vec![42u8; 1024]))
                })
                .unwrap()
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap());
        }

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "fetch closure must be called only once"
        );
        assert_eq!(coalescer.leader_requests(), 1);
        assert_eq!(coalescer.coalesced_requests(), (num_threads - 1) as u64);
        assert_eq!(coalescer.total_requests(), num_threads as u64);
        assert_eq!(coalescer.in_flight(), 0);

        for res in results {
            assert_eq!(&res[..], &[42u8; 1024]);
        }
    }

    #[test]
    fn test_singleflight_independent_keys() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let inv1 = Arc::new(AtomicUsize::new(0));
        let inv2 = Arc::new(AtomicUsize::new(0));

        let c1 = Arc::clone(&coalescer);
        let i1 = Arc::clone(&inv1);
        let h1 = thread::spawn(move || {
            c1.coalesce((1, 0), || {
                i1.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                Ok(Arc::new(vec![1u8; 10]))
            })
            .unwrap()
        });

        let c2 = Arc::clone(&coalescer);
        let i2 = Arc::clone(&inv2);
        let h2 = thread::spawn(move || {
            c2.coalesce((1, 1), || {
                i2.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                Ok(Arc::new(vec![2u8; 10]))
            })
            .unwrap()
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        assert_eq!(&r1[..], &[1u8; 10]);
        assert_eq!(&r2[..], &[2u8; 10]);
        assert_eq!(inv1.load(Ordering::SeqCst), 1);
        assert_eq!(inv2.load(Ordering::SeqCst), 1);
        assert_eq!(coalescer.leader_requests(), 2);
        assert_eq!(coalescer.coalesced_requests(), 0);
    }

    #[test]
    fn test_singleflight_error_propagation() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let mut handles = Vec::new();

        for _ in 0..5 {
            let c = Arc::clone(&coalescer);
            handles.push(thread::spawn(move || {
                c.coalesce((1, 0), || {
                    thread::sleep(Duration::from_millis(20));
                    Err(io::Error::new(io::ErrorKind::ConnectionReset, "network dropped"))
                })
            }));
        }

        for h in handles {
            let res = h.join().unwrap();
            assert!(res.is_err());
            let err = res.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            assert!(err.to_string().contains("network dropped"));
        }

        assert_eq!(coalescer.leader_requests(), 1);
        assert_eq!(coalescer.coalesced_requests(), 4);
    }

    #[test]
    fn test_singleflight_panic_safety() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());

        let c1 = Arc::clone(&coalescer);
        let h1 = thread::spawn(move || {
            c1.coalesce((1, 0), || -> io::Result<Arc<Vec<u8>>> {
                thread::sleep(Duration::from_millis(20));
                panic!("leader thread simulated crash");
            })
        });

        let c2 = Arc::clone(&coalescer);
        let h2 = thread::spawn(move || {
            // Give leader thread a few millis to become leader
            thread::sleep(Duration::from_millis(5));
            c2.coalesce((1, 0), || Ok(Arc::new(vec![0u8])))
        });

        // h1 panics
        assert!(h1.join().is_err());

        // h2 must not deadlock, but receive an Interrupted error
        let r2 = h2.join().unwrap();
        assert!(r2.is_err());
        assert_eq!(r2.unwrap_err().kind(), io::ErrorKind::Interrupted);

        assert_eq!(coalescer.in_flight(), 0);
    }
}
