//! Shared asynchronous runtime management for AppendFS.

use std::future::Future;
use std::sync::LazyLock;
use tokio::runtime::{Builder, Handle, Runtime};

static GLOBAL_ASYNC_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().max(16))
        .unwrap_or(16);
    Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("appendfs-io")
        .enable_all()
        .build()
        .expect("failed to initialize appendfs async runtime")
});

/// Spawns a future on the active Tokio runtime if one exists on the current thread,
/// or on the shared multi-threaded background runtime.
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = Handle::try_current() {
        handle.spawn(future);
    } else {
        GLOBAL_ASYNC_RUNTIME.spawn(future);
    }
}

/// Blocks on a future on the current thread, running it to completion.
pub fn block_on<F: Future>(future: F) -> F::Output {
    if let Ok(handle) = Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        GLOBAL_ASYNC_RUNTIME.block_on(future)
    }
}
