//! Backgrounding a mount.
//!
//! A mount without `-f` forks before it does anything else: before it opens its log, takes
//! the volume lock, or starts a thread. The process doing all of that is then the daemon
//! itself. Forking any later - as libfuse's `fuse_daemonize` does, once the mount is up -
//! leaves the lock file and the log's name recording the pid of a parent that exits
//! straight away, and loses every thread already running, since `fork` carries only the
//! calling one over.
//!
//! The parent waits until the mount is up, so a backgrounded mount still reports errors to
//! the terminal and its exit status, just as a foreground one does. Until then the daemon
//! shares the parent's terminal; once mounted, `run_fuse_ll` detaches it and writes to the
//! [`Ready`] pipe, and the parent exits 0. A daemon that exits first takes the pipe with it,
//! and the parent exits with its status instead.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

/// The daemon's end of the pipe its parent is waiting on, handed to `run_fuse_ll` to write
/// once the mount is up.
#[derive(Debug)]
pub struct Ready(OwnedFd);

impl Ready {
    pub(crate) fn into_raw_fd(self) -> i32 {
        self.0.into_raw_fd()
    }
}

/// Forks into the background. Returns only in the daemon: the parent waits for it to mount,
/// then exits.
pub fn daemonize() -> io::Result<Ready> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(read_end);
            Ok(Ready(write_end))
        }
        daemon => {
            // Dropped so that the daemon's copy is the last writer, and its exit reads as EOF.
            drop(write_end);
            std::process::exit(wait_for_mount(read_end, daemon))
        }
    }
}

/// The parent's exit status: 0 once the daemon reports its mount is up, or the daemon's own
/// status if it exits without doing so.
fn wait_for_mount(read_end: OwnedFd, daemon: libc::pid_t) -> i32 {
    if File::from(read_end).read_exact(&mut [0u8]).is_ok() {
        return 0;
    }
    let mut status = 0;
    if unsafe { libc::waitpid(daemon, &mut status, 0) } != daemon {
        return 1;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}
