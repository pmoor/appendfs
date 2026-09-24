#define FUSE_USE_VERSION 31

#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse_opt.h>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

struct shim_req_t {
  fuse_req_t req;
  void *userdata;
};

struct shim_file_attr {
  uint64_t ino;
  uint32_t mode;
  uint32_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint32_t rdev;
  int64_t size;
  int64_t atime_sec;
  uint32_t atime_nsec;
  int64_t mtime_sec;
  uint32_t mtime_nsec;
  int64_t ctime_sec;
  uint32_t ctime_nsec;
};

struct shim_statfs_attr {
  uint64_t blocks;
  uint64_t bfree;
  uint64_t bavail;
  uint64_t files;
  uint64_t ffree;
  uint32_t bsize;
  uint32_t namelen;
};

struct shim_fuse_ctx {
  uint32_t uid;
  uint32_t gid;
  int32_t pid;
  uint32_t umask;
};

struct shim_flock {
  int16_t type;    // F_RDLCK, F_WRLCK, F_UNLCK
  int16_t whence;  // SEEK_SET, SEEK_CUR, SEEK_END
  int64_t start;
  int64_t len;
  int32_t pid;
};

extern "C" {

typedef void (*shim_lookup_fn)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*shim_getattr_fn)(shim_req_t req, uint64_t ino);
typedef void (*shim_opendir_fn)(shim_req_t req, uint64_t ino, uint32_t flags);
typedef void (*shim_readdir_fn)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*shim_readdirplus_fn)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*shim_read_fn)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*shim_open_fn)(shim_req_t req, uint64_t ino, uint32_t flags);
typedef void (*shim_write_fn)(shim_req_t req, uint64_t ino, const uint8_t *buf, size_t size, int64_t off,
                              uint64_t fh);
typedef void (*shim_setattr_fn)(shim_req_t req, uint64_t ino, uint32_t mode, uint32_t uid, uint32_t gid, int64_t size,
                                int64_t atime_sec, uint32_t atime_nsec, int64_t mtime_sec, uint32_t mtime_nsec,
                                uint32_t to_set);
typedef void (*shim_create_fn)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t flags);
typedef void (*shim_mknod_fn)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t rdev);
typedef void (*shim_unlink_fn)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*shim_mkdir_fn)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode);
typedef void (*shim_rmdir_fn)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*shim_symlink_fn)(shim_req_t req, const char *link, uint64_t parent, const char *name);
typedef void (*shim_readlink_fn)(shim_req_t req, uint64_t ino);
typedef void (*shim_rename_fn)(shim_req_t req, uint64_t parent, const char *name, uint64_t newparent,
                               const char *newname);
typedef void (*shim_link_fn)(shim_req_t req, uint64_t ino, uint64_t newparent, const char *newname);
typedef void (*shim_fsync_fn)(shim_req_t req, uint64_t ino, int datasync, uint64_t fh);
typedef void (*shim_fallocate_fn)(shim_req_t req, uint64_t ino, int32_t mode, int64_t offset, int64_t length,
                                  uint64_t fh);
typedef void (*shim_release_fn)(shim_req_t req, uint64_t ino, uint64_t fh);
typedef void (*shim_releasedir_fn)(shim_req_t req, uint64_t ino, uint64_t fh);
typedef void (*shim_fsyncdir_fn)(shim_req_t req, uint64_t ino, int datasync);
typedef void (*shim_statfs_fn)(shim_req_t req, uint64_t ino);
typedef void (*shim_flock_fn)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, int op);
typedef void (*shim_getlk_fn)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, struct shim_flock *lock);
typedef void (*shim_setlk_fn)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner,
                              const struct shim_flock *lock, int sleep);
typedef void (*shim_getxattr_fn)(shim_req_t req, uint64_t ino, const char *name, size_t size);
typedef void (*shim_setxattr_fn)(shim_req_t req, uint64_t ino, const char *name, const char *value, size_t size,
                                 int flags);
typedef void (*shim_listxattr_fn)(shim_req_t req, uint64_t ino, size_t size);
typedef void (*shim_removexattr_fn)(shim_req_t req, uint64_t ino, const char *name);
typedef void (*shim_init_fn)(void *userdata);
typedef void (*shim_destroy_fn)(void *userdata);

struct RustLowlevelOps {
  shim_lookup_fn lookup;
  shim_getattr_fn getattr;
  shim_opendir_fn opendir;
  shim_readdir_fn readdir;
  shim_readdirplus_fn readdirplus;
  shim_read_fn read;
  shim_open_fn open;
  shim_write_fn write;
  shim_setattr_fn setattr;
  shim_create_fn create;
  shim_mknod_fn mknod;
  shim_unlink_fn unlink;
  shim_mkdir_fn mkdir;
  shim_rmdir_fn rmdir;
  shim_symlink_fn symlink;
  shim_readlink_fn readlink;
  shim_rename_fn rename;
  shim_link_fn link;
  shim_fsync_fn fsync;
  shim_fallocate_fn fallocate;
  shim_release_fn release;
  shim_releasedir_fn releasedir;
  shim_fsyncdir_fn fsyncdir;
  shim_statfs_fn statfs;
  shim_flock_fn flock;
  shim_getlk_fn getlk;
  shim_setlk_fn setlk;
  shim_getxattr_fn getxattr;
  shim_setxattr_fn setxattr;
  shim_listxattr_fn listxattr;
  shim_removexattr_fn removexattr;
  shim_init_fn init;
  shim_destroy_fn destroy;
};

} // extern "C"

struct ShimContext {
  RustLowlevelOps ops;
  void *userdata;
  std::atomic<bool> destroyed;
};

static std::mutex global_mount_lock;

static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.lookup) {
    ctx->ops.lookup(shim_req_t{req, ctx->userdata}, parent, name);
  } else {
    fuse_reply_err(req, 38); // ENOSYS
  }
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  (void)fi;
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.getattr) {
    ctx->ops.getattr(shim_req_t{req, ctx->userdata}, ino);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.opendir) {
    ctx->ops.opendir(shim_req_t{req, ctx->userdata}, ino, fi ? fi->flags : 0);
  } else {
    fuse_reply_open(req, fi);
  }
}

static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.readdir) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.readdir(shim_req_t{req, ctx->userdata}, ino, size, static_cast<int64_t>(off), fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.readdirplus) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.readdirplus(shim_req_t{req, ctx->userdata}, ino, size, static_cast<int64_t>(off), fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.read) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.read(shim_req_t{req, ctx->userdata}, ino, size, static_cast<int64_t>(off), fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.open) {
    ctx->ops.open(shim_req_t{req, ctx->userdata}, ino, fi ? fi->flags : 0);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                     struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.write) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.write(shim_req_t{req, ctx->userdata}, ino, reinterpret_cast<const uint8_t *>(buf), size,
                   static_cast<int64_t>(off), fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
  (void)fi;
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.setattr) {
    uint32_t mode = attr ? attr->st_mode : 0;
    uint32_t uid = attr ? attr->st_uid : 0;
    uint32_t gid = attr ? attr->st_gid : 0;
    int64_t size = attr ? attr->st_size : 0;
    int64_t atime_sec = attr ? attr->st_atim.tv_sec : 0;
    uint32_t atime_nsec = attr ? attr->st_atim.tv_nsec : 0;
    int64_t mtime_sec = attr ? attr->st_mtim.tv_sec : 0;
    uint32_t mtime_nsec = attr ? attr->st_mtim.tv_nsec : 0;
    ctx->ops.setattr(shim_req_t{req, ctx->userdata}, ino, mode, uid, gid, size, atime_sec, atime_nsec, mtime_sec,
                     mtime_nsec, static_cast<uint32_t>(to_set));
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.create) {
    ctx->ops.create(shim_req_t{req, ctx->userdata}, parent, name, static_cast<uint32_t>(mode), fi ? fi->flags : 0);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.mknod) {
    ctx->ops.mknod(shim_req_t{req, ctx->userdata}, parent, name, static_cast<uint32_t>(mode),
                   static_cast<uint32_t>(rdev));
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.unlink) {
    ctx->ops.unlink(shim_req_t{req, ctx->userdata}, parent, name);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.mkdir) {
    ctx->ops.mkdir(shim_req_t{req, ctx->userdata}, parent, name, static_cast<uint32_t>(mode));
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.rmdir) {
    ctx->ops.rmdir(shim_req_t{req, ctx->userdata}, parent, name);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.symlink) {
    ctx->ops.symlink(shim_req_t{req, ctx->userdata}, link, parent, name);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_readlink(fuse_req_t req, fuse_ino_t ino) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.readlink) {
    ctx->ops.readlink(shim_req_t{req, ctx->userdata}, ino);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname,
                      unsigned int flags) {
  (void)flags;
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.rename) {
    ctx->ops.rename(shim_req_t{req, ctx->userdata}, parent, name, newparent, newname);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.link) {
    ctx->ops.link(shim_req_t{req, ctx->userdata}, ino, newparent, newname);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.fsync) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.fsync(shim_req_t{req, ctx->userdata}, ino, datasync, fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length,
                         struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.fallocate) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.fallocate(shim_req_t{req, ctx->userdata}, ino, static_cast<int32_t>(mode),
                       static_cast<int64_t>(offset), static_cast<int64_t>(length), fh);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.release) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.release(shim_req_t{req, ctx->userdata}, ino, fh);
  } else {
    fuse_reply_err(req, 0);
  }
}

static void ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.releasedir) {
    uint64_t fh = fi ? fi->fh : 0;
    ctx->ops.releasedir(shim_req_t{req, ctx->userdata}, ino, fh);
  } else {
    fuse_reply_err(req, 0);
  }
}

static void ll_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
  (void)fi;
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.fsyncdir) {
    ctx->ops.fsyncdir(shim_req_t{req, ctx->userdata}, ino, datasync);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_statfs(fuse_req_t req, fuse_ino_t ino) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.statfs) {
    ctx->ops.statfs(shim_req_t{req, ctx->userdata}, ino);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int op) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.flock) {
    uint64_t fh = fi ? fi->fh : 0;
    uint64_t lock_owner = fi ? fi->lock_owner : 0;
    ctx->ops.flock(shim_req_t{req, ctx->userdata}, ino, fh, lock_owner, op);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_getlk(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.getlk && lock) {
    uint64_t fh = fi ? fi->fh : 0;
    uint64_t lock_owner = fi ? fi->lock_owner : 0;
    struct shim_flock sh_lock = {};
    sh_lock.type = lock->l_type;
    sh_lock.whence = lock->l_whence;
    sh_lock.start = lock->l_start;
    sh_lock.len = lock->l_len;
    sh_lock.pid = lock->l_pid;
    ctx->ops.getlk(shim_req_t{req, ctx->userdata}, ino, fh, lock_owner, &sh_lock);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_setlk(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock, int sleep) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.setlk && lock) {
    uint64_t fh = fi ? fi->fh : 0;
    uint64_t lock_owner = fi ? fi->lock_owner : 0;
    struct shim_flock sh_lock = {};
    sh_lock.type = lock->l_type;
    sh_lock.whence = lock->l_whence;
    sh_lock.start = lock->l_start;
    sh_lock.len = lock->l_len;
    sh_lock.pid = lock->l_pid;
    ctx->ops.setlk(shim_req_t{req, ctx->userdata}, ino, fh, lock_owner, &sh_lock, sleep);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.getxattr && name) {
    ctx->ops.getxattr(shim_req_t{req, ctx->userdata}, ino, name, size);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.setxattr && name) {
    ctx->ops.setxattr(shim_req_t{req, ctx->userdata}, ino, name, value, size, flags);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.listxattr) {
    ctx->ops.listxattr(shim_req_t{req, ctx->userdata}, ino, size);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
  auto *ctx = static_cast<ShimContext *>(fuse_req_userdata(req));
  if (ctx && ctx->ops.removexattr && name) {
    ctx->ops.removexattr(shim_req_t{req, ctx->userdata}, ino, name);
  } else {
    fuse_reply_err(req, 38);
  }
}

static void ll_init(void *userdata, struct fuse_conn_info *conn) {
  if (conn) {
    conn->max_write = 1024 * 1024;
    conn->max_readahead = 1024 * 1024;
    conn->time_gran = 1;
    if (conn->capable & FUSE_CAP_ASYNC_READ) {
      conn->want |= FUSE_CAP_ASYNC_READ;
    }
    if (conn->capable & FUSE_CAP_PARALLEL_DIROPS) {
      conn->want |= FUSE_CAP_PARALLEL_DIROPS;
    }
    if (conn->capable & FUSE_CAP_POSIX_LOCKS) {
      conn->want |= FUSE_CAP_POSIX_LOCKS;
    }
    if (conn->capable & FUSE_CAP_FLOCK_LOCKS) {
      conn->want |= FUSE_CAP_FLOCK_LOCKS;
    }
  }
  auto *ctx = static_cast<ShimContext *>(userdata);
  if (ctx && ctx->ops.init) {
    ctx->ops.init(ctx->userdata);
  }
}

static void ll_destroy(void *userdata) {
  auto *ctx = static_cast<ShimContext *>(userdata);
  if (ctx && ctx->ops.destroy) {
    bool expected = false;
    if (ctx->destroyed.compare_exchange_strong(expected, true)) {
      ctx->ops.destroy(ctx->userdata);
    }
  }
}

// The second half of what `fuse_daemonize` does, for a mount that already forked: leave the
// terminal, then tell the parent waiting on `ready_fd` that the mount is up. The fork itself
// happens in Rust (`daemon::daemonize`) before anything else, so that the volume lock and the
// run log are taken by the daemon rather than by a parent about to exit.
static void detach_from_terminal(int ready_fd) {
  (void)setsid();
  int nullfd = open("/dev/null", O_RDWR, 0);
  if (nullfd != -1) {
    (void)dup2(nullfd, 0);
    (void)dup2(nullfd, 1);
    (void)dup2(nullfd, 2);
    if (nullfd > 2) {
      close(nullfd);
    }
  }
  char mounted = 1;
  (void)write(ready_fd, &mounted, sizeof(mounted));
  close(ready_fd);
}

extern "C" {

int run_fuse_ll(int argc, const char *const *argv, const RustLowlevelOps *ops, void *userdata, int ready_fd) {
  std::unique_lock<std::mutex> mount_lock(global_mount_lock);

  struct fuse_args args = FUSE_ARGS_INIT(argc, const_cast<char **>(argv));
  struct fuse_cmdline_opts opts = {};
  struct fuse_lowlevel_ops ll_ops = {};
  struct fuse_session *se = nullptr;
  int ret = -1;
  bool signals_installed = false;

  ShimContext ctx;
  if (ops) {
    ctx.ops = *ops;
  } else {
    memset(&ctx.ops, 0, sizeof(ctx.ops));
  }
  ctx.userdata = userdata;
  ctx.destroyed.store(false);

  if (fuse_parse_cmdline(&args, &opts) != 0) {
    goto err_out1;
  }

  if (opts.show_help) {
    printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
    fuse_cmdline_help();
    fuse_lowlevel_help();
    ret = 0;
    goto err_out1;
  } else if (opts.show_version) {
    printf("FUSE library version %s\n", fuse_pkgversion());
    fuse_lowlevel_version();
    ret = 0;
    goto err_out1;
  }

  if (opts.mountpoint == nullptr) {
    printf("error: no mountpoint specified\n");
    ret = -1;
    goto err_out1;
  }

  // Always enforce kernel-side permission checks (uid/gid/mode) regardless
  // of what mount options the caller passed on the command line.
  if (fuse_opt_add_arg(&args, "-odefault_permissions") != 0) {
    ret = -1;
    goto err_out1;
  }

  ll_ops.init = ll_init;
  ll_ops.destroy = ll_destroy;
  ll_ops.lookup = ll_lookup;
  ll_ops.getattr = ll_getattr;
  ll_ops.opendir = ll_opendir;
  ll_ops.readdir = ll_readdir;
  ll_ops.readdirplus = ll_readdirplus;
  ll_ops.read = ll_read;
  ll_ops.open = ll_open;
  ll_ops.write = ll_write;
  ll_ops.setattr = ll_setattr;
  ll_ops.create = ll_create;
  ll_ops.mknod = ll_mknod;
  ll_ops.unlink = ll_unlink;
  ll_ops.mkdir = ll_mkdir;
  ll_ops.rmdir = ll_rmdir;
  ll_ops.symlink = ll_symlink;
  ll_ops.readlink = ll_readlink;
  ll_ops.rename = ll_rename;
  ll_ops.link = ll_link;
  ll_ops.fsync = ll_fsync;
  ll_ops.fallocate = ll_fallocate;
  ll_ops.release = ll_release;
  ll_ops.releasedir = ll_releasedir;
  ll_ops.fsyncdir = ll_fsyncdir;
  ll_ops.statfs = ll_statfs;
  ll_ops.flock = ll_flock;
  ll_ops.getlk = ll_getlk;
  ll_ops.setlk = ll_setlk;
  ll_ops.getxattr = ll_getxattr;
  ll_ops.setxattr = ll_setxattr;
  ll_ops.listxattr = ll_listxattr;
  ll_ops.removexattr = ll_removexattr;

  se = fuse_session_new(&args, &ll_ops, sizeof(ll_ops), &ctx);
  if (se == nullptr) {
    goto err_out1;
  }

  signals_installed = (fuse_set_signal_handlers(se) == 0);

  if (fuse_session_mount(se, opts.mountpoint) != 0) {
    if (signals_installed) {
      fuse_remove_signal_handlers(se);
    }
    goto err_out2;
  }

  if (ready_fd >= 0) {
    detach_from_terminal(ready_fd);
    ready_fd = -1;
  }
  (void)chdir("/");

  ret = fuse_session_loop(se);
  if (signals_installed && (ret == SIGINT || ret == SIGTERM || ret == SIGHUP)) {
    ret = 0;
  }

  // Drain in-flight asynchronous operations and clean up filesystem state
  // before unmounting and destroying the FUSE session.
  ll_destroy(&ctx);

  if (signals_installed) {
    fuse_remove_signal_handlers(se);
  }

  fuse_session_unmount(se);
err_out2:
  fuse_session_destroy(se);
err_out1:
  // Still open only if the mount failed: closing it without a byte tells the parent so.
  if (ready_fd >= 0) {
    close(ready_fd);
  }
  free(opts.mountpoint);
  fuse_opt_free_args(&args);

  return ret;
}

namespace {

// Standard ceiling division for 512-byte POSIX stat blocks (st_blocks)
inline blkcnt_t size_to_blocks(uint64_t size) {
  return static_cast<blkcnt_t>((size + 511) / 512);
}

inline void populate_stat(const shim_file_attr *attr, struct stat *st) {
  if (!attr || !st) return;
  st->st_ino = attr->ino;
  st->st_mode = attr->mode;
  st->st_nlink = attr->nlink;
  st->st_uid = attr->uid;
  st->st_gid = attr->gid;
  st->st_rdev = attr->rdev;
  st->st_size = attr->size;
  st->st_blocks = size_to_blocks(attr->size);
  st->st_blksize = 4096;
  st->st_atim.tv_sec = attr->atime_sec;
  st->st_atim.tv_nsec = attr->atime_nsec;
  st->st_mtim.tv_sec = attr->mtime_sec;
  st->st_mtim.tv_nsec = attr->mtime_nsec;
  st->st_ctim.tv_sec = attr->ctime_sec;
  st->st_ctim.tv_nsec = attr->ctime_nsec;
}

inline void populate_fuse_entry(const shim_file_attr *attr, double attr_timeout, double entry_timeout,
                                struct fuse_entry_param *e) {
  if (!e) return;
  if (attr) {
    e->ino = attr->ino;
    e->generation = 1;
    populate_stat(attr, &e->attr);
  }
  e->attr_timeout = attr_timeout;
  e->entry_timeout = entry_timeout;
}

} // namespace

int shim_reply_err(fuse_req_t req, int err) { return fuse_reply_err(req, err); }

int shim_reply_entry(fuse_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout) {
  struct fuse_entry_param e = {};
  populate_fuse_entry(attr, attr_timeout, entry_timeout, &e);
  return fuse_reply_entry(req, &e);
}

int shim_reply_attr(fuse_req_t req, const shim_file_attr *attr, double attr_timeout) {
  struct stat stbuf = {};
  if (attr) {
    populate_stat(attr, &stbuf);
  }
  return fuse_reply_attr(req, &stbuf, attr_timeout);
}

int shim_reply_buf(fuse_req_t req, const char *buf, size_t size) {
  return fuse_reply_buf(req, buf, size);
}

int shim_reply_open(fuse_req_t req, uint64_t fh, bool direct_io, bool keep_cache) {
  struct fuse_file_info fi = {};
  fi.fh = fh;
  if (direct_io) {
    fi.direct_io = 1;
  }
  if (keep_cache) {
    fi.keep_cache = 1;
  }
  return fuse_reply_open(req, &fi);
}

int shim_reply_write(fuse_req_t req, size_t count) { return fuse_reply_write(req, count); }

int shim_reply_create(fuse_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout,
                      uint64_t fh) {
  struct fuse_entry_param e = {};
  populate_fuse_entry(attr, attr_timeout, entry_timeout, &e);
  struct fuse_file_info fi = {};
  fi.fh = fh;
  return fuse_reply_create(req, &e, &fi);
}

int shim_reply_readlink(fuse_req_t req, const char *link) {
  return fuse_reply_readlink(req, link);
}

int shim_reply_statfs(fuse_req_t req, const shim_statfs_attr *attr) {
  struct statvfs stbuf = {};
  if (attr) {
    stbuf.f_bsize = attr->bsize;
    stbuf.f_frsize = attr->bsize;
    stbuf.f_blocks = attr->blocks;
    stbuf.f_bfree = attr->bfree;
    stbuf.f_bavail = attr->bavail;
    stbuf.f_files = attr->files;
    stbuf.f_ffree = attr->ffree;
    stbuf.f_favail = attr->ffree;
    stbuf.f_namemax = attr->namelen;
  }
  return fuse_reply_statfs(req, &stbuf);
}

int shim_reply_lock(fuse_req_t req, const struct shim_flock *lock) {
  if (!lock) {
    return fuse_reply_err(req, EINVAL);
  }
  struct flock fl = {};
  fl.l_type = lock->type;
  fl.l_whence = lock->whence;
  fl.l_start = lock->start;
  fl.l_len = lock->len;
  fl.l_pid = lock->pid;
  return fuse_reply_lock(req, &fl);
}

int shim_reply_xattr(fuse_req_t req, size_t count) {
  return fuse_reply_xattr(req, count);
}

size_t shim_add_direntry(fuse_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode,
                         int64_t off) {
  struct stat stbuf = {};
  stbuf.st_ino = ino;
  stbuf.st_mode = mode;
  return fuse_add_direntry(req, buf, bufsize, name, &stbuf, static_cast<off_t>(off));
}

size_t shim_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize, const char *name, const shim_file_attr *attr,
                              double attr_timeout, double entry_timeout, int64_t off) {
  struct fuse_entry_param e = {};
  populate_fuse_entry(attr, attr_timeout, entry_timeout, &e);
  return fuse_add_direntry_plus(req, buf, bufsize, name, &e, static_cast<off_t>(off));
}

shim_fuse_ctx fuse_req_ctx_shim(fuse_req_t req) {
  const struct fuse_ctx *ctx = fuse_req_ctx(req);
  shim_fuse_ctx result = {};
  if (ctx) {
    result.uid = ctx->uid;
    result.gid = ctx->gid;
    result.pid = ctx->pid;
    result.umask = ctx->umask;
  }
  return result;
}

} // extern "C"
