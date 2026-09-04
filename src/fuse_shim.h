#ifndef FUSE_SHIM_H
#define FUSE_SHIM_H

#include <cstdint>

// High bit flag indicating dynamic synthesized virtual file handles (bit 63)
constexpr uint64_t VIRTUAL_FH_FLAG = 1ULL << 63;

extern "C" {
typedef void *shim_req_t;

// Simple custom C-compatible attributes struct to avoid system layout mismatches
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

struct shim_flock {
  int16_t type;    // F_RDLCK, F_WRLCK, F_UNLCK
  int16_t whence;  // SEEK_SET, SEEK_CUR, SEEK_END
  int64_t start;
  int64_t len;
  int32_t pid;
};

// Callback signatures that Rust will implement for low-level FUSE
typedef void (*rust_lookup_t)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*rust_getattr_t)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*rust_opendir_t)(shim_req_t req, uint64_t ino, uint32_t flags, void *userdata);
typedef void (*rust_readdir_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh, void *userdata);
typedef void (*rust_readdirplus_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh, void *userdata);
typedef void (*rust_read_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh, void *userdata);
typedef void (*rust_open_t)(shim_req_t req, uint64_t ino, uint32_t flags, void *userdata);
typedef void (*rust_write_t)(shim_req_t req, uint64_t ino, const char *buf, size_t size, int64_t off, uint64_t fh, void *userdata);
typedef void (*rust_setattr_t)(shim_req_t req, uint64_t ino, uint32_t mode, uint32_t uid, uint32_t gid, int64_t size,
                               int64_t atime_sec, uint32_t atime_nsec, int64_t mtime_sec, uint32_t mtime_nsec,
                               uint32_t to_set, void *userdata);
typedef void (*rust_create_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t flags,
                              void *userdata);
typedef void (*rust_mknod_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t rdev,
                             void *userdata);
typedef void (*rust_unlink_t)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*rust_mkdir_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, void *userdata);
typedef void (*rust_rmdir_t)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*rust_symlink_t)(shim_req_t req, const char *link, uint64_t parent, const char *name, void *userdata);
typedef void (*rust_readlink_t)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*rust_rename_t)(shim_req_t req, uint64_t parent, const char *name, uint64_t newparent,
                              const char *newname, void *userdata);
typedef void (*rust_link_t)(shim_req_t req, uint64_t ino, uint64_t newparent, const char *newname, void *userdata);
typedef void (*rust_fsync_t)(shim_req_t req, uint64_t ino, int datasync, uint64_t fh, void *userdata);
typedef void (*rust_release_t)(shim_req_t req, uint64_t ino, uint64_t fh, void *userdata);
typedef void (*rust_releasedir_t)(shim_req_t req, uint64_t ino, uint64_t fh, void *userdata);
typedef void (*rust_fsyncdir_t)(shim_req_t req, uint64_t ino, int datasync, void *userdata);
typedef void (*rust_statfs_t)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*rust_flock_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, int op, void *userdata);
typedef void (*rust_getlk_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, struct shim_flock *lock,
                             void *userdata);
typedef void (*rust_setlk_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner,
                             const struct shim_flock *lock, int sleep, void *userdata);
typedef void (*rust_getxattr_t)(shim_req_t req, uint64_t ino, const char *name, size_t size, void *userdata);
typedef void (*rust_setxattr_t)(shim_req_t req, uint64_t ino, const char *name, const char *value, size_t size,
                                int flags, void *userdata);
typedef void (*rust_listxattr_t)(shim_req_t req, uint64_t ino, size_t size, void *userdata);
typedef void (*rust_removexattr_t)(shim_req_t req, uint64_t ino, const char *name, void *userdata);
typedef void (*rust_init_t)(void *userdata);
typedef void (*rust_destroy_t)(void *userdata);

struct rust_lowlevel_ops {
  rust_lookup_t lookup;
  rust_getattr_t getattr;
  rust_opendir_t opendir;
  rust_readdir_t readdir;
  rust_readdirplus_t readdirplus;
  rust_read_t read;
  rust_open_t open;
  rust_write_t write;
  rust_setattr_t setattr;
  rust_create_t create;
  rust_mknod_t mknod;
  rust_unlink_t unlink;
  rust_mkdir_t mkdir;
  rust_rmdir_t rmdir;
  rust_symlink_t symlink;
  rust_readlink_t readlink;
  rust_rename_t rename;
  rust_link_t link;
  rust_fsync_t fsync;
  rust_release_t release;
  rust_releasedir_t releasedir;
  rust_fsyncdir_t fsyncdir;
  rust_statfs_t statfs;
  rust_flock_t flock;
  rust_getlk_t getlk;
  rust_setlk_t setlk;
  rust_getxattr_t getxattr;
  rust_setxattr_t setxattr;
  rust_listxattr_t listxattr;
  rust_removexattr_t removexattr;
  rust_init_t init;
  rust_destroy_t destroy;
};

// Entrypoint to mount and run FUSE low-level loop
int run_fuse_ll(int argc, char *argv[], const rust_lowlevel_ops *ops, void *userdata);

// Context getters
uint32_t shim_req_uid(shim_req_t req);
uint32_t shim_req_gid(shim_req_t req);

// FUSE reply wrappers exposed to Rust
int shim_reply_err(shim_req_t req, int err);
int shim_reply_attr(shim_req_t req, const shim_file_attr *attr, double attr_timeout);
int shim_reply_entry(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout);
int shim_reply_buf(shim_req_t req, const char *buf, size_t size);
int shim_reply_open(shim_req_t req, uint64_t fh);
int shim_reply_write(shim_req_t req, size_t count);
int shim_reply_create(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout,
                      uint64_t fh);
int shim_reply_readlink(shim_req_t req, const char *link);
int shim_reply_statfs(shim_req_t req, const shim_statfs_attr *attr);
int shim_reply_lock(shim_req_t req, const struct shim_flock *lock);
int shim_reply_xattr(shim_req_t req, size_t count);

// Directory entry layout packing helper using individual fields instead of stat struct
size_t shim_add_direntry(shim_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode,
                         int64_t off);
size_t shim_add_direntry_plus(shim_req_t req, char *buf, size_t bufsize, const char *name, const shim_file_attr *attr,
                              double attr_timeout, double entry_timeout, int64_t off);
}

#endif // FUSE_SHIM_H
