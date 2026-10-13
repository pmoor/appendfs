#ifndef FUSE_SHIM_H
#define FUSE_SHIM_H

#include <cstdint>

extern "C" {
struct fuse_req;
typedef struct fuse_req *fuse_req_t;

struct shim_req_t {
  fuse_req_t req;
  void *userdata;
};

// Callback signatures that Rust will implement for low-level FUSE
typedef void (*rust_lookup_t)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*rust_getattr_t)(shim_req_t req, uint64_t ino);
typedef void (*rust_opendir_t)(shim_req_t req, uint64_t ino, uint32_t flags);
typedef void (*rust_readdir_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*rust_readdirplus_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*rust_read_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off, uint64_t fh);
typedef void (*rust_open_t)(shim_req_t req, uint64_t ino, uint32_t flags);
typedef void (*rust_write_t)(shim_req_t req, uint64_t ino, const char *buf, size_t size, int64_t off, uint64_t fh);
typedef void (*rust_setattr_t)(shim_req_t req, uint64_t ino, uint32_t mode, uint32_t uid, uint32_t gid, int64_t size,
                               int64_t atime_sec, uint32_t atime_nsec, int64_t mtime_sec, uint32_t mtime_nsec,
                               uint32_t to_set);
typedef void (*rust_create_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t flags);
typedef void (*rust_mknod_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t rdev);
typedef void (*rust_unlink_t)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*rust_mkdir_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode);
typedef void (*rust_rmdir_t)(shim_req_t req, uint64_t parent, const char *name);
typedef void (*rust_symlink_t)(shim_req_t req, const char *link, uint64_t parent, const char *name);
typedef void (*rust_readlink_t)(shim_req_t req, uint64_t ino);
typedef void (*rust_rename_t)(shim_req_t req, uint64_t parent, const char *name, uint64_t newparent,
                              const char *newname);
typedef void (*rust_link_t)(shim_req_t req, uint64_t ino, uint64_t newparent, const char *newname);
typedef void (*rust_fsync_t)(shim_req_t req, uint64_t ino, int datasync, uint64_t fh);
typedef void (*rust_fallocate_t)(shim_req_t req, uint64_t ino, int32_t mode, int64_t offset, int64_t length,
                                  uint64_t fh);
typedef void (*rust_release_t)(shim_req_t req, uint64_t ino, uint64_t fh);
typedef void (*rust_releasedir_t)(shim_req_t req, uint64_t ino, uint64_t fh);
typedef void (*rust_fsyncdir_t)(shim_req_t req, uint64_t ino, int datasync);
typedef void (*rust_statfs_t)(shim_req_t req, uint64_t ino);
typedef void (*rust_flock_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, int op);
typedef void (*rust_getlk_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner, struct shim_flock *lock);
typedef void (*rust_setlk_t)(shim_req_t req, uint64_t ino, uint64_t fh, uint64_t lock_owner,
                             const struct shim_flock *lock, int sleep);
typedef void (*rust_getxattr_t)(shim_req_t req, uint64_t ino, const char *name, size_t size);
typedef void (*rust_setxattr_t)(shim_req_t req, uint64_t ino, const char *name, const char *value, size_t size,
                                int flags);
typedef void (*rust_listxattr_t)(shim_req_t req, uint64_t ino, size_t size);
typedef void (*rust_removexattr_t)(shim_req_t req, uint64_t ino, const char *name);
typedef void (*rust_copy_file_range_t)(shim_req_t req, uint64_t ino_in, int64_t off_in, uint64_t fh_in,
                                       uint64_t ino_out, int64_t off_out, uint64_t fh_out, size_t len, int flags);
typedef int (*rust_init_t)(void *userdata);
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
  rust_fallocate_t fallocate;
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
  rust_copy_file_range_t copy_file_range;
  rust_init_t init;
  rust_destroy_t destroy;
};

// Entrypoint to mount and run FUSE low-level loop
int run_fuse_ll(int argc, char *argv[], const rust_lowlevel_ops *ops, void *userdata);

// FUSE reply wrappers exposed to Rust
int shim_reply_err(fuse_req_t req, int err);
int shim_reply_attr(fuse_req_t req, const shim_file_attr *attr, double attr_timeout);
int shim_reply_entry(fuse_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout);
int shim_reply_buf(fuse_req_t req, const char *buf, size_t size);
int shim_reply_open(fuse_req_t req, uint64_t fh, bool direct_io, bool keep_cache);
int shim_reply_write(fuse_req_t req, size_t count);
int shim_reply_create(fuse_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout,
                      uint64_t fh);
int shim_reply_readlink(fuse_req_t req, const char *link);
int shim_reply_statfs(fuse_req_t req, const shim_statfs_attr *attr);
int shim_reply_lock(fuse_req_t req, const struct shim_flock *lock);
int shim_reply_xattr(fuse_req_t req, size_t count);

// Directory entry layout packing helper using individual fields instead of stat struct
size_t shim_add_direntry(fuse_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode,
                         int64_t off);
size_t shim_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize, const char *name, const shim_file_attr *attr,
                              double attr_timeout, double entry_timeout, int64_t off);
}

#endif // FUSE_SHIM_H
