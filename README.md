# AppendFS

[![CI](https://github.com/pmoor/appendfs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pmoor/appendfs/actions/workflows/ci.yml)
[![Nightly soak](https://github.com/pmoor/appendfs/actions/workflows/soak.yml/badge.svg?branch=main)](https://github.com/pmoor/appendfs/actions/workflows/soak.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**AppendFS** is a high-performance, log-structured in-memory FUSE filesystem designed around an **append-only backing store** for personal archival storage, corruption-evident data durability, and disaster recovery.

Instead of mutating files in place on disk, AppendFS stages all filesystem operations (file writes, metadata updates, directory creations, deletions, renames, extended attributes) in memory and flushes changes as an append-only sequence of immutable log files ordered by a **monotonic generation sequence number**.

---

## Key Features

- **Append-Only Backing Store**: Physical disk writes are 100% sequential and immutable. Existing log files are never overwritten in place, eliminating fragmentation and protecting against data corruption.
- **In-Memory Staging & Performance**: Operations are staged in memory and served at memory speed while asynchronously committing batches to disk.
- **Instant Crash Recovery**: Power cuts or crashes mid-flush cleanly discard uncommitted trailing batches while preserving all previously committed transactions. Periodic `.summary` checkpoint files enable near-instantaneous startup.
- **Point-in-Time Time Travel**: Mount the filesystem read-only at any past timestamp (`--at-time`) for auditing or backup extraction.
- **Client-Side Authenticated Encryption**: AEAD encryption under a 256-bit key held in a key file, optionally protected by a passphrase that can be changed at any time, with immediate key validation before reading records.
- **Transparent Compression**: Payloads are compressed on the fly using **Zstandard (zstd)**, saving storage space and network transfer costs.
- **Multi-Cloud Replication**: An autonomous background replication worker fans out sealed logs and summaries to S3-compatible cloud providers (AWS S3, Backblaze B2, Cloudflare R2, MinIO, Wasabi, Google Cloud Storage) or local/NFS paths.
- **Tiered Storage & Range Reads**: Local disk space can be reclaimed by pruning uploaded log files. Missing extents are transparently fetched on demand.
- **POSIX Compliant**: Supports regular files, directories, symlinks, hardlinks, special files (FIFOs, Unix sockets, character/block devices), sparse files (hole punching via `fallocate`), zero-copy `copy_file_range` (a `cp` within a volume shares the source's data instead of writing it again), extended attributes (`xattr`), and advisory file locking (`flock` / `fcntl`).
- **Clean-Room Disaster Recovery**: Includes `scripts/restore.py`, an independent Python script that reconstructs the full filesystem tree directly from raw log files without requiring Rust, Cargo, or FUSE.
- **Offline Diagnostics & Verification**: Built-in CLI commands to check filesystem tree consistency and payload checksums (`appendfs fsck`), inspect inode/storage breakdown (`appendfs stats`), and decode individual log records (`appendfs dump`).

---

## Getting Started

### Prerequisites

- **Linux** (Fedora / RHEL):
  ```bash
  sudo dnf install -y fuse3-devel fuse3 pkgconf-pkg-config rust cargo
  ```

### Building from Source

Clone the repository and build the optimized release binary:

```bash
git clone https://github.com/pmoor/appendfs.git
cd appendfs
cargo build --release
```

The compiled binary will be placed at `target/release/appendfs`.

---

## Basic Usage

### 1. Initialize a Volume

Create a directory where AppendFS will store its log files and initialize the volume header:

```bash
# Plaintext volume (compression enabled by default)
appendfs init /var/lib/appendfs_logs

# Encrypted volume: generate a key file (prompts for an optional passphrase), then use it
appendfs key init -o mykey.key
appendfs init --key-file mykey.key /var/lib/appendfs_logs

# Add, change, or remove the key file's passphrase later; the volume is untouched.
# This writes a new key file and leaves the old one for you to remove once it is replaced.
appendfs key change-passphrase mykey.key -o mykey-new.key
```

Back up the key file: it is not stored in the volume, and losing it loses the volume. Key
commands never overwrite an existing file.

### 2. Mount the Filesystem

Mount the volume to a local mountpoint:

```bash
mkdir -p /mnt/mydata

# Mount in background (daemon mode)
appendfs mount /var/lib/appendfs_logs /mnt/mydata

# Or mount in the foreground for debugging
appendfs mount -f /var/lib/appendfs_logs /mnt/mydata
```

*(If the volume is encrypted, pass `--key-file <path>`; you are prompted for the key file's passphrase if it has one).*

### 3. Using the Filesystem

The mounted volume is now ready to use like any standard directory. You can also inspect live runtime metrics and replication status via virtual files in the root of the mount:

```bash
# Inspect live volume runtime status and flush statistics
cat /mnt/mydata/.status

# Inspect remote replication status (when remotes are configured)
cat /mnt/mydata/.remotes
```

### 4. Unmount

Unmount cleanly using standard `fusermount3`:

```bash
fusermount3 -u /mnt/mydata
```

---

## Advanced Operations

### Point-in-Time Time Travel (Read-Only Mounts)

AppendFS enables instant time travel by replaying log records up to a target timestamp:

```bash
# Mount the filesystem state as of a specific timestamp
appendfs mount-ro --at-time "2026-08-17T10:00:00Z" /var/lib/appendfs_logs /mnt/snapshot
```

### Volume Integrity & Statistics

```bash
# Display volume statistics, inode breakdown, and live extent ratio
appendfs stats /var/lib/appendfs_logs

# Run filesystem integrity check (validates structure, link counts, manifests)
appendfs fsck /var/lib/appendfs_logs

# Deep integrity check verifying physical payloads against BLAKE3 checksums
appendfs fsck --verify-data /var/lib/appendfs_logs

# Inspect low-level records inside a specific .log file
appendfs dump -v /var/lib/appendfs_logs/000001.log
```

### Remote Cloud Replication

Configure offsite S3-compatible cloud targets or local backup locations:

```bash
# Add a Backblaze B2 remote target using environment variables for credentials
appendfs remote add /var/lib/appendfs_logs b2 \
  --bucket my-backup-bucket \
  --endpoint https://s3.us-west-002.backblazeb2.com \
  --access-key-id-env B2_KEY_ID \
  --secret-access-key-env B2_APPLICATION_KEY

# Add an AWS S3 target
appendfs remote add /var/lib/appendfs_logs aws \
  --bucket my-aws-archive \
  --region us-east-1 \
  --credentials-file ~/.aws/appendfs_creds

# Add a local NFS / external drive target
appendfs remote add /var/lib/appendfs_logs backup-drive \
  --path /mnt/backup_drive/appendfs_logs

# List configured remotes
appendfs remote list /var/lib/appendfs_logs
```

When mounting a volume with remotes configured, AppendFS automatically spawns a background replication worker to upload sealed generations and checkpoint summaries.

### Standalone Disaster Recovery

If the host machine is lost and neither Rust nor FUSE is available, the clean-room Python recovery script (`scripts/restore.py`) can reconstruct the filesystem tree directly from raw log and summary files:

```bash
# Prerequisites: Python 3 with cryptography, zstandard, argon2-cffi, and blake3
pip install cryptography zstandard argon2-cffi blake3

# Reconstruct all files to a local target directory
python3 scripts/restore.py /var/lib/appendfs_logs /tmp/restored_data

# Encrypted volumes need their key file
python3 scripts/restore.py /var/lib/appendfs_logs /tmp/restored_data --key-file mykey.key
```

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
