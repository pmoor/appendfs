# `appendfs` Future Feature Backlog & TODO

## Future Enhancements & Backlog

- [ ] **Log File Revision Identifiers for Compaction:** Add a revision identifier to the log file naming scheme (e.g., `000001-00.log` or `000001_r0.log`) after the generation ID. This will allow future log compaction routines to rewrite existing log generations while preserving the original generation ID and advancing the revision number.
- [ ] **Multi-Write Batch Records (`OP_BATCH_WRITE`):** Batch small staged writes across multiple files into a single log record payload to minimize header overhead for high-frequency micro-writes.
- [x] **Coalesce Adjacent Writes:** When flushing a batch, merge adjacent (contiguous or overlapping) staged writes to the same file into a single write record instead of one record per write, reducing per-record header/checksum overhead for high-frequency sequential writers. Apply the same coalescing when exporting a `.summary` file.
- [x] **Elide Partially-Overwritten Bytes Within a Flush Batch:** Synthesizing writes directly from `RangeMap` at flush time ensures that superseded/overwritten bytes within a flush batch are eliminated and never written to disk, emitting only the surviving merged contiguous extents.
- [ ] **Extended Attributes (`xattrs`):** Support POSIX extended attributes (`setxattr`, `getxattr`, `listxattr`, `removexattr`) for desktop metadata (e.g. macOS Finder tags, custom user attributes).
- [ ] **File Locking (`flock` / `fcntl`):** Support advisory/mandatory FUSE record locking for application concurrency (e.g. SQLite, Git, office applications).
- [ ] **Summary Catalog Exporter CLI:** Add a CLI command/utility (`appendfs catalog <summary_file>`) to parse and print a human-readable file manifest directly from a `.summary` snapshot file without mounting FUSE.
- [ ] **Live Log Streaming:** Optional real-time log streaming transport protocol for continuous remote replication to a secondary server/cluster.
- [ ] **Native Encryption & Key Rotation:** Envelope AEAD encryption (XChaCha20-Poly1305 / AES-256-GCM) with key rotation, Argon2id KDF, and cryptographic erasure via compaction. (See [Design Document](docs/designs/encryption_and_key_rotation.md)).
- [x] **Coalesce Concurrent Remote Reads:** When multiple concurrent threads or readers request extents residing in the same remote 1 MiB block (or overlapping/adjacent ranges), coalesce in-flight remote requests (single-flight / request deduplication) so only one range request is issued over the network while concurrent readers await the shared fetch, preventing redundant network egress and duplicate cache writes.
