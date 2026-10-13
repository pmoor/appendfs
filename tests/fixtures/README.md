# AppendFS Format Compatibility Fixtures

This directory contains checked-in golden on-disk storage fixtures used by `tests/compat_test.rs` to guarantee backward compatibility across format versions.

## Fixture Versions

- `v2/`: Plaintext uncompressed golden files for format version 2 (`FileHeader` version 2, `SummaryHeader` version 1) - the current format. The same tree as `v1`, plus `dir_b/cloned.bin`, assembled by `copy_file_range` from records of other files, so `000001.log` carries `Ref` extents.
  - `000000.summary`, `000001.log`, `000001.summary`, `*-dump.txt`, `fsck-report.txt`: as for `v1`.

- `v2_key_file_compressed/`: The `v2` tree, ChaCha20-Poly1305 encrypted under the key in `key.pem`, with Zstd record compression.
  - `key.pem`, `000000.summary`, `000001.log`, `000001.summary`, `*-dump.txt`, `fsck-report.txt`: as for `v1_key_file_compressed`.

The `v1*` fixtures below are frozen: they were written by format version 1, which the generator can no longer produce.

- `v1/`: Plaintext uncompressed golden files for format version 1 (`RecordHeader` version 1, `SummaryHeader` version 1).
  - `000000.summary`: Initial volume summary snapshot.
  - `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and extended attributes.
  - `000001.summary`: Exported snapshot of all populated inodes.
  - `*-dump.txt`: Golden dump inspection outputs for summary and log files.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_key_file_compressed/`: ChaCha20-Poly1305 encrypted golden files under the key in `key.pem`, with Zstd record compression.
  - `key.pem`: Canonical unencrypted key file.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_passphrase_compressed/`: Legacy fixture from a retired credential mode: the volume key was derived with Argon2id from the passphrase `"passphrase"` alone. That derived key now sits in `key.pem`, itself encrypted under the passphrase `"passphrase"`. Recovery-only: nothing can generate this fixture any more.
  - `key.pem`: Passphrase-encrypted key file holding the derived volume key.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_secret_key_passphrase_compressed/`: Legacy fixture from a retired credential mode: the volume key was derived with Argon2id from a key file plus the passphrase `"passphrase"`. That derived key now sits in `key.pem`, itself encrypted under the passphrase `"passphrase"`. Recovery-only: nothing can generate this fixture any more.
  - `key.pem`: Passphrase-encrypted key file holding the derived volume key.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

## Generating or Updating Fixtures

Fixtures are generated deterministically using a fixed mock timestamp and explicit IVs via `generate_compat_fixture`, which writes the current format version only:

```bash
# Regenerate all golden fixtures of the current format version:
cargo run --bin generate_compat_fixture

# Regenerate specific golden fixtures:
cargo run --bin generate_compat_fixture tests/fixtures/v2
cargo run --bin generate_compat_fixture tests/fixtures/v2_key_file_compressed
```

When a format change bumps `CURRENT_VERSION`, generate the new version's directories alongside the existing ones, which then become frozen.

Any new version subdirectories added to `tests/fixtures/` are automatically discovered and tested by `tests/compat_test.rs`.
