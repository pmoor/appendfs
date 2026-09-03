# AppendFS Development & Agent Guidelines

AppendFS is a high-performance append-only log-structured filesystem with FUSE support, crash recovery, snapshots, and point-in-time time travel.

## Common Commands

### Build
- `cargo build` (debug build)
- `cargo build --release` (optimized release build)

### Lint & Format
- `cargo fmt --check`
- `cargo clippy --all-targets`

### Standard Testing
- Run all tests (debug): `cargo test`
- Run all tests (release): `cargo test --release`
- Run specific test file: `cargo test --test <name>` (e.g. `cargo test --test integration_test`)

## Extended & Stress Testing

Certain test suites (differential fuzzing and concurrent stress testing) support configurable iterations via environment variables.

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `FUZZ_SEEDS` | Number of seed iterations to sweep across in `fuzz_test.rs` and `concurrency_test.rs`. | `5` |
| `FUZZ_STEPS` | Number of operations/steps per seed in `fuzz_test.rs` (fuzz & summary determinism) and per-thread op count in `concurrency_test.rs`. | `200` / `150` / `400` |

### Running Stress Sweeps

- **Recommended Extended Sanity / Soak Check (~1 minute each in release mode)**:
  - Concurrent stress soak (~90s):
    ```bash
    FUZZ_SEEDS=300 FUZZ_STEPS=8000 cargo test --release --test concurrency_test -- --nocapture
    ```
  - Fuzzing & crash recovery soak (~85s):
    ```bash
    FUZZ_SEEDS=500 FUZZ_STEPS=10000 cargo test --release --test fuzz_test -- --nocapture
    ```

- **Quick 10× Sanity Sweep (~5s total)**:
  ```bash
  FUZZ_SEEDS=50 FUZZ_STEPS=2000 cargo test --release
  ```

- **Custom sweeps**:
  ```bash
  FUZZ_STEPS=500 FUZZ_SEEDS=20 cargo test --release --test fuzz_test -- --nocapture
  ```

## On-Disk Format Compatibility & Golden Fixtures

AppendFS maintains a suite of checked-in golden fixture files in `tests/fixtures/` to verify that older on-disk formats can be reliably recovered and mounted by current and future versions.

### Running Compatibility Tests
```bash
cargo test --test compat_test
```
`tests/compat_test.rs` automatically discovers and runs full recovery checks against all `tests/fixtures/v*` directories.

### Generating or Updating Golden Fixtures
Golden fixtures are produced deterministically via the `generate_compat_fixture` binary:

- **Regenerate existing v1 fixtures**:
  ```bash
  cargo run --bin generate_compat_fixture tests/fixtures/v1
  ```

- **Generate fixtures for a new format version (e.g. v2)**:
  ```bash
  cargo run --bin generate_compat_fixture tests/fixtures/v2
  ```

The generator produces:
- `000000.summary`: Initial volume snapshot with deterministic mock timestamp.
- `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and xattrs.
- `000001.summary`: Exported snapshot of all populated inodes.

## Pre-Release vs. Post-Release Compatibility Policy

- **Pre-Release (v0 development)**:
  - While AppendFS has no real-life production deployments, keep format versioning fresh at version 1.
  - Do not add legacy deserializers, compatibility shims, or migration fallbacks for unreleased schema adjustments.
  - When modifying persisted structs or headers, cleanly regenerate `tests/fixtures/v1`:
    ```bash
    cargo run --bin generate_compat_fixture tests/fixtures/v1
    ```
- **Post-Release (Production)**:
  - Any breaking format modification requires bumping `CURRENT_VERSION` / `CURRENT_SUMMARY_VERSION`.
  - Introduce a new fixture directory (`tests/fixtures/v2/`) and retain `tests/fixtures/v1/` to verify forward/backward compatibility.

## Architectural & Recovery Invariants

- **State Restoration Invariant**:
  - Any runtime state, counter, or threshold in `InMemoryFS` that governs operational lifecycle decisions (e.g. `last_summary_generation` for log pruning/tiered eviction, `next_inode`, `last_tx_id`) **must be explicitly restored in `recover_fs`** from the recovered summary file or replayed log stream.
  - An unmount/remount or crash recovery cycle must never reset operational progress or disable lifecycle tasks like tiered pruning.
- **Test-Only Exports & Standalone Binaries**:
  - Whenever mock stores, latency wrappers, or test doubles are gated behind `#[cfg(any(test, feature = "testing"))]` in submodules, ensure all top-level re-exports in `src/lib.rs` use the identical `cfg` gate so standalone binaries (`src/bin/*`, examples, benchmarks) compile cleanly without requiring test flags.
