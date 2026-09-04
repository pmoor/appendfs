# AppendFS Development & Agent Guidelines

AppendFS is a high-performance append-only log-structured filesystem with FUSE support, crash recovery, snapshots, and point-in-time time travel.

## Core Philosophy & Design Principles

1. **Correctness & Reliability First**:
   - Correctness and reliability are the single most important aspects of this project. Data durability, crash safety, and POSIX compliance take precedence over premature optimization or convenience.
2. **Determinism Everywhere**:
   - Prefer determinism across the entire codebase.
   - Use injected testable clocks (`Arc<dyn Clock>` / `Clock` trait) rather than unmocked calls to `SystemTime::now()`.
   - Use injected randomness with fixed or reproducible seeds (e.g. `ChaCha8Rng::seed_from_u64(...)`) in tests, fuzzers, and stress suites so every failure can be reliably reproduced and investigated.

## Development & Review Workflow

All code contributions follow a standard fork-and-pull-request workflow:
- **`upstream`**: `pmoor/appendfs` (canonical repository). **Never push directly to `upstream`.**
- **`origin`**: `pmoor-agent/appendfs` (agent working fork). Always push feature branches to `origin`.

### Step-by-Step Lifecycle

1. **Develop on a local feature branch**:
   - Always branch off an up-to-date `main` (synchronized with `upstream/main`).
   - Keep changes focused and atomic.
2. **Push feature branch to `pmoor-agent/appendfs` (`origin`)**:
   - Push to `origin`: `git push -u origin <branch-name>`.
   - Remember: **NEVER push directly to `upstream`**.
3. **Open a Pull Request against upstream (`pmoor/appendfs`)**:
   - Open the PR targeting `main` and assign to `pmoor` (e.g. `gh pr create --repo pmoor/appendfs --base main --assignee pmoor ...`).
   - Include a concise summary of changes, rationale, and verification commands executed.
4. **Wait for review & address feedback**:
   - Query active review threads and resolution status via GraphQL:
     ```bash
     gh api graphql -f query='
       query {
         repository(owner: "pmoor", name: "appendfs") {
           pullRequest(number: <pr>) {
             reviewThreads(first: 50) {
               nodes {
                 id
                 isResolved
                 viewerCanResolve
                 comments(first: 10) { nodes { id body } }
               }
             }
           }
         }
       }
     '
     ```
   - Devise a concrete action plan, implement the requested adjustments on the feature branch, and verify (`cargo fmt --check`, `cargo clippy --all-targets`, `cargo test`).
   - Push updated commits to `origin` (or amend and force-push with `git push origin <branch> --force-with-lease`).
   - Respond to comment threads explaining the resolution (`gh api repos/pmoor/appendfs/pulls/<pr>/comments -X POST -F in_reply_to=<comment-id> -f body="..."`).
   - Resolve comment threads via GraphQL once fully addressed and verified:
     ```bash
     gh api graphql -f query='
       mutation {
         resolveReviewThread(input: {threadId: "<thread-id>"}) {
           thread { isResolved }
         }
       }
     '
     ```
5. **Repeat until all unresolved comments are resolved**.
6. **Wait for PR to be approved and merged** into `upstream/main`.
7. **Clean up local and remote feature branches**:
   - Fetch `upstream/main`, fast-forward local `main`, and push `main` to `origin/main`.
   - Delete the local feature branch (`git branch -d <branch-name>`).
   - Delete / prune the merged remote branch on `origin` (`git remote prune origin`).

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
