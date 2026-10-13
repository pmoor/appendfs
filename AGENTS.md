# AppendFS Development & Agent Guidelines

AppendFS is a high-performance append-only log-structured filesystem with FUSE support, crash recovery, snapshots, and point-in-time time travel.

## Core Philosophy & Design Principles

1. **Correctness & Reliability First**:
   - Correctness and reliability are the single most important aspects of this project. Data durability, crash safety, and POSIX compliance take precedence over premature optimization or convenience.
2. **Determinism Everywhere**:
   - Prefer determinism across the entire codebase.
   - Use injected testable clocks (`Arc<dyn Clock>` / `Clock` trait) rather than unmocked calls to `SystemTime::now()`.
   - Use injected randomness with fixed or reproducible seeds (e.g. `ChaCha8Rng::seed_from_u64(...)`) in tests, fuzzers, and stress suites so every failure can be reliably reproduced and investigated.
3. **Clean API Evolution & No Deprecated Shims**:
   - When refactoring and introducing a new function, method, helper, or type (e.g. replacing an instance method with a standalone helper, updating a method signature, or renaming a type without keeping a legacy type alias), do not keep the superseded version around as an unnecessary forwarding shim, alias, or duplicate wrapper.
   - Fully remove the old variant and migrate all callers across the codebase—including internal modules, call sites, and test suites—even if updating callers is tedious.
   - Avoid accumulating duplicate entry points, alias cruft, and method variations to prevent API ambiguity and technical debt.

## Development & Review Workflow

All code contributions follow a standard fork-and-pull-request workflow:
- **`upstream`**: `pmoor/appendfs` (canonical repository). **Never push directly to `upstream`.**
- **`origin`**: `pmoor-agent/appendfs` (agent working fork). Always push feature branches to `origin`.

### Step-by-Step Lifecycle

1. **Develop on a local feature branch**:
   - Always update the repository first (`git fetch upstream`) and base feature branches off `upstream/main`.
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
   - Devise a concrete action plan, implement the requested adjustments on the feature branch, and verify (`cargo fmt --check`, `cargo clippy --all-targets`, `timeout 5m cargo test`).
   - Push updated commits to `origin` (or amend and force-push with `git push origin <branch> --force-with-lease`).
   - Keep the Pull Request description updated: Always run `gh pr edit <pr> --body-file <file>` (or `--body "..."`) whenever review adjustments modify scope, rationale, or behavior so the PR text stays synchronized with the latest commits.
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
   - Never check out `main` in any worktree. `git fetch upstream` keeps local `main` mirrored to `upstream/main` on its own, and refuses to update a `main` that is checked out somewhere, which breaks the fetch for every worktree.
   - Update the fork's `main` without touching local branches: `git fetch upstream && git push origin upstream/main:main`.
   - Detach the worktree from the merged branch (`git checkout --detach`), then delete the local feature branch (`git branch -d <branch-name>`).
   - Delete / prune the merged remote branch on `origin` (`git remote prune origin`).
   - Clean build artifacts in the worktree to reclaim disk space (`cargo clean`).

## Common Commands

### Build
- `cargo build` (debug build)
- `cargo build --release` (optimized release build)

### Lint & Format
- `cargo fmt --check`
- `cargo clippy --all-targets`

### Standard Testing
To prevent test runs from hanging indefinitely due to deadlocks or lock contention, always wrap `cargo test` invocations with an overall timeout using GNU `timeout` (e.g. `timeout 5m` or `timeout -k 10s 5m`):
- Run all tests (debug): `timeout 5m cargo test`
- Run all tests (release): `timeout 5m cargo test --release`
- Run specific test file: `timeout 5m cargo test --test <name>` (e.g. `timeout 5m cargo test --test integration_test`)

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
    FUZZ_SEEDS=300 FUZZ_STEPS=8000 timeout 5m cargo test --release --test concurrency_test -- --nocapture
    ```
  - Fuzzing & crash recovery soak (~85s):
    ```bash
    FUZZ_SEEDS=300 FUZZ_STEPS=10000 timeout 5m cargo test --release --test fuzz_test -- --nocapture
    ```

- **Quick 10× Sanity Sweep (~5s total)**:
  ```bash
  FUZZ_SEEDS=50 FUZZ_STEPS=2000 timeout 5m cargo test --release
  ```

- **Custom sweeps**:
  ```bash
  FUZZ_STEPS=500 FUZZ_SEEDS=20 timeout 5m cargo test --release --test fuzz_test -- --nocapture
  ```

## On-Disk Format Compatibility & Golden Fixtures

AppendFS maintains a suite of checked-in golden fixture files in `tests/fixtures/` to verify that older on-disk formats can be reliably recovered and mounted by current and future versions.

### Running Compatibility Tests
```bash
timeout 5m cargo test --test compat_test
```
`tests/compat_test.rs` automatically discovers and runs full recovery checks against all `tests/fixtures/v*` directories.

### Generating Golden Fixtures
Golden fixtures are produced deterministically via the `generate_compat_fixture` binary:

- **Frozen older fixtures**:
  Fixtures of every format version before the current one (`v1*` today) must **never** be regenerated. The generator only writes the current format, and refuses any other version's directory.
- **Generate fixtures for the current format version (`CURRENT_VERSION`, e.g. v2)**:
  ```bash
  cargo run --bin generate_compat_fixture tests/fixtures/v2
  ```

The generator produces:
- `000000.summary`: Initial volume snapshot with deterministic mock timestamp.
- `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and xattrs.
- `000001.summary`: Exported snapshot of all populated inodes.

## Storage Versioning & Production Compatibility Policy

AppendFS now has a live production deployment. Format changes can **no longer be made willy-nilly**:

- **No v1 Fixture Regeneration**:
  - Golden files for `v1` (`tests/fixtures/v1*`) are frozen and must **never** be regenerated or modified.
- **Explicit Version Increments**:
  - Any breaking change to on-disk structures (log record formats, record headers, summary formats, or volume layout) requires introducing a new storage version by bumping `CURRENT_VERSION` and/or `CURRENT_SUMMARY_VERSION`.
- **Backward Compatibility & Recovery**:
  - New versions of AppendFS must maintain backward compatibility, continuing to cleanly recover and mount volumes created by older format versions (including `v1`).
- **Fixture Retention**:
  - Golden fixtures for each format version must be permanently retained under `tests/fixtures/` (e.g. `tests/fixtures/v1`, `tests/fixtures/v2`) so `tests/compat_test.rs` continuously validates backward compatibility across all supported versions.
- **Generating Fixtures for New Versions**:
  - When introducing a new storage version (e.g. `v2`), generate a new fixture directory rather than modifying existing ones:
    ```bash
    cargo run --bin generate_compat_fixture tests/fixtures/v2
    ```

## Architectural & Recovery Invariants

- **State Restoration Invariant**:
  - Any runtime state, counter, or threshold in `AppendFs` that governs operational lifecycle decisions (e.g. `last_summary_generation` for log pruning/tiered eviction, `next_inode`, `last_batch_id`) **must be explicitly restored in `recover_fs`** from the recovered summary file or replayed log stream.
  - An unmount/remount or crash recovery cycle must never reset operational progress or disable lifecycle tasks like tiered pruning.
- **Test-Only Exports & Standalone Binaries**:
  - Whenever mock stores, latency wrappers, or test doubles are gated behind `#[cfg(any(test, feature = "testing"))]` in submodules, ensure all top-level re-exports in `src/lib.rs` use the identical `cfg` gate so standalone binaries (`src/bin/*`, examples, benchmarks) compile cleanly without requiring test flags.
