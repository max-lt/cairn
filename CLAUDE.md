# Cairn — Content-Addressed File Inventory & Recovery Engine

100% pure Rust. Zero C bindings. Cross-platform (Linux, Windows, macOS). See @docs/plan.md for the full architecture and implementation plan.

## What Cairn Does

Cairn scans filesystems, fingerprints every file by content (BLAKE3), maintains an **append-only inventory** of where each content has ever been seen on every machine, and backs content up to a remote object store (Cloudflare R2). It answers: "do I have this exact file anywhere else?", "where did this file live, and when did it vanish?", "give me back the file that used to be at this path." **Cairn observes; it never deletes user files.**

## Build & Test

```bash
cargo build                          # build everything
cargo test                           # all tests
cargo test -p cairn-types            # single crate
cargo test --test local_pipeline     # single integration test
cargo clippy -- -D warnings          # lint (must pass, zero warnings)
cargo fmt --check                    # format check
```

IMPORTANT: Run `cargo clippy -- -D warnings` and `cargo fmt --check` before considering any milestone complete.

## Workspace Layout

Rust monorepo. All crates live in `crates/`. Integration tests in `tests/`. Plan in `docs/plan.md`.

```
crates/
  cairn-types/      Shared types, IDs (ContentHash, ChunkId, MachineId), HLC, LogEntry, Action, Manifest
  cairn-cas/        CDC chunking, manifests, ChunkTransform pipeline (encryption/compression seam)
  cairn-log/        Append-only hash-chained signed linear log + projection + snapshots
  cairn-catalog/    Local redb cache: scan catalog + materialized hash→locations index
  cairn-scan/       Filesystem walker, incremental hashing, change detection
  cairn-remote/     object_store-backed R2 client (chunks, manifests, segments, snapshots)
  cairn-engine/     Orchestrator: scan → log → catalog → backup → sync in one pass
  cairn-cli/        Binary `cairn` (clap CLI)
```

## Reference Codebase: Shoal

Shoal (`max-lt/shoal`, branch `main`) is a distributed object-storage engine available as reference. Several of its modules solve sub-problems Cairn also faces:

| Cairn needs | Study in Shoal |
| --- | --- |
| CDC chunking | `crates/shoal-cas/src/cdc_chunker.rs` (FastCDC v2020, 1:4:16 ratio) |
| Chunk/manifest shape | `crates/shoal-cas/src/chunker.rs`, `manifest.rs` |
| BLAKE3 newtype IDs | `crates/shoal-types/src/lib.rs` (macro pattern) |
| Hybrid logical clock | `crates/shoal-types/src/lib.rs` (`HybridClock`) |
| Append-only signed log | `crates/shoal-logtree/` (*concepts* only — see below) |
| Verify-on-read discipline | `crates/shoal-store/src/file_store.rs` |
| Manifest versioning | `version: u8` everywhere |

**Do NOT copy these parts of Shoal** (they exist for a distributed multi-writer cluster Cairn is not):

- No multi-parent DAG, no merge entries, no topological sort. Cairn uses **single linear chains per machine** — folded globally with LWW by HLC.
- No erasure coding (`shoal-erasure`, `shoal-placement`). Rely on R2 durability.
- No P2P networking (`shoal-net`, `shoal-cluster`, iroh, foca, gossip). Machines converge **only** through the shared remote object store.
- No S3 server (`shoal-s3`). Cairn is a *client* of object storage.

## Code Style

- `thiserror` for error types in library crates, `anyhow` only in `cairn-cli`
- `tracing` for all logging, with structured fields. No `println!`
- Serialization: `postcard` + `serde` for wire format and persistence
- All IDs are `[u8; 32]` newtypes. Use `blake3` for hashing
- Async: `tokio` runtime for I/O; `rayon` for CPU-bound hashing. Bridge via channels — never hash on the async runtime
- Keep functions small. Prefer composition over deep nesting
- Every public type and function gets a doc comment

## Dependencies (all pure Rust)

| Purpose          | Crate                                       |
| ---------------- | ------------------------------------------- |
| Hashing          | `blake3`                                    |
| Chunking         | `fastcdc` (v2020 module)                    |
| Filesystem walk  | `jwalk` (parallel)                          |
| CPU parallelism  | `rayon`                                     |
| Local KV store   | `redb` v2 (embedded ACID B-tree)            |
| Object storage   | `object_store` (S3/R2/Memory/Local)         |
| Async            | `tokio`                                     |
| Serialization    | `postcard` + `serde`                        |
| Signing          | `ed25519-dalek` v2                          |
| CLI              | `clap` v4 (derive)                          |
| Config           | `toml`                                      |
| Errors           | `thiserror` (libs), `anyhow` (cli)          |
| Logging          | `tracing` + `tracing-subscriber`            |
| Ignore rules     | `ignore` (from ripgrep)                     |
| Buffers          | `bytes`                                     |

IMPORTANT: Never add a dependency that requires C/C++ compilation or a `cc` build script. If unsure, check the dep's build.rs before adding.

## Workflow

This project is built milestone by milestone. See @docs/plan.md for the full plan with checkboxes.

1. Implement only the milestone you are asked to work on
2. Implement ALL checkboxes and ALL specified tests
3. Run ALL tests for the affected crates — they must pass
4. Run `cargo clippy -- -D warnings` — must be clean
5. Run `cargo fmt` to format
6. Commit
7. Do NOT move to the next milestone unless explicitly asked

## Testing Conventions

- Unit tests: in the same file, under `#[cfg(test)] mod tests`
- Integration tests: in `tests/integration/`
- Safety tests (M15): in `tests/safety/` — these are release-blocking
- Use `tempfile` crate for tests that need filesystem
- Use `tokio::test` for async tests
- Name tests descriptively: `test_chunkid_deterministic`, `test_vanished_does_not_drop_remote_chunk`
- Every milestone has explicit test requirements in plan.md — implement ALL of them

## Safety Invariants (violations are critical)

1. **Cairn never deletes, truncates, or modifies a user file.** Read and stat only.
2. **A `Vanished` event never deletes content from the remote store.** Location-index and content-retention are separate code paths.
3. **Restore always verifies** the reassembled plaintext against its `ContentHash` before writing.
4. **Remote content deletion (`gc`) is opt-in, explicit, and never automatic** — default is dry-run.

## Common Patterns

### ID newtypes

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub fn from_data(data: &[u8]) -> Self {
        Self(blake3::hash(data).into())
    }
}
```

### Error types per crate

```rust
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("invalid hash on entry {seq}")]
    InvalidHash { seq: u64 },
    #[error("broken chain: expected {expected}, found {found}")]
    BrokenChain { expected: String, found: String },
}
```

## Bug Fix Workflow

When fixing a reported bug:

1. **Write a failing test first** that reproduces the bug
2. Run the test to confirm it fails
3. Apply the fix
4. Run the test to confirm it passes
5. Run the full test suite to ensure no regressions

## Things to Avoid

- No `unwrap()` in library code. Use proper error propagation
- No `println!`. Use `tracing::{info, debug, warn, error}`
- No `unsafe` unless absolutely necessary and documented why
- No C dependencies. Ever
- No premature optimization. Correctness first
- Do not implement milestones out of order
- **Do not** copy Shoal's DAG / merge / erasure / P2P / S3-server code — Cairn is structurally simpler
