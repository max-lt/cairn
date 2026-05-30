# Cairn — Content-Addressed File Inventory & Recovery Engine

> **Name is a placeholder.** A *cairn* is a stack of stones that marks a location and persists on a trail — you add to it on each pass. Rename freely.

## How to Use This Document

This is the **complete architecture and implementation plan** for Cairn. Read the whole thing first to understand the vision, then implement **one milestone at a time**.

A reference codebase, **Shoal** (`max-lt/shoal`, branch `main`), is available to you. Shoal is a *distributed object-storage engine* — a different system at a lower layer — but several of its modules solve sub-problems you also face. Where that is true, this document points you at the exact file to study. **Read "Relationship to Shoal" carefully: some of Shoal's machinery must NOT be copied.**

When asked to work on a milestone:

1. Read the milestone requirements carefully.
2. Implement all checkboxes.
3. Write all specified tests.
4. Run `cargo test` for the affected crates — everything must pass.
5. Run `cargo clippy -- -D warnings` — must be clean.
6. Run `cargo fmt`.
7. **STOP.** Do not proceed to the next milestone unless explicitly asked.

---

## What is Cairn?

Cairn is a cross-platform (Linux, Windows, macOS) command-line tool, written in **100% pure Rust**, that solves one problem: **never lose a file by accident, and know where every file is.**

It does three things:

1. **Scans** the filesystem of a machine, fingerprinting every file by content (BLAKE3). Re-scans are incremental — unchanged files are not re-hashed.
2. **Maintains an append-only inventory**, keyed by content hash, recording every location where each content has ever been seen, on every machine, at every scan pass. Disappearances are recorded as tombstones — **never as destructive edits.**
3. **Backs up content** to a remote object store (Cloudflare R2). The first time a given content is seen anywhere, its bytes are stored remotely (deduplicated, content-defined chunks). After that, even if every local copy is deleted, the content is recoverable.

The motivating scenario: a person with several machines, full of backups-of-backups-of-backups, who occasionally deletes the wrong thing during cleanup. Cairn answers "do I have this exact file anywhere else?", "where did this file live, and when did it vanish?", and "give me back the file that used to be at this path."

**Cairn observes; it does not clean.** It never deletes user files (see Safety Invariants). It is a safety net, not a janitor.

## Core Design Principles

1. **Pure Rust** — Zero C/C++ bindings. Zero `cc` build scripts. Cross-compilation to all three OSes must be trivial. (Same constraint as Shoal.)
2. **Content-addressed** — Every file and every chunk is identified by its BLAKE3 hash. Identity is content, not path.
3. **Append-only & non-destructive** — The inventory is an event log. A file vanishing is an *event*, never an in-place mutation. History is never overwritten. This principle is the entire point of the project; violations are critical bugs.
4. **Decoupled location-index vs. content-retention** — A file disappearing from a path updates the *index* (tombstone) but must **never** delete the *content blob* from the remote store. These are two separate concerns wired through two separate code paths.
5. **Local-first / offline-capable** — A scan runs fully offline against local state. Remote sync and backup are separate, resumable steps that catch up when connectivity exists.
6. **Incremental** — Re-scanning a tree that hasn't changed must do almost no work (a stat per file, no re-hashing, no new log entries).
7. **Idempotent** — Running the same scan twice with no filesystem changes produces no new content events. Re-uploading an already-present chunk is a no-op.

## Relationship to Shoal

Shoal is available as reference. **Reuse these patterns** (study the file, adapt the idea):

| Cairn needs | Study in Shoal | Notes |
| --- | --- | --- |
| Content-defined chunking | `crates/shoal-cas/src/cdc_chunker.rs` | FastCDC (`fastcdc::v2020`), 1:4:16 min/avg/max ratio. Reuse almost verbatim. |
| Chunk/manifest shape | `crates/shoal-cas/src/chunker.rs`, `manifest.rs` | `Chunk { id, offset, data: Bytes }`; manifest = ordered chunk list. |
| BLAKE3 newtype IDs | `crates/shoal-types/src/lib.rs` | `from_data`, `as_bytes`, hex `Display`, serde — copy the macro pattern. |
| Hybrid logical clock | `crates/shoal-types/src/lib.rs` (`HybridClock`) | `tick()` / `witness()` / `current()`. Copy it. |
| Append-only signed log | `crates/shoal-logtree/` | The *concepts*: hash-chaining, ed25519 signing, snapshots, pruning, verify-on-receive. **But see the warning below.** |
| Verify-on-read discipline | `crates/shoal-store/src/file_store.rs` | Re-hash on read; treat corrupt data as missing. |
| Manifest versioning | `version: u8` field everywhere | Reject unknown versions with a clear error. |

**Do NOT copy these parts of Shoal** — they exist for a distributed multi-writer cluster Cairn is not:

- **No multi-parent DAG.** `shoal-logtree` uses a Git-like DAG with multiple parents, merge entries, auto-merge on multiple tips, and Kahn topological sort (`compute_delta`). Cairn does **not** need any of this. In Cairn, **each machine owns a single linear, hash-chained log** — one writer per chain → no concurrent writes to the same chain → no merges, no DAG, no topo-sort. The global view is simply the **union** of all machines' linear logs, folded with Last-Writer-Wins per `(content, location)` by HLC. This is dramatically simpler and is correct here precisely because a given `(machine, path)` location is only ever written by that one machine.
- **No erasure coding** (`shoal-erasure`, `shoal-placement`). Cairn relies on R2's durability; it does not shard data across nodes.
- **No P2P networking** (`shoal-net`, `shoal-cluster`, `iroh`, `foca`, gossip). Machines never talk to each other directly. They synchronize *only* through the shared remote object store.
- **No S3 server** (`shoal-s3`). Cairn is a client of object storage, not a provider of it.

If you find yourself reaching for `iroh`, `foca`, `reed-solomon`, or a multi-parent `parents: Vec<...>`, stop — you are copying the wrong layer.

## Architecture Overview

```
┌───────────────────────────────────────────────┐
│                  CLI (clap)                     │  cairn-cli
├───────────────────────────────────────────────┤
│            Engine (orchestrator)                │  cairn-engine
│   run_pass: scan → log → catalog → backup → sync│
├──────────────┬───────────────┬──────────────────┤
│   Scanner    │   Log          │   Remote         │
│ walk + hash  │ append-only    │ R2 client        │  cairn-scan / cairn-log / cairn-remote
│ change-detect│ hash-chained   │ blobs + segments │
├──────────────┴───────────────┴──────────────────┤
│   CAS (CDC chunking + manifests + transform)     │  cairn-cas
├───────────────────────────────────────────────┤
│   Catalog (redb): per-machine path cache +       │  cairn-catalog
│   materialized hash→locations index (CACHE)      │
├───────────────────────────────────────────────┤
│   Types (IDs, LogEntry, Action, HLC, config)     │  cairn-types
└───────────────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │   Cloudflare R2 (object_store) │
        │   chunks/<chunk_id>            │   content blobs (CDC chunks)
        │   manifests/<content_hash>     │   chunk recipes per file
        │   log/<machine_id>/<segment>   │   append-only log segments
        │   snapshots/<state_hash>       │   materialized state for compaction
        └───────────────────────────────┘
```

Two truths to internalize:
- **The remote object store is the source of truth for content and the durable log.** R2 holds the blobs (the safety net) and the canonical log segments.
- **The local `catalog` (redb) is a CACHE.** It is the incremental-scan cache and the materialized query index. It is fully reconstructible by replaying the log. If it is lost, rebuild it from the log segments. (Same philosophy as Fjall-as-cache in Shoal.)

## Technology Stack

All dependencies must be pure Rust.

| Layer | Crate | Purpose |
| --- | --- | --- |
| Hashing | `blake3` | Content addressing, integrity. |
| Chunking | `fastcdc` (v2020 module) | Content-defined chunking for inter-version dedup. |
| Filesystem walk | `jwalk` | Parallel directory traversal. |
| CPU parallelism | `rayon` | Parallel hashing across files. |
| Local store | `redb` | Embedded ACID B-tree KV for catalog + materialized index. |
| Object storage | `object_store` | Unified async client; R2 via its S3 backend, plus in-memory & local backends for tests. |
| Async runtime | `tokio` | For network I/O (remote sync/backup). |
| Serialization | `postcard` + `serde` | Compact binary for log entries, manifests, segments. |
| Signatures | `ed25519-dalek` | Per-machine signing of log entries (provenance, tamper-evidence). |
| AEAD (later) | `chacha20poly1305` | Client-side content encryption. |
| KDF (later) | `argon2` | Derive content key from a passphrase. |
| CLI | `clap` (derive) | Command-line interface. |
| Config | `toml` + `serde` | Config file parsing. |
| Errors | `thiserror` (libs), `anyhow` (cli) | Same split as Shoal. |
| Observability | `tracing` | Structured logging. |
| Ignore rules | `ignore` | `.gitignore`-style exclude matching (gitignore crate from ripgrep). |

### Why these choices?

- **redb over fjall**: Cairn's local store has a single writer (this process) and a read-heavy point/range query pattern (`path → entry`, `hash → locations`). redb's ACID B-tree with MVCC gives crash-safe, transactional batch application of a scan pass in one commit. (Shoal chose fjall because rebalancing produces write storms across many keyspaces — not our workload. fjall would also work; redb is the simpler fit. If the implementer already knows fjall, it is an acceptable substitute — keep the "store is a cache" contract either way.)
- **object_store over a hand-rolled S3 client**: It abstracts R2/S3/local/in-memory behind one trait, supports multipart uploads, and — critically — lets the **entire pipeline be tested against the in-memory and local-filesystem backends with no network and no R2 account.** R2 is reached by configuring its Amazon S3 backend with the R2 endpoint. R2 was selected over S3 earlier for one reason: **zero egress fees**, which makes restore (the whole point) free; verify this is still R2's pricing model at implementation time.
- **rayon for hashing, tokio for network**: Hashing is CPU-bound and embarrassingly parallel (one file per task); rayon is the right tool. Remote I/O is async; tokio is the right tool. Bridge them with a channel: the rayon-driven scan produces events, an async task consumes them for upload/sync. Do not block the tokio runtime on hashing, and do not run hashing inside async tasks.
- **fastcdc, not fixed-size chunking**: Fixed-size chunking breaks deduplication the moment content shifts by one byte (every subsequent chunk re-aligns). For "backups of backups" that get re-zipped or re-headered, this matters. Shoal's `main` learned this; its `cdc_chunker.rs` is your template. **CDC parameters are fixed at first deployment and must never change** — changing them changes chunk boundaries and silently destroys dedup.
- **ed25519 signing from the start**: Cheap, and it gives "which machine reported this location" provenance plus tamper-evidence on the log. (May be feature-gated, but design entries with the signature fields present.)

## Monorepo Structure

```
cairn/
├── Cargo.toml                  (workspace)
├── crates/
│   ├── cairn-types/            Shared types, IDs, Action/LogEntry, HLC, config
│   ├── cairn-cas/              CDC chunking, manifests, chunk-transform pipeline
│   ├── cairn-log/              Append-only hash-chained log + projection + snapshots
│   ├── cairn-catalog/          redb: path-cache + materialized hash→locations index
│   ├── cairn-scan/             Filesystem walker, incremental hashing, change detection
│   ├── cairn-remote/           object_store-backed R2 client: blobs, segments, sync
│   ├── cairn-engine/           Orchestrator: run a full scan/backup/sync pass
│   └── cairn-cli/              Binary entrypoint
├── tests/
│   ├── integration/
│   └── safety/                 The deletion-recovery & convergence tests (critical)
└── benches/
```

## Key Data Types

These live in `cairn-types`. Sketches, not gospel — refine as needed, but keep the semantics.

```rust
// === Identifiers (all 32 bytes, all BLAKE3) ===
// Use the newtype-macro pattern from shoal-types: Display=hex, From<[u8;32]>,
// AsRef<[u8]>, serde, Ord, Hash, plus from_data(&[u8]) and as_bytes().
pub struct ContentHash([u8; 32]);   // blake3(full file bytes) — a file's identity
pub struct ChunkId([u8; 32]);       // blake3(chunk bytes)      — a CDC chunk's identity
pub struct MachineId([u8; 32]);     // the machine's ed25519 public key bytes

// === A location: where a content was observed ===
#[derive(Clone, Serialize, Deserialize)]
pub struct Location {
    pub machine: MachineId,
    pub path: PathKey,          // normalized, machine-local absolute path (see Filesystem Portability)
}

// === The log model — HASH-CENTRIC, single linear chain per machine ===
#[derive(Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,               // per-machine monotonic sequence (0, 1, 2, ...)
    pub hlc: u64,               // hybrid logical clock (cross-machine LWW ordering)
    pub machine: MachineId,
    pub action: Action,
    pub prev: [u8; 32],         // hash of the PREVIOUS entry in THIS machine's chain (zero for seq 0)
    pub hash: [u8; 32],         // blake3(postcard(seq, hlc, machine, action, prev))
    pub sig_r: [u8; 32],        // ed25519 signature halves (split for serde, like shoal-logtree)
    pub sig_s: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Action {
    /// A file with this content was observed at this path during a scan.
    Observed {
        content: ContentHash,
        path: PathKey,
        size: u64,
        mtime: u64,             // nanos; treat as coarse (see portability notes)
    },
    /// A path previously observed under a scanned root is no longer present.
    /// This is a TOMBSTONE. It updates the index. It NEVER deletes content.
    Vanished {
        path: PathKey,
        last_content: ContentHash,
    },
    /// This content's bytes are now safely stored in the remote object store.
    Backed {
        content: ContentHash,
    },
    /// Marks the end of a scan pass over a root (for "as of pass N" queries & stats).
    PassCompleted {
        root: PathKey,
        files_seen: u64,
        bytes_seen: u64,
    },
    /// Records a materialized-state hash so older entries can be pruned.
    Snapshot {
        state_hash: [u8; 32],
    },
}

// === Materialized projection (the queryable index, a CACHE in redb) ===
#[derive(Clone, Serialize, Deserialize)]
pub struct ContentRecord {
    pub content: ContentHash,
    pub size: u64,
    pub live_locations: Vec<Location>,  // where it currently exists (live, not tombstoned)
    pub backed_up: bool,                // is it safe in the remote store?
    pub first_seen: u64,                // hlc
    pub last_seen: u64,                 // hlc
}

// === Per-machine catalog entry (the incremental-scan cache, in redb) ===
#[derive(Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub path: PathKey,
    pub content: ContentHash,
    pub size: u64,
    pub mtime: u64,
    pub file_id: u64,           // inode (Unix) / file index (Windows); 0 if unavailable
    pub last_scan: u64,         // hlc of the pass that last saw this path
}

// === File storage recipe (CDC). Keyed by ContentHash. Reuse Shoal's manifest shape. ===
#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,            // current: 1. Reject unknown versions.
    pub content: ContentHash,   // == blake3 of the reassembled file; verified on restore
    pub total_size: u64,
    pub chunks: Vec<ChunkRef>,  // ordered
    pub created_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub id: ChunkId,
    pub offset: u64,
    pub size: u32,
}

// PathKey: a path stored portably. UTF-8 where possible; lossless escape for
// non-UTF-8 bytes (Unix). Comparison is case- and Unicode-normalization-aware
// per the platform. See Filesystem Portability.
pub struct PathKey(String);
```

A note on identity: a **file's identity is `ContentHash` = blake3 of its whole byte stream.** That is what answers "are these two files identical?" The `Manifest` (keyed by `ContentHash`) is merely the storage recipe; its chunks deduplicate *beneath* the file level, across different files and versions. Two byte-identical files share a `ContentHash`, one `Manifest`, and all chunks. A slightly-edited file gets a new `ContentHash` and a new `Manifest`, but shares the unchanged chunks.

## Detailed Behavior

### Scan Pass & Change Detection (`cairn-scan` + `cairn-engine`)

The incremental scan is the heart of the tool. For each configured root:

1. Load the previous catalog slice for paths under this root (`path → CatalogEntry`).
2. Walk the tree with `jwalk`, applying ignore rules (`.gitignore`-style + configured excludes), not crossing mount boundaries by default, not following symlinks by default.
3. For each **regular file** encountered, `stat` it (size, mtime, file_id):
   - If the catalog has this path **and** `(size, mtime)` match (and `file_id` matches where available) → **unchanged**: reuse the stored `ContentHash`, emit **no** `Observed` event, mark the path "seen this pass."
   - Otherwise (new or modified) → **hash it** with BLAKE3 (streaming for large files; rayon across files), emit `Action::Observed`, upsert the `CatalogEntry`, mark "seen."
4. After the walk completes for the root: every catalog path under that root **not** marked "seen this pass" has **vanished** → emit `Action::Vanished` (tombstone) and mark it gone in the materialized index. **Do not touch any remote content.**
5. Emit `Action::PassCompleted`.

All log entries for the pass are appended in order; the catalog/index updates for the pass commit in a **single redb transaction** (crash-safe: a pass either lands or doesn't).

**Edge cases (specify and test):**
- *Symlinks*: do not follow by default; do not hash the target through the link. (Optionally record their existence as metadata in a later milestone — not v1.)
- *Hardlinks*: multiple paths, same `file_id`, same content. Detect via `file_id` to avoid re-hashing the second path; both are recorded as distinct `Location`s of the same `ContentHash`.
- *Permission denied / I/O error on a file*: log a warning, **skip**, do not abort the pass, and **do not** emit `Vanished` for a file you simply couldn't read. (A read error is not a disappearance.)
- *File changes mid-scan*: best-effort. The `mtime` captured at hash time is what's recorded; a race may mean the next pass re-hashes it. Acceptable.
- *Zero-byte files*: hash normally. All empty files share one `ContentHash` — that's correct dedup, not a bug.
- *Excluded directories*: never descend; `node_modules`, `.git`, OS system/cache dirs by default, plus user config.

### Content Backup Path (`cairn-cas` + `cairn-remote` + `cairn-engine`)

After (or interleaved with) a scan, for each `ContentHash` observed this pass that is not yet `backed_up`:

1. CDC-chunk the file (`cairn-cas`), producing ordered `(ChunkId, offset, size, bytes)`.
2. For each chunk, **upload-if-absent** to `chunks/<chunk_id>`: check existence (a `head`), and `put` only if missing. (Content-addressed ⇒ idempotent; concurrent or repeated uploads of the same chunk are safe.) Use multipart for large chunks if needed.
3. `put` the `Manifest` to `manifests/<content_hash>` (also if-absent).
4. Append `Action::Backed { content }` and set `backed_up = true` in the index.

This step is **resumable**: it derives its work list from "observed but not backed_up." An interrupted backup just leaves some content not-yet-backed; the next run picks it up. Re-uploading an already-present chunk is a no-op.

### Restore Path (`cairn-engine`)

Given a `ContentHash` (or a path resolved to its last-known content via the index):

1. Fetch `manifests/<content_hash>`; reject if `version` is unknown.
2. Fetch each `chunks/<chunk_id>` in order (parallel).
3. (Decrypt if encryption is enabled — see M11.)
4. Reassemble, **re-hash the result with BLAKE3, and verify it equals `content`.** Fail loudly on mismatch — never hand back unverified bytes.
5. Write to the user-specified output path.

### Sync Path (`cairn-remote` + `cairn-engine`)

Machines never talk to each other; they converge through R2.

- **Push**: this machine writes only under its own `log/<machine_id>/` prefix. Batch the pass's entries into an immutable **segment** object (postcard `Vec<LogEntry>`), named by sequence range. Segments are append-only; new entries → new segment. Each segment header records the chain tip (hash of its last entry) for continuity checks.
- **Pull**: list `log/*/` prefixes, fetch segments newer than the last-synced sequence recorded per machine, verify each segment's hash chain (each entry's `prev` matches; gaps/forks ⇒ error), `witness()` the HLCs, and **fold** the entries into the local materialized index using **Last-Writer-Wins per `(content, location)` keyed by HLC**, with `MachineId` as tiebreak. A `Vanished` removes that location from `live_locations`; an `Observed` adds/refreshes it.

Because each chain is single-writer and linear, folding is a straight replay — no merge, no DAG reconciliation.

### Snapshots, Pruning & Index Reconstruction (`cairn-log`)

The log grows with every change across every pass on every machine. To bound it:

- Periodically `create_snapshot`: serialize the materialized state, hash it, write `snapshots/<state_hash>`, and append `Action::Snapshot { state_hash }`.
- `prune_before(snapshot)`: segments entirely superseded by a snapshot may be deleted (after the snapshot is durably stored). Study `prune_before` in `shoal-logtree` for the shape — but Cairn prunes **linear ranges per machine chain**, not a DAG.
- **Reconstruction**: if the local catalog/index is lost, rebuild it by loading the most recent snapshot and replaying segments after it. The log + snapshots are sufficient; the local store is disposable.

### Querying (`cairn-engine` → `cairn-cli`)

The materialized index answers:
- **Duplicates**: `ContentHash` values whose `live_locations.len() > 1`.
- **Locate**: all locations (live + tombstoned history) of a given `ContentHash` or a path.
- **Orphans / deletion candidates**: `ContentHash` with `live_locations.is_empty()` but `backed_up == true` — content that exists only in the remote safety net. **Reported, never auto-deleted.**

---

# Implementation Plan

Work through these milestones **in order**. After each, run all tests and ensure everything passes before moving on. Commit after each milestone.

---

## Milestone 0 — Workspace Setup

- [ ] Create `cairn/Cargo.toml` workspace with all member crates.
- [ ] Create each crate directory with `Cargo.toml` and `src/lib.rs` (or `src/main.rs` for `cairn-cli`).
- [ ] Set up `[workspace.dependencies]` with all shared deps (blake3, fastcdc, jwalk, rayon, redb, object_store, tokio, postcard, serde, ed25519-dalek, clap, toml, thiserror, anyhow, tracing, ignore, bytes).
- [ ] Pin and verify versions are mutually compatible: `object_store` (confirm its R2/S3 backend and `head`/multipart APIs), `fastcdc` (confirm the `v2020` module path), `redb` (confirm the current transaction API).
- [ ] Verify the entire workspace compiles: `cargo build`.

**Test**: `cargo build` succeeds with no errors.

---

## Milestone 1 — `cairn-types`

All shared types and identifiers.

- [ ] Define `ContentHash`, `ChunkId`, `MachineId` as newtypes over `[u8; 32]` using a macro (model on `shoal-types`): `Display` (hex), `Debug`, `From<[u8;32]>`, `AsRef<[u8]>`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Ord`, `PartialOrd`, serde, `from_data(&[u8])`, `as_bytes()`.
- [ ] Port `HybridClock` from `shoal-types` (`tick`, `witness`, `current`).
- [ ] Define `PathKey` with a portable constructor: UTF-8 passthrough, lossless escaping of non-UTF-8 bytes, and a documented normalization policy hook (filled in per-platform in `cairn-scan`).
- [ ] Define `Location`, `LogEntry`, `Action`, `ContentRecord`, `CatalogEntry`, `Manifest`, `ChunkRef` with serde derives.
- [ ] Implement `LogEntry::compute_hash`, `verify_hash`, `new_signed`, `verify_signature`, `signature_bytes` (model on `shoal-logtree/src/entry.rs`).
- [ ] Define `Config` (TOML-backed): scan roots, excludes, remote endpoint/bucket/credentials reference, chunk size, encryption toggle, machine key path.

**Tests:**
- [ ] Round-trip serialize/deserialize all types with postcard.
- [ ] ID generation deterministic; different data → different ID; hex `Display` correct.
- [ ] `LogEntry` hash is deterministic and changes with any field; `verify_hash` rejects tampering.
- [ ] `new_signed` + `verify_signature` round-trip; a wrong key fails verification.
- [ ] `HybridClock`: strictly monotonic `tick`; `witness` advances past a future remote value.
- [ ] `PathKey` round-trips a non-UTF-8 byte sequence losslessly.
- [ ] `cargo test -p cairn-types` passes.

---

## Milestone 2 — `cairn-cas`

Content-defined chunking, manifests, and the transform-pipeline hook.

- [ ] Implement a `CdcChunker` over `fastcdc::v2020::FastCDC` with min/avg/max derived from a configured size at a fixed 1:4:16 ratio (port `shoal-cas/src/cdc_chunker.rs`). Each chunk: `id = blake3(bytes)`, `offset`, `size`, `data: Bytes`. Empty input → zero chunks.
- [ ] Implement a streaming chunker (`impl AsyncRead` or a reader over the file) that produces the same chunks as the in-memory chunker for the same bytes.
- [ ] Implement `build_manifest(content: ContentHash, chunks: &[Chunk]) -> Manifest` and manifest (de)serialization with postcard. `version: u8 = 1`. Reject unknown versions on deserialize.
- [ ] Define a `ChunkTransform` trait (`apply`/`reverse`) and an `Identity` implementation. This is the seam where compression (later) and encryption (M11) plug in **without changing the pipeline.** v1 uses `Identity`.

**Tests:**
- [ ] Chunking: 0 bytes, < min, exactly avg, several × max; last chunk may be smaller.
- [ ] `ChunkId` deterministic; identical chunks → identical IDs (dedup).
- [ ] **Boundary stability**: prepend one byte to a multi-chunk buffer; assert that a majority of chunk IDs are unchanged (this is the property fixed-size chunking lacks — it proves CDC works).
- [ ] Streaming chunker matches in-memory chunker.
- [ ] Manifest round-trip; deserialize rejects an unknown `version`.
- [ ] `Identity` transform round-trips.
- [ ] `cargo test -p cairn-cas` passes.

---

## Milestone 3 — `cairn-log`

The append-only, hash-chained, signed **linear** log + projection + snapshots. **Single writer per chain — no DAG.**

- [ ] Implement `MachineLog`: holds a `MachineId`, signing key, `HybridClock`, current `seq`, and current chain tip (`prev`).
- [ ] `append(action) -> LogEntry`: tick HLC, set `prev` = current tip, `seq` = next, build + sign the entry, advance tip and seq. Provide `append_observed`, `append_vanished`, `append_backed`, `append_pass_completed`, `append_snapshot` helpers.
- [ ] `receive_segment(entries: &[LogEntry], origin: MachineId)`: verify each entry's `hash`, `signature`, and **chain continuity** (`prev` of entry *n* equals `hash` of entry *n-1*; first entry's `prev` matches the known tip for that origin or is zero). Reject `InvalidHash` / `InvalidSignature` / `BrokenChain { expected, found }`. `witness` each HLC.
- [ ] `fold(entries)` → apply to a `Projection` (the in-memory materialized state): `Observed` adds/refreshes a `Location` in the content's `live_locations` and the path→content map (LWW by HLC, `MachineId` tiebreak); `Vanished` removes that location; `Backed` sets `backed_up`. `PassCompleted`/`Snapshot` update stats only.
- [ ] `create_snapshot()` and `prune_before(seq, machine)`: snapshot serializes the projection, hashes it; prune drops a contiguous prefix range of one machine's chain that the snapshot supersedes.
- [ ] Segment (de)serialization: a segment is `{ machine, seq_start, seq_end, tip_hash, entries }`, postcard-encoded.

**Tests:**
- [ ] Append produces a valid, continuous, signed chain; `verify_hash`/`verify_signature` pass for every entry.
- [ ] `receive_segment` accepts a valid foreign chain and rejects: a flipped byte (InvalidHash), a re-signed-with-wrong-key entry (InvalidSignature), and a reordered/gapped segment (BrokenChain).
- [ ] **LWW convergence**: feed two machines' segments observing the *same path* at different HLCs, in both orders; the projection's `live_locations` for that path is identical regardless of fold order.
- [ ] **Tombstone**: `Observed` then later `Vanished` for a path ⇒ location removed from `live_locations`, but the content record and `backed_up` flag remain.
- [ ] Snapshot + prune: after pruning, replaying snapshot + remaining segments reproduces the same projection (byte-identical state hash).
- [ ] `cargo test -p cairn-log` passes.

---

## Milestone 4 — `cairn-catalog`

Local persistence (redb) for the incremental-scan cache and the materialized index. **This is a cache — everything is reconstructible from the log.**

- [ ] Open a redb `Database` with tables: `catalog` (`PathKey → CatalogEntry`), `content_index` (`ContentHash → ContentRecord`), `path_to_content` (`PathKey → ContentHash`), `sync_state` (`MachineId → last_synced_seq`), `meta` (e.g. local chain tip/seq).
- [ ] Typed accessors with **transactional batch apply**: `apply_pass(entries, updates)` commits a whole scan pass's catalog + index changes in one write transaction.
- [ ] Query methods: `get_catalog_entry(path)`, `iter_catalog_under(root)`, `get_content(hash)`, `content_locations(hash)`, `duplicates()` (`live_locations.len() > 1`), `orphans()` (`live_locations.is_empty() && backed_up`), `resolve_path(path) -> Option<ContentHash>`.
- [ ] `open(path)` and `open_temporary()` (in-memory for tests).
- [ ] `rebuild_from(projection)`: replace local state from a `cairn-log` projection (used after cache loss).

**Tests:**
- [ ] Catalog CRUD + range scan under a root prefix.
- [ ] `apply_pass` is atomic: simulate a panic between two updates (or just assert all-or-nothing via two-step transaction) — partial state never persists.
- [ ] `duplicates()` and `orphans()` return correct sets on a seeded index.
- [ ] Persistence: write, drop, reopen, read back.
- [ ] `rebuild_from` reproduces an index identical to one built incrementally.
- [ ] `cargo test -p cairn-catalog` passes.

---

## Milestone 5 — `cairn-scan`

Filesystem walker, incremental hashing, change detection. **No Shoal equivalent — this is original.**

- [ ] Implement `Scanner::scan_root(root, prev_catalog, clock) -> Vec<ScanEvent>` where `ScanEvent` is an un-logged precursor (`Observed{...}` / `Vanished{...}` / `PassCompleted{...}`).
- [ ] Walk with `jwalk`; apply `ignore`-crate rules + configured excludes; do not cross mount boundaries by default; do not follow symlinks by default.
- [ ] For each regular file: stat → if `(size, mtime[, file_id])` matches the prior `CatalogEntry`, reuse its `ContentHash` (no re-hash); else stream-hash with BLAKE3. Parallelize hashing with rayon (bounded concurrency). Detect hardlinks via `file_id` to avoid double-hashing.
- [ ] After the walk, diff "seen this pass" against `prev_catalog` under the root to emit `Vanished` for missing paths.
- [ ] Implement a platform abstraction for `file_id` (Unix inode via `MetadataExt`; Windows file index via the appropriate API; `0` when unavailable) and for `PathKey` normalization (case-fold + Unicode-normalize comparison on Windows/macOS; raw on Linux). See Filesystem Portability.
- [ ] Robust error handling: per-file read/permission errors are logged and skipped, never abort the pass, never produce a false `Vanished`.

**Tests** (use `tempfile` trees):
- [ ] Fresh scan of a tree emits `Observed` for every file + one `PassCompleted`.
- [ ] Re-scan with no changes emits **zero** `Observed` (only `PassCompleted`) — incremental cache works.
- [ ] Modify one file → exactly one `Observed` for it; others untouched.
- [ ] Delete a file → exactly one `Vanished`.
- [ ] Two byte-identical files → same `ContentHash`; two empty files → same `ContentHash`.
- [ ] Hardlinked pair → content hashed once, two locations.
- [ ] An unreadable file (chmod 000 on Unix) is skipped with a warning and produces no `Vanished`.
- [ ] Excluded dir is never descended.
- [ ] `cargo test -p cairn-scan` passes.

---

## Milestone 6 — Local Pipeline (Integration, no remote)

Connect scan → log → catalog into a working offline loop. (Mirror of Shoal's M7.)

- [ ] In `tests/integration/local_pipeline.rs`: build a temp tree, run a pass (scan → append to `MachineLog` → `apply_pass` to catalog), assert the index reflects every file and dedup is correct.
- [ ] Run a **second** pass with: one file modified, one deleted, one added. Assert: one `Observed` (modified) + one `Observed` (added) + one `Vanished` (deleted); the index's `live_locations` and `duplicates()` are correct; the deleted path is tombstoned (gone from live, present in history).
- [ ] Kill-and-reopen: drop the catalog, `rebuild_from` the log projection, assert identical state.
- [ ] All assertions pass; `cargo test --test local_pipeline` passes.

---

## Milestone 7 — `cairn-remote`

object_store-backed remote client. Test against in-memory/local backends.

- [ ] Wrap an `object_store::ObjectStore` behind a `Remote` type with a backend selector: `Memory`, `LocalFilesystem(path)`, `R2 { endpoint, bucket, creds }` (the S3 backend configured for R2).
- [ ] Implement: `has_chunk(id)`, `put_chunk_if_absent(id, bytes)`, `get_chunk(id)`, `put_manifest_if_absent(content, bytes)`, `get_manifest(content)`, `put_segment(machine, seq_range, bytes)`, `list_segments(machine)`, `get_segment(key)`, `put_snapshot`/`get_snapshot`. Keys per the layout in Architecture Overview.
- [ ] `*_if_absent` = `head` then `put` (document conditional-put as an optional optimization if the backend supports it). Multipart for large objects where applicable.
- [ ] End-to-end integrity on read: `get_chunk` re-hashes bytes and returns an error if they don't match the requested `ChunkId` (verify-on-read; model on `shoal-store/file_store.rs`).

**Tests** (against `Memory` and `LocalFilesystem`):
- [ ] put/get round-trip for chunk, manifest, segment, snapshot.
- [ ] `put_chunk_if_absent` twice writes once (second is a no-op); `has_chunk` reflects presence.
- [ ] `get_chunk` rejects corrupted bytes (inject a wrong object under the key) as integrity failure.
- [ ] `list_segments` returns this machine's segments in sequence order.
- [ ] `cargo test -p cairn-remote` passes.

---

## Milestone 8 — Content Backup & Restore

Wire CAS + remote into backup and restore (still single-machine).

- [ ] `backup_content(content, file_path, remote)`: CDC-chunk → `put_chunk_if_absent` each → `put_manifest_if_absent` → return so the engine can append `Backed` and set `backed_up`.
- [ ] Backup work derives from "observed but not `backed_up`"; it is resumable and idempotent.
- [ ] `restore(content, out_path, remote)`: fetch manifest (reject unknown version) → fetch chunks in order (parallel) → reassemble → **re-hash and verify equals `content`** → write. Error loudly on mismatch.
- [ ] Engine integration test: scan a tree → back up all content → assert every `ContentHash` is `backed_up` and present remotely.

**Tests:**
- [ ] Backup then restore a file → bytes identical, verification passes.
- [ ] Two files sharing chunks → shared chunks uploaded once (assert remote chunk count < total chunk references).
- [ ] Interrupted backup (stop after k chunks) → re-run completes; no duplicate uploads.
- [ ] Restore of a manifest with a tampered chunk in the store → integrity error, no bytes written.
- [ ] `cargo test` for the backup/restore integration passes.

---

## Milestone 9 — Multi-Machine Sync & Convergence

Push/pull log segments through the remote; converge via LWW. **No P2P.**

- [ ] `push(local_log, remote)`: write new segments under `log/<machine_id>/`; record progress.
- [ ] `pull(remote, log, catalog)`: for every machine prefix, fetch segments after `sync_state[machine]`, `receive_segment` (verify chain), `fold` into the projection, `apply` to the catalog, advance `sync_state`.
- [ ] Conflict semantics: LWW per `(content, location)` by HLC, `MachineId` tiebreak. Document and test that the same set of segments folded in any order yields identical state.

**Tests** (simulate machines as separate logs + one shared `Memory`/`LocalFilesystem` remote):
- [ ] Two machines each scan disjoint trees, push, then each pulls the other → both converge to the same `content_index` (same duplicates, same locations).
- [ ] Same content present on both machines at different paths → one `ContentRecord` with two live `Location`s after convergence.
- [ ] A file deleted on machine A (Vanished) while still present on machine B → after convergence, that content keeps B's location as live; A's is gone. Content remains `backed_up`.
- [ ] Order-independence: shuffle segment-fold order across runs → identical final state hash.
- [ ] `cargo test` for sync passes.

---

## Milestone 10 — Orphan Detection & Retention (report-only)

- [ ] `orphans()` surfaces content with no live location but `backed_up == true`.
- [ ] Retention policy (config-driven): flag content whose last live location vanished more than `retain_after` ago as a *deletion candidate* — **reported only, with an explicit dry-run/no-op default. Cairn never deletes remote content automatically.**
- [ ] A `gc --confirm` path may delete *remote* candidate blobs **only** after the operator explicitly confirms a specific candidate set. (User-file deletion remains entirely out of scope — see Safety Invariants.)

**Tests:**
- [ ] Seed an index where content X lost all locations long ago and Y recently → only X is a candidate under a given `retain_after`.
- [ ] Dry-run lists candidates and deletes nothing (assert remote unchanged).
- [ ] `gc --confirm` on an explicit set removes exactly those remote blobs and nothing else; the index records the removal as an event.
- [ ] `cargo test` passes.

---

## Milestone 11 — Client-Side Encryption (behind a flag)

Designed-for since M2 via `ChunkTransform`. Adding it must not require pipeline changes.

- [ ] Implement an `Encrypt` `ChunkTransform` using `chacha20poly1305` AEAD. Derive the content key from a passphrase with `argon2` (store only the salt + KDF params in config, never the key).
- [ ] **Preserve dedup**: derive each chunk's nonce deterministically from the chunk plaintext hash (e.g. truncate `blake3(chunk_bytes)`), so identical plaintext chunks encrypt to identical ciphertext and still deduplicate. Document the tradeoff: this is *convergent*-style encryption — within a single trust domain (one user's machines) it is appropriate and preserves dedup; it does leak equality of chunks to anyone with store access. (For a single-user personal tool this is the right default; note it explicitly.)
- [ ] The `ChunkId` is `blake3` of the **ciphertext** when encryption is on, so the store and `has_chunk` operate on ciphertext; the `Manifest` records ciphertext chunk IDs plus enough to verify the reassembled *plaintext* `ContentHash` after decryption.
- [ ] Restore decrypts via the transform's reverse, then verifies the plaintext `ContentHash`.

**Tests:**
- [ ] Encrypted backup → restore → plaintext identical; `ContentHash` verifies.
- [ ] Two files with a shared plaintext chunk, encryption on → shared ciphertext chunk stored once (dedup preserved).
- [ ] Wrong passphrase → decryption/auth failure, no bytes written.
- [ ] Encryption-off and encryption-on stores are not silently mixed (guard + clear error).
- [ ] `cargo test` passes.

---

## Milestone 12 — `cairn-engine`

The orchestrator tying everything into one pass.

- [ ] `Engine::open(config)`: load/generate the machine ed25519 key, open catalog, open the local `MachineLog` (restore tip/seq from `meta`), build the `Remote`.
- [ ] `Engine::run_pass()`: for each root → scan → append events to the log → `apply_pass` to catalog → back up not-yet-backed content → push segments → optionally pull peers. Emit a structured summary (files seen, new, vanished, bytes backed up, dedup ratio).
- [ ] `Engine::sync()`, `Engine::restore(...)`, `Engine::query(...)` (duplicates / locate / orphans), `Engine::check()` (verify local chain continuity + sample remote integrity).
- [ ] Graceful interruption: a pass interrupted mid-way leaves a consistent committed state and resumes cleanly next run.

**Tests:**
- [ ] Single machine: `run_pass` on a temp tree + `Memory` remote → index correct, all content backed up.
- [ ] `run_pass` twice with no changes → second pass appends no `Observed`, uploads nothing.
- [ ] Restore a file whose local copy was then deleted from disk → recovered and verified.
- [ ] `check()` flags an artificially corrupted local segment.
- [ ] `cargo test -p cairn-engine` passes.

---

## Milestone 13 — `cairn-cli`

The binary.

- [ ] TOML config: scan roots, excludes, `[remote]` (backend, endpoint, bucket, credentials reference), `[chunking]` size, `[encryption]` toggle + KDF params, `[machine]` key path, `[retention]`.
- [ ] `clap` commands:
  - `cairn scan` — run a full pass (scan + backup + sync).
  - `cairn status` — index stats, dedup ratio, storage used, last pass per root.
  - `cairn dupes` — list duplicate sets (content with >1 live location).
  - `cairn locate <path|hash>` — show all known locations + history (live + tombstoned).
  - `cairn orphans` — list deletion candidates (content with no live location), dry-run.
  - `cairn restore <path|hash> [--at <hlc|date>] --out <path>` — recover content, verified.
  - `cairn sync` — push/pull only, no scan.
  - `cairn check` — verify chain continuity + sample remote integrity.
  - `cairn gc [--confirm]` — remote-blob retention (default dry-run).
- [ ] Auto-detect sensible defaults when fields are absent (e.g. CPU count for hashing concurrency).
- [ ] `tracing` subscriber with configurable level.

**Tests:**
- [ ] Config parses from TOML.
- [ ] `scan` then `status` on a temp tree + local-FS remote reports correct counts.
- [ ] `restore` recovers a deleted file end-to-end.
- [ ] `cargo test -p cairn-cli` passes.

---

## Milestone 14 — End-to-End Integration Tests

- [ ] `tests/integration/full_cycle.rs`: real temp trees + `LocalFilesystem` remote. Scan → back up → delete files on disk → restore → verify. Vary file sizes (1 KB to tens of MB).
- [ ] `tests/integration/incremental.rs`: large tree, initial scan, then small mutations across several passes; assert each pass does work proportional to the change, not the tree size.
- [ ] `tests/integration/dedup.rs`: many near-duplicate files (shared prefixes, one-byte shifts); assert remote chunk count is far below total chunk references (CDC dedup pays off).
- [ ] All pass: `cargo test --test '*'`.

---

## Milestone 15 — Safety & Convergence Tests (CRITICAL)

These encode the project's reason to exist. Treat failures here as release-blocking.

- [ ] `tests/safety/accidental_deletion.rs`: scan + back up a tree; delete the **only** copy of several files; run another pass (they become `Vanished`); assert the content is still `backed_up`, still listed under `orphans`, and **fully restorable with verification**. Assert the remote blob count did **not** drop when the files vanished.
- [ ] `tests/safety/never_deletes_user_files.rs`: assert there is no code path in scan/sync/backup that unlinks, truncates, or writes to any path under a scanned root. (Static check + behavioral: run a full pass over a populated tree and assert every original file still exists, byte-identical.)
- [ ] `tests/safety/convergence.rs`: three simulated machines, overlapping content, interleaved scans/pushes/pulls in randomized order; assert all three converge to an identical materialized state hash, and that a file deleted on one machine but present on another stays live.
- [ ] `tests/safety/crash_resume.rs`: interrupt a pass mid-scan and mid-upload; reopen the engine; assert state is consistent, the pass resumes, and the final result equals an uninterrupted run.
- [ ] `tests/safety/tamper_detection.rs`: corrupt a log segment and a stored chunk in the remote; assert `check()` / restore detect both and refuse to serve corrupted data.
- [ ] All pass.

---

## Notes for Implementation

### Error Handling
- `thiserror` for library error types per crate; `anyhow` only in `cairn-cli`.
- Every error carries context (which path, which chunk, which machine).
- **A read/permission error on a file is never a `Vanished` and never aborts a pass.**

### Logging
- `tracing` throughout, structured fields.
- Info: pass started/completed, files new/vanished, bytes backed up, dedup ratio, sync push/pull counts.
- Warn: skipped unreadable files, retention candidates.
- Debug/Trace: per-file decisions, per-chunk upload/skip.

### Performance
- Hashing: rayon, bounded concurrency (≈ CPU count); stream large files (don't read whole into memory).
- The incremental cache (`size`+`mtime`[+`file_id`]) is what makes re-scans cheap — get it right; re-hashing unchanged files is the cardinal performance sin.
- Network: parallelize chunk uploads/downloads with bounded concurrency; multipart for large objects.
- Bridge CPU (rayon) and network (tokio) via a bounded channel; never hash on the async runtime.

### Filesystem Portability (hard-won — specify and test)
- **`file_id`**: Unix inode via `std::os::unix::fs::MetadataExt`; Windows file index via `GetFileInformationByHandle` (or a maintained crate); `0` (= "unknown") when unavailable, in which case fall back to `(size, mtime)` for change detection. Abstract behind one trait.
- **Path encoding**: store UTF-8 where possible; Unix paths can contain non-UTF-8 bytes — escape losslessly, never panic, never silently drop.
- **Case & Unicode normalization**: Windows and (default) macOS are case-insensitive; macOS HFS+ historically normalizes to NFD. Path *comparison* for the catalog must be platform-aware (case-fold + normalize on Windows/macOS, raw on Linux). Store the original path for display; compare with the normalized form.
- **mtime granularity**: some filesystems (FAT) have 2-second resolution; treat `mtime` as coarse and never rely on sub-second precision for change detection.
- **Windows specifics**: long paths (`\\?\` prefix), reserved names (`CON`, `PRN`, …), and alternate data streams (ignore the latter).

### Safety Invariants (the whole point — violations are critical)
1. **Cairn never deletes, truncates, or modifies a user file.** It only reads and stats. (Enforced by test in M15.)
2. **A `Vanished` event never deletes content from the remote store.** Location-index and content-retention are separate code paths.
3. **Restore always verifies** the reassembled plaintext against its `ContentHash` before writing; mismatches error out, never produce a file.
4. **Remote content deletion (`gc`) is opt-in, explicit, and never automatic**; default is dry-run.
5. If a future "remove duplicates" feature is ever added, it must, before deleting *any* user file, verify that file's content is `backed_up == true` **and** has `live_locations.len() >= 2`, and default to dry-run. (Out of scope for v1.)

### The Transform Pipeline (compression & encryption seam)
`cairn-cas` exposes `ChunkTransform { apply, reverse }`. v1 ships `Identity`. Encryption (M11) and any future compression are *only* implementations of this trait — the scan/backup/restore code paths never branch on which transform is active. When a transform changes ciphertext, `ChunkId` is `blake3` of the post-transform bytes; the `Manifest` still lets restore verify the pre-transform `ContentHash`.

### Things NOT to do (yet)
- **No deletion of user files** — report-only. (Possibly never; if ever, see Safety Invariant 5.)
- **No P2P and no central server** — machines converge solely through the remote object store.
- **No multi-parent DAG, no merge entries, no topological sort** — linear single-writer chains only. (This is where Shoal's `logtree` differs; do not copy its DAG.)
- **No erasure coding** — rely on R2 durability.
- **No real-time filesystem watching** (fsnotify) — scans are pass-based; a watch mode is a later milestone.
- **No compression yet** — later, via the same transform seam as encryption.
- **No web UI** — CLI only.
