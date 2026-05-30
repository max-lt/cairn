//! Append-only, hash-chained, signed **linear** log + projection + snapshots.
//!
//! Each machine writes a single linear chain (one writer per chain → no
//! merges, no DAG). The global view is the union of all chains, folded
//! into a [`Projection`] with Last-Writer-Wins per `(content, location)`
//! keyed by HLC. This is deliberately simpler than Shoal's `logtree`,
//! which serves a multi-writer distributed cluster.
//!
//! Three primary types:
//!
//! - [`MachineLog`] — this machine's local writer + chain state (signing
//!   key, hybrid clock, current seq + tip). Produces [`LogEntry`]s and
//!   witnesses foreign HLCs.
//! - [`Segment`] — an immutable, postcard-serializable range of contiguous
//!   entries from one machine, with a header that records its tip hash for
//!   continuity checks.
//! - [`Projection`] — the in-memory materialized state that a stream of
//!   entries folds into. Snapshots are byte-canonical serializations of
//!   this state.

pub mod machine_log;
pub mod projection;
pub mod segment;

pub use machine_log::MachineLog;
pub use projection::{ChainTip, LocationFold, LocationState, PassStats, Projection, Snapshot};
pub use segment::Segment;

/// Errors produced by [`cairn-log`](crate) operations.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// An entry's stored hash does not match recomputation.
    #[error("invalid hash on entry seq {seq}")]
    InvalidHash {
        /// The entry's sequence number.
        seq: u64,
    },
    /// An entry's signature did not verify against its machine's public key.
    #[error("invalid signature on entry seq {seq}")]
    InvalidSignature {
        /// The entry's sequence number.
        seq: u64,
    },
    /// Chain continuity is broken: an entry's `prev` does not match the
    /// previous entry's `hash` (or the expected known tip for the segment).
    #[error("broken chain at seq {seq}: expected prev {expected}, got {found}")]
    BrokenChain {
        /// The offending entry's sequence number.
        seq: u64,
        /// The expected `prev` value (hex).
        expected: String,
        /// The `prev` value actually present (hex).
        found: String,
    },
    /// Sequence numbers in a segment are not strictly increasing by 1.
    #[error("non-contiguous sequence: seq {got} follows {prev}")]
    NonContiguousSeq {
        /// The previous entry's sequence number.
        prev: u64,
        /// The offending entry's sequence number.
        got: u64,
    },
    /// A segment carries entries from more than one machine.
    #[error("segment mixes machines: saw both {a} and {b}")]
    MixedMachines {
        /// Hex of one machine seen in the segment.
        a: String,
        /// Hex of another machine seen in the segment.
        b: String,
    },
    /// Attempted to build a [`Segment`] with no entries.
    #[error("empty segment")]
    EmptySegment,
    /// The segment header's `tip_hash` does not match the last entry's hash.
    #[error("segment tip mismatch: header says {expected}, last entry has {found}")]
    TipMismatch {
        /// `tip_hash` from the segment header (hex).
        expected: String,
        /// The last entry's actual hash (hex).
        found: String,
    },
    /// The segment header's `machine` does not match an entry's `machine`.
    #[error("machine mismatch: segment header says {header}, entry seq {seq} has {entry}")]
    MachineMismatch {
        /// Hex of the machine declared by the segment header.
        header: String,
        /// Hex of the machine recorded in the offending entry.
        entry: String,
        /// The offending entry's sequence number.
        seq: u64,
    },
    /// Postcard (de)serialization failed.
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
}
