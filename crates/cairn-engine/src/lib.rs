//! Cairn's orchestration layer.
//!
//! In M8 this crate hosts the [`backup_content`] / [`restore`] pair that
//! bridges [`cairn-cas`](../../cairn_cas/index.html) and
//! [`cairn-remote`](../../cairn_remote/index.html). The full
//! "scan → log → catalog → backup → sync" orchestrator [`Engine`] lands
//! in M12.

pub mod backup;
pub mod engine;
pub mod restore;
pub mod retention;
pub mod sync;

pub use backup::{BackupSummary, backup_content};
pub use engine::{CheckReport, Engine, PassSummary};
pub use restore::restore;
pub use retention::{RetentionCandidate, RetentionPlan, dry_run_retention, gc_confirm};
pub use sync::{
    PullSummary, PushSummary, list_remote_machines, pull_from, push_pending_as_segment,
};

/// Errors produced by [`cairn-engine`](crate) backup / restore / sync.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// An I/O error occurred while reading or writing a file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A remote-store operation failed.
    #[error(transparent)]
    Remote(#[from] cairn_remote::RemoteError),
    /// A [`ChunkTransform`](cairn_cas::ChunkTransform) failed (e.g. AEAD).
    #[error(transparent)]
    Cas(#[from] cairn_cas::CasError),
    /// A cairn-types operation failed (postcard, manifest version).
    #[error(transparent)]
    Types(#[from] cairn_types::TypesError),
    /// A local catalog operation failed.
    #[error(transparent)]
    Catalog(#[from] cairn_catalog::CatalogError),
    /// A log-layer operation failed (segment verify, chain continuity).
    #[error(transparent)]
    Log(#[from] cairn_log::LogError),
    /// `push_pending_as_segment` was given entries that do not belong to
    /// the local machine's own chain.
    #[error("attempted to push entries authored by foreign machine {found}")]
    PushForeignChain {
        /// Hex of the foreign machine id that authored the entries.
        found: String,
    },
    /// Restore reassembled bytes whose blake3 did not match the requested
    /// [`ContentHash`](cairn_types::ContentHash). The file was **not**
    /// written.
    #[error("restore integrity failure: reassembled bytes hash to {actual}, expected {expected}")]
    RestoreIntegrity {
        /// The requested content hash (the value restore was asked for).
        expected: cairn_types::ContentHash,
        /// The hash computed from the reassembled bytes.
        actual: cairn_types::ContentHash,
    },
    /// The plaintext size produced by the configured
    /// [`ChunkTransform::reverse`](cairn_cas::ChunkTransform::reverse) did
    /// not match the offset range the manifest's chunk recipe implies.
    #[error(
        "chunk size mismatch at offset {offset}: manifest implies plaintext length {expected}, got {actual}"
    )]
    ChunkSizeMismatch {
        /// Offset within the file.
        offset: u64,
        /// Plaintext length implied by the manifest's chunk recipe.
        expected: u64,
        /// Plaintext length produced by the transform.
        actual: u64,
    },
}
