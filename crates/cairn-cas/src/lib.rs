//! Content-defined chunking, manifests, and the chunk-transform pipeline.
//!
//! Cairn chunks every file with FastCDC ([`CdcChunker`]) before uploading.
//! Each chunk is identified by `blake3` of its stored bytes; identical
//! chunks across files share storage on the remote object store.
//!
//! The [`ChunkTransform`] trait is the seam at which optional encryption
//! and (future) compression plug in. v1 ships [`Identity`] only; encryption
//! lands in M11 without disturbing the scan / backup / restore pipeline.

pub mod chunker;
pub mod manifest;
pub mod transform;

pub use chunker::{CDC_RATIO_DENOM, CdcChunker, Chunk};
pub use manifest::build_manifest;
pub use transform::{ChunkTransform, Identity};

/// Errors produced by [`cairn-cas`](crate) operations.
#[derive(Debug, thiserror::Error)]
pub enum CasError {
    /// I/O failure while reading from a stream.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A [`ChunkTransform`] implementation failed (e.g. AEAD authentication).
    #[error("transform error: {0}")]
    Transform(String),
}
