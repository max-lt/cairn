//! Content-defined chunking, manifests, and the chunk-transform pipeline.
//!
//! Cairn chunks every file with FastCDC ([`CdcChunker`]) before uploading.
//! Each chunk is identified by `blake3` of its stored bytes; identical
//! chunks across files share storage on the remote object store.
//!
//! The [`ChunkTransform`] trait is the seam at which optional encryption
//! and (future) compression plug in. v1 ships [`Identity`] and [`Encrypt`]
//! (ChaCha20-Poly1305 with content-derived nonce → CDC-dedup-preserving
//! convergent encryption).

pub mod chunker;
pub mod manifest;
pub mod transform;

pub use chunker::{CDC_RATIO_DENOM, CdcChunker, Chunk};
pub use manifest::build_manifest;
pub use transform::{ChunkTransform, Encrypt, Identity};

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
