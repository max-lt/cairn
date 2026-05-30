//! [`Manifest`] and [`ChunkRef`]: the storage recipe for a file's content.

use serde::{Deserialize, Serialize};

use crate::TypesError;
use crate::ids::{ChunkId, ContentHash};

/// Current [`Manifest`] format version. Bumped only on incompatible changes.
pub const MANIFEST_VERSION: u8 = 1;

/// The storage recipe for a single file's content.
///
/// Stored remotely at `manifests/<content_hash>`. The `chunks` list
/// references content-addressed blobs at `chunks/<chunk_id>`; the manifest
/// is what allows restore to fetch them in order, reassemble, and verify
/// the result equals [`Self::content`] before handing back any bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version. Always [`MANIFEST_VERSION`] for newly written
    /// manifests; on read, any other value is rejected by [`Self::from_bytes`].
    pub version: u8,
    /// blake3 of the reassembled file's plaintext. Restore re-hashes the
    /// post-decode bytes and aborts if they do not match.
    pub content: ContentHash,
    /// Total plaintext size of the file in bytes.
    pub total_size: u64,
    /// Ordered chunk recipe. Offsets are non-decreasing and the last chunk
    /// reaches `total_size` after decoding.
    pub chunks: Vec<ChunkRef>,
    /// HLC timestamp when the manifest was created.
    pub created_at: u64,
}

/// A reference to one chunk within a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Identifier of the (possibly post-transform) chunk in the object store.
    pub id: ChunkId,
    /// Byte offset of this chunk's plaintext within the reassembled file.
    pub offset: u64,
    /// Stored chunk size in bytes (post-transform — e.g. ciphertext length).
    pub size: u32,
}

impl Manifest {
    /// Serialize with postcard.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TypesError> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Deserialize with postcard. Rejects unknown versions with
    /// [`TypesError::UnknownManifestVersion`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let m: Manifest = postcard::from_bytes(bytes)?;
        if m.version != MANIFEST_VERSION {
            return Err(TypesError::UnknownManifestVersion {
                version: m.version,
                expected: MANIFEST_VERSION,
            });
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            content: ContentHash::from_data(b"test file"),
            total_size: 4096,
            chunks: vec![
                ChunkRef {
                    id: ChunkId::from_data(b"c0"),
                    offset: 0,
                    size: 2048,
                },
                ChunkRef {
                    id: ChunkId::from_data(b"c1"),
                    offset: 2048,
                    size: 2048,
                },
            ],
            created_at: 1_700_000_000_000_000_000,
        }
    }

    #[test]
    fn roundtrip_postcard() {
        let m = sample();
        let bytes = m.to_bytes().unwrap();
        let decoded = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let mut m = sample();
        m.version = 99;
        let bytes = postcard::to_allocvec(&m).unwrap();
        match Manifest::from_bytes(&bytes) {
            Err(TypesError::UnknownManifestVersion { version, expected }) => {
                assert_eq!(version, 99);
                assert_eq!(expected, MANIFEST_VERSION);
            }
            other => panic!("expected UnknownManifestVersion, got {other:?}"),
        }
    }

    #[test]
    fn chunk_ref_postcard_roundtrip() {
        let c = ChunkRef {
            id: ChunkId::from_data(b"x"),
            offset: 1024,
            size: 512,
        };
        let bytes = postcard::to_allocvec(&c).unwrap();
        let decoded: ChunkRef = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn empty_chunks_roundtrip() {
        let m = Manifest {
            version: MANIFEST_VERSION,
            content: ContentHash::from_data(b"empty"),
            total_size: 0,
            chunks: vec![],
            created_at: 0,
        };
        let bytes = m.to_bytes().unwrap();
        let decoded = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }
}
