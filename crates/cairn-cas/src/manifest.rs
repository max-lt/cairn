//! Build a [`Manifest`] from the chunks produced by a [`CdcChunker`](crate::CdcChunker).
//!
//! The on-disk / on-wire `Manifest` shape and its postcard serialization
//! (with version-checking) live in [`cairn-types`]; this module is just the
//! constructor.

use cairn_types::{ChunkRef, ContentHash, MANIFEST_VERSION, Manifest};

use crate::chunker::Chunk;

/// Build a [`Manifest`] from chunks produced by a [`CdcChunker`](crate::CdcChunker).
///
/// `content` is the [`ContentHash`] of the file's *plaintext* — computed
/// separately by the caller (typically a single BLAKE3 streaming hash over
/// the file, in parallel with chunking). `total_size` is the plaintext
/// size in bytes, used by restore to size the output buffer.
///
/// The `version` field is always set to [`MANIFEST_VERSION`].
pub fn build_manifest(
    content: ContentHash,
    total_size: u64,
    chunks: &[Chunk],
    created_at: u64,
) -> Manifest {
    let refs = chunks
        .iter()
        .map(|c| ChunkRef {
            id: c.id,
            offset: c.offset,
            size: c.size,
        })
        .collect();

    Manifest {
        version: MANIFEST_VERSION,
        content,
        total_size,
        chunks: refs,
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CdcChunker;

    #[test]
    fn build_from_cdc_chunks_round_trips() {
        let chunker = CdcChunker::default();
        let data: Vec<u8> = (0..256_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let content = ContentHash::from_data(&data);
        let chunks = chunker.chunk(&data);

        let manifest = build_manifest(content, data.len() as u64, &chunks, 42);
        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.content, content);
        assert_eq!(manifest.total_size, data.len() as u64);
        assert_eq!(manifest.chunks.len(), chunks.len());
        assert_eq!(manifest.created_at, 42);

        for (m, c) in manifest.chunks.iter().zip(chunks.iter()) {
            assert_eq!(m.id, c.id);
            assert_eq!(m.offset, c.offset);
            assert_eq!(m.size, c.size);
        }

        // Postcard round-trip via cairn-types — already-tested but worth
        // exercising the full path that backup / restore will use.
        let bytes = manifest.to_bytes().unwrap();
        let decoded = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn build_from_empty_chunks_yields_empty_manifest() {
        let manifest = build_manifest(ContentHash::from_data(b""), 0, &[], 0);
        assert!(manifest.chunks.is_empty());
        assert_eq!(manifest.total_size, 0);
    }

    #[test]
    fn manifest_reflects_chunk_order() {
        let chunker = CdcChunker::default();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let chunks = chunker.chunk(&data);
        let manifest = build_manifest(ContentHash::from_data(&data), data.len() as u64, &chunks, 0);
        let mut expected = 0u64;
        for r in &manifest.chunks {
            assert_eq!(r.offset, expected);
            expected += r.size as u64;
        }
        assert_eq!(expected, data.len() as u64);
    }
}
