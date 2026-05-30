//! Content-Defined Chunking with FastCDC.
//!
//! Chunk boundaries are determined by a rolling hash, so a single-byte
//! insertion near the start of a file does **not** re-align every
//! subsequent chunk: only the immediate neighborhood is affected, and the
//! rest stays byte-identical. This is the property that makes Cairn able
//! to deduplicate "backups of backups" that differ by small headers or
//! per-version metadata.
//!
//! **CDC parameters are frozen at first deployment**: changing them changes
//! chunk boundaries on existing content and silently destroys prior dedup.

use bytes::Bytes;
use cairn_types::ChunkId;

use crate::CasError;

/// Ratio denominator used to derive `min` and `max` from `avg_size`.
///
/// With `CDC_RATIO_DENOM = 4`, the min:avg:max ratio is 1:4:16.
/// For `avg_size = 1 MiB` this gives `min = 256 KiB`, `max = 4 MiB`.
pub const CDC_RATIO_DENOM: u32 = 4;

/// FastCDC's hard lower bound on min_size (per its v2020 algorithm).
const FASTCDC_MIN_FLOOR: u32 = 64;

/// A single content-addressed chunk produced by [`CdcChunker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// `blake3(stored_bytes)` — i.e. of `data` as-is.
    ///
    /// When a [`ChunkTransform`](crate::ChunkTransform) is active the bytes
    /// in `data` are post-transform (e.g. ciphertext); the [`ChunkId`] still
    /// matches what gets stored at `chunks/<chunk_id>`.
    pub id: ChunkId,
    /// Plaintext offset of this chunk within the original file.
    pub offset: u64,
    /// Stored chunk size in bytes (`data.len() as u32`).
    pub size: u32,
    /// The chunk bytes as they will be stored.
    pub data: Bytes,
}

/// Content-defined chunker over [`fastcdc::v2020::FastCDC`].
///
/// Parameters are derived from `avg_size` at a fixed 1:4:16 min:avg:max
/// ratio (see [`CDC_RATIO_DENOM`]). Empty input yields zero chunks. The
/// last chunk of a non-empty stream may be smaller than `min_size`.
pub struct CdcChunker {
    min_size: u32,
    avg_size: u32,
    max_size: u32,
}

impl CdcChunker {
    /// Build a chunker from a target average chunk size.
    ///
    /// `min` and `max` are derived at the fixed 1:4:16 ratio (clamped to
    /// FastCDC's algorithmic minimum of 64 bytes).
    ///
    /// # Panics
    ///
    /// Panics if `avg_size < CDC_RATIO_DENOM * FASTCDC_MIN_FLOOR` (256
    /// bytes), since the derived `min_size` would then be below FastCDC's
    /// hard floor.
    pub fn from_avg_size(avg_size: u32) -> Self {
        let min_size = avg_size / CDC_RATIO_DENOM;
        let max_size = avg_size.saturating_mul(CDC_RATIO_DENOM);
        assert!(
            min_size >= FASTCDC_MIN_FLOOR,
            "avg_size {avg_size} too small: derived min_size {min_size} < FastCDC floor {FASTCDC_MIN_FLOOR}"
        );
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    /// Create a chunker with explicit (min, avg, max) sizes, intended for
    /// testing with small buffers.
    pub fn with_sizes(min_size: u32, avg_size: u32, max_size: u32) -> Self {
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    /// Target average chunk size.
    pub fn avg_size(&self) -> u32 {
        self.avg_size
    }

    /// Lower bound on non-final chunk size.
    pub fn min_size(&self) -> u32 {
        self.min_size
    }

    /// Hard upper bound on chunk size.
    pub fn max_size(&self) -> u32 {
        self.max_size
    }

    /// Split a fully-resident byte buffer into content-defined chunks.
    ///
    /// Empty input → empty `Vec`. Otherwise the returned chunks are
    /// contiguous (offsets sum to `data.len()`) and their concatenated
    /// `data` reproduces `data` exactly.
    pub fn chunk(&self, data: &[u8]) -> Vec<Chunk> {
        if data.is_empty() {
            return Vec::new();
        }

        let chunker =
            fastcdc::v2020::FastCDC::new(data, self.min_size, self.avg_size, self.max_size);
        let mut out = Vec::new();

        for entry in chunker {
            let slice = &data[entry.offset..entry.offset + entry.length];
            let id = ChunkId::from_data(slice);
            out.push(Chunk {
                id,
                offset: entry.offset as u64,
                size: slice.len() as u32,
                data: Bytes::copy_from_slice(slice),
            });
        }

        out
    }

    /// Split data from an async reader into the same chunks as
    /// [`Self::chunk`] would produce on the same bytes.
    ///
    /// FastCDC's boundary detection is content-defined and *deterministic*
    /// from the full byte stream; the streaming form therefore buffers the
    /// reader into memory before chunking. For Cairn's per-file use (file
    /// sizes are bounded by the user's disk) this is acceptable.
    pub async fn chunk_stream<R: tokio::io::AsyncRead + Unpin>(
        &self,
        mut reader: R,
    ) -> Result<Vec<Chunk>, CasError> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        Ok(self.chunk(&buf))
    }
}

impl Default for CdcChunker {
    /// 1 MiB average chunks — matches
    /// [`DEFAULT_CHUNK_AVG_SIZE`](cairn_types::DEFAULT_CHUNK_AVG_SIZE).
    fn default() -> Self {
        Self::from_avg_size(cairn_types::DEFAULT_CHUNK_AVG_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Pseudo-random byte sequence seeded from a constant, suitable for
    /// deterministic CDC tests. Avoids needing a real RNG dep.
    fn prng_bytes(n: usize) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect()
    }

    #[test]
    fn empty_input_yields_zero_chunks() {
        let chunker = CdcChunker::default();
        assert!(chunker.chunk(b"").is_empty());
    }

    #[test]
    fn small_input_below_min_yields_single_chunk() {
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let data = vec![0xABu8; 1_000]; // < min_size (16 KiB for 64 KiB avg)
        let chunks = chunker.chunk(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data.as_ref(), data.as_slice());
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].size, 1_000);
    }

    #[test]
    fn chunk_id_is_blake3_of_data() {
        let chunker = CdcChunker::default();
        let data = vec![0xCDu8; 4_096];
        let chunks = chunker.chunk(&data);
        assert!(!chunks.is_empty());
        for c in &chunks {
            assert_eq!(c.id, ChunkId::from_data(&c.data));
        }
    }

    #[test]
    fn identical_chunks_share_chunkid() {
        let chunker = CdcChunker::with_sizes(64, 256, 1024);
        // Repeated runs of identical 4-byte blocks → some boundary will
        // produce identical chunks at the chunk level (when CDC's rolling
        // hash hits the same boundaries on identical content).
        let block = b"AAAA";
        let data: Vec<u8> = block.iter().copied().cycle().take(4096).collect();
        let chunks = chunker.chunk(&data);
        // At minimum the first two chunks (over identical periodic data)
        // produce equal IDs once chunk boundaries stabilize.
        let mut counts = std::collections::HashMap::new();
        for c in &chunks {
            *counts.entry(c.id).or_insert(0u32) += 1;
        }
        assert!(
            counts.values().any(|&n| n >= 2),
            "expected at least one ChunkId reused across chunks of periodic data"
        );
    }

    #[test]
    fn chunking_is_deterministic() {
        let chunker = CdcChunker::default();
        let data = prng_bytes(200_000);
        let c1 = chunker.chunk(&data);
        let c2 = chunker.chunk(&data);
        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.size, b.size);
            assert_eq!(a.data, b.data);
        }
    }

    #[test]
    fn offsets_are_contiguous_and_cover_input() {
        let chunker = CdcChunker::default();
        let data = prng_bytes(500_000);
        let chunks = chunker.chunk(&data);
        let mut expected = 0u64;
        for c in &chunks {
            assert_eq!(c.offset, expected);
            expected += c.size as u64;
        }
        assert_eq!(expected, data.len() as u64);
    }

    #[test]
    fn chunk_sizes_respect_bounds_except_last() {
        // Use a small chunker so a moderate input produces many chunks.
        let chunker = CdcChunker::from_avg_size(64 * 1024); // 16k / 64k / 256k
        let data = prng_bytes(2_000_000);
        let chunks = chunker.chunk(&data);
        assert!(chunks.len() > 1, "expected many chunks");
        let last_idx = chunks.len() - 1;
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.size <= chunker.max_size(), "chunk {i} exceeds max");
            if i != last_idx {
                assert!(
                    c.size >= chunker.min_size(),
                    "non-final chunk {i} below min: {} < {}",
                    c.size,
                    chunker.min_size()
                );
            }
        }
    }

    #[test]
    fn boundary_stability_under_prepend() {
        // CDC's selling point: prepending one byte shifts only the
        // immediate-neighborhood chunks. Use a small chunker (avg 64 KiB)
        // so a 2 MB buffer yields many chunks, then assert most ChunkIds
        // survive the one-byte shift.
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let base = prng_bytes(2_000_000);
        let mut shifted = Vec::with_capacity(base.len() + 1);
        shifted.push(0x42);
        shifted.extend_from_slice(&base);

        let chunks_base = chunker.chunk(&base);
        let chunks_shifted = chunker.chunk(&shifted);
        assert!(chunks_base.len() > 8);
        assert!(chunks_shifted.len() > 8);

        let ids_base: HashSet<_> = chunks_base.iter().map(|c| c.id).collect();
        let ids_shifted: HashSet<_> = chunks_shifted.iter().map(|c| c.id).collect();
        let shared = ids_base.intersection(&ids_shifted).count();
        let denom = chunks_base.len().max(chunks_shifted.len());
        let ratio = shared as f64 / denom as f64;
        assert!(
            ratio > 0.50,
            "expected >50% chunk-ID reuse under one-byte prepend, got {:.1}% ({shared}/{denom})",
            ratio * 100.0
        );
    }

    #[tokio::test]
    async fn streaming_matches_in_memory() {
        let chunker = CdcChunker::default();
        let data = prng_bytes(300_000);
        let sync = chunker.chunk(&data);
        let stream = chunker
            .chunk_stream(std::io::Cursor::new(&data))
            .await
            .unwrap();
        assert_eq!(sync.len(), stream.len());
        for (s, a) in sync.iter().zip(stream.iter()) {
            assert_eq!(s.id, a.id);
            assert_eq!(s.offset, a.offset);
            assert_eq!(s.size, a.size);
            assert_eq!(s.data, a.data);
        }
    }

    #[tokio::test]
    async fn streaming_empty_input() {
        let chunker = CdcChunker::default();
        let stream = chunker
            .chunk_stream(std::io::Cursor::new(Vec::<u8>::new()))
            .await
            .unwrap();
        assert!(stream.is_empty());
    }

    #[test]
    fn from_avg_size_derives_ratio() {
        let c = CdcChunker::from_avg_size(64 * 1024);
        assert_eq!(c.min_size(), 16 * 1024);
        assert_eq!(c.avg_size(), 64 * 1024);
        assert_eq!(c.max_size(), 256 * 1024);
    }

    #[test]
    fn default_uses_workspace_constant() {
        let c = CdcChunker::default();
        assert_eq!(c.avg_size(), cairn_types::DEFAULT_CHUNK_AVG_SIZE);
    }

    #[test]
    #[should_panic(expected = "too small")]
    fn from_avg_size_panics_when_below_fastcdc_floor() {
        // avg=200 → min=50 < FASTCDC_MIN_FLOOR(64), must panic.
        let _ = CdcChunker::from_avg_size(200);
    }
}
