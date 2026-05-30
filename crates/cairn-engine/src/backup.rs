//! Back up a file's content to the remote: CDC-chunk + upload + manifest.

use std::path::Path;

use bytes::Bytes;
use cairn_cas::{CdcChunker, ChunkTransform};
use cairn_remote::Remote;
use cairn_types::{ChunkId, ChunkRef, ContentHash, MANIFEST_VERSION, Manifest};
use tracing::debug;

use crate::EngineError;

/// What [`backup_content`] reports back to the engine: enough for the
/// caller to log a structured summary and decide whether anything new
/// actually had to be uploaded (useful for the engine's dedup-ratio
/// metric).
#[derive(Debug, Clone, Copy, Default)]
pub struct BackupSummary {
    /// Number of chunks the file was split into (after CDC).
    pub chunks_total: u32,
    /// Number of chunks newly uploaded (already-present chunks are skipped).
    pub chunks_uploaded: u32,
    /// Plaintext bytes backed up.
    pub bytes_total: u64,
    /// Post-transform bytes actually written across new chunks.
    pub bytes_uploaded: u64,
}

/// Back up a single file's content to the remote.
///
/// 1. Read the file.
/// 2. CDC-chunk it with `chunker`.
/// 3. For each chunk, run `transform.apply` to obtain the bytes that will
///    be stored, compute the post-transform [`ChunkId`], and upload via
///    [`Remote::put_chunk_if_absent`].
/// 4. Build a [`Manifest`] whose `chunks` carry the **post-transform**
///    ids and sizes plus the **plaintext** offset, and upload it.
///
/// Resumable: callers run this only for content not yet `backed_up`, and
/// the head-then-put dance in `put_*_if_absent` makes every step
/// idempotent — an interrupted backup re-uploads only what's missing.
pub async fn backup_content(
    content: ContentHash,
    file_path: &Path,
    remote: &Remote,
    chunker: &CdcChunker,
    transform: &dyn ChunkTransform,
    created_at_hlc: u64,
) -> Result<BackupSummary, EngineError> {
    let bytes = tokio::fs::read(file_path).await?;
    let total_size = bytes.len() as u64;
    let plain_chunks = chunker.chunk(&bytes);

    let mut chunk_refs: Vec<ChunkRef> = Vec::with_capacity(plain_chunks.len());
    let mut summary = BackupSummary {
        chunks_total: plain_chunks.len() as u32,
        bytes_total: total_size,
        ..BackupSummary::default()
    };

    for plain in plain_chunks {
        let stored = transform.apply(&plain.data)?;
        let stored_id = ChunkId::from_data(&stored);
        let stored_size = stored.len() as u32;

        let already_present = remote.has_chunk(stored_id).await?;
        if !already_present {
            remote
                .put_chunk_if_absent(stored_id, stored.clone())
                .await?;
            summary.chunks_uploaded += 1;
            summary.bytes_uploaded += stored_size as u64;
        } else {
            debug!(chunk_id = %stored_id, "chunk already present, skipping upload");
        }

        chunk_refs.push(ChunkRef {
            id: stored_id,
            offset: plain.offset,
            size: stored_size,
        });
    }

    let manifest = Manifest {
        version: MANIFEST_VERSION,
        content,
        total_size,
        chunks: chunk_refs,
        created_at: created_at_hlc,
    };
    let manifest_bytes = manifest.to_bytes()?;
    remote
        .put_manifest_if_absent(content, Bytes::from(manifest_bytes))
        .await?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_cas::Identity;
    use std::fs;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn backup_uploads_chunks_and_manifest() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("file.bin");
            let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
            fs::write(&p, &body).unwrap();

            let content = ContentHash::from_data(&body);
            let remote = Remote::memory();
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            let summary = backup_content(content, &p, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();

            assert!(summary.chunks_total >= 1);
            assert_eq!(summary.chunks_uploaded, summary.chunks_total);
            assert_eq!(summary.bytes_total, body.len() as u64);

            // Manifest is present and version-checks.
            let manifest_bytes = remote.get_manifest(content).await.unwrap();
            let manifest = Manifest::from_bytes(&manifest_bytes).unwrap();
            assert_eq!(manifest.content, content);
            assert_eq!(manifest.total_size, body.len() as u64);
            assert_eq!(manifest.chunks.len(), summary.chunks_total as usize);
        });
    }

    #[test]
    fn second_backup_uploads_nothing_when_already_present() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("file.bin");
            let body = b"identical bytes for both runs";
            fs::write(&p, body).unwrap();

            let content = ContentHash::from_data(body);
            let remote = Remote::memory();
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            let first = backup_content(content, &p, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();
            assert!(first.chunks_uploaded > 0);

            let second = backup_content(content, &p, &remote, &chunker, &Identity, 1)
                .await
                .unwrap();
            assert_eq!(second.chunks_uploaded, 0);
            assert_eq!(second.bytes_uploaded, 0);
            assert_eq!(second.chunks_total, first.chunks_total);
        });
    }

    #[test]
    fn shared_chunks_uploaded_once_across_two_files() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            // Two files sharing a long prefix → CDC produces shared chunks.
            let mut v1: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
            let v2 = v1.clone();
            v1.extend_from_slice(b"v1-suffix"); // differ at the end
            let mut v2 = v2;
            v2.extend_from_slice(b"v2-suffix");

            let p1 = dir.path().join("a.bin");
            let p2 = dir.path().join("b.bin");
            fs::write(&p1, &v1).unwrap();
            fs::write(&p2, &v2).unwrap();
            let c1 = ContentHash::from_data(&v1);
            let c2 = ContentHash::from_data(&v2);

            let remote = Remote::memory();
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            let s1 = backup_content(c1, &p1, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();
            let s2 = backup_content(c2, &p2, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();

            // The second backup uploaded strictly fewer chunks than its
            // chunk count — the shared prefix chunks were already present.
            assert!(
                s2.chunks_uploaded < s2.chunks_total,
                "expected some chunk reuse across the two files: uploaded {} of {}",
                s2.chunks_uploaded,
                s2.chunks_total
            );
            // Total uploads across both backups < sum of chunk references.
            let total_refs = s1.chunks_total + s2.chunks_total;
            let total_uploaded = s1.chunks_uploaded + s2.chunks_uploaded;
            assert!(total_uploaded < total_refs);
        });
    }
}
