//! Restore a file's content from the remote, verifying integrity before
//! writing any bytes to disk.

use std::path::Path;

use cairn_cas::ChunkTransform;
use cairn_remote::Remote;
use cairn_types::{ContentHash, Manifest};

use crate::EngineError;

/// Restore a content's plaintext into `out_path`.
///
/// 1. Fetch the manifest (rejects unknown versions via
///    [`Manifest::from_bytes`]).
/// 2. Fetch each chunk in order (the remote re-hashes stored bytes
///    against their `ChunkId` and refuses corrupted data).
/// 3. Reverse-transform each chunk and place its plaintext at the
///    manifest's recorded offset.
/// 4. Re-hash the reassembled file and assert it equals `content`. If
///    not, return [`EngineError::RestoreIntegrity`] **without writing**
///    anything to `out_path`.
/// 5. Write the verified plaintext to `out_path`.
pub async fn restore(
    content: ContentHash,
    out_path: &Path,
    remote: &Remote,
    transform: &dyn ChunkTransform,
) -> Result<(), EngineError> {
    let manifest_bytes = remote.get_manifest(content).await?;
    let manifest = Manifest::from_bytes(&manifest_bytes)?;

    let total_size = manifest.total_size as usize;
    let mut assembled = vec![0u8; total_size];

    let chunks = &manifest.chunks;
    for (i, chunk_ref) in chunks.iter().enumerate() {
        let stored = remote.get_chunk(chunk_ref.id).await?;
        let plaintext = transform.reverse(&stored)?;

        // The plaintext length is implied by the manifest: the next chunk's
        // offset (or total_size for the last chunk) minus this chunk's
        // offset.
        let expected_plaintext = if i + 1 < chunks.len() {
            chunks[i + 1].offset.saturating_sub(chunk_ref.offset)
        } else {
            manifest.total_size.saturating_sub(chunk_ref.offset)
        };
        if plaintext.len() as u64 != expected_plaintext {
            return Err(EngineError::ChunkSizeMismatch {
                offset: chunk_ref.offset,
                expected: expected_plaintext,
                actual: plaintext.len() as u64,
            });
        }

        let begin = chunk_ref.offset as usize;
        assembled[begin..begin + plaintext.len()].copy_from_slice(&plaintext);
    }

    let computed = ContentHash::from_data(&assembled);
    if computed != content {
        return Err(EngineError::RestoreIntegrity {
            expected: content,
            actual: computed,
        });
    }

    tokio::fs::write(out_path, &assembled).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::backup_content;
    use cairn_cas::{CdcChunker, Identity};
    use std::fs;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn backup_then_restore_round_trip_is_byte_identical() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("orig.bin");
            let restored = dir.path().join("restored.bin");
            let body: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
            fs::write(&original, &body).unwrap();
            let content = ContentHash::from_data(&body);

            let remote = Remote::memory();
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            backup_content(content, &original, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();
            restore(content, &restored, &remote, &Identity)
                .await
                .unwrap();

            let got = fs::read(&restored).unwrap();
            assert_eq!(got, body);
        });
    }

    #[test]
    fn restore_with_tampered_chunk_fails_without_writing_output() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("orig.bin");
            let restored = dir.path().join("restored.bin");
            let body: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
            fs::write(&original, &body).unwrap();
            let content = ContentHash::from_data(&body);

            // Use a real backend we can inject corruption into.
            let store: std::sync::Arc<dyn object_store::ObjectStore> =
                std::sync::Arc::new(object_store::memory::InMemory::new());
            let remote = Remote::with_store(store.clone());
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            backup_content(content, &original, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();

            // Replace the bytes of one chunk with garbage of the same length.
            let manifest_bytes = remote.get_manifest(content).await.unwrap();
            let manifest = Manifest::from_bytes(&manifest_bytes).unwrap();
            let target = manifest.chunks.first().unwrap();
            let key = Remote::chunk_path(target.id);
            let os_path = object_store::path::Path::parse(&key).unwrap();
            let garbage = bytes::Bytes::from(vec![0xAA; target.size as usize]);
            store
                .put(&os_path, object_store::PutPayload::from(garbage))
                .await
                .unwrap();

            // Restore must surface an error and leave no output file.
            let err = restore(content, &restored, &remote, &Identity)
                .await
                .unwrap_err();
            // Either the per-chunk integrity check fires first (Remote
            // re-hashes on get_chunk) or, with identity transform, the
            // reassembly hash differs at the end — both are acceptable
            // here; what matters is that no bytes were written.
            match err {
                EngineError::Remote(cairn_remote::RemoteError::ChunkIntegrity { .. }) => {}
                EngineError::RestoreIntegrity { .. } => {}
                other => panic!("unexpected error: {other:?}"),
            }
            assert!(!restored.exists(), "restore must not write a partial file");
        });
    }

    #[test]
    fn restore_an_empty_file() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("empty");
            let restored = dir.path().join("empty.out");
            fs::write(&original, b"").unwrap();
            let content = ContentHash::from_data(b"");

            let remote = Remote::memory();
            let chunker = CdcChunker::from_avg_size(64 * 1024);
            backup_content(content, &original, &remote, &chunker, &Identity, 0)
                .await
                .unwrap();
            restore(content, &restored, &remote, &Identity)
                .await
                .unwrap();
            assert_eq!(fs::read(&restored).unwrap(), b"");
        });
    }

    #[test]
    fn restore_rejects_unknown_manifest_version() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("orig.bin");
            let restored = dir.path().join("restored.bin");
            fs::write(&original, b"file").unwrap();
            let content = ContentHash::from_data(b"file");

            // Plant a manifest with a bogus version under the right key.
            let store: std::sync::Arc<dyn object_store::ObjectStore> =
                std::sync::Arc::new(object_store::memory::InMemory::new());
            let remote = Remote::with_store(store.clone());
            let bad_manifest = Manifest {
                version: 99, // unknown
                content,
                total_size: 4,
                chunks: vec![],
                created_at: 0,
            };
            let bytes = postcard::to_allocvec(&bad_manifest).unwrap();
            let key = Remote::manifest_path(content);
            let os_path = object_store::path::Path::parse(&key).unwrap();
            store
                .put(&os_path, object_store::PutPayload::from(bytes))
                .await
                .unwrap();

            let err = restore(content, &restored, &remote, &Identity)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                EngineError::Types(cairn_types::TypesError::UnknownManifestVersion { .. })
            ));
        });
    }
}
