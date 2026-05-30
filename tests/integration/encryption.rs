//! M11 integration: backup + restore with the Encrypt transform.
//!
//! The convergent (content-derived nonce) construction is what keeps CDC
//! dedup intact: identical plaintext chunks encrypt to identical
//! ciphertext, so put_chunk_if_absent still no-ops on the second backup.

use std::fs;

use cairn_cas::{CdcChunker, Encrypt, Identity};
use cairn_engine::{EngineError, backup_content, restore};
use cairn_remote::Remote;
use cairn_types::ContentHash;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn encrypted_backup_then_restore_round_trips() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("secret.bin");
        let out = dir.path().join("secret.restored");
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &body).unwrap();
        let content = ContentHash::from_data(&body);

        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let key = [42u8; 32];
        let enc = Encrypt::from_key(key);
        backup_content(content, &src, &remote, &chunker, &enc, 0)
            .await
            .unwrap();
        let enc2 = Encrypt::from_key(key);
        restore(content, &out, &remote, &enc2).await.unwrap();

        let restored = fs::read(&out).unwrap();
        assert_eq!(restored, body);
    });
}

#[test]
fn convergent_encryption_preserves_dedup_across_two_files() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        // Two files sharing a long prefix → CDC produces shared chunks
        // that, under convergent encryption with the same key, must
        // encrypt to byte-identical ciphertext and therefore the second
        // backup must skip them.
        let mut v1: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
        let mut v2 = v1.clone();
        v1.extend_from_slice(b"v1-suffix");
        v2.extend_from_slice(b"v2-suffix");

        let p1 = dir.path().join("a.bin");
        let p2 = dir.path().join("b.bin");
        fs::write(&p1, &v1).unwrap();
        fs::write(&p2, &v2).unwrap();
        let c1 = ContentHash::from_data(&v1);
        let c2 = ContentHash::from_data(&v2);

        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let enc = Encrypt::from_key([7u8; 32]);
        let s1 = backup_content(c1, &p1, &remote, &chunker, &enc, 0)
            .await
            .unwrap();
        let s2 = backup_content(c2, &p2, &remote, &chunker, &enc, 0)
            .await
            .unwrap();

        // Strictly fewer chunks were uploaded in the second backup —
        // ciphertext dedup is preserved under the convergent scheme.
        assert!(
            s2.chunks_uploaded < s2.chunks_total,
            "expected ciphertext dedup: uploaded {} of {}",
            s2.chunks_uploaded,
            s2.chunks_total
        );
        let _ = s1;
    });
}

#[test]
fn wrong_passphrase_fails_without_writing_output() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("secret.bin");
        let out = dir.path().join("secret.restored");
        let body = b"top-secret payload that must not leak";
        fs::write(&src, body).unwrap();
        let content = ContentHash::from_data(body);

        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let salt = b"cairn-test-salt-fixed-value-aa";
        let right = Encrypt::from_passphrase("correct passphrase", salt).unwrap();
        let wrong = Encrypt::from_passphrase("WRONG passphrase", salt).unwrap();

        backup_content(content, &src, &remote, &chunker, &right, 0)
            .await
            .unwrap();
        let err = restore(content, &out, &remote, &wrong).await.unwrap_err();
        // AEAD authentication failure surfaces as a Cas (transform) error.
        assert!(matches!(err, EngineError::Cas(_)), "got {err:?}");
        assert!(
            !out.exists(),
            "no plaintext file may be written on auth failure"
        );
    });
}

#[test]
fn restoring_encrypted_blob_with_identity_transform_errors_clearly() {
    rt().block_on(async {
        // Mixing encryption-off with encryption-on stores is a user
        // configuration mistake, and the guard is the per-chunk
        // integrity check at restore: stored bytes (ciphertext) treated
        // as plaintext via Identity won't hash to the manifest's
        // plaintext content, so restore aborts before writing any output.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("file.bin");
        let out = dir.path().join("file.restored");
        let body = b"this was encrypted on backup";
        fs::write(&src, body).unwrap();
        let content = ContentHash::from_data(body);

        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        let enc = Encrypt::from_key([5u8; 32]);
        backup_content(content, &src, &remote, &chunker, &enc, 0)
            .await
            .unwrap();

        let err = restore(content, &out, &remote, &Identity)
            .await
            .unwrap_err();
        // Identity 'reverse' returns the ciphertext bytes as plaintext;
        // the chunk's plaintext length doesn't match the manifest's
        // implied length, so we get a ChunkSizeMismatch (which is a
        // clear "your transforms don't match" signal). Alternatively,
        // if total_size matched, the final ContentHash check would
        // catch it as RestoreIntegrity. Both are acceptable.
        match err {
            EngineError::ChunkSizeMismatch { .. } | EngineError::RestoreIntegrity { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
        assert!(!out.exists());
    });
}
