//! M14 dedup: many near-duplicate files (shared prefixes / suffixes,
//! one-byte shifts) must produce a remote chunk count far below the
//! sum of chunk references in their manifests — that's the whole
//! point of content-defined chunking.

use std::fs;

use cairn_cas::Identity;
use cairn_catalog::Catalog;
use cairn_engine::Engine;
use cairn_integration_tests::signing_key;
use cairn_remote::Remote;
use cairn_types::{Config, ContentHash, Manifest};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn synth_prefix(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

#[test]
fn near_duplicate_files_share_most_chunks_in_remote() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // 20 files, all sharing a 2 MB prefix, each with a unique suffix.
        // CDC chunks the shared prefix into the same boundaries across
        // every file, so its chunks should be uploaded once.
        let shared = synth_prefix(2 * 1024 * 1024);
        let file_count = 20;
        let mut content_hashes = Vec::with_capacity(file_count);
        for i in 0..file_count {
            let mut body = shared.clone();
            body.extend_from_slice(&format!("--suffix-{i:04}--").into_bytes());
            content_hashes.push(ContentHash::from_data(&body));
            fs::write(scan_dir.path().join(format!("f{i:04}.bin")), body).unwrap();
        }

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            chunking: cairn_types::ChunkingConfig {
                avg_size: 64 * 1024, // small enough to split 2 MB files
            },
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(40), remote, Box::new(Identity))
                .unwrap();

        let s = engine.run_pass().await.unwrap();
        assert_eq!(s.contents_backed_up as usize, file_count);

        // Sum of chunk references across every manifest.
        let mut total_refs = 0u64;
        let mut unique_chunk_ids = std::collections::HashSet::new();
        for content in &content_hashes {
            let manifest_bytes = engine.remote().get_manifest(*content).await.unwrap();
            let manifest = Manifest::from_bytes(&manifest_bytes).unwrap();
            total_refs += manifest.chunks.len() as u64;
            for chunk in &manifest.chunks {
                unique_chunk_ids.insert(chunk.id);
            }
        }

        // The remote should have stored each unique chunk once; the
        // ratio of unique:total chunks should be small because the
        // shared prefix dominates the byte budget.
        let unique = unique_chunk_ids.len() as u64;
        assert!(
            unique * 3 < total_refs,
            "expected dedup: stored {} unique chunks vs {} total references",
            unique,
            total_refs
        );
    });
}

#[test]
fn near_duplicate_files_with_one_byte_prepend_share_chunks() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // Two versions of the same large body where v2 has one byte
        // prepended. Fixed-size chunking would re-align every chunk;
        // CDC keeps most boundaries stable, so the second backup
        // uploads strictly fewer chunks than its own chunk count.
        let base = synth_prefix(2 * 1024 * 1024);
        let mut shifted = Vec::with_capacity(base.len() + 1);
        shifted.push(0x42);
        shifted.extend_from_slice(&base);

        fs::write(scan_dir.path().join("v1.bin"), &base).unwrap();
        fs::write(scan_dir.path().join("v2.bin"), &shifted).unwrap();
        let c1 = ContentHash::from_data(&base);
        let c2 = ContentHash::from_data(&shifted);

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            chunking: cairn_types::ChunkingConfig {
                avg_size: 64 * 1024, // small enough to split 2 MB files
            },
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(41), remote, Box::new(Identity))
                .unwrap();

        let _ = engine.run_pass().await.unwrap();

        let m1 = Manifest::from_bytes(&engine.remote().get_manifest(c1).await.unwrap()).unwrap();
        let m2 = Manifest::from_bytes(&engine.remote().get_manifest(c2).await.unwrap()).unwrap();
        let ids1: std::collections::HashSet<_> = m1.chunks.iter().map(|c| c.id).collect();
        let ids2: std::collections::HashSet<_> = m2.chunks.iter().map(|c| c.id).collect();
        let shared = ids1.intersection(&ids2).count();
        let total_v2 = m2.chunks.len();
        assert!(
            shared * 2 >= total_v2,
            "expected ≥50% chunk reuse under one-byte prepend, got {shared} of {total_v2}"
        );
    });
}
