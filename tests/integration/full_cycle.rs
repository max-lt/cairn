//! M14 full-cycle integration:
//! scan → back up → delete locally → restore → verify byte-identical.
//!
//! Uses a LocalFilesystem remote backend to keep the test offline.
//! Varies file sizes (1 KB, 64 KB, 1 MB, 8 MB) so we exercise both
//! single-chunk and multi-chunk files.

use std::fs;

use cairn_cas::Identity;
use cairn_catalog::Catalog;
use cairn_engine::Engine;
use cairn_integration_tests::signing_key;
use cairn_remote::Remote;
use cairn_types::{Config, ContentHash};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn synth_bytes(seed: u32, n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 24) as u8)
        .collect()
}

#[test]
fn full_cycle_across_varied_file_sizes() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // Files of varying sizes — covers single-chunk (<= min) up to
        // many-chunk multi-megabyte content.
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("tiny.bin", synth_bytes(1, 1_024)),            // 1 KB
            ("small.bin", synth_bytes(2, 64 * 1_024)),      // 64 KB
            ("mid.bin", synth_bytes(3, 1_024 * 1_024)),     // 1 MB
            ("big.bin", synth_bytes(4, 8 * 1_024 * 1_024)), // 8 MB
        ];

        let mut expected: std::collections::HashMap<ContentHash, Vec<u8>> =
            std::collections::HashMap::new();
        for (name, body) in &cases {
            fs::write(scan_dir.path().join(name), body).unwrap();
            expected.insert(ContentHash::from_data(body), body.clone());
        }

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(20), remote, Box::new(Identity))
                .unwrap();

        let summary = engine.run_pass().await.unwrap();
        assert_eq!(summary.files_seen, cases.len() as u64);
        assert_eq!(summary.contents_backed_up, cases.len() as u32);

        // Delete each file locally — the test of the safety net.
        for (name, _) in &cases {
            fs::remove_file(scan_dir.path().join(name)).unwrap();
        }

        // Restore each content from the remote and verify byte-identical.
        for (i, (content, body)) in expected.iter().enumerate() {
            let out_path = scan_dir.path().join(format!("restored_{i}.bin"));
            engine.restore(*content, &out_path).await.unwrap();
            assert_eq!(
                fs::read(&out_path).unwrap(),
                *body,
                "restored bytes must match original (case {i})"
            );
        }
    });
}

#[test]
fn full_cycle_two_files_share_content_dedup_round_trip() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // Two identical files → one ContentHash, both restorable.
        let body = synth_bytes(99, 200_000);
        fs::write(scan_dir.path().join("a.bin"), &body).unwrap();
        fs::write(scan_dir.path().join("b.bin"), &body).unwrap();

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(21), remote, Box::new(Identity))
                .unwrap();

        let s = engine.run_pass().await.unwrap();
        assert_eq!(s.contents_backed_up, 1, "two paths, one content");
        let content = ContentHash::from_data(&body);
        let rec = engine.projection().content_index.get(&content).unwrap();
        assert!(rec.is_duplicate());
        assert!(rec.backed_up);

        fs::remove_file(scan_dir.path().join("a.bin")).unwrap();
        fs::remove_file(scan_dir.path().join("b.bin")).unwrap();

        let out = scan_dir.path().join("restored.bin");
        engine.restore(content, &out).await.unwrap();
        assert_eq!(fs::read(&out).unwrap(), body);
    });
}
