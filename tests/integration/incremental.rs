//! M14 incremental: after a first pass over a tree, further passes
//! should do work proportional to the change, not the tree size.

use std::fs;

use cairn_cas::Identity;
use cairn_catalog::Catalog;
use cairn_engine::Engine;
use cairn_integration_tests::signing_key;
use cairn_remote::Remote;
use cairn_types::Config;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn build_tree(root: &std::path::Path, n_files: usize, file_size: usize) {
    fs::create_dir_all(root).unwrap();
    for i in 0..n_files {
        let body: Vec<u8> = (0..file_size as u32)
            .map(|b| (b.wrapping_add(i as u32).wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        fs::write(root.join(format!("f{i:04}.bin")), body).unwrap();
    }
}

#[test]
fn second_pass_after_no_changes_is_a_no_op_for_a_tree() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        build_tree(scan_dir.path(), 100, 4 * 1024);

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(30), remote, Box::new(Identity))
                .unwrap();

        let s1 = engine.run_pass().await.unwrap();
        assert_eq!(s1.new_observations, 100, "every file observed once");
        assert_eq!(s1.contents_backed_up, 100);

        let s2 = engine.run_pass().await.unwrap();
        assert_eq!(s2.new_observations, 0, "cache hit on every file");
        assert_eq!(s2.contents_backed_up, 0);
        assert_eq!(s2.chunks_uploaded, 0);
        assert_eq!(s2.bytes_uploaded, 0);
    });
}

#[test]
fn pass_after_a_single_mutation_emits_a_single_observation() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        let n_files = 50;
        build_tree(scan_dir.path(), n_files, 8 * 1024);

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(31), remote, Box::new(Identity))
                .unwrap();

        let _ = engine.run_pass().await.unwrap();

        // Mutate exactly one file's content.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(scan_dir.path().join("f0001.bin"), b"changed-version").unwrap();

        let s2 = engine.run_pass().await.unwrap();
        assert_eq!(s2.new_observations, 1, "exactly one mutation observed");
        assert_eq!(s2.vanished, 0);
        assert_eq!(s2.contents_backed_up, 1);
    });
}

#[test]
fn delete_one_file_emits_a_single_vanished_and_no_observations() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        build_tree(scan_dir.path(), 50, 2 * 1024);

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(32), remote, Box::new(Identity))
                .unwrap();

        let _ = engine.run_pass().await.unwrap();
        fs::remove_file(scan_dir.path().join("f0007.bin")).unwrap();

        let s2 = engine.run_pass().await.unwrap();
        assert_eq!(s2.new_observations, 0);
        assert_eq!(s2.vanished, 1);
        assert_eq!(
            s2.contents_backed_up, 0,
            "Vanished alone does not back up new content"
        );
    });
}
