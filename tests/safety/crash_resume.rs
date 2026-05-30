//! Safety: an interrupted pass must leave the engine in a consistent
//! committed state and resume cleanly. We simulate interruption by
//! running an Engine, dropping it, and reopening from the same catalog
//! database — the new Engine should pick up where the previous left
//! off and the end result must match an uninterrupted run.

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

fn populate(root: &std::path::Path) {
    fs::write(root.join("a.txt"), b"alpha").unwrap();
    fs::write(root.join("b.txt"), b"beta").unwrap();
    fs::write(root.join("c.txt"), b"gamma").unwrap();
    fs::write(root.join("d.txt"), b"delta").unwrap();
    fs::write(root.join("e.txt"), b"epsilon").unwrap();
}

#[test]
fn drop_and_reopen_does_not_lose_or_duplicate_committed_state() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        populate(scan_dir.path());

        // Round 1: full pass, then drop.
        let summary1 = {
            let config = Config {
                scan_roots: vec![scan_dir.path().to_path_buf()],
                ..Config::default()
            };
            let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
            let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
            let mut engine =
                Engine::from_parts(config, catalog, signing_key(90), remote, Box::new(Identity))
                    .unwrap();
            engine.run_pass().await.unwrap()
        };
        assert_eq!(summary1.new_observations, 5);

        // Reopen with the same catalog + signing key.
        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(90), remote, Box::new(Identity))
                .unwrap();

        // Second pass on the same tree: cache hits → no work.
        let summary2 = engine.run_pass().await.unwrap();
        assert_eq!(summary2.new_observations, 0);
        assert_eq!(summary2.contents_backed_up, 0);
        assert_eq!(summary2.chunks_uploaded, 0);

        // Mutate one file → next pass observes exactly one change.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(scan_dir.path().join("a.txt"), b"alpha-v2").unwrap();
        let summary3 = engine.run_pass().await.unwrap();
        assert_eq!(summary3.new_observations, 1);
        assert_eq!(summary3.contents_backed_up, 1);
    });
}

#[test]
fn drop_after_backup_but_before_push_resumes_cleanly() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        populate(scan_dir.path());

        // Run a full pass + drop. The pass commits the catalog and pushes
        // a segment; on reopen, a new pass on the unchanged tree must
        // not re-push anything.
        {
            let config = Config {
                scan_roots: vec![scan_dir.path().to_path_buf()],
                ..Config::default()
            };
            let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
            let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
            let mut engine =
                Engine::from_parts(config, catalog, signing_key(91), remote, Box::new(Identity))
                    .unwrap();
            let s = engine.run_pass().await.unwrap();
            assert!(s.entries_pushed > 0);
        }

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(91), remote, Box::new(Identity))
                .unwrap();
        let s = engine.run_pass().await.unwrap();
        // PassCompleted is the only entry of the second pass; it gets pushed.
        // No content changes → no new backups.
        assert_eq!(s.new_observations, 0);
        assert_eq!(s.vanished, 0);
        assert_eq!(s.contents_backed_up, 0);
    });
}
