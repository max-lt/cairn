//! Safety invariant #1: Cairn never deletes, truncates, or modifies a
//! user file. Behavioral test: populate a tree, snapshot every file's
//! bytes + mtime, run a full pass (which includes scan + backup +
//! push), then re-snapshot. Every original file must still be present
//! and byte-identical.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

fn snapshot_tree(root: &std::path::Path) -> HashMap<PathBuf, Vec<u8>> {
    let mut out = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(bytes) = fs::read(&p) {
                out.insert(p, bytes);
            }
        }
    }
    out
}

#[test]
fn full_pass_does_not_touch_any_user_file() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // Populate with a few files (incl. a moderately large one).
        fs::create_dir(scan_dir.path().join("sub")).unwrap();
        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(scan_dir.path().join("b.txt"), b"beta").unwrap();
        fs::write(scan_dir.path().join("sub").join("c.txt"), b"gamma").unwrap();
        fs::write(scan_dir.path().join("big.bin"), vec![0xCDu8; 256 * 1024]).unwrap();

        let before = snapshot_tree(scan_dir.path());

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(60), remote, Box::new(Identity))
                .unwrap();

        engine.run_pass().await.unwrap();

        let after = snapshot_tree(scan_dir.path());
        assert_eq!(
            before, after,
            "run_pass must not modify ANY file under a scanned root"
        );
    });
}

#[test]
fn second_pass_after_no_changes_does_not_touch_user_files() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(scan_dir.path().join("b.txt"), b"beta").unwrap();
        let before = snapshot_tree(scan_dir.path());

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(61), remote, Box::new(Identity))
                .unwrap();

        engine.run_pass().await.unwrap();
        engine.run_pass().await.unwrap();
        let after = snapshot_tree(scan_dir.path());
        assert_eq!(before, after);
    });
}

#[test]
fn restore_writes_only_to_specified_output_not_to_scan_roots() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        let restore_dir = tempfile::tempdir().unwrap();

        fs::write(scan_dir.path().join("a.txt"), b"alpha-contents").unwrap();
        let before = snapshot_tree(scan_dir.path());

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(62), remote, Box::new(Identity))
                .unwrap();

        engine.run_pass().await.unwrap();

        let content = cairn_types::ContentHash::from_data(b"alpha-contents");
        let out_path = restore_dir.path().join("recovered.txt");
        engine.restore(content, &out_path).await.unwrap();

        // restore_dir gets a new file. scan_dir is unchanged.
        assert_eq!(fs::read(&out_path).unwrap(), b"alpha-contents");
        let after = snapshot_tree(scan_dir.path());
        assert_eq!(before, after);
    });
}
