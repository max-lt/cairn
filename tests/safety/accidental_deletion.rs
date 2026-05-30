//! Safety: a file accidentally deleted on disk must remain restorable
//! from the remote. Vanished is a tombstone on the location-index, not
//! a deletion of the content blob.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

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

fn count_chunks(remote_dir: &std::path::Path) -> usize {
    fn walk(dir: &std::path::Path, out: &mut HashSet<PathBuf>) {
        if let Ok(read) = fs::read_dir(dir) {
            for entry in read.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.insert(p);
                }
            }
        }
    }
    let chunks_dir = remote_dir.join("chunks");
    let mut set = HashSet::new();
    walk(&chunks_dir, &mut set);
    set.len()
}

#[test]
fn vanished_file_is_still_restorable_and_chunks_stay_put() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        // Three files with unique content — none share chunks at all.
        let bodies: Vec<Vec<u8>> = vec![
            b"only-copy-of-alpha-xxx-".repeat(100),
            b"only-copy-of-beta-yyy--".repeat(100),
            b"only-copy-of-gamma-zzz-".repeat(100),
        ];
        let names = ["alpha.bin", "beta.bin", "gamma.bin"];
        let contents: Vec<ContentHash> = bodies.iter().map(|b| ContentHash::from_data(b)).collect();
        for (n, b) in names.iter().zip(&bodies) {
            fs::write(scan_dir.path().join(n), b).unwrap();
        }

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(50), remote, Box::new(Identity))
                .unwrap();

        engine.run_pass().await.unwrap();
        let chunks_after_backup = count_chunks(remote_dir.path());
        assert!(chunks_after_backup >= 3, "expected at least 3 chunks");

        // Delete the only local copies.
        for n in &names {
            fs::remove_file(scan_dir.path().join(n)).unwrap();
        }

        // Run another pass — the scanner emits Vanished for each.
        let summary = engine.run_pass().await.unwrap();
        assert_eq!(summary.vanished, names.len() as u64);

        // The chunk count in the remote has NOT dropped.
        let chunks_after_vanish = count_chunks(remote_dir.path());
        assert_eq!(
            chunks_after_vanish, chunks_after_backup,
            "Vanished MUST NOT delete remote chunks"
        );

        // Every vanished content is still backed_up and listed as orphan.
        let orphan_set: HashSet<ContentHash> =
            engine.projection().orphans().map(|r| r.content).collect();
        for c in &contents {
            assert!(orphan_set.contains(c), "content {c} should be an orphan");
            let rec = engine.projection().content_index.get(c).unwrap();
            assert!(rec.backed_up);
            assert!(rec.live_locations.is_empty());
        }

        // Every vanished content is fully restorable + verifies its hash.
        for (i, content) in contents.iter().enumerate() {
            let out = scan_dir.path().join(format!("restored_{i}.bin"));
            engine.restore(*content, &out).await.unwrap();
            assert_eq!(fs::read(&out).unwrap(), bodies[i]);
        }
    });
}
