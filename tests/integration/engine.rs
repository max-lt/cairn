//! M12 integration: drive the high-level [`Engine`] orchestrator.
//!
//! `Engine::run_pass` glues every M1-M9 component into one call —
//! scan + log append + catalog commit + backup + push. Tests below
//! exercise: full first pass, idempotent second pass with no changes,
//! restore after a local-deletion, and check() detecting corruption of
//! a pushed segment.

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

fn build_engine(scan_root: PathBuf, catalog_dir: &std::path::Path, seed: u8) -> Engine {
    let config = Config {
        scan_roots: vec![scan_root],
        excludes: vec![],
        ..Config::default()
    };
    let catalog_path = catalog_dir.join("cat.redb");
    let catalog = Catalog::open(&catalog_path).unwrap();
    let remote = Remote::memory();
    Engine::from_parts(
        config,
        catalog,
        signing_key(seed),
        remote,
        Box::new(Identity),
    )
    .unwrap()
}

#[test]
fn first_run_pass_indexes_and_backs_up_every_file() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(scan_dir.path().join("b.txt"), b"beta").unwrap();
        fs::write(scan_dir.path().join("twin.txt"), b"alpha").unwrap();

        let mut engine = build_engine(scan_dir.path().to_path_buf(), cat_dir.path(), 7);
        let summary = engine.run_pass().await.unwrap();

        assert_eq!(summary.roots_scanned, 1);
        assert_eq!(summary.files_seen, 3);
        assert_eq!(summary.new_observations, 3);
        assert_eq!(summary.vanished, 0);
        // alpha + beta are distinct; twin shares alpha → 2 backups.
        assert_eq!(summary.contents_backed_up, 2);
        assert!(summary.entries_pushed >= 4); // 3 observed + ≥1 pass_completed + 2 backed

        // Every observed content is backed up in the projection.
        let alpha = ContentHash::from_data(b"alpha");
        let beta = ContentHash::from_data(b"beta");
        let p = engine.projection();
        assert!(p.content_index.get(&alpha).unwrap().backed_up);
        assert!(p.content_index.get(&beta).unwrap().backed_up);
        // alpha has two live locations (twin shares it).
        assert_eq!(p.content_index.get(&alpha).unwrap().live_locations.len(), 2);
    });
}

#[test]
fn second_run_pass_with_no_changes_is_a_no_op() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(scan_dir.path().join("b.txt"), b"beta").unwrap();

        let mut engine = build_engine(scan_dir.path().to_path_buf(), cat_dir.path(), 7);
        let _ = engine.run_pass().await.unwrap();
        let second = engine.run_pass().await.unwrap();

        // The cache makes Observed go to zero. PassCompleted still fires.
        assert_eq!(second.new_observations, 0);
        assert_eq!(second.vanished, 0);
        assert_eq!(second.contents_backed_up, 0);
        assert_eq!(second.chunks_uploaded, 0);
        assert_eq!(second.bytes_uploaded, 0);
    });
}

#[test]
fn restore_a_file_after_local_deletion() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let important = scan_dir.path().join("important.txt");
        let body = b"this matters and we will recover it";
        fs::write(&important, body).unwrap();
        let content = ContentHash::from_data(body);

        let mut engine = build_engine(scan_dir.path().to_path_buf(), cat_dir.path(), 9);
        engine.run_pass().await.unwrap();

        // Delete the local copy.
        fs::remove_file(&important).unwrap();
        assert!(!important.exists());

        let recovered = scan_dir.path().join("recovered.txt");
        engine.restore(content, &recovered).await.unwrap();
        assert_eq!(fs::read(&recovered).unwrap(), body);
    });
}

#[test]
fn check_flags_a_corrupted_pushed_segment() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        fs::write(scan_dir.path().join("file.txt"), b"some content").unwrap();

        // Use a shared object_store under the hood so we can corrupt it
        // out-of-band.
        let store: std::sync::Arc<dyn object_store::ObjectStore> =
            std::sync::Arc::new(object_store::memory::InMemory::new());
        let remote = Remote::with_store(store.clone());
        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let mut engine =
            Engine::from_parts(config, catalog, signing_key(5), remote, Box::new(Identity))
                .unwrap();

        engine.run_pass().await.unwrap();

        // First, check() reports no corruption.
        let report = engine.check().await.unwrap();
        assert!(
            report.corruption_found.is_empty(),
            "expected clean: {report:?}"
        );
        assert!(report.local_segments_verified >= 1);

        // Now corrupt the local segment in the remote.
        let machine = engine.machine();
        let segs = engine.remote().list_segments(machine).await.unwrap();
        assert!(!segs.is_empty());
        let seg = &segs[0];
        let os_path = object_store::path::Path::parse(&seg.path).unwrap();
        store
            .put(
                &os_path,
                object_store::PutPayload::from(bytes::Bytes::from_static(b"corrupted bytes")),
            )
            .await
            .unwrap();

        let report = engine.check().await.unwrap();
        assert!(
            !report.corruption_found.is_empty(),
            "check must flag the corrupted segment"
        );
    });
}
