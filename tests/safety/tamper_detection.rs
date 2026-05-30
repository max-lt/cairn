//! Safety: corrupt a log segment in the remote → `check()` flags it.
//! Corrupt a stored chunk → `restore` refuses to serve unverified
//! bytes. In neither case may bad data reach the user.

use std::fs;
use std::sync::Arc;

use cairn_cas::Identity;
use cairn_catalog::Catalog;
use cairn_engine::{Engine, EngineError};
use cairn_integration_tests::signing_key;
use cairn_remote::{Remote, RemoteError};
use cairn_types::{Config, ContentHash, Manifest};
use object_store::ObjectStore;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn check_flags_a_corrupted_local_segment() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let remote = Remote::with_store(store.clone());
        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let mut engine = Engine::from_parts(
            config,
            catalog,
            signing_key(100),
            remote,
            Box::new(Identity),
        )
        .unwrap();
        engine.run_pass().await.unwrap();

        let clean = engine.check().await.unwrap();
        assert!(clean.corruption_found.is_empty());

        // Corrupt the segment in the store.
        let machine = engine.machine();
        let segs = engine.remote().list_segments(machine).await.unwrap();
        let seg = &segs[0];
        let os_path = object_store::path::Path::parse(&seg.path).unwrap();
        store
            .put(
                &os_path,
                object_store::PutPayload::from(bytes::Bytes::from_static(b"corrupted")),
            )
            .await
            .unwrap();

        let dirty = engine.check().await.unwrap();
        assert!(
            !dirty.corruption_found.is_empty(),
            "check must flag the corrupted segment"
        );
    });
}

#[test]
fn restore_rejects_corrupted_chunk_and_writes_no_output() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let body = b"this must be restored intact or refused";
        fs::write(scan_dir.path().join("file.bin"), body).unwrap();
        let content = ContentHash::from_data(body);

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let remote = Remote::with_store(store.clone());
        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let mut engine = Engine::from_parts(
            config,
            catalog,
            signing_key(101),
            remote,
            Box::new(Identity),
        )
        .unwrap();
        engine.run_pass().await.unwrap();

        // Sanity: an honest restore works.
        let happy_path = scan_dir.path().join("happy.bin");
        engine.restore(content, &happy_path).await.unwrap();
        assert_eq!(fs::read(&happy_path).unwrap(), body);

        // Now corrupt the first chunk in the store.
        let manifest_bytes = engine.remote().get_manifest(content).await.unwrap();
        let manifest = Manifest::from_bytes(&manifest_bytes).unwrap();
        let target = manifest.chunks.first().unwrap();
        let key = Remote::chunk_path(target.id);
        let os_path = object_store::path::Path::parse(&key).unwrap();
        let garbage = bytes::Bytes::from(vec![0xAA; target.size as usize]);
        store
            .put(&os_path, object_store::PutPayload::from(garbage))
            .await
            .unwrap();

        // Restore must refuse to serve corrupted data + write no output.
        let bad_out = scan_dir.path().join("should-not-exist.bin");
        let err = engine.restore(content, &bad_out).await.unwrap_err();
        match err {
            EngineError::Remote(RemoteError::ChunkIntegrity { .. }) => {}
            EngineError::RestoreIntegrity { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(!bad_out.exists(), "no partial output on integrity failure");
    });
}

#[test]
fn restore_rejects_corrupted_manifest_version() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let body = b"file";
        fs::write(scan_dir.path().join("f.txt"), body).unwrap();
        let content = ContentHash::from_data(body);

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let remote = Remote::with_store(store.clone());
        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            ..Config::default()
        };
        let catalog = Catalog::open(&cat_dir.path().join("cat.redb")).unwrap();
        let mut engine = Engine::from_parts(
            config,
            catalog,
            signing_key(102),
            remote,
            Box::new(Identity),
        )
        .unwrap();
        engine.run_pass().await.unwrap();

        // Plant a manifest with a bogus version.
        let bad_manifest = Manifest {
            version: 99,
            content,
            total_size: 4,
            chunks: vec![],
            created_at: 0,
        };
        let bad_bytes = postcard::to_allocvec(&bad_manifest).unwrap();
        let key = Remote::manifest_path(content);
        let os_path = object_store::path::Path::parse(&key).unwrap();
        store
            .put(&os_path, object_store::PutPayload::from(bad_bytes))
            .await
            .unwrap();

        let out = scan_dir.path().join("recovered");
        let err = engine.restore(content, &out).await.unwrap_err();
        assert!(matches!(
            err,
            EngineError::Types(cairn_types::TypesError::UnknownManifestVersion { .. })
        ));
        assert!(!out.exists());
    });
}
