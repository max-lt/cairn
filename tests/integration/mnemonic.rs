//! M16 integration: BIP-39 mnemonic-derived encryption + deferred backup.
//!
//! Exercises the "scan now without secret, backup later with secret" flow
//! the user wants:
//!
//! 1. `run_pass_metadata_only` with an Engine wired to `Identity` →
//!    catalog records every observed file but uploads nothing.
//! 2. `backup_pending` with an Engine wired to `Encrypt::from_mnemonic`
//!    → uploads encrypted chunks + manifests for every still-unbacked
//!    content.
//! 3. `restore` with the same mnemonic-derived transform → bytes match
//!    the original.
//! 4. `restore` with a different mnemonic → integrity failure, no output.
//!
//! All headless: no TTY, no env vars, no disk-resident secret. The
//! mnemonic is a fixed test vector parsed from a string.

use std::fs;
use std::sync::Arc;

use cairn_bip39::PhraseInput;
use cairn_bip39::bip39::{Language, Mnemonic};
use cairn_cas::{Encrypt, Identity};
use cairn_catalog::Catalog;
use cairn_engine::{Engine, EngineError};
use cairn_integration_tests::signing_key;
use cairn_remote::Remote;
use cairn_types::{Config, ContentHash, EncryptionConfig};
use object_store::ObjectStore;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn test_mnemonic() -> Mnemonic {
    // Valid 12-word BIP-39 test vector (checksum OK).
    Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about",
    )
    .unwrap()
}

#[test]
fn scan_metadata_only_then_backup_pending_with_mnemonic() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        fs::write(scan_dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(scan_dir.path().join("b.txt"), b"beta").unwrap();
        // Twin shares content with a.txt → only 2 distinct contents.
        fs::write(scan_dir.path().join("twin.txt"), b"alpha").unwrap();

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            encryption: EncryptionConfig {
                enabled: true,
                salt_path: None,
            },
            ..Config::default()
        };
        let catalog_path = cat_dir.path().join("cat.redb");

        // Phase 1: scan without the mnemonic. Engine uses Identity, but
        // we explicitly skip backup via run_pass_metadata_only.
        {
            let catalog = Catalog::open(&catalog_path).unwrap();
            let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
            let mut engine = Engine::from_parts(
                config.clone(),
                catalog,
                signing_key(160),
                remote,
                Box::new(Identity),
            )
            .unwrap();

            let s = engine.run_pass_metadata_only().await.unwrap();
            assert_eq!(s.new_observations, 3);
            assert_eq!(s.contents_backed_up, 0, "metadata-only never backs up");
            assert_eq!(s.chunks_uploaded, 0);

            // Two distinct contents recorded as observed but not backed_up.
            let alpha = ContentHash::from_data(b"alpha");
            let beta = ContentHash::from_data(b"beta");
            let p = engine.projection();
            assert!(!p.content_index.get(&alpha).unwrap().backed_up);
            assert!(!p.content_index.get(&beta).unwrap().backed_up);
        }

        // Phase 2: re-open the engine with the mnemonic-derived
        // transform, and call backup_pending. Now the chunks land in
        // the remote, encrypted with the convergent content key.
        let mnemonic = test_mnemonic();
        {
            let catalog = Catalog::open(&catalog_path).unwrap();
            let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
            let transform = Encrypt::from_mnemonic(&mnemonic);
            let mut engine = Engine::from_parts(
                config.clone(),
                catalog,
                signing_key(160),
                remote,
                Box::new(transform),
            )
            .unwrap();

            let s = engine.backup_pending().await.unwrap();
            assert_eq!(s.contents_backed_up, 2, "alpha + beta");
            assert!(s.chunks_uploaded > 0);

            // Both contents flipped to backed_up.
            let alpha = ContentHash::from_data(b"alpha");
            let beta = ContentHash::from_data(b"beta");
            let p = engine.projection();
            assert!(p.content_index.get(&alpha).unwrap().backed_up);
            assert!(p.content_index.get(&beta).unwrap().backed_up);
        }

        // Phase 3: restore with the same mnemonic — bytes match.
        {
            let catalog = Catalog::open(&catalog_path).unwrap();
            let remote = Remote::local_filesystem(remote_dir.path()).unwrap();
            let transform = Encrypt::from_mnemonic(&mnemonic);
            let engine = Engine::from_parts(
                config.clone(),
                catalog,
                signing_key(160),
                remote,
                Box::new(transform),
            )
            .unwrap();

            let out = scan_dir.path().join("restored.txt");
            engine
                .restore(ContentHash::from_data(b"alpha"), &out)
                .await
                .unwrap();
            assert_eq!(fs::read(&out).unwrap(), b"alpha");
        }
    });
}

#[test]
fn restore_with_wrong_mnemonic_fails_without_writing_output() {
    rt().block_on(async {
        let scan_dir = tempfile::tempdir().unwrap();
        let cat_dir = tempfile::tempdir().unwrap();
        let body = b"secret contents that only my mnemonic can decrypt";
        fs::write(scan_dir.path().join("file.txt"), body).unwrap();
        let content = ContentHash::from_data(body);

        let config = Config {
            scan_roots: vec![scan_dir.path().to_path_buf()],
            encryption: EncryptionConfig {
                enabled: true,
                salt_path: None,
            },
            ..Config::default()
        };
        let catalog_path = cat_dir.path().join("cat.redb");
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());

        let right_mnemonic = test_mnemonic();
        let wrong_mnemonic = Mnemonic::parse_in(
            Language::English,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();

        // Back up with the right mnemonic.
        {
            let catalog = Catalog::open(&catalog_path).unwrap();
            let remote = Remote::with_store(store.clone());
            let transform = Encrypt::from_mnemonic(&right_mnemonic);
            let mut engine = Engine::from_parts(
                config.clone(),
                catalog,
                signing_key(161),
                remote,
                Box::new(transform),
            )
            .unwrap();
            engine.run_pass().await.unwrap();
        }

        // Restore with the wrong mnemonic → AEAD auth failure surfaces
        // as EngineError::Cas, no output file written.
        {
            let catalog = Catalog::open(&catalog_path).unwrap();
            let remote = Remote::with_store(store.clone());
            let transform = Encrypt::from_mnemonic(&wrong_mnemonic);
            let engine = Engine::from_parts(
                config.clone(),
                catalog,
                signing_key(161),
                remote,
                Box::new(transform),
            )
            .unwrap();

            let bad_out = scan_dir.path().join("recovered.bin");
            let err = engine.restore(content, &bad_out).await.unwrap_err();
            assert!(
                matches!(err, EngineError::Cas(_)),
                "got unexpected error variant: {err:?}"
            );
            assert!(!bad_out.exists(), "no output on wrong mnemonic");
        }
    });
}

#[test]
fn cross_machine_convergent_dedup_with_same_mnemonic() {
    rt().block_on(async {
        // Two "machines" sharing the same mnemonic, each backing up the
        // same content to the same remote. The second machine must
        // upload zero chunks — convergent encryption + identical key →
        // byte-identical ciphertext → put_chunk_if_absent no-ops.
        let mnemonic = test_mnemonic();
        let remote_dir = tempfile::tempdir().unwrap();
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let content = ContentHash::from_data(&body);

        let cfg = Config {
            scan_roots: vec![],
            chunking: cairn_types::ChunkingConfig {
                avg_size: 64 * 1024,
            },
            encryption: EncryptionConfig {
                enabled: true,
                salt_path: None,
            },
            ..Config::default()
        };
        let chunker = cairn_cas::CdcChunker::from_avg_size(cfg.chunking.avg_size);

        let scan_a = tempfile::tempdir().unwrap();
        let scan_b = tempfile::tempdir().unwrap();
        fs::write(scan_a.path().join("x.bin"), &body).unwrap();
        fs::write(scan_b.path().join("x.bin"), &body).unwrap();

        let remote = Remote::local_filesystem(remote_dir.path()).unwrap();

        let transform = Encrypt::from_mnemonic(&mnemonic);
        let s_a = cairn_engine::backup_content(
            content,
            &scan_a.path().join("x.bin"),
            &remote,
            &chunker,
            &transform,
            0,
        )
        .await
        .unwrap();
        let s_b = cairn_engine::backup_content(
            content,
            &scan_b.path().join("x.bin"),
            &remote,
            &chunker,
            &transform,
            0,
        )
        .await
        .unwrap();

        assert!(
            s_a.chunks_uploaded > 0,
            "first backup must upload chunks: got {s_a:?}"
        );
        assert_eq!(
            s_b.chunks_uploaded, 0,
            "second backup with same mnemonic must dedup all chunks (convergent encryption); got {s_b:?}"
        );
    });
}

#[test]
fn phrase_input_drives_a_known_mnemonic_headless() {
    // The TUI front-end needs a real terminal; the underlying PhraseInput
    // is a pure state machine and is the way every other front-end
    // (this test, a future GUI) drives mnemonic entry.
    let mut input = PhraseInput::new(Language::English, 12);
    let words = [
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "about",
    ];
    for w in words {
        for c in w.chars() {
            input.push_char(c);
        }
        let accepted = input.accepted().unwrap_or_else(|| {
            panic!(
                "expected unique completion for {w:?}, candidates were {:?}",
                input.candidates()
            )
        });
        input.commit(accepted);
    }
    assert!(input.is_complete());
    let mnemonic = input.validate().expect("checksum should be valid");
    assert_eq!(mnemonic.to_string(), test_mnemonic().to_string());
}
