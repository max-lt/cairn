//! M8 integration: scan a tree → back up every observed content →
//! assert every ContentHash is `backed_up` in the projection and the
//! manifest/chunks are present in the remote.

use std::collections::HashMap;
use std::fs;

use cairn_cas::{CdcChunker, Identity};
use cairn_engine::{backup_content, restore};
use cairn_integration_tests::signing_key;
use cairn_log::{MachineLog, Projection};
use cairn_remote::Remote;
use cairn_scan::{ScanConfig, ScanEvent, Scanner};
use cairn_types::{CatalogEntry, ContentHash, Manifest, PathKey};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn scan_then_back_up_every_content_via_engine() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"beta").unwrap();
        // Two files sharing one ContentHash → backup must hit it once.
        fs::write(dir.path().join("twin.txt"), b"alpha").unwrap();

        let scanner = Scanner::new(ScanConfig {
            respect_gitignore: false,
            ..ScanConfig::default()
        });
        let events = scanner
            .scan_root(dir.path(), &HashMap::<PathKey, CatalogEntry>::new())
            .unwrap();

        // Collect distinct (content, fs_path) observed in this pass.
        let mut by_content: HashMap<ContentHash, std::path::PathBuf> = HashMap::new();
        for e in &events {
            if let ScanEvent::Observed { content, path, .. } = e {
                by_content
                    .entry(*content)
                    .or_insert_with(|| std::path::PathBuf::from(path.as_str()));
            }
        }
        assert_eq!(by_content.len(), 2, "alpha/beta are two distinct contents");

        // Drive the log + projection so we can check backed_up flips.
        let mut log = MachineLog::fresh(signing_key(7));
        let mut projection = Projection::new();
        for e in &events {
            match e {
                ScanEvent::Observed {
                    content,
                    path,
                    size,
                    mtime,
                    ..
                } => {
                    let entry = log.append_observed(*content, path.clone(), *size, *mtime);
                    projection.fold_entry(&entry);
                }
                ScanEvent::Vanished { path, last_content } => {
                    let entry = log.append_vanished(path.clone(), *last_content);
                    projection.fold_entry(&entry);
                }
                ScanEvent::PassCompleted {
                    root,
                    files_seen,
                    bytes_seen,
                } => {
                    let entry = log.append_pass_completed(root.clone(), *files_seen, *bytes_seen);
                    projection.fold_entry(&entry);
                }
            }
        }

        // Back up every observed content via cairn-engine.
        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        for (content, fs_path) in &by_content {
            backup_content(
                *content,
                fs_path,
                &remote,
                &chunker,
                &Identity,
                log.current_hlc(),
            )
            .await
            .unwrap();
            let backed = log.append_backed(*content);
            projection.fold_entry(&backed);
        }

        // Every content is now backed_up in the projection.
        for content in by_content.keys() {
            let rec = projection.content_index.get(content).expect("indexed");
            assert!(rec.backed_up, "content {content} should be backed_up");
        }

        // And the manifest is fetchable + version-correct in the remote.
        for content in by_content.keys() {
            let manifest_bytes = remote.get_manifest(*content).await.unwrap();
            let manifest = Manifest::from_bytes(&manifest_bytes).unwrap();
            assert_eq!(manifest.content, *content);
            assert_eq!(manifest.version, cairn_types::MANIFEST_VERSION);
        }
    });
}

#[test]
fn restore_a_file_after_its_local_copy_was_deleted() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("important.txt");
        let body = b"this file matters and we lost it locally";
        fs::write(&src, body).unwrap();
        let content = ContentHash::from_data(body);

        let remote = Remote::memory();
        let chunker = CdcChunker::from_avg_size(64 * 1024);
        backup_content(content, &src, &remote, &chunker, &Identity, 0)
            .await
            .unwrap();

        // Lose the local copy. The remote still has it.
        fs::remove_file(&src).unwrap();
        assert!(!src.exists());

        // Restore to a new path and verify.
        let out = dir.path().join("recovered.txt");
        restore(content, &out, &remote, &Identity).await.unwrap();
        assert_eq!(fs::read(&out).unwrap(), body);
    });
}
