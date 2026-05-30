//! M6: scan → log → catalog end-to-end (no remote yet).
//!
//! Wires every M1–M5 crate together to prove the local-only loop works
//! before the remote layer (M7) lands. Three scenarios:
//!
//! 1. First pass on a populated temp tree.
//! 2. Second pass after `modify + delete + add` — exactly the expected
//!    deltas, with the deleted path tombstoned (gone from live, present
//!    in history).
//! 3. Kill-and-reopen: drop the catalog, `rebuild_from` the log
//!    projection, and assert all the same queries answer identically.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use cairn_catalog::{Catalog, CatalogChange, LocalChainState, PassUpdates};
use cairn_integration_tests::signing_key;
use cairn_log::{LocationState, MachineLog, Projection};
use cairn_scan::{ScanConfig, ScanEvent, Scanner};
use cairn_types::{CatalogEntry, ContentHash, PathKey};

/// Translate the scanner's events into (log entries, catalog mutations).
///
/// This is the small amount of glue that the engine layer (M12) will own
/// later; for now we inline it here so the integration test is
/// self-contained.
fn apply_events_to_log_and_catalog(
    log: &mut MachineLog,
    projection: &mut Projection,
    events: Vec<ScanEvent>,
) -> Vec<CatalogChange> {
    let mut catalog_changes = Vec::new();
    let mut observed_contents: Vec<ContentHash> = Vec::new();

    for event in events {
        match event {
            ScanEvent::Observed {
                content,
                path,
                size,
                mtime,
                file_id,
            } => {
                let entry = log.append_observed(content, path.clone(), size, mtime);
                projection.fold_entry(&entry);
                catalog_changes.push(CatalogChange::Upsert(CatalogEntry {
                    path,
                    content,
                    size,
                    mtime,
                    file_id,
                    last_scan: entry.hlc,
                }));
                if !observed_contents.contains(&content) {
                    observed_contents.push(content);
                }
            }
            ScanEvent::Vanished { path, last_content } => {
                let entry = log.append_vanished(path.clone(), last_content);
                projection.fold_entry(&entry);
                catalog_changes.push(CatalogChange::Delete(path));
            }
            ScanEvent::PassCompleted {
                root,
                files_seen,
                bytes_seen,
            } => {
                let entry = log.append_pass_completed(root, files_seen, bytes_seen);
                projection.fold_entry(&entry);
            }
        }
    }

    // After observations, mark each new content as backed up. (M6 is
    // local-only; the engine would skip this until a remote backup
    // actually succeeded — here we just want a Backed event in the log
    // so the projection reflects the steady-state.)
    for content in observed_contents {
        let entry = log.append_backed(content);
        projection.fold_entry(&entry);
    }

    catalog_changes
}

fn run_pass(
    scanner: &Scanner,
    log: &mut MachineLog,
    projection: &mut Projection,
    catalog: &Catalog,
    root: &Path,
) -> Vec<ScanEvent> {
    let prev_entries = catalog
        .iter_catalog_under(&PathKey::from_path(root))
        .unwrap();
    let prev_map: HashMap<PathKey, CatalogEntry> = prev_entries
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();

    let events = scanner.scan_root(root, &prev_map).unwrap();
    let events_clone = events.clone();

    let catalog_changes = apply_events_to_log_and_catalog(log, projection, events);

    catalog
        .apply_pass(&PassUpdates {
            catalog_changes,
            projection: projection.clone(),
            local_chain: LocalChainState {
                next_seq: log.next_seq(),
                tip: log.current_tip(),
                last_hlc: log.current_hlc(),
                last_pushed_seq: 0,
            },
        })
        .unwrap();
    events_clone
}

fn observed_paths(events: &[ScanEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            ScanEvent::Observed { path, .. } => Some(path.as_str().to_string()),
            _ => None,
        })
        .collect()
}

fn vanished_paths(events: &[ScanEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            ScanEvent::Vanished { path, .. } => Some(path.as_str().to_string()),
            _ => None,
        })
        .collect()
}

fn scanner() -> Scanner {
    Scanner::new(ScanConfig {
        respect_gitignore: false,
        ..ScanConfig::default()
    })
}

#[test]
fn first_pass_indexes_every_file_and_detects_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    // Two byte-identical files exercise dedup; a third is distinct.
    fs::write(dir.path().join("a.txt"), b"shared bytes").unwrap();
    fs::write(dir.path().join("b.txt"), b"shared bytes").unwrap();
    fs::write(dir.path().join("c.txt"), b"unique bytes").unwrap();

    let catalog = Catalog::open_temporary().unwrap();
    let mut log = MachineLog::fresh(signing_key(1));
    let mut projection = Projection::new();

    let events = run_pass(&scanner(), &mut log, &mut projection, &catalog, dir.path());

    assert_eq!(observed_paths(&events).len(), 3);
    assert!(vanished_paths(&events).is_empty());

    let shared = ContentHash::from_data(b"shared bytes");
    let unique = ContentHash::from_data(b"unique bytes");

    let dup_record = catalog
        .get_content(&shared)
        .unwrap()
        .expect("shared content");
    assert!(dup_record.is_duplicate());
    assert_eq!(dup_record.live_locations.len(), 2);
    assert!(dup_record.backed_up);

    let uniq_record = catalog
        .get_content(&unique)
        .unwrap()
        .expect("unique content");
    assert!(!uniq_record.is_duplicate());
    assert_eq!(uniq_record.live_locations.len(), 1);
    assert!(uniq_record.backed_up);

    let dups = catalog.duplicates().unwrap();
    assert_eq!(dups.len(), 1);
    assert_eq!(dups[0].content, shared);
}

#[test]
fn second_pass_modify_delete_add_emits_expected_deltas() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("modify.txt"), b"v1").unwrap();
    fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
    fs::write(dir.path().join("delete.txt"), b"goodbye").unwrap();

    let catalog = Catalog::open_temporary().unwrap();
    let mut log = MachineLog::fresh(signing_key(2));
    let mut projection = Projection::new();

    let _ = run_pass(&scanner(), &mut log, &mut projection, &catalog, dir.path());

    // Mutate the tree.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(dir.path().join("modify.txt"), b"v2").unwrap();
    fs::remove_file(dir.path().join("delete.txt")).unwrap();
    fs::write(dir.path().join("add.txt"), b"newcomer").unwrap();

    let events = run_pass(&scanner(), &mut log, &mut projection, &catalog, dir.path());

    let observed = observed_paths(&events);
    let vanished = vanished_paths(&events);
    assert_eq!(
        observed.len(),
        2,
        "expected exactly 2 Observed (modify + add), got: {observed:?}"
    );
    assert!(observed.iter().any(|p| p.ends_with("modify.txt")));
    assert!(observed.iter().any(|p| p.ends_with("add.txt")));
    assert_eq!(vanished.len(), 1, "expected exactly 1 Vanished (delete)");
    assert!(vanished[0].ends_with("delete.txt"));

    // The modified file's old content lost its only location;
    // the new content has a live location at modify.txt.
    let old_v1 = ContentHash::from_data(b"v1");
    let v2 = ContentHash::from_data(b"v2");
    let v1_record = catalog.get_content(&old_v1).unwrap().unwrap();
    assert!(v1_record.live_locations.is_empty());
    assert!(v1_record.backed_up);
    let v2_record = catalog.get_content(&v2).unwrap().unwrap();
    assert_eq!(v2_record.live_locations.len(), 1);
    assert!(v2_record.backed_up);

    // The deleted file's content has no live locations; tombstoned but
    // still backed up.
    let goodbye = ContentHash::from_data(b"goodbye");
    let rec = catalog.get_content(&goodbye).unwrap().unwrap();
    assert!(rec.live_locations.is_empty());
    assert!(rec.backed_up);
    assert!(rec.is_orphan());

    // Tombstoned path no longer resolves.
    let tombstoned = catalog
        .resolve_path(&PathKey::from_path(&dir.path().join("delete.txt")))
        .unwrap();
    assert!(tombstoned.is_none());

    // History of the tombstoned content includes that path via the
    // projection's all_locations_of helper.
    let locs = projection.all_locations_of(goodbye);
    assert_eq!(locs.len(), 1);
    assert!(matches!(locs[0].1.state, LocationState::Tombstoned(_)));

    // Steady-state checks via catalog queries.
    let orphans: Vec<_> = catalog
        .orphans()
        .unwrap()
        .into_iter()
        .map(|r| r.content)
        .collect();
    assert!(orphans.contains(&goodbye));
    assert!(orphans.contains(&old_v1));
}

#[test]
fn kill_and_reopen_rebuilds_index_from_projection() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("alpha.txt"), b"shared").unwrap();
    fs::write(dir.path().join("beta.txt"), b"shared").unwrap();
    fs::write(dir.path().join("gamma.txt"), b"unique").unwrap();

    let catalog_a = Catalog::open_temporary().unwrap();
    let mut log = MachineLog::fresh(signing_key(3));
    let mut projection = Projection::new();
    let _ = run_pass(
        &scanner(),
        &mut log,
        &mut projection,
        &catalog_a,
        dir.path(),
    );

    // Simulate cache loss: open a *fresh* catalog and rebuild from the
    // log projection (the engine would replay snapshots + segments here
    // in M9; for M6 we replay the in-memory projection directly).
    let catalog_b = Catalog::open_temporary().unwrap();
    catalog_b.rebuild_from(&projection).unwrap();

    let shared = ContentHash::from_data(b"shared");
    let unique = ContentHash::from_data(b"unique");

    // Every observable content-index query agrees between catalogs.
    let mut a_records = catalog_a.all_content().unwrap();
    let mut b_records = catalog_b.all_content().unwrap();
    a_records.sort_by_key(|r| r.content);
    b_records.sort_by_key(|r| r.content);
    assert_eq!(a_records, b_records);

    let a_resolved = catalog_a
        .resolve_path(&PathKey::from_path(&dir.path().join("alpha.txt")))
        .unwrap();
    let b_resolved = catalog_b
        .resolve_path(&PathKey::from_path(&dir.path().join("alpha.txt")))
        .unwrap();
    assert_eq!(a_resolved, b_resolved);
    assert_eq!(a_resolved, Some(shared));

    let a_dups: Vec<_> = catalog_a
        .duplicates()
        .unwrap()
        .into_iter()
        .map(|r| r.content)
        .collect();
    let b_dups: Vec<_> = catalog_b
        .duplicates()
        .unwrap()
        .into_iter()
        .map(|r| r.content)
        .collect();
    assert_eq!(a_dups, b_dups);
    assert_eq!(a_dups, vec![shared]);

    let _ = unique;
}
