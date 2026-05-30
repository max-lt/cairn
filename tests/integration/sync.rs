//! M9 integration: multi-machine sync through a shared remote.
//!
//! Two (and once three) simulated machines each own their own
//! MachineLog + Projection + Catalog and converge solely by pushing
//! segments to and pulling segments from one shared `Remote::memory()`.
//! No P2P, no peer-to-peer chat — every communication is an object_store
//! read or write.

use std::collections::HashMap;
use std::fs;

use cairn_catalog::{Catalog, LocalChainState, PassUpdates};
use cairn_engine::{pull_from, push_pending_as_segment};
use cairn_integration_tests::signing_key;
use cairn_log::{MachineLog, Projection};
use cairn_remote::Remote;
use cairn_scan::{ScanConfig, ScanEvent, Scanner};
use cairn_types::{CatalogEntry, ContentHash, PathKey};
use ed25519_dalek::SigningKey;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Per-machine state we drive in this test.
struct Machine {
    log: MachineLog,
    projection: Projection,
    catalog: Catalog,
    appended: Vec<cairn_types::LogEntry>,
}

impl Machine {
    fn new(key: SigningKey) -> Self {
        Self {
            log: MachineLog::fresh(key),
            projection: Projection::new(),
            catalog: Catalog::open_temporary().unwrap(),
            appended: Vec::new(),
        }
    }

    fn append_observed(&mut self, content: ContentHash, path: &str, size: u64, mtime: u64) {
        let entry =
            self.log
                .append_observed(content, PathKey::from_bytes(path.as_bytes()), size, mtime);
        self.projection.fold_entry(&entry);
        self.appended.push(entry);
    }

    fn append_vanished(&mut self, path: &str, last_content: ContentHash) {
        let entry = self
            .log
            .append_vanished(PathKey::from_bytes(path.as_bytes()), last_content);
        self.projection.fold_entry(&entry);
        self.appended.push(entry);
    }

    fn append_backed(&mut self, content: ContentHash) {
        let entry = self.log.append_backed(content);
        self.projection.fold_entry(&entry);
        self.appended.push(entry);
    }

    fn commit(&self) {
        self.catalog
            .apply_pass(&PassUpdates {
                catalog_changes: vec![],
                projection: self.projection.clone(),
                local_chain: LocalChainState {
                    next_seq: self.log.next_seq(),
                    tip: self.log.current_tip(),
                    last_hlc: self.log.current_hlc(),
                    last_pushed_seq: self
                        .catalog
                        .local_chain_state()
                        .map(|s| s.last_pushed_seq)
                        .unwrap_or(0),
                },
            })
            .unwrap();
    }

    fn pending_entries(&self) -> Vec<cairn_types::LogEntry> {
        let pushed = self.catalog.local_chain_state().unwrap().last_pushed_seq;
        self.appended
            .iter()
            .filter(|e| if pushed == 0 { true } else { e.seq > pushed })
            .cloned()
            .collect()
    }
}

#[test]
fn two_machines_converge_to_identical_content_index() {
    rt().block_on(async {
        let remote = Remote::memory();
        let mut a = Machine::new(signing_key(1));
        let mut b = Machine::new(signing_key(2));

        let c_a1 = ContentHash::from_data(b"a1");
        let c_a2 = ContentHash::from_data(b"a2");
        let c_b1 = ContentHash::from_data(b"b1");

        a.append_observed(c_a1, "/a/one", 2, 0);
        a.append_observed(c_a2, "/a/two", 2, 0);
        a.append_backed(c_a1);
        a.append_backed(c_a2);
        a.commit();

        b.append_observed(c_b1, "/b/one", 2, 0);
        b.append_backed(c_b1);
        b.commit();

        // Push.
        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();

        // Each pulls the other.
        pull_from(
            b.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        let snap_a = a.projection.create_snapshot();
        let snap_b = b.projection.create_snapshot();
        assert_eq!(
            snap_a.state_hash, snap_b.state_hash,
            "two machines must converge to identical state_hash after mutual pull"
        );

        // Both should know about all three contents.
        for c in [c_a1, c_a2, c_b1] {
            assert!(a.projection.content_index.contains_key(&c));
            assert!(b.projection.content_index.contains_key(&c));
        }
    });
}

#[test]
fn shared_content_across_machines_yields_one_record_two_live_locations() {
    rt().block_on(async {
        let remote = Remote::memory();
        let mut a = Machine::new(signing_key(1));
        let mut b = Machine::new(signing_key(2));

        let shared = ContentHash::from_data(b"shared bytes");
        a.append_observed(shared, "/a/host/file", 12, 0);
        a.append_backed(shared);
        a.commit();

        b.append_observed(shared, "/b/host/file", 12, 0);
        b.append_backed(shared);
        b.commit();

        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();

        pull_from(
            b.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        let rec_a = a.projection.content_index.get(&shared).unwrap();
        let rec_b = b.projection.content_index.get(&shared).unwrap();
        assert_eq!(rec_a.live_locations.len(), 2);
        assert_eq!(rec_b.live_locations.len(), 2);
        assert!(rec_a.is_duplicate());
        assert!(rec_b.backed_up);
        // Same set of live locations on each side.
        assert_eq!(rec_a.live_locations, rec_b.live_locations);
    });
}

#[test]
fn vanished_on_one_machine_keeps_other_machines_location_live() {
    rt().block_on(async {
        let remote = Remote::memory();
        let mut a = Machine::new(signing_key(1));
        let mut b = Machine::new(signing_key(2));

        let shared = ContentHash::from_data(b"shared and then gone on A");
        a.append_observed(shared, "/a/here", 24, 0);
        a.append_backed(shared);
        a.commit();
        b.append_observed(shared, "/b/here", 24, 0);
        b.append_backed(shared);
        b.commit();

        // First round of push + cross-pull.
        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();
        pull_from(
            b.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        // Now A loses its copy. (B keeps its.)
        a.append_vanished("/a/here", shared);
        a.commit();
        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        // After convergence: only B's location is live.
        let rec = b.projection.content_index.get(&shared).unwrap();
        assert_eq!(rec.live_locations.len(), 1);
        assert!(rec.backed_up, "Vanished must NOT clear backed_up");
        assert_eq!(rec.live_locations[0].machine, b.log.machine());
    });
}

#[test]
fn order_independent_fold_across_three_machines() {
    rt().block_on(async {
        let remote = Remote::memory();
        let mut a = Machine::new(signing_key(11));
        let mut b = Machine::new(signing_key(12));
        let mut c = Machine::new(signing_key(13));

        let shared = ContentHash::from_data(b"shared everywhere");
        let unique_a = ContentHash::from_data(b"only-a");
        let unique_b = ContentHash::from_data(b"only-b");

        a.append_observed(shared, "/a/shared", 17, 0);
        a.append_observed(unique_a, "/a/own", 6, 0);
        a.append_backed(shared);
        a.append_backed(unique_a);
        a.commit();

        b.append_observed(shared, "/b/shared", 17, 0);
        b.append_observed(unique_b, "/b/own", 6, 0);
        b.append_backed(shared);
        b.append_backed(unique_b);
        b.commit();

        c.append_observed(shared, "/c/shared", 17, 0);
        c.append_backed(shared);
        c.commit();

        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&c.log, &c.catalog, &remote, c.pending_entries())
            .await
            .unwrap();

        // a pulls b then c
        pull_from(
            b.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();
        pull_from(
            c.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();

        // b pulls c then a
        pull_from(
            c.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        // c pulls a then b
        pull_from(
            a.log.machine(),
            &c.log,
            &c.catalog,
            &remote,
            &mut c.projection,
        )
        .await
        .unwrap();
        pull_from(
            b.log.machine(),
            &c.log,
            &c.catalog,
            &remote,
            &mut c.projection,
        )
        .await
        .unwrap();

        let h_a = a.projection.create_snapshot().state_hash;
        let h_b = b.projection.create_snapshot().state_hash;
        let h_c = c.projection.create_snapshot().state_hash;
        assert_eq!(h_a, h_b);
        assert_eq!(h_b, h_c);
    });
}

#[test]
fn integration_two_machines_each_scan_disjoint_trees() {
    rt().block_on(async {
        let remote = Remote::memory();

        // A's tree
        let dir_a = tempfile::tempdir().unwrap();
        fs::write(dir_a.path().join("alpha"), b"alpha-bytes").unwrap();
        fs::write(dir_a.path().join("beta"), b"beta-bytes").unwrap();
        // B's tree (shared file with A by content!)
        let dir_b = tempfile::tempdir().unwrap();
        fs::write(dir_b.path().join("alpha-copy"), b"alpha-bytes").unwrap();
        fs::write(dir_b.path().join("gamma"), b"gamma-bytes").unwrap();

        let scanner = Scanner::new(ScanConfig {
            respect_gitignore: false,
            ..ScanConfig::default()
        });

        let mut a = Machine::new(signing_key(21));
        let events_a = scanner
            .scan_root(dir_a.path(), &HashMap::<PathKey, CatalogEntry>::new())
            .unwrap();
        for e in events_a {
            match e {
                ScanEvent::Observed {
                    content,
                    path,
                    size,
                    mtime,
                    ..
                } => {
                    a.append_observed(content, path.as_str(), size, mtime);
                    a.append_backed(content);
                }
                ScanEvent::Vanished { path, last_content } => {
                    a.append_vanished(path.as_str(), last_content);
                }
                ScanEvent::PassCompleted { .. } => {}
            }
        }
        a.commit();

        let mut b = Machine::new(signing_key(22));
        let events_b = scanner
            .scan_root(dir_b.path(), &HashMap::<PathKey, CatalogEntry>::new())
            .unwrap();
        for e in events_b {
            match e {
                ScanEvent::Observed {
                    content,
                    path,
                    size,
                    mtime,
                    ..
                } => {
                    b.append_observed(content, path.as_str(), size, mtime);
                    b.append_backed(content);
                }
                ScanEvent::Vanished { path, last_content } => {
                    b.append_vanished(path.as_str(), last_content);
                }
                ScanEvent::PassCompleted { .. } => {}
            }
        }
        b.commit();

        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();
        pull_from(
            b.log.machine(),
            &a.log,
            &a.catalog,
            &remote,
            &mut a.projection,
        )
        .await
        .unwrap();
        pull_from(
            a.log.machine(),
            &b.log,
            &b.catalog,
            &remote,
            &mut b.projection,
        )
        .await
        .unwrap();

        // Convergence.
        assert_eq!(
            a.projection.create_snapshot().state_hash,
            b.projection.create_snapshot().state_hash
        );

        // The shared content has two live locations (one per machine).
        let shared = ContentHash::from_data(b"alpha-bytes");
        let rec = a.projection.content_index.get(&shared).unwrap();
        assert_eq!(rec.live_locations.len(), 2);
        assert!(rec.is_duplicate());
        assert!(rec.backed_up);
    });
}
