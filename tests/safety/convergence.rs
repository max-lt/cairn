//! Safety: three simulated machines with overlapping content converge
//! to the same materialized state, regardless of pull order; a file
//! deleted on one machine but present on another stays live after
//! convergence.

use cairn_engine::{pull_from, push_pending_as_segment};
use cairn_integration_tests::signing_key;
use cairn_log::{MachineLog, Projection};
use cairn_remote::Remote;
use cairn_types::{ContentHash, LogEntry, PathKey};
use ed25519_dalek::SigningKey;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct Machine {
    log: MachineLog,
    projection: Projection,
    catalog: cairn_catalog::Catalog,
    appended: Vec<LogEntry>,
}

impl Machine {
    fn new(key: SigningKey) -> Self {
        Self {
            log: MachineLog::fresh(key),
            projection: Projection::new(),
            catalog: cairn_catalog::Catalog::open_temporary().unwrap(),
            appended: Vec::new(),
        }
    }

    fn append_observed(&mut self, content: ContentHash, path: &str) {
        let e = self
            .log
            .append_observed(content, PathKey::from_bytes(path.as_bytes()), 1, 0);
        self.projection.fold_entry(&e);
        self.appended.push(e);
    }

    fn append_backed(&mut self, content: ContentHash) {
        let e = self.log.append_backed(content);
        self.projection.fold_entry(&e);
        self.appended.push(e);
    }

    fn append_vanished(&mut self, path: &str, last_content: ContentHash) {
        let e = self
            .log
            .append_vanished(PathKey::from_bytes(path.as_bytes()), last_content);
        self.projection.fold_entry(&e);
        self.appended.push(e);
    }

    fn pending_entries(&self) -> Vec<LogEntry> {
        let pushed = self.catalog.local_chain_state().unwrap().last_pushed_seq;
        self.appended
            .iter()
            .filter(|e| if pushed == 0 { true } else { e.seq > pushed })
            .cloned()
            .collect()
    }
}

#[test]
fn three_machines_converge_under_interleaved_push_and_pull() {
    rt().block_on(async {
        let remote = Remote::memory();

        let mut a = Machine::new(signing_key(70));
        let mut b = Machine::new(signing_key(71));
        let mut c = Machine::new(signing_key(72));

        let shared = ContentHash::from_data(b"shared everywhere");
        let unique_a = ContentHash::from_data(b"only-a");
        let unique_b = ContentHash::from_data(b"only-b");
        let unique_c = ContentHash::from_data(b"only-c");

        // Round 1: each machine appends some events, then pushes.
        a.append_observed(shared, "/a/shared");
        a.append_observed(unique_a, "/a/own");
        a.append_backed(shared);
        a.append_backed(unique_a);
        push_pending_as_segment(&a.log, &a.catalog, &remote, a.pending_entries())
            .await
            .unwrap();

        b.append_observed(shared, "/b/shared");
        b.append_observed(unique_b, "/b/own");
        b.append_backed(shared);
        b.append_backed(unique_b);
        push_pending_as_segment(&b.log, &b.catalog, &remote, b.pending_entries())
            .await
            .unwrap();

        c.append_observed(shared, "/c/shared");
        c.append_observed(unique_c, "/c/own");
        c.append_backed(shared);
        c.append_backed(unique_c);
        push_pending_as_segment(&c.log, &c.catalog, &remote, c.pending_entries())
            .await
            .unwrap();

        // Round 2: each machine pulls the other two — in a DIFFERENT
        // order on each side. Convergence must hold regardless of order.
        // A: pull B, then C
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
        // B: pull C, then A
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
        // C: pull A, then B
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

        let ha = a.projection.create_snapshot().state_hash;
        let hb = b.projection.create_snapshot().state_hash;
        let hc = c.projection.create_snapshot().state_hash;
        assert_eq!(ha, hb);
        assert_eq!(hb, hc);

        // shared has three live locations.
        let rec = a.projection.content_index.get(&shared).unwrap();
        assert_eq!(rec.live_locations.len(), 3);
    });
}

#[test]
fn delete_on_one_machine_keeps_other_locations_live_after_convergence() {
    rt().block_on(async {
        let remote = Remote::memory();
        let mut a = Machine::new(signing_key(80));
        let mut b = Machine::new(signing_key(81));

        let shared = ContentHash::from_data(b"present on both");
        a.append_observed(shared, "/a/here");
        a.append_backed(shared);
        b.append_observed(shared, "/b/here");
        b.append_backed(shared);

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

        // Now A loses its copy.
        a.append_vanished("/a/here", shared);
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

        // B's projection: only B's location is live, content remains backed up.
        let rec = b.projection.content_index.get(&shared).unwrap();
        assert_eq!(rec.live_locations.len(), 1);
        assert_eq!(rec.live_locations[0].machine, b.log.machine());
        assert!(rec.backed_up, "Vanished MUST NOT clear backed_up");
    });
}
