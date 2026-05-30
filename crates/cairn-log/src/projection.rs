//! [`Projection`]: the materialized state that a stream of log entries folds into.
//!
//! The projection is the queryable, in-memory representation of "what is
//! where right now, and what is backed up". It is the source from which
//! [`cairn-catalog`](../../cairn_catalog/index.html)'s redb store is
//! refreshed, and the input to query commands like `cairn dupes`,
//! `cairn locate`, and `cairn orphans`.
//!
//! ## Fold semantics
//!
//! Folding is **order-independent** within a fixed set of entries —
//! shuffle the segments any way you like and the resulting projection
//! serializes to the same bytes (and therefore the same `state_hash`).
//! This holds because:
//!
//! - Per `Location`, only entries from that location's machine ever
//!   touch it (single-writer per location), and we apply Last-Writer-Wins
//!   by `(hlc, machine)`.
//! - `first_seen` / `last_seen` are min / max over [`Observed`] HLCs.
//! - `backed_up` is a monotonic OR.
//! - `live_locations` is kept sorted on every mutation.
//! - All maps are [`BTreeMap`]s, which iterate in deterministic key order.
//!
//! [`Observed`]: cairn_types::Action::Observed

use std::collections::BTreeMap;

use cairn_types::{Action, ContentHash, ContentRecord, Location, LogEntry, MachineId, PathKey};
use serde::{Deserialize, Serialize};

use crate::LogError;
use crate::segment::Segment;

/// LWW state recorded per location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationFold {
    /// Highest HLC any entry from the owning machine has produced for this location.
    pub last_hlc: u64,
    /// The current state of the location.
    pub state: LocationState,
}

/// Whether a location currently holds content or has been tombstoned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationState {
    /// Live: the location currently holds this content.
    Live(ContentHash),
    /// Tombstoned: the location no longer holds content; the last content
    /// previously observed is recorded for history queries.
    Tombstoned(ContentHash),
}

/// The most recent (seq, hash) point of a machine's chain that the
/// projection has folded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTip {
    /// Highest sequence number folded.
    pub seq: u64,
    /// Hash of that entry.
    pub hash: [u8; 32],
}

/// Per-root pass statistics from the most recent `PassCompleted` event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassStats {
    /// Number of regular files seen during the last pass over this root.
    pub files_seen: u64,
    /// Total bytes seen during the last pass.
    pub bytes_seen: u64,
    /// HLC of the last `PassCompleted` for this root.
    pub last_pass_hlc: u64,
}

/// The materialized projection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Projection {
    /// Content records keyed by [`ContentHash`].
    pub content_index: BTreeMap<ContentHash, ContentRecord>,
    /// LWW fold state per [`Location`].
    pub location_state: BTreeMap<Location, LocationFold>,
    /// Highest seen tip per machine — used by [`prune_segments_before`].
    pub chain_tips: BTreeMap<MachineId, ChainTip>,
    /// Stats per scan root from the most recent `PassCompleted`.
    pub pass_stats: BTreeMap<PathKey, PassStats>,
    /// The most recent snapshot's state hash, if any has been folded.
    pub last_snapshot: Option<[u8; 32]>,
}

/// A serialized projection plus its blake3 state hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// `blake3` of [`Self::bytes`].
    pub state_hash: [u8; 32],
    /// Postcard-serialized [`Projection`].
    pub bytes: Vec<u8>,
}

impl Projection {
    /// Empty projection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold every entry in a verified [`Segment`].
    pub fn fold_segment(&mut self, segment: &Segment) {
        for entry in &segment.entries {
            self.fold_entry(entry);
        }
    }

    /// Fold a slice of entries (any order, any source).
    pub fn fold(&mut self, entries: &[LogEntry]) {
        for e in entries {
            self.fold_entry(e);
        }
    }

    /// Fold a single entry into the projection.
    pub fn fold_entry(&mut self, entry: &LogEntry) {
        match &entry.action {
            Action::Observed {
                content,
                path,
                size,
                mtime: _,
            } => self.fold_observed(entry, *content, path, *size),
            Action::Vanished { path, last_content } => {
                self.fold_vanished(entry, path, *last_content)
            }
            Action::Backed { content } => self.fold_backed(*content),
            Action::PassCompleted {
                root,
                files_seen,
                bytes_seen,
            } => self.fold_pass_completed(entry.hlc, root.clone(), *files_seen, *bytes_seen),
            Action::Snapshot { state_hash } => {
                self.last_snapshot = Some(*state_hash);
            }
        }
        self.update_chain_tip(entry);
    }

    fn update_chain_tip(&mut self, entry: &LogEntry) {
        let tip = self.chain_tips.entry(entry.machine).or_default();
        // Within a chain, sequence numbers are strictly increasing; we
        // never overwrite a higher tip with a lower one (out-of-order
        // entries from the same machine are caller-prevented via segment
        // verification, but we defend here too).
        if entry.seq >= tip.seq {
            tip.seq = entry.seq;
            tip.hash = entry.hash;
        }
    }

    fn fold_observed(&mut self, entry: &LogEntry, content: ContentHash, path: &PathKey, size: u64) {
        let location = Location {
            machine: entry.machine,
            path: path.clone(),
        };

        if !self.lww_should_apply(&location, entry.hlc) {
            // Even though we skip the location update, we still want to
            // make sure the content record reflects this Observed for
            // first_seen / last_seen — it is order-independent (min/max).
            self.ensure_content_metadata(content, size, entry.hlc);
            return;
        }

        // Drop the previous `(location -> some_content)` link if it pointed
        // to a different content (or to a tombstone we are now reviving).
        if let Some(prev) = self.location_state.get(&location)
            && let LocationState::Live(prev_content) = prev.state
            && prev_content != content
            && let Some(rec) = self.content_index.get_mut(&prev_content)
        {
            remove_sorted(&mut rec.live_locations, &location);
        }

        // Upsert the content record and add the location.
        {
            let rec = self.ensure_content_record(content);
            rec.size = size;
            if rec.first_seen == 0 || entry.hlc < rec.first_seen {
                rec.first_seen = entry.hlc;
            }
            if entry.hlc > rec.last_seen {
                rec.last_seen = entry.hlc;
            }
            insert_sorted_unique(&mut rec.live_locations, location.clone());
        }

        self.location_state.insert(
            location,
            LocationFold {
                last_hlc: entry.hlc,
                state: LocationState::Live(content),
            },
        );
    }

    fn fold_vanished(&mut self, entry: &LogEntry, path: &PathKey, last_content: ContentHash) {
        let location = Location {
            machine: entry.machine,
            path: path.clone(),
        };

        if !self.lww_should_apply(&location, entry.hlc) {
            return;
        }

        // Remove the location from whatever content currently owns it.
        if let Some(prev) = self.location_state.get(&location)
            && let LocationState::Live(prev_content) = prev.state
            && let Some(rec) = self.content_index.get_mut(&prev_content)
        {
            remove_sorted(&mut rec.live_locations, &location);
        }

        self.location_state.insert(
            location,
            LocationFold {
                last_hlc: entry.hlc,
                state: LocationState::Tombstoned(last_content),
            },
        );
    }

    fn fold_backed(&mut self, content: ContentHash) {
        let rec = self.ensure_content_record(content);
        rec.backed_up = true;
    }

    fn fold_pass_completed(&mut self, hlc: u64, root: PathKey, files_seen: u64, bytes_seen: u64) {
        // PassCompleted carries this pass's totals — the latest pass wins,
        // by HLC, so older PassCompleted events do not overwrite newer
        // recorded stats.
        let stats = self.pass_stats.entry(root).or_default();
        if hlc >= stats.last_pass_hlc {
            stats.last_pass_hlc = hlc;
            stats.files_seen = files_seen;
            stats.bytes_seen = bytes_seen;
        }
    }

    fn lww_should_apply(&self, location: &Location, hlc: u64) -> bool {
        match self.location_state.get(location) {
            None => true,
            Some(prev) => hlc > prev.last_hlc,
        }
    }

    fn ensure_content_record(&mut self, content: ContentHash) -> &mut ContentRecord {
        self.content_index
            .entry(content)
            .or_insert_with(|| ContentRecord {
                content,
                size: 0,
                live_locations: Vec::new(),
                backed_up: false,
                first_seen: 0,
                last_seen: 0,
            })
    }

    fn ensure_content_metadata(&mut self, content: ContentHash, size: u64, hlc: u64) {
        let rec = self.ensure_content_record(content);
        if rec.size == 0 {
            rec.size = size;
        }
        if rec.first_seen == 0 || hlc < rec.first_seen {
            rec.first_seen = hlc;
        }
        if hlc > rec.last_seen {
            rec.last_seen = hlc;
        }
    }

    /// Serialize this projection canonically and produce its blake3 hash.
    ///
    /// The output is byte-canonical: two projections folded from the same
    /// set of entries (in any order) produce identical bytes and therefore
    /// identical `state_hash` values.
    pub fn create_snapshot(&self) -> Snapshot {
        let bytes = postcard::to_allocvec(self).expect("postcard serialize should not fail");
        let state_hash = blake3::hash(&bytes).into();
        Snapshot { state_hash, bytes }
    }

    /// Restore a projection from snapshot bytes.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, LogError> {
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Iterate over all duplicate content (`live_locations.len() > 1`).
    pub fn duplicates(&self) -> impl Iterator<Item = &ContentRecord> + '_ {
        self.content_index.values().filter(|r| r.is_duplicate())
    }

    /// Iterate over all orphan content (`backed_up && live_locations.is_empty()`).
    pub fn orphans(&self) -> impl Iterator<Item = &ContentRecord> + '_ {
        self.content_index.values().filter(|r| r.is_orphan())
    }

    /// All known locations (live + tombstoned) for a given content hash.
    pub fn all_locations_of(&self, content: ContentHash) -> Vec<(Location, LocationFold)> {
        self.location_state
            .iter()
            .filter_map(|(loc, fold)| match fold.state {
                LocationState::Live(c) if c == content => Some((loc.clone(), fold.clone())),
                LocationState::Tombstoned(c) if c == content => Some((loc.clone(), fold.clone())),
                _ => None,
            })
            .collect()
    }
}

/// Drop log segments whose entire sequence range is covered by the
/// snapshot's per-machine chain tips.
///
/// A segment is kept iff its `seq_end > snapshot.chain_tips[machine].seq`,
/// i.e. it contributes at least one entry the snapshot has not yet
/// absorbed. Segments from unknown machines are always kept.
pub fn prune_segments_before(snapshot: &Projection, segments: Vec<Segment>) -> Vec<Segment> {
    segments
        .into_iter()
        .filter(|seg| match snapshot.chain_tips.get(&seg.machine) {
            Some(tip) => seg.seq_end > tip.seq,
            None => true,
        })
        .collect()
}

fn insert_sorted_unique(vec: &mut Vec<Location>, location: Location) {
    match vec.binary_search(&location) {
        Ok(_) => {} // already present
        Err(pos) => vec.insert(pos, location),
    }
}

fn remove_sorted(vec: &mut Vec<Location>, location: &Location) {
    if let Ok(pos) = vec.binary_search(location) {
        vec.remove(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_log::MachineLog;
    use cairn_types::{ContentHash, PathKey};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn observed_then_backed(log: &mut MachineLog, path: &str, body: &[u8]) -> ContentHash {
        let content = ContentHash::from_data(body);
        let _ = log.append_observed(
            content,
            PathKey::from_bytes(path.as_bytes()),
            body.len() as u64,
            0,
        );
        let _ = log.append_backed(content);
        content
    }

    #[test]
    fn empty_projection_has_no_records() {
        let p = Projection::new();
        assert!(p.content_index.is_empty());
        assert!(p.location_state.is_empty());
        assert!(p.chain_tips.is_empty());
        assert!(p.duplicates().next().is_none());
        assert!(p.orphans().next().is_none());
    }

    #[test]
    fn observe_then_back_marks_backed_up_and_records_location() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c = ContentHash::from_data(b"file");
        let e1 = log.append_observed(c, PathKey::from_bytes(b"/a.txt"), 4, 0);
        let e2 = log.append_backed(c);
        p.fold_entry(&e1);
        p.fold_entry(&e2);

        let rec = p.content_index.get(&c).expect("record present");
        assert!(rec.backed_up);
        assert_eq!(rec.live_locations.len(), 1);
        assert_eq!(rec.live_locations[0].path, PathKey::from_bytes(b"/a.txt"));
        assert_eq!(rec.size, 4);
        assert_eq!(rec.first_seen, e1.hlc);
        assert_eq!(rec.last_seen, e1.hlc);
    }

    #[test]
    fn tombstone_removes_live_location_but_keeps_record_and_backed_up() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c = ContentHash::from_data(b"file");
        p.fold_entry(&log.append_observed(c, PathKey::from_bytes(b"/a.txt"), 4, 0));
        p.fold_entry(&log.append_backed(c));
        let vanished = log.append_vanished(PathKey::from_bytes(b"/a.txt"), c);
        p.fold_entry(&vanished);

        let rec = p.content_index.get(&c).expect("record still present");
        assert!(rec.live_locations.is_empty());
        assert!(rec.backed_up, "Vanished must NOT clear backed_up");
        assert!(rec.is_orphan(), "now an orphan: no locations, backed up");
    }

    #[test]
    fn two_paths_same_content_is_a_duplicate() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c = ContentHash::from_data(b"shared");
        p.fold_entry(&log.append_observed(c, PathKey::from_bytes(b"/a"), 6, 0));
        p.fold_entry(&log.append_observed(c, PathKey::from_bytes(b"/b"), 6, 0));
        let rec = p.content_index.get(&c).unwrap();
        assert_eq!(rec.live_locations.len(), 2);
        assert!(rec.is_duplicate());
        // Live_locations are stored sorted.
        assert!(rec.live_locations.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn observed_then_replaced_moves_location_between_contents() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c1 = ContentHash::from_data(b"v1");
        let c2 = ContentHash::from_data(b"v2");
        p.fold_entry(&log.append_observed(c1, PathKey::from_bytes(b"/x"), 2, 0));
        p.fold_entry(&log.append_observed(c2, PathKey::from_bytes(b"/x"), 2, 0));

        let r1 = p.content_index.get(&c1).unwrap();
        let r2 = p.content_index.get(&c2).unwrap();
        assert!(
            r1.live_locations.is_empty(),
            "old content lost its location"
        );
        assert_eq!(r2.live_locations.len(), 1);
    }

    #[test]
    fn fold_order_independence_two_machines_same_path() {
        // M1 and M2 each observe at different HLCs on their own paths.
        // Folding either order must yield identical state hashes.
        let mut log1 = MachineLog::fresh(key(1));
        let mut log2 = MachineLog::fresh(key(2));

        let c = ContentHash::from_data(b"shared content");
        let e1 = log1.append_observed(c, PathKey::from_bytes(b"/host1/a"), 14, 0);
        let e2 = log2.append_observed(c, PathKey::from_bytes(b"/host2/a"), 14, 0);

        let mut p_a = Projection::new();
        p_a.fold_entry(&e1);
        p_a.fold_entry(&e2);

        let mut p_b = Projection::new();
        p_b.fold_entry(&e2);
        p_b.fold_entry(&e1);

        assert_eq!(
            p_a.create_snapshot().state_hash,
            p_b.create_snapshot().state_hash
        );
    }

    #[test]
    fn lww_older_observed_ignored_after_vanished() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c = ContentHash::from_data(b"x");
        let e_obs = log.append_observed(c, PathKey::from_bytes(b"/a"), 1, 0);
        let e_van = log.append_vanished(PathKey::from_bytes(b"/a"), c);

        // Now construct an older Observed by reusing the SAME entry e_obs
        // and folding it AFTER e_van. Since fold checks LWW by hlc, the
        // tombstone (newer) wins and the older Observed is a no-op.
        p.fold_entry(&e_van);
        p.fold_entry(&e_obs);

        let rec = p.content_index.get(&c).unwrap();
        assert!(
            rec.live_locations.is_empty(),
            "older Observed must not revive tombstone"
        );
    }

    #[test]
    fn pass_completed_records_stats() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let e = log.append_pass_completed(PathKey::from_bytes(b"/data"), 7, 12_345);
        p.fold_entry(&e);
        let stats = p.pass_stats.get(&PathKey::from_bytes(b"/data")).unwrap();
        assert_eq!(stats.files_seen, 7);
        assert_eq!(stats.bytes_seen, 12_345);
        assert_eq!(stats.last_pass_hlc, e.hlc);
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        observed_then_backed(&mut log, "/a.txt", b"alpha");
        observed_then_backed(&mut log, "/b.txt", b"beta");
        let entries = vec![
            log.append_observed(
                ContentHash::from_data(b"alpha"),
                PathKey::from_bytes(b"/a.txt"),
                5,
                0,
            ),
            log.append_backed(ContentHash::from_data(b"alpha")),
            log.append_observed(
                ContentHash::from_data(b"beta"),
                PathKey::from_bytes(b"/b.txt"),
                4,
                0,
            ),
            log.append_backed(ContentHash::from_data(b"beta")),
        ];
        p.fold(&entries);

        let snapshot = p.create_snapshot();
        let restored = Projection::from_snapshot_bytes(&snapshot.bytes).unwrap();
        assert_eq!(p, restored);
        assert_eq!(snapshot.state_hash, restored.create_snapshot().state_hash);
    }

    #[test]
    fn snapshot_plus_remaining_segments_reproduces_state() {
        let mut log = MachineLog::fresh(key(1));
        let early = vec![
            log.append_observed(
                ContentHash::from_data(b"a"),
                PathKey::from_bytes(b"/a"),
                1,
                0,
            ),
            log.append_backed(ContentHash::from_data(b"a")),
        ];
        let late = vec![
            log.append_observed(
                ContentHash::from_data(b"b"),
                PathKey::from_bytes(b"/b"),
                1,
                0,
            ),
            log.append_backed(ContentHash::from_data(b"b")),
        ];

        // "Pure" fold of everything.
        let mut full = Projection::new();
        full.fold(&early);
        full.fold(&late);
        let full_hash = full.create_snapshot().state_hash;

        // "Snapshot + remainder" fold: snapshot after `early`, then
        // restore and fold `late`.
        let mut early_proj = Projection::new();
        early_proj.fold(&early);
        let snap = early_proj.create_snapshot();
        let mut resumed = Projection::from_snapshot_bytes(&snap.bytes).unwrap();
        resumed.fold(&late);

        assert_eq!(full_hash, resumed.create_snapshot().state_hash);
    }

    #[test]
    fn prune_segments_drops_segments_below_chain_tip() {
        let mut log = MachineLog::fresh(key(1));
        let seg_a = Segment::try_from_entries(vec![
            log.append_backed(ContentHash::from_data(b"a")),
            log.append_backed(ContentHash::from_data(b"b")),
        ])
        .unwrap();
        let seg_b = Segment::try_from_entries(vec![
            log.append_backed(ContentHash::from_data(b"c")),
            log.append_backed(ContentHash::from_data(b"d")),
        ])
        .unwrap();

        let mut snap = Projection::new();
        snap.fold_segment(&seg_a);
        // seg_a's last seq is 1; snap.chain_tips[machine].seq == 1.
        let remaining = prune_segments_before(&snap, vec![seg_a.clone(), seg_b.clone()]);
        assert_eq!(remaining.len(), 1, "seg_a should be pruned, seg_b kept");
        assert_eq!(remaining[0].seq_start, seg_b.seq_start);
    }

    #[test]
    fn duplicates_and_orphans_queries() {
        let mut log1 = MachineLog::fresh(key(1));
        let mut log2 = MachineLog::fresh(key(2));
        let mut p = Projection::new();

        let dup = ContentHash::from_data(b"shared");
        p.fold_entry(&log1.append_observed(dup, PathKey::from_bytes(b"/m1/a"), 6, 0));
        p.fold_entry(&log2.append_observed(dup, PathKey::from_bytes(b"/m2/a"), 6, 0));

        let orphan = ContentHash::from_data(b"only-backed");
        p.fold_entry(&log1.append_backed(orphan));

        let dups: Vec<_> = p.duplicates().map(|r| r.content).collect();
        assert_eq!(dups, vec![dup]);

        let orphans: Vec<_> = p.orphans().map(|r| r.content).collect();
        assert_eq!(orphans, vec![orphan]);
    }

    #[test]
    fn all_locations_of_includes_live_and_tombstones() {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();
        let c = ContentHash::from_data(b"c");
        p.fold_entry(&log.append_observed(c, PathKey::from_bytes(b"/a"), 1, 0));
        p.fold_entry(&log.append_observed(c, PathKey::from_bytes(b"/b"), 1, 0));
        p.fold_entry(&log.append_vanished(PathKey::from_bytes(b"/a"), c));

        let locs = p.all_locations_of(c);
        assert_eq!(locs.len(), 2);
        let live_count = locs
            .iter()
            .filter(|(_, f)| matches!(f.state, LocationState::Live(_)))
            .count();
        let tombstoned_count = locs
            .iter()
            .filter(|(_, f)| matches!(f.state, LocationState::Tombstoned(_)))
            .count();
        assert_eq!(live_count, 1);
        assert_eq!(tombstoned_count, 1);
    }
}
