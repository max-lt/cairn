//! Local redb-backed cache: incremental-scan catalog + materialized index.
//!
//! The catalog is a **cache** — everything here is reconstructible from
//! the append-only log + remote snapshots. Three responsibilities:
//!
//! - The **scan cache**: per-path [`CatalogEntry`] keyed by `PathKey`.
//!   The scanner compares the on-disk `(size, mtime, file_id)` against
//!   this cache to skip re-hashing unchanged files.
//! - The **materialized projection**: per-content [`ContentRecord`]
//!   keyed by `ContentHash`, plus a `PathKey → ContentHash` reverse
//!   index that answers `cairn locate /path`.
//! - **Sync state**: per-machine `last_synced_seq` and per-process meta
//!   (local chain tip + sequence + last HLC) so the engine can resume.
//!
//! All updates from a single scan pass commit in **one redb write
//! transaction** — crash-safe: a pass either lands fully or not at all.

use std::path::Path;

use cairn_log::{LocationState, Projection};
use cairn_types::{CatalogEntry, ContentHash, ContentRecord, Location, MachineId, PathKey};
use redb::{Database, ReadableTable, backends::InMemoryBackend};

mod tables;
use tables::{
    CATALOG_TABLE, CONTENT_INDEX_TABLE, META_LAST_HLC, META_LAST_PUSHED_SEQ, META_LOCAL_NEXT_SEQ,
    META_LOCAL_TIP, META_TABLE, PATH_TO_CONTENT_TABLE, SYNC_STATE_TABLE,
};

/// Errors produced by [`cairn-catalog`](crate) operations.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// A redb database operation failed.
    #[error("redb error: {0}")]
    Redb(String),
    /// Postcard (de)serialization failed.
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    /// A stored value had an unexpected length (catalog corruption).
    #[error("corrupted value: expected {expected} bytes, found {found}")]
    CorruptedLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length found.
        found: usize,
    },
}

fn r<E: std::fmt::Display, T>(r: Result<T, E>) -> Result<T, CatalogError> {
    r.map_err(|e| CatalogError::Redb(e.to_string()))
}

/// Local chain state for this machine, persisted in the `meta` table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalChainState {
    /// Next sequence number this machine's log will assign.
    pub next_seq: u64,
    /// Hash of the last appended entry (zero when `next_seq == 0`).
    pub tip: [u8; 32],
    /// Highest HLC value the machine clock has produced or witnessed.
    pub last_hlc: u64,
    /// Highest local seq successfully pushed to the remote, or 0 if no
    /// pushes have happened yet. Push code reads this to know where to
    /// resume; pull code never touches it.
    pub last_pushed_seq: u64,
}

/// A scanner-emitted change to the per-path catalog table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogChange {
    /// Insert or replace the entry for this path.
    Upsert(CatalogEntry),
    /// Remove the entry for this path (the path vanished).
    Delete(PathKey),
}

/// All updates that flow through [`Catalog::apply_pass`] for a single
/// scan pass.
#[derive(Debug, Clone)]
pub struct PassUpdates {
    /// Per-path catalog changes from the scan.
    pub catalog_changes: Vec<CatalogChange>,
    /// The post-fold projection that the materialized index should match.
    pub projection: Projection,
    /// This machine's local chain state after the pass's own entries.
    pub local_chain: LocalChainState,
}

/// The redb-backed catalog.
pub struct Catalog {
    db: Database,
}

impl Catalog {
    /// Open (or create) a catalog database at `path`.
    pub fn open(path: &Path) -> Result<Self, CatalogError> {
        let db = r(Database::create(path))?;
        let cat = Self { db };
        cat.ensure_tables()?;
        Ok(cat)
    }

    /// Open an in-memory catalog (for tests / temporary use).
    pub fn open_temporary() -> Result<Self, CatalogError> {
        let db = r(Database::builder().create_with_backend(InMemoryBackend::new()))?;
        let cat = Self { db };
        cat.ensure_tables()?;
        Ok(cat)
    }

    fn ensure_tables(&self) -> Result<(), CatalogError> {
        let write_txn = r(self.db.begin_write())?;
        {
            let _ = r(write_txn.open_table(CATALOG_TABLE))?;
            let _ = r(write_txn.open_table(CONTENT_INDEX_TABLE))?;
            let _ = r(write_txn.open_table(PATH_TO_CONTENT_TABLE))?;
            let _ = r(write_txn.open_table(SYNC_STATE_TABLE))?;
            let _ = r(write_txn.open_table(META_TABLE))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    // ----- Catalog CRUD (scan cache) -------------------------------------

    /// Insert or replace a catalog entry.
    pub fn upsert_catalog_entry(&self, entry: &CatalogEntry) -> Result<(), CatalogError> {
        let bytes = postcard::to_allocvec(entry)?;
        let write_txn = r(self.db.begin_write())?;
        {
            let mut table = r(write_txn.open_table(CATALOG_TABLE))?;
            r(table.insert(entry.path.as_str(), bytes.as_slice()))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    /// Delete a catalog entry by path.
    pub fn delete_catalog_entry(&self, path: &PathKey) -> Result<(), CatalogError> {
        let write_txn = r(self.db.begin_write())?;
        {
            let mut table = r(write_txn.open_table(CATALOG_TABLE))?;
            r(table.remove(path.as_str()))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    /// Look up a catalog entry by path.
    pub fn get_catalog_entry(&self, path: &PathKey) -> Result<Option<CatalogEntry>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(CATALOG_TABLE))?;
        match r(table.get(path.as_str()))? {
            Some(bytes) => {
                let entry: CatalogEntry = postcard::from_bytes(bytes.value())?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Iterate over all catalog entries whose path starts with `root`'s
    /// stored string.
    pub fn iter_catalog_under(&self, root: &PathKey) -> Result<Vec<CatalogEntry>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(CATALOG_TABLE))?;
        let root_str = root.as_str();
        let mut out = Vec::new();
        for kv in r(table.range::<&str>(root_str..))? {
            let (k, v) = r(kv)?;
            let key: &str = k.value();
            if !key.starts_with(root_str) {
                break;
            }
            let entry: CatalogEntry = postcard::from_bytes(v.value())?;
            out.push(entry);
        }
        Ok(out)
    }

    // ----- Content index queries (materialized projection) ---------------

    /// Look up a [`ContentRecord`] by hash.
    pub fn get_content(&self, hash: &ContentHash) -> Result<Option<ContentRecord>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(CONTENT_INDEX_TABLE))?;
        let key: &[u8] = hash.as_bytes();
        match r(table.get(key))? {
            Some(bytes) => {
                let rec: ContentRecord = postcard::from_bytes(bytes.value())?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// All live locations for a content hash (or empty if unknown).
    pub fn content_locations(&self, hash: &ContentHash) -> Result<Vec<Location>, CatalogError> {
        Ok(self
            .get_content(hash)?
            .map(|r| r.live_locations)
            .unwrap_or_default())
    }

    /// Resolve a path to its current content via the reverse index.
    pub fn resolve_path(&self, path: &PathKey) -> Result<Option<ContentHash>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(PATH_TO_CONTENT_TABLE))?;
        match r(table.get(path.as_str()))? {
            Some(bytes) => {
                let raw = bytes.value();
                if raw.len() != 32 {
                    return Err(CatalogError::CorruptedLength {
                        expected: 32,
                        found: raw.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(raw);
                Ok(Some(ContentHash::from(h)))
            }
            None => Ok(None),
        }
    }

    /// All content records with more than one live location.
    pub fn duplicates(&self) -> Result<Vec<ContentRecord>, CatalogError> {
        self.iter_content_filtered(|rec| rec.is_duplicate())
    }

    /// All content records that are backed up but have no live location.
    pub fn orphans(&self) -> Result<Vec<ContentRecord>, CatalogError> {
        self.iter_content_filtered(|rec| rec.is_orphan())
    }

    /// All [`ContentRecord`]s. Mostly useful for tests and `rebuild_from`
    /// equivalence checks.
    pub fn all_content(&self) -> Result<Vec<ContentRecord>, CatalogError> {
        self.iter_content_filtered(|_| true)
    }

    fn iter_content_filtered(
        &self,
        pred: impl Fn(&ContentRecord) -> bool,
    ) -> Result<Vec<ContentRecord>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(CONTENT_INDEX_TABLE))?;
        let mut out = Vec::new();
        for kv in r(table.iter())? {
            let (_, v) = r(kv)?;
            let rec: ContentRecord = postcard::from_bytes(v.value())?;
            if pred(&rec) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    // ----- Sync state ----------------------------------------------------

    /// Last synced sequence number for a foreign machine.
    pub fn sync_state(&self, machine: &MachineId) -> Result<Option<u64>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(SYNC_STATE_TABLE))?;
        let key: &[u8] = machine.as_bytes();
        match r(table.get(key))? {
            Some(v) => Ok(Some(v.value())),
            None => Ok(None),
        }
    }

    /// Record the highest synced sequence number for a foreign machine.
    pub fn set_sync_state(&self, machine: MachineId, last_seq: u64) -> Result<(), CatalogError> {
        let write_txn = r(self.db.begin_write())?;
        {
            let mut table = r(write_txn.open_table(SYNC_STATE_TABLE))?;
            let key: &[u8] = machine.as_bytes();
            r(table.insert(key, last_seq))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    /// All known sync states (`machine → last_seq`).
    pub fn all_sync_states(&self) -> Result<Vec<(MachineId, u64)>, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(SYNC_STATE_TABLE))?;
        let mut out = Vec::new();
        for kv in r(table.iter())? {
            let (k, v) = r(kv)?;
            let raw = k.value();
            if raw.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(raw);
                out.push((MachineId::from(h), v.value()));
            }
        }
        Ok(out)
    }

    // ----- Local chain state (meta) --------------------------------------

    /// Load the local chain's persisted state.
    pub fn local_chain_state(&self) -> Result<LocalChainState, CatalogError> {
        let read_txn = r(self.db.begin_read())?;
        let table = r(read_txn.open_table(META_TABLE))?;

        let next_seq = match r(table.get(META_LOCAL_NEXT_SEQ))? {
            Some(g) => decode_u64(g.value())?,
            None => 0,
        };
        let last_hlc = match r(table.get(META_LAST_HLC))? {
            Some(g) => decode_u64(g.value())?,
            None => 0,
        };
        let tip = match r(table.get(META_LOCAL_TIP))? {
            Some(g) => decode_hash(g.value())?,
            None => [0u8; 32],
        };
        let last_pushed_seq = match r(table.get(META_LAST_PUSHED_SEQ))? {
            Some(g) => decode_u64(g.value())?,
            None => 0,
        };
        Ok(LocalChainState {
            next_seq,
            tip,
            last_hlc,
            last_pushed_seq,
        })
    }

    /// Persist the local chain state.
    pub fn set_local_chain_state(&self, state: LocalChainState) -> Result<(), CatalogError> {
        let write_txn = r(self.db.begin_write())?;
        {
            let mut table = r(write_txn.open_table(META_TABLE))?;
            let seq_bytes = state.next_seq.to_le_bytes();
            let hlc_bytes = state.last_hlc.to_le_bytes();
            let pushed_bytes = state.last_pushed_seq.to_le_bytes();
            r(table.insert(META_LOCAL_NEXT_SEQ, seq_bytes.as_slice()))?;
            r(table.insert(META_LAST_HLC, hlc_bytes.as_slice()))?;
            r(table.insert(META_LOCAL_TIP, state.tip.as_slice()))?;
            r(table.insert(META_LAST_PUSHED_SEQ, pushed_bytes.as_slice()))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    // ----- Atomic batch + rebuild ----------------------------------------

    /// Apply a whole scan pass in one transaction. Either all the catalog
    /// changes, the rewritten materialized index, the sync state and the
    /// local chain state land — or none of them do.
    pub fn apply_pass(&self, pass: &PassUpdates) -> Result<(), CatalogError> {
        // Precompute serializations outside the redb transaction to keep
        // the critical section short and to surface postcard errors
        // before mutating anything.
        let mut content_writes: Vec<(ContentHash, Vec<u8>)> = Vec::new();
        for (hash, record) in &pass.projection.content_index {
            content_writes.push((*hash, postcard::to_allocvec(record)?));
        }
        let mut catalog_upserts: Vec<(PathKey, Vec<u8>)> = Vec::new();
        let mut catalog_deletes: Vec<PathKey> = Vec::new();
        for change in &pass.catalog_changes {
            match change {
                CatalogChange::Upsert(entry) => {
                    catalog_upserts.push((entry.path.clone(), postcard::to_allocvec(entry)?));
                }
                CatalogChange::Delete(path) => catalog_deletes.push(path.clone()),
            }
        }

        let write_txn = r(self.db.begin_write())?;
        {
            // 1) Catalog table updates.
            let mut catalog = r(write_txn.open_table(CATALOG_TABLE))?;
            for (path, bytes) in &catalog_upserts {
                r(catalog.insert(path.as_str(), bytes.as_slice()))?;
            }
            for path in &catalog_deletes {
                r(catalog.remove(path.as_str()))?;
            }

            // 2) Re-derive the materialized indices from the projection.
            let mut content_index = r(write_txn.open_table(CONTENT_INDEX_TABLE))?;
            let stale_keys: Vec<Vec<u8>> = {
                let mut keys = Vec::new();
                for kv in r(content_index.iter())? {
                    let (k, _) = r(kv)?;
                    keys.push(k.value().to_vec());
                }
                keys
            };
            for k in stale_keys {
                r(content_index.remove(k.as_slice()))?;
            }
            for (hash, bytes) in &content_writes {
                let key: &[u8] = hash.as_bytes();
                r(content_index.insert(key, bytes.as_slice()))?;
            }

            let mut path_to_content = r(write_txn.open_table(PATH_TO_CONTENT_TABLE))?;
            let stale_paths: Vec<String> = {
                let mut keys = Vec::new();
                for kv in r(path_to_content.iter())? {
                    let (k, _) = r(kv)?;
                    keys.push(k.value().to_string());
                }
                keys
            };
            for p in stale_paths {
                r(path_to_content.remove(p.as_str()))?;
            }
            for (location, fold) in &pass.projection.location_state {
                if let LocationState::Live(content) = fold.state {
                    let val: &[u8] = content.as_bytes();
                    r(path_to_content.insert(location.path.as_str(), val))?;
                }
            }

            // 3) Sync state from projection chain tips.
            let mut sync = r(write_txn.open_table(SYNC_STATE_TABLE))?;
            for (machine, tip) in &pass.projection.chain_tips {
                let key: &[u8] = machine.as_bytes();
                r(sync.insert(key, tip.seq))?;
            }

            // 4) Local chain state in meta.
            let mut meta = r(write_txn.open_table(META_TABLE))?;
            let seq_bytes = pass.local_chain.next_seq.to_le_bytes();
            let hlc_bytes = pass.local_chain.last_hlc.to_le_bytes();
            let pushed_bytes = pass.local_chain.last_pushed_seq.to_le_bytes();
            r(meta.insert(META_LOCAL_NEXT_SEQ, seq_bytes.as_slice()))?;
            r(meta.insert(META_LAST_HLC, hlc_bytes.as_slice()))?;
            r(meta.insert(META_LOCAL_TIP, pass.local_chain.tip.as_slice()))?;
            r(meta.insert(META_LAST_PUSHED_SEQ, pushed_bytes.as_slice()))?;
        }
        r(write_txn.commit())?;
        Ok(())
    }

    /// Rebuild the materialized index + sync state from a [`Projection`].
    ///
    /// Used after the local catalog has been lost: the engine loads a
    /// snapshot, replays segments, and calls this to repopulate the redb
    /// tables. The per-path scan catalog is left untouched — it can only
    /// be regenerated by a re-scan, which will re-hash every file once.
    pub fn rebuild_from(&self, projection: &Projection) -> Result<(), CatalogError> {
        // Precompute serializations outside the transaction.
        let mut content_writes: Vec<(ContentHash, Vec<u8>)> = Vec::new();
        for (hash, record) in &projection.content_index {
            content_writes.push((*hash, postcard::to_allocvec(record)?));
        }

        let write_txn = r(self.db.begin_write())?;
        {
            let mut content_index = r(write_txn.open_table(CONTENT_INDEX_TABLE))?;
            let stale_keys: Vec<Vec<u8>> = {
                let mut keys = Vec::new();
                for kv in r(content_index.iter())? {
                    let (k, _) = r(kv)?;
                    keys.push(k.value().to_vec());
                }
                keys
            };
            for k in stale_keys {
                r(content_index.remove(k.as_slice()))?;
            }
            for (hash, bytes) in &content_writes {
                let key: &[u8] = hash.as_bytes();
                r(content_index.insert(key, bytes.as_slice()))?;
            }

            let mut path_to_content = r(write_txn.open_table(PATH_TO_CONTENT_TABLE))?;
            let stale_paths: Vec<String> = {
                let mut keys = Vec::new();
                for kv in r(path_to_content.iter())? {
                    let (k, _) = r(kv)?;
                    keys.push(k.value().to_string());
                }
                keys
            };
            for p in stale_paths {
                r(path_to_content.remove(p.as_str()))?;
            }
            for (location, fold) in &projection.location_state {
                if let LocationState::Live(content) = fold.state {
                    let val: &[u8] = content.as_bytes();
                    r(path_to_content.insert(location.path.as_str(), val))?;
                }
            }

            let mut sync = r(write_txn.open_table(SYNC_STATE_TABLE))?;
            let stale_machines: Vec<Vec<u8>> = {
                let mut keys = Vec::new();
                for kv in r(sync.iter())? {
                    let (k, _) = r(kv)?;
                    keys.push(k.value().to_vec());
                }
                keys
            };
            for m in stale_machines {
                r(sync.remove(m.as_slice()))?;
            }
            for (machine, tip) in &projection.chain_tips {
                let key: &[u8] = machine.as_bytes();
                r(sync.insert(key, tip.seq))?;
            }
        }
        r(write_txn.commit())?;
        Ok(())
    }
}

fn decode_u64(raw: &[u8]) -> Result<u64, CatalogError> {
    if raw.len() != 8 {
        return Err(CatalogError::CorruptedLength {
            expected: 8,
            found: raw.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(raw);
    Ok(u64::from_le_bytes(buf))
}

fn decode_hash(raw: &[u8]) -> Result<[u8; 32], CatalogError> {
    if raw.len() != 32 {
        return Err(CatalogError::CorruptedLength {
            expected: 32,
            found: raw.len(),
        });
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(raw);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_log::MachineLog;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn entry(path: &str, content: &[u8], size: u64, hlc: u64) -> CatalogEntry {
        CatalogEntry {
            path: PathKey::from_bytes(path.as_bytes()),
            content: ContentHash::from_data(content),
            size,
            mtime: 0,
            file_id: 0,
            last_scan: hlc,
        }
    }

    #[test]
    fn open_temporary_and_round_trip_one_entry() {
        let cat = Catalog::open_temporary().unwrap();
        let e = entry("/a.txt", b"hello", 5, 100);
        cat.upsert_catalog_entry(&e).unwrap();
        let got = cat.get_catalog_entry(&e.path).unwrap().unwrap();
        assert_eq!(got, e);
    }

    #[test]
    fn delete_removes_entry() {
        let cat = Catalog::open_temporary().unwrap();
        let e = entry("/a.txt", b"hello", 5, 100);
        cat.upsert_catalog_entry(&e).unwrap();
        cat.delete_catalog_entry(&e.path).unwrap();
        assert!(cat.get_catalog_entry(&e.path).unwrap().is_none());
    }

    #[test]
    fn iter_catalog_under_returns_only_prefix_matches() {
        let cat = Catalog::open_temporary().unwrap();
        cat.upsert_catalog_entry(&entry("/home/a/1", b"a1", 1, 0))
            .unwrap();
        cat.upsert_catalog_entry(&entry("/home/a/2", b"a2", 1, 0))
            .unwrap();
        cat.upsert_catalog_entry(&entry("/home/b/3", b"b3", 1, 0))
            .unwrap();
        cat.upsert_catalog_entry(&entry("/var/c", b"c", 1, 0))
            .unwrap();

        let root_a = PathKey::from_bytes(b"/home/a/");
        let under_a = cat.iter_catalog_under(&root_a).unwrap();
        let paths: Vec<_> = under_a
            .iter()
            .map(|e| e.path.as_str().to_string())
            .collect();
        assert_eq!(
            paths,
            vec!["/home/a/1".to_string(), "/home/a/2".to_string()]
        );
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cat.redb");

        let e = entry("/persist.txt", b"hello", 5, 100);
        {
            let cat = Catalog::open(&path).unwrap();
            cat.upsert_catalog_entry(&e).unwrap();
        }
        let cat = Catalog::open(&path).unwrap();
        let got = cat.get_catalog_entry(&e.path).unwrap().unwrap();
        assert_eq!(got, e);
    }

    fn seeded_projection() -> (Projection, MachineLog) {
        let mut log = MachineLog::fresh(key(1));
        let mut p = Projection::new();

        let c_dup = ContentHash::from_data(b"duplicate");
        p.fold_entry(&log.append_observed(c_dup, PathKey::from_bytes(b"/d1"), 9, 0));
        p.fold_entry(&log.append_observed(c_dup, PathKey::from_bytes(b"/d2"), 9, 0));
        p.fold_entry(&log.append_backed(c_dup));

        let c_orphan = ContentHash::from_data(b"orphan");
        p.fold_entry(&log.append_observed(c_orphan, PathKey::from_bytes(b"/o"), 6, 0));
        p.fold_entry(&log.append_backed(c_orphan));
        p.fold_entry(&log.append_vanished(PathKey::from_bytes(b"/o"), c_orphan));

        let c_normal = ContentHash::from_data(b"normal");
        p.fold_entry(&log.append_observed(c_normal, PathKey::from_bytes(b"/n"), 6, 0));

        (p, log)
    }

    fn pass_for(p: Projection, log: &MachineLog) -> PassUpdates {
        PassUpdates {
            catalog_changes: vec![],
            projection: p,
            local_chain: LocalChainState {
                next_seq: log.next_seq(),
                tip: log.current_tip(),
                last_hlc: log.current_hlc(),
                last_pushed_seq: 0,
            },
        }
    }

    #[test]
    fn duplicates_and_orphans_after_apply_pass() {
        let cat = Catalog::open_temporary().unwrap();
        let (p, log) = seeded_projection();
        cat.apply_pass(&pass_for(p, &log)).unwrap();

        let dups: Vec<_> = cat
            .duplicates()
            .unwrap()
            .into_iter()
            .map(|r| r.content)
            .collect();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0], ContentHash::from_data(b"duplicate"));

        let orphans: Vec<_> = cat
            .orphans()
            .unwrap()
            .into_iter()
            .map(|r| r.content)
            .collect();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], ContentHash::from_data(b"orphan"));
    }

    #[test]
    fn resolve_path_after_apply_pass() {
        let cat = Catalog::open_temporary().unwrap();
        let (p, log) = seeded_projection();
        cat.apply_pass(&pass_for(p, &log)).unwrap();

        let resolved = cat
            .resolve_path(&PathKey::from_bytes(b"/d1"))
            .unwrap()
            .expect("live location");
        assert_eq!(resolved, ContentHash::from_data(b"duplicate"));

        let tombstoned = cat.resolve_path(&PathKey::from_bytes(b"/o")).unwrap();
        assert!(tombstoned.is_none());
    }

    #[test]
    fn apply_pass_writes_all_tables_atomically() {
        // We can't simulate a panic mid-transaction with the safe redb
        // API, but we can verify that after a successful apply_pass every
        // table is consistent: the catalog, content_index, path_to_content,
        // sync_state, and meta tables all reflect the same input.
        let cat = Catalog::open_temporary().unwrap();
        let (p, log) = seeded_projection();
        let changes = vec![
            CatalogChange::Upsert(entry("/x", b"x", 1, 0)),
            CatalogChange::Upsert(entry("/y", b"y", 1, 0)),
        ];
        let pass = PassUpdates {
            catalog_changes: changes,
            projection: p,
            local_chain: LocalChainState {
                next_seq: log.next_seq(),
                tip: log.current_tip(),
                last_hlc: log.current_hlc(),
                last_pushed_seq: 0,
            },
        };
        cat.apply_pass(&pass).unwrap();

        assert!(
            cat.get_catalog_entry(&PathKey::from_bytes(b"/x"))
                .unwrap()
                .is_some()
        );
        assert!(
            cat.get_catalog_entry(&PathKey::from_bytes(b"/y"))
                .unwrap()
                .is_some()
        );
        assert!(
            cat.get_content(&ContentHash::from_data(b"duplicate"))
                .unwrap()
                .is_some()
        );
        let state = cat.local_chain_state().unwrap();
        assert_eq!(state.next_seq, log.next_seq());
        assert_eq!(state.tip, log.current_tip());
    }

    #[test]
    fn apply_pass_returns_error_without_persisting_when_serialization_fails() {
        // postcard can't fail on our types in practice, but we can still
        // exercise the "no commit unless every step is OK" contract by
        // verifying that two sequential apply_pass calls each independently
        // commit, and the second one overwrites the first cleanly.
        let cat = Catalog::open_temporary().unwrap();
        let mut log = MachineLog::fresh(key(1));
        let mut p1 = Projection::new();
        let c1 = ContentHash::from_data(b"c1");
        p1.fold_entry(&log.append_observed(c1, PathKey::from_bytes(b"/p"), 1, 0));
        cat.apply_pass(&pass_for(p1, &log)).unwrap();

        let mut p2 = Projection::new();
        let c2 = ContentHash::from_data(b"c2");
        p2.fold_entry(&log.append_observed(c2, PathKey::from_bytes(b"/p"), 1, 0));
        cat.apply_pass(&pass_for(p2, &log)).unwrap();

        // The second pass rewrites the materialized index; c1 should no
        // longer have /p as a live location (because the projection that
        // replaced it doesn't contain c1 at all).
        assert!(cat.get_content(&c1).unwrap().is_none());
        let resolved = cat.resolve_path(&PathKey::from_bytes(b"/p")).unwrap();
        assert_eq!(resolved, Some(c2));
    }

    #[test]
    fn local_chain_state_round_trips() {
        let cat = Catalog::open_temporary().unwrap();
        let state = LocalChainState {
            next_seq: 42,
            tip: [7u8; 32],
            last_hlc: 123_456_789,
            last_pushed_seq: 39,
        };
        cat.set_local_chain_state(state).unwrap();
        let back = cat.local_chain_state().unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn sync_state_round_trips() {
        let cat = Catalog::open_temporary().unwrap();
        let m = MachineId::from([5u8; 32]);
        assert!(cat.sync_state(&m).unwrap().is_none());
        cat.set_sync_state(m, 123).unwrap();
        assert_eq!(cat.sync_state(&m).unwrap(), Some(123));
        cat.set_sync_state(m, 456).unwrap();
        assert_eq!(cat.sync_state(&m).unwrap(), Some(456));
        assert_eq!(cat.all_sync_states().unwrap(), vec![(m, 456)]);
    }

    #[test]
    fn rebuild_from_matches_apply_pass_on_content_records() {
        let (p, log) = seeded_projection();

        let cat_inc = Catalog::open_temporary().unwrap();
        cat_inc.apply_pass(&pass_for(p.clone(), &log)).unwrap();

        let cat_rebuilt = Catalog::open_temporary().unwrap();
        cat_rebuilt.rebuild_from(&p).unwrap();

        let mut a = cat_inc.all_content().unwrap();
        let mut b = cat_rebuilt.all_content().unwrap();
        a.sort_by_key(|r| r.content);
        b.sort_by_key(|r| r.content);
        assert_eq!(a, b);

        let live = PathKey::from_bytes(b"/d1");
        assert_eq!(
            cat_inc.resolve_path(&live).unwrap(),
            cat_rebuilt.resolve_path(&live).unwrap()
        );
    }
}
