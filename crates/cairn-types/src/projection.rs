//! Materialized projection types: [`Location`], [`ContentRecord`], [`CatalogEntry`].
//!
//! These are the *queryable* shapes that [`cairn-log`](../../cairn_log/index.html)
//! folds a stream of [`Action`](crate::Action)s into, and that
//! [`cairn-catalog`](../../cairn_catalog/index.html) persists in redb. The
//! catalog is a cache: the canonical truth lives in the log + remote
//! snapshots, and the projection can be rebuilt from them at any time.

use serde::{Deserialize, Serialize};

use crate::ids::{ContentHash, MachineId};
use crate::path::PathKey;

/// A specific location where a content was observed: `(machine, path)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    /// The machine that observed the content at this path.
    pub machine: MachineId,
    /// The path on that machine.
    pub path: PathKey,
}

/// The materialized record for a single [`ContentHash`] in the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRecord {
    /// blake3 of the file bytes.
    pub content: ContentHash,
    /// Size of the file.
    pub size: u64,
    /// All machine+path pairs where this content currently exists (post-fold).
    /// An [`Action::Vanished`](crate::Action::Vanished) removes the matching
    /// entry; an [`Action::Observed`](crate::Action::Observed) adds or
    /// refreshes it.
    pub live_locations: Vec<Location>,
    /// `true` once the content's bytes are safely stored in the remote object store.
    pub backed_up: bool,
    /// HLC of the first observation of this content.
    pub first_seen: u64,
    /// HLC of the most recent observation of this content.
    pub last_seen: u64,
}

impl ContentRecord {
    /// `true` when this content has no live locations but is backed up — a
    /// candidate for remote retention review (never auto-deleted).
    pub fn is_orphan(&self) -> bool {
        self.backed_up && self.live_locations.is_empty()
    }

    /// `true` when this content is currently visible at more than one
    /// location — the input for the duplicate-detection query.
    pub fn is_duplicate(&self) -> bool {
        self.live_locations.len() > 1
    }
}

/// Per-path entry in the local catalog cache, used to make re-scans cheap.
///
/// During a scan, the scanner compares the on-disk `stat` against the
/// stored `CatalogEntry`: matching `(size, mtime[, file_id])` lets it reuse
/// the stored [`Self::content`] without re-hashing the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// The path this entry caches.
    pub path: PathKey,
    /// The content hash from the most recent scan that read this file.
    pub content: ContentHash,
    /// File size in bytes at the time of the last scan.
    pub size: u64,
    /// File mtime in nanoseconds since UNIX epoch.
    pub mtime: u64,
    /// Inode (Unix) or file index (Windows); `0` when unavailable. Used to
    /// detect hardlinks and to bolster `(size, mtime)` change detection.
    pub file_id: u64,
    /// HLC of the scan pass that last touched this entry.
    pub last_scan: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_location() -> Location {
        Location {
            machine: MachineId::from_data(b"m1"),
            path: PathKey::from_bytes(b"/data/a.txt"),
        }
    }

    fn other_location() -> Location {
        Location {
            machine: MachineId::from_data(b"m2"),
            path: PathKey::from_bytes(b"/data/b.txt"),
        }
    }

    #[test]
    fn location_postcard_roundtrip() {
        let l = sample_location();
        let bytes = postcard::to_allocvec(&l).unwrap();
        let decoded: Location = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(l, decoded);
    }

    #[test]
    fn content_record_postcard_roundtrip() {
        let r = ContentRecord {
            content: ContentHash::from_data(b"file"),
            size: 4096,
            live_locations: vec![sample_location(), other_location()],
            backed_up: true,
            first_seen: 100,
            last_seen: 200,
        };
        let bytes = postcard::to_allocvec(&r).unwrap();
        let decoded: ContentRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn orphan_iff_no_locations_and_backed_up() {
        let mut r = ContentRecord {
            content: ContentHash::from_data(b"x"),
            size: 1,
            live_locations: vec![],
            backed_up: true,
            first_seen: 0,
            last_seen: 0,
        };
        assert!(r.is_orphan());

        r.backed_up = false;
        assert!(!r.is_orphan(), "not orphan if not backed up");

        r.backed_up = true;
        r.live_locations.push(sample_location());
        assert!(!r.is_orphan(), "not orphan if still has a live location");
    }

    #[test]
    fn duplicate_when_more_than_one_live_location() {
        let r = ContentRecord {
            content: ContentHash::from_data(b"x"),
            size: 1,
            live_locations: vec![sample_location(), other_location()],
            backed_up: false,
            first_seen: 0,
            last_seen: 0,
        };
        assert!(r.is_duplicate());
    }

    #[test]
    fn not_duplicate_with_single_or_zero_locations() {
        let mut r = ContentRecord {
            content: ContentHash::from_data(b"x"),
            size: 1,
            live_locations: vec![sample_location()],
            backed_up: false,
            first_seen: 0,
            last_seen: 0,
        };
        assert!(!r.is_duplicate());
        r.live_locations.clear();
        assert!(!r.is_duplicate());
    }

    #[test]
    fn catalog_entry_postcard_roundtrip() {
        let e = CatalogEntry {
            path: PathKey::from_bytes(b"/data/a.txt"),
            content: ContentHash::from_data(b"file"),
            size: 4096,
            mtime: 1_700_000_000_000_000_000,
            file_id: 12345,
            last_scan: 100,
        };
        let bytes = postcard::to_allocvec(&e).unwrap();
        let decoded: CatalogEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }
}
