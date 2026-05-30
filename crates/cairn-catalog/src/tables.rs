//! redb table definitions and meta-key constants.

use redb::TableDefinition;

/// `PathKey.as_str()` → postcard([`CatalogEntry`](cairn_types::CatalogEntry)).
pub(crate) const CATALOG_TABLE: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("catalog");

/// `ContentHash.as_bytes()` → postcard([`ContentRecord`](cairn_types::ContentRecord)).
pub(crate) const CONTENT_INDEX_TABLE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("content_index");

/// `PathKey.as_str()` → 32-byte [`ContentHash`](cairn_types::ContentHash).
pub(crate) const PATH_TO_CONTENT_TABLE: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("path_to_content");

/// `MachineId.as_bytes()` → `last_synced_seq: u64`.
pub(crate) const SYNC_STATE_TABLE: TableDefinition<'static, &'static [u8], u64> =
    TableDefinition::new("sync_state");

/// `&str` meta-key → raw bytes (interpretation depends on key).
pub(crate) const META_TABLE: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("meta");

/// Meta key for this machine's next-sequence number (u64 LE).
pub(crate) const META_LOCAL_NEXT_SEQ: &str = "local.next_seq";
/// Meta key for this machine's most recent chain tip hash (32 bytes).
pub(crate) const META_LOCAL_TIP: &str = "local.tip";
/// Meta key for the highest HLC the machine clock has produced or
/// witnessed (u64 LE).
pub(crate) const META_LAST_HLC: &str = "local.last_hlc";
/// Meta key for the highest seq number this machine has successfully
/// pushed to the remote (u64 LE). 0 means "no pushes yet".
pub(crate) const META_LAST_PUSHED_SEQ: &str = "local.last_pushed_seq";
