//! Shared types, identifiers, log entries, hybrid clock, and config for Cairn.
//!
//! This crate is the **types-only** foundation of the workspace: it defines
//! the on-the-wire and on-disk shapes used by every other Cairn crate, but
//! does no I/O of its own beyond loading a [`Config`] from a TOML file.
//!
//! - Identifiers: [`ContentHash`], [`ChunkId`], [`MachineId`] — all 32-byte
//!   BLAKE3 newtypes built with a shared macro pattern.
//! - Per-machine event log: [`LogEntry`] + [`Action`], hash-chained and
//!   ed25519-signed. Each machine writes a **single linear chain** — no DAG,
//!   no merges (see `docs/plan.md` § "Relationship to Shoal").
//! - Materialized projection: [`Location`], [`ContentRecord`], [`CatalogEntry`].
//! - File storage recipe: [`Manifest`] + [`ChunkRef`], versioned for safe evolution.
//! - Cross-machine ordering: [`HybridClock`] (HLC).
//! - Portable filesystem paths: [`PathKey`].
//! - Configuration: [`Config`] and its sub-types, TOML-backed.

pub mod clock;
pub mod config;
pub mod ids;
pub mod log;
pub mod manifest;
pub mod path;
pub mod projection;

pub use clock::HybridClock;
pub use config::{
    ChunkingConfig, Config, DEFAULT_CHUNK_AVG_SIZE, EncryptionConfig, MachineConfig, RemoteConfig,
    RetentionConfig,
};
pub use ids::{ChunkId, ContentHash, MachineId};
pub use log::{Action, LogEntry};
pub use manifest::{ChunkRef, MANIFEST_VERSION, Manifest};
pub use path::PathKey;
pub use projection::{CatalogEntry, ContentRecord, Location};

/// Errors produced by `cairn-types` operations: postcard (de)serialization,
/// manifest version checks, TOML parsing, and config I/O.
#[derive(Debug, thiserror::Error)]
pub enum TypesError {
    /// A postcard encode/decode failed.
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    /// A deserialized [`Manifest`] carried a version this build cannot handle.
    #[error("unknown manifest version: {version} (expected {expected})")]
    UnknownManifestVersion {
        /// The version found on the wire / disk.
        version: u8,
        /// The version this build supports.
        expected: u8,
    },
    /// Parsing a TOML config failed.
    #[error("toml deserialize error: {0}")]
    TomlDe(#[from] toml::de::Error),
    /// Serializing a [`Config`] to TOML failed.
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// An I/O error occurred while loading a config file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
