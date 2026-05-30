//! Per-platform filesystem helpers: inode / file index, mtime.
//!
//! `file_id`:
//! - On Unix, the inode number from [`MetadataExt`](std::os::unix::fs::MetadataExt::ino).
//! - On Windows, the file index from
//!   [`MetadataExt::file_index`](std::os::windows::fs::MetadataExt::file_index).
//! - On any other platform, `0` (= "unknown"); in that case the change
//!   detector falls back to `(size, mtime)`.

use std::fs::Metadata;
use std::time::UNIX_EPOCH;

/// Inode (Unix) / file index (Windows) / `0` elsewhere.
#[cfg(unix)]
pub fn file_id(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

/// Inode (Unix) / file index (Windows) / `0` elsewhere.
#[cfg(windows)]
pub fn file_id(metadata: &Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    metadata.file_index().unwrap_or(0)
}

/// Inode (Unix) / file index (Windows) / `0` elsewhere.
#[cfg(not(any(unix, windows)))]
pub fn file_id(_metadata: &Metadata) -> u64 {
    0
}

/// File mtime as nanoseconds since UNIX epoch. Returns 0 if unavailable.
/// Treat the value as **coarse** — some filesystems only have
/// second-granularity mtime.
pub fn mtime_nanos(metadata: &Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
