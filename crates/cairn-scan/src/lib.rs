//! Filesystem walker, incremental hashing, and change detection.
//!
//! [`Scanner::scan_root`] walks a configured root with the [`ignore`]
//! crate's parallel walker (which provides gitignore-style filtering,
//! single-filesystem traversal, and explicit symlink handling), then
//! BLAKE3-hashes every file whose `(size, mtime, file_id)` does not
//! match its previous [`CatalogEntry`]. Unchanged files reuse the
//! cached `ContentHash` without re-reading their bytes — this is what
//! makes re-scans cheap.
//!
//! The scanner emits an ordered stream of [`ScanEvent`]s: `Observed` for
//! every changed or new file, `Vanished` for every previously-cached
//! path that was not seen this pass, and a single `PassCompleted` at
//! the end with the pass's totals. The engine layer turns these into
//! [`LogEntry`](cairn_types::LogEntry)s and catalog mutations.
//!
//! Per-file read or permission errors are logged at `warn!` and silently
//! skipped — they are **never** turned into a `Vanished` event (a read
//! failure does not mean a file disappeared).

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cairn_types::{CatalogEntry, ContentHash, PathKey};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tracing::warn;

pub mod platform;

/// Errors produced when configuring or running a scan.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// A configured exclude pattern was invalid.
    #[error("invalid exclude pattern {pattern:?}: {source}")]
    InvalidExclude {
        /// The pattern that failed to parse.
        pattern: String,
        /// The underlying ignore-crate error.
        source: ignore::Error,
    },
}

/// Tuning knobs for [`Scanner`].
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// `.gitignore`-style glob patterns to exclude. Each pattern is added
    /// as an ignore rule (NOT a whitelist) — files / dirs matching any of
    /// them are skipped without descent.
    pub excludes: Vec<String>,
    /// Follow symlinks during the walk. Defaults to `false`.
    pub follow_symlinks: bool,
    /// Cross filesystem boundaries during the walk. Defaults to `false`.
    pub cross_mounts: bool,
    /// Respect `.gitignore`, `.ignore`, and global ignore files found in
    /// the tree. Defaults to `true` — backed-up git repositories then
    /// skip build artifacts automatically.
    pub respect_gitignore: bool,
    /// Walker thread count. `0` (default) means "auto".
    pub walker_threads: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            excludes: vec![],
            follow_symlinks: false,
            cross_mounts: false,
            respect_gitignore: true,
            walker_threads: 0,
        }
    }
}

/// The un-logged precursor events that a scan pass emits.
///
/// `Observed` is omitted for files whose cached `(size, mtime, file_id)`
/// matched the previous catalog entry; only new or changed files appear.
/// `Vanished` is emitted exactly once per path that the previous catalog
/// knew about but the current walk did not see. `PassCompleted` is the
/// last event and reports the totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    /// A new or changed file. Carries everything the catalog and the log
    /// will need to record it: the file's [`ContentHash`], its
    /// [`PathKey`], byte size, mtime in nanoseconds, and the platform
    /// `file_id` (inode / file index / 0).
    Observed {
        /// blake3 of the file's bytes (computed this pass, or reused from
        /// the cache when stat matched).
        content: ContentHash,
        /// Path on this machine.
        path: PathKey,
        /// File size in bytes.
        size: u64,
        /// File mtime in nanoseconds since UNIX epoch.
        mtime: u64,
        /// Platform file identifier (inode on Unix, file index on
        /// Windows, 0 elsewhere).
        file_id: u64,
    },
    /// A previously-cached path that the current walk did not see.
    /// Tombstone — the engine never deletes anything in response.
    Vanished {
        /// Path that vanished.
        path: PathKey,
        /// Last [`ContentHash`] known for this path.
        last_content: ContentHash,
    },
    /// End of pass over a single root, with totals.
    PassCompleted {
        /// Path of the scanned root.
        root: PathKey,
        /// Total regular files seen during this pass.
        files_seen: u64,
        /// Total bytes seen during this pass.
        bytes_seen: u64,
    },
}

/// A scanner.
pub struct Scanner {
    config: ScanConfig,
}

impl Scanner {
    /// Build a scanner from a [`ScanConfig`].
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Scan a single root, returning the un-logged event stream.
    ///
    /// `prev_catalog` is the per-path cache loaded from the catalog,
    /// scoped to this root by the caller (see
    /// [`cairn-catalog`](../../cairn_catalog/index.html)'s
    /// `iter_catalog_under`).
    pub fn scan_root(
        &self,
        root: &Path,
        prev_catalog: &HashMap<PathKey, CatalogEntry>,
    ) -> Result<Vec<ScanEvent>, ScanError> {
        // Phase 1 — walk + stat. Per-entry decisions:
        //   - skip-if-unchanged (matched stat → cached ContentHash)
        //   - hash-needed (new or changed)
        //   - hardlink-of-already-seen (skip re-hash, reuse content)
        let candidates = self.walk_and_collect(root)?;

        let mut seen_paths: HashSet<PathKey> = HashSet::new();
        let mut events: Vec<ScanEvent> = Vec::new();
        let mut to_hash: Vec<HashTask> = Vec::new();
        let mut hardlink_index: HashMap<u64, ContentHash> = HashMap::new();
        let mut files_seen: u64 = 0;
        let mut bytes_seen: u64 = 0;

        for c in candidates {
            seen_paths.insert(c.path_key.clone());
            files_seen += 1;
            bytes_seen += c.size;

            // Cache hit (size + mtime [+ file_id]) → reuse content.
            if let Some(prev) = prev_catalog.get(&c.path_key)
                && stat_matches(prev, &c)
            {
                continue;
            }

            // Hardlink to a file we've already decided to hash → reuse.
            if c.file_id != 0
                && let Some(content) = hardlink_index.get(&c.file_id).copied()
            {
                events.push(ScanEvent::Observed {
                    content,
                    path: c.path_key,
                    size: c.size,
                    mtime: c.mtime,
                    file_id: c.file_id,
                });
                continue;
            }

            to_hash.push(c);
        }

        // Phase 2 — hash in parallel via rayon.
        let hashed: Vec<HashedTask> = to_hash
            .into_par_iter()
            .filter_map(|task| match hash_file(&task.fs_path) {
                Ok(content) => Some(HashedTask { task, content }),
                Err(err) => {
                    warn!(
                        path = %task.fs_path.display(),
                        error = %err,
                        "skipping unreadable file"
                    );
                    None
                }
            })
            .collect();

        // Phase 3 — emit Observed events; record hardlinks for the index.
        for HashedTask { task, content } in hashed {
            if task.file_id != 0 {
                hardlink_index.entry(task.file_id).or_insert(content);
            }
            events.push(ScanEvent::Observed {
                content,
                path: task.path_key,
                size: task.size,
                mtime: task.mtime,
                file_id: task.file_id,
            });
        }

        // Phase 4 — Vanished for previously-cached paths under this root
        // that the walk did not see. Only paths whose stored PathKey is
        // a prefix-match under the root are eligible — the caller already
        // scopes prev_catalog to the root, so any entry not in seen_paths
        // is genuinely gone.
        for (path, prev) in prev_catalog {
            if seen_paths.contains(path) {
                continue;
            }
            events.push(ScanEvent::Vanished {
                path: path.clone(),
                last_content: prev.content,
            });
        }

        events.push(ScanEvent::PassCompleted {
            root: PathKey::from_path(root),
            files_seen,
            bytes_seen,
        });

        Ok(events)
    }

    fn walk_and_collect(&self, root: &Path) -> Result<Vec<HashTask>, ScanError> {
        let mut builder = WalkBuilder::new(root);
        builder
            .follow_links(self.config.follow_symlinks)
            .same_file_system(!self.config.cross_mounts)
            .git_ignore(self.config.respect_gitignore)
            .git_exclude(self.config.respect_gitignore)
            .ignore(self.config.respect_gitignore)
            .hidden(false); // include dotfiles; only configured excludes drop them
        if self.config.walker_threads > 0 {
            builder.threads(self.config.walker_threads);
        }
        if !self.config.excludes.is_empty() {
            let mut overrides = OverrideBuilder::new(root);
            for pattern in &self.config.excludes {
                let inverted = format!("!{pattern}");
                overrides
                    .add(&inverted)
                    .map_err(|source| ScanError::InvalidExclude {
                        pattern: pattern.clone(),
                        source,
                    })?;
            }
            let override_matcher =
                overrides
                    .build()
                    .map_err(|source| ScanError::InvalidExclude {
                        pattern: "<built overrides>".to_string(),
                        source,
                    })?;
            builder.overrides(override_matcher);
        }

        let walker = builder.build_parallel();
        let collected: Mutex<Vec<HashTask>> = Mutex::new(Vec::new());

        walker.run(|| {
            Box::new(|res| {
                let entry = match res {
                    Ok(e) => e,
                    Err(err) => {
                        warn!(error = %err, "walk error");
                        return ignore::WalkState::Continue;
                    }
                };
                let file_type = match entry.file_type() {
                    Some(ft) => ft,
                    None => return ignore::WalkState::Continue,
                };
                if !file_type.is_file() {
                    return ignore::WalkState::Continue;
                }
                let fs_path = entry.path().to_path_buf();
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        warn!(path = %fs_path.display(), error = %err, "stat failed; skipping");
                        return ignore::WalkState::Continue;
                    }
                };
                let task = HashTask {
                    path_key: PathKey::from_path(&fs_path),
                    fs_path,
                    size: metadata.len(),
                    mtime: platform::mtime_nanos(&metadata),
                    file_id: platform::file_id(&metadata),
                };
                collected.lock().unwrap().push(task);
                ignore::WalkState::Continue
            })
        });

        Ok(collected.into_inner().unwrap())
    }
}

#[derive(Debug, Clone)]
struct HashTask {
    path_key: PathKey,
    fs_path: PathBuf,
    size: u64,
    mtime: u64,
    file_id: u64,
}

#[derive(Debug, Clone)]
struct HashedTask {
    task: HashTask,
    content: ContentHash,
}

fn stat_matches(prev: &CatalogEntry, candidate: &HashTask) -> bool {
    // file_id must match when both sides have one; otherwise fall back
    // to (size, mtime) — file_id == 0 means "unknown" on this platform.
    if prev.size != candidate.size {
        return false;
    }
    if prev.mtime != candidate.mtime {
        return false;
    }
    if prev.file_id != 0 && candidate.file_id != 0 && prev.file_id != candidate.file_id {
        return false;
    }
    true
}

fn hash_file(path: &Path) -> std::io::Result<ContentHash> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ContentHash::from(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn prev_from(events: &[ScanEvent], root: &Path) -> HashMap<PathKey, CatalogEntry> {
        let mut out = HashMap::new();
        for e in events {
            if let ScanEvent::Observed {
                content,
                path,
                size,
                mtime,
                file_id,
            } = e
            {
                let _ = root;
                out.insert(
                    path.clone(),
                    CatalogEntry {
                        path: path.clone(),
                        content: *content,
                        size: *size,
                        mtime: *mtime,
                        file_id: *file_id,
                        last_scan: 0,
                    },
                );
            }
        }
        out
    }

    fn count_observed(events: &[ScanEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Observed { .. }))
            .count()
    }

    fn count_vanished(events: &[ScanEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Vanished { .. }))
            .count()
    }

    fn scanner_default() -> Scanner {
        // Disable gitignore-style filtering in tests so dotfiles & friends
        // are predictable regardless of what's in the test dir.
        Scanner::new(ScanConfig {
            respect_gitignore: false,
            ..ScanConfig::default()
        })
    }

    #[test]
    fn fresh_scan_emits_observed_per_file_plus_one_pass_completed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"beta").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("c.txt"), b"gamma").unwrap();

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();

        assert_eq!(count_observed(&events), 3);
        assert_eq!(count_vanished(&events), 0);
        assert!(matches!(
            events.last(),
            Some(ScanEvent::PassCompleted { .. })
        ));
    }

    #[test]
    fn rescan_with_no_changes_emits_zero_observed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"beta").unwrap();

        let scanner = scanner_default();
        let first = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let prev = prev_from(&first, dir.path());
        let second = scanner.scan_root(dir.path(), &prev).unwrap();

        assert_eq!(count_observed(&second), 0);
        assert_eq!(count_vanished(&second), 0);
        assert!(matches!(
            second.last(),
            Some(ScanEvent::PassCompleted { .. })
        ));
    }

    #[test]
    fn modify_one_file_yields_one_observed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"beta").unwrap();

        let scanner = scanner_default();
        let first = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let prev = prev_from(&first, dir.path());

        // Bump mtime visibly + change content of a.txt.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.path().join("a.txt"), b"alpha2").unwrap();

        let second = scanner.scan_root(dir.path(), &prev).unwrap();
        let observed: Vec<_> = second
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { path, .. } => Some(path.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(observed.len(), 1);
        assert!(observed[0].ends_with("a.txt"));
        assert_eq!(count_vanished(&second), 0);
    }

    #[test]
    fn delete_one_file_yields_exactly_one_vanished() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::write(dir.path().join("b.txt"), b"beta").unwrap();

        let scanner = scanner_default();
        let first = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let prev = prev_from(&first, dir.path());

        fs::remove_file(dir.path().join("b.txt")).unwrap();

        let second = scanner.scan_root(dir.path(), &prev).unwrap();
        assert_eq!(count_observed(&second), 0);
        assert_eq!(count_vanished(&second), 1);
        if let ScanEvent::Vanished { path, .. } = second
            .iter()
            .find(|e| matches!(e, ScanEvent::Vanished { .. }))
            .unwrap()
        {
            assert!(path.as_str().ends_with("b.txt"));
        }
    }

    #[test]
    fn two_byte_identical_files_share_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("twin1.txt"), b"twin").unwrap();
        fs::write(dir.path().join("twin2.txt"), b"twin").unwrap();

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();

        let contents: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { content, .. } => Some(*content),
                _ => None,
            })
            .collect();
        assert_eq!(contents.len(), 2);
        assert_eq!(contents[0], contents[1]);
    }

    #[test]
    fn two_empty_files_share_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        fs::File::create(dir.path().join("e1")).unwrap();
        fs::File::create(dir.path().join("e2")).unwrap();

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();

        let contents: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { content, .. } => Some(*content),
                _ => None,
            })
            .collect();
        assert_eq!(contents.len(), 2);
        assert_eq!(contents[0], contents[1]);
        // Empty file hash is the blake3 of an empty input.
        assert_eq!(contents[0], ContentHash::from_data(b""));
    }

    #[test]
    #[cfg(unix)]
    fn hardlinked_pair_shares_content_one_hash_two_locations() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let link = dir.path().join("link.txt");
        fs::write(&src, b"shared via hardlink").unwrap();
        std::fs::hard_link(&src, &link).unwrap();

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();

        let observed: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed {
                    content,
                    path,
                    file_id,
                    ..
                } => Some((*content, path.clone(), *file_id)),
                _ => None,
            })
            .collect();
        assert_eq!(observed.len(), 2);
        // Both observations share the same content hash and file_id.
        assert_eq!(observed[0].0, observed[1].0);
        if observed[0].2 != 0 {
            assert_eq!(observed[0].2, observed[1].2);
        }
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_file_is_skipped_with_no_vanished() {
        use std::os::unix::fs::PermissionsExt;

        // chmod 000 doesn't block root, so skip this test when running as
        // root (the typical CI container case).
        // SAFETY: getuid() is read-only.
        let uid = unsafe { libc_getuid() };
        if uid == 0 {
            eprintln!("skipping unreadable_file_is_skipped: running as root");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        fs::write(&p, b"top secret").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();

        let scanner = scanner_default();
        let result = scanner.scan_root(dir.path(), &HashMap::new());
        // Restore permissions before tempdir drop so cleanup succeeds.
        let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o644));
        let events = result.unwrap();

        // The unreadable file produced no Observed but also no Vanished
        // (it was never in our catalog).
        assert_eq!(count_observed(&events), 0);
        assert_eq!(count_vanished(&events), 0);
    }

    #[cfg(unix)]
    unsafe extern "C" {
        fn getuid() -> u32;
    }

    #[cfg(unix)]
    unsafe fn libc_getuid() -> u32 {
        unsafe { getuid() }
    }

    #[test]
    fn excluded_directory_is_not_descended() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
        let excluded_dir = dir.path().join("node_modules");
        fs::create_dir(&excluded_dir).unwrap();
        fs::write(excluded_dir.join("garbage.js"), b"garbage").unwrap();

        let scanner = Scanner::new(ScanConfig {
            respect_gitignore: false,
            excludes: vec!["node_modules".to_string()],
            ..ScanConfig::default()
        });
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();

        let observed_paths: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { path, .. } => Some(path.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(observed_paths.len(), 1);
        assert!(observed_paths[0].ends_with("keep.txt"));
        assert!(!observed_paths[0].contains("node_modules"));
    }

    #[test]
    fn symlinks_are_not_followed_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        fs::write(target_dir.path().join("outside.txt"), b"outside").unwrap();
        fs::write(dir.path().join("inside.txt"), b"inside").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(target_dir.path(), dir.path().join("link")).unwrap();
        #[cfg(not(unix))]
        let _ = target_dir;

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let observed_paths: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { path, .. } => Some(path.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert!(observed_paths.iter().any(|p| p.ends_with("inside.txt")));
        assert!(!observed_paths.iter().any(|p| p.contains("outside.txt")));
    }

    #[test]
    fn pass_completed_reports_totals() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), b"123").unwrap();
        fs::write(dir.path().join("b"), b"4567").unwrap();

        let scanner = scanner_default();
        let events = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let pass = events
            .iter()
            .find_map(|e| match e {
                ScanEvent::PassCompleted {
                    files_seen,
                    bytes_seen,
                    ..
                } => Some((*files_seen, *bytes_seen)),
                _ => None,
            })
            .unwrap();
        assert_eq!(pass.0, 2);
        assert_eq!(pass.1, 3 + 4);
    }

    #[test]
    fn add_a_file_yields_one_observed_for_it() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();

        let scanner = scanner_default();
        let first = scanner.scan_root(dir.path(), &HashMap::new()).unwrap();
        let prev = prev_from(&first, dir.path());

        let new_file = dir.path().join("new.txt");
        let mut f = fs::File::create(&new_file).unwrap();
        f.write_all(b"new content").unwrap();
        drop(f);

        let second = scanner.scan_root(dir.path(), &prev).unwrap();
        let observed_paths: Vec<_> = second
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Observed { path, .. } => Some(path.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(observed_paths.len(), 1);
        assert!(observed_paths[0].ends_with("new.txt"));
        assert_eq!(count_vanished(&second), 0);
    }
}
