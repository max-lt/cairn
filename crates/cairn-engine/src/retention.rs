//! Orphan detection and remote-blob retention policy.
//!
//! **Cairn never deletes user files.** This module concerns deletion only
//! of remote *content blobs* (chunks + manifests), and only after an
//! operator confirms a specific candidate set. The default workflow is
//! always dry-run.
//!
//! Definitions:
//! - **Orphan**: a [`ContentRecord`] with no live locations and
//!   `backed_up == true`. Available via
//!   [`Projection::orphans`](cairn_log::Projection::orphans) and
//!   [`Catalog::orphans`](cairn_catalog::Catalog::orphans); the plan
//!   surfaces these in the `cairn orphans` CLI command.
//! - **Retention candidate**: an orphan whose most-recent `Vanished`
//!   HLC is older than the configured `retain_after_secs`. Reported by
//!   [`dry_run_retention`].

use cairn_log::{LocationState, Projection};
use cairn_remote::Remote;
use cairn_types::ContentHash;

use crate::EngineError;

/// One candidate produced by [`dry_run_retention`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionCandidate {
    /// The content whose remote blobs would be GC'd if confirmed.
    pub content: ContentHash,
    /// HLC of the most recent `Vanished` for any location of this content.
    pub last_vanished_at_hlc: u64,
    /// Time since `last_vanished_at_hlc` in nanoseconds (relative to the
    /// `now_hlc` passed to [`dry_run_retention`]).
    pub age_ns: u64,
}

/// A dry-run retention plan: every orphan whose most recent `Vanished`
/// is at least `retain_after_secs` old, relative to `now_hlc`.
///
/// **No mutations occur.** The result is purely informational; calling
/// [`gc_confirm`] with an explicit slice from this plan is what actually
/// deletes any remote bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Candidates sorted by age (oldest first).
    pub candidates: Vec<RetentionCandidate>,
}

/// Compute the retention plan for the given projection at `now_hlc`.
///
/// HLCs are in nanoseconds since UNIX epoch; `retain_after_secs` is
/// converted to nanoseconds and compared against
/// `now_hlc - last_vanished_at_hlc`.
pub fn dry_run_retention(
    projection: &Projection,
    now_hlc: u64,
    retain_after_secs: u64,
) -> RetentionPlan {
    let threshold_ns = retain_after_secs.saturating_mul(1_000_000_000);
    let mut candidates: Vec<RetentionCandidate> = projection
        .orphans()
        .filter_map(|record| {
            let last_vanished = max_tombstone_hlc(projection, record.content)?;
            let age_ns = now_hlc.saturating_sub(last_vanished);
            if age_ns >= threshold_ns {
                Some(RetentionCandidate {
                    content: record.content,
                    last_vanished_at_hlc: last_vanished,
                    age_ns,
                })
            } else {
                None
            }
        })
        .collect();
    // Oldest first → most-urgent candidates come first when displayed.
    candidates.sort_by(|a, b| b.age_ns.cmp(&a.age_ns));
    RetentionPlan { candidates }
}

/// Delete the **manifest** for each confirmed candidate from the remote.
///
/// Chunks are not deleted by this function: many chunks are shared
/// between manifests (the whole point of CDC dedup) so safely GC'ing a
/// chunk requires proving no live manifest still references it. That
/// reachability sweep can be a follow-up — for v1, deleting the
/// manifest makes the content unreachable through the normal restore
/// path, which is what `cairn gc` promises.
///
/// Returns the list of contents whose manifests were successfully
/// deleted. Manifests that were already missing (`NotFound`) are
/// silently treated as success, since the intent — "this manifest must
/// not exist after this call" — is satisfied.
pub async fn gc_confirm(
    candidates: &[ContentHash],
    remote: &Remote,
) -> Result<Vec<ContentHash>, EngineError> {
    let mut deleted = Vec::with_capacity(candidates.len());
    for &content in candidates {
        match remote.delete_manifest(content).await {
            Ok(()) => deleted.push(content),
            Err(cairn_remote::RemoteError::NotFound { .. }) => deleted.push(content),
            Err(other) => return Err(other.into()),
        }
    }
    Ok(deleted)
}

fn max_tombstone_hlc(projection: &Projection, content: ContentHash) -> Option<u64> {
    projection
        .all_locations_of(content)
        .into_iter()
        .filter_map(|(_, fold)| match fold.state {
            LocationState::Tombstoned(_) => Some(fold.last_hlc),
            LocationState::Live(_) => None,
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_log::MachineLog;
    use cairn_types::PathKey;
    use ed25519_dalek::SigningKey;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn observe_back_vanish(
        log: &mut MachineLog,
        projection: &mut Projection,
        content: ContentHash,
        path: &str,
    ) -> u64 {
        projection.fold_entry(&log.append_observed(
            content,
            PathKey::from_bytes(path.as_bytes()),
            1,
            0,
        ));
        projection.fold_entry(&log.append_backed(content));
        let vanished = log.append_vanished(PathKey::from_bytes(path.as_bytes()), content);
        let hlc = vanished.hlc;
        projection.fold_entry(&vanished);
        hlc
    }

    /// Advance the clock by `secs` so the next `tick` jumps that far ahead.
    fn advance_clock(log: &MachineLog, secs: u64) {
        let target = log.current_hlc() + secs * 1_000_000_000;
        log.clock().witness(target);
    }

    #[test]
    fn dry_run_picks_orphans_older_than_threshold_only() {
        let mut log = MachineLog::fresh(key(1));
        let mut projection = Projection::new();

        let very_old = ContentHash::from_data(b"very-old");
        let recent = ContentHash::from_data(b"recent");
        let live = ContentHash::from_data(b"live");

        let very_old_hlc = observe_back_vanish(&mut log, &mut projection, very_old, "/x");
        // Jump 10 simulated seconds so `recent` looks distinctly fresher.
        advance_clock(&log, 10);
        let recent_hlc = observe_back_vanish(&mut log, &mut projection, recent, "/y");
        projection.fold_entry(&log.append_observed(live, PathKey::from_bytes(b"/z"), 1, 0));
        projection.fold_entry(&log.append_backed(live));

        // "now" = ~1 simulated second after recent vanished.
        let now_hlc = recent_hlc + 1_000_000_000;
        // Threshold = 5 seconds → very_old (≥11s old) qualifies,
        // recent (~1s old) does not, live is filtered out by orphan check.
        let plan = dry_run_retention(&projection, now_hlc, 5);

        let kinds: Vec<_> = plan.candidates.iter().map(|c| c.content).collect();
        assert_eq!(kinds, vec![very_old], "only very_old crosses the threshold");
        assert!(!kinds.contains(&recent));
        assert!(!kinds.contains(&live));
        let _ = very_old_hlc;
    }

    #[test]
    fn dry_run_orders_candidates_oldest_first() {
        let mut log = MachineLog::fresh(key(1));
        let mut projection = Projection::new();

        let old1 = ContentHash::from_data(b"old-1");
        let old2 = ContentHash::from_data(b"old-2");

        observe_back_vanish(&mut log, &mut projection, old1, "/a");
        advance_clock(&log, 5);
        let recent_old_hlc = observe_back_vanish(&mut log, &mut projection, old2, "/b");

        let now_hlc = recent_old_hlc + 10 * 1_000_000_000;
        let plan = dry_run_retention(&projection, now_hlc, 1);
        let kinds: Vec<_> = plan.candidates.iter().map(|c| c.content).collect();
        assert_eq!(kinds.len(), 2);
        assert_eq!(kinds[0], old1, "oldest comes first");
        assert_eq!(kinds[1], old2);
    }

    #[test]
    fn dry_run_excludes_live_records_even_when_old() {
        let mut log = MachineLog::fresh(key(1));
        let mut projection = Projection::new();

        let live = ContentHash::from_data(b"live");
        projection.fold_entry(&log.append_observed(live, PathKey::from_bytes(b"/p"), 1, 0));
        projection.fold_entry(&log.append_backed(live));

        let now_hlc = log.current_hlc() + 100 * 1_000_000_000;
        let plan = dry_run_retention(&projection, now_hlc, 1);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn gc_confirm_deletes_only_the_specified_manifests() {
        rt().block_on(async {
            use bytes::Bytes;
            let remote = Remote::memory();
            let kept = ContentHash::from_data(b"keep this");
            let drop = ContentHash::from_data(b"drop this");
            remote
                .put_manifest_if_absent(kept, Bytes::from_static(b"kept-manifest"))
                .await
                .unwrap();
            remote
                .put_manifest_if_absent(drop, Bytes::from_static(b"drop-manifest"))
                .await
                .unwrap();

            let deleted = gc_confirm(&[drop], &remote).await.unwrap();
            assert_eq!(deleted, vec![drop]);

            // The kept manifest is still present, the dropped one is gone.
            let still_there = remote.get_manifest(kept).await.unwrap();
            assert_eq!(still_there.as_ref(), b"kept-manifest");
            let err = remote.get_manifest(drop).await.unwrap_err();
            assert!(matches!(err, cairn_remote::RemoteError::NotFound { .. }));
        });
    }

    #[test]
    fn gc_confirm_treats_missing_manifest_as_success() {
        rt().block_on(async {
            let remote = Remote::memory();
            let ghost = ContentHash::from_data(b"never uploaded");
            let deleted = gc_confirm(&[ghost], &remote).await.unwrap();
            // The intent — "this manifest must not exist after this call"
            // — is satisfied even though we never had to do any work.
            assert_eq!(deleted, vec![ghost]);
        });
    }
}
