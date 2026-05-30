//! Push / pull through the remote object store. **No P2P** — machines
//! converge solely by writing under their own `log/<machine>/` prefix
//! and pulling from every other machine's prefix.
//!
//! Conflict semantics: Last-Writer-Wins per `(content, location)` keyed
//! by `(hlc, machine)` — implemented entirely by
//! [`Projection::fold_entry`](cairn_log::Projection::fold_entry). The
//! same set of segments, folded in any order, produces a byte-identical
//! [`Projection`] snapshot (see `cairn-log`'s order-independence tests).

use bytes::Bytes;
use cairn_catalog::Catalog;
use cairn_log::{MachineLog, Projection, Segment};
use cairn_remote::{Remote, SegmentKey};
use cairn_types::{LogEntry, MachineId};
use tracing::{debug, info};

use crate::EngineError;

/// What [`push_pending_as_segment`] reports back to the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushSummary {
    /// Number of entries pushed in this call (0 if there was nothing pending).
    pub entries_pushed: u32,
    /// First sequence number pushed (only meaningful when `entries_pushed > 0`).
    pub seq_start: u64,
    /// Last sequence number pushed (only meaningful when `entries_pushed > 0`).
    pub seq_end: u64,
}

/// What [`pull_from`] reports back to the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullSummary {
    /// Number of segments fetched and folded this call.
    pub segments_pulled: u32,
    /// Number of log entries folded across those segments.
    pub entries_folded: u32,
    /// Highest seq folded for the foreign machine after this call.
    pub new_chain_tip_seq: u64,
}

/// Push a contiguous range of `entries` to the remote as one segment.
///
/// `entries` must come from `log`'s own chain (they will be validated as a
/// single-machine, contiguous range by [`Segment::try_from_entries`]).
/// After a successful upload the catalog's `last_pushed_seq` is bumped to
/// the segment's `seq_end`.
pub async fn push_pending_as_segment(
    log: &MachineLog,
    catalog: &Catalog,
    remote: &Remote,
    entries: Vec<LogEntry>,
) -> Result<PushSummary, EngineError> {
    if entries.is_empty() {
        return Ok(PushSummary::default());
    }
    let segment = Segment::try_from_entries(entries)?;
    if segment.machine != log.machine() {
        return Err(EngineError::PushForeignChain {
            found: format!("{}", segment.machine),
        });
    }

    let bytes = segment.to_bytes()?;
    let _key = remote
        .put_segment(segment.machine, segment.seq_start, Bytes::from(bytes))
        .await?;

    let mut state = catalog.local_chain_state()?;
    state.last_pushed_seq = segment.seq_end;
    catalog.set_local_chain_state(state)?;

    info!(
        seq_start = segment.seq_start,
        seq_end = segment.seq_end,
        "pushed segment"
    );
    Ok(PushSummary {
        entries_pushed: segment.entries.len() as u32,
        seq_start: segment.seq_start,
        seq_end: segment.seq_end,
    })
}

/// Pull every new segment for one foreign machine and fold the entries
/// into `projection`. Updates `catalog.sync_state[machine]` to the
/// highest folded seq when at least one segment is pulled.
///
/// `local_log` is borrowed only to witness foreign HLCs (so our own
/// clock stays advanced past anything we have seen). Verifying chain
/// continuity uses `projection.chain_tips[machine]` as the known tip.
pub async fn pull_from(
    foreign: MachineId,
    local_log: &MachineLog,
    catalog: &Catalog,
    remote: &Remote,
    projection: &mut Projection,
) -> Result<PullSummary, EngineError> {
    if foreign == local_log.machine() {
        debug!("pull_from: skipping our own machine");
        return Ok(PullSummary::default());
    }

    let last_synced = catalog.sync_state(&foreign)?.unwrap_or(0);
    let all = remote.list_segments(foreign).await?;
    let to_pull: Vec<SegmentKey> = all
        .into_iter()
        .filter(|k| {
            // First-ever pull: include the very first segment (seq_start = 0).
            if last_synced == 0 {
                return true;
            }
            // Otherwise pull only those that bring strictly new entries.
            k.seq_start > last_synced
        })
        .collect();

    let mut summary = PullSummary {
        new_chain_tip_seq: last_synced,
        ..PullSummary::default()
    };
    if to_pull.is_empty() {
        return Ok(summary);
    }

    for seg_key in to_pull {
        let bytes = remote.get_segment(&seg_key).await?;
        let segment = Segment::from_bytes(&bytes)?;
        let known_tip = projection
            .chain_tips
            .get(&foreign)
            .filter(|t| t.seq > 0 || t.hash != [0u8; 32])
            .map(|t| t.hash);
        local_log.receive_segment(&segment, known_tip)?;
        let entries_count = segment.entries.len() as u32;
        let seq_end = segment.seq_end;
        projection.fold_segment(&segment);
        summary.segments_pulled += 1;
        summary.entries_folded += entries_count;
        summary.new_chain_tip_seq = seq_end;
    }

    catalog.set_sync_state(foreign, summary.new_chain_tip_seq)?;
    info!(
        machine = %foreign,
        segments = summary.segments_pulled,
        entries = summary.entries_folded,
        new_tip_seq = summary.new_chain_tip_seq,
        "pulled segments"
    );
    Ok(summary)
}

/// Discover every machine that has ever pushed a segment to the remote.
pub async fn list_remote_machines(remote: &Remote) -> Result<Vec<MachineId>, EngineError> {
    Ok(remote.list_machines().await?)
}
