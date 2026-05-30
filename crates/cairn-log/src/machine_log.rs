//! [`MachineLog`]: this machine's local writer + chain state.

use cairn_types::{Action, ContentHash, HybridClock, LogEntry, MachineId, PathKey};
use ed25519_dalek::SigningKey;

use crate::LogError;
use crate::segment::Segment;

/// This machine's local log writer.
///
/// Owns the ed25519 signing key, a [`HybridClock`], and the next sequence
/// number + previous-entry hash. `append` ticks the clock, signs the new
/// entry, and advances both `seq` and the tip.
///
/// Persistence of `(seq, prev, current_hlc)` is the responsibility of the
/// catalog layer (M4); `MachineLog` exposes accessors and a `from_state`
/// constructor so the catalog can restore the writer cleanly after a
/// restart.
pub struct MachineLog {
    machine: MachineId,
    signing_key: SigningKey,
    clock: HybridClock,
    seq: u64,
    prev: [u8; 32],
}

impl MachineLog {
    /// Create a fresh log from a signing key. The next sequence number is
    /// 0, the previous-entry hash is zero, and the clock is initialised
    /// from wall time.
    pub fn fresh(signing_key: SigningKey) -> Self {
        let machine = MachineId::from(signing_key.verifying_key().to_bytes());
        Self {
            machine,
            signing_key,
            clock: HybridClock::new(),
            seq: 0,
            prev: [0u8; 32],
        }
    }

    /// Restore a log from persisted state.
    ///
    /// - `next_seq` is the seq number that the *next* appended entry will receive.
    /// - `prev` is the hash of the last appended entry (zero if `next_seq == 0`).
    /// - `last_hlc` seeds the clock so subsequent ticks strictly exceed it.
    pub fn from_state(
        signing_key: SigningKey,
        next_seq: u64,
        prev: [u8; 32],
        last_hlc: u64,
    ) -> Self {
        let machine = MachineId::from(signing_key.verifying_key().to_bytes());
        Self {
            machine,
            signing_key,
            clock: HybridClock::from_value(last_hlc),
            seq: next_seq,
            prev,
        }
    }

    /// This machine's identifier (= bytes of the ed25519 public key).
    pub fn machine(&self) -> MachineId {
        self.machine
    }

    /// Sequence number that the next appended entry will receive.
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Hash of the last appended entry; the next `append` will use this as `prev`.
    pub fn current_tip(&self) -> [u8; 32] {
        self.prev
    }

    /// Current HLC value (does not advance the clock).
    pub fn current_hlc(&self) -> u64 {
        self.clock.current()
    }

    /// Borrow the underlying clock — useful when other components need to
    /// witness foreign HLCs (e.g. after fetching a segment).
    pub fn clock(&self) -> &HybridClock {
        &self.clock
    }

    /// Append a new entry: tick the HLC, sign, advance tip and seq.
    pub fn append(&mut self, action: Action) -> LogEntry {
        let hlc = self.clock.tick();
        let entry = LogEntry::new_signed(
            self.seq,
            hlc,
            self.machine,
            action,
            self.prev,
            &self.signing_key,
        );
        self.prev = entry.hash;
        self.seq += 1;
        entry
    }

    /// Append an [`Action::Observed`].
    pub fn append_observed(
        &mut self,
        content: ContentHash,
        path: PathKey,
        size: u64,
        mtime: u64,
    ) -> LogEntry {
        self.append(Action::Observed {
            content,
            path,
            size,
            mtime,
        })
    }

    /// Append an [`Action::Vanished`] (tombstone — never deletes remote content).
    pub fn append_vanished(&mut self, path: PathKey, last_content: ContentHash) -> LogEntry {
        self.append(Action::Vanished { path, last_content })
    }

    /// Append an [`Action::Backed`].
    pub fn append_backed(&mut self, content: ContentHash) -> LogEntry {
        self.append(Action::Backed { content })
    }

    /// Append an [`Action::PassCompleted`].
    pub fn append_pass_completed(
        &mut self,
        root: PathKey,
        files_seen: u64,
        bytes_seen: u64,
    ) -> LogEntry {
        self.append(Action::PassCompleted {
            root,
            files_seen,
            bytes_seen,
        })
    }

    /// Append an [`Action::Snapshot`] recording a materialized state hash.
    pub fn append_snapshot(&mut self, state_hash: [u8; 32]) -> LogEntry {
        self.append(Action::Snapshot { state_hash })
    }

    /// Verify a foreign [`Segment`] (hash, signature, chain continuity)
    /// and witness every entry's HLC so our local clock advances past
    /// anything we have seen.
    ///
    /// `known_tip` is the hash of the foreign machine's previously-known
    /// tip (or `None` if this is the first segment from that machine).
    pub fn receive_segment(
        &self,
        segment: &Segment,
        known_tip: Option<[u8; 32]>,
    ) -> Result<(), LogError> {
        segment.verify(known_tip)?;
        for entry in &segment.entries {
            self.clock.witness(entry.hlc);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_types::ContentHash;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn fresh_starts_at_zero() {
        let log = MachineLog::fresh(key(1));
        assert_eq!(log.next_seq(), 0);
        assert_eq!(log.current_tip(), [0u8; 32]);
    }

    #[test]
    fn append_produces_continuous_signed_chain() {
        let mut log = MachineLog::fresh(key(2));
        let mut prev_hash = [0u8; 32];
        let mut prev_hlc = 0u64;

        for i in 0u64..16 {
            let entry = log.append_backed(ContentHash::from_data(&i.to_le_bytes()));
            assert_eq!(entry.seq, i);
            assert_eq!(entry.prev, prev_hash);
            assert!(entry.verify_hash(), "hash should verify for seq {i}");
            assert!(
                entry.verify_signature(),
                "signature should verify for seq {i}"
            );
            assert!(entry.hlc > prev_hlc, "HLC must strictly increase");
            prev_hash = entry.hash;
            prev_hlc = entry.hlc;
        }
        assert_eq!(log.current_tip(), prev_hash);
        assert_eq!(log.next_seq(), 16);
    }

    #[test]
    fn from_state_resumes_chain() {
        let mut log = MachineLog::fresh(key(3));
        let first = log.append_backed(ContentHash::from_data(b"a"));
        let second = log.append_backed(ContentHash::from_data(b"b"));

        let mut restored =
            MachineLog::from_state(key(3), log.next_seq(), log.current_tip(), log.current_hlc());
        let third = restored.append_backed(ContentHash::from_data(b"c"));

        assert_eq!(third.seq, 2);
        assert_eq!(third.prev, second.hash);
        assert!(third.hlc > second.hlc);
        let _ = first;
    }

    #[test]
    fn machine_id_matches_verifying_key() {
        let sk = key(7);
        let log = MachineLog::fresh(sk.clone());
        assert_eq!(log.machine().as_bytes(), &sk.verifying_key().to_bytes());
    }
}
