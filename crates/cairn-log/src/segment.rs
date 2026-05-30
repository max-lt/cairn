//! [`Segment`]: an immutable, contiguous range of entries from one machine.
//!
//! Segments are the unit of push / pull on the remote store. A segment
//! header records the originating `machine`, the inclusive sequence range
//! `[seq_start, seq_end]`, and the tip hash (the hash of the last entry)
//! so a consumer can quickly confirm chain continuity before deserializing
//! every entry.

use cairn_types::{LogEntry, MachineId};
use serde::{Deserialize, Serialize};

use crate::LogError;

/// A contiguous range of entries from one machine's linear chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// The machine whose chain these entries belong to.
    pub machine: MachineId,
    /// Sequence number of the first entry (inclusive).
    pub seq_start: u64,
    /// Sequence number of the last entry (inclusive).
    pub seq_end: u64,
    /// Hash of the last entry — the chain tip after this segment is applied.
    pub tip_hash: [u8; 32],
    /// The entries themselves, in chain order.
    pub entries: Vec<LogEntry>,
}

impl Segment {
    /// Build a [`Segment`] from a vector of entries.
    ///
    /// Validates that the entries are non-empty, all from the same
    /// machine, and have contiguous sequence numbers. Does **not** verify
    /// hashes or signatures — call [`Self::verify`] for that.
    pub fn try_from_entries(entries: Vec<LogEntry>) -> Result<Self, LogError> {
        if entries.is_empty() {
            return Err(LogError::EmptySegment);
        }
        let first = &entries[0];
        let machine = first.machine;
        for e in &entries {
            if e.machine != machine {
                return Err(LogError::MixedMachines {
                    a: hex_bytes(machine.as_bytes()),
                    b: hex_bytes(e.machine.as_bytes()),
                });
            }
        }
        for w in entries.windows(2) {
            if w[1].seq != w[0].seq + 1 {
                return Err(LogError::NonContiguousSeq {
                    prev: w[0].seq,
                    got: w[1].seq,
                });
            }
        }
        let seq_start = first.seq;
        let last = entries.last().expect("non-empty by check above");
        let seq_end = last.seq;
        let tip_hash = last.hash;
        Ok(Self {
            machine,
            seq_start,
            seq_end,
            tip_hash,
            entries,
        })
    }

    /// Serialize this segment to postcard bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LogError> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Deserialize a segment from postcard bytes. The deserialized segment
    /// is **not yet verified** — call [`Self::verify`] before folding it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LogError> {
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Verify the segment's header consistency, each entry's hash and
    /// signature, and chain continuity (including the link to `known_tip`
    /// of the previous segment from the same machine).
    ///
    /// `known_tip`:
    /// - `None` means this is the first segment we have seen from this
    ///   machine — `seq_start` must be 0 and the first entry's `prev` must
    ///   be all-zero.
    /// - `Some(hash)` means we have prior segments; `seq_start` must be
    ///   greater than 0 and the first entry's `prev` must equal `hash`.
    pub fn verify(&self, known_tip: Option<[u8; 32]>) -> Result<(), LogError> {
        if self.entries.is_empty() {
            return Err(LogError::EmptySegment);
        }
        let first = &self.entries[0];
        let last = self.entries.last().expect("non-empty");

        if first.seq != self.seq_start {
            return Err(LogError::NonContiguousSeq {
                prev: self.seq_start,
                got: first.seq,
            });
        }
        if last.seq != self.seq_end {
            return Err(LogError::NonContiguousSeq {
                prev: self.seq_end,
                got: last.seq,
            });
        }
        if last.hash != self.tip_hash {
            return Err(LogError::TipMismatch {
                expected: hex_bytes(&self.tip_hash),
                found: hex_bytes(&last.hash),
            });
        }

        match (known_tip, first.seq) {
            (None, 0) => {
                if first.prev != [0u8; 32] {
                    return Err(LogError::BrokenChain {
                        seq: first.seq,
                        expected: hex_bytes(&[0u8; 32]),
                        found: hex_bytes(&first.prev),
                    });
                }
            }
            (None, _) => {
                // No prior tip, but segment doesn't start at seq 0 → gap.
                return Err(LogError::BrokenChain {
                    seq: first.seq,
                    expected: "<chain start, seq 0>".to_string(),
                    found: format!("seq {} with prev {}", first.seq, hex_bytes(&first.prev)),
                });
            }
            (Some(_), 0) => {
                // Prior tip but segment claims a fresh chain → restart.
                return Err(LogError::BrokenChain {
                    seq: 0,
                    expected: "continuation of known chain".to_string(),
                    found: "fresh chain (seq 0)".to_string(),
                });
            }
            (Some(tip), _) => {
                if first.prev != tip {
                    return Err(LogError::BrokenChain {
                        seq: first.seq,
                        expected: hex_bytes(&tip),
                        found: hex_bytes(&first.prev),
                    });
                }
            }
        }

        let mut prev_seq = None::<u64>;
        let mut prev_hash = first.prev;
        for entry in &self.entries {
            if entry.machine != self.machine {
                return Err(LogError::MachineMismatch {
                    header: hex_bytes(self.machine.as_bytes()),
                    entry: hex_bytes(entry.machine.as_bytes()),
                    seq: entry.seq,
                });
            }
            if let Some(p) = prev_seq
                && entry.seq != p + 1
            {
                return Err(LogError::NonContiguousSeq {
                    prev: p,
                    got: entry.seq,
                });
            }
            if entry.prev != prev_hash {
                return Err(LogError::BrokenChain {
                    seq: entry.seq,
                    expected: hex_bytes(&prev_hash),
                    found: hex_bytes(&entry.prev),
                });
            }
            if !entry.verify_hash() {
                return Err(LogError::InvalidHash { seq: entry.seq });
            }
            if !entry.verify_signature() {
                return Err(LogError::InvalidSignature { seq: entry.seq });
            }
            prev_seq = Some(entry.seq);
            prev_hash = entry.hash;
        }
        Ok(())
    }
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_log::MachineLog;
    use cairn_types::ContentHash;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_segment(seed: u8, n: u64) -> (Segment, MachineLog) {
        let mut log = MachineLog::fresh(key(seed));
        let mut entries = Vec::new();
        for i in 0..n {
            entries.push(log.append_backed(ContentHash::from_data(&i.to_le_bytes())));
        }
        (Segment::try_from_entries(entries).unwrap(), log)
    }

    #[test]
    fn try_from_entries_validates_basics() {
        let (seg, _log) = sample_segment(1, 4);
        assert_eq!(seg.seq_start, 0);
        assert_eq!(seg.seq_end, 3);
        assert_eq!(seg.tip_hash, seg.entries.last().unwrap().hash);
    }

    #[test]
    fn empty_entries_rejected() {
        let err = Segment::try_from_entries(vec![]).unwrap_err();
        matches!(err, LogError::EmptySegment);
    }

    #[test]
    fn mixed_machines_rejected() {
        let mut log_a = MachineLog::fresh(key(1));
        let mut log_b = MachineLog::fresh(key(2));
        let e0 = log_a.append_backed(ContentHash::from_data(b"a"));
        let e1 = log_b.append_backed(ContentHash::from_data(b"b"));
        let err = Segment::try_from_entries(vec![e0, e1]).unwrap_err();
        assert!(matches!(err, LogError::MixedMachines { .. }));
    }

    #[test]
    fn non_contiguous_seq_rejected() {
        let mut log = MachineLog::fresh(key(1));
        let e0 = log.append_backed(ContentHash::from_data(b"a"));
        let _skip = log.append_backed(ContentHash::from_data(b"b"));
        let e2 = log.append_backed(ContentHash::from_data(b"c"));
        let err = Segment::try_from_entries(vec![e0, e2]).unwrap_err();
        assert!(matches!(
            err,
            LogError::NonContiguousSeq { prev: 0, got: 2 }
        ));
    }

    #[test]
    fn verify_accepts_initial_segment() {
        let (seg, _log) = sample_segment(1, 3);
        seg.verify(None).unwrap();
    }

    #[test]
    fn verify_accepts_continuation_segment() {
        let mut log = MachineLog::fresh(key(1));
        let first_batch = vec![
            log.append_backed(ContentHash::from_data(b"a")),
            log.append_backed(ContentHash::from_data(b"b")),
        ];
        let known_tip = log.current_tip();
        let second_batch = vec![
            log.append_backed(ContentHash::from_data(b"c")),
            log.append_backed(ContentHash::from_data(b"d")),
        ];

        let seg1 = Segment::try_from_entries(first_batch).unwrap();
        let seg2 = Segment::try_from_entries(second_batch).unwrap();
        seg1.verify(None).unwrap();
        seg2.verify(Some(known_tip)).unwrap();
    }

    #[test]
    fn verify_rejects_flipped_byte_as_invalid_hash() {
        let (mut seg, _log) = sample_segment(1, 3);
        // Flip a byte in an entry's action; the stored hash no longer matches.
        let e = &mut seg.entries[1];
        if let cairn_types::Action::Backed { content } = &mut e.action {
            let mut bytes = *content.as_bytes();
            bytes[0] ^= 0xff;
            *content = cairn_types::ContentHash::from(bytes);
        } else {
            panic!("expected Backed");
        }
        let err = seg.verify(None).unwrap_err();
        assert!(matches!(err, LogError::InvalidHash { seq: 1 }));
    }

    #[test]
    fn verify_rejects_wrong_signature() {
        // Build an entry that claims to be from machine A but is signed by B.
        let mut log_a = MachineLog::fresh(key(1));
        let _ = log_a.append_backed(ContentHash::from_data(b"warmup"));
        let log_b = MachineLog::fresh(key(2));
        let bad = cairn_types::LogEntry::new_signed(
            0,
            log_a.current_hlc() + 1,
            log_a.machine(),
            cairn_types::Action::Backed {
                content: ContentHash::from_data(b"x"),
            },
            [0u8; 32],
            &key(2),
        );
        // Wrap a single forged entry in a segment by itself with prev = 0
        // (so it's a "first segment"); hash will verify but signature won't.
        let seg = Segment {
            machine: log_b.machine(), // claim it's from B (matches signer)
            seq_start: 0,
            seq_end: 0,
            tip_hash: bad.hash,
            entries: vec![cairn_types::LogEntry {
                machine: bad.machine, // still claims A
                ..bad
            }],
        };
        // The segment header says B but the entry's machine is A → mismatch.
        let err = seg.verify(None).unwrap_err();
        assert!(matches!(err, LogError::MachineMismatch { .. }));

        // Now fix the header to match the entry's claimed machine A. Then
        // signature should fail because the entry was signed by B.
        let entry = seg.entries.into_iter().next().unwrap();
        let bad_seg = Segment {
            machine: entry.machine,
            seq_start: 0,
            seq_end: 0,
            tip_hash: entry.hash,
            entries: vec![entry],
        };
        let err = bad_seg.verify(None).unwrap_err();
        assert!(matches!(err, LogError::InvalidSignature { .. }));

        let _ = log_b;
    }

    #[test]
    fn verify_rejects_broken_chain_within_segment() {
        let (mut seg, _log) = sample_segment(1, 3);
        seg.entries[1].prev[0] ^= 0xff;
        let err = seg.verify(None).unwrap_err();
        // The broken prev now also mismatches the stored hash (which was
        // computed with the original prev), so we get InvalidHash first.
        // Both InvalidHash and BrokenChain are acceptable here — pick one
        // and assert robustly.
        assert!(matches!(
            err,
            LogError::InvalidHash { .. } | LogError::BrokenChain { .. }
        ));
    }

    #[test]
    fn verify_rejects_continuation_with_mismatched_prev() {
        let mut log = MachineLog::fresh(key(1));
        let _ = log.append_backed(ContentHash::from_data(b"a"));
        let second_batch = vec![log.append_backed(ContentHash::from_data(b"b"))];
        let seg = Segment::try_from_entries(second_batch).unwrap();
        let wrong_tip = [0xaau8; 32];
        let err = seg.verify(Some(wrong_tip)).unwrap_err();
        assert!(matches!(err, LogError::BrokenChain { .. }));
    }

    #[test]
    fn verify_rejects_initial_segment_with_known_tip() {
        // Segment is fresh (seq starts at 0) but we already had a tip.
        let (seg, _log) = sample_segment(1, 2);
        let err = seg.verify(Some([0xaau8; 32])).unwrap_err();
        assert!(matches!(err, LogError::BrokenChain { seq: 0, .. }));
    }

    #[test]
    fn postcard_roundtrip() {
        let (seg, _log) = sample_segment(1, 4);
        let bytes = seg.to_bytes().unwrap();
        let decoded = Segment::from_bytes(&bytes).unwrap();
        assert_eq!(seg, decoded);
        decoded.verify(None).unwrap();
    }
}
