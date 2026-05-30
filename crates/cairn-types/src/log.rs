//! [`LogEntry`] and [`Action`]: the per-machine, hash-chained, signed event log.
//!
//! Each machine writes a **single linear chain** — one writer per chain, so
//! there are no merges, no DAG, no topological sort. The global view is the
//! union of all chains, folded with LWW per `(content, location)` keyed by
//! `(hlc, machine)`. This is deliberately simpler than Shoal's `logtree`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ids::{ContentHash, MachineId};
use crate::path::PathKey;

/// A mutation observed by a machine, recorded in its log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A file with this content was observed at this path during a scan.
    Observed {
        /// blake3 of the file's bytes.
        content: ContentHash,
        /// The path at which the content was observed.
        path: PathKey,
        /// File size in bytes at the time of observation.
        size: u64,
        /// File mtime in nanoseconds since UNIX epoch. Treat as coarse:
        /// some filesystems only have second-granularity.
        mtime: u64,
    },
    /// A path previously observed under a scanned root is no longer present.
    ///
    /// This is a TOMBSTONE: it updates the location index but **never**
    /// deletes content from the remote store. Location-tracking and
    /// content-retention are two separate code paths in Cairn.
    Vanished {
        /// The path that disappeared.
        path: PathKey,
        /// The last [`ContentHash`] observed at that path, retained for
        /// history queries.
        last_content: ContentHash,
    },
    /// This content's bytes are now safely stored in the remote object store.
    Backed {
        /// The content whose backup is now complete.
        content: ContentHash,
    },
    /// Marks the end of a scan pass over a root (for "as of pass N" stats).
    PassCompleted {
        /// The scanned root.
        root: PathKey,
        /// Number of regular files seen during this pass (changed or not).
        files_seen: u64,
        /// Total bytes seen during this pass.
        bytes_seen: u64,
    },
    /// Records a materialized-state hash so older entries can be pruned.
    Snapshot {
        /// blake3 of the serialized projection at the moment of the snapshot.
        state_hash: [u8; 32],
    },
}

/// A single entry in a machine's linear, hash-chained, signed log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Per-machine monotonic sequence number (0, 1, 2, ...).
    pub seq: u64,
    /// Hybrid logical clock at the moment of append.
    pub hlc: u64,
    /// The machine that authored this entry.
    pub machine: MachineId,
    /// The recorded mutation.
    pub action: Action,
    /// Hash of the previous entry in *this* machine's chain. Zero for `seq == 0`.
    pub prev: [u8; 32],
    /// `blake3(postcard((seq, hlc, machine, action, prev)))`.
    pub hash: [u8; 32],
    /// First half of the ed25519 signature over [`Self::hash`] (split for
    /// serde, since `[u8; 64]` does not derive serde by default).
    pub sig_r: [u8; 32],
    /// Second half of the ed25519 signature over [`Self::hash`].
    pub sig_s: [u8; 32],
}

/// Content of a [`LogEntry`] that participates in its [`hash`](LogEntry::hash).
///
/// Excludes `hash` and `sig_*`; the `prev` field is *included* so chain
/// continuity is itself part of every entry's content fingerprint.
#[derive(Serialize)]
struct HashableContent<'a> {
    seq: u64,
    hlc: u64,
    machine: MachineId,
    action: &'a Action,
    prev: &'a [u8; 32],
}

impl LogEntry {
    /// Compute the blake3 hash of an entry's content fields.
    pub fn compute_hash(
        seq: u64,
        hlc: u64,
        machine: MachineId,
        action: &Action,
        prev: &[u8; 32],
    ) -> [u8; 32] {
        let content = HashableContent {
            seq,
            hlc,
            machine,
            action,
            prev,
        };
        let bytes = postcard::to_allocvec(&content).expect("postcard serialize should not fail");
        blake3::hash(&bytes).into()
    }

    /// Verify that the stored hash matches the entry's content.
    pub fn verify_hash(&self) -> bool {
        let expected =
            Self::compute_hash(self.seq, self.hlc, self.machine, &self.action, &self.prev);
        self.hash == expected
    }

    /// Reassemble the 64-byte ed25519 signature from its two halves.
    pub fn signature_bytes(&self) -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        sig
    }

    /// Verify the ed25519 signature over [`Self::hash`].
    ///
    /// Reconstructs the verifying key from `machine`'s bytes. Returns `false`
    /// if the bytes are not a valid ed25519 public key, or if the signature
    /// does not verify.
    pub fn verify_signature(&self) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(self.machine.as_bytes()) else {
            return false;
        };
        let signature = Signature::from_bytes(&self.signature_bytes());
        verifying_key.verify(&self.hash, &signature).is_ok()
    }

    /// Build and sign a new entry.
    ///
    /// `machine` MUST be the [`MachineId`] derived from `signing_key`'s
    /// verifying-key bytes — otherwise [`verify_signature`](Self::verify_signature)
    /// will reject the resulting entry. `cairn-log` enforces this invariant
    /// at append time.
    pub fn new_signed(
        seq: u64,
        hlc: u64,
        machine: MachineId,
        action: Action,
        prev: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let hash = Self::compute_hash(seq, hlc, machine, &action, &prev);
        let signature: Signature = signing_key.sign(&hash);
        let sig_bytes = signature.to_bytes();
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig_bytes[..32]);
        sig_s.copy_from_slice(&sig_bytes[32..]);

        Self {
            seq,
            hlc,
            machine,
            action,
            prev,
            hash,
            sig_r,
            sig_s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed: u8) -> (MachineId, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let machine = MachineId::from(signing_key.verifying_key().to_bytes());
        (machine, signing_key)
    }

    fn sample_observed() -> Action {
        Action::Observed {
            content: ContentHash::from_data(b"hello"),
            path: PathKey::from_bytes(b"/a/b.txt"),
            size: 5,
            mtime: 1_000,
        }
    }

    #[test]
    fn new_signed_then_verify_hash_and_signature() {
        let (machine, key) = test_identity(1);
        let entry = LogEntry::new_signed(0, 42, machine, sample_observed(), [0u8; 32], &key);
        assert!(entry.verify_hash());
        assert!(entry.verify_signature());
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let (machine, _) = test_identity(1);
        let a = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_changes_with_seq() {
        let (machine, _) = test_identity(1);
        let a = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(1, 42, machine, &sample_observed(), &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_changes_with_hlc() {
        let (machine, _) = test_identity(1);
        let a = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(0, 43, machine, &sample_observed(), &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_changes_with_machine() {
        let (m1, _) = test_identity(1);
        let (m2, _) = test_identity(2);
        let a = LogEntry::compute_hash(0, 42, m1, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(0, 42, m2, &sample_observed(), &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_changes_with_action() {
        let (machine, _) = test_identity(1);
        let other = Action::Observed {
            content: ContentHash::from_data(b"different"),
            path: PathKey::from_bytes(b"/a/b.txt"),
            size: 9,
            mtime: 1_000,
        };
        let a = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(0, 42, machine, &other, &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_changes_with_prev() {
        let (machine, _) = test_identity(1);
        let a = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[0u8; 32]);
        let b = LogEntry::compute_hash(0, 42, machine, &sample_observed(), &[1u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn verify_hash_rejects_tampered_action() {
        let (machine, key) = test_identity(1);
        let mut entry = LogEntry::new_signed(0, 42, machine, sample_observed(), [0u8; 32], &key);
        entry.action = Action::Backed {
            content: ContentHash::from_data(b"other"),
        };
        assert!(!entry.verify_hash());
    }

    #[test]
    fn verify_hash_rejects_tampered_seq() {
        let (machine, key) = test_identity(1);
        let mut entry = LogEntry::new_signed(0, 42, machine, sample_observed(), [0u8; 32], &key);
        entry.seq = 99;
        assert!(!entry.verify_hash());
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        // Sign with k1 but claim authorship by machine m2. The hash still
        // verifies (it depends only on content), but the signature must fail
        // because the verifying key derived from m2 isn't the one that signed.
        let (_, k1) = test_identity(1);
        let (m2, _k2) = test_identity(2);
        let entry = LogEntry::new_signed(0, 42, m2, sample_observed(), [0u8; 32], &k1);
        assert!(entry.verify_hash());
        assert!(!entry.verify_signature());
    }

    #[test]
    fn verify_signature_rejects_tampered_hash() {
        let (machine, key) = test_identity(1);
        let mut entry = LogEntry::new_signed(0, 42, machine, sample_observed(), [0u8; 32], &key);
        entry.hash[0] ^= 0xff;
        assert!(!entry.verify_signature());
    }

    #[test]
    fn postcard_roundtrip_all_action_variants() {
        let actions = vec![
            sample_observed(),
            Action::Vanished {
                path: PathKey::from_bytes(b"/a/gone.txt"),
                last_content: ContentHash::from_data(b"x"),
            },
            Action::Backed {
                content: ContentHash::from_data(b"y"),
            },
            Action::PassCompleted {
                root: PathKey::from_bytes(b"/data"),
                files_seen: 1234,
                bytes_seen: 99_999,
            },
            Action::Snapshot {
                state_hash: [7u8; 32],
            },
        ];
        for a in actions {
            let bytes = postcard::to_allocvec(&a).unwrap();
            let decoded: Action = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(a, decoded);
        }
    }

    #[test]
    fn log_entry_postcard_roundtrip_preserves_validity() {
        let (machine, key) = test_identity(3);
        let entry = LogEntry::new_signed(7, 12345, machine, sample_observed(), [9u8; 32], &key);
        let bytes = postcard::to_allocvec(&entry).unwrap();
        let decoded: LogEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(entry, decoded);
        assert!(decoded.verify_hash());
        assert!(decoded.verify_signature());
    }

    #[test]
    fn signature_bytes_match_split_halves() {
        let (machine, key) = test_identity(4);
        let entry = LogEntry::new_signed(0, 1, machine, sample_observed(), [0u8; 32], &key);
        let sig = entry.signature_bytes();
        assert_eq!(sig.len(), 64);
        assert_eq!(&sig[..32], &entry.sig_r);
        assert_eq!(&sig[32..], &entry.sig_s);
    }
}
