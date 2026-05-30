//! The chunk transform pipeline.
//!
//! [`ChunkTransform`] is the seam at which Cairn plugs optional encryption
//! and (future) compression. v1 ships [`Identity`] only; encryption lands
//! in M11 by adding a new implementor — the scan, backup, and restore code
//! paths never branch on which transform is active.
//!
//! When a transform changes its input bytes (e.g. AEAD encryption), the
//! [`ChunkId`](cairn_types::ChunkId) is `blake3` of the **post-transform**
//! bytes so the remote store and existence checks operate on what is
//! actually stored. The [`Manifest`](cairn_types::Manifest) still records
//! the pre-transform plaintext [`ContentHash`](cairn_types::ContentHash) so
//! restore can verify the reassembled, reverse-transformed file.

use bytes::Bytes;

use crate::CasError;

/// Two-way transform applied to chunk bytes on the way to / from the
/// remote object store.
///
/// Implementations must be **deterministic** under a fixed key: identical
/// plaintext chunks must produce identical post-transform bytes, otherwise
/// deduplication breaks. (The M11 encryption transform uses
/// content-derived nonces to satisfy this.)
pub trait ChunkTransform: Send + Sync {
    /// Transform plaintext bytes into the form that will be uploaded.
    fn apply(&self, plaintext: &[u8]) -> Result<Bytes, CasError>;

    /// Reverse the transform: ciphertext from the store → plaintext.
    fn reverse(&self, stored: &[u8]) -> Result<Bytes, CasError>;

    /// Stable identifier for the transform, embedded into the manifest in a
    /// future revision so restore can detect a mismatched pipeline.
    fn name(&self) -> &'static str;
}

/// No-op transform. Plaintext is uploaded as-is.
///
/// This is the v1 default: chunks are content-addressed by their plaintext
/// `blake3`, so deduplication is automatic across files and machines.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity;

impl ChunkTransform for Identity {
    fn apply(&self, plaintext: &[u8]) -> Result<Bytes, CasError> {
        Ok(Bytes::copy_from_slice(plaintext))
    }

    fn reverse(&self, stored: &[u8]) -> Result<Bytes, CasError> {
        Ok(Bytes::copy_from_slice(stored))
    }

    fn name(&self) -> &'static str {
        "identity"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips() {
        let t = Identity;
        let input = b"the quick brown fox jumps over the lazy dog";
        let applied = t.apply(input).unwrap();
        assert_eq!(applied.as_ref(), input);
        let reversed = t.reverse(&applied).unwrap();
        assert_eq!(reversed.as_ref(), input);
    }

    #[test]
    fn identity_round_trips_empty() {
        let t = Identity;
        let applied = t.apply(b"").unwrap();
        assert!(applied.is_empty());
        let reversed = t.reverse(&applied).unwrap();
        assert!(reversed.is_empty());
    }

    #[test]
    fn identity_name_is_stable() {
        assert_eq!(Identity.name(), "identity");
    }

    #[test]
    fn identity_object_safe_via_dyn() {
        // The whole point of the trait is that callers can hold a
        // `Box<dyn ChunkTransform>` and swap implementations later.
        let t: Box<dyn ChunkTransform> = Box::new(Identity);
        let out = t.apply(b"hi").unwrap();
        assert_eq!(out.as_ref(), b"hi");
    }
}
