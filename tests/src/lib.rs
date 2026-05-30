//! Shared utilities for Cairn's integration tests.
//!
//! Kept intentionally minimal: per-test helpers live with the test they
//! support; only crate-wide fixtures (e.g. a deterministic signing key
//! seeded from a constant) go here.

use cairn_types::MachineId;
use ed25519_dalek::SigningKey;

/// Build a deterministic ed25519 signing key from a single seed byte.
///
/// Tests use this instead of [`SigningKey::generate`] so failures are
/// reproducible and chain content is hash-stable across runs.
pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Convenience: derive the [`MachineId`] paired with [`signing_key`].
pub fn machine_id(seed: u8) -> MachineId {
    MachineId::from(signing_key(seed).verifying_key().to_bytes())
}
