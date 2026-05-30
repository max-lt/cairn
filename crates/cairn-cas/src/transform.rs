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
use zeroize::Zeroizing;

use crate::CasError;

/// Domain-separation label for the chunk-encryption key derivation. Bumping
/// this label invalidates every prior backup, so it must NEVER change in
/// a deployed installation.
pub const CONTENT_KEY_DOMAIN: &str = "cairn-content-key-v1";

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

/// AEAD `ChunkTransform` using ChaCha20-Poly1305 with a deterministic,
/// content-derived nonce.
///
/// **Convergent-style encryption.** The nonce for each chunk is
/// `blake3(plaintext)[..12]`, so two identical plaintext chunks under
/// the same key encrypt to byte-identical ciphertext — that's what keeps
/// CDC dedup intact across files and machines.
///
/// The tradeoff: anyone with access to the store can learn whether two
/// chunks have identical plaintexts (because their ciphertexts are
/// equal). For a single-user personal backup tool — the intended Cairn
/// trust domain — this is appropriate. Anything that requires hiding
/// plaintext equality across users must NOT enable this transform.
///
/// On-wire format: `nonce(12 bytes) || ciphertext_with_tag`. The 16-byte
/// Poly1305 tag is appended by ChaCha20-Poly1305 to the ciphertext, so
/// the stored size for a plaintext of length `N` is `12 + N + 16`.
pub struct Encrypt {
    key: Zeroizing<[u8; 32]>,
}

impl Encrypt {
    /// Build from a 32-byte raw key (test fixtures).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Derive a 32-byte content key from a passphrase + salt via
    /// Argon2id with the crate's default parameters.
    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Self, CasError> {
        use argon2::Argon2;
        let argon = Argon2::default();
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| CasError::Transform(format!("argon2 KDF failed: {e}")))?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Derive the content key from a BIP-39 mnemonic.
    ///
    /// `mnemonic.to_seed("")` runs PBKDF2-HMAC-SHA512 with 2048 iterations
    /// per BIP-39 — 64 bytes of pre-spread entropy. We then domain-separate
    /// via `blake3::derive_key(CONTENT_KEY_DOMAIN, seed)` so this key is
    /// unrelated to any other key the user might derive from the same
    /// mnemonic (notably the per-machine signing key, which gets its own
    /// domain label in `cairn-engine`).
    ///
    /// The mnemonic ITSELF is the master content secret — the same
    /// mnemonic on every one of the user's machines produces the same
    /// content key, which is what keeps convergent dedup intact across
    /// machines (see Scheme A in `docs/plan.md`).
    pub fn from_mnemonic(mnemonic: &bip39::Mnemonic) -> Self {
        let seed = mnemonic.to_seed("");
        let key = blake3::derive_key(CONTENT_KEY_DOMAIN, &seed);
        Self {
            key: Zeroizing::new(key),
        }
    }
}

impl ChunkTransform for Encrypt {
    fn apply(&self, plaintext: &[u8]) -> Result<Bytes, CasError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&blake3::hash(plaintext).as_bytes()[..12]);

        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|e| CasError::Transform(format!("invalid AEAD key: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CasError::Transform(format!("AEAD encrypt failed: {e}")))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(Bytes::from(out))
    }

    fn reverse(&self, stored: &[u8]) -> Result<Bytes, CasError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        if stored.len() < 12 + 16 {
            return Err(CasError::Transform(format!(
                "ciphertext too short: {} bytes (need at least 28)",
                stored.len()
            )));
        }
        let (nonce_bytes, body) = stored.split_at(12);
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|e| CasError::Transform(format!("invalid AEAD key: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, body)
            .map_err(|e| CasError::Transform(format!("AEAD decrypt failed: {e}")))?;
        Ok(Bytes::from(plaintext))
    }

    fn name(&self) -> &'static str {
        "chacha20poly1305"
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

    #[test]
    fn encrypt_round_trips() {
        let e = Encrypt::from_key([7u8; 32]);
        let plain = b"some chunk bytes to round-trip";
        let cipher = e.apply(plain).unwrap();
        assert_ne!(
            cipher.as_ref(),
            plain,
            "ciphertext must differ from plaintext"
        );
        assert_eq!(cipher.len(), plain.len() + 12 + 16);
        let back = e.reverse(&cipher).unwrap();
        assert_eq!(back.as_ref(), plain);
    }

    #[test]
    fn encrypt_is_deterministic_for_same_key_and_plaintext() {
        let e = Encrypt::from_key([13u8; 32]);
        let plain = b"identical plaintext chunks should encrypt identically";
        let c1 = e.apply(plain).unwrap();
        let c2 = e.apply(plain).unwrap();
        assert_eq!(
            c1, c2,
            "convergent encryption: equal plaintext + key → equal ciphertext"
        );
    }

    #[test]
    fn encrypt_with_different_keys_gives_different_ciphertext() {
        let e1 = Encrypt::from_key([1u8; 32]);
        let e2 = Encrypt::from_key([2u8; 32]);
        let plain = b"the same plaintext";
        let c1 = e1.apply(plain).unwrap();
        let c2 = e2.apply(plain).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn encrypt_reverse_with_wrong_key_fails() {
        let good = Encrypt::from_key([1u8; 32]);
        let bad = Encrypt::from_key([2u8; 32]);
        let cipher = good.apply(b"secret").unwrap();
        let err = bad.reverse(&cipher).unwrap_err();
        assert!(matches!(err, CasError::Transform(_)));
        // No bytes leak — the error path returns no plaintext.
    }

    #[test]
    fn encrypt_reverse_on_corrupted_ciphertext_fails() {
        let e = Encrypt::from_key([1u8; 32]);
        let mut cipher = e.apply(b"hello world").unwrap().to_vec();
        // Flip a byte deep in the ciphertext body (past the 12-byte nonce).
        cipher[20] ^= 0xff;
        let err = e.reverse(&cipher).unwrap_err();
        assert!(matches!(err, CasError::Transform(_)));
    }

    #[test]
    fn encrypt_reverse_rejects_too_short_input() {
        let e = Encrypt::from_key([1u8; 32]);
        let err = e.reverse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, CasError::Transform(_)));
    }

    #[test]
    fn encrypt_name_is_stable() {
        assert_eq!(Encrypt::from_key([0u8; 32]).name(), "chacha20poly1305");
    }

    #[test]
    fn passphrase_derived_keys_are_deterministic() {
        let salt = b"cairn-test-salt-fixed-value-aa";
        let a = Encrypt::from_passphrase("correct horse battery staple", salt).unwrap();
        let b = Encrypt::from_passphrase("correct horse battery staple", salt).unwrap();
        let plain = b"some bytes";
        assert_eq!(a.apply(plain).unwrap(), b.apply(plain).unwrap());
    }

    #[test]
    fn passphrase_with_different_salt_yields_different_key() {
        let a = Encrypt::from_passphrase("pass", b"salt-aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let b = Encrypt::from_passphrase("pass", b"salt-bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let plain = b"identical plaintext";
        assert_ne!(a.apply(plain).unwrap(), b.apply(plain).unwrap());
    }

    #[test]
    fn from_mnemonic_is_deterministic_for_same_words() {
        // Standard BIP-39 12-word test vector with valid checksum.
        let m = bip39::Mnemonic::parse_in(
            bip39::Language::English,
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let e1 = Encrypt::from_mnemonic(&m);
        let e2 = Encrypt::from_mnemonic(&m);
        let plain = b"some chunk";
        assert_eq!(e1.apply(plain).unwrap(), e2.apply(plain).unwrap());
    }

    #[test]
    fn from_mnemonic_round_trips() {
        let m = bip39::Mnemonic::parse_in(
            bip39::Language::English,
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let e = Encrypt::from_mnemonic(&m);
        let plain = b"the round-trip plaintext";
        let cipher = e.apply(plain).unwrap();
        assert_eq!(e.reverse(&cipher).unwrap().as_ref(), plain);
    }

    #[test]
    fn different_mnemonics_yield_different_ciphertext() {
        let m1 = bip39::Mnemonic::parse_in(
            bip39::Language::English,
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let m2 = bip39::Mnemonic::parse_in(
            bip39::Language::English,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        )
        .unwrap();
        let plain = b"same plaintext";
        let c1 = Encrypt::from_mnemonic(&m1).apply(plain).unwrap();
        let c2 = Encrypt::from_mnemonic(&m2).apply(plain).unwrap();
        assert_ne!(c1, c2);
    }
}
