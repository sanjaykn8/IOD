//! AEAD wrapper (ChaCha20-Poly1305) for application-layer confidentiality
//! and integrity of secure messages and encrypted protocol payloads.
//!
//! Nonce policy (documented exactly, per the "never reuse a nonce under
//! the same key" requirement):
//!   nonce = first 4 bytes of a per-key monotonic sequence counter
//!           (big-endian u32) || 8 fresh random bytes
//! A key is only ever used for a single logical session (each session
//! derives its own `K_AEAD` — see `identity::derive_aead_key`), and
//! within that session `SequenceCounter` is strictly increasing and
//! persisted in the session record, so the same (key, nonce) pair cannot
//! be produced twice even across process restarts, as long as the
//! session record's counter is durably advanced before the ciphertext is
//! sent (see `storage::sessions`). The additional random bytes give a
//! second, independent line of defense against counter-reuse bugs.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub struct AeadKey(pub [u8; KEY_LEN]);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedMessage {
    pub seq: u32,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn seal(key: &AeadKey, seq: u32, associated_data: &[u8], plaintext: &[u8]) -> SealedMessage {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..4].copy_from_slice(&seq.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut nonce_bytes[4..]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("AEAD seal should not fail for well-formed input");
    SealedMessage {
        seq,
        nonce: nonce_bytes,
        ciphertext,
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AeadError {
    #[error("AEAD authentication failed (tag mismatch or tampering detected)")]
    AuthenticationFailed,
    #[error("replayed or out-of-order sequence number: expected > {expected}, got {got}")]
    ReplayedSequence { expected: u32, got: u32 },
}

/// Opens a sealed message, additionally enforcing strictly-increasing
/// sequence numbers against `last_seen_seq` (replay protection at the
/// transport layer, independent of AEAD's own tag check).
pub fn open(
    key: &AeadKey,
    associated_data: &[u8],
    msg: &SealedMessage,
    last_seen_seq: u32,
) -> Result<Vec<u8>, AeadError> {
    if msg.seq <= last_seen_seq {
        return Err(AeadError::ReplayedSequence {
            expected: last_seen_seq + 1,
            got: msg.seq,
        });
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = Nonce::from_slice(&msg.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &msg.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| AeadError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AeadKey {
        let mut k = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut k);
        AeadKey(k)
    }

    #[test]
    fn round_trip() {
        let k = key();
        let sealed = seal(&k, 1, b"aad", b"hello drone");
        let opened = open(&k, b"aad", &sealed, 0).unwrap();
        assert_eq!(opened, b"hello drone");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = key();
        let mut sealed = seal(&k, 1, b"aad", b"hello drone");
        sealed.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            open(&k, b"aad", &sealed, 0),
            Err(AeadError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let k = key();
        let sealed = seal(&k, 1, b"aad-1", b"hello drone");
        assert!(matches!(
            open(&k, b"aad-2", &sealed, 0),
            Err(AeadError::AuthenticationFailed)
        ));
    }

    #[test]
    fn replayed_sequence_rejected() {
        let k = key();
        let sealed = seal(&k, 5, b"aad", b"hello drone");
        assert!(matches!(
            open(&k, b"aad", &sealed, 5),
            Err(AeadError::ReplayedSequence { .. })
        ));
        assert!(matches!(
            open(&k, b"aad", &sealed, 10),
            Err(AeadError::ReplayedSequence { .. })
        ));
    }

    #[test]
    fn nonces_are_not_reused_across_many_seals() {
        let k = key();
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000u32 {
            let m = seal(&k, i, b"aad", b"msg");
            assert!(seen.insert(m.nonce), "nonce reuse detected");
        }
    }
}
