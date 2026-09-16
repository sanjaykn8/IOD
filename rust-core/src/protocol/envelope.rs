//! KEM-then-AEAD secure envelope helper.
//!
//! ## Implementation-level correction (documented, spec-preserving)
//!
//! The specification's pseudocode repeatedly writes things like:
//! `(ct, K_shared) = Enc_KEM(pk, payload)` and then transmits `{ "ct":
//! ct }` — i.e. it treats `Enc_KEM` as if it directly encrypted a
//! structured `payload`. **ML-KEM/Kyber is a Key Encapsulation
//! Mechanism, not a public-key encryption scheme**: `encapsulate(pk)`
//! only ever produces `(ciphertext, shared_secret)` for a FRESH random
//! shared secret — it cannot take an arbitrary plaintext as input at
//! all. This is exactly the "ML-KEM must be used as a KEM, not treated
//! as an ordinary public-key encryption primitive" correction the
//! project brief requires.
//!
//! **Correction applied, consistently, everywhere the spec calls for an
//! "encrypted" message (M2, M3, the optional M4/M5 KEM exchange, K1's
//! `ct6`, the `GroupKeyResp` envelope, and the per-drone group-key
//! wrapping `env1`/`env2`)**:
//!
//! ```text
//! seal_for_recipient(pk, aad, payload):
//!     (ct, shared_secret) = ML-KEM.Encapsulate(pk)
//!     aead_key = HKDF-SHA256(shared_secret, info = "IOD-SEED-ENVELOPE-KEY-v1")
//!     sealed   = AEAD.Seal(aead_key, seq=1, aad, payload)
//!     return (ct, sealed)
//! ```
//!
//! `seq` is fixed at 1 because every envelope uses a **freshly
//! encapsulated** shared secret (a fresh KEM ciphertext each call), so
//! the derived AEAD key is different every time — there is no
//! (key, nonce) reuse across envelopes even though the sequence counter
//! itself does not increment. This preserves the specification's
//! intended data flow (a KEM-protected structured payload travels from
//! sender to recipient) and its intended security property
//! (confidentiality + integrity under the recipient's KEM key pair)
//! while using ML-KEM/Kyber768 the way it actually works.

use crate::crypto::aead::{self, AeadKey, SealedMessage};
use crate::crypto::domains::SEED_DOMAIN_ENVELOPE;
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::kem::{self, KemCiphertext, KemPublicKey, KemSecretKey};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SecureEnvelope {
    pub kem_ciphertext: Vec<u8>,
    pub sealed: SealedMessage,
}

fn derive_envelope_key(shared_secret: &[u8]) -> AeadKey {
    let bytes = hkdf_expand(shared_secret, None, SEED_DOMAIN_ENVELOPE, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    AeadKey(key)
}

pub fn seal_for_recipient(
    recipient_kem_pk: &KemPublicKey,
    associated_data: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<SecureEnvelope> {
    let (ct, shared_secret) = kem::encapsulate(recipient_kem_pk)?;
    let key = derive_envelope_key(&shared_secret.0);
    let sealed = aead::seal(&key, 1, associated_data, plaintext);
    Ok(SecureEnvelope {
        kem_ciphertext: ct.0,
        sealed,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum EnvelopeError {
    #[error("KEM decapsulation failed: {0}")]
    Kem(#[from] anyhow::Error),
    #[error("AEAD open failed: {0}")]
    Aead(#[from] aead::AeadError),
}

pub fn open_as_recipient(
    recipient_kem_sk: &KemSecretKey,
    associated_data: &[u8],
    envelope: &SecureEnvelope,
) -> Result<Vec<u8>, EnvelopeError> {
    let shared_secret = kem::decapsulate(recipient_kem_sk, &KemCiphertext(envelope.kem_ciphertext.clone()))?;
    let key = derive_envelope_key(&shared_secret.0);
    let plaintext = aead::open(&key, associated_data, &envelope.sealed, 0)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (pk, sk) = kem::keypair();
        let env = seal_for_recipient(&pk, b"aad", b"structured payload bytes").unwrap();
        let opened = open_as_recipient(&sk, b"aad", &env).unwrap();
        assert_eq!(opened, b"structured payload bytes");
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let (pk, _sk) = kem::keypair();
        let (_pk2, sk2) = kem::keypair();
        let env = seal_for_recipient(&pk, b"aad", b"secret").unwrap();
        assert!(open_as_recipient(&sk2, b"aad", &env).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let (pk, sk) = kem::keypair();
        let env = seal_for_recipient(&pk, b"aad-1", b"secret").unwrap();
        assert!(open_as_recipient(&sk, b"aad-2", &env).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (pk, sk) = kem::keypair();
        let mut env = seal_for_recipient(&pk, b"aad", b"secret").unwrap();
        env.sealed.ciphertext[0] ^= 0xFF;
        assert!(open_as_recipient(&sk, b"aad", &env).is_err());
    }
}
