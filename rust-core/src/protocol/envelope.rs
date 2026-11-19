//! KEM-then-AEAD secure envelope helper.
//!
//! ## Implementation-level correction (documented, spec-preserving)
//!
//! The specification's pseudocode repeatedly writes things like:
//! `(ct, K_shared) = Enc_KEM(pk, payload)` and then transmits `{ "ct":
//! ct }` — i.e. it treats `Enc_KEM` as if it directly encrypted a
//! structured `payload`. **ML-KEM is a Key Encapsulation
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
//! while using ML-KEM-768 (FIPS 203) the way it actually works.

use crate::crypto::aead::{self, AeadKey, SealedMessage};
use crate::crypto::domains::SEED_DOMAIN_ENVELOPE;
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::kem::{self, KemCiphertext, KemPublicKey, KemSecretKey};
use crate::crypto::suite::SUITE_ID;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SecureEnvelope {
    /// Cryptographic suite that produced `kem_ciphertext`. Also bound into the
    /// envelope key (HKDF info), so relabelling it makes the AEAD tag fail.
    pub suite: String,
    pub kem_ciphertext: Vec<u8>,
    pub sealed: SealedMessage,
}

fn derive_envelope_key(shared_secret: &[u8], suite: &str) -> AeadKey {
    let mut info = SEED_DOMAIN_ENVELOPE.to_vec();
    info.push(0);
    info.extend_from_slice(suite.as_bytes());
    let bytes = hkdf_expand(shared_secret, None, &info, 32);
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
    let key = derive_envelope_key(&shared_secret.0, SUITE_ID);
    let sealed = aead::seal(&key, 1, associated_data, plaintext);
    Ok(SecureEnvelope {
        suite: SUITE_ID.to_string(),
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
    #[error(transparent)]
    Suite(#[from] crate::crypto::suite::SuiteMismatch),
}

pub fn open_as_recipient(
    recipient_kem_sk: &KemSecretKey,
    associated_data: &[u8],
    envelope: &SecureEnvelope,
) -> Result<Vec<u8>, EnvelopeError> {
    crate::crypto::suite::require(&envelope.suite)?;
    let shared_secret = kem::decapsulate(recipient_kem_sk, &KemCiphertext(envelope.kem_ciphertext.clone()))?;
    let key = derive_envelope_key(&shared_secret.0, &envelope.suite);
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

    #[test]
    fn tampered_kem_ciphertext_is_caught_by_the_aead_after_implicit_rejection() {
        // ML-KEM decapsulation of a modified ciphertext "succeeds" with a pseudo-random
        // secret (FIPS 203 implicit rejection); the envelope must still refuse to open.
        let (pk, sk) = kem::keypair();
        let env = seal_for_recipient(&pk, b"aad", b"secret").unwrap();
        for pos in [0usize, 543, env.kem_ciphertext.len() - 1] {
            let mut bad = env.clone();
            bad.kem_ciphertext[pos] ^= 0x01;
            assert!(matches!(open_as_recipient(&sk, b"aad", &bad), Err(EnvelopeError::Aead(_))), "pos {pos}");
        }
        let mut short = env.clone();
        short.kem_ciphertext.truncate(100);
        assert!(matches!(open_as_recipient(&sk, b"aad", &short), Err(EnvelopeError::Kem(_))));
    }

    #[test]
    fn envelopes_of_another_suite_are_rejected() {
        let (pk, sk) = kem::keypair();
        let env = seal_for_recipient(&pk, b"aad", b"secret").unwrap();
        assert_eq!(env.suite, SUITE_ID);
        for suite in [crate::crypto::suite::LEGACY_SUITE_ID, ""] {
            let mut bad = env.clone();
            bad.suite = suite.into();
            assert!(matches!(open_as_recipient(&sk, b"aad", &bad), Err(EnvelopeError::Suite(_))), "{suite}");
        }
        // the suite is bound into the key: a key derived for another label cannot open it
        let ss = kem::decapsulate(&sk, &KemCiphertext(env.kem_ciphertext.clone())).unwrap();
        let other = derive_envelope_key(&ss.0, crate::crypto::suite::LEGACY_SUITE_ID);
        assert!(aead::open(&other, b"aad", &env.sealed, 0).is_err());
        assert!(aead::open(&derive_envelope_key(&ss.0, SUITE_ID), b"aad", &env.sealed, 0).is_ok());
    }
}
