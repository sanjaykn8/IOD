//! Post-quantum signature wrapper: Dilithium2 (NIST Round-3), the direct
//! algorithmic predecessor of standardized ML-DSA-44 (FIPS 204).
//!
//! All signing in this codebase goes through `sign_transcript`, which
//! takes an already-canonicalized byte transcript (see
//! `protocol::transcript`) rather than an arbitrary serde/JSON value.
//! This enforces the "do not sign vague JSON strings without
//! canonicalization" requirement: signatures never cover a
//! serialization whose byte representation could vary (e.g. due to
//! HashMap key ordering) between the signer and verifier.

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignPublicKey(pub Vec<u8>);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignSecretKey(pub Vec<u8>);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature(pub Vec<u8>);

pub fn keypair() -> (SignPublicKey, SignSecretKey) {
    let (pk, sk) = dilithium2::keypair();
    (
        SignPublicKey(pk.as_bytes().to_vec()),
        SignSecretKey(sk.as_bytes().to_vec()),
    )
}

pub fn sign_transcript(sk: &SignSecretKey, transcript: &[u8]) -> anyhow::Result<Signature> {
    let sk = dilithium2::SecretKey::from_bytes(&sk.0)
        .map_err(|_| anyhow::anyhow!("invalid Dilithium2 secret key encoding"))?;
    let sig = dilithium2::detached_sign(transcript, &sk);
    Ok(Signature(sig.as_bytes().to_vec()))
}

pub fn verify_transcript(pk: &SignPublicKey, transcript: &[u8], sig: &Signature) -> bool {
    let pk = match dilithium2::PublicKey::from_bytes(&pk.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match dilithium2::DetachedSignature::from_bytes(&sig.0) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    dilithium2::verify_detached_signature(&sig, transcript, &pk).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (pk, sk) = keypair();
        let msg = b"authenticated transcript bytes";
        let sig = sign_transcript(&sk, msg).unwrap();
        assert!(verify_transcript(&pk, msg, &sig));
    }

    #[test]
    fn altered_transcript_fails_verification() {
        let (pk, sk) = keypair();
        let msg = b"authenticated transcript bytes";
        let sig = sign_transcript(&sk, msg).unwrap();
        assert!(!verify_transcript(&pk, b"altered transcript bytes!!", &sig));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let (_pk, sk) = keypair();
        let (other_pk, _other_sk) = keypair();
        let msg = b"authenticated transcript bytes";
        let sig = sign_transcript(&sk, msg).unwrap();
        assert!(!verify_transcript(&other_pk, msg, &sig));
    }

    #[test]
    fn corrupted_signature_fails() {
        let (pk, sk) = keypair();
        let msg = b"authenticated transcript bytes";
        let mut sig = sign_transcript(&sk, msg).unwrap();
        sig.0[0] ^= 0xFF;
        assert!(!verify_transcript(&pk, msg, &sig));
    }
}
