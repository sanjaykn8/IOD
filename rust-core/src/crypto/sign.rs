//! Post-quantum signature wrapper: **ML-DSA-44 (FIPS 204, final)** via the RustCrypto
//! `ml-dsa` crate (pinned `=0.1.2`, which includes the fixes for CVE-2026-22705 and
//! CVE-2026-24850).
//!
//! All signing goes through `sign_transcript`, which takes already-canonicalized
//! transcript bytes (see `protocol::canon` / `protocol::transcript`), never an
//! arbitrary serde/JSON value.
//!
//! * Mode: "pure" ML-DSA (FIPS 204 Algorithm 2/3), no pre-hash.
//! * Context string: the active suite id ([`crate::crypto::suite::SUITE_ID`]). A
//!   signature made under any other context (or by another suite) does not verify.
//! * Signing is **hedged** (FIPS 204 default): fresh 32-byte `rnd` from the OS RNG.
//! * Encodings: public key 1312 bytes; signature 2420 bytes; private key stored in
//!   **seed form** `xi` (32 bytes), the crate's preferred serialization and permitted
//!   by FIPS 204 §3.6.3. The expanded 2560-byte encoding is checked in tests only.

use crate::crypto::suite::SUITE_ID;
use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature as DsaSignature, SigningKey, VerifyingKey};

pub const PUBLIC_KEY_BYTES: usize = 1312;
pub const EXPANDED_SECRET_KEY_BYTES: usize = 2560;
pub const SECRET_SEED_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 2420;

/// FIPS 204 context string used for every signature in this system.
pub fn context() -> &'static [u8] {
    SUITE_ID.as_bytes()
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SignPublicKey(pub Vec<u8>);
/// Signing key in seed form `xi` (32 bytes). Device-local only.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SignSecretKey(pub Vec<u8>);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature(pub Vec<u8>);

impl std::fmt::Debug for SignSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignSecretKey(<redacted>)")
    }
}

fn parse_sk(sk: &SignSecretKey) -> anyhow::Result<SigningKey<MlDsa44>> {
    let seed = ml_dsa::B32::try_from(sk.0.as_slice())
        .map_err(|_| anyhow::anyhow!("ML-DSA-44 private key seed must be {SECRET_SEED_BYTES} bytes, got {}", sk.0.len()))?;
    Ok(SigningKey::<MlDsa44>::from_seed(&seed))
}

fn parse_vk(pk: &SignPublicKey) -> Option<VerifyingKey<MlDsa44>> {
    let enc = EncodedVerifyingKey::<MlDsa44>::try_from(pk.0.as_slice()).ok()?;
    Some(VerifyingKey::<MlDsa44>::decode(&enc))
}

fn export(sk: &SigningKey<MlDsa44>) -> (SignPublicKey, SignSecretKey) {
    (SignPublicKey(sk.verifying_key().encode().to_vec()), SignSecretKey(sk.to_seed().to_vec()))
}

/// Fresh keypair from the operating-system CSPRNG (FIPS 204 ML-DSA.KeyGen).
pub fn keypair() -> (SignPublicKey, SignSecretKey) {
    let mut xi = [0u8; SECRET_SEED_BYTES];
    getrandom04::fill(&mut xi).expect("operating-system RNG unavailable");
    keypair_from_seed(&xi)
}

/// Deterministic keypair from `xi` (FIPS 204 ML-DSA.KeyGen_internal). Used by the
/// NIST known-answer tests and as the documented seam for future physical-PUF
/// provisioning; the simulator does not derive device keys from the simulated PUF.
pub fn keypair_from_seed(xi: &[u8; SECRET_SEED_BYTES]) -> (SignPublicKey, SignSecretKey) {
    export(&SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from(*xi)))
}

/// Derive the public key from a stored private key (used to check stored state).
pub fn public_from_secret(sk: &SignSecretKey) -> anyhow::Result<SignPublicKey> {
    Ok(export(&parse_sk(sk)?).0)
}

/// Hedged pure-ML-DSA signature over canonical transcript bytes, context = suite id.
pub fn sign_transcript(sk: &SignSecretKey, transcript: &[u8]) -> anyhow::Result<Signature> {
    let sk = parse_sk(sk)?;
    let mut rng = getrandom04::SysRng;
    let sig = sk
        .expanded_key()
        .sign_randomized(transcript, context(), &mut rng)
        .map_err(|_| anyhow::anyhow!("ML-DSA-44 signing failed"))?;
    Ok(Signature(sig.encode().to_vec()))
}

/// Verify a pure-ML-DSA signature with context = suite id. Malformed key or
/// signature encodings return `false`; nothing panics.
pub fn verify_transcript(pk: &SignPublicKey, transcript: &[u8], sig: &Signature) -> bool {
    let Some(vk) = parse_vk(pk) else { return false };
    let Ok(enc) = EncodedSignature::<MlDsa44>::try_from(sig.0.as_slice()) else { return false };
    let Some(sig) = DsaSignature::<MlDsa44>::decode(&enc) else { return false };
    vk.verify_with_context(transcript, context(), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_sizes() {
        let (pk, sk) = keypair();
        assert_eq!(pk.0.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sk.0.len(), SECRET_SEED_BYTES);
        assert_eq!(sign_transcript(&sk, b"x").unwrap().0.len(), SIGNATURE_BYTES);
        #[allow(deprecated)]
        {
            let k = parse_sk(&sk).unwrap();
            assert_eq!(k.expanded_key().to_expanded().len(), EXPANDED_SECRET_KEY_BYTES);
        }
    }

    #[test]
    fn sign_and_verify() {
        let (pk, sk) = keypair();
        let msg = b"authenticated transcript bytes";
        let sig = sign_transcript(&sk, msg).unwrap();
        assert!(verify_transcript(&pk, msg, &sig));
        assert_eq!(public_from_secret(&sk).unwrap(), pk);
        // hedged: two signatures over the same message differ, both verify
        let sig2 = sign_transcript(&sk, msg).unwrap();
        assert_ne!(sig.0, sig2.0);
        assert!(verify_transcript(&pk, msg, &sig2));
    }

    #[test]
    fn altered_transcript_fails_verification() {
        let (pk, sk) = keypair();
        let sig = sign_transcript(&sk, b"authenticated transcript bytes").unwrap();
        assert!(!verify_transcript(&pk, b"altered transcript bytes!!", &sig));
        assert!(!verify_transcript(&pk, b"", &sig));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let (_pk, sk) = keypair();
        let (other_pk, _other_sk) = keypair();
        let sig = sign_transcript(&sk, b"m").unwrap();
        assert!(!verify_transcript(&other_pk, b"m", &sig));
    }

    #[test]
    fn corrupted_signature_fails() {
        let (pk, sk) = keypair();
        let sig = sign_transcript(&sk, b"m").unwrap();
        for pos in [0usize, 31, 32, 1000, SIGNATURE_BYTES - 1] {
            let mut bad = sig.clone();
            bad.0[pos] ^= 0x01;
            assert!(!verify_transcript(&pk, b"m", &bad), "pos {pos}");
        }
    }

    #[test]
    fn malformed_encodings_are_rejected_without_panicking() {
        let (pk, sk) = keypair();
        let sig = sign_transcript(&sk, b"m").unwrap();
        assert!(!verify_transcript(&SignPublicKey(pk.0[..100].to_vec()), b"m", &sig));
        assert!(!verify_transcript(&SignPublicKey(vec![]), b"m", &sig));
        assert!(!verify_transcript(&pk, b"m", &Signature(sig.0[..SIGNATURE_BYTES - 1].to_vec())));
        assert!(!verify_transcript(&pk, b"m", &Signature(vec![0xFF; SIGNATURE_BYTES])));
        assert!(!verify_transcript(&pk, b"m", &Signature(vec![])));
        assert!(sign_transcript(&SignSecretKey(vec![0; 2528]), b"m").is_err(), "legacy Dilithium2-length private keys are not accepted");
        assert!(sign_transcript(&SignSecretKey(vec![0; 2560]), b"m").is_err(), "expanded keys are not the stored form");
    }

    #[test]
    fn signature_is_bound_to_the_suite_context() {
        let (pk, sk) = keypair();
        let k = parse_sk(&sk).unwrap();
        let other_ctx = k.expanded_key().sign_deterministic(b"m", b"iod-round3-kyber768-dilithium2-v0").unwrap();
        assert!(!verify_transcript(&pk, b"m", &Signature(other_ctx.encode().to_vec())));
        let no_ctx = k.expanded_key().sign_deterministic(b"m", b"").unwrap();
        assert!(!verify_transcript(&pk, b"m", &Signature(no_ctx.encode().to_vec())));
        let right = k.expanded_key().sign_deterministic(b"m", context()).unwrap();
        assert!(verify_transcript(&pk, b"m", &Signature(right.encode().to_vec())));
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        assert_eq!(format!("{:?}", keypair().1), "SignSecretKey(<redacted>)");
    }
}
