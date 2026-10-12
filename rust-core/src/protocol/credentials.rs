//! GCS-signed credentials (ML-DSA, no ECC certificates).
//!
//! Every drone holds the GCS ML-DSA public key as its pinned **trust
//! anchor** (installed at enrollment, R3). A `SignedCredential` binds a
//! pseudonymous credential id to the drone's ML-KEM and ML-DSA public
//! keys, its commitment `comm_PK`, its group and metadata. Verifiers
//! always take keys from a verified credential, never from the message
//! that is being verified.

use crate::crypto::sign::{self, SignPublicKey, SignSecretKey, Signature};
use crate::identity::metadata::MembershipMetadata;
use crate::protocol::canon::Canon;
use crate::zkhash::Limbs;
use serde::{Deserialize, Serialize};

pub const CRED_VERSION: u32 = 2;
pub const CRED_VALIDITY_MS: u64 = 30 * 24 * 3600 * 1000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialBody {
    pub version: u32,
    /// Random pseudonymous identifier; NOT the permanent DroneID.
    pub cred_id: [u8; 16],
    pub group_id: String,
    pub pk_kem: Vec<u8>,
    pub pk_dil: Vec<u8>,
    pub comm_pk: Limbs,
    pub metadata: MembershipMetadata,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl CredentialBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("CREDENTIAL");
        c.u32(self.version)
            .bytes(&self.cred_id)
            .str(&self.group_id)
            .bytes(&self.pk_kem)
            .bytes(&self.pk_dil)
            .limbs(&self.comm_pk)
            .str(&self.metadata.role)
            .u64(self.metadata.issued_at_unix)
            .u64(self.issued_at_ms)
            .u64(self.expires_at_ms);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCredential {
    pub body: CredentialBody,
    pub sig: Vec<u8>,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CredentialError {
    #[error("credential signature invalid (not issued by the pinned GCS trust anchor)")]
    BadSignature,
    #[error("credential expired or not yet valid")]
    Expired,
    #[error("credential version unsupported")]
    Version,
    #[error("credential commitment does not match its public keys")]
    CommitmentMismatch,
}

pub fn issue(gcs_sk: &SignSecretKey, body: CredentialBody) -> anyhow::Result<SignedCredential> {
    let sig = sign::sign_transcript(gcs_sk, &body.signing_bytes())?;
    Ok(SignedCredential { body, sig: sig.0 })
}

impl SignedCredential {
    /// Verify against the pinned GCS trust anchor, the clock, and the
    /// internal consistency of comm_PK with the embedded keys.
    pub fn verify(&self, trust_anchor: &SignPublicKey, now_ms: u64) -> Result<(), CredentialError> {
        if self.body.version != CRED_VERSION {
            return Err(CredentialError::Version);
        }
        if !sign::verify_transcript(trust_anchor, &self.body.signing_bytes(), &Signature(self.sig.clone())) {
            return Err(CredentialError::BadSignature);
        }
        if now_ms < self.body.issued_at_ms.saturating_sub(crate::protocol::MAX_TIMESTAMP_SKEW_MS as u64)
            || now_ms > self.body.expires_at_ms
        {
            return Err(CredentialError::Expired);
        }
        if crate::identity::commitment::comm_pk(&self.body.pk_kem, &self.body.pk_dil) != self.body.comm_pk {
            return Err(CredentialError::CommitmentMismatch);
        }
        Ok(())
    }

    pub fn pk_dil(&self) -> SignPublicKey {
        SignPublicKey(self.body.pk_dil.clone())
    }
    pub fn pk_kem(&self) -> crate::crypto::kem::KemPublicKey {
        crate::crypto::kem::KemPublicKey(self.body.pk_kem.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::commitment::comm_pk;

    fn body(now: u64) -> (CredentialBody, SignPublicKey, SignSecretKey) {
        let (kpk, _) = crate::crypto::kem::keypair();
        let (dpk, _) = sign::keypair();
        let (apk, ask) = sign::keypair();
        (
            CredentialBody {
                version: CRED_VERSION,
                cred_id: [3; 16],
                group_id: "alpha".into(),
                comm_pk: comm_pk(&kpk.0, &dpk.0),
                pk_kem: kpk.0,
                pk_dil: dpk.0,
                metadata: MembershipMetadata { role: "recon".into(), issued_at_unix: 1 },
                issued_at_ms: now,
                expires_at_ms: now + 1000,
            },
            apk,
            ask,
        )
    }

    #[test]
    fn valid_credential_verifies_and_rejects_every_tamper() {
        let now = 1_700_000_000_000u64;
        let (b, anchor, sk) = body(now);
        let c = issue(&sk, b).unwrap();
        assert_eq!(c.verify(&anchor, now + 10), Ok(()));
        // wrong anchor
        let (other, _) = sign::keypair();
        assert_eq!(c.verify(&other, now + 10), Err(CredentialError::BadSignature));
        // expired / not yet valid
        assert_eq!(c.verify(&anchor, now + 5000), Err(CredentialError::Expired));
        assert_eq!(c.verify(&anchor, now - 10 * 60 * 1000), Err(CredentialError::Expired));
        // tampered fields invalidate the signature
        let mut t = c.clone();
        t.body.group_id = "bravo".into();
        assert_eq!(t.verify(&anchor, now + 10), Err(CredentialError::BadSignature));
        let mut t = c.clone();
        t.body.pk_dil[0] ^= 1;
        assert_eq!(t.verify(&anchor, now + 10), Err(CredentialError::BadSignature));
        let mut t = c.clone();
        t.body.version = 1;
        assert_eq!(t.verify(&anchor, now + 10), Err(CredentialError::Version));
    }

    #[test]
    fn issuer_cannot_certify_inconsistent_commitment() {
        let now = 1_700_000_000_000u64;
        let (mut b, anchor, sk) = body(now);
        b.comm_pk[0] ^= 1;
        let c = issue(&sk, b).unwrap();
        assert_eq!(c.verify(&anchor, now + 10), Err(CredentialError::CommitmentMismatch));
    }
}
