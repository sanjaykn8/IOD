//! Canonical transcript construction for `T_base` (PUF-MAC) and `T`
//! (the Dilithium-signed authentication transcript).
//!
//! Both use `crypto::kdf::shake256_transcript`, which length-prefixes
//! every segment before hashing — this is the "do not sign vague JSON
//! strings without canonicalization" requirement in concrete form: the
//! signer and verifier both build these bytes from the same explicit,
//! ordered list of fixed-width/length-prefixed fields, so there is no
//! possible reordering or re-encoding ambiguity between them.

use crate::crypto::domains::{TRANSCRIPT_AUTH, TRANSCRIPT_BASE_PUF};
use crate::crypto::field::Fp;
use crate::crypto::kdf::shake256_transcript;

pub fn build_t_base(
    g: Fp,
    v_g: u64,
    r_g: Fp,
    comm_pk_d1: Fp,
    n1: &[u8],
    n2: &[u8],
    ts1: u64,
    ts4: u64,
    pid1: &[u8],
) -> [u8; 32] {
    shake256_transcript(
        TRANSCRIPT_BASE_PUF,
        &[
            &g.to_bytes_le(),
            &v_g.to_le_bytes(),
            &r_g.to_bytes_le(),
            &comm_pk_d1.to_bytes_le(),
            n1,
            n2,
            &ts1.to_le_bytes(),
            &ts4.to_le_bytes(),
            pid1,
        ],
    )
}

/// `T = SHAKE256("AuthTranscript" || G || V_G || R_G || comm_PK_D1 ||
/// proof_ZK || N1 || N2 || TS1 || TS4 || PID1)`.
///
/// `proof_zk_digest` is the SHA-independent digest of the serialized
/// `ZkProof` (see `protocol::messages::digest_zk_proof`) rather than the
/// raw proof bytes, per the specification's own "(or its hash if large)"
/// allowance — this keeps the signed transcript a fixed, small size
/// regardless of proof size, while still cryptographically binding the
/// exact proof that was presented (any change to the proof changes its
/// digest, which changes `T`, which invalidates `sig1`).
#[allow(clippy::too_many_arguments)]
pub fn build_auth_transcript(
    g: Fp,
    v_g: u64,
    r_g: Fp,
    comm_pk_d1: Fp,
    proof_zk_digest: &[u8; 32],
    n1: &[u8],
    n2: &[u8],
    ts1: u64,
    ts4: u64,
    pid1: &[u8],
) -> [u8; 32] {
    shake256_transcript(
        TRANSCRIPT_AUTH,
        &[
            &g.to_bytes_le(),
            &v_g.to_le_bytes(),
            &r_g.to_bytes_le(),
            &comm_pk_d1.to_bytes_le(),
            proof_zk_digest,
            n1,
            n2,
            &ts1.to_le_bytes(),
            &ts4.to_le_bytes(),
            pid1,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_base_deterministic() {
        let a = build_t_base(Fp::new(1), 2, Fp::new(3), Fp::new(4), b"n1", b"n2", 5, 6, b"pid");
        let b = build_t_base(Fp::new(1), 2, Fp::new(3), Fp::new(4), b"n1", b"n2", 5, 6, b"pid");
        assert_eq!(a, b);
    }

    #[test]
    fn t_base_sensitive_to_version() {
        let a = build_t_base(Fp::new(1), 2, Fp::new(3), Fp::new(4), b"n1", b"n2", 5, 6, b"pid");
        let b = build_t_base(Fp::new(1), 3, Fp::new(3), Fp::new(4), b"n1", b"n2", 5, 6, b"pid");
        assert_ne!(a, b, "T_base must change when V_G changes (version binding)");
    }

    #[test]
    fn auth_transcript_sensitive_to_proof_digest() {
        let a = build_auth_transcript(Fp::new(1), 2, Fp::new(3), Fp::new(4), &[0u8; 32], b"n1", b"n2", 5, 6, b"pid");
        let b = build_auth_transcript(Fp::new(1), 2, Fp::new(3), Fp::new(4), &[1u8; 32], b"n1", b"n2", 5, 6, b"pid");
        assert_ne!(a, b);
    }
}
