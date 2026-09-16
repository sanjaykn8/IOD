//! Public-key commitment: comm_PK_D = Poseidon(0x02, PK_KEM, PK_Dil)
//!
//! This is the same PK_KEM/PK_Dil bytes used (a) inside the leaf, and
//! (b) for real Dilithium/ML-DSA signature verification elsewhere in the
//! protocol — enforced by construction, since every call site sources
//! these bytes from the same `identity::keys::DeviceKeys` public-key
//! fields, preventing proof/key splicing (spec requirement: "the public
//! keys used to construct the commitment must be the same public keys
//! used by the protocol for Dilithium/ML-DSA verification").

use crate::crypto::canonical::{encode_bytes, encode_record};
use crate::crypto::domains::POSEIDON_PK_COMMITMENT;
use crate::crypto::field::Fp;
use crate::crypto::poseidon;

pub fn compute_commitment(pk_kem_bytes: &[u8], pk_dil_bytes: &[u8]) -> Fp {
    let fields = encode_record(&[encode_bytes(pk_kem_bytes), encode_bytes(pk_dil_bytes)]);
    poseidon::hash(POSEIDON_PK_COMMITMENT, &fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sensitive_to_inputs() {
        let a = compute_commitment(b"kem-a", b"dil-a");
        let b = compute_commitment(b"kem-a", b"dil-a");
        assert_eq!(a, b);
        let c = compute_commitment(b"kem-b", b"dil-a");
        assert_ne!(a, c);
    }

    #[test]
    fn distinct_from_leaf_domain() {
        // Same raw bytes must not collide between the leaf domain and
        // the commitment domain, by construction (different Poseidon
        // domain tags absorbed).
        use crate::identity::leaf::compute_leaf;
        use crate::identity::metadata::MembershipMetadata;
        let md = MembershipMetadata {
            role: "r".into(),
            issued_at_unix: 1,
        };
        let rho = [0u8; 32];
        let leaf = compute_leaf(b"kem-a", b"dil-a", "g", &md, &rho);
        let comm = compute_commitment(b"kem-a", b"dil-a");
        assert_ne!(leaf, comm);
    }
}
