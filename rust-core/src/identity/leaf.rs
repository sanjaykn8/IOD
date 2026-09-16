//! Merkle-leaf construction:
//!   L_D,G = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)
//! using the canonical, length-prefixed encoding throughout (see
//! `crypto::canonical` and `identity::group_id`).

use super::group_id::group_field;
use super::metadata::MembershipMetadata;
use crate::crypto::canonical::{encode_bytes, encode_record};
use crate::crypto::domains::POSEIDON_LEAF;
use crate::crypto::field::Fp;
use crate::crypto::poseidon;

pub fn compute_leaf(
    pk_kem_bytes: &[u8],
    pk_dil_bytes: &[u8],
    group_id: &str,
    metadata: &MembershipMetadata,
    rho: &[u8; 32],
) -> Fp {
    let fields = encode_record(&[
        encode_bytes(pk_kem_bytes),
        encode_bytes(pk_dil_bytes),
        vec![group_field(group_id)],
        metadata.to_field_vec(),
        encode_bytes(rho),
    ]);
    poseidon::hash(POSEIDON_LEAF, &fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md() -> MembershipMetadata {
        MembershipMetadata {
            role: "recon".to_string(),
            issued_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn deterministic() {
        let rho = [1u8; 32];
        let a = compute_leaf(b"pk-kem", b"pk-dil", "alpha", &md(), &rho);
        let b = compute_leaf(b"pk-kem", b"pk-dil", "alpha", &md(), &rho);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_any_field_changes_leaf() {
        let rho = [1u8; 32];
        let base = compute_leaf(b"pk-kem", b"pk-dil", "alpha", &md(), &rho);
        assert_ne!(base, compute_leaf(b"pk-kem-2", b"pk-dil", "alpha", &md(), &rho));
        assert_ne!(base, compute_leaf(b"pk-kem", b"pk-dil-2", "alpha", &md(), &rho));
        assert_ne!(base, compute_leaf(b"pk-kem", b"pk-dil", "bravo", &md(), &rho));
        assert_ne!(base, compute_leaf(b"pk-kem", b"pk-dil", "alpha", &md(), &[2u8; 32]));
        let mut md2 = md();
        md2.role = "leader".to_string();
        assert_ne!(base, compute_leaf(b"pk-kem", b"pk-dil", "alpha", &md2, &rho));
    }
}
