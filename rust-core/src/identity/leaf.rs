//! Merkle leaf: Poseidon2-BabyBear sponge over the fixed 48-limb stream
//! `[format, G(11), comm_PK(11), meta(11), rho(8), 0*6]`.

use super::group_id::group_digest;
use super::metadata::MembershipMetadata;
use crate::zkhash::{leaf_hash, Digest, Limbs, RHO_LIMBS};

pub fn compute_leaf(
    comm_pk: &Limbs,
    group_id: &str,
    metadata: &MembershipMetadata,
    rho: &[u32; RHO_LIMBS],
) -> Digest {
    leaf_hash(&group_digest(group_id), comm_pk, &metadata.digest(), rho)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::commitment::comm_pk;

    fn md() -> MembershipMetadata {
        MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 }
    }

    #[test]
    fn deterministic_and_binds_every_field() {
        let c = comm_pk(b"k", b"d");
        let rho = [1u32; 8];
        let base = compute_leaf(&c, "alpha", &md(), &rho);
        assert_eq!(base, compute_leaf(&c, "alpha", &md(), &rho));
        assert_ne!(base, compute_leaf(&comm_pk(b"k2", b"d"), "alpha", &md(), &rho));
        assert_ne!(base, compute_leaf(&c, "bravo", &md(), &rho));
        assert_ne!(base, compute_leaf(&c, "alpha", &md(), &[2u32; 8]));
        let mut m2 = md();
        m2.role = "leader".into();
        assert_ne!(base, compute_leaf(&c, "alpha", &m2, &rho));
    }
}
