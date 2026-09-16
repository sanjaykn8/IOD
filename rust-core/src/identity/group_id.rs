//! Canonical mapping from a human-readable group identifier to a single
//! Poseidon-domain field element.
//!
//! IMPLEMENTATION CORRECTION (documented, spec-preserving): the
//! specification's leaf formula folds `G` directly into
//! `Poseidon(0x01 || PK_KEM || PK_Dil || G || metadata || rho)`. Taken
//! literally, `G` is a variable-length byte string (a group name/ID),
//! and mixing a variable-length string directly into a fixed-arity
//! Poseidon call without a fixed encoding is exactly the "do not
//! concatenate variable-length byte arrays ambiguously" problem the
//! project brief calls out. We resolve this by mapping every group
//! identifier to a single canonical field element via a dedicated
//! Poseidon domain (`POSEIDON_GROUP_ID`) applied to the canonically
//! length-prefixed byte encoding of the group ID string. This single
//! field element (`group_field`) is then used consistently everywhere
//! `G` appears: inside the leaf hash, inside the PK commitment context
//! (not used there per spec, only PK_KEM/PK_Dil), as the ZK circuit's
//! public input `G_public`, and inside signed transcripts. This
//! preserves the protocol's data flow and security property (two
//! different group IDs still yield different leaves/roots/transcripts)
//! while making the encoding unambiguous and canonical.

use crate::crypto::canonical::encode_bytes;
use crate::crypto::domains::POSEIDON_GROUP_ID;
use crate::crypto::field::Fp;
use crate::crypto::poseidon;

pub fn group_field(group_id: &str) -> Fp {
    poseidon::hash(POSEIDON_GROUP_ID, &encode_bytes(group_id.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(group_field("alpha"), group_field("alpha"));
    }

    #[test]
    fn distinct_groups_differ() {
        assert_ne!(group_field("alpha"), group_field("bravo"));
    }
}
