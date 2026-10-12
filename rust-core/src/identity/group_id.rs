//! Canonical mapping group id string -> 11 BabyBear limbs (SHAKE256,
//! domain separated, injective packing). Used as public input `G`.

use crate::zkhash::{shake_limbs, Limbs};

pub const DOMAIN_GROUP: &[u8] = b"IOD/v2/GROUP";

pub fn group_digest(group_id: &str) -> Limbs {
    shake_limbs(DOMAIN_GROUP, &[group_id.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct() {
        assert_eq!(group_digest("alpha"), group_digest("alpha"));
        assert_ne!(group_digest("alpha"), group_digest("bravo"));
    }
}
