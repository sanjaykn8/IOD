//! Public-key commitment `comm_PK = SHAKE256(domain, PK_KEM, PK_Dil)`,
//! packed injectively into 11 BabyBear limbs. It is computed natively
//! (outside the circuit) from the SAME key bytes the protocol uses for
//! ML-KEM encapsulation and ML-DSA verification; the circuit proves the
//! leaf contains this commitment. See docs/zk-specification.md §4.

use crate::zkhash::{shake_limbs, Limbs};

pub const DOMAIN_COMM_PK: &[u8] = b"IOD/v2/COMM-PK";

pub fn comm_pk(pk_kem: &[u8], pk_dil: &[u8]) -> Limbs {
    shake_limbs(DOMAIN_COMM_PK, &[pk_kem, pk_dil])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sensitive_to_inputs() {
        assert_eq!(comm_pk(b"kem-a", b"dil-a"), comm_pk(b"kem-a", b"dil-a"));
        assert_ne!(comm_pk(b"kem-a", b"dil-a"), comm_pk(b"kem-b", b"dil-a"));
        assert_ne!(comm_pk(b"kem-a", b"dil-a"), comm_pk(b"kem-a", b"dil-b"));
    }

    #[test]
    fn no_concatenation_ambiguity() {
        assert_ne!(comm_pk(b"AB", b"C"), comm_pk(b"A", b"BC"));
    }
}
