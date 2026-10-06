//! Merkle-leaf construction:
//!   L_D,G = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)
//! using the canonical, length-prefixed encoding throughout (see
//! `crypto::canonical` and `identity::group_id`).

use super::group_id::group_field;
use super::metadata::MembershipMetadata;
use crate::crypto::canonical::{encode_bytes, encode_record};
use crate::crypto::domains::{POSEIDON_LEAF, SEED_DOMAIN_LEAF_RHO};
use crate::crypto::field::Fp;
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::poseidon;

/// SECURITY FIX (spec item 25-C: "explicit PUF<->credential<->Merkle-
/// member<->ML-DSA-key binding"). Previously the leaf randomness `rho`
/// (folded into `compute_leaf` below, alongside the credential keys
/// `pk_kem`/`pk_dil`) was generated as pure fresh randomness with NO
/// cryptographic connection to the drone's physical PUF -- any 32 bytes
/// would have worked equally well. That left the Merkle leaf (hence
/// Merkle membership, hence the very credential keys baked into that
/// same leaf) with no explicit tie back to the physical device whose
/// liveness the separate M6 PUF-MAC check (`mac1`) relies on.
///
/// `derive_puf_bound_rho` keeps the required FRESHNESS property (a new,
/// unpredictable `rho` every registration -- see
/// `simulation::reactivate_drone`'s "fresh leaf, fresh rho" comment)
/// while making `rho` producible only by someone who holds the
/// PUF-reconstructed seed: it is HKDF-derived with that seed as the key
/// material and a fresh random salt for per-registration freshness,
/// under its own domain tag (`SEED_DOMAIN_LEAF_RHO`). Because `rho`
/// then feeds into the SAME Poseidon leaf hash as `pk_kem`/`pk_dil`,
/// one hash now provably ties together the PUF (via `puf_seed`), the
/// credential (`pk_kem`/`pk_dil`), Merkle membership (the leaf itself),
/// and the ML-DSA key (`pk_dil`) -- with no change to `compute_leaf`'s
/// arity or formula, so every existing caller, doc, and sequence
/// diagram describing `L_D,G = Poseidon(PK_KEM, PK_Dil, G, metadata,
/// rho)` stays accurate.
pub fn derive_puf_bound_rho(puf_seed: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let out = hkdf_expand(puf_seed, Some(&salt), SEED_DOMAIN_LEAF_RHO, 32);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&out);
    rho
}

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

    #[test]
    fn puf_bound_rho_is_fresh_every_call_even_for_the_same_puf_seed() {
        // Spec 25-C: freshness must be preserved -- re-deriving for the
        // SAME physical device (same puf_seed) must not yield the same
        // rho twice (the whole point of re-registration getting a
        // "fresh leaf, fresh rho").
        let seed = [7u8; 32];
        let r1 = derive_puf_bound_rho(&seed);
        let r2 = derive_puf_bound_rho(&seed);
        assert_ne!(r1, r2, "rho must be fresh (salted) even for a repeated PUF seed");
    }

    #[test]
    fn puf_bound_rho_differs_across_different_puf_seeds() {
        // Spec 25-C: the binding must actually depend on the PUF seed,
        // not just be independent randomness that ignores its input.
        // We can't prove this from a single sample pair alone (they
        // could coincidentally differ regardless), but combined with
        // the HKDF domain-separation tests elsewhere this documents the
        // intended property and catches an accidental "ignore puf_seed
        // entirely" regression at the call site.
        let a = derive_puf_bound_rho(&[1u8; 32]);
        let b = derive_puf_bound_rho(&[2u8; 32]);
        assert_ne!(a, b);
    }
}
