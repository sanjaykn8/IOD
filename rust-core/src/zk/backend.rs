//! `TransparentSimulationBackend`: the concrete (documented-limitations)
//! ZK backend used by this project. See `zk` module docs for the full
//! honest security-property breakdown before relying on anything here.

use super::statement::ZkStatement;
use super::witness::ZkWitness;
use crate::crypto::canonical::{encode_bytes, encode_record};
use crate::crypto::domains::{
    POSEIDON_PK_COMMITMENT, POSEIDON_ZK_FS_CHALLENGE, POSEIDON_ZK_WITNESS_COMMITMENT,
};
use crate::crypto::field::Fp;
use crate::crypto::poseidon;
use crate::merkle::tree::{verify_witness, MerkleWitness};
use rand::RngCore;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WitnessOpening {
    pub leaf: Fp,
    pub siblings: Vec<Fp>,
    pub path_indices: Vec<u8>,
    pub pk_kem: Vec<u8>,
    pub pk_dil: Vec<u8>,
    pub metadata: crate::identity::metadata::MembershipMetadata,
    pub rho: [u8; 32],
    /// Fresh randomness mixed into `witness_commitment` (see
    /// `zk` module docs: NOT a zero-knowledge hiding mechanism once this
    /// `opening` travels with the proof — see `ZkProof` docs).
    pub blinding: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkProof {
    /// Poseidon commitment to the full witness + `opening.blinding`.
    /// Genuinely hiding *in isolation* (without the opening); see module
    /// docs for why this backend nonetheless discloses the opening.
    pub witness_commitment: Fp,
    /// Fiat-Shamir challenge binding this proof to the exact
    /// (G, R_G, V_G, comm_PK) tuple it was generated against.
    pub fs_challenge: Fp,
    pub opening: WitnessOpening,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ZkError {
    #[error("witness leaf does not match Poseidon(PK_KEM, PK_Dil, G, metadata, rho)")]
    LeafMismatch,
    #[error("witness PK commitment does not match the public comm_PK input")]
    CommitmentMismatch,
    #[error("Merkle path does not fold to the public root R_G")]
    MerklePathInvalid,
}

fn witness_commitment_fields(opening: &WitnessOpening) -> Vec<Fp> {
    encode_record(&[
        vec![opening.leaf],
        opening.siblings.clone(),
        opening
            .path_indices
            .iter()
            .map(|b| Fp::new(*b as u64))
            .collect(),
        encode_bytes(&opening.pk_kem),
        encode_bytes(&opening.pk_dil),
        opening.metadata.to_field_vec(),
        encode_bytes(&opening.rho),
        encode_bytes(&opening.blinding),
    ])
}

fn compute_witness_commitment(opening: &WitnessOpening) -> Fp {
    poseidon::hash(
        POSEIDON_ZK_WITNESS_COMMITMENT,
        &witness_commitment_fields(opening),
    )
}

fn compute_fs_challenge(statement: &ZkStatement, witness_commitment: Fp) -> Fp {
    poseidon::hash(
        POSEIDON_ZK_FS_CHALLENGE,
        &[
            statement.g,
            statement.r_g,
            statement.v_g_field(),
            statement.comm_pk,
            witness_commitment,
        ],
    )
}

/// Run every real algebraic check the relation requires. Used by both
/// `prove` (so a prover can never emit a proof for an inconsistent
/// witness — "do not fabricate results") and `verify` (so a verifier
/// never has to trust the prover ran this honestly). The leaf
/// recomputation uses `statement.g` — the VERIFIER's trusted group field
/// element — via `leaf_field_check` below, which is precisely the
/// G_public/G_witness binding spec correction #3 requires: there is no
/// separate "G_witness" copy anywhere for a malicious prover to splice.
fn check_relation(statement: &ZkStatement, opening: &WitnessOpening) -> Result<(), ZkError> {
    if leaf_field_check(statement.g, opening) != opening.leaf {
        return Err(ZkError::LeafMismatch);
    }
    let comm_check = poseidon::hash(
        POSEIDON_PK_COMMITMENT,
        &encode_record(&[encode_bytes(&opening.pk_kem), encode_bytes(&opening.pk_dil)]),
    );
    if comm_check != statement.comm_pk {
        return Err(ZkError::CommitmentMismatch);
    }
    let mw = MerkleWitness {
        siblings: opening.siblings.clone(),
        path_indices: opening.path_indices.clone(),
        leaf_index: 0, // not needed for verification, only for regeneration bookkeeping
    };
    if !verify_witness(statement.r_g, opening.leaf, &mw) {
        return Err(ZkError::MerklePathInvalid);
    }
    Ok(())
}

/// Field-level leaf recomputation using an already-canonical group field
/// element (`g`), rather than `identity::leaf::compute_leaf`'s
/// string-keyed API. Kept in this module (not `identity::leaf`) because
/// it is specifically the G_public/G_witness-binding recomputation the
/// ZK verifier performs.
fn leaf_field_check(g: Fp, opening: &WitnessOpening) -> Fp {
    use crate::crypto::domains::POSEIDON_LEAF;
    let fields = encode_record(&[
        encode_bytes(&opening.pk_kem),
        encode_bytes(&opening.pk_dil),
        vec![g],
        opening.metadata.to_field_vec(),
        encode_bytes(&opening.rho),
    ]);
    poseidon::hash(POSEIDON_LEAF, &fields)
}

pub fn prove(statement: &ZkStatement, witness: &ZkWitness) -> Result<ZkProof, ZkError> {
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding);
    let opening = WitnessOpening {
        leaf: witness.leaf,
        siblings: witness.siblings.clone(),
        path_indices: witness.path_indices.clone(),
        pk_kem: witness.pk_kem.clone(),
        pk_dil: witness.pk_dil.clone(),
        metadata: witness.metadata.clone(),
        rho: witness.rho,
        blinding,
    };
    // The prover itself must never be able to emit a proof for an
    // inconsistent witness (this is a real, executed check — not
    // skipped for "the honest case").
    check_relation(statement, &opening)?;

    let witness_commitment = compute_witness_commitment(&opening);
    let fs_challenge = compute_fs_challenge(statement, witness_commitment);
    Ok(ZkProof {
        witness_commitment,
        fs_challenge,
        opening,
    })
}

pub fn verify(statement: &ZkStatement, proof: &ZkProof) -> bool {
    // 1. Binding check: the opening must match the committed value
    //    (catches any post-hoc tampering with the transmitted opening).
    let recomputed_commitment = compute_witness_commitment(&proof.opening);
    if recomputed_commitment != proof.witness_commitment {
        return false;
    }
    // 2. Fiat-Shamir / session-context check, using the VERIFIER's own
    //    trusted `statement` (which must be independently obtained, not
    //    taken from the proof) — this is what makes a stale V_G/R_G
    //    reject even if the rest of the proof is internally consistent.
    let recomputed_challenge = compute_fs_challenge(statement, proof.witness_commitment);
    if recomputed_challenge != proof.fs_challenge {
        return false;
    }
    // 3. The real algebraic relation.
    check_relation(statement, &proof.opening).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::commitment::compute_commitment;
    use crate::identity::group_id::group_field;
    use crate::identity::leaf::compute_leaf;
    use crate::identity::metadata::MembershipMetadata;
    use crate::merkle::group_tree::GroupMembershipTree;

    fn setup() -> (ZkStatement, ZkWitness, GroupMembershipTree) {
        let md = MembershipMetadata {
            role: "recon".into(),
            issued_at_unix: 1_700_000_000,
        };
        let rho = [7u8; 32];
        let pk_kem = b"pk-kem-bytes-demo".to_vec();
        let pk_dil = b"pk-dil-bytes-demo".to_vec();
        let group_id = "alpha";
        let leaf = compute_leaf(&pk_kem, &pk_dil, group_id, &md, &rho);
        let comm_pk = compute_commitment(&pk_kem, &pk_dil);

        let mut tree = GroupMembershipTree::new(group_id, 4);
        tree.register("drone-1", leaf).unwrap();
        tree.register("drone-2", compute_leaf(b"other-kem", b"other-dil", group_id, &md, &[9u8; 32]))
            .unwrap();
        let mw = tree.witness_for("drone-1").unwrap();

        let statement = ZkStatement {
            g: group_field(group_id),
            r_g: tree.root(),
            v_g: tree.version,
            comm_pk,
        };
        let witness = ZkWitness {
            leaf,
            siblings: mw.siblings,
            path_indices: mw.path_indices,
            pk_kem,
            pk_dil,
            metadata: md,
            rho,
        };
        (statement, witness, tree)
    }

    #[test]
    fn honest_proof_verifies() {
        let (statement, witness, _tree) = setup();
        let proof = prove(&statement, &witness).unwrap();
        assert!(verify(&statement, &proof));
    }

    #[test]
    fn tampered_opening_after_the_fact_is_rejected() {
        let (statement, witness, _tree) = setup();
        let mut proof = prove(&statement, &witness).unwrap();
        proof.opening.rho[0] ^= 0xFF; // tamper post-hoc
        assert!(!verify(&statement, &proof), "tampered opening must be rejected by the commitment-binding check");
    }

    #[test]
    fn wrong_root_is_rejected() {
        let (mut statement, witness, _tree) = setup();
        let proof = prove(&statement, &witness).unwrap();
        statement.r_g = Fp::new(statement.r_g.0.wrapping_add(1));
        assert!(!verify(&statement, &proof));
    }

    #[test]
    fn stale_version_is_rejected_even_if_root_unchanged_in_the_proof() {
        // This directly tests spec correction #4/#5: V_G must actually
        // bind the proof, not merely appear as an unused input.
        let (statement, witness, _tree) = setup();
        let proof = prove(&statement, &witness).unwrap();
        assert!(verify(&statement, &proof));

        let mut stale_check_statement = statement;
        stale_check_statement.v_g += 1; // verifier's own current V_G has advanced
        assert!(
            !verify(&stale_check_statement, &proof),
            "a verifier with a newer V_G must reject a proof generated against the old version"
        );
    }

    #[test]
    fn wrong_group_is_rejected() {
        let (statement, witness, _tree) = setup();
        let proof = prove(&statement, &witness).unwrap();
        let mut wrong_group_statement = statement;
        wrong_group_statement.g = group_field("bravo");
        assert!(!verify(&wrong_group_statement, &proof));
    }

    #[test]
    fn revoked_member_fails_to_prove_against_the_current_root() {
        let (mut statement, witness, mut tree) = setup();
        tree.revoke("drone-1").unwrap();
        statement.r_g = tree.root();
        statement.v_g = tree.version;
        // The (now-stale) witness no longer folds to the new root.
        assert_eq!(prove(&statement, &witness).unwrap_err(), ZkError::MerklePathInvalid);
    }

    #[test]
    fn cannot_prove_with_an_inconsistent_witness() {
        let (statement, mut witness, _tree) = setup();
        witness.rho = [0u8; 32]; // wrong rho => leaf won't match
        assert_eq!(prove(&statement, &witness).unwrap_err(), ZkError::LeafMismatch);
    }

    #[test]
    fn wrong_commitment_in_statement_is_rejected() {
        let (mut statement, witness, _tree) = setup();
        statement.comm_pk = Fp::new(statement.comm_pk.0.wrapping_add(1));
        assert_eq!(prove(&statement, &witness).unwrap_err(), ZkError::CommitmentMismatch);
    }
}
