//! Witness-hiding, transparent, non-ECC proof of group membership.
//!
//! Construction: a zero-knowledge STARK (AIR + hiding FRI) from Plonky3
//! 0.9.0-rc.1: random masking of every committed polynomial, a randomizing
//! codeword, and Merkle-tree commitments with salted leaves
//! (Haböck, "A note on adding zero-knowledge to STARKs", ePrint 2024/1037).
//! All hashing is Keccak-256 (commitments, Fiat–Shamir) and Poseidon2 over
//! BabyBear (statement hash). No pairing, no elliptic curve, no trusted
//! setup. See `docs/zk-design.md` and `docs/zk-security-analysis.md`.
//!
//! The proof carries NO witness field: the prover never serializes `rho`,
//! the siblings or the path bits. Only the STARK transcript is sent.

pub mod air;
mod config;

use crate::zkhash::*;
use air::*;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 2;
pub use config::{security_estimate, security_report, SecurityEstimate, ZkParams};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPublicInputs {
    pub protocol_version: u32,
    /// V_G, the group-tree version this root corresponds to.
    pub group_version: u32,
    /// G: SHAKE256-derived group digest limbs.
    pub group_digest: Limbs,
    pub root: Digest,
    /// comm_PK_D1 = SHAKE256(PK_KEM_D1, PK_Dil_D1) limbs.
    pub comm_pk: Limbs,
    /// Digest of the (public) membership metadata bound into the leaf.
    pub metadata_digest: Limbs,
    /// Domain-separated digest of the session context (see spec §6).
    pub session_digest: Limbs,
}

impl MembershipPublicInputs {
    /// Canonical ordered public-value vector (54 field elements).
    pub fn to_field_vec(&self) -> Result<Vec<Bb>, ZkError> {
        if self.group_version >= P || self.protocol_version >= P {
            return Err(ZkError::OutOfRange);
        }
        let all = [
            &self.group_digest,
            &self.comm_pk,
            &self.metadata_digest,
            &self.session_digest,
        ];
        if all.iter().any(|l| l.iter().any(|&x| x >= P)) || self.root.0.iter().any(|&x| x >= P) {
            return Err(ZkError::OutOfRange);
        }
        let mut v = Vec::with_capacity(NUM_PV);
        v.push(bb(self.protocol_version));
        v.push(bb(self.group_version));
        v.extend(self.group_digest.iter().map(|&x| bb(x)));
        v.extend(self.root.to_bb());
        v.extend(self.comm_pk.iter().map(|&x| bb(x)));
        v.extend(self.metadata_digest.iter().map(|&x| bb(x)));
        v.extend(self.session_digest.iter().map(|&x| bb(x)));
        debug_assert_eq!(v.len(), NUM_PV);
        Ok(v)
    }
}

/// Private witness. Deliberately NOT `Serialize`; `Debug` is redacted.
pub struct MembershipPrivateWitness {
    pub rho: [u32; RHO_LIMBS],
    pub siblings: Vec<Digest>,
    /// path_bits[i] == true: the current node is the RIGHT child at level i.
    pub path_bits: Vec<bool>,
}

impl core::fmt::Debug for MembershipPrivateWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MembershipPrivateWitness(<redacted>)")
    }
}

impl Drop for MembershipPrivateWitness {
    fn drop(&mut self) {
        self.rho = [0; RHO_LIMBS];
        for s in self.siblings.iter_mut() {
            *s = Digest::ZERO;
        }
        for b in self.path_bits.iter_mut() {
            *b = false;
        }
    }
}

/// Opaque serialized proof: `magic(4) || param_id(1) || postcard(STARK proof)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipProof {
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl MembershipProof {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ZkError {
    #[error("public input out of canonical range")]
    OutOfRange,
    #[error("witness does not satisfy the membership relation: {0}")]
    InvalidWitness(&'static str),
    #[error("proving failed: {0}")]
    Prover(String),
    #[error("malformed proof encoding")]
    Malformed,
    #[error("proof verification failed")]
    Rejected,
    #[error("unsupported protocol/proof version")]
    Version,
}

const MAGIC: &[u8; 4] = b"IMP2";

/// Check the relation natively (prover-side sanity; never sent anywhere).
fn check_relation(
    params: &ZkParams,
    pi: &MembershipPublicInputs,
    w: &MembershipPrivateWitness,
) -> Result<[Bb; LEAF_STREAM_LEN], ZkError> {
    if w.siblings.len() != params.depth || w.path_bits.len() != params.depth {
        return Err(ZkError::InvalidWitness("path length != tree depth"));
    }
    if w.rho.iter().any(|&x| x >= P) || w.siblings.iter().any(|s| s.0.iter().any(|&x| x >= P)) {
        return Err(ZkError::InvalidWitness("non-canonical field element"));
    }
    let stream = leaf_stream(&pi.group_digest, &pi.comm_pk, &pi.metadata_digest, &w.rho);
    let mut cur = leaf_hash(&pi.group_digest, &pi.comm_pk, &pi.metadata_digest, &w.rho);
    for (s, &right) in w.siblings.iter().zip(w.path_bits.iter()) {
        cur = if right { node_hash(s, &cur) } else { node_hash(&cur, s) };
    }
    if cur != pi.root {
        return Err(ZkError::InvalidWitness("Merkle path does not reach the public root"));
    }
    Ok(stream)
}

pub fn prove_membership(
    params: &ZkParams,
    pi: &MembershipPublicInputs,
    w: &MembershipPrivateWitness,
) -> Result<MembershipProof, ZkError> {
    let stream = check_relation(params, pi, w)?;
    let pv = pi.to_field_vec()?;
    let air = MembershipAir::new(params.depth);
    let height = params.trace_height(&air);
    let ti = TraceInputs {
        stream: &stream,
        siblings: &w.siblings,
        bits: &w.path_bits,
        pc: pc_from_pv(&pv),
    };
    let trace = build_trace(&air, &ti, height);
    let proof = config::prove(params, &air, trace, &pv)?;
    let mut bytes = Vec::with_capacity(proof.len() + 5);
    bytes.extend_from_slice(MAGIC);
    bytes.push(params.param_id());
    bytes.extend_from_slice(&proof);
    Ok(MembershipProof { bytes })
}

pub fn verify_membership(
    params: &ZkParams,
    pi: &MembershipPublicInputs,
    proof: &MembershipProof,
) -> Result<(), ZkError> {
    if pi.protocol_version != PROTOCOL_VERSION {
        return Err(ZkError::Version);
    }
    let b = &proof.bytes;
    if b.len() < 5 || &b[..4] != MAGIC {
        return Err(ZkError::Malformed);
    }
    if b[4] != params.param_id() {
        return Err(ZkError::Version);
    }
    let pv = pi.to_field_vec()?;
    let air = MembershipAir::new(params.depth);
    config::verify(params, &air, &b[5..], &pv)
}

#[cfg(test)]
mod tests;
