//! Wire message structs for M1-M8 (authentication) and K1-K4 (group key).
//!
//! Every struct that gets Dilithium-signed exposes a `signing_bytes()`
//! method that builds a canonical, length-prefixed byte transcript from
//! its fields explicitly (see `crypto::kdf::length_prefixed_concat`) —
//! never a raw `serde_json`/JS-object stringification — per the "do not
//! sign vague JSON strings without canonicalization" requirement. The
//! `serde::Serialize`/`Deserialize` derives are for the wire/API/UI
//! layer only and are never what gets signed.

use crate::crypto::field::Fp;
use crate::crypto::kdf::length_prefixed_concat;
use crate::identity::metadata::MembershipMetadata;
use crate::protocol::envelope::SecureEnvelope;
use crate::zk::backend::ZkProof;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- M1 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommReq {
    pub msg_type: String,
    pub g: String,
    pub pid1: Vec<u8>,
    pub ts1: u64,
    pub n1: Vec<u8>,
}

// ---------------------------------------------------------------- M2 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredReqPlain {
    pub msg_type: String,
    pub g: String,
    pub pid1: Vec<u8>,
    pub d2_id: String,
    pub ts2: u64,
    pub n2: Vec<u8>,
}
pub type CredReqWire = SecureEnvelope; // M2 wire payload: { "ct2": ... }

// ---------------------------------------------------------------- M3 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredD1 {
    pub pk_kem_d1: Vec<u8>,
    pub pk_dil_d1: Vec<u8>,
    pub membership_metadata_1: MembershipMetadata,
    pub r_g: Fp,
    pub v_g: u64,
    /// Resolves the spec's underspecified "C_PUF: PUF challenge
    /// identifier for D1 (GCS-managed)" — see `protocol::entities`
    /// module docs for the analogous PID-pool design-decision writeup.
    /// GCS is the natural authority for which CRP challenge is valid for
    /// D1, so it is included here and forwarded by D2 to D1 in M4.
    pub crp_challenge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredRespPlain {
    pub msg_type: String,
    pub cred_d1: CredD1,
    pub ts3: u64,
    pub n3: Vec<u8>,
}
pub type CredRespWire = SecureEnvelope; // M3 wire payload: { "ct3": ... }

// ---------------------------------------------------------------- M4 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengePayload {
    pub msg_type: String,
    pub g: String,
    pub c_puf: Vec<u8>,
    pub n2: Vec<u8>,
    pub ts4: u64,
    pub ct_kem_d2d1: Option<SecureEnvelope>,
}

impl ChallengePayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        length_prefixed_concat(&[
            self.msg_type.as_bytes(),
            self.g.as_bytes(),
            &self.c_puf,
            &self.n2,
            &self.ts4.to_le_bytes(),
            self.ct_kem_d2d1
                .as_ref()
                .map(|e| e.kem_ciphertext.as_slice())
                .unwrap_or(b""),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMsg {
    pub challenge_payload: ChallengePayload,
    pub sig4: Vec<u8>,
    pub pk_dil_d2: Vec<u8>,
}

// ---------------------------------------------------------------- M5 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub msg_type: String,
    pub pid1: Vec<u8>,
    pub comm_pk_d1: Fp,
    pub proof_zk: ZkProof,
    pub mac1: Vec<u8>,
    pub sig1: Vec<u8>,
    pub pk_dil_d1: Vec<u8>,
    pub pk_kem_d1: Vec<u8>,
    pub ts5: u64,
    pub n5: Vec<u8>,
    pub ct_kem_d1d2: Option<SecureEnvelope>,
}

/// Digest of the ZK proof used inside the signed auth transcript `T`
/// (spec: "π_M is the ZK membership proof (or its hash if large)"). We
/// always use the digest form for a fixed-size transcript. `ZkProof`
/// contains no unordered maps, so `serde_json::to_vec` on it is
/// deterministic given the struct's fixed field order (unlike a HashMap,
/// whose iteration order is not stable) — see module docs for why this
/// is safe here specifically, unlike the general canonicalization
/// concern elsewhere in this project.
pub fn digest_zk_proof(proof: &ZkProof) -> [u8; 32] {
    use crate::crypto::kdf::shake256_bytes;
    let bytes = serde_json::to_vec(proof).expect("ZkProof always serializes");
    let d = shake256_bytes(b"IOD-ZKPROOF-DIGEST-v1", &bytes, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ---------------------------------------------------------------- M6 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyReq {
    pub msg_type: String,
    pub pid1: Vec<u8>,
    pub g: String,
    pub v_g: u64,
    pub c_puf: Vec<u8>,
    pub n2: Vec<u8>,
    pub t_base: Vec<u8>,
    pub mac1: Vec<u8>,
}
pub type PufVerifyReqWire = SecureEnvelope; // sent over the D2<->GCS secure channel

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PufVerifyResult {
    Valid,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyRespPayload {
    pub msg_type: String,
    pub pid1: Vec<u8>,
    pub result: PufVerifyResult,
    pub ts7: u64,
    /// GCS's live view of the group's root/version at verification time,
    /// so D2 can detect a concurrent membership mutation (a revocation
    /// racing this very session) WITHOUT needing the whole tree — see
    /// `protocol::auth_flow` docs for the "root_version_ok" check this
    /// feeds.
    pub current_r_g: Fp,
    pub current_v_g: u64,
}

impl PufVerifyRespPayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        length_prefixed_concat(&[
            self.msg_type.as_bytes(),
            &self.pid1,
            if self.result == PufVerifyResult::Valid { b"VALID" } else { b"INVALID" },
            &self.ts7.to_le_bytes(),
            &self.current_r_g.to_bytes_le(),
            &self.current_v_g.to_le_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyResp {
    pub payload: PufVerifyRespPayload,
    pub sig7: Vec<u8>,
}

// ---------------------------------------------------------------- M7 ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroTrustDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub freshness_ok: bool,
    pub zk_membership_ok: bool,
    pub signature_ok: bool,
    pub puf_ok: bool,
    pub root_version_ok: bool,
    pub zero_trust: ZeroTrustDecision,
    pub reason_code: String,
}

// ---------------------------------------------------------------- M8 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResultPayload {
    pub msg_type: String,
    pub result: ZeroTrustDecision,
    pub reason_code: String,
    pub ts9: u64,
    pub n9: Vec<u8>,
}

impl AuthResultPayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        length_prefixed_concat(&[
            self.msg_type.as_bytes(),
            if self.result == ZeroTrustDecision::Allow { b"ALLOW" } else { b"DENY" },
            self.reason_code.as_bytes(),
            &self.ts9.to_le_bytes(),
            &self.n9,
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResultMsg {
    pub payload9: AuthResultPayload,
    pub sig9: Vec<u8>,
    pub pk_dil_d2: Vec<u8>,
}

// ---------------------------------------------------------------- K1 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyReq {
    pub msg_type: String,
    pub g: String,
    /// CORRECTION (documented, preserves the spec's intended data flow
    /// while fixing a genuine privacy contradiction in the source
    /// specification): the specification's own K1 payload literally puts
    /// `"D1_ID": DroneID_D1` into a message *sent by D2*, directly
    /// contradicting the project's own non-negotiable requirement that
    /// "D2 must not learn D1's permanent DroneID." We replace the raw
    /// DroneID with D1's session PID (which D2 already legitimately
    /// holds from the M1-M8 session just completed), and GCS resolves it
    /// internally via the same pre-registered pseudonym pool used at M2
    /// (see `protocol::entities` module docs). This preserves the
    /// message's purpose (GCS learns which two drones are establishing a
    /// group key) without leaking D1's permanent identity to D2.
    pub d1_pid1: Vec<u8>,
    pub d2_id: String,
    pub mission_id: String,
    pub ts6: u64,
    pub n6: Vec<u8>,
    pub auth_evidence_hash: Vec<u8>,
}
pub type GroupKeyReqWire = SecureEnvelope;

// ---------------------------------------------------------------- K1r --

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyEnvelopeInner {
    pub k_g_m: Vec<u8>,
    pub g: String,
    pub mission_id: String,
    pub ts7: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyResp {
    pub msg_type: String,
    pub ct_kem_g_d1: SecureEnvelope,
    pub ct_kem_g_d2: SecureEnvelope,
    pub ts7: u64,
    pub n7: Vec<u8>,
}
pub type GroupKeyRespWire = SecureEnvelope; // GCS -> D2, re-wrapped for transport to D2

// ---------------------------------------------------------------- K2 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDeliveryPayload {
    pub msg_type: String,
    pub ct_kem_g_d1: SecureEnvelope,
    pub ts8: u64,
    pub n8: Vec<u8>,
}

impl KeyDeliveryPayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        length_prefixed_concat(&[
            self.msg_type.as_bytes(),
            &self.ct_kem_g_d1.kem_ciphertext,
            &self.ts8.to_le_bytes(),
            &self.n8,
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDeliveryMsg {
    pub payload8: KeyDeliveryPayload,
    pub sig8: Vec<u8>,
    pub pk_dil_d2: Vec<u8>,
}

// -------------------------------------------------- secure messaging ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecureAppMessage {
    pub header_seq: u32,
    pub header_ts: u64,
    pub src_pid: Vec<u8>,
    pub dst_pid: Vec<u8>,
    pub sealed: crate::crypto::aead::SealedMessage,
}

impl SecureAppMessage {
    pub fn associated_data(&self) -> Vec<u8> {
        length_prefixed_concat(&[
            &self.header_seq.to_le_bytes(),
            &self.header_ts.to_le_bytes(),
            &self.src_pid,
            &self.dst_pid,
        ])
    }
}
