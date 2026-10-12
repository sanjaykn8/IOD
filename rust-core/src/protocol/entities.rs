//! Simulated entities: `DroneState` (a drone) and `GcsState` (Ground
//! Control Station) plus the GCS-side lifecycle tables for pseudonyms
//! (PIDs), PUF challenge-response pairs (CRPs) and authentication
//! sessions. Everything the GCS must remember across messages lives in
//! `GcsState` and is persisted (see `storage::snapshots`).
//!
//! ## PID lifecycle (spec: docs/protocol.md §PID)
//! `ACTIVE` --(M3 issues a credential for it)--> `CONSUMED(session)`
//! `ACTIVE|CONSUMED` --(time or revocation)--> `EXPIRED`.
//! A PID can start at most one session; replaying M1/M2 with a
//! consumed/expired PID is rejected at the GCS.
//!
//! ## CRP lifecycle
//! `FRESH` --(M3 picks it as C_PUF)--> `RESERVED(session)`
//! --(M6 verified or failed)--> `USED`. A challenge is never reused.

use crate::crypto::kem::{KemPublicKey, KemSecretKey};
use crate::crypto::sign::{SignPublicKey, SignSecretKey};
use crate::identity::keys::DeviceKeys;
use crate::merkle::group_tree::GroupMembershipTree;
use crate::merkle::tree::MerkleWitness;
use crate::protocol::credentials::SignedCredential;
use crate::puf::fuzzy_extractor::HelperData;
use crate::puf::sram_puf::SramPuf;
use crate::zkhash::{Digest, Limbs, RHO_LIMBS};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub struct DroneState {
    pub drone_id: String,
    pub group_id: Option<String>,
    pub puf: SramPuf,
    pub helper_data: Option<HelperData>,
    pub keys: Option<DeviceKeys>,
    /// Leaf randomness: 8 uniform BabyBear elements. PRIVATE witness.
    pub rho: Option<[u32; RHO_LIMBS]>,
    pub leaf: Option<Digest>,
    pub metadata: Option<crate::identity::metadata::MembershipMetadata>,
    /// GCS-issued credential for this drone and the pinned GCS ML-DSA
    /// trust anchor (both installed at enrollment, R3).
    pub credential: Option<SignedCredential>,
    pub trust_anchor: Option<SignPublicKey>,
    /// Pinned GCS ML-KEM public key (for sealing messages to the GCS).
    pub gcs_kem_pk: Option<KemPublicKey>,
    pub cached_witness: Option<MerkleWitness>,
    pub cached_root: Option<Digest>,
    pub cached_version: Option<u64>,
    pub pid_counter: u64,
    /// PID counters [0, pid_registered_upto) have been registered at the GCS.
    pub pid_registered_upto: u64,
    pub revoked: bool,
}

impl DroneState {
    pub fn new(drone_id: impl Into<String>, device_entropy: [u8; 32]) -> Self {
        DroneState {
            drone_id: drone_id.into(),
            group_id: None,
            puf: SramPuf::new(device_entropy, crate::puf::fuzzy_extractor::DEFAULT_BIT_FLIP_PROB),
            helper_data: None,
            keys: None,
            rho: None,
            leaf: None,
            metadata: None,
            credential: None,
            trust_anchor: None,
            gcs_kem_pk: None,
            cached_witness: None,
            cached_root: None,
            cached_version: None,
            pid_counter: 0,
            pid_registered_upto: 0,
            revoked: false,
        }
    }

    /// Reconstruct `s_D` from a fresh noisy PUF reading via the fuzzy
    /// extractor. Callers must check `is_registered()` first.
    pub fn reconstruct_seed(&self) -> [u8; 32] {
        let helper = self.helper_data.as_ref().expect("reconstruct_seed called before registration");
        let reading = self.puf.read();
        crate::puf::fuzzy_extractor::reproduce(&reading, helper)
    }

    pub fn is_registered(&self) -> bool {
        self.helper_data.is_some() && self.keys.is_some() && self.group_id.is_some() && self.credential.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PidState {
    Active,
    Consumed,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PidRecord {
    pub drone_id: String,
    pub state: PidState,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub bound_session: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrpState {
    Fresh,
    Reserved(String),
    Used,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CrpEntry {
    pub challenge: Vec<u8>,
    pub reference_response: [u8; 32],
    pub state: CrpState,
}

/// Public/GCS-visible record of a registered drone.
#[derive(Clone, Serialize, Deserialize)]
pub struct DronePublicRecord {
    pub drone_id: String,
    pub group_id: String,
    pub kem_pk: KemPublicKey,
    pub dil_pk: SignPublicKey,
    pub comm_pk: Limbs,
    pub metadata: crate::identity::metadata::MembershipMetadata,
    pub credential: SignedCredential,
    pub crps: Vec<CrpEntry>,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// M3 issued; waiting for M6.
    CredIssued,
    /// M6 verified (PID, CRP/PUF MAC, membership, freshness, root/version).
    PufVerified,
    /// M6 failed or session invalidated; terminal.
    Failed,
    /// K1 accepted for this exact session; terminal (one key per session).
    KeyIssued,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub pid1: Vec<u8>,
    pub d1_id: String,
    pub d2_id: String,
    pub group_id: String,
    pub issued_r_g: Digest,
    pub issued_v_g: u64,
    pub c_puf: Vec<u8>,
    pub n1: Vec<u8>,
    pub ts1: u64,
    pub n2: Vec<u8>,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub state: SessionState,
    pub reason_code: String,
    pub session_ctx: Option<Limbs>,
    pub verified_ms: Option<u64>,
}

pub struct GcsState {
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub groups: HashMap<String, GroupMembershipTree>,
    pub drones: HashMap<String, DronePublicRecord>,
    pub cred_index: HashMap<[u8; 16], String>,
    pub pid_pool: HashMap<Vec<u8>, PidRecord>,
    pub sessions: HashMap<String, AuthSession>,
    /// Nonces (n1, n2, n6, ...) already accepted, for replay detection.
    pub seen_nonces: HashSet<Vec<u8>>,
    /// Outstanding enrollment nonces (R2).
    pub enroll_nonces: HashSet<Vec<u8>>,
}

impl GcsState {
    pub fn new() -> Self {
        let (kem_pk, kem_sk) = crate::crypto::kem::keypair();
        let (sign_pk, sign_sk) = crate::crypto::sign::keypair();
        GcsState {
            kem_pk,
            kem_sk,
            sign_pk,
            sign_sk,
            groups: HashMap::new(),
            drones: HashMap::new(),
            cred_index: HashMap::new(),
            pid_pool: HashMap::new(),
            sessions: HashMap::new(),
            seen_nonces: HashSet::new(),
            enroll_nonces: HashSet::new(),
        }
    }

    pub fn create_group(&mut self, group_id: &str, merkle_depth: usize) {
        self.groups
            .entry(group_id.to_string())
            .or_insert_with(|| GroupMembershipTree::new(group_id, merkle_depth));
    }

    /// Administrative resolution PID -> DroneID (Trace Manager only).
    pub fn resolve_pid(&self, pid: &[u8]) -> Option<&str> {
        self.pid_pool.get(pid).map(|r| r.drone_id.as_str())
    }

    pub fn drone_by_cred(&self, cred_id: &[u8; 16]) -> Option<&DronePublicRecord> {
        self.cred_index.get(cred_id).and_then(|id| self.drones.get(id))
    }

    /// Expire every PID of a drone (revocation, re-enrollment).
    pub fn expire_pids_of(&mut self, drone_id: &str) {
        for r in self.pid_pool.values_mut().filter(|r| r.drone_id == drone_id) {
            r.state = PidState::Expired;
        }
    }

    /// Mark sessions that involve a drone as failed (revocation).
    pub fn fail_sessions_of(&mut self, drone_id: &str, reason: &str) {
        for s in self.sessions.values_mut() {
            if (s.d1_id == drone_id || s.d2_id == drone_id) && s.state != SessionState::Failed && s.state != SessionState::KeyIssued {
                s.state = SessionState::Failed;
                s.reason_code = reason.to_string();
            }
        }
    }
}

impl Default for GcsState {
    fn default() -> Self {
        Self::new()
    }
}
