//! Serializable snapshot DTOs for SQLite persistence (see `storage::db`).
//!
//! ## Documented design decision: JSON-blob-per-entity, not a full
//! relational schema
//!
//! A fully normalized relational schema (separate tables + foreign keys
//! for drones, groups, memberships, witnesses, ...) would take
//! substantially more implementation time for very little benefit in a
//! single-operator research prototype with at most a few dozen
//! simulated drones. We instead store one JSON snapshot per logical
//! entity (the whole `GcsState`, and one row per drone's local device
//! state), which is simple to get exactly right, easy to inspect
//! (`sqlite3 iod_simulation.db 'select data from gcs_state'` is
//! human-readable JSON), and trivially versioned by just changing the
//! Rust struct (old rows fail to deserialize loudly rather than silently
//! corrupting). Append-only logs (protocol events, trace records) use
//! one row per entry instead, since those are naturally row-shaped.
//!
//! ## Documented design decision: two separate "sides" of storage
//!
//! `GcsSnapshot` holds exactly what a real GCS server would persist:
//! group Merkle state, drones' PUBLIC records (public keys, metadata,
//! CRP *reference* data), and the PID pool. It never contains a drone's
//! private ML-KEM/ML-DSA secret keys or PUF golden pattern.
//!
//! `DroneLocalSnapshot` holds what would physically live on ONE drone's
//! own flash storage in a real deployment — including its private keys
//! and simulated PUF golden pattern. In this single-machine simulator
//! there is nowhere else to durably put that state between runs, so it
//! is written to a clearly-separate `drones_local` table, and every
//! place this module is used is commented to make sure this distinction
//! is never blurred with the GCS-side table.

use crate::crypto::kem::{KemPublicKey, KemSecretKey};
use crate::crypto::sign::{SignPublicKey, SignSecretKey};
use crate::identity::keys::DeviceKeys;
use crate::identity::metadata::MembershipMetadata;
use crate::merkle::group_tree::GroupTreeSnapshot;
use crate::merkle::tree::MerkleWitness;
use crate::protocol::credentials::SignedCredential;
use crate::protocol::entities::{AuthSession, DronePublicRecord, DroneState, GcsState, PidRecord};
use crate::zkhash::{Digest, RHO_LIMBS};
use crate::puf::fuzzy_extractor::HelperData;
use crate::puf::sram_puf::SramPuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GcsSnapshot {
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub groups: Vec<GroupTreeSnapshot>,
    pub drones: Vec<DronePublicRecord>,
    pub pid_pool: Vec<(Vec<u8>, PidRecord)>,
    /// Durable authentication-session records (PID/CRP/session state).
    #[serde(default)]
    pub sessions: Vec<AuthSession>,
    /// Replay-detection nonces are persisted so replays are still
    /// rejected after a restart.
    #[serde(default)]
    pub seen_nonces: Vec<Vec<u8>>,
}

impl GcsState {
    pub fn to_snapshot(&self) -> GcsSnapshot {
        GcsSnapshot {
            kem_pk: self.kem_pk.clone(),
            kem_sk: self.kem_sk.clone(),
            sign_pk: self.sign_pk.clone(),
            sign_sk: self.sign_sk.clone(),
            groups: self.groups.values().map(|g| g.snapshot()).collect(),
            drones: self.drones.values().cloned().collect(),
            pid_pool: self.pid_pool.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            sessions: self.sessions.values().cloned().collect(),
            seen_nonces: self.seen_nonces.iter().cloned().collect(),
        }
    }

    pub fn from_snapshot(snap: GcsSnapshot) -> Self {
        let mut groups = std::collections::HashMap::new();
        for g in snap.groups {
            groups.insert(g.group_id.clone(), crate::merkle::group_tree::GroupMembershipTree::from_snapshot(g));
        }
        let mut drones = std::collections::HashMap::new();
        let mut cred_index = std::collections::HashMap::new();
        for d in snap.drones {
            cred_index.insert(d.credential.body.cred_id, d.drone_id.clone());
            drones.insert(d.drone_id.clone(), d);
        }
        let mut pid_pool = std::collections::HashMap::new();
        for (k, v) in snap.pid_pool {
            pid_pool.insert(k, v);
        }
        GcsState {
            kem_pk: snap.kem_pk,
            kem_sk: snap.kem_sk,
            sign_pk: snap.sign_pk,
            sign_sk: snap.sign_sk,
            groups,
            drones,
            cred_index,
            pid_pool,
            sessions: snap.sessions.into_iter().map(|s| (s.session_id.clone(), s)).collect(),
            seen_nonces: snap.seen_nonces.into_iter().collect(),
            enroll_nonces: std::collections::HashSet::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DroneLocalSnapshot {
    pub drone_id: String,
    pub group_id: Option<String>,
    /// See module docs: simulated hardware secret, device-local table
    /// only, never part of `GcsSnapshot`.
    pub golden_pattern_hex: String,
    pub bit_flip_prob: f64,
    pub helper_data: Option<HelperData>,
    pub keys: Option<DeviceKeys>,
    pub rho: Option<[u32; RHO_LIMBS]>,
    pub leaf: Option<Digest>,
    pub metadata: Option<MembershipMetadata>,
    pub cached_witness: Option<MerkleWitness>,
    pub cached_root: Option<Digest>,
    pub cached_version: Option<u64>,
    pub pid_counter: u64,
    pub credential: Option<SignedCredential>,
    pub trust_anchor: Option<SignPublicKey>,
    pub gcs_kem_pk: Option<KemPublicKey>,
    pub pid_registered_upto: u64,
    pub revoked: bool,
}

impl DroneState {
    pub fn to_local_snapshot(&self) -> DroneLocalSnapshot {
        DroneLocalSnapshot {
            drone_id: self.drone_id.clone(),
            group_id: self.group_id.clone(),
            golden_pattern_hex: hex::encode(self.puf.export_golden_pattern()),
            bit_flip_prob: self.puf.bit_flip_prob,
            helper_data: self.helper_data.clone(),
            keys: self.keys.clone(),
            rho: self.rho,
            leaf: self.leaf,
            metadata: self.metadata.clone(),
            cached_witness: self.cached_witness.clone(),
            cached_root: self.cached_root,
            cached_version: self.cached_version,
            pid_counter: self.pid_counter,
            credential: self.credential.clone(),
            trust_anchor: self.trust_anchor.clone(),
            gcs_kem_pk: self.gcs_kem_pk.clone(),
            pid_registered_upto: self.pid_registered_upto,
            revoked: self.revoked,
        }
    }

    pub fn from_local_snapshot(snap: DroneLocalSnapshot) -> anyhow::Result<Self> {
        let golden_bytes = hex::decode(&snap.golden_pattern_hex)?;
        let mut golden = [0u8; crate::puf::sram_puf::PUF_BYTES];
        if golden_bytes.len() != golden.len() {
            anyhow::bail!("corrupt golden pattern length in snapshot");
        }
        golden.copy_from_slice(&golden_bytes);
        Ok(DroneState {
            drone_id: snap.drone_id,
            group_id: snap.group_id,
            puf: SramPuf::from_golden_pattern(golden, snap.bit_flip_prob),
            helper_data: snap.helper_data,
            keys: snap.keys,
            rho: snap.rho,
            leaf: snap.leaf,
            metadata: snap.metadata,
            cached_witness: snap.cached_witness,
            cached_root: snap.cached_root,
            cached_version: snap.cached_version,
            pid_counter: snap.pid_counter,
            credential: snap.credential,
            trust_anchor: snap.trust_anchor,
            gcs_kem_pk: snap.gcs_kem_pk,
            pid_registered_upto: snap.pid_registered_upto,
            revoked: snap.revoked,
        })
    }
}
