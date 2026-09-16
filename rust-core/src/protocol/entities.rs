//! In-process simulation entities: `DroneState` (a simulated drone) and
//! `GcsState` (the Ground Control Station). These hold everything a real
//! deployment would split across separate machines/processes; here they
//! are simulated in one process and exchange explicit message structs
//! (see `protocol::messages`) exactly as if they were serialized over a
//! network, which is what the HTTP/SSE API layer (`api` crate binary)
//! actually does when driven from the web dashboard.
//!
//! ## Documented implementation decision: PID → DroneID resolution
//!
//! The specification says "GCS: Resolves PID1 → DroneID_D1 (internal
//! mapping)" without specifying the mechanism. Since `PID_1 =
//! SHAKE256(0x03 || s_D1 || "PID" || counter)` depends on `s_D1`, which
//! **GCS never possesses** (by design — GCS does not store drone
//! private/PUF secrets), GCS cannot simply recompute a drone's PID
//! on-the-fly. We resolve this ambiguity with a **pre-registered
//! pseudonym pool**: at registration (and whenever the pool runs low),
//! each drone locally derives a batch of upcoming PIDs (using its own
//! seed and known future counter values) and submits `(pid ->
//! drone_id)` bindings to GCS over the same trusted enrollment channel
//! already used for R1-R3. GCS stores these bindings and consumes one
//! per session. This preserves every stated security property (D2 never
//! learns the permanent DroneID; GCS still never learns `s_D1`; PIDs
//! still rotate per session) while giving "internal mapping" a concrete,
//! implementable mechanism. The trade-off (a finite pool that needs
//! periodic top-up) is documented in `docs/protocol.md`.

use crate::identity::keys::DeviceKeys;
use crate::merkle::group_tree::GroupMembershipTree;
use crate::merkle::tree::MerkleWitness;
use crate::puf::crp::CrpReference;
use crate::puf::fuzzy_extractor::HelperData;
use crate::puf::sram_puf::SramPuf;
use crate::crypto::field::Fp;
use crate::crypto::kem::{KemPublicKey, KemSecretKey};
use crate::crypto::sign::{SignPublicKey, SignSecretKey};
use std::collections::HashMap;

/// A drone's full local state. In a real deployment, everything except
/// `drone_id`/`group_id`/cached membership metadata would live only on
/// the physical device; see field-level comments for what is/is not
/// realistic to expose via the API/UI layer (governed centrally by
/// `api::redact`, not by this struct itself, which is the trusted
/// internal simulation model).
pub struct DroneState {
    pub drone_id: String,
    pub group_id: Option<String>,
    pub puf: SramPuf,
    pub helper_data: Option<HelperData>,
    pub keys: Option<DeviceKeys>,
    pub rho: Option<[u8; 32]>,
    pub leaf: Option<Fp>,
    pub metadata: Option<crate::identity::metadata::MembershipMetadata>,
    pub cached_witness: Option<MerkleWitness>,
    pub cached_root: Option<Fp>,
    pub cached_version: Option<u64>,
    pub pid_counter: u64,
    pub crp_default_challenge: Vec<u8>,
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
            cached_witness: None,
            cached_root: None,
            cached_version: None,
            pid_counter: 0,
            crp_default_challenge: b"default-challenge-v1".to_vec(),
            revoked: false,
        }
    }

    /// Reconstruct `s_D` from a fresh (noisy) PUF reading via the fuzzy
    /// extractor. Panics if the drone has not completed registration
    /// (no helper data yet) — callers must check `is_registered()`.
    pub fn reconstruct_seed(&self) -> [u8; 32] {
        let helper = self
            .helper_data
            .as_ref()
            .expect("reconstruct_seed called before registration");
        let reading = self.puf.read();
        crate::puf::fuzzy_extractor::reproduce(&reading, helper)
    }

    pub fn is_registered(&self) -> bool {
        self.helper_data.is_some() && self.keys.is_some() && self.group_id.is_some()
    }
}

/// Public (GCS-visible / non-sensitive) record for a registered drone.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DronePublicRecord {
    pub drone_id: String,
    pub group_id: String,
    pub kem_pk: KemPublicKey,
    pub dil_pk: SignPublicKey,
    pub metadata: crate::identity::metadata::MembershipMetadata,
    pub rho: [u8; 32], // leaf randomness — public per the spec's own leaf construction (not a secret key)
    pub crp: CrpReference,
    pub active: bool,
}

pub struct GcsState {
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub groups: HashMap<String, GroupMembershipTree>,
    pub drones: HashMap<String, DronePublicRecord>,
    /// Pre-registered pseudonym pool: pid bytes -> drone_id (see module
    /// docs above). Consumed (removed) as sessions start.
    pub pid_pool: HashMap<Vec<u8>, String>,
    /// Nonces GCS has already seen at the M6 PUF-verification step, for
    /// replay detection (spec security-test requirement: "reused
    /// nonce"). Keyed on the raw nonce bytes; in a production system
    /// this would be time-windowed and evicted, which we note as a
    /// simplification (an ever-growing set is fine for a bounded demo).
    pub used_nonces: std::collections::HashSet<Vec<u8>>,
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
            pid_pool: HashMap::new(),
            used_nonces: std::collections::HashSet::new(),
        }
    }

    pub fn create_group(&mut self, group_id: &str, merkle_depth: usize) {
        self.groups
            .entry(group_id.to_string())
            .or_insert_with(|| GroupMembershipTree::new(group_id, merkle_depth));
    }

    pub fn resolve_pid(&self, pid: &[u8]) -> Option<&str> {
        self.pid_pool.get(pid).map(|s| s.as_str())
    }
}

impl Default for GcsState {
    fn default() -> Self {
        Self::new()
    }
}
