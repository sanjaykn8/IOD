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

/// SECURITY FIX (spec item 25-F: "PID lifecycle states
/// ACTIVE/CONSUMED/EXPIRED"). The module doc above already promised
/// pre-registered pseudonyms are "consumed... as sessions start," but
/// until this fix nothing in the code actually implemented that --
/// `resolve_pid` was a pure, non-mutating lookup, so every pre-
/// provisioned PID stayed usable to start arbitrarily many independent
/// sessions forever. These three states are now explicit and enforced:
///   - `Active`: provisioned, never yet used to start a session.
///   - `Consumed`: used once to start a session (via `consume_pid`,
///     called at M2 -- see `auth_flow::gcs_receive_m2`). Re-presenting
///     the SAME pid1 to start a SECOND, independent session is now
///     rejected as a replay. It remains legitimately resolvable within
///     the session that consumed it (M6 looks it up again via
///     `resolve_pid`, which treats Active and Consumed as equally
///     resolvable -- only Expired/unknown PIDs are refused there).
///   - `Expired`: administratively retired (`expire_pid`) and can never
///     be consumed, or even resolved, again. A real deployment would
///     call this on a time horizon (e.g. unused PIDs past their
///     provisioning window); this prototype exposes the transition
///     itself rather than inventing a specific retention policy with no
///     stated basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PidState {
    Active,
    Consumed,
    Expired,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidLifecycleError {
    #[error("PID is not a known pre-registered pseudonym")]
    Unknown,
    #[error("PID has already been consumed to start a prior session (replay rejected)")]
    AlreadyConsumed,
    #[error("PID has been administratively expired and may no longer be used")]
    Expired,
}

pub struct GcsState {
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub groups: HashMap<String, GroupMembershipTree>,
    pub drones: HashMap<String, DronePublicRecord>,
    /// Pre-registered pseudonym pool: pid bytes -> drone_id (see module
    /// docs above). Lifecycle state (see `PidState`) is tracked
    /// separately in `consumed_pids`/`expired_pids` below rather than by
    /// removing entries here, so `resolve_pid` can still serve
    /// legitimate same-session lookups (M6) after M2 has consumed a pid.
    pub pid_pool: HashMap<Vec<u8>, String>,
    /// PIDs that have been consumed (spec 25-F / `PidState::Consumed`).
    /// Like `used_nonces` below, NOT persisted across a process restart
    /// in this research prototype -- documented limitation, same
    /// rationale as that field.
    pub consumed_pids: std::collections::HashSet<Vec<u8>>,
    /// PIDs administratively retired (spec 25-F / `PidState::Expired`).
    /// Same persistence caveat as `consumed_pids`.
    pub expired_pids: std::collections::HashSet<Vec<u8>>,
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
            consumed_pids: std::collections::HashSet::new(),
            expired_pids: std::collections::HashSet::new(),
            used_nonces: std::collections::HashSet::new(),
        }
    }

    pub fn create_group(&mut self, group_id: &str, merkle_depth: usize) {
        self.groups
            .entry(group_id.to_string())
            .or_insert_with(|| GroupMembershipTree::new(group_id, merkle_depth));
    }

    /// Read-only lookup used by every party that may legitimately need
    /// to resolve a pid MORE THAN ONCE within a single already-started
    /// session (M6's `gcs_m6_verify`, K1's `gcs_handle_k1`, and the
    /// trace/administrator PID-resolution path) -- so it deliberately
    /// treats both `Active` and `Consumed` as resolvable. Only
    /// `Expired` (or never-provisioned) PIDs are refused here; the
    /// one-time-use-to-START-a-session enforcement lives in
    /// `consume_pid`, not here.
    pub fn resolve_pid(&self, pid: &[u8]) -> Option<&str> {
        if self.expired_pids.contains(pid) {
            return None;
        }
        self.pid_pool.get(pid).map(|s| s.as_str())
    }

    /// Current lifecycle state of a pid (spec 25-F). Returns `None` for
    /// a pid that was never provisioned at all (distinct from any of
    /// the three real states).
    pub fn pid_state(&self, pid: &[u8]) -> Option<PidState> {
        if !self.pid_pool.contains_key(pid) {
            return None;
        }
        if self.expired_pids.contains(pid) {
            Some(PidState::Expired)
        } else if self.consumed_pids.contains(pid) {
            Some(PidState::Consumed)
        } else {
            Some(PidState::Active)
        }
    }

    /// Consume an `Active` pid to start a new session -- called once,
    /// at M2 (see `auth_flow::gcs_receive_m2`). Transitions
    /// `Active` -> `Consumed` and returns the owning drone_id. Any
    /// other current state is a hard, explicit rejection: this is what
    /// actually stops a pid from starting a second, independent
    /// session (the module docs always claimed this; see `PidState`
    /// docs for why it previously did not happen).
    pub fn consume_pid(&mut self, pid: &[u8]) -> Result<String, PidLifecycleError> {
        match self.pid_state(pid) {
            None => Err(PidLifecycleError::Unknown),
            Some(PidState::Expired) => Err(PidLifecycleError::Expired),
            Some(PidState::Consumed) => Err(PidLifecycleError::AlreadyConsumed),
            Some(PidState::Active) => {
                let drone_id = self.pid_pool.get(pid).expect("checked present by pid_state").clone();
                self.consumed_pids.insert(pid.to_vec());
                Ok(drone_id)
            }
        }
    }

    /// Administrative transition: retire a pid (spec 25-F /
    /// `PidState::Expired`) so it can never be consumed, or resolved,
    /// again regardless of its current state. Returns `false` for a pid
    /// that was never provisioned.
    pub fn expire_pid(&mut self, pid: &[u8]) -> bool {
        if !self.pid_pool.contains_key(pid) {
            return false;
        }
        self.expired_pids.insert(pid.to_vec());
        true
    }
}

impl Default for GcsState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod pid_lifecycle_tests {
    use super::*;

    fn gcs_with_one_pid() -> (GcsState, Vec<u8>) {
        let mut gcs = GcsState::new();
        let pid = vec![1u8, 2, 3, 4];
        gcs.pid_pool.insert(pid.clone(), "drone-1".to_string());
        (gcs, pid)
    }

    #[test]
    fn freshly_provisioned_pid_is_active() {
        let (gcs, pid) = gcs_with_one_pid();
        assert_eq!(gcs.pid_state(&pid), Some(PidState::Active));
    }

    #[test]
    fn unprovisioned_pid_has_no_state() {
        let gcs = GcsState::new();
        assert_eq!(gcs.pid_state(&[9u8; 4]), None);
        assert!(gcs.resolve_pid(&[9u8; 4]).is_none());
    }

    #[test]
    fn consuming_an_active_pid_transitions_to_consumed_and_returns_owner() {
        let (mut gcs, pid) = gcs_with_one_pid();
        let owner = gcs.consume_pid(&pid).unwrap();
        assert_eq!(owner, "drone-1");
        assert_eq!(gcs.pid_state(&pid), Some(PidState::Consumed));
    }

    #[test]
    fn consuming_an_already_consumed_pid_is_rejected_as_replay() {
        let (mut gcs, pid) = gcs_with_one_pid();
        gcs.consume_pid(&pid).unwrap();
        let second = gcs.consume_pid(&pid);
        assert_eq!(second, Err(PidLifecycleError::AlreadyConsumed));
    }

    #[test]
    fn consumed_pid_remains_resolvable_for_same_session_lookups() {
        // M6/K1/trace all need to resolve a pid again AFTER M2 already
        // consumed it in the same session -- `resolve_pid` must keep
        // working for `Consumed`, only `consume_pid` enforces
        // one-time-use.
        let (mut gcs, pid) = gcs_with_one_pid();
        gcs.consume_pid(&pid).unwrap();
        assert_eq!(gcs.resolve_pid(&pid), Some("drone-1"));
    }

    #[test]
    fn expiring_a_pid_blocks_both_consume_and_resolve() {
        let (mut gcs, pid) = gcs_with_one_pid();
        assert!(gcs.expire_pid(&pid));
        assert_eq!(gcs.pid_state(&pid), Some(PidState::Expired));
        assert!(gcs.resolve_pid(&pid).is_none(), "an expired pid must no longer resolve, even for same-session lookups");
        assert_eq!(gcs.consume_pid(&pid), Err(PidLifecycleError::Expired));
    }

    #[test]
    fn expiring_an_already_consumed_pid_still_blocks_resolution() {
        let (mut gcs, pid) = gcs_with_one_pid();
        gcs.consume_pid(&pid).unwrap();
        gcs.expire_pid(&pid);
        assert_eq!(gcs.pid_state(&pid), Some(PidState::Expired));
        assert!(gcs.resolve_pid(&pid).is_none());
    }

    #[test]
    fn expiring_an_unknown_pid_returns_false() {
        let mut gcs = GcsState::new();
        assert!(!gcs.expire_pid(&[9u8; 4]));
    }

    #[test]
    fn consuming_an_unknown_pid_is_rejected() {
        let mut gcs = GcsState::new();
        assert_eq!(gcs.consume_pid(&[9u8; 4]), Err(PidLifecycleError::Unknown));
    }
}
