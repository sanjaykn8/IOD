//! R1-R3: drone registration/enrollment into a group.
//!
//! This entire exchange happens over what the specification calls a
//! "secure enrollment channel" (e.g. TLS, or a technician physically
//! provisioning the device) — i.e. it is explicitly a TRUSTED channel,
//! unlike the M1-M8 authentication flow which must defend against a
//! network attacker. We still model it as explicit request/response
//! structs (for logging/audit and UI display), but do not apply
//! KEM/AEAD wrapping to it, matching the specification.

use crate::identity::keys::derive_device_keys;
use crate::identity::leaf::{compute_leaf, derive_puf_bound_rho};
use crate::identity::metadata::MembershipMetadata;
use crate::identity::pid::derive_pid;
use crate::merkle::group_tree::GroupError;
use crate::puf::crp::CrpReference;
use crate::puf::fuzzy_extractor;
use crate::protocol::entities::{DronePublicRecord, DroneState, GcsState};

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("group '{0}' does not exist")]
    UnknownGroup(String),
    #[error(transparent)]
    Group(#[from] GroupError),
    #[error("drone is revoked and cannot be re-registered without reactivation")]
    Revoked,
}

/// Number of pseudonyms to pre-provision per registration/top-up (see
/// `entities` module docs on the PID pool design decision).
pub const PID_POOL_BATCH_SIZE: u64 = 64;

/// R1 (drone-side) + R2/R3 (GCS-side), run end to end for this
/// simulation's trusted enrollment channel. Returns the assigned leaf
/// index for logging/UI purposes.
pub fn register_drone(
    gcs: &mut GcsState,
    drone: &mut DroneState,
    group_id: &str,
    metadata: MembershipMetadata,
    merkle_depth: usize,
) -> Result<usize, RegistrationError> {
    if drone.revoked {
        return Err(RegistrationError::Revoked);
    }
    gcs.create_group(group_id, merkle_depth);

    // --- R1: drone generates PUF-derived keys locally ---
    let reference_reading = drone.puf.read();
    let enrolled = fuzzy_extractor::generate(&reference_reading);
    let keys = derive_device_keys(&enrolled.seed);
    // SECURITY FIX (spec 25-C): rho is now cryptographically bound to
    // this drone's PUF-reconstructed seed (still fresh per
    // registration) rather than independent randomness with no tie to
    // the physical device. See `identity::leaf::derive_puf_bound_rho`.
    let rho = derive_puf_bound_rho(&enrolled.seed);

    let reference_response = drone.puf.challenge_response(&drone.crp_default_challenge);

    // --- R2: GCS computes the leaf and updates the group's tree ---
    let leaf = compute_leaf(&keys.kem_pk.0, &keys.dil_pk.0, group_id, &metadata, &rho);
    let tree = gcs
        .groups
        .get_mut(group_id)
        .ok_or_else(|| RegistrationError::UnknownGroup(group_id.to_string()))?;
    let index = tree.register(&drone.drone_id, leaf)?;

    gcs.drones.insert(
        drone.drone_id.clone(),
        DronePublicRecord {
            drone_id: drone.drone_id.clone(),
            group_id: group_id.to_string(),
            kem_pk: keys.kem_pk.clone(),
            dil_pk: keys.dil_pk.clone(),
            metadata: metadata.clone(),
            rho,
            crp: CrpReference {
                challenge: drone.crp_default_challenge.clone(),
                reference_response,
            },
            active: true,
        },
    );

    // Pre-provision a PID pool (see module/entities docs).
    for i in 0..PID_POOL_BATCH_SIZE {
        let counter = drone.pid_counter + i;
        let pid = derive_pid(&enrolled.seed, counter);
        gcs.pid_pool.insert(pid, drone.drone_id.clone());
    }

    // --- R3: GCS -> drone enrollment response, drone stores local state ---
    let tree_ref = gcs.groups.get(group_id).unwrap();
    let witness = tree_ref.witness_for(&drone.drone_id).unwrap();

    drone.group_id = Some(group_id.to_string());
    drone.helper_data = Some(enrolled.helper_data);
    drone.keys = Some(keys);
    drone.rho = Some(rho);
    drone.leaf = Some(leaf);
    drone.metadata = Some(metadata);
    drone.cached_witness = Some(witness);
    drone.cached_root = Some(tree_ref.root());
    drone.cached_version = Some(tree_ref.version);

    Ok(index)
}

/// Called by the higher-level simulation orchestrator after ANY group
/// mutation (another drone's registration/revocation) to give every
/// still-active drone in the group a fresh witness+root+version — this
/// is the "regenerate affected witnesses" requirement in concrete form.
pub fn refresh_drone_cache(gcs: &GcsState, drone: &mut DroneState) {
    let Some(group_id) = &drone.group_id else { return };
    let Some(tree) = gcs.groups.get(group_id) else { return };
    if let Some(w) = tree.witness_for(&drone.drone_id) {
        drone.cached_witness = Some(w);
        drone.cached_root = Some(tree.root());
        drone.cached_version = Some(tree.version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_single_drone() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata {
            role: "recon".into(),
            issued_at_unix: 1_700_000_000,
        };
        let idx = register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();
        assert_eq!(idx, 0);
        assert!(d1.is_registered());
        assert!(gcs.groups.get("alpha").unwrap().is_active("drone-1"));
        assert_eq!(gcs.pid_pool.len() as u64, PID_POOL_BATCH_SIZE);
    }

    #[test]
    fn register_two_drones_same_group() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let mut d2 = DroneState::new("drone-2", [2u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md.clone(), 6).unwrap();
        register_drone(&mut gcs, &mut d2, "alpha", md, 6).unwrap();
        assert_ne!(d1.leaf, d2.leaf);
        // d1's cached root/witness is now stale relative to the tree
        // after d2 joined; refreshing brings it back in sync.
        let tree_root_after = gcs.groups.get("alpha").unwrap().root();
        assert_ne!(d1.cached_root.unwrap(), tree_root_after);
        refresh_drone_cache(&gcs, &mut d1);
        assert_eq!(d1.cached_root.unwrap(), tree_root_after);
    }

    #[test]
    fn revoked_drone_cannot_reregister_without_explicit_reactivation_path() {
        // registering while `revoked` flag is set is rejected; the
        // reactivation path (clearing `revoked` first) is exercised in
        // the higher-level simulation orchestrator tests.
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        d1.revoked = true;
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        assert!(matches!(
            register_drone(&mut gcs, &mut d1, "alpha", md, 6),
            Err(RegistrationError::Revoked)
        ));
    }
}
