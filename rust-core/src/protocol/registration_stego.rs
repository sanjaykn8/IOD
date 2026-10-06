//! R1-R3, steganographically transported.
//!
//! This module implements the SAME logical enrollment exchange as
//! `protocol::registration` (which remains unchanged and is still used
//! directly by every test/benchmark that does not need the
//! steganographic transport -- see that module's "do not rewrite good
//! existing modules unnecessarily" framing in the project's own
//! instructions), but as explicit, ML-KEM+AEAD-encrypted wire messages
//! that are embedded into, and extracted from, real cover images via
//! the real 2D steganography algorithms in the Python `python-service`
//! (`stego/*.py`), reached over HTTP through `StegoClient`.
//!
//! ## Message flow (matches `docs/diagrams/iod_full_sequence`)
//!
//! - **R1** (D1 -> GCS): D1 builds an [`EnrollmentRequest`], encrypts it
//!   with [`encrypt_enrollment_request`] (KEM-then-AEAD, reusing
//!   `protocol::envelope` exactly as M2/M3/K1 already do), and the
//!   ciphertext is embedded into a cover image by the RAG-assisted
//!   selector (`stego.benchmark` + `rag.selector` on the Python side).
//!   The resulting stego image is what actually "crosses the network"
//!   in this simulation.
//! - **R2** (GCS-internal): [`gcs_process_enrollment`] -- no message is
//!   sent anywhere for this step; it is GCS computing the Merkle leaf,
//!   registering it, and preparing its response. Diagrammed as internal
//!   processing, never as a network arrow (spec notation requirement).
//! - **R3** (GCS -> D1): GCS builds an [`EnrollmentResponse`], encrypts
//!   it for D1's (just-learned) KEM public key, and it too is
//!   steganographically embedded and sent back.
//!
//! ## Two documented, necessary additions to the spec's own R1/R3 field
//! lists (same style as this project's other documented spec
//! corrections, e.g. `protocol::messages::GroupKeyReq`'s `d1_pid1`
//! correction)
//!
//! 1. **`rho` added to `EnrollmentRequest`.** The spec's R1 field list
//!    (`DroneID_D, G, PK_KEM_D, PK_Dil_D, membership_metadata_D`) and
//!    R3 field list (`G, R_G, V_G, Path, index, PK_KEM_GCS`) never
//!    actually transmit the leaf-randomness `rho` that
//!    `identity::leaf::compute_leaf` requires both parties to agree on.
//!    In the original fused `registration::register_drone`, this was
//!    invisible because D1 and GCS are the same in-process call; once
//!    split across a real (simulated) channel, `rho` MUST travel from
//!    D1 (who generates it) to GCS (who needs it to compute the leaf).
//!    It is not a secret (the existing `DronePublicRecord.rho` field is
//!    already GCS-visible/public), so including it in `EnrollmentRequest`
//!    introduces no new trust assumption.
//! 2. **`pid_pool` added to `EnrollmentRequest`.** `protocol::entities`'
//!    own module docs already specify the INTENDED design ("each drone
//!    locally derives a batch of upcoming PIDs ... and submits
//!    `(pid -> drone_id)` bindings to GCS over the same trusted
//!    enrollment channel") but the fused `register_drone` function
//!    took a shortcut only possible because it has direct access to
//!    the drone's secret seed in-process. This module implements the
//!    INTENDED design for real: D1 derives its own PID batch locally
//!    (`identity::pid::derive_pid`, using its own seed, which never
//!    leaves the drone) and sends only the resulting opaque PID bytes;
//!    GCS maps each one to `drone_id` without ever learning the seed.
//!
//! ## A genuine, new integrity check this split enables
//!
//! Because R3 now travels as an explicit, independently-decryptable
//! message instead of being silently assigned into `DroneState` by a
//! function that already trusts itself, [`d1_apply_enrollment_response`]
//! actually calls `merkle::tree::verify_witness` on the witness GCS
//! sent, before accepting it -- D1 no longer blindly trusts that GCS's
//! `R3` is internally consistent (leaf/witness/root), the same
//! "recompute, don't just store" posture already used in `auth_flow`.

use crate::crypto::field::Fp;
use crate::crypto::kem::{KemPublicKey, KemSecretKey};
use crate::identity::keys::{derive_device_keys, DeviceKeys};
use crate::identity::leaf::{compute_leaf, derive_puf_bound_rho};
use crate::identity::metadata::MembershipMetadata;
use crate::identity::pid::derive_pid;
use crate::merkle::group_tree::GroupError;
use crate::merkle::tree::{verify_witness, MerkleWitness};
use crate::protocol::entities::{DronePublicRecord, DroneState, GcsState};
use crate::protocol::envelope::{self, SecureEnvelope};
use crate::protocol::registration::PID_POOL_BATCH_SIZE;
use crate::puf::crp::CrpReference;
use crate::puf::fuzzy_extractor::{self, HelperData};
use serde::{Deserialize, Serialize};

// =============================================================== R1 ===

/// R1 wire payload (plaintext, before KEM+AEAD sealing). See module
/// docs for the two documented additions (`rho`, `pid_pool`) beyond the
/// spec's literal field list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub msg_type: String,
    pub drone_id: String,
    pub g: String,
    pub pk_kem_d: Vec<u8>,
    pub pk_dil_d: Vec<u8>,
    pub membership_metadata_d: MembershipMetadata,
    pub rho: [u8; 32],
    pub pid_pool: Vec<Vec<u8>>,
}

/// Locally-generated material D1 needs to hold onto between building
/// R1 and applying R3 -- NOT part of any wire message (the secret key
/// material here never leaves the drone).
pub struct EnrollmentMaterial {
    pub request: EnrollmentRequest,
    pub keys: DeviceKeys,
    pub helper_data: HelperData,
    pub seed: [u8; 32],
}

/// D1-side R1 construction: real PUF read, real fuzzy-extractor
/// generation, real ML-KEM/ML-DSA keypair derivation -- identical to
/// the first half of `registration::register_drone`, just packaged as
/// an explicit message instead of writing straight into shared state.
pub fn d1_build_enrollment_request(drone: &DroneState, group_id: &str, metadata: &MembershipMetadata) -> EnrollmentMaterial {
    let reference_reading = drone.puf.read();
    let enrolled = fuzzy_extractor::generate(&reference_reading);
    let keys = derive_device_keys(&enrolled.seed);

    // SECURITY FIX (spec 25-C): see `registration::register_drone`'s
    // identical fix and `identity::leaf::derive_puf_bound_rho` docs.
    let rho = derive_puf_bound_rho(&enrolled.seed);

    let pid_pool: Vec<Vec<u8>> = (0..PID_POOL_BATCH_SIZE)
        .map(|i| derive_pid(&enrolled.seed, drone.pid_counter + i))
        .collect();

    let request = EnrollmentRequest {
        msg_type: "EnrollmentRequest".into(),
        drone_id: drone.drone_id.clone(),
        g: group_id.to_string(),
        pk_kem_d: keys.kem_pk.0.clone(),
        pk_dil_d: keys.dil_pk.0.clone(),
        membership_metadata_d: metadata.clone(),
        rho,
        pid_pool,
    };
    EnrollmentMaterial { request, keys, helper_data: enrolled.helper_data, seed: enrolled.seed }
}

pub fn encrypt_enrollment_request(request: &EnrollmentRequest, gcs_kem_pk: &KemPublicKey) -> anyhow::Result<SecureEnvelope> {
    envelope::seal_for_recipient(gcs_kem_pk, b"R1-EnrollmentRequest", &serde_json::to_vec(request)?)
}

pub fn decrypt_enrollment_request(envelope: &SecureEnvelope, gcs_kem_sk: &KemSecretKey) -> anyhow::Result<EnrollmentRequest> {
    let bytes = envelope::open_as_recipient(gcs_kem_sk, b"R1-EnrollmentRequest", envelope).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ======================================================= R2 (internal) =

#[derive(thiserror::Error, Debug)]
pub enum StegoRegistrationError {
    #[error(transparent)]
    Group(#[from] GroupError),
    #[error("group '{0}' does not exist")]
    UnknownGroup(String),
    #[error("drone '{0}' is revoked and cannot be re-registered without reactivation")]
    Revoked(String),
    #[error("R3 witness failed local verification against R_G -- GCS response is internally inconsistent")]
    WitnessVerificationFailed,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// R2: GCS-internal processing only -- no message leaves GCS here (see
/// module docs; diagram this as internal processing, never a network
/// arrow). Computes the leaf, registers it in the group's Merkle tree,
/// stores the public record, and maps the drone-derived PID batch --
/// all real, same primitives `registration::register_drone` uses.
pub fn gcs_process_enrollment(
    gcs: &mut GcsState,
    request: &EnrollmentRequest,
    merkle_depth: usize,
    puf_crp: CrpReference,
) -> Result<EnrollmentResponse, StegoRegistrationError> {
    gcs.create_group(&request.g, merkle_depth);

    let leaf = compute_leaf(&request.pk_kem_d, &request.pk_dil_d, &request.g, &request.membership_metadata_d, &request.rho);
    let tree = gcs.groups.get_mut(&request.g).ok_or_else(|| StegoRegistrationError::UnknownGroup(request.g.clone()))?;
    let index = tree.register(&request.drone_id, leaf)?;

    gcs.drones.insert(
        request.drone_id.clone(),
        DronePublicRecord {
            drone_id: request.drone_id.clone(),
            group_id: request.g.clone(),
            kem_pk: KemPublicKey(request.pk_kem_d.clone()),
            dil_pk: crate::crypto::sign::SignPublicKey(request.pk_dil_d.clone()),
            metadata: request.membership_metadata_d.clone(),
            rho: request.rho,
            crp: puf_crp,
            active: true,
        },
    );

    // Map the DRONE-derived PID batch (see module docs, addition #2) --
    // GCS only ever sees opaque PID bytes, never the seed they came from.
    for pid in &request.pid_pool {
        gcs.pid_pool.insert(pid.clone(), request.drone_id.clone());
    }

    let tree_ref = gcs.groups.get(&request.g).unwrap();
    let witness = tree_ref.witness_for(&request.drone_id).unwrap();
    let _ = index; // witness.leaf_index already carries this (spec's index_D,G)

    Ok(EnrollmentResponse {
        msg_type: "EnrollmentResponse".into(),
        g: request.g.clone(),
        r_g: tree_ref.root(),
        v_g: tree_ref.version,
        witness,
        pk_kem_gcs: gcs.kem_pk.0.clone(),
    })
}

// =============================================================== R3 ===

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub msg_type: String,
    pub g: String,
    pub r_g: Fp,
    pub v_g: u64,
    /// Carries the spec's `Path_D,G` (`siblings`/`path_indices`) AND
    /// `index_D,G` (`leaf_index`) in one already-defined, already-tested
    /// struct (`merkle::tree::MerkleWitness`) rather than three loose
    /// fields -- no new type needed for data this project already models.
    pub witness: MerkleWitness,
    pub pk_kem_gcs: Vec<u8>,
}

pub fn encrypt_enrollment_response(response: &EnrollmentResponse, drone_kem_pk: &KemPublicKey) -> anyhow::Result<SecureEnvelope> {
    envelope::seal_for_recipient(drone_kem_pk, b"R3-EnrollmentResponse", &serde_json::to_vec(response)?)
}

pub fn decrypt_enrollment_response(envelope: &SecureEnvelope, drone_kem_sk: &KemSecretKey) -> anyhow::Result<EnrollmentResponse> {
    let bytes = envelope::open_as_recipient(drone_kem_sk, b"R3-EnrollmentResponse", envelope).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// D1-side: apply a (locally re-verified -- see module docs) R3 onto
/// the drone's local state. Returns the assigned leaf index for
/// logging/UI parity with `registration::register_drone`.
#[allow(clippy::too_many_arguments)]
pub fn d1_apply_enrollment_response(
    drone: &mut DroneState,
    response: &EnrollmentResponse,
    material: EnrollmentMaterial,
    metadata: MembershipMetadata,
) -> Result<usize, StegoRegistrationError> {
    let leaf = compute_leaf(
        &material.request.pk_kem_d,
        &material.request.pk_dil_d,
        &response.g,
        &metadata,
        &material.request.rho,
    );
    if !verify_witness(response.r_g, leaf, &response.witness) {
        return Err(StegoRegistrationError::WitnessVerificationFailed);
    }

    let index = response.witness.leaf_index;
    drone.group_id = Some(response.g.clone());
    drone.helper_data = Some(material.helper_data);
    drone.keys = Some(material.keys);
    drone.rho = Some(material.request.rho);
    drone.leaf = Some(leaf);
    drone.metadata = Some(metadata);
    drone.cached_witness = Some(response.witness.clone());
    drone.cached_root = Some(response.r_g);
    drone.cached_version = Some(response.v_g);
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem;
    use crate::puf::crp::CrpReference;

    fn setup() -> (GcsState, DroneState, MembershipMetadata) {
        let gcs = GcsState::new();
        let drone = DroneState::new("drone-stego-1", [7u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 };
        (gcs, drone, md)
    }

    /// Full R1 -> R2 -> R3 round trip WITHOUT any steganographic
    /// embedding (pure crypto + framing correctness) -- the
    /// steganographic transport is a separate concern, exercised by
    /// `StegoClient` implementations and the cross-language end-to-end
    /// demo (see `docs/registration-stego.md`); this test guarantees the
    /// message pipeline itself (encrypt/decrypt, leaf/witness agreement,
    /// PID mapping) is correct independent of which bytes carried it.
    #[test]
    fn full_r1_r2_r3_round_trip_without_stego() {
        let (mut gcs, mut drone, md) = setup();
        let material = d1_build_enrollment_request(&drone, "alpha", &md);

        let sealed_r1 = encrypt_enrollment_request(&material.request, &gcs.kem_pk).unwrap();
        // "Transport" stand-in: in the stego-enabled path this would be
        // embedded into a cover image and extracted at the other end;
        // here it is passed directly, since this test is scoped to the
        // crypto/framing layer only.
        let received_request = decrypt_enrollment_request(&sealed_r1, &gcs.kem_sk).unwrap();
        assert_eq!(received_request.drone_id, drone.drone_id);

        let crp = CrpReference { challenge: drone.crp_default_challenge.clone(), reference_response: drone.puf.challenge_response(&drone.crp_default_challenge) };
        let response = gcs_process_enrollment(&mut gcs, &received_request, 6, crp).unwrap();

        let drone_kem_pk = KemPublicKey(material.keys.kem_pk.0.clone());
        let sealed_r3 = encrypt_enrollment_response(&response, &drone_kem_pk).unwrap();
        let received_response = decrypt_enrollment_response(&sealed_r3, &material.keys.kem_sk).unwrap();

        let index = d1_apply_enrollment_response(&mut drone, &received_response, material, md).unwrap();
        assert_eq!(index, 0);
        assert!(drone.is_registered());
        assert!(gcs.groups.get("alpha").unwrap().is_active("drone-stego-1"));
        assert_eq!(gcs.pid_pool.len() as u64, PID_POOL_BATCH_SIZE);
    }

    #[test]
    fn tampered_r3_witness_is_rejected_by_d1() {
        let (mut gcs, drone, md) = setup();
        let material = d1_build_enrollment_request(&drone, "alpha", &md);
        let crp = CrpReference { challenge: drone.crp_default_challenge.clone(), reference_response: drone.puf.challenge_response(&drone.crp_default_challenge) };
        let mut response = gcs_process_enrollment(&mut gcs, &material.request, 6, crp).unwrap();
        response.witness.siblings[0].0 ^= 1; // tamper

        let mut drone2 = DroneState::new("drone-stego-1", [7u8; 32]);
        let result = d1_apply_enrollment_response(&mut drone2, &response, material, md);
        assert!(matches!(result, Err(StegoRegistrationError::WitnessVerificationFailed)));
    }

    #[test]
    fn gcs_never_sees_the_puf_seed_only_opaque_pids() {
        let (mut gcs, drone, md) = setup();
        let material = d1_build_enrollment_request(&drone, "alpha", &md);
        // The request struct that actually crosses the wire contains no
        // seed field at all -- this is a compile-time guarantee (there is
        // no such field on `EnrollmentRequest`), reinforced here by
        // checking the PIDs registered are exactly the ones D1 computed,
        // not re-derived by GCS from anything secret.
        let crp = CrpReference { challenge: drone.crp_default_challenge.clone(), reference_response: drone.puf.challenge_response(&drone.crp_default_challenge) };
        gcs_process_enrollment(&mut gcs, &material.request, 6, crp).unwrap();
        for pid in &material.request.pid_pool {
            assert_eq!(gcs.pid_pool.get(pid).map(|s| s.as_str()), Some("drone-stego-1"));
        }
        let _ = kem::keypair(); // keep `kem` import used across cfg permutations
    }
}
