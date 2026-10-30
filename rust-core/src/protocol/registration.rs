//! R1-R3: factory CRP provisioning, authenticated enrollment, credential
//! issuance and pseudonym pool registration.
//!
//! R1  device provisioning: the device (PUF) and the GCS agree on a pool of
//!     CRP references (simulation of a trusted factory/enrollment step).
//! R2  enrollment request: signed with the device's fresh ML-DSA key
//!     (proof of possession) and MAC'd with a PUF-derived key over the
//!     same canonical body plus a fresh GCS nonce. This is the link
//!     PUF identity -> key commitment -> ML-DSA key.
//! R3  GCS verifies, inserts the leaf (Poseidon2 Merkle tree), issues a
//!     GCS-signed credential (ML-DSA), registers the PID batch and returns
//!     the witness, root, version and the GCS trust anchor.

use crate::crypto::domains::SEED_DOMAIN_PUF_MAC;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256, hmac_verify};
use crate::crypto::sign::{self, SignPublicKey, Signature};
use crate::identity::commitment::comm_pk as compute_comm_pk;
use crate::identity::keys::derive_device_keys;
use crate::identity::leaf::compute_leaf;
use crate::identity::metadata::MembershipMetadata;
use crate::identity::pid::derive_pid;
use crate::merkle::group_tree::GroupError;
use crate::protocol::credentials::{self, CredentialBody, CRED_VALIDITY_MS, CRED_VERSION};
use crate::protocol::entities::*;
use crate::protocol::events::now_unix_ms;
use crate::protocol::messages::*;
use crate::protocol::{MAX_TIMESTAMP_SKEW_MS, PID_VALIDITY_MS};
use crate::puf::fuzzy_extractor;
use crate::zkhash::{P, RHO_LIMBS};
use rand::{Rng, RngCore};

pub const PID_POOL_BATCH_SIZE: u64 = 64;
pub const CRP_POOL_SIZE: usize = 16;

#[derive(thiserror::Error, Debug)]
pub enum RegistrationError {
    #[error("group '{0}' does not exist")]
    UnknownGroup(String),
    #[error(transparent)]
    Group(#[from] GroupError),
    #[error("drone is revoked and cannot be re-registered without reactivation")]
    Revoked,
    #[error("enrollment rejected: {0}")]
    Rejected(&'static str),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub fn gcs_begin_enrollment(gcs: &mut GcsState) -> Vec<u8> {
    let mut n = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    gcs.enroll_nonces.insert(n.clone());
    n
}

fn random_rho() -> [u32; RHO_LIMBS] {
    let mut rng = rand::thread_rng();
    core::array::from_fn(|_| rng.gen_range(0..P))
}

fn pop_mac(response: &[u8; 32], body_bytes: &[u8]) -> [u8; 32] {
    let k = hkdf_expand(response, None, SEED_DOMAIN_PUF_MAC, 32);
    hmac_sha256(&k, body_bytes)
}

/// R1-R3 in one call (the three steps are explicit below).
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

    // ---- R1: PUF enrollment + CRP provisioning --------------------------
    let reference_reading = drone.puf.read();
    let enrolled = fuzzy_extractor::generate(&reference_reading);
    let mut crps = Vec::with_capacity(CRP_POOL_SIZE);
    for _ in 0..CRP_POOL_SIZE {
        let mut c = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut c);
        let r = drone.puf.challenge_response(&c);
        crps.push(CrpEntry { challenge: c, reference_response: r, state: CrpState::Fresh });
    }

    // ---- R2: enrollment request ----------------------------------------
    let keys = derive_device_keys(&enrolled.seed);
    let rho = random_rho();
    let nonce = gcs_begin_enrollment(gcs);
    let pid_batch: Vec<Vec<u8>> = (0..PID_POOL_BATCH_SIZE)
        .map(|i| derive_pid(&enrolled.seed, drone.pid_counter + i))
        .collect();
    let body = EnrollmentBody {
        drone_id: drone.drone_id.clone(),
        group_id: group_id.to_string(),
        pk_kem: keys.kem_pk.0.clone(),
        pk_dil: keys.dil_pk.0.clone(),
        comm_pk: compute_comm_pk(&keys.kem_pk.0, &keys.dil_pk.0),
        rho,
        metadata: metadata.clone(),
        pid_batch,
        gcs_nonce: nonce,
        ts: now_unix_ms(),
    };
    let body_bytes = body.signing_bytes();
    let pop_sig = sign::sign_transcript(&keys.dil_sk, &body_bytes)?;
    // The device answers a CRP challenge with its PUF *now*.
    let pop_challenge = crps[0].challenge.clone();
    let pop_resp = drone.puf.challenge_response(&pop_challenge);
    let req = EnrollmentRequest {
        pop_mac: pop_mac(&pop_resp, &body_bytes).to_vec(),
        pop_sig: pop_sig.0,
        pop_challenge,
        body,
    };

    // ---- R3: GCS side -----------------------------------------------------
    let resp = gcs_enroll(gcs, &req, crps)?;

    drone.group_id = Some(group_id.to_string());
    drone.helper_data = Some(enrolled.helper_data);
    drone.keys = Some(keys);
    drone.rho = Some(rho);
    drone.leaf = Some(compute_leaf(&req.body.comm_pk, group_id, &metadata, &rho));
    drone.metadata = Some(metadata);
    drone.credential = Some(resp.credential);
    drone.trust_anchor = Some(SignPublicKey(resp.trust_anchor));
    drone.gcs_kem_pk = Some(crate::crypto::kem::KemPublicKey(resp.gcs_kem_pk));
    drone.cached_witness = Some(resp.witness);
    drone.cached_root = Some(resp.root);
    drone.cached_version = Some(resp.version);
    drone.pid_registered_upto = drone.pid_counter + PID_POOL_BATCH_SIZE;
    Ok(resp.leaf_index)
}

/// GCS-side enrollment: verifies PoP (ML-DSA) and the PUF MAC, then
/// inserts the leaf and issues the credential.
pub fn gcs_enroll(
    gcs: &mut GcsState,
    req: &EnrollmentRequest,
    mut provisioned_crps: Vec<CrpEntry>,
) -> Result<EnrollmentResponse, RegistrationError> {
    let b = &req.body;
    let now = now_unix_ms();
    if !gcs.enroll_nonces.remove(&b.gcs_nonce) {
        return Err(RegistrationError::Rejected("unknown or replayed enrollment nonce"));
    }
    if (now as i64 - b.ts as i64).abs() > MAX_TIMESTAMP_SKEW_MS {
        return Err(RegistrationError::Rejected("stale enrollment timestamp"));
    }
    let body_bytes = b.signing_bytes();
    if !sign::verify_transcript(&SignPublicKey(b.pk_dil.clone()), &body_bytes, &Signature(req.pop_sig.clone())) {
        return Err(RegistrationError::Rejected("ML-DSA proof of possession invalid"));
    }
    if compute_comm_pk(&b.pk_kem, &b.pk_dil) != b.comm_pk {
        return Err(RegistrationError::Rejected("comm_PK does not match the supplied public keys"));
    }
    if b.rho.iter().any(|&x| x >= P) {
        return Err(RegistrationError::Rejected("non-canonical rho"));
    }
    let idx = provisioned_crps
        .iter()
        .position(|c| c.challenge == req.pop_challenge)
        .ok_or(RegistrationError::Rejected("PoP challenge is not a provisioned CRP"))?;
    if !hmac_verify(
        &hkdf_expand(&provisioned_crps[idx].reference_response, None, SEED_DOMAIN_PUF_MAC, 32),
        &body_bytes,
        &req.pop_mac,
    ) {
        return Err(RegistrationError::Rejected("PUF MAC over enrollment body invalid"));
    }
    provisioned_crps[idx].state = CrpState::Used;

    if !gcs.groups.contains_key(&b.group_id) {
        return Err(RegistrationError::UnknownGroup(b.group_id.clone()));
    }
    let leaf = compute_leaf(&b.comm_pk, &b.group_id, &b.metadata, &b.rho);
    // Replace any previous identity of this drone (re-enrollment).
    if let Some(old) = gcs.drones.get(&b.drone_id) {
        let old_cred = old.credential.body.cred_id;
        gcs.cred_index.remove(&old_cred);
    }
    gcs.expire_pids_of(&b.drone_id);
    let tree = gcs.groups.get_mut(&b.group_id).unwrap();
    let index = tree.register(&b.drone_id, leaf)?;

    let mut cred_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cred_id);
    let cred = credentials::issue(
        &gcs.sign_sk,
        CredentialBody {
            version: CRED_VERSION,
            cred_id,
            group_id: b.group_id.clone(),
            pk_kem: b.pk_kem.clone(),
            pk_dil: b.pk_dil.clone(),
            comm_pk: b.comm_pk,
            metadata: b.metadata.clone(),
            issued_at_ms: now,
            expires_at_ms: now + CRED_VALIDITY_MS,
        },
    )?;
    gcs.cred_index.insert(cred_id, b.drone_id.clone());
    gcs.drones.insert(
        b.drone_id.clone(),
        DronePublicRecord {
            drone_id: b.drone_id.clone(),
            group_id: b.group_id.clone(),
            kem_pk: crate::crypto::kem::KemPublicKey(b.pk_kem.clone()),
            dil_pk: SignPublicKey(b.pk_dil.clone()),
            comm_pk: b.comm_pk,
            metadata: b.metadata.clone(),
            credential: cred.clone(),
            crps: provisioned_crps,
            active: true,
        },
    );
    for pid in &b.pid_batch {
        gcs.pid_pool.insert(
            pid.clone(),
            PidRecord {
                drone_id: b.drone_id.clone(),
                state: PidState::Active,
                issued_at_ms: now,
                expires_at_ms: now + PID_VALIDITY_MS,
                bound_session: None,
            },
        );
    }
    let tree = gcs.groups.get(&b.group_id).unwrap();
    Ok(EnrollmentResponse {
        credential: cred,
        trust_anchor: gcs.sign_pk.0.clone(),
        gcs_kem_pk: gcs.kem_pk.0.clone(),
        witness: tree.witness_for(&b.drone_id).unwrap(),
        root: tree.root(),
        version: tree.version,
        leaf_index: index,
    })
}

/// Authenticated PID top-up (the drone signs the new batch).
pub fn pid_topup(gcs: &mut GcsState, drone: &mut DroneState) -> anyhow::Result<()> {
    let keys = drone.keys.as_ref().ok_or_else(|| anyhow::anyhow!("not registered"))?;
    let seed = drone.reconstruct_seed();
    let from = drone.pid_registered_upto;
    let pids: Vec<Vec<u8>> = (0..PID_POOL_BATCH_SIZE).map(|i| derive_pid(&seed, from + i)).collect();
    let mut c = crate::protocol::canon::Canon::new("PID-TOPUP");
    c.str(&drone.drone_id).u64(from).u64(pids.len() as u64);
    for p in &pids {
        c.bytes(p);
    }
    let ts = now_unix_ms();
    c.u64(ts);
    let sig = sign::sign_transcript(&keys.dil_sk, c.as_slice())?;
    // --- GCS side ---
    let rec = gcs.drones.get(&drone.drone_id).filter(|r| r.active).ok_or_else(|| anyhow::anyhow!("drone not active"))?;
    anyhow::ensure!(
        sign::verify_transcript(&rec.dil_pk, c.as_slice(), &sig),
        "PID top-up signature invalid"
    );
    anyhow::ensure!((now_unix_ms() as i64 - ts as i64).abs() <= MAX_TIMESTAMP_SKEW_MS, "stale top-up");
    let now = now_unix_ms();
    for pid in pids {
        gcs.pid_pool.entry(pid).or_insert(PidRecord {
            drone_id: drone.drone_id.clone(),
            state: PidState::Active,
            issued_at_ms: now,
            expires_at_ms: now + PID_VALIDITY_MS,
            bound_session: None,
        });
    }
    drone.pid_registered_upto = from + PID_POOL_BATCH_SIZE;
    Ok(())
}

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

    fn md() -> MembershipMetadata {
        MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 }
    }

    #[test]
    fn register_single_drone_issues_verifiable_credential() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let idx = register_drone(&mut gcs, &mut d1, "alpha", md(), 6).unwrap();
        assert_eq!(idx, 0);
        assert!(d1.is_registered());
        assert!(gcs.groups.get("alpha").unwrap().is_active("drone-1"));
        assert_eq!(gcs.pid_pool.len() as u64, PID_POOL_BATCH_SIZE);
        let cred = d1.credential.as_ref().unwrap();
        cred.verify(d1.trust_anchor.as_ref().unwrap(), now_unix_ms()).unwrap();
        assert_eq!(cred.body.pk_dil, d1.keys.as_ref().unwrap().dil_pk.0);
        // permanent DroneID is not in the credential
        assert!(!format!("{:?}", cred.body).contains("drone-1"));
        // leaf in the tree matches the drone's own leaf
        assert!(gcs.groups["alpha"].verify(d1.leaf.unwrap(), d1.cached_witness.as_ref().unwrap()));
    }

    #[test]
    fn credential_from_a_foreign_authority_is_rejected() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        register_drone(&mut gcs, &mut d1, "alpha", md(), 4).unwrap();
        let other = GcsState::new();
        assert_eq!(
            d1.credential.as_ref().unwrap().verify(&other.sign_pk, now_unix_ms()),
            Err(credentials::CredentialError::BadSignature)
        );
    }

    #[test]
    fn tampered_credential_fails() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        register_drone(&mut gcs, &mut d1, "alpha", md(), 4).unwrap();
        let mut c = d1.credential.clone().unwrap();
        c.body.pk_dil[0] ^= 1;
        assert!(c.verify(&gcs.sign_pk, now_unix_ms()).is_err());
    }

    #[test]
    fn expired_credential_fails() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        register_drone(&mut gcs, &mut d1, "alpha", md(), 4).unwrap();
        let far = now_unix_ms() + CRED_VALIDITY_MS + 1000;
        assert_eq!(
            d1.credential.as_ref().unwrap().verify(&gcs.sign_pk, far),
            Err(credentials::CredentialError::Expired)
        );
    }

    #[test]
    fn two_drones_same_group_and_cache_refresh() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let mut d2 = DroneState::new("drone-2", [2u8; 32]);
        register_drone(&mut gcs, &mut d1, "alpha", md(), 6).unwrap();
        register_drone(&mut gcs, &mut d2, "alpha", md(), 6).unwrap();
        assert_ne!(d1.leaf, d2.leaf);
        let root = gcs.groups["alpha"].root();
        assert_ne!(d1.cached_root.unwrap(), root);
        refresh_drone_cache(&gcs, &mut d1);
        assert_eq!(d1.cached_root.unwrap(), root);
    }

    #[test]
    fn revoked_drone_cannot_reregister_without_reactivation() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        d1.revoked = true;
        assert!(matches!(register_drone(&mut gcs, &mut d1, "alpha", md(), 6), Err(RegistrationError::Revoked)));
    }

    #[test]
    fn enrollment_nonce_is_single_use_and_pop_is_checked() {
        let mut gcs = GcsState::new();
        let d = DroneState::new("drone-1", [1u8; 32]);
        gcs.create_group("alpha", 4);
        // Build a request manually, then corrupt it.
        let reading = d.puf.read();
        let enrolled = fuzzy_extractor::generate(&reading);
        let keys = derive_device_keys(&enrolled.seed);
        let c = vec![5u8; 16];
        let r = d.puf.challenge_response(&c);
        let crps = vec![CrpEntry { challenge: c.clone(), reference_response: r, state: CrpState::Fresh }];
        let nonce = gcs_begin_enrollment(&mut gcs);
        let body = EnrollmentBody {
            drone_id: "drone-1".into(), group_id: "alpha".into(),
            pk_kem: keys.kem_pk.0.clone(), pk_dil: keys.dil_pk.0.clone(),
            comm_pk: compute_comm_pk(&keys.kem_pk.0, &keys.dil_pk.0), rho: [1; 8], metadata: md(),
            pid_batch: vec![], gcs_nonce: nonce, ts: now_unix_ms(),
        };
        let bytes = body.signing_bytes();
        let req = EnrollmentRequest {
            pop_sig: sign::sign_transcript(&keys.dil_sk, &bytes).unwrap().0,
            pop_mac: pop_mac(&r, &bytes).to_vec(),
            pop_challenge: c,
            body,
        };
        // a request whose signature belongs to a different key fails
        let mut bad = req.clone();
        bad.pop_sig[0] ^= 1;
        assert!(gcs_enroll(&mut gcs, &bad, crps.clone()).is_err());
        // the nonce was consumed by the failed attempt: replaying the good request fails
        assert!(matches!(
            gcs_enroll(&mut gcs, &req, crps.clone()),
            Err(RegistrationError::Rejected("unknown or replayed enrollment nonce"))
        ));
    }
}
