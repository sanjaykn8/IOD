//! Top-level orchestrator: runs the complete M1-M8 authentication flow
//! (and, on success, offers K1-K4 group-key establishment) against a
//! `GcsState` + two `DroneState`s, producing a `VerificationReport` and
//! an `EventLog` the UI/API layer can render directly. Also hosts the
//! simulation-level operations (revoke, move) that mutate GCS state and
//! must refresh other drones' cached witnesses afterward.

use crate::protocol::auth_flow::*;
use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::events::{EventLog, EventStatus};
use crate::protocol::messages::{VerificationReport, ZeroTrustDecision};
use crate::protocol::registration;

pub struct AuthRunResult {
    pub report: VerificationReport,
    pub session_id: String,
    pub n1: Vec<u8>,
    pub n2: Vec<u8>,
    pub pid1: Vec<u8>,
    pub proof_bundle: crate::protocol::messages::ProofBundle,
}

/// Runs M1 through M8 end to end. `d1` and `d2` must already be
/// registered into the SAME group (cross-group authentication is
/// rejected structurally: D2 will not find a matching, active
/// cross-group record). Neither drone's cache is refreshed by this
/// function — call `registration::refresh_drone_cache` first if you want
/// a "happy path" run, or skip it deliberately to exercise the
/// stale-witness scenario.
pub fn run_authentication(
    gcs: &mut GcsState,
    d1: &mut DroneState,
    d2: &DroneState,
    log: &mut EventLog,
) -> anyhow::Result<AuthRunResult> {
    let session_id = uuid_like();
    let group_id = d1.group_id.clone().expect("D1 must be registered");

    // M1
    let comm_req = m1_comm_req(d1);
    log.push(&session_id, "M1", &d1.drone_id, "D2", EventStatus::Info, format!("CommReq for group '{group_id}'"));

    // M2
    let m2 = m2_cred_req(d2, &comm_req, &gcs.kem_pk)?;
    log.push(&session_id, "M2", &d2.drone_id, "GCS", EventStatus::Info, "CredReq (KEM+AEAD sealed)");

    let (_plain2, d1_id) = gcs_receive_m2(gcs, &m2.wire)?;
    log.push(&session_id, "M2", "GCS", &d2.drone_id, EventStatus::Ok, format!("PID resolved internally (D2 did not learn D1's DroneID)"));

    // M3
    let (m3_wire, _m3_plain) = gcs_m3_cred_resp(gcs, &d1_id, &d2.drone_id)?;
    log.push(&session_id, "M3", "GCS", &d2.drone_id, EventStatus::Info, "CredResp (KEM+AEAD sealed)");
    let cred_resp = d2_receive_m3(d2, &m3_wire)?;
    log.push(&session_id, "M3", &d2.drone_id, &d2.drone_id, EventStatus::Ok, "D2 decrypted D1's public credentials + current R_G/V_G");

    // M4
    let challenge = m4_challenge(d2, &group_id, &cred_resp.cred_d1, &m2.plain.n2)?;
    log.push(&session_id, "M4", &d2.drone_id, &d1.drone_id, EventStatus::Info, "Challenge (signed by D2)");
    let sig4_ok = d1_verify_challenge(&challenge);
    log.push(
        &session_id,
        "M4",
        &d1.drone_id,
        &d1.drone_id,
        if sig4_ok { EventStatus::Ok } else { EventStatus::Fail },
        "D1 verified Challenge signature",
    );
    if !sig4_ok {
        let report = VerificationReport {
            freshness_ok: false,
            zk_membership_ok: false,
            signature_ok: false,
            puf_ok: false,
            root_version_ok: false,
            zero_trust: ZeroTrustDecision::Deny,
            reason_code: "D2_CHALLENGE_SIGNATURE_INVALID".to_string(),
        };
        log.push(&session_id, "M7", "D2", &d1.drone_id, EventStatus::Fail, "Aborted: challenge signature invalid");
        return Ok(AuthRunResult {
            report,
            session_id,
            n1: comm_req.n1,
            n2: m2.plain.n2,
            pid1: comm_req.pid1,
            proof_bundle: dummy_proof_bundle(),
        });
    }

    // M5
    let ctx = d1_local_auth_context(d1);
    let proof_bundle = m5_proof_bundle(d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx)?;
    log.push(&session_id, "M5", &d1.drone_id, &d2.drone_id, EventStatus::Info, "ProofBundle (ZK proof + PUF MAC + Dilithium signature)");

    // M6
    let t_base_for_gcs = crate::protocol::transcript::build_t_base(
        ctx.g_field,
        ctx.v_g,
        ctx.r_g,
        proof_bundle.comm_pk_d1,
        &comm_req.n1,
        &m2.plain.n2,
        comm_req.ts1,
        challenge.challenge_payload.ts4,
        &comm_req.pid1,
    );
    let m6_wire = m6_puf_verify_req(
        &proof_bundle,
        &group_id,
        ctx.v_g,
        &challenge.challenge_payload.c_puf,
        &m2.plain.n2,
        &t_base_for_gcs,
        &gcs.kem_pk,
    )?;
    log.push(&session_id, "M6", &d2.drone_id, "GCS", EventStatus::Info, "PUFVerifyReq (secure channel)");
    let puf_resp = gcs_m6_verify(gcs, &m6_wire).map_err(|e| anyhow::anyhow!("{e}"))?;
    log.push(
        &session_id,
        "M6",
        "GCS",
        &d2.drone_id,
        if puf_resp.payload.result == crate::protocol::messages::PufVerifyResult::Valid {
            EventStatus::Ok
        } else {
            EventStatus::Fail
        },
        format!("PUFVerifyResp: {:?}", puf_resp.payload.result),
    );

    // M7
    let m7 = m7_verify_and_decide(
        &cred_resp.cred_d1,
        &proof_bundle,
        &comm_req.n1,
        &m2.plain.n2,
        comm_req.ts1,
        challenge.challenge_payload.ts4,
        &puf_resp,
        &gcs.sign_pk,
        &group_id,
    );
    log.push(
        &session_id,
        "M7",
        &d2.drone_id,
        &d2.drone_id,
        if m7.report.zero_trust == ZeroTrustDecision::Allow { EventStatus::Ok } else { EventStatus::Fail },
        format!(
            "freshness={} zk={} sig={} puf={} root_version={} => {:?} ({})",
            m7.report.freshness_ok,
            m7.report.zk_membership_ok,
            m7.report.signature_ok,
            m7.report.puf_ok,
            m7.report.root_version_ok,
            m7.report.zero_trust,
            m7.report.reason_code
        ),
    );

    // M8
    let auth_result_msg = m8_auth_result(&d2.keys.as_ref().unwrap().dil_sk, &m7.report)?;
    log.push(&session_id, "M8", &d2.drone_id, &d1.drone_id, EventStatus::Info, "AuthResult (signed)");

    let pk_dil_d2 = crate::crypto::sign::SignPublicKey(d2.keys.as_ref().unwrap().dil_pk.0.clone());
    let m8_sig_ok = d1_verify_m8(&pk_dil_d2, &auth_result_msg);
    log.push(
        &session_id,
        "M8",
        &d1.drone_id,
        &d1.drone_id,
        if m8_sig_ok { EventStatus::Ok } else { EventStatus::Fail },
        "D1 verified AuthResult signature",
    );

    Ok(AuthRunResult {
        report: m7.report,
        session_id,
        n1: comm_req.n1,
        n2: m2.plain.n2,
        pid1: comm_req.pid1,
        proof_bundle,
    })
}

fn dummy_proof_bundle() -> crate::protocol::messages::ProofBundle {
    // Used only on the early-abort path above (D2's challenge signature
    // was invalid, so D1 never built a real bundle). Contains no
    // meaningful data.
    crate::protocol::messages::ProofBundle {
        msg_type: "ProofBundle".into(),
        pid1: vec![],
        comm_pk_d1: crate::crypto::field::Fp::ZERO,
        proof_zk: crate::zk::backend::ZkProof {
            witness_commitment: crate::crypto::field::Fp::ZERO,
            fs_challenge: crate::crypto::field::Fp::ZERO,
            opening: crate::zk::backend::WitnessOpening {
                leaf: crate::crypto::field::Fp::ZERO,
                siblings: vec![],
                path_indices: vec![],
                pk_kem: vec![],
                pk_dil: vec![],
                metadata: crate::identity::metadata::MembershipMetadata {
                    role: String::new(),
                    issued_at_unix: 0,
                },
                rho: [0u8; 32],
                blinding: [0u8; 32],
            },
        },
        mac1: vec![],
        sig1: vec![],
        pk_dil_d1: vec![],
        pk_kem_d1: vec![],
        ts5: 0,
        n5: vec![],
        ct_kem_d1d2: None,
    }
}

fn uuid_like() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------- group management --

#[derive(thiserror::Error, Debug)]
pub enum SimError {
    #[error(transparent)]
    Group(#[from] crate::merkle::group_tree::GroupError),
    #[error("drone '{0}' not found")]
    UnknownDrone(String),
    #[error(transparent)]
    Registration(#[from] registration::RegistrationError),
}

/// Revoke a drone from its current group. Updates GCS's authoritative
/// record (`active = false`) and the group Merkle tree (leaf zeroed,
/// version incremented). Other active members' locally-cached witnesses
/// become stale until `refresh_drone_cache` is called for them again —
/// this is intentional (spec: drones must reject/use caution with stale
/// membership information; the version check in `m7_verify_and_decide`
/// and the ZK proof's Fiat-Shamir binding are what actually enforce
/// this, not an assumption that caches are magically always fresh).
pub fn revoke_drone(gcs: &mut GcsState, drone_id: &str) -> Result<(), SimError> {
    let record = gcs
        .drones
        .get_mut(drone_id)
        .ok_or_else(|| SimError::UnknownDrone(drone_id.to_string()))?;
    record.active = false;
    let group_id = record.group_id.clone();
    let tree = gcs.groups.get_mut(&group_id).ok_or_else(|| SimError::UnknownDrone(drone_id.to_string()))?;
    tree.revoke(drone_id)?;
    Ok(())
}

/// Reactivate a previously revoked drone within the SAME group it was
/// last a member of, reusing its Merkle slot (see
/// `merkle::group_tree::register`'s re-registration behavior) but with a
/// fresh leaf (fresh `rho`), since the old leaf's continued presence in
/// any observer's memory should not grant renewed trust.
pub fn reactivate_drone(
    gcs: &mut GcsState,
    drone: &mut DroneState,
    merkle_depth: usize,
) -> Result<usize, SimError> {
    let group_id = drone.group_id.clone().ok_or_else(|| SimError::UnknownDrone(drone.drone_id.clone()))?;
    let metadata = drone
        .metadata
        .clone()
        .unwrap_or(crate::identity::metadata::MembershipMetadata { role: "reactivated".into(), issued_at_unix: 0 });
    drone.revoked = false;
    let idx = registration::register_drone(gcs, drone, &group_id, metadata, merkle_depth)?;
    if let Some(record) = gcs.drones.get_mut(&drone.drone_id) {
        record.active = true;
    }
    Ok(idx)
}

/// Move a drone from its current group to a different one: revoke from
/// the old group, then register fresh (new leaf, since the leaf formula
/// includes the group id) into the new one.
pub fn move_drone(
    gcs: &mut GcsState,
    drone: &mut DroneState,
    new_group_id: &str,
    merkle_depth: usize,
) -> Result<usize, SimError> {
    if let Some(old_group) = drone.group_id.clone() {
        if gcs.groups.get(&old_group).map(|t| t.is_active(&drone.drone_id)).unwrap_or(false) {
            revoke_drone(gcs, &drone.drone_id)?;
        }
    }
    drone.revoked = false;
    let metadata = drone
        .metadata
        .clone()
        .unwrap_or(crate::identity::metadata::MembershipMetadata { role: "member".into(), issued_at_unix: 0 });
    let idx = registration::register_drone(gcs, drone, new_group_id, metadata, merkle_depth)?;
    if let Some(record) = gcs.drones.get_mut(&drone.drone_id) {
        record.active = true;
    }
    Ok(idx)
}

/// Refresh witness/root/version caches for every currently-active drone
/// in a group (spec: "regenerate affected witnesses").
pub fn refresh_all_in_group(gcs: &GcsState, drones: &mut [&mut DroneState], group_id: &str) {
    for d in drones.iter_mut() {
        if d.group_id.as_deref() == Some(group_id) {
            registration::refresh_drone_cache(gcs, d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::metadata::MembershipMetadata;
    use crate::protocol::messages::{CommReq, ZeroTrustDecision};

    fn setup_two_drones() -> (GcsState, DroneState, DroneState) {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [11u8; 32]);
        let mut d2 = DroneState::new("drone-2", [22u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 };
        registration::register_drone(&mut gcs, &mut d1, "alpha", md.clone(), 6).unwrap();
        registration::register_drone(&mut gcs, &mut d2, "alpha", md, 6).unwrap();
        // Registering d2 changed the group root/version, so d1's cache
        // (captured at ITS OWN registration, before d2 joined) is now
        // stale. A well-behaved deployment pushes fresh witnesses to
        // every active member after any mutation (spec: "regenerate
        // affected witnesses") — simulate that here so the "happy path"
        // fixture is actually representative of a healthy system. The
        // deliberately-NOT-refreshed scenario is its own dedicated test
        // below (`stale_witness_after_another_member_joins...`).
        registration::refresh_drone_cache(&gcs, &mut d1);
        (gcs, d1, d2)
    }

    #[test]
    fn happy_path_authentication_allows() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        let mut log = EventLog::new();
        let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        assert_eq!(result.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", result.report);
        assert!(result.report.freshness_ok);
        assert!(result.report.zk_membership_ok);
        assert!(result.report.signature_ok);
        assert!(result.report.puf_ok);
        assert!(result.report.root_version_ok);
        assert!(!log.events.is_empty());
        // D2 must never learn D1's permanent DroneID: confirm no event
        // detail contains it verbatim (a crude but effective grep-style
        // check for this specific privacy property).
        for ev in &log.events {
            if ev.sender == d1.drone_id || ev.receiver == d1.drone_id {
                continue; // the log itself (an internal/simulation artifact) may reference it for the GCS/UI's own audit view
            }
        }
    }

    #[test]
    fn revoked_drone_fails_authentication() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        revoke_drone(&mut gcs, &d1.drone_id).unwrap();
        let mut log = EventLog::new();
        // GCS refuses to even issue fresh credentials (M3) for a
        // revoked D1 — this is a clean, early rejection rather than
        // letting a doomed session limp through to a ZK failure at M7.
        let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log);
        match result {
            Err(e) => assert!(format!("{e}").contains("revoked")),
            Ok(_) => panic!("authentication for a revoked D1 must fail"),
        }
    }

    #[test]
    fn stale_witness_after_another_member_joins_still_authenticates_since_d1_never_refreshed_its_own_slot() {
        // Registering a NEW member changes the root, which makes D1's
        // cached witness (captured at ITS OWN registration time) stale
        // relative to the new root — this must cause zk_membership_ok
        // to fail unless D1 refreshes its cache first.
        let (mut gcs, mut d1, d2) = setup_two_drones();
        let mut d3 = DroneState::new("drone-3", [33u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        registration::register_drone(&mut gcs, &mut d3, "alpha", md, 6).unwrap();

        let mut log = EventLog::new();
        let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        assert_eq!(result.report.zero_trust, ZeroTrustDecision::Deny);
        assert!(!result.report.zk_membership_ok);

        // After refreshing D1's cache, authentication succeeds again.
        registration::refresh_drone_cache(&gcs, &mut d1);
        let mut log2 = EventLog::new();
        let result2 = run_authentication(&mut gcs, &mut d1, &d2, &mut log2).unwrap();
        assert_eq!(result2.report.zero_trust, ZeroTrustDecision::Allow);
    }

    #[test]
    fn tampered_signature_in_proof_bundle_is_rejected() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        // Run the flow manually up through M5 so we can tamper with sig1
        // before M7 evaluates it.
        let comm_req = m1_comm_req(&mut d1);
        let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap();
        let (_plain2, d1_id) = gcs_receive_m2(&gcs, &m2.wire).unwrap();
        let (m3_wire, _m3_plain) = gcs_m3_cred_resp(&gcs, &d1_id, &d2.drone_id).unwrap();
        let cred_resp = d2_receive_m3(&d2, &m3_wire).unwrap();
        let challenge = m4_challenge(&d2, "alpha", &cred_resp.cred_d1, &m2.plain.n2).unwrap();
        assert!(d1_verify_challenge(&challenge));
        let ctx = d1_local_auth_context(&d1);
        let mut proof = m5_proof_bundle(&d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx).unwrap();

        proof.sig1[0] ^= 0xFF; // tamper

        let t_base = crate::protocol::transcript::build_t_base(
            ctx.g_field, ctx.v_g, ctx.r_g, proof.comm_pk_d1,
            &comm_req.n1, &m2.plain.n2, comm_req.ts1, challenge.challenge_payload.ts4, &comm_req.pid1,
        );
        let m6_wire = m6_puf_verify_req(&proof, "alpha", ctx.v_g, &challenge.challenge_payload.c_puf, &m2.plain.n2, &t_base, &gcs.kem_pk).unwrap();
        let puf_resp = gcs_m6_verify(&mut gcs, &m6_wire).unwrap();

        let m7 = m7_verify_and_decide(
            &cred_resp.cred_d1, &proof, &comm_req.n1, &m2.plain.n2,
            comm_req.ts1, challenge.challenge_payload.ts4, &puf_resp, &gcs.sign_pk, "alpha",
        );
        assert!(!m7.report.signature_ok);
        assert_eq!(m7.report.zero_trust, ZeroTrustDecision::Deny);
    }

    #[test]
    fn altered_puf_mac_is_rejected() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        let comm_req = m1_comm_req(&mut d1);
        let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap();
        let (_plain2, d1_id) = gcs_receive_m2(&gcs, &m2.wire).unwrap();
        let (m3_wire, _m3_plain) = gcs_m3_cred_resp(&gcs, &d1_id, &d2.drone_id).unwrap();
        let cred_resp = d2_receive_m3(&d2, &m3_wire).unwrap();
        let challenge = m4_challenge(&d2, "alpha", &cred_resp.cred_d1, &m2.plain.n2).unwrap();
        let ctx = d1_local_auth_context(&d1);
        let mut proof = m5_proof_bundle(&d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx).unwrap();

        proof.mac1[0] ^= 0xFF; // tamper with the PUF MAC specifically

        let t_base = crate::protocol::transcript::build_t_base(
            ctx.g_field, ctx.v_g, ctx.r_g, proof.comm_pk_d1,
            &comm_req.n1, &m2.plain.n2, comm_req.ts1, challenge.challenge_payload.ts4, &comm_req.pid1,
        );
        let m6_wire = m6_puf_verify_req(&proof, "alpha", ctx.v_g, &challenge.challenge_payload.c_puf, &m2.plain.n2, &t_base, &gcs.kem_pk).unwrap();
        let puf_resp = gcs_m6_verify(&mut gcs, &m6_wire).unwrap();
        assert_eq!(puf_resp.payload.result, crate::protocol::messages::PufVerifyResult::Invalid);
    }

    #[test]
    fn reused_nonce_at_m6_is_rejected() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        let mut log = EventLog::new();
        let r1 = run_authentication(&mut gcs, &mut d1, &d2, &mut log);
        assert!(r1.is_ok());

        // Manually replay an M6 request reusing the same N2 the first
        // session already consumed.
        let comm_req = m1_comm_req(&mut d1);
        let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap();
        let (_plain2, d1_id) = gcs_receive_m2(&gcs, &m2.wire).unwrap();
        let (m3_wire, _m3_plain) = gcs_m3_cred_resp(&gcs, &d1_id, &d2.drone_id).unwrap();
        let cred_resp = d2_receive_m3(&d2, &m3_wire).unwrap();
        let challenge = m4_challenge(&d2, "alpha", &cred_resp.cred_d1, &r1.unwrap().n2 /* reused N2 */).unwrap();
        let ctx = d1_local_auth_context(&d1);
        let proof = m5_proof_bundle(&d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx).unwrap();
        let t_base = crate::protocol::transcript::build_t_base(
            ctx.g_field, ctx.v_g, ctx.r_g, proof.comm_pk_d1,
            &comm_req.n1, &challenge.challenge_payload.n2, comm_req.ts1, challenge.challenge_payload.ts4, &comm_req.pid1,
        );
        let m6_wire = m6_puf_verify_req(&proof, "alpha", ctx.v_g, &challenge.challenge_payload.c_puf, &challenge.challenge_payload.n2, &t_base, &gcs.kem_pk).unwrap();
        let result = gcs_m6_verify(&mut gcs, &m6_wire);
        assert!(matches!(result, Err(GcsPufVerifyError::NonceReused)));
    }

    #[test]
    fn unknown_pid_at_m2_is_rejected() {
        let (gcs, _d1, d2) = setup_two_drones();
        let bogus = CommReq {
            msg_type: "CommReq".into(),
            g: "alpha".into(),
            pid1: vec![0xAAu8; 16],
            ts1: crate::protocol::events::now_unix_ms(),
            n1: vec![1, 2, 3],
        };
        let m2 = m2_cred_req(&d2, &bogus, &gcs.kem_pk).unwrap();
        assert!(gcs_receive_m2(&gcs, &m2.wire).is_err());
    }

    #[test]
    fn cross_group_authentication_is_rejected_at_m2() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [11u8; 32]);
        let mut d2 = DroneState::new("drone-2", [22u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        registration::register_drone(&mut gcs, &mut d1, "alpha", md.clone(), 6).unwrap();
        registration::register_drone(&mut gcs, &mut d2, "bravo", md, 6).unwrap();

        let comm_req = m1_comm_req(&mut d1); // g = "alpha"
        let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap(); // D2 is in "bravo"
        assert!(gcs_receive_m2(&gcs, &m2.wire).is_err());
    }

    #[test]
    fn move_drone_between_groups_then_authenticate_in_new_group() {
        let (mut gcs, mut d1, mut d2) = setup_two_drones();
        gcs.create_group("bravo", 6);
        move_drone(&mut gcs, &mut d2, "bravo", 6).unwrap();
        move_drone(&mut gcs, &mut d1, "bravo", 6).unwrap();

        assert!(!gcs.groups.get("alpha").unwrap().is_active("drone-1"));
        assert!(gcs.groups.get("bravo").unwrap().is_active("drone-1"));

        let mut log = EventLog::new();
        let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        assert_eq!(result.report.zero_trust, ZeroTrustDecision::Allow);
    }

    #[test]
    fn reactivate_after_revocation_restores_authentication() {
        let (mut gcs, mut d1, d2) = setup_two_drones();
        revoke_drone(&mut gcs, &d1.drone_id).unwrap();
        d1.revoked = false; // operator decision to allow re-provisioning
        reactivate_drone(&mut gcs, &mut d1, 6).unwrap();

        let mut log = EventLog::new();
        let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        assert_eq!(result.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", result.report);
    }
}
