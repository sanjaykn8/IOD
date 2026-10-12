//! Orchestrator for the v2 protocol: runs M1-M8 (and K1-K3) against a
//! `GcsState` and two `DroneState`s, producing a `VerificationReport`
//! and an `EventLog`. Also hosts the membership-management operations
//! (revoke, re-enroll, move) that mutate GCS state.
//!
//! The orchestrator moves *messages* between the entities exactly as a
//! network would; it never hands one entity another's private state.
//! Session state needed by K1 (`D1Session`, `D2Session`, the D1
//! confirmation) is returned to the caller, so K1 can only be started
//! from a completed M1-M8 run.

use crate::protocol::auth_flow::*;
use crate::protocol::entities::{DroneState, GcsState, SessionState};
use crate::protocol::events::{EventLog, EventStatus};
use crate::protocol::group_key::*;
use crate::protocol::messages::*;
use crate::protocol::registration;
use crate::zero_trust::DefaultPolicy;

/// Everything produced by one M1-M8 run.
pub struct AuthRunResult {
    pub report: VerificationReport,
    pub session_id: String,
    pub d1_session: D1Session,
    pub d2_session: D2Session,
    pub proof_bundle: ProofBundle,
    pub m8: AuthResultMsg,
    /// Decision D1 read out of the verified M8 (None if M8 failed to verify).
    pub d1_decision: Option<ZeroTrustDecision>,
    /// D1's signed confirmation (present only if M8 verified).
    pub confirm: Option<SignedSessionConfirm>,
}

fn status(ok: bool) -> EventStatus {
    if ok {
        EventStatus::Ok
    } else {
        EventStatus::Fail
    }
}

/// Runs M1 through M8. `Err` means the run was rejected before a verdict
/// could be produced (GCS refused M2, D1 could not build M5, ...); a
/// completed run with a DENY verdict is `Ok` with `report.zero_trust ==
/// Deny`.
pub fn run_authentication(
    gcs: &mut GcsState,
    d1: &mut DroneState,
    d2: &DroneState,
    log: &mut EventLog,
) -> Result<AuthRunResult, AuthError> {
    run_authentication_with(gcs, d1, d2, log, &DefaultPolicy::default())
}

pub fn run_authentication_with(
    gcs: &mut GcsState,
    d1: &mut DroneState,
    d2: &DroneState,
    log: &mut EventLog,
    policy: &dyn crate::zero_trust::PolicyEngine,
) -> Result<AuthRunResult, AuthError> {
    // M1
    let comm_req = m1_comm_req(d1)?;
    // The session id is only known after M3; use a placeholder label for
    // the first events and re-key the log afterwards via the real id.
    // M2
    let m2 = m2_cred_req(d2, &comm_req)?;
    let acc = gcs_receive_m2(gcs, &m2.wire)?;
    // M3
    let (m3_wire, m3) = gcs_m3_cred_resp(gcs, &acc)?;
    let sid = m3.body.session_id.clone();
    log.push(&sid, "M1", "D1", "D2", EventStatus::Info, "CommReq(G, PID1, ts1, n1)");
    log.push(&sid, "M2", "D2", "GCS", EventStatus::Info, "CredReq sealed to GCS KEM key, signed sig2");
    log.push(&sid, "M2", "GCS", "GCS", EventStatus::Ok, "PID1 resolved internally; D2 never learns D1's DroneID");
    log.push(&sid, "M3", "GCS", "D2", EventStatus::Info, "GCS-signed CredResp sealed to D2 (PID consumed, CRP reserved)");
    let mut d2s = d2_receive_m3(d2, &m3_wire, &comm_req, &m2)?;
    log.push(&sid, "M3", "D2", "D2", EventStatus::Ok, "GCS signature, binding and D1 credential verified");

    // M4
    let challenge = m4_challenge(d2, &mut d2s)?;
    log.push(&sid, "M4", "D2", "D1", EventStatus::Info, "Challenge + GCS-signed M3 + D2 credential + sig4");
    let d1s = match d1_verify_challenge(d1, &challenge, &comm_req) {
        Ok(s) => {
            log.push(&sid, "M4", "D1", "D1", EventStatus::Ok, "GCS sig, D2 credential and sig4 (certified key) verified");
            s
        }
        Err(e) => {
            log.push(&sid, "M4", "D1", "D1", EventStatus::Fail, format!("rejected: {}", e.code));
            return Err(e);
        }
    };

    // M5
    let proof = match m5_proof_bundle(d1, &d1s) {
        Ok(p) => p,
        Err(e) => {
            log.push(&sid, "M5", "D1", "D2", EventStatus::Fail, format!("D1 cannot prove membership: {}", e.code));
            return Err(e);
        }
    };
    log.push(&sid, "M5", "D1", "D2", EventStatus::Info, "ProofBundle (zero-knowledge membership proof + PUF MAC + ML-DSA sig); no key fields, no witness");

    // M6
    let m6 = m6_puf_verify_req(d2, &d2s, &proof)?;
    log.push(&sid, "M6", "D2", "GCS", EventStatus::Info, "PUFVerifyReq signed sig6, sealed to GCS");
    let puf = gcs_m6_verify(gcs, &m6).map_err(|e| AuthError { code: "M6_REJECTED", detail: e.to_string() })?;
    log.push(
        &sid,
        "M6",
        "GCS",
        "D2",
        status(puf.body.result == PufVerifyResult::Valid),
        format!("GCS-signed PUFVerifyResp: {:?} ({})", puf.body.result, puf.body.reason_code),
    );

    // M7
    let m7 = m7_verify_and_decide(d2, &d2s, &proof, &puf, policy);
    let r = &m7.report;
    log.push(
        &sid,
        "M7",
        "D2",
        "D2",
        status(r.zero_trust == ZeroTrustDecision::Allow),
        format!(
            "fresh={} cred={} commit={} zk={} sig={} puf={} root/ver={} bind={} => authenticated={} {:?} ({})",
            r.freshness_ok, r.credential_ok, r.commitment_ok, r.zk_membership_ok, r.signature_ok,
            r.puf_ok, r.root_version_ok, r.session_binding_ok, r.authenticated, r.zero_trust, r.reason_code
        ),
    );

    // M8
    let m8 = m8_auth_result(d2, &d2s, &m7.report)?;
    log.push(&sid, "M8", "D2", "D1", EventStatus::Info, "AuthResult signed sig8 (session-bound)");
    let mut d1s = d1s;
    let (d1_decision, confirm) = match d1_verify_m8(&mut d1s, &m8) {
        Ok(dec) => {
            log.push(&sid, "M8", "D1", "D1", EventStatus::Ok, format!("verified under certified D2 key: {dec:?}"));
            let c = d1_session_confirm(d1, &d1s, dec)?;
            (Some(dec), Some(c))
        }
        Err(e) => {
            log.push(&sid, "M8", "D1", "D1", EventStatus::Fail, format!("rejected: {}", e.code));
            (None, None)
        }
    };

    Ok(AuthRunResult {
        report: m7.report,
        session_id: sid,
        d1_session: d1s,
        d2_session: d2s,
        proof_bundle: proof,
        m8,
        d1_decision,
        confirm,
    })
}

/// Outcome of K1-K3.
pub struct ChannelEstablished {
    pub d1_keys: ChannelKeys,
    pub d2_keys: ChannelKeys,
    pub d1_cred_id: [u8; 16],
    pub d2_cred_id: [u8; 16],
}

/// K1-K3. Requires the completed run (K1 is built from D1's signed
/// confirmation and the D2 verdict); the GCS independently enforces the
/// session state, so a DENY run, a forged request or a replay fails.
pub fn run_group_key_establishment(
    gcs: &mut GcsState,
    d1: &DroneState,
    d2: &DroneState,
    run: &AuthRunResult,
    mission_id: &str,
    log: &mut EventLog,
) -> Result<ChannelEstablished, AuthError> {
    let sid = &run.session_id;
    let confirm = run
        .confirm
        .clone()
        .ok_or(AuthError { code: "SESSION_INCOMPLETE", detail: "D1 did not confirm M8".into() })?;
    let (wire, _plain) = d2_k1_group_key_req(d2, &run.d2_session, &run.report, confirm, mission_id)?;
    log.push(sid, "K1", "D2", "GCS", EventStatus::Info, "GroupKeyReq (D2 sig + D1 confirm) sealed to GCS");
    let resp_wire = match gcs_handle_k1(gcs, &wire) {
        Ok(w) => w,
        Err(e) => {
            log.push(sid, "K1", "GCS", "D2", EventStatus::Fail, format!("refused: {}", e.code));
            return Err(e);
        }
    };
    log.push(sid, "K1", "GCS", "D2", EventStatus::Ok, "group key issued: signed, sealed separately to D1 and D2");
    let (resp, delivery) = d2_handle_k1_response(d2, &resp_wire)?;
    log.push(sid, "K2", "D2", "D1", EventStatus::Info, "KeyDelivery (D1's sealed key forwarded, signed sig8)");
    if !d1_verify_key_delivery(&run.d1_session, &delivery) {
        return Err(AuthError { code: "KEY_DELIVERY_INVALID", detail: "K2 not bound to D1's session".into() });
    }
    let m1 = d1_decapsulate_group_key(d1, &run.d1_session, &delivery)?;
    let m2 = d2_decapsulate_group_key(d2, &run.d2_session, &resp)?;
    log.push(sid, "K3", "D1", "D2", EventStatus::Ok, "both drones hold the GCS-issued group key (GCS knows it)");
    let d1c = d1.credential.as_ref().unwrap().body.cred_id;
    let d2c = d2.credential.as_ref().unwrap().body.cred_id;
    Ok(ChannelEstablished {
        d1_keys: derive_channel_keys(&m1, &d1c, &d2c),
        d2_keys: derive_channel_keys(&m2, &d1c, &d2c),
        d1_cred_id: d1c,
        d2_cred_id: d2c,
    })
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

/// Revoke a drone: record inactive, Merkle leaf zeroed (version++), all
/// its PIDs expired, open sessions failed. Other members' cached witnesses
/// become stale until refreshed; M5/M6 enforce root/version equality.
pub fn revoke_drone(gcs: &mut GcsState, drone_id: &str) -> Result<(), SimError> {
    let record = gcs.drones.get_mut(drone_id).ok_or_else(|| SimError::UnknownDrone(drone_id.to_string()))?;
    record.active = false;
    let group_id = record.group_id.clone();
    let tree = gcs.groups.get_mut(&group_id).ok_or_else(|| SimError::UnknownDrone(drone_id.to_string()))?;
    if tree.is_active(drone_id) {
        tree.revoke(drone_id)?;
    }
    gcs.expire_pids_of(drone_id);
    gcs.fail_sessions_of(drone_id, "MEMBER_REVOKED");
    Ok(())
}

/// Re-enroll a previously revoked drone in its group (fresh rho, fresh
/// credential, fresh CRPs and PIDs). An operator decision.
pub fn reactivate_drone(gcs: &mut GcsState, drone: &mut DroneState, merkle_depth: usize) -> Result<usize, SimError> {
    let group_id = drone.group_id.clone().ok_or_else(|| SimError::UnknownDrone(drone.drone_id.clone()))?;
    let metadata = drone
        .metadata
        .clone()
        .unwrap_or(crate::identity::metadata::MembershipMetadata { role: "reactivated".into(), issued_at_unix: 0 });
    drone.revoked = false;
    Ok(registration::register_drone(gcs, drone, &group_id, metadata, merkle_depth)?)
}

/// Move a drone to another group: revoke from the old one, enroll afresh.
pub fn move_drone(gcs: &mut GcsState, drone: &mut DroneState, new_group_id: &str, merkle_depth: usize) -> Result<usize, SimError> {
    if let Some(old) = drone.group_id.clone() {
        if gcs.groups.get(&old).map(|t| t.is_active(&drone.drone_id)).unwrap_or(false) {
            revoke_drone(gcs, &drone.drone_id)?;
        }
    }
    drone.revoked = false;
    let metadata = drone
        .metadata
        .clone()
        .unwrap_or(crate::identity::metadata::MembershipMetadata { role: "member".into(), issued_at_unix: 0 });
    Ok(registration::register_drone(gcs, drone, new_group_id, metadata, merkle_depth)?)
}

pub fn refresh_all_in_group(gcs: &GcsState, drones: &mut [&mut DroneState], group_id: &str) {
    for d in drones.iter_mut() {
        if d.group_id.as_deref() == Some(group_id) {
            registration::refresh_drone_cache(gcs, d);
        }
    }
}

/// Session state helper for tests / API views.
pub fn session_state(gcs: &GcsState, session_id: &str) -> Option<SessionState> {
    gcs.sessions.get(session_id).map(|s| s.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::metadata::MembershipMetadata;
    use crate::protocol::registration::refresh_drone_cache;
    use crate::protocol::secure_messaging;

    const DEPTH: usize = 4;

    fn md() -> MembershipMetadata {
        MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 }
    }

    fn setup() -> (GcsState, DroneState, DroneState) {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [11u8; 32]);
        let mut d2 = DroneState::new("drone-2", [22u8; 32]);
        registration::register_drone(&mut gcs, &mut d1, "alpha", md(), DEPTH).unwrap();
        registration::register_drone(&mut gcs, &mut d2, "alpha", md(), DEPTH).unwrap();
        refresh_drone_cache(&gcs, &mut d1);
        refresh_drone_cache(&gcs, &mut d2);
        (gcs, d1, d2)
    }

    /// Manual stepping up to (and including) M5, for tamper tests.
    struct Stage {
        comm_req: CommReq,
        m2: M2Output,
        d2s: D2Session,
        challenge: ChallengeMsg,
        d1s: D1Session,
        proof: ProofBundle,
    }

    fn up_to_m5(gcs: &mut GcsState, d1: &mut DroneState, d2: &DroneState) -> Stage {
        let comm_req = m1_comm_req(d1).unwrap();
        let m2 = m2_cred_req(d2, &comm_req).unwrap();
        let acc = gcs_receive_m2(gcs, &m2.wire).unwrap();
        let (m3w, _) = gcs_m3_cred_resp(gcs, &acc).unwrap();
        let mut d2s = d2_receive_m3(d2, &m3w, &comm_req, &m2).unwrap();
        let challenge = m4_challenge(d2, &mut d2s).unwrap();
        let d1s = d1_verify_challenge(d1, &challenge, &comm_req).unwrap();
        let proof = m5_proof_bundle(d1, &d1s).unwrap();
        Stage { comm_req, m2, d2s, challenge, d1s, proof }
    }

    fn m6_m7(gcs: &mut GcsState, d2: &DroneState, st: &Stage, proof: &ProofBundle) -> (PufVerifyResp, VerificationReport) {
        let w = m6_puf_verify_req(d2, &st.d2s, proof).unwrap();
        let resp = gcs_m6_verify(gcs, &w).unwrap();
        let rep = m7_verify_and_decide(d2, &st.d2s, proof, &resp, &DefaultPolicy::default()).report;
        (resp, rep)
    }

    #[test]
    fn happy_path_authentication_allows() {
        let (mut gcs, mut d1, d2) = setup();
        let mut log = EventLog::new();
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        assert_eq!(r.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", r.report);
        assert!(r.report.authenticated);
        assert_eq!(r.d1_decision, Some(ZeroTrustDecision::Allow));
        assert_eq!(session_state(&gcs, &r.session_id), Some(SessionState::PufVerified));
        // D2 must not learn D1's permanent DroneID from anything it received.
        let json = serde_json::to_string(&r.d2_session.m3).unwrap();
        assert!(!json.contains("drone-1"));
    }

    #[test]
    fn revoked_d1_is_rejected_at_m2() {
        let (mut gcs, mut d1, d2) = setup();
        revoke_drone(&mut gcs, "drone-1").unwrap();
        let mut log = EventLog::new();
        match run_authentication(&mut gcs, &mut d1, &d2, &mut log) {
            Err(e) => assert!(e.code == "D1_NOT_ACTIVE_MEMBER" || e.code == "PID_NOT_ACTIVE", "{e}"),
            Ok(_) => panic!("revoked D1 must not authenticate"),
        }
    }

    #[test]
    fn stale_cache_cannot_prove_until_refreshed() {
        let (mut gcs, mut d1, d2) = setup();
        let mut d3 = DroneState::new("drone-3", [33u8; 32]);
        registration::register_drone(&mut gcs, &mut d3, "alpha", md(), DEPTH).unwrap();
        let mut log = EventLog::new();
        let e = run_authentication(&mut gcs, &mut d1, &d2, &mut log).err().expect("stale");
        assert_eq!(e.code, "STALE_MEMBERSHIP");
        refresh_drone_cache(&gcs, &mut d1);
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
        assert_eq!(r.report.zero_trust, ZeroTrustDecision::Allow);
    }

    #[test]
    fn tampered_signature_is_denied() {
        let (mut gcs, mut d1, d2) = setup();
        let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
        st.proof.sig1[0] ^= 0xFF;
        let (_, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
        assert!(!rep.signature_ok);
        assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
    }

    #[test]
    fn altered_puf_mac_yields_signed_failure_and_burns_session() {
        let (mut gcs, mut d1, d2) = setup();
        let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
        st.proof.mac1[0] ^= 0xFF;
        let (resp, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
        assert_eq!(resp.body.result, PufVerifyResult::Invalid);
        assert!(verify_m6_signature(&gcs.sign_pk, &resp), "failure result must be GCS-signed");
        assert!(!rep.puf_ok);
        assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
        assert_eq!(session_state(&gcs, &st.d2s.m3.body.session_id), Some(SessionState::Failed));
    }

    #[test]
    fn tampered_zk_proof_is_denied() {
        let (mut gcs, mut d1, d2) = setup();
        let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
        let n = st.proof.proof.bytes.len();
        st.proof.proof.bytes[n / 2] ^= 1;
        let (_, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
        assert!(!rep.zk_membership_ok);
        assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
    }

    #[test]
    fn replayed_m2_is_rejected() {
        let (mut gcs, mut d1, d2) = setup();
        let comm_req = m1_comm_req(&mut d1).unwrap();
        let m2 = m2_cred_req(&d2, &comm_req).unwrap();
        let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
        gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
        let e = gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap();
        assert!(e.code == "NONCE_REPLAY" || e.code == "PID_NOT_ACTIVE", "{e}");
    }

    #[test]
    fn consumed_pid_cannot_start_second_session() {
        let (mut gcs, mut d1, d2) = setup();
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
        let _ = r;
        // Re-use the PID with fresh nonces.
        let mut replay = CommReq { g: "alpha".into(), pid1: r.d1_session.pid1.clone(), ts1: crate::protocol::events::now_unix_ms(), n1: fresh_nonce(16) };
        replay.n1[0] ^= 1;
        let m2 = m2_cred_req(&d2, &replay).unwrap();
        assert_eq!(gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap().code, "PID_NOT_ACTIVE");
    }

    #[test]
    fn unknown_pid_and_cross_group_rejected_at_m2() {
        let (mut gcs, _d1, d2) = setup();
        let bogus = CommReq { g: "alpha".into(), pid1: vec![0xAA; 16], ts1: crate::protocol::events::now_unix_ms(), n1: fresh_nonce(16) };
        let m2 = m2_cred_req(&d2, &bogus).unwrap();
        assert_eq!(gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap().code, "UNKNOWN_PID");

        let mut d3 = DroneState::new("drone-3", [33u8; 32]);
        let mut d4 = DroneState::new("drone-4", [44u8; 32]);
        registration::register_drone(&mut gcs, &mut d3, "alpha", md(), DEPTH).unwrap();
        registration::register_drone(&mut gcs, &mut d4, "bravo", md(), DEPTH).unwrap();
        let cr = m1_comm_req(&mut d3).unwrap();
        let m2 = m2_cred_req(&d4, &cr).unwrap();
        assert!(gcs_receive_m2(&mut gcs, &m2.wire).is_err());
    }

    #[test]
    fn forged_m4_key_is_rejected_by_d1() {
        let (mut gcs, mut d1, d2) = setup();
        let comm_req = m1_comm_req(&mut d1).unwrap();
        let m2 = m2_cred_req(&d2, &comm_req).unwrap();
        let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
        let (m3w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
        let mut d2s = d2_receive_m3(&d2, &m3w, &comm_req, &m2).unwrap();
        let mut ch = m4_challenge(&d2, &mut d2s).unwrap();
        // Attacker swaps in its own signing key and re-signs M4.
        let (apk, ask) = crate::crypto::sign::keypair();
        ch.d2_cred.body.pk_dil = apk.0.clone();
        ch.sig4 = crate::crypto::sign::sign_transcript(&ask, &ch.payload.signing_bytes()).unwrap().0;
        assert_eq!(d1_verify_challenge(&d1, &ch, &comm_req).err().unwrap().code, "CREDENTIAL_INVALID");
    }

    #[test]
    fn invalid_gcs_signature_on_m3_is_rejected() {
        let (mut gcs, mut d1, d2) = setup();
        let comm_req = m1_comm_req(&mut d1).unwrap();
        let m2 = m2_cred_req(&d2, &comm_req).unwrap();
        let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
        let (m3w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
        let mut d2s = d2_receive_m3(&d2, &m3w, &comm_req, &m2).unwrap();
        let mut ch = m4_challenge(&d2, &mut d2s).unwrap();
        ch.m3.sig3[0] ^= 1;
        assert_eq!(d1_verify_challenge(&d1, &ch, &comm_req).err().unwrap().code, "GCS_SIGNATURE_INVALID");
    }

    #[test]
    fn k1_rejected_before_auth_and_after_deny() {
        let (mut gcs, mut d1, d2) = setup();
        let st = up_to_m5(&mut gcs, &mut d1, &d2);
        // K1 before M6: session is CredIssued.
        let rep = VerificationReport { zero_trust: ZeroTrustDecision::Allow, ..empty_report(st.d2s.session_ctx) };
        let confirm = {
            let mut s1 = st.d1s;
            // forge a "completed" session locally to build a confirm
            s1.completed = true;
            d1_session_confirm(&d1, &s1, ZeroTrustDecision::Allow).unwrap()
        };
        let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &rep, confirm, "m1").unwrap();
        assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "SESSION_NOT_AUTHENTICATED");

        // After a failed M6 (DENY) the session is Failed.
        let (mut gcs, mut d1, d2) = setup();
        let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
        st.proof.mac1[0] ^= 1;
        let _ = m6_m7(&mut gcs, &d2, &st, &st.proof);
        let rep = VerificationReport { zero_trust: ZeroTrustDecision::Allow, ..empty_report(st.d2s.session_ctx) };
        let mut s1 = st.d1s;
        s1.completed = true;
        let confirm = d1_session_confirm(&d1, &s1, ZeroTrustDecision::Allow).unwrap();
        let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &rep, confirm, "m1").unwrap();
        assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "SESSION_DENIED");
    }

    fn empty_report(ctx: crate::zkhash::Limbs) -> VerificationReport {
        VerificationReport {
            freshness_ok: true, credential_ok: true, commitment_ok: true, zk_membership_ok: true,
            signature_ok: true, puf_ok: true, root_version_ok: true, session_binding_ok: true,
            authenticated: true, zero_trust: ZeroTrustDecision::Allow, reason_code: String::new(), session_ctx: ctx,
        }
    }

    #[test]
    fn full_flow_k1_once_per_session_and_aead() {
        let (mut gcs, mut d1, d2) = setup();
        let mut log = EventLog::new();
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        let ch = run_group_key_establishment(&mut gcs, &d1, &d2, &r, "mission-7", &mut log).unwrap();
        assert_eq!(session_state(&gcs, &r.session_id), Some(SessionState::KeyIssued));
        assert_eq!(ch.d1_keys.channel_tag, ch.d2_keys.channel_tag);
        let m = secure_messaging::send_message(&ch.d1_keys.d1_to_d2, &crate::transport::PassthroughTransport, ch.d1_keys.channel_tag, 1, 1, b"hello").unwrap();
        let pt = secure_messaging::receive_message(&ch.d2_keys.d1_to_d2, ch.d2_keys.channel_tag, 1, &m.0, 0).unwrap();
        assert_eq!(pt, b"hello");
        // Second K1 for the same session is refused.
        let again = run_group_key_establishment(&mut gcs, &d1, &d2, &r, "mission-7", &mut log);
        assert!(again.is_err());
    }

    #[test]
    fn revocation_after_auth_blocks_k1() {
        let (mut gcs, mut d1, d2) = setup();
        let mut log = EventLog::new();
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        revoke_drone(&mut gcs, "drone-1").unwrap();
        assert!(run_group_key_establishment(&mut gcs, &d1, &d2, &r, "m", &mut log).is_err());
    }

    #[test]
    fn move_and_reactivate() {
        let (mut gcs, mut d1, mut d2) = setup();
        gcs.create_group("bravo", DEPTH);
        move_drone(&mut gcs, &mut d2, "bravo", DEPTH).unwrap();
        move_drone(&mut gcs, &mut d1, "bravo", DEPTH).unwrap();
        refresh_drone_cache(&gcs, &mut d1);
        refresh_drone_cache(&gcs, &mut d2);
        assert!(!gcs.groups["alpha"].is_active("drone-1"));
        assert!(gcs.groups["bravo"].is_active("drone-1"));
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
        assert_eq!(r.report.zero_trust, ZeroTrustDecision::Allow);

        revoke_drone(&mut gcs, "drone-1").unwrap();
        reactivate_drone(&mut gcs, &mut d1, DEPTH).unwrap();
        refresh_drone_cache(&gcs, &mut d1);
        refresh_drone_cache(&gcs, &mut d2);
        let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
        assert_eq!(r.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", r.report);
    }
}
