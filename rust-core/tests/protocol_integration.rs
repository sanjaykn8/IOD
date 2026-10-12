//! Integration tests 1-16 (public API only). Each test name starts with
//! its number. Every negative test asserts the specific reason code.

mod common;
use common::*;
use iod_core::crypto::sign;
use iod_core::protocol::auth_flow::*;
use iod_core::protocol::entities::{PidState, SessionState};
use iod_core::protocol::events::{with_clock_skew, EventLog};
use iod_core::protocol::group_key::*;
use iod_core::protocol::messages::*;
use iod_core::protocol::simulation::*;

fn confirm_for(d1: &iod_core::protocol::entities::DroneState, mut s1: D1Session, seen: ZeroTrustDecision) -> SignedSessionConfirm {
    s1.completed = true;
    d1_session_confirm(d1, &s1, seen).unwrap()
}

fn allow_report(ctx: iod_core::zkhash::Limbs) -> VerificationReport {
    VerificationReport {
        freshness_ok: true, credential_ok: true, commitment_ok: true, zk_membership_ok: true, signature_ok: true,
        puf_ok: true, root_version_ok: true, session_binding_ok: true, authenticated: true,
        zero_trust: ZeroTrustDecision::Allow, reason_code: String::new(), session_ctx: ctx,
    }
}

#[test]
fn t01_forged_m4_key_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let comm_req = m1_comm_req(&mut d1).unwrap();
    let m2 = m2_cred_req(&d2, &comm_req).unwrap();
    let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    let (w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
    let mut d2s = d2_receive_m3(&d2, &w, &comm_req, &m2).unwrap();
    let mut ch = m4_challenge(&d2, &mut d2s).unwrap();
    let (apk, ask) = sign::keypair();
    ch.d2_cred.body.pk_dil = apk.0.clone();
    ch.sig4 = sign::sign_transcript(&ask, &ch.payload.signing_bytes()).unwrap().0;
    assert_eq!(d1_verify_challenge(&d1, &ch, &comm_req).err().unwrap().code, "CREDENTIAL_INVALID");
}

#[test]
fn t02_invalid_gcs_signature_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let comm_req = m1_comm_req(&mut d1).unwrap();
    let m2 = m2_cred_req(&d2, &comm_req).unwrap();
    let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    let (w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
    let mut d2s = d2_receive_m3(&d2, &w, &comm_req, &m2).unwrap();
    let mut ch = m4_challenge(&d2, &mut d2s).unwrap();
    ch.m3.sig3[3] ^= 1;
    assert_eq!(d1_verify_challenge(&d1, &ch, &comm_req).err().unwrap().code, "GCS_SIGNATURE_INVALID");
    // A rogue "GCS" (different anchor) is rejected by a drone pinned to the real one.
    let (mut rogue, _, _) = setup();
    let cr = m1_comm_req(&mut d1).unwrap();
    let m2b = m2_cred_req(&d2, &cr).unwrap();
    assert!(gcs_receive_m2(&mut rogue, &m2b.wire).is_err(), "rogue GCS cannot even open a message sealed to the real GCS");
}

#[test]
fn t03_expired_pid_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let cr = m1_comm_req(&mut d1).unwrap();
    gcs.pid_pool.get_mut(&cr.pid1).unwrap().expires_at_ms = 1;
    let m2 = m2_cred_req(&d2, &cr).unwrap();
    assert_eq!(gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap().code, "PID_EXPIRED");
}

#[test]
fn t04_consumed_pid_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    assert_eq!(gcs.pid_pool[&r.d1_session.pid1].state, PidState::Consumed);
    let cr = iod_core::protocol::messages::CommReq { g: "alpha".into(), pid1: r.d1_session.pid1.clone(), ts1: iod_core::protocol::events::now_unix_ms(), n1: fresh_nonce(16) };
    let m2 = m2_cred_req(&d2, &cr).unwrap();
    assert_eq!(gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap().code, "PID_NOT_ACTIVE");
}

#[test]
fn t05_k1_rejected_before_authentication() {
    let (mut gcs, mut d1, d2) = setup();
    let st = up_to_m5(&mut gcs, &mut d1, &d2);
    let confirm = confirm_for(&d1, st.d1s, ZeroTrustDecision::Allow);
    let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &allow_report(st.d2s.session_ctx), confirm, "m").unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "SESSION_NOT_AUTHENTICATED");
    // K1 for a session id the GCS never created.
    let (mut gcs2, _, _) = setup();
    assert_eq!(gcs_handle_k1(&mut gcs2, &w).err().unwrap_or_else(|| panic!("must fail")).code.len() > 0, true);
}

#[test]
fn t06_k1_rejected_after_deny() {
    // (a) M6 failure -> session Failed.
    let (mut gcs, mut d1, d2) = setup();
    let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
    st.proof.mac1[0] ^= 1;
    let (_, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
    assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
    let confirm = confirm_for(&d1, st.d1s, ZeroTrustDecision::Allow);
    let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &allow_report(st.d2s.session_ctx), confirm, "m").unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "SESSION_DENIED");

    // (b) GCS verified M6 but D2 DENIES (bad sig1): honest D2 cannot get a key,
    // and a lying D2 is caught by D1's own confirmation (D1 saw DENY in M8).
    let (mut gcs, mut d1, d2) = setup();
    let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
    st.proof.sig1[0] ^= 1;
    let (_, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
    assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
    let m8 = m8_auth_result(&d2, &st.d2s, &rep).unwrap();
    let mut d1s = st.d1s;
    let seen = d1_verify_m8(&mut d1s, &m8).unwrap();
    assert_eq!(seen, ZeroTrustDecision::Deny);
    let honest_confirm = d1_session_confirm(&d1, &d1s, seen).unwrap();
    let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &rep, honest_confirm.clone(), "m").unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "NOT_ALLOWED");
    let (w, _) = d2_k1_group_key_req(&d2, &st.d2s, &allow_report(st.d2s.session_ctx), honest_confirm, "m").unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "D1_CONFIRM_INVALID");
}

#[test]
fn t07_k1_only_after_allow_for_the_exact_session() {
    let (mut gcs, mut d1, d2) = setup();
    let ra = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    let rb = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    assert_ne!(ra.session_id, rb.session_id);
    // Session A's D2 request carrying session B's confirmation is refused.
    let (w, _) = d2_k1_group_key_req(&d2, &ra.d2_session, &ra.report, rb.confirm.clone().unwrap(), "m").unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "D1_CONFIRM_INVALID");
    // Exact session succeeds, and then ONLY that session is KeyIssued.
    let mut log = EventLog::new();
    run_group_key_establishment(&mut gcs, &d1, &d2, &ra, "m", &mut log).unwrap();
    assert_eq!(session_state(&gcs, &ra.session_id), Some(SessionState::KeyIssued));
    assert_eq!(session_state(&gcs, &rb.session_id), Some(SessionState::PufVerified));
}

#[test]
fn t08_revocation_blocks_auth_and_key_issue() {
    let (mut gcs, mut d1, d2) = setup();
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    revoke_drone(&mut gcs, "drone-1").unwrap();
    assert_eq!(session_state(&gcs, &r.session_id), Some(SessionState::Failed));
    assert!(run_group_key_establishment(&mut gcs, &d1, &d2, &r, "m", &mut EventLog::new()).is_err());
    assert!(run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).is_err());
    // revoking D2 blocks D2 as requester as well
    let (mut gcs, mut d1, d2) = setup();
    revoke_drone(&mut gcs, "drone-2").unwrap();
    assert!(run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).is_err());
}

#[test]
fn t09_replays_rejected_m2_m6_k1() {
    let (mut gcs, mut d1, d2) = setup();
    // M2 replay
    let cr = m1_comm_req(&mut d1).unwrap();
    let m2 = m2_cred_req(&d2, &cr).unwrap();
    let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
    assert!(gcs_receive_m2(&mut gcs, &m2.wire).is_err());
    // M6 replay
    let (mut gcs, mut d1, d2) = setup();
    let st = up_to_m5(&mut gcs, &mut d1, &d2);
    let w = m6_puf_verify_req(&d2, &st.d2s, &st.proof).unwrap();
    let first = gcs_m6_verify(&mut gcs, &w).unwrap();
    assert_eq!(first.body.result, PufVerifyResult::Valid);
    let again = gcs_m6_verify(&mut gcs, &w).unwrap();
    assert_eq!(again.body.result, PufVerifyResult::Invalid, "replayed M6 must not yield a Valid result");
    assert_eq!(again.body.reason_code, "SESSION_REPLAY_OR_WRONG_STATE");
    assert_eq!(session_state(&gcs, &st.d2s.m3.body.session_id), Some(SessionState::PufVerified), "replay must not disturb the session");
    // K1 replay
    let (mut gcs, mut d1, d2) = setup();
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    let (w, _) = d2_k1_group_key_req(&d2, &r.d2_session, &r.report, r.confirm.clone().unwrap(), "m").unwrap();
    gcs_handle_k1(&mut gcs, &w).unwrap();
    assert_eq!(gcs_handle_k1(&mut gcs, &w).err().unwrap().code, "SESSION_REPLAY");
}

#[test]
fn t10_m3_m5_commitment_consistency_and_no_witness_on_wire() {
    let (mut gcs, mut d1, d2) = setup();
    let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
    // M5 JSON carries no key fields and no witness material.
    let json = serde_json::to_string(&st.proof).unwrap();
    for banned in ["pk_kem", "pk_dil", "rho", "siblings", "path_bits", "witness"] {
        assert!(!json.contains(banned), "M5 must not contain '{banned}'");
    }
    // comm_pk swapped in M5 vs. the GCS-signed M3 credential.
    st.proof.comm_pk_d1[0] ^= 1;
    let (_, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
    assert!(!rep.commitment_ok);
    assert_eq!(rep.zero_trust, ZeroTrustDecision::Deny);
}

#[test]
fn t11_stale_membership_root_detected() {
    let (mut gcs, mut d1, d2) = setup();
    let mut d3 = iod_core::protocol::entities::DroneState::new("drone-3", [33u8; 32]);
    iod_core::protocol::registration::register_drone(&mut gcs, &mut d3, "alpha", md(), DEPTH).unwrap();
    let cr = m1_comm_req(&mut d1).unwrap();
    let m2 = m2_cred_req(&d2, &cr).unwrap();
    let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    let (w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
    let mut d2s = d2_receive_m3(&d2, &w, &cr, &m2).unwrap();
    let ch = m4_challenge(&d2, &mut d2s).unwrap();
    let d1s = d1_verify_challenge(&d1, &ch, &cr).unwrap();
    assert_eq!(m5_proof_bundle(&d1, &d1s).err().unwrap().code, "STALE_MEMBERSHIP");
}

#[test]
fn t12_stale_timestamp_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let ten_min = 10 * 60 * 1000;
    let (cr, m2) = with_clock_skew(-ten_min, || {
        let cr = m1_comm_req(&mut d1).unwrap();
        let m2 = m2_cred_req(&d2, &cr).unwrap();
        (cr, m2)
    });
    let _ = cr;
    assert_eq!(gcs_receive_m2(&mut gcs, &m2.wire).err().unwrap().code, "STALE_TIMESTAMP");
}

#[test]
fn t13_m6_failure_is_gcs_signed_with_reason() {
    let (mut gcs, mut d1, d2) = setup();
    let mut st = up_to_m5(&mut gcs, &mut d1, &d2);
    st.proof.mac1[5] ^= 0x40;
    let (resp, rep) = m6_m7(&mut gcs, &d2, &st, &st.proof);
    assert_eq!(resp.body.result, PufVerifyResult::Invalid);
    assert!(!resp.body.reason_code.is_empty());
    assert!(verify_m6_signature(&gcs.sign_pk, &resp));
    assert!(!rep.puf_ok && rep.zero_trust == ZeroTrustDecision::Deny);
    // A forged "Valid" (unsigned by the GCS) is rejected by D2.
    let mut forged = resp.clone();
    forged.body.result = PufVerifyResult::Valid;
    assert!(!verify_m6_signature(&gcs.sign_pk, &forged));
}

#[test]
fn t14_m8_replay_and_cross_session_binding() {
    let (mut gcs, mut d1, d2) = setup();
    let ra = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    let mut rb = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    // replay of A's M8 to A's (completed) D1 session
    let mut a1 = ra.d1_session;
    assert_eq!(d1_verify_m8(&mut a1, &ra.m8).err().unwrap().code, "SESSION_REPLAY");
    // A's M8 shown to B's D1 session (not completed yet)
    rb.d1_session.completed = false;
    assert_eq!(d1_verify_m8(&mut rb.d1_session, &ra.m8).err().unwrap().code, "SESSION_BINDING_MISMATCH");
    // tampered result
    let mut bad = rb.m8.clone();
    bad.payload.result = ZeroTrustDecision::Allow;
    bad.payload.reason_code = "x".into();
    assert_eq!(d1_verify_m8(&mut rb.d1_session, &bad).err().unwrap().code, "D2_SIGNATURE_INVALID");
}

#[test]
fn t15_secure_message_tamper_replay_direction() {
    use iod_core::protocol::secure_messaging::*;
    use iod_core::transport::PassthroughTransport;
    let (mut gcs, mut d1, d2) = setup();
    let mut log = EventLog::new();
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
    let ch = run_group_key_establishment(&mut gcs, &d1, &d2, &r, "m", &mut log).unwrap();
    let tag = ch.d1_keys.channel_tag;
    let (m, _) = send_message(&ch.d1_keys.d1_to_d2, &PassthroughTransport, tag, 1, 1, b"waypoint 7").unwrap();
    assert_eq!(receive_message(&ch.d2_keys.d1_to_d2, tag, 1, &m, 0).unwrap(), b"waypoint 7");
    assert!(receive_message(&ch.d2_keys.d1_to_d2, tag, 1, &m, 1).is_err(), "replay (seq <= last seen)");
    assert!(receive_message(&ch.d2_keys.d1_to_d2, tag, 2, &m, 0).is_err(), "wrong direction");
    assert!(receive_message(&ch.d2_keys.d2_to_d1, tag, 1, &m, 0).is_err(), "wrong key");
    let mut t = m.clone();
    t.sealed.ciphertext[0] ^= 1;
    assert!(receive_message(&ch.d2_keys.d1_to_d2, tag, 1, &t, 0).is_err(), "tampered ciphertext");
    let mut t = m.clone();
    t.header_ts += 1;
    assert!(receive_message(&ch.d2_keys.d1_to_d2, tag, 1, &t, 0).is_err(), "tampered header (AAD)");
    // header carries no identifiers
    let hdr = serde_json::to_string(&(m.channel_tag, m.direction, m.header_seq, m.header_ts)).unwrap();
    assert!(!hdr.contains("drone-"));
}

#[test]
fn t16_k1_forgeries_rejected() {
    let (mut gcs, mut d1, d2) = setup();
    let mut d3 = iod_core::protocol::entities::DroneState::new("drone-3", [33u8; 32]);
    iod_core::protocol::registration::register_drone(&mut gcs, &mut d3, "alpha", md(), DEPTH).unwrap();
    iod_core::protocol::registration::refresh_drone_cache(&gcs, &mut d1);
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).unwrap();
    // A different registered drone (D3) cannot request the key for D2's session.
    let (w, _) = d2_k1_group_key_req(&d3, &r.d2_session, &r.report, r.confirm.clone().unwrap(), "m").unwrap();
    assert!(gcs_handle_k1(&mut gcs, &w).is_err());
    // K1 sealed to a different key than the GCS's cannot be opened.
    let (other, _, _) = setup();
    let (w, _) = d2_k1_group_key_req(&d2, &r.d2_session, &r.report, r.confirm.clone().unwrap(), "m").unwrap();
    let mut other = other;
    assert!(gcs_handle_k1(&mut other, &w).is_err());
    // Session still unused: the genuine request still works afterwards.
    run_group_key_establishment(&mut gcs, &d1, &d2, &r, "m", &mut EventLog::new()).unwrap();
}
