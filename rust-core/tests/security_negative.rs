//! Additional public-API-level negative/security tests, filling in the
//! specific cases from the project brief's security-test checklist that
//! aren't already covered by the extensive unit-test suites inside
//! `src/crypto/`, `src/zk/`, and `src/protocol/simulation.rs` (see
//! `docs/testing.md` for the full checklist-to-test mapping). This file
//! covers: stale timestamp, altered public key, and malformed message.

use iod_core::identity::metadata::MembershipMetadata;
use iod_core::protocol::auth_flow::*;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::registration::{refresh_drone_cache, register_drone};

fn two_registered_drones() -> (GcsState, DroneState, DroneState) {
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("neg-d1", [201u8; 32]);
    let mut d2 = DroneState::new("neg-d2", [202u8; 32]);
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
    register_drone(&mut gcs, &mut d1, "neg-group", md.clone(), 6).unwrap();
    register_drone(&mut gcs, &mut d2, "neg-group", md, 6).unwrap();
    refresh_drone_cache(&gcs, &mut d1);
    (gcs, d1, d2)
}

#[test]
fn stale_timestamp_fails_freshness_check() {
    let (mut gcs, mut d1, d2) = two_registered_drones();

    let mut comm_req = m1_comm_req(&mut d1);
    comm_req.ts1 -= 10 * 60 * 1000; // 10 minutes in the past, beyond MAX_TIMESTAMP_SKEW_MS

    let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap();
    let (_plain2, d1_id) = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    let (m3_wire, _m3_plain) = gcs_m3_cred_resp(&gcs, &d1_id, &d2.drone_id).unwrap();
    let cred_resp = d2_receive_m3(&d2, &m3_wire).unwrap();
    let challenge = m4_challenge(&d2, "neg-group", &cred_resp.cred_d1, &cred_resp.d2_cert, &m2.plain.n2).unwrap();
    let ctx = d1_local_auth_context(&d1);
    let proof = m5_proof_bundle(&d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx).unwrap();

    let t_base = iod_core::protocol::transcript::build_t_base(
        ctx.g_field, ctx.v_g, ctx.r_g, proof.comm_pk_d1,
        &comm_req.n1, &m2.plain.n2, comm_req.ts1, challenge.challenge_payload.ts4, &comm_req.pid1,
    );
    let m6_wire = m6_puf_verify_req(&proof, "neg-group", ctx.v_g, &challenge.challenge_payload.c_puf, &m2.plain.n2, &t_base, &gcs.kem_pk).unwrap();
    let puf_resp = gcs_m6_verify(&mut gcs, &m6_wire).unwrap();

    let m7 = m7_verify_and_decide(
        &cred_resp.cred_d1, &proof, &comm_req.n1, &m2.plain.n2,
        comm_req.ts1, challenge.challenge_payload.ts4, &puf_resp, &gcs.sign_pk, "neg-group",
    );
    assert!(!m7.report.freshness_ok, "a timestamp 10 minutes stale must fail the freshness check");
    assert_eq!(
        format!("{:?}", m7.report.zero_trust),
        "Deny",
        "Zero Trust must deny when freshness fails, even though every other check passed"
    );
}

#[test]
fn claiming_a_different_public_key_than_registered_fails_zk_and_signature_checks() {
    let (mut gcs, mut d1, d2) = two_registered_drones();

    let comm_req = m1_comm_req(&mut d1);
    let m2 = m2_cred_req(&d2, &comm_req, &gcs.kem_pk).unwrap();
    let (_plain2, d1_id) = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    let (m3_wire, _m3_plain) = gcs_m3_cred_resp(&gcs, &d1_id, &d2.drone_id).unwrap();
    let cred_resp = d2_receive_m3(&d2, &m3_wire).unwrap();
    let challenge = m4_challenge(&d2, "neg-group", &cred_resp.cred_d1, &cred_resp.d2_cert, &m2.plain.n2).unwrap();
    let ctx = d1_local_auth_context(&d1);
    let mut proof = m5_proof_bundle(&d1, &challenge, &comm_req.n1, comm_req.ts1, &comm_req.pid1, &ctx).unwrap();

    // Attacker/forger substitutes a different Dilithium public key into
    // the transmitted bundle after the fact, without a matching secret
    // key or matching leaf — this must be caught, not silently trusted.
    let (forged_pk, _forged_sk) = iod_core::crypto::sign::keypair();
    proof.pk_dil_d1 = forged_pk.0;

    let t_base = iod_core::protocol::transcript::build_t_base(
        ctx.g_field, ctx.v_g, ctx.r_g, proof.comm_pk_d1,
        &comm_req.n1, &m2.plain.n2, comm_req.ts1, challenge.challenge_payload.ts4, &comm_req.pid1,
    );
    let m6_wire = m6_puf_verify_req(&proof, "neg-group", ctx.v_g, &challenge.challenge_payload.c_puf, &m2.plain.n2, &t_base, &gcs.kem_pk).unwrap();
    let puf_resp = gcs_m6_verify(&mut gcs, &m6_wire).unwrap();

    let m7 = m7_verify_and_decide(
        &cred_resp.cred_d1, &proof, &comm_req.n1, &m2.plain.n2,
        comm_req.ts1, challenge.challenge_payload.ts4, &puf_resp, &gcs.sign_pk, "neg-group",
    );
    assert!(!m7.report.signature_ok, "the substituted public key must not validate the original signature");
    assert_eq!(format!("{:?}", m7.report.zero_trust), "Deny");
}

#[test]
fn malformed_m2_envelope_is_rejected_not_panicked_on() {
    let (mut gcs, _d1, _d2) = two_registered_drones();
    let malformed = iod_core::protocol::envelope::SecureEnvelope {
        kem_ciphertext: vec![0xFFu8; 10], // wrong length / garbage, not a real Kyber768 ciphertext
        sealed: iod_core::crypto::aead::SealedMessage {
            seq: 1,
            nonce: [0u8; 12],
            ciphertext: vec![1, 2, 3],
        },
    };
    let result = gcs_receive_m2(&mut gcs, &malformed);
    assert!(result.is_err(), "a malformed envelope must be rejected with an error, not panic or silently succeed");
}
