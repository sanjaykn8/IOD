//! Integration test compiled as a separate binary against `iod_core`'s
//! PUBLIC API only (the Cargo `tests/` convention) — this is a different
//! testing modality from the `#[cfg(test)]` unit tests scattered through
//! `src/`: it verifies the crate's public surface actually composes into
//! a working system from the outside, the way `rust-core/src/api/` (and
//! ultimately the Node gateway + React dashboard) actually uses it.
//!
//! Covers the exact combination the project brief's "END-TO-END TEST"
//! section requires: GCS + D1 + D2 + group + registration +
//! authentication + authorization + group-key establishment + secure
//! message + logging, all executing automatically with `cargo test`.

use iod_core::identity::metadata::MembershipMetadata;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::events::EventLog;
use iod_core::protocol::messages::ZeroTrustDecision;
use iod_core::protocol::registration::{refresh_drone_cache, register_drone};
use iod_core::protocol::simulation::run_authentication;

#[test]
fn full_stack_end_to_end_gcs_d1_d2_group_auth_authz_groupkey_message_logging() {
    // GCS
    let mut gcs = GcsState::new();

    // Group
    gcs.create_group("mission-alpha", 8);

    // D1 + D2
    let mut d1 = DroneState::new("e2e-d1", [101u8; 32]);
    let mut d2 = DroneState::new("e2e-d2", [102u8; 32]);

    // Registration
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 };
    register_drone(&mut gcs, &mut d1, "mission-alpha", md.clone(), 8).expect("D1 registration must succeed");
    register_drone(&mut gcs, &mut d2, "mission-alpha", md, 8).expect("D2 registration must succeed");
    refresh_drone_cache(&gcs, &mut d1); // keep D1's witness fresh after D2 joined

    assert!(d1.is_registered());
    assert!(d2.is_registered());
    assert!(gcs.groups.get("mission-alpha").unwrap().is_active("e2e-d1"));
    assert!(gcs.groups.get("mission-alpha").unwrap().is_active("e2e-d2"));

    // Authentication + Authorization (Zero Trust)
    let mut log = EventLog::new();
    let auth_result = run_authentication(&mut gcs, &mut d1, &d2, &mut log)
        .expect("authentication must complete without a hard error for two freshly registered drones");

    assert_eq!(auth_result.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", auth_result.report);
    assert!(auth_result.report.freshness_ok);
    assert!(auth_result.report.zk_membership_ok);
    assert!(auth_result.report.signature_ok);
    assert!(auth_result.report.puf_ok);
    assert!(auth_result.report.root_version_ok);

    // Logging: every M1-M8 stage must appear in the event log.
    let stages: Vec<&str> = log.events.iter().map(|e| e.stage.as_str()).collect();
    for expected in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"] {
        assert!(stages.contains(&expected), "expected stage {expected} in event log, got {stages:?}");
    }

    // Group-key establishment (K1-K4)
    use iod_core::protocol::group_key::*;
    let d1_pid1 = iod_core::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);
    gcs.pid_pool.entry(d1_pid1.clone()).or_insert_with(|| d1.drone_id.clone());
    let (wire1, _plain1) = k1_group_key_req(&d2, "mission-alpha", &d1_pid1, "e2e-mission", [0u8; 32], &gcs.kem_pk)
        .expect("K1 request must build");
    let wire7 = gcs_handle_k1(&gcs, &wire1).expect("GCS must handle K1");
    let (resp, key_delivery) = d2_handle_k1_response(&d2, &wire7).expect("D2 must handle the K1 response");
    let k_d1 = d1_decapsulate_group_key(&d1, &key_delivery).expect("D1 must decapsulate the group key");
    let k_d2 = d2_decapsulate_group_key(&d2, &resp).expect("D2 must decapsulate the group key");
    assert_eq!(k_d1, k_d2, "D1 and D2 must derive the identical group key");

    let aead_key = derive_aead_key(&k_d1, b"n1", b"n2", b"n6", b"n7");

    // Secure message (K4 / AEAD)
    use iod_core::protocol::secure_messaging::{receive_message, send_message};
    use iod_core::transport::PassthroughTransport;
    let transport = PassthroughTransport;
    let (sealed_msg, _wire) = send_message(&aead_key, &transport, 1, b"e2e-d1", b"e2e-d2", b"mission status nominal")
        .expect("sealing the application message must succeed");
    let opened = receive_message(&aead_key, &sealed_msg, 0).expect("D2 must be able to open the message D1 sent");
    assert_eq!(opened, b"mission status nominal");
}

#[test]
fn revoke_then_reauthenticate_is_cleanly_denied_end_to_end() {
    let mut gcs = GcsState::new();
    gcs.create_group("mission-bravo", 8);
    let mut d1 = DroneState::new("e2e-revoke-d1", [111u8; 32]);
    let mut d2 = DroneState::new("e2e-revoke-d2", [112u8; 32]);
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
    register_drone(&mut gcs, &mut d1, "mission-bravo", md.clone(), 8).unwrap();
    register_drone(&mut gcs, &mut d2, "mission-bravo", md, 8).unwrap();
    refresh_drone_cache(&gcs, &mut d1);

    iod_core::protocol::simulation::revoke_drone(&mut gcs, "e2e-revoke-d1").expect("revocation must succeed");

    let mut log = EventLog::new();
    let result = run_authentication(&mut gcs, &mut d1, &d2, &mut log);
    assert!(result.is_err(), "GCS must refuse to vouch for a revoked drone");
}

/// The full mandated chain, end to end against the crate's public API
/// only: **Stego Registration -> Authentication -> Authorization ->
/// Group Key -> Secure Message -> Revocation -> Authentication
/// Failure.** Registration for BOTH drones goes through
/// `protocol::registration_stego` (the redesigned R1-R3-over-
/// steganography path), using `StegoClient`'s `MockStegoClient` test
/// double for the pixel-level embed/extract hop only (see that type's
/// docs: it is explicitly not a steganography implementation and is
/// never used to claim embed/extract correctness -- that is the real
/// algorithms' own test suite in `python-service/tests/` plus the live
/// cross-language `iod-register-stego-demo` run documented in
/// `docs/registration-stego.md`). Everything else in this test --
/// every crypto operation, every protocol message, every one of the
/// section-25 security fixes exercised along the way (credential
/// consistency at M7, the GCS-certified keys at M4/M8, the PUF-bound
/// leaf randomness from registration) -- is the real code, unmocked.
#[test]
fn full_chain_stego_registration_through_revocation_and_denied_reauthentication() {
    use iod_core::identity::metadata::MembershipMetadata;
    use iod_core::protocol::registration_stego::*;
    use iod_core::protocol::stego_client::{MockStegoClient, StegoClient};
    use iod_core::puf::crp::CrpReference;

    let stego = MockStegoClient;
    let mut gcs = GcsState::new();
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_750_000_000 };

    // ---- Stego Registration: D1 then D2, each a full real R1/R2/R3 ----
    let mut register_via_stego = |drone: &mut DroneState, entropy_tag: &str| -> usize {
        let material = d1_build_enrollment_request(drone, "mission-stego", &md);
        let sealed_r1 = encrypt_enrollment_request(&material.request, &gcs.kem_pk).expect("R1 must encrypt");
        let plaintext_r1 = serde_json::to_vec(&sealed_r1).expect("R1 envelope must serialize");

        // "Transit": a real embed call (mocked at the pixel level only).
        let embed_r1 = stego
            .select_and_embed(format!("cover-{entropy_tag}").as_bytes(), &plaintext_r1, "CRITICAL")
            .expect("R1 embed must succeed");
        let extracted_r1 = stego
            .extract(&embed_r1.stego_image_bytes, &embed_r1.stego_algorithm_id, embed_r1.payload_length, &embed_r1.algorithm_params_json)
            .expect("R1 extract must succeed");
        assert_eq!(extracted_r1, plaintext_r1, "stego transit must not alter the sealed R1 payload");

        let sealed_r1_recv: iod_core::protocol::envelope::SecureEnvelope =
            serde_json::from_slice(&extracted_r1).expect("R1 envelope must deserialize");
        let request = decrypt_enrollment_request(&sealed_r1_recv, &gcs.kem_sk).expect("GCS must decrypt R1");

        let crp = CrpReference {
            challenge: drone.crp_default_challenge.clone(),
            reference_response: drone.puf.challenge_response(&drone.crp_default_challenge),
        };
        let response = gcs_process_enrollment(&mut gcs, &request, 8, crp).expect("R2 (GCS-internal) must succeed");

        let drone_kem_pk = iod_core::crypto::kem::KemPublicKey(material.keys.kem_pk.0.clone());
        let sealed_r3 = encrypt_enrollment_response(&response, &drone_kem_pk).expect("R3 must encrypt");
        let plaintext_r3 = serde_json::to_vec(&sealed_r3).expect("R3 envelope must serialize");

        let embed_r3 = stego
            .select_and_embed(format!("cover-resp-{entropy_tag}").as_bytes(), &plaintext_r3, "CRITICAL")
            .expect("R3 embed must succeed");
        let extracted_r3 = stego
            .extract(&embed_r3.stego_image_bytes, &embed_r3.stego_algorithm_id, embed_r3.payload_length, &embed_r3.algorithm_params_json)
            .expect("R3 extract must succeed");
        assert_eq!(extracted_r3, plaintext_r3, "stego transit must not alter the sealed R3 payload");

        let sealed_r3_recv: iod_core::protocol::envelope::SecureEnvelope =
            serde_json::from_slice(&extracted_r3).expect("R3 envelope must deserialize");
        let response_recv = decrypt_enrollment_response(&sealed_r3_recv, &material.keys.kem_sk).expect("D1 must decrypt R3");
        d1_apply_enrollment_response(drone, &response_recv, material, md.clone()).expect("D1 must accept + locally re-verify R3")
    };

    let mut d1 = DroneState::new("chain-d1", [201u8; 32]);
    let mut d2 = DroneState::new("chain-d2", [202u8; 32]);
    register_via_stego(&mut d1, "d1");
    register_via_stego(&mut d2, "d2");
    assert!(d1.is_registered());
    assert!(d2.is_registered());
    // D1 registered first, so its cached root is stale relative to the
    // tree after D2 joined -- refresh, matching every other test's
    // "healthy deployment pushes fresh witnesses" convention.
    iod_core::protocol::registration::refresh_drone_cache(&gcs, &mut d1);

    // ---- Authentication + Authorization (Zero Trust), M1-M8 ----
    let mut log = EventLog::new();
    let auth_result = run_authentication(&mut gcs, &mut d1, &d2, &mut log)
        .expect("authentication must complete for two drones registered via the stego path");
    assert_eq!(auth_result.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", auth_result.report);
    assert!(auth_result.report.credential_consistency_ok, "spec 25-B check must pass for a genuine session");

    // ---- Group Key (K1-K4) ----
    use iod_core::protocol::group_key::*;
    let d1_pid1 = iod_core::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);
    gcs.pid_pool.entry(d1_pid1.clone()).or_insert_with(|| d1.drone_id.clone());
    let (wire1, plain1) = k1_group_key_req(&d2, "mission-stego", &d1_pid1, "chain-mission", [0u8; 32], &gcs.kem_pk)
        .expect("K1 request must build");
    let wire7 = gcs_handle_k1(&gcs, &wire1).expect("GCS must handle K1");
    let (resp, key_delivery) = d2_handle_k1_response(&d2, &wire7).expect("D2 must handle the K1 response");
    let k_d1 = d1_decapsulate_group_key(&d1, &key_delivery).expect("D1 must decapsulate the group key");
    let k_d2 = d2_decapsulate_group_key(&d2, &resp).expect("D2 must decapsulate the group key");
    assert_eq!(k_d1, k_d2);
    let aead_key = derive_aead_key(&k_d1, &auth_result.n1, &auth_result.n2, &plain1.n6, &resp.n7);

    // ---- Secure Message (K4 / AEAD), both directions ----
    use iod_core::protocol::secure_messaging::{receive_message, send_message};
    use iod_core::transport::PassthroughTransport;
    let transport = PassthroughTransport;
    let (sealed_msg, _wire) = send_message(&aead_key, &transport, 1, b"chain-d1-tag", b"chain-d2-tag", b"payload delivered via stego-registered identities")
        .expect("sealing must succeed");
    let opened = receive_message(&aead_key, &sealed_msg, 0).expect("D2 must open the message");
    assert_eq!(opened, b"payload delivered via stego-registered identities");

    // ---- Revocation ----
    iod_core::protocol::simulation::revoke_drone(&mut gcs, "chain-d1").expect("revocation must succeed");

    // ---- Authentication Failure (post-revocation) ----
    let mut log2 = EventLog::new();
    let post_revoke = run_authentication(&mut gcs, &mut d1, &d2, &mut log2);
    assert!(post_revoke.is_err(), "GCS must refuse to vouch for a drone revoked after a stego registration + successful session");
}
