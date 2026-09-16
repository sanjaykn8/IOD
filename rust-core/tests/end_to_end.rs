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
