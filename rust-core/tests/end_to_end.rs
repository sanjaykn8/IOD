//! End-to-end: Register -> M1-M8 -> ALLOW -> K1-K4 -> AEAD message ->
//! Revoke -> authentication rejected, key issue rejected, no bypass.

mod common;
use common::*;
use iod_core::protocol::events::EventLog;
use iod_core::protocol::messages::ZeroTrustDecision;
use iod_core::protocol::secure_messaging::*;
use iod_core::protocol::simulation::*;
use iod_core::transport::PassthroughTransport;

#[test]
fn register_auth_allow_keys_message_revoke_reject() {
    let (mut gcs, mut d1, d2) = setup();
    assert!(d1.is_registered() && d2.is_registered());
    let mut log = EventLog::new();

    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).expect("M1-M8");
    assert_eq!(r.report.zero_trust, ZeroTrustDecision::Allow, "{:?}", r.report);
    assert!(r.report.authenticated && r.d1_decision == Some(ZeroTrustDecision::Allow));

    let ch = run_group_key_establishment(&mut gcs, &d1, &d2, &r, "mission-e2e", &mut log).expect("K1-K3");
    let tag = ch.d1_keys.channel_tag;
    let (m, _) = send_message(&ch.d1_keys.d1_to_d2, &PassthroughTransport, tag, 1, 1, b"hold position").unwrap();
    assert_eq!(receive_message(&ch.d2_keys.d1_to_d2, tag, 1, &m, 0).unwrap(), b"hold position");
    let (m, _) = send_message(&ch.d2_keys.d2_to_d1, &PassthroughTransport, tag, 2, 1, b"ack").unwrap();
    assert_eq!(receive_message(&ch.d1_keys.d2_to_d1, tag, 2, &m, 0).unwrap(), b"ack");

    // Event log never contains secrets or the permanent DroneID of D1 in D2-facing stages.
    let dump = serde_json::to_string(&log.events).unwrap();
    assert!(!dump.contains("drone-1"), "event log leaks D1's permanent DroneID");

    revoke_drone(&mut gcs, "drone-1").unwrap();
    assert!(run_authentication(&mut gcs, &mut d1, &d2, &mut EventLog::new()).is_err());
    assert!(run_group_key_establishment(&mut gcs, &d1, &d2, &r, "mission-e2e", &mut log).is_err());
}
