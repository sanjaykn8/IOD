//! FIPS 203/204 suite lifecycle through the real simulation state:
//! registration -> M1-M8 -> K1-K3 -> K4 application message (image transport, fake
//! pixel backend), persistence and restart, re-registration (key replacement), and
//! explicit archiving of state written under the previous Round-3 suite.

use iod_core::api::state::SimulationState;
use iod_core::crypto::{kem, sign, suite};
use iod_core::transport::backend::StegoBackend;
use iod_core::transport::config::StegoConfig;
use iod_core::transport::fake::FakeStegoBackend;
use iod_core::transport::pipeline::{self, MessageRequest};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("iod-suite-{tag}-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(d: &PathBuf) -> SimulationState {
    let mut c = StegoConfig::default();
    c.artifact_dir = d.join("artifacts").to_string_lossy().to_string();
    let fake = Arc::new(FakeStegoBackend::new(d.join("artifacts")));
    SimulationState::with_backend(&d.join("s.db").to_string_lossy(), c, fake as Arc<dyn StegoBackend>).unwrap()
}

fn message(s: SimulationState, sid: &str, from: &str, text: &str) -> (SimulationState, Value) {
    let m = Mutex::new(s);
    let r = pipeline::run_message(&m, MessageRequest {
        session_id: sid.into(), from_id: from.into(), plaintext: text.as_bytes().to_vec(), cover_generation: Value::Null, origin: "test",
    }).unwrap_or_else(|f| panic!("{}", f.error));
    (m.into_inner().unwrap(), r)
}

fn full_flow(s: &mut SimulationState) -> String {
    let (sid, rep) = s.authenticate("drone-1", "drone-2").unwrap();
    assert!(rep.authenticated, "{rep:?}");
    assert!(rep.signature_ok && rep.puf_ok && rep.zk_membership_ok, "{rep:?}");
    s.establish_group_key(&sid, "mission-fips").unwrap();
    sid
}

#[test]
fn register_authenticate_group_key_and_message_with_the_fips_suite_then_restart() {
    let d = dir("flow");
    let mut s = open(&d);
    s.create_group("g1").unwrap();
    for id in ["drone-1", "drone-2"] {
        s.create_drone(id).unwrap();
        s.register_drone(id, "g1", "member").unwrap();
    }
    for id in ["drone-1", "drone-2"] {
        let dr = &s.drones[id];
        let k = dr.keys.as_ref().unwrap();
        assert_eq!(k.suite, suite::SUITE_ID);
        assert_eq!((k.kem_pk.0.len(), k.kem_sk.0.len()), (kem::PUBLIC_KEY_BYTES, kem::SECRET_SEED_BYTES));
        assert_eq!((k.dil_pk.0.len(), k.dil_sk.0.len()), (sign::PUBLIC_KEY_BYTES, sign::SECRET_SEED_BYTES));
        assert_eq!(dr.credential.as_ref().unwrap().body.suite, suite::SUITE_ID);
        assert_eq!(dr.credential.as_ref().unwrap().sig.len(), sign::SIGNATURE_BYTES);
        // GCS holds only the public record
        assert_eq!(s.gcs.drones[id].kem_pk, k.kem_pk);
    }
    let sid = full_flow(&mut s);
    let (s, r) = message(s, &sid, "drone-1", "K4 over ML-KEM-derived keys");
    assert_eq!(r["delivered_message"], "K4 over ML-KEM-derived keys");
    let (s, r) = message(s, &sid, "drone-2", "and back");
    assert_eq!(r["delivered_message"], "and back");
    let fp_before = (s.drones["drone-1"].keys.as_ref().unwrap().kem_pk.clone(), s.gcs.sign_pk.clone());
    drop(s);

    // restart: identities reload unchanged, nothing is archived, the protocol still runs
    let mut s = open(&d);
    assert_eq!(s.crypto_migration["archived_now"].as_array().unwrap().len(), 0);
    assert_eq!(s.drones.len(), 2);
    assert_eq!(s.drones["drone-1"].keys.as_ref().unwrap().kem_pk, fp_before.0);
    assert_eq!(s.gcs.sign_pk, fp_before.1);
    let sid = full_flow(&mut s);
    let (_s, r) = message(s, &sid, "drone-1", "after restart");
    assert_eq!(r["delivered_message"], "after restart");
}

#[test]
fn key_replacement_by_revoke_and_reactivate_retires_the_old_credential() {
    let d = dir("rereg");
    let mut s = open(&d);
    s.create_group("g1").unwrap();
    for id in ["drone-1", "drone-2"] {
        s.create_drone(id).unwrap();
        s.register_drone(id, "g1", "member").unwrap();
    }
    let old_keys = s.drones["drone-1"].keys.clone().unwrap();
    let old_cred = s.drones["drone-1"].credential.clone().unwrap();
    // an active member cannot simply enroll again; key replacement = revoke + reactivate
    assert!(s.register_drone("drone-1", "g1", "member").is_err());
    s.revoke_drone("drone-1").unwrap();
    s.reactivate_drone("drone-1").unwrap();
    let new_keys = s.drones["drone-1"].keys.clone().unwrap();
    assert_ne!(old_keys.kem_pk, new_keys.kem_pk);
    assert_ne!(old_keys.dil_pk, new_keys.dil_pk);
    assert!(!s.gcs.cred_index.contains_key(&old_cred.body.cred_id), "old credential id retired");
    assert_eq!(s.gcs.drones["drone-1"].dil_pk, new_keys.dil_pk);
    full_flow(&mut s);
}

/// A database as the Round-3 release left it: rows without a suite tag,
/// Dilithium2-length private keys (2528 B) and Kyber768 expanded secret keys (2400 B).
fn write_round3_db(d: &PathBuf) {
    let mut s = open(d);
    s.create_group("g1").unwrap();
    for id in ["drone-1", "drone-2"] {
        s.create_drone(id).unwrap();
        s.register_drone(id, "g1", "member").unwrap();
    }
    let g = s.gcs.to_snapshot();
    let ds: Vec<_> = s.drones.values().map(|x| x.to_local_snapshot()).collect();
    let db = &s.db;
    let mut gv = serde_json::to_value(&g).unwrap();
    gv.as_object_mut().unwrap().remove("suite");
    gv["sign_sk"] = serde_json::json!(vec![1u8; 2528]);
    gv["kem_sk"] = serde_json::json!(vec![1u8; 2400]);
    db.put_raw_identity_row("gcs", "gcs", &gv.to_string()).unwrap();
    for snap in ds {
        let mut v = serde_json::to_value(&snap).unwrap();
        v.as_object_mut().unwrap().remove("suite");
        v["keys"].as_object_mut().unwrap().remove("suite");
        v["keys"]["dil_sk"] = serde_json::json!(vec![2u8; 2528]);
        v["keys"]["kem_sk"] = serde_json::json!(vec![2u8; 2400]);
        db.put_raw_identity_row("drone", &snap.drone_id, &v.to_string()).unwrap();
    }
}

#[test]
fn round3_state_is_archived_at_startup_and_the_simulation_starts_clean() {
    let d = dir("legacy");
    write_round3_db(&d);
    let s = open(&d);
    let archived = s.crypto_migration["archived_now"].as_array().unwrap().clone();
    assert_eq!(archived.len(), 3, "GCS + two drones: {archived:?}");
    assert!(archived.iter().all(|r| r["detected_suite"] == suite::LEGACY_SUITE_ID));
    assert!(s.drones.is_empty(), "no legacy drone was loaded");
    assert!(s.gcs.drones.is_empty() && s.gcs.groups.is_empty(), "fresh GCS identity");
    assert_eq!(s.gcs.sign_pk.0.len(), sign::PUBLIC_KEY_BYTES);
    let sum = s.db.legacy_snapshot_summary().unwrap();
    assert_eq!(sum["count"], 3);
    // the archive keeps the old rows verbatim for inspection, but they are never live again
    drop(s);
    let mut s = open(&d);
    assert_eq!(s.crypto_migration["archived_now"].as_array().unwrap().len(), 0);
    assert_eq!(s.db.legacy_snapshot_summary().unwrap()["count"], 3);
    // re-registration under the new suite works end to end
    s.create_group("g1").unwrap();
    for id in ["drone-1", "drone-2"] {
        s.create_drone(id).unwrap();
        s.register_drone(id, "g1", "member").unwrap();
    }
    let sid = full_flow(&mut s);
    let (s, r) = message(s, &sid, "drone-1", "fresh identities");
    assert_eq!(r["delivered_message"], "fresh identities");
    // a simulation reset also clears the archive (documented operator action)
    let mut s = s;
    s.reset().unwrap();
    assert_eq!(s.db.legacy_snapshot_summary().unwrap()["count"], 0);
}
