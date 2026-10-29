//! Image-transport pipeline tests against the in-process fake backend
//! (no Python needed). They exercise the REAL Rust sealing, frame/MAC,
//! strict parsing, replay and AEAD code; only pixel work is faked.
//! The real Python service is covered by `stego_e2e_python.rs`.

use iod_core::api::state::SimulationState;
use iod_core::crypto::aead::AeadKey;
use iod_core::protocol::secure_messaging::seal_message;
use iod_core::transport::backend::StegoBackend;
use iod_core::transport::config::StegoConfig;
use iod_core::transport::fake::{ExplainMode, FakeStegoBackend};
use iod_core::transport::frame::{build_frame, derive_meta_key};
use iod_core::transport::pipeline::{self, MessageRequest};
use iod_core::transport::wire::encode_app_wire;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SECRET: &str = "TOP-SECRET-PLAINTEXT-123";

struct World {
    state: Mutex<SimulationState>,
    fake: Arc<FakeStegoBackend>,
    dir: PathBuf,
    db: String,
    sid: String,
}

fn unique_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("iod-stego-test-{tag}-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cfg_for(dir: &Path) -> StegoConfig {
    let mut c = StegoConfig::default();
    c.artifact_dir = dir.to_string_lossy().to_string();
    c.max_frame_bytes = 4096;
    c
}

fn build_state(dir: &Path, db: &str, fake: Arc<FakeStegoBackend>) -> SimulationState {
    SimulationState::with_backend(db, cfg_for(dir), fake as Arc<dyn StegoBackend>).unwrap()
}

fn world(tag: &str) -> World {
    let dir = unique_dir(tag);
    let db = dir.join("state.db").to_string_lossy().to_string();
    let fake = Arc::new(FakeStegoBackend::new(dir.join("artifacts")));
    let mut cfg = cfg_for(&dir.join("artifacts"));
    cfg.max_frame_bytes = 4096;
    let mut s = SimulationState::with_backend(&db, cfg, fake.clone() as Arc<dyn StegoBackend>).unwrap();
    s.create_group("g1").unwrap();
    s.create_drone("drone-1").unwrap();
    s.create_drone("drone-2").unwrap();
    s.register_drone("drone-1", "g1", "member").unwrap();
    s.register_drone("drone-2", "g1", "member").unwrap();
    let (sid, rep) = s.authenticate("drone-1", "drone-2").unwrap();
    assert!(rep.authenticated, "{rep:?}");
    s.establish_group_key(&sid, "mission-stego").unwrap();
    World { state: Mutex::new(s), fake, dir, db, sid }
}

fn req(w: &World, from: &str, text: &str) -> MessageRequest {
    MessageRequest { session_id: w.sid.clone(), from_id: from.into(), plaintext: text.as_bytes().to_vec(), algorithm: None, cover: json!({"source": "webcam"}), priority: "normal".into(), origin: "test" }
}

fn art_path(w: &World, id: &str) -> PathBuf {
    w.fake.stego_path(id)
}

fn send(w: &World, from: &str, text: &str) -> Value {
    match pipeline::run_send(&w.state, req(w, from, text)) {
        Ok(v) => v,
        Err(f) => panic!("send failed: {}", f.error),
    }
}

fn receive_err(w: &World, rcpt: &str, id: &str) -> String {
    match pipeline::run_receive(&w.state, &w.sid, rcpt, id) {
        Ok(_) => panic!("receive unexpectedly succeeded"),
        Err(f) => f.error.code.clone(),
    }
}

fn events(w: &World) -> Vec<Value> {
    let s = w.state.lock().unwrap();
    s.db.query_stego_events(&Default::default()).unwrap()
}

// -------------------------------------------------------------- tests ---

#[test]
fn both_directions_round_trip_through_saved_files_with_all_stages() {
    let w = world("roundtrip");
    for (from, to_role, text) in [("drone-1", "D2", "hold position"), ("drone-2", "D1", "ack, holding")] {
        let v = pipeline::run_message(&w.state, req(&w, from, text)).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["to_role"], to_role);
        assert_eq!(v["verification"]["frame_match"], true);
        assert_eq!(v["verification"]["aead_ok"], true);
        let names: Vec<&str> = v["stages"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["aead_seal", "selector", "embed", "save", "read", "extract", "verify_frame", "aead_open", "explain"]);
        assert!(v["stages"].as_array().unwrap().iter().all(|s| s["status"] == "ok"));
        let id = v["artifact"]["id"].as_str().unwrap();
        assert!(art_path(&w, id).exists(), "the saved image file must exist");
        assert_eq!(v["explanation"]["fallback"], false);
        assert_eq!(v["selection"]["selected"], v["embed"]["algorithm"]);
    }
    let evs = events(&w);
    assert_eq!(evs.len(), 2);
    assert!(evs.iter().all(|e| e["success"] == true && e["frame_match"] == true && e["aead_ok"] == true));
    assert_eq!(evs.iter().map(|e| e["direction"].as_i64().unwrap()).collect::<Vec<_>>(), vec![2, 1]);
}

#[test]
fn receiver_input_is_only_the_saved_file() {
    let w = world("fileonly");
    let sent = send(&w, "drone-1", SECRET);
    let id = sent["artifact"]["id"].as_str().unwrap().to_string();
    // The sender response carries no plaintext and no ciphertext.
    let dump = sent.to_string();
    assert!(!dump.contains(SECRET) && sent.get("delivered_message").is_none());
    // Remove the file: the receiver cannot succeed from any in-memory leftovers.
    let backup = std::fs::read(art_path(&w, &id)).unwrap();
    std::fs::remove_file(art_path(&w, &id)).unwrap();
    assert_eq!(receive_err(&w, "drone-2", &id), "ARTIFACT_NOT_FOUND");
    // Restore: receiver now succeeds purely from the file contents.
    std::fs::write(art_path(&w, &id), &backup).unwrap();
    let r = pipeline::run_receive(&w.state, &w.sid, "drone-2", &id).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(r["delivered_message"], SECRET);
    // Same file again: replay is refused.
    assert_eq!(receive_err(&w, "drone-2", &id), "REPLAY");
}

#[test]
fn tampered_saved_images_fail_closed_and_are_recorded() {
    let w = world("tamper");
    // (description, mutation of the stored container, expected stable code)
    type Mutator = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Mutator, &str)> = vec![
        ("algorithm id (bootstrap) changed", Box::new(|f| f[8] = if f[8] == 2 { 3 } else { 2 }), "FRAME_ALGORITHM_MISMATCH"),
        ("bootstrap parameter changed", Box::new(|f| f[9] ^= 1), "FRAME_ALGORITHM_MISMATCH"),
        ("frame payload-length field changed", Box::new(|f| f[10 + 11] ^= 1), "FRAME_MALFORMED"),
        ("frame version changed", Box::new(|f| f[10 + 4] = 9), "FRAME_VERSION_UNSUPPORTED"),
        ("frame magic changed", Box::new(|f| f[10] ^= 0xff), "FRAME_MALFORMED"),
        ("ciphertext byte flipped", Box::new(|f| { let n = f.len(); f[n - 40] ^= 1 }), "FRAME_AUTH_FAILED"),
        ("MAC tag byte flipped", Box::new(|f| { let n = f.len(); f[n - 1] ^= 1 }), "FRAME_AUTH_FAILED"),
        ("header algorithm field (authenticated copy) changed", Box::new(|f| f[10 + 5] ^= 3), "FRAME_AUTH_FAILED"),
        ("frame truncated", Box::new(|f| { f.truncate(f.len() - 7) }), "FRAME_MALFORMED"),
        ("image header corrupted", Box::new(|f| f[0] ^= 0xff), "IMAGE_DECODE_ERROR"),
        ("unknown algorithm id in bootstrap", Box::new(|f| f[8] = 99), "UNKNOWN_ALGORITHM"),
    ];
    for (desc, mutate, code) in &cases {
        let sent = send(&w, "drone-1", SECRET);
        let id = sent["artifact"]["id"].as_str().unwrap().to_string();
        let mut file = std::fs::read(art_path(&w, &id)).unwrap();
        mutate(&mut file);
        std::fs::write(art_path(&w, &id), &file).unwrap();
        let got = match pipeline::run_receive(&w.state, &w.sid, "drone-2", &id) {
            Ok(v) => panic!("[{desc}] delivered {:?}", v["delivered_message"]),
            Err(f) => f,
        };
        assert_eq!(&got.error.code, code, "[{desc}] wrong failure code");
        assert!(got.to_json().to_string().find(SECRET).is_none(), "[{desc}] leaked plaintext");
        assert!(got.event_id > 0);
    }
    // failures never advanced the receiver's replay state: a fresh valid message is still accepted
    let ok = pipeline::run_message(&w.state, req(&w, "drone-1", "still works")).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(ok["delivered_message"], "still works");
    let failed: Vec<Value> = events(&w).into_iter().filter(|e| e["success"] == false).collect();
    assert_eq!(failed.len(), cases.len());
    assert!(failed.iter().all(|e| e["error_code"].is_string() && e["error_stage"].is_string()));
}

#[test]
fn wrong_recipient_and_direction_fail_closed() {
    let w = world("recipient");
    let id = send(&w, "drone-1", SECRET)["artifact"]["id"].as_str().unwrap().to_string();
    // The sender itself is not the right recipient: directional keys differ.
    assert_eq!(receive_err(&w, "drone-1", &id), "FRAME_AUTH_FAILED");
    assert_eq!(receive_err(&w, "drone-9", &id), "WRONG_RECIPIENT");
    // The intended recipient still gets it.
    assert!(pipeline::run_receive(&w.state, &w.sid, "drone-2", &id).is_ok());
}

/// Forge a stored image whose frame is MAC-valid for the receiver but whose inner message is wrong,
/// to prove the *second* line of defence (channel/direction/replay/AEAD) independently of the MAC.
fn forge(w: &World, mutate: impl Fn(&mut iod_core::protocol::messages::SecureAppMessage), seq: u32, dir_for_keys: u8) -> String {
    let (key, tag) = {
        let s = w.state.lock().unwrap();
        let ch = s.channels.get(&w.sid).unwrap();
        (AeadKey(ch.d1_keys.d1_to_d2.0), ch.d1_keys.channel_tag)
    };
    let mut msg = seal_message(&key, tag, 1, seq, b"forged-body");
    mutate(&mut msg);
    let wire = encode_app_wire(&msg);
    let meta = derive_meta_key(&key, &tag, dir_for_keys);
    let frame = build_frame(&meta, 1, 0, &wire, 4096).unwrap();
    let id = format!("{:032x}", rand::random::<u128>());
    let mut file = b"FAKEIMG1".to_vec();
    file.extend_from_slice(&[1, 0]);
    file.extend_from_slice(&frame);
    std::fs::write(art_path(w, &id), file).unwrap();
    id
}

#[test]
fn inner_checks_hold_even_when_the_frame_mac_is_valid() {
    let w = world("inner");
    // altered AAD field (timestamp changed after sealing) -> AEAD failure
    let id = forge(&w, |m| m.header_ts += 1, 1, 1);
    assert_eq!(receive_err(&w, "drone-2", &id), "AEAD_FAILED");
    // wrong channel tag
    let id = forge(&w, |m| m.channel_tag = [7; 16], 1, 1);
    assert_eq!(receive_err(&w, "drone-2", &id), "WRONG_CHANNEL");
    // wrong direction field
    let id = forge(&w, |m| m.direction = 2, 1, 1);
    assert_eq!(receive_err(&w, "drone-2", &id), "WRONG_CHANNEL");
    // altered ciphertext
    let id = forge(&w, |m| m.sealed.ciphertext[0] ^= 1, 1, 1);
    assert_eq!(receive_err(&w, "drone-2", &id), "AEAD_FAILED");
    // a genuine message with seq 5 is accepted; anything <= 5 afterwards is a replay
    let id5 = forge(&w, |_| {}, 5, 1);
    assert!(pipeline::run_receive(&w.state, &w.sid, "drone-2", &id5).is_ok());
    let id3 = forge(&w, |_| {}, 3, 1);
    assert_eq!(receive_err(&w, "drone-2", &id3), "REPLAY");
    assert_eq!(receive_err(&w, "drone-2", &id5), "REPLAY");
}

#[test]
fn out_of_order_delivery_is_rejected_as_replay() {
    let w = world("order");
    let a = send(&w, "drone-1", "first")["artifact"]["id"].as_str().unwrap().to_string();
    let b = send(&w, "drone-1", "second")["artifact"]["id"].as_str().unwrap().to_string();
    assert!(pipeline::run_receive(&w.state, &w.sid, "drone-2", &b).is_ok());
    assert_eq!(receive_err(&w, "drone-2", &a), "REPLAY");
}

#[test]
fn capacity_and_size_rejections_are_structured_and_recorded() {
    let w = world("capacity");
    // frame limit (4096) exceeded before any backend call
    let big = "x".repeat(5000);
    let e = pipeline::run_message(&w.state, req(&w, "drone-1", &big)).err().unwrap();
    assert_eq!(e.error.code, "FRAME_TOO_LARGE");
    assert_eq!(e.error.http_status, 413);
    // backend has no eligible algorithm
    *w.fake.capacity_bytes.lock().unwrap() = 20;
    let e = pipeline::run_message(&w.state, req(&w, "drone-1", "hello world, longer than twenty bytes of capacity")).err().unwrap();
    assert_eq!(e.error.code, "NO_ELIGIBLE_ALGORITHM");
    // manual override that cannot hold the frame is rejected, not downgraded
    *w.fake.capacity_bytes.lock().unwrap() = 500;
    let mut r = req(&w, "drone-1", &"y".repeat(150));
    r.algorithm = Some("dct".into()); // fake gives dct capacity 100 bytes
    assert_eq!(pipeline::run_message(&w.state, r).err().unwrap().error.code, "ALGORITHM_NOT_ELIGIBLE");
    let evs = events(&w);
    assert_eq!(evs.len(), 3);
    assert!(evs.iter().all(|e| e["success"] == false && e["error_code"].is_string()));
    // nothing was delivered: receiver replay state untouched, no files saved
    let pngs = std::fs::read_dir(&w.fake.dir).unwrap().filter(|f| f.as_ref().unwrap().file_name().to_string_lossy().ends_with(".png") && !f.as_ref().unwrap().file_name().to_string_lossy().contains(".cover")).count();
    assert_eq!(pngs, 0);
}

#[test]
fn manual_override_is_honoured_when_eligible() {
    let w = world("manual");
    for alg in ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"] {
        let mut r = req(&w, "drone-2", "manual experiment");
        r.algorithm = Some(alg.into());
        let v = pipeline::run_message(&w.state, r).unwrap_or_else(|f| panic!("{alg}: {}", f.error));
        assert_eq!(v["embed"]["algorithm"], alg);
        assert_eq!(v["selection"]["mode"], "manual");
        assert_eq!(v["selection"]["reason_code"], "MANUAL_OVERRIDE");
    }
}

#[test]
fn rag_failures_never_block_delivery_or_change_the_decision() {
    let w = world("rag");
    for (mode, label) in [(ExplainMode::Unavailable, "unavailable"), (ExplainMode::UnsupportedClaims, "unsupported"), (ExplainMode::ChangesDecision, "decision-changing")] {
        *w.fake.explain_mode.lock().unwrap() = mode;
        let v = pipeline::run_message(&w.state, req(&w, "drone-1", &format!("msg {label}"))).unwrap_or_else(|f| panic!("{label}: {}", f.error));
        assert_eq!(v["delivered_message"], format!("msg {label}"));
        assert_eq!(v["explanation"]["status"], "fallback_deterministic", "{label}");
        assert_eq!(v["explanation"]["fallback"], true);
        assert_eq!(v["selection"]["selected"], v["embed"]["algorithm"], "{label}: decision must stay the selector's");
    }
    assert!(events(&w).iter().all(|e| e["explanation_status"] == "fallback_deterministic"));
}

#[test]
fn unreachable_backend_fails_closed_without_passthrough() {
    let dir = unique_dir("down");
    let db = dir.join("s.db").to_string_lossy().to_string();
    let mut cfg = cfg_for(&dir.join("artifacts"));
    cfg.python_url = "http://127.0.0.1:1".into();
    cfg.http_timeout_ms = 1000;
    let backend = Arc::new(iod_core::transport::backend::HttpBackend::new(&cfg).unwrap());
    let mut s = SimulationState::with_backend(&db, cfg, backend).unwrap();
    s.create_group("g1").unwrap();
    s.create_drone("drone-1").unwrap();
    s.create_drone("drone-2").unwrap();
    s.register_drone("drone-1", "g1", "member").unwrap();
    s.register_drone("drone-2", "g1", "member").unwrap();
    let (sid, _) = s.authenticate("drone-1", "drone-2").unwrap();
    s.establish_group_key(&sid, "m").unwrap();
    let st = Mutex::new(s);
    let r = MessageRequest { session_id: sid, from_id: "drone-1".into(), plaintext: b"hi".to_vec(), algorithm: None, cover: json!({"source":"webcam"}), priority: "normal".into(), origin: "test" };
    let f = pipeline::run_message(&st, r).err().expect("must fail closed");
    assert_eq!(f.error.code, "STEGO_BACKEND_UNAVAILABLE");
    assert_eq!(f.error.http_status, 503);
    let evs = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["error_code"], "STEGO_BACKEND_UNAVAILABLE");
}

#[test]
fn key_and_session_preconditions() {
    let dir = unique_dir("precond");
    let db = dir.join("s.db").to_string_lossy().to_string();
    let fake = Arc::new(FakeStegoBackend::new(dir.join("artifacts")));
    let mut s = build_state(&dir.join("artifacts"), &db, fake.clone());
    s.create_group("g1").unwrap();
    for d in ["drone-1", "drone-2"] {
        s.create_drone(d).unwrap();
        s.register_drone(d, "g1", "member").unwrap();
    }
    let (sid, _) = s.authenticate("drone-1", "drone-2").unwrap();
    let st = Mutex::new(s);
    let mk = |sid: &str, from: &str| MessageRequest { session_id: sid.into(), from_id: from.into(), plaintext: b"x".to_vec(), algorithm: None, cover: json!({"source":"webcam"}), priority: "normal".into(), origin: "test" };
    // authenticated but no K1-K3 yet
    assert_eq!(pipeline::run_message(&st, mk(&sid, "drone-1")).err().unwrap().error.code, "NO_GROUP_KEY");
    st.lock().unwrap().establish_group_key(&sid, "m").unwrap();
    assert_eq!(pipeline::run_message(&st, mk("no-such-session", "drone-1")).err().unwrap().error.code, "NO_GROUP_KEY");
    assert_eq!(pipeline::run_message(&st, mk(&sid, "intruder")).err().unwrap().error.code, "NOT_PARTICIPANT");
    assert!(pipeline::run_message(&st, mk(&sid, "drone-1")).is_ok());
    // revocation after key issue blocks both sending and receiving
    st.lock().unwrap().revoke_drone("drone-2").unwrap();
    let code = pipeline::run_message(&st, mk(&sid, "drone-1")).err().unwrap().error.code;
    assert!(code == "MEMBER_REVOKED" || code == "SESSION_NOT_ACTIVE", "{code}");
}

#[test]
fn events_never_contain_plaintext_ciphertext_or_keys() {
    let w = world("nosecrets");
    let v = pipeline::run_message(&w.state, req(&w, "drone-1", SECRET)).unwrap_or_else(|f| panic!("{}", f.error));
    let id = v["artifact"]["id"].as_str().unwrap();
    let file = std::fs::read(art_path(&w, id)).unwrap();
    let ciphertext_tail = &file[file.len() - 32 - 20..file.len() - 32];
    let (key_hex, meta_marker) = {
        let s = w.state.lock().unwrap();
        let ch = s.channels.get(&w.sid).unwrap();
        (hex::encode(ch.d1_keys.d1_to_d2.0), hex::encode(ch.d1_keys.channel_tag))
    };
    let mut dump = serde_json::to_string(&events(&w)).unwrap();
    {
        let s = w.state.lock().unwrap();
        dump.push_str(&serde_json::to_string(&s.log.events).unwrap());
        dump.push_str(&serde_json::to_string(&s.db.recent_events(10_000).unwrap()).unwrap());
    }
    assert!(!dump.contains(SECRET));
    assert!(!dump.contains(&hex::encode(ciphertext_tail)) && !dump.contains(&iod_core::transport::b64::encode(ciphertext_tail)));
    assert!(!dump.contains(&key_hex));
    assert!(!dump.contains(&meta_marker), "channel tag is session key material and must not be logged");
    // also: no key-like fields in the public status
    let cfgv = w.state.lock().unwrap().stego_cfg.public_view().to_string();
    assert!(!cfgv.contains(&w.dir.to_string_lossy().to_string()));
}

#[test]
fn history_survives_restart_and_filters_work() {
    let w = world("persist");
    pipeline::run_message(&w.state, req(&w, "drone-1", "one")).ok().unwrap();
    pipeline::run_message(&w.state, req(&w, "drone-2", "two")).ok().unwrap();
    let _ = pipeline::run_message(&w.state, req(&w, "intruder", "bad")).err().unwrap();
    // simulate process restart: new state over the same DB file
    let dir_art = w.fake.dir.clone();
    let db = w.db.clone();
    let fake = w.fake.clone();
    drop(w.state);
    let s2 = build_state(&dir_art, &db, fake);
    use iod_core::storage::StegoEventFilter as F;
    let all = s2.db.query_stego_events(&F::default()).unwrap();
    assert_eq!(all.len(), 3, "events (including the failed attempt) persisted across the restart");
    let failed = s2.db.query_stego_events(&F { outcome: Some("failed".into()), ..Default::default() }).unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["error_code"], "NOT_PARTICIPANT");
    assert_eq!(failed[0]["outcome"], "failed");
    let d2 = s2.db.query_stego_events(&F { direction: Some(2), ..Default::default() }).unwrap();
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0]["from_role"], "D2");
    let none = s2.db.query_stego_events(&F { session_id: Some("other".into()), ..Default::default() }).unwrap();
    assert!(none.is_empty());
    let future = s2.db.query_stego_events(&F { since_ms: Some(i64::MAX), ..Default::default() }).unwrap();
    assert!(future.is_empty());
    let one = s2.db.query_stego_events(&F { limit: Some(1), ..Default::default() }).unwrap();
    assert_eq!(one.len(), 1);
    let by_alg = s2.db.query_stego_events(&F { algorithm: Some(all.iter().find_map(|e| e["algorithm"].as_str()).unwrap().to_string()), ..Default::default() }).unwrap();
    assert!(!by_alg.is_empty());
    // injection-shaped filter values are plain bound parameters
    let inj = s2.db.query_stego_events(&F { session_id: Some("x' OR '1'='1".into()), ..Default::default() }).unwrap();
    assert!(inj.is_empty());
}

#[test]
fn report_csv_and_benchmark_use_real_events() {
    let w = world("report");
    let b = pipeline::run_benchmark(&w.state, &w.sid, 2, &[32], &["pvd".to_string(), "lsb_matching".to_string()], &json!({"source":"webcam"})).unwrap();
    assert_eq!(b["samples"], 4);
    assert!(b["runs"].as_array().unwrap().iter().all(|r| r["ok"] == true));
    let evs = events(&w);
    let rep = iod_core::transport::report::build_report(&evs, json!({}), 1);
    assert_eq!(rep["totals"]["events"], 4);
    assert_eq!(rep["totals"]["ok"], 4);
    assert_eq!(rep["per_algorithm"].as_array().unwrap().len(), 2);
    assert_eq!(rep["per_algorithm"][0]["timings_ms"]["total"]["p95"], Value::Null, "n<20 => no percentile");
    let csv = iod_core::transport::report::events_to_csv(&evs);
    assert_eq!(csv.lines().count(), 5);
    assert!(pipeline::run_benchmark(&w.state, &w.sid, 51, &[32], &["pvd".to_string()], &json!({})).is_err());
    assert!(pipeline::run_benchmark(&w.state, &w.sid, 1, &[32], &["rot13".to_string()], &json!({})).is_err());
}

#[test]
fn artifact_preview_access_is_confined_to_valid_ids() {
    let w = world("preview");
    let v = pipeline::run_message(&w.state, req(&w, "drone-1", "p")).ok().unwrap();
    let cfg = w.state.lock().unwrap().stego_cfg.clone();
    let id = v["artifact"]["id"].as_str().unwrap();
    assert!(pipeline::artifact_png(&cfg, id, "stego").is_ok());
    let cover_id = v["cover"]["artifact_id"].as_str().unwrap();
    assert!(pipeline::artifact_png(&cfg, cover_id, "cover").is_ok());
    for bad in ["../state.db", "..%2f..%2fetc%2fpasswd", &id[..31], &id.to_uppercase(), "", "a/b"] {
        assert!(pipeline::artifact_png(&cfg, bad, "stego").is_err(), "accepted {bad:?}");
    }
    assert!(pipeline::artifact_png(&cfg, id, "../x").is_err());
}
