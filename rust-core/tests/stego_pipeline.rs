//! Patch-wise image-transport pipeline tests against the in-process fake backend
//! (no Python needed). They exercise the REAL Rust sealing, manifest validation,
//! Frame v2 / MAC, strict parsing, bounded re-planning, replay and AEAD code;
//! only pixel work is faked.
//! The real Python service is covered by `stego_e2e_python.rs`.

use iod_core::api::state::SimulationState;
use iod_core::crypto::aead::AeadKey;
use iod_core::protocol::secure_messaging::seal_message;
use iod_core::transport::backend::StegoBackend;
use iod_core::transport::config::StegoConfig;
use iod_core::transport::fake::FakeStegoBackend;
use iod_core::transport::frame::{build_frame, derive_meta_key};
use iod_core::transport::manifest::{self, Manifest};
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
    MessageRequest { session_id: w.sid.clone(), from_id: from.into(), plaintext: text.as_bytes().to_vec(), cover: json!({"source": "webcam"}), origin: "test" }
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

const F: usize = FakeStegoBackend::FRAME_OFFSET; // frame offset inside a saved fake image
const M: usize = F + 16; // manifest offset
const E1: usize = M + 24 + 12; // first used patch entry

/// Replace the manifest inside a saved file by a mutated (still structurally valid) one, keeping
/// the original payload and tag -- what an attacker without the MAC key can do at best.
fn swap_manifest(file: &mut Vec<u8>, mutate: impl Fn(&mut Manifest)) {
    let frame = file[F..].to_vec();
    let mlen = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
    let mut man = manifest::parse(&frame[16..16 + mlen], 4096).unwrap();
    mutate(&mut man);
    let mut enc = man.encode();
    let rr = manifest::reserved_rows_for(enc.len(), man.width, man.channels) as u16;
    enc[14..16].copy_from_slice(&rr.to_be_bytes());
    manifest::parse(&enc, 4096).expect("the tampered manifest must itself be well-formed for this test");
    let mut out = file[..F].to_vec();
    out.extend_from_slice(&frame[..8]);
    out.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    out.extend_from_slice(&frame[12..16]);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&frame[16 + mlen..]);
    *file = out;
}

#[test]
fn both_directions_round_trip_through_saved_files_with_all_stages() {
    let w = world("roundtrip");
    for (from, to_role, text) in [("drone-1", "D2", "hold position"), ("drone-2", "D1", "ack, holding")] {
        let v = pipeline::run_message(&w.state, req(&w, from, text)).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["to_role"], to_role);
        assert_eq!(v["verification"]["frame_match"], true);
        assert_eq!(v["verification"]["aead_ok"], true);
        assert_eq!(v["verification"]["manifest_authenticated"], true);
        assert_eq!(v["verification"]["resegmented"], false);
        let names: Vec<&str> = v["stages"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["aead_seal", "plan", "embed", "save", "read", "extract", "verify_frame", "aead_open"], "no explanation stage");
        assert!(v["stages"].as_array().unwrap().iter().all(|s| s["status"] == "ok"));
        let id = v["artifact"]["id"].as_str().unwrap();
        assert!(art_path(&w, id).exists(), "the saved image file must exist");
        assert!(v.get("explanation").is_none() && v.get("selection").is_none());
        // the manifest the receiver authenticated is the one the sender planned
        assert_eq!(v["manifest"], v["received_manifest"]);
        assert_eq!(v["manifest"]["used_patches"], 3);
        let used: Vec<&Value> = v["manifest"]["patches"].as_array().unwrap().iter().filter(|p| p["used"] == true).collect();
        let mut off = 0u64;
        for p in &used {
            assert_eq!(p["payload_offset"].as_u64().unwrap(), off, "sequential, contiguous chunks");
            off += p["payload_length"].as_u64().unwrap();
        }
        assert_eq!(off, v["transport"]["payload_section_bytes"].as_u64().unwrap());
        assert_eq!(v["transport"]["format_version"], "frame-v2/appwire-v1/bootstrap-v2/manifest-v1");
        assert_eq!(v["transport"]["frame_bytes"].as_u64().unwrap(), 16 + v["transport"]["manifest_bytes"].as_u64().unwrap() + off);
        assert!(v["artifact"]["segmentation_overlay_url"].as_str().unwrap().ends_with("/seg"));
    }
    let evs = events(&w);
    assert_eq!(evs.len(), 2);
    assert!(evs.iter().all(|e| e["success"] == true && e["frame_match"] == true && e["aead_ok"] == true));
    assert_eq!(evs.iter().map(|e| e["direction"].as_i64().unwrap()).collect::<Vec<_>>(), vec![2, 1]);
    for e in &evs {
        assert_eq!(e["patch_count"], 4);
        assert_eq!(e["used_patches"], 3);
        assert_eq!(e["algorithms_used"]["dwt"]["patches"], 1);
        assert_eq!(e["patches"].as_array().unwrap().len(), 4);
        assert_eq!(e["patches"][1]["bm25"], 1.25);
        assert_eq!(e["segmentation_version"], "arg-cells-1");
        assert_eq!(e["selector_version"], "kb-bm25-1");
        let text = e.to_string().to_lowercase();
        for banned in ["priority", "explanation", "urgent", "selection_mode"] {
            assert!(!text.contains(banned), "event mentions removed concept '{banned}'");
        }
    }
}

#[test]
fn the_image_service_receives_lengths_only_for_planning() {
    let w = world("planreq");
    pipeline::run_message(&w.state, req(&w, "drone-1", SECRET)).unwrap_or_else(|f| panic!("{}", f.error));
    let reqs = w.fake.plan_requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 1);
    let mut keys: Vec<&str> = reqs[0].as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(keys, ["cover", "limits", "min_level", "payload_bytes", "segmentation", "target_chunk_bytes"]);
    // AppWire (28-byte header + plaintext + 16-byte AEAD tag) + 32-byte frame tag
    assert_eq!(reqs[0]["payload_bytes"].as_u64().unwrap() as usize, iod_core::transport::wire::WIRE_HEADER_LEN + SECRET.len() + 16 + 32);
    assert!(!reqs[0].to_string().contains(SECRET));
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
    // Restore: receiver now succeeds purely from the file contents (no plan call on the receive side).
    std::fs::write(art_path(&w, &id), &backup).unwrap();
    let plans_before = w.fake.count("plan");
    let r = pipeline::run_receive(&w.state, &w.sid, "drone-2", &id).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(r["delivered_message"], SECRET);
    assert_eq!(w.fake.count("plan"), plans_before, "the receiver never plans or segments");
    assert_eq!(r["received_manifest"]["used_patches"], 3);
    // Same file again: replay is refused.
    assert_eq!(receive_err(&w, "drone-2", &id), "REPLAY");
}

#[test]
fn tampered_saved_images_fail_closed_and_are_recorded() {
    let w = world("tamper");
    // (description, mutation of the stored container, expected stable code)
    type Mutator = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Mutator, &str)> = vec![
        ("manifest: algorithm id of a patch changed (2 -> 1)", Box::new(|f| f[E1] = 1), "FRAME_AUTH_FAILED"),
        ("manifest: algorithm parameter changed (dwt step 4 -> 5)", Box::new(|f| f[E1 + 12 + 1] = 5), "FRAME_AUTH_FAILED"),
        ("manifest: image height changed", Box::new(|f| swap_manifest(f, |m| m.height = 60)), "FRAME_AUTH_FAILED"),
        ("manifest: patch map changed (one cell moved to another patch)", Box::new(|f| swap_manifest(f, |m| { let i = m.cell_labels.iter().position(|l| *l == 1).unwrap(); m.cell_labels[i] = 0; })), "FRAME_AUTH_FAILED"),
        ("manifest: chunk lengths rebalanced (offsets still contiguous)", Box::new(|f| swap_manifest(f, |m| { m.patches[1].length += 1; m.patches[2].offset += 1; m.patches[2].length -= 1; })), "FRAME_AUTH_FAILED"),
        ("manifest: algorithms swapped between two patches", Box::new(|f| swap_manifest(f, |m| { let (a, b) = (m.patches[1].clone(), m.patches[2].clone()); m.patches[1].alg_id = b.alg_id; m.patches[1].param = b.param; m.patches[2].alg_id = a.alg_id; m.patches[2].param = a.param; })), "FRAME_AUTH_FAILED"),
        ("manifest: two patches exchange their regions (chunk order across the image changed)", Box::new(|f| swap_manifest(f, |m| { for l in m.cell_labels.iter_mut() { *l = match *l { 1 => 2, 2 => 1, x => x }; } })), "FRAME_AUTH_FAILED"),
        ("manifest: unused patch turned into a used one", Box::new(|f| swap_manifest(f, |m| { let l = m.patches[1].length; m.patches[0] = manifest::PatchEntry { alg_id: 1, param: 0, offset: 0, length: 5 }; m.patches[1].offset = 5; m.patches[1].length = l - 5; })), "FRAME_AUTH_FAILED"),
        ("manifest: payload offset changed (now overlapping)", Box::new(|f| f[E1 + 12 + 7] ^= 1), "MANIFEST_INVALID"),
        ("manifest: payload length changed", Box::new(|f| f[E1 + 11] ^= 1), "MANIFEST_INVALID"),
        ("manifest: unknown algorithm id", Box::new(|f| f[E1] = 99), "UNKNOWN_ALGORITHM"),
        ("manifest: patch count changed", Box::new(|f| f[M + 13] += 1), "MANIFEST_INVALID"),
        ("manifest: version changed", Box::new(|f| f[M + 4] = 2), "UNSUPPORTED_VERSION"),
        ("manifest: map label out of range", Box::new(|f| { let n = f.len(); let mlen = u32::from_be_bytes(f[F + 8..F + 12].try_into().unwrap()) as usize; let _ = n; f[M + mlen - 2] = 200; }), "MANIFEST_INVALID"),
        ("frame: payload-length field changed", Box::new(|f| f[F + 15] ^= 1), "FRAME_MALFORMED"),
        ("frame: version changed", Box::new(|f| f[F + 4] = 9), "FRAME_VERSION_UNSUPPORTED"),
        ("frame: magic changed (e.g. a Frame v1 image)", Box::new(|f| f[F..F + 4].copy_from_slice(b"IODF")), "FRAME_MALFORMED"),
        ("payload: ciphertext byte flipped", Box::new(|f| { let n = f.len(); f[n - 40] ^= 1 }), "FRAME_AUTH_FAILED"),
        ("payload: MAC tag byte flipped", Box::new(|f| { let n = f.len(); f[n - 1] ^= 1 }), "FRAME_AUTH_FAILED"),
        ("frame truncated", Box::new(|f| { f.truncate(f.len() - 7) }), "FRAME_MALFORMED"),
        ("image header corrupted", Box::new(|f| f[0] ^= 0xff), "IMAGE_DECODE_ERROR"),
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
        assert!(got.to_json().get("delivered_message").is_none());
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
fn structurally_bad_manifests_are_rejected_by_rust_even_if_the_image_service_passes_them_on() {
    // The image service is not trusted to validate: with its own check disabled, Rust still refuses
    // (the MAC fails first, because no manifest byte can change without the key).
    let w = world("lenient");
    *w.fake.lenient_extract.lock().unwrap() = true;
    for (off, val) in [(E1 + 12 + 7, 0x55u8), (E1, 99), (M + 13, 9), (M + 12, 5)] {
        let id = send(&w, "drone-1", SECRET)["artifact"]["id"].as_str().unwrap().to_string();
        let mut file = std::fs::read(art_path(&w, &id)).unwrap();
        file[off] = val;
        std::fs::write(art_path(&w, &id), &file).unwrap();
        assert_eq!(receive_err(&w, "drone-2", &id), "FRAME_AUTH_FAILED");
    }
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

/// Forge a stored image whose frame is MAC-valid for the receiver (test-only: uses the real session key)
/// to prove the checks BEHIND the MAC independently: manifest parsing and channel/direction/replay/AEAD.
fn forge_with(w: &World, mutate: impl Fn(&mut iod_core::protocol::messages::SecureAppMessage), seq: u32, dir_for_keys: u8, man: impl Fn(u32) -> Vec<u8>) -> String {
    let (key, tag) = {
        let s = w.state.lock().unwrap();
        let ch = s.channels.get(&w.sid).unwrap();
        (AeadKey(ch.d1_keys.d1_to_d2.0), ch.d1_keys.channel_tag)
    };
    let mut msg = seal_message(&key, tag, 1, seq, b"forged-body");
    mutate(&mut msg);
    let wire = encode_app_wire(&msg);
    let meta = derive_meta_key(&key, &tag, dir_for_keys);
    let frame = build_frame(&meta, &man(wire.len() as u32 + 32), &wire, 4096).unwrap();
    let id = format!("{:032x}", rand::random::<u128>());
    let mut file = b"FAKEIMG2".to_vec();
    file.extend_from_slice(&frame);
    std::fs::write(art_path(w, &id), file).unwrap();
    id
}

fn forge(w: &World, mutate: impl Fn(&mut iod_core::protocol::messages::SecureAppMessage), seq: u32, dir_for_keys: u8) -> String {
    forge_with(w, mutate, seq, dir_for_keys, |n| manifest::sample(64, 64, 1, n, &[(1, 0), (3, 0)]).encode())
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
fn an_authenticated_frame_still_needs_a_strictly_valid_manifest() {
    let w = world("authman");
    *w.fake.lenient_extract.lock().unwrap() = true;
    // MAC-valid, but the manifest is garbage / inconsistent with the payload / for another image size
    let id = forge_with(&w, |_| {}, 1, 1, |_| vec![0xAA; 60]);
    assert_eq!(receive_err(&w, "drone-2", &id), "MANIFEST_INVALID");
    let id = forge_with(&w, |_| {}, 1, 1, |n| manifest::sample(64, 64, 1, n + 3, &[(1, 0)]).encode());
    assert_eq!(receive_err(&w, "drone-2", &id), "MANIFEST_INVALID");
    let id = forge_with(&w, |_| {}, 1, 1, |n| manifest::sample(128, 96, 3, n, &[(1, 0)]).encode());
    assert_eq!(receive_err(&w, "drone-2", &id), "MANIFEST_INVALID");
    let id = forge_with(&w, |_| {}, 1, 1, |n| { let mut m = manifest::sample(64, 64, 1, n, &[(1, 0)]).encode(); m[24 + 12] = 77; m });
    assert_eq!(receive_err(&w, "drone-2", &id), "UNKNOWN_ALGORITHM");
    // none of these advanced the replay window
    let ok = forge(&w, |_| {}, 1, 1);
    assert!(pipeline::run_receive(&w.state, &w.sid, "drone-2", &ok).is_ok());
}

#[test]
fn out_of_order_delivery_is_rejected_as_replay() {
    let w = world("order");
    let a = send(&w, "drone-1", "first")["artifact"]["id"].as_str().unwrap().to_string();
    let b = send(&w, "drone-1", "second")["artifact"]["id"].as_str().unwrap().to_string();
    assert!(pipeline::run_receive(&w.state, &w.sid, "drone-2", &b).is_ok());
    assert_eq!(receive_err(&w, "drone-2", &a), "REPLAY");
}

fn stego_files(w: &World) -> usize {
    std::fs::read_dir(&w.fake.dir).unwrap().filter(|f| {
        let n = f.as_ref().unwrap().file_name().to_string_lossy().to_string();
        n.ends_with(".png") && n.matches('.').count() == 1
    }).count()
}

#[test]
fn capacity_and_size_rejections_are_structured_and_recorded() {
    let w = world("capacity");
    // frame limit (4096) exceeded before any backend call
    let big = "x".repeat(5000);
    let e = pipeline::run_message(&w.state, req(&w, "drone-1", &big)).err().unwrap();
    assert_eq!(e.error.code, "FRAME_TOO_LARGE");
    assert_eq!(e.error.http_status, 413);
    assert_eq!(w.fake.count("plan"), 0);
    // the cover cannot carry the frame even after refinement: rejected, never downgraded
    *w.fake.capacity_bytes.lock().unwrap() = 20;
    let e = pipeline::run_message(&w.state, req(&w, "drone-1", "hello world, longer than twenty bytes of capacity")).err().unwrap();
    assert_eq!(e.error.code, "PATCH_CAPACITY_INSUFFICIENT");
    assert_eq!(e.error.stage, "plan");
    *w.fake.fail_plan.lock().unwrap() = Some("NO_ELIGIBLE_ALGORITHM".into());
    assert_eq!(pipeline::run_message(&w.state, req(&w, "drone-1", "x")).err().unwrap().error.code, "NO_ELIGIBLE_ALGORITHM");
    let evs = events(&w);
    assert_eq!(evs.len(), 3);
    assert!(evs.iter().all(|e| e["success"] == false && e["error_code"].is_string()));
    assert_eq!(evs[1]["plan_attempts"].as_array().unwrap().len(), 2, "refinement attempts are recorded");
    // nothing was embedded or saved
    assert_eq!(w.fake.count("encode"), 0);
    assert_eq!(stego_files(&w), 0);
}

#[test]
fn a_failed_patch_embedding_triggers_a_bounded_coarser_replan_not_an_algorithm_fallback() {
    let w = world("replan");
    *w.fake.fail_encode_times.lock().unwrap() = 1;
    let v = pipeline::run_message(&w.state, req(&w, "drone-1", "after one re-plan")).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(v["delivered_message"], "after one re-plan");
    assert_eq!(*w.fake.plan_levels.lock().unwrap(), vec![0, 1]);
    assert_eq!(v["plan"]["refinement_level"], 1);
    let ev = &events(&w)[0];
    assert_eq!(ev["refinement_level"], 1);
    assert_eq!(ev["replans"].as_array().unwrap().len(), 1);
    assert_eq!(ev["replans"][0]["error_code"], "PATCH_EMBED_FAILED");
    // the re-plan reuses the SAME stored cover, and keeps the original acquisition label
    let reqs = w.fake.plan_requests.lock().unwrap().clone();
    assert_eq!(reqs[1]["cover"]["source"], "test_cover");
    assert_eq!(reqs[1]["cover"]["test_cover_id"], v["cover"]["artifact_id"]);
    assert_eq!(v["cover"]["source"], "procedural_fallback");
    // bounded: max_replans = 2 -> three attempts in total, then a structured failure and no saved image
    let before = stego_files(&w);
    *w.fake.fail_encode_times.lock().unwrap() = 10;
    w.fake.plan_levels.lock().unwrap().clear();
    let e = pipeline::run_message(&w.state, req(&w, "drone-1", "never embeds")).err().unwrap();
    assert_eq!(e.error.code, "PATCH_EMBED_FAILED");
    assert_eq!(e.error.stage, "embed");
    assert_eq!(*w.fake.plan_levels.lock().unwrap(), vec![0, 1, 2]);
    assert_eq!(stego_files(&w), before);
    assert_eq!(events(&w)[0]["replans"].as_array().unwrap().len(), 2);
}

#[test]
fn rust_validates_the_planned_manifest_before_authenticating_it() {
    let w = world("planman");
    let wire_len = iod_core::transport::wire::WIRE_HEADER_LEN + 2 + 16;
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("garbage", vec![1, 2, 3], "MANIFEST_INVALID"),
        ("payload length differs from the sealed message", manifest::sample(64, 64, 1, wire_len as u32 + 33, &[(1, 0)]).encode(), "MANIFEST_INVALID"),
        ("geometry differs from the cover", manifest::sample(128, 96, 3, wire_len as u32 + 32, &[(1, 0)]).encode(), "MANIFEST_INVALID"),
        ("unknown algorithm", { let mut m = manifest::sample(64, 64, 1, wire_len as u32 + 32, &[(1, 0)]).encode(); m[24 + 12] = 42; m }, "UNKNOWN_ALGORITHM"),
        ("parameter outside the whitelist", { let mut m = manifest::sample(64, 64, 1, wire_len as u32 + 32, &[(6, 4)]).encode(); m[24 + 13] = 200; m }, "MANIFEST_INVALID"),
        ("diagnostics disagree (different patch count)", manifest::sample(64, 64, 1, wire_len as u32 + 32, &[(1, 0)]).encode(), "BACKEND_MALFORMED_RESPONSE"),
    ];
    for (desc, bytes, code) in cases {
        *w.fake.manifest_override.lock().unwrap() = Some(bytes);
        let e = pipeline::run_message(&w.state, req(&w, "drone-1", "hi")).err().unwrap_or_else(|| panic!("[{desc}] accepted"));
        assert_eq!(e.error.code, code, "[{desc}]");
        assert_eq!(e.error.stage, "plan", "[{desc}]");
    }
    assert_eq!(w.fake.count("encode"), 0, "nothing is framed, authenticated or embedded for a rejected manifest");
    assert_eq!(stego_files(&w), 0);
}

#[test]
fn plan_preview_is_validated_and_bounded() {
    let w = world("preview-plan");
    let v = pipeline::run_plan_preview(&w.state, 300, &json!({"source": "procedural"}), 0).unwrap();
    assert_eq!(v["manifest"]["payload_len"], 300);
    assert_eq!(v["plan"]["patches"].as_array().unwrap().len(), 4);
    assert!(v["note"].as_str().unwrap().contains("no message sealed"));
    assert_eq!(w.fake.count("encode"), 0);
    assert_eq!(pipeline::run_plan_preview(&w.state, 32, &json!({}), 0).unwrap_err().code, "INVALID_REQUEST");
    assert_eq!(pipeline::run_plan_preview(&w.state, 1 << 20, &json!({}), 0).unwrap_err().code, "INVALID_REQUEST");
    assert_eq!(pipeline::run_plan_preview(&w.state, 300, &json!({}), 5).unwrap_err().code, "SEGMENTATION_FAILED");
    assert!(events(&w).is_empty(), "previews are not transport events");
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
    let r = MessageRequest { session_id: sid, from_id: "drone-1".into(), plaintext: b"hi".to_vec(), cover: json!({"source":"webcam"}), origin: "test" };
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
    let mk = |sid: &str, from: &str| MessageRequest { session_id: sid.into(), from_id: from.into(), plaintext: b"x".to_vec(), cover: json!({"source":"webcam"}), origin: "test" };
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
    let b = pipeline::run_benchmark(&w.state, &w.sid, 2, &[32, 200], &json!({"source":"webcam"})).unwrap();
    assert_eq!(b["samples"], 4);
    assert!(b["runs"].as_array().unwrap().iter().all(|r| r["ok"] == true));
    let evs = events(&w);
    let rep = iod_core::transport::report::build_report(&evs, json!({}), 1);
    assert_eq!(rep["totals"]["events"], 4);
    assert_eq!(rep["totals"]["ok"], 4);
    assert_eq!(rep["per_algorithm"].as_array().unwrap().len(), 3);
    assert_eq!(rep["per_algorithm"][0]["events"], 4);
    assert_eq!(rep["overall"]["timings_ms"]["total"]["p95"], Value::Null, "n<20 => no percentile");
    assert_eq!(rep["overall"]["used_patches"]["mean"], 3.0);
    let pcsv = iod_core::transport::report::patches_to_csv(&evs);
    assert_eq!(pcsv.lines().count(), 1 + 4 * 4, "one row per patch of every event");
    let csv = iod_core::transport::report::events_to_csv(&evs);
    assert_eq!(csv.lines().count(), 5);
    assert!(pipeline::run_benchmark(&w.state, &w.sid, 51, &[32], &json!({})).is_err());
    assert!(pipeline::run_benchmark(&w.state, &w.sid, 1, &[0], &json!({})).is_err());
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
    assert!(pipeline::artifact_png(&cfg, cover_id, "seg").is_ok());
    assert!(pipeline::artifact_png(&cfg, cover_id, "labels").is_ok());
    assert!(pipeline::artifact_png(&cfg, id, "diff").is_ok());
    for bad in ["../state.db", "..%2f..%2fetc%2fpasswd", &id[..31], &id.to_uppercase(), "", "a/b"] {
        assert!(pipeline::artifact_png(&cfg, bad, "stego").is_err(), "accepted {bad:?}");
    }
    assert!(pipeline::artifact_png(&cfg, id, "../x").is_err());
}
