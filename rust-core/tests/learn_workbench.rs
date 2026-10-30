//! Educational workbench: isolation from the operational transport, test-only envelope,
//! persistence and export. Uses the in-process fake backend, plus one test against the
//! real Python service (skippable with IOD_E2E_ALLOW_SKIP=1 like the other e2e tests).

use iod_core::api::state::SimulationState;
use iod_core::learn;
use iod_core::transport::backend::{learn_path_allowed, HttpBackend, StegoBackend, ALGS};
use iod_core::transport::config::StegoConfig;
use iod_core::transport::fake::FakeStegoBackend;
use iod_core::transport::pipeline::{self, MessageRequest};
use serde_json::json;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("iod-learn-{tag}-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn state_with(backend: Arc<dyn StegoBackend>, tag: &str) -> (Mutex<SimulationState>, String) {
    state_in(backend, dir(tag))
}

fn state_in(backend: Arc<dyn StegoBackend>, d: PathBuf) -> (Mutex<SimulationState>, String) {
    let mut cfg = StegoConfig::default();
    cfg.artifact_dir = d.join("artifacts").to_string_lossy().to_string();
    let mut s = SimulationState::with_backend(&d.join("s.db").to_string_lossy(), cfg, backend).unwrap();
    s.create_group("g1").unwrap();
    s.create_drone("drone-1").unwrap();
    s.create_drone("drone-2").unwrap();
    s.register_drone("drone-1", "g1", "member").unwrap();
    s.register_drone("drone-2", "g1", "member").unwrap();
    let (sid, rep) = s.authenticate("drone-1", "drone-2").unwrap();
    assert!(rep.authenticated);
    s.establish_group_key(&sid, "m").unwrap();
    (Mutex::new(s), sid)
}

#[test]
fn learning_experiments_never_touch_operational_state() {
    let d = dir("iso");
    let fake = Arc::new(FakeStegoBackend::new(d.join("artifacts")));
    let (st, sid) = state_in(fake.clone(), d);
    // one real operational message first
    let r = MessageRequest { session_id: sid.clone(), from_id: "drone-1".into(), plaintext: b"op".to_vec(), algorithm: None,
                             cover: json!({"source": "webcam"}), priority: "normal".into(), origin: "test" };
    pipeline::run_message(&st, r).unwrap_or_else(|f| panic!("{}", f.error));
    let (seq_before, seen_before, ev_before) = {
        let s = st.lock().unwrap();
        (s.message_seq.clone(), s.recv_seen.clone(), s.db.count_stego_events().unwrap())
    };
    for mode in ["aead_fixture", "synthetic"] {
        let out = learn::run_experiment(&st, &json!({"payload_mode": mode, "algorithms": "all"})).unwrap();
        assert_eq!(out["operational"], false);
        assert_eq!(out["label"], learn::LABEL);
        assert_eq!(out["results"].as_array().unwrap().len(), ALGS.len());
        for r in out["results"].as_array().unwrap() {
            assert!(r.get("extracted_b64").is_none(), "raw extracted payload must not be returned");
            let st = r["verification"]["status"].as_str().unwrap();
            if mode == "aead_fixture" {
                assert_eq!(st, "aead_verified");
                assert_eq!(r["verification"]["plaintext_matches"], true);
            } else {
                assert_eq!(st, "not_applicable_synthetic");
                assert_eq!(r["verification"]["bit_exact"], true);
            }
        }
        let c = &out["payload_construction"];
        if mode == "aead_fixture" {
            assert_eq!(c["wire_bytes"], 50 + learn::SAMPLE_MESSAGE.len() + 16);
            assert!(c["key"].as_str().unwrap().contains("TEST-ONLY"));
        } else {
            assert_eq!(c["fixture_hex"], "A63C915E");
        }
    }
    let s = st.lock().unwrap();
    assert_eq!(s.message_seq, seq_before, "learning must not advance operational sequence numbers");
    assert_eq!(s.recv_seen, seen_before, "learning must not touch replay windows");
    assert_eq!(s.db.count_stego_events().unwrap(), ev_before, "learning must not write operational events");
    assert_eq!(s.db.list_learn_experiments(10).unwrap().len(), 2);
}

#[test]
fn records_persist_and_export_without_images() {
    let fake = Arc::new(FakeStegoBackend::new(dir("fake2").join("artifacts")));
    let (st, _) = state_with(fake, "exp");
    let out = learn::run_experiment(&st, &json!({"payload_mode": "aead_fixture", "algorithms": ["dwt", "wow"]})).unwrap();
    let id = out["experiment_id"].as_str().unwrap().to_string();
    assert!(out["results"][0]["images"].is_object(), "live response may carry images");
    let rec = st.lock().unwrap().db.get_learn_experiment(&id).unwrap().unwrap();
    assert!(rec["results"][0].get("images").is_none() && rec["cover"].get("png").is_none(), "stored record has no images");
    assert_eq!(rec["results"][1]["algorithm"], "wow");
    let csv = learn::to_csv(&rec);
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.contains("aead_verified"));
    let md = learn::to_markdown(&rec);
    assert!(md.contains("not a live UAV transmission") && md.contains("| dwt |") && md.contains("TEST-ONLY"));
    // the exported record matches what was displayed (minus images)
    assert_eq!(rec["results"][0]["verification"], out["results"][0]["verification"]);
}

#[test]
fn invalid_requests_rejected() {
    let fake = Arc::new(FakeStegoBackend::new(dir("fake3").join("artifacts")));
    let (st, _) = state_with(fake.clone(), "bad");
    assert_eq!(learn::run_experiment(&st, &json!({"payload_mode": "plaintext"})).unwrap_err().code, "INVALID_REQUEST");
    assert_eq!(learn::run_experiment(&st, &json!({"message": ""})).unwrap_err().code, "INVALID_REQUEST");
    assert_eq!(learn::run_experiment(&st, &json!({"message": "x".repeat(3000)})).unwrap_err().code, "INVALID_REQUEST");
    assert!(learn_path_allowed("/learn/walkthrough/hugo") && learn_path_allowed("/learn/experiment"));
    for p in ["/stego/encode", "/learn/walkthrough/../stego", "/learn/walkthrough/nope", "/learn/experimentx"] {
        assert!(!learn_path_allowed(p), "{p}");
        assert_eq!(fake.learn_post(p, &json!({})).unwrap_err().code, "INVALID_REQUEST");
    }
}

// ---------------------------------------------------------------- real Python service
fn python() -> String {
    std::env::var("IOD_TEST_PYTHON").unwrap_or_else(|_| "python3".into())
}

#[test]
fn real_service_all_ten_algorithms_verify_the_test_envelope() {
    let ok = Command::new(python()).args(["-c", "import numpy, PIL, flask"]).stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        if std::env::var("IOD_E2E_ALLOW_SKIP").ok().as_deref() == Some("1") {
            eprintln!("SKIPPED: python3 with numpy, Pillow and Flask is not available");
            return;
        }
        panic!("python3 with numpy, Pillow and Flask is required (set IOD_E2E_ALLOW_SKIP=1 to skip visibly)");
    }
    let d = dir("py");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let mut child = Command::new(python()).arg(root.join("python-service/src/app.py"))
        .env("IOD_PYTHON_PORT", port.to_string()).env("IOD_STEGO_ARTIFACT_DIR", d.join("artifacts")).env("IOD_STEGO_CAMERA", "disabled")
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let t = Instant::now();
    while std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(200)).is_err() {
        assert!(t.elapsed() < Duration::from_secs(30), "python did not start");
        std::thread::sleep(Duration::from_millis(150));
    }
    std::thread::sleep(Duration::from_millis(200));
    let mut cfg = StegoConfig::default();
    cfg.python_url = format!("http://127.0.0.1:{port}");
    let backend: Arc<dyn StegoBackend> = Arc::new(HttpBackend::new(&cfg).unwrap());
    let (st, _) = state_with(backend.clone(), "realpy");
    let out = learn::run_experiment(&st, &json!({"payload_mode": "aead_fixture", "algorithms": "all", "include_images": false,
                                                 "verify_capacity": false, "cover": {"sample": "natural_rgb_256"}})).unwrap();
    let rs = out["results"].as_array().unwrap();
    assert_eq!(rs.len(), 10);
    for r in rs {
        assert_eq!(r["status"], "ok", "{}", r);
        assert_eq!(r["verification"]["status"], "aead_verified", "{}", r["algorithm"]);
        assert_eq!(r["ber"], 0.0);
    }
    // the same payload was used for all algorithms
    let sizes: std::collections::HashSet<String> = rs.iter().map(|r| r["payload_bytes"].to_string()).collect();
    assert_eq!(sizes.len(), 1);
    // walkthroughs are reachable through the backend and recover their bits exactly
    for a in ALGS {
        let w = backend.learn_get(&format!("/learn/walkthrough/{a}")).unwrap();
        assert_eq!(w["exact_match"], true, "{a}");
        assert_eq!(w["all_checks_passed"], true, "{a}");
    }
    let _ = child.kill();
    let _ = child.wait();
}
