//! End-to-end tests against the REAL Python image service (real PNG files,
//! real algorithms, no webcam). The service is spawned on a free loopback
//! port with its camera disabled, so the procedural fallback is exercised.
//!
//! If python3/numpy/Pillow/Flask are unavailable these tests FAIL loudly
//! (set IOD_E2E_ALLOW_SKIP=1 to turn that into a visible skip message).

use iod_core::api::state::SimulationState;
use iod_core::transport::backend::HttpBackend;
use iod_core::transport::config::StegoConfig;
use iod_core::transport::pipeline::{self, MessageRequest};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &str = "E2E-SECRET-PLAINTEXT-777";

struct Py {
    child: Child,
    port: u16,
    dir: PathBuf,
}
impl Drop for Py {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn python() -> String {
    std::env::var("IOD_TEST_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn start_python(tag: &str) -> Option<Py> {
    let ok = Command::new(python()).args(["-c", "import numpy, PIL, flask"]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        if std::env::var("IOD_E2E_ALLOW_SKIP").ok().as_deref() == Some("1") {
            eprintln!("SKIPPED ({tag}): python3 with numpy, Pillow and Flask is not available");
            return None;
        }
        panic!("python3 with numpy, Pillow and Flask is required for the real end-to-end tests (set IOD_E2E_ALLOW_SKIP=1 to skip visibly)");
    }
    let dir = std::env::temp_dir().join(format!("iod-e2e-{tag}-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(dir.join("artifacts")).unwrap();
    let port = free_port();
    let child = Command::new(python())
        .arg(repo_root().join("python-service/src/app.py"))
        .env("IOD_PYTHON_PORT", port.to_string())
        .env("IOD_STEGO_ARTIFACT_DIR", dir.join("artifacts"))
        .env("IOD_STEGO_CAMERA", "disabled")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python service");
    let py = Py { child, port, dir };
    let start = Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(200)).is_ok() {
            std::thread::sleep(Duration::from_millis(200));
            return Some(py);
        }
        assert!(start.elapsed() < Duration::from_secs(30), "python service did not start");
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn cfg(py: &Py) -> StegoConfig {
    let mut c = StegoConfig::default();
    c.python_url = format!("http://127.0.0.1:{}", py.port);
    c.artifact_dir = py.dir.join("artifacts").to_string_lossy().to_string();
    c.max_frame_bytes = 16 * 1024;
    c.http_timeout_ms = 60_000;
    c
}

fn state(py: &Py) -> (Mutex<SimulationState>, String) {
    state_with(py, 16 * 1024)
}

fn state_with(py: &Py, max_frame: usize) -> (Mutex<SimulationState>, String) {
    let mut c = cfg(py);
    c.max_frame_bytes = max_frame;
    let backend = Arc::new(HttpBackend::new(&c).unwrap());
    let mut s = SimulationState::with_backend(&py.dir.join("s.db").to_string_lossy(), c, backend).unwrap();
    s.create_group("g1").unwrap();
    for d in ["drone-1", "drone-2"] {
        s.create_drone(d).unwrap();
        s.register_drone(d, "g1", "member").unwrap();
    }
    let (sid, rep) = s.authenticate("drone-1", "drone-2").unwrap();
    assert!(rep.authenticated);
    s.establish_group_key(&sid, "mission-e2e").unwrap();
    (Mutex::new(s), sid)
}

fn req(sid: &str, from: &str, text: &str, alg: Option<&str>, cover: Value) -> MessageRequest {
    MessageRequest { session_id: sid.into(), from_id: from.into(), plaintext: text.as_bytes().to_vec(), algorithm: alg.map(|s| s.to_string()), cover, priority: "normal".into(), origin: "e2e" }
}

fn tamper(mode: &str, path: &Path, arg: Option<&str>) {
    let mut c = Command::new(python());
    c.arg("-I").arg(repo_root().join("rust-core/tests/helpers/tamper_png.py")).arg(mode).arg(path);
    if let Some(a) = arg {
        c.arg(a);
    }
    let out = c.output().unwrap();
    assert!(out.status.success(), "tamper helper failed: {}", String::from_utf8_lossy(&out.stderr));
}

fn png_path(py: &Py, id: &str) -> PathBuf {
    py.dir.join("artifacts").join(format!("{id}.png"))
}

#[test]
fn both_directions_every_algorithm_real_png_with_camera_fallback() {
    let Some(py) = start_python("roundtrip") else { return };
    let (st, sid) = state(&py);
    // automatic selection, both directions
    for (from, text) in [("drone-1", format!("auto d1->d2 {SECRET}")), ("drone-2", format!("auto d2->d1 {SECRET}"))] {
        let v = pipeline::run_message(&st, req(&sid, from, &text, None, json!({"source": "webcam"}))).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["cover"]["source"], "procedural_fallback", "no webcam => procedural fallback");
        assert_eq!(v["cover"]["fallback_reason"], "CAMERA_DISABLED");
        assert_eq!(v["selection"]["mode"], "auto");
        assert_eq!(v["verification"]["frame_match"], true);
        let id = v["artifact"]["id"].as_str().unwrap();
        let bytes = std::fs::read(png_path(&py, id)).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "saved artifact is a real PNG");
        assert!(v["stages"].as_array().unwrap().iter().all(|s| s["status"] == "ok"));
    }
    // manual override for each of the five algorithms, on the procedural B/W cover; DCT may be
    // legitimately refused on saturated covers (clean structured failure, never silent corruption)
    let mut delivered = 0;
    for alg in ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"] {
        for (from, dir) in [("drone-1", 1), ("drone-2", 2)] {
            let text = format!("{alg} message {dir}");
            match pipeline::run_message(&st, req(&sid, from, &text, Some(alg), json!({"source": "procedural"}))) {
                Ok(v) => {
                    assert_eq!(v["delivered_message"], text);
                    assert_eq!(v["embed"]["algorithm"], alg);
                    delivered += 1;
                }
                Err(f) => {
                    assert!(["ALGORITHM_NOT_ELIGIBLE", "ENCODE_VERIFY_FAILED", "NO_ELIGIBLE_ALGORITHM", "EDGE_CAPACITY_INSUFFICIENT"].contains(&f.error.code.as_str()), "{alg}: unexpected failure {}", f.error);
                    eprintln!("note: {alg} refused on the B/W procedural cover: {}", f.error.code);
                }
            }
        }
    }
    assert!(delivered >= 6, "at least the three always-eligible algorithms must deliver in both directions (got {delivered})");
}

#[test]
fn pixel_level_tampering_of_real_pngs_fails_closed() {
    let Some(py) = start_python("tamper") else { return };
    let (st, sid) = state(&py);
    let cover = json!({"source": "procedural", "seed": "e2e-tamper"});
    // (tamper mode, arg, acceptable stable codes). All start from a genuine lsb_replacement image.
    let cases: &[(&str, Option<&str>, &[&str])] = &[
        ("flip-payload", Some("200"), &["FRAME_AUTH_FAILED"]),
        ("flip-bootstrap-crc", None, &["BOOTSTRAP_CORRUPT"]),
        ("set-alg", Some("2"), &["FRAME_ALGORITHM_MISMATCH"]),
        ("set-alg", Some("9"), &["UNKNOWN_ALGORITHM"]),
        ("set-version", Some("7"), &["UNSUPPORTED_VERSION"]),
        ("adjust-length", Some("-5"), &["FRAME_MALFORMED"]),
        ("huge-length", None, &["FRAME_LENGTH_INVALID", "FRAME_TOO_LARGE"]),
        ("blank", None, &["BOOTSTRAP_MISSING"]),
        ("truncate", None, &["IMAGE_DECODE_ERROR"]),
        ("garbage", None, &["IMAGE_DECODE_ERROR"]),
        ("jpeg", None, &["BOOTSTRAP_MISSING", "BOOTSTRAP_CORRUPT", "FRAME_AUTH_FAILED", "FRAME_MALFORMED", "UNSUPPORTED_VERSION", "UNKNOWN_ALGORITHM", "FRAME_LENGTH_INVALID", "FRAME_TOO_LARGE"]),
    ];
    for (mode, arg, codes) in cases {
        let sent = pipeline::run_send(&st, req(&sid, "drone-1", SECRET, Some("lsb_replacement"), cover.clone())).unwrap_or_else(|f| panic!("send: {}", f.error));
        let id = sent["artifact"]["id"].as_str().unwrap().to_string();
        tamper(mode, &png_path(&py, &id), *arg);
        let got = match pipeline::run_receive(&st, &sid, "drone-2", &id) {
            Ok(v) => panic!("[{mode} {arg:?}] delivered {:?}", v["delivered_message"]),
            Err(f) => f,
        };
        assert!(codes.contains(&got.error.code.as_str()), "[{mode} {arg:?}] got {} expected one of {codes:?}", got.error);
        assert!(!got.to_json().to_string().contains(SECRET));
    }
    // the receiver is still healthy afterwards
    let ok = pipeline::run_message(&st, req(&sid, "drone-1", "after tamper", None, cover)).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(ok["delivered_message"], "after tamper");
}

#[test]
fn rag_explanation_is_real_service_output_and_does_not_change_the_choice() {
    let Some(py) = start_python("rag") else { return };
    let (st, sid) = state(&py);
    let v = pipeline::run_message(&st, req(&sid, "drone-1", "explain me", None, json!({"source": "procedural"}))).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(v["explanation"]["status"], "simulated_rag");
    assert_eq!(v["explanation"]["fallback"], false);
    assert_eq!(v["selection"]["selected"], v["embed"]["algorithm"]);
    let narrative = v["explanation"]["narrative"].as_str().unwrap();
    assert!(narrative.contains(v["selection"]["selected"].as_str().unwrap()));
    // determinism of the selector: identical analysis twice (same seed => same cover) gives the same choice and scores
    let a = pipeline::run_analyze(&st, 300, &json!({"source":"procedural","seed":"fixed"}), "normal", None).unwrap();
    let b = pipeline::run_analyze(&st, 300, &json!({"source":"procedural","seed":"fixed"}), "normal", None).unwrap();
    assert_eq!(a["selection"]["selected"], b["selection"]["selected"]);
    let scores = |x: &Value| x["selection"]["candidates"].as_array().unwrap().iter().map(|c| (c["algorithm"].clone(), c["score"].clone(), c["eligible"].clone())).collect::<Vec<_>>();
    assert_eq!(scores(&a), scores(&b));
}

#[test]
fn oversized_frames_are_rejected_without_bypassing_the_image_transport() {
    let Some(py) = start_python("capacity") else { return };
    // frame limit raised so the rejection must come from the image capacity, not the size limit
    let (st, sid) = state_with(&py, 262_144);
    // a 512x512 procedural cover (~32 KB capacity at best) cannot hold a ~100 KB frame
    let big = "z".repeat(100_000);
    let e = pipeline::run_message(&st, req(&sid, "drone-1", &big, None, json!({"source": "procedural"}))).err().expect("must be rejected");
    assert!(["NO_ELIGIBLE_ALGORITHM", "FRAME_TOO_LARGE"].contains(&e.error.code.as_str()), "{}", e.error);
    let evs = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert_eq!(evs[0]["success"], false);
    assert!(evs[0]["error_code"].is_string());
    // no PNG was written for the rejected message
    let pngs = std::fs::read_dir(py.dir.join("artifacts")).unwrap().filter(|f| { let n = f.as_ref().unwrap().file_name().to_string_lossy().to_string(); n.ends_with(".png") && !n.contains(".cover.") }).count();
    assert_eq!(pngs, 0);
}

#[test]
fn all_five_algorithms_deliver_both_directions_on_a_natural_rgb_cover() {
    let Some(py) = start_python("natural") else { return };
    let (st, sid) = state(&py);
    // A webcam-like RGB frame placed in the artifact directory and referenced as a saved test cover.
    let cover_id = format!("{:032x}", rand::random::<u128>());
    tamper("make-cover", &py.dir.join("artifacts").join(format!("{cover_id}.cover.png")), None);
    let cover = json!({"source": "test_cover", "test_cover_id": cover_id});
    for alg in ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"] {
        for (from, text) in [("drone-1", format!("{alg}: D1 to D2 \u{1F681}")), ("drone-2", format!("{alg}: D2 to D1 \u{2713}"))] {
            let v = pipeline::run_message(&st, req(&sid, from, &text, Some(alg), cover.clone())).unwrap_or_else(|f| panic!("{alg}: {}", f.error));
            assert_eq!(v["delivered_message"], text, "{alg}");
            assert_eq!(v["embed"]["algorithm"], alg);
            assert_eq!(v["verification"]["frame_match"], true);
            assert_eq!(v["cover"]["width"], 320);
            assert_eq!(v["cover"]["mode"], "RGB");
        }
    }
    // automatic selection on the same cover is deterministic across repeated analyses
    let a = pipeline::run_analyze(&st, 200, &cover, "normal", None).unwrap();
    let b = pipeline::run_analyze(&st, 200, &cover, "normal", None).unwrap();
    assert_eq!(a["selection"]["selected"], b["selection"]["selected"]);
    // different priority classes may legitimately choose differently; both must be valid algorithms
    let urgent = pipeline::run_analyze(&st, 200, &cover, "urgent", None).unwrap();
    assert!(urgent["selection"]["selected"].is_string());
}

#[test]
fn browser_webcam_frame_upload_becomes_the_cover_and_is_labelled() {
    use iod_core::transport::b64;
    let Some(py) = start_python("browsercam") else { return };
    let (st, sid) = state(&py);
    // a PNG that stands in for a frame captured in the browser (canvas.toBlob -> base64)
    let tmp = py.dir.join("frame.png");
    tamper("make-cover", &tmp, None);
    let png = std::fs::read(&tmp).unwrap();
    let backend = st.lock().unwrap().backend.clone();
    let limits = st.lock().unwrap().stego_cfg.limits();
    let up = backend.cover_upload(&b64::encode(&png), "browser_webcam", &limits).expect("upload");
    let cover_id = up["cover"]["artifact_id"].as_str().unwrap().to_string();
    assert_eq!(up["cover"]["source"], "browser_webcam");
    assert_eq!(up["cover"]["width"], 320);
    let cover = json!({"source": "browser_webcam", "cover_id": cover_id});
    for (from, text) in [("drone-1", "from the browser camera D1->D2"), ("drone-2", "from the browser camera D2->D1")] {
        let v = pipeline::run_message(&st, req(&sid, from, text, None, cover.clone())).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["cover"]["source"], "browser_webcam");
        assert_eq!(v["cover"]["artifact_id"], cover_id.as_str());
        assert_eq!(v["verification"]["frame_match"], true);
    }
    // events record the cover source
    let events = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert!(events.iter().any(|e| e.to_string().contains("browser_webcam")));
    // non-PNG and traversal-shaped input is rejected without storing anything
    let bad = backend.cover_upload(&b64::encode(b"GIF89a-not-a-png"), "browser_webcam", &limits).unwrap_err();
    assert_eq!(bad.code, "IMAGE_DECODE_ERROR");
    let bad = backend.analyze(&json!({"frame_bytes": 100, "cover": {"source": "browser_webcam", "cover_id": "../../etc/passwd"}})).unwrap_err();
    assert!(bad.code == "INVALID_REQUEST", "{}", bad.code);
}
