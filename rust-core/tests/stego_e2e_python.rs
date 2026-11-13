//! End-to-end tests of the patch-wise transport against the REAL Python image service
//! (real segmentation, knowledge-base selection, ten real algorithms, real PNG files, no webcam). The service is spawned on a free loopback
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

fn req(sid: &str, from: &str, text: &str, cover: Value) -> MessageRequest {
    MessageRequest { session_id: sid.into(), from_id: from.into(), plaintext: text.as_bytes().to_vec(), cover, origin: "e2e" }
}

fn helper(mode: &str, path: &Path, args: &[&str]) -> String {
    let mut c = Command::new(python());
    c.arg("-I").arg(repo_root().join("rust-core/tests/helpers/tamper_png.py")).arg(mode).arg(path).args(args);
    let out = c.output().unwrap();
    assert!(out.status.success(), "helper {mode} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn png_path(py: &Py, id: &str) -> PathBuf {
    py.dir.join("artifacts").join(format!("{id}.png"))
}

fn stego_pngs(py: &Py) -> usize {
    std::fs::read_dir(py.dir.join("artifacts")).unwrap().filter(|f| {
        let n = f.as_ref().unwrap().file_name().to_string_lossy().to_string();
        n.ends_with(".png") && n.matches('.').count() == 1
    }).count()
}

/// A stored cover produced outside the service (stands in for a camera frame).
fn stored_cover(py: &Py, mode: &str) -> Value {
    let cover_id = format!("{:032x}", rand::random::<u128>());
    helper(mode, &py.dir.join("artifacts").join(format!("{cover_id}.cover.png")), &[]);
    json!({"source": "test_cover", "test_cover_id": cover_id})
}

fn check_sequential(manifest: &Value, payload: u64) {
    let mut off = 0u64;
    for p in manifest["patches"].as_array().unwrap().iter().filter(|p| p["used"] == true) {
        assert_eq!(p["payload_offset"].as_u64().unwrap(), off);
        assert!(p["payload_length"].as_u64().unwrap() >= 1);
        off += p["payload_length"].as_u64().unwrap();
    }
    assert_eq!(off, payload, "chunks cover the payload exactly once");
}

#[test]
fn both_directions_real_png_patchwise_with_camera_fallback() {
    let Some(py) = start_python("roundtrip") else { return };
    let (st, sid) = state(&py);
    for (from, text) in [("drone-1", format!("patch-wise d1->d2 {SECRET}")), ("drone-2", format!("patch-wise d2->d1 {SECRET} \u{1F681}"))] {
        let v = pipeline::run_message(&st, req(&sid, from, &text, json!({"source": "webcam"}))).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["cover"]["source"], "procedural_fallback", "no webcam => procedural fallback");
        assert_eq!(v["cover"]["fallback_reason"], "CAMERA_DISABLED");
        assert_eq!(v["verification"]["frame_match"], true);
        assert_eq!(v["verification"]["resegmented"], false);
        assert_eq!(v["manifest"], v["received_manifest"], "the receiver authenticated exactly the planned manifest");
        assert!(v["stages"].as_array().unwrap().iter().all(|s| s["status"] == "ok"));
        assert_eq!(v["embed"]["exact_frame_recovery_from_saved_png"], true);
        let payload = v["transport"]["payload_section_bytes"].as_u64().unwrap();
        check_sequential(&v["manifest"], payload);
        // the saved artifact is a real PNG whose embedded bootstrap + manifest an INDEPENDENT reader agrees with
        let id = v["artifact"]["id"].as_str().unwrap();
        let bytes = std::fs::read(png_path(&py, id)).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        let dump: Value = serde_json::from_str(&helper("dump", &png_path(&py, id), &[])).unwrap();
        assert_eq!(dump["crc_ok"], true);
        assert_eq!(dump["frame_len"], v["transport"]["frame_bytes"]);
        assert_eq!(dump["manifest_len"], v["transport"]["manifest_bytes"]);
        assert_eq!(dump["patch_count"], v["manifest"]["patch_count"]);
        assert_eq!(dump["reserved_rows"], v["manifest"]["reserved_rows"]);
        for (d, m) in dump["patches"].as_array().unwrap().iter().zip(v["manifest"]["patches"].as_array().unwrap()) {
            if m["used"] == true {
                assert_eq!(d["alg_id"], m["alg_id"]);
                assert_eq!(d["param"], m["param"]);
                assert_eq!(d["offset"], m["payload_offset"]);
                assert_eq!(d["length"], m["payload_length"]);
            } else {
                assert_eq!(d["alg_id"], 0);
            }
        }
        // per-patch records: selected algorithm comes from the knowledge-base ranking, with real scores
        for p in v["plan"]["patches"].as_array().unwrap().iter().filter(|p| p["used"] == true) {
            assert_eq!(p["retrieval"]["ranking"][0], p["selected"]);
            assert_eq!(p["retrieval"]["selector_version"], "kb-bm25-1");
            assert!(p["retrieval"]["candidates"].as_array().unwrap().len() == 10);
            assert_eq!(p["dry_run"]["ok"], true);
        }
        for p in v["embed"]["patches"].as_array().unwrap().iter().filter(|p| p["used"] == true) {
            assert_eq!(p["extraction"], "verified_from_saved_png");
        }
        // inspection images exist and are served by id only
        let cfg = st.lock().unwrap().stego_cfg.clone();
        let cid = v["cover"]["artifact_id"].as_str().unwrap();
        for (aid, kind) in [(cid, "cover"), (cid, "seg"), (cid, "labels"), (id, "diff"), (id, "stego")] {
            assert_eq!(&pipeline::artifact_png(&cfg, aid, kind).unwrap()[..4], b"\x89PNG", "{kind}");
        }
    }
    let evs = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert_eq!(evs.len(), 2);
    assert!(evs.iter().all(|e| e["success"] == true && e["patches"].as_array().map(|a| !a.is_empty()).unwrap_or(false)));
    assert!(!serde_json::to_string(&evs).unwrap().contains(SECRET));
}

#[test]
fn a_varied_cover_is_split_into_irregular_patches_using_several_algorithms() {
    let Some(py) = start_python("mixed") else { return };
    let (st, sid) = state(&py);
    let cover = stored_cover(&py, "make-mixed-cover");
    let mut seen = std::collections::BTreeSet::new();
    for (from, n) in [("drone-1", 60usize), ("drone-2", 400), ("drone-1", 1500), ("drone-2", 3000)] {
        let text = "m".repeat(n);
        let v = pipeline::run_message(&st, req(&sid, from, &text, cover.clone())).unwrap_or_else(|f| panic!("{n}: {}", f.error));
        assert_eq!(v["delivered_message"].as_str().unwrap().len(), n);
        assert_eq!(v["cover"]["width"], 320);
        assert_eq!(v["cover"]["mode"], "RGB");
        assert!(v["manifest"]["patch_count"].as_u64().unwrap() >= 4);
        check_sequential(&v["manifest"], v["transport"]["payload_section_bytes"].as_u64().unwrap());
        for (a, _) in v["plan"]["algorithms_used"].as_object().unwrap() {
            seen.insert(a.clone());
        }
        // patches are irregular: pixel counts differ and are not all multiples of one rectangle size
        let dump: Value = serde_json::from_str(&helper("dump", &png_path(&py, v["artifact"]["id"].as_str().unwrap()), &[])).unwrap();
        let sizes: std::collections::BTreeSet<u64> = dump["pixels_per_patch"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
        assert!(sizes.len() >= 3, "{sizes:?}");
        assert_eq!(dump["pixels_per_patch"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).sum::<u64>(), 320 * 240, "every pixel in exactly one patch");
    }
    assert!(seen.len() >= 2, "expected different algorithms across patches, got {seen:?}");
    // the plan is deterministic for the same cover and payload length
    let a = pipeline::run_plan_preview(&st, 500, &cover, 0).unwrap();
    let b = pipeline::run_plan_preview(&st, 500, &cover, 0).unwrap();
    assert_eq!(a["manifest"], b["manifest"]);
    let essence = |v: &Value| v["plan"]["patches"].as_array().unwrap().iter()
        .map(|p| (p["selected"].clone(), p["payload_offset"].clone(), p["payload_length"].clone(), p["retrieval"].clone(), p["features"].clone())).collect::<Vec<_>>();
    assert_eq!(essence(&a), essence(&b), "features, retrieval scores and allocation are reproducible");
    // a coarser level has fewer patches
    let c = pipeline::run_plan_preview(&st, 500, &cover, 2).unwrap();
    assert!(c["manifest"]["patch_count"].as_u64().unwrap() < a["manifest"]["patch_count"].as_u64().unwrap());
}

#[test]
fn pixel_level_tampering_of_real_pngs_fails_closed() {
    let Some(py) = start_python("tamper") else { return };
    let (st, sid) = state(&py);
    let cover = stored_cover(&py, "make-mixed-cover");
    // (helper mode, args, acceptable stable codes). `U` = the first used patch id, `N` = an unused/other id.
    let cases: &[(&str, &[&str], &[&str])] = &[
        // --- payload area: Python cannot notice; the Rust MAC must (or extraction itself fails closed)
        ("flip-patch", &["U"], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED"]),
        ("flip-patch", &["U", "40"], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED"]),
        // --- manifest fields rewritten WITH a valid carrier CRC (CRC is not authentication)
        ("manifest-entry", &["U", "alg", "SWAP"], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED", "MANIFEST_INVALID"]),
        ("manifest-entry", &["U", "alg", "11"], &["UNKNOWN_ALGORITHM"]),
        ("manifest-entry", &["U", "alg", "200"], &["UNKNOWN_ALGORITHM"]),
        ("manifest-entry", &["U", "param", "33"], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED", "MANIFEST_INVALID"]),
        ("manifest-entry", &["U", "offset", "7"], &["MANIFEST_INVALID"]),
        ("manifest-entry", &["U", "length", "1"], &["MANIFEST_INVALID"]),
        ("manifest-entry", &["U", "length", "4000000000"], &["MANIFEST_INVALID"]),
        ("manifest-move-byte", &[], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED"]),
        ("manifest-relabel", &["U", "OTHER"], &["FRAME_AUTH_FAILED", "EXTRACT_FAILED", "MANIFEST_INVALID"]),
        ("manifest-byte", &["9", "72"], &["MANIFEST_INVALID"]),           // width low byte (320 -> 328)
        ("manifest-byte", &["11", "232"], &["MANIFEST_INVALID"]),         // height low byte
        ("manifest-byte", &["12", "5"], &["MANIFEST_INVALID"]),           // cell size not whitelisted
        ("manifest-byte", &["13", "1"], &["MANIFEST_INVALID"]),           // patch count
        ("manifest-byte", &["4", "9"], &["UNSUPPORTED_VERSION"]),         // manifest version
        ("manifest-byte", &["5", "9"], &["UNSUPPORTED_VERSION"]),         // segmentation version
        ("manifest-byte", &["-2", "250"], &["MANIFEST_INVALID"]),         // map label out of range
        // --- carrier / preamble
        ("carrier-flip", &["100"], &["BOOTSTRAP_CORRUPT"]),
        ("carrier-flip", &["400"], &["BOOTSTRAP_CORRUPT"]),
        ("preamble-set", &["version", "7"], &["UNSUPPORTED_VERSION"]),
        ("preamble-set", &["version", "1"], &["UNSUPPORTED_VERSION"]),
        ("preamble-set", &["flags", "1"], &["BOOTSTRAP_CORRUPT"]),
        ("preamble-set", &["frame_len", "-5"], &["FRAME_LENGTH_INVALID"]),
        ("preamble-set", &["frame_len", "+5"], &["FRAME_LENGTH_INVALID"]),
        ("preamble-set", &["frame_len", "2147483647"], &["FRAME_LENGTH_INVALID", "FRAME_TOO_LARGE"]),
        ("preamble-set", &["manifest_len", "-3"], &["BOOTSTRAP_CORRUPT", "MANIFEST_INVALID", "FRAME_LENGTH_INVALID"]),
        ("preamble-set", &["manifest_len", "4000000000"], &["MANIFEST_TOO_LARGE", "BOOTSTRAP_CORRUPT"]),
        // --- whole-image damage
        ("blank", &[], &["BOOTSTRAP_MISSING"]),
        ("truncate", &[], &["IMAGE_DECODE_ERROR"]),
        ("garbage", &[], &["IMAGE_DECODE_ERROR"]),
        ("jpeg", &[], &["BOOTSTRAP_MISSING", "BOOTSTRAP_CORRUPT", "UNSUPPORTED_VERSION", "MANIFEST_INVALID", "MANIFEST_TOO_LARGE", "FRAME_LENGTH_INVALID", "FRAME_AUTH_FAILED", "EXTRACT_FAILED", "UNKNOWN_ALGORITHM"]),
    ];
    for (mode, raw_args, codes) in cases {
        let sent = pipeline::run_send(&st, req(&sid, "drone-1", &format!("{SECRET} {}", "t".repeat(300)), cover.clone())).unwrap_or_else(|f| panic!("send: {}", f.error));
        let id = sent["artifact"]["id"].as_str().unwrap().to_string();
        let used: Vec<&Value> = sent["manifest"]["patches"].as_array().unwrap().iter().filter(|p| p["used"] == true).collect();
        assert!(used.len() >= 2, "the tamper cases need at least two used patches");
        let u = used[0]["patch_id"].as_u64().unwrap();
        let other = used[1]["patch_id"].as_u64().unwrap();
        // a different but VALID algorithm id/parameter combination for the first used patch
        let swap = if used[0]["alg_id"] == 1 { "2" } else { "1" };
        let args: Vec<String> = raw_args.iter().map(|a| match *a { "U" => u.to_string(), "OTHER" => other.to_string(), "SWAP" => swap.to_string(), x => x.to_string() }).collect();
        let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        helper(mode, &png_path(&py, &id), &argv);
        let got = match pipeline::run_receive(&st, &sid, "drone-2", &id) {
            Ok(v) => panic!("[{mode} {argv:?}] delivered {:?}", v["delivered_message"]),
            Err(f) => f,
        };
        assert!(codes.contains(&got.error.code.as_str()), "[{mode} {argv:?}] got {} expected one of {codes:?}", got.error);
        assert!(!got.to_json().to_string().contains(SECRET));
        assert!(got.event_id > 0);
    }
    // the receiver is still healthy afterwards (no failure advanced the replay window)
    let ok = pipeline::run_message(&st, req(&sid, "drone-1", "after tamper", cover)).unwrap_or_else(|f| panic!("{}", f.error));
    assert_eq!(ok["delivered_message"], "after tamper");
    // every tamper case that reached the Rust verifier with an intact carrier was a MAC failure
    let evs = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert!(evs.iter().filter(|e| e["error_code"] == "FRAME_AUTH_FAILED").count() >= 3);
}

#[test]
fn oversized_frames_are_rejected_without_bypassing_the_image_transport() {
    let Some(py) = start_python("capacity") else { return };
    // frame limit raised so the rejection must come from the image capacity, not the size limit
    let (st, sid) = state_with(&py, 262_144);
    let big = "z".repeat(150_000);
    let e = pipeline::run_message(&st, req(&sid, "drone-1", &big, json!({"source": "procedural"}))).err().expect("must be rejected");
    assert_eq!(e.error.code, "PATCH_CAPACITY_INSUFFICIENT", "{}", e.error);
    let evs = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert_eq!(evs[0]["success"], false);
    let attempts = evs[0]["plan_attempts"].as_array().expect("refinement attempts recorded");
    assert_eq!(attempts.len(), 4, "levels 0..=3 were tried before rejecting");
    assert!(attempts.iter().all(|a| a["outcome"] != "OK"));
    // no PNG was written for the rejected message
    assert_eq!(stego_pngs(&py), 0);
}

#[test]
fn browser_webcam_frame_upload_becomes_the_cover_and_is_labelled() {
    use iod_core::transport::b64;
    let Some(py) = start_python("browsercam") else { return };
    let (st, sid) = state(&py);
    // a PNG that stands in for a frame captured in the browser (canvas.toBlob -> base64)
    let tmp = py.dir.join("frame.png");
    helper("make-cover", &tmp, &[]);
    let png = std::fs::read(&tmp).unwrap();
    let backend = st.lock().unwrap().backend.clone();
    let limits = st.lock().unwrap().stego_cfg.limits();
    let up = backend.cover_upload(&b64::encode(&png), "browser_webcam", &limits).expect("upload");
    let cover_id = up["cover"]["artifact_id"].as_str().unwrap().to_string();
    assert_eq!(up["cover"]["source"], "browser_webcam");
    assert_eq!(up["cover"]["width"], 320);
    let cover = json!({"source": "browser_webcam", "cover_id": cover_id});
    for (from, text) in [("drone-1", "from the browser camera D1->D2"), ("drone-2", "from the browser camera D2->D1")] {
        let v = pipeline::run_message(&st, req(&sid, from, text, cover.clone())).unwrap_or_else(|f| panic!("{}", f.error));
        assert_eq!(v["delivered_message"], text);
        assert_eq!(v["cover"]["source"], "browser_webcam");
        assert_eq!(v["cover"]["artifact_id"], cover_id.as_str());
        assert_eq!(v["verification"]["frame_match"], true);
    }
    // events record the cover source
    let events = st.lock().unwrap().db.query_stego_events(&Default::default()).unwrap();
    assert!(events.iter().any(|e| e["cover_source"] == "browser_webcam"));
    // non-PNG and traversal-shaped input is rejected without storing anything
    let bad = backend.cover_upload(&b64::encode(b"GIF89a-not-a-png"), "browser_webcam", &limits).unwrap_err();
    assert_eq!(bad.code, "IMAGE_DECODE_ERROR");
    let bad = backend.plan(&json!({"payload_bytes": 100, "cover": {"source": "browser_webcam", "cover_id": "../../etc/passwd"}})).unwrap_err();
    assert!(bad.code == "INVALID_REQUEST", "{}", bad.code);
}

#[test]
fn knowledge_base_is_served_validated_and_old_endpoints_are_gone() {
    let Some(py) = start_python("kb") else { return };
    let (st, _sid) = state(&py);
    let backend = st.lock().unwrap().backend.clone();
    let kb = backend.kb().unwrap();
    assert_eq!(kb["selector"]["version"], "kb-bm25-1");
    let entries = kb["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 10);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e["id"], i + 1);
        assert_eq!(e["name"], iod_core::transport::backend::ALGS[i]);
        assert!(e["variant"].is_string() && e["evidence"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
    }
    let health = backend.health().unwrap();
    assert_eq!(health["format_version"], pipeline::TRANSPORT_FORMAT_VERSION);
    // removed endpoints of the old whole-image / generic-RAG flow
    let base = iod_core::transport::http::parse_base_url(&format!("http://127.0.0.1:{}", py.port), false).unwrap();
    for path in ["/stego/explain", "/stego/analyze", "/rag/run", "/rag/contribute"] {
        let r = iod_core::transport::http::request(&base, "POST", path, Some(b"{}"), Duration::from_secs(5), 1 << 20).unwrap();
        assert_eq!(r.status, 404, "{path}");
    }
}
