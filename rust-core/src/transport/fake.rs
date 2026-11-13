//! In-process stand-in for the Python image service, used by Rust tests (no Python needed).
//! It implements the same JSON contract (plan / encode / extract / kb): `plan` returns a real,
//! strictly valid patch manifest; `encode` stores the frame in a small container file
//! (`FAKEIMG2 | frame`) in the artifact directory so tests can tamper with the *saved file*
//! exactly as they would a PNG, and the receiver still has to read that file.
//! It is NOT a steganography implementation and never runs in the live application.

use crate::transport::backend::{is_artifact_id, StegoBackend, ALGS};
use crate::transport::b64;
use crate::transport::error::StegoError;
use crate::transport::manifest;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct FakeStegoBackend {
    pub dir: PathBuf,
    /// Total patch capacity; larger payloads are rejected with PATCH_CAPACITY_INSUFFICIENT.
    pub capacity_bytes: Mutex<usize>,
    /// Force `plan` to fail with this error code.
    pub fail_plan: Mutex<Option<String>>,
    /// The next N `encode` calls fail with PATCH_EMBED_FAILED (exercises the bounded re-plan).
    pub fail_encode_times: Mutex<u32>,
    /// Replace the manifest returned by `plan` (to test Rust-side manifest validation).
    pub manifest_override: Mutex<Option<Vec<u8>>>,
    pub fallback_reason: Mutex<Option<String>>,
    /// `min_level` of every plan request, in call order.
    pub plan_levels: Mutex<Vec<u64>>,
    /// Every plan request body, in call order (tests assert that no payload bytes or keys are sent).
    pub plan_requests: Mutex<Vec<Value>>,
    /// Skip the structural manifest check in `extract` (to exercise the Rust-side checks in isolation).
    pub lenient_extract: Mutex<bool>,
    /// Number of calls per endpoint name.
    pub calls: Mutex<Vec<String>>,
    counter: Mutex<u64>,
}

fn rand_id(counter: &Mutex<u64>) -> String {
    let mut c = counter.lock().unwrap();
    *c += 1;
    format!("{:016x}{:016x}", 0xfeed_beef_0000_0000u64 + *c, rand::random::<u64>())
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub const FAKE_ALGS: [(u8, u8); 3] = [(2, 0), (6, 4), (9, 8)];
const MAGIC: &[u8; 8] = b"FAKEIMG2";

impl FakeStegoBackend {
    pub fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        FakeStegoBackend {
            dir,
            capacity_bytes: Mutex::new(100_000),
            fail_plan: Mutex::new(None),
            fail_encode_times: Mutex::new(0),
            manifest_override: Mutex::new(None),
            fallback_reason: Mutex::new(Some("CAMERA_ABSENT".into())),
            plan_levels: Mutex::new(vec![]),
            plan_requests: Mutex::new(vec![]),
            lenient_extract: Mutex::new(false),
            calls: Mutex::new(vec![]),
            counter: Mutex::new(0),
        }
    }
    pub fn stego_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.png"))
    }
    /// Offset of the frame inside a saved fake image file.
    pub const FRAME_OFFSET: usize = 8;
    fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.to_string());
    }
    pub fn count(&self, what: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| *c == what).count()
    }
}

impl StegoBackend for FakeStegoBackend {
    fn health(&self) -> Result<Value, StegoError> {
        Ok(json!({"ok": true, "service": "fake-stego", "version": "test", "format_version": "frame-v2/appwire-v1/bootstrap-v2/manifest-v1",
                  "segmentation_version": manifest::SEG_VERSION_NAME, "selector_version": manifest::SEL_VERSION_NAME, "kb_version": "fake-kb",
                  "algorithms": ALGS.iter().enumerate().map(|(i,a)| json!({"id": i+1, "name": a})).collect::<Vec<_>>(),
                  "camera": {"backend": "fake", "opencv_available": false, "mode": "fake"}}))
    }
    fn camera_probe(&self, _i: i64, _t: u64) -> Result<Value, StegoError> {
        Ok(json!({"available": false, "reason": "CAMERA_ABSENT"}))
    }
    fn cover_upload(&self, image_b64: &str, origin: &str, _limits: &Value) -> Result<Value, StegoError> {
        let raw = b64::decode(image_b64, 1 << 24).map_err(|e| StegoError::new("INVALID_REQUEST", "prepare", 400, e))?;
        if !raw.starts_with(b"\x89PNG") {
            return Err(StegoError::new("IMAGE_DECODE_ERROR", "prepare", 422, "only PNG images are accepted"));
        }
        let id = rand_id(&self.counter);
        std::fs::write(self.dir.join(format!("{id}.cover.png")), &raw).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "prepare", 500, e.to_string()))?;
        Ok(json!({"ok": true, "cover": {"artifact_id": id, "source": origin, "fallback_reason": Value::Null, "width": 64, "height": 64, "mode": "L",
                  "channels": 1, "transforms": [], "sha256": sha(&raw)}, "timings_ms": {"store": 1.0}}))
    }
    fn learn_get(&self, path: &str) -> Result<Value, StegoError> {
        if !crate::transport::backend::learn_path_allowed(path) {
            return Err(StegoError::new("INVALID_REQUEST", "prepare", 400, "learn path not allowed"));
        }
        Ok(json!({"ok": true, "fake": true, "path": path}))
    }
    fn learn_post(&self, path: &str, body: &Value) -> Result<Value, StegoError> {
        if !crate::transport::backend::learn_path_allowed(path) {
            return Err(StegoError::new("INVALID_REQUEST", "prepare", 400, "learn path not allowed"));
        }
        // perfect-extraction fake: echoes the payload back for every requested algorithm
        let algs: Vec<String> = match &body["algorithms"] {
            Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => ALGS.iter().map(|s| s.to_string()).collect(),
        };
        let pb = body["payload_b64"].as_str().unwrap_or("");
        let n = b64::decode(pb, 1 << 20).map(|v| v.len()).unwrap_or(0);
        let results: Vec<Value> = algs.iter().map(|a| json!({"algorithm": a, "status": "ok", "payload_bytes": n, "extracted_b64": pb,
            "mse": 0.01, "psnr_db": 60.0, "ssim": 0.999, "ber": 0.0, "bit_accuracy": 1.0, "exact_recovery": true, "outside_patch_changes": 0, "images": {"stego": "data:"}})).collect();
        Ok(json!({"ok": true, "experiment_id": format!("{:032x}", rand::random::<u128>()), "mode": "educational", "cover": {"description": "fake", "png": "data:"},
                  "segmentation": {"version": manifest::SEG_VERSION_NAME, "patch_count": 4}, "patch": {"patch_id": 1, "chosen_by": "most_textured"},
                  "payload": {"bytes": n, "bits": n * 8, "sha256": "00"}, "results": results, "survey": [], "metric_definitions": {}, "interpretation": [], "attacks": []}))
    }
    fn plan(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("plan");
        self.plan_requests.lock().unwrap().push(req.clone());
        if let Some(code) = self.fail_plan.lock().unwrap().clone() {
            return Err(StegoError::new(&code, "plan", 422, "forced failure"));
        }
        let payload = req["payload_bytes"].as_u64().unwrap_or(0) as usize;
        let level = req["min_level"].as_u64().unwrap_or(0);
        self.plan_levels.lock().unwrap().push(level);
        if level > 3 {
            return Err(StegoError::new("SEGMENTATION_FAILED", "plan", 422, "refinement level exhausted"));
        }
        let cap = *self.capacity_bytes.lock().unwrap();
        if payload > cap {
            return Err(StegoError::new("PATCH_CAPACITY_INSUFFICIENT", "plan", 422, "the cover cannot carry this frame patch-wise within the refinement limit")
                .with_details(json!({"attempts": [{"level": 0, "outcome": "CAPACITY_INSUFFICIENT"}, {"level": 1, "outcome": "CAPACITY_INSUFFICIENT"}], "payload_bytes": payload})));
        }
        // a planned cover is reused as-is on a re-plan (same id) -- as the real service does
        let (cover_id, source) = match (req["cover"]["source"].as_str(), req["cover"]["test_cover_id"].as_str().or(req["cover"]["cover_id"].as_str())) {
            (Some(src @ ("test_cover" | "browser_webcam" | "uploaded")), Some(id)) if is_artifact_id(id) => (id.to_string(), src.to_string()),
            _ => {
                let id = rand_id(&self.counter);
                let fb = self.fallback_reason.lock().unwrap().is_some();
                (id, if fb { "procedural_fallback".to_string() } else { "webcam".to_string() })
            }
        };
        let cover_path = self.dir.join(format!("{cover_id}.cover.png"));
        if !cover_path.exists() {
            std::fs::write(&cover_path, format!("FAKECOVER{cover_id}")).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "plan", 500, e.to_string()))?;
        }
        let cover_bytes = std::fs::read(&cover_path).unwrap_or_default();
        for kind in ["seg", "labels"] {
            let _ = std::fs::write(self.dir.join(format!("{cover_id}.{kind}.png")), b"FAKEINSPECT");
        }
        let algs: &[(u8, u8)] = if level == 0 { &FAKE_ALGS } else { &FAKE_ALGS[..2] };
        let man = manifest::sample(64, 64, 1, payload as u32, algs);
        let bytes = self.manifest_override.lock().unwrap().clone().unwrap_or_else(|| man.encode());
        let mut counts = serde_json::Map::new();
        let patches: Vec<Value> = man.patches.iter().enumerate().map(|(i, p)| {
            if p.alg_id == 0 {
                return json!({"patch_id": i, "used": false, "selected": Value::Null, "payload_offset": Value::Null, "payload_length": 0,
                              "features": {"pixels": 1024, "usable_pixels": 0, "gradient_mean": 1.0, "variance": 2.0, "entropy": 1.0}, "retrieval": Value::Null});
            }
            let name = ALGS[p.alg_id as usize - 1];
            *counts.entry(name.to_string()).or_insert(json!(0)) = json!(counts.get(name).and_then(|v| v.as_u64()).unwrap_or(0) + 1);
            json!({"patch_id": i, "used": true, "selected": name, "alg_id": p.alg_id, "param": p.param, "variant": "fake", "payload_offset": p.offset,
                   "payload_length": p.length, "measured_capacity_bytes": cap / 3, "max_capacity_bytes": cap / 3, "utilisation": 0.1,
                   "features": {"pixels": 1024, "usable_pixels": 1000, "gradient_mean": 6.5, "variance": 80.0, "entropy": 5.5},
                   "dry_run": {"ok": true, "error": Value::Null, "ms": 0.1},
                   "retrieval": {"selector_version": manifest::SEL_VERSION_NAME, "kb_version": "fake-kb", "query_terms": ["textured"], "required_bits": p.length * 8,
                                 "selected": name, "ranking": [name], "tie": false,
                                 "candidates": [{"algorithm": name, "alg_id": p.alg_id, "kb_entry": format!("fake-kb#{}", p.alg_id), "eligible": true, "filters": [],
                                                 "exclusion_reason": Value::Null, "bm25": 1.25, "matched_terms": ["textured"], "capacity_bits": cap * 8 / 3, "rank": 1}]}})
        }).collect();
        let fb = self.fallback_reason.lock().unwrap().clone();
        Ok(json!({"ok": true, "format_version": "frame-v2/appwire-v1/bootstrap-v2/manifest-v1", "manifest_b64": b64::encode(&bytes), "manifest_sha256": sha(&bytes),
            "plan": {"selector_version": manifest::SEL_VERSION_NAME, "kb_version": "fake-kb",
                     "segmentation": {"version": manifest::SEG_VERSION_NAME, "level": level, "regions": man.patches.len(), "cell_size": 8, "settings": req["segmentation"]},
                     "refinement_level": level, "attempts": [{"level": level, "regions": man.patches.len(), "outcome": "OK"}], "payload_bytes": payload,
                     "manifest_bytes": bytes.len(), "reserved_rows": man.reserved_rows, "patch_count": man.patches.len(), "used_patches": algs.len(),
                     "algorithms_used": counts, "target_chunk_bytes": req["target_chunk_bytes"], "patches": patches, "plan_ms": 1.0},
            "cover": {"artifact_id": cover_id, "source": source, "fallback_reason": if source == "procedural_fallback" { json!(fb) } else { Value::Null },
                      "width": 64, "height": 64, "mode": "L", "channels": 1, "transforms": [], "sha256": sha(&cover_bytes)},
            "inspection": {"segmentation_overlay": format!("{cover_id}.seg.png"), "label_map": format!("{cover_id}.labels.png"), "palette": [[1, 2, 3]]},
            "timings_ms": {"capture": 1.0, "plan": 2.0, "save": 0.5}}))
    }
    fn encode(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("encode");
        {
            let mut n = self.fail_encode_times.lock().unwrap();
            if *n > 0 {
                *n -= 1;
                return Err(StegoError::new("PATCH_EMBED_FAILED", "embed", 422, "patch failed immediate re-extraction").with_details(json!({"patch": 1, "algorithm": "lsb_matching"})));
            }
        }
        let frame = b64::decode(req["frame_b64"].as_str().unwrap_or(""), 1 << 22).map_err(|e| StegoError::new("INVALID_REQUEST", "embed", 400, e))?;
        // structural split only (as the real service: no key, no MAC check)
        if frame.len() < 16 + 32 + 1 || &frame[..4] != b"IOD2" {
            return Err(StegoError::new("FRAME_MALFORMED", "embed", 422, "not a v2 frame"));
        }
        let mlen = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
        let man = manifest::parse(frame.get(16..16 + mlen).unwrap_or(&[]), 4096)?;
        let cover_id = req["cover"]["test_cover_id"].as_str().or(req["cover"]["cover_id"].as_str()).unwrap_or("").to_string();
        if !is_artifact_id(&cover_id) || !self.dir.join(format!("{cover_id}.cover.png")).exists() {
            return Err(StegoError::new("INVALID_REQUEST", "embed", 400, "encode needs the stored cover that was planned"));
        }
        let id = rand_id(&self.counter);
        let mut file = MAGIC.to_vec();
        file.extend_from_slice(&frame);
        std::fs::write(self.stego_path(&id), &file).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "save", 500, e.to_string()))?;
        let _ = std::fs::write(self.dir.join(format!("{id}.diff.png")), b"FAKEINSPECT");
        let per: Vec<Value> = man.patches.iter().enumerate().map(|(i, p)| if p.alg_id == 0 { json!({"patch_id": i, "used": false}) } else {
            json!({"patch_id": i, "used": true, "algorithm": ALGS[p.alg_id as usize - 1], "alg_id": p.alg_id, "param": p.param, "payload_offset": p.offset,
                   "payload_length": p.length, "capacity_bytes": 1000, "changed_samples": 10, "patch_mse": 0.5, "extraction": "verified_from_saved_png"})
        }).collect();
        Ok(json!({"ok": true, "artifact_id": id, "format_version": "frame-v2/appwire-v1/bootstrap-v2/manifest-v1",
            "stego": {"path_name": format!("{id}.png"), "sha256": sha(&file), "size": file.len(), "width": 64, "height": 64, "mode": "L", "channels": 1, "format": "PNG"},
            "cover": {"artifact_id": cover_id, "source": "test_cover", "width": 64, "height": 64, "mode": "L", "channels": 1},
            "embed": {"frame_len": frame.len(), "manifest_len": mlen, "payload_len": man.payload_len, "patch_count": man.patches.len(), "used_patches": man.used().count(),
                      "reserved_rows": man.reserved_rows, "patches": per, "exact_frame_recovery_from_saved_png": true,
                      "metrics": {"mse": 0.25, "psnr": 54.2, "ssim": 0.9995, "changed_samples": 10, "changed_fraction": 0.001, "max_abs_diff": 1}},
            "timings_ms": {"capture": 0.2, "embed": 1.5, "verify": 0.5, "save": 0.7}}))
    }
    fn extract(&self, artifact_id: &str, _limits: &Value) -> Result<Value, StegoError> {
        self.note("extract");
        if !is_artifact_id(artifact_id) {
            return Err(StegoError::new("INVALID_REQUEST", "read", 400, "bad artifact id"));
        }
        let data = std::fs::read(self.stego_path(artifact_id)).map_err(|_| StegoError::new("ARTIFACT_NOT_FOUND", "read", 404, "no such artifact"))?;
        if data.len() < 8 + 16 || &data[..8] != MAGIC {
            return Err(StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"));
        }
        let frame = &data[8..];
        let mlen = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
        // like the real service: the (unauthenticated) manifest must at least parse before chunks are read
        if *self.lenient_extract.lock().unwrap() {
            return Ok(json!({"ok": true, "frame_b64": b64::encode(frame), "bootstrap": {"version": 2, "manifest_len": mlen, "frame_len": frame.len()},
                "manifest": Value::Null, "patches": [], "resegmented": false,
                "image": {"width": 64, "height": 64, "mode": "L", "channels": 1, "format": "PNG", "size": data.len(), "sha256": sha(&data)},
                "timings_ms": {"read": 0.4, "extract": 0.6}}));
        }
        let man = manifest::parse(frame.get(16..16usize.saturating_add(mlen)).unwrap_or(&[]), 4096)?;
        let per: Vec<Value> = man.used().map(|(i, p)| json!({"patch_id": i, "algorithm": ALGS[p.alg_id as usize - 1], "alg_id": p.alg_id, "param": p.param,
            "payload_offset": p.offset, "payload_length": p.length, "status": "extracted"})).collect();
        Ok(json!({"ok": true, "frame_b64": b64::encode(frame), "format_version": "frame-v2/appwire-v1/bootstrap-v2/manifest-v1",
            "bootstrap": {"version": 2, "manifest_len": mlen, "frame_len": frame.len()}, "manifest": man.summary(), "patches": per, "resegmented": false,
            "image": {"width": 64, "height": 64, "mode": "L", "channels": 1, "format": "PNG", "size": data.len(), "sha256": sha(&data)},
            "timings_ms": {"read": 0.4, "extract": 0.6}}))
    }
    fn kb(&self) -> Result<Value, StegoError> {
        Ok(json!({"ok": true, "kb_version": "fake-kb", "selector": {"version": manifest::SEL_VERSION_NAME}, "entries": [], "references": [], "query_terms": []}))
    }
}
