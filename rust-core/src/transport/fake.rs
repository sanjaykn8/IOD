//! In-process stand-in for the Python image service, used by Rust tests
//! (no Python needed). It stores each "image" as a small container file
//! (`FAKEIMG1 | alg | param | frame`) in the artifact directory, so tests
//! can tamper with the *saved file* exactly as they would a PNG, and the
//! receiver still has to read that file. It implements the same JSON
//! contract as the real service. It is NOT a steganography implementation.

use crate::transport::backend::{is_artifact_id, StegoBackend, ALGS};
use crate::transport::b64;
use crate::transport::error::StegoError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub enum ExplainMode {
    Ok,
    Unavailable,
    UnsupportedClaims,
    ChangesDecision,
}

pub struct FakeStegoBackend {
    pub dir: PathBuf,
    pub capacity_bytes: Mutex<usize>,
    pub force_algorithm: Mutex<Option<String>>,
    pub explain_mode: Mutex<ExplainMode>,
    pub fail_analyze: Mutex<Option<String>>,
    pub fallback_reason: Mutex<Option<String>>,
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

impl FakeStegoBackend {
    pub fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        FakeStegoBackend {
            dir,
            capacity_bytes: Mutex::new(100_000),
            force_algorithm: Mutex::new(None),
            explain_mode: Mutex::new(ExplainMode::Ok),
            fail_analyze: Mutex::new(None),
            fallback_reason: Mutex::new(Some("CAMERA_ABSENT".into())),
            counter: Mutex::new(0),
        }
    }
    pub fn stego_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.png"))
    }
    fn alg_id(name: &str) -> u8 {
        ALGS.iter().position(|a| *a == name).map(|i| i as u8 + 1).unwrap_or(0)
    }
}

impl StegoBackend for FakeStegoBackend {
    fn health(&self) -> Result<Value, StegoError> {
        Ok(json!({"ok": true, "service": "fake-stego", "version": "test", "algorithms": ALGS.iter().enumerate().map(|(i,a)| json!({"id": i+1, "name": a})).collect::<Vec<_>>(),
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
        Ok(json!({"ok": true, "cover": {"artifact_id": id, "source": origin, "fallback_reason": Value::Null, "width": 64, "height": 64, "mode": "RGB",
                  "channels": 3, "transforms": [], "sha256": sha(&raw)}, "timings_ms": {"store": 1.0}}))
    }
    fn analyze(&self, req: &Value) -> Result<Value, StegoError> {
        if let Some(code) = self.fail_analyze.lock().unwrap().clone() {
            return Err(StegoError::new(&code, "capture_select", 422, "forced failure"));
        }
        let frame_bytes = req["frame_bytes"].as_u64().unwrap_or(0) as usize;
        let cap = *self.capacity_bytes.lock().unwrap();
        let manual = req["algorithm"].as_str().map(|s| s.to_string()).or_else(|| self.force_algorithm.lock().unwrap().clone());
        let mut candidates = Vec::new();
        for (i, a) in ALGS.iter().enumerate() {
            // pseudo capacities so that selection is non-trivial
            let c = cap / (i + 1);
            let eligible = c >= frame_bytes;
            candidates.push(json!({"algorithm": a, "eligible": eligible, "exclusion_reason": if eligible { Value::Null } else { json!("CAPACITY_INSUFFICIENT") },
                "capacity_bits": c * 8, "capacity_bytes": c, "utilization": frame_bytes as f64 / c.max(1) as f64, "score": 0.1 + i as f64 * 0.05,
                "est_cost_units": 1.0 + i as f64, "mse": 0.4, "psnr": 52.0 - i as f64, "ssim": 0.999}));
        }
        let elig: Vec<&str> = candidates.iter().filter(|c| c["eligible"] == true).map(|c| c["algorithm"].as_str().unwrap()).collect();
        if elig.is_empty() {
            return Err(StegoError::new("NO_ELIGIBLE_ALGORITHM", "capture_select", 422, "no algorithm can hold the frame").with_details(json!({"candidates": candidates})));
        }
        let (selected, mode, reason) = match &manual {
            Some(m) => {
                if !elig.contains(&m.as_str()) {
                    return Err(StegoError::new("ALGORITHM_NOT_ELIGIBLE", "capture_select", 422, "forced algorithm not eligible"));
                }
                (m.clone(), "manual", "MANUAL_OVERRIDE")
            }
            None => (elig[0].to_string(), "auto", if elig.len() == 1 { "ONLY_ELIGIBLE" } else { "BEST_SCORE" }),
        };
        let cover_id = rand_id(&self.counter);
        let cover_bytes = format!("FAKECOVER{}", cover_id).into_bytes();
        std::fs::write(self.dir.join(format!("{cover_id}.cover.png")), &cover_bytes).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "capture_select", 500, e.to_string()))?;
        let fb = self.fallback_reason.lock().unwrap().clone();
        Ok(json!({"ok": true,
            "selection": {"policy_version": "sel-policy-1", "mode": mode, "selected": selected, "selected_alg_id": Self::alg_id(&selected), "selected_param": 0,
                          "reason_code": reason, "features": {"frame_bytes": frame_bytes}, "candidates": candidates},
            "cover": {"artifact_id": cover_id, "source": if fb.is_some() {"procedural_fallback"} else {"webcam"}, "fallback_reason": fb,
                      "width": 64, "height": 64, "mode": "L", "channels": 1, "transforms": ["mode:1->L"], "sha256": sha(&cover_bytes)},
            "timings_ms": {"capture": 1.0, "select": 2.0}}))
    }
    fn encode(&self, req: &Value) -> Result<Value, StegoError> {
        let frame = b64::decode(req["frame_b64"].as_str().unwrap_or(""), 1 << 22).map_err(|e| StegoError::new("INVALID_REQUEST", "embed", 400, e))?;
        let alg = req["algorithm"].as_str().unwrap_or("lsb_replacement");
        let param = req["param"].as_u64().unwrap_or(0) as u8;
        let id = rand_id(&self.counter);
        let mut file = b"FAKEIMG1".to_vec();
        file.push(Self::alg_id(alg));
        file.push(param);
        file.extend_from_slice(&frame);
        std::fs::write(self.stego_path(&id), &file).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "save", 500, e.to_string()))?;
        Ok(json!({"ok": true, "artifact_id": id,
            "stego": {"path_name": format!("{id}.png"), "sha256": sha(&file), "size": file.len(), "width": 64, "height": 64, "mode": "L", "channels": 1, "format": "PNG"},
            "embed": {"algorithm": alg, "alg_id": Self::alg_id(alg), "param": param, "params": {}, "capacity_bytes": *self.capacity_bytes.lock().unwrap(),
                      "frame_len": frame.len(), "used_fraction": 0.01, "metrics": {"mse": 0.25, "psnr": 54.2, "ssim": 0.9995, "changed_samples": 10, "changed_fraction": 0.001, "max_abs_diff": 1}},
            "timings_ms": {"embed": 1.5, "verify": 0.5, "save": 0.7}}))
    }
    fn extract(&self, artifact_id: &str, _limits: &Value) -> Result<Value, StegoError> {
        if !is_artifact_id(artifact_id) {
            return Err(StegoError::new("INVALID_REQUEST", "read", 400, "bad artifact id"));
        }
        let data = std::fs::read(self.stego_path(artifact_id)).map_err(|_| StegoError::new("ARTIFACT_NOT_FOUND", "read", 404, "no such artifact"))?;
        if data.len() < 10 || &data[..8] != b"FAKEIMG1" {
            return Err(StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"));
        }
        let alg = data[8];
        if !(1..=5).contains(&alg) {
            return Err(StegoError::new("UNKNOWN_ALGORITHM", "extract", 422, "unknown algorithm id"));
        }
        let frame = &data[10..];
        Ok(json!({"ok": true, "frame_b64": b64::encode(frame),
            "bootstrap": {"version": 1, "alg_id": alg, "algorithm": ALGS[alg as usize - 1], "param": data[9], "frame_len": frame.len()},
            "image": {"width": 64, "height": 64, "mode": "L", "channels": 1, "format": "PNG", "size": data.len(), "sha256": sha(&data)},
            "timings_ms": {"read": 0.4, "extract": 0.6}}))
    }
    fn explain(&self, report: &Value) -> Result<Value, StegoError> {
        let sel = report["selection"]["selected"].as_str().unwrap_or("?").to_string();
        match self.explain_mode.lock().unwrap().clone() {
            ExplainMode::Ok => Ok(json!({"status": "simulated_rag", "narrative": format!("{sel} was selected (fake narrative)."), "evidence": [{"id":"report.selected","source":"report","text":format!("selected={sel}")}],
                "retrieved": [], "kb_version": "fake-kb-1", "generator": "mock-template", "selected_unchanged": true, "selected": sel})),
            ExplainMode::Unavailable => Err(StegoError::new("STEGO_BACKEND_UNAVAILABLE", "explain", 503, "rag down")),
            ExplainMode::UnsupportedClaims => Ok(json!({"status": "unsupported_claims", "narrative": "x", "selected_unchanged": true})),
            ExplainMode::ChangesDecision => Ok(json!({"status": "simulated_rag", "narrative": "use dct instead", "selected_unchanged": true, "selected": "dct"})),
        }
    }
}
