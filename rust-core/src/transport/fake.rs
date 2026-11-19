//! In-process stand-in for the Python image service, used by Rust tests (no Python needed).
//! It implements the same JSON contract (plan / encode / carrier probe / carrier read / extract / kb):
//! `plan` "generates" a fresh cover for a new transmission (counted as a `generate` call) or reuses
//! the stored one for a re-plan, and returns a real, strictly valid manifest-v2 plus its DEFLATE form;
//! `encode` stores what a real stego PNG would carry in a small container file in the artifact
//! directory, so tests can tamper with the *saved file* and the receiver still has to read it:
//!
//! ```text
//! "FAKEIMG3" | u32 carrier_len | carrier (encrypted bootstrap-v3 bytes) | u32 values_len | values
//!            | payload section (wire | tag, what the patches carry)
//! ```
//! `values` stands in for the pixel positions: a probe or read with a different value stream (wrong
//! key, sequence or direction) gets pseudo-random bits, exactly like reading random pixels. The frame
//! header and manifest are NOT in the file; extraction rebuilds the frame from the manifest Rust supplies.
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
    /// Every encode request body, in call order.
    pub encode_requests: Mutex<Vec<Value>>,
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

/// lsb_matching, edge_adaptive_lsb (param 4), wow (STC h=8): all permitted by the default policy.
pub const FAKE_ALGS: [(u8, u8); 3] = [(2, 0), (4, 4), (9, 8)];
pub const FAKE_W: u16 = 128;
pub const FAKE_H: u16 = 96;
pub const FAKE_CH: u8 = 3;
pub const MAGIC: &[u8; 8] = b"FAKEIMG3";

/// Parsed fake stego file: (carrier, values, payload section).
pub fn split_fake(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if data.len() < 16 || &data[..8] != MAGIC {
        return None;
    }
    let cl = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
    let c_end = 12usize.checked_add(cl)?;
    let vl_end = c_end.checked_add(4)?;
    if data.len() < vl_end {
        return None;
    }
    let vl = u32::from_be_bytes(data[c_end..vl_end].try_into().ok()?) as usize;
    let v_end = vl_end.checked_add(vl)?;
    if data.len() < v_end {
        return None;
    }
    Some((&data[12..c_end], &data[vl_end..v_end], &data[v_end..]))
}

/// Build a fake stego file (tests use this to forge images with real session keys).
pub fn build_fake(carrier: &[u8], values: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut f = MAGIC.to_vec();
    f.extend_from_slice(&(carrier.len() as u32).to_be_bytes());
    f.extend_from_slice(carrier);
    f.extend_from_slice(&(values.len() as u32).to_be_bytes());
    f.extend_from_slice(values);
    f.extend_from_slice(payload);
    f
}

/// What random pixels would return for an unrelated value stream: deterministic pseudo-random bytes.
fn noise(values: &[u8], file_sha: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut ctr = 0u32;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(b"FAKE-NOISE");
        h.update(values);
        h.update(file_sha.as_bytes());
        h.update(ctr.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    out.truncate(n);
    out
}

impl FakeStegoBackend {
    pub fn new(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        FakeStegoBackend {
            dir,
            capacity_bytes: Mutex::new(100_000),
            fail_plan: Mutex::new(None),
            fail_encode_times: Mutex::new(0),
            manifest_override: Mutex::new(None),
            encode_requests: Mutex::new(vec![]),
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
    fn note(&self, what: &str) {
        self.calls.lock().unwrap().push(what.to_string());
    }
    pub fn count(&self, what: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| *c == what).count()
    }
    fn read_fake(&self, req: &Value) -> Result<(Vec<u8>, String), StegoError> {
        let id = req["artifact_id"].as_str().unwrap_or("");
        if !is_artifact_id(id) {
            return Err(StegoError::new("INVALID_REQUEST", "read", 400, "bad artifact id"));
        }
        let data = std::fs::read(self.stego_path(id)).map_err(|_| StegoError::new("ARTIFACT_NOT_FOUND", "read", 404, "no such artifact"))?;
        if split_fake(&data).is_none() {
            return Err(StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"));
        }
        let h = sha(&data);
        Ok((data, h))
    }
    fn image_json(&self, data: &[u8], sha_hex: &str) -> Value {
        json!({"width": FAKE_W, "height": FAKE_H, "mode": "RGB", "channels": FAKE_CH, "format": "PNG", "size": data.len(), "sha256": sha_hex})
    }
}

impl StegoBackend for FakeStegoBackend {
    fn health(&self) -> Result<Value, StegoError> {
        Ok(json!({"ok": true, "service": "fake-stego", "version": "test", "format_version": crate::transport::pipeline::TRANSPORT_FORMAT_VERSION,
                  "segmentation_version": manifest::SEG_VERSION_NAME, "selector_version": manifest::SEL_VERSION_NAME, "kb_version": "fake-kb",
                  "algorithms": ALGS.iter().enumerate().map(|(i,a)| json!({"id": i+1, "name": a})).collect::<Vec<_>>(),
                  "cover_generator": {"generator_version": "fake-gen", "quality_version": "fake-quality", "active_profile": "raspberry_pi_5_cpu",
                                      "families": ["terrain", "clouds", "strata", "cells"], "seeding": "os-random", "pretrained_models": false, "network": false}}))
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
        // same request contract as the real service: a new transmission carries `cover_generation`
        // (fresh cover), a re-plan carries `replan_cover_id` (stored cover, NO generation)
        let obj = req.as_object().cloned().unwrap_or_default();
        if let Some(k) = obj.keys().find(|k| !["payload_bytes", "cover_generation", "replan_cover_id", "limits", "segmentation", "min_level", "target_chunk_bytes", "carrier", "policy"].contains(&k.as_str())) {
            return Err(StegoError::new("INVALID_REQUEST", "plan", 400, format!("unknown or removed field '{k}'")));
        }
        let gen_cfg = req["cover_generation"].clone();
        let (cover_id, generated_now) = match req["replan_cover_id"].as_str() {
            Some(id) => {
                if !is_artifact_id(id) || !self.dir.join(format!("{id}.cover.png")).exists() || !gen_cfg.is_null() {
                    return Err(StegoError::new("INVALID_REQUEST", "plan", 400, "re-plan needs the stored generated cover of this transmission"));
                }
                (id.to_string(), false)
            }
            None => {
                if !gen_cfg.is_object() {
                    return Err(StegoError::new("GENERATOR_CONFIG_INVALID", "plan", 400, "cover_generation must be an object"));
                }
                self.note("generate");
                (rand_id(&self.counter), true)
            }
        };
        let cover_path = self.dir.join(format!("{cover_id}.cover.png"));
        if generated_now {
            std::fs::write(&cover_path, format!("FAKECOVER{cover_id}{:032x}", rand::random::<u128>())).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "plan", 500, e.to_string()))?;
        }
        let cover_bytes = std::fs::read(&cover_path).unwrap_or_default();
        for kind in ["seg", "labels"] {
            let _ = std::fs::write(self.dir.join(format!("{cover_id}.{kind}.png")), b"FAKEINSPECT");
        }
        let algs: &[(u8, u8)] = if level == 0 { &FAKE_ALGS } else { &FAKE_ALGS[..2] };
        if req["carrier"]["version"].as_u64() != Some(3) || req["carrier"]["values_b64"].as_str().map(|v| v.is_empty()).unwrap_or(true) {
            return Err(StegoError::new("INVALID_REQUEST", "plan", 400, "plan needs the bootstrap-v3 value stream"));
        }
        let man = manifest::sample(FAKE_W, FAKE_H, FAKE_CH, payload as u32, algs);
        let bytes = self.manifest_override.lock().unwrap().clone().unwrap_or_else(|| man.encode());
        let deflated = miniz_oxide::deflate::compress_to_vec(&bytes, 9);
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
        let fp = &sha(&cover_bytes)[..16];
        let generation = if generated_now {
            json!({"generator_version": "fake-gen", "quality_version": "fake-quality", "profile": gen_cfg["profile"], "payload_bytes": payload,
                   "requested": {"width": gen_cfg["width"], "height": gen_cfg["height"]}, "actual": {"width": FAKE_W, "height": FAKE_H}, "resized": false, "mode": "RGB",
                   "family": "terrain", "seed_fingerprint": fp, "quality_score": 0.9, "selected": 0, "candidate_count": 1, "max_candidates": gen_cfg["max_candidates"],
                   "planner_invocations": 1, "seeding": "os-random", "config": gen_cfg,
                   "candidates": [{"index": 0, "round": 0, "family": "terrain", "width": FAKE_W, "height": FAKE_H, "mode": "RGB", "seed_fingerprint": fp, "generate_ms": 1.0,
                                   "prescreen_ms": 0.5, "plan_ms": 2.0, "quality_score": 0.9, "gates_passed": true, "rejection_reasons": [], "outcome": "selected",
                                   "capacity_bytes": cap, "planned": true}],
                   "timings_ms": {"generate": 1.0, "prescreen": 0.5, "plan": 2.0, "total": 3.5},
                   "budget": {"limit_ms": gen_cfg["processing_budget_ms"], "used_ms": 3.5, "exceeded": false, "approached": false, "stopped_early": false}})
        } else {
            json!({"reused_for_replan": true, "generator_version": "fake-gen", "profile": "raspberry_pi_5_cpu", "family": "terrain", "seed_fingerprint": fp,
                   "quality_score": 0.9, "candidate_count": 0, "candidates": [], "note": "re-plan on the stored cover of this transmission; nothing was generated"})
        };
        Ok(json!({"ok": true, "format_version": crate::transport::pipeline::TRANSPORT_FORMAT_VERSION, "manifest_b64": b64::encode(&bytes), "manifest_deflate_b64": b64::encode(&deflated), "manifest_sha256": sha(&bytes),
            "plan": {"selector_version": manifest::SEL_VERSION_NAME, "kb_version": "fake-kb",
                     "segmentation": {"version": manifest::SEG_VERSION_NAME, "level": level, "regions": man.patches.len(), "cell_size": 8, "settings": req["segmentation"]},
                     "refinement_level": level, "attempts": [{"level": level, "regions": man.patches.len(), "outcome": "OK"}], "payload_bytes": payload,
                     "manifest_bytes": bytes.len(), "carrier_pixels": man.carrier_pixels, "patch_count": man.patches.len(), "used_patches": algs.len(),
                     "algorithms_used": counts, "target_chunk_bytes": req["target_chunk_bytes"], "patches": patches, "plan_ms": 1.0},
            "cover": {"artifact_id": cover_id, "source": "generated", "width": FAKE_W, "height": FAKE_H, "mode": "RGB", "channels": FAKE_CH, "sha256": sha(&cover_bytes),
                      "generator_version": "fake-gen", "profile": "raspberry_pi_5_cpu", "family": "terrain", "seed_fingerprint": fp, "quality_score": 0.9},
            "generation": generation,
            "inspection": {"segmentation_overlay": format!("{cover_id}.seg.png"), "label_map": format!("{cover_id}.labels.png"), "palette": [[1, 2, 3]]},
            "timings_ms": if generated_now { json!({"generate": 1.0, "prescreen": 0.5, "plan": 2.0, "selection_total": 3.5, "save": 0.5}) }
                          else { json!({"generate": 0.0, "prescreen": 0.0, "plan": 2.0, "selection_total": 2.0, "save": 0.5}) }}))
    }
    fn encode(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("encode");
        self.encode_requests.lock().unwrap().push(req.clone());
        if let Some(k) = req.as_object().and_then(|o| o.keys().find(|k| !["frame_b64", "cover_id", "limits", "carrier"].contains(&k.as_str())).cloned()) {
            return Err(StegoError::new("INVALID_REQUEST", "embed", 400, format!("unknown or removed field '{k}'")));
        }
        {
            let mut n = self.fail_encode_times.lock().unwrap();
            if *n > 0 {
                *n -= 1;
                return Err(StegoError::new("PATCH_EMBED_FAILED", "embed", 422, "patch failed immediate re-extraction").with_details(json!({"patch": 1, "algorithm": "lsb_matching"})));
            }
        }
        let frame = b64::decode(req["frame_b64"].as_str().unwrap_or(""), 1 << 22).map_err(|e| StegoError::new("INVALID_REQUEST", "embed", 400, e))?;
        // structural split only (as the real service: no key, no MAC check)
        if frame.len() < 16 + 32 + 1 || &frame[..4] != b"IOD3" {
            return Err(StegoError::new("FRAME_MALFORMED", "embed", 422, "not a v3 frame"));
        }
        let mlen = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
        let man = manifest::parse(frame.get(16..16 + mlen).unwrap_or(&[]), 4096)?;
        let cover_id = req["cover_id"].as_str().unwrap_or("").to_string();
        if !is_artifact_id(&cover_id) || !self.dir.join(format!("{cover_id}.cover.png")).exists() {
            return Err(StegoError::new("INVALID_REQUEST", "embed", 400, "encode needs the stored generated cover that was planned"));
        }
        let c = &req["carrier"];
        let values = b64::decode(c["values_b64"].as_str().unwrap_or(""), 1 << 20).map_err(|e| StegoError::new("INVALID_REQUEST", "embed", 400, e))?;
        let bits = b64::decode(c["bits_b64"].as_str().unwrap_or(""), 1 << 20).map_err(|e| StegoError::new("INVALID_REQUEST", "embed", 400, e))?;
        if values.is_empty() || values.len() % 4 != 0 || c["n_bits"].as_u64() != Some(8 * bits.len() as u64) || bits.len() < 12 {
            return Err(StegoError::new("INVALID_REQUEST", "embed", 400, "carrier needs values, bits and a matching bit count"));
        }
        if (8 * bits.len()).div_ceil(FAKE_CH as usize) > man.carrier_pixels as usize {
            return Err(StegoError::new("INVALID_REQUEST", "embed", 400, "carrier larger than the reserved carrier pixels"));
        }
        let id = rand_id(&self.counter);
        let file = build_fake(&bits, &values, &frame[16 + mlen..]);
        std::fs::write(self.stego_path(&id), &file).map_err(|e| StegoError::new("IMAGE_WRITE_FAILED", "save", 500, e.to_string()))?;
        let _ = std::fs::write(self.dir.join(format!("{id}.diff.png")), b"FAKEINSPECT");
        let per: Vec<Value> = man.patches.iter().enumerate().map(|(i, p)| if p.alg_id == 0 { json!({"patch_id": i, "used": false}) } else {
            json!({"patch_id": i, "used": true, "algorithm": ALGS[p.alg_id as usize - 1], "alg_id": p.alg_id, "param": p.param, "payload_offset": p.offset,
                   "payload_length": p.length, "capacity_bytes": 1000, "changed_samples": 10, "patch_mse": 0.5, "extraction": "verified_from_saved_png"})
        }).collect();
        Ok(json!({"ok": true, "artifact_id": id, "format_version": crate::transport::pipeline::TRANSPORT_FORMAT_VERSION,
            "stego": {"path_name": format!("{id}.png"), "sha256": sha(&file), "size": file.len(), "width": FAKE_W, "height": FAKE_H, "mode": "RGB", "channels": FAKE_CH, "format": "PNG"},
            "cover": {"artifact_id": cover_id, "source": "generated", "width": FAKE_W, "height": FAKE_H, "mode": "RGB", "channels": FAKE_CH},
            "embed": {"frame_len": frame.len(), "manifest_len": mlen, "payload_len": man.payload_len, "patch_count": man.patches.len(), "used_patches": man.used().count(),
                      "carrier_pixels": man.carrier_pixels, "carrier_bits": 8 * bits.len(), "carrier_changed_samples": 4 * bits.len(),
                      "patches": per, "exact_frame_recovery_from_saved_png": true,
                      "metrics": {"mse": 0.25, "psnr": 54.2, "ssim": 0.9995, "changed_samples": 10, "changed_fraction": 0.001, "max_abs_diff": 1}},
            "timings_ms": {"load_cover": 0.2, "embed": 1.5, "verify": 0.5, "save": 0.7}}))
    }
    fn carrier_probe(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("probe");
        let (data, sha_hex) = self.read_fake(req)?;
        let (carrier, values, _) = split_fake(&data).ok_or_else(|| StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"))?;
        let nbytes = req["locator_bits"].as_u64().unwrap_or(96) as usize / 8;
        let mut probes = Vec::new();
        for c in req["candidates"].as_array().cloned().unwrap_or_default() {
            let v = b64::decode(c["values_b64"].as_str().unwrap_or(""), 1 << 16).map_err(|e| StegoError::new("INVALID_REQUEST", "read", 400, e))?;
            let bits = if !v.is_empty() && values.starts_with(&v) && carrier.len() >= nbytes { carrier[..nbytes].to_vec() } else { noise(&v, &sha_hex, nbytes) };
            probes.push(json!({"id": c["id"], "bits_b64": b64::encode(&bits)}));
        }
        Ok(json!({"ok": true, "probes": probes, "legacy_bootstrap_v2": false, "image": self.image_json(&data, &sha_hex)}))
    }
    fn carrier_read(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("carrier_read");
        let (data, sha_hex) = self.read_fake(req)?;
        let (carrier, values, _) = split_fake(&data).ok_or_else(|| StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"))?;
        let v = b64::decode(req["values_b64"].as_str().unwrap_or(""), 1 << 20).map_err(|e| StegoError::new("INVALID_REQUEST", "read", 400, e))?;
        let (skip, n) = (req["skip_bits"].as_u64().unwrap_or(0) as usize, req["n_bits"].as_u64().unwrap_or(0) as usize);
        if skip % 8 != 0 || n % 8 != 0 {
            return Err(StegoError::new("INVALID_REQUEST", "read", 400, "fake reads whole bytes only"));
        }
        let bits = if v == values && carrier.len() >= (skip + n) / 8 { carrier[skip / 8..(skip + n) / 8].to_vec() } else { noise(&v, &sha_hex, n / 8) };
        Ok(json!({"ok": true, "bits_b64": b64::encode(&bits), "image": self.image_json(&data, &sha_hex)}))
    }
    fn extract(&self, req: &Value) -> Result<Value, StegoError> {
        self.note("extract");
        let (data, sha_hex) = self.read_fake(req)?;
        let (_, _, payload) = split_fake(&data).ok_or_else(|| StegoError::new("IMAGE_DECODE_ERROR", "read", 422, "not a decodable image"))?;
        let mb = b64::decode(req["manifest_b64"].as_str().unwrap_or(""), manifest::MAX_MANIFEST_BYTES).map_err(|e| StegoError::new("INVALID_REQUEST", "extract", 400, e))?;
        let per: Vec<Value> = if *self.lenient_extract.lock().unwrap() {
            vec![]
        } else {
            // like the real service: the manifest must parse before any chunk is read
            let man = manifest::parse(&mb, 4096)?;
            if man.payload_len as usize != payload.len() {
                return Err(StegoError::new("EXTRACT_FAILED", "extract", 422, "manifest payload length does not fit the image"));
            }
            man.used().map(|(i, p)| json!({"patch_id": i, "algorithm": ALGS[p.alg_id as usize - 1], "alg_id": p.alg_id, "param": p.param,
                "payload_offset": p.offset, "payload_length": p.length, "status": "extracted"})).collect()
        };
        let wire_len = payload.len().saturating_sub(32);
        let mut frame = b"IOD3\x03\x00\x00\x00".to_vec();
        frame.extend_from_slice(&(mb.len() as u32).to_be_bytes());
        frame.extend_from_slice(&(wire_len as u32).to_be_bytes());
        frame.extend_from_slice(&mb);
        frame.extend_from_slice(payload);
        Ok(json!({"ok": true, "frame_b64": b64::encode(&frame), "format_version": crate::transport::pipeline::TRANSPORT_FORMAT_VERSION,
            "patches": per, "resegmented": false, "image": self.image_json(&data, &sha_hex), "timings_ms": {"read": 0.4, "extract": 0.6}}))
    }
    fn kb(&self) -> Result<Value, StegoError> {
        Ok(json!({"ok": true, "kb_version": "fake-kb", "selector": {"version": manifest::SEL_VERSION_NAME}, "entries": [], "references": [], "query_terms": []}))
    }
}
