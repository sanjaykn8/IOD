//! End-to-end patch-wise image-transport transactions (docs/patchwise-transport.md).
//!
//! seal (Rust) -> plan: FRESH payload-aware generated cover + adaptive segmentation + per-patch
//! knowledge-base selection + chunk allocation (Python; receives only the payload LENGTH and the
//! validated cover-generation configuration) -> manifest validation +
//! Frame v2 + MAC over manifest and payload (Rust) -> patch embedding + PNG save + re-read
//! (Python) -> [handoff by artifact id] -> local read -> extraction from the image's own
//! bootstrap + manifest, no re-segmentation (Python) -> frame MAC, strict manifest parse,
//! AppWire, channel/direction/replay, AEAD (Rust).
//!
//! One cover is generated per transmission. A bounded internal re-plan reuses that same stored
//! cover (no generation); the receiver never generates or re-segments anything.
//!
//! No LLM, no explanation stage, no message priority, no single-algorithm or plaintext fallback,
//! no camera, no uploaded or client-selected cover.
//!
//! The global state mutex is never held across a backend call.
//! Everything fails closed with a stable error code and a persisted event.

use crate::api::state::SimulationState;
use crate::crypto::aead::AeadKey;
use crate::protocol::entities::SessionState;
use crate::protocol::secure_messaging::{self, SecureMessagingError};
use crate::transport::backend::{is_artifact_id, StegoBackend};
use crate::transport::config::StegoConfig;
use crate::transport::error::{stage, StegoError};
use crate::transport::frame;
use crate::transport::manifest::{self, Manifest};
use crate::transport::wire;
use crate::transport::b64;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const TRANSPORT_FORMAT_VERSION: &str = "frame-v2/appwire-v1/bootstrap-v2/manifest-v1";
const MAX_ARTIFACT_FILE: u64 = 64 * 1024 * 1024;

pub struct TxFailure {
    pub error: StegoError,
    pub event_id: i64,
    pub stages: Vec<Value>,
}

impl TxFailure {
    pub fn to_json(&self) -> Value {
        json!({"ok": false, "event_id": self.event_id, "error": self.error.to_json(), "stages": self.stages})
    }
}

pub struct MessageRequest {
    pub session_id: String,
    pub from_id: String,
    pub plaintext: Vec<u8>,
    /// The request's `cover_generation` object (or Null for the process defaults). Validated and
    /// tightened against the process configuration before anything else happens.
    pub cover_generation: Value,
    pub origin: &'static str,
}

// ---------------------------------------------------------------- tx ---

struct Tx {
    ev: Map<String, Value>,
    stages: Vec<Value>,
    timings: Map<String, Value>,
    t0: Instant,
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

impl Tx {
    fn new(kind: &'static str, session_id: &str, origin: &str) -> Self {
        let mut ev = Map::new();
        ev.insert("kind".into(), json!(kind));
        ev.insert("origin".into(), json!(origin));
        ev.insert("session_id".into(), json!(session_id));
        ev.insert("transport_format_version".into(), json!(TRANSPORT_FORMAT_VERSION));
        Tx { ev, stages: vec![], timings: Map::new(), t0: Instant::now() }
    }
    fn ms(&self, t: Instant) -> f64 {
        r3(t.elapsed().as_secs_f64() * 1000.0)
    }
    fn timing(&mut self, key: &str, ms: f64) {
        self.timings.insert(key.to_string(), json!(r3(ms)));
    }
    fn ok(&mut self, name: &str, ms: f64, detail: impl Into<String>) {
        self.stages.push(json!({"name": name, "status": "ok", "ms": r3(ms), "detail": detail.into()}));
    }
    fn fail(&mut self, name: &str, ms: f64, e: &StegoError) {
        self.stages.push(json!({"name": name, "status": "failed", "ms": r3(ms), "detail": e.code}));
    }
    fn set(&mut self, k: &str, v: Value) {
        self.ev.insert(k.to_string(), v);
    }
}

fn restage(mut e: StegoError, st: &'static str) -> StegoError {
    e.stage = st;
    e
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn need_str<'a>(v: &'a Value, k: &str, st: &'static str) -> Result<&'a str, StegoError> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| StegoError::new("BACKEND_MALFORMED_RESPONSE", st, 502, format!("backend response missing '{k}'")))
}

fn now_ms() -> i64 {
    crate::protocol::events::now_unix_ms() as i64
}

// --------------------------------------------------------- send half ---

struct Sent {
    artifact_id: String,
    direction: u8,
    seq: u32,
    from_role: &'static str,
    to_role: &'static str,
    plan: Value,
    inspection: Value,
    manifest: Value,
    cover: Value,
    generation: Value,
    stego: Value,
    embed: Value,
    frame_sha: String,
    frame_len: usize,
    wire_len: usize,
    manifest_len: usize,
    file_sha: String,
    file_size: u64,
}

struct Handles {
    backend: Arc<dyn StegoBackend>,
    cfg: StegoConfig,
}

fn handles(state: &Mutex<SimulationState>) -> Handles {
    let s = state.lock().unwrap();
    Handles { backend: s.backend.clone(), cfg: s.stego_cfg.clone() }
}

fn read_artifact_file(cfg: &StegoConfig, id: &str, kind_suffix: &str, st: &'static str) -> Result<Vec<u8>, StegoError> {
    if !is_artifact_id(id) {
        return Err(StegoError::new("INVALID_ARTIFACT_ID", st, 400, "artifact id must be 32 lowercase hex characters"));
    }
    let path = std::path::Path::new(&cfg.artifact_dir).join(format!("{id}{kind_suffix}"));
    let md = std::fs::metadata(&path).map_err(|_| StegoError::new("ARTIFACT_NOT_FOUND", st, 404, "saved image not found in the artifact directory"))?;
    if !md.is_file() || md.len() > MAX_ARTIFACT_FILE {
        return Err(StegoError::new("ARTIFACT_NOT_FOUND", st, 404, "artifact is not a readable file within limits"));
    }
    std::fs::read(&path).map_err(|_| StegoError::new("ARTIFACT_NOT_FOUND", st, 404, "saved image could not be read"))
}

/// Raw PNG bytes for the dashboard (id validated, fixed suffixes only).
pub fn artifact_png(cfg: &StegoConfig, id: &str, kind: &str) -> Result<Vec<u8>, StegoError> {
    let suffix = match kind {
        "stego" => ".png",
        "cover" => ".cover.png",
        "seg" => ".seg.png",
        "labels" => ".labels.png",
        "diff" => ".diff.png",
        _ => return Err(StegoError::new("INVALID_REQUEST", stage::READ, 400, "kind must be stego, cover, seg, labels or diff")),
    };
    read_artifact_file(cfg, id, suffix, stage::READ)
}

fn malformed(st: &'static str, msg: &str) -> StegoError {
    StegoError::new("BACKEND_MALFORMED_RESPONSE", st, 502, msg)
}

/// Where the cover of a plan request comes from. There is no third option.
enum PlanCover<'a> {
    /// New transmission: generate a fresh cover under this (already validated) configuration.
    Generate(&'a Value),
    /// Internal re-plan: the stored cover generated for THIS transmission; nothing is generated.
    Reuse(&'a str),
}

/// What the plan request may contain: the payload LENGTH and generation/segmentation parameters --
/// never payload bytes, keys, a seed, an image or a client-chosen artifact.
fn plan_request(h: &Handles, payload_bytes: usize, cover: PlanCover, min_level: u32) -> Value {
    let mut r = json!({"payload_bytes": payload_bytes, "limits": h.cfg.limits(), "segmentation": h.cfg.segmentation,
                       "min_level": min_level, "target_chunk_bytes": h.cfg.target_chunk_bytes});
    match cover {
        PlanCover::Generate(cfg) => r["cover_generation"] = cfg.clone(),
        PlanCover::Reuse(id) => r["replan_cover_id"] = json!(id),
    }
    r
}

/// Compact, secret-free record of the generation step for the persisted event.
fn compact_generation(g: &Value) -> Value {
    let cands: Vec<Value> = g["candidates"].as_array().map(|a| a.iter().map(|c| json!({
        "index": c["index"], "round": c["round"], "family": c["family"], "width": c["width"], "height": c["height"],
        "seed_fingerprint": c["seed_fingerprint"], "quality_score": c["quality_score"], "gates_passed": c["gates_passed"],
        "rejection_reasons": c["rejection_reasons"], "outcome": c["outcome"], "capacity_bytes": c["capacity_bytes"],
        "generate_ms": c["generate_ms"], "prescreen_ms": c["prescreen_ms"], "plan_ms": c["plan_ms"],
    })).collect()).unwrap_or_default();
    json!({"generator_version": g["generator_version"], "quality_version": g["quality_version"], "profile": g["profile"], "config": g["config"],
           "requested": g["requested"], "actual": g["actual"], "resized": g["resized"], "family": g["family"], "params": g["params"],
           "seed_fingerprint": g["seed_fingerprint"], "quality_score": g["quality_score"], "candidate_count": g["candidate_count"],
           "planner_invocations": g["planner_invocations"], "candidates": cands, "timings_ms": g["timings_ms"], "budget": g["budget"],
           "embedding_rate": g["embedding_rate"], "memory": g["memory"], "seeding": g["seeding"]})
}

struct Planned {
    manifest_bytes: Vec<u8>,
    manifest: Manifest,
    plan: Value,
    cover: Value,
    generation: Value,
    inspection: Value,
    timings: Value,
    level: u32,
}

/// Decode and independently validate what the image service planned. The manifest is not trusted:
/// it must parse strictly, describe exactly this payload and this cover, and agree with the diagnostics.
fn accept_plan(h: &Handles, resp: &Value, payload_bytes: usize) -> Result<Planned, StegoError> {
    let mb = b64::decode(need_str(resp, "manifest_b64", stage::PLAN)?, manifest::MAX_MANIFEST_BYTES).map_err(|m| malformed(stage::PLAN, &m))?;
    let man = manifest::parse(&mb, h.cfg.max_width.max(h.cfg.max_height)).map_err(|e| restage(e, stage::PLAN))?;
    let cover = resp.get("cover").cloned().unwrap_or(Value::Null);
    let plan = resp.get("plan").cloned().unwrap_or(Value::Null);
    if man.payload_len as usize != payload_bytes {
        return Err(StegoError::new("MANIFEST_INVALID", stage::PLAN, 422, "planned manifest does not cover the sealed payload length"));
    }
    if man.width as u32 > h.cfg.max_width || man.height as u32 > h.cfg.max_height {
        return Err(StegoError::new("MANIFEST_INVALID", stage::PLAN, 422, "planned image exceeds the configured dimensions"));
    }
    if cover["width"].as_u64() != Some(man.width as u64) || cover["height"].as_u64() != Some(man.height as u64) || cover["channels"].as_u64() != Some(man.channels as u64) {
        return Err(StegoError::new("MANIFEST_INVALID", stage::PLAN, 422, "manifest geometry differs from the reported cover"));
    }
    let cover_id = need_str(&cover, "artifact_id", stage::PLAN)?;
    if !is_artifact_id(cover_id) {
        return Err(malformed(stage::PLAN, "cover artifact id malformed"));
    }
    // the only operational cover is one the image service generated itself
    if cover["source"].as_str() != Some("generated") {
        return Err(malformed(stage::PLAN, "cover was not produced by the local generator"));
    }
    if (man.width as u32) > h.cfg.generator.max_width || (man.height as u32) > h.cfg.generator.max_height
        || (man.width as u64) * (man.height as u64) > h.cfg.generator.max_pixels
    {
        return Err(StegoError::new("MANIFEST_INVALID", stage::PLAN, 422, "generated cover exceeds the configured generator ceilings"));
    }
    if plan["patch_count"].as_u64() != Some(man.patches.len() as u64) || plan["used_patches"].as_u64() != Some(man.used().count() as u64) {
        return Err(malformed(stage::PLAN, "plan diagnostics disagree with the manifest"));
    }
    let level = plan["refinement_level"].as_u64().filter(|l| *l <= 6).ok_or_else(|| malformed(stage::PLAN, "refinement level missing"))? as u32;
    Ok(Planned { manifest_bytes: mb, manifest: man, plan, cover, generation: resp.get("generation").cloned().unwrap_or(Value::Null), inspection: resp.get("inspection").cloned().unwrap_or(Value::Null),
                 timings: resp.get("timings_ms").cloned().unwrap_or(json!({})), level })
}

/// Per-patch record kept in the persisted event (the full diagnostics go to the API response only).
fn compact_patches(plan: &Value) -> Value {
    let rows: Vec<Value> = plan["patches"].as_array().map(|a| a.iter().map(|p| {
        let r = &p["retrieval"];
        let top = r["candidates"].as_array().and_then(|c| c.iter().find(|c| c["algorithm"] == p["selected"]));
        json!({
            "patch_id": p["patch_id"], "used": p["used"], "pixels": p["features"]["pixels"], "usable_pixels": p["features"]["usable_pixels"],
            "gradient_mean": p["features"]["gradient_mean"], "variance": p["features"]["variance"], "entropy": p["features"]["entropy"],
            "algorithm": p["selected"], "alg_id": p["alg_id"], "param": p["param"],
            "payload_offset": p["payload_offset"], "payload_length": p["payload_length"],
            "capacity_bytes": p["measured_capacity_bytes"], "kb_entry": top.map(|c| c["kb_entry"].clone()).unwrap_or(Value::Null),
            "bm25": top.map(|c| c["bm25"].clone()).unwrap_or(Value::Null), "query_terms": r["query_terms"], "ranking": r["ranking"],
        })
    }).collect()).unwrap_or_default();
    Value::Array(rows)
}

fn algorithms_json(man: &Manifest) -> (Value, Option<&'static str>) {
    let used = man.algorithms_used();
    let dominant = used.iter().max_by(|a, b| a.2.cmp(&b.2).then(b.0.cmp(a.0))).map(|a| a.0);
    let mut m = Map::new();
    for (name, patches, bytes) in &used {
        m.insert(name.to_string(), json!({"patches": patches, "payload_bytes": bytes}));
    }
    (Value::Object(m), dominant)
}

fn do_send(state: &Mutex<SimulationState>, h: &Handles, tx: &mut Tx, req: &MessageRequest) -> Result<Sent, StegoError> {
    // ---- cover-generation configuration: validated before a sequence number is reserved
    let gen_cfg = match h.cfg.generator.resolve(Some(&req.cover_generation)) {
        Ok(c) => c,
        Err(e) => {
            tx.fail("prepare", 0.0, &e);
            return Err(e);
        }
    };
    let gen_json = gen_cfg.to_json();
    tx.set("generator_profile", json!(gen_cfg.profile));
    tx.set("generation_config", gen_json.clone());
    // ---- phase 1 (locked, short): validate session/keys, reserve sequence number.
    let (direction, seq, from_role, to_role, key, tag) = {
        let mut s = state.lock().unwrap();
        let sid = req.session_id.as_str();
        if !s.channels.contains_key(sid) {
            return Err(StegoError::new("NO_GROUP_KEY", stage::PREPARE, 409, "no group key established for this session (run K1-K3 first)"));
        }
        let (d1_id, d2_id, state_ok) = {
            let sess = s.gcs.sessions.get(sid).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "unknown session"))?;
            (sess.d1_id.clone(), sess.d2_id.clone(), sess.state == SessionState::KeyIssued)
        };
        if !state_ok {
            return Err(StegoError::new("SESSION_NOT_ACTIVE", stage::PREPARE, 409, "session is not in the key-issued state (failed, revoked or incomplete)"));
        }
        for id in [&d1_id, &d2_id] {
            if !s.gcs.drones.get(id).map(|d| d.active).unwrap_or(false) {
                return Err(StegoError::new("MEMBER_REVOKED", stage::PREPARE, 403, "a session participant is no longer an active member"));
            }
        }
        let direction: u8 = if req.from_id == d1_id {
            1
        } else if req.from_id == d2_id {
            2
        } else {
            return Err(StegoError::new("NOT_PARTICIPANT", stage::PREPARE, 403, "sender is not a participant of this session"));
        };
        let ch = s.channels.get(sid).unwrap();
        let (kb, tag) = if direction == 1 { (ch.d1_keys.d1_to_d2.0, ch.d1_keys.channel_tag) } else { (ch.d2_keys.d2_to_d1.0, ch.d1_keys.channel_tag) };
        let c = s.message_seq.entry((sid.to_string(), direction)).or_insert(0);
        *c += 1;
        let seq = *c;
        let (fr, to) = if direction == 1 { ("D1", "D2") } else { ("D2", "D1") };
        (direction, seq, fr, to, AeadKey(kb), tag)
    };
    tx.set("direction", json!(direction));
    tx.set("seq", json!(seq));
    tx.set("from_role", json!(from_role));
    tx.set("to_role", json!(to_role));

    // ---- seal (Rust only)
    let t = Instant::now();
    let msg = secure_messaging::seal_message(&key, tag, direction, seq, &req.plaintext);
    let wire_bytes = wire::encode_app_wire(&msg);
    let meta = frame::derive_meta_key(&key, &tag, direction);
    let payload_bytes = frame::payload_section_len(wire_bytes.len());
    let min_frame = frame::frame_len_for(manifest::FIXED_LEN + manifest::ENTRY_LEN + 2, wire_bytes.len());
    let ms = tx.ms(t);
    tx.timing("aead_seal", ms);
    tx.set("wire_bytes", json!(wire_bytes.len()));
    tx.set("payload_bytes", json!(payload_bytes));
    if min_frame > h.cfg.max_frame_bytes {
        let e = StegoError::new("FRAME_TOO_LARGE", stage::AEAD_SEAL, 413, format!("sealed message needs a frame of at least {min_frame} bytes, above the configured maximum of {} bytes", h.cfg.max_frame_bytes));
        tx.fail("aead_seal", ms, &e);
        return Err(e);
    }
    tx.ok("aead_seal", ms, format!("sealed; {payload_bytes} bytes (AppWire + frame tag) to distribute over patches"));

    // ---- plan -> validate -> frame + MAC -> embed, with a bounded re-plan at a coarser segmentation
    // Exactly one cover is generated per transmission (first plan). Every re-plan names that stored cover.
    let mut min_level: u32 = 0;
    let mut replans: Vec<Value> = Vec::new();
    let mut first: Option<(Value, Value, Value)> = None; // (cover, generation, timings) of the generating plan
    let mut planner_ms_total = 0.0f64;
    let (planned, frame_bytes, enc, plan_wall, embed_wall) = loop {
        let t = Instant::now();
        let first_id = first.as_ref().and_then(|f| f.0["artifact_id"].as_str()).map(str::to_string);
        let spec = match &first_id {
            None => PlanCover::Generate(&gen_json),
            Some(id) => PlanCover::Reuse(id),
        };
        let resp = h.backend.plan(&plan_request(h, payload_bytes, spec, min_level)).map_err(|e| restage(e, stage::PLAN));
        let planned = resp.and_then(|r| accept_plan(h, &r, payload_bytes)).and_then(|p| match &first {
            // a re-plan must come back on the very same cover artifact (same id, same pixels)
            Some((c, _, _)) if p.cover["artifact_id"] != c["artifact_id"] || p.cover["sha256"] != c["sha256"] => {
                Err(malformed(stage::PLAN, "re-plan did not reuse the cover generated for this transmission"))
            }
            _ => Ok(p),
        });
        let planned = match planned {
            Ok(p) => p,
            Err(e) => {
                let ms = tx.ms(t);
                tx.fail("plan", ms, &e);
                if let Some(d) = e.details.as_ref() {
                    if let Some(a) = d.get("attempts") {
                        tx.set("plan_attempts", a.clone());
                    }
                    if d.get("candidates").is_some() {
                        // structured generation failure: which candidates were tried and why each was rejected
                        tx.set("generation", compact_generation(d));
                        tx.set("generation_failure_reason", d["reason"].clone());
                    }
                }
                tx.set("replans", json!(replans));
                return Err(e);
            }
        };
        let plan_wall = tx.ms(t);
        planner_ms_total += planned.timings["plan"].as_f64().unwrap_or(0.0);
        if first.is_none() {
            first = Some((planned.cover.clone(), planned.generation.clone(), planned.timings.clone()));
        }
        // Frame v2: header | manifest | AppWire | HMAC (the tag covers the manifest and the payload)
        let frame_bytes = match frame::build_frame(&meta, &planned.manifest_bytes, &wire_bytes, h.cfg.max_frame_bytes) {
            Ok(f) => f,
            Err(e) => {
                tx.fail("plan", plan_wall, &e);
                return Err(e);
            }
        };
        let cover_id = planned.cover["artifact_id"].as_str().unwrap_or("").to_string();
        let t = Instant::now();
        // encode loads the stored cover by id; it never generates
        let ereq = json!({"frame_b64": b64::encode(&frame_bytes), "cover_id": cover_id, "limits": h.cfg.limits()});
        match h.backend.encode(&ereq).map_err(|e| restage(e, stage::EMBED)) {
            Ok(enc) => break (planned, frame_bytes, enc, plan_wall, tx.ms(t)),
            Err(e) if e.code == "PATCH_EMBED_FAILED" && (replans.len() as u32) < h.cfg.max_replans => {
                // A patch could not carry its chunk with the selected algorithm. There is no fallback to
                // another algorithm and no new cover: the SAME cover is re-planned with a coarser segmentation (bounded).
                replans.push(json!({"level": planned.level, "error_code": e.code, "details": e.details, "patches": planned.manifest.patches.len(), "cover_id": cover_id}));
                min_level = planned.level + 1;
                continue;
            }
            Err(e) => {
                let ms = tx.ms(t);
                tx.ok("plan", plan_wall, format!("{} patches planned at level {}", planned.manifest.patches.len(), planned.level));
                tx.fail("embed", ms, &e);
                tx.set("replans", json!(replans));
                return Err(e);
            }
        }
    };
    let man = &planned.manifest;
    let (cover, generation, gen_timings) = first.unwrap_or((Value::Null, Value::Null, Value::Null));
    if enc["cover"]["artifact_id"] != cover["artifact_id"] {
        let e = malformed(stage::EMBED, "the image was not embedded into the cover generated for this transmission");
        tx.fail("embed", embed_wall, &e);
        return Err(e);
    }
    let (algs, dominant) = algorithms_json(man);
    // generation-stage timings come from the one plan that generated; planner time accumulates over re-plans
    tx.timing("cover_generate", gen_timings["generate"].as_f64().unwrap_or(0.0));
    tx.timing("cover_prescreen", gen_timings["prescreen"].as_f64().unwrap_or(0.0));
    tx.timing("cover_selection_total", gen_timings["selection_total"].as_f64().unwrap_or(0.0));
    tx.timing("plan", planner_ms_total);
    tx.set("generation", compact_generation(&generation));
    tx.set("generator_version", generation["generator_version"].clone());
    tx.set("cover_family", cover["family"].clone());
    tx.set("seed_fingerprint", cover["seed_fingerprint"].clone());
    tx.set("cover_quality_score", cover["quality_score"].clone());
    tx.set("generation_candidates", generation["candidate_count"].clone());
    tx.set("generation_budget_ms", generation["budget"]["limit_ms"].clone());
    tx.set("generation_used_ms", generation["budget"]["used_ms"].clone());
    tx.set("generation_budget_exceeded", generation["budget"]["exceeded"].clone());
    tx.set("requested_width", generation["requested"]["width"].clone());
    tx.set("requested_height", generation["requested"]["height"].clone());
    tx.set("cover_resized", generation["resized"].clone());
    tx.set("covers_generated", json!(1));
    tx.set("segmentation_version", planned.plan["segmentation"]["version"].clone());
    tx.set("selector_version", planned.plan["selector_version"].clone());
    tx.set("kb_version", planned.plan["kb_version"].clone());
    tx.set("refinement_level", json!(planned.level));
    tx.set("replans", json!(replans));
    tx.set("plan_attempts", planned.plan["attempts"].clone());
    tx.set("patch_count", json!(man.patches.len()));
    tx.set("used_patches", json!(man.used().count()));
    tx.set("reserved_rows", json!(man.reserved_rows));
    tx.set("manifest_bytes", json!(planned.manifest_bytes.len()));
    tx.set("algorithms_used", algs);
    tx.set("algorithm", json!(dominant));
    tx.set("patches", compact_patches(&planned.plan));
    tx.set("cover_source", cover["source"].clone());
    for k in ["width", "height", "mode", "channels"] {
        tx.set(k, cover[k].clone());
    }
    tx.set("cover_sha256", cover["sha256"].clone());
    tx.set("cover_artifact_id", cover["artifact_id"].clone());
    tx.ok("plan", plan_wall, format!("fresh {} cover {}x{} (quality {}); {} patches ({} used) at refinement level {}; manifest {} bytes validated",
        cover["family"].as_str().unwrap_or("generated"), man.width, man.height, cover["quality_score"], man.patches.len(), man.used().count(), planned.level, planned.manifest_bytes.len()));

    let frame_sha = sha_hex(&frame_bytes);
    tx.set("frame_bytes", json!(frame_bytes.len()));
    tx.set("frame_sha256_prefix", json!(&frame_sha[..16]));

    let artifact_id = need_str(&enc, "artifact_id", stage::EMBED)?.to_string();
    if !is_artifact_id(&artifact_id) {
        return Err(malformed(stage::EMBED, "artifact id malformed"));
    }
    let embed = enc.get("embed").cloned().unwrap_or(Value::Null);
    let stego = enc.get("stego").cloned().unwrap_or(Value::Null);
    if embed["frame_len"].as_u64() != Some(frame_bytes.len() as u64) || embed["used_patches"].as_u64() != Some(man.used().count() as u64)
        || embed["exact_frame_recovery_from_saved_png"].as_bool() != Some(true)
    {
        let e = malformed(stage::EMBED, "embed report disagrees with the requested frame or did not verify the saved image");
        tx.fail("embed", embed_wall, &e);
        return Err(e);
    }
    let etim = enc.get("timings_ms").cloned().unwrap_or(json!({}));
    tx.timing("load_cover", etim["load_cover"].as_f64().unwrap_or(0.0));
    tx.timing("embed", etim["embed"].as_f64().unwrap_or(0.0));
    tx.timing("embed_verify", etim["verify"].as_f64().unwrap_or(0.0));
    tx.ok("embed", embed_wall, format!("{} bytes embedded in {} patches; saved image re-read and verified", frame_bytes.len(), man.used().count()));

    // ---- Rust confirms the saved file exists, is readable, and matches the reported hash
    let t = Instant::now();
    let file = read_artifact_file(&h.cfg, &artifact_id, ".png", stage::SAVE).map_err(|e| {
        if e.code == "ARTIFACT_NOT_FOUND" { StegoError::new("ARTIFACT_NOT_VISIBLE", stage::SAVE, 500, "saved PNG is not visible to the Rust core (artifact directory not shared?)") } else { e }
    });
    let file = match file {
        Ok(f) => f,
        Err(e) => {
            let ms = tx.ms(t);
            tx.fail("save", ms, &e);
            return Err(e);
        }
    };
    let file_sha = sha_hex(&file);
    let ms = tx.ms(t);
    if Some(file_sha.as_str()) != stego["sha256"].as_str() {
        let e = StegoError::new("ARTIFACT_HASH_MISMATCH", stage::SAVE, 500, "saved PNG hash differs from the hash reported by the image service");
        tx.fail("save", ms, &e);
        return Err(e);
    }
    tx.timing("save", etim["save"].as_f64().unwrap_or(0.0) + ms);
    tx.ok("save", etim["save"].as_f64().unwrap_or(0.0) + ms, format!("{}.png ({} bytes)", artifact_id, file.len()));

    tx.set("artifact_id", json!(artifact_id));
    tx.set("stego_sha256", json!(file_sha));
    tx.set("image_bytes", json!(file.len()));
    tx.set("output_format", json!("PNG"));
    let m = &embed["metrics"];
    tx.set("mse", m["mse"].clone());
    tx.set("psnr", m["psnr"].clone());
    tx.set("ssim", m["ssim"].clone());
    tx.set("psnr_defined", json!(m["psnr"].is_number()));
    tx.set("ssim_defined", json!(m["ssim"].is_number()));
    tx.set("changed_fraction", m["changed_fraction"].clone());

    Ok(Sent { artifact_id, direction, seq, from_role, to_role, manifest: man.summary(), plan: planned.plan, inspection: planned.inspection, cover, generation, stego, embed,
              frame_sha, frame_len: frame_bytes.len(), wire_len: wire_bytes.len(), manifest_len: planned.manifest_bytes.len(), file_sha, file_size: file.len() as u64 })
}

// ------------------------------------------------------ receive half ---

struct Received {
    plaintext: Vec<u8>,
    direction: u8,
    seq: u32,
    from_role: &'static str,
    to_role: &'static str,
    image: Value,
    bootstrap: Value,
    manifest: Value,
    patches: Value,
    frame_sha: String,
}

fn do_receive(state: &Mutex<SimulationState>, h: &Handles, tx: &mut Tx, session_id: &str, recipient_id: &str, artifact_id: &str, sent_frame_sha: Option<&str>) -> Result<Received, StegoError> {
    // ---- phase 1 (locked, short): receiver identity + key copy
    let (expected_dir, key, tag, from_role, to_role) = {
        let s = state.lock().unwrap();
        if !s.channels.contains_key(session_id) {
            return Err(StegoError::new("NO_GROUP_KEY", stage::PREPARE, 409, "no group key established for this session"));
        }
        let sess = s.gcs.sessions.get(session_id).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "unknown session"))?;
        if sess.state != SessionState::KeyIssued {
            return Err(StegoError::new("SESSION_NOT_ACTIVE", stage::PREPARE, 409, "session is not in the key-issued state"));
        }
        for id in [&sess.d1_id, &sess.d2_id] {
            if !s.gcs.drones.get(id).map(|d| d.active).unwrap_or(false) {
                return Err(StegoError::new("MEMBER_REVOKED", stage::PREPARE, 403, "a session participant is no longer an active member"));
            }
        }
        let ch = s.channels.get(session_id).unwrap();
        // The receiver of D1->D2 traffic is D2 and vice versa.
        if recipient_id == sess.d2_id {
            (1u8, AeadKey(ch.d2_keys.d1_to_d2.0), ch.d2_keys.channel_tag, "D1", "D2")
        } else if recipient_id == sess.d1_id {
            (2u8, AeadKey(ch.d1_keys.d2_to_d1.0), ch.d1_keys.channel_tag, "D2", "D1")
        } else {
            return Err(StegoError::new("WRONG_RECIPIENT", stage::PREPARE, 403, "recipient is not a participant of this session"));
        }
    };
    tx.set("direction", json!(expected_dir));
    tx.set("from_role", json!(from_role));
    tx.set("to_role", json!(to_role));
    tx.set("artifact_id", json!(artifact_id));

    // ---- local read: the saved file is the ONLY receive input
    let t = Instant::now();
    let file = match read_artifact_file(&h.cfg, artifact_id, ".png", stage::READ) {
        Ok(f) => f,
        Err(e) => {
            let ms = tx.ms(t);
            tx.fail("read", ms, &e);
            return Err(e);
        }
    };
    let file_sha = sha_hex(&file);
    let ms = tx.ms(t);
    tx.timing("read", ms);
    tx.ok("read", ms, format!("{} bytes read from the artifact directory", file.len()));
    tx.set("image_bytes", json!(file.len()));
    tx.set("stego_sha256", json!(file_sha));
    tx.set("output_format", json!("PNG"));

    // ---- extraction (Python reads the same saved file by id; bootstrap + manifest come from the image)
    let t = Instant::now();
    let ex = h.backend.extract(artifact_id, &h.cfg.limits()).map_err(|e| restage(e, stage::EXTRACT));
    let ex = match ex {
        Ok(v) => v,
        Err(e) => {
            let ms = tx.ms(t);
            tx.fail("extract", ms, &e);
            return Err(e);
        }
    };
    let wall = tx.ms(t);
    let image = ex.get("image").cloned().unwrap_or(Value::Null);
    let bootstrap = ex.get("bootstrap").cloned().unwrap_or(Value::Null);
    tx.timing("extract", wall);
    let step = (|| -> Result<Vec<u8>, StegoError> {
        if image["sha256"].as_str() != Some(file_sha.as_str()) {
            return Err(StegoError::new("ARTIFACT_HASH_MISMATCH", stage::EXTRACT, 500, "the image service read different bytes than the Rust core"));
        }
        if ex["resegmented"].as_bool() != Some(false) {
            return Err(malformed(stage::EXTRACT, "the image service must extract from the embedded manifest without re-segmenting"));
        }
        b64::decode(need_str(&ex, "frame_b64", stage::EXTRACT)?, h.cfg.max_frame_bytes).map_err(|m| malformed(stage::EXTRACT, &m))
    })();
    let frame_bytes = match step {
        Ok(f) => f,
        Err(e) => {
            tx.fail("extract", wall, &e);
            return Err(e);
        }
    };
    tx.ok("extract", wall, format!("reconstructed a {}-byte frame from the image's bootstrap, manifest and patches (untrusted until verified)", frame_bytes.len()));
    for k in ["width", "height", "mode", "channels"] {
        tx.set(k, image[k].clone());
    }
    let frame_sha = sha_hex(&frame_bytes);
    tx.set("frame_sha256_prefix", json!(&frame_sha[..16]));
    tx.set("frame_bytes", json!(frame_bytes.len()));
    if let Some(sent) = sent_frame_sha {
        tx.set("frame_match", json!(sent == frame_sha));
    }

    // ---- frame MAC first, then strict manifest + AppWire parsing (Rust)
    let t = Instant::now();
    let meta = frame::derive_meta_key(&key, &tag, expected_dir);
    let verify = (|| -> Result<(wire::Parsed, Manifest), StegoError> {
        if bootstrap["frame_len"].as_u64() != Some(frame_bytes.len() as u64) {
            return Err(StegoError::new("FRAME_LENGTH_MISMATCH", stage::VERIFY, 422, "bootstrap frame length differs from the recovered frame"));
        }
        let (man_bytes, payload) = frame::parse_and_verify(&meta, &frame_bytes, h.cfg.max_frame_bytes)?;
        // authenticated from here on; still parsed strictly
        let man = manifest::parse(man_bytes, h.cfg.max_width.max(h.cfg.max_height))?;
        if man.payload_len as usize != frame::payload_section_len(payload.len()) {
            return Err(StegoError::new("MANIFEST_INVALID", stage::VERIFY, 422, "authenticated manifest does not match the frame payload length"));
        }
        if image["width"].as_u64() != Some(man.width as u64) || image["height"].as_u64() != Some(man.height as u64) || image["channels"].as_u64() != Some(man.channels as u64) {
            return Err(StegoError::new("MANIFEST_INVALID", stage::VERIFY, 422, "authenticated manifest geometry differs from the image that was read"));
        }
        let msg = wire::decode_app_wire(payload, h.cfg.max_frame_bytes)?;
        Ok((wire::Parsed { msg }, man))
    })();
    let ms = tx.ms(t);
    tx.timing("verify", ms);
    let (parsed, man) = match verify {
        Ok(p) => {
            tx.set("header_mac_ok", json!(true));
            tx.ok("verify_frame", ms, "frame MAC verified over manifest and payload; manifest parsed strictly");
            p
        }
        Err(e) => {
            tx.set("header_mac_ok", json!(false));
            tx.fail("verify_frame", ms, &e);
            return Err(e);
        }
    };
    let (algs, dominant) = algorithms_json(&man);
    if tx.ev.get("algorithm").map(|a| a.is_null()).unwrap_or(true) {
        tx.set("algorithm", json!(dominant));
        tx.set("algorithms_used", algs);
        tx.set("patch_count", json!(man.patches.len()));
        tx.set("used_patches", json!(man.used().count()));
        tx.set("manifest_bytes", json!(man.encode().len()));
    }

    // ---- channel/direction/replay + AEAD open (locked, commit last_seen)
    let t = Instant::now();
    let opened = {
        let mut s = state.lock().unwrap();
        let last = *s.recv_seen.get(&(session_id.to_string(), expected_dir)).unwrap_or(&0);
        match secure_messaging::receive_message(&key, tag, expected_dir, &parsed.msg, last) {
            Ok(pt) => {
                s.recv_seen.insert((session_id.to_string(), expected_dir), parsed.msg.header_seq);
                Ok(pt)
            }
            Err(e) => Err(e),
        }
    };
    let ms = tx.ms(t);
    tx.timing("aead_open", ms);
    let plaintext = match opened {
        Ok(p) => p,
        Err(e) => {
            let se = match e {
                SecureMessagingError::WrongChannel => StegoError::new("WRONG_CHANNEL", stage::AEAD_OPEN, 403, "message is not for this channel/direction"),
                SecureMessagingError::Aead(crate::crypto::aead::AeadError::ReplayedSequence { .. }) => StegoError::new("REPLAY", stage::AEAD_OPEN, 409, "replayed or out-of-order sequence number"),
                _ => StegoError::new("AEAD_FAILED", stage::AEAD_OPEN, 422, "AEAD authentication/decryption failed"),
            };
            tx.set("aead_ok", json!(false));
            tx.fail("aead_open", ms, &se);
            return Err(se);
        }
    };
    tx.set("aead_ok", json!(true));
    tx.set("seq", json!(parsed.msg.header_seq));
    tx.ok("aead_open", ms, "channel, direction, replay and AEAD checks passed");
    Ok(Received { plaintext, direction: expected_dir, seq: parsed.msg.header_seq, from_role, to_role, image, bootstrap,
                  manifest: man.summary(), patches: ex.get("patches").cloned().unwrap_or(json!([])), frame_sha })
}

// ----------------------------------------------------------- finish ---

fn persist_event(state: &Mutex<SimulationState>, tx: &mut Tx, success: bool, err: Option<&StegoError>) -> i64 {
    tx.timing("total", tx.t0.elapsed().as_secs_f64() * 1000.0);
    let mut ev = tx.ev.clone();
    ev.insert("ts_ms".into(), json!(now_ms()));
    if let Some(d) = ev.get("direction").and_then(|d| d.as_u64()) {
        ev.insert("direction_label".into(), json!(if d == 1 { "D1->D2" } else { "D2->D1" }));
    }
    ev.insert("success".into(), json!(success));
    ev.insert("timings_ms".into(), Value::Object(tx.timings.clone()));
    ev.insert("stages".into(), Value::Array(tx.stages.clone()));
    if let Some(e) = err {
        ev.insert("error_code".into(), json!(e.code));
        ev.insert("error_message".into(), json!(e.message));
        ev.insert("error_stage".into(), json!(e.stage));
    }
    let data = Value::Object(ev);
    let s = state.lock().unwrap();
    let id = s
        .db
        .append_stego_event(
            data["ts_ms"].as_i64().unwrap_or(0),
            data["session_id"].as_str().unwrap_or(""),
            data["direction"].as_i64(),
            data["algorithm"].as_str(),
            if success { "ok" } else { "failed" },
            &data,
        )
        .unwrap_or(-1);
    id
}

fn fail_out(state: &Mutex<SimulationState>, mut tx: Tx, e: StegoError) -> TxFailure {
    let id = persist_event(state, &mut tx, false, Some(&e));
    TxFailure { error: e, event_id: id, stages: tx.stages }
}

fn artifact_json(sent: &Sent) -> Value {
    let cid = sent.cover["artifact_id"].as_str().unwrap_or("");
    json!({
        "id": sent.artifact_id, "cover_id": cid, "stego_sha256": sent.file_sha, "size": sent.file_size,
        "preview_url": format!("/api/stego/artifacts/{}/stego", sent.artifact_id),
        "cover_preview_url": format!("/api/stego/artifacts/{cid}/cover"),
        "segmentation_overlay_url": format!("/api/stego/artifacts/{cid}/seg"),
        "label_map_url": format!("/api/stego/artifacts/{cid}/labels"),
        "difference_url": format!("/api/stego/artifacts/{}/diff", sent.artifact_id),
        "image": sent.stego,
        "width": sent.stego["width"], "height": sent.stego["height"], "mode": sent.stego["mode"],
        "channels": sent.stego["channels"], "format": sent.stego["format"],
    })
}

fn transport_json(sent: &Sent) -> Value {
    json!({"format_version": TRANSPORT_FORMAT_VERSION, "frame_bytes": sent.frame_len, "wire_bytes": sent.wire_len, "manifest_bytes": sent.manifest_len,
           "payload_section_bytes": sent.wire_len + frame::TAG_LEN, "mac": "HMAC-SHA256 over header | manifest | AppWire (Rust only)"})
}

// ----------------------------------------------------------- public ---

/// Full transaction: send -> save -> receive (from the saved file) -> verify.
pub fn run_message(state: &Mutex<SimulationState>, req: MessageRequest) -> Result<Value, TxFailure> {
    let h = handles(state);
    let mut tx = Tx::new("transaction", &req.session_id, req.origin);
    let sent = match do_send(state, &h, &mut tx, &req) {
        Ok(s) => s,
        Err(e) => return Err(fail_out(state, tx, e)),
    };
    let rcpt = {
        let s = state.lock().unwrap();
        s.gcs.sessions.get(&req.session_id).map(|x| if sent.direction == 1 { x.d2_id.clone() } else { x.d1_id.clone() })
    };
    let Some(rcpt) = rcpt else {
        return Err(fail_out(state, tx, StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "unknown session")));
    };
    // The receive half sees ONLY (session, recipient, artifact id).
    let rec = match do_receive(state, &h, &mut tx, &req.session_id, &rcpt, &sent.artifact_id, Some(&sent.frame_sha)) {
        Ok(r) => r,
        Err(e) => return Err(fail_out(state, tx, e)),
    };
    let id = persist_event(state, &mut tx, true, None);
    let timings = Value::Object({
        let mut t = tx.timings.clone();
        t.insert("total".into(), json!(r3(tx.t0.elapsed().as_secs_f64() * 1000.0)));
        t
    });
    Ok(json!({
        "ok": true, "event_id": id, "session_id": req.session_id, "direction": rec.direction, "seq": rec.seq,
        "from_role": rec.from_role, "to_role": rec.to_role,
        "delivered_message": String::from_utf8_lossy(&rec.plaintext),
        "artifact": artifact_json(&sent), "cover": sent.cover, "generation": sent.generation, "plan": sent.plan, "inspection": sent.inspection, "manifest": sent.manifest, "embed": sent.embed,
        "bootstrap": rec.bootstrap, "received_image": rec.image, "received_manifest": rec.manifest, "extraction": rec.patches,
        "verification": {"frame_match": rec.frame_sha == sent.frame_sha, "header_mac_ok": true, "manifest_authenticated": true, "aead_ok": true,
                         "resegmented": false, "full_frame_recovered": true},
        "timings_ms": timings, "stages": tx.stages, "transport": transport_json(&sent),
    }))
}

/// Sender half only: stops after the PNG is saved; returns the artifact id for the receiver.
pub fn run_send(state: &Mutex<SimulationState>, req: MessageRequest) -> Result<Value, TxFailure> {
    let h = handles(state);
    let mut tx = Tx::new("send", &req.session_id, req.origin);
    let sent = match do_send(state, &h, &mut tx, &req) {
        Ok(s) => s,
        Err(e) => return Err(fail_out(state, tx, e)),
    };
    let id = persist_event(state, &mut tx, true, None);
    Ok(json!({
        "ok": true, "event_id": id, "session_id": req.session_id, "direction": sent.direction, "seq": sent.seq,
        "from_role": sent.from_role, "to_role": sent.to_role,
        "artifact": artifact_json(&sent), "cover": sent.cover, "generation": sent.generation, "plan": sent.plan, "inspection": sent.inspection, "manifest": sent.manifest, "embed": sent.embed,
        "frame_sha256_prefix": &sent.frame_sha[..16],
        "timings_ms": Value::Object(tx.timings.clone()), "stages": tx.stages, "transport": transport_json(&sent),
    }))
}

/// Receiver half only: input is just the saved artifact (by id).
pub fn run_receive(state: &Mutex<SimulationState>, session_id: &str, recipient_id: &str, artifact_id: &str) -> Result<Value, TxFailure> {
    let h = handles(state);
    let mut tx = Tx::new("receive", session_id, "api");
    let rec = match do_receive(state, &h, &mut tx, session_id, recipient_id, artifact_id, None) {
        Ok(r) => r,
        Err(e) => return Err(fail_out(state, tx, e)),
    };
    let id = persist_event(state, &mut tx, true, None);
    Ok(json!({
        "ok": true, "event_id": id, "session_id": session_id, "direction": rec.direction, "seq": rec.seq,
        "from_role": rec.from_role, "to_role": rec.to_role, "delivered_message": String::from_utf8_lossy(&rec.plaintext),
        "bootstrap": rec.bootstrap, "received_image": rec.image, "received_manifest": rec.manifest, "extraction": rec.patches,
        "verification": {"header_mac_ok": true, "manifest_authenticated": true, "aead_ok": true, "resegmented": false, "full_frame_recovered": true},
        "timings_ms": Value::Object(tx.timings.clone()), "stages": tx.stages,
    }))
}

/// Plan preview for the Lab (no keys, no message, nothing embedded): segmentation, per-patch
/// retrieval and allocation for a payload of `payload_bytes`. The returned manifest is validated
/// exactly as on the send path.
pub fn run_plan_preview(state: &Mutex<SimulationState>, payload_bytes: usize, cover_generation: &Value, min_level: u32) -> Result<Value, StegoError> {
    let h = handles(state);
    let gen_json = h.cfg.generator.resolve(Some(cover_generation))?.to_json();
    if payload_bytes <= frame::TAG_LEN || payload_bytes > h.cfg.max_frame_bytes {
        return Err(StegoError::new("INVALID_REQUEST", stage::PLAN, 400, format!("payload_bytes must be within {}..={}", frame::TAG_LEN + 1, h.cfg.max_frame_bytes)));
    }
    let t = Instant::now();
    let resp = h.backend.plan(&plan_request(&h, payload_bytes, PlanCover::Generate(&gen_json), min_level)).map_err(|e| restage(e, stage::PLAN))?;
    let p = accept_plan(&h, &resp, payload_bytes)?;
    let cid = p.cover["artifact_id"].as_str().unwrap_or("").to_string();
    Ok(json!({"ok": true, "plan": p.plan, "manifest": p.manifest.summary(), "manifest_bytes": p.manifest_bytes.len(), "cover": p.cover, "generation": p.generation, "inspection": p.inspection,
              "artifact": {"cover_id": cid, "cover_preview_url": format!("/api/stego/artifacts/{cid}/cover"),
                           "segmentation_overlay_url": format!("/api/stego/artifacts/{cid}/seg"), "label_map_url": format!("/api/stego/artifacts/{cid}/labels")},
              "timings_ms": p.timings, "wall_ms": r3(t.elapsed().as_secs_f64() * 1000.0),
              "note": "plan preview only: a fresh cover was generated for this preview; no message sealed, no frame authenticated, no stego image saved. A later send generates its own fresh cover."}))
}

/// Repeatable benchmark: real sealed messages through the full pipeline.
/// Every run generates its own fresh cover under the active resource profile.
pub fn run_benchmark(state: &Mutex<SimulationState>, session_id: &str, iterations: usize, sizes: &[usize], cover_generation: &Value) -> Result<Value, StegoError> {
    let gen_cfg = handles(state).cfg.generator.resolve(Some(cover_generation))?;
    if iterations == 0 || iterations > 50 || sizes.is_empty() || sizes.len() > 8 || iterations * sizes.len() > 400 {
        return Err(StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "benchmark bounds: iterations<=50, sizes<=8, total runs<=400"));
    }
    let (d1, d2) = {
        let s = state.lock().unwrap();
        let sess = s.gcs.sessions.get(session_id).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "unknown session"))?;
        (sess.d1_id.clone(), sess.d2_id.clone())
    };
    let mut runs = Vec::new();
    let mut ids: Vec<i64> = Vec::new();
    for &size in sizes {
        if size == 0 || size > 60_000 {
            return Err(StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "benchmark payload size must be within 1..=60000"));
        }
        for i in 0..iterations {
            let from = if i % 2 == 0 { d1.clone() } else { d2.clone() };
            let req = MessageRequest { session_id: session_id.to_string(), from_id: from, plaintext: vec![b'b'; size], cover_generation: cover_generation.clone(), origin: "benchmark" };
            let (ok, id, code, total, algs, gen) = match run_message(state, req) {
                Ok(v) => (true, v["event_id"].as_i64().unwrap_or(-1), Value::Null, v["timings_ms"]["total"].clone(), v["plan"]["algorithms_used"].clone(),
                          json!({"cover_id": v["cover"]["artifact_id"], "family": v["cover"]["family"], "seed_fingerprint": v["cover"]["seed_fingerprint"],
                                 "quality_score": v["cover"]["quality_score"], "width": v["cover"]["width"], "height": v["cover"]["height"],
                                 "candidates": v["generation"]["candidate_count"], "generation_ms": v["generation"]["timings_ms"]["total"],
                                 "budget_exceeded": v["generation"]["budget"]["exceeded"]})),
                Err(f) => (false, f.event_id, json!(f.error.code), Value::Null, Value::Null, Value::Null),
            };
            ids.push(id);
            runs.push(json!({"payload_bytes": size, "iteration": i, "ok": ok, "event_id": id, "error_code": code, "total_ms": total, "algorithms_used": algs, "cover": gen}));
        }
    }
    let events: Vec<Value> = {
        let s = state.lock().unwrap();
        ids.iter().filter_map(|id| s.db.get_stego_event(*id).ok().flatten()).collect()
    };
    let summary = crate::transport::report::build_report(&events, json!({"scope": "benchmark_run"}), now_ms());
    Ok(json!({"ok": true, "runs": runs, "summary": summary, "samples": runs.len(),
              "cover_generation": {"profile": gen_cfg.profile, "effective": gen_cfg.to_json(), "fresh_cover_per_run": true},
              "host": crate::transport::report::host_metadata(),
              "measurement_label": format!("profile-constrained host benchmark ({}): the profile's limits were enforced on THIS host; these are not measurements from the profile's target hardware", gen_cfg.profile)}))
}
