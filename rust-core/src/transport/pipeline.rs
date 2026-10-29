//! End-to-end image-transport transactions (docs/stego-implementation-note.md).
//!
//! seal (Rust) -> select+cover (Python, deterministic) -> frame+MAC (Rust)
//! -> embed + PNG save (Python) -> [handoff by artifact id] -> local read
//! -> extract (Python) -> strict parse + MAC (Rust) -> channel/replay/AEAD (Rust)
//! -> explanation (Python RAG, explanation only).
//!
//! The global state mutex is never held across a backend call.
//! Everything fails closed with a stable error code and a persisted event.

use crate::api::state::SimulationState;
use crate::crypto::aead::AeadKey;
use crate::protocol::entities::SessionState;
use crate::protocol::secure_messaging::{self, SecureMessagingError};
use crate::transport::backend::{is_artifact_id, StegoBackend, ALGS};
use crate::transport::config::StegoConfig;
use crate::transport::error::{stage, StegoError};
use crate::transport::explain;
use crate::transport::frame;
use crate::transport::wire;
use crate::transport::b64;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const TRANSPORT_FORMAT_VERSION: &str = "frame-v1/appwire-v1/bootstrap-v1";
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
    pub algorithm: Option<String>,
    pub cover: Value,
    pub priority: String,
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
    selection: Value,
    cover: Value,
    stego: Value,
    embed: Value,
    frame_sha: String,
    frame_len: usize,
    wire_len: usize,
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

/// Raw PNG bytes for the dashboard preview (id validated, fixed suffixes only).
pub fn artifact_png(cfg: &StegoConfig, id: &str, kind: &str) -> Result<Vec<u8>, StegoError> {
    let suffix = match kind {
        "stego" => ".png",
        "cover" => ".cover.png",
        _ => return Err(StegoError::new("INVALID_REQUEST", stage::READ, 400, "kind must be stego or cover")),
    };
    read_artifact_file(cfg, id, suffix, stage::READ)
}

fn do_send(state: &Mutex<SimulationState>, h: &Handles, tx: &mut Tx, req: &MessageRequest) -> Result<Sent, StegoError> {
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
    let frame_len = frame::frame_len_for(wire_bytes.len());
    let ms = tx.ms(t);
    tx.timing("aead_seal", ms);
    tx.set("wire_bytes", json!(wire_bytes.len()));
    tx.set("frame_bytes", json!(frame_len));
    if frame_len > h.cfg.max_frame_bytes {
        let e = StegoError::new("FRAME_TOO_LARGE", stage::AEAD_SEAL, 413, format!("sealed frame of {frame_len} bytes exceeds the configured maximum of {} bytes", h.cfg.max_frame_bytes));
        tx.fail("aead_seal", ms, &e);
        return Err(e);
    }
    tx.ok("aead_seal", ms, format!("sealed; frame will be {frame_len} bytes"));

    // ---- cover acquisition + deterministic selection (Python; no keys, only the frame length)
    let t = Instant::now();
    let mut areq = json!({"frame_bytes": frame_len, "cover": req.cover, "priority": req.priority, "policy": h.cfg.policy, "limits": h.cfg.limits()});
    if let Some(a) = &req.algorithm {
        areq["algorithm"] = json!(a);
    }
    let analysis = h.backend.analyze(&areq).map_err(|e| restage(e, stage::SELECTOR));
    let analysis = match analysis {
        Ok(a) => a,
        Err(e) => {
            let ms = tx.ms(t);
            tx.fail("selector", ms, &e);
            if let Some(d) = &e.details {
                if let Some(c) = d.get("candidates") {
                    tx.set("candidates", c.clone());
                }
            }
            return Err(e);
        }
    };
    let wall = tx.ms(t);
    let selection = analysis.get("selection").cloned().unwrap_or(Value::Null);
    let cover = analysis.get("cover").cloned().unwrap_or(Value::Null);
    let selected = need_str(&selection, "selected", stage::SELECTOR)?.to_string();
    let alg_idx = ALGS.iter().position(|a| *a == selected).ok_or_else(|| StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::SELECTOR, 502, "backend selected an unknown algorithm"))?;
    let alg_id = (alg_idx + 1) as u8;
    if selection["selected_alg_id"].as_u64() != Some(alg_id as u64) {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::SELECTOR, 502, "selected algorithm id does not match its name"));
    }
    let param = selection["selected_param"].as_u64().unwrap_or(0);
    if param > 255 {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::SELECTOR, 502, "selected parameter out of range"));
    }
    let cover_id = need_str(&cover, "artifact_id", stage::SELECTOR)?.to_string();
    if !is_artifact_id(&cover_id) {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::SELECTOR, 502, "cover artifact id malformed"));
    }
    let atim = analysis.get("timings_ms").cloned().unwrap_or(json!({}));
    tx.timing("capture", atim["capture"].as_f64().unwrap_or(0.0));
    tx.timing("select", atim["select"].as_f64().unwrap_or(0.0));
    tx.set("selection_policy_version", selection["policy_version"].clone());
    tx.set("selection_mode", selection["mode"].clone());
    tx.set("selection_reason_code", selection["reason_code"].clone());
    tx.set("candidates", selection["candidates"].clone());
    tx.set("algorithm", json!(selected));
    tx.set("param", json!(param));
    tx.set("cover_source", cover["source"].clone());
    tx.set("cover_fallback_reason", cover["fallback_reason"].clone());
    for k in ["width", "height", "mode", "channels"] {
        tx.set(k, cover[k].clone());
    }
    tx.set("cover_sha256", cover["sha256"].clone());
    tx.ok("selector", wall, format!("{selected} selected ({})", selection["reason_code"].as_str().unwrap_or("?")));

    // ---- frame + metadata MAC (Rust)
    let frame_bytes = frame::build_frame(&meta, alg_id, param as u8, &wire_bytes, h.cfg.max_frame_bytes)?;
    let frame_sha = sha_hex(&frame_bytes);
    tx.set("frame_sha256_prefix", json!(&frame_sha[..16]));

    // ---- embed + save PNG (Python)
    let t = Instant::now();
    let ereq = json!({
        "frame_b64": b64::encode(&frame_bytes),
        "cover": {"source": "test_cover", "test_cover_id": cover_id},
        "algorithm": selected, "param": param, "priority": req.priority, "policy": h.cfg.policy, "limits": h.cfg.limits(),
    });
    let enc = h.backend.encode(&ereq).map_err(|e| restage(e, stage::EMBED));
    let enc = match enc {
        Ok(v) => v,
        Err(e) => {
            let ms = tx.ms(t);
            tx.fail("embed", ms, &e);
            return Err(e);
        }
    };
    let wall = tx.ms(t);
    let artifact_id = need_str(&enc, "artifact_id", stage::EMBED)?.to_string();
    if !is_artifact_id(&artifact_id) {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::EMBED, 502, "artifact id malformed"));
    }
    let embed = enc.get("embed").cloned().unwrap_or(Value::Null);
    let stego = enc.get("stego").cloned().unwrap_or(Value::Null);
    if embed["frame_len"].as_u64() != Some(frame_bytes.len() as u64) || embed["alg_id"].as_u64() != Some(alg_id as u64) {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::EMBED, 502, "embed report disagrees with the requested frame/algorithm"));
    }
    let etim = enc.get("timings_ms").cloned().unwrap_or(json!({}));
    tx.timing("embed", etim["embed"].as_f64().unwrap_or(0.0));
    tx.timing("embed_verify", etim["verify"].as_f64().unwrap_or(0.0));
    tx.ok("embed", wall, format!("embedded {} bytes with {selected}", frame_bytes.len()));

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

    // record rich fields
    tx.set("artifact_id", json!(artifact_id));
    tx.set("stego_sha256", json!(file_sha));
    tx.set("image_bytes", json!(file.len()));
    tx.set("output_format", json!("PNG"));
    tx.set("capacity_bytes", embed["capacity_bytes"].clone());
    let cap = embed["capacity_bytes"].as_u64().unwrap_or(0) as i64;
    tx.set("capacity_margin_bytes", json!(cap - frame_bytes.len() as i64));
    let m = &embed["metrics"];
    tx.set("mse", m["mse"].clone());
    tx.set("psnr", m["psnr"].clone());
    tx.set("ssim", m["ssim"].clone());
    tx.set("psnr_defined", json!(m["psnr"].is_number()));
    tx.set("ssim_defined", json!(m["ssim"].is_number()));
    tx.set("changed_fraction", m["changed_fraction"].clone());

    Ok(Sent { artifact_id, direction, seq, from_role, to_role, selection, cover, stego, embed, frame_sha, frame_len: frame_bytes.len(), wire_len: wire_bytes.len(), file_sha, file_size: file.len() as u64 })
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

    // ---- extraction (Python reads the same saved file by id)
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
    let xt = ex.get("timings_ms").cloned().unwrap_or(json!({}));
    tx.timing("extract", wall);
    let step = (|| -> Result<Vec<u8>, StegoError> {
        if image["sha256"].as_str() != Some(file_sha.as_str()) {
            return Err(StegoError::new("ARTIFACT_HASH_MISMATCH", stage::EXTRACT, 500, "the image service read different bytes than the Rust core"));
        }
        b64::decode(need_str(&ex, "frame_b64", stage::EXTRACT)?, h.cfg.max_frame_bytes)
            .map_err(|m| StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::EXTRACT, 502, m))
    })();
    let frame_bytes = match step {
        Ok(f) => f,
        Err(e) => {
            tx.fail("extract", wall, &e);
            return Err(e);
        }
    };
    let _ = xt;
    tx.ok("extract", wall, format!("recovered {} bytes via {}", frame_bytes.len(), bootstrap["algorithm"].as_str().unwrap_or("?")));
    tx.set("algorithm", bootstrap["algorithm"].clone());
    tx.set("param", bootstrap["param"].clone());
    for k in ["width", "height", "mode", "channels"] {
        tx.set(k, image[k].clone());
    }
    let frame_sha = sha_hex(&frame_bytes);
    tx.set("frame_sha256_prefix", json!(&frame_sha[..16]));
    tx.set("frame_bytes", json!(frame_bytes.len()));
    if let Some(sent) = sent_frame_sha {
        tx.set("frame_match", json!(sent == frame_sha));
    }

    // ---- strict frame parse + metadata MAC (Rust)
    let t = Instant::now();
    let meta = frame::derive_meta_key(&key, &tag, expected_dir);
    let verify = (|| -> Result<wire::Parsed, StegoError> {
        if bootstrap["frame_len"].as_u64() != Some(frame_bytes.len() as u64) {
            return Err(StegoError::new("FRAME_LENGTH_MISMATCH", stage::VERIFY, 422, "bootstrap frame length differs from the recovered frame"));
        }
        let alg = bootstrap["alg_id"].as_u64().filter(|a| (1..=5).contains(a)).ok_or_else(|| StegoError::new("UNKNOWN_ALGORITHM", stage::VERIFY, 422, "bootstrap algorithm id invalid"))? as u8;
        let param = bootstrap["param"].as_u64().filter(|p| *p <= 255).ok_or_else(|| StegoError::new("BOOTSTRAP_CORRUPT", stage::VERIFY, 422, "bootstrap parameter invalid"))? as u8;
        let payload = frame::parse_and_verify(&meta, &frame_bytes, alg, param, h.cfg.max_frame_bytes)?;
        let msg = wire::decode_app_wire(payload, h.cfg.max_frame_bytes)?;
        Ok(wire::Parsed { msg })
    })();
    let ms = tx.ms(t);
    tx.timing("verify", ms);
    let parsed = match verify {
        Ok(p) => {
            tx.set("header_mac_ok", json!(true));
            tx.ok("verify_frame", ms, "frame header authenticated; algorithm consistent with bootstrap");
            p
        }
        Err(e) => {
            tx.set("header_mac_ok", json!(false));
            tx.fail("verify_frame", ms, &e);
            return Err(e);
        }
    };

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
    Ok(Received { plaintext, direction: expected_dir, seq: parsed.msg.header_seq, from_role, to_role, image, bootstrap, frame_sha })
}

// ---------------------------------------------------------- explain ---

fn do_explain(h: &Handles, tx: &mut Tx, selection: &Value, embed: &Value, cover: &Value) -> Value {
    let t = Instant::now();
    let report = json!({
        "selection": selection,
        "embed": {"algorithm": embed["algorithm"], "capacity_bytes": embed["capacity_bytes"], "frame_len": embed["frame_len"], "metrics": embed["metrics"]},
        "cover": {"source": cover["source"], "fallback_reason": cover["fallback_reason"], "width": cover["width"], "height": cover["height"], "mode": cover["mode"]},
        "policy": h.cfg.policy,
    });
    let result = match h.backend.explain(&report) {
        Ok(resp) => explain::accept_rag_response(&resp, selection).map_err(|why| why),
        Err(e) => Err(format!("rag_unavailable:{}", e.code)),
    };
    let ms = tx.ms(t);
    tx.timing("explain", ms);
    match result {
        Ok(v) => {
            tx.ok("explain", ms, "simulated RAG explanation (explanation only)");
            tx.set("explanation_status", json!("simulated_rag"));
            v
        }
        Err(why) => {
            tx.ok("explain", ms, format!("deterministic fallback explanation ({why})"));
            tx.set("explanation_status", json!("fallback_deterministic"));
            explain::fallback_explanation(selection, embed, &why)
        }
    }
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
    json!({
        "id": sent.artifact_id, "stego_sha256": sent.file_sha, "size": sent.file_size,
        "preview_url": format!("/api/stego/artifacts/{}/stego", sent.artifact_id),
        "cover_preview_url": format!("/api/stego/artifacts/{}/cover", sent.cover["artifact_id"].as_str().unwrap_or("")),
        "image": sent.stego,
        "width": sent.stego["width"], "height": sent.stego["height"], "mode": sent.stego["mode"],
        "channels": sent.stego["channels"], "format": sent.stego["format"],
    })
}

// ----------------------------------------------------------- public ---

/// Full transaction: send -> save -> receive (from the saved file) -> verify -> explain.
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
    let explanation = do_explain(&h, &mut tx, &sent.selection, &sent.embed, &sent.cover);
    tx.set("explanation_payload_kind", json!(explanation["status"]));
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
        "artifact": artifact_json(&sent), "cover": sent.cover, "selection": sent.selection, "embed": sent.embed,
        "bootstrap": rec.bootstrap, "received_image": rec.image,
        "verification": {"frame_match": rec.frame_sha == sent.frame_sha, "header_mac_ok": true, "algorithm_consistent": true, "aead_ok": true},
        "timings_ms": timings, "stages": tx.stages, "explanation": explanation,
        "transport": {"format_version": TRANSPORT_FORMAT_VERSION, "frame_bytes": sent.frame_len, "wire_bytes": sent.wire_len},
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
    let explanation = do_explain(&h, &mut tx, &sent.selection, &sent.embed, &sent.cover);
    let id = persist_event(state, &mut tx, true, None);
    Ok(json!({
        "ok": true, "event_id": id, "session_id": req.session_id, "direction": sent.direction, "seq": sent.seq,
        "from_role": sent.from_role, "to_role": sent.to_role,
        "artifact": artifact_json(&sent), "cover": sent.cover, "selection": sent.selection, "embed": sent.embed,
        "frame_sha256_prefix": &sent.frame_sha[..16],
        "timings_ms": Value::Object(tx.timings.clone()), "stages": tx.stages, "explanation": explanation,
        "transport": {"format_version": TRANSPORT_FORMAT_VERSION, "frame_bytes": sent.frame_len, "wire_bytes": sent.wire_len},
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
        "bootstrap": rec.bootstrap, "received_image": rec.image,
        "verification": {"header_mac_ok": true, "algorithm_consistent": true, "aead_ok": true},
        "timings_ms": Value::Object(tx.timings.clone()), "stages": tx.stages,
    }))
}

/// Selection analysis for the Lab (no keys, no message): a synthetic frame length only.
pub fn run_analyze(state: &Mutex<SimulationState>, frame_bytes: usize, cover: &Value, priority: &str, algorithm: Option<&str>) -> Result<Value, StegoError> {
    let h = handles(state);
    if frame_bytes == 0 || frame_bytes > h.cfg.max_frame_bytes {
        return Err(StegoError::new("FRAME_TOO_LARGE", stage::SELECTOR, 413, format!("frame_bytes must be within 1..={}", h.cfg.max_frame_bytes)));
    }
    let mut areq = json!({"frame_bytes": frame_bytes, "cover": cover, "priority": priority, "policy": h.cfg.policy, "limits": h.cfg.limits()});
    if let Some(a) = algorithm {
        areq["algorithm"] = json!(a);
    }
    let t = Instant::now();
    let out = h.backend.analyze(&areq).map_err(|e| restage(e, stage::SELECTOR))?;
    Ok(json!({"ok": true, "selection": out["selection"], "cover": out["cover"], "timings_ms": out["timings_ms"],
              "wall_ms": r3(t.elapsed().as_secs_f64() * 1000.0), "note": "analysis only: no message sealed, no stego image saved"}))
}

/// Repeatable benchmark: real sealed messages through the full pipeline.
pub fn run_benchmark(state: &Mutex<SimulationState>, session_id: &str, iterations: usize, sizes: &[usize], algorithms: &[String], cover: &Value) -> Result<Value, StegoError> {
    if iterations == 0 || iterations > 50 || sizes.is_empty() || sizes.len() > 8 || algorithms.is_empty() || algorithms.len() > 5 || iterations * sizes.len() * algorithms.len() > 400 {
        return Err(StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "benchmark bounds: iterations<=50, sizes<=8, algorithms<=5, total runs<=400"));
    }
    for a in algorithms {
        if !ALGS.contains(&a.as_str()) {
            return Err(StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, format!("unknown algorithm '{a}'")));
        }
    }
    let (d1, d2) = {
        let s = state.lock().unwrap();
        let sess = s.gcs.sessions.get(session_id).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "unknown session"))?;
        (sess.d1_id.clone(), sess.d2_id.clone())
    };
    let mut runs = Vec::new();
    let mut ids: Vec<i64> = Vec::new();
    for alg in algorithms {
        for &size in sizes {
            if size == 0 || size > 60_000 {
                return Err(StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "benchmark payload size must be within 1..=60000"));
            }
            for i in 0..iterations {
                let from = if i % 2 == 0 { d1.clone() } else { d2.clone() };
                let req = MessageRequest { session_id: session_id.to_string(), from_id: from, plaintext: vec![b'b'; size], algorithm: Some(alg.clone()), cover: cover.clone(), priority: "normal".into(), origin: "benchmark" };
                let (ok, id, code, total) = match run_message(state, req) {
                    Ok(v) => (true, v["event_id"].as_i64().unwrap_or(-1), Value::Null, v["timings_ms"]["total"].clone()),
                    Err(f) => (false, f.event_id, json!(f.error.code), Value::Null),
                };
                ids.push(id);
                runs.push(json!({"algorithm": alg, "payload_bytes": size, "iteration": i, "ok": ok, "event_id": id, "error_code": code, "total_ms": total}));
            }
        }
    }
    let events: Vec<Value> = {
        let s = state.lock().unwrap();
        ids.iter().filter_map(|id| s.db.get_stego_event(*id).ok().flatten()).collect()
    };
    let summary = crate::transport::report::build_report(&events, json!({"scope": "benchmark_run"}), now_ms());
    Ok(json!({"ok": true, "runs": runs, "summary": summary, "samples": runs.len()}))
}
