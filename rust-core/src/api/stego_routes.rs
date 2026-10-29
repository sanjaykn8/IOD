//! HTTP routes for the image transport (`/api/stego/*`) plus the legacy
//! `/api/secure-message` shim, which now travels through the same pipeline.
//! Validation happens here; security decisions live in `transport::pipeline`.

use crate::api::state::SimulationState;
use crate::transport::backend::{is_artifact_id, ALGS};
use crate::transport::error::{stage, StegoError};
use crate::transport::pipeline::{self, MessageRequest, TxFailure};
use crate::transport::report;
use crate::storage::StegoEventFilter;
use serde_json::{json, Value};
use std::sync::Mutex;
use tiny_http::{Header, Method, Response};

pub type Resp = Response<std::io::Cursor<Vec<u8>>>;

fn hdr(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn json_resp(status: u16, body: Value) -> Resp {
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(hdr("Content-Type", "application/json"))
        .with_header(hdr("Access-Control-Allow-Origin", "*"))
}

fn err_resp(e: &StegoError) -> Resp {
    json_resp(e.http_status, json!({"ok": false, "error": e.to_json()}))
}

fn fail_resp(f: &TxFailure) -> Resp {
    json_resp(f.error.http_status, f.to_json())
}

fn bad(msg: &str) -> StegoError {
    StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, msg)
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn qparam(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|p| p.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| pct_decode(v))).filter(|v| !v.is_empty())
}

fn read_body_strict(request: &mut tiny_http::Request, max: usize) -> Result<Value, StegoError> {
    let mut buf = Vec::new();
    let reader = request.as_reader();
    std::io::Read::take(reader, max as u64 + 1).read_to_end(&mut buf).map_err(|_| bad("could not read request body"))?;
    if buf.len() > max {
        return Err(StegoError::new("REQUEST_TOO_LARGE", stage::PREPARE, 413, "request body too large"));
    }
    if buf.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&buf).map_err(|_| bad("request body is not valid JSON"))
}
use std::io::Read as _;

fn cover_from(body: &Value) -> Result<Value, StegoError> {
    let c = match body.get("cover") {
        None | Some(Value::Null) => return Ok(json!({"source": "webcam"})),
        Some(c) => c,
    };
    let src = c.get("source").and_then(|s| s.as_str()).unwrap_or("webcam");
    let mut out = json!({"source": src});
    match src {
        "webcam" | "procedural" => {}
        "test_cover" => {
            let id = c.get("test_cover_id").and_then(|s| s.as_str()).unwrap_or("");
            if !is_artifact_id(id) {
                return Err(bad("test_cover requires test_cover_id (32 lowercase hex characters)"));
            }
            out["test_cover_id"] = json!(id);
        }
        _ => return Err(bad("cover.source must be webcam, procedural or test_cover")),
    }
    if let Some(i) = c.get("camera_index") {
        let i = i.as_i64().filter(|i| (0..=16).contains(i)).ok_or_else(|| bad("camera_index must be an integer within 0..=16"))?;
        out["camera_index"] = json!(i);
    }
    if let Some(s) = c.get("seed") {
        let s = s.as_str().filter(|s| s.len() <= 64).ok_or_else(|| bad("seed must be a string of at most 64 characters"))?;
        out["seed"] = json!(s);
    }
    Ok(out)
}

fn priority_from(body: &Value) -> Result<String, StegoError> {
    match body.get("priority").and_then(|p| p.as_str()) {
        None => Ok("normal".into()),
        Some(p @ ("urgent" | "normal" | "background")) => Ok(p.into()),
        Some(_) => Err(bad("priority must be urgent, normal or background")),
    }
}

fn algorithm_from(body: &Value) -> Result<Option<String>, StegoError> {
    match body.get("algorithm") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(a)) if a.is_empty() || a == "auto" => Ok(None),
        Some(Value::String(a)) if ALGS.contains(&a.as_str()) => Ok(Some(a.clone())),
        _ => Err(bad("algorithm must be one of lsb_replacement, lsb_matching, pvd, edge_adaptive_lsb, dct (or omitted for automatic)")),
    }
}

fn resolve_session(state: &Mutex<SimulationState>, body: &Value, from: &str) -> Result<String, StegoError> {
    if let Some(sid) = body.get("session_id").and_then(|s| s.as_str()) {
        return Ok(sid.to_string());
    }
    if let Some(to) = body.get("to_id").and_then(|s| s.as_str()) {
        let s = state.lock().unwrap();
        return s.latest_session(from, to).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "no authenticated session between these drones"));
    }
    if let (Some(a), Some(b)) = (body.get("d1_id").and_then(|s| s.as_str()), body.get("d2_id").and_then(|s| s.as_str())) {
        let s = state.lock().unwrap();
        return s.latest_session(a, b).ok_or_else(|| StegoError::new("NO_AUTH_SESSION", stage::PREPARE, 409, "no authenticated session between these drones"));
    }
    Err(bad("missing session_id (or to_id / d1_id+d2_id)"))
}

fn message_request(state: &Mutex<SimulationState>, body: &Value, origin: &'static str) -> Result<MessageRequest, StegoError> {
    let from = body.get("from_id").and_then(|s| s.as_str()).ok_or_else(|| bad("missing from_id"))?;
    let text = body.get("plaintext").and_then(|s| s.as_str()).ok_or_else(|| bad("missing plaintext"))?;
    let max = state.lock().unwrap().stego_cfg.max_frame_bytes;
    if text.len() > max {
        return Err(StegoError::new("FRAME_TOO_LARGE", stage::PREPARE, 413, format!("plaintext of {} bytes cannot fit the {max}-byte frame limit", text.len())));
    }
    Ok(MessageRequest {
        session_id: resolve_session(state, body, from)?,
        from_id: from.to_string(),
        plaintext: text.as_bytes().to_vec(),
        algorithm: algorithm_from(body)?,
        cover: cover_from(body)?,
        priority: priority_from(body)?,
        origin,
    })
}

/// Legacy `/api/secure-message`: same pipeline, legacy response keys preserved.
pub fn legacy_secure_message(state: &Mutex<SimulationState>, body: &Value) -> Resp {
    let req = match message_request(state, body, "secure_message_api") {
        Ok(r) => r,
        Err(e) => return json_resp(e.http_status, json!({"error": format!("{}: {}", e.code, e.message), "error_detail": e.to_json()})),
    };
    match pipeline::run_message(state, req) {
        Ok(v) => json_resp(200, json!({"status": "delivered", "decrypted_by_receiver": v["delivered_message"], "transport": "image/png (steganographic)", "stego": v})),
        Err(f) => json_resp(f.error.http_status, json!({"error": format!("{}: {}", f.error.code, f.error.message), "error_detail": f.error.to_json(), "event_id": f.event_id, "stages": f.stages})),
    }
}

fn filter_from(query: &str) -> StegoEventFilter {
    StegoEventFilter {
        session_id: qparam(query, "session_id"),
        direction: qparam(query, "direction").and_then(|d| match d.to_ascii_lowercase().as_str() {
            "1" | "d1_to_d2" => Some(1),
            "2" | "d2_to_d1" => Some(2),
            _ => None,
        }),
        algorithm: qparam(query, "algorithm"),
        outcome: qparam(query, "outcome").filter(|o| o == "ok" || o == "failed"),
        since_ms: qparam(query, "since_ms").and_then(|v| v.parse().ok()),
        until_ms: qparam(query, "until_ms").and_then(|v| v.parse().ok()),
        limit: qparam(query, "limit").and_then(|v| v.parse().ok()),
    }
}

pub fn handle(request: &mut tiny_http::Request, method: &Method, segs: &[&str], query: &str, state: &Mutex<SimulationState>) -> Resp {
    // segs = ["api","stego", ...]
    let rest = &segs[2..];
    match (method, rest) {
        (Method::Get, ["status"]) => {
            let (backend, cfg) = {
                let s = state.lock().unwrap();
                (s.backend.clone(), s.stego_cfg.clone())
            };
            let health = backend.health();
            let (ok, failed) = state.lock().unwrap().db.count_stego_events().unwrap_or((0, 0));
            let b = match &health {
                Ok(h) => json!({"reachable": true, "health": h}),
                Err(e) => json!({"reachable": false, "error": e.to_json()}),
            };
            json_resp(200, json!({"backend": b, "config": cfg.public_view(), "counts": {"events": ok + failed, "ok": ok, "failed": failed},
                "transport": {"format_version": pipeline::TRANSPORT_FORMAT_VERSION, "passthrough_fallback": false}}))
        }
        (Method::Post, ["camera", "probe"]) => {
            let body = match read_body_strict(request, 4096) { Ok(b) => b, Err(e) => return err_resp(&e) };
            let (backend, cfg) = {
                let s = state.lock().unwrap();
                (s.backend.clone(), s.stego_cfg.clone())
            };
            let idx = body.get("camera_index").and_then(|i| i.as_i64()).filter(|i| (0..=16).contains(i)).unwrap_or(cfg.camera_index);
            match backend.camera_probe(idx, cfg.capture_timeout_ms) {
                Ok(v) => json_resp(200, v),
                Err(e) => err_resp(&e),
            }
        }
        (Method::Post, ["analyze"]) => {
            let body = match read_body_strict(request, 16 * 1024) { Ok(b) => b, Err(e) => return err_resp(&e) };
            let n = body.get("frame_bytes").and_then(|v| v.as_u64()).unwrap_or(256) as usize;
            let run = (|| -> Result<Value, StegoError> {
                let cover = cover_from(&body)?;
                let pr = priority_from(&body)?;
                let alg = algorithm_from(&body)?;
                pipeline::run_analyze(state, n, &cover, &pr, alg.as_deref())
            })();
            match run {
                Ok(v) => json_resp(200, v),
                Err(e) => err_resp(&e),
            }
        }
        (Method::Post, ["message"]) | (Method::Post, ["send"]) => {
            let body = match read_body_strict(request, 256 * 1024) { Ok(b) => b, Err(e) => return err_resp(&e) };
            let full = rest[0] == "message";
            let req = match message_request(state, &body, "api") { Ok(r) => r, Err(e) => return err_resp(&e) };
            let r = if full { pipeline::run_message(state, req) } else { pipeline::run_send(state, req) };
            match r {
                Ok(v) => json_resp(200, v),
                Err(f) => fail_resp(&f),
            }
        }
        (Method::Post, ["receive"]) => {
            let body = match read_body_strict(request, 16 * 1024) { Ok(b) => b, Err(e) => return err_resp(&e) };
            let (Some(sid), Some(rcpt), Some(aid)) = (
                body.get("session_id").and_then(|v| v.as_str()),
                body.get("recipient_id").and_then(|v| v.as_str()),
                body.get("artifact_id").and_then(|v| v.as_str()),
            ) else {
                return err_resp(&bad("session_id, recipient_id and artifact_id are required"));
            };
            match pipeline::run_receive(state, sid, rcpt, aid) {
                Ok(v) => json_resp(200, v),
                Err(f) => fail_resp(&f),
            }
        }
        (Method::Get, ["events"]) => {
            let f = filter_from(query);
            let s = state.lock().unwrap();
            match s.db.query_stego_events(&f) {
                Ok(events) => json_resp(200, json!({"events": events})),
                Err(e) => json_resp(500, json!({"ok": false, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
            }
        }
        (Method::Get, ["events", id]) => {
            let Ok(id) = id.parse::<i64>() else { return err_resp(&bad("event id must be an integer")) };
            let s = state.lock().unwrap();
            match s.db.get_stego_event(id) {
                Ok(Some(e)) => json_resp(200, e),
                Ok(None) => json_resp(404, json!({"ok": false, "error": {"code": "EVENT_NOT_FOUND", "message": "no such event"}})),
                Err(e) => json_resp(500, json!({"ok": false, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
            }
        }
        (Method::Get, ["report"]) => {
            let (backend, events) = {
                let s = state.lock().unwrap();
                let mut f = filter_from(query);
                f.limit = Some(100_000);
                (s.backend.clone(), s.db.query_stego_events(&f))
            };
            let events = match events {
                Ok(e) => e,
                Err(e) => return json_resp(500, json!({"ok": false, "error": {"code": "DB_ERROR", "message": e.to_string()}})),
            };
            let py = backend.health().ok().map(|h| json!({"version": h["version"], "numpy": h["numpy"], "pillow": h["pillow"], "camera_mode": h["camera"]["mode"]}));
            let env = json!({"os": std::env::consts::OS, "arch": std::env::consts::ARCH, "rust_core_version": env!("CARGO_PKG_VERSION"), "python_service": py});
            if qparam(query, "format").as_deref() == Some("csv") {
                let mut chrono = events.clone();
                chrono.reverse();
                let body = report::events_to_csv(&chrono);
                return Response::from_string(body)
                    .with_header(hdr("Content-Type", "text/csv; charset=utf-8"))
                    .with_header(hdr("Content-Disposition", "attachment; filename=\"stego-events.csv\""))
                    .with_header(hdr("Access-Control-Allow-Origin", "*"));
            }
            json_resp(200, report::build_report(&events, env, crate::protocol::events::now_unix_ms() as i64))
        }
        (Method::Post, ["benchmark"]) => {
            let body = match read_body_strict(request, 16 * 1024) { Ok(b) => b, Err(e) => return err_resp(&e) };
            let run = (|| -> Result<Value, StegoError> {
                let sid = body.get("session_id").and_then(|s| s.as_str()).ok_or_else(|| bad("missing session_id"))?;
                let iterations = body.get("iterations").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
                let sizes: Vec<usize> = body.get("frame_sizes").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as usize)).collect()).unwrap_or_else(|| vec![64, 512]);
                let algs: Vec<String> = match body.get("algorithms").and_then(|v| v.as_array()) {
                    Some(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
                    None => ALGS.iter().map(|s| s.to_string()).collect(),
                };
                pipeline::run_benchmark(state, sid, iterations, &sizes, &algs, &cover_from(&body)?)
            })();
            match run {
                Ok(v) => json_resp(200, v),
                Err(e) => err_resp(&e),
            }
        }
        (Method::Get, ["artifacts", id, kind]) => {
            let cfg = state.lock().unwrap().stego_cfg.clone();
            match pipeline::artifact_png(&cfg, id, kind) {
                Ok(bytes) => Response::from_data(bytes)
                    .with_header(hdr("Content-Type", "image/png"))
                    .with_header(hdr("Cache-Control", "private, max-age=3600"))
                    .with_header(hdr("Access-Control-Allow-Origin", "*")),
                Err(e) => err_resp(&e),
            }
        }
        _ => json_resp(404, json!({"ok": false, "error": {"code": "NOT_FOUND", "message": "unknown stego route"}})),
    }
}
