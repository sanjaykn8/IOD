//! Minimal JSON HTTP API over `SimulationState`, using `tiny_http`.
//!
//! ## Documented implementation decision: `tiny_http`, not `axum`/`tokio`
//!
//! This sandbox's Rust toolchain is rustc 1.75.0 (Dec 2023), and there
//! is no network path available to fetch a newer one (see
//! `docs/dependency-rationale.md`). Current `axum`/`hyper`/`tokio`
//! release chains have moved their MSRV past 1.75. `tiny_http` is a
//! small, synchronous, dependency-light HTTP/1.1 server with a much
//! lower MSRV, so it actually builds here. Each request is handled
//! sequentially against a single `Mutex<SimulationState>` — entirely
//! adequate for a local research-demo simulator driven by one browser
//! tab, and much simpler to reason about than introducing an async
//! runtime for no real benefit at this scale.
//!
//! ## Documented implementation decision: polling instead of WebSockets
//!
//! For the same toolchain reason, this service exposes `GET
//! /api/events?since=<id>` for the dashboard to poll (effectively an
//! SSE-style incremental log fetch over plain HTTP) rather than a
//! WebSocket push channel. The Node.js gateway (see
//! `node-server/src/index.ts`) re-exposes this as a real
//! Server-Sent-Events stream to the browser by polling this endpoint
//! internally, so the browser-facing contract still gets incremental,
//! near-real-time updates.

use crate::api::state::SimulationState;
use crate::api::views;
use serde_json::{json, Value};
use std::sync::Mutex;
use tiny_http::{Header, Method, Response, Server};

fn cors_header() -> Header {
    Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap()
}
fn content_type_json() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn json_response(status: u16, body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(content_type_json())
        .with_header(cors_header())
}

fn ok(body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(200, body)
}
fn err(status: u16, msg: impl std::fmt::Display) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, json!({ "error": msg.to_string() }))
}

fn read_body_json(request: &mut tiny_http::Request) -> Value {
    let mut s = String::new();
    let _ = std::io::Read::read_to_string(request.as_reader(), &mut s);
    serde_json::from_str(&s).unwrap_or(json!({}))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

pub fn run(bind_addr: &str, db_path: &str) -> anyhow::Result<()> {
    let state = Mutex::new(SimulationState::new(db_path)?);
    let server = Server::http(bind_addr).map_err(|e| anyhow::anyhow!("failed to bind {bind_addr}: {e}"))?;
    eprintln!("iod-core HTTP API listening on http://{bind_addr}");

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (url.clone(), String::new()),
        };

        if method == Method::Options {
            let _ = request.respond(
                Response::from_string("")
                    .with_header(cors_header())
                    .with_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap())
                    .with_header(Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type, X-Admin-Token"[..]).unwrap()),
            );
            continue;
        }

        let response = route(&mut request, &method, &path, &query, &state);
        let _ = request.respond(response);
    }
    Ok(())
}

fn route(
    request: &mut tiny_http::Request,
    method: &Method,
    path: &str,
    query: &str,
    state: &Mutex<SimulationState>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();

    if segs.len() >= 3 && segs[0] == "api" && segs[1] == "stego" {
        return crate::api::stego_routes::handle(request, method, &segs, query, state);
    }

    match (method, segs.as_slice()) {
        (Method::Post, ["api", "reset"]) => {
            let mut s = state.lock().unwrap();
            match s.reset() {
                Ok(()) => ok(json!({ "status": "reset" })),
                Err(e) => err(500, e),
            }
        }

        (Method::Get, ["api", "state"]) => {
            let s = state.lock().unwrap();
            let groups: Vec<_> = s.gcs.groups.keys().filter_map(|g| views::group_view(g, &s.gcs)).collect();
            let drones: Vec<_> = s.drones.values().map(|d| views::drone_view(&s.gcs, d)).collect();
            ok(json!({
                "group_count": s.gcs.groups.len(),
                "drone_count": s.drones.len(),
                "groups": groups,
                "drones": drones,
                "event_count": s.log.events.len(),
            }))
        }

        (Method::Post, ["api", "groups"]) => {
            let body = read_body_json(request);
            let Some(group_id) = str_field(&body, "group_id") else { return err(400, "missing group_id") };
            let mut s = state.lock().unwrap();
            match s.create_group(group_id) {
                Ok(()) => ok(json!({ "status": "created" })),
                Err(e) => err(500, e),
            }
        }

        (Method::Get, ["api", "groups"]) => {
            let s = state.lock().unwrap();
            let groups: Vec<_> = s.gcs.groups.keys().filter_map(|g| views::group_view(g, &s.gcs)).collect();
            ok(json!({ "groups": groups }))
        }

        (Method::Get, ["api", "groups", group_id]) => {
            let s = state.lock().unwrap();
            match views::group_view(group_id, &s.gcs) {
                Some(v) => ok(serde_json::to_value(v).unwrap()),
                None => err(404, "unknown group"),
            }
        }

        (Method::Post, ["api", "drones"]) => {
            let body = read_body_json(request);
            let Some(drone_id) = str_field(&body, "drone_id") else { return err(400, "missing drone_id") };
            let mut s = state.lock().unwrap();
            match s.create_drone(drone_id) {
                Ok(()) => ok(json!({ "status": "created" })),
                Err(e) => err(500, e),
            }
        }

        (Method::Get, ["api", "drones"]) => {
            let s = state.lock().unwrap();
            let drones: Vec<_> = s.drones.values().map(|d| views::drone_view(&s.gcs, d)).collect();
            ok(json!({ "drones": drones }))
        }

        (Method::Get, ["api", "drones", drone_id]) => {
            let s = state.lock().unwrap();
            match s.drones.get(*drone_id) {
                Some(d) => ok(serde_json::to_value(views::drone_view(&s.gcs, d)).unwrap()),
                None => err(404, "unknown drone"),
            }
        }

        (Method::Post, ["api", "drones", drone_id, "register"]) => {
            let body = read_body_json(request);
            let Some(group_id) = str_field(&body, "group_id") else { return err(400, "missing group_id") };
            let role = str_field(&body, "role").unwrap_or("member");
            let mut s = state.lock().unwrap();
            match s.register_drone(drone_id, group_id, role) {
                Ok(idx) => ok(json!({ "status": "registered", "leaf_index": idx })),
                Err(e) => err(400, e),
            }
        }

        (Method::Post, ["api", "drones", drone_id, "revoke"]) => {
            let mut s = state.lock().unwrap();
            match s.revoke_drone(drone_id) {
                Ok(()) => ok(json!({ "status": "revoked" })),
                Err(e) => err(400, e),
            }
        }

        (Method::Post, ["api", "drones", drone_id, "reactivate"]) => {
            let mut s = state.lock().unwrap();
            match s.reactivate_drone(drone_id) {
                Ok(idx) => ok(json!({ "status": "reactivated", "leaf_index": idx })),
                Err(e) => err(400, e),
            }
        }

        (Method::Post, ["api", "drones", drone_id, "move"]) => {
            let body = read_body_json(request);
            let Some(group_id) = str_field(&body, "group_id") else { return err(400, "missing group_id") };
            let mut s = state.lock().unwrap();
            match s.move_drone(drone_id, group_id) {
                Ok(idx) => ok(json!({ "status": "moved", "leaf_index": idx })),
                Err(e) => err(400, e),
            }
        }

        (Method::Post, ["api", "authenticate"]) => {
            let body = read_body_json(request);
            let (Some(d1), Some(d2)) = (str_field(&body, "d1_id"), str_field(&body, "d2_id")) else {
                return err(400, "missing d1_id/d2_id");
            };
            let mut s = state.lock().unwrap();
            match s.authenticate(d1, d2) {
                Ok((session_id, report)) => ok(serde_json::to_value(views::auth_result_view(&session_id, &report)).unwrap()),
                Err(e) => err(400, e),
            }
        }

        (Method::Post, ["api", "group-key"]) => {
            let body = read_body_json(request);
            let mission_id = str_field(&body, "mission_id").unwrap_or("default-mission");
            let mut s = state.lock().unwrap();
            // K1 is bound to a completed session. A client may name the
            // session directly or the pair (resolved to that pair's latest
            // session); the GCS still enforces ALLOW + exact session.
            let sid = match (str_field(&body, "session_id"), str_field(&body, "d1_id"), str_field(&body, "d2_id")) {
                (Some(sid), _, _) => sid.to_string(),
                (None, Some(a), Some(b)) => match s.latest_session(a, b) {
                    Some(sid) => sid,
                    None => return err(409, "NO_AUTH_SESSION: authenticate first"),
                },
                _ => return err(400, "missing session_id (or d1_id/d2_id)"),
            };
            match s.establish_group_key(&sid, mission_id) {
                Ok(()) => ok(json!({ "status": "group_key_established", "session_id": sid })),
                Err(e) => err(403, e),
            }
        }

        (Method::Post, ["api", "secure-message"]) => {
            // Application messages travel as images; the pipeline never holds the state lock across backend calls.
            let body = read_body_json(request);
            crate::api::stego_routes::legacy_secure_message(state, &body)
        }

        (Method::Get, ["api", "events"]) => {
            let since: usize = query
                .split('&')
                .find_map(|p| p.strip_prefix("since="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let s = state.lock().unwrap();
            let events: Vec<_> = s.log.events.iter().skip(since).cloned().collect();
            ok(json!({ "events": events, "next_cursor": s.log.events.len() }))
        }

        (Method::Get, ["api", "events", "history"]) => {
            let limit: i64 = query
                .split('&')
                .find_map(|p| p.strip_prefix("limit="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(200);
            let s = state.lock().unwrap();
            match s.db.recent_events(limit) {
                Ok(events) => ok(json!({ "events": events })),
                Err(e) => err(500, e),
            }
        }

        (Method::Post, ["api", "trace", "flag"]) => {
            let body = read_body_json(request);
            let (Some(session_id), Some(flagged_by), Some(reason)) = (
                str_field(&body, "session_id"),
                str_field(&body, "flagged_by"),
                str_field(&body, "reason"),
            ) else {
                return err(400, "missing fields");
            };
            let mut s = state.lock().unwrap();
            let flag = s.trace.flag_session(session_id, flagged_by, reason);
            let _ = s.db.append_suspicion_flag(&flag);
            ok(serde_json::to_value(flag).unwrap())
        }

        (Method::Post, ["api", "trace", "request"]) => {
            // Administrator status comes ONLY from the X-Admin-Token
            // header verified against IOD_ADMIN_TOKEN; any role in the
            // body is ignored.
            let token = request
                .headers()
                .iter()
                .find(|h| h.field.equiv("X-Admin-Token"))
                .map(|h| h.value.as_str().to_string());
            let body = read_body_json(request);
            let (Some(requested_by), Some(reason), Some(pid_hex)) = (
                str_field(&body, "requested_by"),
                str_field(&body, "reason"),
                str_field(&body, "target_pid_hex"),
            ) else {
                return err(400, "missing fields");
            };
            let Ok(target_pid) = hex::decode(pid_hex) else { return err(400, "target_pid_hex is not valid hex") };
            let mut s = state.lock().unwrap();
            let is_admin = s.admin.verify(token.as_deref());
            let s = &mut *s;
            let record = s.trace.request_trace(&s.gcs, is_admin, requested_by, reason, &target_pid);
            let _ = s.db.append_trace_record(&record);
            let status = if record.authorized { 200 } else if is_admin { 422 } else { 403 };
            json_response(status, serde_json::to_value(record).unwrap())
        }

        (Method::Get, ["api", "trace"]) => {
            let s = state.lock().unwrap();
            ok(json!({ "flags": s.trace.flags, "trace_records": s.trace.trace_records }))
        }

        _ => err(404, format!("no route for {method:?} {path}")),
    }
}
