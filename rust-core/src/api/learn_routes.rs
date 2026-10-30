//! `/api/learn/*` -- EDUCATIONAL workbench routes. Completely separate from `/api/stego/*`:
//! no session, key, replay window, operational event or artifact is read or written here.

use crate::api::state::SimulationState;
use crate::api::stego_routes::{err_resp, hdr, json_resp, qparam, read_body_strict, Resp};
use crate::learn;
use crate::transport::backend::{is_artifact_id, ALGS};
use crate::transport::error::{stage, StegoError};
use serde_json::json;
use std::sync::Mutex;
use tiny_http::{Method, Response};

fn not_found() -> StegoError {
    StegoError::new("NOT_FOUND", stage::PREPARE, 404, "no such learning experiment")
}

pub fn handle(request: &mut tiny_http::Request, method: &Method, segs: &[&str], query: &str, state: &Mutex<SimulationState>) -> Resp {
    let rest = &segs[2..];
    let backend = || state.lock().unwrap().backend.clone();
    match (method, rest) {
        (Method::Get, ["registry"]) => match backend().learn_get("/learn/registry") {
            Ok(mut v) => {
                v["test_only_key_notice"] = json!("The 'readable message -> encryption' mode uses the production AEAD code path with a TEST-ONLY key derived from a public label.");
                json_resp(200, v)
            }
            Err(e) => err_resp(&e),
        },
        (Method::Get, ["walkthrough", alg]) => {
            if !ALGS.contains(alg) {
                return err_resp(&StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "unknown algorithm"));
            }
            match backend().learn_get(&format!("/learn/walkthrough/{alg}")) {
                Ok(v) => json_resp(200, v),
                Err(e) => err_resp(&e),
            }
        }
        (Method::Post, ["experiment"]) => {
            // optional uploaded sample cover (<= 512x512 PNG) -> ~1.5 MB base64
            let body = match read_body_strict(request, 3 * 1024 * 1024) { Ok(b) => b, Err(e) => return err_resp(&e) };
            match learn::run_experiment(state, &body) {
                Ok(v) => json_resp(200, v),
                Err(e) => err_resp(&e),
            }
        }
        (Method::Get, ["experiments"]) => {
            let limit = qparam(query, "limit").and_then(|v| v.parse::<i64>().ok()).unwrap_or(50);
            match state.lock().unwrap().db.list_learn_experiments(limit) {
                Ok(v) => json_resp(200, json!({"experiments": v, "label": learn::LABEL})),
                Err(e) => err_resp(&StegoError::new("INTERNAL_ERROR", stage::PREPARE, 500, &e.to_string())),
            }
        }
        (Method::Get, ["experiments", id]) | (Method::Get, ["experiments", id, "export"]) => {
            if !is_artifact_id(id) {
                return err_resp(&not_found());
            }
            let rec = match state.lock().unwrap().db.get_learn_experiment(id) {
                Ok(Some(r)) => r,
                Ok(None) => return err_resp(&not_found()),
                Err(e) => return err_resp(&StegoError::new("INTERNAL_ERROR", stage::PREPARE, 500, &e.to_string())),
            };
            let fmt = if rest.len() == 3 { qparam(query, "format").unwrap_or_else(|| "json".into()) } else { "json".into() };
            let (body, ctype, ext) = match fmt.as_str() {
                "csv" => (learn::to_csv(&rec), "text/csv; charset=utf-8", "csv"),
                "md" | "markdown" => (learn::to_markdown(&rec), "text/markdown; charset=utf-8", "md"),
                "json" => (serde_json::to_string_pretty(&rec).unwrap_or_default(), "application/json", "json"),
                _ => return err_resp(&StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, "format must be json, csv or md")),
            };
            let mut resp = Response::from_string(body).with_status_code(200)
                .with_header(hdr("Content-Type", ctype)).with_header(hdr("Access-Control-Allow-Origin", "*"));
            if rest.len() == 3 {
                resp = resp.with_header(hdr("Content-Disposition", &format!("attachment; filename=\"learn-{}.{}\"", &id[..12], ext)));
            }
            resp
        }
        _ => err_resp(&StegoError::new("NOT_FOUND", stage::PREPARE, 404, "unknown learning route")),
    }
}
