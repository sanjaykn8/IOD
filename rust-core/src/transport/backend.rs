//! The boundary to the image-processing service. Rust never sends keys or
//! plaintext through it: only the (already encrypted + MACed) frame bytes,
//! cover/policy parameters, artifact ids and finished selection reports.

use crate::transport::config::StegoConfig;
use crate::transport::error::StegoError;
use crate::transport::http::{self, BaseUrl};
use serde_json::Value;
use std::time::Duration;

/// Canonical algorithm names; the index + 1 is the wire `alg_id`.
pub const ALGS: [&str; 5] = ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"];

pub trait StegoBackend: Send + Sync {
    fn health(&self) -> Result<Value, StegoError>;
    fn camera_probe(&self, camera_index: i64, timeout_ms: u64) -> Result<Value, StegoError>;
    /// Validate and store a client-supplied PNG (browser webcam frame / uploaded image) as a cover artifact.
    fn cover_upload(&self, image_b64: &str, origin: &str, limits: &Value) -> Result<Value, StegoError>;
    /// Acquire + persist cover, run the deterministic selector (or validate a manual override).
    fn analyze(&self, req: &Value) -> Result<Value, StegoError>;
    /// Embed `frame_b64` into the saved cover with the chosen algorithm and save the PNG.
    fn encode(&self, req: &Value) -> Result<Value, StegoError>;
    /// Read the saved PNG identified by `artifact_id` and return the embedded frame.
    fn extract(&self, artifact_id: &str, limits: &Value) -> Result<Value, StegoError>;
    /// Explanation only; never influences the decision.
    fn explain(&self, selection_report: &Value) -> Result<Value, StegoError>;
}

pub struct HttpBackend {
    base: BaseUrl,
    timeout: Duration,
    max_resp: usize,
}

impl HttpBackend {
    pub fn new(cfg: &StegoConfig) -> Result<Self, String> {
        Ok(HttpBackend {
            base: http::parse_base_url(&cfg.python_url, cfg.allow_nonloopback)?,
            timeout: Duration::from_millis(cfg.http_timeout_ms),
            max_resp: cfg.max_response_bytes,
        })
    }
    fn post(&self, path: &str, body: &Value) -> Result<Value, StegoError> {
        http::call_json(&self.base, "POST", path, Some(body), self.timeout, self.max_resp)
    }
}

impl StegoBackend for HttpBackend {
    fn health(&self) -> Result<Value, StegoError> {
        http::call_json(&self.base, "GET", "/stego/health", None, Duration::from_millis(3000).min(self.timeout), self.max_resp)
    }
    fn camera_probe(&self, camera_index: i64, timeout_ms: u64) -> Result<Value, StegoError> {
        self.post("/stego/camera/probe", &serde_json::json!({"camera_index": camera_index, "timeout_s": timeout_ms as f64 / 1000.0}))
    }
    fn cover_upload(&self, image_b64: &str, origin: &str, limits: &Value) -> Result<Value, StegoError> {
        self.post("/stego/cover/upload", &serde_json::json!({"image_b64": image_b64, "origin": origin, "limits": limits}))
    }
    fn analyze(&self, req: &Value) -> Result<Value, StegoError> {
        self.post("/stego/analyze", req)
    }
    fn encode(&self, req: &Value) -> Result<Value, StegoError> {
        self.post("/stego/encode", req)
    }
    fn extract(&self, artifact_id: &str, limits: &Value) -> Result<Value, StegoError> {
        self.post("/stego/extract", &serde_json::json!({"artifact_id": artifact_id, "limits": limits}))
    }
    fn explain(&self, selection_report: &Value) -> Result<Value, StegoError> {
        // Explanation must never stall delivery: short dedicated timeout.
        http::call_json(&self.base, "POST", "/stego/explain", Some(selection_report), Duration::from_millis(5000).min(self.timeout), self.max_resp)
    }
}

pub fn is_artifact_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
