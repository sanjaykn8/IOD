//! The boundary to the image-processing service. Rust never sends keys or
//! plaintext through it: only the payload LENGTH and the validated cover-generation
//! configuration (for planning), the already encrypted + MACed frame bytes (for embedding)
//! and artifact ids. There is no camera and no cover upload: every cover is generated locally
//! by the image service.

use crate::transport::config::StegoConfig;
use crate::transport::error::StegoError;
use crate::transport::http::{self, BaseUrl};
use serde_json::Value;
use std::time::Duration;

/// Canonical algorithm names; the index + 1 is the `alg_id` used in the patch manifest (stable).
pub const ALGS: [&str; 10] = [
    "lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct",
    "dwt", "dct_svd", "hugo", "wow", "s_uniward",
];

pub trait StegoBackend: Send + Sync {
    fn health(&self) -> Result<Value, StegoError>;
    /// New transmission (`cover_generation` present): generate a fresh payload-aware cover, persist
    /// it, segment it, select one algorithm per patch from the static knowledge base (structured
    /// filters + BM25) and allocate the payload. Re-plan (`replan_cover_id` present): plan again on
    /// that stored cover WITHOUT generating. Returns the manifest.
    fn plan(&self, req: &Value) -> Result<Value, StegoError>;
    /// Embed the authenticated Frame v2 into the planned cover exactly as its manifest says; save the PNG.
    fn encode(&self, req: &Value) -> Result<Value, StegoError>;
    /// Read the saved PNG identified by `artifact_id` and return the reconstructed (unverified) frame.
    fn extract(&self, artifact_id: &str, limits: &Value) -> Result<Value, StegoError>;
    /// The static algorithm knowledge base (inspection only).
    fn kb(&self) -> Result<Value, StegoError>;
    /// EDUCATIONAL workbench only (`/learn/*` namespace of the image service).
    fn learn_get(&self, path: &str) -> Result<Value, StegoError>;
    fn learn_post(&self, path: &str, body: &Value) -> Result<Value, StegoError>;
}

/// Paths the learning workbench may call (nothing else is reachable through learn_*).
pub fn learn_path_allowed(path: &str) -> bool {
    path == "/learn/registry" || path == "/learn/experiment"
        || path.strip_prefix("/learn/walkthrough/").map(|a| ALGS.contains(&a)).unwrap_or(false)
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
    fn plan(&self, req: &Value) -> Result<Value, StegoError> {
        self.post("/stego/plan", req)
    }
    fn encode(&self, req: &Value) -> Result<Value, StegoError> {
        self.post("/stego/encode", req)
    }
    fn extract(&self, artifact_id: &str, limits: &Value) -> Result<Value, StegoError> {
        self.post("/stego/extract", &serde_json::json!({"artifact_id": artifact_id, "limits": limits}))
    }
    fn kb(&self) -> Result<Value, StegoError> {
        http::call_json(&self.base, "GET", "/stego/kb", None, self.timeout, self.max_resp)
    }
    fn learn_get(&self, path: &str) -> Result<Value, StegoError> {
        if !learn_path_allowed(path) {
            return Err(StegoError::new("INVALID_REQUEST", "prepare", 400, "learn path not allowed"));
        }
        http::call_json(&self.base, "GET", path, None, self.timeout, self.max_resp)
    }
    fn learn_post(&self, path: &str, body: &Value) -> Result<Value, StegoError> {
        if !learn_path_allowed(path) {
            return Err(StegoError::new("INVALID_REQUEST", "prepare", 400, "learn path not allowed"));
        }
        // comparisons with the robustness suite run ten algorithms x eleven attacks
        http::call_json(&self.base, "POST", path, Some(body), Duration::from_secs(180).max(self.timeout), self.max_resp)
    }
}

pub fn is_artifact_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
