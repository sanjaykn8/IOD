//! Structured, stable error model for the image transport.
use serde_json::{json, Value};

/// Pipeline stages (used for the `stage` field of errors and the stage timeline).
pub mod stage {
    pub const PREPARE: &str = "prepare";
    pub const AEAD_SEAL: &str = "aead_seal";
    pub const SELECTOR: &str = "selector";
    pub const EMBED: &str = "embed";
    pub const SAVE: &str = "save";
    pub const READ: &str = "read";
    pub const EXTRACT: &str = "extract";
    pub const VERIFY: &str = "verify_frame";
    pub const AEAD_OPEN: &str = "aead_open";
    pub const EXPLAIN: &str = "explain";
}

#[derive(Debug, Clone)]
pub struct StegoError {
    pub code: String,
    pub message: String,
    pub stage: &'static str,
    pub http_status: u16,
    pub details: Option<Value>,
}

impl StegoError {
    pub fn new(code: &str, stage: &'static str, http_status: u16, message: impl Into<String>) -> Self {
        StegoError { code: code.to_string(), message: message.into(), stage, http_status, details: None }
    }
    pub fn with_details(mut self, d: Value) -> Self {
        self.details = Some(d);
        self
    }
    pub fn to_json(&self) -> Value {
        let mut v = json!({"code": self.code, "message": self.message, "stage": self.stage});
        if let Some(d) = &self.details {
            v["details"] = d.clone();
        }
        v
    }
}

impl std::fmt::Display for StegoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for StegoError {}

/// Map a Python-service error code onto an HTTP status for our API.
pub fn status_for_backend_code(code: &str) -> u16 {
    match code {
        "FRAME_TOO_LARGE" => 413,
        "NO_ELIGIBLE_ALGORITHM" | "ALGORITHM_NOT_ELIGIBLE" | "ENCODE_VERIFY_FAILED" | "EMBED_VERIFY_FAILED" => 422,
        "INVALID_REQUEST" | "IMAGE_TOO_LARGE" | "IMAGE_TOO_SMALL" | "UNSUPPORTED_IMAGE_MODE" => 400,
        "ARTIFACT_NOT_FOUND" => 404,
        "IMAGE_DECODE_ERROR" | "BOOTSTRAP_MISSING" | "BOOTSTRAP_CORRUPT" | "UNSUPPORTED_VERSION" | "UNKNOWN_ALGORITHM"
        | "FRAME_LENGTH_INVALID" | "EXTRACT_FAILED" => 422,
        _ => 502,
    }
}
