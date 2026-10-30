//! Validated configuration for the image transport (environment-driven,
//! conservative defaults). See docs/stego-transport.md.

use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct StegoConfig {
    pub python_url: String,
    pub allow_nonloopback: bool,
    pub artifact_dir: String,
    pub camera_index: i64,
    pub capture_timeout_ms: u64,
    pub max_width: u32,
    pub max_height: u32,
    pub max_frame_bytes: usize,
    pub http_timeout_ms: u64,
    pub max_response_bytes: usize,
    /// Selector policy handed to the Python selector on every call.
    pub policy: Value,
}

impl Default for StegoConfig {
    fn default() -> Self {
        StegoConfig {
            python_url: "http://127.0.0.1:5001".into(),
            allow_nonloopback: false,
            artifact_dir: "./data/stego-artifacts".into(),
            camera_index: 0,
            capture_timeout_ms: 3000,
            max_width: 1920,
            max_height: 1080,
            max_frame_bytes: 65_536,
            http_timeout_ms: 20_000,
            max_response_bytes: 32 * 1024 * 1024,
            policy: json!({"version": "sel-policy-2", "max_mse": 4.0, "min_psnr_db": 40.0, "max_cost_units": 1000.0, "tie_epsilon": 0.01}),
        }
    }
}

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().parse::<T>().map_err(|_| format!("{name} has an invalid value")),
        _ => Ok(default),
    }
}

impl StegoConfig {
    pub fn from_env() -> Result<Self, String> {
        let d = StegoConfig::default();
        let c = StegoConfig {
            python_url: std::env::var("IOD_PYTHON_URL").ok().filter(|s| !s.trim().is_empty()).unwrap_or(d.python_url.clone()),
            allow_nonloopback: std::env::var("IOD_STEGO_ALLOW_NONLOOPBACK").map(|v| v == "1").unwrap_or(false),
            artifact_dir: std::env::var("IOD_STEGO_ARTIFACT_DIR").ok().filter(|s| !s.trim().is_empty()).unwrap_or(d.artifact_dir.clone()),
            camera_index: env_parse("IOD_STEGO_CAMERA_INDEX", d.camera_index)?,
            capture_timeout_ms: env_parse("IOD_STEGO_CAPTURE_TIMEOUT_MS", d.capture_timeout_ms)?,
            max_width: env_parse("IOD_STEGO_MAX_WIDTH", d.max_width)?,
            max_height: env_parse("IOD_STEGO_MAX_HEIGHT", d.max_height)?,
            max_frame_bytes: env_parse("IOD_STEGO_MAX_FRAME_BYTES", d.max_frame_bytes)?,
            http_timeout_ms: env_parse("IOD_STEGO_HTTP_TIMEOUT_MS", d.http_timeout_ms)?,
            max_response_bytes: d.max_response_bytes,
            policy: {
                let mut p = d.policy.clone();
                for (env, key) in [("IOD_STEGO_MAX_MSE", "max_mse"), ("IOD_STEGO_MIN_PSNR_DB", "min_psnr_db"), ("IOD_STEGO_MAX_COST_UNITS", "max_cost_units")] {
                    if let Ok(v) = std::env::var(env) {
                        p[key] = json!(v.trim().parse::<f64>().map_err(|_| format!("{env} must be a number"))?);
                    }
                }
                p
            },
        };
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(32..=4096).contains(&self.max_width) || !(32..=4096).contains(&self.max_height) {
            return Err("max image dimensions must be within 32..=4096".into());
        }
        if !(64..=1_048_576).contains(&self.max_frame_bytes) {
            return Err("IOD_STEGO_MAX_FRAME_BYTES must be within 64..=1048576".into());
        }
        if !(100..=120_000).contains(&self.capture_timeout_ms) || !(500..=300_000).contains(&self.http_timeout_ms) {
            return Err("timeouts out of range".into());
        }
        if !(0..=16).contains(&self.camera_index) {
            return Err("IOD_STEGO_CAMERA_INDEX must be within 0..=16".into());
        }
        if self.artifact_dir.contains('\0') || self.artifact_dir.trim().is_empty() {
            return Err("invalid artifact directory".into());
        }
        crate::transport::http::parse_base_url(&self.python_url, self.allow_nonloopback).map(|_| ())
    }

    /// Per-request limits object handed to Python (Rust is the single source of truth).
    pub fn limits(&self) -> Value {
        json!({
            "max_width": self.max_width, "max_height": self.max_height, "max_frame_bytes": self.max_frame_bytes,
            "capture_timeout_ms": self.capture_timeout_ms, "camera_index": self.camera_index,
        })
    }

    /// Public (non-sensitive) view; only the artifact directory *name* is exposed.
    pub fn public_view(&self) -> Value {
        let name = std::path::Path::new(&self.artifact_dir).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        json!({"limits": self.limits(), "policy": self.policy, "artifact_dir_name": name, "http_timeout_ms": self.http_timeout_ms})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_validate_and_bad_values_fail() {
        assert!(StegoConfig::default().validate().is_ok());
        let mut c = StegoConfig::default();
        c.max_frame_bytes = 10;
        assert!(c.validate().is_err());
        let mut c = StegoConfig::default();
        c.python_url = "https://example.com".into();
        assert!(c.validate().is_err());
        let mut c = StegoConfig::default();
        c.python_url = "http://example.com:80".into();
        assert!(c.validate().is_err(), "non-loopback needs explicit opt-in");
        c.allow_nonloopback = true;
        assert!(c.validate().is_ok());
    }
    #[test]
    fn public_view_hides_full_path() {
        let mut c = StegoConfig::default();
        c.artifact_dir = "/secret/place/artifacts".into();
        let v = c.public_view().to_string();
        assert!(v.contains("artifacts") && !v.contains("secret"));
    }
}
