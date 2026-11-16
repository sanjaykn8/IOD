//! Validated configuration for the image transport (environment-driven,
//! conservative defaults). See docs/patchwise-transport.md and docs/development.md.

use crate::transport::generator::GeneratorConfig;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct StegoConfig {
    pub python_url: String,
    pub allow_nonloopback: bool,
    pub artifact_dir: String,
    pub max_width: u32,
    pub max_height: u32,
    pub max_frame_bytes: usize,
    pub http_timeout_ms: u64,
    pub max_response_bytes: usize,
    /// Segmentation overrides handed to the image service (empty object = its documented defaults).
    pub segmentation: Value,
    /// Preferred payload bytes per patch (drives how many patches a frame is spread over).
    pub target_chunk_bytes: usize,
    /// How many times the sender may re-plan with a coarser segmentation after a patch failed to embed.
    pub max_replans: u32,
    /// Process-level cover-generation configuration (profile + IOD_STEGO_GENERATOR_*). Requests may only tighten it.
    pub generator: GeneratorConfig,
}

impl Default for StegoConfig {
    fn default() -> Self {
        StegoConfig {
            python_url: "http://127.0.0.1:5001".into(),
            allow_nonloopback: false,
            artifact_dir: "./data/stego-artifacts".into(),
            max_width: 1920,
            max_height: 1080,
            max_frame_bytes: 65_536,
            http_timeout_ms: 20_000,
            max_response_bytes: 32 * 1024 * 1024,
            segmentation: json!({}),
            target_chunk_bytes: 48,
            max_replans: 2,
            generator: GeneratorConfig::profile(crate::transport::generator::DEFAULT_PROFILE).expect("default profile exists"),
        }
    }
}

/// (environment variable, segmentation setting, integer?) -- bounds are enforced in `validate`
/// and again by the image service.
const SEG_ENV: &[(&str, &str, bool)] = &[
    ("IOD_STEGO_SEG_CELL_SIZE", "cell_size", true),
    ("IOD_STEGO_SEG_MIN_REGION_PX", "min_region_px", true),
    ("IOD_STEGO_SEG_MAX_REGION_FRAC", "max_region_frac", false),
    ("IOD_STEGO_SEG_MAX_REGIONS", "max_regions", true),
    ("IOD_STEGO_SEG_W_INTENSITY", "w_intensity", false),
    ("IOD_STEGO_SEG_W_TEXTURE", "w_texture", false),
    ("IOD_STEGO_SEG_W_GRADIENT", "w_gradient", false),
    ("IOD_STEGO_SEG_W_COLOR", "w_color", false),
    ("IOD_STEGO_SEG_TAU_ITERATIONS", "tau_iterations", true),
    ("IOD_STEGO_SEG_MAX_REFINE_LEVELS", "max_refine_levels", true),
];
const SEG_BOUNDS: &[(&str, f64, f64)] = &[
    ("cell_size", 0.0, 16.0), ("min_region_px", 16.0, 1_048_576.0), ("max_region_frac", 0.05, 1.0), ("max_regions", 2.0, 255.0),
    ("w_intensity", 0.0, 10.0), ("w_texture", 0.0, 10.0), ("w_gradient", 0.0, 10.0), ("w_color", 0.0, 10.0),
    ("tau_iterations", 1.0, 12.0), ("max_refine_levels", 0.0, 6.0),
];

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
            max_width: env_parse("IOD_STEGO_MAX_WIDTH", d.max_width)?,
            max_height: env_parse("IOD_STEGO_MAX_HEIGHT", d.max_height)?,
            max_frame_bytes: env_parse("IOD_STEGO_MAX_FRAME_BYTES", d.max_frame_bytes)?,
            http_timeout_ms: env_parse("IOD_STEGO_HTTP_TIMEOUT_MS", d.http_timeout_ms)?,
            max_response_bytes: d.max_response_bytes,
            segmentation: {
                let mut seg = serde_json::Map::new();
                for (env, key, int) in SEG_ENV {
                    if let Ok(v) = std::env::var(env) {
                        let v = v.trim();
                        if v.is_empty() {
                            continue;
                        }
                        let n = v.parse::<f64>().map_err(|_| format!("{env} must be a number"))?;
                        seg.insert(key.to_string(), if *int { json!(n as i64) } else { json!(n) });
                    }
                }
                Value::Object(seg)
            },
            target_chunk_bytes: env_parse("IOD_STEGO_TARGET_CHUNK_BYTES", d.target_chunk_bytes)?,
            max_replans: env_parse("IOD_STEGO_MAX_REPLANS", d.max_replans)?,
            generator: GeneratorConfig::from_env()?,
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
        if !(500..=300_000).contains(&self.http_timeout_ms) {
            return Err("timeouts out of range".into());
        }
        self.generator.validate().map_err(|e| format!("generator configuration: {}", e.message))?;
        if self.generator.max_width > self.max_width || self.generator.max_height > self.max_height {
            return Err("generator max dimensions exceed IOD_STEGO_MAX_WIDTH / IOD_STEGO_MAX_HEIGHT".into());
        }
        if !(8..=65_536).contains(&self.target_chunk_bytes) {
            return Err("IOD_STEGO_TARGET_CHUNK_BYTES must be within 8..=65536".into());
        }
        if self.max_replans > 6 {
            return Err("IOD_STEGO_MAX_REPLANS must be within 0..=6".into());
        }
        let seg = self.segmentation.as_object().ok_or("segmentation settings must be an object")?;
        for (k, v) in seg {
            let (_, lo, hi) = SEG_BOUNDS.iter().find(|(n, _, _)| n == k).ok_or_else(|| format!("unknown segmentation setting '{k}'"))?;
            let x = v.as_f64().ok_or_else(|| format!("segmentation.{k} must be a number"))?;
            if !(*lo..=*hi).contains(&x) || (k == "cell_size" && ![0.0, 4.0, 8.0, 16.0].contains(&x)) {
                return Err(format!("segmentation.{k} out of range"));
            }
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
        })
    }

    /// Public (non-sensitive) view; only the artifact directory *name* is exposed.
    pub fn public_view(&self) -> Value {
        let name = std::path::Path::new(&self.artifact_dir).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        json!({"limits": self.limits(), "segmentation_overrides": self.segmentation, "target_chunk_bytes": self.target_chunk_bytes,
               "max_replans": self.max_replans, "artifact_dir_name": name, "http_timeout_ms": self.http_timeout_ms,
               "cover_generation": self.generator.public_view()})
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
    fn segmentation_overrides_are_bounded() {
        let mut c = StegoConfig::default();
        c.segmentation = json!({"min_region_px": 512, "max_regions": 40, "w_color": 0.25});
        assert!(c.validate().is_ok());
        for bad in [json!({"max_regions": 999}), json!({"cell_size": 5}), json!({"nope": 1}), json!({"w_color": "x"}), json!([1])] {
            c.segmentation = bad;
            assert!(c.validate().is_err());
        }
        let mut c = StegoConfig::default();
        c.target_chunk_bytes = 1;
        assert!(c.validate().is_err());
        let mut c = StegoConfig::default();
        c.max_replans = 99;
        assert!(c.validate().is_err());
        assert!(!StegoConfig::default().public_view().to_string().contains("policy"));
    }
    #[test]
    fn public_view_hides_full_path() {
        let mut c = StegoConfig::default();
        c.artifact_dir = "/secret/place/artifacts".into();
        let v = c.public_view().to_string();
        assert!(v.contains("artifacts") && !v.contains("secret"));
    }
}
