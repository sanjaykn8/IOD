//! Cover-generation configuration (docs/patchwise-transport.md section 2a).
//!
//! The operational cover of every transmission is generated locally by the image service; the only
//! thing a client can influence is this validated configuration. Three layers, each of which can only
//! TIGHTEN the one above it:
//!
//! ```text
//! hard ceilings (constants)  >  process configuration (profile + IOD_STEGO_GENERATOR_*)  >  request `cover_generation`
//! ```
//!
//! The same names and bounds are implemented in `python-service/src/stego/generator/profile.py`; the
//! image service validates the effective configuration again. A request can never select a seed, a
//! file, an artifact, a cover source or an algorithm.
//!
//! `raspberry_pi_5_cpu` is a conservative RESOURCE profile for a CPU-only Raspberry Pi 5. On any other
//! machine it applies the same limits but does not reproduce Raspberry Pi execution speed.

use crate::transport::error::{stage, StegoError};
use serde_json::{json, Map, Value};

pub const DEFAULT_PROFILE: &str = "raspberry_pi_5_cpu";
pub const FAMILIES: [&str; 4] = ["terrain", "clouds", "strata", "cells"];
pub const REQUEST_FIELDS: [&str; 15] = [
    "profile", "width", "height", "max_width", "max_height", "max_candidates", "processing_budget_ms", "max_pixels",
    "max_working_memory_mb", "min_quality_score", "max_embedding_rate", "allow_payload_driven_resize", "families", "workers", "mode",
];

pub mod hard {
    pub const MIN_DIM: u32 = 96;
    pub const MAX_WIDTH: u32 = 1920;
    pub const MAX_HEIGHT: u32 = 1080;
    pub const MAX_PIXELS: u64 = 1920 * 1080;
    pub const MAX_CANDIDATES: u32 = 8;
    pub const MIN_BUDGET_MS: u32 = 200;
    pub const MAX_BUDGET_MS: u32 = 30_000;
    pub const MIN_MEMORY_MB: u32 = 16;
    pub const MAX_MEMORY_MB: u32 = 1024;
    pub const MAX_WORKERS: u32 = 1;
    pub const MIN_EMBED_RATE: f64 = 0.001;
    pub const MAX_EMBED_RATE: f64 = 1.0;
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeneratorConfig {
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
    pub max_candidates: u32,
    pub processing_budget_ms: u32,
    pub max_working_memory_mb: u32,
    pub min_quality_score: f64,
    pub max_embedding_rate: f64,
    pub allow_payload_driven_resize: bool,
    pub workers: u32,
    pub mode: String,
    pub families: Vec<String>,
}

fn invalid(msg: impl Into<String>) -> StegoError {
    StegoError::new("GENERATOR_CONFIG_INVALID", stage::PREPARE, 400, msg)
}

fn all_families() -> Vec<String> {
    FAMILIES.iter().map(|s| s.to_string()).collect()
}

impl GeneratorConfig {
    pub fn profile(name: &str) -> Option<Self> {
        match name {
            "raspberry_pi_5_cpu" => Some(GeneratorConfig {
                profile: name.into(), width: 320, height: 240, max_width: 640, max_height: 480, max_pixels: 640 * 480,
                max_candidates: 2, processing_budget_ms: 2500, max_working_memory_mb: 96, min_quality_score: 0.70,
                max_embedding_rate: 0.20, allow_payload_driven_resize: false, workers: 1, mode: "RGB".into(), families: all_families(),
            }),
            // larger ceilings for development machines; never the default
            "development_host" => Some(GeneratorConfig {
                profile: name.into(), width: 480, height: 360, max_width: 1280, max_height: 960, max_pixels: 1280 * 960,
                max_candidates: 4, processing_budget_ms: 8000, max_working_memory_mb: 512, min_quality_score: 0.70,
                max_embedding_rate: 0.20, allow_payload_driven_resize: false, workers: 1, mode: "RGB".into(), families: all_families(),
            }),
            _ => None,
        }
    }

    /// Bounds that hold for every configuration (process or request).
    pub fn validate(&self) -> Result<(), StegoError> {
        let rng = |name: &str, v: u64, lo: u64, hi: u64| {
            if v < lo || v > hi { Err(invalid(format!("{name} must be within {lo}..={hi}"))) } else { Ok(()) }
        };
        rng("max_width", self.max_width as u64, hard::MIN_DIM as u64, hard::MAX_WIDTH as u64)?;
        rng("max_height", self.max_height as u64, hard::MIN_DIM as u64, hard::MAX_HEIGHT as u64)?;
        rng("max_pixels", self.max_pixels, (hard::MIN_DIM as u64).pow(2), hard::MAX_PIXELS)?;
        rng("width", self.width as u64, hard::MIN_DIM as u64, self.max_width as u64)?;
        rng("height", self.height as u64, hard::MIN_DIM as u64, self.max_height as u64)?;
        if self.width as u64 * self.height as u64 > self.max_pixels {
            return Err(invalid("width x height exceeds max_pixels"));
        }
        if self.width % 8 != 0 || self.height % 8 != 0 {
            return Err(invalid("width and height must be multiples of 8"));
        }
        rng("max_candidates", self.max_candidates as u64, 1, hard::MAX_CANDIDATES as u64)?;
        rng("processing_budget_ms", self.processing_budget_ms as u64, hard::MIN_BUDGET_MS as u64, hard::MAX_BUDGET_MS as u64)?;
        rng("max_working_memory_mb", self.max_working_memory_mb as u64, hard::MIN_MEMORY_MB as u64, hard::MAX_MEMORY_MB as u64)?;
        rng("workers", self.workers as u64, 1, hard::MAX_WORKERS as u64)?;
        if !(0.0..=1.0).contains(&self.min_quality_score) {
            return Err(invalid("min_quality_score must be within 0..=1"));
        }
        if !(hard::MIN_EMBED_RATE..=hard::MAX_EMBED_RATE).contains(&self.max_embedding_rate) {
            return Err(invalid("max_embedding_rate must be within 0.001..=1 (payload bits per cover sample)"));
        }
        if self.mode != "RGB" && self.mode != "L" {
            return Err(invalid("mode must be RGB or L"));
        }
        let mut seen: Vec<&str> = Vec::new();
        for f in &self.families {
            if !FAMILIES.contains(&f.as_str()) || seen.contains(&f.as_str()) {
                return Err(invalid("families must be distinct names out of terrain, clouds, strata, cells"));
            }
            seen.push(f);
        }
        if self.families.is_empty() {
            return Err(invalid("at least one generator family must be enabled"));
        }
        Ok(())
    }

    /// Profile defaults overridden by `IOD_STEGO_GENERATOR_*` (validated against the hard ceilings).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let val = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let name = val("IOD_STEGO_GENERATOR_PROFILE").unwrap_or_else(|| DEFAULT_PROFILE.to_string());
        let mut c = Self::profile(&name).ok_or_else(|| format!("IOD_STEGO_GENERATOR_PROFILE: unknown profile '{name}'"))?;
        fn num<T: std::str::FromStr>(k: &str, v: Option<String>, slot: &mut T) -> Result<(), String> {
            if let Some(v) = v {
                *slot = v.parse::<T>().map_err(|_| format!("{k} has an invalid value"))?;
            }
            Ok(())
        }
        num("IOD_STEGO_GENERATOR_WIDTH", val("IOD_STEGO_GENERATOR_WIDTH"), &mut c.width)?;
        num("IOD_STEGO_GENERATOR_HEIGHT", val("IOD_STEGO_GENERATOR_HEIGHT"), &mut c.height)?;
        num("IOD_STEGO_GENERATOR_MAX_WIDTH", val("IOD_STEGO_GENERATOR_MAX_WIDTH"), &mut c.max_width)?;
        num("IOD_STEGO_GENERATOR_MAX_HEIGHT", val("IOD_STEGO_GENERATOR_MAX_HEIGHT"), &mut c.max_height)?;
        num("IOD_STEGO_GENERATOR_MAX_PIXELS", val("IOD_STEGO_GENERATOR_MAX_PIXELS"), &mut c.max_pixels)?;
        num("IOD_STEGO_GENERATOR_MAX_CANDIDATES", val("IOD_STEGO_GENERATOR_MAX_CANDIDATES"), &mut c.max_candidates)?;
        num("IOD_STEGO_GENERATOR_BUDGET_MS", val("IOD_STEGO_GENERATOR_BUDGET_MS"), &mut c.processing_budget_ms)?;
        num("IOD_STEGO_GENERATOR_MAX_MEMORY_MB", val("IOD_STEGO_GENERATOR_MAX_MEMORY_MB"), &mut c.max_working_memory_mb)?;
        num("IOD_STEGO_GENERATOR_MIN_QUALITY", val("IOD_STEGO_GENERATOR_MIN_QUALITY"), &mut c.min_quality_score)?;
        num("IOD_STEGO_GENERATOR_MAX_EMBED_RATE", val("IOD_STEGO_GENERATOR_MAX_EMBED_RATE"), &mut c.max_embedding_rate)?;
        num("IOD_STEGO_GENERATOR_WORKERS", val("IOD_STEGO_GENERATOR_WORKERS"), &mut c.workers)?;
        if let Some(v) = val("IOD_STEGO_GENERATOR_ALLOW_RESIZE") {
            c.allow_payload_driven_resize = match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => return Err("IOD_STEGO_GENERATOR_ALLOW_RESIZE must be true or false".into()),
            };
        }
        if let Some(v) = val("IOD_STEGO_GENERATOR_MODE") {
            c.mode = v.to_ascii_uppercase();
        }
        if let Some(v) = val("IOD_STEGO_GENERATOR_FAMILIES") {
            c.families = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        c.validate().map_err(|e| format!("generator configuration: {}", e.message))?;
        Ok(c)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "profile": self.profile, "width": self.width, "height": self.height, "max_width": self.max_width, "max_height": self.max_height,
            "max_pixels": self.max_pixels, "max_candidates": self.max_candidates, "processing_budget_ms": self.processing_budget_ms,
            "max_working_memory_mb": self.max_working_memory_mb, "min_quality_score": self.min_quality_score,
            "max_embedding_rate": self.max_embedding_rate, "allow_payload_driven_resize": self.allow_payload_driven_resize,
            "workers": self.workers, "mode": self.mode, "families": self.families,
        })
    }

    /// Non-secret description for `/api/stego/status` and the dashboard.
    pub fn public_view(&self) -> Value {
        json!({
            "active_profile": self.profile, "effective": self.to_json(), "request_fields": REQUEST_FIELDS,
            "hard_ceilings": {"min_dim": hard::MIN_DIM, "max_width": hard::MAX_WIDTH, "max_height": hard::MAX_HEIGHT, "max_pixels": hard::MAX_PIXELS,
                              "max_candidates": hard::MAX_CANDIDATES, "min_budget_ms": hard::MIN_BUDGET_MS, "max_budget_ms": hard::MAX_BUDGET_MS,
                              "min_memory_mb": hard::MIN_MEMORY_MB, "max_memory_mb": hard::MAX_MEMORY_MB, "max_workers": hard::MAX_WORKERS},
            "note": "resource profile only: limits are enforced, hardware speed is not emulated",
        })
    }

    /// Effective configuration for one request (`None`/`null`/missing fields -> process defaults).
    /// Tightening only; unknown fields are rejected.
    pub fn resolve(&self, request: Option<&Value>) -> Result<GeneratorConfig, StegoError> {
        let obj: &Map<String, Value> = match request {
            None | Some(Value::Null) => return Ok(self.clone()),
            Some(Value::Object(m)) => m,
            Some(_) => return Err(invalid("cover_generation must be an object")),
        };
        if let Some(k) = obj.keys().find(|k| !REQUEST_FIELDS.contains(&k.as_str())) {
            return Err(invalid(format!("unknown cover_generation field '{k}': a request cannot choose a seed, file, artifact, source or algorithm")));
        }
        let get = |k: &str| obj.get(k).filter(|v| !v.is_null());
        let uint = |k: &str| -> Result<Option<u64>, StegoError> {
            match get(k) {
                None => Ok(None),
                Some(v) => v.as_u64().filter(|_| v.is_u64()).map(Some).ok_or_else(|| invalid(format!("{k} must be a non-negative integer"))),
            }
        };
        let mut c = self.clone();
        if let Some(p) = get("profile") {
            if p.as_str() != Some(self.profile.as_str()) {
                return Err(invalid(format!("profile differs from the active process profile '{}' (a request cannot switch profiles)", self.profile)));
            }
        }
        // ceilings: may only go down
        macro_rules! lower {
            ($field:ident, $key:literal, $ty:ty) => {
                if let Some(v) = uint($key)? {
                    if v > self.$field as u64 {
                        return Err(invalid(format!("{} cannot be raised above the configured limit of {}", $key, self.$field)));
                    }
                    c.$field = v as $ty;
                }
            };
        }
        lower!(max_width, "max_width", u32);
        lower!(max_height, "max_height", u32);
        lower!(max_pixels, "max_pixels", u64);
        lower!(max_candidates, "max_candidates", u32);
        lower!(processing_budget_ms, "processing_budget_ms", u32);
        lower!(max_working_memory_mb, "max_working_memory_mb", u32);
        if let Some(v) = uint("width")? {
            c.width = u32::try_from(v).map_err(|_| invalid("width out of range"))?;
        }
        if let Some(v) = uint("height")? {
            c.height = u32::try_from(v).map_err(|_| invalid("height out of range"))?;
        }
        if let Some(v) = uint("workers")? {
            c.workers = u32::try_from(v).map_err(|_| invalid("workers out of range"))?;
        }
        if let Some(v) = get("min_quality_score") {
            let q = v.as_f64().ok_or_else(|| invalid("min_quality_score must be a number"))?;
            if q < self.min_quality_score {
                return Err(invalid(format!("min_quality_score cannot be lowered below the configured floor of {}", self.min_quality_score)));
            }
            c.min_quality_score = q;
        }
        if let Some(v) = get("max_embedding_rate") {
            let e = v.as_f64().ok_or_else(|| invalid("max_embedding_rate must be a number"))?;
            if e > self.max_embedding_rate {
                return Err(invalid(format!("max_embedding_rate cannot be raised above the configured limit of {}", self.max_embedding_rate)));
            }
            c.max_embedding_rate = e;
        }
        if let Some(v) = get("allow_payload_driven_resize") {
            c.allow_payload_driven_resize = v.as_bool().ok_or_else(|| invalid("allow_payload_driven_resize must be a boolean"))?;
        }
        if let Some(v) = get("mode") {
            c.mode = v.as_str().ok_or_else(|| invalid("mode must be a string"))?.to_string();
        }
        if let Some(v) = get("families") {
            let arr = v.as_array().ok_or_else(|| invalid("families must be an array of family names"))?;
            let mut want: Vec<String> = Vec::new();
            for f in arr {
                let f = f.as_str().ok_or_else(|| invalid("families must be an array of family names"))?;
                if !self.families.iter().any(|x| x == f) {
                    return Err(invalid(format!("family '{f}' is not enabled")));
                }
                want.push(f.to_string());
            }
            // canonical order = order of the process configuration
            c.families = self.families.iter().filter(|f| want.contains(f)).cloned().collect();
        }
        c.validate()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pi() -> GeneratorConfig {
        GeneratorConfig::profile(DEFAULT_PROFILE).unwrap()
    }

    #[test]
    fn raspberry_pi_defaults_match_the_documented_profile() {
        let c = pi();
        assert_eq!((c.width, c.height, c.max_width, c.max_height), (320, 240, 640, 480));
        assert_eq!((c.max_candidates, c.processing_budget_ms, c.max_pixels, c.max_working_memory_mb, c.workers), (2, 2500, 307_200, 96, 1));
        assert_eq!(c.mode, "RGB");
        assert!(!c.allow_payload_driven_resize);
        assert_eq!(c.families, all_families());
        assert_eq!((c.min_quality_score, c.max_embedding_rate), (0.70, 0.20));
        c.validate().unwrap();
        GeneratorConfig::profile("development_host").unwrap().validate().unwrap();
        assert!(GeneratorConfig::profile("gpu").is_none());
        assert_eq!(c.resolve(None).unwrap(), c);
        assert_eq!(c.resolve(Some(&json!({}))).unwrap(), c);
        assert_eq!(c.resolve(Some(&Value::Null)).unwrap(), c);
    }

    #[test]
    fn requests_can_only_tighten() {
        let c = pi();
        let r = c.resolve(Some(&json!({"profile": "raspberry_pi_5_cpu", "width": 480, "height": 360, "max_candidates": 1, "processing_budget_ms": 1000,
            "max_width": 480, "max_height": 360, "min_quality_score": 0.9, "families": ["cells", "terrain"], "allow_payload_driven_resize": true,
            "max_embedding_rate": 0.05, "max_working_memory_mb": 64, "mode": "L"}))).unwrap();
        assert_eq!((r.width, r.height, r.max_candidates, r.processing_budget_ms, r.max_width), (480, 360, 1, 1000, 480));
        assert_eq!(r.families, vec!["terrain".to_string(), "cells".to_string()]);
        assert!(r.allow_payload_driven_resize && r.mode == "L" && r.min_quality_score == 0.9 && r.max_embedding_rate == 0.05);
        for bad in [
            json!({"max_candidates": 3}), json!({"processing_budget_ms": 2501}), json!({"max_width": 641}), json!({"max_height": 481}),
            json!({"max_pixels": 307201}), json!({"max_working_memory_mb": 97}), json!({"min_quality_score": 0.5}), json!({"max_embedding_rate": 0.21}),
            json!({"width": 648}), json!({"height": 488}), json!({"width": 640, "height": 480, "max_pixels": 100000}), json!({"workers": 2}),
            json!({"profile": "development_host"}), json!({"families": ["terrain", "plasma"]}), json!({"families": []}),
        ] {
            assert_eq!(c.resolve(Some(&bad)).unwrap_err().code, "GENERATOR_CONFIG_INVALID", "{bad}");
        }
    }

    #[test]
    fn seeds_files_artifacts_sources_and_algorithms_cannot_be_requested() {
        let c = pi();
        for bad in [
            json!({"seed": "abc"}), json!({"seed_hex": "00"}), json!({"cover_id": "a"}), json!({"test_cover_id": "a"}), json!({"source": "webcam"}),
            json!({"image_b64": "AAAA"}), json!({"file": "x.png"}), json!({"algorithm": "pvd"}), json!({"family": "terrain"}), json!({"camera_index": 0}),
            json!({"width": "320"}), json!({"width": 320.5}), json!({"width": -8}), json!({"width": 0}), json!({"width": 100}), json!({"height": 90}),
            json!({"max_candidates": 0}), json!({"processing_budget_ms": 10}), json!({"allow_payload_driven_resize": "yes"}), json!({"mode": "CMYK"}),
            json!({"min_quality_score": 2}), json!({"max_embedding_rate": 0}), json!([]), json!("pi"), json!(5),
        ] {
            let e = c.resolve(Some(&bad)).unwrap_err();
            assert_eq!(e.code, "GENERATOR_CONFIG_INVALID", "{bad}");
            assert_eq!(e.http_status, 400);
        }
    }

    #[test]
    fn environment_overrides_are_bounded_by_the_hard_ceilings() {
        let env = |pairs: &[(&str, &str)]| {
            let v: Vec<(String, String)> = pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
            GeneratorConfig::from_lookup(move |k| v.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone()))
        };
        let c = env(&[("IOD_STEGO_GENERATOR_WIDTH", "480"), ("IOD_STEGO_GENERATOR_HEIGHT", "360"), ("IOD_STEGO_GENERATOR_MAX_CANDIDATES", "3"),
                      ("IOD_STEGO_GENERATOR_BUDGET_MS", "4000"), ("IOD_STEGO_GENERATOR_FAMILIES", "terrain, cells"), ("IOD_STEGO_GENERATOR_ALLOW_RESIZE", "true"),
                      ("IOD_STEGO_GENERATOR_MIN_QUALITY", "0.8"), ("IOD_STEGO_GENERATOR_MODE", "l")]).unwrap();
        assert_eq!((c.width, c.height, c.max_candidates, c.processing_budget_ms), (480, 360, 3, 4000));
        assert!(c.allow_payload_driven_resize && c.mode == "L" && c.families.len() == 2);
        assert_eq!(env(&[("IOD_STEGO_GENERATOR_PROFILE", "development_host")]).unwrap().max_width, 1280);
        assert_eq!(env(&[]).unwrap(), pi());
        for bad in [
            ("IOD_STEGO_GENERATOR_PROFILE", "gpu_cluster"), ("IOD_STEGO_GENERATOR_MAX_WIDTH", "5000"), ("IOD_STEGO_GENERATOR_MAX_CANDIDATES", "9"),
            ("IOD_STEGO_GENERATOR_BUDGET_MS", "60000"), ("IOD_STEGO_GENERATOR_BUDGET_MS", "abc"), ("IOD_STEGO_GENERATOR_WORKERS", "4"),
            ("IOD_STEGO_GENERATOR_MAX_MEMORY_MB", "4096"), ("IOD_STEGO_GENERATOR_FAMILIES", "terrain,gan"), ("IOD_STEGO_GENERATOR_WIDTH", "324"),
            ("IOD_STEGO_GENERATOR_WIDTH", "800"), ("IOD_STEGO_GENERATOR_ALLOW_RESIZE", "maybe"), ("IOD_STEGO_GENERATOR_MAX_EMBED_RATE", "3"),
            ("IOD_STEGO_GENERATOR_MAX_PIXELS", "99999999"),
        ] {
            assert!(env(&[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn public_view_has_no_seed_or_secret() {
        let v = pi().public_view().to_string();
        assert!(v.contains("raspberry_pi_5_cpu") && v.contains("hardware speed is not emulated"));
        assert!(!v.contains("\"seed\""));
    }
}
