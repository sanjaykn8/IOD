//! Report export (schema `stego-report-3`, patch-wise transport over generated covers): aggregates computed ONLY
//! from persisted events. Percentiles are reported as null when n < 20.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "stego-report-3";
pub const MIN_N_FOR_PERCENTILES: usize = 20;

pub const CSV_COLUMNS: &[&str] = &[
    "event_id", "ts_ms", "kind", "origin", "session_id", "direction", "seq", "from_role", "to_role", "transport_format_version",
    "segmentation_version", "selector_version", "kb_version", "refinement_level", "patch_count", "used_patches", "algorithms_used",
    "algorithm", "cover_source", "generator_version", "generator_profile", "cover_family", "seed_fingerprint", "cover_quality_score",
    "generation_candidates", "generation_budget_ms", "generation_used_ms", "generation_budget_exceeded", "requested_width", "requested_height",
    "cover_resized", "width", "height", "mode", "channels", "output_format",
    "wire_bytes", "payload_bytes", "manifest_bytes", "frame_bytes", "image_bytes", "mse", "psnr", "ssim", "success", "error_code",
    "error_stage", "artifact_id", "stego_sha256", "frame_sha256_prefix", "frame_match", "header_mac_ok", "aead_ok", "t_aead_seal_ms",
    "t_cover_generate_ms", "t_cover_prescreen_ms", "t_cover_selection_total_ms", "t_plan_ms", "t_load_cover_ms", "t_embed_ms", "t_save_ms", "t_read_ms", "t_extract_ms", "t_verify_ms", "t_aead_open_ms", "t_total_ms",
];

/// One CSV row per patch of every event that recorded a plan.
pub const PATCH_CSV_COLUMNS: &[&str] = &[
    "event_id", "patch_id", "used", "pixels", "usable_pixels", "gradient_mean", "variance", "entropy", "algorithm", "alg_id", "param",
    "payload_offset", "payload_length", "capacity_bytes", "kb_entry", "bm25", "query_terms", "ranking",
];

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = p * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo as f64)
}

pub fn stats(values: &[f64]) -> Value {
    let n = values.len();
    if n == 0 {
        return json!({"n": 0, "mean": null, "p50": null, "p95": null});
    }
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        return json!({"n": 0, "mean": null, "p50": null, "p95": null});
    }
    let mean = v.iter().sum::<f64>() / n as f64;
    let (p50, p95) = if n >= MIN_N_FOR_PERCENTILES { (json!(percentile(&v, 0.5)), json!(percentile(&v, 0.95))) } else { (Value::Null, Value::Null) };
    json!({"n": n, "mean": mean, "p50": p50, "p95": p95})
}

fn num(v: &Value, path: &[&str]) -> Option<f64> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    cur.as_f64()
}

pub fn build_report(events: &[Value], environment: Value, now_ms: i64) -> Value {
    let total = events.len();
    let ok = events.iter().filter(|e| e["success"].as_bool() == Some(true)).count();
    let mut error_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut families: BTreeMap<String, u64> = BTreeMap::new();
    let mut profiles: BTreeMap<String, u64> = BTreeMap::new();
    let mut gen_failures: BTreeMap<String, u64> = BTreeMap::new();
    let mut rejections: BTreeMap<String, u64> = BTreeMap::new();
    let (mut budget_exceeded, mut resized, mut covers_generated) = (0u64, 0u64, 0u64);
    let mut cover_sources: BTreeMap<String, u64> = BTreeMap::new();
    for e in events {
        if let Some(c) = e["error_code"].as_str() {
            *error_counts.entry(c.to_string()).or_default() += 1;
        }
        if let Some(f) = e["cover_family"].as_str() {
            *families.entry(f.to_string()).or_default() += 1;
        }
        if let Some(p) = e["generator_profile"].as_str() {
            *profiles.entry(p.to_string()).or_default() += 1;
        }
        if e["generation_budget_exceeded"].as_bool() == Some(true) {
            budget_exceeded += 1;
        }
        if e["cover_resized"].as_bool() == Some(true) {
            resized += 1;
        }
        covers_generated += e["covers_generated"].as_u64().unwrap_or(0);
        if let Some(c) = e["error_code"].as_str().filter(|c| GENERATION_ERRORS.contains(c)) {
            *gen_failures.entry(c.to_string()).or_default() += 1;
        }
        // why candidates were rejected by the quality pre-screen (successful and failed transmissions)
        for c in e["generation"]["candidates"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            for r in c["rejection_reasons"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                if let Some(r) = r.as_str() {
                    *rejections.entry(r.to_string()).or_default() += 1;
                }
            }
        }
        if let Some(s) = e["cover_source"].as_str() {
            *cover_sources.entry(s.to_string()).or_default() += 1;
        }
    }
    // per-algorithm usage: patches and payload bytes actually assigned (from the validated manifests)
    let mut per: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new(); // events, patches, bytes
    for e in events.iter().filter(|e| e["success"].as_bool() == Some(true)) {
        if let Some(m) = e["algorithms_used"].as_object() {
            for (alg, v) in m {
                let x = per.entry(alg.clone()).or_default();
                x.0 += 1;
                x.1 += v["patches"].as_u64().unwrap_or(0);
                x.2 += v["payload_bytes"].as_u64().unwrap_or(0);
            }
        }
    }
    let per_alg: Vec<Value> = per.iter().map(|(a, (ev, pa, by))| json!({"algorithm": a, "events": ev, "patches": pa, "payload_bytes": by})).collect();
    let succ: Vec<&Value> = events.iter().filter(|e| e["success"].as_bool() == Some(true)).collect();
    let col = |path: &[&str]| -> Vec<f64> { succ.iter().filter_map(|e| num(e, path)).collect() };
    let mut timings = Map::new();
    for stage in ["aead_seal", "cover_generate", "cover_prescreen", "cover_selection_total", "plan", "load_cover", "embed", "save", "read", "extract", "verify", "aead_open", "total"] {
        timings.insert(stage.to_string(), stats(&col(&["timings_ms", stage])));
    }
    let overall = json!({
        "n_ok": succ.len(),
        "patch_count": stats(&col(&["patch_count"])), "used_patches": stats(&col(&["used_patches"])),
        "refinement_level": stats(&col(&["refinement_level"])), "manifest_bytes": stats(&col(&["manifest_bytes"])),
        "frame_bytes": stats(&col(&["frame_bytes"])), "image_bytes": stats(&col(&["image_bytes"])),
        "mse": stats(&col(&["mse"])), "psnr": stats(&col(&["psnr"])), "ssim": stats(&col(&["ssim"])),
        "timings_ms": Value::Object(timings),
    });
    // Three different kinds of number that must not be confused:
    //  - cover_quality_score: heuristic coherence score of the generated cover BEFORE embedding;
    //  - mse / psnr / ssim: distortion between that cover and the stego image;
    //  - detector AUC: offline steganalysis evaluation (scripts/eval_detectability.py), never part of this report.
    let generation = json!({
        "covers_generated": covers_generated, "families": families, "profiles": profiles,
        "cover_quality_score": stats(&col(&["cover_quality_score"])),
        "candidates_per_transmission": stats(&col(&["generation_candidates"])),
        "generation_used_ms": stats(&col(&["generation_used_ms"])),
        "budget_exceeded_count": budget_exceeded, "payload_driven_resize_count": resized,
        "failures": gen_failures, "candidate_rejection_reasons": rejections,
        "metric_kinds": {"cover_quality_score": "heuristic coherence of the cover before embedding (not a steganalysis detector)",
                         "mse_psnr_ssim": "cover-versus-stego distortion", "detector_auc": "offline evaluation only; not measured here"},
    });
    json!({
        "schema": SCHEMA,
        "generated_ms": now_ms,
        "environment": environment,
        "totals": {"events": total, "ok": ok, "failed": total - ok, "cover_sources": cover_sources, "error_counts": error_counts},
        "overall": overall,
        "cover_generation": generation,
        "per_algorithm": per_alg,
        "limitations": [
            "Host-simulation measurements on one machine; not representative of drone hardware. A resource profile such as raspberry_pi_5_cpu enforces that device's LIMITS on this host; it does not reproduce its speed, and these figures are not Raspberry Pi measurements.",
            "Covers are procedurally generated images (no pretrained model). The cover quality score is a documented heuristic, not a steganalysis detector, and no generated cover or embedding is claimed to be undetectable.",
            "Percentiles are null when fewer than 20 successful samples exist for the series.",
            "PSNR/SSIM are null when undefined (e.g. identical images); they are never imputed.",
            "Lossless PNG handoff only; no robustness to JPEG/resizing/filtering is claimed.",
            "LSB-class methods are statistically detectable; no anti-steganalysis claim is made for any algorithm.",
            "Per-patch selection is a static knowledge-base lookup (structured filters + BM25); no learned model is involved.",
            "Algorithm names denote this repository's variants (e.g. additive HUGO approximation, custom STC matrices)."
        ],
    })
}

pub const GENERATION_ERRORS: [&str; 6] = ["COVER_GENERATION_FAILED", "COVER_QUALITY_REJECTED", "GENERATION_BUDGET_EXCEEDED",
                                           "PATCH_CAPACITY_INSUFFICIENT", "GENERATOR_CONFIG_INVALID", "GENERATOR_MEMORY_LIMIT"];

/// Where a measurement was taken (benchmarks and reports). Hardware model is read from the device
/// tree when present (Raspberry Pi OS), otherwise from /proc/cpuinfo; nothing is guessed.
pub fn host_metadata() -> Value {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let model = read("/proc/device-tree/model").map(|s| s.trim_matches(char::from(0)).trim().to_string()).filter(|s| !s.is_empty());
    let cpu = read("/proc/cpuinfo").and_then(|s| {
        s.lines().find(|l| l.starts_with("model name") || l.starts_with("Model") || l.starts_with("Hardware"))
            .and_then(|l| l.split(':').nth(1)).map(|v| v.trim().to_string())
    });
    let mem_kb = read("/proc/meminfo").and_then(|s| s.lines().find(|l| l.starts_with("MemTotal")).and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok())));
    let is_pi5 = model.as_deref().map(|m| m.contains("Raspberry Pi 5")).unwrap_or(false);
    json!({"os": std::env::consts::OS, "arch": std::env::consts::ARCH, "device_model": model, "cpu_model": cpu,
           "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).ok(), "mem_total_mb": mem_kb.map(|k| k / 1024),
           "is_raspberry_pi_5": is_pi5})
}

pub fn csv_cell(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    // Neutralise spreadsheet formula injection and quote when needed.
    let s = if matches!(s.chars().next(), Some('=') | Some('+') | Some('-') | Some('@')) && s.parse::<f64>().is_err() { format!("'{s}") } else { s };
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn patches_to_csv(events: &[Value]) -> String {
    let mut out = PATCH_CSV_COLUMNS.join(",");
    out.push('\n');
    for e in events {
        let Some(patches) = e["patches"].as_array() else { continue };
        for p in patches {
            let row: Vec<String> = PATCH_CSV_COLUMNS.iter().map(|c| {
                let v = if *c == "event_id" { e["event_id"].clone() } else { p.get(*c).cloned().unwrap_or(Value::Null) };
                csv_cell(&match v {
                    Value::Array(a) => Value::String(a.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(" ")),
                    other => other,
                })
            }).collect();
            out.push_str(&row.join(","));
            out.push('\n');
        }
    }
    out
}

pub fn events_to_csv(events: &[Value]) -> String {
    let mut out = CSV_COLUMNS.join(",");
    out.push('\n');
    for e in events {
        let row: Vec<String> = CSV_COLUMNS
            .iter()
            .map(|c| {
                let v = if let Some(stage) = c.strip_prefix("t_").and_then(|s| s.strip_suffix("_ms")) {
                    e["timings_ms"].get(stage).cloned().unwrap_or(Value::Null)
                } else if *c == "algorithms_used" {
                    match e["algorithms_used"].as_object() {
                        Some(m) => Value::String(m.iter().map(|(k, v)| format!("{k}:{}", v["patches"])).collect::<Vec<_>>().join(" ")),
                        None => Value::Null,
                    }
                } else {
                    e.get(*c).cloned().unwrap_or(Value::Null)
                };
                csv_cell(&v)
            })
            .collect();
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentiles_need_enough_samples() {
        assert_eq!(stats(&[1.0, 2.0, 3.0])["p95"], Value::Null);
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let s = stats(&v);
        assert_eq!(s["n"], 100);
        assert!((s["p50"].as_f64().unwrap() - 50.5).abs() < 1e-9);
        assert!((s["p95"].as_f64().unwrap() - 95.05).abs() < 1e-9);
        assert_eq!(stats(&[])["mean"], Value::Null);
    }
    #[test]
    fn report_counts_and_csv_safety() {
        let evs = vec![
            json!({"event_id":1,"success":true,"algorithm":"pvd","algorithms_used":{"pvd":{"patches":2,"payload_bytes":90},"dwt":{"patches":1,"payload_bytes":10}},
                   "patch_count":5,"used_patches":3,"frame_bytes":10,"psnr":60.0,"timings_ms":{"embed":2.0,"plan":4.0},"cover_source":"generated","cover_family":"terrain","generator_profile":"raspberry_pi_5_cpu","cover_quality_score":0.9,"covers_generated":1,"generation_candidates":2,
                   "generation":{"candidates":[{"rejection_reasons":["flat_block_fraction_above_0.25"]},{"rejection_reasons":[]}]},
                   "patches":[{"patch_id":0,"used":false},{"patch_id":1,"used":true,"algorithm":"pvd","payload_offset":0,"payload_length":50,"bm25":1.5,"query_terms":["textured","edge-rich"]}]}),
            json!({"success":false,"algorithm":"pvd","error_code":"FRAME_AUTH_FAILED"}),
            json!({"success":false,"error_code":"NO_ELIGIBLE_ALGORITHM","session_id":"=cmd|' /C calc'!A0"}),
        ];
        let r = build_report(&evs, json!({}), 1);
        assert_eq!(r["schema"], "stego-report-3");
        assert_eq!(r["totals"]["events"], 3);
        assert_eq!(r["totals"]["failed"], 2);
        assert_eq!(r["totals"]["cover_sources"]["generated"], 1);
        assert_eq!(r["cover_generation"]["families"]["terrain"], 1);
        assert_eq!(r["cover_generation"]["covers_generated"], 1);
        assert_eq!(r["cover_generation"]["candidate_rejection_reasons"]["flat_block_fraction_above_0.25"], 1);
        assert!(r.to_string().contains("not Raspberry Pi measurements") && !r.to_string().contains("fallback_cover"));
        assert_eq!(r["totals"]["error_counts"]["FRAME_AUTH_FAILED"], 1);
        assert_eq!(r["per_algorithm"][0]["algorithm"], "dwt");
        assert_eq!(r["per_algorithm"][1]["patches"], 2);
        assert_eq!(r["per_algorithm"][1]["payload_bytes"], 90);
        assert_eq!(r["overall"]["psnr"]["mean"], 60.0);
        assert_eq!(r["overall"]["timings_ms"]["plan"]["mean"], 4.0);
        assert!(!r.to_string().to_lowercase().contains("explain"));
        let pc = patches_to_csv(&evs);
        let pl: Vec<&str> = pc.lines().collect();
        assert_eq!(pl.len(), 3);
        assert!(pl[2].starts_with("1,1,true") && pl[2].contains("textured edge-rich"));
        assert_eq!(pl[0].split(',').count(), PATCH_CSV_COLUMNS.len());
        let csv = events_to_csv(&evs);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[3].contains("'=cmd"), "formula injection neutralised");
        assert_eq!(lines[0].split(',').count(), CSV_COLUMNS.len());
    }
}
