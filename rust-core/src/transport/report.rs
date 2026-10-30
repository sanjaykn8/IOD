//! Report export (schema `stego-report-1`): aggregates computed ONLY from
//! persisted events. Percentiles are reported as null when n < 20.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "stego-report-1";
pub const MIN_N_FOR_PERCENTILES: usize = 20;

pub const CSV_COLUMNS: &[&str] = &[
    "event_id", "ts_ms", "kind", "origin", "session_id", "direction", "seq", "from_role", "to_role", "transport_format_version",
    "algorithm", "param", "selection_policy_version", "selection_mode", "selection_reason_code", "explanation_status", "cover_source",
    "cover_fallback_reason", "width", "height", "mode", "channels", "output_format", "frame_bytes", "wire_bytes", "image_bytes",
    "capacity_bytes", "capacity_margin_bytes", "mse", "psnr", "ssim", "success", "error_code", "error_stage", "artifact_id",
    "stego_sha256", "frame_sha256_prefix", "frame_match", "header_mac_ok", "aead_ok", "t_aead_seal_ms", "t_capture_ms", "t_select_ms",
    "t_embed_ms", "t_save_ms", "t_read_ms", "t_extract_ms", "t_verify_ms", "t_aead_open_ms", "t_explain_ms", "t_total_ms",
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
    let mut fallback_cover = 0u64;
    let mut cover_sources: BTreeMap<String, u64> = BTreeMap::new();
    for e in events {
        if let Some(c) = e["error_code"].as_str() {
            *error_counts.entry(c.to_string()).or_default() += 1;
        }
        if e["cover_fallback_reason"].as_str().is_some() {
            fallback_cover += 1;
        }
        if let Some(s) = e["cover_source"].as_str() {
            *cover_sources.entry(s.to_string()).or_default() += 1;
        }
    }
    let mut by_alg: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for e in events {
        if let Some(a) = e["algorithm"].as_str() {
            by_alg.entry(a.to_string()).or_default().push(e);
        }
    }
    let mut per_alg = Vec::new();
    for (alg, evs) in &by_alg {
        let succ: Vec<&&Value> = evs.iter().filter(|e| e["success"].as_bool() == Some(true)).collect();
        let col = |path: &[&str]| -> Vec<f64> { succ.iter().filter_map(|e| num(e, path)).collect() };
        let mut timings = Map::new();
        for stage in ["aead_seal", "capture", "select", "embed", "save", "read", "extract", "verify", "aead_open", "explain", "total"] {
            timings.insert(stage.to_string(), stats(&col(&["timings_ms", stage])));
        }
        per_alg.push(json!({
            "algorithm": alg,
            "n_ok": succ.len(),
            "n_failed": evs.len() - succ.len(),
            "capacity_bytes": stats(&col(&["capacity_bytes"])),
            "frame_bytes": stats(&col(&["frame_bytes"])),
            "image_bytes": stats(&col(&["image_bytes"])),
            "mse": stats(&col(&["mse"])),
            "psnr": stats(&col(&["psnr"])),
            "ssim": stats(&col(&["ssim"])),
            "timings_ms": Value::Object(timings),
        }));
    }
    json!({
        "schema": SCHEMA,
        "generated_ms": now_ms,
        "environment": environment,
        "totals": {"events": total, "ok": ok, "failed": total - ok, "fallback_cover_count": fallback_cover,
                   "cover_sources": cover_sources, "error_counts": error_counts},
        "per_algorithm": per_alg,
        "limitations": [
            "Host-simulation measurements on one machine; not representative of drone hardware.",
            "Percentiles are null when fewer than 20 successful samples exist for the series.",
            "PSNR/SSIM are null when undefined (e.g. identical images); they are never imputed.",
            "Lossless PNG handoff only; no robustness to JPEG/resizing/filtering is claimed.",
            "LSB-class methods are statistically detectable; no anti-steganalysis claim is made.",
            "RAG explanations are simulated (word-overlap retrieval + template text) and explanation-only."
        ],
    })
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

pub fn events_to_csv(events: &[Value]) -> String {
    let mut out = CSV_COLUMNS.join(",");
    out.push('\n');
    for e in events {
        let row: Vec<String> = CSV_COLUMNS
            .iter()
            .map(|c| {
                let v = if let Some(stage) = c.strip_prefix("t_").and_then(|s| s.strip_suffix("_ms")) {
                    e["timings_ms"].get(stage).cloned().unwrap_or(Value::Null)
                } else if *c == "mse" || *c == "psnr" || *c == "ssim" {
                    e.get(*c).cloned().unwrap_or(Value::Null)
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
            json!({"success":true,"algorithm":"pvd","capacity_bytes":100,"frame_bytes":10,"psnr":60.0,"timings_ms":{"embed":2.0},"cover_source":"procedural_fallback","cover_fallback_reason":"CAMERA_ABSENT"}),
            json!({"success":false,"algorithm":"pvd","error_code":"FRAME_AUTH_FAILED"}),
            json!({"success":false,"error_code":"NO_ELIGIBLE_ALGORITHM","session_id":"=cmd|' /C calc'!A0"}),
        ];
        let r = build_report(&evs, json!({}), 1);
        assert_eq!(r["totals"]["events"], 3);
        assert_eq!(r["totals"]["failed"], 2);
        assert_eq!(r["totals"]["fallback_cover_count"], 1);
        assert_eq!(r["totals"]["error_counts"]["FRAME_AUTH_FAILED"], 1);
        assert_eq!(r["per_algorithm"][0]["n_ok"], 1);
        assert_eq!(r["per_algorithm"][0]["psnr"]["mean"], 60.0);
        let csv = events_to_csv(&evs);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[3].contains("'=cmd"), "formula injection neutralised");
        assert_eq!(lines[0].split(',').count(), CSV_COLUMNS.len());
    }
}
