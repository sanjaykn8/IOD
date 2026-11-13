//! Algorithm Learning workbench (EDUCATIONAL ONLY) -- core side.
//!
//! Strictly separate from the operational UAV transport:
//! * never touches sessions, group keys, replay windows, `stego_events` or the
//!   operational artifact store; records go to the separate `learn_experiments` table;
//! * the "real encryption" demonstration uses the PRODUCTION code path
//!   (`secure_messaging::seal_message` + AppWire v1 + `receive_message`) but with a
//!   TEST-ONLY key derived from a public constant -- it protects nothing and is never
//!   used operationally;
//! * the image work is done by the Python `/learn/*` namespace on caller-supplied bytes.

use crate::api::state::SimulationState;
use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::hkdf_expand;
use crate::protocol::secure_messaging;
use crate::transport::b64;
use crate::transport::error::{stage, StegoError};
use crate::transport::{report, wire};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// Public constant; deliberately NOT a secret. Documented as test-only everywhere it appears.
pub const TEST_KEY_LABEL: &[u8] = b"IOD-LEARN-TEST-ONLY-KEY-v1 (public constant; not a secret; never operational)";
pub const SAMPLE_MESSAGE: &str = "UAV_ID=D1\nTARGET=D2\nLAT=9.45\nLON=77.80\nALT=120";
pub const SYNTHETIC_HEX: &str = "A63C915E";
pub const LABEL: &str = "Educational experiment - not a live UAV transmission";
const MAX_MESSAGE: usize = 2048;
/// Operational transport overhead that the learning payload does NOT include
/// besides the patch manifest (Frame v2 header 16 B + HMAC-SHA256 tag 32 B; the manifest and the
/// bootstrap preamble travel in reserved rows of the image).
pub const OPERATIONAL_FRAME_OVERHEAD: usize = 16 + 32;

fn test_key() -> AeadKey {
    let okm = hkdf_expand(TEST_KEY_LABEL, None, b"aead-key", 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm);
    AeadKey(k)
}

fn test_channel() -> [u8; 16] {
    let d = Sha256::digest(b"IOD-LEARN-CHANNEL-v1");
    let mut t = [0u8; 16];
    t.copy_from_slice(&d[..16]);
    t
}

fn hex_preview(b: &[u8], n: usize) -> String {
    let mut s: Vec<String> = b.iter().take(n).map(|x| format!("{x:02X}")).collect();
    if b.len() > n {
        s.push("...".into());
    }
    s.join(" ")
}

fn bin_preview(b: &[u8], n: usize) -> String {
    let mut s: Vec<String> = b.iter().take(n).map(|x| format!("{x:08b}")).collect();
    if b.len() > n {
        s.push("...".into());
    }
    s.join(" ")
}

/// Seal `plaintext` with the TEST-ONLY envelope; returns (AppWire bytes, description).
pub fn seal_fixture(plaintext: &[u8]) -> (Vec<u8>, Value) {
    let msg = secure_messaging::seal_message(&test_key(), test_channel(), 1, 1, plaintext);
    let wire_bytes = wire::encode_app_wire(&msg);
    let info = json!({
        "plaintext_bytes": plaintext.len(),
        "plaintext_hex_preview": hex_preview(plaintext, 48),
        "serialisation": "UTF-8 message bytes -> ChaCha20-Poly1305 AEAD (header bound as associated data) -> AppWire v1",
        "aead": "ChaCha20-Poly1305 (production seal_message code path)",
        "key": "TEST-ONLY key = HKDF-SHA256(public label) -- not secret, never used for UAV traffic, not displayed",
        "appwire_header_bytes": wire::WIRE_HEADER_LEN,
        "aead_tag_bytes": 16,
        "ciphertext_bytes": msg.sealed.ciphertext.len(),
        "wire_bytes": wire_bytes.len(),
        "wire_bits": wire_bytes.len() * 8,
        "overhead_bytes": wire_bytes.len() - plaintext.len(),
        "wire_hex_preview": hex_preview(&wire_bytes, 64),
        "wire_binary_preview": bin_preview(&wire_bytes, 8),
        "operational_frame_overhead_bytes_not_included": OPERATIONAL_FRAME_OVERHEAD,
        "note": "The same AppWire bytes are embedded by every algorithm in this comparison. The live transport additionally splits them over several patches and wraps them in Frame v2 (16-byte header + patch manifest + 32-byte HMAC over manifest and payload).",
    });
    (wire_bytes, info)
}

/// Verify an extracted payload against the TEST-ONLY envelope.
pub fn open_fixture(extracted: &[u8], expected_plaintext: &[u8]) -> Value {
    match wire::decode_app_wire(extracted, 1 << 16) {
        Err(e) => json!({"aead_verified": false, "plaintext_matches": false, "error": e.code}),
        Ok(msg) => match secure_messaging::receive_message(&test_key(), test_channel(), 1, &msg, 0) {
            Ok(pt) => json!({"aead_verified": true, "plaintext_matches": pt == expected_plaintext}),
            Err(_) => json!({"aead_verified": false, "plaintext_matches": false, "error": "AEAD_AUTH_FAILED"}),
        },
    }
}

fn bad(msg: &str) -> StegoError {
    StegoError::new("INVALID_REQUEST", stage::PREPARE, 400, msg)
}

fn strip_images(v: &Value) -> Value {
    let mut c = v.clone();
    if let Some(cv) = c.get_mut("cover").and_then(|x| x.as_object_mut()) {
        cv.remove("png");
    }
    if let Some(rs) = c.get_mut("results").and_then(|x| x.as_array_mut()) {
        for r in rs {
            if let Some(o) = r.as_object_mut() {
                o.remove("images");
            }
        }
    }
    c
}

/// Run an educational experiment: build the payload (test-only envelope or synthetic
/// fixture), let Python run the algorithms, verify extractions, persist a record.
pub fn run_experiment(state: &Mutex<SimulationState>, body: &Value) -> Result<Value, StegoError> {
    let mode = body.get("payload_mode").and_then(|v| v.as_str()).unwrap_or("aead_fixture");
    let (payload, construction, plaintext): (Vec<u8>, Value, Vec<u8>) = match mode {
        "aead_fixture" => {
            let msg = body.get("message").and_then(|v| v.as_str()).unwrap_or(SAMPLE_MESSAGE);
            if msg.is_empty() || msg.len() > MAX_MESSAGE {
                return Err(bad("message must be 1..2048 bytes"));
            }
            let pt = msg.as_bytes().to_vec();
            let (w, info) = seal_fixture(&pt);
            (w, info, pt)
        }
        "synthetic" => {
            let p = (0..SYNTHETIC_HEX.len() / 2).map(|i| u8::from_str_radix(&SYNTHETIC_HEX[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<_>>();
            let info = json!({"fixture_hex": SYNTHETIC_HEX, "bytes": p.len(), "bits": p.len() * 8,
                "binary": bin_preview(&p, 8),
                "label": "synthetic byte sequence for mathematical illustration -- NOT a real ciphertext; cannot pass AEAD verification"});
            (p, info, vec![])
        }
        _ => return Err(bad("payload_mode must be aead_fixture or synthetic")),
    };
    let mut req = json!({
        "algorithms": body.get("algorithms").cloned().unwrap_or(json!("all")),
        "cover": body.get("cover").cloned().unwrap_or(json!({"sample": "natural_rgb_256"})),
        "payload_b64": b64::encode(&payload),
        "payload_kind": if mode == "aead_fixture" { "aead_test_envelope" } else { "synthetic" },
        "robustness": body.get("robustness").and_then(|v| v.as_bool()).unwrap_or(false),
        "patch": match body.get("patch") {
            None | Some(Value::Null) => json!("most_textured"),
            Some(Value::String(k)) if ["most_textured", "smoothest", "largest", "smallest"].contains(&k.as_str()) => json!(k),
            Some(v) if v.as_u64().map(|n| n < 255).unwrap_or(false) => v.clone(),
            _ => return Err(bad("patch must be a patch id or one of most_textured, smoothest, largest, smallest")),
        },
        "survey": body.get("survey").and_then(|v| v.as_bool()).unwrap_or(true),
        "include_images": body.get("include_images").and_then(|v| v.as_bool()).unwrap_or(true),
    });
    if let Some(o) = req.as_object_mut() {
        o.retain(|_, v| !v.is_null());
    }
    let backend = state.lock().unwrap().backend.clone();
    let mut out = backend.learn_post("/learn/experiment", &req)?;
    if let Some(rs) = out.get_mut("results").and_then(|x| x.as_array_mut()) {
        for r in rs.iter_mut() {
            let extracted = r.get("extracted_b64").and_then(|v| v.as_str()).map(|s| b64::decode(s, 1 << 20).unwrap_or_default());
            let verification = match (mode, &extracted) {
                (_, None) => json!({"status": "not_extracted"}),
                ("aead_fixture", Some(bytes)) => {
                    let mut v = open_fixture(bytes, &plaintext);
                    v["status"] = json!(if v["aead_verified"] == true { "aead_verified" } else { "aead_failed" });
                    v
                }
                (_, Some(bytes)) => json!({"status": "not_applicable_synthetic", "bit_exact": bytes == &payload,
                    "note": "synthetic bytes can prove bit-level extraction only"}),
            };
            if let Some(o) = r.as_object_mut() {
                if let Some(bytes) = &extracted {
                    o.insert("extracted_hex_preview".into(), json!(hex_preview(bytes, 32)));
                }
                o.remove("extracted_b64");
                o.insert("verification".into(), verification);
            }
        }
    }
    let ts = crate::protocol::events::now_unix_ms() as i64;
    out["payload_mode"] = json!(mode);
    out["payload_construction"] = construction;
    out["label"] = json!(LABEL);
    out["operational"] = json!(false);
    out["created_ms"] = json!(ts);
    let record = strip_images(&out);
    let id = out["experiment_id"].as_str().unwrap_or("").to_string();
    let algs: Vec<String> = out["results"].as_array().map(|a| a.iter().filter_map(|r| r["algorithm"].as_str().map(String::from)).collect()).unwrap_or_default();
    {
        let s = state.lock().unwrap();
        if let Err(e) = s.db.insert_learn_experiment(&id, ts, mode, &algs.join(","), &record) {
            out["persist_error"] = json!(e.to_string());
        }
    }
    Ok(out)
}

const CSV_COLS: [&str; 28] = [
    "experiment_id", "patch_id", "algorithm", "variant", "status", "geometry_supported", "geometry_reason", "capacity_bits", "param",
    "payload_bytes", "payload_bits", "bits_per_patch_sample", "mse", "psnr_db", "ssim", "patch_mse", "patch_psnr_db", "embed_ms",
    "setup_ms", "extract_ms", "bit_accuracy", "byte_accuracy", "ber", "exact_recovery", "outside_patch_changes", "verification",
    "changed_samples", "robustness",
];

pub fn to_csv(rec: &Value) -> String {
    let mut out = CSV_COLS.join(",") + "\n";
    for r in rec["results"].as_array().cloned().unwrap_or_default() {
        let rob = r["robustness"].as_array().map(|a| {
            a.iter().map(|x| format!("{}={}", x["attack"].as_str().unwrap_or("?"), x["outcome"].as_str().unwrap_or("?"))).collect::<Vec<_>>().join(";")
        });
        let cells: Vec<String> = CSV_COLS.iter().map(|c| {
            let v = match *c {
                "experiment_id" => rec["experiment_id"].clone(),
                "patch_id" => rec["patch"]["patch_id"].clone(),
                "verification" => r["verification"]["status"].clone(),
                "robustness" => rob.clone().map(Value::String).unwrap_or(Value::Null),
                k => r[k].clone(),
            };
            report::csv_cell(&v)
        }).collect();
        out += &cells.join(",");
        out += "\n";
    }
    out
}

fn md_num(v: &Value, d: usize) -> String {
    match v {
        Value::Number(n) => n.as_f64().map(|f| format!("{f:.d$}")).unwrap_or_default(),
        Value::Null => "n/a".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.replace('|', "/"),
        other => other.to_string(),
    }
}

pub fn to_markdown(rec: &Value) -> String {
    let mut s = String::new();
    s += "# Patch-level steganography algorithm comparison (educational)\n\n";
    s += &format!("> **{}.** No UAV session, key or protocol state was involved.\n\n", LABEL);
    s += &format!("* Experiment: `{}`\n", rec["experiment_id"].as_str().unwrap_or("?"));
    s += &format!("* Cover: {} ({}x{} {}, sha256 `{}`)\n", rec["cover"]["description"].as_str().unwrap_or("?"),
        md_num(&rec["cover"]["width"], 0), md_num(&rec["cover"]["height"], 0), rec["cover"]["mode"].as_str().unwrap_or("?"),
        &rec["cover"]["sha256"].as_str().unwrap_or("")[..16.min(rec["cover"]["sha256"].as_str().unwrap_or("").len())]);
    s += &format!("* Segmentation: `{}`, {} irregular patches; experiment patch **#{}** (chosen by `{}`, {} pixels)\n",
        rec["segmentation"]["version"].as_str().unwrap_or("?"), md_num(&rec["segmentation"]["patch_count"], 0), md_num(&rec["patch"]["patch_id"], 0),
        rec["patch"]["chosen_by"].as_str().unwrap_or("?"), md_num(&rec["patch"]["features"]["pixels"], 0));
    s += "* Algorithms are this repository's implemented variants (see the Variant column), not canonical paper implementations. The production knowledge base and selector are not modified by experiments.\n";
    s += &format!("* Payload mode: `{}`; {} bytes ({} bits), sha256 `{}`; same cover, patch and payload for every algorithm\n",
        rec["payload_mode"].as_str().unwrap_or("?"), md_num(&rec["payload"]["bytes"], 0), md_num(&rec["payload"]["bits"], 0),
        &rec["payload"]["sha256"].as_str().unwrap_or("")[..16.min(rec["payload"]["sha256"].as_str().unwrap_or("").len())]);
    if rec["payload_mode"] == "aead_fixture" {
        let c = &rec["payload_construction"];
        s += &format!("* Payload construction: {} plaintext bytes -> AppWire v1 {} bytes ({}-byte header, {}-byte AEAD tag), TEST-ONLY key\n",
            md_num(&c["plaintext_bytes"], 0), md_num(&c["wire_bytes"], 0), md_num(&c["appwire_header_bytes"], 0), md_num(&c["aead_tag_bytes"], 0));
    } else {
        s += "* Payload: synthetic fixture A6 3C 91 5E (not a real ciphertext; AEAD verification not applicable)\n";
    }
    s += "\n## Metrics\n\n| Algorithm | Variant | Status | Patch capacity bits | bits / patch sample | MSE | PSNR dB | SSIM | Patch PSNR dB | Embed ms | Extract ms | Bit acc. | BER | Outside-patch changes | Verification |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n";
    for r in rec["results"].as_array().cloned().unwrap_or_default() {
        s += &format!("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r["algorithm"].as_str().unwrap_or("?"), md_num(&r["variant"], 0), md_num(&r["status"], 0),
            md_num(&r["capacity_bits"], 0), md_num(&r["bits_per_patch_sample"], 6),
            md_num(&r["mse"], 6), if r["psnr_db"].is_null() && r["status"] == "ok" { "inf".into() } else { md_num(&r["psnr_db"], 3) },
            md_num(&r["ssim"], 6), md_num(&r["patch_psnr_db"], 3), md_num(&r["embed_ms"], 2), md_num(&r["extract_ms"], 2), md_num(&r["bit_accuracy"], 4),
            md_num(&r["ber"], 6), md_num(&r["outside_patch_changes"], 0), md_num(&r["verification"]["status"], 0));
    }
    if let Some(sv) = rec["survey"].as_array().filter(|a| !a.is_empty()) {
        s += "\n## Per-patch survey (measured capacity in bits; read-only knowledge-base ranking)\n\n| Patch | Pixels | Gradient | 8x8 blocks | KB top-1 | Unsupported geometry |\n|---|---|---|---|---|---|\n";
        for p in sv {
            let uns: Vec<String> = p["unsupported_reasons"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
            s += &format!("| {} | {} | {} | {} | {} | {} |\n", md_num(&p["patch_id"], 0), md_num(&p["pixels"], 0), md_num(&p["gradient_mean"], 2),
                md_num(&p["blocks8"], 0), md_num(&p["kb_selected"], 0), if uns.is_empty() { "-".into() } else { uns.join(", ") });
        }
    }
    let with_rob: Vec<Value> = rec["results"].as_array().cloned().unwrap_or_default().into_iter().filter(|r| r["robustness"].is_array()).collect();
    if let Some(first) = with_rob.first() {
        let attacks: Vec<String> = first["robustness"].as_array().unwrap().iter().map(|a| a["attack"].as_str().unwrap_or("?").to_string()).collect();
        s += "\n## Robustness (outcome / oracle BER)\n\n| Algorithm | ";
        s += &attacks.join(" | ");
        s += " |\n|---|";
        s += &"---|".repeat(attacks.len());
        s += "\n";
        for r in &with_rob {
            let cells: Vec<String> = r["robustness"].as_array().unwrap().iter()
                .map(|a| format!("{} / {}", a["outcome"].as_str().unwrap_or("?"), md_num(&a["oracle_ber"], 3))).collect();
            s += &format!("| {} | {} |\n", r["algorithm"].as_str().unwrap_or("?"), cells.join(" | "));
        }
        s += "\nAttack parameters:\n\n";
        for a in rec["attacks"].as_array().cloned().unwrap_or_default() {
            s += &format!("* `{}`: {} {}\n", a["id"].as_str().unwrap_or("?"), a["label"].as_str().unwrap_or(""), a["params"]);
        }
    }
    s += "\n## Metric definitions\n\n";
    if let Some(m) = rec["metric_definitions"].as_object() {
        for (k, v) in m {
            s += &format!("* **{k}**: {}\n", v.as_str().unwrap_or(""));
        }
    }
    s += "\n## Interpretation\n\n";
    for l in rec["interpretation"].as_array().cloned().unwrap_or_default() {
        s += &format!("* {}\n", l.as_str().unwrap_or(""));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_round_trip_and_tamper() {
        let pt = SAMPLE_MESSAGE.as_bytes();
        let (w, info) = seal_fixture(pt);
        assert_eq!(info["wire_bytes"], w.len());
        assert_eq!(w.len(), wire::WIRE_HEADER_LEN + pt.len() + 16);
        assert_eq!(open_fixture(&w, pt)["aead_verified"], true);
        assert_eq!(open_fixture(&w, pt)["plaintext_matches"], true);
        let mut t = w.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert_eq!(open_fixture(&t, pt)["aead_verified"], false);
        assert_eq!(open_fixture(&[0xA6, 0x3C, 0x91, 0x5E], pt)["aead_verified"], false);
        // nothing secret or plaintext-like leaks into the description beyond the public sample preview
        assert!(!info.to_string().contains("key\":\"0x"));
    }

    #[test]
    fn test_key_is_not_an_operational_key_shape() {
        // derived only from the public label; deterministic
        assert_eq!(test_key().0, test_key().0);
        assert_ne!(test_key().0, [0u8; 32]);
    }

    #[test]
    fn csv_and_markdown_render() {
        let rec = json!({"experiment_id": "e1", "payload_mode": "synthetic", "segmentation": {"version": "arg-cells-1", "patch_count": 3},
            "patch": {"patch_id": 2, "chosen_by": "largest", "features": {"pixels": 640}},
            "survey": [{"patch_id": 0, "pixels": 100, "gradient_mean": 3.5, "blocks8": 0, "kb_selected": "lsb_matching", "unsupported_reasons": {"dct": "NO_COMPLETE_8X8_BLOCK"}}], "cover": {"description": "c", "width": 8, "height": 8, "mode": "L", "sha256": "ab"},
            "payload": {"bytes": 4, "bits": 32, "sha256": "cd"}, "metric_definitions": {"mse": "x"}, "interpretation": ["y"],
            "results": [{"algorithm": "dwt", "variant": "=cmd", "status": "ok", "mse": 0.1, "psnr_db": 50.0, "verification": {"status": "not_applicable_synthetic"},
                         "robustness": [{"attack": "none", "outcome": "recovered", "oracle_ber": 0.0}]}],
            "attacks": [{"id": "none", "label": "No attack", "params": {}}]});
        let c = to_csv(&rec);
        assert!(c.lines().count() == 2 && c.contains("'=cmd") && c.contains("none=recovered") && c.lines().nth(1).unwrap().starts_with("e1,2,dwt"));
        assert_eq!(c.lines().next().unwrap().split(',').count(), CSV_COLS.len());
        let m = to_markdown(&rec);
        assert!(m.contains("| dwt |") && m.contains("not a live UAV transmission") && m.contains("Robustness"));
        assert!(m.contains("experiment patch **#2**") && m.contains("| 0 | 100 | 3.50 | 0 | lsb_matching | dct |") && m.contains("not canonical paper implementations"));
    }
}
