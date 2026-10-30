//! Deterministic, rule-based explanation used when the (simulated) RAG
//! service is unavailable or its output fails the claim check. It reads the
//! finished selection report only; it never decides anything.

use serde_json::{json, Value};

fn f(v: &Value) -> Option<f64> {
    v.as_f64()
}

pub fn fallback_explanation(selection: &Value, embed: &Value, reason: &str) -> Value {
    let selected = selection["selected"].as_str().unwrap_or("?");
    let policy = selection["policy_version"].as_str().unwrap_or("?");
    let code = selection["reason_code"].as_str().unwrap_or("?");
    let cands = selection["candidates"].as_array().cloned().unwrap_or_default();
    let eligible: Vec<&Value> = cands.iter().filter(|c| c["eligible"].as_bool() == Some(true)).collect();
    let excluded: Vec<String> = cands
        .iter()
        .filter(|c| c["eligible"].as_bool() != Some(true))
        .map(|c| format!("{} ({})", c["algorithm"].as_str().unwrap_or("?"), c["exclusion_reason"].as_str().unwrap_or("?")))
        .collect();
    let mut evidence = vec![
        json!({"id": "sel.policy", "source": "report", "text": format!("policy_version={policy}")}),
        json!({"id": "sel.reason_code", "source": "report", "text": format!("reason_code={code}")}),
        json!({"id": "sel.selected", "source": "report", "text": format!("selected={selected}")}),
    ];
    let mut sentences = vec![format!(
        "{selected} was chosen by the deterministic selection policy {policy} (reason code {code}); {} of {} candidate algorithms were eligible.",
        eligible.len(),
        cands.len()
    )];
    if let Some(c) = cands.iter().find(|c| c["algorithm"].as_str() == Some(selected)) {
        if let Some(v) = c["variant"].as_str().filter(|v| !v.is_empty()) {
            sentences.push(format!("Implemented variant: {v}."));
            evidence.push(json!({"id": "cand.selected.variant", "source": "report", "text": format!("variant={v}")}));
        }
        if let Some(sc) = f(&c["score"]) {
            sentences.push(format!("Its score was {sc:.6} (lower is better)."));
            evidence.push(json!({"id": "cand.selected.score", "source": "report", "text": format!("score={sc:.6}")}));
        }
        if let Some(u) = f(&c["utilization"]) {
            sentences.push(format!("The frame used {:.2}% of its capacity.", u * 100.0));
            evidence.push(json!({"id": "cand.selected.utilization", "source": "report", "text": format!("utilization={u:.6}")}));
        }
    }
    if !excluded.is_empty() {
        sentences.push(format!("Excluded: {}.", excluded.join(", ")));
    }
    match f(&embed["metrics"]["psnr"]) {
        Some(p) => sentences.push(format!("Measured PSNR of the stego image: {p:.2} dB.")),
        None => sentences.push("PSNR is undefined (identical images or not measured).".to_string()),
    }
    sentences.push(format!("This is a locally generated rule-based explanation ({reason}); it did not influence the selection."));
    json!({
        "status": "fallback_deterministic",
        "narrative": sentences.join(" "),
        "evidence": evidence,
        "retrieved": [],
        "kb_version": null,
        "generator": "rust-rule-based",
        "fallback": true,
        "fallback_reason": reason,
        "selected_unchanged": true,
    })
}

/// Validate a RAG response against OUR selection; any mismatch => fallback.
pub fn accept_rag_response(resp: &Value, selection: &Value) -> Result<Value, String> {
    let status = resp["status"].as_str().unwrap_or("");
    if status != "simulated_rag" {
        return Err(format!("rag_status_{status}"));
    }
    if resp["selected_unchanged"].as_bool() != Some(true) {
        return Err("rag_did_not_confirm_selected_unchanged".into());
    }
    if let Some(s) = resp.get("selected").and_then(|s| s.as_str()) {
        if Some(s) != selection["selected"].as_str() {
            return Err("rag_echoed_a_different_selection".into());
        }
    }
    let narrative = resp["narrative"].as_str().ok_or("rag_missing_narrative")?;
    if narrative.is_empty() || narrative.len() > 8000 {
        return Err("rag_narrative_size".into());
    }
    let mut v = json!({
        "status": "simulated_rag",
        "narrative": narrative,
        "evidence": resp.get("evidence").cloned().unwrap_or(json!([])),
        "retrieved": resp.get("retrieved").cloned().unwrap_or(json!([])),
        "kb_version": resp.get("kb_version").cloned().unwrap_or(Value::Null),
        "generator": resp.get("generator").cloned().unwrap_or(json!("mock-template")),
        "fallback": false,
        "selected_unchanged": true,
    });
    v["note"] = json!("Simulated RAG (word-overlap retrieval + template text). Explanation only; it does not choose the algorithm.");
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sel() -> Value {
        json!({"selected":"pvd","policy_version":"sel-policy-2","reason_code":"BEST_SCORE","candidates":[
            {"algorithm":"pvd","eligible":true,"score":0.12,"utilization":0.01},
            {"algorithm":"dct","eligible":false,"exclusion_reason":"CAPACITY_INSUFFICIENT"}]})
    }
    #[test]
    fn fallback_is_deterministic_and_labelled() {
        let a = fallback_explanation(&sel(), &json!({"metrics":{"psnr":61.5}}), "rag_unavailable");
        let b = fallback_explanation(&sel(), &json!({"metrics":{"psnr":61.5}}), "rag_unavailable");
        assert_eq!(a, b);
        assert_eq!(a["status"], "fallback_deterministic");
        assert!(a["narrative"].as_str().unwrap().contains("pvd") && a["narrative"].as_str().unwrap().contains("did not influence"));
    }
    #[test]
    fn rag_response_must_confirm_the_decision_unchanged() {
        let good = json!({"status":"simulated_rag","narrative":"x","selected_unchanged":true,"selected":"pvd"});
        assert!(accept_rag_response(&good, &sel()).is_ok());
        let other = json!({"status":"simulated_rag","narrative":"x","selected_unchanged":true,"selected":"dct"});
        assert!(accept_rag_response(&other, &sel()).is_err());
        let bad = json!({"status":"unsupported_claims","narrative":"x","selected_unchanged":true});
        assert!(accept_rag_response(&bad, &sel()).is_err());
        let noconf = json!({"status":"simulated_rag","narrative":"x"});
        assert!(accept_rag_response(&noconf, &sel()).is_err());
    }
}
