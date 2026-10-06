//! `StegoClient`: the boundary between the Rust security core and the
//! real 2D-steganography + RAG-selection subsystem, which lives in
//! `python-service` (Python has the mature DCT/DWT/SVD/image-quality
//! libraries this needed -- see `docs/steganography.md` for why the
//! split is per-language rather than reimplemented in Rust).
//!
//! `HttpStegoClient` is the real implementation, calling
//! `python-service`'s `/stego/select-and-embed` and `/stego/extract`
//! endpoints (see `python-service/src/stego_api.py`) over plain HTTP.
//! `MockStegoClient` is a pure-Rust, no-network, no-image-codec test
//! double used ONLY by `registration_stego`'s crypto/framing unit tests
//! (see that module's test docs) -- it is explicitly NOT a
//! steganography implementation (it does not touch pixels at all) and
//! must never be used to claim embed/extract correctness; that is
//! covered by `python-service/tests/test_stego_algorithms.py` against
//! the real algorithms, and by the real cross-language end-to-end demo
//! (`docs/registration-stego.md`).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StegoEmbedOutcome {
    pub stego_image_bytes: Vec<u8>,
    /// Non-secret routing metadata needed to extract again: which
    /// algorithm was used, its version, and any algorithm-specific
    /// parameters (e.g. quantization step) -- combined by the caller
    /// with the KEM/AEAD-related fields into the full `StegoHint` sent
    /// alongside the image (see `registration_stego`'s wire messages).
    pub stego_algorithm_id: String,
    pub algorithm_version: String,
    pub stego_profile_id: String,
    pub payload_length: usize,
    pub algorithm_params_json: String,
    /// The full selection record (every candidate's real measurements
    /// and scores) and RAG narrative, as JSON, kept around for
    /// logging/UI display -- never re-parsed for a decision, since the
    /// decision already happened server-side.
    pub selection_json: String,
    pub explanation_json: String,
}

pub trait StegoClient {
    fn select_and_embed(&self, cover_image_bytes: &[u8], payload: &[u8], importance: &str) -> anyhow::Result<StegoEmbedOutcome>;
    fn extract(&self, stego_image_bytes: &[u8], algorithm_id: &str, payload_len: usize, algorithm_params_json: &str) -> anyhow::Result<Vec<u8>>;
}

// =============================================== real HTTP implementation

pub struct HttpStegoClient {
    pub base_url: String,
}

impl HttpStegoClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into() }
    }
}

impl StegoClient for HttpStegoClient {
    fn select_and_embed(&self, cover_image_bytes: &[u8], payload: &[u8], importance: &str) -> anyhow::Result<StegoEmbedOutcome> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::json!({
            "cover_image_b64": b64.encode(cover_image_bytes),
            "payload_b64": b64.encode(payload),
            "importance": importance,
        });
        let url = format!("{}/stego/select-and-embed", self.base_url);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| anyhow::anyhow!("stego select-and-embed HTTP call failed: {e}"))?;
        let parsed: serde_json::Value = resp.into_json()?;
        let stego_image_b64 = parsed["stego_image_b64"].as_str().ok_or_else(|| anyhow::anyhow!("missing stego_image_b64 in response"))?;
        let stego_image_bytes = b64.decode(stego_image_b64)?;
        let hint = &parsed["stego_hint"];
        Ok(StegoEmbedOutcome {
            stego_image_bytes,
            stego_algorithm_id: hint["stego_algorithm_id"].as_str().unwrap_or_default().to_string(),
            algorithm_version: hint["algorithm_version"].as_str().unwrap_or_default().to_string(),
            stego_profile_id: hint["stego_profile_id"].as_str().unwrap_or_default().to_string(),
            payload_length: hint["payload_length"].as_u64().unwrap_or(0) as usize,
            algorithm_params_json: hint["algorithm_params"].to_string(),
            selection_json: parsed["selection"].to_string(),
            explanation_json: parsed["explanation"].to_string(),
        })
    }

    fn extract(&self, stego_image_bytes: &[u8], algorithm_id: &str, payload_len: usize, algorithm_params_json: &str) -> anyhow::Result<Vec<u8>> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let params: serde_json::Value = serde_json::from_str(algorithm_params_json).unwrap_or(serde_json::json!({}));
        let body = serde_json::json!({
            "stego_image_b64": b64.encode(stego_image_bytes),
            "stego_hint": {
                "stego_algorithm_id": algorithm_id,
                "payload_length": payload_len,
                "algorithm_params": params,
            },
        });
        let url = format!("{}/stego/extract", self.base_url);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| anyhow::anyhow!("stego extract HTTP call failed: {e}"))?;
        let parsed: serde_json::Value = resp.into_json()?;
        let payload_b64 = parsed["payload_b64"].as_str().ok_or_else(|| anyhow::anyhow!("missing payload_b64 in response"))?;
        Ok(b64.decode(payload_b64)?)
    }
}

// ============================================ pure-Rust test double only

/// NOT a steganography implementation -- see module docs. Simply
/// carries the ciphertext bytes through unchanged, tagged with a fixed
/// fake algorithm id, so `registration_stego`'s tests can exercise the
/// R1/R2/R3 crypto+framing pipeline without a live Python process or
/// any image codec.
pub struct MockStegoClient;

impl StegoClient for MockStegoClient {
    fn select_and_embed(&self, _cover_image_bytes: &[u8], payload: &[u8], importance: &str) -> anyhow::Result<StegoEmbedOutcome> {
        Ok(StegoEmbedOutcome {
            stego_image_bytes: payload.to_vec(),
            stego_algorithm_id: "mock_passthrough".to_string(),
            algorithm_version: "0.0.0-test-double".to_string(),
            stego_profile_id: importance.to_string(),
            payload_length: payload.len(),
            algorithm_params_json: "{}".to_string(),
            selection_json: "{}".to_string(),
            explanation_json: "{}".to_string(),
        })
    }

    fn extract(&self, stego_image_bytes: &[u8], algorithm_id: &str, payload_len: usize, _algorithm_params_json: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(algorithm_id == "mock_passthrough", "MockStegoClient can only extract its own passthrough output");
        anyhow::ensure!(stego_image_bytes.len() == payload_len, "mock passthrough length mismatch");
        Ok(stego_image_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_round_trips_arbitrary_bytes() {
        let client = MockStegoClient;
        let payload = b"some ciphertext bytes".to_vec();
        let outcome = client.select_and_embed(b"fake-cover-image-bytes", &payload, "CRITICAL").unwrap();
        let recovered = client.extract(&outcome.stego_image_bytes, &outcome.stego_algorithm_id, outcome.payload_length, &outcome.algorithm_params_json).unwrap();
        assert_eq!(recovered, payload);
    }
}
