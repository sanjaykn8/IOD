//! Real, end-to-end, cross-language demo of the steganographic R1-R3
//! registration flow: D1 builds a real EnrollmentRequest, encrypts it
//! with real ML-KEM-768+ChaCha20-Poly1305, hands it to a LIVE
//! `python-service` over real HTTP for RAG-assisted algorithm
//! selection and real embedding into a real cover image, "sends" the
//! resulting stego PNG to GCS, which extracts (via the same live
//! service), decrypts, and processes R2/builds R3 -- then the whole
//! thing happens in reverse for the response.
//!
//! Requires `python-service` already running (see
//! `docs/registration-stego.md` for the exact command). Prints every
//! stage's real measurements so this can be read as a worked example,
//! not just a pass/fail check.
//!
//! Usage: `cargo run --release --bin iod-register-stego-demo -- <python_service_base_url>`
//! (base URL defaults to `http://127.0.0.1:5001` if omitted -- the same
//! default `python-service` itself uses, see `IOD_PYTHON_PORT` in
//! `python-service/src/app.py` and `node-server/src/config.ts`.)

use iod_core::identity::metadata::MembershipMetadata;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::registration_stego::*;
use iod_core::protocol::stego_client::{HttpStegoClient, StegoClient};
use iod_core::puf::crp::CrpReference;

fn main() -> anyhow::Result<()> {
    let base_url = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:5001".to_string());
    let client = HttpStegoClient::new(base_url.clone());
    println!("== IOD steganographic registration demo == (python-service @ {base_url})");

    let cover_r1 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cover_d1_to_gcs.png"))?;
    let cover_r3 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cover_gcs_to_d1.png"))?;

    let mut gcs = GcsState::new();
    let mut drone = DroneState::new("demo-drone-1", [0x42u8; 32]);
    let metadata = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_735_000_000 };

    // ---- R1: D1 builds + encrypts + embeds its EnrollmentRequest ----
    let material = d1_build_enrollment_request(&drone, "alpha", &metadata);
    println!("[R1] D1 generated real ML-KEM-768 pk ({} bytes) + ML-DSA-44 pk ({} bytes), pid_pool batch of {}",
        material.keys.kem_pk.0.len(), material.keys.dil_pk.0.len(), material.request.pid_pool.len());

    let sealed_r1 = encrypt_enrollment_request(&material.request, &gcs.kem_pk)?;
    let plaintext_r1 = serde_json::to_vec(&sealed_r1)?;
    println!("[R1] KEM-then-AEAD sealed: kem_ciphertext={}B, aead_ciphertext={}B",
        sealed_r1.kem_ciphertext.len(), sealed_r1.sealed.ciphertext.len());

    let embed_r1 = client.select_and_embed(&cover_r1, &plaintext_r1, "CRITICAL")?;
    println!("[R1] RAG-assisted selector chose '{}' (profile={}) -> stego PNG {} bytes",
        embed_r1.stego_algorithm_id, embed_r1.stego_profile_id, embed_r1.stego_image_bytes.len());
    let selection: serde_json::Value = serde_json::from_str(&embed_r1.selection_json)?;
    if let Some(candidates) = selection["candidates"].as_array() {
        for c in candidates {
            println!(
                "       candidate={:<13} feasible={:<5} score={:.4} ssim={:.4}",
                c["algorithm_id"].as_str().unwrap_or("?"),
                c["feasible"].as_bool().unwrap_or(false),
                c["score"].as_f64().unwrap_or(0.0),
                c["measurement"]["ssim"].as_f64().unwrap_or(0.0),
            );
        }
    }

    // --- "network": the stego PNG bytes are what actually transits ---
    let stego_png_r1 = embed_r1.stego_image_bytes.clone();

    // ---- GCS extracts + decrypts R1, runs R2, builds + encrypts + ----
    // ---- embeds R3                                                 ----
    let extracted_plaintext_r1 = client.extract(&stego_png_r1, &embed_r1.stego_algorithm_id, embed_r1.payload_length, &embed_r1.algorithm_params_json)?;
    anyhow::ensure!(extracted_plaintext_r1 == plaintext_r1, "R1 extraction did not recover the exact sealed envelope bytes");
    println!("[GCS] extracted {} bytes from the stego image, matches what D1 sent exactly", extracted_plaintext_r1.len());

    let sealed_r1_recv: iod_core::protocol::envelope::SecureEnvelope = serde_json::from_slice(&extracted_plaintext_r1)?;
    let request = decrypt_enrollment_request(&sealed_r1_recv, &gcs.kem_sk)?;
    println!("[R1] GCS decrypted EnrollmentRequest for drone_id='{}' group='{}'", request.drone_id, request.g);

    let crp = CrpReference { challenge: drone.crp_default_challenge.clone(), reference_response: drone.puf.challenge_response(&drone.crp_default_challenge) };
    let response = gcs_process_enrollment(&mut gcs, &request, 8, crp)?;
    println!("[R2] GCS (internal, no network): leaf registered at index={}, R_G version={}", response.witness.leaf_index, response.v_g);

    let drone_kem_pk = iod_core::crypto::kem::KemPublicKey(material.keys.kem_pk.0.clone());
    let sealed_r3 = encrypt_enrollment_response(&response, &drone_kem_pk)?;
    let plaintext_r3 = serde_json::to_vec(&sealed_r3)?;
    let embed_r3 = client.select_and_embed(&cover_r3, &plaintext_r3, "CRITICAL")?;
    println!("[R3] RAG-assisted selector chose '{}' for the response -> stego PNG {} bytes", embed_r3.stego_algorithm_id, embed_r3.stego_image_bytes.len());

    // ---- D1 extracts + decrypts + applies R3 ----
    let stego_png_r3 = embed_r3.stego_image_bytes.clone();
    let extracted_plaintext_r3 = client.extract(&stego_png_r3, &embed_r3.stego_algorithm_id, embed_r3.payload_length, &embed_r3.algorithm_params_json)?;
    anyhow::ensure!(extracted_plaintext_r3 == plaintext_r3, "R3 extraction did not recover the exact sealed envelope bytes");

    let sealed_r3_recv: iod_core::protocol::envelope::SecureEnvelope = serde_json::from_slice(&extracted_plaintext_r3)?;
    let response_recv = decrypt_enrollment_response(&sealed_r3_recv, &material.keys.kem_sk)?;
    let index = d1_apply_enrollment_response(&mut drone, &response_recv, material, metadata)?;

    println!("[R3] D1 decrypted + locally re-verified the Merkle witness against R_G -- OK");
    println!("== registration complete == drone '{}' is_registered={} leaf_index={}", drone.drone_id, drone.is_registered(), index);
    assert!(drone.is_registered());
    assert!(gcs.groups.get("alpha").unwrap().is_active(&drone.drone_id));
    println!("== all real-code assertions passed ==");
    Ok(())
}
