//! Protocol test-vector generator.
//!
//! ## Honest determinism accounting (read before treating any field as
//! a fixed known-answer value)
//!
//! Section A below uses fully fixed, literal byte inputs (no RNG
//! anywhere in the call path) for every Poseidon/hash-based computation,
//! so those values ARE byte-for-byte reproducible on every run, on any
//! machine, forever — this is what a "known-answer test" vector is
//! supposed to be, and it is genuinely one.
//!
//! Section B captures one real, concrete run of the actual system
//! (real generated ML-KEM/ML-DSA keypairs, real simulated PUF noise,
//! real current timestamps, real random nonces and ZK-proof blinding).
//! **These values will differ on every run** — this is not a bug to fix
//! before shipping, it is the direct, documented consequence of two
//! things that are true by design: (1) real randomness sources (nonces,
//! blinding factors, PUF noise, timestamps) are supposed to differ every
//! run, and (2) the pqcrypto keygen library this project uses has no
//! seeded/deterministic entry point (see
//! `rust-core/src/identity/keys.rs` and `docs/cryptography.md`). Section
//! B is included anyway because it is still useful as a concrete,
//! non-fabricated example of what real output looks like, and every
//! boolean verification RESULT in it (signature valid, ZK proof valid,
//! PUF MAC valid) IS reproducible in the sense that it will always be
//! `true` for any honestly-generated run, and the negative-test suite in
//! `rust-core/src/protocol/simulation.rs` and `rust-core/tests/` covers
//! the corresponding `false` cases explicitly.
//!
//! No private key, PUF seed, or shared secret appears anywhere in this
//! output — only public keys (as fingerprints), public hashes, and
//! non-secret protocol metadata.

use iod_core::crypto::field::Fp;
use iod_core::crypto::{kem, sign};
use iod_core::identity;
use iod_core::merkle::tree::{verify_witness, MerkleTree};
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::events::EventLog;
use iod_core::protocol::registration::register_drone;
use iod_core::protocol::simulation;
use iod_core::zk;
use serde_json::json;

fn fingerprint(bytes: &[u8]) -> String {
    let d = iod_core::crypto::kdf::shake256_bytes(b"IOD-VECTOR-FINGERPRINT-v1", bytes, 8);
    hex::encode(d)
}

fn section_a_deterministic() -> serde_json::Value {
    let pk_kem = b"FIXED-TEST-VECTOR-PK-KEM-BYTES-0001";
    let pk_dil = b"FIXED-TEST-VECTOR-PK-DIL-BYTES-0002";
    let rho = [0x42u8; 32];
    let md = identity::metadata::MembershipMetadata {
        role: "test-vector".to_string(),
        issued_at_unix: 1_700_000_000,
    };
    let group_id = "vector-group";

    let leaf = identity::leaf::compute_leaf(pk_kem, pk_dil, group_id, &md, &rho);
    let commitment = identity::commitment::compute_commitment(pk_kem, pk_dil);
    let g_field = identity::group_id::group_field(group_id);

    let seed = [0x11u8; 32];
    let pid0 = identity::pid::derive_pid(&seed, 0);
    let pid1 = identity::pid::derive_pid(&seed, 1);

    // 4-leaf Merkle tree, fully fixed leaves.
    let mut tree = MerkleTree::new(2); // capacity 4
    let leaves = [Fp::new(1001), Fp::new(1002), leaf, Fp::new(1004)];
    for (i, l) in leaves.iter().enumerate() {
        tree.set_leaf(i, *l);
    }
    let root = tree.root();
    let witness = tree.witness(2);
    let witness_ok = verify_witness(root, leaf, &witness);

    let t_base = iod_core::protocol::transcript::build_t_base(
        g_field, 1, root, commitment, b"fixed-n1-000000", b"fixed-n2-000000", 1_700_000_001, 1_700_000_002, &pid0,
    );

    let statement = zk::statement::ZkStatement { g: g_field, r_g: root, v_g: 1, comm_pk: commitment };
    let witness_zk = zk::witness::ZkWitness {
        leaf,
        siblings: witness.siblings.clone(),
        path_indices: witness.path_indices.clone(),
        pk_kem: pk_kem.to_vec(),
        pk_dil: pk_dil.to_vec(),
        metadata: md.clone(),
        rho,
    };
    let proof = zk::backend::prove(&statement, &witness_zk).expect("fixed witness must be self-consistent");
    let zk_verify_result = zk::backend::verify(&statement, &proof);

    json!({
        "note": "Every value in this section is derived ONLY from literal fixed bytes below plus deterministic hash functions (Poseidon/SHAKE256) — no RNG anywhere in this call path except the ZK proof's hiding blinding factor (noted separately). Reproducible byte-for-byte on any machine, forever, EXCEPT the two fields explicitly marked.",
        "inputs": {
            "pk_kem_bytes_utf8": String::from_utf8_lossy(pk_kem),
            "pk_dil_bytes_utf8": String::from_utf8_lossy(pk_dil),
            "rho_hex": hex::encode(rho),
            "metadata": { "role": md.role, "issued_at_unix": md.issued_at_unix },
            "group_id": group_id,
            "seed_hex_for_pid": hex::encode(seed),
        },
        "outputs": {
            "group_field_hex": hex::encode(g_field.to_bytes_le()),
            "leaf_hex": hex::encode(leaf.to_bytes_le()),
            "pk_commitment_hex": hex::encode(commitment.to_bytes_le()),
            "pid_counter_0_hex": hex::encode(&pid0),
            "pid_counter_1_hex": hex::encode(&pid1),
            "merkle_root_hex": hex::encode(root.to_bytes_le()),
            "merkle_witness_verifies": witness_ok,
            "t_base_transcript_hash_hex": hex::encode(t_base),
            "zk_proof_witness_commitment_hex": "NON-REPRODUCIBLE: includes a fresh random blinding factor each run (see zk module docs); only the verification RESULT below is reproducible",
            "zk_proof_verifies": zk_verify_result,
        }
    })
}

fn section_b_captured_real_run() -> serde_json::Value {
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("vector-d1", [51u8; 32]);
    let mut d2 = DroneState::new("vector-d2", [52u8; 32]);
    let md = identity::metadata::MembershipMetadata { role: "vector-role".into(), issued_at_unix: 1_700_000_000 };
    register_drone(&mut gcs, &mut d1, "vector-live-group", md.clone(), 6).unwrap();
    register_drone(&mut gcs, &mut d2, "vector-live-group", md, 6).unwrap();
    iod_core::protocol::registration::refresh_drone_cache(&gcs, &mut d1);

    let d1_kem_pk = d1.keys.as_ref().unwrap().kem_pk.0.clone();
    let d1_dil_pk = d1.keys.as_ref().unwrap().dil_pk.0.clone();
    let (kpk, ksk) = kem::keypair();
    let (ct, ss1) = kem::encapsulate(&kpk).unwrap();
    let ss2 = kem::decapsulate(&ksk, &ct).unwrap();
    let (spk, ssk) = sign::keypair();
    let msg = b"example transcript for the test-vector document";
    let sig = sign::sign_transcript(&ssk, msg).unwrap();
    let sig_ok = sign::verify_transcript(&spk, msg, &sig);

    let mut log = EventLog::new();
    let auth = simulation::run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();

    json!({
        "note": "Captured from one concrete run of the real system. Will differ on every re-run (real RNG, real timestamps, and the pqcrypto library's non-seeded keygen — see module docs above). No private key or PUF seed appears here.",
        "example_kem_roundtrip": {
            "public_key_fingerprint": fingerprint(&kpk.0),
            "public_key_size_bytes": kpk.0.len(),
            "ciphertext_size_bytes": ct.0.len(),
            "shared_secrets_match": ss1.0 == ss2.0,
        },
        "example_signature": {
            "public_key_fingerprint": fingerprint(&spk.0),
            "signature_size_bytes": sig.0.len(),
            "verifies": sig_ok,
        },
        "drone1_public_keys": {
            "kem_pk_fingerprint": fingerprint(&d1_kem_pk),
            "dil_pk_fingerprint": fingerprint(&d1_dil_pk),
        },
        "group_state": {
            "group_id": "vector-live-group",
            "root_hex": hex::encode(gcs.groups.get("vector-live-group").unwrap().root().to_bytes_le()),
            "version": gcs.groups.get("vector-live-group").unwrap().version,
        },
        "authentication_result": {
            "session_id": auth.session_id,
            "freshness_ok": auth.report.freshness_ok,
            "zk_membership_ok": auth.report.zk_membership_ok,
            "signature_ok": auth.report.signature_ok,
            "puf_ok": auth.report.puf_ok,
            "root_version_ok": auth.report.root_version_ok,
            "zero_trust_decision": format!("{:?}", auth.report.zero_trust),
            "reason_code": auth.report.reason_code,
        },
    })
}

fn main() {
    let output = json!({
        "generator": "iod-vectors",
        "generated_at_unix_ms": iod_core::protocol::events::now_unix_ms(),
        "section_a_fully_deterministic_hash_chain": section_a_deterministic(),
        "section_b_captured_real_run_non_reproducible": section_b_captured_real_run(),
    });
    let pretty = serde_json::to_string_pretty(&output).unwrap();
    println!("{pretty}");

    if let Some(dir) = std::env::args().nth(1) {
        let path = format!("{dir}/generated_vectors.json");
        std::fs::write(&path, &pretty).expect("failed to write test vectors file");
        eprintln!("\nAlso wrote: {path}");
    }
}
