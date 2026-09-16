//! Real, executed benchmarks for every primitive the project brief asks
//! for. Reports average, p50, and p95 latency over N trials (default
//! 100, or 1000 for very fast operations), computed from actually
//! measured `Instant::now()` deltas — nothing here is a fabricated or
//! assumed number. Also reports a few concrete sizes (proof size,
//! message size) where meaningful.
//!
//! Run with: `cargo run --release --bin iod-bench`

use iod_core::crypto::{aead, kem, poseidon, sign};
use iod_core::identity;
use iod_core::merkle::group_tree::GroupMembershipTree;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::events::EventLog;
use iod_core::protocol::registration::register_drone;
use iod_core::protocol::simulation;
use iod_core::puf::{fuzzy_extractor, sram_puf::SramPuf};
use iod_core::zk;
use std::time::Instant;

fn stats(mut samples: Vec<f64>, label: &str, unit: &str) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let avg = samples.iter().sum::<f64>() / n as f64;
    let p50 = samples[n / 2];
    let p95_idx = ((n as f64 * 0.95) as usize).min(n - 1);
    let p95 = samples[p95_idx];
    println!(
        "{:<45} avg={:>10.6}{unit}  p50={:>10.6}{unit}  p95={:>10.6}{unit}  (n={n})",
        label, avg, p50, p95
    );
}

fn time_it<F: FnMut()>(mut f: F, trials: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(trials);
    for _ in 0..trials {
        let start = Instant::now();
        f();
        out.push(start.elapsed().as_secs_f64() * 1000.0); // ms
    }
    out
}

fn main() {
    println!("=== IoD Secure Simulator — Benchmarks ===");
    println!("(all numbers below are actually measured on this run, not assumed)\n");

    // --- PUF reconstruction ---
    let puf = SramPuf::new([1u8; 32], fuzzy_extractor::DEFAULT_BIT_FLIP_PROB);
    let reference = puf.read();
    let enrolled = fuzzy_extractor::generate(&reference);
    let samples = time_it(
        || {
            let noisy = puf.read();
            let _ = fuzzy_extractor::reproduce(&noisy, &enrolled.helper_data);
        },
        200,
    );
    stats(samples, "PUF fuzzy-extractor reconstruction", "ms");

    // --- ML-KEM / Kyber768 ---
    let samples = time_it(|| { let _ = kem::keypair(); }, 100);
    stats(samples, "ML-KEM-768 (Kyber768) key generation", "ms");

    let (kpk, ksk) = kem::keypair();
    let samples = time_it(|| { let _ = kem::encapsulate(&kpk).unwrap(); }, 200);
    stats(samples, "ML-KEM-768 encapsulate", "ms");

    let (ct, _ss) = kem::encapsulate(&kpk).unwrap();
    let samples = time_it(|| { let _ = kem::decapsulate(&ksk, &ct).unwrap(); }, 200);
    stats(samples, "ML-KEM-768 decapsulate", "ms");
    println!("{:<45} {} bytes", "  -> Kyber768 public key size", kpk.0.len());
    println!("{:<45} {} bytes", "  -> Kyber768 ciphertext size", ct.0.len());

    // --- ML-DSA / Dilithium2 ---
    let samples = time_it(|| { let _ = sign::keypair(); }, 100);
    stats(samples, "ML-DSA-44 (Dilithium2) key generation", "ms");

    let (spk, ssk) = sign::keypair();
    let msg = b"benchmark authentication transcript payload of representative length!!";
    let samples = time_it(|| { let _ = sign::sign_transcript(&ssk, msg).unwrap(); }, 100);
    stats(samples, "ML-DSA-44 sign", "ms");

    let sig = sign::sign_transcript(&ssk, msg).unwrap();
    let samples = time_it(|| { let _ = sign::verify_transcript(&spk, msg, &sig); }, 100);
    stats(samples, "ML-DSA-44 verify", "ms");
    println!("{:<45} {} bytes", "  -> Dilithium2 public key size", spk.0.len());
    println!("{:<45} {} bytes", "  -> Dilithium2 signature size", sig.0.len());

    // --- Poseidon ---
    use iod_core::crypto::field::Fp;
    let inputs: Vec<Fp> = (0..8).map(Fp::new).collect();
    let samples = time_it(|| { let _ = poseidon::hash(1, &inputs); }, 1000);
    stats(samples, "Poseidon hash (8 field elements)", "ms");

    // --- Merkle tree ---
    let mut tree = GroupMembershipTree::new("bench-group", 12); // capacity 4096
    for i in 0..500u64 {
        tree.register(&format!("d{i}"), Fp::new(1000 + i)).unwrap();
    }
    let samples = time_it(
        || {
            let mut t2 = GroupMembershipTree::new("bench-scratch", 12);
            let _ = t2.register("d0", Fp::new(1));
        },
        200,
    );
    stats(samples, "Merkle registration (single leaf, depth=12)", "ms");

    let samples = time_it(|| { let _ = tree.witness_for("d250").unwrap(); }, 500);
    stats(samples, "Merkle witness generation (depth=12, 500 members)", "ms");

    let w = tree.witness_for("d250").unwrap();
    let leaf = Fp::new(1250);
    let root = tree.root();
    let samples = time_it(
        || { let _ = iod_core::merkle::tree::verify_witness(root, leaf, &w); },
        1000,
    );
    stats(samples, "Merkle witness verification (depth=12)", "ms");

    // --- ZK membership proof ---
    let md = identity::metadata::MembershipMetadata { role: "bench".into(), issued_at_unix: 0 };
    let rho = [7u8; 32];
    let leaf_val = identity::leaf::compute_leaf(b"pk-kem-bench", b"pk-dil-bench", "bench-group-zk", &md, &rho);
    let mut ztree = GroupMembershipTree::new("bench-group-zk", 10);
    ztree.register("zk-bench-drone", leaf_val).unwrap();
    let zw = ztree.witness_for("zk-bench-drone").unwrap();
    let statement = zk::statement::ZkStatement {
        g: identity::group_id::group_field("bench-group-zk"),
        r_g: ztree.root(),
        v_g: ztree.version,
        comm_pk: identity::commitment::compute_commitment(b"pk-kem-bench", b"pk-dil-bench"),
    };
    let witness = zk::witness::ZkWitness {
        leaf: leaf_val,
        siblings: zw.siblings.clone(),
        path_indices: zw.path_indices.clone(),
        pk_kem: b"pk-kem-bench".to_vec(),
        pk_dil: b"pk-dil-bench".to_vec(),
        metadata: md.clone(),
        rho,
    };
    let samples = time_it(|| { let _ = zk::backend::prove(&statement, &witness).unwrap(); }, 200);
    stats(samples, "ZK membership proof generation (depth=10)", "ms");

    let proof = zk::backend::prove(&statement, &witness).unwrap();
    let samples = time_it(|| { let _ = zk::backend::verify(&statement, &proof); }, 200);
    stats(samples, "ZK membership proof verification (depth=10)", "ms");
    let proof_bytes = serde_json::to_vec(&proof).unwrap();
    println!("{:<45} {} bytes (JSON-serialized)", "  -> ZK proof size", proof_bytes.len());

    // --- AEAD ---
    let key = aead::AeadKey([9u8; 32]);
    let plaintext = vec![0x41u8; 256];
    let samples = time_it(|| { let _ = aead::seal(&key, 1, b"aad", &plaintext); }, 1000);
    stats(samples, "AEAD (ChaCha20-Poly1305) seal (256B)", "ms");

    let sealed = aead::seal(&key, 1, b"aad", &plaintext);
    let samples = time_it(|| { let _ = aead::open(&key, b"aad", &sealed, 0); }, 1000);
    stats(samples, "AEAD (ChaCha20-Poly1305) open (256B)", "ms");

    // --- Full authentication end-to-end ---
    let samples = time_it(
        || {
            let mut gcs = GcsState::new();
            let mut d1 = DroneState::new("bench-d1", [21u8; 32]);
            let mut d2 = DroneState::new("bench-d2", [22u8; 32]);
            let md = identity::metadata::MembershipMetadata { role: "bench".into(), issued_at_unix: 0 };
            register_drone(&mut gcs, &mut d1, "bench-auth-group", md.clone(), 8).unwrap();
            register_drone(&mut gcs, &mut d2, "bench-auth-group", md, 8).unwrap();
            iod_core::protocol::registration::refresh_drone_cache(&gcs, &mut d1);
            let mut log = EventLog::new();
            let _ = simulation::run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
        },
        50,
    );
    stats(samples, "Full end-to-end authentication (M1-M8, incl. registration)", "ms");

    // --- Group key establishment ---
    let samples = time_it(
        || {
            let mut gcs = GcsState::new();
            let mut d1 = DroneState::new("bench-gk-d1", [31u8; 32]);
            let mut d2 = DroneState::new("bench-gk-d2", [32u8; 32]);
            let md = identity::metadata::MembershipMetadata { role: "bench".into(), issued_at_unix: 0 };
            register_drone(&mut gcs, &mut d1, "bench-gk-group", md.clone(), 8).unwrap();
            register_drone(&mut gcs, &mut d2, "bench-gk-group", md, 8).unwrap();
            let d1_pid1 = identity::pid::derive_pid(&d1.reconstruct_seed(), 0);
            gcs.pid_pool.insert(d1_pid1.clone(), d1.drone_id.clone());
            use iod_core::protocol::group_key::*;
            let (wire1, _plain1) = k1_group_key_req(&d2, "bench-gk-group", &d1_pid1, "bench-mission", [0u8; 32], &gcs.kem_pk).unwrap();
            let wire7 = gcs_handle_k1(&gcs, &wire1).unwrap();
            let (_resp, key_delivery) = d2_handle_k1_response(&d2, &wire7).unwrap();
            let _ = d1_decapsulate_group_key(&d1, &key_delivery).unwrap();
        },
        50,
    );
    stats(samples, "Group-key establishment (K1-K4)", "ms");

    println!("\nDone. These numbers were measured with `cargo run --release` on this sandbox VM's shared CPU — they demonstrate relative cost and correctness of measurement methodology, but are NOT representative of embedded-drone-hardware performance (which would have a much slower CPU, no OS-level scheduling noise from a shared VM host, and different cache behavior). Re-run this binary directly on target hardware for numbers that matter for a real deployment decision.");
}
