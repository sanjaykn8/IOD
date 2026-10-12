//! Host-simulation benchmarks. Every number is measured on this run with
//! `Instant`; nothing is assumed. ALL RESULTS ARE HOST-SIMULATION
//! MEASUREMENTS on the machine described in the header, NOT Raspberry Pi,
//! flight-controller or drone-hardware numbers.
//!
//! Run: `cargo run --release --bin iod-bench`
//! Optional env: IOD_BENCH_QUICK=1 (fewer repetitions).

use iod_core::crypto::{aead, kem, sign};
use iod_core::identity::metadata::MembershipMetadata;
use iod_core::merkle::tree::{verify_witness, MerkleTree};
use iod_core::protocol::auth_flow::*;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::group_key::*;
use iod_core::protocol::registration::{refresh_drone_cache, register_drone};
use iod_core::puf::{fuzzy_extractor, sram_puf::SramPuf};
use iod_core::zero_trust::DefaultPolicy;
use iod_core::zk::{self, MembershipPrivateWitness, MembershipPublicInputs, ZkParams};
use iod_core::zkhash::{leaf_hash, node_hash, shake_limbs, Digest};
use std::time::Instant;

fn quick() -> bool {
    std::env::var("IOD_BENCH_QUICK").is_ok()
}
fn reps(n: usize) -> usize {
    if quick() {
        (n / 10).max(3)
    } else {
        n
    }
}

fn stats(mut s: Vec<f64>, label: &str) {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    let avg = s.iter().sum::<f64>() / n as f64;
    let p95 = s[((n as f64 * 0.95) as usize).min(n - 1)];
    println!("{:<52} avg={:>10.4} ms  p50={:>10.4} ms  p95={:>10.4} ms  (n={n})", label, avg, s[n / 2], p95);
}

fn time_it<F: FnMut()>(mut f: F, trials: usize) -> Vec<f64> {
    (0..trials)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect()
}

fn cmd(c: &str, args: &[&str]) -> String {
    std::process::Command::new(c).args(args).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(|| "unknown".into())
}

fn peak_rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<f64>().ok()))
        .map(|kb| kb / 1024.0)
        .unwrap_or(f64::NAN)
}

fn header() {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string()))
        .unwrap_or_else(|| "unknown".into());
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.to_string()))
        .unwrap_or_default();
    println!("=== IoD Secure Simulator benchmarks: HOST-SIMULATION MEASUREMENTS ===");
    println!("NOT Raspberry Pi / drone-hardware numbers.");
    println!("CPU      : {cpu} ({} logical cores)", std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0));
    println!("RAM      : {mem}");
    println!("OS       : {}", cmd("uname", &["-srm"]));
    println!("rustc    : {}", cmd("rustc", &["--version"]));
    println!("build    : {}", if cfg!(debug_assertions) { "DEBUG (numbers not meaningful)" } else { "release" });
    println!("libs     : pqcrypto-kyber 0.8.1 (Kyber768), pqcrypto-dilithium 0.5.0 (Dilithium2), plonky3 =0.9.0-rc.1 (BabyBear, Poseidon2, hiding FRI), chacha20poly1305, sha3, hkdf");
    println!("quick    : {}\n", quick());
}

fn zk_fixture(depth: usize, params: &ZkParams) -> (MembershipPublicInputs, MembershipPrivateWitness) {
    let g = shake_limbs(b"g", &[b"bench"]);
    let comm = shake_limbs(b"c", &[b"pk"]);
    let meta = shake_limbs(b"m", &[b"role"]);
    let _ = params;
    let mut t = MerkleTree::new(depth);
    let rho: [u32; 8] = core::array::from_fn(|j| 11 + j as u32);
    let idx = (1usize << depth) / 2 + 1;
    for i in 0..(1usize << depth).min(64) {
        let r: [u32; 8] = core::array::from_fn(|j| 3 + (i * 7 + j) as u32);
        t.set_leaf(i, leaf_hash(&g, &comm, &meta, &r));
    }
    t.set_leaf(idx, leaf_hash(&g, &comm, &meta, &rho));
    let w = t.witness(idx);
    (
        MembershipPublicInputs {
            protocol_version: zk::PROTOCOL_VERSION,
            group_version: 1,
            group_digest: g,
            root: t.root(),
            comm_pk: comm,
            metadata_digest: meta,
            session_digest: shake_limbs(b"s", &[b"x"]),
        },
        MembershipPrivateWitness { rho, siblings: w.siblings, path_bits: w.path_indices.iter().map(|&b| b == 1).collect() },
    )
}

fn main() {
    header();

    println!("--- PUF (simulated SRAM PUF + fuzzy extractor) ---");
    let puf = SramPuf::new([1u8; 32], fuzzy_extractor::DEFAULT_BIT_FLIP_PROB);
    let enrolled = fuzzy_extractor::generate(&puf.read());
    stats(time_it(|| { let _ = fuzzy_extractor::reproduce(&puf.read(), &enrolled.helper_data); }, reps(200)), "PUF fuzzy-extractor reconstruction");

    println!("\n--- ML-KEM-768 (Kyber768) / ML-DSA-44 (Dilithium2) ---");
    stats(time_it(|| { let _ = kem::keypair(); }, reps(200)), "ML-KEM-768 keygen");
    let (kpk, ksk) = kem::keypair();
    stats(time_it(|| { let _ = kem::encapsulate(&kpk).unwrap(); }, reps(500)), "ML-KEM-768 encapsulate");
    let (ct, _) = kem::encapsulate(&kpk).unwrap();
    stats(time_it(|| { let _ = kem::decapsulate(&ksk, &ct).unwrap(); }, reps(500)), "ML-KEM-768 decapsulate");
    println!("  sizes: pk={} B, ct={} B", kpk.0.len(), ct.0.len());
    stats(time_it(|| { let _ = sign::keypair(); }, reps(200)), "ML-DSA-44 keygen");
    let (spk, ssk) = sign::keypair();
    let msg = [0x5au8; 256];
    stats(time_it(|| { let _ = sign::sign_transcript(&ssk, &msg).unwrap(); }, reps(500)), "ML-DSA-44 sign (256 B transcript)");
    let sig = sign::sign_transcript(&ssk, &msg).unwrap();
    stats(time_it(|| { let _ = sign::verify_transcript(&spk, &msg, &sig); }, reps(500)), "ML-DSA-44 verify");
    println!("  sizes: pk={} B, sig={} B", spk.0.len(), sig.0.len());

    println!("\n--- AEAD / hash / Merkle ---");
    let key = aead::AeadKey([9u8; 32]);
    let pt = vec![0x41u8; 256];
    stats(time_it(|| { let _ = aead::seal(&key, 1, b"aad", &pt); }, reps(2000)), "ChaCha20-Poly1305 seal (256 B)");
    let sealed = aead::seal(&key, 1, b"aad", &pt);
    stats(time_it(|| { let _ = aead::open(&key, b"aad", &sealed, 0); }, reps(2000)), "ChaCha20-Poly1305 open (256 B)");
    let (a, b) = (Digest([1; 8]), Digest([2; 8]));
    stats(time_it(|| { let _ = node_hash(&a, &b); }, reps(5000)), "Poseidon2 node hash (2x8 limbs -> 8)");
    let (g, c, m) = (shake_limbs(b"g", &[b"1"]), shake_limbs(b"c", &[b"2"]), shake_limbs(b"m", &[b"3"]));
    stats(time_it(|| { let _ = leaf_hash(&g, &c, &m, &[5; 8]); }, reps(2000)), "Poseidon2 leaf hash (6 permutations)");
    let mut tree = MerkleTree::new(12);
    for i in 0..500 {
        tree.set_leaf(i, Digest([i as u32 + 1; 8]));
    }
    stats(time_it(|| { let _ = tree.witness(250); }, reps(1000)), "Merkle witness generation (depth 12)");
    let w = tree.witness(250);
    let (root, leaf) = (tree.root(), tree.leaf(250));
    stats(time_it(|| { assert!(verify_witness(root, leaf, &w)); }, reps(2000)), "Merkle witness verification (depth 12)");

    println!("\n--- ZK membership proof (Plonky3 hiding FRI; Poseidon2/BabyBear AIR) ---");
    for depth in [4usize, 8, 12] {
        let params = ZkParams::standard(depth);
        let (pi, wit) = zk_fixture(depth, &params);
        println!("[depth {depth}] {}", zk::security_report(&params));
        let mut proof = None;
        let n = reps(if depth == 12 { 15 } else { 30 });
        stats(time_it(|| { proof = Some(zk::prove_membership(&params, &pi, &wit).unwrap()); }, n), &format!("ZK prove  (depth {depth})"));
        let p = proof.unwrap();
        stats(time_it(|| { zk::verify_membership(&params, &pi, &p).unwrap(); }, reps(100)), &format!("ZK verify (depth {depth})"));
        println!("  proof size = {} B ; public inputs = {} field elements (54 x 4 B = {} B); peak RSS so far = {:.1} MB", p.len(), 54, 54 * 4, peak_rss_mb());
    }

    println!("\n--- Protocol (depth 8, standard ZK parameters), per-message stage timings ---");
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("bench-d1", [21u8; 32]);
    let mut d2 = DroneState::new("bench-d2", [22u8; 32]);
    let md = MembershipMetadata { role: "bench".into(), issued_at_unix: 0 };
    let reg = time_it(
        || {
            let mut g = GcsState::new();
            let mut x = DroneState::new("bench-reg", [23u8; 32]);
            register_drone(&mut g, &mut x, "bench", md.clone(), 8).unwrap();
        },
        reps(20),
    );
    stats(reg, "R1-R3 registration (incl. keygen, 16 CRPs, 64 PIDs)");
    register_drone(&mut gcs, &mut d1, "g", md.clone(), 8).unwrap();
    register_drone(&mut gcs, &mut d2, "g", md.clone(), 8).unwrap();
    refresh_drone_cache(&gcs, &mut d1);
    refresh_drone_cache(&gcs, &mut d2);
    let n = reps(20);
    let mut t: Vec<Vec<f64>> = vec![Vec::new(); 11];
    let mut sizes = [0usize; 6];
    let mut total = Vec::new();
    let mut k_total = Vec::new();
    for rep in 0..n {
        // The GCS provisions 16 CRPs per drone (one per session); the
        // simulator has no CRP refill, so re-enroll D1 before they run out.
        if rep > 0 && rep % 12 == 0 {
            iod_core::protocol::simulation::revoke_drone(&mut gcs, "bench-d1").unwrap();
            iod_core::protocol::simulation::reactivate_drone(&mut gcs, &mut d1, 8).unwrap();
            refresh_drone_cache(&gcs, &mut d1);
            refresh_drone_cache(&gcs, &mut d2);
        }
        let t0 = Instant::now();
        let mut lap = |i: usize, s: &mut Instant| {
            t[i].push(s.elapsed().as_secs_f64() * 1000.0);
            *s = Instant::now();
        };
        let mut s = Instant::now();
        let cr = m1_comm_req(&mut d1).unwrap();
        lap(0, &mut s);
        let m2 = m2_cred_req(&d2, &cr).unwrap();
        sizes[0] = serde_json::to_vec(&m2.wire).unwrap().len();
        lap(1, &mut s);
        let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
        let (m3w, _) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
        sizes[1] = serde_json::to_vec(&m3w).unwrap().len();
        lap(2, &mut s);
        let mut d2s = d2_receive_m3(&d2, &m3w, &cr, &m2).unwrap();
        let ch = m4_challenge(&d2, &mut d2s).unwrap();
        sizes[2] = serde_json::to_vec(&ch).unwrap().len();
        lap(3, &mut s);
        let d1s = d1_verify_challenge(&d1, &ch, &cr).unwrap();
        lap(4, &mut s);
        let proof = m5_proof_bundle(&d1, &d1s).unwrap();
        sizes[3] = serde_json::to_vec(&proof).unwrap().len();
        lap(5, &mut s);
        let w6 = m6_puf_verify_req(&d2, &d2s, &proof).unwrap();
        lap(6, &mut s);
        let resp = gcs_m6_verify(&mut gcs, &w6).unwrap();
        sizes[4] = serde_json::to_vec(&resp).unwrap().len();
        lap(7, &mut s);
        let m7 = m7_verify_and_decide(&d2, &d2s, &proof, &resp, &DefaultPolicy::default());
        lap(8, &mut s);
        let m8 = m8_auth_result(&d2, &d2s, &m7.report).unwrap();
        sizes[5] = serde_json::to_vec(&m8).unwrap().len();
        let mut d1s = d1s;
        let dec = d1_verify_m8(&mut d1s, &m8).unwrap();
        let conf = d1_session_confirm(&d1, &d1s, dec).unwrap();
        lap(9, &mut s);
        total.push(t0.elapsed().as_secs_f64() * 1000.0);
        let k0 = Instant::now();
        let (kw, _) = d2_k1_group_key_req(&d2, &d2s, &m7.report, conf, "bench").unwrap();
        let rw = gcs_handle_k1(&mut gcs, &kw).unwrap();
        let (resp, del) = d2_handle_k1_response(&d2, &rw).unwrap();
        assert!(d1_verify_key_delivery(&d1s, &del));
        let _a = d1_decapsulate_group_key(&d1, &d1s, &del).unwrap();
        let _b = d2_decapsulate_group_key(&d2, &d2s, &resp).unwrap();
        k_total.push(k0.elapsed().as_secs_f64() * 1000.0);
        let _ = &mut t[10];
    }
    let names = ["M1 D1 builds CommReq", "M2 D2 builds+seals CredReq", "M2/M3 GCS checks, signs, seals", "M3/M4 D2 verifies M3, signs M4", "M4 D1 verifies M4 (GCS+D2 cred+sig4)", "M5 D1 ZK prove + MAC + sign", "M6 D2 builds+signs+seals request", "M6 GCS verifies (MAC, PID, CRP, membership)", "M7 D2 verifies ZK + sigs + decides", "M8 D2 signs; D1 verifies + confirms"];
    for (i, nme) in names.iter().enumerate() {
        stats(t[i].clone(), nme);
    }
    stats(total, "TOTAL M1-M8 (sequential, no network)");
    stats(k_total, "TOTAL K1-K3 (sequential, no network)");
    println!("  message sizes (JSON on the wire): M2={} B, M3={} B, M4={} B, M5={} B, M6resp={} B, M8={} B", sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5]);
    println!("  peak RSS of this process = {:.1} MB", peak_rss_mb());
    println!("\nReminder: host-simulation measurements only; no network, no embedded hardware.");
}
