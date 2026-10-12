//! Test-vector generator.
//!
//! Section A: fully deterministic known-answer values (fixed literal
//! inputs, no RNG): SHAKE-limb digests, Poseidon2 leaf/node hashes and a
//! Merkle root. These are reproducible on any machine.
//!
//! Section B: one real run (random keys, nonces, PUF noise, proof
//! randomness). Values differ every run by design; only booleans and
//! sizes are stable. No secret (private key, rho, PUF seed, AEAD key,
//! KEM shared secret, witness) is printed.

use iod_core::identity::metadata::MembershipMetadata;
use iod_core::merkle::tree::MerkleTree;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::events::EventLog;
use iod_core::protocol::registration::{refresh_drone_cache, register_drone};
use iod_core::protocol::simulation::*;
use iod_core::zkhash::*;

fn main() {
    let out_dir = std::env::args().nth(1);
    let mut j = serde_json::Map::new();
    j.insert("param_set_id".into(), PARAM_SET_ID.into());
    println!("=== Section A: deterministic known-answer vectors (PARAM_SET_ID={PARAM_SET_ID}) ===");
    let g = shake_limbs(b"IOD/v2/GROUP", &[b"alpha"]);
    let comm = shake_limbs(b"IOD/v2/COMM-PK", &[b"pk-kem-literal", b"pk-dil-literal"]);
    let meta = shake_limbs(b"IOD/v2/METADATA", &[b"recon", &1_700_000_000u64.to_le_bytes()]);
    println!("G            = {g:?}");
    println!("comm_PK      = {comm:?}");
    println!("meta_digest  = {meta:?}");
    let rho: [u32; 8] = core::array::from_fn(|i| 1000 + i as u32);
    let leaf = leaf_hash(&g, &comm, &meta, &rho);
    println!("leaf (rho=1000..1007) = {}", leaf.to_hex());
    let mut t = MerkleTree::new(3);
    t.set_leaf(0, leaf);
    t.set_leaf(1, Digest([7; 8]));
    println!("node(leaf,[7;8])      = {}", node_hash(&leaf, &Digest([7; 8])).to_hex());
    println!("depth-3 root          = {}", t.root().to_hex());
    j.insert("deterministic".into(), serde_json::json!({
        "G": g, "comm_pk": comm, "meta_digest": meta, "rho": rho,
        "leaf_hex": leaf.to_hex(),
        "node_leaf_7_hex": node_hash(&leaf, &Digest([7; 8])).to_hex(),
        "depth3_root_hex": t.root().to_hex(),
    }));

    println!("\n=== Section B: one live run (values vary; booleans/sizes are the stable part) ===");
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("vec-d1", [1u8; 32]);
    let mut d2 = DroneState::new("vec-d2", [2u8; 32]);
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 };
    register_drone(&mut gcs, &mut d1, "vec-group", md.clone(), 6).unwrap();
    register_drone(&mut gcs, &mut d2, "vec-group", md, 6).unwrap();
    refresh_drone_cache(&gcs, &mut d1);
    let mut log = EventLog::new();
    let r = run_authentication(&mut gcs, &mut d1, &d2, &mut log).unwrap();
    println!("group root R_G        = {}", r.d1_session.r_g.to_hex());
    println!("group version V_G     = {}", r.d1_session.v_g);
    println!("session_id            = {}", r.session_id);
    println!("session_ctx digest    = {:?}", r.report.session_ctx);
    println!("zk proof size         = {} bytes (magic IMP2)", r.proof_bundle.proof.len());
    println!("D1 credential id      = {}", hex::encode(d1.credential.as_ref().unwrap().body.cred_id));
    println!("report: {:?}", r.report);
    println!("D1 decision (from verified M8) = {:?}", r.d1_decision);
    println!("events logged: {}", log.events.len());
    j.insert("live_run_NOT_REPRODUCIBLE".into(), serde_json::json!({
        "r_g_hex": r.d1_session.r_g.to_hex(), "v_g": r.d1_session.v_g,
        "session_id": r.session_id, "session_ctx": r.report.session_ctx,
        "zk_proof_bytes": r.proof_bundle.proof.len(),
        "authenticated": r.report.authenticated, "decision": format!("{:?}", r.report.zero_trust),
        "reason_code": r.report.reason_code, "events": log.events.len(),
    }));
    if let Some(dir) = out_dir {
        let path = std::path::Path::new(&dir).join("generated_vectors.json");
        std::fs::write(&path, serde_json::to_string_pretty(&serde_json::Value::Object(j)).unwrap()).unwrap();
        println!("wrote {}", path.display());
    }
}
