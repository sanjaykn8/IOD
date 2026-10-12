//! Prints a REAL run of R1-R3, M1-M8, K1-K3 with actual values (public
//! values in full or truncated; secrets only as 8-byte fingerprints).
//! `cargo run --release --example walkthrough`
use iod_core::crypto::kdf::shake256_bytes;
use iod_core::identity::metadata::MembershipMetadata;
use iod_core::merkle::tree::MerkleTree;
use iod_core::protocol::auth_flow::*;
use iod_core::protocol::entities::*;
use iod_core::protocol::group_key::*;
use iod_core::protocol::registration::*;
use iod_core::zero_trust::DefaultPolicy;
use iod_core::zkhash::*;

fn fp(b: &[u8]) -> String {
    hex::encode(shake256_bytes(b"walkthrough-fingerprint", b, 4))
}
fn h(b: &[u8]) -> String {
    let x = hex::encode(b);
    if x.len() > 24 { format!("{}…({} B)", &x[..24], b.len()) } else { x }
}
fn dg(d: &Digest) -> String {
    format!("{}…", &d.to_hex()[..16])
}

fn main() {
    println!("##### Tiny Merkle example (depth 3, 3 members) #####");
    let leaves = [Digest([11; 8]), Digest([22; 8]), Digest([33; 8])];
    let mut t = MerkleTree::new(3);
    for (i, l) in leaves.iter().enumerate() {
        t.set_leaf(i, *l);
    }
    let w = t.witness(1);
    println!("leaf1 = {}  index=1  path_bits={:?}", dg(&leaves[1]), w.path_indices);
    let mut cur = leaves[1];
    for (i, (s, b)) in w.siblings.iter().zip(&w.path_indices).enumerate() {
        cur = if *b == 1 { node_hash(s, &cur) } else { node_hash(&cur, s) };
        println!("  level {i}: sibling={} bit={} -> parent={}", dg(s), b, dg(&cur));
    }
    println!("  root = {}  (tree.root() = {})", dg(&cur), dg(&t.root()));

    println!("\n##### R1-R3 #####");
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("drone-1", [11u8; 32]);
    let mut d2 = DroneState::new("drone-2", [22u8; 32]);
    let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 };
    let golden = d1.puf.read();
    println!("R1 PUF read: {} bits; fingerprint of one noisy reading = {}; two readings differ in {} bits (noise)", golden.len() * 8, fp(&golden),
        golden.iter().zip(d1.puf.read().iter()).map(|(a, b)| (a ^ b).count_ones()).sum::<u32>());
    register_drone(&mut gcs, &mut d1, "alpha", md.clone(), 4).unwrap();
    register_drone(&mut gcs, &mut d2, "alpha", md, 4).unwrap();
    refresh_drone_cache(&gcs, &mut d1);
    refresh_drone_cache(&gcs, &mut d2);
    let rec = &gcs.drones["drone-1"];
    println!("R1 helper data = {} B (public); seed fingerprint = {} (secret, not shown)", d1.helper_data.as_ref().unwrap().0.len(), fp(&d1.reconstruct_seed()));
    println!("R1 CRP table at GCS: {} entries; CRP[0].challenge = {} ; reference response fp = {}", rec.crps.len(), h(&rec.crps[0].challenge), fp(&rec.crps[0].reference_response));
    println!("R2 pk_kem={} B, pk_dil={} B, comm_PK[0..3]={:?}", d1.keys.as_ref().unwrap().kem_pk.0.len(), d1.keys.as_ref().unwrap().dil_pk.0.len(), &rec.comm_pk[..3]);
    println!("R3 leaf = {} ; leaf index = {:?} ; R_G = {} ; V_G = {}", dg(d1.leaf.as_ref().unwrap()), gcs.groups["alpha"].leaf_index_of("drone-1"), dg(&d1.cached_root.unwrap()), d1.cached_version.unwrap());
    println!("R3 credential id = {} (random, not the DroneID), expires_at_ms - issued = {} days", hex::encode(d1.credential.as_ref().unwrap().body.cred_id),
        (d1.credential.as_ref().unwrap().body.expires_at_ms - d1.credential.as_ref().unwrap().body.issued_at_ms) / 86_400_000);
    println!("R3 PIDs registered: {} ; PID[0] = {}", d1.pid_registered_upto, h(&iod_core::identity::pid::derive_pid(&d1.reconstruct_seed(), 0)));

    println!("\n##### M1-M8 #####");
    let cr = m1_comm_req(&mut d1).unwrap();
    println!("M1 CommReq: G={} PID1={} ts1={} n1={}", cr.g, h(&cr.pid1), cr.ts1, h(&cr.n1));
    let m2 = m2_cred_req(&d2, &cr).unwrap();
    println!("M2 body: d2_cred_id={} ts2={} n2={}; sealed wire = {} B JSON", hex::encode(m2.body.d2_cred_id), m2.body.ts2, h(&m2.body.n2), serde_json::to_vec(&m2.wire).unwrap().len());
    let acc = gcs_receive_m2(&mut gcs, &m2.wire).unwrap();
    println!("   GCS: PID1 resolves internally to '{}' (D2 never sees this); PID state before M3 = {:?}", acc.d1_id, gcs.pid_pool[&cr.pid1].state);
    let (m3w, m3) = gcs_m3_cred_resp(&mut gcs, &acc).unwrap();
    println!("M3 session_id={} C_PUF={} R_G={} V_G={} sig3={} B; PID state now {:?}; CRP reserved", m3.body.session_id, h(&m3.body.c_puf), dg(&m3.body.r_g), m3.body.v_g, m3.sig3.len(), gcs.pid_pool[&cr.pid1].state);
    let mut d2s = d2_receive_m3(&d2, &m3w, &cr, &m2).unwrap();
    let ch = m4_challenge(&d2, &mut d2s).unwrap();
    println!("M4 ts4={} sig4={} B; carries D2 credential ({} B pk_dil) and GCS-signed M3", ch.payload.ts4, ch.sig4.len(), ch.d2_cred.body.pk_dil.len());
    let d1s = d1_verify_challenge(&d1, &ch, &cr).unwrap();
    println!("   D1 verified: GCS sig on M3, D2 credential vs anchor, sig4 vs certified D2 key. session_ctx limbs[0..3]={:?}", &d1s.session_ctx[..3]);
    let proof = m5_proof_bundle(&d1, &d1s).unwrap();
    println!("M5 proof = {} B (IMP2 header {:?}), mac1={} sig1={} B; bundle JSON has no key/witness fields", proof.proof.len(), &proof.proof.bytes[..4], h(&proof.mac1), proof.sig1.len());
    let w6 = m6_puf_verify_req(&d2, &d2s, &proof).unwrap();
    let resp = gcs_m6_verify(&mut gcs, &w6).unwrap();
    println!("M6 GCS result={:?} reason={} current R_G={} V_G={} sig7={} B; session state={:?}; CRP now Used", resp.body.result, resp.body.reason_code, dg(&resp.body.current_r_g), resp.body.current_v_g, resp.sig7.len(), gcs.sessions[&m3.body.session_id].state);
    let m7 = m7_verify_and_decide(&d2, &d2s, &proof, &resp, &DefaultPolicy::default());
    println!("M7 {:?}", m7.report);
    let m8 = m8_auth_result(&d2, &d2s, &m7.report).unwrap();
    let mut d1s = d1s;
    let dec = d1_verify_m8(&mut d1s, &m8).unwrap();
    let conf = d1_session_confirm(&d1, &d1s, dec).unwrap();
    println!("M8 D1 read {:?} under D2's certified key; sig8={} B; D1 confirm sig={} B", dec, m8.sig8.len(), conf.sig.len());

    println!("\n##### K1-K3 #####");
    let (kw, _) = d2_k1_group_key_req(&d2, &d2s, &m7.report, conf, "mission-7").unwrap();
    let rw = gcs_handle_k1(&mut gcs, &kw).unwrap();
    println!("K1 accepted; session state={:?}", gcs.sessions[&m3.body.session_id].state);
    let (resp_k, del) = d2_handle_k1_response(&d2, &rw).unwrap();
    println!("K2 forwarded D1's sealed key; D1 verifies sig8 = {}", d1_verify_key_delivery(&d1s, &del));
    let a = d1_decapsulate_group_key(&d1, &d1s, &del).unwrap();
    let b = d2_decapsulate_group_key(&d2, &d2s, &resp_k).unwrap();
    println!("K3 both hold the same K_G,M: {} (fp {}); epoch={} n6={} n7={}", a.k_g_m == b.k_g_m, fp(&a.k_g_m), a.inner.key_epoch, h(&a.inner.n6), h(&a.inner.n7));
    let ck = derive_channel_keys(&a, &d1.credential.as_ref().unwrap().body.cred_id, &d2.credential.as_ref().unwrap().body.cred_id);
    println!("K4 channel tag = {} ; d1->d2 key fp = {} ; d2->d1 key fp = {}", hex::encode(ck.channel_tag), fp(&ck.d1_to_d2.0), fp(&ck.d2_to_d1.0));
}
