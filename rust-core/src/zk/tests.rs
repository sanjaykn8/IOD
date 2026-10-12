use super::*;
use crate::merkle::tree::MerkleTree;
use super::config;

struct Fixture {
    params: ZkParams,
    pi: MembershipPublicInputs,
    rho: [u32; 8],
    siblings: Vec<Digest>,
    bits: Vec<bool>,
}

fn fixture(depth: usize, index: usize) -> Fixture {
    let g = shake_limbs(b"g", &[b"alpha"]);
    let comm = shake_limbs(b"c", &[b"pk-kem", b"pk-dil"]);
    let meta = shake_limbs(b"m", &[b"recon"]);
    let mut t = MerkleTree::new(depth);
    for i in 0..(1usize << depth).min(6) {
        let rho: [u32; 8] = core::array::from_fn(|j| 7 + (i * 13 + j) as u32);
        let leaf = leaf_hash(&g, &comm, &meta, &rho);
        t.set_leaf(i, leaf);
    }
    let rho: [u32; 8] = core::array::from_fn(|j| 7 + (index * 13 + j) as u32);
    let w = t.witness(index);
    Fixture {
        params: ZkParams::testing(depth),
        pi: MembershipPublicInputs {
            protocol_version: PROTOCOL_VERSION,
            group_version: 5,
            group_digest: g,
            root: t.root(),
            comm_pk: comm,
            metadata_digest: meta,
            session_digest: shake_limbs(b"sess", &[b"s1"]),
        },
        rho,
        siblings: w.siblings,
        bits: w.path_indices.iter().map(|&b| b == 1).collect(),
    }
}

fn witness(f: &Fixture) -> MembershipPrivateWitness {
    MembershipPrivateWitness { rho: f.rho, siblings: f.siblings.clone(), path_bits: f.bits.clone() }
}

#[test]
fn honest_proof_verifies() {
    let f = fixture(4, 3);
    let p = prove_membership(&f.params, &f.pi, &witness(&f)).unwrap();
    verify_membership(&f.params, &f.pi, &p).unwrap();
    eprintln!("proof bytes: {}", p.len());
}

fn prove_ok(f: &Fixture) -> MembershipProof {
    prove_membership(&f.params, &f.pi, &witness(f)).unwrap()
}

#[test]
fn every_member_position_verifies_and_sizes_do_not_depend_on_position() {
    let mut sizes = vec![];
    for idx in 0..6 {
        let f = fixture(4, idx);
        let p = prove_ok(&f);
        verify_membership(&f.params, &f.pi, &p).unwrap();
        sizes.push(p.len());
    }
    let (mn, mx) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
    assert!(mx - mn < mx / 20, "proof size should not leak the position: {sizes:?}");
}

#[test]
fn proofs_are_randomized_not_deterministic() {
    let f = fixture(4, 2);
    let a = prove_ok(&f);
    let b = prove_ok(&f);
    assert_ne!(a.bytes, b.bytes, "identical statement+witness must yield different proofs");
    verify_membership(&f.params, &f.pi, &a).unwrap();
    verify_membership(&f.params, &f.pi, &b).unwrap();
}

#[test]
fn proof_contains_no_witness_bytes() {
    let f = fixture(4, 3);
    let p = prove_ok(&f);
    let contains = |needle: &[u8]| p.bytes.windows(needle.len()).any(|w| w == needle);
    let rho_le: Vec<u8> = f.rho.iter().flat_map(|x| x.to_le_bytes()).collect();
    assert!(!contains(&rho_le), "rho serialized in proof");
    assert!(!contains(&rho_le[..12]), "rho prefix serialized in proof");
    for s in f.siblings.iter().filter(|s| !s.is_zero()) {
        assert!(!contains(&s.to_bytes()), "sibling serialized in proof");
        assert!(!contains(&s.to_bytes()[..12]), "sibling prefix serialized in proof");
    }
    let leaf = leaf_hash(&f.pi.group_digest, &f.pi.comm_pk, &f.pi.metadata_digest, &f.rho);
    assert!(!contains(&leaf.to_bytes()), "leaf digest serialized in proof");
    // JSON form is just hex of the same bytes, and the type has no witness field.
    let j = serde_json::to_string(&p).unwrap();
    assert!(j.contains("\"bytes\""));
    assert!(!j.contains("rho") && !j.contains("siblings") && !j.contains("path"));
}

#[test]
fn witness_debug_is_redacted() {
    let f = fixture(4, 1);
    let w = witness(&f);
    let s = format!("{w:?}");
    assert!(s.contains("redacted"));
    assert!(!s.contains(&f.rho[0].to_string()));
}

#[test]
fn invalid_witnesses_are_refused_by_prover() {
    let f = fixture(4, 3);
    let params = f.params;
    // wrong rho
    let mut w = witness(&f);
    w.rho[0] ^= 1;
    assert!(matches!(prove_membership(&params, &f.pi, &w), Err(ZkError::InvalidWitness(_))));
    // wrong sibling
    let mut w = witness(&f);
    w.siblings[1].0[0] ^= 1;
    assert!(matches!(prove_membership(&params, &f.pi, &w), Err(ZkError::InvalidWitness(_))));
    // flipped path bit
    let mut w = witness(&f);
    w.path_bits[0] = !w.path_bits[0];
    assert!(matches!(prove_membership(&params, &f.pi, &w), Err(ZkError::InvalidWitness(_))));
    // wrong path length
    let mut w = witness(&f);
    w.siblings.pop();
    w.path_bits.pop();
    assert!(matches!(prove_membership(&params, &f.pi, &w), Err(ZkError::InvalidWitness(_))));
    // non-canonical element
    let mut w = witness(&f);
    w.rho[2] = P;
    assert!(matches!(prove_membership(&params, &f.pi, &w), Err(ZkError::InvalidWitness(_))));
}

#[test]
fn statement_mismatch_is_refused_by_prover() {
    let f = fixture(4, 3);
    for mutate in [
        |pi: &mut MembershipPublicInputs| pi.group_digest[0] ^= 1,
        |pi: &mut MembershipPublicInputs| pi.comm_pk[3] ^= 1,
        |pi: &mut MembershipPublicInputs| pi.metadata_digest[5] ^= 1,
        |pi: &mut MembershipPublicInputs| pi.root.0[0] ^= 1,
    ] {
        let mut pi = f.pi.clone();
        mutate(&mut pi);
        assert!(matches!(
            prove_membership(&f.params, &pi, &witness(&f)),
            Err(ZkError::InvalidWitness(_))
        ));
    }
}

#[test]
fn revoked_zero_leaf_cannot_prove() {
    // Revocation sets the leaf slot to Digest::ZERO. A prover holding the
    // old witness for that slot cannot reach the NEW root.
    let g = shake_limbs(b"g", &[b"alpha"]);
    let comm = shake_limbs(b"c", &[b"pk"]);
    let meta = shake_limbs(b"m", &[b"r"]);
    let rho = [9u32; 8];
    let mut t = MerkleTree::new(4);
    t.set_leaf(2, leaf_hash(&g, &comm, &meta, &rho));
    t.set_leaf(3, Digest([1, 2, 3, 4, 5, 6, 7, 8]));
    let old = t.witness(2);
    t.set_leaf(2, Digest::ZERO); // revoke
    let pi = MembershipPublicInputs {
        protocol_version: PROTOCOL_VERSION, group_version: 9, group_digest: g, root: t.root(),
        comm_pk: comm, metadata_digest: meta, session_digest: [1; 11],
    };
    let w = MembershipPrivateWitness {
        rho, siblings: old.siblings.clone(), path_bits: old.path_indices.iter().map(|&b| b == 1).collect(),
    };
    assert!(matches!(
        prove_membership(&ZkParams::testing(4), &pi, &w),
        Err(ZkError::InvalidWitness(_))
    ));
}

#[test]
fn tampered_public_inputs_fail_verification() {
    let f = fixture(4, 3);
    let p = prove_ok(&f);
    let muts: Vec<(&str, Box<dyn Fn(&mut MembershipPublicInputs)>)> = vec![
        ("protocol_version", Box::new(|x| x.protocol_version += 1)),
        ("group_version", Box::new(|x| x.group_version += 1)),
        ("group_digest", Box::new(|x| x.group_digest[4] ^= 1)),
        ("root", Box::new(|x| x.root.0[7] ^= 1)),
        ("comm_pk", Box::new(|x| x.comm_pk[10] ^= 1)),
        ("metadata_digest", Box::new(|x| x.metadata_digest[0] ^= 1)),
        ("session_digest", Box::new(|x| x.session_digest[6] ^= 1)),
    ];
    for (name, m) in muts {
        let mut pi = f.pi.clone();
        m(&mut pi);
        assert!(verify_membership(&f.params, &pi, &p).is_err(), "tampered {name} accepted");
    }
}

#[test]
fn tampered_or_truncated_proof_fails() {
    let f = fixture(4, 3);
    let p = prove_ok(&f);
    for pos in [5usize, 40, p.len() / 3, p.len() / 2, p.len() - 3] {
        let mut q = p.clone();
        q.bytes[pos] ^= 0x01;
        assert!(verify_membership(&f.params, &f.pi, &q).is_err(), "flip at {pos} accepted");
    }
    let mut q = p.clone();
    q.bytes.truncate(q.len() / 2);
    assert!(verify_membership(&f.params, &f.pi, &q).is_err());
    let mut q = p.clone();
    q.bytes[0] = b'X';
    assert_eq!(verify_membership(&f.params, &f.pi, &q), Err(ZkError::Malformed));
    assert_eq!(
        verify_membership(&f.params, &f.pi, &MembershipProof { bytes: vec![] }),
        Err(ZkError::Malformed)
    );
}

#[test]
fn proof_for_other_depth_or_params_is_rejected() {
    let f = fixture(4, 3);
    let p = prove_ok(&f);
    let other = ZkParams::testing(5);
    assert!(verify_membership(&other, &f.pi, &p).is_err());
}

#[test]
fn malicious_prover_bypassing_native_check_is_rejected_by_verifier() {
    // Build a trace for a WRONG Merkle path directly (skipping
    // check_relation) and prove it. The verifier must reject: the AIR,
    // not the prover's honesty, enforces soundness.
    let f = fixture(4, 3);
    let pv = f.pi.to_field_vec().unwrap();
    let air = air::MembershipAir::new(4);
    let stream = leaf_stream(&f.pi.group_digest, &f.pi.comm_pk, &f.pi.metadata_digest, &f.rho);
    let mut bad_sibs = f.siblings.clone();
    bad_sibs[2].0[3] ^= 1; // path no longer reaches the root
    let ti = air::TraceInputs { stream: &stream, siblings: &bad_sibs, bits: &f.bits, pc: air::pc_from_pv(&pv) };
    let trace = air::build_trace(&air, &ti, f.params.trace_height(&air));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        config::prove(&f.params, &air, trace, &pv)
    }));
    match res {
        Err(_) => {} // debug builds: prover's constraint check panics
        Ok(Err(_)) => {}
        Ok(Ok(bytes)) => {
            let mut full = b"IMP2".to_vec();
            full.push(f.params.param_id());
            full.extend(bytes);
            assert!(verify_membership(&f.params, &f.pi, &MembershipProof { bytes: full }).is_err());
        }
    }
}

#[test]
fn public_input_canonicality_is_enforced() {
    let f = fixture(4, 3);
    let mut pi = f.pi.clone();
    pi.comm_pk[0] = P;
    assert_eq!(pi.to_field_vec(), Err(ZkError::OutOfRange));
}

#[test]
#[ignore]
fn standard_params_smoke() {
    let mut f = fixture(8, 5);
    f.params = ZkParams::standard(8);
    let t = std::time::Instant::now();
    let p = prove_ok(&f);
    let tp = t.elapsed();
    let t = std::time::Instant::now();
    verify_membership(&f.params, &f.pi, &p).unwrap();
    eprintln!("STANDARD depth8: proof={}B prove={:?} verify={:?} [{}]", p.len(), tp, t.elapsed(), security_report(&f.params));
}

#[test]
#[ignore]
fn param_sweep() {
    for (lb, q, pw, bw) in [(2, 100, 16, 10), (3, 70, 16, 10), (3, 60, 20, 12), (4, 50, 20, 12), (2, 120, 16, 12), (3, 80, 20, 14)] {
        let mut p = ZkParams::standard(8);
        p.log_blowup = lb; p.num_queries = q; p.query_pow_bits = pw; p.batch_pow_bits = bw;
        eprintln!("SWEEP {}", security_report(&p));
    }
}
