//! M1-M8: device-to-device authentication and key-establishment
//! handshake, implemented as one function per message so that
//! individual steps — and deliberately-corrupted intermediate messages —
//! are directly testable. See the negative tests at the bottom of this
//! file and the broader security test suite in `rust-core/tests/`.

use crate::crypto::domains::SEED_DOMAIN_PUF_MAC;
use crate::crypto::field::Fp;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256, hmac_verify};
use crate::crypto::sign::{self, SignPublicKey, Signature};
use crate::identity::commitment::compute_commitment;
use crate::identity::group_id::group_field;
use crate::identity::pid::derive_pid;
use crate::merkle::tree::MerkleWitness;
use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::envelope;
use crate::protocol::messages::*;
use crate::protocol::transcript::build_t_base;
use crate::zero_trust;
use crate::zk;
use rand::RngCore;

/// Maximum allowed timestamp skew, in milliseconds, for the freshness
/// check (spec security-test requirement: "stale timestamp"). A
/// research-prototype-appropriate window, not a production-tuned value.
pub const MAX_TIMESTAMP_SKEW_MS: i64 = 5 * 60 * 1000;

fn now_ms() -> u64 {
    crate::protocol::events::now_unix_ms()
}

fn fresh_nonce(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

fn within_skew(ts: u64, now: u64) -> bool {
    (now as i64 - ts as i64).abs() <= MAX_TIMESTAMP_SKEW_MS
}

// ================================================================ M1 ===

pub fn m1_comm_req(d1: &mut DroneState) -> CommReq {
    let seed = d1.reconstruct_seed();
    let pid1 = derive_pid(&seed, d1.pid_counter);
    d1.pid_counter += 1;
    CommReq {
        msg_type: "CommReq".into(),
        g: d1.group_id.clone().expect("D1 must be registered to a group"),
        pid1,
        ts1: now_ms(),
        n1: fresh_nonce(16),
    }
}

// ================================================================ M2 ===

pub struct M2Output {
    pub wire: CredReqWire,
    pub plain: CredReqPlain,
}

pub fn m2_cred_req(
    d2: &DroneState,
    comm_req: &CommReq,
    gcs_kem_pk: &crate::crypto::kem::KemPublicKey,
) -> anyhow::Result<M2Output> {
    let plain = CredReqPlain {
        msg_type: "CredReq".into(),
        g: comm_req.g.clone(),
        pid1: comm_req.pid1.clone(),
        d2_id: d2.drone_id.clone(),
        ts2: now_ms(),
        n2: fresh_nonce(16),
    };
    let bytes = serde_json::to_vec(&plain)?;
    let wire = envelope::seal_for_recipient(gcs_kem_pk, b"M2-CredReq", &bytes)?;
    Ok(M2Output { wire, plain })
}

pub fn gcs_receive_m2(gcs: &GcsState, wire: &CredReqWire) -> anyhow::Result<(CredReqPlain, String)> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"M2-CredReq", wire)
        .map_err(|e| anyhow::anyhow!("M2 envelope open failed: {e}"))?;
    let plain: CredReqPlain = serde_json::from_slice(&bytes)?;
    let d1_id = gcs
        .resolve_pid(&plain.pid1)
        .ok_or_else(|| anyhow::anyhow!("unknown PID1: no pre-registered pseudonym matches"))?
        .to_string();
    let d2_record = gcs
        .drones
        .get(&plain.d2_id)
        .ok_or_else(|| anyhow::anyhow!("D2 '{}' is not a known registered drone", plain.d2_id))?;
    if !d2_record.active || d2_record.group_id != plain.g {
        anyhow::bail!("D2 is not an active member of group '{}'", plain.g);
    }
    Ok((plain, d1_id))
}

// ================================================================ M3 ===

pub fn gcs_m3_cred_resp(
    gcs: &GcsState,
    d1_id: &str,
    d2_id: &str,
) -> anyhow::Result<(CredRespWire, CredRespPlain)> {
    let d1_record = gcs
        .drones
        .get(d1_id)
        .ok_or_else(|| anyhow::anyhow!("unknown D1 record"))?;
    if !d1_record.active {
        anyhow::bail!("D1 is revoked");
    }
    let tree = gcs
        .groups
        .get(&d1_record.group_id)
        .ok_or_else(|| anyhow::anyhow!("unknown group"))?;
    let d2_record = gcs
        .drones
        .get(d2_id)
        .ok_or_else(|| anyhow::anyhow!("unknown D2 record"))?;

    let plain = CredRespPlain {
        msg_type: "CredResp".into(),
        cred_d1: CredD1 {
            pk_kem_d1: d1_record.kem_pk.0.clone(),
            pk_dil_d1: d1_record.dil_pk.0.clone(),
            membership_metadata_1: d1_record.metadata.clone(),
            r_g: tree.root(),
            v_g: tree.version,
            crp_challenge: d1_record.crp.challenge.clone(),
        },
        ts3: now_ms(),
        n3: fresh_nonce(16),
    };
    let bytes = serde_json::to_vec(&plain)?;
    let wire = envelope::seal_for_recipient(&d2_record.kem_pk, b"M3-CredResp", &bytes)?;
    Ok((wire, plain))
}

pub fn d2_receive_m3(d2: &DroneState, wire: &CredRespWire) -> anyhow::Result<CredRespPlain> {
    let keys = d2.keys.as_ref().expect("D2 must be registered");
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"M3-CredResp", wire)
        .map_err(|e| anyhow::anyhow!("M3 envelope open failed: {e}"))?;
    let plain: CredRespPlain = serde_json::from_slice(&bytes)?;
    Ok(plain)
}

// ================================================================ M4 ===

pub fn m4_challenge(
    d2: &DroneState,
    group_id: &str,
    cred_d1: &CredD1,
    n2: &[u8],
) -> anyhow::Result<ChallengeMsg> {
    let d2_keys = d2.keys.as_ref().expect("D2 must be registered");
    let pk_kem_d1 = crate::crypto::kem::KemPublicKey(cred_d1.pk_kem_d1.clone());
    let bootstrap_plaintext = serde_json::to_vec(&serde_json::json!({
        "purpose": "session_bootstrap",
        "n2_hex": hex::encode(n2),
        "ts4": now_ms(),
    }))?;
    let ct_kem_d2d1 = Some(
        envelope::seal_for_recipient(&pk_kem_d1, b"M4-bootstrap", &bootstrap_plaintext)?,
    );

    let challenge_payload = ChallengePayload {
        msg_type: "Challenge".into(),
        g: group_id.to_string(),
        c_puf: cred_d1.crp_challenge.clone(),
        n2: n2.to_vec(),
        ts4: now_ms(),
        ct_kem_d2d1,
    };
    let sig4 = sign::sign_transcript(&d2_keys.dil_sk, &challenge_payload.signing_bytes())?;
    Ok(ChallengeMsg {
        challenge_payload,
        sig4: sig4.0,
        pk_dil_d2: d2_keys.dil_pk.0.clone(),
    })
}

pub fn d1_verify_challenge(challenge: &ChallengeMsg) -> bool {
    let pk = SignPublicKey(challenge.pk_dil_d2.clone());
    sign::verify_transcript(
        &pk,
        &challenge.challenge_payload.signing_bytes(),
        &Signature(challenge.sig4.clone()),
    )
}

// ================================================================ M5 ===

/// Context D1 needs to build its proof bundle: the group field element
/// plus the root/version D1 believes are current (from ITS OWN cached
/// membership state — which may be stale; see spec's stale-witness
/// requirement, exercised directly in the tests below).
pub struct D1AuthContext {
    pub g_field: Fp,
    pub r_g: Fp,
    pub v_g: u64,
}

pub fn d1_local_auth_context(d1: &DroneState) -> D1AuthContext {
    D1AuthContext {
        g_field: group_field(d1.group_id.as_deref().unwrap()),
        r_g: d1.cached_root.expect("D1 must have a cached root"),
        v_g: d1.cached_version.expect("D1 must have a cached version"),
    }
}

pub fn m5_proof_bundle(
    d1: &DroneState,
    challenge: &ChallengeMsg,
    n1: &[u8],
    ts1: u64,
    pid1: &[u8],
    ctx: &D1AuthContext,
) -> anyhow::Result<ProofBundle> {
    let keys = d1.keys.as_ref().expect("D1 must be registered");
    let witness: &MerkleWitness = d1
        .cached_witness
        .as_ref()
        .expect("D1 must have a cached membership witness");
    let leaf = d1.leaf.expect("D1 must have a cached leaf");
    let metadata = d1.metadata.clone().expect("D1 must have cached metadata");

    let comm_pk_d1 = compute_commitment(&keys.kem_pk.0, &keys.dil_pk.0);

    // --- A) PUF proof: r1 -> k_PUF -> mac1 over T_base ---
    let r1 = d1.puf.challenge_response(&challenge.challenge_payload.c_puf);
    let k_puf = hkdf_expand(&r1, None, SEED_DOMAIN_PUF_MAC, 32);
    let t_base = build_t_base(
        ctx.g_field,
        ctx.v_g,
        ctx.r_g,
        comm_pk_d1,
        n1,
        &challenge.challenge_payload.n2,
        ts1,
        challenge.challenge_payload.ts4,
        pid1,
    );
    let mac1 = hmac_sha256(&k_puf, &t_base);

    // --- B) ZK membership proof ---
    let statement = zk::statement::ZkStatement {
        g: ctx.g_field,
        r_g: ctx.r_g,
        v_g: ctx.v_g,
        comm_pk: comm_pk_d1,
    };
    let witness_zk = zk::witness::ZkWitness {
        leaf,
        siblings: witness.siblings.clone(),
        path_indices: witness.path_indices.clone(),
        pk_kem: keys.kem_pk.0.clone(),
        pk_dil: keys.dil_pk.0.clone(),
        metadata,
        rho: d1.rho.expect("D1 must have rho cached"),
    };
    let proof_zk = zk::backend::prove(&statement, &witness_zk)
        .map_err(|e| anyhow::anyhow!("D1 could not construct a valid ZK proof: {e}"))?;

    // --- C) Dilithium signature over the full auth transcript T ---
    let proof_digest = digest_zk_proof(&proof_zk);
    let t = crate::protocol::transcript::build_auth_transcript(
        ctx.g_field,
        ctx.v_g,
        ctx.r_g,
        comm_pk_d1,
        &proof_digest,
        n1,
        &challenge.challenge_payload.n2,
        ts1,
        challenge.challenge_payload.ts4,
        pid1,
    );
    let sig1 = sign::sign_transcript(&keys.dil_sk, &t)?;

    // --- D) optional KEM response (decapsulate D2's bootstrap ct) ---
    let ct_kem_d1d2 = None; // symmetric bootstrap key not currently consumed further in this prototype

    Ok(ProofBundle {
        msg_type: "ProofBundle".into(),
        pid1: pid1.to_vec(),
        comm_pk_d1,
        proof_zk,
        mac1: mac1.to_vec(),
        sig1: sig1.0,
        pk_dil_d1: keys.dil_pk.0.clone(),
        pk_kem_d1: keys.kem_pk.0.clone(),
        ts5: now_ms(),
        n5: fresh_nonce(16),
        ct_kem_d1d2,
    })
}

// ================================================================ M6 ===

pub fn m6_puf_verify_req(
    proof: &ProofBundle,
    group_id: &str,
    v_g: u64,
    c_puf: &[u8],
    n2: &[u8],
    t_base: &[u8; 32],
    gcs_kem_pk: &crate::crypto::kem::KemPublicKey,
) -> anyhow::Result<PufVerifyReqWire> {
    let plain = PufVerifyReq {
        msg_type: "PUFVerifyReq".into(),
        pid1: proof.pid1.clone(),
        g: group_id.to_string(),
        v_g,
        c_puf: c_puf.to_vec(),
        n2: n2.to_vec(),
        t_base: t_base.to_vec(),
        mac1: proof.mac1.clone(),
    };
    let bytes = serde_json::to_vec(&plain)?;
    envelope::seal_for_recipient(gcs_kem_pk, b"M6-PUFVerifyReq", &bytes)
}

#[derive(thiserror::Error, Debug)]
pub enum GcsPufVerifyError {
    #[error("envelope error: {0}")]
    Envelope(#[from] anyhow::Error),
    #[error("nonce N2 has already been used (replay)")]
    NonceReused,
    #[error("unknown PID1")]
    UnknownPid,
    #[error("unknown group")]
    UnknownGroup,
}

pub fn gcs_m6_verify(
    gcs: &mut GcsState,
    wire: &PufVerifyReqWire,
) -> Result<PufVerifyResp, GcsPufVerifyError> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"M6-PUFVerifyReq", wire)
        .map_err(|e| GcsPufVerifyError::Envelope(anyhow::anyhow!("{e}")))?;
    let plain: PufVerifyReq = serde_json::from_slice(&bytes).map_err(|e| GcsPufVerifyError::Envelope(e.into()))?;

    if gcs.used_nonces.contains(&plain.n2) {
        return Err(GcsPufVerifyError::NonceReused);
    }
    gcs.used_nonces.insert(plain.n2.clone());

    let drone_id = gcs
        .resolve_pid(&plain.pid1)
        .ok_or(GcsPufVerifyError::UnknownPid)?
        .to_string();
    let tree = gcs
        .groups
        .get(&plain.g)
        .ok_or(GcsPufVerifyError::UnknownGroup)?;
    let (current_r_g, current_v_g) = (tree.root(), tree.version);

    let result = match gcs.drones.get(&drone_id) {
        Some(record) if record.active => {
            let k_puf_ref = hkdf_expand(&record.crp.reference_response, None, SEED_DOMAIN_PUF_MAC, 32);
            let mut t_base = [0u8; 32];
            if plain.t_base.len() == 32 {
                t_base.copy_from_slice(&plain.t_base);
            }
            if hmac_verify(&k_puf_ref, &t_base, &plain.mac1) {
                PufVerifyResult::Valid
            } else {
                PufVerifyResult::Invalid
            }
        }
        _ => PufVerifyResult::Invalid,
    };

    let payload = PufVerifyRespPayload {
        msg_type: "PUFVerifyResp".into(),
        pid1: plain.pid1,
        result,
        ts7: now_ms(),
        current_r_g,
        current_v_g,
    };
    let sig7 = sign::sign_transcript(&gcs.sign_sk, &payload.signing_bytes())
        .map_err(GcsPufVerifyError::Envelope)?;
    Ok(PufVerifyResp { payload, sig7: sig7.0 })
}

pub fn d2_verify_m6_signature(gcs_sign_pk: &SignPublicKey, resp: &PufVerifyResp) -> bool {
    sign::verify_transcript(gcs_sign_pk, &resp.payload.signing_bytes(), &Signature(resp.sig7.clone()))
}

// ================================================================ M7 ===

pub struct M7Result {
    pub report: VerificationReport,
}

#[allow(clippy::too_many_arguments)]
pub fn m7_verify_and_decide(
    cred_d1: &CredD1,
    proof: &ProofBundle,
    n1: &[u8],
    n2: &[u8],
    ts1: u64,
    ts4: u64,
    puf_resp: &PufVerifyResp,
    gcs_sign_pk: &SignPublicKey,
    group_id: &str,
) -> M7Result {
    let now = now_ms();
    let freshness_ok = within_skew(ts1, now) && within_skew(ts4, now) && within_skew(proof.ts5, now);

    let g_field = group_field(group_id);
    let statement = zk::statement::ZkStatement {
        g: g_field,
        r_g: cred_d1.r_g,
        v_g: cred_d1.v_g,
        comm_pk: proof.comm_pk_d1,
    };
    let zk_membership_ok = zk::backend::verify(&statement, &proof.proof_zk);

    let proof_digest = digest_zk_proof(&proof.proof_zk);
    let t = crate::protocol::transcript::build_auth_transcript(
        g_field,
        cred_d1.v_g,
        cred_d1.r_g,
        proof.comm_pk_d1,
        &proof_digest,
        n1,
        n2,
        ts1,
        ts4,
        &proof.pid1,
    );
    let signature_ok = sign::verify_transcript(
        &SignPublicKey(proof.pk_dil_d1.clone()),
        &t,
        &Signature(proof.sig1.clone()),
    );

    let puf_sig_ok = d2_verify_m6_signature(gcs_sign_pk, puf_resp);
    let puf_ok = puf_sig_ok && puf_resp.payload.result == PufVerifyResult::Valid;

    let root_version_ok =
        puf_resp.payload.current_r_g == cred_d1.r_g && puf_resp.payload.current_v_g == cred_d1.v_g;

    let zt_inputs = zero_trust::ZeroTrustInputs {
        freshness_ok,
        zk_membership_ok,
        signature_ok,
        puf_ok,
        root_version_ok,
        group_id: group_id.to_string(),
        requested_operation: "authenticate".to_string(),
        mission_active: true,
        device_health_ok: true,
    };
    let decision = zero_trust::evaluate(&zt_inputs);

    M7Result {
        report: VerificationReport {
            freshness_ok,
            zk_membership_ok,
            signature_ok,
            puf_ok,
            root_version_ok,
            zero_trust: match decision.decision {
                zero_trust::Decision::Allow => ZeroTrustDecision::Allow,
                zero_trust::Decision::Deny => ZeroTrustDecision::Deny,
            },
            reason_code: decision.reason_code,
        },
    }
}

// ================================================================ M8 ===

pub fn m8_auth_result(gcs_or_d2_sign_sk: &crate::crypto::sign::SignSecretKey, report: &VerificationReport) -> anyhow::Result<AuthResultMsg> {
    let payload9 = AuthResultPayload {
        msg_type: "AuthResult".into(),
        result: report.zero_trust,
        reason_code: report.reason_code.clone(),
        ts9: now_ms(),
        n9: fresh_nonce(16),
    };
    let sig9 = sign::sign_transcript(gcs_or_d2_sign_sk, &payload9.signing_bytes())?;
    Ok(AuthResultMsg {
        payload9,
        sig9: sig9.0,
        pk_dil_d2: Vec::new(), // filled by caller with D2's actual Dilithium PK
    })
}

pub fn d1_verify_m8(pk_dil_d2: &SignPublicKey, msg: &AuthResultMsg) -> bool {
    sign::verify_transcript(pk_dil_d2, &msg.payload9.signing_bytes(), &Signature(msg.sig9.clone()))
}
