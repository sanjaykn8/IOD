//! M1-M8: device-to-device authentication, one function per message so
//! that every step -- and deliberately corrupted intermediate messages --
//! is directly testable.
//!
//! Trust model (see docs/protocol.md):
//! * Every drone pins the GCS ML-DSA key (trust anchor) and GCS ML-KEM key
//!   at enrollment. Every key used to verify a message comes from a
//!   GCS-signed credential verified against that anchor, never from the
//!   message being verified.
//! * M3 is signed by the GCS and forwarded by D2 to D1 (inside M4), so D1
//!   learns R_G, V_G and C_PUF from the GCS itself.
//! * The GCS verifies the PUF MAC, PID/CRP/session state, membership and
//!   freshness (M6). D2 verifies the zero-knowledge membership proof, the
//!   ML-DSA signature, the GCS response and the session binding (M7).
//!   Authentication results are reported separately from the Zero Trust
//!   authorization decision.

use crate::crypto::domains::SEED_DOMAIN_PUF_MAC;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256, hmac_verify};
use crate::crypto::sign::{self, SignPublicKey, Signature};
use crate::identity::commitment::comm_pk as compute_comm_pk;
use crate::identity::group_id::group_digest;
use crate::identity::pid::derive_pid;
use crate::protocol::credentials::SignedCredential;
use crate::protocol::entities::*;
use crate::protocol::envelope;
use crate::protocol::messages::*;
use crate::protocol::transcript::*;
use crate::protocol::{MAX_TIMESTAMP_SKEW_MS, SESSION_VALIDITY_MS};
use crate::zero_trust;
use crate::zk::{self, MembershipPrivateWitness, MembershipPublicInputs, ZkParams, PROTOCOL_VERSION};
use crate::zkhash::{Digest, Limbs};
use rand::RngCore;

fn now_ms() -> u64 {
    crate::protocol::events::now_unix_ms()
}

pub fn fresh_nonce(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

pub fn within_skew(ts: u64, now: u64) -> bool {
    (now as i64 - ts as i64).abs() <= MAX_TIMESTAMP_SKEW_MS
}

pub fn zk_params_for(depth: usize) -> ZkParams {
    ZkParams::standard(depth)
}

/// Protocol-level error carrying a stable machine-readable reason code.
#[derive(thiserror::Error, Debug)]
#[error("{code}: {detail}")]
pub struct AuthError {
    pub code: &'static str,
    pub detail: String,
}

pub fn err<T>(code: &'static str, detail: impl Into<String>) -> Result<T, AuthError> {
    Err(AuthError { code, detail: detail.into() })
}

impl From<anyhow::Error> for AuthError {
    fn from(e: anyhow::Error) -> Self {
        AuthError { code: "INTERNAL", detail: e.to_string() }
    }
}

fn hex16(b: &[u8; 16]) -> String {
    hex::encode(b)
}

// ================================================================ M1 ===

pub fn m1_comm_req(d1: &mut DroneState) -> Result<CommReq, AuthError> {
    if !d1.is_registered() || d1.revoked {
        return err("NOT_REGISTERED", "D1 is not registered or is revoked");
    }
    if d1.pid_counter >= d1.pid_registered_upto {
        return err("PID_POOL_EXHAUSTED", "no registered pseudonyms left; top-up required");
    }
    let seed = d1.reconstruct_seed();
    let pid1 = derive_pid(&seed, d1.pid_counter);
    d1.pid_counter += 1;
    Ok(CommReq { g: d1.group_id.clone().unwrap(), pid1, ts1: now_ms(), n1: fresh_nonce(16) })
}

// ================================================================ M2 ===

pub struct M2Output {
    pub wire: CredReqWire,
    pub body: CredReqBody,
}

pub fn m2_cred_req(d2: &DroneState, comm_req: &CommReq) -> Result<M2Output, AuthError> {
    if !d2.is_registered() || d2.revoked {
        return err("NOT_REGISTERED", "D2 is not registered or is revoked");
    }
    let keys = d2.keys.as_ref().unwrap();
    let body = CredReqBody {
        g: comm_req.g.clone(),
        pid1: comm_req.pid1.clone(),
        n1: comm_req.n1.clone(),
        ts1: comm_req.ts1,
        d2_cred_id: d2.credential.as_ref().unwrap().body.cred_id,
        ts2: now_ms(),
        n2: fresh_nonce(16),
    };
    let sig2 = sign::sign_transcript(&keys.dil_sk, &body.signing_bytes())?;
    let plain = CredReqPlain { body: body.clone(), sig2: sig2.0 };
    let bytes = serde_json::to_vec(&plain).map_err(anyhow::Error::from)?;
    let wire = envelope::seal_for_recipient(d2.gcs_kem_pk.as_ref().unwrap(), b"M2-CredReq", &bytes)?;
    Ok(M2Output { wire, body })
}

pub struct M2Accepted {
    pub plain: CredReqPlain,
    pub d1_id: String,
    pub d2_id: String,
}

/// GCS: open and validate M2 (no session state is created yet).
pub fn gcs_receive_m2(gcs: &mut GcsState, wire: &CredReqWire) -> Result<M2Accepted, AuthError> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"M2-CredReq", wire)
        .map_err(|e| AuthError { code: "ENVELOPE_INVALID", detail: e.to_string() })?;
    let plain: CredReqPlain =
        serde_json::from_slice(&bytes).map_err(|e| AuthError { code: "MALFORMED", detail: e.to_string() })?;
    let b = &plain.body;
    let now = now_ms();
    let d2_rec = match gcs.drone_by_cred(&b.d2_cred_id) {
        Some(r) => r,
        None => return err("UNKNOWN_D2", "D2 credential id is not registered"),
    };
    if !sign::verify_transcript(&d2_rec.dil_pk, &b.signing_bytes(), &Signature(plain.sig2.clone())) {
        return err("D2_SIGNATURE_INVALID", "M2 signature does not verify under D2's registered key");
    }
    if !d2_rec.active || d2_rec.group_id != b.g {
        return err("D2_NOT_ACTIVE_MEMBER", format!("D2 is not an active member of '{}'", b.g));
    }
    if !gcs.groups.get(&b.g).map(|t| t.is_active(&d2_rec.drone_id)).unwrap_or(false) {
        return err("D2_NOT_ACTIVE_MEMBER", "D2 is not in the current membership tree");
    }
    let d2_id = d2_rec.drone_id.clone();
    if !within_skew(b.ts1, now) || !within_skew(b.ts2, now) {
        return err("STALE_TIMESTAMP", "M1/M2 timestamp outside the freshness window");
    }
    let pid = match gcs.pid_pool.get(&b.pid1) {
        Some(p) => p,
        None => return err("UNKNOWN_PID", "PID1 was never registered"),
    };
    if pid.state != PidState::Active {
        return err("PID_NOT_ACTIVE", format!("PID1 is {:?} (single-use pseudonym replayed or revoked)", pid.state));
    }
    if now > pid.expires_at_ms {
        return err("PID_EXPIRED", "PID1 has expired");
    }
    let d1_id = pid.drone_id.clone();
    if d1_id == d2_id {
        return err("SELF_AUTH", "D1 and D2 resolve to the same drone");
    }
    let d1_rec = gcs.drones.get(&d1_id).ok_or(AuthError { code: "UNKNOWN_D1", detail: "no record".into() })?;
    if !d1_rec.active || d1_rec.group_id != b.g {
        return err("D1_NOT_ACTIVE_MEMBER", "D1 is revoked or not in the requested group");
    }
    if !gcs.groups.get(&b.g).map(|t| t.is_active(&d1_id)).unwrap_or(false) {
        return err("D1_NOT_ACTIVE_MEMBER", "D1 is not in the current membership tree");
    }
    if gcs.seen_nonces.contains(&b.n1) || gcs.seen_nonces.contains(&b.n2) {
        return err("NONCE_REPLAY", "n1 or n2 already used");
    }
    gcs.seen_nonces.insert(b.n1.clone());
    gcs.seen_nonces.insert(b.n2.clone());
    Ok(M2Accepted { plain, d1_id, d2_id })
}

// ================================================================ M3 ===

/// GCS: create the session record, consume the PID, reserve a CRP,
/// sign and seal the credential response.
pub fn gcs_m3_cred_resp(gcs: &mut GcsState, acc: &M2Accepted) -> Result<(CredRespWire, SignedCredResp), AuthError> {
    let b = &acc.plain.body;
    let now = now_ms();
    let session_id = hex::encode(fresh_nonce(16));
    let (r_g, v_g) = {
        let t = gcs.groups.get(&b.g).ok_or(AuthError { code: "UNKNOWN_GROUP", detail: b.g.clone() })?;
        (t.root(), t.version)
    };
    let d1 = gcs.drones.get_mut(&acc.d1_id).ok_or(AuthError { code: "UNKNOWN_D1", detail: "".into() })?;
    let crp = match d1.crps.iter_mut().find(|c| c.state == CrpState::Fresh) {
        Some(c) => c,
        None => return err("CRP_POOL_EXHAUSTED", "no fresh PUF challenge left for D1"),
    };
    crp.state = CrpState::Reserved(session_id.clone());
    let c_puf = crp.challenge.clone();
    let cred_d1 = d1.credential.clone();
    let d2_kem = gcs.drones[&acc.d2_id].kem_pk.clone();

    let pid = gcs.pid_pool.get_mut(&b.pid1).unwrap();
    pid.state = PidState::Consumed;
    pid.bound_session = Some(session_id.clone());

    let body = CredRespBody {
        session_id: session_id.clone(),
        group_id: b.g.clone(),
        pid1: b.pid1.clone(),
        d2_cred_id: b.d2_cred_id,
        n2: b.n2.clone(),
        cred_d1,
        r_g,
        v_g,
        c_puf: c_puf.clone(),
        ts3: now,
        n3: fresh_nonce(16),
        expires_ms: now + SESSION_VALIDITY_MS,
    };
    let sig3 = sign::sign_transcript(&gcs.sign_sk, &body.signing_bytes())?;
    let signed = SignedCredResp { body, sig3: sig3.0 };

    gcs.sessions.insert(
        session_id.clone(),
        AuthSession {
            session_id,
            pid1: b.pid1.clone(),
            d1_id: acc.d1_id.clone(),
            d2_id: acc.d2_id.clone(),
            group_id: b.g.clone(),
            issued_r_g: r_g,
            issued_v_g: v_g,
            c_puf,
            n1: b.n1.clone(),
            ts1: b.ts1,
            n2: b.n2.clone(),
            created_ms: now,
            expires_ms: now + SESSION_VALIDITY_MS,
            state: SessionState::CredIssued,
            reason_code: String::new(),
            session_ctx: None,
            verified_ms: None,
        },
    );
    let bytes = serde_json::to_vec(&signed).map_err(anyhow::Error::from)?;
    let wire = envelope::seal_for_recipient(&d2_kem, b"M3-CredResp", &bytes)?;
    Ok((wire, signed))
}

/// D2 state for one session.
pub struct D2Session {
    pub m3: SignedCredResp,
    pub comm_req: CommReq,
    pub own_cred_id: [u8; 16],
    pub ts4: u64,
    pub session_ctx: Limbs,
}

impl D2Session {
    pub fn depth(&self, d2: &DroneState) -> usize {
        d2.cached_witness.as_ref().map(|w| w.siblings.len()).unwrap_or(0)
    }
}

pub fn d2_receive_m3(
    d2: &DroneState,
    wire: &CredRespWire,
    comm_req: &CommReq,
    m2: &M2Output,
) -> Result<D2Session, AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let anchor = d2.trust_anchor.as_ref().unwrap();
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"M3-CredResp", wire)
        .map_err(|e| AuthError { code: "ENVELOPE_INVALID", detail: e.to_string() })?;
    let m3: SignedCredResp =
        serde_json::from_slice(&bytes).map_err(|e| AuthError { code: "MALFORMED", detail: e.to_string() })?;
    if !sign::verify_transcript(anchor, &m3.body.signing_bytes(), &Signature(m3.sig3.clone())) {
        return err("GCS_SIGNATURE_INVALID", "M3 is not signed by the pinned GCS trust anchor");
    }
    let now = now_ms();
    let b = &m3.body;
    if b.pid1 != comm_req.pid1 || b.n2 != m2.body.n2 || b.d2_cred_id != m2.body.d2_cred_id {
        return err("SESSION_BINDING_MISMATCH", "M3 does not echo this session's PID1/n2/D2 credential");
    }
    if Some(&b.group_id) != d2.group_id.as_ref() {
        return err("GROUP_MISMATCH", "M3 group differs from D2's group");
    }
    if !within_skew(b.ts3, now) || now > b.expires_ms {
        return err("STALE_TIMESTAMP", "M3 stale or expired");
    }
    if let Err(e) = b.cred_d1.verify(anchor, now) {
        return err("CREDENTIAL_INVALID", format!("D1 credential: {e}"));
    }
    if b.cred_d1.body.group_id != b.group_id {
        return err("GROUP_MISMATCH", "D1 credential group differs from session group");
    }
    Ok(D2Session {
        m3,
        comm_req: comm_req.clone(),
        own_cred_id: m2.body.d2_cred_id,
        ts4: 0,
        session_ctx: [0; 11],
    })
}

pub fn session_ctx_for(
    session_id: &str,
    group_id: &str,
    v_g: u64,
    r_g: &Digest,
    pid1: &[u8],
    d2_cred_id: &[u8; 16],
    n1: &[u8],
    ts1: u64,
    n2: &[u8],
    ts4: u64,
    c_puf: &[u8],
) -> Limbs {
    session_ctx_digest(&SessionCtxInputs {
        protocol_version: PROTOCOL_VERSION,
        session_id,
        group_id,
        v_g,
        r_g,
        pid1,
        d2_cred_id,
        n1,
        ts1,
        n2,
        ts4,
        c_puf,
    })
}

// ================================================================ M4 ===

pub fn m4_challenge(d2: &DroneState, sess: &mut D2Session) -> Result<ChallengeMsg, AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let b = &sess.m3.body;
    sess.ts4 = now_ms();
    let payload = ChallengePayload {
        session_id: b.session_id.clone(),
        group_id: b.group_id.clone(),
        pid1: b.pid1.clone(),
        c_puf: b.c_puf.clone(),
        n2: b.n2.clone(),
        ts4: sess.ts4,
        d2_cred_id: sess.own_cred_id,
    };
    sess.session_ctx = session_ctx_for(
        &b.session_id, &b.group_id, b.v_g, &b.r_g, &b.pid1, &sess.own_cred_id,
        &sess.comm_req.n1, sess.comm_req.ts1, &b.n2, sess.ts4, &b.c_puf,
    );
    let sig4 = sign::sign_transcript(&keys.dil_sk, &payload.signing_bytes())?;
    Ok(ChallengeMsg {
        payload,
        sig4: sig4.0,
        d2_cred: d2.credential.clone().unwrap(),
        m3: sess.m3.clone(),
    })
}

/// D1 state for one session, built only from VERIFIED data.
pub struct D1Session {
    pub session_id: String,
    pub group_id: String,
    pub pid1: Vec<u8>,
    pub n1: Vec<u8>,
    pub ts1: u64,
    pub d2_cred: SignedCredential,
    pub n2: Vec<u8>,
    pub ts4: u64,
    pub c_puf: Vec<u8>,
    pub r_g: Digest,
    pub v_g: u64,
    pub session_ctx: Limbs,
    pub completed: bool,
}

pub fn d1_verify_challenge(d1: &DroneState, challenge: &ChallengeMsg, comm_req: &CommReq) -> Result<D1Session, AuthError> {
    let anchor = d1.trust_anchor.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let own = d1.credential.as_ref().unwrap();
    let now = now_ms();
    let m3 = &challenge.m3;
    let p = &challenge.payload;

    // (1) GCS authenticity of the forwarded M3 (R_G, V_G, C_PUF, ids).
    if !sign::verify_transcript(anchor, &m3.body.signing_bytes(), &Signature(m3.sig3.clone())) {
        return err("GCS_SIGNATURE_INVALID", "forwarded M3 is not signed by the GCS trust anchor");
    }
    // (2) Session binding to THIS D1's M1.
    if m3.body.pid1 != comm_req.pid1 || p.pid1 != comm_req.pid1 {
        return err("SESSION_BINDING_MISMATCH", "PID1 differs from the one D1 used in M1");
    }
    if Some(&m3.body.group_id) != d1.group_id.as_ref() || p.group_id != m3.body.group_id {
        return err("GROUP_MISMATCH", "session group differs from D1's group");
    }
    if p.session_id != m3.body.session_id || p.c_puf != m3.body.c_puf || p.n2 != m3.body.n2 || p.d2_cred_id != m3.body.d2_cred_id {
        return err("SESSION_BINDING_MISMATCH", "M4 payload disagrees with the GCS-signed M3");
    }
    if m3.body.cred_d1.body.cred_id != own.body.cred_id || m3.body.cred_d1.body.comm_pk != own.body.comm_pk {
        return err("CREDENTIAL_MISMATCH", "M3 was issued for a different credential than D1's own");
    }
    // (3) D2's key comes from a GCS-signed credential, not from M4.
    if let Err(e) = challenge.d2_cred.verify(anchor, now) {
        return err("CREDENTIAL_INVALID", format!("D2 credential: {e}"));
    }
    if challenge.d2_cred.body.cred_id != p.d2_cred_id || challenge.d2_cred.body.group_id != m3.body.group_id {
        return err("CREDENTIAL_MISMATCH", "D2 credential id/group do not match the signed session");
    }
    // (4) sig4 under the CERTIFIED key.
    if !sign::verify_transcript(&challenge.d2_cred.pk_dil(), &p.signing_bytes(), &Signature(challenge.sig4.clone())) {
        return err("D2_SIGNATURE_INVALID", "M4 signature does not verify under D2's certified key");
    }
    // (5) freshness.
    if !within_skew(m3.body.ts3, now) || !within_skew(p.ts4, now) || now > m3.body.expires_ms {
        return err("STALE_TIMESTAMP", "M3/M4 stale or expired");
    }
    let session_ctx = session_ctx_for(
        &p.session_id, &p.group_id, m3.body.v_g, &m3.body.r_g, &p.pid1, &p.d2_cred_id,
        &comm_req.n1, comm_req.ts1, &p.n2, p.ts4, &p.c_puf,
    );
    Ok(D1Session {
        session_id: p.session_id.clone(),
        group_id: p.group_id.clone(),
        pid1: p.pid1.clone(),
        n1: comm_req.n1.clone(),
        ts1: comm_req.ts1,
        d2_cred: challenge.d2_cred.clone(),
        n2: p.n2.clone(),
        ts4: p.ts4,
        c_puf: p.c_puf.clone(),
        r_g: m3.body.r_g,
        v_g: m3.body.v_g,
        session_ctx,
        completed: false,
    })
}

// ================================================================ M5 ===

pub fn zk_public_inputs(
    group_id: &str,
    v_g: u64,
    r_g: &Digest,
    comm_pk: &Limbs,
    metadata_digest: &Limbs,
    session_ctx: &Limbs,
) -> Result<MembershipPublicInputs, AuthError> {
    let v = u32::try_from(v_g).map_err(|_| AuthError { code: "VERSION_RANGE", detail: "V_G too large".into() })?;
    Ok(MembershipPublicInputs {
        protocol_version: PROTOCOL_VERSION,
        group_version: v,
        group_digest: group_digest(group_id),
        root: *r_g,
        comm_pk: *comm_pk,
        metadata_digest: *metadata_digest,
        session_digest: *session_ctx,
    })
}

pub fn m5_proof_bundle(d1: &DroneState, sess: &D1Session) -> Result<ProofBundle, AuthError> {
    let keys = d1.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let cred = d1.credential.as_ref().unwrap();
    let witness = d1.cached_witness.as_ref().ok_or(AuthError { code: "NO_WITNESS", detail: "".into() })?;
    if d1.cached_root != Some(sess.r_g) || d1.cached_version != Some(sess.v_g) {
        return err("STALE_MEMBERSHIP", "D1's cached root/version differ from the GCS-signed R_G/V_G; refresh needed");
    }
    let comm_pk = compute_comm_pk(&keys.kem_pk.0, &keys.dil_pk.0);
    if comm_pk != cred.body.comm_pk {
        return err("CREDENTIAL_MISMATCH", "own keys do not match own credential");
    }

    // A) PUF MAC over T_base (c_puf is GCS-signed).
    let r1 = d1.puf.challenge_response(&sess.c_puf);
    let k_puf = hkdf_expand(&r1, None, SEED_DOMAIN_PUF_MAC, 32);
    let t_base = build_t_base(&sess.session_ctx, &comm_pk);
    let mac1 = hmac_sha256(&k_puf, &t_base);

    // B) Witness-hiding membership proof.
    let pi = zk_public_inputs(&sess.group_id, sess.v_g, &sess.r_g, &comm_pk, &cred.body.metadata.digest(), &sess.session_ctx)?;
    let w = MembershipPrivateWitness {
        rho: d1.rho.ok_or(AuthError { code: "NO_WITNESS", detail: "rho missing".into() })?,
        siblings: witness.siblings.clone(),
        path_bits: witness.path_indices.iter().map(|&b| b == 1).collect(),
    };
    let params = zk_params_for(witness.siblings.len());
    let proof = zk::prove_membership(&params, &pi, &w)
        .map_err(|e| AuthError { code: "ZK_PROVE_FAILED", detail: e.to_string() })?;

    // C) ML-DSA signature over T.
    let t = build_auth_transcript(&sess.session_ctx, &comm_pk, &cred.body.cred_id, &proof_digest(&proof.bytes));
    let sig1 = sign::sign_transcript(&keys.dil_sk, &t)?;

    Ok(ProofBundle {
        session_id: sess.session_id.clone(),
        pid1: sess.pid1.clone(),
        cred_id_d1: cred.body.cred_id,
        comm_pk_d1: comm_pk,
        proof,
        mac1: mac1.to_vec(),
        sig1: sig1.0,
        ts5: now_ms(),
        n5: fresh_nonce(16),
    })
}

// ================================================================ M6 ===

pub fn m6_puf_verify_req(d2: &DroneState, sess: &D2Session, proof: &ProofBundle) -> Result<PufVerifyReqWire, AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let b = &sess.m3.body;
    let body = PufVerifyReqBody {
        session_id: b.session_id.clone(),
        pid1: b.pid1.clone(),
        d2_cred_id: sess.own_cred_id,
        g: b.group_id.clone(),
        n1: sess.comm_req.n1.clone(),
        ts1: sess.comm_req.ts1,
        n2: b.n2.clone(),
        ts4: sess.ts4,
        c_puf: b.c_puf.clone(),
        comm_pk: proof.comm_pk_d1,
        mac1: proof.mac1.clone(),
        ts6: now_ms(),
        n6: fresh_nonce(16),
    };
    let sig6 = sign::sign_transcript(&keys.dil_sk, &body.signing_bytes())?;
    let plain = PufVerifyReqPlain { body, sig6: sig6.0 };
    let bytes = serde_json::to_vec(&plain).map_err(anyhow::Error::from)?;
    Ok(envelope::seal_for_recipient(d2.gcs_kem_pk.as_ref().unwrap(), b"M6-PUFVerifyReq", &bytes)?)
}

#[derive(thiserror::Error, Debug)]
pub enum GcsPufVerifyError {
    #[error("envelope error: {0}")]
    Envelope(String),
    #[error("unknown session")]
    UnknownSession,
    #[error("requester authentication failed: {0}")]
    Unauthenticated(&'static str),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

fn sign_m6_resp(
    gcs: &GcsState,
    b: &PufVerifyReqBody,
    result: PufVerifyResult,
    reason: &str,
    cur: (Digest, u64),
    ctx: Limbs,
) -> Result<PufVerifyResp, GcsPufVerifyError> {
    let body = PufVerifyRespBody {
        session_id: b.session_id.clone(),
        pid1: b.pid1.clone(),
        result,
        reason_code: reason.to_string(),
        current_r_g: cur.0,
        current_v_g: cur.1,
        session_ctx: ctx,
        ts7: now_ms(),
        n7: fresh_nonce(16),
    };
    let sig7 = sign::sign_transcript(&gcs.sign_sk, &body.signing_bytes())?;
    Ok(PufVerifyResp { body, sig7: sig7.0 })
}

/// GCS: M6 verification. Requester authentication failures return an
/// error (no session is touched). All authenticated failures return a
/// GCS-SIGNED `Invalid` result with a reason code and burn the session.
pub fn gcs_m6_verify(gcs: &mut GcsState, wire: &PufVerifyReqWire) -> Result<PufVerifyResp, GcsPufVerifyError> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"M6-PUFVerifyReq", wire)
        .map_err(|e| GcsPufVerifyError::Envelope(e.to_string()))?;
    let plain: PufVerifyReqPlain =
        serde_json::from_slice(&bytes).map_err(|e| GcsPufVerifyError::Envelope(e.to_string()))?;
    let b = &plain.body;
    let sess = gcs.sessions.get(&b.session_id).ok_or(GcsPufVerifyError::UnknownSession)?.clone();
    let d2_rec = gcs.drones.get(&sess.d2_id).ok_or(GcsPufVerifyError::Unauthenticated("D2 unknown"))?.clone();
    if d2_rec.credential.body.cred_id != b.d2_cred_id
        || !sign::verify_transcript(&d2_rec.dil_pk, &b.signing_bytes(), &Signature(plain.sig6.clone()))
    {
        return Err(GcsPufVerifyError::Unauthenticated("M6 signature does not verify under the session's D2 key"));
    }
    let tree = gcs.groups.get(&sess.group_id);
    let cur = tree.map(|t| (t.root(), t.version)).unwrap_or((Digest::ZERO, 0));

    // A replayed/late M6 must not disturb a terminal session.
    if sess.state != SessionState::CredIssued {
        return sign_m6_resp(gcs, b, PufVerifyResult::Invalid, "SESSION_REPLAY_OR_WRONG_STATE", cur, [0; 11]);
    }

    let now = now_ms();
    let reason: Option<&'static str> = (|| {
        if now > sess.expires_ms {
            return Some("SESSION_EXPIRED");
        }
        if !within_skew(b.ts1, now) || !within_skew(b.ts4, now) || !within_skew(b.ts6, now) {
            return Some("STALE_TIMESTAMP");
        }
        if b.pid1 != sess.pid1 || b.g != sess.group_id || b.n1 != sess.n1 || b.n2 != sess.n2 || b.ts1 != sess.ts1 {
            return Some("SESSION_BINDING_MISMATCH");
        }
        if gcs.seen_nonces.contains(&b.n6) {
            return Some("NONCE_REPLAY");
        }
        match gcs.pid_pool.get(&b.pid1) {
            Some(p) if p.state == PidState::Consumed && p.bound_session.as_deref() == Some(&sess.session_id) && now <= p.expires_at_ms => {}
            _ => return Some("PID_NOT_VALID"),
        }
        let d1 = match gcs.drones.get(&sess.d1_id) {
            Some(d) => d,
            None => return Some("UNKNOWN_D1"),
        };
        let t = tree?;
        if !d1.active || !t.is_active(&sess.d1_id) || !d2_rec.active || !t.is_active(&sess.d2_id) {
            return Some("MEMBERSHIP_INACTIVE");
        }
        if b.comm_pk != d1.comm_pk {
            return Some("COMM_PK_MISMATCH");
        }
        if b.c_puf != sess.c_puf
            || !d1.crps.iter().any(|c| c.challenge == b.c_puf && c.state == CrpState::Reserved(sess.session_id.clone()))
        {
            return Some("CRP_INVALID");
        }
        if cur.0 != sess.issued_r_g || cur.1 != sess.issued_v_g {
            return Some("MEMBERSHIP_CHANGED_DURING_SESSION");
        }
        None
    })();

    let ctx = session_ctx_for(
        &sess.session_id, &sess.group_id, sess.issued_v_g, &sess.issued_r_g, &sess.pid1,
        &b.d2_cred_id, &b.n1, b.ts1, &b.n2, b.ts4, &sess.c_puf,
    );
    gcs.seen_nonces.insert(b.n6.clone());

    let mut reason = reason;
    if reason.is_none() {
        let crp = gcs.drones[&sess.d1_id].crps.iter().find(|c| c.challenge == b.c_puf).unwrap().reference_response;
        let k = hkdf_expand(&crp, None, SEED_DOMAIN_PUF_MAC, 32);
        let t_base = build_t_base(&ctx, &b.comm_pk);
        if !hmac_verify(&k, &t_base, &b.mac1) {
            reason = Some("PUF_MAC_INVALID");
        }
    }

    // Burn the CRP either way (a challenge is never reused).
    if let Some(d1) = gcs.drones.get_mut(&sess.d1_id) {
        if let Some(c) = d1.crps.iter_mut().find(|c| c.challenge == sess.c_puf) {
            c.state = CrpState::Used;
        }
    }
    let s = gcs.sessions.get_mut(&sess.session_id).unwrap();
    match reason {
        None => {
            s.state = SessionState::PufVerified;
            s.session_ctx = Some(ctx);
            s.verified_ms = Some(now);
            sign_m6_resp(gcs, b, PufVerifyResult::Valid, "OK", cur, ctx)
        }
        Some(r) => {
            s.state = SessionState::Failed;
            s.reason_code = r.to_string();
            sign_m6_resp(gcs, b, PufVerifyResult::Invalid, r, cur, ctx)
        }
    }
}

pub fn verify_m6_signature(gcs_sign_pk: &SignPublicKey, resp: &PufVerifyResp) -> bool {
    sign::verify_transcript(gcs_sign_pk, &resp.body.signing_bytes(), &Signature(resp.sig7.clone()))
}

// ================================================================ M7 ===

pub struct M7Result {
    pub report: VerificationReport,
}

pub fn m7_verify_and_decide(
    d2: &DroneState,
    sess: &D2Session,
    proof: &ProofBundle,
    puf_resp: &PufVerifyResp,
    policy: &dyn zero_trust::PolicyEngine,
) -> M7Result {
    let anchor = d2.trust_anchor.as_ref().expect("D2 must be registered");
    let m3 = &sess.m3.body;
    let now = now_ms();

    let freshness_ok = within_skew(sess.comm_req.ts1, now) && within_skew(sess.ts4, now) && within_skew(proof.ts5, now);
    let credential_ok = m3.cred_d1.verify(anchor, now).is_ok()
        && sign::verify_transcript(anchor, &m3.signing_bytes(), &Signature(sess.m3.sig3.clone()));
    let commitment_ok = proof.comm_pk_d1 == m3.cred_d1.body.comm_pk
        && proof.cred_id_d1 == m3.cred_d1.body.cred_id
        && proof.session_id == m3.session_id
        && proof.pid1 == m3.pid1;

    let session_ctx = sess.session_ctx;
    let metadata_digest = m3.cred_d1.body.metadata.digest();
    let depth = sess.depth(d2);
    let zk_membership_ok = commitment_ok
        && zk_public_inputs(&m3.group_id, m3.v_g, &m3.r_g, &m3.cred_d1.body.comm_pk, &metadata_digest, &session_ctx)
            .ok()
            .map(|pi| zk::verify_membership(&zk_params_for(depth), &pi, &proof.proof).is_ok())
            .unwrap_or(false);

    // Signature verified under the key of the GCS-signed credential.
    let t = build_auth_transcript(&session_ctx, &m3.cred_d1.body.comm_pk, &m3.cred_d1.body.cred_id, &proof_digest(&proof.proof.bytes));
    let signature_ok = sign::verify_transcript(&m3.cred_d1.pk_dil(), &t, &Signature(proof.sig1.clone()));

    let session_binding_ok = puf_resp.body.session_id == m3.session_id
        && puf_resp.body.pid1 == m3.pid1
        && puf_resp.body.session_ctx == session_ctx;
    let puf_ok = verify_m6_signature(anchor, puf_resp)
        && session_binding_ok
        && puf_resp.body.result == PufVerifyResult::Valid;
    let root_version_ok = puf_resp.body.current_r_g == m3.r_g && puf_resp.body.current_v_g == m3.v_g;

    let authenticated = freshness_ok && credential_ok && commitment_ok && zk_membership_ok && signature_ok
        && puf_ok && root_version_ok && session_binding_ok;

    // Explicit, ordered reason for authentication failures; the
    // authorization policy is evaluated only on its own inputs.
    let zt_inputs = zero_trust::ZeroTrustInputs {
        freshness_ok,
        credential_ok,
        commitment_ok,
        zk_membership_ok,
        signature_ok,
        puf_ok,
        root_version_ok,
        session_binding_ok,
        group_id: m3.group_id.clone(),
        requested_operation: "authenticate".to_string(),
        peer_role: m3.cred_d1.body.metadata.role.clone(),
        mission_active: true,
        device_health_ok: true,
    };
    let mut decision = policy.decide(&zt_inputs);
    if !puf_ok && puf_resp.body.result == PufVerifyResult::Invalid && decision.reason_code == "PUF_VERIFICATION_FAILED" {
        decision.reason_code = format!("PUF_VERIFICATION_FAILED:{}", puf_resp.body.reason_code);
    }
    M7Result {
        report: VerificationReport {
            freshness_ok,
            credential_ok,
            commitment_ok,
            zk_membership_ok,
            signature_ok,
            puf_ok,
            root_version_ok,
            session_binding_ok,
            authenticated,
            zero_trust: match decision.decision {
                zero_trust::Decision::Allow => ZeroTrustDecision::Allow,
                zero_trust::Decision::Deny => ZeroTrustDecision::Deny,
            },
            reason_code: decision.reason_code,
            session_ctx,
        },
    }
}

// ================================================================ M8 ===

pub fn m8_auth_result(d2: &DroneState, sess: &D2Session, report: &VerificationReport) -> Result<AuthResultMsg, AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let payload = AuthResultPayload {
        session_id: sess.m3.body.session_id.clone(),
        session_ctx: sess.session_ctx,
        result: report.zero_trust,
        reason_code: report.reason_code.clone(),
        d2_cred_id: sess.own_cred_id,
        ts8: now_ms(),
        n8: fresh_nonce(16),
    };
    let sig8 = sign::sign_transcript(&keys.dil_sk, &payload.signing_bytes())?;
    Ok(AuthResultMsg { payload, sig8: sig8.0 })
}

/// D1 verifies M8 with the key of the D2 credential it verified in M4.
pub fn d1_verify_m8(sess: &mut D1Session, msg: &AuthResultMsg) -> Result<ZeroTrustDecision, AuthError> {
    if sess.completed {
        return err("SESSION_REPLAY", "M8 already processed for this session");
    }
    let p = &msg.payload;
    if !sign::verify_transcript(&sess.d2_cred.pk_dil(), &p.signing_bytes(), &Signature(msg.sig8.clone())) {
        return err("D2_SIGNATURE_INVALID", "M8 signature does not verify under D2's certified key");
    }
    if p.session_id != sess.session_id || p.session_ctx != sess.session_ctx || p.d2_cred_id != sess.d2_cred.body.cred_id {
        return err("SESSION_BINDING_MISMATCH", "M8 is not bound to this session");
    }
    if !within_skew(p.ts8, now_ms()) {
        return err("STALE_TIMESTAMP", "M8 stale");
    }
    sess.completed = true;
    Ok(p.result)
}

/// D1's signed confirmation (required by the GCS for K1).
pub fn d1_session_confirm(d1: &DroneState, sess: &D1Session, result: ZeroTrustDecision) -> Result<SignedSessionConfirm, AuthError> {
    if !sess.completed {
        return err("SESSION_INCOMPLETE", "M8 not verified yet");
    }
    let keys = d1.keys.as_ref().unwrap();
    let body = SessionConfirmBody {
        session_id: sess.session_id.clone(),
        session_ctx: sess.session_ctx,
        result_seen: result,
        d1_cred_id: d1.credential.as_ref().unwrap().body.cred_id,
        ts: now_ms(),
        n: fresh_nonce(16),
    };
    let sig = sign::sign_transcript(&keys.dil_sk, &body.signing_bytes())?;
    Ok(SignedSessionConfirm { body, sig: sig.0 })
}

#[allow(dead_code)]
fn _unused(_: &[u8; 16]) -> String {
    hex16(&[0; 16])
}
