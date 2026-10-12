//! K1-K3: GCS-assisted group/session key establishment.
//!
//! The GCS accepts K1 only for the EXACT session that completed
//! M1-M8: the session record must be `PufVerified` (the GCS verified M6
//! itself), both drones must still be active members, and the request
//! must carry (a) D2's signed ALLOW decision bound to the session
//! context and (b) D1's signed confirmation that it verified M8. A
//! session can yield one key (`KeyIssued` is terminal).
//!
//! NOTE (documented limitation): the GCS generates and therefore KNOWS
//! `K_G,M`; this is key distribution, not end-to-end secrecy from the
//! GCS. The pairwise AEAD keys are derived from K_G,M with a context that
//! binds group, mission, session, both credentials, the K1/K2 nonces and a
//! key epoch, one key per direction.

use crate::crypto::aead::AeadKey;
use crate::crypto::domains::SEED_DOMAIN_GROUP_KEY_AEAD;
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::sign::{self, Signature};
use crate::protocol::auth_flow::{fresh_nonce, within_skew, AuthError, D1Session, D2Session};
use crate::protocol::canon::Canon;
use crate::protocol::entities::*;
use crate::protocol::envelope;
use crate::protocol::messages::*;
use rand::RngCore;

fn now_ms() -> u64 {
    crate::protocol::events::now_unix_ms()
}

pub fn d2_k1_group_key_req(
    d2: &crate::protocol::entities::DroneState,
    sess: &D2Session,
    report: &VerificationReport,
    d1_confirm: SignedSessionConfirm,
    mission_id: &str,
) -> Result<(GroupKeyReqWire, GroupKeyReq), AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let body = GroupKeyReqBody {
        session_id: sess.m3.body.session_id.clone(),
        mission_id: mission_id.to_string(),
        d2_cred_id: sess.own_cred_id,
        session_ctx: sess.session_ctx,
        d2_result: report.zero_trust,
        d1_confirm,
        ts6: now_ms(),
        n6: fresh_nonce(16),
    };
    let sig6 = sign::sign_transcript(&keys.dil_sk, &body.signing_bytes())?;
    let plain = GroupKeyReq { body, sig6: sig6.0 };
    let wire = envelope::seal_for_recipient(
        d2.gcs_kem_pk.as_ref().unwrap(),
        b"K1-GroupKeyReq",
        &serde_json::to_vec(&plain).map_err(anyhow::Error::from)?,
    )?;
    Ok((wire, plain))
}

pub fn gcs_handle_k1(gcs: &mut GcsState, wire: &GroupKeyReqWire) -> Result<GroupKeyRespWire, AuthError> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"K1-GroupKeyReq", wire)
        .map_err(|e| AuthError { code: "ENVELOPE_INVALID", detail: e.to_string() })?;
    let req: GroupKeyReq =
        serde_json::from_slice(&bytes).map_err(|e| AuthError { code: "MALFORMED", detail: e.to_string() })?;
    let b = &req.body;
    let now = now_ms();

    let sess = match gcs.sessions.get(&b.session_id) {
        Some(s) => s.clone(),
        None => return Err(AuthError { code: "NO_AUTH_SESSION", detail: "K1 without a completed authentication session".into() }),
    };
    let d2 = gcs.drones.get(&sess.d2_id).cloned().ok_or(AuthError { code: "UNKNOWN_D2", detail: "".into() })?;
    let d1 = gcs.drones.get(&sess.d1_id).cloned().ok_or(AuthError { code: "UNKNOWN_D1", detail: "".into() })?;
    if d2.credential.body.cred_id != b.d2_cred_id
        || !sign::verify_transcript(&d2.dil_pk, &b.signing_bytes(), &Signature(req.sig6.clone()))
    {
        return Err(AuthError { code: "D2_SIGNATURE_INVALID", detail: "K1 not signed by this session's D2".into() });
    }
    match sess.state {
        SessionState::PufVerified => {}
        SessionState::KeyIssued => return Err(AuthError { code: "SESSION_REPLAY", detail: "a key was already issued for this session".into() }),
        SessionState::CredIssued => return Err(AuthError { code: "SESSION_NOT_AUTHENTICATED", detail: "M6 not verified for this session".into() }),
        SessionState::Failed => return Err(AuthError { code: "SESSION_DENIED", detail: format!("session failed: {}", sess.reason_code) }),
    }
    if now > sess.expires_ms.saturating_add(crate::protocol::SESSION_VALIDITY_MS) || !within_skew(b.ts6, now) {
        return Err(AuthError { code: "STALE_TIMESTAMP", detail: "K1 stale or session too old".into() });
    }
    if gcs.seen_nonces.contains(&b.n6) {
        return Err(AuthError { code: "NONCE_REPLAY", detail: "n6 reused".into() });
    }
    if Some(b.session_ctx) != sess.session_ctx {
        return Err(AuthError { code: "SESSION_BINDING_MISMATCH", detail: "session context differs from the GCS's own".into() });
    }
    if b.d2_result != ZeroTrustDecision::Allow {
        return Err(AuthError { code: "NOT_ALLOWED", detail: "D2 did not ALLOW this session".into() });
    }
    let c = &b.d1_confirm;
    if c.body.session_id != sess.session_id
        || c.body.session_ctx != b.session_ctx
        || c.body.d1_cred_id != d1.credential.body.cred_id
        || c.body.result_seen != ZeroTrustDecision::Allow
        || !sign::verify_transcript(&d1.dil_pk, &c.body.signing_bytes(), &Signature(c.sig.clone()))
        || !within_skew(c.body.ts, now)
    {
        return Err(AuthError { code: "D1_CONFIRM_INVALID", detail: "D1 did not confirm M8 for this session".into() });
    }
    let tree = gcs.groups.get(&sess.group_id).ok_or(AuthError { code: "UNKNOWN_GROUP", detail: "".into() })?;
    if !d1.active || !d2.active || !tree.is_active(&sess.d1_id) || !tree.is_active(&sess.d2_id) {
        return Err(AuthError { code: "MEMBERSHIP_INACTIVE", detail: "a participant was revoked".into() });
    }
    gcs.seen_nonces.insert(b.n6.clone());

    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    let n7 = fresh_nonce(16);
    let epoch = now;
    let mk = |recipient: &DronePublicRecord| -> Result<envelope::SecureEnvelope, AuthError> {
        let inner = GroupKeyInner {
            k_g_m: k.to_vec(),
            group_id: sess.group_id.clone(),
            mission_id: b.mission_id.clone(),
            session_id: sess.session_id.clone(),
            session_ctx: b.session_ctx,
            recipient_cred_id: recipient.credential.body.cred_id,
            key_epoch: epoch,
            ts: now,
            n6: b.n6.clone(),
            n7: n7.clone(),
        };
        let gcs_sig = sign::sign_transcript(&gcs.sign_sk, &inner.signing_bytes())?.0;
        let signed = SignedGroupKeyInner { inner, gcs_sig };
        Ok(envelope::seal_for_recipient(
            &recipient.kem_pk,
            b"K-GroupKey",
            &serde_json::to_vec(&signed).map_err(anyhow::Error::from)?,
        )?)
    };
    let resp = GroupKeyResp { session_id: sess.session_id.clone(), ct_d1: mk(&d1)?, ct_d2: mk(&d2)?, ts7: now, n7 };
    gcs.sessions.get_mut(&sess.session_id).unwrap().state = SessionState::KeyIssued;
    Ok(envelope::seal_for_recipient(
        &d2.kem_pk,
        b"K1-GroupKeyResp-transport",
        &serde_json::to_vec(&resp).map_err(anyhow::Error::from)?,
    )?)
}

pub fn d2_handle_k1_response(
    d2: &DroneState,
    wire: &GroupKeyRespWire,
) -> Result<(GroupKeyResp, KeyDeliveryMsg), AuthError> {
    let keys = d2.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"K1-GroupKeyResp-transport", wire)
        .map_err(|e| AuthError { code: "ENVELOPE_INVALID", detail: e.to_string() })?;
    let resp: GroupKeyResp =
        serde_json::from_slice(&bytes).map_err(|e| AuthError { code: "MALFORMED", detail: e.to_string() })?;
    let payload = KeyDeliveryPayload { session_id: resp.session_id.clone(), ct_d1: resp.ct_d1.clone(), ts8: now_ms(), n8: fresh_nonce(16) };
    let sig8 = sign::sign_transcript(&keys.dil_sk, &payload.signing_bytes())?;
    Ok((resp, KeyDeliveryMsg { payload, sig8: sig8.0 }))
}

/// D1 verifies K2 under D2's certified key (from M4).
pub fn d1_verify_key_delivery(sess: &D1Session, msg: &KeyDeliveryMsg) -> bool {
    msg.payload.session_id == sess.session_id
        && within_skew(msg.payload.ts8, now_ms())
        && sign::verify_transcript(&sess.d2_cred.pk_dil(), &msg.payload.signing_bytes(), &Signature(msg.sig8.clone()))
}

pub struct GroupKeyMaterial {
    pub k_g_m: [u8; 32],
    pub inner: GroupKeyInner,
}

fn open_inner(
    drone: &DroneState,
    env: &envelope::SecureEnvelope,
    session_id: &str,
    session_ctx: &crate::zkhash::Limbs,
) -> Result<GroupKeyMaterial, AuthError> {
    let keys = drone.keys.as_ref().ok_or(AuthError { code: "NOT_REGISTERED", detail: "".into() })?;
    let anchor = drone.trust_anchor.as_ref().unwrap();
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"K-GroupKey", env)
        .map_err(|e| AuthError { code: "ENVELOPE_INVALID", detail: e.to_string() })?;
    let signed: SignedGroupKeyInner =
        serde_json::from_slice(&bytes).map_err(|e| AuthError { code: "MALFORMED", detail: e.to_string() })?;
    if !sign::verify_transcript(anchor, &signed.inner.signing_bytes(), &Signature(signed.gcs_sig.clone())) {
        return Err(AuthError { code: "GCS_SIGNATURE_INVALID", detail: "group key not signed by the GCS".into() });
    }
    let i = &signed.inner;
    if i.session_id != session_id
        || &i.session_ctx != session_ctx
        || i.recipient_cred_id != drone.credential.as_ref().unwrap().body.cred_id
        || !within_skew(i.ts, now_ms())
        || i.k_g_m.len() != 32
    {
        return Err(AuthError { code: "SESSION_BINDING_MISMATCH", detail: "group key not bound to this session/recipient".into() });
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&i.k_g_m);
    Ok(GroupKeyMaterial { k_g_m: k, inner: signed.inner })
}

pub fn d1_decapsulate_group_key(d1: &DroneState, sess: &D1Session, msg: &KeyDeliveryMsg) -> Result<GroupKeyMaterial, AuthError> {
    open_inner(d1, &msg.payload.ct_d1, &sess.session_id, &sess.session_ctx)
}

pub fn d2_decapsulate_group_key(d2: &DroneState, sess: &D2Session, resp: &GroupKeyResp) -> Result<GroupKeyMaterial, AuthError> {
    open_inner(d2, &resp.ct_d2, &sess.m3.body.session_id, &sess.session_ctx)
}

/// Directional AEAD keys + a pseudonymous channel tag, derived with a
/// full context (no literal nonces).
pub struct ChannelKeys {
    pub d1_to_d2: AeadKey,
    pub d2_to_d1: AeadKey,
    pub channel_tag: [u8; 16],
}

pub fn derive_channel_keys(m: &GroupKeyMaterial, d1_cred_id: &[u8; 16], d2_cred_id: &[u8; 16]) -> ChannelKeys {
    let i = &m.inner;
    let ctx = |label: &str| -> Vec<u8> {
        let mut c = Canon::new("GROUPKEY-KDF");
        c.str(label)
            .str(&i.group_id)
            .str(&i.mission_id)
            .str(&i.session_id)
            .limbs(&i.session_ctx)
            .bytes(d1_cred_id)
            .bytes(d2_cred_id)
            .u64(i.key_epoch)
            .bytes(&i.n6)
            .bytes(&i.n7);
        c.into_vec()
    };
    let key = |label: &str| {
        let info = [SEED_DOMAIN_GROUP_KEY_AEAD, &ctx(label)[..]].concat();
        let b = hkdf_expand(&m.k_g_m, None, &info, 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        AeadKey(k)
    };
    let tag_bytes = hkdf_expand(&m.k_g_m, None, &[SEED_DOMAIN_GROUP_KEY_AEAD, &ctx("channel-tag")[..]].concat(), 16);
    let mut channel_tag = [0u8; 16];
    channel_tag.copy_from_slice(&tag_bytes);
    ChannelKeys { d1_to_d2: key("d1->d2"), d2_to_d1: key("d2->d1"), channel_tag }
}
