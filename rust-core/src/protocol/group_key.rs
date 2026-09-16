//! K1-K4: GCS-assisted group-key establishment + AEAD session-key
//! derivation.
//!
//! **Trust assumption, stated plainly (spec requirement — do not hide
//! this)**: GCS itself generates `K_G,M` and therefore knows the group
//! key. GCS compromise breaks confidentiality of all traffic protected
//! under that key. See `docs/threat-model.md` and
//! `docs/security-assumptions.md`.

use crate::crypto::aead::AeadKey;
use crate::crypto::domains::SEED_DOMAIN_GROUP_KEY_AEAD;
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::kem::KemPublicKey;
use crate::crypto::sign::{self, Signature};
use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::envelope;
use crate::protocol::messages::*;
use rand::RngCore;

fn now_ms() -> u64 {
    crate::protocol::events::now_unix_ms()
}
fn fresh_nonce(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

// ================================================================ K1 ===

#[allow(clippy::too_many_arguments)]
pub fn k1_group_key_req(
    d2: &DroneState,
    group_id: &str,
    d1_pid1: &[u8],
    mission_id: &str,
    auth_evidence_hash: [u8; 32],
    gcs_kem_pk: &KemPublicKey,
) -> anyhow::Result<(GroupKeyReqWire, GroupKeyReq)> {
    let plain = GroupKeyReq {
        msg_type: "GroupKeyReq".into(),
        g: group_id.to_string(),
        d1_pid1: d1_pid1.to_vec(),
        d2_id: d2.drone_id.clone(),
        mission_id: mission_id.to_string(),
        ts6: now_ms(),
        n6: fresh_nonce(16),
        auth_evidence_hash: auth_evidence_hash.to_vec(),
    };
    let wire = envelope::seal_for_recipient(gcs_kem_pk, b"K1-GroupKeyReq", &serde_json::to_vec(&plain)?)?;
    Ok((wire, plain))
}

#[derive(thiserror::Error, Debug)]
pub enum GroupKeyError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("unknown PID for D1")]
    UnknownD1Pid,
    #[error("D2 is not a known active drone")]
    UnknownOrInactiveD2,
    #[error("D1 is not a known active drone")]
    UnknownOrInactiveD1,
}

/// GCS handles K1 and immediately produces the K1-response envelope
/// (`GroupKeyResp`, wrapped for transport to D2 — spec's `ct7`).
pub fn gcs_handle_k1(
    gcs: &GcsState,
    wire: &GroupKeyReqWire,
) -> Result<GroupKeyRespWire, GroupKeyError> {
    let bytes = envelope::open_as_recipient(&gcs.kem_sk, b"K1-GroupKeyReq", wire)
        .map_err(|e| GroupKeyError::Other(anyhow::anyhow!("{e}")))?;
    let plain: GroupKeyReq = serde_json::from_slice(&bytes).map_err(|e| GroupKeyError::Other(e.into()))?;

    let d1_id = gcs.resolve_pid(&plain.d1_pid1).ok_or(GroupKeyError::UnknownD1Pid)?;
    let d1_record = gcs
        .drones
        .get(d1_id)
        .filter(|r| r.active)
        .ok_or(GroupKeyError::UnknownOrInactiveD1)?;
    let d2_record = gcs
        .drones
        .get(&plain.d2_id)
        .filter(|r| r.active)
        .ok_or(GroupKeyError::UnknownOrInactiveD2)?;

    let mut k_g_m = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k_g_m);
    let ts7 = now_ms();

    let env1_plain = GroupKeyEnvelopeInner {
        k_g_m: k_g_m.to_vec(),
        g: plain.g.clone(),
        mission_id: plain.mission_id.clone(),
        ts7,
    };
    let env2_plain = env1_plain.clone();

    let ct_kem_g_d1 = envelope::seal_for_recipient(
        &d1_record.kem_pk,
        b"K-GroupKey-D1",
        &serde_json::to_vec(&env1_plain).map_err(anyhow::Error::from)?,
    )
    .map_err(GroupKeyError::Other)?;
    let ct_kem_g_d2 = envelope::seal_for_recipient(
        &d2_record.kem_pk,
        b"K-GroupKey-D2",
        &serde_json::to_vec(&env2_plain).map_err(anyhow::Error::from)?,
    )
    .map_err(GroupKeyError::Other)?;

    let resp = GroupKeyResp {
        msg_type: "GroupKeyResp".into(),
        ct_kem_g_d1,
        ct_kem_g_d2,
        ts7,
        n7: fresh_nonce(16),
    };
    let wire7 = envelope::seal_for_recipient(
        &d2_record.kem_pk,
        b"K1-GroupKeyResp-transport",
        &serde_json::to_vec(&resp).map_err(anyhow::Error::from)?,
    )
    .map_err(GroupKeyError::Other)?;
    Ok(wire7)
}

// ================================================================ K2 ===

/// D2 opens the outer K1-response transport envelope, keeps its own
/// `ct_kem_g_d2` to decapsulate locally, and forwards `ct_kem_g_d1`
/// on to D1 as a signed `KeyDelivery` message.
pub fn d2_handle_k1_response(
    d2: &DroneState,
    wire: &GroupKeyRespWire,
) -> anyhow::Result<(GroupKeyResp, KeyDeliveryMsg)> {
    let d2_keys = d2.keys.as_ref().expect("D2 must be registered");
    let bytes = envelope::open_as_recipient(&d2_keys.kem_sk, b"K1-GroupKeyResp-transport", wire)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let resp: GroupKeyResp = serde_json::from_slice(&bytes)?;

    let payload8 = KeyDeliveryPayload {
        msg_type: "KeyDelivery".into(),
        ct_kem_g_d1: resp.ct_kem_g_d1.clone(),
        ts8: now_ms(),
        n8: fresh_nonce(16),
    };
    let sig8 = sign::sign_transcript(&d2_keys.dil_sk, &payload8.signing_bytes())?;
    let msg8 = KeyDeliveryMsg {
        payload8,
        sig8: sig8.0,
        pk_dil_d2: d2_keys.dil_pk.0.clone(),
    };
    Ok((resp, msg8))
}

pub fn d1_verify_key_delivery(pk_dil_d2: &crate::crypto::sign::SignPublicKey, msg: &KeyDeliveryMsg) -> bool {
    sign::verify_transcript(pk_dil_d2, &msg.payload8.signing_bytes(), &Signature(msg.sig8.clone()))
}

/// D1 decapsulates its own copy of the group key from the forwarded
/// envelope.
pub fn d1_decapsulate_group_key(d1: &DroneState, msg: &KeyDeliveryMsg) -> anyhow::Result<[u8; 32]> {
    let keys = d1.keys.as_ref().expect("D1 must be registered");
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"K-GroupKey-D1", &msg.payload8.ct_kem_g_d1)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let inner: GroupKeyEnvelopeInner = serde_json::from_slice(&bytes)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(&inner.k_g_m);
    Ok(k)
}

/// D2 decapsulates its own copy directly from the K1 response.
pub fn d2_decapsulate_group_key(d2: &DroneState, resp: &GroupKeyResp) -> anyhow::Result<[u8; 32]> {
    let keys = d2.keys.as_ref().expect("D2 must be registered");
    let bytes = envelope::open_as_recipient(&keys.kem_sk, b"K-GroupKey-D2", &resp.ct_kem_g_d2)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let inner: GroupKeyEnvelopeInner = serde_json::from_slice(&bytes)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(&inner.k_g_m);
    Ok(k)
}

// ================================================================ K3 ===

/// `K_AEAD = KDF(K_G_M, "AEAD-key", N1, N2, N6, N7)` — both parties
/// derive the same session AEAD key from the (now-shared) group key plus
/// the session's nonces, binding the derived key to this specific
/// session rather than reusing `K_G,M` directly for transport.
pub fn derive_aead_key(k_g_m: &[u8; 32], n1: &[u8], n2: &[u8], n6: &[u8], n7: &[u8]) -> AeadKey {
    let info = crate::crypto::kdf::length_prefixed_concat(&[n1, n2, n6, n7]);
    let bytes = hkdf_expand(k_g_m, None, &[SEED_DOMAIN_GROUP_KEY_AEAD, &info].concat(), 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    AeadKey(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::metadata::MembershipMetadata;
    use crate::protocol::registration::register_drone;

    fn setup() -> (GcsState, DroneState, DroneState) {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let mut d2 = DroneState::new("drone-2", [2u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md.clone(), 6).unwrap();
        register_drone(&mut gcs, &mut d2, "alpha", md, 6).unwrap();
        (gcs, d1, d2)
    }

    #[test]
    fn full_group_key_round_trip() {
        let (gcs, d1, d2) = setup();
        let d1_pid1 = crate::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);
        // Register the pid explicitly for this test (normally the pool
        // is pre-provisioned at registration; this simulates M1 having
        // consumed pid_counter=0 already).
        let mut gcs = gcs;
        gcs.pid_pool.insert(d1_pid1.clone(), d1.drone_id.clone());

        let (wire1, _plain1) = k1_group_key_req(&d2, "alpha", &d1_pid1, "mission-x", [0u8; 32], &gcs.kem_pk).unwrap();
        let wire7 = gcs_handle_k1(&gcs, &wire1).unwrap();
        let (resp, key_delivery) = d2_handle_k1_response(&d2, &wire7).unwrap();

        assert!(d1_verify_key_delivery(
            &crate::crypto::sign::SignPublicKey(d2.keys.as_ref().unwrap().dil_pk.0.clone()),
            &key_delivery
        ));

        let k_d1 = d1_decapsulate_group_key(&d1, &key_delivery).unwrap();
        let k_d2 = d2_decapsulate_group_key(&d2, &resp).unwrap();
        assert_eq!(k_d1, k_d2, "D1 and D2 must derive the identical group key");

        let aead_d1 = derive_aead_key(&k_d1, b"n1", b"n2", b"n6", b"n7");
        let aead_d2 = derive_aead_key(&k_d2, b"n1", b"n2", b"n6", b"n7");
        assert_eq!(aead_d1.0, aead_d2.0);
    }

    #[test]
    fn unknown_d1_pid_is_rejected() {
        let (gcs, _d1, d2) = setup();
        let bogus_pid = vec![9u8; 16];
        let (wire1, _plain1) = k1_group_key_req(&d2, "alpha", &bogus_pid, "mission-x", [0u8; 32], &gcs.kem_pk).unwrap();
        assert!(matches!(gcs_handle_k1(&gcs, &wire1), Err(GroupKeyError::UnknownD1Pid)));
    }
}
