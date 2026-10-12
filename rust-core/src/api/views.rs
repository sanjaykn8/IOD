//! API-safe response DTOs, built by hand from internal state — NEVER by
//! directly serializing an internal struct that might carry secret
//! material. This is the structural enforcement of the "never expose
//! private keys / PUF seeds / shared secrets / AEAD keys" requirement:
//! there is no code path from a `DroneState` (which holds
//! `DeviceKeys`/`rho`/PUF state) to an HTTP response body that does not
//! go through one of these `*View` constructors, each of which lists
//! explicitly, field by field, what is safe to expose.

use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::messages::VerificationReport;
use serde::Serialize;

fn fingerprint(bytes: &[u8]) -> String {
    let digest = crate::crypto::kdf::shake256_bytes(b"IOD-API-FINGERPRINT-v1", bytes, 8);
    hex::encode(digest)
}

#[derive(Serialize)]
pub struct DroneView {
    pub drone_id: String,
    pub group_id: Option<String>,
    pub registered: bool,
    pub active: bool,
    pub revoked_flag: bool,
    pub kem_pk_fingerprint: Option<String>,
    pub dil_pk_fingerprint: Option<String>,
    pub role: Option<String>,
    pub leaf_index: Option<usize>,
    pub cached_root_hex: Option<String>,
    pub cached_version: Option<u64>,
}

pub fn drone_view(gcs: &GcsState, d: &DroneState) -> DroneView {
    let record = gcs.drones.get(&d.drone_id);
    DroneView {
        drone_id: d.drone_id.clone(),
        group_id: d.group_id.clone(),
        registered: d.is_registered(),
        active: record.map(|r| r.active).unwrap_or(false),
        revoked_flag: d.revoked,
        kem_pk_fingerprint: d.keys.as_ref().map(|k| fingerprint(&k.kem_pk.0)),
        dil_pk_fingerprint: d.keys.as_ref().map(|k| fingerprint(&k.dil_pk.0)),
        role: d.metadata.as_ref().map(|m| m.role.clone()),
        leaf_index: d
            .group_id
            .as_ref()
            .and_then(|g| gcs.groups.get(g))
            .and_then(|t| t.leaf_index_of(&d.drone_id)),
        cached_root_hex: d.cached_root.map(|r| r.to_hex()),
        cached_version: d.cached_version,
    }
}

#[derive(Serialize)]
pub struct GroupView {
    pub group_id: String,
    pub root_hex: String,
    pub version: u64,
    pub capacity: usize,
    pub active_members: Vec<String>,
}

pub fn group_view(group_id: &str, gcs: &GcsState) -> Option<GroupView> {
    let t = gcs.groups.get(group_id)?;
    Some(GroupView {
        group_id: group_id.to_string(),
        root_hex: t.root().to_hex(),
        version: t.version,
        capacity: t.capacity(),
        active_members: t.active_members(),
    })
}

#[derive(Serialize)]
pub struct AuthResultView {
    pub session_id: String,
    pub freshness_ok: bool,
    pub credential_ok: bool,
    pub commitment_ok: bool,
    pub session_binding_ok: bool,
    pub authenticated: bool,
    pub zk_membership_ok: bool,
    pub signature_ok: bool,
    pub puf_ok: bool,
    pub root_version_ok: bool,
    pub decision: String,
    pub reason_code: String,
}

pub fn auth_result_view(session_id: &str, report: &VerificationReport) -> AuthResultView {
    AuthResultView {
        session_id: session_id.to_string(),
        freshness_ok: report.freshness_ok,
        credential_ok: report.credential_ok,
        commitment_ok: report.commitment_ok,
        session_binding_ok: report.session_binding_ok,
        authenticated: report.authenticated,
        zk_membership_ok: report.zk_membership_ok,
        signature_ok: report.signature_ok,
        puf_ok: report.puf_ok,
        root_version_ok: report.root_version_ok,
        decision: format!("{:?}", report.zero_trust).to_uppercase(),
        reason_code: report.reason_code.clone(),
    }
}
