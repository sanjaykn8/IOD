//! Trace Manager: NOT part of the normal authentication path. It is
//! activated only for a flagged session and only for an authenticated
//! administrator.
//!
//! Authorization model (v2):
//! * The caller's role is never taken from the request body. Administrator
//!   status is established by an admin credential (`AdminAuth`, a secret
//!   token supplied out of band via `IOD_ADMIN_TOKEN`; only an HMAC of it
//!   is held in memory and the comparison is constant-time). If no token
//!   is configured, nobody is an administrator (fail closed).
//! * A trace needs a non-empty reason, and the target PID must belong to a
//!   session that has been flagged as suspicious.
//! * Every attempt -- authorized or not, with the outcome -- is appended
//!   to the audit trail. Resolved DroneIDs are returned only on success.

use crate::crypto::kdf::{hmac_sha256, hmac_verify};
use crate::protocol::entities::GcsState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuspicionFlag {
    pub flag_id: String,
    pub session_id: String,
    pub flagged_by: String,
    pub reason: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceRecord {
    pub trace_id: String,
    pub requested_by: String,
    pub requester_role: String,
    pub reason: String,
    pub target_pid_hex: String,
    pub authorized: bool,
    /// Machine-readable outcome: OK, NOT_ADMIN, EMPTY_REASON,
    /// PID_NOT_FLAGGED, UNKNOWN_PID.
    #[serde(default)]
    pub outcome: String,
    pub resolved_drone_id: Option<String>,
    pub timestamp_unix_ms: u64,
}

/// Administrator credential verifier (constant-time, token never stored).
pub struct AdminAuth {
    key: [u8; 32],
    tag: Option<[u8; 32]>,
}

impl AdminAuth {
    pub fn new(token: Option<&str>) -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        let tag = token.filter(|t| t.len() >= 16).map(|t| hmac_sha256(&key, t.as_bytes()));
        AdminAuth { key, tag }
    }

    /// Reads `IOD_ADMIN_TOKEN` (>= 16 chars). Unset/short => no admin.
    pub fn from_env() -> Self {
        Self::new(std::env::var("IOD_ADMIN_TOKEN").ok().as_deref())
    }

    pub fn verify(&self, presented: Option<&str>) -> bool {
        match (&self.tag, presented) {
            (Some(tag), Some(p)) => hmac_verify(&self.key, p.as_bytes(), tag),
            _ => false,
        }
    }
}

pub struct TraceManager {
    pub flags: Vec<SuspicionFlag>,
    pub trace_records: Vec<TraceRecord>,
}

impl TraceManager {
    pub fn new() -> Self {
        TraceManager { flags: Vec::new(), trace_records: Vec::new() }
    }

    pub fn flag_session(&mut self, session_id: &str, flagged_by: &str, reason: &str) -> SuspicionFlag {
        let flag = SuspicionFlag {
            flag_id: random_id(),
            session_id: session_id.to_string(),
            flagged_by: flagged_by.to_string(),
            reason: reason.to_string(),
            timestamp_unix_ms: crate::protocol::events::now_unix_ms(),
        };
        self.flags.push(flag.clone());
        flag
    }

    /// `is_admin` must come from `AdminAuth::verify`, never from caller
    /// input. Always appends an audit record.
    pub fn request_trace(
        &mut self,
        gcs: &GcsState,
        is_admin: bool,
        requested_by: &str,
        reason: &str,
        target_pid: &[u8],
    ) -> TraceRecord {
        let flagged_pid = self.flags.iter().any(|f| {
            gcs.sessions.get(&f.session_id).map(|s| s.pid1.as_slice() == target_pid).unwrap_or(false)
        });
        let (outcome, resolved) = if !is_admin {
            ("NOT_ADMIN", None)
        } else if reason.trim().is_empty() {
            ("EMPTY_REASON", None)
        } else if !flagged_pid {
            ("PID_NOT_FLAGGED", None)
        } else {
            match gcs.resolve_pid(target_pid) {
                Some(d) => ("OK", Some(d.to_string())),
                None => ("UNKNOWN_PID", None),
            }
        };
        let record = TraceRecord {
            trace_id: random_id(),
            requested_by: requested_by.to_string(),
            requester_role: if is_admin { "administrator".into() } else { "unauthenticated".into() },
            reason: reason.to_string(),
            target_pid_hex: hex::encode(target_pid),
            authorized: outcome == "OK",
            outcome: outcome.to_string(),
            resolved_drone_id: resolved,
            timestamp_unix_ms: crate::protocol::events::now_unix_ms(),
        };
        self.trace_records.push(record.clone());
        record
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

fn random_id() -> String {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::metadata::MembershipMetadata;
    use crate::protocol::entities::{AuthSession, DroneState, SessionState};
    use crate::protocol::registration::register_drone;

    fn fixture() -> (GcsState, Vec<u8>, String) {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 4).unwrap();
        let pid = crate::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);
        let sid = "sess-1".to_string();
        gcs.sessions.insert(
            sid.clone(),
            AuthSession {
                session_id: sid.clone(), pid1: pid.clone(), d1_id: "drone-1".into(), d2_id: "x".into(),
                group_id: "alpha".into(), issued_r_g: crate::zkhash::Digest::ZERO, issued_v_g: 0, c_puf: vec![],
                n1: vec![], ts1: 0, n2: vec![], created_ms: 0, expires_ms: 0, state: SessionState::Failed,
                reason_code: String::new(), session_ctx: None, verified_ms: None,
            },
        );
        (gcs, pid, sid)
    }

    #[test]
    fn admin_resolves_pid_of_flagged_session() {
        let (gcs, pid, sid) = fixture();
        let mut tm = TraceManager::new();
        tm.flag_session(&sid, "D2", "suspected spoofing");
        let r = tm.request_trace(&gcs, true, "admin-1", "investigating spoofing", &pid);
        assert!(r.authorized);
        assert_eq!(r.resolved_drone_id.as_deref(), Some("drone-1"));
    }

    #[test]
    fn non_admin_empty_reason_and_unflagged_are_refused_and_audited() {
        let (gcs, pid, sid) = fixture();
        let mut tm = TraceManager::new();
        let r = tm.request_trace(&gcs, false, "mallory", "curious", &pid);
        assert_eq!(r.outcome, "NOT_ADMIN");
        tm.flag_session(&sid, "D2", "x");
        assert_eq!(tm.request_trace(&gcs, true, "a", "  ", &pid).outcome, "EMPTY_REASON");
        assert_eq!(tm.request_trace(&gcs, false, "a", "r", &pid).outcome, "NOT_ADMIN");
        let mut tm2 = TraceManager::new();
        assert_eq!(tm2.request_trace(&gcs, true, "a", "reason", &pid).outcome, "PID_NOT_FLAGGED");
        assert!(tm2.trace_records.iter().all(|r| r.resolved_drone_id.is_none()));
        assert_eq!(tm.trace_records.len(), 3, "every attempt is audited");
    }

    #[test]
    fn admin_auth_fails_closed() {
        assert!(!AdminAuth::new(None).verify(Some("anything-at-all-123456")));
        assert!(!AdminAuth::new(Some("short")).verify(Some("short")));
        let a = AdminAuth::new(Some("correct-horse-battery-staple"));
        assert!(a.verify(Some("correct-horse-battery-staple")));
        assert!(!a.verify(Some("correct-horse-battery-stapl3")));
        assert!(!a.verify(None));
    }

    #[test]
    fn flagging_a_session_records_it() {
        let mut tm = TraceManager::new();
        let flag = tm.flag_session("session-123", "D2", "MAC failed");
        assert_eq!(tm.flags.len(), 1);
        assert_eq!(flag.session_id, "session-123");
    }
}
