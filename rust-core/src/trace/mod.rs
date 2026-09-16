//! Trace Manager: NOT part of the normal authentication path. Activated
//! only when suspicious/malicious behavior is flagged, and only usable
//! by an authorized administrator role — see spec requirements.
//!
//! Privacy model preserved: `request_trace` only resolves a PID to a
//! permanent DroneID when `requester_role == "administrator"`; every
//! other caller gets `resolved_drone_id: None` plus an explicit
//! `authorized: false`, and the attempt itself is still recorded in the
//! audit trail (so unauthorized trace attempts are themselves visible to
//! a real administrator later).

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
    pub resolved_drone_id: Option<String>,
    pub timestamp_unix_ms: u64,
}

pub struct TraceManager {
    pub flags: Vec<SuspicionFlag>,
    pub trace_records: Vec<TraceRecord>,
}

impl TraceManager {
    pub fn new() -> Self {
        TraceManager {
            flags: Vec::new(),
            trace_records: Vec::new(),
        }
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

    /// Only `requester_role == "administrator"` ever gets a resolved
    /// DroneID back; every attempt (authorized or not) is appended to
    /// `trace_records` for GCS's own audit trail.
    ///
    /// Takes the already-resolved lookup result rather than `&GcsState`
    /// directly, purely so callers holding both `&GcsState` and
    /// `&mut TraceManager` as sibling fields of one larger struct (see
    /// `api::state::SimulationState`) can do the GCS lookup first and
    /// avoid an artificial simultaneous-borrow conflict. The
    /// authorization *decision* still happens in here, not at the call
    /// site — a non-administrator's lookup result is simply never
    /// computed/passed in by well-behaved callers, and even if it were,
    /// this function still gates on `requester_role` itself.
    pub fn request_trace(
        &mut self,
        requester_role: &str,
        resolved_if_authorized: Option<String>,
        requested_by: &str,
        reason: &str,
        target_pid: &[u8],
    ) -> TraceRecord {
        let authorized = requester_role == "administrator";
        let resolved_drone_id = if authorized { resolved_if_authorized } else { None };
        let record = TraceRecord {
            trace_id: random_id(),
            requested_by: requested_by.to_string(),
            requester_role: requester_role.to_string(),
            reason: reason.to_string(),
            target_pid_hex: hex::encode(target_pid),
            authorized,
            resolved_drone_id,
            timestamp_unix_ms: crate::protocol::events::now_unix_ms(),
        };
        self.trace_records.push(record.clone());
        record
    }

    /// Convenience wrapper for callers that DO have both `&GcsState` and
    /// `&mut TraceManager` available as genuinely separate borrows
    /// (e.g. a direct, non-struct-field call site, or tests).
    pub fn request_trace_with_gcs(
        &mut self,
        gcs: &GcsState,
        requested_by: &str,
        requester_role: &str,
        reason: &str,
        target_pid: &[u8],
    ) -> TraceRecord {
        let resolved = if requester_role == "administrator" {
            gcs.resolve_pid(target_pid).map(|s| s.to_string())
        } else {
            None
        };
        self.request_trace(requester_role, resolved, requested_by, reason, target_pid)
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
    use crate::protocol::entities::DroneState;
    use crate::protocol::registration::register_drone;

    #[test]
    fn administrator_can_resolve_a_pid() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();
        let pid = crate::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);

        let mut tm = TraceManager::new();
        let record = tm.request_trace_with_gcs(&gcs, "admin-1", "administrator", "suspected spoofing", &pid);
        assert!(record.authorized);
        assert_eq!(record.resolved_drone_id.as_deref(), Some("drone-1"));
        assert_eq!(tm.trace_records.len(), 1);
    }

    #[test]
    fn non_administrator_cannot_resolve_a_pid_but_attempt_is_logged() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();
        let pid = crate::identity::pid::derive_pid(&d1.reconstruct_seed(), 0);

        let mut tm = TraceManager::new();
        let record = tm.request_trace_with_gcs(&gcs, "drone-2", "drone", "curious", &pid);
        assert!(!record.authorized);
        assert!(record.resolved_drone_id.is_none());
        assert_eq!(tm.trace_records.len(), 1, "unauthorized attempts must still be audited");
    }

    #[test]
    fn flagging_a_session_records_it() {
        let mut tm = TraceManager::new();
        let flag = tm.flag_session("session-123", "D2", "MAC verification failed twice in a row");
        assert_eq!(tm.flags.len(), 1);
        assert_eq!(flag.session_id, "session-123");
    }
}
