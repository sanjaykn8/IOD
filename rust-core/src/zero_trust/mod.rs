//! Zero Trust authorization layer.
//!
//! IMPORTANT (spec requirement): Zero Trust is an AUTHORIZATION layer,
//! not the cryptographic authentication mechanism. `evaluate()` never
//! re-derives or re-checks a cryptographic proof itself — it only
//! consumes the boolean *results* of authentication checks performed
//! elsewhere (freshness, ZK membership, ML-DSA signature, PUF
//! verification, root/version) plus policy-relevant context, and
//! returns ALLOW/DENY with a reason code.
//!
//! The engine is a replaceable trait (`PolicyEngine`) so a deployment
//! could swap in a different policy without touching the protocol code
//! that calls it (`protocol::auth_flow::m7_verify_and_decide`).
//! `DefaultPolicy` is a deterministic, configurable implementation —
//! not a learned/ML model, and not claimed to be one.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroTrustInputs {
    pub freshness_ok: bool,
    pub zk_membership_ok: bool,
    pub signature_ok: bool,
    pub puf_ok: bool,
    pub root_version_ok: bool,
    pub group_id: String,
    pub requested_operation: String,
    /// Structural extension point for a mission-time-window policy
    /// (e.g. "only allow authentication during an active mission
    /// window"). Not yet wired to a UI control in this prototype — every
    /// current call site passes `true` — but present so the policy
    /// engine's shape does not need to change when that control is
    /// added.
    pub mission_active: bool,
    /// Structural extension point for a simulated device-health signal
    /// (e.g. battery critical, tamper flag). Same status as
    /// `mission_active` above.
    pub device_health_ok: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: Decision,
    pub reason_code: String,
}

fn deny(reason: &str) -> PolicyResult {
    PolicyResult { decision: Decision::Deny, reason_code: reason.to_string() }
}
fn allow(reason: &str) -> PolicyResult {
    PolicyResult { decision: Decision::Allow, reason_code: reason.to_string() }
}

pub trait PolicyEngine: Send + Sync {
    fn decide(&self, inputs: &ZeroTrustInputs) -> PolicyResult;
    fn name(&self) -> &'static str;
}

/// Deterministic, configurable default policy: ALLOW iff every upstream
/// check passed. Checks are ordered so the reason code reflects the
/// *first* failing check an operator would want to triage.
pub struct DefaultPolicy {
    /// Operations this policy will authorize at all, even when every
    /// cryptographic check passes (a simple allowlist — extend as
    /// needed; e.g. a read-only telemetry group might not authorize
    /// "actuate").
    pub allowed_operations: Vec<String>,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        DefaultPolicy {
            allowed_operations: vec!["authenticate".into(), "secure_message".into(), "group_key".into()],
        }
    }
}

impl PolicyEngine for DefaultPolicy {
    fn decide(&self, inputs: &ZeroTrustInputs) -> PolicyResult {
        if !inputs.freshness_ok {
            return deny("STALE_TIMESTAMP_OR_NONCE");
        }
        if !inputs.root_version_ok {
            return deny("STALE_MEMBERSHIP_ROOT_OR_VERSION");
        }
        if !inputs.zk_membership_ok {
            return deny("ZK_MEMBERSHIP_PROOF_INVALID");
        }
        if !inputs.signature_ok {
            return deny("ML_DSA_SIGNATURE_INVALID");
        }
        if !inputs.puf_ok {
            return deny("PUF_VERIFICATION_FAILED");
        }
        if !inputs.mission_active {
            return deny("MISSION_WINDOW_INACTIVE");
        }
        if !inputs.device_health_ok {
            return deny("DEVICE_HEALTH_CHECK_FAILED");
        }
        if !self.allowed_operations.iter().any(|op| op == &inputs.requested_operation) {
            return deny("OPERATION_NOT_AUTHORIZED_BY_POLICY");
        }
        allow("ALL_CHECKS_PASSED")
    }

    fn name(&self) -> &'static str {
        "default-policy-v1"
    }
}

/// Convenience free function using `DefaultPolicy` — kept so existing
/// call sites (and the Phase-4 tests written before this policy-engine
/// generalization) do not need to construct a `DefaultPolicy` directly.
pub fn evaluate(inputs: &ZeroTrustInputs) -> PolicyResult {
    DefaultPolicy::default().decide(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ZeroTrustInputs {
        ZeroTrustInputs {
            freshness_ok: true,
            zk_membership_ok: true,
            signature_ok: true,
            puf_ok: true,
            root_version_ok: true,
            group_id: "alpha".into(),
            requested_operation: "authenticate".into(),
            mission_active: true,
            device_health_ok: true,
        }
    }

    #[test]
    fn all_pass_allows() {
        assert_eq!(evaluate(&base()).decision, Decision::Allow);
    }

    #[test]
    fn any_single_failure_denies_with_specific_reason() {
        let mut i = base();
        i.puf_ok = false;
        let r = evaluate(&i);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.reason_code, "PUF_VERIFICATION_FAILED");
    }

    #[test]
    fn stale_version_denies_before_other_checks_are_considered() {
        let mut i = base();
        i.root_version_ok = false;
        i.signature_ok = false;
        let r = evaluate(&i);
        assert_eq!(r.reason_code, "STALE_MEMBERSHIP_ROOT_OR_VERSION");
    }

    #[test]
    fn inactive_mission_window_denies() {
        let mut i = base();
        i.mission_active = false;
        assert_eq!(evaluate(&i).reason_code, "MISSION_WINDOW_INACTIVE");
    }

    #[test]
    fn unhealthy_device_denies() {
        let mut i = base();
        i.device_health_ok = false;
        assert_eq!(evaluate(&i).reason_code, "DEVICE_HEALTH_CHECK_FAILED");
    }

    #[test]
    fn operation_outside_allowlist_denies() {
        let mut i = base();
        i.requested_operation = "actuate_payload".into();
        assert_eq!(evaluate(&i).reason_code, "OPERATION_NOT_AUTHORIZED_BY_POLICY");
    }

    #[test]
    fn custom_policy_engine_can_be_swapped_in() {
        struct AlwaysDeny;
        impl PolicyEngine for AlwaysDeny {
            fn decide(&self, _inputs: &ZeroTrustInputs) -> PolicyResult {
                deny("TEST_POLICY_ALWAYS_DENIES")
            }
            fn name(&self) -> &'static str {
                "always-deny-test-policy"
            }
        }
        let policy: Box<dyn PolicyEngine> = Box::new(AlwaysDeny);
        assert_eq!(policy.decide(&base()).reason_code, "TEST_POLICY_ALWAYS_DENIES");
        assert_eq!(policy.name(), "always-deny-test-policy");
    }
}
