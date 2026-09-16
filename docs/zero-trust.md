# Zero Trust Authorization

## Zero Trust is authorization, not authentication

`zero_trust::evaluate` (backed by the replaceable `PolicyEngine` trait,
default implementation `DefaultPolicy`) never re-derives or re-checks a
cryptographic proof itself. It consumes the boolean *results* of
authentication checks performed elsewhere:

```rust
pub struct ZeroTrustInputs {
    pub freshness_ok: bool,
    pub zk_membership_ok: bool,
    pub signature_ok: bool,
    pub puf_ok: bool,
    pub root_version_ok: bool,
    pub group_id: String,
    pub requested_operation: String,
    pub mission_active: bool,     // structural extension point, always true today
    pub device_health_ok: bool,   // structural extension point, always true today
}
```

## Decision logic

Checks run in a fixed order, denying on the first failure, so the
returned `reason_code` reflects the check an operator would want to
triage first: `STALE_TIMESTAMP_OR_NONCE` → `STALE_MEMBERSHIP_ROOT_OR_VERSION`
→ `ZK_MEMBERSHIP_PROOF_INVALID` → `ML_DSA_SIGNATURE_INVALID` →
`PUF_VERIFICATION_FAILED` → `MISSION_WINDOW_INACTIVE` →
`DEVICE_HEALTH_CHECK_FAILED` → `OPERATION_NOT_AUTHORIZED_BY_POLICY` →
(all pass) `ALL_CHECKS_PASSED`.

`DefaultPolicy` also enforces a simple operation allowlist
(`authenticate`, `secure_message`, `group_key` by default) — a
deployment could restrict a read-only telemetry group to a smaller
allowlist, for instance.

## This is deterministic and configurable, not learned

Explicitly NOT a machine-learning model, and never described as one.
The `mission_active`/`device_health_ok` fields are structural extension
points for future mission-time-window and device-health-telemetry
policies; no current call site wires real data into them (both are
always `true` today), which is stated here rather than left to be
discovered by reading the code.

## Replaceability

`PolicyEngine` is a trait; `protocol::auth_flow::m7_verify_and_decide`
calls the free function `zero_trust::evaluate`, which is a thin wrapper
around `DefaultPolicy::default().decide(...)`. A deployment-specific
policy (e.g., time-of-day restrictions, per-role operation allowlists,
integration with an external policy decision point) can implement
`PolicyEngine` and be substituted without touching the protocol code —
directly tested in
`zero_trust::tests::custom_policy_engine_can_be_swapped_in`.
