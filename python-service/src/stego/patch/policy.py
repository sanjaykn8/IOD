"""Operational algorithm policy (mirrors rust-core/src/transport/policy.rs; Rust is the authority).

The educational workbench always offers all ten algorithms; this module only restricts OPERATIONAL plans.

* ``low_detectability`` (default): DCT, DWT and DCT-SVD are excluded by rule pending an independent
  evaluation; LSB replacement is excluded because the versioned risk table ``risk-table-1`` (built from
  validation seeds only; ``kb/risk_table.json``) puts it in the high tier. The remaining algorithms are
  *candidates*, not "safe"; the selector ranks them by measured risk, distortion and cost.
* ``all_algorithms``: everything may be selected (comparison / research runs only).

Rust sends ``{"name": ..., "allowed": [...]}``; the allowed list may only restrict the named policy.
If no permitted plan fits, planning fails (NO_ELIGIBLE_ALGORITHM / PATCH_CAPACITY_INSUFFICIENT); there is
no fallback to an excluded algorithm, and Rust re-checks every manifest (POLICY_VIOLATION).
"""

from ..algorithms import NAMES
from ..errors import StegoError

DEFAULT = "low_detectability"
TRANSFORM_EXCLUDED = ("dct", "dwt", "dct_svd")
RISK_EXCLUDED = ("lsb_replacement",)          # high tier in risk-table-1 (tests check it against the file)
RISK_TABLE_VERSION = "risk-table-1"
POLICIES = {
    "low_detectability": tuple(n for n in NAMES if n not in TRANSFORM_EXCLUDED and n not in RISK_EXCLUDED),
    "all_algorithms": tuple(NAMES),
}


def reason(name, policy_name):
    if policy_name == "low_detectability" and name in TRANSFORM_EXCLUDED:
        return "excluded by rule pending independent evaluation"
    if policy_name == "low_detectability" and name in RISK_EXCLUDED:
        return f"excluded by {RISK_TABLE_VERSION}: high tier on the validation split"
    return "not in the allow list"


def parse(obj):
    """-> (policy_name, allowed tuple in registry order). Absent -> the default policy."""
    if obj is None:
        return DEFAULT, POLICIES[DEFAULT]
    if not isinstance(obj, dict) or set(obj) - {"name", "allowed"}:
        raise StegoError("INVALID_REQUEST", "policy must be an object with 'name' and optional 'allowed'")
    name = obj.get("name", DEFAULT)
    if name not in POLICIES:
        raise StegoError("INVALID_REQUEST", "unknown algorithm policy", {"policy": name, "known": sorted(POLICIES)})
    base = POLICIES[name]
    allowed = obj.get("allowed", list(base))
    if not isinstance(allowed, list) or not allowed or not all(isinstance(a, str) for a in allowed):
        raise StegoError("INVALID_REQUEST", "policy.allowed must be a non-empty list of algorithm names")
    extra = sorted(set(allowed) - set(base))
    if extra:
        raise StegoError("INVALID_REQUEST", "policy.allowed may only restrict the named policy", {"policy": name, "not_permitted": extra})
    return name, tuple(n for n in NAMES if n in allowed)


def describe(name, allowed):
    return {"name": name, "allowed": list(allowed),
            "excluded": [{"algorithm": n, "reason": reason(n, name)} for n in NAMES if n not in allowed]}
