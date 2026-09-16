"""Context fusion: combine validated contributions into one fused
context string, ordered by trust score (highest first), excluding
contributions flagged as suspicious below a minimum trust floor.
"""

from typing import List
from .models import Contribution

MIN_TRUST_TO_INCLUDE = 0.15


def fuse(contributions: List[Contribution]) -> dict:
    included = [c for c in contributions if c.trust_score >= MIN_TRUST_TO_INCLUDE]
    excluded = [c for c in contributions if c.trust_score < MIN_TRUST_TO_INCLUDE]
    included.sort(key=lambda c: c.trust_score, reverse=True)

    fused_text = "\n".join(f"[{c.drone_id} | trust={c.trust_score:.2f}] {c.content}" for c in included)
    return {
        "fused_context": fused_text,
        "included_drone_ids": [c.drone_id for c in included],
        "excluded_drone_ids": [c.drone_id for c in excluded],
    }
