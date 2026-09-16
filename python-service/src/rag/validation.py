"""Contribution validation / deterministic "Byzantine-ish" scoring.

IMPORTANT — read before citing this as a security feature: this is a
SIMULATOR-LEVEL heuristic, not a real Byzantine fault-tolerant defense.
A genuine BFT contribution-validation scheme would need cryptographic
attestation of provenance (which the Rust core's AEAD/signature layers
actually provide upstream of this service) plus a principled statistical
or ML-based outlier-detection method with characterized false-positive
/false-negative rates. What this module does is much simpler and is
labeled as such everywhere it appears (code comments, API responses,
docs/rag.md): it flags a contribution as "suspicious" if its content is
a substantial outlier (low average word-overlap) relative to the rest of
the batch, and reduces its trust score proportionally. This can and will
misfire on genuinely novel-but-true reports; it is a demonstration of
where a defense would go, not a working defense.
"""

from typing import List
from .models import Contribution
from .retrieval import jaccard

SUSPICION_THRESHOLD = 0.08  # average pairwise Jaccard similarity below this => flagged


def validate(contributions: List[Contribution]) -> List[Contribution]:
    n = len(contributions)
    for i, c in enumerate(contributions):
        if n <= 1:
            c.trust_score = c.confidence
            continue
        similarities = [
            jaccard(c.content, other.content) for j, other in enumerate(contributions) if j != i
        ]
        avg_similarity = sum(similarities) / len(similarities)
        if avg_similarity < SUSPICION_THRESHOLD:
            c.flagged_suspicious = True
            c.flag_reason = (
                f"content is an outlier relative to the batch "
                f"(avg word-overlap similarity {avg_similarity:.3f} < threshold {SUSPICION_THRESHOLD})"
            )
            c.trust_score = max(0.0, c.confidence * avg_similarity * 2.0)
        else:
            c.flagged_suspicious = False
            c.flag_reason = ""
            c.trust_score = c.confidence
    return contributions
