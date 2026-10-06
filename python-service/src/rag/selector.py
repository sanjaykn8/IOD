"""Deterministic, measurement-driven steganography algorithm selector.

This is the ONLY component in the stego-selection subsystem that picks
a winner. It consumes exclusively the real `AlgorithmMeasurement`
objects produced by `stego.benchmark.measure_all` (never anything from
the RAG knowledge-base retrieval in `stego_knowledge.py`, which supplies
explanatory text only -- see that module's docstring). Given the exact
same measurements and importance level, this function always returns
the exact same winner: there is no randomness, no LLM call, and no
tie-breaking by insertion order (ties break on `algorithm_id` ascending,
explicitly, so the result does not depend on dict/list iteration
order).

## Selection procedure

1. **Feasibility gate**: any candidate with `feasible=False` (payload
   exceeds real capacity, or a genuine round-trip/boundary failure) is
   dropped immediately -- it cannot win regardless of its other
   measurements.
2. **Per-metric normalization** across the remaining feasible
   candidates only (never across the full candidate set, so an
   infeasible algorithm's measurements can't skew the scale):
   - `time_score`: 1.0 for the fastest (lowest `embed_time_ms +
     extract_time_ms`), 0.0 for the slowest, linear in between. All 1.0
     if every candidate takes the same time.
   - `capacity_score`: 1.0 for the highest real `capacity_bytes`, 0.0
     for the lowest, linear in between.
   - `distortion_score`: real SSIM directly (already bounded to
     [0, 1], with 1.0 meaning "identical to the cover") -- used as-is
     rather than re-normalized across candidates, since it is already
     a meaningful, comparable quality measure on its own scale. This is
     a deliberate, documented simplification: it does not additionally
     fold in MSE/PSNR into the score (those remain available on each
     measurement for display), on the reasoning that SSIM alone already
     tracks structural/perceptual similarity well and keeps the scoring
     formula simple enough to audit by hand.
3. **Weighted sum** using the importance-level weight table below
   (`IMPORTANCE_WEIGHTS`): `score = w_time*time_score +
   w_capacity*capacity_score + w_distortion*distortion_score`.
4. **Winner**: the feasible candidate with the highest score; exact
   ties break on `algorithm_id` ascending (alphabetical), not on
   measurement order, so the result is reproducible regardless of how
   `measure_all` happened to order its list.

## Default importance weight tables

Registration payloads (drone enrollment credentials) default to
`CRITICAL` importance. The four tables below are this project's chosen
defaults, each summing to 1.0; they are intentionally configurable
(`select_algorithm(..., weights_override=...)`) rather than hardcoded
constants, since the "right" weighting is a deployment policy decision,
not a fact this project can determine once and for all.

| importance | time | capacity | distortion |
|-----------|------|----------|------------|
| LOW       | 0.50 | 0.35     | 0.15       |
| MEDIUM    | 0.30 | 0.35     | 0.35       |
| HIGH      | 0.20 | 0.30     | 0.50       |
| CRITICAL  | 0.15 | 0.25     | 0.60       |

The trend is deliberate: as payload importance rises, the weighting
shifts away from raw speed and toward minimizing visible distortion
(registration credentials are embedded once per drone, infrequently,
so a slower embed is an acceptable cost for a harder-to-detect/less-
damaged stego image; LOW-importance traffic might be embedded far more
often, where speed matters more and any single embed's distortion
matters less).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum

from stego.benchmark import AlgorithmMeasurement


class PayloadImportance(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


IMPORTANCE_WEIGHTS: dict[str, dict[str, float]] = {
    "LOW": {"time": 0.50, "capacity": 0.35, "distortion": 0.15},
    "MEDIUM": {"time": 0.30, "capacity": 0.35, "distortion": 0.35},
    "HIGH": {"time": 0.20, "capacity": 0.30, "distortion": 0.50},
    "CRITICAL": {"time": 0.15, "capacity": 0.25, "distortion": 0.60},
}


@dataclass
class ScoredCandidate:
    algorithm_id: str
    feasible: bool
    score: float
    time_score: float
    capacity_score: float
    distortion_score: float
    measurement: dict

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class SelectionResult:
    winner_algorithm_id: str | None
    importance: str
    weights: dict[str, float]
    candidates: list[ScoredCandidate]  # every candidate, feasible or not, ranked best-first among feasible ones
    reason: str

    def to_dict(self) -> dict:
        return {
            "winner_algorithm_id": self.winner_algorithm_id,
            "importance": self.importance,
            "weights": self.weights,
            "candidates": [c.to_dict() for c in self.candidates],
            "reason": self.reason,
        }


def _normalize(values: list[float]) -> list[float]:
    """Linear min-max normalization to [0, 1], higher input -> higher
    output. Returns all 1.0 if every value is identical (avoids a
    divide-by-zero, and correctly expresses "no candidate is better
    than another on this metric")."""
    lo, hi = min(values), max(values)
    if hi - lo < 1e-12:
        return [1.0 for _ in values]
    return [(v - lo) / (hi - lo) for v in values]


def select_algorithm(
    measurements: list[AlgorithmMeasurement],
    importance: str = "CRITICAL",
    weights_override: dict[str, float] | None = None,
) -> SelectionResult:
    """Deterministically select the best feasible algorithm for this
    exact set of REAL measurements (see module docstring for the full
    procedure). Never receives, and never needs, the cover image or
    payload directly -- `measurements` already encodes everything
    about them that matters to this decision."""
    importance = importance.upper()
    if importance not in IMPORTANCE_WEIGHTS:
        raise ValueError(f"unknown importance level {importance!r}; known: {sorted(IMPORTANCE_WEIGHTS)}")
    weights = dict(weights_override) if weights_override else dict(IMPORTANCE_WEIGHTS[importance])

    feasible = [m for m in measurements if m.feasible]
    infeasible = [m for m in measurements if not m.feasible]

    if not feasible:
        candidates = [
            ScoredCandidate(m.algorithm_id, False, 0.0, 0.0, 0.0, 0.0, m.to_dict()) for m in measurements
        ]
        return SelectionResult(
            winner_algorithm_id=None,
            importance=importance,
            weights=weights,
            candidates=candidates,
            reason="no candidate algorithm is feasible for this image/payload combination",
        )

    total_times = [m.embed_time_ms + m.extract_time_ms for m in feasible]
    capacities = [float(m.capacity_bytes) for m in feasible]
    distortions = [m.ssim for m in feasible]  # already in [0,1], higher = better

    time_scores = [1.0 - t for t in _normalize(total_times)]  # lower time -> higher score, so invert
    capacity_scores = _normalize(capacities)
    distortion_scores = distortions  # used directly, see module docstring

    scored: list[ScoredCandidate] = []
    for m, ts, cs, ds in zip(feasible, time_scores, capacity_scores, distortion_scores):
        total = weights["time"] * ts + weights["capacity"] * cs + weights["distortion"] * ds
        scored.append(ScoredCandidate(m.algorithm_id, True, total, ts, cs, ds, m.to_dict()))
    for m in infeasible:
        scored.append(ScoredCandidate(m.algorithm_id, False, -1.0, 0.0, 0.0, 0.0, m.to_dict()))

    # Rank feasible candidates best-first; deterministic tie-break on
    # algorithm_id ascending (never on original list order).
    feasible_scored = [c for c in scored if c.feasible]
    feasible_scored.sort(key=lambda c: (-c.score, c.algorithm_id))
    infeasible_scored = sorted((c for c in scored if not c.feasible), key=lambda c: c.algorithm_id)

    winner = feasible_scored[0].algorithm_id
    ranked = feasible_scored + infeasible_scored

    return SelectionResult(
        winner_algorithm_id=winner,
        importance=importance,
        weights=weights,
        candidates=ranked,
        reason=f"highest weighted score ({feasible_scored[0].score:.4f}) among {len(feasible_scored)} feasible candidate(s)",
    )
