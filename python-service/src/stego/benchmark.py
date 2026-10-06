"""Benchmark engine: the ONLY source of performance/quality numbers used
by the algorithm selector.

Spec requirement (restated because it is the single most important
design constraint of this subsystem): "RAG must never invent
performance numbers; a separate benchmark engine measures real
embed/extract time, capacity, PSNR, SSIM, etc., on the actual current
image+payload." This module IS that separate benchmark engine. It:

  1. Actually calls each candidate algorithm's real `embed()` on the
     real cover image and real payload bytes at hand (never a cached or
     "representative" number from a prior run).
  2. Actually calls `extract()` on the real output and asserts it
     round-trips (a correctness gate, not just a perf number -- an
     algorithm that cannot even recover its own payload for this
     specific image+payload is marked infeasible, not merely "slow").
  3. Actually computes MSE/PSNR/SSIM between the real cover and real
     stego pixel arrays (`stego.base.mse/psnr/ssim_metric`).
  4. Actually times the embed/extract calls with a real wall clock.

Nothing in this module is a lookup table, a literature-derived
estimate, or an LLM-generated guess. The RAG subsystem
(`rag/stego_knowledge.py`) is a STRICT reader of these outputs plus
algorithm documentation text -- see that module's docstring for why it
is architecturally unable to fabricate a number.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

import numpy as np

from .base import StegoCapacityError, StegoExtractError, mse, psnr, ssim_metric, timed
from .registry import ALGORITHMS, all_algorithm_ids


@dataclass
class AlgorithmMeasurement:
    algorithm_id: str
    feasible: bool
    reason: str  # "ok" or why infeasible (e.g. "capacity_exceeded", "boundary_case", "roundtrip_mismatch")
    capacity_bytes: int = 0
    payload_bytes: int = 0
    embed_time_ms: float = 0.0
    extract_time_ms: float = 0.0
    mse: float = 0.0
    psnr_db: float = 0.0
    ssim: float = 0.0
    output_size_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def measure_one(algorithm_id: str, cover_pixels: np.ndarray, payload: bytes) -> AlgorithmMeasurement:
    """Real, single-algorithm measurement against this specific cover
    image and this specific payload. Never raises for an infeasible
    candidate -- it reports `feasible=False` with a reason instead, so
    the selector (and the UI) can show every candidate, not just the
    winner."""
    algo = ALGORITHMS[algorithm_id]
    cap = algo.capacity_bytes(cover_pixels)
    if len(payload) > cap:
        return AlgorithmMeasurement(
            algorithm_id=algorithm_id, feasible=False, reason="capacity_exceeded",
            capacity_bytes=cap, payload_bytes=len(payload),
        )
    try:
        embed_result, embed_ms = timed(algo.embed, cover_pixels, payload)
    except StegoCapacityError as e:
        return AlgorithmMeasurement(
            algorithm_id=algorithm_id, feasible=False, reason=f"boundary_case: {e}",
            capacity_bytes=cap, payload_bytes=len(payload),
        )
    stego_pixels = embed_result.stego_pixels
    try:
        recovered, extract_ms = timed(algo.extract, stego_pixels, len(payload), embed_result.algorithm_params)
    except StegoExtractError as e:
        return AlgorithmMeasurement(
            algorithm_id=algorithm_id, feasible=False, reason=f"extract_error: {e}",
            capacity_bytes=cap, payload_bytes=len(payload),
        )
    if recovered != payload:
        return AlgorithmMeasurement(
            algorithm_id=algorithm_id, feasible=False, reason="roundtrip_mismatch",
            capacity_bytes=cap, payload_bytes=len(payload),
        )
    m = mse(cover_pixels, stego_pixels)
    p = psnr(cover_pixels, stego_pixels)
    s = ssim_metric(cover_pixels, stego_pixels)
    return AlgorithmMeasurement(
        algorithm_id=algorithm_id,
        feasible=True,
        reason="ok",
        capacity_bytes=cap,
        payload_bytes=len(payload),
        embed_time_ms=embed_ms,
        extract_time_ms=extract_ms,
        mse=m,
        psnr_db=p if p != float("inf") else 999.0,  # JSON has no literal Infinity; 999 dB is flagged distinctly below
        ssim=s,
        output_size_bytes=stego_pixels.nbytes,
    )


def measure_all(cover_pixels: np.ndarray, payload: bytes) -> list[AlgorithmMeasurement]:
    """Real measurement of every registered algorithm against this
    exact (cover, payload) pair. This is what the selector consumes --
    it never receives anything else."""
    return [measure_one(algo_id, cover_pixels, payload) for algo_id in all_algorithm_ids()]
