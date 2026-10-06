"""Tests for the deterministic stego-algorithm selector
(rag/selector.py) -- determinism, tie-breaking, importance-weight
sensitivity, capacity-based rejection, and all-candidates-failing.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rag.selector import select_algorithm, IMPORTANCE_WEIGHTS
from stego.benchmark import AlgorithmMeasurement


def m(algo_id, feasible=True, capacity=1000, payload=100, embed_ms=1.0, extract_ms=1.0, mse=10.0, psnr=30.0, ssim=0.95, reason="ok"):
    return AlgorithmMeasurement(
        algorithm_id=algo_id, feasible=feasible, reason=reason, capacity_bytes=capacity,
        payload_bytes=payload, embed_time_ms=embed_ms, extract_time_ms=extract_ms, mse=mse,
        psnr_db=psnr, ssim=ssim, output_size_bytes=capacity * 3,
    )


def test_determinism_same_inputs_same_winner():
    measurements = [m("dct", ssim=0.9), m("dwt", ssim=0.95), m("svd", ssim=0.8), m("pvd", ssim=0.7), m("adaptive_lsb", ssim=0.6)]
    r1 = select_algorithm(measurements, importance="CRITICAL")
    r2 = select_algorithm(measurements, importance="CRITICAL")
    assert r1.winner_algorithm_id == r2.winner_algorithm_id
    assert [c.score for c in r1.candidates] == [c.score for c in r2.candidates]


def test_critical_importance_favors_lower_distortion_over_speed():
    # dct is much faster but has worse SSIM; dwt is slower but near-perfect SSIM.
    measurements = [
        m("dct", embed_ms=0.1, extract_ms=0.1, ssim=0.5),
        m("dwt", embed_ms=5.0, extract_ms=5.0, ssim=0.99),
    ]
    result = select_algorithm(measurements, importance="CRITICAL")
    assert result.winner_algorithm_id == "dwt", "CRITICAL weighting (distortion=0.60) should favor the far-higher-SSIM candidate"


def test_low_importance_favors_speed_over_distortion():
    measurements = [
        m("dct", embed_ms=0.1, extract_ms=0.1, ssim=0.5),
        m("dwt", embed_ms=50.0, extract_ms=50.0, ssim=0.60),
    ]
    result = select_algorithm(measurements, importance="LOW")
    assert result.winner_algorithm_id == "dct", "LOW weighting (time=0.50) should favor the much faster candidate when SSIM gap is small"


def test_infeasible_candidates_are_excluded():
    measurements = [m("dct", feasible=False, reason="capacity_exceeded"), m("dwt", ssim=0.9)]
    result = select_algorithm(measurements, importance="CRITICAL")
    assert result.winner_algorithm_id == "dwt"


def test_all_infeasible_returns_no_winner():
    measurements = [m("dct", feasible=False, reason="capacity_exceeded"), m("dwt", feasible=False, reason="capacity_exceeded")]
    result = select_algorithm(measurements, importance="CRITICAL")
    assert result.winner_algorithm_id is None
    assert "no candidate" in result.reason


def test_exact_tie_breaks_on_algorithm_id_ascending():
    measurements = [m("svd", ssim=0.9, capacity=500, embed_ms=1.0), m("dct", ssim=0.9, capacity=500, embed_ms=1.0)]
    result = select_algorithm(measurements, importance="CRITICAL")
    assert result.winner_algorithm_id == "dct", "exact tie must break alphabetically, not by input order"


def test_unknown_importance_level_raises():
    import pytest
    with pytest.raises(ValueError):
        select_algorithm([m("dct")], importance="URGENT")


def test_all_weight_tables_sum_to_one():
    for level, weights in IMPORTANCE_WEIGHTS.items():
        assert abs(sum(weights.values()) - 1.0) < 1e-9, f"{level} weights must sum to 1.0"
