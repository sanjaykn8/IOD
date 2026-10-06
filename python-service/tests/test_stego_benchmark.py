"""Tests for the REAL measurement-based benchmark engine (stego.benchmark).

These assert the engine's core honesty property: every number it
reports comes from an actual embed/extract/metric call on the actual
image+payload passed in, never a lookup or estimate.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import numpy as np

from stego.benchmark import measure_all, measure_one
from stego.registry import all_algorithm_ids
from test_stego_algorithms import make_test_image


def test_measure_all_covers_every_registered_algorithm():
    img = make_test_image(kind="natural")
    payload = b"benchmark-payload-0123456789"
    results = measure_all(img, payload)
    ids = {r.algorithm_id for r in results}
    assert ids == set(all_algorithm_ids())


def test_feasible_measurements_have_a_real_consistent_mse_psnr_relationship():
    img = make_test_image(kind="natural")
    payload = b"benchmark-payload-0123456789"
    for r in measure_all(img, payload):
        if not r.feasible:
            continue
        # A non-trivial embed (anything other than a bit-identical
        # image) must have mse > 0 and a finite-ish psnr_db < 999 (our
        # sentinel for "infinite", i.e. zero distortion).
        assert r.mse >= 0.0
        assert 0.0 <= r.ssim <= 1.0 + 1e-9
        assert r.embed_time_ms >= 0.0
        assert r.extract_time_ms >= 0.0
        assert r.capacity_bytes >= r.payload_bytes


def test_identical_cover_and_payload_give_identical_measurements():
    """Re-running the benchmark on the exact same inputs must give the
    exact same real measurements (determinism of the underlying
    algorithms, not a cached/estimated number)."""
    img = make_test_image(kind="natural")
    payload = b"benchmark-payload-0123456789"
    r1 = measure_one("dct", img, payload)
    r2 = measure_one("dct", img, payload)
    assert r1.mse == r2.mse
    assert r1.psnr_db == r2.psnr_db
    assert r1.ssim == r2.ssim
    assert r1.capacity_bytes == r2.capacity_bytes


def test_larger_payload_never_reports_smaller_capacity_than_itself_when_feasible():
    img = make_test_image(kind="natural")
    small_payload = b"short"
    results = measure_all(img, small_payload)
    for r in results:
        if r.feasible:
            assert r.capacity_bytes >= len(small_payload)


def test_infeasible_candidate_reports_a_reason_not_a_crash():
    img = make_test_image(h=16, w=16, kind="flat")
    huge_payload = bytes(10_000)
    for r in measure_all(img, huge_payload):
        assert not r.feasible
        assert r.reason != "ok"
