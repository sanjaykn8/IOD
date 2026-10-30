import copy
import random

import numpy as np
import pytest

from stego import selector
from stego.algorithms import NAMES
from stego.errors import StegoError
from stego_helpers import bw_cover, natural_cover

RGB = natural_cover(96, 128, 3)
GRAY = natural_cover(96, 128, 1)


def strip(report):
    r = copy.deepcopy(report)
    for c in r["candidates"]:
        c.pop("trial_ms")
    return r


def err(**kw):
    with pytest.raises(StegoError) as ei:
        selector.select(**kw)
    return ei.value


def by(rep, name):
    return next(c for c in rep["candidates"] if c["algorithm"] == name)


def test_report_shape():
    r = selector.select(RGB, 40)
    assert r["policy_version"] == "sel-policy-2" and r["priority"] == "normal" and r["mode"] == "auto"
    assert r["selected_alg_id"] == NAMES.index(r["selected"]) + 1 and r["selected_param"] == 0
    assert [c["algorithm"] for c in r["candidates"]] == NAMES
    for c in r["candidates"]:
        for k in ("eligible", "exclusion_reason", "capacity_bits", "capacity_bytes", "utilization", "headroom_bits",
                  "est_cost_units", "mse", "psnr", "ssim", "score", "trial_ms"):
            assert k in c
    assert r["features"]["frame_bytes"] == 40 and r["features"]["width"] == 128


def test_determinism_repeated_and_shuffled():
    base = strip(selector.select(RGB, 40))
    for _ in range(3):
        assert strip(selector.select(RGB, 40)) == base
    rnd = random.Random(1)
    for _ in range(5):
        names = list(NAMES)
        rnd.shuffle(names)
        assert strip(selector.select(RGB, 40, candidates=names)) == base


def test_cost_model_exact():
    # work*(frame+16)/64 + scan*(H*W)/1e5
    assert selector.est_cost_units("dct", 48, 100, 1000) == pytest.approx(2.0 * 64 / 64 + 1.0 * 1.0)
    assert selector.est_cost_units("lsb_replacement", 112, 480, 640) == pytest.approx(0.5 * 2.0)
    r = selector.select(RGB, 40)
    assert by(r, "pvd")["est_cost_units"] == pytest.approx(round(1.2 * 56 / 64 + 0.2 * 96 * 128 / 1e5, 6))


def test_score_formula_recomputed_independently():
    r = selector.select(RGB, 40, "normal")
    wd, wu, wt = 0.5, 0.2, 0.3
    for c in r["candidates"]:
        if not c["eligible"]:
            assert c["score"] is None
            continue
        d = 0 if c["psnr"] is None else min(1, max(0, 1 - c["psnr"] / 80))
        u = 320 / c["capacity_bits"]
        t = min(1, c["est_cost_units"] / 20)
        assert c["score"] == pytest.approx(wd * d + wu * u + wt * t, abs=2e-6)


def test_trial_payload_deterministic_and_length():
    assert selector.trial_payload(50) == selector.trial_payload(50)
    assert selector.trial_payload(50) != selector.trial_payload(51)[:50]
    assert len(selector.trial_payload(333)) == 333


def test_tie_break_order_and_epsilon():
    r = selector.select(RGB, 40, policy={"tie_epsilon": 1.0})  # everything tied
    assert r["selected"] == "s_uniward" and r["reason_code"] == "TIE_BREAK_ORDER"
    order = ["dct"] + [n for n in NAMES if n != "dct"]
    r = selector.select(RGB, 40, policy={"tie_epsilon": 1.0, "tie_break_order": order})
    assert r["selected"] == "dct" and r["reason_code"] == "TIE_BREAK_ORDER"
    # epsilon 0 -> strict best score
    r0 = selector.select(RGB, 40, policy={"tie_epsilon": 0.0})
    best = min((c for c in r0["candidates"] if c["eligible"]), key=lambda c: c["score"])
    assert r0["selected"] == best["algorithm"] and r0["reason_code"] == "BEST_SCORE"
    # epsilon exactly spanning two candidates ties only those
    sc = sorted(c["score"] for c in r0["candidates"] if c["eligible"])
    eps = (sc[1] - sc[0]) + 1e-9
    rt = selector.select(RGB, 40, policy={"tie_epsilon": eps, "tie_break_order": list(reversed(NAMES))})
    tied = [c["algorithm"] for c in rt["candidates"] if c["eligible"] and c["score"] <= sc[0] + eps + 1e-12]
    assert len(tied) >= 2 and rt["selected"] == next(n for n in reversed(NAMES) if n in tied)


def test_best_score_unique():
    r = selector.select(RGB, 100, "urgent", {"tie_epsilon": 0.001})
    assert r["selected"] == "lsb_replacement" and r["reason_code"] == "BEST_SCORE"


def test_only_eligible():
    r = selector.select(RGB, 40, candidates=["pvd"])
    assert r["selected"] == "pvd" and r["reason_code"] == "ONLY_ELIGIBLE"
    assert [c["algorithm"] for c in r["candidates"]] == ["pvd"]


def test_priority_classes_give_documented_different_outcomes():
    assert selector.WEIGHTS == {"urgent": (0.2, 0.1, 0.7), "normal": (0.5, 0.2, 0.3), "background": (0.8, 0.15, 0.05)}
    u = selector.select(RGB, 100, "urgent")
    n = selector.select(RGB, 100, "normal")
    assert (u["selected"], n["selected"]) == ("lsb_replacement", "lsb_matching")
    assert u["weights"] == {"w_d": 0.2, "w_u": 0.1, "w_t": 0.7}
    assert selector.select(RGB, 100)["priority"] == "normal"  # default
    assert selector.select(RGB, 1000, "normal")["selected"] == "lsb_replacement"
    assert selector.select(RGB, 1000, "background")["selected"] == "lsb_matching"
    assert by(u, "dct")["score"] != by(n, "dct")["score"]


def test_different_inputs_change_eligibility():
    small = selector.select(RGB, 40)
    big = selector.select(RGB, 1000)
    assert by(small, "dct")["eligible"] and not by(big, "dct")["eligible"]
    assert by(big, "dct")["exclusion_reason"] == "CAPACITY_INSUFFICIENT"
    assert not by(big, "pvd")["eligible"] or by(big, "pvd")["capacity_bytes"] >= 1000
    assert selector.select(GRAY, 40)["features"]["mode"] == "L"


def test_no_capacity_returns_candidate_table():
    tiny = natural_cover(32, 32, 1)
    e = err(arr=tiny, frame_bytes=500)
    assert e.code == "NO_ELIGIBLE_ALGORITHM"
    assert [c["algorithm"] for c in e.details["candidates"]] == NAMES
    assert all(c["exclusion_reason"] in ("CAPACITY_INSUFFICIENT", "EDGE_CAPACITY_INSUFFICIENT") for c in e.details["candidates"])
    assert e.details["policy_version"] == "sel-policy-2"
    assert by(e.details, "edge_adaptive_lsb")["exclusion_reason"] == "EDGE_CAPACITY_INSUFFICIENT"


def test_flat_cover_edge_excluded_specific_reason():
    flat = np.full((64, 64, 3), 100, np.uint8)
    r = selector.select(flat, 10)
    assert by(r, "edge_adaptive_lsb")["exclusion_reason"] == "EDGE_CAPACITY_INSUFFICIENT"
    assert r["selected"] != "edge_adaptive_lsb"


def test_hard_constraints():
    r = selector.select(RGB, 40, policy={"max_cost_units": 1.0})
    assert by(r, "pvd")["exclusion_reason"] == "COST_LIMIT" and by(r, "dct")["exclusion_reason"] == "COST_LIMIT"
    assert by(r, "lsb_replacement")["eligible"]
    base = selector.select(RGB, 40)
    dct_mse = by(base, "dct")["mse"]
    lsb_mse = by(base, "lsb_matching")["mse"]
    r = selector.select(RGB, 40, policy={"max_mse": (dct_mse + lsb_mse) / 2})
    assert by(r, "dct")["exclusion_reason"] == "MSE_LIMIT" and by(r, "lsb_matching")["eligible"]
    e = err(arr=RGB, frame_bytes=40, policy={"min_psnr_db": 200})
    assert e.code == "NO_ELIGIBLE_ALGORITHM"
    cap = {"CAPACITY_INSUFFICIENT"}  # dct_svd cannot hold 40 bytes in a 96x128 cover
    assert {c["exclusion_reason"] for c in e.details["candidates"]} - cap == {"PSNR_LIMIT"}
    e = err(arr=RGB, frame_bytes=40, policy={"max_mse": 0.0})
    assert e.code == "NO_ELIGIBLE_ALGORITHM" and {c["exclusion_reason"] for c in e.details["candidates"]} - cap == {"MSE_LIMIT"}


def test_infinite_psnr_passes_psnr_limit():
    # a one-byte frame whose trial bits already match the cover would give inf PSNR; emulate via constraint path
    r = selector.select(RGB, 1, policy={"min_psnr_db": 40})
    for c in r["candidates"]:
        assert c["psnr"] is None or c["psnr"] >= 40 or not c["eligible"]


def test_dct_trial_failure_excludes_with_reason():
    sat = np.full((64, 64, 3), 255, np.uint8)
    r = selector.select(sat, 4)
    assert by(r, "dct")["exclusion_reason"] == "ENCODE_VERIFY_FAILED"
    assert r["selected"] != "dct"


def test_manual_override_validated():
    r = selector.select(RGB, 40, forced="dct")
    assert r["selected"] == "dct" and r["reason_code"] == "MANUAL_OVERRIDE" and r["mode"] == "manual"
    assert r["selected_alg_id"] == 5
    e = err(arr=RGB, frame_bytes=1000, forced="dct")
    assert e.code == "ALGORITHM_NOT_ELIGIBLE" and e.details["reason"] == "CAPACITY_INSUFFICIENT"
    assert len(e.details["candidates"]) == len(NAMES) == 10
    e = err(arr=RGB, frame_bytes=40, forced="dct", policy={"max_mse": 0.0001})
    assert e.code == "ALGORITHM_NOT_ELIGIBLE" and e.details["reason"] == "MSE_LIMIT"
    e = err(arr=np.full((64, 64), 7, np.uint8), frame_bytes=4, forced="edge_adaptive_lsb")
    assert e.code == "ALGORITHM_NOT_ELIGIBLE" and e.details["reason"] == "EDGE_CAPACITY_INSUFFICIENT"
    e = err(arr=bw_cover(64, 64), frame_bytes=30, forced="dct")
    assert e.code == "ALGORITHM_NOT_ELIGIBLE"


def test_manual_param_and_policy_params():
    r = selector.select(RGB, 40, forced="dct", forced_param=20)
    assert r["selected_param"] == 20 and by(r, "dct")["param"] == 20
    r = selector.select(RGB, 40, policy={"params": {"edge_adaptive_lsb": 10}}, forced="edge_adaptive_lsb")
    assert r["selected_param"] == 10
    assert err(arr=RGB, frame_bytes=40, forced="dct", forced_param=3).code == "INVALID_REQUEST"


@pytest.mark.parametrize("kw", [
    {"forced": "nope"}, {"candidates": ["nope"]}, {"priority": "high"}, {"priority": 3},
    {"policy": []}, {"policy": {"max_mse": -1}}, {"policy": {"max_mse": "x"}}, {"policy": {"max_mse": float("nan")}},
    {"policy": {"max_mse": True}}, {"policy": {"tie_break_order": ["dct"]}}, {"policy": {"name": "sel-policy-9"}},
    {"policy": {"params": {"pvd": 4}}}, {"policy": {"params": {"zzz": 1}}}, {"policy": {"tie_epsilon": 5}},
])
def test_invalid_inputs(kw):
    assert err(arr=RGB, frame_bytes=40, **kw).code == "INVALID_REQUEST"


def test_unknown_policy_keys_ignored_and_defaults_applied():
    p = selector.parse_policy({"extra": 1})
    assert p["max_mse"] == 4.0 and p["min_psnr_db"] == 40.0 and p["max_cost_units"] == 1000.0 and p["tie_epsilon"] == 0.01
    assert p["tie_break_order"] == selector.DEFAULT_TIE_ORDER and sorted(p["tie_break_order"]) == sorted(NAMES)


def test_frame_validation():
    assert err(arr=RGB, frame_bytes=0).code == "INVALID_REQUEST"
    assert err(arr=RGB, frame_bytes=-3).code == "INVALID_REQUEST"
    assert err(arr=RGB, frame_bytes="5").code == "INVALID_REQUEST"
    assert err(arr=RGB, frame_bytes=2000, max_frame_bytes=1000).code == "FRAME_TOO_LARGE"


def test_selector_does_not_modify_cover():
    before = RGB.copy()
    selector.select(RGB, 40)
    assert np.array_equal(before, RGB)


def test_640x480_selection_time_budget():
    import time
    cov = natural_cover(480, 640, 3)
    t = time.perf_counter()
    selector.select(cov, 1024)
    # ten trial encodes incl. three STC/cost-map methods; measured ~3-4 s on the build host
    assert time.perf_counter() - t < 10.0
