"""The offline evaluation tools (scripts/eval_detectability.py, scripts/bench_generator.py) are not part of
the service, but their numbers are reported, so their building blocks are tested here."""
import importlib.util
import os
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


E = _load("eval_detectability")
B = _load("bench_generator")


def test_auc_matches_brute_force_including_ties():
    rng = np.random.default_rng(1)
    for _ in range(20):
        y = rng.integers(0, 2, 40)
        s = rng.integers(0, 6, 40).astype(float)        # many ties
        if y.min() == y.max():
            continue
        pos, neg = s[y == 1], s[y == 0]
        brute = np.mean([1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg])
        assert abs(E.auc(y, s) - brute) < 1e-12
    assert E.auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert E.auc([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1]) == 0.0
    assert np.isnan(E.auc([1, 1], [0.3, 0.4]))


def test_classification_counts():
    c = E.classification([0, 0, 1, 1, 1], [0.2, 0.7, 0.9, 0.4, 0.6])
    assert c["confusion_matrix"] == {"true_cover_pred_cover": 1, "true_cover_pred_stego": 1, "true_stego_pred_cover": 1, "true_stego_pred_stego": 2}
    assert c["accuracy"] == 0.6 and abs(c["precision"] - 2 / 3) < 1e-12 and abs(c["recall"] - 2 / 3) < 1e-12
    assert E.classification([0, 0], [0.1, 0.2])["precision"] is None


def test_logistic_regression_learns_a_separable_problem_and_not_noise():
    rng = np.random.default_rng(2)
    X = rng.normal(size=(300, 6))
    y = (X[:, 0] + 0.5 * X[:, 3] > 0).astype(float)
    m = E.LogReg(l2=1.0).fit(X[:200], y[:200])
    assert E.auc(y[200:], m.score(X[200:])) > 0.97
    ynoise = rng.integers(0, 2, 300).astype(float)
    m = E.LogReg(l2=1.0).fit(X[:200], ynoise[:200])
    assert 0.3 < E.auc(ynoise[200:], m.score(X[200:])) < 0.7
    # constant feature columns do not break the standardisation
    Xc = np.hstack([X, np.ones((300, 1))])
    assert np.isfinite(E.LogReg().fit(Xc[:200], y[:200]).score(Xc[200:])).all()


def test_evaluation_is_chance_for_identical_classes_and_perfect_for_shifted_ones():
    rng = np.random.default_rng(3)
    n = 80
    Xc = rng.normal(size=(n, 5))
    seeds = np.array([f"s{i}" for i in range(n)])
    fams = np.array(["a", "b", "c", "d"] * (n // 4))
    same = E.evaluate(Xc, Xc + rng.normal(scale=1e-9, size=Xc.shape), seeds, fams, np.random.default_rng(4))
    assert 0.35 < same["auc"] < 0.65, "paired cover/stego with no difference must not be separable"
    shifted = E.evaluate(Xc, Xc + np.array([3.0, 0, 0, 0, 0]), seeds, fams, np.random.default_rng(4))
    assert shifted["auc"] > 0.95 and shifted["accuracy"] > 0.9
    assert set(shifted["leave_one_family_out"]) == {"a", "b", "c", "d"}
    assert shifted["auc_ci95"][0] <= shifted["auc"] <= shifted["auc_ci95"][1] + 1e-9
    assert shifted["n_pairs"] == n and "grouped" in shifted["split"]


def test_features_are_deterministic_named_and_react_to_lsb_embedding():
    from stego.generator import families
    arr, _ = families.generate(E.test_seed(0, "terrain"), 160, 120, "RGB", "terrain")
    f1, f2 = E.features(arr), E.features(arr.copy())
    assert f1.shape == (len(E.FEATURE_NAMES),) and np.array_equal(f1, f2) and np.isfinite(f1).all()
    assert len(set(E.FEATURE_NAMES)) == len(E.FEATURE_NAMES)
    assert abs(f1[:49].sum() - 1.0) < 1e-9, "co-occurrence block is a normalised histogram"
    flipped = arr.copy()
    flipped[::2] ^= 1
    assert not np.allclose(E.features(flipped), f1)
    assert E.features(arr[:, :, 0]).shape == f1.shape
    # test seeds are explicit, distinct per family/index and unrelated to OS randomness
    assert E.test_seed(0, "terrain") == E.test_seed(0, "terrain") != E.test_seed(1, "terrain") != E.test_seed(1, "cells")


def test_stego_builders_produce_real_extractable_embeddings():
    from stego import codec, config
    from stego.generator import families
    arr, _ = families.generate(E.test_seed(2, "clouds"), 320, 240, "RGB", "clouds")
    rng = np.random.default_rng(5)
    out, used = E.stego_mixed(arr, 300, rng, config.Limits())
    assert out.shape == arr.shape and not np.array_equal(out, arr) and sum(used.values()) >= 1
    frame, man, _pre, _per = codec.extract_frame(out, config.Limits())
    assert man.payload_len == 300 and frame[:4] == b"IOD2" and len(frame) > 16 + 300
    for name in ("lsb_matching", "dct", "wow"):
        s, n = E.stego_single(arr, name, 200, rng)
        assert s is not None and n == 200 and not np.array_equal(s, arr), name


def test_benchmark_helpers():
    h = B.host_metadata()
    assert {"system", "machine", "logical_cpus", "is_raspberry_pi_5", "python", "numpy"} <= set(h) and isinstance(h["is_raspberry_pi_5"], bool)
    s = B.stats([1.0, 2.0, 3.0])
    assert s["n"] == 3 and s["mean"] == 2.0 and s["p95"] is None, "no percentiles below 20 samples"
    s = B.stats(list(range(1, 101)))
    assert s["p50"] == 50.5 and s["p95"] == pytest.approx(95.05)
    assert B.stats([])["mean"] is None
    from stego.generator import profile
    r = B.one(200, profile.process_config({}))
    assert r["ok"] and r["candidates"] <= 2 and r["family"] in ("terrain", "clouds", "strata", "cells") and r["total"] > 0
    bad = B.one(50000, profile.process_config({}))
    assert not bad["ok"] and bad["code"] == "PATCH_CAPACITY_INSUFFICIENT"
