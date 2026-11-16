"""Visual-coherence heuristics: pathological images are rejected, generated covers pass, gray and RGB work."""
import numpy as np
import pytest

from stego.generator import QUALITY_VERSION, families as F, quality as Q
from stego.procedural import decode_latent, encode_text

H, W = 240, 320
RNG = np.random.default_rng(0)
YY, XX = np.mgrid[0:H, 0:W]


def rgb(g):
    return np.repeat(np.asarray(g)[..., None], 3, axis=2).astype(np.uint8)


PATHOLOGICAL = {
    "flat": (lambda: np.full((H, W, 3), 128, np.uint8), {"flat_block_fraction", "rms_contrast"}),
    "saturated": (lambda: np.full((H, W, 3), 255, np.uint8), {"clipped_fraction"}),
    "black": (lambda: np.zeros((H, W, 3), np.uint8), {"clipped_fraction"}),
    "white_noise": (lambda: RNG.integers(0, 256, (H, W, 3), dtype=np.uint8), {"adjacent_correlation", "spectral_slope"}),
    "gaussian_noise_on_gray": (lambda: np.clip(128 + RNG.normal(0, 30, (H, W, 3)), 0, 255).astype(np.uint8), {"adjacent_correlation", "spectral_slope"}),
    "harsh_stripes": (lambda: rgb(np.sin(XX / 3.0) * 100 + 128), {"periodic_peak_ratio", "tile_similarity"}),
    "soft_stripes": (lambda: np.clip(rgb(np.sin(XX / 9.0) * 40 + 128) + RNG.normal(0, 2, (H, W, 3)), 0, 255).astype(np.uint8), {"tile_similarity"}),
    "checkerboard": (lambda: rgb(((XX // 8 + YY // 8) % 2) * 160 + 40), {"periodic_peak_ratio"}),
    "repeated_tile_5x5": (lambda: np.tile(F.generate(b"a" * 16, 64, 48, family="terrain")[0], (5, 5, 1)), {"periodic_peak_ratio", "tile_similarity"}),
    "repeated_tile_2x2": (lambda: np.tile(F.generate(b"b" * 16, 160, 120, family="clouds")[0], (2, 2, 1)), {"periodic_peak_ratio"}),
    "legacy_black_white_pattern": (lambda: rgb(np.array(decode_latent(encode_text("s"), W).convert("L"))[:H]), {"distinct_levels", "clipped_fraction"}),
    "smooth_ramp_no_detail": (lambda: rgb(XX / W * 200 + 20), {"highpass_std"}),
    "posterised": (lambda: rgb((F.generate(b"c" * 16, W, H, "L", "clouds")[0] // 64) * 64 + 20), {"distinct_levels"}),
}


@pytest.mark.parametrize("name", list(PATHOLOGICAL))
def test_pathological_images_are_rejected_for_the_expected_reason(name):
    make, expect = PATHOLOGICAL[name]
    r = Q.evaluate(make(), min_score=0.70)
    assert r["passed"] is False, name
    failed = {g["metric"] for g in r["gates"] if not g["passed"]}
    assert failed & expect, f"{name}: failed gates {failed}, expected one of {expect}"
    assert r["rejection_reasons"]


@pytest.mark.parametrize("family", F.FAMILIES)
@pytest.mark.parametrize("mode", F.MODES)
def test_generated_covers_pass_the_gates_and_score_well(family, mode):
    scores = []
    for i in range(6):
        arr, _ = F.generate(bytes([40 + i]) * 16, W, H, mode, family)
        r = Q.evaluate(arr, min_score=0.70)
        assert r["passed"], (family, mode, i, r["rejection_reasons"])
        assert all(g["passed"] for g in r["gates"])
        scores.append(r["score"])
    assert min(scores) >= 0.70 and len(set(scores)) > 1
    # a generated cover always outscores white noise and a flat field
    assert min(scores) > Q.evaluate(PATHOLOGICAL["white_noise"][0]())["score"] + 0.3
    assert min(scores) > Q.evaluate(PATHOLOGICAL["flat"][0]())["score"] + 0.3


def test_high_entropy_is_not_treated_as_quality():
    noise = Q.evaluate(PATHOLOGICAL["white_noise"][0]())
    cover = Q.evaluate(F.generate(b"q" * 16, W, H)[0])
    assert noise["metrics"]["local_entropy_mean"] > cover["metrics"]["local_entropy_mean"]
    assert noise["score"] < 0.5 < cover["score"]


def test_metrics_on_known_inputs():
    flat = Q.measure(np.full((64, 64), 100, np.uint8))
    assert flat["rms_contrast"] == 0 and flat["flat_block_fraction"] == 1.0 and flat["distinct_levels"] == 1
    assert flat["clipped_fraction"] == 0.0 and "colorfulness" not in flat
    sat = Q.measure(np.full((64, 64, 3), 254, np.uint8))
    assert sat["clipped_fraction"] == 1.0
    noise = Q.measure(RNG.integers(0, 256, (128, 128), dtype=np.uint8))
    assert abs(noise["adjacent_correlation"]) < 0.05 and abs(noise["spectral_slope"]) < 0.4
    smooth = Q.measure(F.generate(b"m" * 16, 160, 120, "L", "clouds")[0])
    assert smooth["adjacent_correlation"] > 0.95 and smooth["spectral_slope"] < -2.0
    # multi-scale correlation decreases with distance on a coherent image
    assert smooth["adjacent_correlation"] >= smooth["lag2_correlation"] >= smooth["lag4_correlation"] >= smooth["lag8_correlation"]
    col = Q.measure(F.generate(b"m" * 16, 160, 120, "RGB", "clouds")[0])
    assert col["colorfulness"] > 0 and -1 <= col["channel_correlation"] <= 1 and len(col["channel_means"]) == 3
    gray_as_rgb = Q.measure(rgb(F.generate(b"m" * 16, 160, 120, "L", "clouds")[0]))
    assert gray_as_rgb["colorfulness"] == pytest.approx(0, abs=1e-6) and gray_as_rgb["channel_correlation"] > 0.999


def test_tile_similarity_and_periodicity_are_specific():
    cover = F.generate(b"t" * 16, W, H, "L", "strata")[0]
    tiled = np.tile(F.generate(b"t" * 16, 80, 60, "L", "strata")[0], (4, 4))
    a, b = Q.measure(cover), Q.measure(tiled)
    assert b["tile_similarity"] > 2 * a["tile_similarity"] and b["periodic_peak_ratio"] > 20 * a["periodic_peak_ratio"]


def test_evaluate_is_deterministic_serialisable_and_labelled():
    import json
    arr = F.generate(b"z" * 16, W, H)[0]
    a, b = Q.evaluate(arr, 0.7), Q.evaluate(arr.copy(), 0.7)
    a.pop("prescreen_ms"), b.pop("prescreen_ms")
    assert a == b and a["quality_version"] == QUALITY_VERSION == "cover-quality-1"
    assert "not a steganalysis detector" in a["note"]
    json.dumps(a)
    assert 0.0 <= a["score"] <= 1.0 and set(a["components"]) <= set(Q.PREFERENCES)
    # the score threshold is itself a gate
    hard = Q.evaluate(arr, min_score=0.999)
    assert hard["passed"] is False and hard["rejection_reasons"] == ["score_below_0.999"]


def test_weights_and_gates_are_configurable():
    arr = F.generate(b"z" * 16, W, H)[0]
    base = Q.evaluate(arr)
    only = Q.evaluate(arr, weights={"rms_contrast": 1.0})
    assert only["score"] == base["components"]["rms_contrast"]
    strict = Q.evaluate(arr, gates=(("rms_contrast", "min", 200.0),))
    assert strict["passed"] is False and strict["rejection_reasons"] == ["rms_contrast_below_200.0"]


def test_large_images_are_analysed_on_a_bounded_crop():
    arr = F.generate(b"L" * 16, 800, 600)[0]
    r = Q.evaluate(arr, 0.7)
    assert r["passed"] and r["prescreen_ms"] < 2000
