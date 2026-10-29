import math

import numpy as np
import pytest

from stego import metrics
from stego_helpers import natural_cover


def brute_ssim(a, b):
    a = a.astype(np.float64)
    b = b.astype(np.float64)
    if a.ndim == 2:
        a, b = a[..., None], b[..., None]
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    vals = []
    for ch in range(a.shape[2]):
        for i in range(a.shape[0] - 6):
            for j in range(a.shape[1] - 6):
                x, y = a[i:i + 7, j:j + 7, ch], b[i:i + 7, j:j + 7, ch]
                mx, my = x.mean(), y.mean()
                vx, vy = x.var(), y.var()
                cxy = ((x - mx) * (y - my)).mean()
                vals.append(((2 * mx * my + c1) * (2 * cxy + c2)) / ((mx ** 2 + my ** 2 + c1) * (vx + vy + c2)))
    return float(np.mean(vals))


def test_mse_psnr_known():
    a = np.full((32, 32), 100, np.uint8)
    b = a + 2
    assert metrics.mse(a, b) == 4.0
    assert metrics.psnr(4.0) == pytest.approx(10 * math.log10(255 ** 2 / 4))
    c = a.copy()
    c[0, 0] = 110  # one sample off by 10
    assert metrics.mse(a, c) == pytest.approx(100 / 1024)


def test_identical_images():
    a = natural_cover(40, 40, 3)
    m = metrics.compute(a, a.copy())
    assert m["mse"] == 0 and m["psnr"] is None and m["psnr_defined"] is False
    assert m["ssim"] == 1.0 and m["ssim_defined"] is True
    assert m["changed_samples"] == 0 and m["changed_fraction"] == 0 and m["max_abs_diff"] == 0
    assert metrics.psnr(0.0) is None


def test_constant_image_ssim_closed_form():
    a = np.full((20, 20), 50, np.uint8)
    b = np.full((20, 20), 80, np.uint8)
    c1 = (0.01 * 255) ** 2
    expected = (2 * 50 * 80 + c1) / (50 ** 2 + 80 ** 2 + c1)
    assert metrics.ssim(a, b) == pytest.approx(expected, rel=1e-12)


@pytest.mark.parametrize("shape", [(12, 15), (10, 10, 3)])
def test_ssim_matches_bruteforce(shape):
    rng = np.random.default_rng(2)
    a = rng.integers(0, 256, shape, dtype=np.uint8)
    b = np.clip(a.astype(int) + rng.integers(-20, 21, shape), 0, 255).astype(np.uint8)
    assert metrics.ssim(a, b) == pytest.approx(brute_ssim(a, b), abs=1e-9)


def test_ssim_none_when_smaller_than_window():
    a = np.zeros((6, 40), np.uint8)
    assert metrics.ssim(a, a) is None
    m = metrics.compute(a, a + 1)
    assert m["ssim"] is None and m["ssim_defined"] is False
    assert metrics.ssim(np.zeros((7, 7), np.uint8), np.zeros((7, 7), np.uint8)) == 1.0


def test_changed_counts_and_bounds():
    a = natural_cover(48, 48, 3)
    b = a.copy()
    b.reshape(-1)[:100] ^= 1
    m = metrics.compute(a, b)
    assert m["changed_samples"] == 100
    assert m["changed_fraction"] == pytest.approx(100 / a.size, rel=1e-6)
    assert m["max_abs_diff"] == 1
    assert 0 < m["mse"] < 1 and m["psnr"] > 50 and 0.99 < m["ssim"] <= 1.0


def test_sanity_ordering_more_noise_is_worse():
    a = natural_cover(64, 64, 3)
    rng = np.random.default_rng(5)
    prev = None
    for amp in (1, 4, 16, 48):
        b = np.clip(a.astype(int) + rng.integers(-amp, amp + 1, a.shape), 0, 255).astype(np.uint8)
        m = metrics.compute(a, b)
        assert 0 <= m["ssim"] <= 1
        if prev:
            assert m["mse"] > prev["mse"] and m["psnr"] < prev["psnr"] and m["ssim"] < prev["ssim"]
        prev = m


def test_extremes_and_determinism():
    z = np.zeros((32, 32), np.uint8)
    f = np.full((32, 32), 255, np.uint8)
    m = metrics.compute(z, f)
    assert m["mse"] == 65025.0 and m["psnr"] == 0.0 and m["max_abs_diff"] == 255
    assert -1 <= m["ssim"] < 0.01
    a = natural_cover(40, 40, 3)
    b = a ^ 3
    assert metrics.compute(a, b) == metrics.compute(a, b)


def test_shape_mismatch_rejected():
    with pytest.raises(ValueError):
        metrics.ssim(np.zeros((10, 10), np.uint8), np.zeros((10, 11), np.uint8))
