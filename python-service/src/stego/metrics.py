"""Distortion metrics (numpy only). SSIM: uniform 7x7 window, population
variance, K1=.01 K2=.03 L=255, mean over all windows and channels."""

import numpy as np

WIN = 7
_C1 = (0.01 * 255) ** 2
_C2 = (0.03 * 255) ** 2


def mse(a, b):
    d = a.astype(np.float64) - b.astype(np.float64)
    return float(np.mean(d * d))


def psnr(m):
    """Returns None for identical images (infinite PSNR)."""
    if m == 0:
        return None
    return float(10.0 * np.log10(255.0 ** 2 / m))


def _wsum(x):
    s = np.zeros((x.shape[0] + 1, x.shape[1] + 1) + x.shape[2:], dtype=np.int64)
    s[1:, 1:] = x.cumsum(axis=0).cumsum(axis=1)
    return s[WIN:, WIN:] - s[:-WIN, WIN:] - s[WIN:, :-WIN] + s[:-WIN, :-WIN]


def ssim(a, b):
    """Mean SSIM, or None if the image is smaller than the window."""
    if a.shape != b.shape:
        raise ValueError("shape mismatch")
    if a.shape[0] < WIN or a.shape[1] < WIN:
        return None
    x = a.astype(np.int64)
    y = b.astype(np.int64)
    n = WIN * WIN
    sx, sy = _wsum(x), _wsum(y)
    sxx, syy, sxy = _wsum(x * x), _wsum(y * y), _wsum(x * y)  # exact integer sums
    mx, my = sx / n, sy / n
    vx = (n * sxx - sx * sx) / (n * n)
    vy = (n * syy - sy * sy) / (n * n)
    cxy = (n * sxy - sx * sy) / (n * n)
    num = (2 * mx * my + _C1) * (2 * cxy + _C2)
    den = (mx * mx + my * my + _C1) * (vx + vy + _C2)
    return float(np.mean(num / den))


def compute(cover, stego):
    m = mse(cover, stego)
    p = psnr(m)
    s = ssim(cover, stego)
    diff = cover.astype(np.int16) != stego.astype(np.int16)
    changed = int(diff.sum())
    return {
        "mse": round(m, 6),
        "psnr": None if p is None else round(p, 4),
        "psnr_defined": p is not None,
        "ssim": None if s is None else round(s, 10),
        "ssim_defined": s is not None,
        "changed_samples": changed,
        "changed_fraction": round(changed / cover.size, 8),
        "max_abs_diff": int(np.abs(cover.astype(np.int16) - stego.astype(np.int16)).max()) if cover.size else 0,
    }
