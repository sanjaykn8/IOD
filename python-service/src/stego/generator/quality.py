"""Visual-coherence heuristics for generated covers ("cover-quality-1").

These are transparent, documented HEURISTICS: they describe whether an image has the multi-scale,
spatially correlated structure of a plausible picture and they reject pathological images (flat,
clipped, white noise, stripes, tiles). They are NOT a steganalysis detector and a high score is
not evidence that embedding in the image is hard to detect.

`measure(arr)` -> metrics, `evaluate(arr, min_score)` -> {score, components, gates, passed, ...}.
All thresholds are local choices of this project, calibrated on the generator's own output and on
the pathological fixtures in tests/test_generator_quality.py.
"""

import time

import numpy as np

from . import QUALITY_VERSION

# ---- hard gates: (metric, kind, limit). A candidate failing any gate is rejected before planning.
GATES = (
    ("clipped_fraction", "max", 0.02),        # samples <= 2 or >= 253
    ("flat_block_fraction", "max", 0.25),     # 8x8 luma blocks with std < 0.35
    ("rms_contrast", "min", 9.0),             # global luma standard deviation
    ("adjacent_correlation", "min", 0.80),    # mean of horizontal/vertical lag-1 luma correlation
    ("lag8_correlation", "min", 0.35),        # multi-scale coherence: correlation survives 8 px
    ("spectral_slope", "max", -1.6),          # log-log radial power slope; white noise is ~0
    ("periodic_peak_ratio", "max", 1500.0),     # strongest spectral line over its ring median
    ("tile_similarity", "max", 0.55),         # strongest off-origin autocorrelation peak
    ("edge_density", "max", 0.40),            # fraction of pixels with gradient >= 24
    ("highpass_std", "max", 9.0),             # residual after a 3x3 mean: grain / noise level
    ("highpass_std", "min", 0.35),            # no fine detail at all -> banded bit planes
    ("distinct_levels", "min", 48),           # luma levels in use (rejects binary / posterised)
)

# ---- soft score: weighted mean of trapezoid preferences (lo0, lo1, hi1, hi0) -> [0, 1]
PREFERENCES = {
    "adjacent_correlation": (0.80, 0.93, 0.999, 1.0),
    "lag8_correlation": (0.35, 0.60, 0.97, 1.0),
    "correlation_decay": (0.0, 0.03, 0.45, 0.8),          # corr(lag 1) - corr(lag 16): structure at several scales
    "spectral_slope": (-5.0, -3.6, -2.2, -1.6),
    "rms_contrast": (9.0, 22.0, 62.0, 85.0),
    "local_std_median": (0.5, 1.6, 9.0, 18.0),
    "local_std_spread": (0.05, 0.35, 2.5, 6.0),           # IQR / median of block std: varied regions
    "local_entropy_mean": (1.0, 2.2, 4.3, 4.9),           # 16x16 blocks, 32 bins (max 5 bits)
    "local_entropy_spread": (0.02, 0.15, 1.2, 2.5),
    "gradient_mean": (0.6, 1.8, 9.0, 20.0),
    "edge_density": (0.0, 0.004, 0.12, 0.40),
    "highpass_std": (0.35, 0.8, 3.5, 9.0),
    "periodic_peak_ratio": (0.0, 0.0, 150.0, 1500.0),
    "tile_similarity": (0.0, 0.0, 0.25, 0.55),
    "clipped_fraction": (0.0, 0.0, 0.002, 0.02),
    "flat_block_fraction": (0.0, 0.0, 0.03, 0.25),
    "colorfulness": (2.0, 10.0, 70.0, 110.0),             # RGB only (Hasler-Suesstrunk)
    "channel_correlation": (0.05, 0.35, 0.985, 1.0),      # RGB only: correlated but not identical channels
    "histogram_fill": (0.15, 0.35, 1.0, 1.0),             # fraction of the 0..255 luma range in use
}
WEIGHTS = {
    "adjacent_correlation": 1.5, "lag8_correlation": 1.5, "correlation_decay": 1.0, "spectral_slope": 1.5,
    "rms_contrast": 1.0, "local_std_median": 1.0, "local_std_spread": 1.0, "local_entropy_mean": 0.75,
    "local_entropy_spread": 0.75, "gradient_mean": 0.75, "edge_density": 0.75, "highpass_std": 1.0,
    "periodic_peak_ratio": 1.0, "tile_similarity": 1.0, "clipped_fraction": 0.75, "flat_block_fraction": 0.75,
    "colorfulness": 0.5, "channel_correlation": 0.5, "histogram_fill": 0.5,
}
MAX_ANALYSIS_PIXELS = 640 * 480      # larger images are analysed on a centre crop of this many pixels at most


def luma(arr):
    if arr.ndim == 2:
        return arr.astype(np.float32)
    return arr.astype(np.float32) @ np.array([0.299, 0.587, 0.114], dtype=np.float32)


def _corr(a, b):
    a = a - a.mean()
    b = b - b.mean()
    d = float(np.sqrt((a * a).sum() * (b * b).sum()))
    return float((a * b).sum() / d) if d > 1e-9 else 0.0


def _lag_corr(y, lag):
    if y.shape[0] <= lag + 1 or y.shape[1] <= lag + 1:
        return 0.0
    return 0.5 * (_corr(y[:, :-lag], y[:, lag:]) + _corr(y[:-lag, :], y[lag:, :]))


def _blocks(y, b):
    h, w = (y.shape[0] // b) * b, (y.shape[1] // b) * b
    return y[:h, :w].reshape(h // b, b, w // b, b).transpose(0, 2, 1, 3).reshape(-1, b * b)


def _spectrum(y):
    """Radial power statistics of the mean-removed, Hann-windowed luma."""
    h, w = y.shape
    win = np.hanning(h)[:, None] * np.hanning(w)[None, :]
    f = np.fft.rfft2((y - y.mean()) * win)
    p = (f.real ** 2 + f.imag ** 2).astype(np.float64)
    fy = np.fft.fftfreq(h)[:, None] * h
    fx = np.fft.rfftfreq(w)[None, :] * w
    # normalised radius so that non-square images do not bias the rings
    r = np.sqrt((fy / (h / 2.0)) ** 2 + (fx / (w / 2.0)) ** 2)
    nb = 48
    idx = np.minimum((r * nb).astype(np.int32), nb * 2)
    keep = (idx >= 1) & (idx < nb)
    ring = idx[keep]
    pw = p[keep]
    sums = np.bincount(ring, weights=pw, minlength=nb)
    cnt = np.bincount(ring, minlength=nb)
    ok = cnt > 0
    mean = np.where(ok, sums / np.maximum(cnt, 1), 0.0)
    rr = np.arange(nb)[ok & (mean > 0)]
    slope = float(np.polyfit(np.log(rr[rr >= 2]), np.log(mean[rr[rr >= 2]]), 1)[0]) if (rr >= 2).sum() >= 6 else 0.0
    # strongest isolated line: power over the median of its ring (ignore the lowest rings: broad structure)
    order = np.argsort(ring, kind="stable")
    ring_s, pw_s = ring[order], pw[order]
    starts = np.searchsorted(ring_s, np.arange(nb))
    ends = np.searchsorted(ring_s, np.arange(nb), side="right")
    peak = 0.0
    for k in range(4, nb):
        seg = pw_s[starts[k]:ends[k]]
        if seg.size >= 8:
            med = float(np.median(seg))
            if med > 0:
                peak = max(peak, float(seg.max()) / med)
    return slope, peak, p, (h, w)


def _box(y, k):
    """Mean over a (2k+1)^2 window with edge replication (integral image)."""
    p = np.pad(y.astype(np.float64), k, mode="edge")
    c = np.zeros((p.shape[0] + 1, p.shape[1] + 1))
    c[1:, 1:] = p.cumsum(0).cumsum(1)
    n = 2 * k + 1
    return (c[n:, n:] - c[:-n, n:] - c[n:, :-n] + c[:-n, :-n]) / (n * n)


def _tile_similarity(y):
    """Largest normalised autocorrelation of the DETAIL band away from the origin.

    Broad structure is removed first (local mean over ~1/8 of the image) and the result is windowed, so a
    smooth non-repeating picture scores near 0 while a repeated tile or a regular stripe pattern scores high."""
    h, w = y.shape
    k = max(2, min(h, w) // 16)
    z = (y - _box(y, k)) * (np.hanning(h)[:, None] * np.hanning(w)[None, :])
    f = np.fft.rfft2(z, s=(2 * h, 2 * w))                 # zero padding: linear, not circular, correlation
    ac = np.fft.irfft2(f.real ** 2 + f.imag ** 2, s=(2 * h, 2 * w))
    if ac[0, 0] <= 1e-9:
        return 1.0
    ac = ac / ac[0, 0]
    m = 2 * k                                              # ignore the main lobe around zero lag
    ac[:m, :m] = 0
    ac[:m, -m + 1:] = 0
    ac[-m + 1:, :m] = 0
    ac[-m + 1:, -m + 1:] = 0
    return float(max(0.0, ac.max()))


def measure(arr):
    """All component metrics of one image (uint8, (H,W) or (H,W,3))."""
    if arr.ndim == 3 and arr.shape[0] * arr.shape[1] > MAX_ANALYSIS_PIXELS:
        h, w = arr.shape[:2]
        s = (MAX_ANALYSIS_PIXELS / (h * w)) ** 0.5
        ch, cw = int(h * s) // 8 * 8, int(w * s) // 8 * 8
        y0, x0 = (h - ch) // 2, (w - cw) // 2
        arr = arr[y0:y0 + ch, x0:x0 + cw]
    y = luma(arr)
    h, w = y.shape
    m = {}
    m["clipped_fraction"] = float(np.mean((arr <= 2) | (arr >= 253)))
    b8 = _blocks(y, 8)
    std8 = b8.std(axis=1)
    m["flat_block_fraction"] = float(np.mean(std8 < 0.35))
    m["rms_contrast"] = float(y.std())
    med = float(np.median(std8))
    q1, q3 = np.percentile(std8, [25, 75])
    m["local_std_median"] = med
    m["local_std_spread"] = float((q3 - q1) / med) if med > 1e-6 else 0.0
    c1, c2, c4, c8, c16 = (_lag_corr(y, k) for k in (1, 2, 4, 8, 16))
    m["adjacent_correlation"] = c1
    m["lag2_correlation"], m["lag4_correlation"] = c2, c4
    m["lag8_correlation"], m["lag16_correlation"] = c8, c16
    m["correlation_decay"] = c1 - c16
    # local entropy: 16x16 blocks, 32 grey bins
    b16 = (_blocks(y, 16) / 8.0).astype(np.int32).clip(0, 31)
    n = b16.shape[0]
    hist = np.zeros((n, 32), dtype=np.float64)
    np.add.at(hist, (np.repeat(np.arange(n), b16.shape[1]), b16.ravel()), 1.0)
    pr = hist / b16.shape[1]
    ent = -(np.where(pr > 0, pr * np.log2(np.where(pr > 0, pr, 1.0)), 0.0)).sum(axis=1)
    m["local_entropy_mean"] = float(ent.mean())
    m["local_entropy_spread"] = float(ent.std())
    gy, gx = np.gradient(y)
    g = np.sqrt(gy * gy + gx * gx)
    m["gradient_mean"] = float(g.mean())
    m["edge_density"] = float(np.mean(g >= 24.0))
    p = np.pad(y, 1, mode="edge")
    box = (p[:-2, :-2] + p[:-2, 1:-1] + p[:-2, 2:] + p[1:-1, :-2] + p[1:-1, 1:-1] + p[1:-1, 2:]
           + p[2:, :-2] + p[2:, 1:-1] + p[2:, 2:]) / 9.0
    m["highpass_std"] = float((y - box).std())
    slope, peak, _p, _ = _spectrum(y)
    m["spectral_slope"] = slope
    m["periodic_peak_ratio"] = peak
    m["tile_similarity"] = _tile_similarity(y)
    yi = np.rint(y).astype(np.int32).clip(0, 255)
    levels = np.bincount(yi.ravel(), minlength=256)
    m["distinct_levels"] = int(np.count_nonzero(levels))
    lo, hi = np.percentile(y, [1, 99])
    m["histogram_fill"] = float((hi - lo) / 255.0)
    if arr.ndim == 3:
        r, gch, bch = (arr[..., i].astype(np.float32) for i in range(3))
        rg, yb = r - gch, 0.5 * (r + gch) - bch
        m["colorfulness"] = float(np.sqrt(rg.var() + yb.var()) + 0.3 * np.sqrt(rg.mean() ** 2 + yb.mean() ** 2))
        m["channel_correlation"] = float(min(_corr(r, gch), _corr(r, bch), _corr(gch, bch)))
        m["channel_means"] = [round(float(c.mean()), 2) for c in (r, gch, bch)]
    return m


def _pref(v, t):
    lo0, lo1, hi1, hi0 = t
    if v <= lo0 or v >= hi0:
        # the outer bounds themselves are acceptable only where the trapezoid is flat at that end
        if v <= lo0:
            return 1.0 if lo0 == lo1 and v == lo0 else 0.0
        return 1.0 if hi0 == hi1 and v == hi0 else 0.0
    if v < lo1:
        return (v - lo0) / (lo1 - lo0)
    if v > hi1:
        return (hi0 - v) / (hi0 - hi1)
    return 1.0


def evaluate(arr, min_score=0.0, weights=None, gates=None):
    """Score one image. Returns a JSON-serialisable dict; `passed` = all gates passed and score >= min_score."""
    t0 = time.perf_counter()
    weights = WEIGHTS if weights is None else weights
    gates = GATES if gates is None else gates
    m = measure(arr)
    comps, num, den = {}, 0.0, 0.0
    for name, trap in PREFERENCES.items():
        if name not in m:
            continue                      # colour components do not exist for grayscale
        s = _pref(float(m[name]), trap)
        comps[name] = round(s, 4)
        wgt = float(weights.get(name, 0.0))
        num += s * wgt
        den += wgt
    score = num / den if den > 0 else 0.0
    gate_rows, failed = [], []
    for name, kind, limit in gates:
        v = float(m[name])
        ok = v <= limit if kind == "max" else v >= limit
        gate_rows.append({"metric": name, "kind": kind, "limit": limit, "value": round(v, 6), "passed": bool(ok)})
        if not ok:
            failed.append(f"{name}_{'above' if kind == 'max' else 'below'}_{limit}")
    if score < min_score:
        failed.append(f"score_below_{min_score}")
    return {
        "quality_version": QUALITY_VERSION, "score": round(score, 4), "min_score": min_score,
        "passed": not failed, "rejection_reasons": failed, "gates": gate_rows, "components": comps,
        "metrics": {k: (round(v, 6) if isinstance(v, float) else v) for k, v in m.items()},
        "prescreen_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "note": "heuristic visual-coherence proxy; not a steganalysis detector",
    }
