"""Per-patch feature vectors (computed on the COVER, over every pixel of the region).

All statistics use luma (0.299R + 0.587G + 0.114B, or the gray value). Definitions:
  pixels            exact pixel count of the region (full region, carrier pixels included)
  usable_pixels     pixels minus the reserved bootstrap-v3 carrier pixels (what algorithms may use)
  bbox              [row0, col0, row1, col1) ; width/height/aspect from it
  compactness       4*pi*area / perimeter^2 (perimeter = pixel edges to other regions or the border)
  mean, variance    of luma ; mean_rgb for colour covers
  entropy           Shannon entropy (bits) of the 256-bin luma histogram
  gradient_mean/std |dx| + |dy| forward differences of luma
  edge_density      fraction of pixels with gradient >= 24
  texture           mean |4-neighbour Laplacian| of luma
  smoothness        1 / (1 + variance)
  hf_energy_ratio   over complete 8x8 blocks inside the region: energy of DCT coefficients with
                    u+v >= 4 divided by all AC energy (0 when the region holds no complete block)
  saturation        fraction of pixels with luma <= 2 or >= 253
"""

import numpy as np

from ..algorithms.dct import _C, _CT
from .segment import gradient_of, luma_of

EDGE_T = 24.0
_HF = (np.add.outer(np.arange(8), np.arange(8)) >= 4)
_AC = np.ones((8, 8), dtype=bool)
_AC[0, 0] = False


def _r(x, d=6):
    return round(float(x), d)


def compute(arr, labels, n, excluded=None):
    """Return a list of feature dicts, one per region id 0..n-1. `excluded`: flat pixel indices
    (the reserved carrier pixels) that no algorithm may use."""
    h, w = labels.shape
    lab = labels.reshape(-1).astype(np.int64)
    luma = luma_of(arr)
    lf = luma.reshape(-1)
    cnt = np.bincount(lab, minlength=n).astype(np.float64)
    s1 = np.bincount(lab, weights=lf, minlength=n)
    s2 = np.bincount(lab, weights=lf * lf, minlength=n)
    mean = s1 / cnt
    var = np.maximum(s2 / cnt - mean * mean, 0.0)
    grad = gradient_of(luma).reshape(-1)
    g1 = np.bincount(lab, weights=grad, minlength=n) / cnt
    g2 = np.bincount(lab, weights=grad * grad, minlength=n) / cnt
    edge = np.bincount(lab, weights=(grad >= EDGE_T).astype(np.float64), minlength=n) / cnt
    lp = np.pad(luma, 1, mode="edge")
    lap = np.abs(4 * luma - lp[:-2, 1:-1] - lp[2:, 1:-1] - lp[1:-1, :-2] - lp[1:-1, 2:]).reshape(-1)
    tex = np.bincount(lab, weights=lap, minlength=n) / cnt
    sat = np.bincount(lab, weights=((lf <= 2) | (lf >= 253)).astype(np.float64), minlength=n) / cnt
    hist = np.bincount(lab * 256 + np.clip(np.rint(lf), 0, 255).astype(np.int64), minlength=n * 256).reshape(n, 256)
    p = hist / cnt[:, None]
    with np.errstate(divide="ignore", invalid="ignore"):
        ent = -np.where(p > 0, p * np.log2(p), 0.0).sum(axis=1)
    # perimeter: pixel edges between different labels + image border edges
    per = np.zeros(n)
    dh = labels[:, 1:] != labels[:, :-1]
    dv = labels[1:, :] != labels[:-1, :]
    for a, b, d in ((labels[:, 1:], labels[:, :-1], dh), (labels[1:, :], labels[:-1, :], dv)):
        per += np.bincount(a[d].astype(np.int64), minlength=n) + np.bincount(b[d].astype(np.int64), minlength=n)
    for edge_line in (labels[0, :], labels[-1, :], labels[:, 0], labels[:, -1]):
        per += np.bincount(edge_line.astype(np.int64), minlength=n)
    # bbox via row/col presence
    rows_idx = np.repeat(np.arange(h), w)
    cols_idx = np.tile(np.arange(w), h)
    r0 = np.full(n, h); r1 = np.zeros(n, dtype=np.int64); c0 = np.full(n, w); c1 = np.zeros(n, dtype=np.int64)
    np.minimum.at(r0, lab, rows_idx); np.maximum.at(r1, lab, rows_idx)
    np.minimum.at(c0, lab, cols_idx); np.maximum.at(c1, lab, cols_idx)
    usable = np.bincount(lab, minlength=n)
    if excluded is not None and len(excluded):
        usable = usable - np.bincount(lab[np.asarray(excluded, dtype=np.int64)], minlength=n)
    # frequency energy over complete 8x8 blocks inside one region
    hb, wb = h // 8, w // 8
    hf_ratio = np.zeros(n)
    ac_mean = np.zeros(n)
    if hb and wb:
        lb = labels[:hb * 8, :wb * 8].reshape(hb, 8, wb, 8)
        whole = (lb.min(axis=(1, 3)) == lb.max(axis=(1, 3))).reshape(-1)
        bl = lb[:, 0, :, 0].reshape(-1).astype(np.int64)
        blocks = luma[:hb * 8, :wb * 8].reshape(hb, 8, wb, 8).transpose(0, 2, 1, 3).reshape(-1, 8, 8)
        x = _C @ blocks @ _CT
        e = x * x
        ac = (e * _AC).sum(axis=(1, 2))
        hf = (e * _HF).sum(axis=(1, 2))
        nb = np.bincount(bl[whole], minlength=n).astype(np.float64)
        sac = np.bincount(bl[whole], weights=ac[whole], minlength=n)
        shf = np.bincount(bl[whole], weights=hf[whole], minlength=n)
        with np.errstate(divide="ignore", invalid="ignore"):
            hf_ratio = np.where(sac > 0, shf / sac, 0.0)
            ac_mean = np.where(nb > 0, sac / nb, 0.0)
    rgb = None
    if arr.ndim == 3:
        rgb = [np.bincount(lab, weights=arr[..., c].reshape(-1).astype(np.float64), minlength=n) / cnt for c in range(3)]
    out = []
    for i in range(n):
        bw, bh = int(c1[i] - c0[i] + 1), int(r1[i] - r0[i] + 1)
        f = {
            "patch_id": i, "pixels": int(cnt[i]), "usable_pixels": int(usable[i]),
            "bbox": [int(r0[i]), int(c0[i]), int(r1[i]) + 1, int(c1[i]) + 1], "width": bw, "height": bh,
            "aspect_ratio": _r(max(bw, bh) / max(1, min(bw, bh)), 4),
            "compactness": _r(min(1.0, 4 * np.pi * cnt[i] / max(per[i] ** 2, 1.0)), 6),
            "perimeter": int(per[i]), "centroid": None,
            "mean": _r(mean[i], 4), "variance": _r(var[i], 4), "entropy": _r(ent[i], 4),
            "gradient_mean": _r(g1[i], 4), "gradient_std": _r(np.sqrt(max(g2[i] - g1[i] ** 2, 0.0)), 4),
            "edge_density": _r(edge[i]), "texture": _r(tex[i], 4), "smoothness": _r(1.0 / (1.0 + var[i]), 8),
            "hf_energy_ratio": _r(hf_ratio[i]), "ac_energy_mean": _r(ac_mean[i], 3), "saturation": _r(sat[i]),
        }
        if rgb is not None:
            f["mean_rgb"] = [_r(rgb[c][i], 3) for c in range(3)]
        out.append(f)
    cy = np.bincount(lab, weights=rows_idx.astype(np.float64), minlength=n) / cnt
    cx = np.bincount(lab, weights=cols_idx.astype(np.float64), minlength=n) / cnt
    for i in range(n):
        out[i]["centroid"] = [_r(cy[i], 2), _r(cx[i], 2)]
    return out
