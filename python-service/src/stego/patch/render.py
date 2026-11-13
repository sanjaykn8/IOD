"""Inspection renderings of a segmentation (display only; never used for embedding or extraction)."""

import numpy as np

from .. import images
from . import segment as S


def palette(n):
    """Distinct, deterministic colours (golden-ratio hues)."""
    i = np.arange(n)
    h = (i * 0.61803398875) % 1.0
    s = np.where(i % 2 == 0, 0.85, 0.6)
    v = np.where(i % 3 == 0, 0.95, 0.8)
    k = (h * 6).astype(int) % 6
    f = h * 6 - np.floor(h * 6)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r = np.choose(k, [v, q, p, p, t, v]); g = np.choose(k, [t, v, v, q, p, p]); b = np.choose(k, [p, p, t, v, v, q])
    return (np.stack([r, g, b], axis=1) * 255).astype(np.uint8)


def overlay_png(arr, labels, n, reserved_rows=0):
    gray = S.luma_of(arr)
    base = np.repeat(gray[:, :, None], 3, axis=2)
    out = 0.5 * base + 0.5 * palette(n)[labels].astype(np.float64)
    edge = np.zeros(labels.shape, dtype=bool)
    edge[:, 1:] |= labels[:, 1:] != labels[:, :-1]
    edge[1:, :] |= labels[1:, :] != labels[:-1, :]
    out[edge] = (20, 20, 20)
    if reserved_rows:
        out[:reserved_rows] = 0.6 * out[:reserved_rows] + 0.4 * np.array([255.0, 255.0, 255.0])
    return images.encode_png(np.clip(out, 0, 255).astype(np.uint8))
