"""Shared helpers for block-transform algorithms (DCT, DWT, DCT-SVD).

Transform methods modify one plane (the grayscale image, or the blue plane of RGB) in
non-overlapping b x b blocks of the GLOBAL b-grid. Only blocks lying entirely inside the
patch mask are used (Region.blocks), in raster order; partial blocks are never touched.
"""

import numpy as np

PLANE_INDEX_RGB = 2


def plane(img):
    return img if img.ndim == 2 else img[:, :, PLANE_INDEX_RGB]


def gather(pl, block, br, bc):
    """Return float64 blocks (count, block, block)."""
    r = br[:, None, None] * block + np.arange(block)[None, :, None]
    c = bc[:, None, None] * block + np.arange(block)[None, None, :]
    return pl[r, c].astype(np.float64)


def scatter(pl, block, br, bc, blocks):
    r = br[:, None, None] * block + np.arange(block)[None, :, None]
    c = bc[:, None, None] * block + np.arange(block)[None, None, :]
    pl[r, c] = blocks.astype(np.uint8)


def qim_candidates(value, delta, bit, count, nonnegative=False):
    """Quantisation indices q with q % 2 == bit, ordered by |q*delta - value| (ties: lower q first).
    value, bit: (k,) arrays. Returns (k, count) int64 indices.
    """
    q0 = np.floor(value / delta).astype(np.int64)
    lo = np.where((q0 & 1) == bit, q0, q0 - 1)
    hi = lo + 2
    span = np.arange(count // 2 + 2)
    cands = np.concatenate([lo[:, None] - 2 * span[None, ::-1], hi[:, None] + 2 * span[None, :]], axis=1)
    dist = np.abs(cands * delta - value[:, None])
    if nonnegative:
        dist = np.where(cands < 0, np.inf, dist)
    order = np.argsort(dist, axis=1, kind="stable")
    return np.take_along_axis(cands, order, axis=1)[:, :count]
