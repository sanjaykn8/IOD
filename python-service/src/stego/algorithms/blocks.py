"""Shared helpers for block-transform algorithms (DWT, DCT-SVD).

Transform methods modify a single plane (the grayscale image, or the blue
plane of an RGB image -- the same convention as the existing `dct`
algorithm) in non-overlapping square blocks. Blocks that contain any of
the bootstrap samples [0,128) are skipped, so the bootstrap written after
embedding can never disturb the payload.
"""

import numpy as np

from .base import RESERVED

PLANE_INDEX_RGB = 2


def plane(img):
    return img if img.ndim == 2 else img[:, :, PLANE_INDEX_RGB]


def first_block_row(img, block):
    """First block row whose pixels contain no reserved (bootstrap) sample."""
    h, w = img.shape[:2]
    ch = 1 if img.ndim == 2 else 3
    reserved_rows = -(-RESERVED // (w * ch))  # rows touched by samples [0,128)
    return -(-reserved_rows // block)


def grid(img, block):
    h, w = img.shape[:2]
    return h // block, w // block


def block_count(img, block):
    nbr, nbc = grid(img, block)
    return max(0, nbr - first_block_row(img, block)) * nbc


def block_coords(img, block, count):
    """Row-major block coordinates (block-row, block-col) of the first `count` usable blocks."""
    _, nbc = grid(img, block)
    b0 = first_block_row(img, block)
    k = np.arange(count)
    return b0 + k // nbc, k % nbc


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
    # the two nearest indices with the right parity around value/delta
    lo = np.where((q0 & 1) == bit, q0, q0 - 1)
    hi = lo + 2
    span = np.arange(count // 2 + 2)
    # ascending in every row, so a stable sort by distance breaks ties towards the lower index
    cands = np.concatenate([lo[:, None] - 2 * span[None, ::-1], hi[:, None] + 2 * span[None, :]], axis=1)
    dist = np.abs(cands * delta - value[:, None])
    if nonnegative:
        dist = np.where(cands < 0, np.inf, dist)
    order = np.argsort(dist, axis=1, kind="stable")
    return np.take_along_axis(cands, order, axis=1)[:, :count]
