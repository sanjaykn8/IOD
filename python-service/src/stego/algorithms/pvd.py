"""Pixel-value differencing (Wu-Tsai range table), fully vectorised."""

import numpy as np

from ..errors import StegoError
from .base import RESERVED, Algorithm, EmbedOutcome, from_bits

LOWER = np.array([0, 8, 16, 32, 64, 128], dtype=np.int64)
NBITS = np.array([3, 3, 4, 5, 6, 7], dtype=np.int64)


def _pairs(flat):
    n = max(0, (flat.size - RESERVED) // 2)
    a = flat[RESERVED:RESERVED + 2 * n:2].astype(np.int64)
    b = flat[RESERVED + 1:RESERVED + 1 + 2 * n:2].astype(np.int64)
    return a, b


def range_index(d):
    return np.searchsorted(LOWER, d, side="right") - 1


class Pvd(Algorithm):
    id = 3
    name = "pvd"

    def capacity_bits(self, img, param=0):
        a, b = _pairs(img.reshape(-1))
        return int(NBITS[range_index(np.abs(a - b))].sum())

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        flat = out.reshape(-1)
        total = int(bits.size)
        if total == 0:
            return EmbedOutcome(out, 0, cap, p)
        a, b = _pairs(flat)
        idx = range_index(np.abs(a - b))
        nb = NBITS[idx]
        cs = np.cumsum(nb)
        k = int(np.searchsorted(cs, total, side="left")) + 1  # pairs needed
        a, b, idx, nb, cs = a[:k], b[:k], idx[:k], nb[:k], cs[:k]
        off = cs - nb
        padded = np.concatenate([bits.astype(np.int64), np.zeros(8, dtype=np.int64)])
        v = np.zeros(k, dtype=np.int64)
        for j in range(7):
            bit = padded[np.minimum(off + j, padded.size - 1)]
            v = np.where(j < nb, v * 2 + bit, v)
        dnew = LOWER[idx] + v
        t = np.where(a >= b, dnew, -dnew)  # target signed difference (sign of a-b kept; a==b -> +)
        delta = t - (a - b)
        a_new = a + (-((-delta) // 2))  # a + ceil(delta/2): nearest integer to optimum
        lo = np.maximum(0, t)
        hi = np.minimum(255, 255 + t)
        a_new = np.clip(a_new, lo, hi)
        b_new = a_new - t
        if (b_new.min() < 0) or (b_new.max() > 255) or np.any(np.abs(a_new - b_new) != dnew):
            raise StegoError("INTERNAL_ERROR", "pvd internal invariant violated")
        flat[RESERVED:RESERVED + 2 * k:2] = a_new.astype(np.uint8)
        flat[RESERVED + 1:RESERVED + 1 + 2 * k:2] = b_new.astype(np.uint8)
        return EmbedOutcome(out, total, cap, p, {"pairs_used": k})

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        total = nbytes * 8
        if total == 0:
            return b""
        a, b = _pairs(img.reshape(-1))
        d = np.abs(a - b)
        idx = range_index(d)
        nb = NBITS[idx]
        cs = np.cumsum(nb)
        k = int(np.searchsorted(cs, total, side="left")) + 1
        d, idx, nb = d[:k], idx[:k], nb[:k]
        v = d - LOWER[idx]
        cols = np.arange(7)[None, :]
        mask = cols < nb[:, None]
        shift = np.where(mask, nb[:, None] - 1 - cols, 0)
        bitmat = (v[:, None] >> shift) & 1
        stream = bitmat[mask].astype(np.uint8)
        return from_bits(stream, nbytes)
