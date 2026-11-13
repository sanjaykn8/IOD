"""Pixel-value differencing (Wu-Tsai range table), vectorised, on the patch's sample list.

Pairs are consecutive entries (2k, 2k+1) of the patch's raster-order sample list, so a pair
never contains a sample of another patch. The range of a pair is preserved by embedding,
so the receiver recomputes the same capacity and bit positions from the stego image."""

import numpy as np

from ..errors import StegoError
from .base import Algorithm, channels_of, from_bits

LOWER = np.array([0, 8, 16, 32, 64, 128], dtype=np.int64)
NBITS = np.array([3, 3, 4, 5, 6, 7], dtype=np.int64)


def range_index(d):
    return np.searchsorted(LOWER, d, side="right") - 1


def _pairs(img, region):
    idx = region.samples(channels_of(img))
    n = idx.size // 2
    flat = img.reshape(-1)
    ia, ib = idx[0:2 * n:2], idx[1:2 * n:2]
    return flat[ia].astype(np.int64), flat[ib].astype(np.int64), ia, ib


class Pvd(Algorithm):
    variant = "wu-tsai-pvd-6range-v1 (pairs = consecutive patch samples)"
    domain = "spatial (pixel-pair differences)"
    reference = "Wu & Tsai, Pattern Recognit. Lett. 24 (2003) 1613-1626, doi:10.1016/S0167-8655(02)00402-6"
    id = 3
    name = "pvd"
    mask_support = "any irregular mask with at least 2 samples"

    def support(self, img, region):
        return (True, None) if region.n_pixels * channels_of(img) >= 2 else (False, "FEWER_THAN_ONE_PAIR")

    def capacity_bits(self, img, region, param=0):
        a, b, _, _ = _pairs(img, region)
        return int(NBITS[range_index(np.abs(a - b))].sum())

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        total = int(bits.size)
        if total == 0:
            return {"pairs_used": 0}
        a, b, ia, ib = _pairs(ctx.cover, region)
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
        a_new = a + (-((-delta) // 2))  # a + ceil(delta/2)
        a_new = np.clip(a_new, np.maximum(0, t), np.minimum(255, 255 + t))
        b_new = a_new - t
        if (b_new.min() < 0) or (b_new.max() > 255) or np.any(np.abs(a_new - b_new) != dnew):
            raise StegoError("INTERNAL_ERROR", "pvd internal invariant violated")
        flat = out.reshape(-1)
        flat[ia[:k]] = a_new.astype(np.uint8)
        flat[ib[:k]] = b_new.astype(np.uint8)
        return {"pairs_used": k}

    def extract(self, img, region, nbytes, param=0):
        self._check_extract(img, region, nbytes, self.resolve_param(param))
        total = nbytes * 8
        if total == 0:
            return b""
        a, b, _, _ = _pairs(img, region)
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
        return from_bits(bitmat[mask].astype(np.uint8), nbytes)
