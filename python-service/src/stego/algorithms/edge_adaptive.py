"""Edge-adaptive LSB replacement. Mask uses only the 7 MSBs, so it is
identical for cover and stego."""

import numpy as np

from .base import RESERVED, Algorithm, EmbedOutcome, from_bits


def edge_mask(img, threshold):
    g = (img >> 1).astype(np.int32)
    if g.ndim == 3:
        g = (299 * g[..., 0] + 587 * g[..., 1] + 114 * g[..., 2]) // 1000
    grad = np.zeros(g.shape, dtype=np.int32)
    grad[:, :-1] += np.abs(np.diff(g, axis=1))
    grad[:-1, :] += np.abs(np.diff(g, axis=0))
    return grad >= threshold


def eligible_samples(img, threshold):
    m = edge_mask(img, threshold)
    ch = 1 if img.ndim == 2 else 3
    idx = np.flatnonzero(np.repeat(m.reshape(-1), ch))
    return idx[idx >= RESERVED]


class EdgeAdaptiveLsb(Algorithm):
    variant = "edge-mask-7msb-grad-threshold-v1"
    domain = "spatial (edge/texture mask + LSB)"
    reference = "Edge-adaptive LSB family, cf. Luo, Huang & Huang, IEEE TIFS 2010, doi:10.1109/TIFS.2009.2035372 (simplified mask, not identical)"
    id = 4
    name = "edge_adaptive_lsb"
    default_param = 6
    param_range = (1, 255)
    capacity_code = "EDGE_CAPACITY_INSUFFICIENT"

    def capacity_bits(self, img, param=0):
        return int(eligible_samples(img, self.resolve_param(param)).size)

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        n = bits.size
        if n:
            idx = eligible_samples(img, p)[:n]
            flat = out.reshape(-1)
            flat[idx] = (flat[idx] & 0xFE) | bits
        return EmbedOutcome(out, int(n), cap, p)

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        if nbytes == 0:
            return b""
        idx = eligible_samples(img, p)[: nbytes * 8]
        return from_bits(img.reshape(-1)[idx] & 1, nbytes)
