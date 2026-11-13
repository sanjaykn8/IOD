"""Edge-adaptive LSB replacement. The edge mask uses only the 7 MSBs, so it is identical
for cover and stego. In patch mode the gradient of a pixel uses only neighbours INSIDE the
same patch, so a neighbouring patch's algorithm can never change this patch's mask."""

import numpy as np

from .base import Algorithm, channels_of, from_bits


def _g7(img):
    g = (img >> 1).astype(np.int32)
    if g.ndim == 3:
        g = (299 * g[..., 0] + 587 * g[..., 1] + 114 * g[..., 2]) // 1000
    return g


def edge_mask(img, threshold, within=None):
    """Pixels whose 7-MSB gradient reaches `threshold`. `within` (bool mask) restricts both the
    result and the neighbours that contribute to the gradient."""
    g = _g7(img)
    grad = np.zeros(g.shape, dtype=np.int32)
    dx = np.abs(np.diff(g, axis=1))
    dy = np.abs(np.diff(g, axis=0))
    if within is not None:
        dx = dx * (within[:, :-1] & within[:, 1:])
        dy = dy * (within[:-1, :] & within[1:, :])
    grad[:, :-1] += dx
    grad[:-1, :] += dy
    m = grad >= threshold
    return m if within is None else (m & within)


def eligible_samples(img, region, threshold):
    r0, c0, r1, c1 = region.bbox()
    sub = edge_mask(img[r0:r1, c0:c1], threshold, region.mask[r0:r1, c0:c1])
    rr, cc = np.nonzero(sub)
    pix = (rr + r0) * img.shape[1] + (cc + c0)
    ch = channels_of(img)
    return pix if ch == 1 else (pix[:, None] * ch + np.arange(ch)[None, :]).reshape(-1)


class EdgeAdaptiveLsb(Algorithm):
    variant = "edge-mask-7msb-grad-threshold-v2 (gradient restricted to the patch)"
    domain = "spatial (edge/texture mask + LSB)"
    reference = "Edge-adaptive LSB family, cf. Luo, Huang & Huang, IEEE TIFS 2010, doi:10.1109/TIFS.2009.2035372 (simplified mask, not identical)"
    id = 4
    name = "edge_adaptive_lsb"
    default_param = 6
    param_range = (1, 255)
    capacity_code = "EDGE_CAPACITY_INSUFFICIENT"
    mask_support = "any irregular mask; capacity = edge samples inside the patch"

    def capacity_bits(self, img, region, param=0):
        return int(eligible_samples(img, region, self.resolve_param(param)).size)

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        if bits.size:
            idx = eligible_samples(ctx.cover, region, p)[:bits.size]
            flat = out.reshape(-1)
            flat[idx] = (flat[idx] & 0xFE) | bits
        return {"carriers_used": int(bits.size), "edge_samples": cap, "threshold": p}

    def extract(self, img, region, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, region, nbytes, p)
        if nbytes == 0:
            return b""
        idx = eligible_samples(img, region, p)[: nbytes * 8]
        return from_bits(img.reshape(-1)[idx] & 1, nbytes)
