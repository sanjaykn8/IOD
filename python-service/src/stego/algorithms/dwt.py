"""DWT: one-level orthonormal 2-D Haar transform, QIM on the HH (diagonal) sub-band.

Variant ``haar-l1-hh-qim-v1``
  * plane: grayscale image, or the blue plane of RGB (same convention as ``dct``)
  * one-level 2-D Haar DWT on non-overlapping 2x2 blocks. For a block
    [[a, b], [c, d]] the orthonormal coefficients are
        LL = (a+b+c+d)/2, HL = (a-b+c-d)/2, LH = (a+b-c-d)/2, HH = (a-b-c+d)/2
    (a full one-level Haar DWT is exactly this blockwise computation, because the
    Haar filters have support 2).
  * one payload bit per block, in HH, by quantisation-index modulation with step
    delta (param, default 4): the target is HH' = q*delta with q % 2 == bit and
    |HH' - HH| minimal; the inverse transform with only HH changed is
        a' = a + e, b' = b - e, c' = c - e, d' = d + e,   e = (HH' - HH)/2
  * pixels are rounded (numpy round-half-to-even) and clipped to [0, 255]. Each
    block is re-analysed after rounding/clipping; if the decoded bit is wrong
    (only possible near 0/255) the same HH change is applied with other pixel
    patterns (pairs or single pixels, see PATTERNS), then the next-nearest index
    of the right parity is tried (up to 8 candidates x 11 patterns). No side information is
    needed for extraction, which reads HH only.
  * extraction: bit = round(HH / delta) mod 2, same block order.
Rounding moves HH by at most (4 * 0.5) / 2 = 1, so any delta >= 4 leaves a
margin of delta/2 - 1 >= 1 for unclipped blocks.
Not robust to JPEG/resizing (not claimed); lossless PNG hand-off only.
"""

import numpy as np

from ..errors import StegoError
from . import blocks as B
from .base import Algorithm, EmbedOutcome, from_bits

BLOCK = 2
CANDIDATES = 8


def haar_hh(blk):
    return (blk[:, 0, 0] - blk[:, 0, 1] - blk[:, 1, 0] + blk[:, 1, 1]) / 2.0


def haar_all(blk):
    a, b, c, d = blk[:, 0, 0], blk[:, 0, 1], blk[:, 1, 0], blk[:, 1, 1]
    return {"LL": (a + b + c + d) / 2.0, "HL": (a - b + c - d) / 2.0,
            "LH": (a + b - c - d) / 2.0, "HH": (a - b - c + d) / 2.0}


# Pixel-change patterns v (over a, b, c, d) with HH-sensitivity (1, -1, -1, 1)/2 . v = 1,
# so v * delta changes HH by exactly delta. "balanced" spreads the change over all four
# pixels (lowest distortion); the others are only tried when clipping at 0/255 defeats it.
PATTERNS = {
    "balanced": (0.5, -0.5, -0.5, 0.5),
    "a+b": (1, -1, 0, 0), "c+d": (0, 0, -1, 1), "a+c": (1, 0, -1, 0), "b+d": (0, -1, 0, 1),
    "a+d": (1, 0, 0, 1), "b+c": (0, -1, -1, 0),
    "a": (2, 0, 0, 0), "b": (0, -2, 0, 0), "c": (0, 0, -2, 0), "d": (0, 0, 0, 2),
}


def apply_hh(blk, target, pattern="balanced"):
    """Move HH to `target` using the given change pattern, then round and clip."""
    delta = target - haar_hh(blk)
    v = PATTERNS[pattern]
    out = blk.copy()
    out[:, 0, 0] += v[0] * delta
    out[:, 0, 1] += v[1] * delta
    out[:, 1, 0] += v[2] * delta
    out[:, 1, 1] += v[3] * delta
    return np.clip(np.rint(out), 0, 255)


def read_bits(blk, delta):
    return (np.rint(haar_hh(blk) / delta).astype(np.int64) & 1).astype(np.uint8)


class Dwt(Algorithm):
    id = 6
    name = "dwt"
    variant = "haar-l1-hh-qim-v1"
    domain = "transform (Haar DWT)"
    default_param = 4
    param_range = (4, 64)
    reference = ("Blockwise 1-level Haar DWT with QIM (Chen & Wornell 2001, doi:10.1109/18.923725); "
                 "one documented variant of the DWT family, e.g. doi:10.1080/09720529.2019.1698801")

    def capacity_bits(self, img, param=0):
        self.resolve_param(param)
        return B.block_count(img, BLOCK)

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        n = int(bits.size)
        if n == 0:
            return EmbedOutcome(out, 0, cap, p, {"blocks_used": 0})
        delta = float(p)
        br, bc = B.block_coords(img, BLOCK, n)
        blk = B.gather(B.plane(img), BLOCK, br, bc)
        cands = B.qim_candidates(haar_hh(blk), delta, bits.astype(np.int64), CANDIDATES)
        result = np.empty_like(blk)
        pending = np.arange(n)
        retried = 0
        for k in range(CANDIDATES):
            for pattern in PATTERNS:
                trial = apply_hh(blk[pending], cands[pending, k] * delta, pattern)
                ok = read_bits(trial, delta) == bits[pending]
                result[pending[ok]] = trial[ok]
                if k > 0 or pattern != "balanced":
                    retried += int(ok.sum())
                pending = pending[~ok]
                if pending.size == 0:
                    break
            if pending.size == 0:
                break
        if pending.size:
            raise StegoError("ENCODE_VERIFY_FAILED", "dwt: blocks failed round-trip verification",
                             {"failed_blocks": int(pending.size), "blocks_used": n})
        B.scatter(B.plane(out), BLOCK, br, bc, result)
        return EmbedOutcome(out, n, cap, p, {"blocks_used": n, "blocks_retried": retried, "subband": "HH"})

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        if nbytes == 0:
            return b""
        n = nbytes * 8
        br, bc = B.block_coords(img, BLOCK, n)
        return from_bits(read_bits(B.gather(B.plane(img), BLOCK, br, bc), float(p)), nbytes)
