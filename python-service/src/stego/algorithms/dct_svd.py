"""DCT-SVD: 8x8 block DCT, SVD of a mid-band 4x4 coefficient sub-matrix, QIM on sigma_1.

Variant ``dct8-svd-s1-qim-v1`` (one concrete member of the DCT-SVD family; other
DCT-SVD papers use different regions, rules and purposes such as watermarking):
  1. plane: grayscale image, or the blue plane of RGB (same convention as ``dct``)
  2. non-overlapping 8x8 blocks, row-major, skipping block rows that contain
     bootstrap samples; partial blocks at the right/bottom edge are not used
  3. orthonormal 2-D DCT-II: X = C B C^T
  4. region: S = X[1:5, 1:5] (4x4, excludes the DC row and column)
  5. SVD: S = U diag(s1, s2, s3, s4) V^T  (numpy.linalg.svd, s1 >= s2 >= ...)
  6. one payload bit per block: s1' = q*delta with q >= 0, q % 2 == bit, |s1' - s1| minimal
     (delta = param, default 16)
  7. reconstruct S' = U diag(s1', s2, s3, s4) V^T, inverse DCT, round half to even, clip [0,255]
  8. verify every block by recomputing s1 from the rounded pixels; on failure try the
     next-nearest valid index (up to 8; failures happen near saturation or when s1'
     would fall below s2)
  Extraction: bit = round(s1(S_stego) / delta) mod 2 with the same block order and region.
Rounding noise changes s1 by at most ||E||_2 <= ||E||_F <= 0.5 * 8 = 4 (orthonormal
transforms), so delta = 16 leaves a margin of 4 for unclipped blocks.
Not robust to JPEG/resizing (not claimed); lossless PNG hand-off only.
"""

import numpy as np

from ..errors import StegoError
from . import blocks as B
from .base import Algorithm, EmbedOutcome, from_bits
from .dct import _C, _CT

BLOCK = 8
R0, R1 = 1, 5
CANDIDATES = 8


def sub_svd(blk):
    x = _C @ blk @ _CT
    s = x[:, R0:R1, R0:R1]
    u, sv, vt = np.linalg.svd(s)
    return x, u, sv, vt


def rebuild(x, u, sv, vt, s1):
    sv2 = sv.copy()
    sv2[:, 0] = s1
    s_new = u @ (sv2[:, :, None] * vt)
    xn = x.copy()
    xn[:, R0:R1, R0:R1] = s_new
    return np.clip(np.rint(_CT @ xn @ _C), 0, 255)


def read_s1(blk):
    return np.linalg.svd((_C @ blk @ _CT)[:, R0:R1, R0:R1], compute_uv=False)[:, 0]


def read_bits(blk, delta):
    return (np.rint(read_s1(blk) / delta).astype(np.int64) & 1).astype(np.uint8)


class DctSvd(Algorithm):
    id = 7
    name = "dct_svd"
    variant = "dct8-svd-s1-qim-v1"
    domain = "transform (block DCT + SVD)"
    default_param = 16
    param_range = (8, 64)
    reference = ("One concrete DCT-SVD variant (QIM on the largest singular value of a mid-band 4x4 DCT "
                 "sub-matrix); family reference doi:10.1145/2345396.2345490 -- not identical to it")

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
        x, u, sv, vt = sub_svd(blk)
        cands = B.qim_candidates(sv[:, 0], delta, bits.astype(np.int64), CANDIDATES, nonnegative=True)
        result = np.empty_like(blk)
        pending = np.arange(n)
        retried = 0
        for k in range(CANDIDATES):
            trial = rebuild(x[pending], u[pending], sv[pending], vt[pending], cands[pending, k] * delta)
            ok = read_bits(trial, delta) == bits[pending]
            result[pending[ok]] = trial[ok]
            if k > 0:
                retried += int(ok.sum())
            pending = pending[~ok]
            if pending.size == 0:
                break
        if pending.size:
            raise StegoError("ENCODE_VERIFY_FAILED", "dct_svd: blocks failed round-trip verification",
                             {"failed_blocks": int(pending.size), "blocks_used": n})
        B.scatter(B.plane(out), BLOCK, br, bc, result)
        return EmbedOutcome(out, n, cap, p, {"blocks_used": n, "blocks_retried": retried,
                                             "region": "DCT[1:5,1:5]", "singular_value": "s1"})

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        if nbytes == 0:
            return b""
        n = nbytes * 8
        br, bc = B.block_coords(img, BLOCK, n)
        return from_bits(read_bits(B.gather(B.plane(img), BLOCK, br, bc), float(p)), nbytes)
