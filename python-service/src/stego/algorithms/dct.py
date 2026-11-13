"""8x8 block DCT quantisation-index modulation on one plane."""

import numpy as np

from ..errors import StegoError
from . import blocks as B
from .base import Algorithm, from_bits

_k = np.arange(8)
_C = np.cos((2 * _k[None, :] + 1) * _k[:, None] * np.pi / 16.0)
_C[0] *= np.sqrt(1.0 / 8.0)
_C[1:] *= np.sqrt(2.0 / 8.0)
_CT = _C.T.copy()
COEFFS = [(1, 2), (2, 1), (2, 2), (1, 3), (3, 1), (3, 0)]
_UI = np.array([c[0] for c in COEFFS])
_VI = np.array([c[1] for c in COEFFS])
PER_BLOCK = len(COEFFS)


def _read_bits(blocks, delta):
    x = _C @ blocks @ _CT
    c = x[:, _UI, _VI]
    q = np.rint(c / delta).astype(np.int64)
    return (q & 1).astype(np.uint8)


class Dct(Algorithm):
    variant = "dct8-midband-6coef-qim-v1 (complete 8x8 blocks inside the patch)"
    domain = "transform (8x8 block DCT)"
    reference = "Block-DCT quantisation-index modulation (Chen & Wornell 2001, doi:10.1109/18.923725)"
    id = 5
    name = "dct"
    default_param = 12
    param_range = (4, 64)
    block = 8
    mask_support = "needs complete 8x8 blocks of the global grid inside the patch"

    def capacity_bits(self, img, region, param=0):
        self.resolve_param(param)
        return PER_BLOCK * int(region.blocks(8)[0].size)

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        n = int(bits.size)
        if n == 0:
            return {"blocks_used": 0}
        delta = float(p)
        k = -(-n // PER_BLOCK)
        want = np.zeros(k * PER_BLOCK, dtype=np.uint8)
        want[:n] = bits
        want = want.reshape(k, PER_BLOCK)
        br, bc = (x[:k] for x in region.blocks(8))
        blocks = B.gather(B.plane(ctx.cover), 8, br, bc)
        x = _C @ blocks @ _CT
        c = x[:, _UI, _VI]
        qr = c / delta
        q = np.rint(qr)
        mism = (q.astype(np.int64) & 1) != want
        toward = np.where(qr >= q, 1.0, -1.0)

        def build(direction, sel):
            qn = q[sel] + np.where(mism[sel], direction[sel], 0.0)
            xn = x[sel].copy()
            xn[:, _UI, _VI] = qn * delta
            return np.clip(np.rint(_CT @ xn @ _C), 0, 255)

        pix = build(toward, slice(None))
        bad = np.any(_read_bits(pix, delta) != want, axis=1)
        retried = int(bad.sum())
        if retried:
            sel = np.flatnonzero(bad)
            pix[sel] = build(-toward, sel)
            bad = np.any(_read_bits(pix, delta) != want, axis=1)
            if bad.any():
                raise StegoError("ENCODE_VERIFY_FAILED", "dct: blocks failed round-trip verification",
                                 {"failed_blocks": int(bad.sum()), "blocks_used": k, "patch": region.id})
        B.scatter(B.plane(out), 8, br, bc, pix)
        return {"blocks_used": k, "blocks_retried": retried, "delta": p}

    def extract(self, img, region, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, region, nbytes, p)
        if nbytes == 0:
            return b""
        k = -(-nbytes * 8 // PER_BLOCK)
        br, bc = (x[:k] for x in region.blocks(8))
        return from_bits(_read_bits(B.gather(B.plane(img), 8, br, bc), float(p)).reshape(-1), nbytes)
