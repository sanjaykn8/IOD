import hashlib

import numpy as np

from .base import RESERVED, Algorithm, EmbedOutcome, from_bits


def _seed(img):
    h = hashlib.sha256(np.ascontiguousarray(img).tobytes() + b"LSBM-v1").digest()
    return int.from_bytes(h[:8], "big")


class LsbMatching(Algorithm):
    variant = "lsb-matching-pm1-seeded-v1"
    domain = "spatial (LSB plane, +/-1)"
    reference = "LSB matching (+/-1 embedding); Sharp 2001, doi:10.1007/3-540-45496-9_2; Ker 2005"
    id = 2
    name = "lsb_matching"

    def capacity_bits(self, img, param=0):
        return max(0, img.size - RESERVED)

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        flat = out.reshape(-1)
        n = bits.size
        if n:
            rng = np.random.Generator(np.random.PCG64(_seed(img)))
            coin = rng.integers(0, 2, size=n, dtype=np.uint8)  # one draw per bit position
            seg = flat[RESERVED:RESERVED + n].astype(np.int16)
            step = np.where(coin == 1, 1, -1).astype(np.int16)
            step[seg == 0] = 1
            step[seg == 255] = -1
            mismatch = (seg & 1) != bits
            seg = np.where(mismatch, seg + step, seg)
            flat[RESERVED:RESERVED + n] = seg.astype(np.uint8)
        return EmbedOutcome(out, n, cap, p)

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        flat = img.reshape(-1)
        return from_bits(flat[RESERVED:RESERVED + nbytes * 8] & 1, nbytes)
