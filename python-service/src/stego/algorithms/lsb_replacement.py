import numpy as np

from .base import RESERVED, Algorithm, EmbedOutcome, from_bits


class LsbReplacement(Algorithm):
    variant = "lsb-replacement-msb-first-v1"
    domain = "spatial (LSB plane)"
    reference = "Classic LSB replacement; e.g. Fridrich, Steganography in Digital Media, CUP 2009, ch. 5"
    id = 1
    name = "lsb_replacement"

    def capacity_bits(self, img, param=0):
        return max(0, img.size - RESERVED)

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        flat = out.reshape(-1)
        n = bits.size
        flat[RESERVED:RESERVED + n] = (flat[RESERVED:RESERVED + n] & 0xFE) | bits
        return EmbedOutcome(out, n, cap, p)

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        flat = img.reshape(-1)
        return from_bits(flat[RESERVED:RESERVED + nbytes * 8] & 1, nbytes)
