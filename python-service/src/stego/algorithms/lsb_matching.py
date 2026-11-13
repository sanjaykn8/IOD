import hashlib

import numpy as np

from .base import Algorithm, channels_of, from_bits


def _seed(img):
    """Whole-array seed (kept for the worked example); patches use CoverCtx.seed(b"LSBM-v2", patch id)."""
    h = hashlib.sha256(np.ascontiguousarray(img).tobytes() + b"LSBM-v1").digest()
    return int.from_bytes(h[:8], "big")


class LsbMatching(Algorithm):
    variant = "lsb-matching-pm1-seeded-v2 (patch samples; sign stream seeded per patch from the cover hash)"
    domain = "spatial (LSB plane, +/-1)"
    reference = "LSB matching (+/-1 embedding); Sharp 2001, doi:10.1007/3-540-45496-9_2; Ker 2005"
    id = 2
    name = "lsb_matching"

    def capacity_bits(self, img, region, param=0):
        return region.n_pixels * channels_of(img)

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        n = int(bits.size)
        changed = 0
        if n:
            idx = region.samples(ctx.channels)[:n]
            flat = out.reshape(-1)
            rng = np.random.Generator(np.random.PCG64(ctx.seed(b"LSBM-v2", region.id)))
            coin = rng.integers(0, 2, size=n, dtype=np.uint8)
            seg = flat[idx].astype(np.int16)
            step = np.where(coin == 1, 1, -1).astype(np.int16)
            step[seg == 0] = 1
            step[seg == 255] = -1
            mismatch = (seg & 1) != bits
            changed = int(mismatch.sum())
            flat[idx] = np.where(mismatch, seg + step, seg).astype(np.uint8)
        return {"carriers_used": n, "changes": changed}

    def extract(self, img, region, nbytes, param=0):
        self._check_extract(img, region, nbytes, self.resolve_param(param))
        idx = region.samples(channels_of(img))[:nbytes * 8]
        return from_bits(img.reshape(-1)[idx] & 1, nbytes)
