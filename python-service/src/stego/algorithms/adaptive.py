"""Content-adaptive algorithms driven by binary STC: HUGO, WOW, S-UNIWARD (patch mode).

Common embedding scheme (``stc-pm1-v2``)
  * cover elements: every sample (all channels) of the patch's own pixels -- nothing else.
  * element order: a public, deterministic permutation of the patch's raster-order sample
    list (PCG64 seeded with SHA-256("IOD-STC-PERM-v2" | name | H | W | C | patch id | count));
    at most N_MAX elements are available, the first n = m*w are used. The permutation is not
    secret: confidentiality and integrity come from the AEAD and the frame MAC (no stego key).
  * m = payload bits of this patch's chunk, w = 1/rate = the manifest `param` (2..64, always
    explicit). The planner chooses w = min(W_MAX, N_eff // m).
  * x = LSBs of the selected elements, rho = the algorithm's additive cost; STC (h = 7)
    returns y with H y = payload and minimal sum of rho over changed elements.
  * costs are read-only functions of the COVER (WOW / S-UNIWARD maps are computed once on the
    cover; HUGO single-change costs are evaluated for the selected elements). They read
    neighbouring pixels, but only the patch's own samples are ever modified.
  * every element whose LSB must change moves by +1 or -1: HUGO uses the cheaper of its exact
    rho+ / rho-; WOW and S-UNIWARD use a PCG64 sign stream seeded per patch from the cover
    hash; 0 -> +1 and 255 -> -1 are forced.
  * extraction: y = LSBs of the same elements, payload = H y (no costs, no cover needed).
"""

import hashlib
import time

import numpy as np

from ..errors import StegoError
from . import costs as K
from . import stc
from .base import Algorithm, channels_of, from_bits

N_MAX = 131072   # cover elements available to STC per patch (bounds the Viterbi run time)
W_MAX = 10       # the planner never uses a rate below 1/10
W_MIN = 2


def _elements(name, img, region):
    idx = region.samples(channels_of(img))
    shape = img.shape if img.ndim == 3 else img.shape + (1,)
    seed = int.from_bytes(hashlib.sha256(
        b"IOD-STC-PERM-v2|" + name.encode() + b"|" + "x".join(map(str, shape)).encode()
        + b"|" + str(region.id).encode() + b"|" + str(idx.size).encode()).digest()[:8], "big")
    rng = np.random.Generator(np.random.PCG64(seed))
    return idx[rng.permutation(idx.size)[:N_MAX]]


class AdaptiveStc(Algorithm):
    default_param = 0
    param_range = (W_MIN, 64)
    coding = stc.VARIANT
    mask_support = "any irregular mask; STC domain = the patch's own samples"

    def resolve_param(self, param):
        if isinstance(param, bool) or not isinstance(param, int) or not 0 <= param <= 255:
            raise StegoError("INVALID_REQUEST", "param must be an integer 0..255")
        if param == 0:
            return 0  # capacity queries only: densest supported rate (w = 2)
        lo, hi = self.param_range
        if not lo <= param <= hi:
            raise StegoError("INVALID_REQUEST", f"param out of range for {self.name}", {"allowed": [lo, hi]})
        return param

    @staticmethod
    def n_eff(img, region):
        return min(region.n_pixels * channels_of(img), N_MAX)

    def support(self, img, region):
        return (True, None) if self.n_eff(img, region) >= 8 * W_MIN else (False, "TOO_FEW_SAMPLES_FOR_STC")

    def capacity_bits(self, img, region, param=0):
        p = self.resolve_param(param)
        return self.n_eff(img, region) // (p or W_MIN)

    def choose_w(self, img, region, nbytes):
        """Planner helper: sparsest rate (largest w <= W_MAX) that still fits `nbytes`."""
        m = nbytes * 8
        w = min(W_MAX, self.n_eff(img, region) // max(m, 1))
        return w if w >= W_MIN else 0

    def elements(self, img, region, n):
        return _elements(self.name, img, region)[:n]

    # subclasses: return (rho, sign) for the selected flat sample indices; sign may be None
    def element_costs(self, ctx, idx):
        raise NotImplementedError

    def embed(self, ctx, region, out, payload, param=0):
        p, bits, cap = self._need(ctx.cover, region, payload, param, out)
        m = int(bits.size)
        if m == 0:
            return {"w": None, "n": 0, "changes": 0}
        if p < W_MIN:
            raise StegoError("INVALID_REQUEST", f"{self.name}: explicit STC width required")
        n = m * p
        idx = self.elements(ctx.cover, region, n)
        flat = out.reshape(-1)
        x = flat[idx] & 1
        t0 = time.perf_counter()
        rho, sign = self.element_costs(ctx, idx)
        cost_ms = (time.perf_counter() - t0) * 1000
        t1 = time.perf_counter()
        y, total = stc.embed(x, rho, bits, p)
        stc_ms = (time.perf_counter() - t1) * 1000
        change = np.flatnonzero(y != x)
        vals = flat[idx[change]].astype(np.int16)
        if sign is None:
            rng = np.random.Generator(np.random.PCG64(ctx.seed(b"STC-PM1-v2", region.id)))
            s = np.where(rng.integers(0, 2, size=n, dtype=np.uint8)[change] == 1, 1, -1).astype(np.int16)
        else:
            s = sign[change].astype(np.int16)
        s[vals == 0] = 1
        s[vals == 255] = -1
        flat[idx[change]] = (vals + s).astype(np.uint8)
        return {"w": p, "n": n, "h": stc.H_DEFAULT, "rate": round(1.0 / p, 6), "changes": int(change.size),
                "stc_cost": round(total, 6), "cost_ms": round(cost_ms, 3), "stc_ms": round(stc_ms, 3), "coding": stc.VARIANT}

    def extract(self, img, region, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, region, nbytes, p)
        if nbytes == 0:
            return b""
        if p < W_MIN:
            raise StegoError("EXTRACT_FAILED", f"{self.name}: explicit STC width required")
        m = nbytes * 8
        idx = self.elements(img, region, m * p)
        return from_bits(stc.syndrome(img.reshape(-1)[idx] & 1, m, p), nbytes)


class _MapCost(AdaptiveStc):
    plane_fn = None

    def full_costs(self, img):
        return K.per_sample(img, type(self).plane_fn)

    def element_costs(self, ctx, idx):
        return ctx.cost_map(self.name, self.full_costs).reshape(-1)[idx], None


class Wow(_MapCost):
    id = 9
    name = "wow"
    variant = "WOW (p=-1, db8 filter bank) + binary STC h=7 (custom submatrices)"
    domain = "spatial, content-adaptive (wavelet directional filters)"
    reference = "Holub & Fridrich, IEEE WIFS 2012, doi:10.1109/WIFS.2012.6412655"
    plane_fn = staticmethod(K.wow_plane)


class SUniward(_MapCost):
    id = 10
    name = "s_uniward"
    variant = "S-UNIWARD (spatial, sigma=1, db8 filter bank) + binary STC h=7 (custom submatrices)"
    domain = "spatial, content-adaptive (wavelet relative change)"
    reference = "Holub, Fridrich & Denemark, EURASIP J. Inf. Secur. 2014:1, doi:10.1186/1687-417X-2014-1"
    plane_fn = staticmethod(K.uniward_plane)


class Hugo(AdaptiveStc):
    id = 8
    name = "hugo"
    variant = ("HUGO additive approximation: exact single-change costs (T=90, sigma=1, gamma=1) "
               "+ binary STC h=7 (custom submatrices), no model correction")
    domain = "spatial, content-adaptive (SPAM co-occurrence model)"
    reference = "Pevny, Filler & Bas, Information Hiding 2010, doi:10.1007/978-3-642-16435-4_13"

    def element_costs(self, ctx, idx):
        img = ctx.cover
        ch = ctx.channels
        pix = idx // ch
        chan = idx % ch
        w = img.shape[1]
        rows, cols = pix // w, pix % w
        rp = np.empty(idx.size)
        rm = np.empty(idx.size)
        for c in range(ch):
            sel = np.flatnonzero(chan == c)
            if sel.size == 0:
                continue
            plane = img if img.ndim == 2 else img[:, :, c]
            a, b = K.hugo_costs(plane, rows[sel], cols[sel])
            rp[sel], rm[sel] = a, b
        rho = np.minimum(rp, rm)
        rho = np.where(np.isfinite(rho), rho, K.WET)
        return rho, np.where(rp <= rm, 1, -1)
