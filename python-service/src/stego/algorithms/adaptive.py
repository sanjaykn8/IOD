"""Content-adaptive algorithms driven by binary STC: HUGO, WOW, S-UNIWARD.

Common embedding scheme (``stc-pm1-v1``)
  * cover elements: every sample (all channels) except the bootstrap samples [0,128)
  * element order: a public, deterministic permutation (PCG64 seeded with
    SHA-256("IOD-STC-PERM-v1" | name | H | W | C)); the first n = m*w elements are used.
    The permutation is not secret: confidentiality and integrity come from the AEAD and the
    frame MAC, not from the embedding key (documented limitation: no stego key).
  * m = payload bits (the complete frame), w = 1/rate: param (2..64) or, when param = 0,
    w = min(W_MAX, N_eff // m) where N_eff = min(#elements, N_MAX). The receiver recomputes
    the same w from the image size and the bootstrap length, so no extra side information.
  * x = LSBs of the selected elements, rho = the algorithm's additive cost map; STC (h = 7)
    returns y with H y = payload and minimal sum of rho over changed elements.
  * every element whose LSB must change is moved by +1 or -1 (binary embedding with +/-1
    changes): HUGO uses the cheaper of its exact rho+ / rho-; WOW and S-UNIWARD costs are
    symmetric, so the sign comes from a PCG64 stream seeded with SHA-256(cover | "STC-PM1-v1");
    0 -> +1 and 255 -> -1 are forced.
  * extraction: y = LSBs of the same elements, payload = H y (no costs, no cover needed).
"""

import hashlib
import time
from functools import lru_cache

import numpy as np

from ..errors import StegoError
from . import costs as K
from . import stc
from .base import RESERVED, Algorithm, EmbedOutcome, from_bits

N_MAX = 131072   # cover elements available to STC per image (bounds the Viterbi run time)
W_MAX = 10       # automatic rate is never below 1/10
W_MIN = 2


@lru_cache(maxsize=16)
def _perm(name, shape):
    n_total = int(np.prod(shape))
    seed = int.from_bytes(hashlib.sha256(b"IOD-STC-PERM-v1|" + name.encode() + b"|" +
                                         "x".join(map(str, shape)).encode()).digest()[:8], "big")
    rng = np.random.Generator(np.random.PCG64(seed))
    p = rng.permutation(n_total - RESERVED) + RESERVED
    p.setflags(write=False)
    return p


def _sign_seed(img):
    return int.from_bytes(hashlib.sha256(np.ascontiguousarray(img).tobytes() + b"STC-PM1-v1").digest()[:8], "big")


class AdaptiveStc(Algorithm):
    default_param = 0
    param_range = (W_MIN, 64)
    coding = stc.VARIANT

    def resolve_param(self, param):
        if isinstance(param, bool) or not isinstance(param, int) or not 0 <= param <= 255:
            raise StegoError("INVALID_REQUEST", "param must be an integer 0..255")
        if param == 0:
            return 0  # automatic rate
        lo, hi = self.param_range
        if not lo <= param <= hi:
            raise StegoError("INVALID_REQUEST", f"param out of range for {self.name}", {"allowed": [lo, hi]})
        return param

    @staticmethod
    def n_eff(img):
        return max(0, min(img.size - RESERVED, N_MAX))

    def capacity_bits(self, img, param=0):
        p = self.resolve_param(param)
        return self.n_eff(img) // (p or W_MIN)

    def rate_w(self, img, m, param):
        p = self.resolve_param(param)
        ne = self.n_eff(img)
        w = p if p else min(W_MAX, ne // max(m, 1))
        if w < W_MIN or m * w > ne:
            raise StegoError(self.capacity_code, f"{self.name}: payload exceeds STC capacity",
                             {"capacity_bits": ne // (p or W_MIN), "needed_bits": m})
        return w

    def elements(self, img, n):
        return _perm(self.name, img.shape)[:n]

    # subclasses: return (rho, sign) for the selected flat indices; sign may be None
    def element_costs(self, img, idx):
        raise NotImplementedError

    def cost_map(self, img):
        """Full per-sample cost map (for visualisation); subclasses may override."""
        idx = np.arange(RESERVED, img.size)
        rho, _ = self.element_costs(img, idx)
        full = np.full(img.size, np.nan)
        full[idx] = rho
        return full.reshape(img.shape)

    def embed(self, img, payload, param=0):
        p, bits, cap = self._need(img, payload, param)
        out = img.copy()
        m = int(bits.size)
        if m == 0:
            return EmbedOutcome(out, 0, cap, p, {"w": None, "n": 0, "changes": 0})
        w = self.rate_w(img, m, p)
        n = m * w
        idx = self.elements(img, n)
        flat = out.reshape(-1)
        x = flat[idx] & 1
        t0 = time.perf_counter()
        rho, sign = self.element_costs(img, idx)
        cost_ms = (time.perf_counter() - t0) * 1000
        t1 = time.perf_counter()
        y, total = stc.embed(x, rho, bits, w)
        stc_ms = (time.perf_counter() - t1) * 1000
        change = np.flatnonzero(y != x)
        vals = flat[idx[change]].astype(np.int16)
        if sign is None:
            rng = np.random.Generator(np.random.PCG64(_sign_seed(img)))
            s = np.where(rng.integers(0, 2, size=n, dtype=np.uint8)[change] == 1, 1, -1).astype(np.int16)
        else:
            s = sign[change].astype(np.int16)
        s[vals == 0] = 1
        s[vals == 255] = -1
        flat[idx[change]] = (vals + s).astype(np.uint8)
        return EmbedOutcome(out, m, cap, p, {
            "w": w, "n": n, "h": stc.H_DEFAULT, "rate": round(1.0 / w, 6), "changes": int(change.size),
            "stc_cost": round(total, 6), "cost_ms": round(cost_ms, 3), "stc_ms": round(stc_ms, 3),
            "coding": stc.VARIANT})

    def extract(self, img, nbytes, param=0):
        p = self.resolve_param(param)
        self._check_extract(img, nbytes, p)
        if nbytes == 0:
            return b""
        m = nbytes * 8
        w = self.rate_w(img, m, p)
        idx = self.elements(img, m * w)
        y = img.reshape(-1)[idx] & 1
        return from_bits(stc.syndrome(y, m, w), nbytes)


class _MapCost(AdaptiveStc):
    plane_fn = None

    def full_costs(self, img):
        return K.per_sample(img, type(self).plane_fn)

    def element_costs(self, img, idx):
        return self.full_costs(img).reshape(-1)[idx], None

    def cost_map(self, img):
        return self.full_costs(img)


class Wow(_MapCost):
    id = 9
    name = "wow"
    variant = "WOW (p=-1, db8 filter bank) + binary STC h=7"
    domain = "spatial, content-adaptive (wavelet directional filters)"
    reference = "Holub & Fridrich, IEEE WIFS 2012, doi:10.1109/WIFS.2012.6412655"
    plane_fn = staticmethod(K.wow_plane)


class SUniward(_MapCost):
    id = 10
    name = "s_uniward"
    variant = "S-UNIWARD (spatial, sigma=1, db8 filter bank) + binary STC h=7"
    domain = "spatial, content-adaptive (wavelet relative change)"
    reference = "Holub, Fridrich & Denemark, EURASIP J. Inf. Secur. 2014:1, doi:10.1186/1687-417X-2014-1"
    plane_fn = staticmethod(K.uniward_plane)


class Hugo(AdaptiveStc):
    id = 8
    name = "hugo"
    variant = ("HUGO, exact single-change costs (T=90, sigma=1, gamma=1), additive approximation "
               "+ binary STC h=7, no model correction")
    domain = "spatial, content-adaptive (SPAM co-occurrence model)"
    reference = "Pevny, Filler & Bas, Information Hiding 2010, doi:10.1007/978-3-642-16435-4_13"

    def element_costs(self, img, idx):
        ch = 1 if img.ndim == 2 else 3
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
        sign = np.where(rp <= rm, 1, -1)
        return rho, sign
