"""Common algorithm contract (patch/mask based).

Every algorithm works on ONE patch: a `Region` (exact pixel mask with the reserved
bootstrap-v3 carrier pixels already removed). It may read and write only the patch's own pixels/samples, so patches
are independent and extraction never depends on a neighbouring patch.

    support(img, region)                 -> (ok, reason)   structural/geometry support
    capacity_bits(img, region, param)    -> measured capacity (identical on cover and stego)
    embed(ctx, region, out, payload, p)  -> detail dict; writes `out` in place inside the patch only
    extract(img, region, nbytes, p)      -> bytes

Images are uint8 (H,W) or (H,W,3); payload bits are MSB-first. `param` is always explicit
in the manifest (the effective value), 0 only where an algorithm has no parameter.
"""

import numpy as np

from ..errors import StegoError


def check_image(img):
    if (not isinstance(img, np.ndarray) or img.dtype != np.uint8 or img.ndim not in (2, 3)
            or (img.ndim == 3 and img.shape[2] != 3)):
        raise StegoError("UNSUPPORTED_IMAGE_MODE", "image must be uint8 (H,W) or (H,W,3)")


def channels_of(img):
    return 1 if img.ndim == 2 else 3


def to_bits(payload):
    if not isinstance(payload, (bytes, bytearray)):
        raise StegoError("INVALID_REQUEST", "payload must be bytes")
    return np.unpackbits(np.frombuffer(bytes(payload), dtype=np.uint8))


def from_bits(bits, nbytes):
    return np.packbits(bits[: nbytes * 8]).tobytes()[:nbytes]


def check_nbytes(nbytes):
    if isinstance(nbytes, bool) or not isinstance(nbytes, int) or nbytes < 0:
        raise StegoError("FRAME_LENGTH_INVALID", "invalid payload length")


class Algorithm:
    id = 0
    name = ""
    default_param = 0
    param_range = (0, 0)  # inclusive, excluding 0 meaning default
    capacity_code = "CAPACITY_INSUFFICIENT"
    variant = ""
    domain = ""
    reference = ""
    coding = "direct (no coding)"
    block = 0             # block geometry in pixels (0 = sample based)
    mask_support = "any irregular mask (sample based)"

    def describe(self):
        return {"id": self.id, "name": self.name, "variant": self.variant, "domain": self.domain,
                "reference": self.reference, "coding": self.coding, "default_param": self.default_param,
                "param_range": list(self.param_range), "block": self.block, "mask_support": self.mask_support}

    def resolve_param(self, param):
        if isinstance(param, bool) or not isinstance(param, int) or not 0 <= param <= 255:
            raise StegoError("INVALID_REQUEST", "param must be an integer 0..255")
        if param == 0:
            return self.default_param
        lo, hi = self.param_range
        if not lo <= param <= hi:
            raise StegoError("INVALID_REQUEST", f"param out of range for {self.name}",
                             {"allowed": [lo, hi] if hi else [0, 0]})
        return param

    # ---- contract
    def support(self, img, region):
        if self.block:
            n = int(region.blocks(self.block)[0].size)
            if n == 0:
                return False, f"NO_COMPLETE_{self.block}X{self.block}_BLOCK"
            return True, None
        return (True, None) if region.n_pixels > 0 else (False, "EMPTY_PATCH")

    def capacity_bits(self, img, region, param=0):
        raise NotImplementedError

    def embed(self, ctx, region, out, payload, param=0):
        raise NotImplementedError

    def extract(self, img, region, nbytes, param=0):
        raise NotImplementedError

    # ---- helpers
    def _need(self, img, region, payload, param, out=None):
        check_image(img)
        if out is not None:
            check_image(out)
            if out.shape != img.shape:
                raise StegoError("INVALID_REQUEST", "output image shape differs from the cover")
        if region.shape != img.shape[:2]:
            raise StegoError("INVALID_REQUEST", "patch mask shape differs from the image")
        p = self.resolve_param(param)
        bits = to_bits(payload)
        cap = self.capacity_bits(img, region, p)
        if bits.size > cap:
            raise StegoError(self.capacity_code, f"{self.name}: payload exceeds patch capacity",
                             {"capacity_bits": cap, "needed_bits": int(bits.size), "patch": region.id})
        return p, bits, cap

    def _check_extract(self, img, region, nbytes, p):
        check_image(img)
        check_nbytes(nbytes)
        cap = self.capacity_bits(img, region, p)
        if nbytes * 8 > cap:
            raise StegoError("EXTRACT_FAILED", f"{self.name}: requested length exceeds patch capacity",
                             {"capacity_bits": cap, "requested_bits": nbytes * 8, "patch": region.id})
        return cap
