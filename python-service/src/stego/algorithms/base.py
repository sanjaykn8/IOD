"""Common algorithm contract and helpers.

All algorithms take/return uint8 ndarrays (H,W) or (H,W,3), always copy,
use MSB-first payload bits, and never touch samples [0,128).
"""

from dataclasses import dataclass, field

import numpy as np

from ..errors import StegoError

RESERVED = 128  # samples [0,128) belong to the bootstrap


@dataclass
class EmbedOutcome:
    stego: np.ndarray
    used_bits: int
    capacity_bits: int
    param: int  # resolved (effective) parameter
    detail: dict = field(default_factory=dict)


def check_image(img):
    if (not isinstance(img, np.ndarray) or img.dtype != np.uint8 or img.ndim not in (2, 3)
            or (img.ndim == 3 and img.shape[2] != 3)):
        raise StegoError("UNSUPPORTED_IMAGE_MODE", "image must be uint8 (H,W) or (H,W,3)")


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

    def describe(self):
        return {"id": self.id, "name": self.name, "variant": self.variant, "domain": self.domain,
                "reference": self.reference, "coding": self.coding, "default_param": self.default_param,
                "param_range": list(self.param_range)}

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

    def capacity_bits(self, img, param=0):
        raise NotImplementedError

    def embed(self, img, payload, param=0):
        raise NotImplementedError

    def extract(self, img, nbytes, param=0):
        raise NotImplementedError

    def _need(self, img, payload, param):
        check_image(img)
        p = self.resolve_param(param)
        bits = to_bits(payload)
        cap = self.capacity_bits(img, p)
        if bits.size > cap:
            raise StegoError(self.capacity_code, f"{self.name}: payload exceeds capacity",
                             {"capacity_bits": cap, "needed_bits": int(bits.size)})
        return p, bits, cap

    def _check_extract(self, img, nbytes, p):
        check_image(img)
        check_nbytes(nbytes)
        cap = self.capacity_bits(img, p)
        if nbytes * 8 > cap:
            raise StegoError("EXTRACT_FAILED", f"{self.name}: requested length exceeds capacity",
                             {"capacity_bits": cap, "requested_bits": nbytes * 8})
        return cap
