"""Image decode/encode with mode handling. No resizing or lossy ops, ever."""

import io

import numpy as np
from PIL import Image

from .config import Limits
from .errors import StegoError

_CONVERT = {  # source mode -> (target mode)
    "1": "L", "P": "RGB", "PA": "RGB", "RGBA": "RGB", "RGBa": "RGB", "LA": "L", "La": "L",
}


def check_dims(width, height, limits):
    if width < limits.min_dim or height < limits.min_dim:
        raise StegoError("IMAGE_TOO_SMALL", "image smaller than minimum size",
                         {"width": width, "height": height, "min": limits.min_dim})
    if width > limits.max_width or height > limits.max_height:
        raise StegoError("IMAGE_TOO_LARGE", "image larger than configured maximum",
                         {"width": width, "height": height,
                          "max_width": limits.max_width, "max_height": limits.max_height})


def check_array(arr, limits):
    if (not isinstance(arr, np.ndarray) or arr.dtype != np.uint8 or arr.ndim not in (2, 3)
            or (arr.ndim == 3 and arr.shape[2] != 3)):
        raise StegoError("UNSUPPORTED_IMAGE_MODE", "image must be uint8 (H,W) or (H,W,3)")
    check_dims(arr.shape[1], arr.shape[0], limits)


def mode_of(arr):
    return "L" if arr.ndim == 2 else "RGB"


def channels_of(arr):
    return 1 if arr.ndim == 2 else 3


def decode_png(data, limits, convert=False):
    """Decode PNG bytes -> (uint8 array, transforms). Size is checked before pixel decode.

    convert=False (stego images): only L/RGB accepted.
    convert=True (covers): other modes are converted, transform recorded.
    """
    try:
        img = Image.open(io.BytesIO(data), formats=["PNG"])
        width, height = img.size
    except Exception as exc:
        raise StegoError("IMAGE_DECODE_ERROR", "not a decodable PNG") from exc
    check_dims(width, height, limits)
    transforms = []
    try:
        mode = img.mode
        if mode not in ("L", "RGB"):
            if not convert or mode not in _CONVERT:
                raise StegoError("UNSUPPORTED_IMAGE_MODE", "unsupported image mode", {"mode": mode})
            target = _CONVERT[mode]
            img.load()
            img = img.convert(target)
            transforms.append(f"mode:{mode}->{target}")
        arr = np.array(img, dtype=np.uint8)
    except StegoError:
        raise
    except Exception as exc:
        raise StegoError("IMAGE_DECODE_ERROR", "PNG decode failed") from exc
    if mode == "1":
        arr = np.where(arr > 0, 255, 0).astype(np.uint8)
    return arr, transforms


def encode_png(arr):
    if arr.ndim == 2:
        img = Image.fromarray(np.ascontiguousarray(arr), "L")
    else:
        img = Image.fromarray(np.ascontiguousarray(arr), "RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG", compress_level=6)
    return buf.getvalue()


def from_pil(img, limits):
    """Convert a PIL image (e.g. procedural mode '1') to (array, transforms)."""
    transforms = []
    mode = img.mode
    if mode not in ("L", "RGB"):
        if mode not in _CONVERT:
            raise StegoError("UNSUPPORTED_IMAGE_MODE", "unsupported image mode", {"mode": mode})
        target = _CONVERT[mode]
        img = img.convert(target)
        transforms.append(f"mode:{mode}->{target}")
    arr = np.array(img, dtype=np.uint8)
    if mode == "1":
        arr = np.where(arr > 0, 255, 0).astype(np.uint8)
    check_array(arr, limits)
    return arr, transforms
