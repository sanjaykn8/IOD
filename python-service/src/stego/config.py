"""Configuration and hard ceilings. Environment is read at call time."""

import logging
import os
from dataclasses import dataclass

from .errors import StegoError

log = logging.getLogger("stego")

HARD_MAX_DIM = 4096
HARD_MAX_FRAME_BYTES = 1024 * 1024
MIN_DIM = 32
MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024  # read cap for any artifact file


def artifact_dir():
    return os.environ.get("IOD_STEGO_ARTIFACT_DIR") or os.path.join(".", "data", "stego-artifacts")


def retention_max():
    raw = os.environ.get("IOD_STEGO_RETENTION_MAX_ARTIFACTS", "0")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        log.warning("invalid IOD_STEGO_RETENTION_MAX_ARTIFACTS; keeping all")
        return 0
    return max(0, n)


def camera_mode():
    raw = (os.environ.get("IOD_STEGO_CAMERA") or "auto").strip().lower()
    return raw if raw in ("auto", "disabled") else "auto"


def camera_timeout_s():
    try:
        v = float(os.environ.get("IOD_STEGO_CAMERA_TIMEOUT_S", "3.0"))
    except ValueError:
        v = 3.0
    return min(max(v, 0.05), 30.0)


@dataclass(frozen=True)
class Limits:
    max_width: int = HARD_MAX_DIM
    max_height: int = HARD_MAX_DIM
    max_frame_bytes: int = HARD_MAX_FRAME_BYTES
    min_dim: int = MIN_DIM


def _pos_int(name, v, ceiling):
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise StegoError("INVALID_REQUEST", f"limits.{name} must be a positive integer")
    return min(v, ceiling)  # a request can only lower the ceilings


def parse_limits(raw):
    """Client limits can only tighten the hard ceilings, never raise them."""
    if raw is None:
        return Limits()
    if not isinstance(raw, dict):
        raise StegoError("INVALID_REQUEST", "limits must be an object")
    w = h = HARD_MAX_DIM
    for key in ("max_dim", "max_image_dim"):
        if key in raw:
            w = h = _pos_int(key, raw[key], HARD_MAX_DIM)
    if "max_width" in raw:
        w = _pos_int("max_width", raw["max_width"], HARD_MAX_DIM)
    if "max_height" in raw:
        h = _pos_int("max_height", raw["max_height"], HARD_MAX_DIM)
    f = HARD_MAX_FRAME_BYTES
    if "max_frame_bytes" in raw:
        f = _pos_int("max_frame_bytes", raw["max_frame_bytes"], HARD_MAX_FRAME_BYTES)
    return Limits(max_width=w, max_height=h, max_frame_bytes=f)
