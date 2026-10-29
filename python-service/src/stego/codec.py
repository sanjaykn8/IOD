"""Bootstrap + payload embedding/extraction on arrays (shared by selector and service)."""

from . import bootstrap
from .algorithms import get_by_id
from .config import Limits
from .errors import StegoError
from .images import check_array


def embed_frame(arr, alg, param, frame):
    """Embed payload with `alg`, then write the bootstrap. Returns (stego, outcome)."""
    out = alg.embed(arr, frame, param)
    flat = out.stego.reshape(-1)
    bootstrap.write(flat, bootstrap.pack(alg.id, param, len(frame)))
    return out.stego, out


def extract_frame(arr, limits):
    """Validate bootstrap against this image, then extract. Returns (frame, Bootstrap, alg)."""
    check_array(arr, limits)
    flat = arr.reshape(-1)
    bs = bootstrap.parse(bootstrap.read(flat))
    alg = get_by_id(bs.alg_id)
    try:
        alg.resolve_param(bs.param)
    except StegoError as exc:
        raise StegoError("BOOTSTRAP_CORRUPT", "bootstrap param invalid for algorithm") from exc
    if bs.frame_len < 1 or bs.frame_len > limits.max_frame_bytes:
        raise StegoError("FRAME_LENGTH_INVALID", "frame length out of bounds", {"frame_len": bs.frame_len})
    cap = alg.capacity_bits(arr, bs.param)
    if bs.frame_len * 8 > cap:
        raise StegoError("FRAME_LENGTH_INVALID", "frame length exceeds capacity of this image",
                         {"frame_len": bs.frame_len, "capacity_bytes": cap // 8})
    try:
        frame = alg.extract(arr, bs.frame_len, bs.param)
    except StegoError as exc:
        raise StegoError("EXTRACT_FAILED", "payload extraction failed", {"cause": exc.code}) from exc
    return frame, bs, alg
