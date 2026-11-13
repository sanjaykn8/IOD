"""Patch-wise embedding/extraction of a Frame v2 (shared by service, learning and tests).

embed_frame : frame bytes (already built + MACed by Rust) -> stego array
extract_frame: stego array -> reconstructed frame bytes
The receiver NEVER segments: masks come from the manifest read out of the image.
Nothing here is trusted until the Rust core verifies the frame MAC.
"""

import numpy as np

from . import bootstrap
from .algorithms import get_by_id
from .errors import StegoError
from .images import check_array
from .patch import manifest as M
from .patch.region import CoverCtx, Region


def _check_against_image(man, arr):
    h, w = arr.shape[:2]
    ch = 1 if arr.ndim == 2 else 3
    if (man.height, man.width, man.channels) != (h, w, ch):
        raise StegoError("MANIFEST_INVALID", "manifest image geometry differs from the image",
                         {"manifest": [man.height, man.width, man.channels], "image": [h, w, ch]})


def _resolve(entry, patch_id):
    alg = get_by_id(entry.alg_id)
    try:
        p = alg.resolve_param(entry.param)
    except StegoError as exc:
        raise StegoError("MANIFEST_INVALID", "patch parameter invalid for its algorithm", {"patch": patch_id}) from exc
    if p != entry.param or (alg.param_range[1] and p == 0):
        raise StegoError("MANIFEST_INVALID", "patch parameter must be explicit", {"patch": patch_id})
    return alg, p


def embed_frame(cover, frame, limits):
    """Embed `frame` (Frame v2) into a copy of `cover` exactly as its manifest prescribes.
    Returns (stego, manifest, per_patch list)."""
    check_array(cover, limits)
    man_bytes, payload = M.split_frame(frame, limits.max_frame_bytes)
    man = M.parse(man_bytes, max(limits.max_width, limits.max_height))
    _check_against_image(man, cover)
    if man.payload_len != len(payload):
        raise StegoError("MANIFEST_INVALID", "manifest payload length differs from the frame")
    eff = M.effective_masks(man)
    ctx = CoverCtx(cover)
    out = cover.copy()
    per_patch = []
    allowed = np.zeros(cover.shape[:2], dtype=bool)
    for i, e in enumerate(man.patches):
        if e.alg_id == 0:
            per_patch.append({"patch_id": i, "used": False})
            continue
        alg, p = _resolve(e, i)
        reg = Region.from_labels(eff, i)
        ok, why = alg.support(cover, reg)
        cap = alg.capacity_bits(cover, reg, p) if ok else 0
        if not ok or cap < 8 * e.length:
            raise StegoError("PATCH_EMBED_FAILED", "patch cannot carry its chunk with the manifest algorithm",
                             {"patch": i, "algorithm": alg.name, "reason": why or "CAPACITY", "capacity_bits": int(cap), "needed_bits": 8 * e.length})
        chunk = payload[e.offset:e.offset + e.length]
        try:
            detail = alg.embed(ctx, reg, out, chunk, p)
        except StegoError as exc:
            raise StegoError("PATCH_EMBED_FAILED", "patch embedding failed", {"patch": i, "algorithm": alg.name, "cause": exc.code}) from exc
        if alg.extract(out, reg, e.length, p) != chunk:
            raise StegoError("PATCH_EMBED_FAILED", "patch failed immediate re-extraction", {"patch": i, "algorithm": alg.name})
        allowed |= reg.mask
        d = (out.astype(np.int16) - cover.astype(np.int16))[reg.mask]
        per_patch.append({"patch_id": i, "used": True, "algorithm": alg.name, "alg_id": alg.id, "param": p,
                          "payload_offset": e.offset, "payload_length": e.length, "capacity_bytes": int(cap) // 8,
                          "changed_samples": int(np.count_nonzero(d)), "patch_mse": round(float(np.mean(d.astype(np.float64) ** 2)), 6) if d.size else 0.0,
                          "detail": detail})
    # invariant: nothing outside the used patches was modified by any algorithm
    changed = (out != cover) if cover.ndim == 2 else (out != cover).any(axis=2)
    if np.any(changed & ~allowed):
        raise StegoError("PATCH_EMBED_FAILED", "an algorithm modified pixels outside its patch")
    used_bits = bootstrap.write_carrier(out.reshape(-1), man_bytes, len(frame))
    ch = man.channels
    if used_bits > man.reserved_rows * man.width * ch:
        raise StegoError("INTERNAL_ERROR", "bootstrap carrier exceeds its reserved rows")
    return out, man, per_patch


def extract_frame(arr, limits):
    """Read preamble + manifest from the image, rebuild the masks from the manifest, extract every
    chunk and return (frame_bytes, manifest, preamble, per_patch). Fails closed on any inconsistency."""
    check_array(arr, limits)
    flat = arr.reshape(-1)
    pre, man_bytes = bootstrap.read_carrier(flat, limits.max_frame_bytes)
    man = M.parse(man_bytes, max(limits.max_width, limits.max_height))
    _check_against_image(man, arr)
    wire_len = pre.frame_len - M.FRAME_HEADER_LEN - pre.manifest_len - M.TAG_LEN
    if wire_len < 1 or man.payload_len != wire_len + M.TAG_LEN:
        raise StegoError("FRAME_LENGTH_INVALID", "bootstrap frame length inconsistent with the manifest")
    eff = M.effective_masks(man)
    payload = bytearray(man.payload_len)
    per_patch = []
    for i, e in enumerate(man.patches):
        if e.alg_id == 0:
            continue
        alg, p = _resolve(e, i)
        reg = Region.from_labels(eff, i)
        ok, _ = alg.support(arr, reg)
        if not ok or alg.capacity_bits(arr, reg, p) < 8 * e.length:
            raise StegoError("EXTRACT_FAILED", "manifest chunk exceeds the patch capacity", {"patch": i, "algorithm": alg.name})
        try:
            chunk = alg.extract(arr, reg, e.length, p)
        except StegoError as exc:
            raise StegoError("EXTRACT_FAILED", "patch extraction failed", {"patch": i, "cause": exc.code}) from exc
        if len(chunk) != e.length:
            raise StegoError("EXTRACT_FAILED", "patch returned a wrong chunk length", {"patch": i})
        payload[e.offset:e.offset + e.length] = chunk
        per_patch.append({"patch_id": i, "algorithm": alg.name, "alg_id": alg.id, "param": p,
                          "payload_offset": e.offset, "payload_length": e.length, "status": "extracted"})
    frame = M.frame_header(pre.manifest_len, wire_len) + man_bytes + bytes(payload)
    if len(frame) != pre.frame_len:
        raise StegoError("FRAME_LENGTH_INVALID", "reconstructed frame length mismatch")
    return frame, man, pre, per_patch
