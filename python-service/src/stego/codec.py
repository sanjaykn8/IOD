"""Patch-wise embedding/extraction of a Frame v3 with a bootstrap-v3 carrier (service, tests, evaluation).

embed_frame  : frame (built + MACed by Rust) + value stream + encrypted carrier bits -> stego array
read_carrier : stego array + value stream -> carrier bits (for Rust to check, decrypt and parse)
extract_frame: stego array + manifest (decoded and validated by Rust) + value stream -> frame bytes

The receiver NEVER segments: masks come from the manifest Rust hands back. This module holds no key and
cannot locate the carrier on its own; nothing here is trusted until the Rust core verifies the frame MAC.
"""

import numpy as np

from . import bootstrap as B
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


def embed_frame(cover, frame, limits, values, carrier, n_bits, rng=None):
    """Embed `frame` (Frame v3) into a copy of `cover` exactly as its manifest prescribes, then write the
    carrier bits into the reserved carrier pixels. Returns (stego, manifest, per_patch, carrier_info)."""
    check_array(cover, limits)
    man_bytes, payload = M.split_frame(frame, limits.max_frame_bytes)
    man = M.parse(man_bytes, max(limits.max_width, limits.max_height))
    _check_against_image(man, cover)
    if man.payload_len != len(payload):
        raise StegoError("MANIFEST_INVALID", "manifest payload length differs from the frame")
    ch = man.channels
    if not B.LOCATOR_BITS < n_bits <= 8 * len(carrier) or n_bits % 8:
        raise StegoError("INVALID_REQUEST", "carrier bit count invalid")
    if n_bits > man.carrier_pixels * ch:
        raise StegoError("INVALID_REQUEST", "carrier larger than the reserved carrier pixels",
                         {"carrier_bits": n_bits, "reserved_slots": man.carrier_pixels * ch})
    reserved = M.carrier_positions(man, values)
    eff = M.effective_masks(man, reserved)
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
    # carrier last: its pixels are disjoint from every patch mask
    changed_carrier = B.write_bits(out, reserved, carrier, n_bits, rng)
    written = -(-n_bits // ch)
    allowed.reshape(-1)[reserved[:written]] = True
    changed = (out != cover) if cover.ndim == 2 else (out != cover).any(axis=2)
    if np.any(changed & ~allowed):
        raise StegoError("INTERNAL_ERROR", "carrier write touched pixels outside the reserved carrier pixels")
    if B.read_bits(out, reserved, 0, n_bits) != bytes(carrier[:n_bits // 8]):
        raise StegoError("EMBED_VERIFY_FAILED", "carrier did not read back")
    info = {"version": B.VERSION, "carrier_pixels": man.carrier_pixels, "carrier_bits": n_bits,
            "carrier_pixels_written": written, "carrier_changed_samples": changed_carrier}
    return out, man, per_patch, info


def read_carrier(arr, values, skip, n_bits):
    """Carrier bits at slots [skip, skip + n_bits) of the pixels the value stream maps to."""
    return B.read_bits(arr, B.positions(values, arr.shape[0] * arr.shape[1]), skip, n_bits)


def extract_frame(arr, man_bytes, values, limits):
    """Rebuild the masks from `man_bytes` (already validated by Rust; parsed again here) without the
    reserved carrier pixels, extract every chunk and return (frame_bytes, manifest, per_patch)."""
    check_array(arr, limits)
    man = M.parse(man_bytes, max(limits.max_width, limits.max_height))
    _check_against_image(man, arr)
    wire_len = man.payload_len - M.TAG_LEN
    if M.frame_len_for(len(man_bytes), wire_len) > limits.max_frame_bytes:
        raise StegoError("FRAME_TOO_LARGE", "frame described by the manifest exceeds the maximum")
    eff = M.effective_masks(man, M.carrier_positions(man, values))
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
    frame = M.frame_header(len(man_bytes), wire_len) + bytes(man_bytes) + bytes(payload)
    return frame, man, per_patch
