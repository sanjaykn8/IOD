"""Manifest v1 and Frame v2 layout (untrusted-input parser; no keys, no MAC here).

All integers big-endian. The manifest is authenticated by Rust as part of Frame v2;
this module only parses it defensively (bounds, versions, whitelists, exact coverage)
before any pixel is touched.

Frame v2      = "IOD2" | ver=2 | flags=0 | reserved(2)=0 | manifest_len u32 | wire_len u32
                | manifest | wire | tag(32)                       (header = 16 bytes)
Manifest v1   = "IOPM" | ver=1 | seg_ver | sel_ver | channels | width u16 | height u16
                | cell u8 | n_patches u8 | reserved_rows u16 | payload_len u32 | map_len u32
                | n_patches x (alg_id u8 | param u8 | flags u16=0 | offset u32 | length u32)
                | map (row-major cell labels as (label u8, run LEB128) pairs)
payload section (carried by patches) = wire | tag  -> payload_len = wire_len + 32
"""

import struct
from dataclasses import dataclass

import numpy as np

from ..errors import StegoError
from . import SEGMENTATION_VERSION_ID, SELECTOR_VERSION_ID

FRAME_MAGIC = b"IOD2"
FRAME_VERSION = 2
FRAME_HEADER_LEN = 16
TAG_LEN = 32
MANIFEST_MAGIC = b"IOPM"
MANIFEST_VERSION = 1
MANIFEST_FIXED = 24
PATCH_ENTRY = 12
MAX_PATCHES = 255
MAX_MANIFEST_BYTES = 65536
ALLOWED_CELLS = (4, 8, 16)
N_ALGORITHMS = 10
_FIXED = struct.Struct(">4sBBBBHHBBHII")
_ENTRY = struct.Struct(">BBHII")
_FHDR = struct.Struct(">4sBBHII")


def _bad(msg, code="MANIFEST_INVALID", details=None):
    return StegoError(code, msg, details)


@dataclass(frozen=True)
class PatchEntry:
    alg_id: int      # 0 = patch carries no payload
    param: int
    offset: int
    length: int


@dataclass(frozen=True)
class Manifest:
    channels: int
    width: int
    height: int
    cell: int
    reserved_rows: int
    payload_len: int
    patches: tuple          # tuple[PatchEntry]
    cell_labels: np.ndarray  # (rows, cols) uint8
    seg_version: int = SEGMENTATION_VERSION_ID
    sel_version: int = SELECTOR_VERSION_ID

    @property
    def grid(self):
        return grid_shape(self.height, self.width, self.cell)


def grid_shape(height, width, cell):
    return -(-height // cell), -(-width // cell)


# ------------------------------------------------------------------ map RLE
def rle_encode(cell_labels):
    flat = np.asarray(cell_labels, dtype=np.uint8).reshape(-1)
    if flat.size == 0:
        raise _bad("empty label map")
    change = np.flatnonzero(np.diff(flat)) + 1
    starts = np.concatenate([[0], change])
    lens = np.diff(np.concatenate([starts, [flat.size]]))
    out = bytearray()
    for lab, run in zip(flat[starts].tolist(), lens.tolist()):
        out.append(lab)
        while True:
            b = run & 0x7F
            run >>= 7
            if run:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
    return bytes(out)


def rle_decode(data, n_cells, n_patches):
    """Strict decode: exactly n_cells labels, every label < n_patches, canonical varints, no trailing bytes."""
    out = np.empty(n_cells, dtype=np.uint8)
    pos, filled, n = 0, 0, len(data)
    prev = -1
    while pos < n:
        lab = data[pos]
        pos += 1
        if lab >= n_patches:
            raise _bad("map label out of range")
        if lab == prev:
            raise _bad("map runs are not canonical (adjacent runs share a label)")
        run, shift = 0, 0
        while True:
            if pos >= n:
                raise _bad("map truncated inside a run length")
            b = data[pos]
            pos += 1
            run |= (b & 0x7F) << shift
            if not b & 0x80:
                if b == 0 and shift:
                    raise _bad("map run length not minimally encoded")
                break
            shift += 7
            if shift > 28:
                raise _bad("map run length overflow")
        if run < 1 or filled + run > n_cells:
            raise _bad("map run exceeds the cell grid")
        out[filled:filled + run] = lab
        filled += run
        prev = lab
    if filled != n_cells:
        raise _bad("map does not cover the cell grid exactly")
    return out


# ------------------------------------------------------------------ manifest
def manifest_len_for(n_patches, map_len):
    return MANIFEST_FIXED + PATCH_ENTRY * n_patches + map_len


def carrier_bits(manifest_len):
    """Bootstrap carrier = preamble(16) | manifest | crc32(manifest)(4), one bit per sample LSB."""
    return 8 * (16 + manifest_len + 4)


def reserved_rows_for(manifest_len, width, channels):
    return -(-carrier_bits(manifest_len) // (width * channels))


def pack(m):
    mp = rle_encode(m.cell_labels)
    n = len(m.patches)
    if not 1 <= n <= MAX_PATCHES:
        raise _bad("patch count out of range")
    out = bytearray(_FIXED.pack(MANIFEST_MAGIC, MANIFEST_VERSION, m.seg_version, m.sel_version, m.channels,
                                m.width, m.height, m.cell, n, m.reserved_rows, m.payload_len, len(mp)))
    for p in m.patches:
        out += _ENTRY.pack(p.alg_id, p.param, 0, p.offset, p.length)
    out += mp
    if len(out) > MAX_MANIFEST_BYTES:
        raise _bad("manifest too large", "MANIFEST_TOO_LARGE", {"bytes": len(out), "max": MAX_MANIFEST_BYTES})
    data = bytes(out)
    parse(data)  # never emit something our own strict parser would reject
    return data


def parse(data, max_dim=4096):
    if not isinstance(data, (bytes, bytearray)):
        raise _bad("manifest must be bytes")
    data = bytes(data)
    if len(data) > MAX_MANIFEST_BYTES:
        raise _bad("manifest too large", "MANIFEST_TOO_LARGE")
    if len(data) < MANIFEST_FIXED + PATCH_ENTRY:
        raise _bad("manifest truncated")
    (magic, ver, seg, sel, ch, w, h, cell, n, rrows, plen, mlen) = _FIXED.unpack_from(data, 0)
    if magic != MANIFEST_MAGIC:
        raise _bad("bad manifest magic")
    if ver != MANIFEST_VERSION:
        raise _bad("unsupported manifest version", "UNSUPPORTED_VERSION", {"manifest_version": ver})
    if seg != SEGMENTATION_VERSION_ID or sel != SELECTOR_VERSION_ID:
        raise _bad("unsupported segmentation/selector version", "UNSUPPORTED_VERSION", {"seg": seg, "sel": sel})
    if ch not in (1, 3) or cell not in ALLOWED_CELLS:
        raise _bad("invalid channels or cell size")
    if not (1 <= w <= max_dim and 1 <= h <= max_dim):
        raise _bad("image dimensions out of bounds")
    if not 1 <= n <= MAX_PATCHES:
        raise _bad("patch count out of range")
    if len(data) != manifest_len_for(n, mlen):
        raise _bad("manifest length does not match its declared sizes")
    if rrows != reserved_rows_for(len(data), w, ch) or rrows >= h:
        raise _bad("reserved_rows inconsistent with the manifest size")
    if plen < TAG_LEN + 1:
        raise _bad("payload length too small")
    entries, expect = [], 0
    for i in range(n):
        alg, param, flags, off, ln = _ENTRY.unpack_from(data, MANIFEST_FIXED + PATCH_ENTRY * i)
        if flags != 0:
            raise _bad("non-zero patch flags")
        if alg == 0:
            if param or off or ln:
                raise _bad("unused patch must have zero param/offset/length")
        else:
            if not 1 <= alg <= N_ALGORITHMS:
                raise _bad("unknown algorithm id in manifest", "UNKNOWN_ALGORITHM", {"alg_id": alg})
            if ln < 1 or off != expect:   # sequential, contiguous, in patch-id order
                raise _bad("payload chunks are not sequential and contiguous")
            expect = off + ln
            if expect > plen:
                raise _bad("payload chunks exceed the payload length")
        entries.append(PatchEntry(alg, param, off, ln))
    if expect != plen:
        raise _bad("payload chunks do not cover the payload exactly")
    rows, cols = grid_shape(h, w, cell)
    labels = rle_decode(data[MANIFEST_FIXED + PATCH_ENTRY * n:], rows * cols, n)
    present = np.bincount(labels, minlength=n)
    if np.any(present == 0):
        raise _bad("a patch id has no cells in the map")
    return Manifest(ch, w, h, cell, rrows, plen, tuple(entries), labels.reshape(rows, cols), seg, sel)


def pixel_labels(m):
    """Exact per-pixel patch ids (H, W) uint8 from the cell map."""
    big = np.repeat(np.repeat(m.cell_labels, m.cell, axis=0), m.cell, axis=1)
    return np.ascontiguousarray(big[:m.height, :m.width])


def effective_masks(m):
    """label map with bootstrap-reserved rows set to 255 (never a patch id: ids <= 254)."""
    lab = pixel_labels(m).copy()
    lab[:m.reserved_rows, :] = 255
    return lab


# ------------------------------------------------------------------ frame v2 (structure only)
def frame_len_for(manifest_len, wire_len):
    return FRAME_HEADER_LEN + manifest_len + wire_len + TAG_LEN


def frame_header(manifest_len, wire_len):
    return _FHDR.pack(FRAME_MAGIC, FRAME_VERSION, 0, 0, manifest_len, wire_len)


def split_frame(frame, max_frame_bytes):
    """Structural split of an (unauthenticated) Frame v2 -> (manifest_bytes, payload_section)."""
    if not isinstance(frame, (bytes, bytearray)) or len(frame) > max_frame_bytes:
        raise StegoError("FRAME_TOO_LARGE", "frame exceeds maximum")
    frame = bytes(frame)
    if len(frame) < FRAME_HEADER_LEN + MANIFEST_FIXED + PATCH_ENTRY + 1 + TAG_LEN:
        raise _bad("frame too short", "FRAME_MALFORMED")
    magic, ver, flags, rsv, mlen, wlen = _FHDR.unpack_from(frame, 0)
    if magic != FRAME_MAGIC:
        raise _bad("bad frame magic", "FRAME_MALFORMED")
    if ver != FRAME_VERSION:
        raise _bad("unsupported frame version", "UNSUPPORTED_VERSION", {"frame_version": ver})
    if flags or rsv:
        raise _bad("non-zero frame flags", "FRAME_MALFORMED")
    if mlen > MAX_MANIFEST_BYTES or len(frame) != frame_len_for(mlen, wlen) or wlen < 1:
        raise _bad("frame lengths inconsistent", "FRAME_MALFORMED")
    man = frame[FRAME_HEADER_LEN:FRAME_HEADER_LEN + mlen]
    return man, frame[FRAME_HEADER_LEN + mlen:]
