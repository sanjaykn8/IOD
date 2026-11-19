"""Bootstrap-v3 carrier: pixel mapping and bit I/O only (docs/bootstrap-v3-design.md).

The Rust core derives everything secret-dependent: the per-frame placement key, the value stream, the
sync word, the keystream and therefore the (already encrypted) carrier bits. This module receives only

  * a value stream: big-endian u32 values (pseudo-random, independent of the image size), and
  * carrier bits to write, or a bit range to read,

and maps them onto the image:

  carrier pixels P = first distinct values of (v_i mod (W*H)), in stream order   (flat pixel index)
  sample slot k    = pixel P[k div C], channel k mod C                           (C = 3 RGB, 1 grey)
  write            = +-1 LSB matching at each slot whose LSB differs (random sign; 0 -> +1, 255 -> -1)

No key, sync word, keystream or plaintext ever reaches this module, and nothing here is trusted: the
receiver's Rust core checks the sync word, decrypts the header and body, checks the CRC (corruption only,
not authentication) and parses the manifest before anything else happens. The value stream and carrier
bits reveal where the carrier is in one image, so they are never logged.

`legacy_v2_preamble` recognises images written by the retired bootstrap-v2 (fixed top-row preamble) so the
receiver can report BOOTSTRAP_VERSION_UNSUPPORTED instead of a generic "not found".
"""

import base64
import binascii
import struct
import zlib

import numpy as np

from .errors import StegoError

VERSION = 3
SYNC_BITS = 64
HEADER_BITS = 32
LOCATOR_BITS = SYNC_BITS + HEADER_BITS
MAX_VALUES = 16384            # Rust sends 8192 for reads and 128 per discovery candidate
MAX_CANDIDATES = 63 + 1024 + 1
MAX_BODY_BYTES = 65535
DEFLATE_SLACK = 64            # reserve bound: DEFLATE output <= input + 64 for manifests <= 64 KiB


def reserve_pixels_for(manifest_len, channels):
    """Carrier pixels the sender reserves for a manifest of `manifest_len` bytes (same formula as Rust)."""
    bits = LOCATOR_BITS + 8 * (manifest_len + DEFLATE_SLACK + 4)
    return -(-bits // max(1, channels))


def carrier_bits_for(deflated_len):
    """Exact carrier size: sync | header | DEFLATE(manifest) | CRC32."""
    return LOCATOR_BITS + 8 * (deflated_len + 4)


def deflate(manifest_bytes):
    """Raw DEFLATE (RFC 1951, no zlib header), level 9 -- the form Rust inflates with a size limit."""
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    out = c.compress(bytes(manifest_bytes)) + c.flush()
    if len(out) > len(manifest_bytes) + DEFLATE_SLACK:
        raise StegoError("INTERNAL_ERROR", "DEFLATE output exceeds the reserve bound")
    return out


def decode_values(b64, what="values_b64", max_values=MAX_VALUES):
    """Decode a base64 value stream into a uint32 array (bounded before decoding)."""
    if not isinstance(b64, str) or not b64:
        raise StegoError("INVALID_REQUEST", f"{what} must be a non-empty base64 string")
    if len(b64) > ((4 * max_values + 2) // 3) * 4 + 4:
        raise StegoError("INVALID_REQUEST", f"{what} is too long", {"max_values": max_values})
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StegoError("INVALID_REQUEST", f"{what} is not valid base64") from exc
    if not raw or len(raw) % 4 or len(raw) > 4 * max_values:
        raise StegoError("INVALID_REQUEST", f"{what} must hold 1..{max_values} big-endian u32 values")
    return np.frombuffer(raw, dtype=">u4").astype(np.int64)


def decode_bits(b64, what="bits_b64", max_bytes=MAX_BODY_BYTES + 12):
    if not isinstance(b64, str) or not b64:
        raise StegoError("INVALID_REQUEST", f"{what} must be a non-empty base64 string")
    if len(b64) > ((max_bytes + 2) // 3) * 4 + 4:
        raise StegoError("INVALID_REQUEST", f"{what} is too long")
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StegoError("INVALID_REQUEST", f"{what} is not valid base64") from exc
    if not raw or len(raw) > max_bytes:
        raise StegoError("INVALID_REQUEST", f"{what} has an invalid length")
    return raw


def positions(values, n_pixels):
    """Flat pixel indices: first distinct values of (v mod n_pixels), in stream order."""
    if n_pixels < 1:
        raise StegoError("IMAGE_TOO_SMALL", "image has no pixels")
    v = np.asarray(values, dtype=np.int64) % int(n_pixels)
    _, first = np.unique(v, return_index=True)
    return v[np.sort(first)]


def _channels(arr):
    return 1 if arr.ndim == 2 else arr.shape[2]


def _slots(arr, pos, skip, n_bits):
    c = _channels(arr)
    k = np.arange(skip, skip + n_bits, dtype=np.int64)
    if n_bits and (k[-1] // c) >= len(pos):
        raise StegoError("BOOTSTRAP_CORRUPT", "carrier range exceeds the available carrier pixels",
                         {"needed_pixels": int(k[-1] // c + 1), "available_pixels": int(len(pos))})
    return pos[k // c] * c + (k % c)


def read_bits(arr, pos, skip, n_bits):
    """Read `n_bits` carrier bits (LSBs) starting at slot `skip`; returns packed bytes (MSB first)."""
    if skip < 0 or n_bits < 0 or n_bits % 8:
        raise StegoError("INVALID_REQUEST", "carrier reads are whole bytes")
    flat = arr.reshape(-1)
    return np.packbits(flat[_slots(arr, pos, skip, n_bits)] & 1).tobytes()


def write_bits(out, pos, data, n_bits, rng=None):
    """+-1 LSB matching of `data` (first `n_bits` bits) into slots 0..n_bits-1. In place; returns #changed samples."""
    if n_bits < 0 or n_bits > 8 * len(data):
        raise StegoError("INVALID_REQUEST", "carrier bit count exceeds the supplied bits")
    rng = rng or np.random.default_rng()        # OS-seeded; the sign carries no information
    bits = np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))[:n_bits]
    flat = out.reshape(-1)
    idx = _slots(out, pos, 0, n_bits)
    cur = flat[idx]
    diff = (cur & 1) != bits
    sel = idx[diff]
    v = flat[sel].astype(np.int16)
    step = np.where(rng.integers(0, 2, size=sel.size) == 1, 1, -1)
    step = np.where(v == 0, 1, np.where(v == 255, -1, step))
    flat[sel] = (v + step).astype(flat.dtype)
    return int(sel.size)


# ---- retired bootstrap-v2 recognition (diagnostics only) -------------------------------------
_V2 = struct.Struct(">2sBBII")


def legacy_v2_preamble(arr):
    """True if the first 128 sample LSBs (raster order) hold a valid bootstrap-v2 preamble."""
    flat = arr.reshape(-1)
    if flat.size < 128:
        return False
    raw = np.packbits(flat[:128] & 1).tobytes()
    magic, ver, flags, _, _ = _V2.unpack(raw[:12])
    return magic == b"SB" and ver == 2 and flags == 0 and struct.unpack(">I", raw[12:])[0] == zlib.crc32(raw[:12]) & 0xFFFFFFFF
