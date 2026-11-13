"""Bootstrap v2: fixed 16-byte preamble + manifest + CRC32, in the LSBs of the first samples.

preamble = "SB" | version=2 | flags=0 | manifest_len u32 | frame_len u32 | crc32(first 12 bytes)
carrier  = preamble | manifest | crc32(manifest)      one bit per sample LSB, MSB-first, raster order
The carrier occupies whole image rows [0, reserved_rows); no patch algorithm may touch them.
CRC32 only detects accidental corruption. It is NOT authentication: the manifest is
authenticated by the Rust core as part of Frame v2.
"""

import struct
import zlib
from dataclasses import dataclass

import numpy as np

from .errors import StegoError
from .patch import manifest as M

MAGIC = b"SB"
VERSION = 2
SIZE = 16
BITS = SIZE * 8
_BODY = struct.Struct(">2sBBII")


@dataclass(frozen=True)
class Preamble:
    version: int
    manifest_len: int
    frame_len: int


def pack_preamble(manifest_len, frame_len):
    for v in (manifest_len, frame_len):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 < v < 2 ** 32:
            raise StegoError("INVALID_REQUEST", "bootstrap length out of range")
    body = _BODY.pack(MAGIC, VERSION, 0, manifest_len, frame_len)
    return body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def parse_preamble(raw, max_frame_bytes):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != SIZE:
        raise StegoError("BOOTSTRAP_MISSING", "bootstrap has wrong size")
    raw = bytes(raw)
    magic, version, flags, mlen, flen = _BODY.unpack(raw[:12])
    if magic != MAGIC:
        raise StegoError("BOOTSTRAP_MISSING", "no bootstrap magic found")
    if version != VERSION:
        raise StegoError("UNSUPPORTED_VERSION", "unsupported bootstrap version", {"version": version})
    if struct.unpack(">I", raw[12:])[0] != zlib.crc32(raw[:12]) & 0xFFFFFFFF:
        raise StegoError("BOOTSTRAP_CORRUPT", "bootstrap CRC mismatch")
    if flags != 0:
        raise StegoError("BOOTSTRAP_CORRUPT", "bootstrap flags must be zero")
    if not M.MANIFEST_FIXED + M.PATCH_ENTRY + 1 <= mlen <= M.MAX_MANIFEST_BYTES:
        raise StegoError("MANIFEST_TOO_LARGE" if mlen > M.MAX_MANIFEST_BYTES else "BOOTSTRAP_CORRUPT", "manifest length out of bounds")
    if flen > max_frame_bytes or flen < M.frame_len_for(mlen, 1):
        raise StegoError("FRAME_LENGTH_INVALID", "frame length out of bounds", {"frame_len": flen})
    return Preamble(version, mlen, flen)


def write_carrier(flat, manifest_bytes, frame_len):
    """Write preamble | manifest | crc into the LSBs of flat[0:n] (in place). Returns n."""
    blob = pack_preamble(len(manifest_bytes), frame_len) + manifest_bytes + struct.pack(">I", zlib.crc32(manifest_bytes) & 0xFFFFFFFF)
    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8))
    if flat.size < bits.size:
        raise StegoError("IMAGE_TOO_SMALL", "image too small for the bootstrap carrier")
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return int(bits.size)


def read_carrier(flat, max_frame_bytes):
    """Returns (Preamble, manifest_bytes). Bounded: nothing is read before the preamble validates."""
    if flat.size < BITS:
        raise StegoError("IMAGE_TOO_SMALL", "image too small for bootstrap")
    pre = parse_preamble(np.packbits(flat[:BITS] & 1).tobytes(), max_frame_bytes)
    need = M.carrier_bits(pre.manifest_len)
    if need > flat.size:
        raise StegoError("BOOTSTRAP_CORRUPT", "manifest length exceeds the image")
    body = np.packbits(flat[BITS:need] & 1).tobytes()
    man, crc = body[:pre.manifest_len], body[pre.manifest_len:]
    if struct.unpack(">I", crc)[0] != zlib.crc32(man) & 0xFFFFFFFF:
        raise StegoError("BOOTSTRAP_CORRUPT", "manifest CRC mismatch")
    return pre, man
