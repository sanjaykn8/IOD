"""Bootstrap v1: 16 bytes, LSB of samples [0,128), MSB-first, fixed method."""

import struct
import zlib
from dataclasses import dataclass

import numpy as np

from .errors import StegoError

MAGIC = b"SB"
VERSION = 1
SIZE = 16
BITS = SIZE * 8
_BODY = struct.Struct(">2sBBBBIH")  # 12 bytes


@dataclass(frozen=True)
class Bootstrap:
    version: int
    alg_id: int
    param: int
    flags: int
    frame_len: int
    reserved: int = 0


def pack(alg_id, param, frame_len, version=VERSION, flags=0, reserved=0):
    for name, v, hi in (("alg_id", alg_id, 255), ("param", param, 255), ("version", version, 255),
                        ("flags", flags, 255), ("reserved", reserved, 65535), ("frame_len", frame_len, 2**32 - 1)):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= hi:
            raise StegoError("INVALID_REQUEST", f"bootstrap field {name} out of range")
    body = _BODY.pack(MAGIC, version, alg_id, param, flags, frame_len, reserved)
    return body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def parse(raw):
    """Parse + structurally validate (magic, version, CRC, flags, reserved).

    Algorithm id and length-vs-capacity checks are done by the caller.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != SIZE:
        raise StegoError("BOOTSTRAP_MISSING", "bootstrap has wrong size")
    raw = bytes(raw)
    magic, version, alg_id, param, flags, frame_len, reserved = _BODY.unpack(raw[:12])
    if magic != MAGIC:
        raise StegoError("BOOTSTRAP_MISSING", "no bootstrap magic found")
    if version != VERSION:
        raise StegoError("UNSUPPORTED_VERSION", "unsupported bootstrap version", {"version": version})
    (crc,) = struct.unpack(">I", raw[12:])
    if crc != zlib.crc32(raw[:12]) & 0xFFFFFFFF:
        raise StegoError("BOOTSTRAP_CORRUPT", "bootstrap CRC mismatch")
    if flags != 0 or reserved != 0:
        raise StegoError("BOOTSTRAP_CORRUPT", "bootstrap flags/reserved must be zero")
    return Bootstrap(version, alg_id, param, flags, frame_len, reserved)


def write(flat, raw16):
    """Replace the LSBs of flat[0:128] (in place) with the bootstrap bits."""
    if flat.size < BITS:
        raise StegoError("IMAGE_TOO_SMALL", "image too small for bootstrap")
    bits = np.unpackbits(np.frombuffer(raw16, dtype=np.uint8))
    flat[:BITS] = (flat[:BITS] & 0xFE) | bits


def read(flat):
    if flat.size < BITS:
        raise StegoError("IMAGE_TOO_SMALL", "image too small for bootstrap")
    return np.packbits(flat[:BITS] & 1).tobytes()
