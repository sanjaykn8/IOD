"""Deterministic procedural latent images with lossless embedding.

Moved verbatim (in behaviour) from tools/stego-standalone/latent_image.py;
byte-oriented helpers added, text functions kept as wrappers.
"""
import hashlib
import struct

import numpy as np
from PIL import Image

MAGIC = b"LIMG01"
BW_MAGIC = b"LIMG02"
HEADER = struct.Struct(">6sI32s")


def encode_text(text):
    # Explicit byte conversion makes this independent of Python's random hash.
    raw = hashlib.shake_256(text.encode("utf-8")).digest(256 * 4)
    return np.frombuffer(raw, dtype=">u4").astype(np.float64) / (2**32 - 1) * 2 - 1


def decode_latent(latent, size=512):
    """A procedural decoder, not a trained semantic image model."""
    y, x = np.mgrid[-1:1:complex(size), -1:1:complex(size)]
    channels = []
    for channel in range(3):
        field = np.zeros((size, size), dtype=np.float64)
        for j in range(12):
            a, b, phase, amplitude = latent[channel * 48 + j * 4:channel * 48 + j * 4 + 4]
            field += (0.3 + abs(amplitude)) * np.sin(
                (a * x + b * y) * (4 + j * 1.6) + phase * np.pi
            ) / (1 + j * 0.25)
        channels.append(np.clip((np.tanh(field * 0.6) + 1) * 127.5, 0, 255).astype(np.uint8))
    gray = np.mean(np.stack(channels, axis=-1), axis=-1)
    return Image.fromarray(np.where(gray >= 127.5, 255, 0).astype(np.uint8)).convert("1")


def embed_bytes(image, payload):
    payload = bytes(payload)
    packet = HEADER.pack(BW_MAGIC if image.mode == "1" else MAGIC, len(payload), hashlib.sha256(payload).digest()) + payload
    if image.mode == "1":
        pixels = np.array(image, dtype=np.uint8).reshape(-1).copy()
        bits = np.unpackbits(np.frombuffer(packet, dtype=np.uint8))
        pairs = np.random.default_rng(2026).permutation(pixels.size // 2) * 2
        if bits.size > pairs.size:
            raise ValueError(f"Input too large: maximum is {pairs.size // 8 - HEADER.size} UTF-8 bytes at this size.")
        positions = pairs[:bits.size]
        pixels[positions + 1] = pixels[positions] ^ bits
        return Image.fromarray((pixels.reshape(image.height, image.width) * 255).astype(np.uint8)).convert("1")
    pixels = np.array(image.convert("RGB"), dtype=np.uint8, copy=True)
    bits = np.unpackbits(np.frombuffer(packet, dtype=np.uint8))
    flat = pixels.reshape(-1)
    if bits.size > flat.size:
        raise ValueError(f"Input too large: maximum is {flat.size // 8 - HEADER.size} UTF-8 bytes at this size.")
    flat[:bits.size] = (flat[:bits.size] & 254) | bits
    return Image.fromarray(pixels)


def extract_bytes(path):
    with Image.open(path) as image:
        if image.mode == "1":
            pixels = np.array(image, dtype=np.uint8).reshape(-1)
            pairs = np.random.default_rng(2026).permutation(pixels.size // 2) * 2
            flat = pixels[pairs] ^ pixels[pairs + 1]
        else:
            flat = np.array(image.convert("RGB"), dtype=np.uint8).reshape(-1)
    if flat.size < HEADER.size * 8:
        raise ValueError("Image is too small to contain a payload.")
    magic, length, checksum = HEADER.unpack(np.packbits(flat[:HEADER.size * 8] & 1).tobytes())
    if magic not in (MAGIC, BW_MAGIC):
        raise ValueError("No supported hidden payload found.")
    end = (HEADER.size + length) * 8
    if end > flat.size:
        raise ValueError("Hidden payload length is invalid; image may be damaged.")
    payload = np.packbits(flat[HEADER.size * 8:end] & 1).tobytes()
    if hashlib.sha256(payload).digest() != checksum:
        raise ValueError("Hidden payload is damaged (checksum mismatch).")
    return payload


def embed(image, text):
    return embed_bytes(image, text.encode("utf-8"))


def extract(path):
    return extract_bytes(path).decode("utf-8")
