"""Deterministic educational fixtures. No external imagery: every cover is generated here."""

import numpy as np

from stego.procedural import decode_latent, encode_text

# The 8x8 luminance block used in many JPEG/DCT tutorials (also the Wikipedia JPEG example).
HAND_MATRIX = np.array([
    [52, 55, 61, 66, 70, 61, 64, 73],
    [63, 59, 55, 90, 109, 85, 69, 72],
    [62, 59, 68, 113, 144, 104, 66, 73],
    [63, 58, 71, 122, 154, 106, 70, 69],
    [67, 61, 68, 104, 126, 88, 68, 70],
    [79, 65, 60, 70, 77, 68, 58, 75],
    [85, 71, 64, 59, 55, 61, 65, 83],
    [87, 79, 69, 68, 65, 76, 78, 94],
], dtype=np.uint8)

# Synthetic ciphertext fixture: a fixed byte sequence for bit-level illustration.
# It is NOT a real encrypted message and cannot pass AEAD verification.
SYNTHETIC_CIPHERTEXT = bytes.fromhex("A63C915E")
SYNTHETIC_LABEL = "synthetic byte sequence for mathematical illustration (not a real ciphertext)"

SAMPLE_MESSAGE = "UAV_ID=D1\nTARGET=D2\nLAT=9.45\nLON=77.80\nALT=120"

BIT_ORDER = "MSB-first"


def bits_of(data):
    return [int(b) for b in np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))]


def _natural(h, w, channels, seed, noise):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w].astype(np.float64)
    planes = []
    for c in range(channels):
        base = (118 + 55 * np.sin(x / (13.0 + 4 * c) + 0.7 * c) * np.cos(y / (17.0 + 3 * c))
                + 30 * np.sin((x + y) / 23.0 + c) + 0.12 * (x - y))
        # a textured region (bottom-right quadrant) next to smooth areas, so adaptive methods differ visibly
        tex = (x > w * 0.5) & (y > h * 0.5)
        base = base + np.where(tex, rng.normal(0, 18, (h, w)), rng.normal(0, noise, (h, w)))
        planes.append(base)
    arr = np.stack(planes, axis=-1) if channels == 3 else planes[0]
    return np.clip(arr, 0, 255).astype(np.uint8)


def sample_cover(name):
    """Return (array, description)."""
    if name == "natural_rgb_256":
        return _natural(256, 256, 3, 2026, 2.5), "256x256 RGB synthetic natural-looking scene (generated, seed 2026)"
    if name == "natural_gray_256":
        return _natural(256, 256, 1, 2027, 2.5), "256x256 grayscale synthetic natural-looking scene (generated, seed 2027)"
    if name == "gray_64":
        return _natural(64, 64, 1, 7, 2.0), "64x64 grayscale small sample (generated, seed 7)"
    if name == "bw_procedural_256":
        img = decode_latent(encode_text("learn-sample"), 256)
        return (np.array(img, dtype=np.uint8) > 0).astype(np.uint8) * 255, \
            "256x256 black-and-white procedural cover (the operational fallback generator, seed 'learn-sample')"
    raise KeyError(name)


SAMPLES = ["natural_rgb_256", "natural_gray_256", "gray_64", "bw_procedural_256"]
