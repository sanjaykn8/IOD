"""Deterministic synthetic covers (no network, no webcam)."""
import numpy as np


def natural_cover(h=96, w=128, channels=3, seed=7, noise=10.0):
    """Smooth gradients + seeded noise, kept inside [30, 225] (no saturation)."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w].astype(np.float64)
    planes = []
    for c in range(channels):
        base = 110 + 60 * np.sin(x / (9.0 + 3 * c) + c) + 40 * np.cos(y / (11.0 + 2 * c))
        planes.append(base + rng.normal(0, noise, (h, w)))
    arr = np.stack(planes, axis=-1) if channels == 3 else planes[0]
    return np.clip(arr, 30, 225).astype(np.uint8)


def bw_cover(h=64, w=64, seed="bw-test"):
    from stego.procedural import decode_latent, encode_text
    img = decode_latent(encode_text(seed), max(h, w))
    return np.where(np.array(img, dtype=np.uint8) > 0, 255, 0).astype(np.uint8)[:h, :w]


def payload(n, seed=3):
    return np.random.default_rng(seed).integers(0, 256, n, dtype=np.uint8).tobytes()
