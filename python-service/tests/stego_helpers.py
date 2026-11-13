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


def disc_mask(h, w, cy=None, cx=None, r=None):
    """Irregular (non-rectangular) test mask: a disc with a bite taken out."""
    cy = h / 2 if cy is None else cy
    cx = w / 2 if cx is None else cx
    r = min(h, w) * 0.4 if r is None else r
    y, x = np.mgrid[0:h, 0:w]
    m = (y - cy) ** 2 + (x - cx) ** 2 <= r * r
    m &= ~((y - cy + r * 0.6) ** 2 + (x - cx - r * 0.6) ** 2 <= (r * 0.35) ** 2)
    return m


def mixed_cover(h=192, w=256, channels=3, seed=11):
    """Flat sky, smooth gradient, textured and edged areas in one image (drives mixed selection)."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w].astype(np.float64)
    g = np.full((h, w), 120.0)
    g[: h // 3] = 200 + 0.02 * x[: h // 3]
    g[h // 3: 2 * h // 3, : w // 2] = 80 + 60 * np.sin(x[h // 3: 2 * h // 3, : w // 2] / 5.0) + rng.normal(0, 14, (h // 3, w // 2))
    g[h // 3: 2 * h // 3, w // 2:] = 60 + 0.5 * x[h // 3: 2 * h // 3, w // 2:]
    g[2 * h // 3:] = 110 + rng.normal(0, 28, (h - 2 * h // 3, w))
    g[2 * h // 3:, ::16] = 30
    if channels == 1:
        return np.clip(g, 4, 251).astype(np.uint8)
    arr = np.stack([g, g * 0.9 + 10, g * 0.8 + 25 + rng.normal(0, 2, (h, w))], axis=-1)
    return np.clip(arr, 4, 251).astype(np.uint8)
