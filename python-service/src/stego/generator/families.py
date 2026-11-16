"""Procedural image families: multi-octave gradient noise, domain warping, coherent palettes.

Everything is vectorised NumPy on float32 arrays (no per-pixel Python loops, no tiling, no periodic
basis functions). An image is a pure function of (seed bytes, width, height, mode, family, detail_bias):
the same inputs give byte-identical output on the same NumPy version.

Why there is fine "grain": a perfectly smooth synthetic gradient quantised to 8 bits has banded,
highly structured low-order bit planes, which no camera image has and which makes any +-1 change
conspicuous. A small spatially correlated grain (about 1-2 grey levels) is added as the last step,
the way sensor noise or dithering would. It is a minor component; the quality gates reject images
whose energy is dominated by it.
"""

import hashlib
import time

import numpy as np

from ..errors import StegoError
from . import GENERATOR_VERSION

FAMILIES = ("terrain", "clouds", "strata", "cells")
MODES = ("RGB", "L")
SEED_BYTES = 16
MAX_LATTICE_CELLS = 2_000_000  # safety bound for one noise lattice (float32 -> 8 MB)
F32 = np.float32

_coord_cache = {}  # (h, w) -> (Y, X); at most two entries


def seed_fingerprint(seed):
    """Public, non-reversible label of a seed (the raw production seed is never stored or returned)."""
    return hashlib.sha256(b"IOD-COVER-SEED-v1" + bytes(seed)).hexdigest()[:16]


def _coords(h, w):
    key = (h, w)
    hit = _coord_cache.get(key)
    if hit is None:
        if len(_coord_cache) >= 2:
            _coord_cache.pop(next(iter(_coord_cache)))
        y = np.arange(h, dtype=F32)[:, None] + np.zeros((1, w), dtype=F32)
        x = np.arange(w, dtype=F32)[None, :] + np.zeros((h, 1), dtype=F32)
        y.setflags(write=False)
        x.setflags(write=False)
        hit = _coord_cache[key] = (y, x)
    return hit


def _fade(t):
    return t * t * t * (t * (t * 6.0 - 15.0) + 10.0)


def gradient_noise(rng, y, x):
    """Perlin-style gradient noise at float coordinates (lattice units). Non-periodic: the lattice is
    drawn fresh and is exactly as large as the coordinate range needs. Output roughly in [-0.7, 0.7]."""
    y0 = np.floor(y).astype(np.int32)
    x0 = np.floor(x).astype(np.int32)
    oy, ox = int(y0.min()), int(x0.min())
    gh, gw = int(y0.max()) - oy + 2, int(x0.max()) - ox + 2
    if gh * gw > MAX_LATTICE_CELLS:
        raise StegoError("COVER_GENERATION_FAILED", "noise lattice exceeds the safety bound")
    ang = rng.random((gh, gw), dtype=F32) * F32(2 * np.pi)
    gy, gx = np.sin(ang), np.cos(ang)
    fy, fx = y - y0, x - x0
    iy, ix = y0 - oy, x0 - ox
    ty, tx = _fade(fy), _fade(fx)

    def corner(dy, dx):
        return gy[iy + dy, ix + dx] * (fy - dy) + gx[iy + dy, ix + dx] * (fx - dx)

    top = corner(0, 0)
    top += (corner(0, 1) - top) * tx
    bot = corner(1, 0)
    bot += (corner(1, 1) - bot) * tx
    top += (bot - top) * ty
    return top


def fbm(rng, y, x, octaves, lacunarity=2.0, gain=0.5, ridged=False):
    """Sum of octaves, each with its own rotation and offset (no axis-aligned or repeated structure)."""
    out = np.zeros(y.shape, dtype=F32)
    amp, freq, total = 1.0, 1.0, 0.0
    for _ in range(octaves):
        a = rng.random() * 2 * np.pi
        c, s = F32(np.cos(a) * freq), F32(np.sin(a) * freq)
        oy, ox = F32(rng.random() * 64), F32(rng.random() * 64)
        n = gradient_noise(rng, y * c - x * s + oy, y * s + x * c + ox)
        if ridged:
            n = 1.0 - np.abs(n) * 2.0
            n *= n
        out += n * F32(amp)
        total += amp
        amp *= gain
        freq *= lacunarity * (0.94 + 0.12 * rng.random())  # never an exact doubling
    out /= F32(total)
    return out


def _norm01(v, lo_p=0.5, hi_p=99.5):
    lo, hi = np.percentile(v, [lo_p, hi_p])
    if hi - lo < 1e-9:
        raise StegoError("COVER_GENERATION_FAILED", "degenerate field")
    return np.clip((v - F32(lo)) / F32(hi - lo), 0.0, 1.0).astype(F32)


def _hsv(h, s, v):
    i = int(h * 6.0) % 6
    f = h * 6.0 - int(h * 6.0)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    return [(v, t, p), (q, v, p), (p, v, t), (p, q, v), (t, p, v), (v, p, q)][i]


def make_palette(rng, n=None):
    """A coherent ramp: analogous hues around a random base (sometimes with one contrasting accent),
    moderate saturation, value rising along the ramp with jitter. Returns (positions, rgb[n,3])."""
    n = int(rng.integers(4, 7)) if n is None else n
    h0 = rng.random()
    spread = 0.05 + 0.22 * rng.random()
    accent = int(rng.integers(0, n)) if rng.random() < 0.35 else -1
    v0, v1 = 0.16 + 0.14 * rng.random(), 0.78 + 0.16 * rng.random()
    if rng.random() < 0.25:
        v0, v1 = v1, v0
    cols = []
    for i in range(n):
        t = i / (n - 1)
        h = (h0 + spread * (rng.random() * 2 - 1) + (0.33 + 0.3 * rng.random() if i == accent else 0.0)) % 1.0
        s = 0.10 + 0.38 * rng.random()
        v = v0 + (v1 - v0) * t + 0.07 * (rng.random() * 2 - 1)
        cols.append(_hsv(h, min(max(s, 0.0), 1.0), min(max(v, 0.08), 0.96)))
    pos = np.linspace(0.0, 1.0, n) + np.concatenate([[0.0], (rng.random(n - 2) - 0.5) * (0.5 / n), [0.0]])
    return pos.astype(np.float64), np.asarray(cols, dtype=np.float64)


def apply_palette(v, pal):
    pos, cols = pal
    out = np.empty(v.shape + (3,), dtype=F32)
    for c in range(3):
        out[..., c] = np.interp(v, pos, cols[:, c])
    return out


def _warp(rng, y, x, scale, strength, octaves=2):
    """Displace coordinates by a low-frequency vector field (strength in lattice units of `scale`)."""
    wy = fbm(rng, y / F32(scale), x / F32(scale), octaves)
    wx = fbm(rng, y / F32(scale), x / F32(scale), octaves)
    k = F32(strength * scale * 2.0)
    return y + wy * k, x + wx * k


# ------------------------------------------------------------------ families
def _ref(h, w):
    """Reference length for feature sizes. Floored at 240 px so that a small cover is a crop of a
    normally-scaled scene instead of a miniature whose features approach the pixel grid."""
    return max(min(h, w), 240)


def _terrain(rng, h, w, detail):
    y, x = _coords(h, w)
    base = (0.32 + 0.33 * rng.random()) * _ref(h, w)
    wy, wx = _warp(rng, y, x, base * (1.2 + rng.random()), 0.1 + 0.25 * rng.random())
    octs = 5 + (detail > 0.5)
    e = fbm(rng, wy / F32(base), wx / F32(base), octs, gain=0.40 + 0.08 * detail)
    r = rng.random() * 0.45
    if r > 0.15:
        e = e * F32(1 - r) + (fbm(rng, wy / F32(base * 0.8), wx / F32(base * 0.8), 4, ridged=True) - 0.5) * F32(r)
    e = _norm01(e)
    gy, gx = np.gradient(e)
    a = rng.random() * 2 * np.pi
    k = (0.4 + 0.6 * rng.random()) * _ref(h, w) / 14.0
    shade = np.clip(0.5 + (gy * F32(np.sin(a)) + gx * F32(np.cos(a))) * F32(k), 0.0, 1.0)
    rgb = apply_palette(e, make_palette(rng))
    rgb *= (F32(0.62) + F32(0.38) * shade * 2.0 * F32(0.5 + 0.5 * rng.random()))[..., None].clip(0.4, 1.25)
    return rgb, {"base_scale_px": round(base, 1), "octaves": octs, "ridge_mix": round(r, 3)}


def _clouds(rng, h, w, detail):
    y, x = _coords(h, w)
    base = (0.3 + 0.4 * rng.random()) * _ref(h, w)
    stretch = 1.0 + 1.2 * rng.random()          # directional structure
    a = rng.random() * np.pi
    ry = (y * F32(np.cos(a)) - x * F32(np.sin(a))) * F32(stretch)
    rx = y * F32(np.sin(a)) + x * F32(np.cos(a))
    wy, wx = _warp(rng, ry, rx, base, 0.25 + 0.35 * rng.random(), 3)
    wy, wx = _warp(rng, wy, wx, base * 0.45, 0.15 + 0.2 * rng.random(), 2)
    octs = 5 + (detail > 0.5)
    v = _norm01(fbm(rng, wy / F32(base), wx / F32(base), octs, gain=0.5 + 0.08 * detail))
    v2 = _norm01(fbm(rng, wy / F32(base * 1.7), wx / F32(base * 1.7), 3))
    pal_a, pal_b = make_palette(rng, 3), make_palette(rng, 4)
    # broad backdrop gradient + a soft cloud layer blended by a smooth mask
    d = rng.random() * 2 * np.pi
    ramp = _norm01(y * F32(np.sin(d)) + x * F32(np.cos(d)) + (v2 - 0.5) * F32(0.35 * _ref(h, w)), 0.0, 100.0)
    back = apply_palette(ramp, pal_a)
    front = apply_palette(v, pal_b)
    t0 = 0.3 + 0.25 * rng.random()
    m = np.clip((v - F32(t0)) / F32(0.45), 0.0, 1.0)
    m = (m * m * (3 - 2 * m))[..., None]
    rgb = back * (1 - m) + front * m
    return rgb, {"base_scale_px": round(base, 1), "octaves": octs, "stretch": round(stretch, 2)}


def _lattice1d(rng, t, octaves=2):
    """Irregular 1-D value noise (random knots): layer tones without any periodic function."""
    out = np.zeros(t.shape, dtype=F32)
    amp, freq, total = 1.0, 1.0, 0.0
    for _ in range(octaves):
        u = t * F32(freq) + F32(rng.random() * 32)
        u0 = np.floor(u).astype(np.int32)
        o = int(u0.min())
        g = rng.random(int(u0.max()) - o + 2, dtype=F32)
        f = _fade(u - u0)
        i = u0 - o
        out += (g[i] + (g[i + 1] - g[i]) * f) * F32(amp)
        total += amp
        amp *= 0.45
        freq *= 2.7 + rng.random()
    return out / F32(total)


def _strata(rng, h, w, detail):
    y, x = _coords(h, w)
    a = rng.random() * np.pi
    thick = (0.06 + 0.12 * rng.random()) * _ref(h, w)      # mean layer thickness in pixels
    base = (0.35 + 0.4 * rng.random()) * _ref(h, w)
    fold = fbm(rng, y / F32(base), x / F32(base), 3) * F32(2.5 + 4.0 * rng.random())
    fine = fbm(rng, y / F32(base * 0.2), x / F32(base * 0.2), 3) * F32(0.25 + 0.35 * detail)
    t = (y * F32(np.cos(a)) + x * F32(np.sin(a))) / F32(thick) + fold + fine
    v = _norm01(_lattice1d(rng, t, 3), 0.0, 100.0)
    body = _norm01(fbm(rng, y / F32(base * 0.5), x / F32(base * 0.5), 4))
    v = np.clip(v * F32(0.78) + body * F32(0.22), 0.0, 1.0)
    rgb = apply_palette(v, make_palette(rng))
    vein = fbm(rng, y / F32(base * 0.33), x / F32(base * 0.33), 4, ridged=True)
    rgb *= (F32(0.86) + F32(0.2) * vein)[..., None]
    return rgb, {"layer_thickness_px": round(thick, 1), "fold_scale_px": round(base, 1)}


def _cells(rng, h, w, detail):
    y, x = _coords(h, w)
    size = (0.14 + 0.13 * rng.random()) * _ref(h, w)       # mean cell size in pixels
    wy, wx = _warp(rng, y, x, size * 2.5, 0.12 + 0.2 * rng.random())
    ny, nx = int(h / size) + 3, int(w / size) + 3
    py = ((np.arange(ny)[:, None] - 1) + rng.random((ny, nx))) * size
    px = ((np.arange(nx)[None, :] - 1) + rng.random((ny, nx))) * size
    tone = rng.random(ny * nx)
    f1 = np.full((h, w), np.inf, dtype=F32)
    f2 = np.full((h, w), np.inf, dtype=F32)
    val = np.zeros((h, w), dtype=F32)
    for cy, cx, tv in zip(py.ravel(), px.ravel(), tone):   # loop over ~10^2 sites, not pixels
        d = (wy - F32(cy)) ** 2 + (wx - F32(cx)) ** 2
        closer = d < f1
        f2 = np.where(closer, f1, np.minimum(f2, d))
        val = np.where(closer, F32(tv), val)
        f1 = np.where(closer, d, f1)
    f1, f2 = np.sqrt(f1), np.sqrt(f2)
    edge = np.clip((f2 - f1) / F32(size * (0.25 + 0.2 * rng.random())), 0.0, 1.0)
    edge = edge * edge * (3 - 2 * edge)
    body = _norm01(fbm(rng, y / F32(size * 1.8), x / F32(size * 1.8), 4 + (detail > 0.5)))
    inner = np.clip(f1 / F32(size), 0.0, 1.0)
    v = np.clip(val * F32(0.42) + body * F32(0.4) + inner * F32(0.18), 0.0, 1.0)
    rgb = apply_palette(v, make_palette(rng))
    rgb *= (F32(0.6) + F32(0.4) * edge)[..., None]
    return rgb, {"cell_size_px": round(size, 1), "sites": int(ny * nx)}


_FAMILY_FN = {"terrain": _terrain, "clouds": _clouds, "strata": _strata, "cells": _cells}


def _blur3(a):
    """Separable [1,2,1]/4 blur with edge replication."""
    p = np.pad(a, ((1, 1), (0, 0)) + ((0, 0),) * (a.ndim - 2), mode="edge")
    a = (p[:-2] + 2 * p[1:-1] + p[2:]) * F32(0.25)
    p = np.pad(a, ((0, 0), (1, 1)) + ((0, 0),) * (a.ndim - 2), mode="edge")
    return (p[:, :-2] + 2 * p[:, 1:-1] + p[:, 2:]) * F32(0.25)


def _finish(rng, rgb, detail, mode):
    """Tone range without clipping, correlated grain, 8-bit quantisation."""
    lum = rgb @ np.array([0.299, 0.587, 0.114], dtype=F32)
    lo, hi = np.percentile(lum, [0.2, 99.8])
    span = max(float(hi - lo), 1e-6)
    out_lo, out_hi = 22 + 22 * rng.random(), 232 - 26 * rng.random()
    rgb = (rgb - F32(lo)) * F32((out_hi - out_lo) / span) + F32(out_lo)
    h, w = lum.shape
    sigma = 0.9 + 0.8 * rng.random() + 0.7 * detail          # grey levels
    shared = _blur3(rng.standard_normal((h, w), dtype=F32))
    indiv = _blur3(rng.standard_normal((h, w, 3), dtype=F32))
    grain = shared[..., None] * F32(0.75) + indiv * F32(0.5)
    grain *= F32(sigma / max(float(grain.std()), 1e-6))
    l01 = np.clip((lum - F32(lo)) / F32(span), 0.0, 1.0)
    grain *= (F32(0.65) + F32(1.4) * l01 * (1 - l01))[..., None]      # strongest in mid-tones
    rgb = np.clip(rgb + grain, 4.0, 251.0)
    if mode == "L":
        g = rgb @ np.array([0.299, 0.587, 0.114], dtype=F32)
        return np.ascontiguousarray(np.rint(g).astype(np.uint8)), round(sigma, 3)
    return np.ascontiguousarray(np.rint(rgb).astype(np.uint8)), round(sigma, 3)


def choose_family(rng, enabled=FAMILIES):
    return enabled[int(rng.integers(0, len(enabled)))]


def generate(seed, width, height, mode="RGB", family=None, enabled=FAMILIES, detail_bias=0.0):
    """Generate one cover. `seed` is bytes (16 from os.urandom in production). Returns (array, info).

    `detail_bias` in [0, 1] shifts the fine-detail parameter upward within the family's normal range
    (used for a second candidate after a capacity failure). It is not a function of the payload size.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) < 8:
        raise StegoError("COVER_GENERATION_FAILED", "seed must be at least 8 bytes")
    if mode not in MODES or not all(f in FAMILIES for f in enabled) or not enabled:
        raise StegoError("GENERATOR_CONFIG_INVALID", "unknown mode or family")
    if family is not None and family not in enabled:
        raise StegoError("GENERATOR_CONFIG_INVALID", "family is not enabled")
    t0 = time.perf_counter()
    rng = np.random.default_rng(int.from_bytes(hashlib.sha256(b"IOD-COVER-GEN-v1" + bytes(seed)).digest(), "big"))
    fam = family or choose_family(rng, tuple(enabled))
    detail = float(min(1.0, max(0.0, detail_bias + (1.0 - detail_bias) * rng.random())))
    try:
        rgb, params = _FAMILY_FN[fam](rng, int(height), int(width), detail)
        arr, sigma = _finish(rng, rgb, detail, mode)
    except StegoError:
        raise
    except (MemoryError, ValueError, FloatingPointError) as exc:
        raise StegoError("COVER_GENERATION_FAILED", "generator failed", {"family": fam, "reason": type(exc).__name__}) from exc
    params.update(detail=round(detail, 3), grain_sigma=sigma)
    info = {"generator_version": GENERATOR_VERSION, "family": fam, "width": int(width), "height": int(height), "mode": mode,
            "channels": 1 if mode == "L" else 3, "seed_fingerprint": seed_fingerprint(seed), "params": params,
            "generate_ms": round((time.perf_counter() - t0) * 1000.0, 3)}
    return arr, info
