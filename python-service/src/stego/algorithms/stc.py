"""Binary syndrome-trellis codes (STC), Filler, Judas & Fridrich 2011 (doi:10.1109/TIFS.2011.2134094).

Parameters (``stc-binary-h7-v1``)
  * constraint height h = 7 (2^7 = 128 trellis states)
  * submatrix H_hat: h x w, columns are h-bit integers drawn from a PCG64 generator seeded
    with SHA-256("IOD-STC-HHAT-v1" | h | w); bit 0 and bit h-1 of every column are forced
    to 1 (so every block can satisfy its syndrome bit). These are NOT the optimised
    submatrices published with the reference implementation, so coding efficiency is
    somewhat lower than the paper's tables (documented coding loss).
  * parity-check matrix H (m x n, n = m*w): H_hat placed along the diagonal, shifted down one
    row per block of w columns; rows beyond m are cropped (the last h-1 blocks use masked columns).
  * embedding: Viterbi search for y minimising sum(rho_i * [y_i != x_i]) subject to H y = msg.
  * extraction: msg = H y (needs only the stego LSBs, h, w and m -- no costs, no cover).
The payload rate is alpha = m / n = 1 / w.
"""

import hashlib
from functools import lru_cache

import numpy as np

from ..errors import StegoError

H_DEFAULT = 7
VARIANT = "stc-binary-h7-v1"


@lru_cache(maxsize=256)
def submatrix(h, w):
    if not 2 <= h <= 12 or not 1 <= w <= 255:
        raise StegoError("INVALID_REQUEST", "invalid STC parameters")
    seed = int.from_bytes(hashlib.sha256(b"IOD-STC-HHAT-v1" + bytes([h, w])).digest()[:8], "big")
    rng = np.random.Generator(np.random.PCG64(seed))
    cols = rng.integers(0, 1 << h, size=w, dtype=np.int64) | 1 | (1 << (h - 1))
    return tuple(int(c) for c in cols)


def syndrome(y, m, w, h=H_DEFAULT):
    """H y for the first m*w elements of y (uint8 0/1)."""
    cols = submatrix(h, w)
    if y.size < m * w:
        raise StegoError("EXTRACT_FAILED", "not enough cover elements for STC extraction")
    yy = (y[: m * w].astype(np.uint8) & 1).reshape(m, w)
    syn = np.zeros(m, dtype=np.uint8)
    for j, c in enumerate(cols):
        for r in range(h):
            if (c >> r) & 1 and r < m:
                syn[r:] ^= yy[: m - r, j]
    return syn


def embed(x, rho, msg, w, h=H_DEFAULT):
    """Viterbi STC embedding.

    x: cover bits (n = m*w,), rho: costs (n,) >= 0 (may be large for 'wet' elements),
    msg: (m,) bits. Returns (y, total_cost). Raises if no finite solution exists.
    """
    msg = np.asarray(msg, dtype=np.uint8)
    m = int(msg.size)
    n = m * w
    if m == 0:
        return np.zeros(0, dtype=np.uint8), 0.0
    if x.size < n or rho.size < n:
        raise StegoError("INVALID_REQUEST", "STC: cover shorter than m*w")
    cols = submatrix(h, w)
    S = 1 << h
    states = np.arange(S, dtype=np.int64)
    perms = {}

    def perm(j, mask):
        key = (j, mask)
        if key not in perms:
            perms[key] = states ^ (cols[j] & mask)
        return perms[key]

    xs = x[:n].astype(np.uint8)
    rs = np.asarray(rho[:n], dtype=np.float64)
    inf = np.inf
    wght = np.full(S, inf)
    wght[0] = 0.0
    path = np.zeros((n, S), dtype=bool)
    idx = 0
    half = np.full(S // 2, inf)
    for i in range(m):
        mask = (1 << min(h, m - i)) - 1
        for j in range(w):
            r = rs[idx]
            if xs[idx]:
                w0 = wght + r
                w1 = wght[perm(j, mask)]
            else:
                w0 = wght
                w1 = wght[perm(j, mask)] + r
            sel = w1 < w0
            path[idx] = sel
            wght = np.where(sel, w1, w0)
            idx += 1
        wght = np.concatenate([wght[msg[i]::2], half])
    cost = float(wght[0])
    if not np.isfinite(cost):
        raise StegoError("ENCODE_VERIFY_FAILED", "STC: no finite-cost solution")
    y = np.zeros(n, dtype=np.uint8)
    state = 0
    idx = n - 1
    for i in range(m - 1, -1, -1):
        state = 2 * state + int(msg[i])
        mask = (1 << min(h, m - i)) - 1
        for j in range(w - 1, -1, -1):
            bit = path[idx, state]
            y[idx] = bit
            if bit:
                state ^= cols[j] & mask
            idx -= 1
    return y, cost
