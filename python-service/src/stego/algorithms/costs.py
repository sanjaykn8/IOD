"""Additive embedding-cost maps for the content-adaptive algorithms.

WOW (Holub & Fridrich, "Designing steganographic distortion using directional filters",
IEEE WIFS 2012, doi:10.1109/WIFS.2012.6412655):
    R_k  = K_k * X                       (k = 1..3, directional wavelet filters)
    xi_k = |R_k| * |K_k rotated 180|      (embedding suitability)
    rho  = (sum_k xi_k^p)^(-1/p),  p = -1   =>  rho = 1 / (sum_k 1/xi_k) ... with p=-1:
           (xi_1^-1 + xi_2^-1 + xi_3^-1)^(1)
S-UNIWARD (Holub, Fridrich & Denemark, EURASIP J. Inf. Secur. 2014, doi:10.1186/1687-417X-2014-1):
    rho  = sum_k ( 1 / (sigma + |K_k * X|) ) * |K_k rotated 180|,   sigma = 1 (spatial)
    (the additive approximation of D(X,Y) = sum_k sum_uv |W_k(X)-W_k(Y)| / (sigma + |W_k(X)|))
Both use the 16-tap Daubechies-8 decomposition filters (db8; coefficients identical to
PyWavelets' Wavelet('db8').dec_hi) and the three 2-D filters
    K1 = lpdf^T hpdf (LH), K2 = hpdf^T lpdf (HL), K3 = hpdf^T hpdf (HH),
computed on the cover after symmetric padding by 16 samples, with zero-padded 'same'
convolution (MATLAB conv2 convention, centre offset floor(L/2)) for the residuals and its
exact adjoint for the aggregation step ("* |K rotated|"), so that for S-UNIWARD rho_ij equals
D(X, X +/- e_ij) exactly (MATLAB's conv2 'same' with an even 16-tap kernel shifts that map by
one pixel). Costs above WET (or NaN) are set to WET = 1e10.

HUGO (Pevny, Filler & Bas, Information Hiding 2010, doi:10.1007/978-3-642-16435-4_13):
    D(X,Y) = sum_{d1,d2,d3 in [-T,T]} w(d1,d2,d3) * ( |sum_{k in {->,<-,v,^}} (C^X_k - C^Y_k)(d)|
                                                    + |sum_{k in 4 diagonals} (C^X_k - C^Y_k)(d)| )
    w(d) = 1 / (sqrt(d1^2 + d2^2 + d3^2) + sigma)^gamma,  T = 90, sigma = 1, gamma = 1
    C_k(d) = co-occurrence count of triples of consecutive pixel differences (truncated to
    [-T, T]) along direction k.
    This module computes the EXACT single-change cost rho_i^(+/-) = D(X, X +/- e_i) for every
    requested element (all triples touching pixel i, with cancellation inside each direction
    group), i.e. the additive single-change approximation used to drive STC. No model
    correction / Gibbs re-sweeps are performed (see hugo.py).
"""

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

WET = 1e10

# Daubechies-8 (16-tap) high-pass decomposition filter
HPDF = np.array([
    -0.0544158422, 0.3128715909, -0.6756307363, 0.5853546837, 0.0158291053, -0.2840155430,
    -0.0004724846, 0.1287474266, 0.0173693010, -0.0440882539, -0.0139810279, 0.0087460940,
    0.0048703530, -0.0003917404, -0.0006754494, -0.0001174768])
LPDF = ((-1.0) ** np.arange(16)) * HPDF[::-1]
# separable 2-D filters as (vertical 1-D filter, horizontal 1-D filter): K[i, j] = v[i] * h[j]
FILTERS = {"LH": (LPDF, HPDF), "HL": (HPDF, LPDF), "HH": (HPDF, HPDF)}
PAD = 16
SIGMA_UNIWARD = 1.0
WOW_P = -1.0


def conv1d_same(x, f, axis):
    """Zero-padded 'same' 1-D convolution along axis (MATLAB conv2 'same' centring):
    out[n] = sum_t f[t] * x[n + floor(L/2) - t], with x = 0 outside the array."""
    L = f.size
    s = L // 2
    x = np.moveaxis(np.asarray(x, dtype=np.float64), axis, -1)
    n = x.shape[-1]
    off = L - 1 - s
    xp = np.zeros(x.shape[:-1] + (n + L - 1,))
    xp[..., off:off + n] = x
    out = sliding_window_view(xp, L, axis=-1)[..., :n, :] @ f[::-1]
    return np.moveaxis(out, -1, axis)


def conv2_same(x, v, h):
    return conv1d_same(conv1d_same(x, v, 0), h, 1)


def adjoint1d_same(g, f, axis):
    """Adjoint of conv1d_same: out[p] = sum_t f[t] * g[p - floor(L/2) + t].

    out[p] is exactly how much a unit impulse at p contributes through `f`, i.e. the cost
    aggregation sum_n |K(n - p)| g(n) of UNIWARD/WOW for a change at p. (MATLAB's
    conv2(g, rot90(|K|,2), 'same') equals this shifted by one sample for even-length
    kernels; we use the exactly aligned form, verified against direct D(X, X+e) in tests.)"""
    L = f.size
    s = L // 2
    g = np.moveaxis(np.asarray(g, dtype=np.float64), axis, -1)
    n = g.shape[-1]
    xp = np.zeros(g.shape[:-1] + (n + L - 1,))
    xp[..., s:s + n] = g
    out = sliding_window_view(xp, L, axis=-1)[..., :n, :] @ f
    return np.moveaxis(out, -1, axis)


def adjoint2_same(g, v, h):
    return adjoint1d_same(adjoint1d_same(g, v, 0), h, 1)


def _padded(plane):
    return np.pad(plane.astype(np.float64), PAD, mode="symmetric")


def _crop(a):
    return a[PAD:-PAD, PAD:-PAD]


def residuals(plane):
    xp = _padded(plane)
    return {k: conv2_same(xp, v, h) for k, (v, h) in FILTERS.items()}


def _finish(rho):
    rho = np.where(np.isnan(rho) | (rho > WET), WET, rho)
    return rho


def wow_plane(plane, detail=False):
    res = residuals(plane)
    xis = {}
    for k, (v, h) in FILTERS.items():
        xis[k] = adjoint2_same(np.abs(res[k]), np.abs(v), np.abs(h))
    with np.errstate(divide="ignore", invalid="ignore"):
        acc = sum(xi ** WOW_P for xi in xis.values())
        rho = acc ** (-1.0 / WOW_P)
    rho = _finish(_crop(rho))
    if detail:
        return rho, {k: _crop(r) for k, r in res.items()}, {k: _crop(x) for k, x in xis.items()}
    return rho


def uniward_plane(plane, sigma=SIGMA_UNIWARD, detail=False):
    res = residuals(plane)
    parts = {}
    for k, (v, h) in FILTERS.items():
        parts[k] = adjoint2_same(1.0 / (sigma + np.abs(res[k])), np.abs(v), np.abs(h))
    rho = _finish(_crop(sum(parts.values())))
    if detail:
        return rho, {k: _crop(r) for k, r in res.items()}, {k: _crop(p) for k, p in parts.items()}
    return rho


def per_sample(img, fn):
    """Apply a plane cost function to every channel; returns costs with img's shape."""
    if img.ndim == 2:
        return fn(img)
    return np.stack([fn(img[:, :, c]) for c in range(3)], axis=-1)


# ---------------------------------------------------------------- HUGO
HUGO_T = 90
HUGO_SIGMA = 1.0
HUGO_GAMMA = 1.0
_DIRS_HV = [(0, 1), (1, 0)]
_DIRS_DIAG = [(1, 1), (1, -1)]


def hugo_weight(d1, d2, d3, sigma=HUGO_SIGMA, gamma=HUGO_GAMMA):
    return 1.0 / (np.sqrt(d1 * d1 + d2 * d2 + d3 * d3) + sigma) ** gamma


def _group_entries(plane, rows, cols, delta, dirs, T):
    """Triples touching (rows, cols) before and after adding delta.

    Returns codes (k, E), weights (k, E), signs (k, E), valid (k, E) for E = len(dirs)*2*4*2
    entries (2 orientations x 4 window positions x {old,new}).
    """
    H, W = plane.shape
    k = rows.size
    codes, wts, sgn, val = [], [], [], []
    P = plane.astype(np.int64)
    base = 2 * T + 1
    for (dr, dc) in dirs:
        for pos in range(4):  # pixel is p_pos of the 4-pixel window
            r0 = rows - pos * dr
            c0 = cols - pos * dc
            rr = r0[:, None] + np.arange(4)[None, :] * dr
            cc = c0[:, None] + np.arange(4)[None, :] * dc
            inside = (rr >= 0).all(1) & (rr < H).all(1) & (cc >= 0).all(1) & (cc < W).all(1)
            rrc = np.clip(rr, 0, H - 1)
            ccc = np.clip(cc, 0, W - 1)
            win = P[rrc, ccc]
            for new in (False, True):
                w4 = win.copy()
                if new:
                    w4[:, pos] += delta
                d = np.clip(w4[:, :3] - w4[:, 1:], -T, T)  # forward differences d1,d2,d3
                for orient in (0, 1):
                    if orient == 0:
                        t1, t2, t3 = d[:, 0], d[:, 1], d[:, 2]
                    else:  # opposite direction: reversed window -> (-d3, -d2, -d1)
                        t1, t2, t3 = -d[:, 2], -d[:, 1], -d[:, 0]
                    codes.append(((t1 + T) * base + (t2 + T)) * base + (t3 + T))
                    wts.append(hugo_weight(t1.astype(np.float64), t2.astype(np.float64), t3.astype(np.float64)))
                    sgn.append(np.full(k, 1 if new else -1, dtype=np.int64))
                    val.append(inside)
    return (np.stack(codes, 1), np.stack(wts, 1), np.stack(sgn, 1), np.stack(val, 1))


def _net_weighted_abs(codes, wts, sgn, val):
    """sum over distinct bins of w(bin) * |sum of signs in bin| (row-wise)."""
    sgn = np.where(val, sgn, 0)
    order = np.argsort(codes, axis=1, kind="stable")
    c = np.take_along_axis(codes, order, 1)
    s = np.take_along_axis(sgn, order, 1)
    w = np.take_along_axis(wts, order, 1)
    E = c.shape[1]
    cs = np.cumsum(s, axis=1)
    end = np.ones_like(c, dtype=bool)
    end[:, :-1] = c[:, 1:] != c[:, :-1]
    # cumulative sum at the previous segment end (0 before the first segment)
    idx = np.where(end, np.arange(E)[None, :], -1)
    prev_end = np.maximum.accumulate(np.concatenate([np.full((c.shape[0], 1), -1), idx[:, :-1]], 1), axis=1)
    prev_cs = np.where(prev_end >= 0, np.take_along_axis(cs, np.maximum(prev_end, 0), 1), 0)
    net = np.where(end, cs - prev_cs, 0)
    return (w * np.abs(net)).sum(axis=1)


def hugo_costs(plane, rows, cols, T=HUGO_T):
    """Exact HUGO single-change costs (rho_plus, rho_minus) for the given pixel positions.

    A change that would leave [0, 255] gets cost inf.
    """
    out = []
    for delta in (1, -1):
        total = np.zeros(rows.size)
        for dirs in (_DIRS_HV, _DIRS_DIAG):
            total += _net_weighted_abs(*_group_entries(plane, rows, cols, delta, dirs, T))
        v = plane[rows, cols].astype(np.int64)
        bad = (v + delta < 0) | (v + delta > 255)
        out.append(np.where(bad, np.inf, total))
    return out[0], out[1]


def hugo_distortion(x, y, T=HUGO_T):
    """Full (non-additive) HUGO distortion D(X, Y) between two planes; used by tests/workbench."""
    def cooc(p, dirs):
        P = p.astype(np.int64)
        H, W = P.shape
        acc = {}
        for (dr, dc) in dirs:
            for r in range(H):
                for c in range(W):
                    rr = [r + i * dr for i in range(4)]
                    cc = [c + i * dc for i in range(4)]
                    if min(rr) < 0 or max(rr) >= H or min(cc) < 0 or max(cc) >= W:
                        continue
                    v = [P[rr[i], cc[i]] for i in range(4)]
                    d = [int(np.clip(v[i] - v[i + 1], -T, T)) for i in range(3)]
                    for t in ((d[0], d[1], d[2]), (-d[2], -d[1], -d[0])):
                        acc[t] = acc.get(t, 0) + 1
        return acc
    total = 0.0
    for dirs in (_DIRS_HV, _DIRS_DIAG):
        cx, cy = cooc(x, dirs), cooc(y, dirs)
        for t in set(cx) | set(cy):
            diff = cx.get(t, 0) - cy.get(t, 0)
            if diff:
                total += float(hugo_weight(*map(float, t))) * abs(diff)
    return total
