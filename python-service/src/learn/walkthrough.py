"""Deterministic, step-by-step worked calculations for all ten algorithms (EDUCATIONAL).

Every number shown is produced by code in this file from the fixed fixtures, and the
arithmetic reuses the operational low-level helpers (no second implementation of any rule).
Each walkthrough ends with an extraction from the modified values and an exact-match check.

Differences between a walkthrough and the runtime transport are stated in `runtime_link`
(the runtime skips the 128 bootstrap samples / block rows, works on whole images, and uses
STC h = 7, which is too large to show by hand).
"""

import numpy as np

from stego.algorithms import adaptive, costs as K, dct as DCT, dct_svd as DS, dwt as D, lsb_matching, pvd as PVD, stc
from stego.algorithms import blocks as B
from stego.algorithms.edge_adaptive import edge_mask

from . import fixtures as F

SYN = F.SYNTHETIC_CIPHERTEXT


def _r(x, d=4):
    if isinstance(x, (list, tuple)):
        return [_r(v, d) for v in x]
    if isinstance(x, np.ndarray):
        return _r(x.tolist(), d)
    if isinstance(x, (bool, np.bool_)):
        return bool(x)
    if isinstance(x, (int, np.integer)):
        return int(x)
    v = float(x)
    if not np.isfinite(v):
        return "inf" if v > 0 else "-inf"
    return round(v, d)


def _bits_str(bits):
    return "".join(str(int(b)) for b in bits)


def _byte_of(bits):
    return int("".join(str(int(b)) for b in bits[:8]), 2)


class _W:
    def __init__(self, name, title, variant, teaching_model=False, simplification=None):
        self.d = {"algorithm": name, "title": title, "runtime_variant": variant, "teaching_model": teaching_model,
                  "simplification": simplification, "bit_order": F.BIT_ORDER, "inputs": {}, "steps": [], "checks": []}

    def inp(self, **kw):
        self.d["inputs"].update({k: _r(v) if not isinstance(v, str) else v for k, v in kw.items()})

    def step(self, title, formula, substitution, result, table=None, matrix=None, note=None):
        s = {"n": len(self.d["steps"]) + 1, "title": title, "formula": formula,
             "substitution": substitution, "result": result}
        if table is not None:
            s["table"] = table
        if matrix is not None:
            s["matrices"] = matrix
        if note:
            s["note"] = note
        self.d["steps"].append(s)

    def check(self, name, passed):
        self.d["checks"].append({"name": name, "passed": bool(passed)})

    def done(self, embedded_bits, recovered_bits, runtime_link):
        ok = list(map(int, embedded_bits)) == list(map(int, recovered_bits))
        self.check("recovered bits equal embedded bits", ok)
        self.d.update(embedded_bits=_bits_str(embedded_bits), recovered_bits=_bits_str(recovered_bits),
                      exact_match=ok, all_checks_passed=all(c["passed"] for c in self.d["checks"]),
                      runtime_link=runtime_link)
        return self.d


def _payload_step(w, nbits):
    bits = F.bits_of(SYN)[:nbits]
    w.step("Payload bits", "bits = MSB-first expansion of the synthetic fixture bytes",
           "A6 3C 91 5E -> " + " ".join(format(b, "08b") for b in SYN),
           f"first {nbits} bits used here: {_bits_str(bits)}",
           note=F.SYNTHETIC_LABEL)
    return bits


# ------------------------------------------------------------------ 1 LSB replacement
def lsb_replacement():
    w = _W("lsb_replacement", "LSB replacement", "lsb-replacement-msb-first-v1")
    px = F.HAND_MATRIX[0, :8].astype(int)
    w.inp(cover_pixels=px, source="row 0 of the 8x8 hand matrix")
    bits = _payload_step(w, 8)
    new = [(int(p) & 0xFE) | b for p, b in zip(px, bits)]
    rows = [[i, int(p), format(int(p), "08b"), b, n, format(n, "08b"), n - int(p)] for i, (p, b, n) in enumerate(zip(px, bits, new))]
    w.step("Replace each least significant bit", "p' = (p AND 11111110b) OR b",
           f"e.g. p0 = {px[0]} = {format(int(px[0]), '08b')}b, b0 = {bits[0]} -> {format(new[0], '08b')}b = {new[0]}",
           f"stego pixels = {new}",
           table={"columns": ["i", "p", "p (bin)", "b", "p'", "p' (bin)", "change"], "rows": rows})
    changed = sum(1 for p, n in zip(px, new) if p != n)
    w.step("Distortion", "change_i = p'_i - p_i in {-1, 0, +1}", f"changed pixels: {changed} of 8",
           f"MSE over these 8 samples = {_r(np.mean((np.array(new) - px) ** 2))}")
    rec = [n & 1 for n in new]
    w.step("Extraction", "b_i = p'_i mod 2", " ".join(f"{n} mod 2 = {n & 1}" for n in new),
           f"bits {_bits_str(rec)} -> byte 0x{_byte_of(rec):02X}")
    return w.done(bits, rec, "Runtime: same rule on every sample after the 128 bootstrap samples, MSB-first.")


# ------------------------------------------------------------------ 2 LSB matching
def lsb_matching_wt():
    w = _W("lsb_matching", "LSB matching (+/-1)", "lsb-matching-pm1-seeded-v1")
    px = F.HAND_MATRIX[0, :8].copy()
    w.inp(cover_pixels=px)
    bits = _payload_step(w, 8)
    seed = lsb_matching._seed(px)
    coin = np.random.Generator(np.random.PCG64(seed)).integers(0, 2, size=8, dtype=np.uint8)
    w.step("Direction stream", "coin_i from PCG64(seed), seed = first 8 bytes of SHA-256(cover || 'LSBM-v1')",
           f"seed = {seed}", f"coins = {list(map(int, coin))} (1 -> +1, 0 -> -1)")
    rows, new = [], []
    for i, (p, b, c) in enumerate(zip(px.astype(int), bits, coin)):
        if (p & 1) == b:
            n, why = p, "LSB already equals b: unchanged"
        else:
            step = 1 if c == 1 else -1
            if p == 0:
                step = 1
            if p == 255:
                step = -1
            n, why = p + step, f"mismatch: p {'+' if step > 0 else '-'} 1"
        new.append(int(n))
        rows.append([i, int(p), int(p & 1), b, int(c), n, why])
    w.step("Change only mismatching pixels by +/-1", "p' = p if p mod 2 = b, else p + s (s = +1/-1 from the coin; 0 -> +1, 255 -> -1)",
           f"p0 = {px[0]}, LSB {int(px[0]) & 1}, b0 = {bits[0]}", f"stego pixels = {new}",
           table={"columns": ["i", "p", "LSB", "b", "coin", "p'", "decision"], "rows": rows})
    rec = [n & 1 for n in new]
    w.step("Extraction", "b_i = p'_i mod 2", " ".join(str(n & 1) for n in new), f"bits {_bits_str(rec)} -> 0x{_byte_of(rec):02X}")
    w.check("every change is +/-1", all(abs(a - int(b)) <= 1 for a, b in zip(new, px)))
    return w.done(bits, rec, "Runtime: seed from the whole cover image, applied after the bootstrap samples.")


# ------------------------------------------------------------------ 3 PVD
def pvd_wt():
    w = _W("pvd", "Pixel-value differencing (Wu-Tsai)", "wu-tsai-pvd-6range-v1")
    flat = F.HAND_MATRIX.reshape(-1)[8:].astype(np.int64)  # start at row 1
    bits = _payload_step(w, 16)
    w.step("Range table", "ranges [l_k, u_k] with n_k bits", "[0,7]:3  [8,15]:3  [16,31]:4  [32,63]:5  [64,127]:6  [128,255]:7",
           "a pair whose |a-b| lies in range k carries n_k bits")
    pos, rows, pairs_new = 0, [], []
    k = 0
    padded = list(bits) + [0] * 8
    while pos < len(bits):
        a, b = int(flat[2 * k]), int(flat[2 * k + 1])
        d = abs(a - b)
        ri = int(PVD.range_index(np.array([d]))[0])
        n = int(PVD.NBITS[ri])
        chunk = padded[pos:pos + n]
        v = int(_bits_str(chunk), 2)
        dn = int(PVD.LOWER[ri]) + v
        t = dn if a >= b else -dn
        delta = t - (a - b)
        an = a + (-((-delta) // 2))
        an = int(np.clip(an, max(0, t), min(255, 255 + t)))
        bn = an - t
        rows.append([k, a, b, d, f"[{int(PVD.LOWER[ri])},{int(PVD.LOWER[ri]) + (1 << n) - 1}]", n, _bits_str(chunk), v, dn, an, bn])
        pairs_new.append((an, bn, ri, n))
        pos += n
        k += 1
    w.step("Embed into pixel pairs", "d = |a-b|; v = next n bits; d' = l + v; keep the sign of a-b; a' = a + ceil((t-(a-b))/2), b' = a' - t",
           f"pair 0: a={rows[0][1]}, b={rows[0][2]}, d={rows[0][3]} in {rows[0][4]} -> n={rows[0][5]}, v={rows[0][7]}, d'={rows[0][8]}",
           f"{k} pairs used; the last pair is zero-padded if bits run out",
           table={"columns": ["pair", "a", "b", "d", "range", "n", "bits", "v", "d'", "a'", "b'"], "rows": rows})
    rec = []
    for an, bn, _, _ in pairs_new:
        d = abs(an - bn)
        ri = int(PVD.range_index(np.array([d]))[0])
        n = int(PVD.NBITS[ri])
        rec += [int(c) for c in format(d - int(PVD.LOWER[ri]), f"0{n}b")]
    w.step("Extraction", "d'' = |a'-b'|; same range table; bits = binary(d'' - l, n bits)",
           ", ".join(f"|{an}-{bn}|={abs(an - bn)}" for an, bn, _, _ in pairs_new), f"bits {_bits_str(rec[:16])}")
    w.check("range of every new difference equals the original range",
            all(int(PVD.range_index(np.array([abs(an - bn)]))[0]) == ri for an, bn, ri, _ in pairs_new))
    return w.done(bits, rec[:16], "Runtime: identical arithmetic on consecutive sample pairs after the bootstrap samples.")


# ------------------------------------------------------------------ 4 edge-adaptive LSB
def edge_wt():
    w = _W("edge_adaptive_lsb", "Edge-adaptive LSB", "edge-mask-7msb-grad-threshold-v1")
    M = F.HAND_MATRIX
    bits = _payload_step(w, 8)
    g = (M >> 1).astype(int)
    grad = np.zeros_like(g)
    grad[:, :-1] += np.abs(np.diff(g, axis=1))
    grad[:-1, :] += np.abs(np.diff(g, axis=0))
    mask = edge_mask(M, 6)
    w.step("7-MSB image", "g = floor(p / 2) (the LSB is ignored so the mask is identical after embedding)",
           f"g[0,0] = floor({M[0, 0]}/2) = {g[0, 0]}", "8x8 matrix g", matrix={"g": g.tolist()})
    w.step("Gradient and mask", "grad = |g[r,c+1]-g[r,c]| + |g[r+1,c]-g[r,c]|;  eligible if grad >= T, T = 6",
           f"grad[0,0] = |{g[0, 1]}-{g[0, 0]}| + |{g[1, 0]}-{g[0, 0]}| = {grad[0, 0]}",
           f"{int(mask.sum())} of 64 pixels eligible", matrix={"grad": grad.tolist(), "mask": mask.astype(int).tolist()})
    idx = np.flatnonzero(mask.reshape(-1))[:8]
    flat = M.reshape(-1).astype(int).copy()
    rows = []
    for i, (j, b) in enumerate(zip(idx, bits)):
        n = (flat[j] & 0xFE) | b
        rows.append([i, f"({j // 8},{j % 8})", int(flat[j]), b, int(n)])
        flat[j] = n
    st = flat.reshape(8, 8).astype(np.uint8)
    w.step("LSB replacement on eligible pixels (row-major)", "p' = (p AND 0xFE) OR b at the first 8 eligible positions",
           f"first eligible pixel {rows[0][1]} = {rows[0][2]} -> {rows[0][4]}", "stego block computed",
           table={"columns": ["i", "pixel", "p", "b", "p'"], "rows": rows})
    same = np.array_equal(edge_mask(st, 6), mask)
    w.check("receiver rebuilds the same mask from the stego pixels", same)
    rec = [int(v) & 1 for v in st.reshape(-1)[np.flatnonzero(edge_mask(st, 6).reshape(-1))[:8]]]
    w.step("Extraction", "rebuild mask from g' = floor(p'/2) (unchanged), read LSBs at the first 8 eligible positions",
           f"mask identical: {same}", f"bits {_bits_str(rec)} -> 0x{_byte_of(rec):02X}")
    return w.done(bits, rec, "Runtime: RGB uses a luma of the 7-MSB planes; positions before sample 128 are skipped.")


# ------------------------------------------------------------------ 5 DCT
def dct_wt():
    w = _W("dct", "8x8 block DCT, QIM on 6 mid-frequency coefficients", "dct8-midband-6coef-qim-v1")
    M = F.HAND_MATRIX.astype(np.float64)
    delta = 12.0
    bits = _payload_step(w, 6)
    X = DCT._C @ M @ DCT._CT
    w.step("Forward 2-D DCT", "X = C B C^T, C[u,x] = a(u) cos((2x+1)u pi/16), a(0)=sqrt(1/8), a(u>0)=sqrt(2/8)",
           f"X[0,0] = sum(B)/8 = {_r(M.sum() / 8, 3)}", f"X[0,0] = {_r(X[0, 0], 3)}", matrix={"X (rounded)": _r(X, 2)})
    rows, Xn = [], X.copy()
    for (u, v), b in zip(DCT.COEFFS, bits):
        c = X[u, v]
        qr = c / delta
        q = np.rint(qr)
        toward = 1.0 if qr >= q else -1.0
        qn = q if (int(q) & 1) == b else q + toward
        Xn[u, v] = qn * delta
        rows.append([f"({u},{v})", _r(c, 3), _r(qr, 3), int(q), int(q) & 1, b, int(qn), _r(qn * delta, 1)])
    w.step("Quantisation-index modulation", "q = round(X[u,v]/delta); if q mod 2 != b move q one step towards X[u,v]/delta; X'[u,v] = q delta (delta = 12)",
           f"X{rows[0][0]} = {rows[0][1]} -> {rows[0][1]}/12 = {rows[0][2]} -> q = {rows[0][3]} -> q' = {rows[0][6]}",
           "coefficients set", table={"columns": ["(u,v)", "X", "X/delta", "q", "q mod 2", "b", "q'", "X'"], "rows": rows})
    Bn = np.clip(np.rint(DCT._CT @ Xn @ DCT._C), 0, 255)
    got = DCT._read_bits(Bn[None], delta)[0]
    if not np.array_equal(got, bits):  # runtime retry: the other neighbouring index
        w.d.setdefault("notes", []).append("rounding broke a bit; runtime retries the opposite direction")
    w.step("Inverse DCT, round and clip", "B' = clip(round(C^T X' C), 0, 255)", f"B'[0,0] = {int(Bn[0, 0])} (was {int(M[0, 0])})",
           f"max |B'-B| = {int(np.abs(Bn - M).max())}, MSE = {_r(np.mean((Bn - M) ** 2))}",
           matrix={"B'": Bn.astype(int).tolist(), "B' - B": (Bn - M).astype(int).tolist()})
    w.step("Extraction", "re-run the DCT on B', bit = round(X''[u,v]/delta) mod 2",
           ", ".join(f"{p}: {_r((DCT._C @ Bn @ DCT._CT)[p[0], p[1]] / delta, 3)}" for p in DCT.COEFFS),
           f"bits {_bits_str(got)}")
    return w.done(bits, got, "Runtime: blue plane (RGB) or gray, skips block row 0 (bootstrap), retries the other direction on failure.")


# ------------------------------------------------------------------ 6 DWT
def dwt_wt():
    w = _W("dwt", "One-level Haar DWT, QIM on HH", "haar-l1-hh-qim-v1")
    M = F.HAND_MATRIX[:4, :4].astype(np.float64)
    delta = 4.0
    w.inp(cover_block=M.astype(int), delta=delta)
    bits = _payload_step(w, 4)
    blocks = np.array([M[r:r + 2, c:c + 2] for r in (0, 2) for c in (0, 2)])
    co = D.haar_all(blocks)
    w.step("Haar coefficients of each 2x2 block", "LL=(a+b+c+d)/2, HL=(a-b+c-d)/2, LH=(a+b-c-d)/2, HH=(a-b-c+d)/2",
           f"block 0 = [[{int(blocks[0,0,0])},{int(blocks[0,0,1])}],[{int(blocks[0,1,0])},{int(blocks[0,1,1])}]] -> "
           f"HH = ({int(blocks[0,0,0])}-{int(blocks[0,0,1])}-{int(blocks[0,1,0])}+{int(blocks[0,1,1])})/2 = {_r(co['HH'][0], 2)}",
           "four blocks analysed",
           table={"columns": ["block", "a", "b", "c", "d", "LL", "HL", "LH", "HH"],
                  "rows": [[k, *map(int, blocks[k].reshape(-1)), *(_r(co[s][k], 2) for s in ("LL", "HL", "LH", "HH"))] for k in range(4)]})
    cands = B.qim_candidates(co["HH"], delta, np.array(bits), D.CANDIDATES)
    rows, out = [], []
    for k in range(4):
        done = None
        for ci in range(D.CANDIDATES):
            for pat in D.PATTERNS:
                t = D.apply_hh(blocks[k:k + 1], cands[k, ci] * delta, pat)
                if D.read_bits(t, delta)[0] == bits[k]:
                    done = (ci, pat, t[0])
                    break
            if done:
                break
        ci, pat, nb = done
        tgt = cands[k, ci] * delta
        out.append(nb)
        rows.append([k, bits[k], _r(co["HH"][k], 2), int(cands[k, ci]), _r(tgt, 1), _r((tgt - co["HH"][k]) / 2, 2), pat,
                     str(nb.astype(int).tolist()), _r(D.haar_hh(nb[None])[0], 2)])
    w.step("Move HH to the nearest index of the right parity", "q: q mod 2 = b, minimal |q delta - HH|; e = (q delta - HH)/2; a'=a+e, b'=b-e, c'=c-e, d'=d+e; round",
           f"block 0: HH = {rows[0][2]}, b = {rows[0][1]} -> q = {rows[0][3]}, target {rows[0][4]}, e = {rows[0][5]}",
           "all four blocks modified", table={"columns": ["block", "b", "HH", "q", "target", "e", "pattern", "new pixels", "HH after rounding"], "rows": rows})
    rec = [int(D.read_bits(nb[None], delta)[0]) for nb in out]
    w.step("Extraction", "bit = round(HH'/delta) mod 2", ", ".join(f"round({r[8]}/4) mod 2 = {b}" for r, b in zip(rows, rec)),
           f"bits {_bits_str(rec)}")
    w.check("rounding moved HH by at most 1", all(abs(r[8] - r[4]) <= 1.0 + 1e-9 for r in rows))
    return w.done(bits, rec, "Runtime: whole plane in 2x2 blocks, skipping block rows that contain bootstrap samples; up to 8 indices x 11 patterns near 0/255.")


# ------------------------------------------------------------------ 7 DCT-SVD
def dct_svd_wt():
    w = _W("dct_svd", "Block DCT + SVD, QIM on the largest singular value", "dct8-svd-s1-qim-v1")
    delta = 16.0
    bits = _payload_step(w, 2)
    blocks = [F.HAND_MATRIX.astype(np.float64), F.HAND_MATRIX.T.astype(np.float64)]
    w.inp(blocks="block 0 = hand matrix, block 1 = its transpose", delta=delta, region="X[1:5,1:5]")
    rec = []
    for k, (blk, b) in enumerate(zip(blocks, bits)):
        x, u, sv, vt = DS.sub_svd(blk[None])
        S = x[0, 1:5, 1:5]
        w.step(f"Block {k}: DCT and sub-matrix", "X = C B C^T; S = X[1:5, 1:5] (4x4, no DC row/column)",
               f"S[0,0] = X[1,1] = {_r(S[0, 0], 3)}", "S extracted", matrix={"S": _r(S, 3)})
        w.step(f"Block {k}: SVD", "S = U diag(s1,s2,s3,s4) V^T", f"s = {_r(sv[0], 4)}", f"s1 = {_r(sv[0, 0], 4)}",
               matrix={"U": _r(u[0], 4), "Sigma": _r(np.diag(sv[0]), 4), "V^T": _r(vt[0], 4)})
        cands = B.qim_candidates(sv[:, 0], delta, np.array([b]), DS.CANDIDATES, nonnegative=True)[0]
        chosen = None
        for q in cands:
            nb = DS.rebuild(x, u, sv, vt, np.array([q * delta]))
            if DS.read_bits(nb, delta)[0] == b:
                chosen = (int(q), nb[0])
                break
        q, nb = chosen
        w.step(f"Block {k}: quantise s1", "s1' = q delta, q >= 0, q mod 2 = b, minimal |s1' - s1| (delta = 16)",
               f"s1/delta = {_r(sv[0, 0] / delta, 4)}, b = {b} -> q = {q} -> s1' = {q * delta}",
               f"change in s1 = {_r(q * delta - sv[0, 0], 4)}")
        s1b = DS.read_s1(nb[None])[0]
        w.step(f"Block {k}: reconstruct, inverse DCT, round", "S' = U diag(s1',s2,s3,s4) V^T; B' = clip(round(C^T X' C))",
               f"recomputed s1 from rounded B' = {_r(s1b, 4)} (target {q * delta})",
               f"max |B'-B| = {int(np.abs(nb - blk).max())}", matrix={"B' - B": (nb - blk).astype(int).tolist()})
        got = int(DS.read_bits(nb[None], delta)[0])
        w.step(f"Block {k}: extraction", "bit = round(s1(B')/delta) mod 2", f"round({_r(s1b, 4)}/16) = {int(np.rint(s1b / delta))}",
               f"bit = {got}")
        rec.append(got)
    return w.done(bits, rec, "Runtime: one bit per 8x8 block over the plane, skipping bootstrap rows, verified with up to 8 candidates.")


# ------------------------------------------------------------------ mini STC (shared by HUGO/WOW/S-UNIWARD)
def _mini_stc(w, x_bits, rho, msg, signs=None, label="rho"):
    h, ww = 2, 4
    m = len(msg)
    cols = stc.submatrix(h, ww)
    H = np.zeros((m, m * ww), dtype=int)
    for i in range(m):
        for j, c in enumerate(cols):
            for r in range(h):
                if (c >> r) & 1 and i + r < m:
                    H[i + r, i * ww + j] = 1
    w.step("Teaching STC code (h = 2, w = 4)", "H_hat columns from SHA-256-seeded PCG64; H = H_hat stacked along the diagonal",
           f"H_hat columns (bit0 = top row) = {list(cols)}", f"H ({m}x{m * ww}) shown", matrix={"H": H.tolist()},
           note="The runtime uses h = 7 (128 trellis states); h = 2 keeps the trellis small enough to read.")
    y, cost = stc.embed(np.array(x_bits, np.uint8), np.array(rho, float), np.array(msg, np.uint8), ww, h)
    syn = stc.syndrome(y, m, ww, h)
    changed = [i for i in range(len(x_bits)) if y[i] != x_bits[i]]
    w.step("Viterbi search for the cheapest y with H y = m",
           "minimise sum(rho_i [y_i != x_i]) subject to H y = m (mod 2)",
           f"x = {_bits_str(x_bits)}, m = {_bits_str(msg)}, {label} = {_r(rho, 3)}",
           f"y = {_bits_str(y)}, changed elements {changed}, total cost {_r(cost, 4)}",
           table={"columns": ["i", "x", label, "y", "changed"], "rows": [[i, int(x_bits[i]), _r(rho[i], 4), int(y[i]), int(y[i] != x_bits[i])] for i in range(len(x_bits))]})
    w.step("Extraction (receiver)", "m = H y' with y' = LSBs of the stego elements (no costs needed)",
           " + ".join(f"row{r}: {_bits_str(H[r])}" for r in range(m)), f"H y = {_bits_str(syn)}")
    return y, list(map(int, syn)), changed


# ------------------------------------------------------------------ 8 HUGO
def hugo_wt():
    w = _W("hugo", "HUGO (teaching model)", adaptive.Hugo.variant, teaching_model=True,
           simplification=("Miniature illustration: the hand calculation evaluates only the horizontal triples of one pixel "
                           "on an 8x8 patch; the exact cost (all 8 directions, grouped, with cancellation) is then taken "
                           "from the runtime function and checked against a brute-force evaluation of the full HUGO "
                           "distortion on the patch. It does not reproduce HUGO's high-dimensional model over a whole "
                           "image, its model-correction sweeps or the h = 7 STC."))
    P = F.HAND_MATRIX
    r0, c0 = 3, 3
    T = K.HUGO_T
    row = P[r0].astype(int)
    w.inp(patch="8x8 hand matrix", pixel=f"({r0},{c0}) = {int(P[r0, c0])}", T=T, sigma=K.HUGO_SIGMA, gamma=K.HUGO_GAMMA)
    w.step("Weight function", "w(d1,d2,d3) = 1 / (sqrt(d1^2+d2^2+d3^2) + sigma)^gamma, differences truncated to [-T, T]",
           f"T = {T}, sigma = {K.HUGO_SIGMA}, gamma = {K.HUGO_GAMMA}", "small differences (smooth content) weigh most")
    rows, tot = [], 0.0
    for s in range(max(0, c0 - 3), min(c0, 4) + 1):
        win = row[s:s + 4].copy()
        d_old = np.clip(win[:3] - win[1:], -T, T)
        win2 = win.copy()
        win2[c0 - s] += 1
        d_new = np.clip(win2[:3] - win2[1:], -T, T)
        wo = float(K.hugo_weight(*map(float, d_old)))
        wn = float(K.hugo_weight(*map(float, d_new)))
        rows.append([f"cols {s}..{s + 3}", str(win.tolist()), str(d_old.tolist()), _r(wo, 4), str(d_new.tolist()), _r(wn, 4), _r(wo + wn, 4)])
        tot += wo + wn
    w.step("Horizontal triples touching the pixel (forward direction, change +1)",
           "each window of 4 pixels gives (d1,d2,d3) = (p0-p1, p1-p2, p2-p3); a change removes the old triple and adds the new one",
           f"row {r0} = {row.tolist()}", f"sum of w(old)+w(new) over these windows = {_r(tot, 4)} (bound before cancellation)",
           table={"columns": ["window", "pixels", "d old", "w old", "d new", "w new", "w old + w new"], "rows": rows})
    rp, rm = K.hugo_costs(P, np.array([r0]), np.array([c0]))
    y = P.astype(np.int64)
    y[r0, c0] += 1
    brute = K.hugo_distortion(P, y)
    w.step("Exact single-change cost (all directions)",
           "rho+ = D(X, X + e) = sum_bins w(bin) (|sum_{H,V dirs} dC| + |sum_{diag dirs} dC|)",
           f"runtime hugo_costs: rho+ = {_r(rp[0], 6)}, rho- = {_r(rm[0], 6)}; brute-force D(X, X+e) = {_r(brute, 6)}",
           f"rho = min(rho+, rho-) = {_r(min(rp[0], rm[0]), 6)}, direction {'+1' if rp[0] <= rm[0] else '-1'}")
    w.check("runtime cost equals brute-force HUGO distortion", abs(rp[0] - brute) < 1e-9)
    rr, cc = np.repeat(np.arange(8), 8), np.tile(np.arange(8), 8)
    a, b = K.hugo_costs(P, rr, cc)
    rho_map = np.minimum(a, b).reshape(8, 8)
    w.step("Cost map of the patch", "rho_ij = min(rho+_ij, rho-_ij)", "computed for all 64 pixels",
           f"min {_r(rho_map.min(), 3)}, max {_r(rho_map.max(), 3)}", matrix={"rho": _r(rho_map, 3)})
    xs = [int(v) & 1 for v in P[r0]]
    msg = F.bits_of(SYN)[:2]
    y_bits, rec, changed = _mini_stc(w, xs, rho_map[r0].tolist(), msg)
    w.step("Apply the changes", "changed element i: p' = p + s, s = +1 if rho+ <= rho- else -1",
           ", ".join(f"col {i}: {int(P[r0, i])} -> {int(P[r0, i]) + (1 if a[r0 * 8 + i] <= b[r0 * 8 + i] else -1)}" for i in changed) or "no change needed",
           "LSBs now equal y")
    return w.done(msg, rec, "Runtime: exact costs for every used sample (whole image, 8 directions), binary STC h = 7, rate 1/w with w <= 10 automatically.")


# ------------------------------------------------------------------ 9 WOW
def wow_wt():
    w = _W("wow", "WOW (teaching model)", adaptive.Wow.variant, teaching_model=True,
           simplification=("Reduced illustration: the real WOW formulas and the 16-tap db8 filter bank are evaluated, but "
                           "on an 8x8 patch (after symmetric padding by 16), so padding dominates the numbers; the mini STC "
                           "uses h = 2 instead of 7."))
    P = F.HAND_MATRIX
    r0, c0 = 3, 3
    rho, R, XI = K.wow_plane(P, detail=True)
    w.step("Filter bank", "K1 = l^T h (LH), K2 = h^T l (HL), K3 = h^T h (HH); h = db8 high-pass, l[n] = (-1)^n h[15-n]",
           f"h = {_r(K.HPDF, 6)}", f"l = {_r(K.LPDF, 6)}")
    w.step("Directional residuals at the pixel", "R_k = K_k * X (after symmetric padding)",
           f"pixel ({r0},{c0}) = {int(P[r0, c0])}", ", ".join(f"R_{k} = {_r(R[k][r0, c0], 4)}" for k in R))
    w.step("Embedding suitability", "xi_k = |R_k| * |K_k rotated 180 deg|",
           "convolution of the residual magnitude with the absolute filter", ", ".join(f"xi_{k} = {_r(XI[k][r0, c0], 4)}" for k in XI))
    inv = [1.0 / XI[k][r0, c0] for k in XI]
    w.step("Aggregate with p = -1", "rho = (xi_1^p + xi_2^p + xi_3^p)^(-1/p) = 1/xi_1 + 1/xi_2 + 1/xi_3",
           " + ".join(f"1/{_r(XI[k][r0, c0], 4)}" for k in XI) + " = " + " + ".join(_r(v, 6).__str__() for v in inv),
           f"rho({r0},{c0}) = {_r(rho[r0, c0], 6)}")
    w.check("aggregated cost matches the formula", abs(sum(inv) - rho[r0, c0]) < 1e-9)
    w.step("Cost map of the patch", "low cost = textured in every direction; smooth or clean-edge directions dominate the sum",
           "computed for all 64 pixels", f"min {_r(rho.min(), 4)}, max {_r(rho.max(), 4)}", matrix={"rho": _r(rho, 4)})
    xs = [int(v) & 1 for v in P[r0]]
    msg = F.bits_of(SYN)[:2]
    _, rec, changed = _mini_stc(w, xs, rho[r0].tolist(), msg)
    w.step("Apply the changes", "changed element: +/-1 (sign from the seeded stream; 0 -> +1, 255 -> -1)",
           f"changed columns {changed}", "LSBs now equal y")
    return w.done(msg, rec, "Runtime: cost map over the whole image (per channel), binary STC h = 7, public element permutation.")


# ------------------------------------------------------------------ 10 S-UNIWARD
def uniward_wt():
    w = _W("s_uniward", "S-UNIWARD (teaching model)", adaptive.SUniward.variant, teaching_model=True,
           simplification=("Reduced illustration of the spatial UNIWARD computation on an 8x8 patch (symmetric padding "
                           "by 16 dominates); the additive cost of one pixel is shown to equal the directly computed "
                           "relative wavelet change for that single change. Mini STC with h = 2 instead of 7."))
    P = F.HAND_MATRIX
    r0, c0 = 3, 3
    sigma = K.SIGMA_UNIWARD
    rho, R, parts = K.uniward_plane(P, detail=True)
    w.step("Relative-change distortion", "D(X,Y) = sum_k sum_uv |W_k(X)-W_k(Y)|_uv / (sigma + |W_k(X)|_uv), W_k = K_k * X",
           f"sigma = {sigma} (spatial S-UNIWARD)", "db8 filter bank as in WOW")
    w.step("Wavelet coefficients at the pixel", "W_k(X) = K_k * X", f"pixel ({r0},{c0}) = {int(P[r0, c0])}",
           ", ".join(f"W_{k} = {_r(R[k][r0, c0], 4)}" for k in R))
    w.step("Additive cost", "rho = sum_k (1/(sigma + |W_k(X)|)) * |K_k rotated 180 deg|",
           " + ".join(f"{_r(parts[k][r0, c0], 6)} ({k})" for k in parts), f"rho({r0},{c0}) = {_r(rho[r0, c0], 6)}")
    # direct relative change for a single +1 at (r0, c0), padding taken from X
    xp = np.pad(P.astype(np.float64), K.PAD, mode="symmetric")
    yp = xp.copy()
    yp[K.PAD + r0, K.PAD + c0] += 1.0
    direct = 0.0
    for k, (v, h) in K.FILTERS.items():
        wx = K.conv2_same(xp, v, h)
        wy = K.conv2_same(yp, v, h)
        direct += float(np.sum(np.abs(wy - wx) / (sigma + np.abs(wx))))
    w.step("Check against the direct distortion of one change", "D(X, X + e_ij) computed from W_k(X) and W_k(Y)",
           f"direct D = {_r(direct, 6)}, additive rho = {_r(rho[r0, c0], 6)}", "equal for a single change (additivity)")
    w.check("additive cost equals direct relative change for one pixel", abs(direct - rho[r0, c0]) < 1e-9)
    w.step("Cost map of the patch", "rho for all 64 pixels", "computed", f"min {_r(rho.min(), 4)}, max {_r(rho.max(), 4)}",
           matrix={"rho": _r(rho, 4)})
    xs = [int(v) & 1 for v in P[r0]]
    msg = F.bits_of(SYN)[:2]
    _, rec, changed = _mini_stc(w, xs, rho[r0].tolist(), msg)
    w.step("Apply the changes", "changed element: +/-1 (seeded sign; 0 -> +1, 255 -> -1)", f"changed columns {changed}", "LSBs now equal y")
    return w.done(msg, rec, "Runtime: S-UNIWARD costs over the whole image (per channel), binary STC h = 7.")


WALKTHROUGHS = {
    "lsb_replacement": lsb_replacement, "lsb_matching": lsb_matching_wt, "pvd": pvd_wt, "edge_adaptive_lsb": edge_wt,
    "dct": dct_wt, "dwt": dwt_wt, "dct_svd": dct_svd_wt, "hugo": hugo_wt, "wow": wow_wt, "s_uniward": uniward_wt,
}


def clean(o):
    """JSON-safe copy (numpy scalars/arrays -> Python types)."""
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, np.ndarray):
        return clean(o.tolist())
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return _r(o, 6)
    return o


def walkthrough(name):
    if name not in WALKTHROUGHS:
        raise KeyError(name)
    d = clean(WALKTHROUGHS[name]())
    d["educational"] = True
    d["fixtures"] = {"synthetic_ciphertext_hex": SYN.hex().upper(), "synthetic_label": F.SYNTHETIC_LABEL,
                     "hand_matrix": F.HAND_MATRIX.tolist()}
    return d
