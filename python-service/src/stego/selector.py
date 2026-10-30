"""Deterministic selector sel-policy-2. Pure function of (cover, frame length, policy).

sel-policy-2 = sel-policy-1's rule set (capacity filter -> trial encode -> hard limits ->
weighted score -> tie-break) applied to the ten-algorithm registry, with static cost-model
entries for the five new algorithms and a tie-break order that prefers the content-adaptive
methods on ties.
"""

import hashlib
import math
import time

import numpy as np

from . import POLICY_VERSION, metrics
from .algorithms import BY_NAME, NAMES, get_by_name
from .algorithms.edge_adaptive import edge_mask
from .codec import embed_frame
from .config import Limits
from .errors import StegoError

WEIGHTS = {"urgent": (0.2, 0.1, 0.7), "normal": (0.5, 0.2, 0.3), "background": (0.8, 0.15, 0.05)}
# Static cost model (estimated units, NOT measurements): WORK per 64 frame bytes, SCAN per 1e5 pixels.
# STC methods pay for cost-map computation (SCAN) and the Viterbi search (WORK, ~w*2^h per bit).
WORK = {"lsb_replacement": 0.5, "lsb_matching": 0.7, "pvd": 1.2, "edge_adaptive_lsb": 0.9, "dct": 2.0,
        "dwt": 1.0, "dct_svd": 2.5, "hugo": 8.0, "wow": 6.0, "s_uniward": 6.0}
SCAN = {"lsb_replacement": 0.0, "lsb_matching": 0.1, "pvd": 0.2, "edge_adaptive_lsb": 0.6, "dct": 1.0,
        "dwt": 0.4, "dct_svd": 1.2, "hugo": 3.0, "wow": 1.5, "s_uniward": 1.5}
DEFAULT_TIE_ORDER = ["s_uniward", "wow", "hugo", "lsb_matching", "pvd", "edge_adaptive_lsb", "dwt", "dct_svd",
                     "lsb_replacement", "dct"]


def _num(raw, key, default, lo, hi):
    if key not in raw or raw[key] is None:
        return default
    v = raw[key]
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not lo <= v <= hi:
        raise StegoError("INVALID_REQUEST", f"policy.{key} must be a number in [{lo}, {hi}]")
    return float(v)


def parse_policy(raw):
    """Validate ranges and apply defaults. Unknown keys are ignored."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise StegoError("INVALID_REQUEST", "policy must be an object")
    name = raw.get("name", raw.get("policy_version", POLICY_VERSION))
    if name != POLICY_VERSION:
        raise StegoError("INVALID_REQUEST", "unknown selector policy", {"supported": [POLICY_VERSION]})
    order = raw.get("tie_break_order", DEFAULT_TIE_ORDER)
    if (not isinstance(order, list) or sorted(map(str, order)) != sorted(NAMES)
            or not all(isinstance(o, str) for o in order)):
        raise StegoError("INVALID_REQUEST", "policy.tie_break_order must be a permutation of all algorithm names")
    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise StegoError("INVALID_REQUEST", "policy.params must be an object")
    clean = {}
    for k, v in params.items():
        alg = get_by_name(k)
        alg.resolve_param(v)  # validates
        clean[k] = v
    return {
        "name": POLICY_VERSION,
        "max_mse": _num(raw, "max_mse", 4.0, 0.0, 65025.0),
        "min_psnr_db": _num(raw, "min_psnr_db", 40.0, 0.0, 200.0),
        "max_cost_units": _num(raw, "max_cost_units", 1000.0, 0.0, 1e9),
        "tie_epsilon": _num(raw, "tie_epsilon", 0.01, 0.0, 1.0),
        "tie_break_order": list(order),
        "params": clean,
    }


def parse_priority(p):
    if p is None:
        return "normal"
    if not isinstance(p, str) or p not in WEIGHTS:
        raise StegoError("INVALID_REQUEST", "priority must be urgent|normal|background")
    return p


def est_cost_units(name, frame_bytes, h, w):
    return WORK[name] * (frame_bytes + 16) / 64.0 + SCAN[name] * (h * w) / 1e5


def trial_payload(n):
    seed = int.from_bytes(hashlib.sha256(b"sel-trial" + n.to_bytes(4, "big")).digest()[:8], "big")
    return np.random.Generator(np.random.PCG64(seed)).integers(0, 256, size=n, dtype=np.uint8).tobytes()


def texture(arr):
    """Mean absolute horizontal+vertical neighbour difference (luma for RGB): a cheap complexity statistic."""
    g = arr.astype(np.float64)
    if g.ndim == 3:
        g = 0.299 * g[..., 0] + 0.587 * g[..., 1] + 0.114 * g[..., 2]
    return float((np.abs(np.diff(g, axis=1)).mean() + np.abs(np.diff(g, axis=0)).mean()) / 2.0)


def features(arr, frame_bytes, priority, cover_source=None):
    h, w = arr.shape[:2]
    return {
        "cover_source": cover_source, "bits_per_pixel": round(frame_bytes * 8 / (h * w), 8),
        "texture_mean_abs_diff": round(texture(arr), 6), "bit_depth": 8, "format": "PNG (lossless)",
        "width": w, "height": h, "channels": 1 if arr.ndim == 2 else 3,
        "mode": "L" if arr.ndim == 2 else "RGB", "samples": int(arr.size),
        "frame_bytes": frame_bytes, "frame_bits": frame_bytes * 8, "priority": priority,
        "edge_eligible_fraction": round(float(edge_mask(arr, 6).mean()), 6),
    }


def _row(name):
    return {"algorithm": name, "alg_id": BY_NAME[name].id, "variant": BY_NAME[name].variant, "eligible": False, "exclusion_reason": None,
            "exclusion_reasons": [], "capacity_bits": 0, "capacity_bytes": 0, "utilization": None,
            "headroom_bits": None, "est_cost_units": None, "mse": None, "psnr": None,
            "psnr_defined": None, "ssim": None, "changed_samples": None, "score": None, "trial_ms": None,
            "param": 0}


def select(arr, frame_bytes, priority=None, policy=None, forced=None, forced_param=None,
           candidates=None, max_frame_bytes=1024 * 1024, cover_source=None):
    """Returns the selection report. Raises NO_ELIGIBLE_ALGORITHM / ALGORITHM_NOT_ELIGIBLE."""
    priority = parse_priority(priority)
    pol = parse_policy(policy)
    if isinstance(frame_bytes, bool) or not isinstance(frame_bytes, int) or frame_bytes < 1:
        raise StegoError("INVALID_REQUEST", "frame_bytes must be an integer >= 1")
    if frame_bytes > max_frame_bytes:
        raise StegoError("FRAME_TOO_LARGE", "frame exceeds maximum", {"max_frame_bytes": max_frame_bytes})
    names = list(NAMES) if candidates is None else list(candidates)
    for n in names:
        get_by_name(n)
    if forced is not None:
        get_by_name(forced)
        if forced_param is not None:
            pol["params"] = dict(pol["params"], **{forced: forced_param})
    wd, wu, wt = WEIGHTS[priority]
    h, w = arr.shape[:2]
    bits = frame_bytes * 8
    trial = trial_payload(frame_bytes)
    rows = []
    for name in sorted(set(names), key=lambda n: BY_NAME[n].id):  # canonical order, input order irrelevant
        alg = BY_NAME[name]
        row = _row(name)
        param = pol["params"].get(name, 0)
        row["param"] = param
        cap = alg.capacity_bits(arr, param)
        cost = est_cost_units(name, frame_bytes, h, w)
        row.update(capacity_bits=cap, capacity_bytes=cap // 8, est_cost_units=round(cost, 6),
                   headroom_bits=cap - bits, utilization=round(bits / cap, 6) if cap else None)
        rows.append(row)
        if cap < bits:
            reason = alg.capacity_code
            row.update(exclusion_reason=reason, exclusion_reasons=[reason])
            continue
        t0 = time.perf_counter()
        try:
            stego, _ = embed_frame(arr, alg, param, trial)
        except StegoError as exc:
            reason = "ENCODE_VERIFY_FAILED" if exc.code == "ENCODE_VERIFY_FAILED" else exc.code
            row.update(exclusion_reason=reason, exclusion_reasons=[reason],
                       trial_ms=round((time.perf_counter() - t0) * 1000, 3))
            continue
        m = metrics.compute(arr, stego)
        row.update(mse=m["mse"], psnr=m["psnr"], psnr_defined=m["psnr_defined"], ssim=m["ssim"],
                   changed_samples=m["changed_samples"], trial_ms=round((time.perf_counter() - t0) * 1000, 3))
        reasons = []
        if m["mse"] > pol["max_mse"]:
            reasons.append("MSE_LIMIT")
        if m["psnr"] is not None and m["psnr"] < pol["min_psnr_db"]:
            reasons.append("PSNR_LIMIT")
        if cost > pol["max_cost_units"]:
            reasons.append("COST_LIMIT")
        if reasons:
            row.update(exclusion_reason=reasons[0], exclusion_reasons=reasons)
            continue
        row["eligible"] = True
        d = 0.0 if m["psnr"] is None else min(1.0, max(0.0, 1.0 - m["psnr"] / 80.0))
        u = bits / cap
        t = min(1.0, cost / 20.0)
        row["score"] = round(wd * d + wu * u + wt * t, 6)

    base = {
        "policy_version": POLICY_VERSION, "priority": priority, "weights": {"w_d": wd, "w_u": wu, "w_t": wt},
        "features": features(arr, frame_bytes, priority, cover_source), "candidates": rows,
        "policy": {k: v for k, v in pol.items() if k != "name"},
    }
    eligible = [r for r in rows if r["eligible"]]

    def fin(selected, reason, mode):
        r = next(x for x in rows if x["algorithm"] == selected)
        out = dict(base, selected=selected, selected_alg_id=BY_NAME[selected].id,
                   selected_param=r["param"], reason_code=reason, mode=mode)
        return out

    if forced is not None:
        row = next((r for r in rows if r["algorithm"] == forced), None)
        if row is None or not row["eligible"]:
            raise StegoError("ALGORITHM_NOT_ELIGIBLE", "forced algorithm is not eligible",
                             {"algorithm": forced, "reason": None if row is None else row["exclusion_reason"],
                              "reasons": [] if row is None else row["exclusion_reasons"],
                              "candidates": rows, "policy_version": POLICY_VERSION})
        return fin(forced, "MANUAL_OVERRIDE", "manual")
    if not eligible:
        raise StegoError("NO_ELIGIBLE_ALGORITHM", "no algorithm satisfies capacity and constraints",
                         {"candidates": rows, "policy_version": POLICY_VERSION, "features": base["features"]})
    if len(eligible) == 1:
        return fin(eligible[0]["algorithm"], "ONLY_ELIGIBLE", "auto")
    best = min(r["score"] for r in eligible)
    tied = {r["algorithm"] for r in eligible if r["score"] <= best + pol["tie_epsilon"] + 1e-12}
    winner = next(n for n in pol["tie_break_order"] if n in tied)
    reason = "TIE_BREAK_ORDER" if len(tied) > 1 else "BEST_SCORE"
    return fin(winner, reason, "auto")
