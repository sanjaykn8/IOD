"""Payload-aware cover selection: bounded candidates -> pre-screen -> real planner -> best feasible.

Inputs are the payload LENGTH and configuration only. For one transmission:

1. preflight: memory estimate for the chosen size (before any image allocation);
2. size: the payload must respect the embedding-rate limit (`max_embedding_rate` payload bits per cover
   sample) at the requested size; if it does not, the smallest size of a fixed ladder that does is used
   - only when `allow_payload_driven_resize` is set - otherwise the request is rejected up front;
3. generate a bounded batch of candidates with fresh OS-random seeds and different families;
4. pre-screen each with the visual-coherence gates and score (`quality.evaluate`);
5. run the REAL patch planner (segmentation, measured capacities, knowledge-base selection, dry run)
   on the candidates that passed, best score first; the first one that plans is, by construction, the
   highest-quality feasible candidate among those evaluated;
6. otherwise fail with a structured error. Nothing is relaxed and no other cover source exists.

The processing budget is checked before every candidate generation, every pre-screen and every planner
invocation (and between the planner's refinement levels). Work that has started is completed; a plan
that completes after the deadline is accepted and reported as `budget.exceeded`. The number of
candidates and planner invocations is bounded by `max_candidates` regardless of time.
"""

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass

from ..errors import StegoError
from ..patch import planner
from . import GENERATOR_VERSION, QUALITY_VERSION, families, profile, quality

LADDER = (1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0)
APPROACH_FRACTION = 0.8
_test_counter = [0]
_test_lock = threading.Lock()


def fresh_seed():
    """16 bytes from the operating system's CSPRNG. Never derived from the payload.

    Test/experiment hook: when the PROCESS environment has IOD_STEGO_GENERATOR_TEST_SEED set, seeds are
    the deterministic sequence SHA-256(test seed | counter). It is not reachable from any request and the
    service reports `seeding: "test-fixed"` in /stego/health while it is active.
    """
    fixed = os.environ.get("IOD_STEGO_GENERATOR_TEST_SEED")
    if fixed:
        with _test_lock:
            n = _test_counter[0]
            _test_counter[0] += 1
        return hashlib.sha256(b"IOD-TEST-SEED|" + fixed.encode("utf-8") + b"|" + str(n).encode()).digest()[:families.SEED_BYTES]
    return os.urandom(families.SEED_BYTES)


def seeding_mode():
    return "test-fixed" if os.environ.get("IOD_STEGO_GENERATOR_TEST_SEED") else "os-random"


def rate_limit_bytes(width, height, channels, max_rate):
    """Largest payload the embedding-rate limit allows at this size: `max_rate` payload bits per cover
    sample (pixels x channels). This is a QUALITY constraint, not a capacity measurement: several
    algorithms could physically hold far more (PVD carries 3-7 bits per pair), but filling a small
    image that densely is exactly the conspicuous case the generator must not produce."""
    return int(width * height * channels * max_rate) // 8


def size_ladder(cfg):
    """Sizes (multiples of 8, same aspect) from the requested size up to the configured ceilings."""
    out = []
    for f in LADDER:
        w, h = int(cfg.width * f) // 8 * 8, int(cfg.height * f) // 8 * 8
        if w > cfg.max_width or h > cfg.max_height or w * h > cfg.max_pixels:
            break
        if (w, h) not in out:
            out.append((w, h))
    return out or [(cfg.width, cfg.height)]


@dataclass
class Selection:
    array: object
    plan: object            # planner.Plan
    generation: dict        # public diagnostics (no seed, no payload)


def _compact_attempts(att):
    return [{k: a.get(k) for k in ("level", "regions", "outcome", "capacity_bytes", "usable_patches", "failed_patch")} for a in att or []]


def select_cover(payload_bytes, cfg, seg_cfg=None, min_level=0, target_chunk=planner.DEFAULT_TARGET_CHUNK,
                 seeds=None, clock=time.perf_counter, generate_fn=families.generate, evaluate_fn=quality.evaluate,
                 plan_fn=planner.plan):
    """Returns a `Selection` or raises a StegoError whose details carry the candidate table.

    `seeds` (iterable of bytes) is for tests and reproducible experiments only; production passes None and
    every candidate gets `fresh_seed()`.
    """
    if isinstance(payload_bytes, bool) or not isinstance(payload_bytes, int) or payload_bytes < 1:
        raise StegoError("INVALID_REQUEST", "payload length must be a positive integer")
    t0 = clock()
    limit_ms = float(cfg.processing_budget_ms)
    channels = 1 if cfg.mode == "L" else 3
    seed_iter = iter(seeds) if seeds is not None else None

    def used_ms():
        return (clock() - t0) * 1000.0

    def over():
        return used_ms() >= limit_ms

    ladder = size_ladder(cfg)
    idx = 0
    fits = [rate_limit_bytes(w, h, channels, cfg.max_embedding_rate) >= payload_bytes for (w, h) in ladder]
    rate_info = {"max_embedding_rate": cfg.max_embedding_rate, "unit": "payload bits per cover sample",
                 "limit_bytes_at_requested_size": rate_limit_bytes(cfg.width, cfg.height, channels, cfg.max_embedding_rate),
                 "requested_size_within_limit": fits[0]}
    if not fits[0]:
        usable = [k for k, ok in enumerate(fits) if ok] if cfg.allow_payload_driven_resize else []
        if not usable:
            raise StegoError("PATCH_CAPACITY_INSUFFICIENT",
                             "the payload exceeds the embedding-rate limit for the allowed cover size (a denser embedding would be conspicuous)",
                             {"reason": "embedding_rate_above_limit", "payload_bytes": payload_bytes, "embedding_rate": rate_info,
                              "requested": {"width": cfg.width, "height": cfg.height}, "ladder": [list(s) for s in ladder],
                              "allow_payload_driven_resize": cfg.allow_payload_driven_resize, "candidates": [], "candidate_count": 0,
                              "generator_version": GENERATOR_VERSION, "profile": cfg.profile, "config": cfg.to_dict(),
                              "budget": {"limit_ms": int(limit_ms), "used_ms": round(used_ms(), 3), "exceeded": False,
                                         "approached": False, "stopped_early": False}})
        idx = usable[0]
    # preflight for the first size happens before anything is allocated
    mem_est = profile.preflight_memory(cfg, ladder[idx][0], ladder[idx][1], cfg.max_candidates)

    cands = []                  # public candidate rows
    held = {}                   # index -> array (only until the round is decided)
    used_families = []
    remaining = cfg.max_candidates
    planner_calls = 0
    t_gen = t_pre = t_plan = 0.0
    stopped_by_budget = False
    selected = None
    rnd = 0
    detail_bias = 0.0
    resize_note = None

    while remaining > 0 and selected is None and not stopped_by_budget:
        w, h = ladder[idx]
        last_size = (not cfg.allow_payload_driven_resize) or idx == len(ladder) - 1
        batch = remaining if last_size else max(1, math.ceil(remaining / 2))
        if rnd > 0:
            try:
                mem_est = max(mem_est, profile.preflight_memory(cfg, w, h, batch))
            except StegoError as exc:
                resize_note = {"stopped": "memory_limit", "details": exc.details}
                break
        round_rows = []
        for _ in range(batch):
            if over():
                stopped_by_budget = True
                break
            seed = next(seed_iter, None) if seed_iter is not None else fresh_seed()
            if seed is None:
                break                                   # explicit test seeds exhausted
            enabled = tuple(f for f in cfg.families if f not in used_families) or cfg.families
            arr, info = generate_fn(seed, w, h, cfg.mode, None, enabled, detail_bias)
            used_families.append(info["family"])
            remaining -= 1
            t_gen += info["generate_ms"]
            row = {"index": len(cands), "round": rnd, "family": info["family"], "width": w, "height": h, "mode": cfg.mode,
                   "seed_fingerprint": info["seed_fingerprint"], "params": info["params"], "generate_ms": info["generate_ms"],
                   "quality_score": None, "gates_passed": None, "rejection_reasons": [], "outcome": "generated",
                   "prescreen_ms": None, "plan_ms": None, "capacity_bytes": None, "plan_attempts": None, "planned": False}
            cands.append(row)
            round_rows.append(row)
            held[row["index"]] = (arr, info, None)
            if over():
                row["outcome"] = "not_evaluated_budget"
                stopped_by_budget = True
                break
            q = evaluate_fn(arr, cfg.min_quality_score)
            t_pre += q["prescreen_ms"]
            row.update(quality_score=q["score"], gates_passed=q["passed"], rejection_reasons=q["rejection_reasons"],
                       prescreen_ms=q["prescreen_ms"], outcome="passed_prescreen" if q["passed"] else "rejected_quality")
            held[row["index"]] = (arr, info, q)
            if not q["passed"]:
                held.pop(row["index"])                  # free pathological candidates immediately
        capacity_failed = False
        # best quality first; ties broken by generation order (deterministic)
        for row in sorted((r for r in round_rows if r["outcome"] == "passed_prescreen"), key=lambda r: (-r["quality_score"], r["index"])):
            if stopped_by_budget or over():
                row["outcome"] = "not_planned_budget"
                stopped_by_budget = True
                continue
            arr, info, q = held[row["index"]]
            tp = clock()
            planner_calls += 1
            row["planned"] = True
            try:
                pl = plan_fn(arr, payload_bytes, seg_cfg, min_level, target_chunk, True, over)
            except StegoError as exc:
                row["plan_ms"] = round((clock() - tp) * 1000.0, 3)
                t_plan += row["plan_ms"]
                att = (exc.details or {}).get("attempts")
                row["plan_attempts"] = _compact_attempts(att)
                row["capacity_bytes"] = max([a.get("capacity_bytes") or 0 for a in att or []] or [0]) or None
                if exc.code == "PATCH_CAPACITY_INSUFFICIENT":
                    row["outcome"] = "capacity_insufficient"
                    capacity_failed = True
                elif exc.code == "NO_ELIGIBLE_ALGORITHM":
                    row["outcome"] = "no_eligible_algorithm"
                    capacity_failed = True
                elif exc.code == "GENERATION_BUDGET_EXCEEDED":
                    row["outcome"] = "planning_stopped_budget"
                    stopped_by_budget = True
                else:
                    raise
                held.pop(row["index"], None)
                continue
            row["plan_ms"] = round((clock() - tp) * 1000.0, 3)
            t_plan += row["plan_ms"]
            row["plan_attempts"] = _compact_attempts(pl.diagnostics.get("attempts"))
            row["capacity_bytes"] = next((a.get("capacity_bytes") for a in pl.diagnostics["attempts"] if a.get("outcome") == "OK"), None)
            row["outcome"] = "selected"
            selected = (row, arr, info, q, pl)
            break
        for row in round_rows:
            if row["outcome"] == "passed_prescreen":
                row["outcome"] = "not_needed" if selected is not None else "not_planned_budget"
            if selected is None or row is not selected[0]:
                held.pop(row["index"], None)
        if selected is not None or stopped_by_budget:
            break
        if cfg.allow_payload_driven_resize and capacity_failed and idx < len(ladder) - 1 and remaining > 0:
            idx += 1
            rnd += 1
            detail_bias = 0.5
            continue
        if remaining > 0 and capacity_failed and not cfg.allow_payload_driven_resize:
            rnd += 1
            detail_bias = 0.5
            continue                                    # (only reachable when a batch was cut short)
        break

    total = used_ms()
    budget = {"limit_ms": int(limit_ms), "used_ms": round(total, 3), "exceeded": total > limit_ms,
              "approached": total >= APPROACH_FRACTION * limit_ms, "stopped_early": stopped_by_budget}
    common = {
        "generator_version": GENERATOR_VERSION, "quality_version": QUALITY_VERSION, "profile": cfg.profile,
        "payload_bytes": payload_bytes, "requested": {"width": cfg.width, "height": cfg.height}, "mode": cfg.mode,
        "candidates": cands, "candidate_count": len(cands), "max_candidates": cfg.max_candidates,
        "planner_invocations": planner_calls, "seeding": "explicit-test-seeds" if seeds is not None else seeding_mode(),
        "timings_ms": {"generate": round(t_gen, 3), "prescreen": round(t_pre, 3), "plan": round(t_plan, 3), "total": round(total, 3)},
        "budget": budget,
        "memory": {"estimate_mb": round(mem_est / 1048576, 2), "limit_mb": cfg.max_working_memory_mb,
                   "method": "preflight estimate (bytes per pixel measured with tracemalloc), not a live measurement"},
        "embedding_rate": rate_info,
        "resize": {"allowed": cfg.allow_payload_driven_resize, "ladder": [list(s) for s in ladder], "note": resize_note},
        "config": cfg.to_dict(),
    }
    if selected is None:
        outcomes = [c["outcome"] for c in cands]
        if stopped_by_budget:
            code, msg = "GENERATION_BUDGET_EXCEEDED", "the processing budget was reached before a feasible cover was selected"
        elif cands and all(o == "rejected_quality" for o in outcomes):
            code, msg = "COVER_QUALITY_REJECTED", "every generated candidate failed the visual-quality gates"
        elif any(o == "capacity_insufficient" for o in outcomes):
            code, msg = "PATCH_CAPACITY_INSUFFICIENT", "no quality-acceptable generated cover can carry this frame within the configured size"
        elif any(o == "no_eligible_algorithm" for o in outcomes):
            code, msg = "NO_ELIGIBLE_ALGORITHM", "no knowledge-base entry was eligible for a patch of any acceptable candidate"
        else:
            code, msg = "COVER_GENERATION_FAILED", "no candidate cover could be generated"
        raise StegoError(code, msg, dict(common, resized=False, selected=None))
    row, arr, info, q, pl = selected
    samples = row["width"] * row["height"] * channels
    gen = dict(common, embedding_rate=dict(rate_info, actual_bits_per_sample=round(8.0 * payload_bytes / samples, 6)),
               family=info["family"], seed_fingerprint=info["seed_fingerprint"], params=info["params"],
               actual={"width": row["width"], "height": row["height"]},
               resized=(row["width"], row["height"]) != (cfg.width, cfg.height),
               selected=row["index"], quality_score=q["score"],
               quality={"score": q["score"], "min_score": q["min_score"], "gates": q["gates"], "components": q["components"],
                        "metrics": q["metrics"], "note": q["note"]})
    return Selection(arr, pl, gen)
