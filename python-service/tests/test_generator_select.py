"""Profiles/validation and payload-aware candidate selection (bounded, quality-first, fail closed)."""
import numpy as np
import pytest

from stego.errors import StegoError
from stego.generator import families as F, profile as P, quality as Q, select as S
from stego.patch import planner

PI = P.process_config({})


def seeds(n, tag=1):
    return [bytes([tag, i]) * 8 for i in range(n)]


class Clock:
    """Deterministic clock: every reading advances by `step` seconds."""
    def __init__(self, step):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


# ------------------------------------------------------------------ profile / validation
def test_raspberry_pi_profile_defaults():
    assert PI.profile == "raspberry_pi_5_cpu" == P.DEFAULT_PROFILE
    assert (PI.width, PI.height, PI.max_width, PI.max_height) == (320, 240, 640, 480)
    assert (PI.max_candidates, PI.processing_budget_ms, PI.max_pixels, PI.max_working_memory_mb) == (2, 2500, 307200, 96)
    assert PI.workers == 1 and PI.mode == "RGB" and PI.allow_payload_driven_resize is False
    assert PI.families == F.FAMILIES and PI.min_quality_score == 0.70 and PI.max_embedding_rate == 0.20
    v = P.public_view()
    assert v["active_profile"] == PI.profile and "hardware speed is not emulated" in v["note"]
    assert P.resolve(None, PI) == PI and P.resolve({}, PI) == PI


def test_environment_overrides_are_validated_against_hard_ceilings():
    c = P.process_config({"IOD_STEGO_GENERATOR_WIDTH": "480", "IOD_STEGO_GENERATOR_HEIGHT": "360", "IOD_STEGO_GENERATOR_MAX_CANDIDATES": "3",
                          "IOD_STEGO_GENERATOR_BUDGET_MS": "4000", "IOD_STEGO_GENERATOR_FAMILIES": "terrain, cells",
                          "IOD_STEGO_GENERATOR_ALLOW_RESIZE": "true", "IOD_STEGO_GENERATOR_MIN_QUALITY": "0.8", "IOD_STEGO_GENERATOR_MODE": "l"})
    assert (c.width, c.height, c.max_candidates, c.processing_budget_ms) == (480, 360, 3, 4000)
    assert c.families == ("terrain", "cells") and c.allow_payload_driven_resize and c.min_quality_score == 0.8 and c.mode == "L"
    assert P.process_config({"IOD_STEGO_GENERATOR_PROFILE": "development_host"}).max_width == 1280
    for env in ({"IOD_STEGO_GENERATOR_PROFILE": "gpu_cluster"}, {"IOD_STEGO_GENERATOR_MAX_WIDTH": "5000"},
                {"IOD_STEGO_GENERATOR_MAX_CANDIDATES": "9"}, {"IOD_STEGO_GENERATOR_BUDGET_MS": "60000"}, {"IOD_STEGO_GENERATOR_BUDGET_MS": "abc"},
                {"IOD_STEGO_GENERATOR_WORKERS": "4"}, {"IOD_STEGO_GENERATOR_MAX_MEMORY_MB": "4096"}, {"IOD_STEGO_GENERATOR_FAMILIES": "terrain,gan"},
                {"IOD_STEGO_GENERATOR_WIDTH": "324"}, {"IOD_STEGO_GENERATOR_WIDTH": "800"}, {"IOD_STEGO_GENERATOR_ALLOW_RESIZE": "maybe"},
                {"IOD_STEGO_GENERATOR_MAX_EMBED_RATE": "3"}, {"IOD_STEGO_GENERATOR_MAX_PIXELS": "99999999"}):
        with pytest.raises(StegoError) as e:
            P.process_config(env)
        assert e.value.code == "GENERATOR_CONFIG_INVALID", env


def test_requests_can_only_tighten():
    ok = P.resolve({"profile": "raspberry_pi_5_cpu", "width": 480, "height": 360, "max_candidates": 1, "processing_budget_ms": 1000,
                    "max_width": 480, "max_height": 360, "min_quality_score": 0.9, "families": ["cells", "terrain"],
                    "allow_payload_driven_resize": True, "max_embedding_rate": 0.05, "max_working_memory_mb": 64, "mode": "L"}, PI)
    assert (ok.width, ok.height, ok.max_candidates, ok.processing_budget_ms, ok.max_width) == (480, 360, 1, 1000, 480)
    assert ok.families == ("terrain", "cells") and ok.min_quality_score == 0.9 and ok.max_embedding_rate == 0.05 and ok.mode == "L"
    raising = [{"max_candidates": 3}, {"processing_budget_ms": 2501}, {"max_width": 641}, {"max_height": 481}, {"max_pixels": 307201},
               {"max_working_memory_mb": 97}, {"min_quality_score": 0.5}, {"max_embedding_rate": 0.21}, {"width": 648}, {"height": 488},
               {"width": 640, "height": 480, "max_pixels": 100000}, {"workers": 2}, {"profile": "development_host"},
               {"families": ["terrain", "plasma"]}, {"families": []}]
    for r in raising:
        with pytest.raises(StegoError) as e:
            P.resolve(r, PI)
        assert e.value.code == "GENERATOR_CONFIG_INVALID", r
    narrowed = P.process_config({"IOD_STEGO_GENERATOR_FAMILIES": "terrain,cells"})
    with pytest.raises(StegoError):
        P.resolve({"families": ["clouds"]}, narrowed)


@pytest.mark.parametrize("bad", [
    {"seed": "abc"}, {"seed_hex": "00" * 16}, {"cover_id": "a" * 32}, {"test_cover_id": "a" * 32}, {"source": "webcam"},
    {"image_b64": "AAAA"}, {"file": "x.png"}, {"algorithm": "pvd"}, {"family": "terrain"}, {"camera_index": 0},
    {"width": "320"}, {"width": 320.5}, {"width": True}, {"width": 0}, {"width": 100}, {"height": 90}, {"max_candidates": 0},
    {"processing_budget_ms": 10}, {"allow_payload_driven_resize": "yes"}, {"mode": "CMYK"}, {"min_quality_score": 2},
    {"max_embedding_rate": 0}, [], "pi", 5,
])
def test_invalid_or_unsafe_requests_are_rejected(bad):
    with pytest.raises(StegoError) as e:
        P.resolve(bad, PI)
    assert e.value.code == "GENERATOR_CONFIG_INVALID"


def test_memory_preflight_rejects_before_allocation(monkeypatch):
    small = P.resolve({"max_working_memory_mb": 16}, PI)                # 320x240 needs ~24 MB
    called = []
    monkeypatch.setattr(F, "generate", lambda *a, **k: called.append(1))
    with pytest.raises(StegoError) as e:
        S.select_cover(200, small, generate_fn=F.generate)
    assert e.value.code == "GENERATOR_MEMORY_LIMIT" and called == []
    assert e.value.details["estimate_mb"] > 16 == e.value.details["limit_mb"]
    assert P.memory_estimate_bytes(640, 480) < 96 * 1048576 < P.memory_estimate_bytes(1280, 960)
    assert P.preflight_memory(PI, 640, 480, 2) > P.preflight_memory(PI, 320, 240, 2)


# ------------------------------------------------------------------ selection
def test_selects_a_feasible_cover_and_reports_everything():
    sel = S.select_cover(300, PI, seeds=seeds(2))
    g = sel.generation
    assert sel.array.shape == (240, 320, 3) and sel.array.dtype == np.uint8
    assert g["candidate_count"] == 2 and g["planner_invocations"] == 1 and g["selected"] is not None
    assert g["profile"] == "raspberry_pi_5_cpu" and g["generator_version"] == "procgen-1" and g["family"] in F.FAMILIES
    assert g["requested"] == g["actual"] == {"width": 320, "height": 240} and g["resized"] is False
    rows = g["candidates"]
    assert sorted(r["outcome"] for r in rows) == ["not_needed", "selected"]
    assert len({r["family"] for r in rows}) == 2, "candidates of one transmission use different families"
    win = next(r for r in rows if r["outcome"] == "selected")
    assert win["quality_score"] == max(r["quality_score"] for r in rows) == g["quality_score"] >= 0.70
    assert win["planned"] and win["capacity_bytes"] >= 300 and win["plan_attempts"][-1]["outcome"] == "OK"
    assert set(g["timings_ms"]) == {"generate", "prescreen", "plan", "total"} and g["timings_ms"]["total"] > 0
    assert g["budget"]["limit_ms"] == 2500 and g["budget"]["exceeded"] is False and g["budget"]["stopped_early"] is False
    assert g["embedding_rate"]["actual_bits_per_sample"] == pytest.approx(2400 / 230400, rel=1e-3)
    assert g["memory"]["estimate_mb"] <= g["memory"]["limit_mb"] == 96
    assert sel.plan.parsed.payload_len == 300 and sel.plan.diagnostics["used_patches"] >= 1
    text = str(g)
    assert all(s.hex() not in text for s in seeds(2)), "raw seeds are never reported"
    assert all(len(r["seed_fingerprint"]) == 16 for r in rows)


def test_explicit_seeds_make_selection_reproducible():
    a = S.select_cover(500, PI, seeds=seeds(2, 7))
    b = S.select_cover(500, PI, seeds=seeds(2, 7))
    assert np.array_equal(a.array, b.array) and a.plan.manifest == b.plan.manifest
    strip = lambda g: {k: v for k, v in g.items() if k not in ("timings_ms", "budget", "candidates")}
    assert strip(a.generation) == strip(b.generation)
    c = S.select_cover(500, PI, seeds=seeds(2, 8))
    assert not np.array_equal(a.array, c.array)


def test_highest_quality_feasible_candidate_wins_not_the_largest_capacity():
    """Three candidates with fixed scores and capacities: the middle-capacity, best-quality one is chosen;
    when the best one cannot carry the payload the next best feasible one is chosen."""
    cfg = P.resolve({"max_candidates": 2}, PI)
    imgs = {}

    def gen(seed, w, h, mode, family, enabled, bias):
        arr, info = F.generate(seed, w, h, mode, family, enabled, bias)
        imgs[arr.tobytes()[:64]] = seed[0]
        return arr, info

    score = {1: 0.95, 2: 0.80}
    cap = {1: 500, 2: 9000}

    def ev(arr, min_score):
        r = Q.evaluate(arr, 0.0)
        s = score[imgs[arr.tobytes()[:64]]]
        return dict(r, score=s, passed=s >= min_score, rejection_reasons=[] if s >= min_score else ["score"])

    planned = []

    def plan(arr, n, seg, lvl, tc, dry, stop):
        k = imgs[arr.tobytes()[:64]]
        planned.append(k)
        if n > cap[k]:
            raise StegoError("PATCH_CAPACITY_INSUFFICIENT", "x", {"attempts": [{"level": 0, "outcome": "CAPACITY_INSUFFICIENT", "capacity_bytes": cap[k]}]})
        return planner.plan(arr, n, seg, lvl, tc)

    two = [bytes([1]) * 16, bytes([2]) * 16]
    a = S.select_cover(300, cfg, seeds=two, generate_fn=gen, evaluate_fn=ev, plan_fn=plan)
    assert a.generation["quality_score"] == 0.95 and planned == [1], "best quality is tried first and wins although it has 18x less capacity"
    planned.clear()
    b = S.select_cover(2000, cfg, seeds=two, generate_fn=gen, evaluate_fn=ev, plan_fn=plan)
    assert b.generation["quality_score"] == 0.80 and planned == [1, 2]
    out = {r["quality_score"]: r["outcome"] for r in b.generation["candidates"]}
    assert out == {0.95: "capacity_insufficient", 0.80: "selected"}
    # generation order does not matter, only quality
    planned.clear()
    c = S.select_cover(300, cfg, seeds=two[::-1], generate_fn=gen, evaluate_fn=ev, plan_fn=plan)
    assert c.generation["quality_score"] == 0.95 and planned == [1]


def test_quality_rejection_is_structured_and_never_relaxed():
    def bad_gen(seed, w, h, mode, family, enabled, bias):
        _, info = F.generate(seed, w, h, mode, family, enabled, bias)
        return np.random.default_rng(seed[0]).integers(0, 256, (h, w, 3), dtype=np.uint8), info     # white noise

    planned = []
    with pytest.raises(StegoError) as e:
        S.select_cover(200, PI, seeds=seeds(2), generate_fn=bad_gen, plan_fn=lambda *a: planned.append(1))
    assert e.value.code == "COVER_QUALITY_REJECTED" and planned == [], "a rejected candidate is never planned"
    d = e.value.details
    assert d["candidate_count"] == 2 and all(c["outcome"] == "rejected_quality" and c["rejection_reasons"] for c in d["candidates"])
    assert d["selected"] is None and d["planner_invocations"] == 0


def test_capacity_failure_is_structured_with_candidate_table():
    def no_room(arr, n, seg, lvl, tc, dry, stop):
        raise StegoError("PATCH_CAPACITY_INSUFFICIENT", "x", {"attempts": [{"level": k, "outcome": "CAPACITY_INSUFFICIENT", "capacity_bytes": 77} for k in range(4)]})

    with pytest.raises(StegoError) as e:
        S.select_cover(400, PI, seeds=seeds(2), plan_fn=no_room)
    d = e.value.details
    assert e.value.code == "PATCH_CAPACITY_INSUFFICIENT" and d["planner_invocations"] == 2
    assert [c["outcome"] for c in d["candidates"]] == ["capacity_insufficient"] * 2
    assert all(c["capacity_bytes"] == 77 and len(c["plan_attempts"]) == 4 for c in d["candidates"])

    def no_alg(arr, n, seg, lvl, tc, dry, stop):
        raise StegoError("NO_ELIGIBLE_ALGORITHM", "x", {"attempts": [{"level": 0, "outcome": "NO_ELIGIBLE_ALGORITHM"}]})
    with pytest.raises(StegoError) as e:
        S.select_cover(400, PI, seeds=seeds(2), plan_fn=no_alg)
    assert e.value.code == "NO_ELIGIBLE_ALGORITHM"


def test_embedding_rate_limit_rejects_dense_payloads_up_front_unless_resize_is_allowed():
    limit = S.rate_limit_bytes(320, 240, 3, 0.20)
    assert limit == 5760
    calls = []
    with pytest.raises(StegoError) as e:
        S.select_cover(limit + 1, PI, seeds=seeds(2), generate_fn=lambda *a: calls.append(1))
    assert e.value.code == "PATCH_CAPACITY_INSUFFICIENT" and e.value.details["reason"] == "embedding_rate_above_limit" and calls == []
    assert e.value.details["candidate_count"] == 0
    assert S.select_cover(limit, PI, seeds=seeds(2)).generation["resized"] is False
    grow = P.resolve({"allow_payload_driven_resize": True}, PI)
    sel = S.select_cover(limit + 1, grow, seeds=seeds(2))
    g = sel.generation
    assert g["resized"] is True and g["actual"] == {"width": 400, "height": 296} and sel.array.shape[:2] == (296, 400)
    assert g["requested"] == {"width": 320, "height": 240}
    # never beyond the ceilings: 640x480 allows 23040 bytes at rate 0.2
    with pytest.raises(StegoError) as e:
        S.select_cover(23041, grow, seeds=seeds(2))
    assert e.value.details["reason"] == "embedding_rate_above_limit"
    assert S.size_ladder(PI) == [(320, 240), (400, 296), (480, 360), (640, 480)]
    assert S.size_ladder(P.resolve({"max_width": 400, "max_height": 304}, PI)) == [(320, 240), (400, 296)]


def test_resize_after_a_capacity_failure_uses_the_next_size_and_stays_bounded():
    grow = P.resolve({"allow_payload_driven_resize": True}, PI)
    sizes = []

    def plan(arr, n, seg, lvl, tc, dry, stop):
        sizes.append(arr.shape[1])
        if arr.shape[1] < 400:
            raise StegoError("PATCH_CAPACITY_INSUFFICIENT", "x", {"attempts": [{"level": 0, "outcome": "CAPACITY_INSUFFICIENT", "capacity_bytes": 10}]})
        return planner.plan(arr, n, seg, lvl, tc)

    sel = S.select_cover(300, grow, seeds=seeds(4), plan_fn=plan)
    assert sizes == [320, 400] and sel.generation["actual"]["width"] == 400 and sel.generation["candidate_count"] == 2
    assert [c["round"] for c in sel.generation["candidates"]] == [0, 1]


@pytest.mark.parametrize("max_candidates", [1, 2])
def test_candidates_and_planner_calls_are_bounded_by_the_candidate_limit(max_candidates):
    cfg = P.resolve({"max_candidates": max_candidates}, PI)
    gens, plans = [], []

    def gen(*a):
        gens.append(1)
        return F.generate(*a)

    def plan(arr, n, seg, lvl, tc, dry, stop):
        plans.append(1)
        raise StegoError("PATCH_CAPACITY_INSUFFICIENT", "x", {"attempts": []})

    with pytest.raises(StegoError):
        S.select_cover(300, cfg, seeds=seeds(8), generate_fn=gen, plan_fn=plan)
    assert len(gens) == max_candidates and len(plans) == max_candidates


def test_budget_stops_generation_and_planning_at_the_boundaries():
    # (a) budget already spent before the first candidate: nothing is generated
    gens = []
    with pytest.raises(StegoError) as e:
        S.select_cover(300, P.resolve({"processing_budget_ms": 200}, PI), seeds=seeds(2), clock=Clock(1.0),
                       generate_fn=lambda *a: gens.append(1))
    assert e.value.code == "GENERATION_BUDGET_EXCEEDED" and gens == []
    assert e.value.details["budget"]["stopped_early"] and e.value.details["budget"]["exceeded"]
    # (b) budget runs out during pre-screening: candidates exist, none is planned, nothing more is generated
    plans, t = [], {"v": 0.0}

    def slow_eval(arr, min_score):
        t["v"] += 1.0
        return Q.evaluate(arr, min_score)
    with pytest.raises(StegoError) as e:
        S.select_cover(300, P.resolve({"processing_budget_ms": 200}, PI), seeds=seeds(2), clock=lambda: t["v"],
                       evaluate_fn=slow_eval, plan_fn=lambda *a: plans.append(1))
    d = e.value.details
    assert e.value.code == "GENERATION_BUDGET_EXCEEDED" and plans == [] and d["candidate_count"] == 1
    assert [c["outcome"] for c in d["candidates"]] == ["not_planned_budget"] and d["planner_invocations"] == 0
    # (c) the planner itself gives up between refinement levels when the budget is gone
    stops = []

    def plan(arr, n, seg, lvl, tc, dry, stop):
        stops.append(stop())
        raise StegoError("GENERATION_BUDGET_EXCEEDED", "between levels", {"attempts": [{"level": 0, "outcome": "CAPACITY_INSUFFICIENT"}]})
    with pytest.raises(StegoError) as e:
        S.select_cover(300, PI, seeds=seeds(2), plan_fn=plan)
    assert e.value.code == "GENERATION_BUDGET_EXCEEDED" and len(stops) == 1, "no further planner call after a budget stop"
    assert "planning_stopped_budget" in [c["outcome"] for c in e.value.details["candidates"]]


def test_a_plan_that_finishes_late_is_accepted_and_flagged():
    t = {"v": 0.0}
    def clock():
        return t["v"]

    def slow_plan(arr, n, seg, lvl, tc, dry, stop):
        t["v"] += 9.0                                   # the planner overran the 2.5 s budget while running
        return planner.plan(arr, n, seg, lvl, tc)
    sel = S.select_cover(300, PI, seeds=seeds(2), clock=clock, plan_fn=slow_plan)
    b = sel.generation["budget"]
    assert b["exceeded"] is True and b["approached"] is True and b["stopped_early"] is False and b["used_ms"] >= 9000


def test_planner_should_stop_hook():
    arr = F.generate(b"p" * 16, 320, 240)[0]
    with pytest.raises(StegoError) as e:
        planner.plan(arr, 10 ** 6, should_stop=lambda: True)       # level 0 fails for capacity, then the hook stops it
    assert e.value.code == "GENERATION_BUDGET_EXCEEDED" and len(e.value.details["attempts"]) == 1
    assert planner.plan(arr, 300, should_stop=lambda: True).diagnostics["refinement_level"] == 0   # first level always runs


def test_payload_length_changes_feasibility_but_not_the_image():
    """Same seeds, different payload lengths: the same candidate images are generated (no payload-keyed texture)."""
    seen = {}
    def gen(tag):
        def g(*a):
            arr, info = F.generate(*a)
            seen.setdefault(tag, []).append(arr.tobytes())
            return arr, info
        return g
    S.select_cover(100, PI, seeds=seeds(2, 3), generate_fn=gen("small"))
    S.select_cover(5000, PI, seeds=seeds(2, 3), generate_fn=gen("large"))
    assert seen["small"] == seen["large"]
    for bad in (0, -1, True, "100", 1.5, None):
        with pytest.raises(StegoError):
            S.select_cover(bad, PI, seeds=seeds(1))


def test_production_selection_uses_fresh_seeds_each_time(monkeypatch):
    monkeypatch.delenv("IOD_STEGO_GENERATOR_TEST_SEED", raising=False)
    a, b = S.select_cover(200, PI), S.select_cover(200, PI)
    fa = {c["seed_fingerprint"] for c in a.generation["candidates"]}
    fb = {c["seed_fingerprint"] for c in b.generation["candidates"]}
    assert len(fa) == 2 and not (fa & fb) and not np.array_equal(a.array, b.array)
    assert a.generation["seeding"] == "os-random"
