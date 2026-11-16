#!/usr/bin/env python3
"""Cover-generator benchmark and quality report (offline; NumPy only).

Runs the OPERATIONAL selection path (`stego.generator.select.select_cover`: generate candidates with
OS randomness -> quality pre-screen -> real planner in descending quality order) under a resource
profile, a fresh cover per transaction, and measures per-stage wall time, candidates, failures and
Python-heap peak (tracemalloc, measured in a separate pass because tracing slows execution).
It also writes a generator QUALITY report: per-family gate pass rates, score distribution and
rejection reasons over fresh covers.

The profile enforces RESOURCE LIMITS only. On any machine other than a Raspberry Pi 5 the output is a
"profile-constrained host benchmark": it is NOT a Raspberry Pi measurement and is labelled accordingly.
To measure a real Raspberry Pi 5, run this same command on the device:

    python3 scripts/bench_generator.py --profile raspberry_pi_5_cpu --runs 30 --out docs/samples

Usage: python3 scripts/bench_generator.py [--profile raspberry_pi_5_cpu] [--runs 30] [--payloads 96,512,2048,5000]
                                          [--quality-covers 60] [--out DIR]
"""
import argparse, json, os, platform, sys, time, tracemalloc

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python-service", "src"))

from stego.errors import StegoError                                          # noqa: E402
from stego.generator import GENERATOR_VERSION, QUALITY_VERSION, families, profile, quality, select   # noqa: E402


def host_metadata():
    def read(p):
        try:
            with open(p, "rb") as fh:
                return fh.read().decode("utf-8", "replace").strip("\x00\n ")
        except OSError:
            return None
    model = read("/proc/device-tree/model")
    cpu = None
    info = read("/proc/cpuinfo") or ""
    for line in info.splitlines():
        if line.startswith(("model name", "Model", "Hardware")) and ":" in line:
            cpu = line.split(":", 1)[1].strip()
            break
    mem = None
    for line in (read("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal"):
            mem = int(line.split()[1]) // 1024
    return {"system": platform.system(), "machine": platform.machine(), "device_model": model, "cpu_model": cpu or platform.processor() or None,
            "logical_cpus": os.cpu_count(), "mem_total_mb": mem, "python": platform.python_version(), "numpy": np.__version__,
            "is_raspberry_pi_5": bool(model and "Raspberry Pi 5" in model)}


def stats(v):
    v = [float(x) for x in v if x is not None]
    if not v:
        return {"n": 0, "mean": None, "p50": None, "p95": None, "min": None, "max": None}
    a = np.array(v)
    pct = len(v) >= 20          # same rule as the transport report: no percentiles from fewer than 20 samples
    return {"n": len(v), "mean": round(float(a.mean()), 3), "p50": round(float(np.percentile(a, 50)), 3) if pct else None,
            "p95": round(float(np.percentile(a, 95)), 3) if pct else None, "min": round(float(a.min()), 3), "max": round(float(a.max()), 3)}


def one(payload, cfg):
    t = time.perf_counter()
    try:
        sel = select.select_cover(payload, cfg)
        g = sel.generation
        return {"ok": True, "wall_ms": (time.perf_counter() - t) * 1000.0, "generate": g["timings_ms"]["generate"], "prescreen": g["timings_ms"]["prescreen"],
                "plan": g["timings_ms"]["plan"], "total": g["timings_ms"]["total"], "candidates": g["candidate_count"], "planner_invocations": g["planner_invocations"],
                "family": g["family"], "quality": g["quality_score"], "exceeded": g["budget"]["exceeded"], "resized": g["resized"],
                "size": [g["actual"]["width"], g["actual"]["height"]], "rejections": [r for c in g["candidates"] for r in c["rejection_reasons"]]}
    except StegoError as exc:
        d = exc.details or {}
        return {"ok": False, "wall_ms": (time.perf_counter() - t) * 1000.0, "code": exc.code, "reason": d.get("reason"),
                "rejections": [r for c in d.get("candidates", []) for r in c.get("rejection_reasons", [])]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", default=profile.DEFAULT_PROFILE, choices=sorted(profile.PROFILES))
    ap.add_argument("--runs", type=int, default=30, help="transactions per payload size (a fresh cover each)")
    ap.add_argument("--payloads", default="96,512,2048,5000", help="payload-section sizes in bytes")
    ap.add_argument("--memory-runs", type=int, default=5)
    ap.add_argument("--quality-covers", type=int, default=60, help="fresh covers per family for the quality report")
    ap.add_argument("--allow-resize", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "samples"))
    a = ap.parse_args()
    cfg = profile.process_config({"IOD_STEGO_GENERATOR_PROFILE": a.profile})
    if a.allow_resize:
        cfg = profile.resolve({"allow_payload_driven_resize": True}, cfg)
    payloads = [int(x) for x in a.payloads.split(",") if x.strip()]
    host = host_metadata()
    label = (f"Raspberry Pi 5 measurement ({host['device_model']})" if host["is_raspberry_pi_5"] and a.profile == "raspberry_pi_5_cpu"
             else f"profile-constrained host benchmark ({a.profile}): the profile's limits were enforced on THIS host; NOT a measurement of the profile's target hardware")
    print(label)
    print("host:", json.dumps(host))
    t0 = time.time()
    rows = []
    for pb in payloads:
        runs = [one(pb, cfg) for _ in range(a.runs)]
        ok = [r for r in runs if r["ok"]]
        fam, rej, codes = {}, {}, {}
        for r in runs:
            for x in r["rejections"]:
                rej[x] = rej.get(x, 0) + 1
            if r["ok"]:
                fam[r["family"]] = fam.get(r["family"], 0) + 1
            else:
                codes[r["code"]] = codes.get(r["code"], 0) + 1
        tracemalloc.start()
        peaks = []
        for _ in range(a.memory_runs):
            tracemalloc.reset_peak()
            one(pb, cfg)
            peaks.append(tracemalloc.get_traced_memory()[1] / (1024 * 1024))
        tracemalloc.stop()
        row = {"payload_bytes": pb, "runs": a.runs, "ok": len(ok), "failed": len(runs) - len(ok), "failure_codes": codes,
               "timings_ms": {k: stats([r[k] for r in ok]) for k in ("generate", "prescreen", "plan", "total", "wall_ms")},
               "candidates_generated": stats([r["candidates"] for r in ok]), "planner_invocations": stats([r["planner_invocations"] for r in ok]),
               "cover_quality_score": stats([r["quality"] for r in ok]), "families_selected": fam, "candidate_rejection_reasons": rej,
               "budget_ms": cfg.processing_budget_ms, "budget_exceeded": sum(1 for r in ok if r["exceeded"]), "resized": sum(1 for r in ok if r["resized"]),
               "tracemalloc_peak_mb": stats(peaks), "memory_estimate_mb": round(profile.memory_estimate_bytes(cfg.width, cfg.height, cfg.max_candidates) / (1024 * 1024), 2),
               "memory_limit_mb": cfg.max_working_memory_mb}
        rows.append(row)
        tm = row["timings_ms"]
        print(f"{pb:>6} B  ok {len(ok)}/{a.runs}  total mean {tm['total']['mean']} ms (p50 {tm['total']['p50']}, p95 {tm['total']['p95']})  generate {tm['generate']['mean']}  prescreen {tm['prescreen']['mean']}  "
              f"plan {tm['plan']['mean']}  candidates {row['candidates_generated']['mean']}  over-budget {row['budget_exceeded']}  peak {row['tracemalloc_peak_mb']['max']} MB  failures {codes}", flush=True)

    # ---- quality report: fresh covers, every family, operational gates
    qrep = {}
    metrics_keys = None
    for fam in cfg.families:
        scores, reasons, passed, gen_ms, pre_ms, meas = [], {}, 0, [], [], []
        for _ in range(a.quality_covers):
            t = time.perf_counter()
            arr, _info = families.generate(select.fresh_seed(), cfg.width, cfg.height, cfg.mode, fam)
            gen_ms.append((time.perf_counter() - t) * 1000.0)
            t = time.perf_counter()
            q = quality.evaluate(arr, cfg.min_quality_score)
            pre_ms.append((time.perf_counter() - t) * 1000.0)
            scores.append(q["score"])
            meas.append(q["metrics"])
            passed += bool(q["passed"])
            for r in q["rejection_reasons"]:
                reasons[r] = reasons.get(r, 0) + 1
        metrics_keys = sorted(meas[0])
        qrep[fam] = {"covers": a.quality_covers, "passed": passed, "pass_rate": round(passed / a.quality_covers, 4), "score": stats(scores),
                     "rejection_reasons": reasons, "generate_ms": stats(gen_ms), "prescreen_ms": stats(pre_ms),
                     "metric_means": {k: round(float(np.mean([m[k] for m in meas])), 5) for k in metrics_keys}}
        print(f"quality {fam:<8} pass {passed}/{a.quality_covers}  score mean {qrep[fam]['score']['mean']} min {qrep[fam]['score']['min']}  rejections {reasons}", flush=True)

    out = {"schema": "generator-bench-1", "measurement_label": label, "host": host, "generator_version": GENERATOR_VERSION, "quality_version": QUALITY_VERSION,
           "profile": a.profile, "config": cfg.to_dict(), "seeding": select.seeding_mode(), "fresh_cover_per_transaction": True,
           "benchmark": rows,
           "quality_report": {"size": [cfg.width, cfg.height], "mode": cfg.mode, "min_quality_score": cfg.min_quality_score, "gates": quality.GATES,
                              "weights": quality.WEIGHTS, "families": qrep,
                              "note": "Scores and gates are documented heuristics for coherent, natural-looking structure. They are not a steganalysis detector."},
           "wall_seconds": round(time.time() - t0, 1),
           "limitations": ["Single process, one worker, wall-clock timing on a shared machine.",
                           "tracemalloc reports the Python/NumPy heap peak during one selection, not the resident set size of the service.",
                           "Percentiles are null below 20 samples.",
                           "Unless is_raspberry_pi_5 is true, nothing here is a Raspberry Pi measurement."]}
    os.makedirs(a.out, exist_ok=True)
    name = f"generator-benchmark-{a.profile}{'-on-pi5' if host['is_raspberry_pi_5'] else '-host'}.json"
    with open(os.path.join(a.out, name), "w") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", os.path.join(a.out, name))


if __name__ == "__main__":
    main()
