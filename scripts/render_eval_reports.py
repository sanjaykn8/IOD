#!/usr/bin/env python3
"""Render the measured JSON results (detectability evaluation, generator benchmark) as Markdown tables.

The tables in docs/detectability-evaluation.md and docs/benchmarking.md are produced by this script from
docs/samples/*.json, so the documents never contain hand-copied numbers.

Usage: python3 scripts/render_eval_reports.py detectability|generator [json-file]
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "docs", "samples")


def f(x, n=3):
    return "n/a" if x is None else f"{x:.{n}f}"


def ci(v):
    return "n/a" if not v else f"{v[0]:.3f}–{v[1]:.3f}"


def detectability(path):
    d = json.load(open(path))
    if d.get("schema") != "detectability-eval-2":
        raise SystemExit("expected schema detectability-eval-2")
    c = d["cover"]
    dets = list(d["detectors"])
    out = [f"Source: `docs/samples/{os.path.basename(path)}` · transport `{d['transport_format']}` · generator `{d['generator_version']}` · "
           f"risk table `{d['risk_table']}` · train {c['train_accepted']} / test {c['test_accepted']} covers "
           f"({c['train_seeds_per_family']} / {c['test_seeds_per_family']} seeds × {len(c['families'])} families, {c['width']}×{c['height']} RGB) · "
           f"features: {d['features']['basic_count']} basic + {d['features']['srm_lite_count']} SRM-lite · wall time {d['wall_seconds']} s · "
           f"command `{d['command']}`.", ""]

    def cell(r, det):
        m = r["detectors"].get(det, {})
        if "auc" not in m:
            return "n/a"
        return f"**{m['auc']:.3f}** ({ci(m.get('auc_ci95'))})"

    def tpr(r, det):
        m = r["detectors"].get(det, {})
        return f(m.get("tpr_at_1pct_fpr"), 2) if "auc" in m else "n/a"

    rows = [r for r in d["results"] if r["kind"] in ("transport", "carrier_only", "patches_only")]
    out += ["**Operational transport and diagnostics** (ROC-AUC on the untouched test split, 95 % seed-bootstrap interval; TPR at 1 % FPR; "
            f"resolution of the FPR is 1/{rows[0].get('n_test_pairs', '?') if rows else '?'})", "",
            "| Condition | Payload (B) | Bits / sample | Test pairs | PSNR (dB) | " + " | ".join(f"AUC {x}" for x in dets) + " | " + " | ".join(f"TPR@1% {x}" for x in dets) + " |",
            "|---|---|---|---|---|" + "---|" * (2 * len(dets))]
    for r in rows:
        out.append(f"| `{r['condition']}` | {r.get('payload_bytes', 'n/a')} | {f(r.get('bits_per_sample_mean'), 4)} | {r.get('n_test_pairs', 0)} | {f(r.get('psnr_db_mean'), 1)} | "
                   + " | ".join(cell(r, x) for x in dets) + " | " + " | ".join(tpr(r, x) for x in dets) + " |")
    out.append("")
    for r in rows:
        if r.get("algorithms_selected_patches"):
            out.append(f"* `{r['condition']}` patches by algorithm (test split): " + ", ".join(f"`{k}` {v}" for k, v in r["algorithms_selected_patches"].items()) + ".")
    out.append("")
    singles = [r for r in d["results"] if r["kind"] == "single"]
    if singles:
        rates = sorted({r["requested_rate_bps"] for r in singles})
        algs = []
        for r in singles:
            if r["algorithm"] not in algs:
                algs.append(r["algorithm"])
        for det in dets:
            out += [f"**Single algorithm over the whole image, detector `{det}`** (AUC; measured rate in bits per sample when below the request)", "",
                    "| Algorithm | " + " | ".join(f"{x} b/s" for x in rates) + " |", "|---|" + "---|" * len(rates)]
            for a in algs:
                cells = []
                for rate in rates:
                    r = next((x for x in singles if x["algorithm"] == a and x["requested_rate_bps"] == rate), None)
                    if not r or "auc" not in r["detectors"].get(det, {}):
                        cells.append("refused" if r and r.get("refused") else "n/a")
                        continue
                    m = r["detectors"][det]
                    short = r.get("short_of_rate") and r.get("bits_per_sample_mean") is not None and r["bits_per_sample_mean"] < rate * 0.98
                    cells.append(f"{m['auc']:.3f}" + (f" @{r['bits_per_sample_mean']:.3f}" if short else ""))
                out.append(f"| `{a}` | " + " | ".join(cells) + " |")
            out.append("")
    med = next((r for r in d["results"] if r["condition"] == "transport_med"), None)
    if med:
        fams = sorted(next(iter(med["detectors"].values())).get("per_family_auc", {}))
        out += ["**Per family and held-out family, `transport_med`** (per-family AUC of the model trained on all training families / "
                "AUC on a family whose covers were never in training)", "",
                "| Detector | " + " | ".join(f"{x} (all / held out)" for x in fams) + " | Held-out mean |", "|---|" + "---|" * (len(fams) + 1)]
        for det in dets:
            m = med["detectors"].get(det, {})
            if "auc" not in m:
                continue
            out.append(f"| `{det}` | " + " | ".join(f"{f(m['per_family_auc'].get(x))} / {f(m['held_out_family_auc'].get(x))}" for x in fams) + f" | {f(m.get('held_out_family_auc_mean'))} |")
        out.append("")
    fc = d.get("cover_family_classification", {})
    if fc:
        out.append("**Cover-only family classification** (test accuracy; chance " + f"{next(iter(fc.values()))['chance']:.2f}): " +
                   ", ".join(f"`{k}` {v['accuracy']:.3f}" for k, v in fc.items()) + ".")
        out.append("")
    return "\n".join(out)


def st(s, unit=""):
    if not s or s.get("mean") is None:
        return "n/a"
    p = f" (p50 {s['p50']}, p95 {s['p95']})" if s.get("p50") is not None else ""
    return f"{s['mean']}{unit}{p}"


def generator(path):
    d = json.load(open(path))
    h, c = d["host"], d["config"]
    out = [f"Source: `docs/samples/{os.path.basename(path)}`. **{d['measurement_label']}.**", "",
           f"Host: {h.get('device_model') or h.get('cpu_model')} · {h['machine']} · {h['logical_cpus']} logical CPUs · {h['mem_total_mb']} MB RAM · Python {h['python']} · NumPy {h['numpy']} · "
           f"`is_raspberry_pi_5: {str(h['is_raspberry_pi_5']).lower()}`.",
           f"Profile `{d['profile']}`: {c['width']}×{c['height']} {c['mode']}, ceiling {c['max_width']}×{c['max_height']}, ≤ {c['max_candidates']} candidates, budget {c['processing_budget_ms']} ms, "
           f"memory ≤ {c['max_working_memory_mb']} MB, {c['workers']} worker, seeding `{d['seeding']}`, a fresh cover per transaction.", "",
           "| Payload (B) | OK / runs | Selection total ms | Generate ms | Pre-screen ms | Planner ms | Candidates generated | Planner runs | Quality score | Over budget | Heap peak MB (max) | Failures |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in d["benchmark"]:
        t = r["timings_ms"]
        out.append(f"| {r['payload_bytes']} | {r['ok']} / {r['runs']} | {st(t['total'])} | {st(t['generate'])} | {st(t['prescreen'])} | {st(t['plan'])} | {r['candidates_generated']['mean']} | "
                   f"{r['planner_invocations']['mean']} | {r['cover_quality_score']['mean']} | {r['budget_exceeded']} | {r['tracemalloc_peak_mb']['max']} | {json.dumps(r['failure_codes']) if r['failure_codes'] else '—'} |")
    q = d["quality_report"]
    out += ["", f"Generator quality report ({q['size'][0]}×{q['size'][1]} {q['mode']}, fresh OS-random covers, score floor {q['min_quality_score']}):", "",
            "| Family | Passed / covers | Score mean (min – max) | Rejection reasons | Generate ms | Pre-screen ms | adjacent corr. | lag-8 corr. | spectral slope | high-pass σ | RMS contrast | flat blocks | clipped |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for fam, v in q["families"].items():
        m = v["metric_means"]
        out.append(f"| `{fam}` | {v['passed']} / {v['covers']} | {v['score']['mean']} ({v['score']['min']} – {v['score']['max']}) | {json.dumps(v['rejection_reasons']) if v['rejection_reasons'] else '—'} | {st(v['generate_ms'])} | {st(v['prescreen_ms'])} | "
                   f"{m.get('adjacent_correlation')} | {m.get('lag8_correlation')} | {m.get('spectral_slope')} | {m.get('highpass_std')} | {m.get('rms_contrast')} | {m.get('flat_block_fraction')} | {m.get('clipped_fraction')} |")
    return "\n".join(out)


if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv) > 1 else "detectability"
    if kind == "detectability":
        print(detectability(sys.argv[2] if len(sys.argv) > 2 else os.path.join(S, "detectability-results.json")))
    else:
        print(generator(sys.argv[2] if len(sys.argv) > 2 else os.path.join(S, "generator-benchmark-raspberry_pi_5_cpu-host.json")))
