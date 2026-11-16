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
    c = d["cover"]
    out = [f"Source: `docs/samples/{os.path.basename(path)}` · generator `{d['generator_version']}` · {c['accepted']} covers "
           f"({c['test_seeds_per_family']} test seeds × {len(c['families'])} families, {c['width']}×{c['height']} {c['mode']}, all passed the quality gates"
           f"{'' if not c['rejection_reasons'] else ' except ' + json.dumps(c['rejection_reasons'])}) · {d['detector']['feature_count']} features · "
           f"{d['protocol']['split']} · wall time {d['wall_seconds']} s.", ""]
    for nb in sorted({r["payload_bytes_requested"] for r in d["results"] if "auc" in r}):
        rows = [r for r in d["results"] if r.get("payload_bytes_requested") == nb and "auc" in r]
        out += [f"**Payload {nb} bytes** ({rows[0]['bits_per_sample_mean']:.4f} payload bits per cover sample for the transport)", "",
                "| Condition | Pairs | Embedded (mean B) | PSNR (dB) | ROC-AUC | AUC 95 % CI | Accuracy | Acc. 95 % CI | Precision | Recall | Confusion (cover→cover / cover→stego / stego→cover / stego→stego) | Leave-one-family-out AUC (mean) |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            cm = r["confusion_matrix"]
            out.append(f"| `{r['condition']}` | {r['n_pairs']} | {r['payload_bytes_embedded_mean']:.0f} | {f(r['psnr_db_mean'], 1)} | **{r['auc']:.3f}** | {ci(r['auc_ci95'])} | {r['accuracy']:.3f} | {ci(r['accuracy_ci95'])} | "
                       f"{f(r['precision'])} | {f(r['recall'])} | {cm['true_cover_pred_cover']} / {cm['true_cover_pred_stego']} / {cm['true_stego_pred_cover']} / {cm['true_stego_pred_stego']} | {f(r['leave_one_family_out_mean_auc'])} |")
        mixed = next((r for r in rows if r["condition"] == "patch_mixed"), None)
        if mixed:
            out += ["", f"Algorithms the planner selected in `patch_mixed` at {nb} bytes (patches over all covers): " + ", ".join(f"`{k}` {v}" for k, v in mixed["algorithms_selected_patches"].items()) + ".",
                    "Leave-one-family-out AUC of `patch_mixed`: " + ", ".join(f"{k} {v['auc']:.3f}" for k, v in mixed["leave_one_family_out"].items()) + "."]
        out.append("")
    if d["skipped_count"]:
        out.append(f"Embeddings skipped (algorithm refused the image or payload): {d['skipped_count']}.")
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
