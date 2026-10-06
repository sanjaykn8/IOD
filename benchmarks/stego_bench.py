"""Per-algorithm steganography benchmark over the bundled fixture covers.

Real measurements via stego.benchmark.measure_one, repeated N trials per
(cover, payload size, algorithm); reports avg/p50/p95 for timings, and the
(deterministic) capacity/MSE/PSNR/SSIM from the last trial. Exports
CSV + JSON next to this file. Run: python-service/venv/bin/python benchmarks/stego_bench.py
"""
import csv, json, os, platform, statistics, sys
import numpy as np
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python-service", "src"))
from stego.benchmark import measure_one
from stego.registry import all_algorithm_ids

TRIALS = 10
COVERS = {n: np.array(Image.open(os.path.join(ROOT, "rust-core/tests/fixtures", n)).convert("RGB"))
          for n in ("cover_d1_to_gcs.png", "cover_gcs_to_d1.png")}
PAYLOADS = [1024, 8192, 50007]  # 50007B = real sealed R1 EnrollmentRequest size observed in the live run
rng = np.random.default_rng(12345)

def pct(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p / 100
    f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)

rows = []
for cname, cover in COVERS.items():
    for size in PAYLOADS:
        payload = bytes(rng.integers(0, 256, size, dtype=np.uint8))
        for aid in all_algorithm_ids():
            ms = [measure_one(aid, cover, payload) for _ in range(TRIALS)]
            m = ms[-1]
            e = [x.embed_time_ms for x in ms]; x_ = [x.extract_time_ms for x in ms]
            rows.append(dict(cover=cname, resolution=f"{cover.shape[1]}x{cover.shape[0]}", payload_bytes=size,
                algorithm=aid, feasible=m.feasible, reason=m.reason, capacity_bytes=m.capacity_bytes,
                embed_avg_ms=round(statistics.mean(e), 3), embed_p50_ms=round(pct(e, 50), 3), embed_p95_ms=round(pct(e, 95), 3),
                extract_avg_ms=round(statistics.mean(x_), 3), extract_p50_ms=round(pct(x_, 50), 3), extract_p95_ms=round(pct(x_, 95), 3),
                mse=round(m.mse, 6), psnr_db=round(m.psnr_db, 3), ssim=round(m.ssim, 6), trials=TRIALS))
meta = dict(trials=TRIALS, python=platform.python_version(), platform=platform.platform(), cpu_count=os.cpu_count(),
            note="Shared sandbox VM, single process; relative comparison only, not drone-hardware performance.")
out = os.path.join(ROOT, "benchmarks")
json.dump(dict(meta=meta, results=rows), open(os.path.join(out, "stego_benchmark.json"), "w"), indent=2)
with open(os.path.join(out, "stego_benchmark.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
for r in rows:
    print(f"{r['cover'][:12]} {r['payload_bytes']:>6}B {r['algorithm']:<13} feas={str(r['feasible']):<5} cap={r['capacity_bytes']:>7} "
          f"emb={r['embed_avg_ms']:>9.2f}ms ext={r['extract_avg_ms']:>9.2f}ms ssim={r['ssim']:.4f} psnr={r['psnr_db']:.2f}")
