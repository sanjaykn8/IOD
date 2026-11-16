#!/usr/bin/env python3
"""OFFLINE detectability evaluation of the generated covers and the patch-wise transport.

This is an evaluation tool, not part of the running system, and its result is NOT a security claim.

What it does
------------
1. Generates procedural covers with the operational generator (`stego.generator`), for every family and a
   list of explicit TEST seeds (the only place seeds are chosen by hand; operation uses OS randomness),
   and keeps the covers that pass the operational quality gates.
2. Produces cover/stego pairs
     * `patch_mixed`  -- the operational path: real planner (segmentation + knowledge-base selection per
       patch) + real patch-wise embedding of a random frame, including the in-image bootstrap carrier;
     * `patch_mixed_below_carrier` -- the same images, but the detector only sees the rows below the
       reserved carrier rows (top 16 rows cropped from cover and stego), which separates the trace of the
       patch embedding from the trace of the plain-LSB bootstrap carrier;
     * one condition per algorithm (ten) -- that single algorithm embeds random bytes over the whole image
       (no carrier), which isolates the statistical trace of each algorithm variant.
   for several payload sizes.
3. Extracts a small, fully transparent feature vector (documented in `FEATURES`): truncated residual
   co-occurrences (first-order SPAM-like), LSB-plane statistics, a pairs-of-values chi-square, histogram
   characteristic-function moments, high-pass residual moments and 8x8 blockiness.
4. Trains a small classical detector written here from scratch (standardisation + L2-regularised logistic
   regression fitted by Newton/IRLS; NumPy only -- no scikit-learn, no pretrained model, no network).
5. Evaluates with splits that never put a cover and its own stego image on different sides:
     * grouped K-fold by seed (out-of-fold scores), and
     * leave-one-family-out (trained on three families, tested on the unseen fourth).
   Reports ROC-AUC, accuracy, precision, recall, the confusion matrix and bootstrap 95 % confidence
   intervals (resampling seeds), per algorithm and for the patch-mixed transport.

How to read the numbers
-----------------------
AUC 0.5 = this detector cannot tell cover from stego; AUC 1.0 = it always can. A low AUC here means only
that THIS weak, hand-made detector with THESE features and THIS little training data did not separate
the classes. It does not mean "undetectable": modern learned steganalysers are much stronger, and an
adversary who knows the generator can train on unlimited generated covers.

Usage:  python3 scripts/eval_detectability.py [--seeds 40] [--payloads 256,1536] [--out DIR] [--quick]
"""
import argparse, hashlib, json, os, platform, sys, time

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python-service", "src"))

from stego import codec, config                                    # noqa: E402
from stego.algorithms import BY_NAME                               # noqa: E402
from stego.errors import StegoError                                # noqa: E402
from stego.generator import GENERATOR_VERSION, QUALITY_VERSION, families, quality   # noqa: E402
from stego.patch import manifest as M, planner                     # noqa: E402
from stego.patch.region import CoverCtx, Region                    # noqa: E402

T = 3  # residual truncation
CARRIER_CROP = 16  # rows removed for the `patch_mixed_below_carrier` condition (the carrier needs fewer than this at the evaluated sizes)
FEATURES = [
    ("spam1[49]", "first-order co-occurrence of horizontally/vertically adjacent pixel differences truncated to [-3,3], "
                  "averaged over both directions and all channels (7x7 normalised counts)"),
    ("lsb_ones", "fraction of ones in the least-significant bit plane"),
    ("lsb_corr_h / lsb_corr_v", "correlation of the LSB plane with its right / lower neighbour"),
    ("lsb_msb_corr", "correlation between bit 0 and bit 1"),
    ("pov_chi2", "pairs-of-values chi-square statistic of the histogram, divided by the number of populated pairs"),
    ("hist_pair_diff", "mean |h[2k]-h[2k+1]| / (h[2k]+h[2k+1]) over populated pairs"),
    ("hcf_com", "centre of mass of the histogram characteristic function (|DFT| of the 256-bin histogram)"),
    ("hist_smooth", "mean absolute second difference of the normalised histogram"),
    ("hp_std / hp_mad / hp_kurt", "standard deviation, mean absolute value and kurtosis of a 3x3 high-pass (KV-style) residual"),
    ("d1_std / d1_kurt", "standard deviation and kurtosis of first differences"),
    ("d2_mad", "mean absolute second difference"),
    ("block8", "8x8 blockiness: mean |difference| across block boundaries divided by the same inside blocks"),
    ("parity_run", "mean run length of equal LSBs along rows"),
]
FEATURE_NAMES = ([f"spam1_{a}_{b}" for a in range(-T, T + 1) for b in range(-T, T + 1)]
                 + ["lsb_ones", "lsb_corr_h", "lsb_corr_v", "lsb_msb_corr", "pov_chi2", "hist_pair_diff", "hcf_com", "hist_smooth",
                    "hp_std", "hp_mad", "hp_kurt", "d1_std", "d1_kurt", "d2_mad", "block8", "parity_run"])


def _corr(a, b):
    a = a.astype(np.float64).ravel() - a.mean()
    b = b.astype(np.float64).ravel() - b.mean()
    d = np.sqrt((a * a).sum() * (b * b).sum())
    return float((a * b).sum() / d) if d > 0 else 0.0


def _kurt(x):
    x = x.astype(np.float64).ravel()
    s = x.std()
    return float(((x - x.mean()) ** 4).mean() / s ** 4) if s > 0 else 0.0


def _cooc(d):
    """7x7 normalised co-occurrence of neighbouring truncated differences along the last axis."""
    d = np.clip(d, -T, T) + T
    idx = (d[..., :-1] * (2 * T + 1) + d[..., 1:]).ravel()
    c = np.bincount(idx, minlength=(2 * T + 1) ** 2).astype(np.float64)
    return c / max(c.sum(), 1.0)


def _channel_features(x):
    xi = x.astype(np.int16)
    dh = xi[:, 1:] - xi[:, :-1]
    dv = (xi[1:, :] - xi[:-1, :]).T
    spam = 0.5 * (_cooc(dh) + _cooc(dv))
    lsb = (x & 1).astype(np.int8)
    b1 = ((x >> 1) & 1).astype(np.int8)
    h = np.bincount(x.ravel(), minlength=256).astype(np.float64)
    ev, od = h[0::2], h[1::2]
    tot = ev + od
    pop = tot > 0
    exp = tot[pop] / 2.0
    chi = float((((ev[pop] - exp) ** 2) / exp).sum() / max(int(pop.sum()), 1))
    pair = float((np.abs(ev[pop] - od[pop]) / tot[pop]).mean()) if pop.any() else 0.0
    hn = h / h.sum()
    f = np.abs(np.fft.rfft(hn))[1:]
    hcf = float((np.arange(1, f.size + 1) * f).sum() / f.sum()) if f.sum() > 0 else 0.0
    smooth = float(np.abs(hn[2:] - 2 * hn[1:-1] + hn[:-2]).mean())
    xf = x.astype(np.float64)
    hp = (-xf[:-2, :-2] + 2 * xf[:-2, 1:-1] - xf[:-2, 2:] + 2 * xf[1:-1, :-2] - 4 * xf[1:-1, 1:-1] + 2 * xf[1:-1, 2:]
          - xf[2:, :-2] + 2 * xf[2:, 1:-1] - xf[2:, 2:]) / 4.0
    d2 = xf[:, 2:] - 2 * xf[:, 1:-1] + xf[:, :-2]
    adh = np.abs(dh).astype(np.float64)
    cols = np.arange(adh.shape[1])
    edge = adh[:, cols % 8 == 7].mean()
    inner = adh[:, cols % 8 != 7].mean()
    changes = np.count_nonzero(lsb[:, 1:] != lsb[:, :-1])
    run = float(lsb.size / (changes + lsb.shape[0]))
    extra = [float(lsb.mean()), _corr(lsb[:, :-1], lsb[:, 1:]), _corr(lsb[:-1, :], lsb[1:, :]), _corr(lsb, b1), chi, pair, hcf, smooth,
             float(hp.std()), float(np.abs(hp).mean()), _kurt(hp), float(dh.std()), _kurt(dh), float(np.abs(d2).mean()),
             float(edge / inner) if inner > 0 else 1.0, run]
    return np.concatenate([spam, np.array(extra)])


def features(arr):
    if arr.ndim == 2:
        return _channel_features(arr)
    return np.mean([_channel_features(arr[:, :, c]) for c in range(arr.shape[2])], axis=0)


# ------------------------------------------------------------------ detector (from scratch)
class LogReg:
    """Standardisation + L2-regularised logistic regression, fitted by Newton's method (IRLS)."""

    def __init__(self, l2=1.0, iters=50):
        self.l2, self.iters = l2, iters

    def fit(self, X, y):
        self.mu = X.mean(axis=0)
        self.sd = X.std(axis=0)
        self.sd[self.sd < 1e-12] = 1.0
        Z = np.hstack([(X - self.mu) / self.sd, np.ones((X.shape[0], 1))])
        w = np.zeros(Z.shape[1])
        reg = np.eye(Z.shape[1]) * self.l2
        reg[-1, -1] = 0.0                      # the bias is not penalised
        for _ in range(self.iters):
            p = 1.0 / (1.0 + np.exp(-np.clip(Z @ w, -30, 30)))
            g = Z.T @ (p - y) + reg @ w
            H = (Z * (p * (1 - p))[:, None]).T @ Z + reg + 1e-9 * np.eye(Z.shape[1])
            step = np.linalg.solve(H, g)
            w -= step
            if np.abs(step).max() < 1e-8:
                break
        self.w = w
        return self

    def score(self, X):
        Z = np.hstack([(X - self.mu) / self.sd, np.ones((X.shape[0], 1))])
        return 1.0 / (1.0 + np.exp(-np.clip(Z @ self.w, -30, 30)))


def auc(y, s):
    """ROC-AUC as the Mann-Whitney statistic (ties count one half)."""
    y = np.asarray(y)
    s = np.asarray(s, dtype=np.float64)
    pos, neg = s[y == 1], s[y == 0]
    if pos.size == 0 or neg.size == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(s.size)
    sorted_s = s[order]
    i = 0
    while i < s.size:
        j = i
        while j + 1 < s.size and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((ranks[y == 1].sum() - pos.size * (pos.size + 1) / 2.0) / (pos.size * neg.size))


def classification(y, s, thr=0.5):
    y = np.asarray(y)
    pred = (np.asarray(s) >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    return {"accuracy": (tp + tn) / max(len(y), 1), "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
            "confusion_matrix": {"true_cover_pred_cover": tn, "true_cover_pred_stego": fp, "true_stego_pred_cover": fn, "true_stego_pred_stego": tp}}


def bootstrap_ci(y, s, groups, rng, reps=1000):
    """95 % percentile intervals, resampling whole seeds (a cover and its stego stay together)."""
    y, s, groups = np.asarray(y), np.asarray(s), np.asarray(groups)
    uniq = np.unique(groups)
    index = {g: np.nonzero(groups == g)[0] for g in uniq}
    aucs, accs = [], []
    for _ in range(reps):
        pick = rng.choice(uniq, size=uniq.size, replace=True)
        idx = np.concatenate([index[g] for g in pick])
        a = auc(y[idx], s[idx])
        if a == a:
            aucs.append(a)
        accs.append(float(((s[idx] >= 0.5).astype(int) == y[idx]).mean()))
    q = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None
    return {"auc_ci95": q(aucs), "accuracy_ci95": q(accs)}


def evaluate(Xc, Xs, seed_ids, fams, rng, folds=5, l2=1.0):
    """Xc/Xs: features of covers and of their stego images (row i belongs to seed_ids[i], fams[i])."""
    n = Xc.shape[0]
    X = np.vstack([Xc, Xs])
    y = np.concatenate([np.zeros(n), np.ones(n)])
    g = np.concatenate([seed_ids, seed_ids])
    f = np.concatenate([fams, fams])
    uniq = np.unique(seed_ids)
    perm = rng.permutation(uniq)
    fold_of = {s: i % folds for i, s in enumerate(perm)}
    oof = np.full(2 * n, np.nan)
    for k in range(folds):
        te = np.array([fold_of[s] == k for s in g])
        if te.sum() == 0 or (~te).sum() == 0:
            continue
        oof[te] = LogReg(l2).fit(X[~te], y[~te]).score(X[te])
    ok = ~np.isnan(oof)
    res = {"n_pairs": int(n), "split": f"grouped {folds}-fold by seed (a cover and its stego are always on the same side)",
           "auc": auc(y[ok], oof[ok]), **classification(y[ok], oof[ok]), **bootstrap_ci(y[ok], oof[ok], g[ok], rng)}
    lofo = {}
    for fam in sorted(set(fams)):
        te = f == fam
        if te.sum() < 4 or (~te).sum() < 8:
            continue
        s = LogReg(l2).fit(X[~te], y[~te]).score(X[te])
        lofo[fam] = {"n_pairs": int(te.sum() // 2), "auc": auc(y[te], s), "accuracy": classification(y[te], s)["accuracy"]}
    res["leave_one_family_out"] = lofo
    vals = [v["auc"] for v in lofo.values() if v["auc"] == v["auc"]]
    res["leave_one_family_out_mean_auc"] = float(np.mean(vals)) if vals else None
    return res


# ------------------------------------------------------------------ data
def test_seed(i, family):
    return hashlib.sha256(f"IOD-DETECT-EVAL-v1|{family}|{i}".encode()).digest()[:families.SEED_BYTES]


def rand_bytes(rng, n):
    return rng.integers(0, 256, size=n, dtype=np.uint8).tobytes()


def stego_mixed(arr, nbytes, rng, limits):
    """Operational path: plan for `nbytes` of payload section, embed a random frame patch-wise."""
    pl = planner.plan(arr, nbytes)
    wire = rand_bytes(rng, nbytes - 32)
    frame = M.frame_header(len(pl.manifest), len(wire)) + pl.manifest + wire + rand_bytes(rng, 32)
    out, _man, per = codec.embed_frame(arr, frame, limits)
    return out, {a: sum(1 for p in per if p.get("algorithm") == a) for a in {p["algorithm"] for p in per if p.get("used")}}


def stego_single(arr, name, nbytes, rng):
    """One algorithm over the whole image (no bootstrap carrier). Returns (stego, embedded_bytes) or (None, 0)."""
    alg = BY_NAME[name]
    reg = Region(0, np.ones(arr.shape[:2], dtype=bool))
    ok, _why = alg.support(arr, reg)
    if not ok:
        return None, 0
    stc = hasattr(alg, "choose_w")          # adaptive (STC-coded) algorithms need an explicit code width
    p = 0 if stc else alg.resolve_param(0)
    n = min(nbytes, int(alg.capacity_bits(arr, reg, p)) // 8)
    if n < 16:
        return None, 0
    if stc:
        p = alg.choose_w(arr, reg, n)        # same rule as the planner: sparsest rate that fits
        if not p:
            return None, 0
    out = arr.copy()
    data = rand_bytes(rng, n)
    alg.embed(CoverCtx(arr), reg, out, data, p)
    if alg.extract(out, reg, n, p) != data:
        return None, 0
    return out, n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seeds", type=int, default=40, help="test seeds per family")
    ap.add_argument("--payloads", default="256,1536", help="payload sizes in bytes (comma separated)")
    ap.add_argument("--width", type=int, default=320)
    ap.add_argument("--height", type=int, default=240)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--l2", type=float, default=1.0)
    ap.add_argument("--algorithms", default="all")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "samples"))
    ap.add_argument("--quick", action="store_true", help="tiny run for a smoke test (results are not meaningful)")
    a = ap.parse_args()
    if a.quick:
        a.seeds, a.payloads = 6, "256"
    payloads = [int(x) for x in a.payloads.split(",") if x.strip()]
    algs = sorted(BY_NAME, key=lambda n: BY_NAME[n].id) if a.algorithms == "all" else [x for x in a.algorithms.split(",") if x in BY_NAME]
    limits = config.Limits()
    rng = np.random.default_rng(20261115)
    t0 = time.time()

    covers, rejected = [], {}
    for fam in families.FAMILIES:
        for i in range(a.seeds):
            arr, _info = families.generate(test_seed(i, fam), a.width, a.height, "RGB", fam)
            q = quality.evaluate(arr, 0.70)
            if not q["passed"]:
                for r in q["rejection_reasons"]:
                    rejected[r] = rejected.get(r, 0) + 1
                continue
            covers.append({"family": fam, "seed": f"{fam}:{i}", "arr": arr, "feat": features(arr), "feat_crop": features(arr[CARRIER_CROP:]), "score": q["score"]})
    print(f"covers: {len(covers)} accepted, {sum(rejected.values())} rejection reasons {rejected}  ({time.time() - t0:.1f}s)", flush=True)
    seed_ids = np.array([c["seed"] for c in covers])
    fams = np.array([c["family"] for c in covers])
    Xc = np.array([c["feat"] for c in covers])
    Xc_crop = np.array([c["feat_crop"] for c in covers])

    results, skipped = [], []
    for nbytes in payloads:
        for cond in ["patch_mixed"] + algs:
            ts = time.time()
            keep, Xs, Xs_crop, emb, psnr, used = [], [], [], [], [], {}
            for k, c in enumerate(covers):
                try:
                    if cond == "patch_mixed":
                        out, u = stego_mixed(c["arr"], nbytes, rng, limits)
                        n = nbytes
                        Xs_crop.append(features(out[CARRIER_CROP:]))
                        for name, cnt in u.items():
                            used[name] = used.get(name, 0) + cnt
                    else:
                        out, n = stego_single(c["arr"], cond, nbytes, rng)
                except StegoError as exc:
                    out, n = None, 0
                    skipped.append({"condition": cond, "payload_bytes": nbytes, "seed": c["seed"], "code": exc.code})
                if out is None:
                    continue
                mse = float(np.mean((out.astype(np.float64) - c["arr"].astype(np.float64)) ** 2))
                keep.append(k); Xs.append(features(out)); emb.append(n)
                psnr.append(10 * np.log10(255.0 ** 2 / mse) if mse > 0 else float("inf"))
            if len(keep) < 4 * a.folds:
                results.append({"condition": cond, "payload_bytes": nbytes, "n_pairs": len(keep), "skipped": "too few pairs for the split"})
                continue
            keep = np.array(keep)
            r = evaluate(Xc[keep], np.array(Xs), seed_ids[keep], fams[keep], rng, a.folds, a.l2)
            samples = a.width * a.height * 3
            r.update({"condition": cond, "kind": "operational patch-wise transport (planner + KB selection + carrier)" if cond == "patch_mixed" else "single algorithm over the whole image, no carrier",
                      "payload_bytes_requested": nbytes, "payload_bytes_embedded_mean": float(np.mean(emb)),
                      "bits_per_sample_mean": float(np.mean(emb)) * 8 / samples,
                      "psnr_db_mean": float(np.mean([p for p in psnr if np.isfinite(p)])) if any(np.isfinite(p) for p in psnr) else None,
                      "seconds": round(time.time() - ts, 1)})
            if cond == "patch_mixed":
                r["algorithms_selected_patches"] = dict(sorted(used.items()))
            results.append(r)
            if cond == "patch_mixed" and len(Xs_crop) == len(keep):
                rc = evaluate(Xc_crop[keep], np.array(Xs_crop), seed_ids[keep], fams[keep], rng, a.folds, a.l2)
                rc.update({"condition": "patch_mixed_below_carrier", "kind": f"same images as patch_mixed; the detector sees only rows >= {CARRIER_CROP} (carrier rows cropped from cover and stego)",
                           "payload_bytes_requested": nbytes, "payload_bytes_embedded_mean": float(nbytes), "bits_per_sample_mean": r["bits_per_sample_mean"], "psnr_db_mean": r["psnr_db_mean"], "seconds": 0.0})
                results.append(rc)
                print(f"{nbytes:>5} B  {'  below carrier':<18} n={rc['n_pairs']:<4} AUC={rc['auc']:.3f} CI95={rc['auc_ci95']}  acc={rc['accuracy']:.3f}  LOFO-AUC={rc['leave_one_family_out_mean_auc']}", flush=True)
            print(f"{nbytes:>5} B  {cond:<18} n={r['n_pairs']:<4} AUC={r['auc']:.3f} CI95={r['auc_ci95']}  acc={r['accuracy']:.3f}  LOFO-AUC={r['leave_one_family_out_mean_auc']}  ({r['seconds']}s)", flush=True)

    report = {
        "schema": "detectability-eval-1",
        "label": "OFFLINE EVALUATION ONLY. Weak classical detector on synthetic generated covers. A low AUC is NOT evidence of undetectability.",
        "generator_version": GENERATOR_VERSION, "quality_version": QUALITY_VERSION,
        "cover": {"width": a.width, "height": a.height, "mode": "RGB", "families": list(families.FAMILIES), "test_seeds_per_family": a.seeds,
                  "accepted": len(covers), "rejection_reasons": rejected, "quality_score_mean": float(np.mean([c["score"] for c in covers]))},
        "detector": {"model": "standardisation + L2 logistic regression (Newton/IRLS), implemented in this script with NumPy", "l2": a.l2,
                     "features": [{"name": n, "definition": d} for n, d in FEATURES], "feature_count": len(FEATURE_NAMES)},
        "protocol": {"split": f"grouped {a.folds}-fold by seed; leave-one-family-out", "confidence_intervals": "percentile bootstrap, 1000 resamples of seeds",
                     "threshold": 0.5, "payload": "uniformly random bytes (ciphertext-like)", "rng_seed": 20261115},
        "results": results, "skipped_embeddings": skipped[:200], "skipped_count": len(skipped),
        "environment": {"python": platform.python_version(), "numpy": np.__version__, "machine": platform.machine(), "system": platform.system()},
        "wall_seconds": round(time.time() - t0, 1),
        "limitations": [
            "Synthetic procedural covers only; no photographs. Results do not transfer to natural images.",
            "The detector is a small linear model on about 65 hand-made features with a few hundred training images; learned steganalysers (rich models with ensemble classifiers, CNNs) are far stronger.",
            "An adversary who knows the generator can produce unlimited training covers; this evaluation trains on a small sample.",
            "The single-algorithm conditions embed over the whole image without the bootstrap carrier; the operational transport is the patch_mixed condition.",
            "The bootstrap carrier of the transport is written in plain least-significant bits of the reserved top rows and is itself a detectable structure for a detector that looks for it.",
            "Confidence intervals reflect sampling of seeds only, not model or feature choice.",
        ],
    }
    os.makedirs(a.out, exist_ok=True)
    name = "detectability-results-quick.json" if a.quick else "detectability-results.json"
    with open(os.path.join(a.out, name), "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"wrote {os.path.join(a.out, name)}  ({report['wall_seconds']}s)")


if __name__ == "__main__":
    main()
