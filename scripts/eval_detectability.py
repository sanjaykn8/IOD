#!/usr/bin/env python3
"""OFFLINE detectability evaluation of the generated covers and the patch-wise transport (bootstrap-v3).

This is an evaluation tool, not part of the running system, and its result is NOT a security claim.

Two stages, on disjoint seed namespaces (the only place seeds are chosen by hand; operation uses OS randomness):

* ``--stage risk-table`` uses ONLY the validation split (``val``). Every algorithm embeds random bytes over the
  whole image at a reference rate; a detector is evaluated by grouped cross-validation on validation seeds; the
  measured AUC, changes per embedded bit and processing time per KiB are written to the versioned risk table
  ``python-service/src/stego/kb/risk_table.json`` that the operational selector and policy use.
* ``--stage evaluate`` trains detectors on the ``train`` split and reports them ONCE on the untouched ``test``
  split (never used for any choice), for:
    - the operational transport (planner + policy + risk-aware selection + patch embedding + keyed bootstrap-v3
      carrier) at low / medium / high payload, and, for comparison, the previous selector's behaviour (all ten
      algorithms, BM25-only ranking) on the same v3 transport;
    - diagnostics that isolate the bootstrap carrier (carrier only) and the patches (no carrier);
    - every algorithm over the whole image at several exact rates (bits per cover sample);
    - per family, a held-out family (train on three families, test on the fourth), and cover-only family
      classification (how much family information the features carry).
  Detectors: L2 logistic regression on a small hand-made feature set (``basic``), the same model on
  ``basic`` + SRM-inspired residual co-occurrences (``srm-lite``), and a tree ensemble (extremely randomised
  trees, scikit-learn, evaluation-only dependency) on the same features. A CNN is not trained: no deep-learning
  framework is available in this environment (reported as a limitation).

Metrics: ROC-AUC with a seed-bootstrap 95 % interval, accuracy at threshold 0.5, TPR at 1 % FPR (with n test covers
the smallest non-zero FPR is 1/n; the value is reported with that resolution), sample counts, exact rates, and the
raw per-image scores of the test split (CSV). A cover and its stego image always share a seed and therefore a split.

AUC 0.5 = this detector cannot tell cover from stego; AUC 1.0 = it always can. A low AUC means only that THESE
detectors with THESE features and THIS little training data did not separate the classes. It is not evidence of
undetectability: stronger steganalysers exist and an adversary who knows the generator can train on unlimited covers.

Usage:
  python3 scripts/eval_detectability.py --stage risk-table [--val-seeds 12]
  python3 scripts/eval_detectability.py --stage evaluate [--train-seeds 20 --test-seeds 15] [--workers 2]
  python3 scripts/eval_detectability.py --stage evaluate --quick        (smoke test; numbers meaningless)
"""
import argparse, csv, hashlib, json, os, platform, sys, time
from multiprocessing import Pool

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python-service", "src"))

from stego import bootstrap as B, codec, config                     # noqa: E402
from stego.algorithms import BY_NAME                               # noqa: E402
from stego.errors import StegoError                                # noqa: E402
from stego.generator import GENERATOR_VERSION, QUALITY_VERSION, families, quality   # noqa: E402
from stego.patch import manifest as M, planner, policy as P          # noqa: E402
from stego.patch.region import CoverCtx, Region                    # noqa: E402

T = 3  # residual truncation
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


def stego_mixed(arr, nbytes, rng, limits, policy=None, return_plan=False):
    """Operational path: plan for `nbytes` of payload section (bootstrap-v3 carrier pixels reserved for a
    random value stream), embed a random frame patch-wise, then write a random carrier of the exact v3 size.
    Random bytes stand in for Rust's encrypted carrier and value stream: both are pseudo-random by design."""
    values = rand_bytes(rng, 4 * 8192)
    pl = planner.plan(arr, nbytes, carrier_values=values, policy=policy)
    wire = rand_bytes(rng, nbytes - 32)
    frame = M.frame_header(len(pl.manifest), len(wire)) + pl.manifest + wire + rand_bytes(rng, 32)
    carrier = rand_bytes(rng, 12 + len(pl.deflated) + 4)
    out, _man, per, _info = codec.embed_frame(arr, frame, limits, np.frombuffer(values, dtype=">u4").astype(np.int64), carrier,
                                              8 * len(carrier), np.random.default_rng(int(rng.integers(0, 2 ** 63))))
    used = {a: sum(1 for p in per if p.get("algorithm") == a) for a in {p["algorithm"] for p in per if p.get("used")}}
    return (out, used, pl, values) if return_plan else (out, used)


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


# ------------------------------------------------------------------ SRM-inspired residual co-occurrences
SRM_T = 2
SRM_RESIDUALS = (("d1", 1.0), ("d2", 2.0), ("d3", 3.0), ("kb", 4.0))   # residual, quantisation step


def _srm_classes():
    """Canonical class of every 3-tuple in [-T, T]^3 under sign flip and reversal (SRM-style symmetrisation)."""
    n = 2 * SRM_T + 1
    cls, out = {}, np.zeros(n ** 3, dtype=np.int64)
    for a in range(-SRM_T, SRM_T + 1):
        for b in range(-SRM_T, SRM_T + 1):
            for c in range(-SRM_T, SRM_T + 1):
                key = min((a, b, c), (-a, -b, -c), (c, b, a), (-c, -b, -a))
                out[((a + SRM_T) * n + (b + SRM_T)) * n + (c + SRM_T)] = cls.setdefault(key, len(cls))
    return out, len(cls)


SRM_CLASS, SRM_NCLASS = _srm_classes()
SRM_FEATURE_NAMES = [f"srm_{r}_{k}" for r, _ in SRM_RESIDUALS for k in range(SRM_NCLASS)]
SRM_DESCRIPTION = ("SRM-inspired: residuals d1 (first difference, q=1), d2 (second difference, q=2), d3 (third difference, q=3) "
                   "and kb (3x3 KB high-pass, q=4), quantised and truncated to [-2, 2]; third-order co-occurrence of horizontally and "
                   f"vertically adjacent residual triples, symmetrised under sign flip and reversal ({SRM_NCLASS} classes per residual), "
                   "normalised, averaged over directions and channels. A small subset of the spatial rich model, not the SRM itself.")


def _q(r, step):
    return np.clip(np.rint(r / step), -SRM_T, SRM_T).astype(np.int64) + SRM_T


def _cooc3(r):
    n = 2 * SRM_T + 1
    idx = (r[:, :-2] * n + r[:, 1:-1]) * n + r[:, 2:]
    return np.bincount(SRM_CLASS[idx.ravel()], minlength=SRM_NCLASS).astype(np.float64)


def _srm_channel(x):
    x = x.astype(np.float64)
    feats = []
    for name, step in SRM_RESIDUALS:
        hist = np.zeros(SRM_NCLASS)
        for img in (x, x.T):                 # horizontal residuals + triples, then vertical via transposition
            if name == "d1":
                r = img[:, 1:] - img[:, :-1]
            elif name == "d2":
                r = img[:, 2:] - 2 * img[:, 1:-1] + img[:, :-2]
            elif name == "d3":
                r = img[:, 3:] - 3 * img[:, 2:-1] + 3 * img[:, 1:-2] - img[:, :-3]
            else:
                r = (-img[:-2, :-2] + 2 * img[:-2, 1:-1] - img[:-2, 2:] + 2 * img[1:-1, :-2] - 4 * img[1:-1, 1:-1] + 2 * img[1:-1, 2:]
                     - img[2:, :-2] + 2 * img[2:, 1:-1] - img[2:, 2:])
            hist += _cooc3(_q(r, step))
        feats.append(hist / max(hist.sum(), 1.0))
    return np.concatenate(feats)


def srm_features(arr):
    if arr.ndim == 2:
        return _srm_channel(arr)
    return np.mean([_srm_channel(arr[:, :, c]) for c in range(arr.shape[2])], axis=0)


def all_features(arr):
    """(basic, srm-lite) feature vectors."""
    return features(arr), srm_features(arr)


# ------------------------------------------------------------------ detectors
DETECTORS = {
    "lr_basic": "L2 logistic regression (l2 = 1, NumPy, Newton/IRLS) on the basic features",
    "lr_srm": "L2 logistic regression (l2 = 10, NumPy, Newton/IRLS) on basic + srm-lite features",
    "trees_srm": "extremely randomised trees (scikit-learn ExtraTreesClassifier, 500 trees, min_samples_leaf 2, seed 0) on basic + srm-lite features",
}


def fit_score(det, Xtr, ytr, Xte):
    """Hyper-parameters are fixed a priori (not tuned on the test split)."""
    if det == "lr_basic":
        return LogReg(1.0).fit(Xtr, ytr).score(Xte)
    if det == "lr_srm":
        return LogReg(10.0).fit(Xtr, ytr).score(Xte)
    from sklearn.ensemble import ExtraTreesClassifier
    m = ExtraTreesClassifier(n_estimators=500, min_samples_leaf=2, random_state=0, n_jobs=1).fit(Xtr, ytr)
    return m.predict_proba(Xte)[:, 1]


def det_matrix(det, basic, srm):
    return basic if det == "lr_basic" else np.hstack([basic, srm])


def tpr_at_fpr(y, s, fpr=0.01):
    """TPR at the largest threshold whose cover false-positive rate is <= fpr (resolution 1 / #covers)."""
    y, s = np.asarray(y), np.asarray(s, dtype=np.float64)
    neg, pos = np.sort(s[y == 0])[::-1], s[y == 1]
    if neg.size == 0 or pos.size == 0:
        return None
    k = int(np.floor(fpr * neg.size))            # false positives allowed
    thr = neg[k] if k < neg.size else -np.inf    # strictly above the (k+1)-th highest cover score
    return float((pos > thr).mean())


def metrics(y, s, groups, rng):
    return {"auc": auc(y, s), **classification(y, s), "tpr_at_1pct_fpr": tpr_at_fpr(y, s), **bootstrap_ci(y, s, groups, rng)}


# ------------------------------------------------------------------ splits and conditions
SPLITS = ("train", "val", "test")
REF_RATE = 0.05                                 # risk table reference rate, payload bits per cover sample
RATES = (0.02, 0.05, 0.10)                      # per-algorithm sweep
TRANSPORT = (("transport_low", 256, "low_detectability"), ("transport_med", 1024, "low_detectability"),
             ("transport_high", 3072, "low_detectability"),
             # comparison: the previous selector's behaviour (all ten algorithms, BM25-only ranking, as kb-bm25-1) on the v3 transport
             ("transport_med_previous_selector", 1024, "all_algorithms+bm25"))


def split_seed(split, i, family):
    assert split in SPLITS
    return hashlib.sha256(f"IOD-DETECT-EVAL-v2|{split}|{family}|{i}".encode()).digest()[:families.SEED_BYTES]


def cond_rng(seed_label, cond):
    return np.random.default_rng(int.from_bytes(hashlib.sha256(f"{seed_label}|{cond}".encode()).digest()[:8], "big"))


def make_covers(split, n, width, height):
    covers, rejected = [], {}
    for fam in families.FAMILIES:
        for i in range(n):
            arr, _ = families.generate(split_seed(split, i, fam), width, height, "RGB", fam)
            q = quality.evaluate(arr, 0.70)
            if not q["passed"]:
                for r in q["rejection_reasons"]:
                    rejected[r] = rejected.get(r, 0) + 1
                continue
            covers.append({"family": fam, "seed": f"{split}:{fam}:{i}", "arr": arr, "score": q["score"]})
    return covers, rejected


def carrier_only(arr, nbytes, rng, limits):
    """Diagnostic: the bootstrap-v3 carrier of a real plan for `nbytes`, written into the cover WITHOUT any patch embedding."""
    values = rand_bytes(rng, 4 * 8192)
    pl = planner.plan(arr, nbytes, carrier_values=values)
    n_bits = B.carrier_bits_for(len(pl.deflated))
    vals = np.frombuffer(values, dtype=">u4").astype(np.int64)
    pos = M.carrier_positions(pl.parsed, vals)
    out = arr.copy()
    B.write_bits(out, pos, rand_bytes(rng, n_bits // 8), n_bits, np.random.default_rng(int(rng.integers(0, 2 ** 63))))
    return out, n_bits // 8


def patches_only(arr, nbytes, rng, limits):
    """Diagnostic: the real plan and patch embedding for `nbytes`, but the carrier pixels are left untouched."""
    values = rand_bytes(rng, 4 * 8192)
    pl = planner.plan(arr, nbytes, carrier_values=values)
    wire = rand_bytes(rng, nbytes - 32)
    frame = M.frame_header(len(pl.manifest), len(wire)) + pl.manifest + wire + rand_bytes(rng, 32)
    vals = np.frombuffer(values, dtype=">u4").astype(np.int64)
    carrier = rand_bytes(rng, 12 + len(pl.deflated) + 4)
    pos = M.carrier_positions(pl.parsed, vals)
    out, _man, per, _info = codec.embed_frame(arr, frame, limits, vals, carrier, 8 * len(carrier))
    flat_out, flat_cov = out.reshape(-1, out.shape[-1] if out.ndim == 3 else 1), arr.reshape(-1, arr.shape[-1] if arr.ndim == 3 else 1)
    flat_out[pos] = flat_cov[pos]                       # undo the carrier: patches only
    return out, nbytes


def conditions(stage):
    if stage == "risk-table":
        return [(f"single_{n}@{REF_RATE}", "single", n, REF_RATE) for n in sorted(BY_NAME, key=lambda k: BY_NAME[k].id)]
    out = [(name, "transport", (nb, pol), None) for name, nb, pol in TRANSPORT]
    out += [("bootstrap_only_med", "carrier_only", 1024, None), ("transport_med_patches_only", "patches_only", 1024, None)]
    out += [(f"single_{n}@{r}", "single", n, r) for n in sorted(BY_NAME, key=lambda k: BY_NAME[k].id) for r in RATES]
    return out


def _work(args):
    """One cover: features of the cover and of every condition's stego image (runs in a worker process)."""
    cover, conds, width, height = args
    limits = config.Limits()
    arr = cover["arr"]
    samples = arr.size
    res = {"seed": cover["seed"], "family": cover["family"], "cover": all_features(arr), "stego": {}}
    for name, kind, spec, rate in conds:
        rng = cond_rng(cover["seed"], name)
        t = time.perf_counter()
        row = {"used": {}}
        try:
            if kind == "transport":
                nb, pol = spec
                if pol.endswith("+bm25"):
                    from stego.patch import kb as KB
                    real = KB.risk_key
                    KB.risk_key = lambda name: (0, 0.0, 0.0)      # ranking degenerates to (BM25 desc, id): the kb-bm25-1 order
                    try:
                        out, used = stego_mixed(arr, nb, rng, limits, policy=P.parse({"name": pol.split("+")[0]}))
                    finally:
                        KB.risk_key = real
                else:
                    out, used = stego_mixed(arr, nb, rng, limits, policy=P.parse({"name": pol}))
                n = nb
                row["used"] = used
            elif kind == "carrier_only":
                out, n = carrier_only(arr, spec, rng, limits)
            elif kind == "patches_only":
                out, n = patches_only(arr, spec, rng, limits)
            else:
                want = int(round(rate * samples / 8))
                out, n = stego_single(arr, spec, want, rng)
                if out is not None and n < want:
                    row["short"] = True          # the algorithm could not reach the requested rate on this image
        except StegoError as exc:
            out, n, row["error"] = None, 0, exc.code
        row["ms"] = (time.perf_counter() - t) * 1000.0
        if out is not None:
            d = out.astype(np.int16) - arr.astype(np.int16)
            mse = float(np.mean(d.astype(np.float64) ** 2))
            row.update(bytes=n, bits=8 * n, bps=8 * n / samples, changed=int(np.count_nonzero(d)),
                       psnr=10 * np.log10(255.0 ** 2 / mse) if mse > 0 else None, feat=all_features(out))
        res["stego"][name] = row
    return res


def run_split(covers, conds, width, height, workers):
    jobs = [(c, conds, width, height) for c in covers]
    if workers > 1:
        with Pool(workers) as pool:
            return pool.map(_work, jobs, chunksize=1)
    return [_work(j) for j in jobs]


def _pairs(results, cond, det):
    """Cover/stego matrices for one condition; covers without a stego image (refused embedding) are dropped from both."""
    Xc, Xs, seeds, fams, meta = [], [], [], [], []
    for r in results:
        st = r["stego"].get(cond)
        if not st or "feat" not in st:
            continue
        Xc.append(det_matrix(det, *[v[None, :] for v in r["cover"]])[0])
        Xs.append(det_matrix(det, *[v[None, :] for v in st["feat"]])[0])
        seeds.append(r["seed"]); fams.append(r["family"]); meta.append(st)
    return np.array(Xc), np.array(Xs), np.array(seeds), np.array(fams), meta


def _xy(Xc, Xs):
    return np.vstack([Xc, Xs]), np.concatenate([np.zeros(len(Xc)), np.ones(len(Xs))])


# ------------------------------------------------------------------ stage 1: risk table (validation split only)
RISK_TIERS = {"high": 0.80, "medium": 0.65}      # AUC thresholds (lower bound of the tier)


def tier_of(a):
    return "high" if a >= RISK_TIERS["high"] else "medium" if a >= RISK_TIERS["medium"] else "low"


def stage_risk_table(a):
    t0 = time.time()
    rng = np.random.default_rng(20261119)
    covers, rejected = make_covers("val", a.val_seeds, a.width, a.height)
    print(f"validation covers: {len(covers)} accepted, rejected {rejected}", flush=True)
    conds = conditions("risk-table")
    results = run_split(covers, conds, a.width, a.height, a.workers)
    algs = {}
    for name, _kind, alg, _rate in conds:
        Xc, Xs, seeds, fams, meta = _pairs(results, name, "lr_srm")
        row = {"n_pairs": int(len(Xc)), "requested_rate_bps": REF_RATE}
        if len(Xc) >= 8:
            X, y = _xy(Xc, Xs)
            g = np.concatenate([seeds, seeds])
            uniq = rng.permutation(np.unique(seeds))
            fold = {s: i % 4 for i, s in enumerate(uniq)}
            oof = np.full(len(y), np.nan)
            for k in range(4):
                te = np.array([fold[s] == k for s in g])
                oof[te] = fit_score("lr_srm", X[~te], y[~te], X[te])
            ci = bootstrap_ci(y, oof, g, rng)
            row.update(auc=round(auc(y, oof), 4), auc_ci95=[round(v, 4) for v in ci["auc_ci95"]], tier=tier_of(auc(y, oof)))
        else:
            row.update(auc=None, auc_ci95=None, tier="not_measured")
        if meta:
            row.update(achieved_rate_bps=round(float(np.mean([m["bps"] for m in meta])), 5),
                       changes_per_bit=round(float(np.sum([m["changed"] for m in meta]) / np.sum([m["bits"] for m in meta])), 4),
                       ms_per_kib=round(float(np.sum([m["ms"] for m in meta]) / (np.sum([m["bytes"] for m in meta]) / 1024.0)), 2),
                       reached_reference_rate=not any(m.get("short") for m in meta))
        algs[alg] = row
        print(f"{alg:<18} n={row['n_pairs']:<3} AUC={row['auc']} tier={row['tier']} changes/bit={row.get('changes_per_bit')} ms/KiB={row.get('ms_per_kib')}", flush=True)
    table = {
        "version": "risk-table-1",
        "label": "Built from the VALIDATION split only (seed namespace 'val'); never from the test split. Offline measurement, not a security claim.",
        "generator_version": GENERATOR_VERSION,
        "cover": {"width": a.width, "height": a.height, "mode": "RGB", "families": list(families.FAMILIES), "val_seeds_per_family": a.val_seeds,
                  "accepted": len(covers), "rejection_reasons": rejected},
        "condition": f"each algorithm alone over the whole image, uniformly random payload, requested rate {REF_RATE} payload bits per cover sample "
                     "(algorithms that cannot reach it embed their maximum; see achieved_rate_bps)",
        "detector": DETECTORS["lr_srm"] + "; grouped 4-fold cross-validation over validation seeds",
        "tiers": {"high": f"AUC >= {RISK_TIERS['high']}", "medium": f"{RISK_TIERS['medium']} <= AUC < {RISK_TIERS['high']}", "low": f"AUC < {RISK_TIERS['medium']}"},
        "selection_use": "operational selector kb-risk-1: tier, then changes_per_bit (expected distortion), then ms_per_kib (processing cost); "
                         "policy low_detectability excludes the high tier (and DCT/DWT/DCT-SVD by rule)",
        "algorithms": algs,
        "command": f"python3 scripts/eval_detectability.py --stage risk-table --val-seeds {a.val_seeds} --width {a.width} --height {a.height}",
        "environment": {"python": platform.python_version(), "numpy": np.__version__, "machine": platform.machine()},
        "wall_seconds": round(time.time() - t0, 1),
    }
    path = a.risk_out
    with open(path, "w") as fh:
        json.dump(table, fh, indent=1)
        fh.write("\n")
    print(f"wrote {path} ({table['wall_seconds']} s)")


# ------------------------------------------------------------------ stage 2: train on train, report once on test
def stage_evaluate(a):
    t0 = time.time()
    rng = np.random.default_rng(20261119)
    tr_cov, tr_rej = make_covers("train", a.train_seeds, a.width, a.height)
    te_cov, te_rej = make_covers("test", a.test_seeds, a.width, a.height)
    print(f"covers: train {len(tr_cov)}, test {len(te_cov)}; rejected {tr_rej} / {te_rej}  ({time.time() - t0:.1f}s)", flush=True)
    conds = conditions("evaluate")
    if a.quick:
        conds = [c for c in conds if c[1] != "single" or c[3] == 0.05][:8]
    tr = run_split(tr_cov, conds, a.width, a.height, a.workers)
    print(f"train features done ({time.time() - t0:.1f}s)", flush=True)
    te = run_split(te_cov, conds, a.width, a.height, a.workers)
    print(f"test features done ({time.time() - t0:.1f}s)", flush=True)
    results, raw = [], []
    for name, kind, spec, rate in conds:
        entry = {"condition": name, "kind": kind}
        if kind == "transport":
            entry.update(payload_bytes=spec[0], policy=spec[1])
        elif kind in ("carrier_only", "patches_only"):
            entry.update(payload_bytes=spec, policy="low_detectability")
        else:
            entry.update(algorithm=spec, requested_rate_bps=rate)
        _, _, _, _, te_meta = _pairs(te, name, "lr_basic")
        errors = {}
        for r in tr + te:
            e = r["stego"].get(name, {}).get("error")
            if e:
                errors[e] = errors.get(e, 0) + 1
        entry["refused"] = errors
        if te_meta:
            entry.update(n_test_pairs=len(te_meta), bits_per_sample_mean=float(np.mean([m["bps"] for m in te_meta])),
                         bytes_mean=float(np.mean([m["bytes"] for m in te_meta])),
                         changed_samples_mean=float(np.mean([m["changed"] for m in te_meta])),
                         psnr_db_mean=float(np.mean([m["psnr"] for m in te_meta if m["psnr"] is not None])) if any(m["psnr"] is not None for m in te_meta) else None,
                         short_of_rate=int(sum(1 for m in te_meta if m.get("short"))))
            used = {}
            for m in te_meta:
                for k, v in m["used"].items():
                    used[k] = used.get(k, 0) + v
            if used:
                entry["algorithms_selected_patches"] = dict(sorted(used.items()))
        entry["detectors"] = {}
        for det in DETECTORS:
            Xc_tr, Xs_tr, s_tr, f_tr, _ = _pairs(tr, name, det)
            Xc_te, Xs_te, s_te, f_te, meta = _pairs(te, name, det)
            if len(Xc_tr) < 8 or len(Xc_te) < 4:
                entry["detectors"][det] = {"skipped": "too few pairs"}
                continue
            Xtr, ytr = _xy(Xc_tr, Xs_tr)
            Xte, yte = _xy(Xc_te, Xs_te)
            g_te = np.concatenate([s_te, s_te])
            f_te2 = np.concatenate([f_te, f_te])
            sc = fit_score(det, Xtr, ytr, Xte)
            m = {"n_train_pairs": int(len(Xc_tr)), "n_test_pairs": int(len(Xc_te)), **metrics(yte, sc, g_te, rng)}
            m["per_family_auc"] = {fam: auc(yte[f_te2 == fam], sc[f_te2 == fam]) for fam in sorted(set(f_te))}
            # held-out family: train on the other three families of the TRAIN split, test on this family of the TEST split
            f_tr2 = np.concatenate([f_tr, f_tr])
            held = {}
            for fam in sorted(set(f_te)):
                if (f_tr2 != fam).sum() < 16 or (f_te2 == fam).sum() < 4:
                    continue
                s2 = fit_score(det, Xtr[f_tr2 != fam], ytr[f_tr2 != fam], Xte[f_te2 == fam])
                held[fam] = auc(yte[f_te2 == fam], s2)
            m["held_out_family_auc"] = held
            m["held_out_family_auc_mean"] = float(np.mean(list(held.values()))) if held else None
            entry["detectors"][det] = m
            for i in range(len(yte)):
                raw.append({"condition": name, "detector": det, "seed": g_te[i], "family": f_te2[i], "label": int(yte[i]), "score": round(float(sc[i]), 6),
                            "bits_per_sample": round(meta[i % len(meta)]["bps"], 6) if yte[i] == 1 else 0.0})
        results.append(entry)
        line = "  ".join(f"{d}={v['auc']:.3f}" for d, v in entry["detectors"].items() if "auc" in v)
        print(f"{name:<34} n={entry.get('n_test_pairs', 0):<3} bps={entry.get('bits_per_sample_mean', 0):.4f}  {line}", flush=True)
    # cover-only family classification (how much family information the features carry; chance = 1 / #families)
    fam_cls = {}
    for det in DETECTORS:
        Xtr = np.array([det_matrix(det, r["cover"][0][None, :], r["cover"][1][None, :])[0] for r in tr])
        Xte = np.array([det_matrix(det, r["cover"][0][None, :], r["cover"][1][None, :])[0] for r in te])
        ytr = np.array([r["family"] for r in tr]); yte = np.array([r["family"] for r in te])
        if det == "trees_srm":
            from sklearn.ensemble import ExtraTreesClassifier
            pred = ExtraTreesClassifier(n_estimators=500, min_samples_leaf=2, random_state=0).fit(Xtr, ytr).predict(Xte)
        else:
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
            pred = make_pipeline(StandardScaler(), LogisticRegression(C=1.0 if det == "lr_basic" else 0.1, max_iter=2000)).fit(Xtr, ytr).predict(Xte)
        fam_cls[det] = {"accuracy": float((pred == yte).mean()), "chance": 1.0 / len(families.FAMILIES), "n_test": int(len(yte))}
    import sklearn
    report = {
        "schema": "detectability-eval-2",
        "label": "OFFLINE EVALUATION ONLY. Classical detectors on synthetic generated covers. A low AUC is NOT evidence of undetectability.",
        "transport_format": "frame-v3/appwire-v1/bootstrap-v3/manifest-v2",
        "generator_version": GENERATOR_VERSION, "quality_version": QUALITY_VERSION,
        "risk_table": _risk_table_version(),
        "cover": {"width": a.width, "height": a.height, "mode": "RGB", "families": list(families.FAMILIES),
                  "train_seeds_per_family": a.train_seeds, "test_seeds_per_family": a.test_seeds,
                  "train_accepted": len(tr_cov), "test_accepted": len(te_cov), "rejection_reasons": {"train": tr_rej, "test": te_rej},
                  "samples_per_image": a.width * a.height * 3},
        "features": {"basic": [{"name": n, "definition": d} for n, d in FEATURES], "basic_count": len(FEATURE_NAMES),
                     "srm_lite": SRM_DESCRIPTION, "srm_lite_count": len(SRM_FEATURE_NAMES)},
        "detectors": DETECTORS,
        "protocol": {"splits": "seed namespaces train / val / test (disjoint); detectors are trained on train and evaluated once on test; "
                               "val is used only for the risk table", "pairing": "a cover and its stego image share a seed and a split",
                     "confidence_intervals": "percentile bootstrap, 1000 resamples of test seeds", "threshold": 0.5,
                     "tpr_at_1pct_fpr": "largest threshold with cover FPR <= 1 %; resolution 1 / #test covers",
                     "payload": "uniformly random bytes (ciphertext-like); carrier bits and value streams random (indistinguishable from the real ones)",
                     "rng_seed": 20261119, "hyperparameters": "fixed a priori (see detectors); nothing tuned on the test split"},
        "results": results,
        "cover_family_classification": fam_cls,
        "environment": {"python": platform.python_version(), "numpy": np.__version__, "scikit_learn": sklearn.__version__,
                        "machine": platform.machine(), "system": platform.system(), "workers": a.workers},
        "command": f"python3 scripts/eval_detectability.py --stage evaluate --train-seeds {a.train_seeds} --test-seeds {a.test_seeds} "
                   f"--width {a.width} --height {a.height} --workers {a.workers}" + (" --quick" if a.quick else ""),
        "wall_seconds": round(time.time() - t0, 1),
        "limitations": [
            "Synthetic procedural covers only; no photographs. Results do not transfer to natural images.",
            "Small samples (tens of covers per family): confidence intervals are wide; differences inside an interval are not meaningful.",
            "Detectors are small classical models on hand-made features (a subset of SRM-style residual co-occurrences); full rich models with "
            "ensemble classifiers and CNN steganalysers are stronger. No CNN was trained: no deep-learning framework is available here.",
            "An adversary who knows the generator can produce unlimited training covers; these detectors train on a small sample.",
            "The single-algorithm conditions embed over the whole image without the carrier; the operational transport is the transport_* conditions.",
            "Confidence intervals reflect sampling of test seeds only, not model or feature choice.",
        ],
    }
    os.makedirs(a.out, exist_ok=True)
    base = "detectability-results-quick" if a.quick else "detectability-results"
    with open(os.path.join(a.out, base + ".json"), "w") as fh:
        json.dump(report, fh, indent=1)
    with open(os.path.join(a.out, base.replace("results", "raw-scores") + ".csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["condition", "detector", "seed", "family", "label", "score", "bits_per_sample"])
        w.writeheader()
        w.writerows(raw)
    print(f"wrote {os.path.join(a.out, base + '.json')} and the raw scores ({report['wall_seconds']} s)")


def _risk_table_version():
    try:
        with open(RISK_TABLE_PATH) as fh:
            return json.load(fh).get("version")
    except (OSError, ValueError):
        return None


RISK_TABLE_PATH = os.path.join(ROOT, "python-service", "src", "stego", "kb", "risk_table.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stage", choices=("risk-table", "evaluate"), default="evaluate")
    ap.add_argument("--val-seeds", type=int, default=12, help="validation seeds per family (risk table)")
    ap.add_argument("--train-seeds", type=int, default=20, help="training seeds per family")
    ap.add_argument("--test-seeds", type=int, default=15, help="test seeds per family")
    ap.add_argument("--width", type=int, default=320)
    ap.add_argument("--height", type=int, default=240)
    ap.add_argument("--workers", type=int, default=min(2, os.cpu_count() or 1))
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "samples"))
    ap.add_argument("--risk-out", default=RISK_TABLE_PATH)
    ap.add_argument("--quick", action="store_true", help="tiny run for a smoke test (results are not meaningful)")
    a = ap.parse_args()
    if a.quick:
        a.val_seeds, a.train_seeds, a.test_seeds = 3, 3, 2
    if a.stage == "risk-table":
        stage_risk_table(a)
    else:
        stage_evaluate(a)


if __name__ == "__main__":
    main()
