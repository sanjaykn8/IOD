# Detectability evaluation (offline)

**This is an evaluation aid. Nothing in it is a security claim, and no result here means "undetectable".**
The detectors are small and transparent; stronger steganalysers exist and would do better.

Tool: `scripts/eval_detectability.py` (NumPy; scikit-learn only for the tree ensemble and the family
classifier, pinned in `python-service/requirements-eval.txt`, evaluation-only). Tables are rendered from the
measured JSON by `scripts/render_eval_reports.py detectability`. Raw per-image test scores:
`docs/samples/detectability-raw-scores.csv`.

## 1. Method

**Splits.** Three disjoint seed namespaces, `SHA-256("IOD-DETECT-EVAL-v2|split|family|i")[:16]`:
`val` (risk table only), `train` (detector training), `test` (reported once, never used for any choice).
A cover and its stego image share a seed and therefore a split. Covers failing the operational quality gates
are excluded and counted.

**Covers.** Operational generator `procgen-1`, 320×240 RGB, families terrain / clouds / strata / cells.

**Conditions** (payload = uniformly random bytes; carrier bits and value streams random, which is what the real
encrypted carrier and SHAKE value streams look like to an observer):

* `transport_low` / `_med` / `_high` — the operational path at 256 / 1024 / 3072 payload bytes: planner,
  default policy `low_detectability`, risk-aware selector `kb-risk-1`, patch embedding **and** the keyed
  bootstrap-v3 carrier.
* `transport_med_previous_selector` — same transport, but all ten algorithms and BM25-only ranking (the behaviour
  of the previous selector `kb-bm25-1`), for comparison.
* `bootstrap_only_med` — diagnostic: only the bootstrap-v3 carrier of a real 1024-byte plan, no patch embedding.
* `transport_med_patches_only` — diagnostic: the real patch embedding with the carrier pixels left untouched.
* `single_<algorithm>@rate` — one algorithm alone over the whole image at 0.02 / 0.05 / 0.10 payload bits per
  cover sample (exact achieved rates are reported when an algorithm cannot reach the request).

**Features.** `basic` (65 hand-made features, unchanged from the previous evaluation: SPAM-like residual
co-occurrences, LSB-plane statistics, pairs-of-values, histogram features, high-pass moments, blockiness) and
`srm-lite` (156: quantised, truncated residuals d1/d2/d3/KB, third-order co-occurrences of horizontal and
vertical triples, symmetrised; a small subset of the spatial rich model, not the SRM).

**Detectors** (hyper-parameters fixed before measuring): `lr_basic` L2 logistic regression (λ = 1) on basic;
`lr_srm` the same (λ = 10) on basic + srm-lite; `trees_srm` extremely randomised trees (500 trees,
min_samples_leaf 2) on basic + srm-lite. **No CNN was trained**: no deep-learning framework is available in this
environment. This is a limitation, not a choice.

**Metrics.** ROC-AUC with 95 % percentile bootstrap over test seeds (1000 resamples), accuracy at 0.5, TPR at
1 % FPR (with 60 test covers the smallest non-zero FPR is 1/60, so this is effectively TPR at zero false
positives), sample counts, per-family AUC, held-out-family AUC (train on three families, test on the fourth),
and cover-only family classification accuracy.

## 2. Risk table (validation split)

`python-service/src/stego/kb/risk_table.json` (`risk-table-1`): 80 validation covers, each algorithm alone at
0.05 bits per sample, `lr_srm` with grouped 4-fold cross-validation over validation seeds. Tier thresholds were
fixed before measuring (high AUC ≥ 0.80, medium 0.65–0.80, low < 0.65).

| Algorithm | AUC (95 % CI) | Tier | Changes / bit | ms / KiB |
|---|---|---|---|---|
| `lsb_replacement` | 0.802 (0.754–0.856) | high | 0.499 | 0.6 |
| `lsb_matching` | 0.745 (0.699–0.800) | medium | 0.5 | 0.9 |
| `pvd` | 0.793 (0.745–0.851) | medium | 0.41 | 7.03 |
| `edge_adaptive_lsb` | 0.699 (0.651–0.757) | medium | 0.4998 | 4.51 |
| `dct` | 0.980 (0.961–0.994) | high | 8.6038 | 3.99 |
| `dwt` | 1.000 (0.999–1.000) | high | 2.5507 | 4.5 |
| `dct_svd` | 0.962 (0.937–0.984) | high | 30.2383 | 108.84 |
| `hugo` | 0.639 (0.610–0.680) | low | 0.2222 | 1859.97 |
| `wow` | 0.628 (0.598–0.667) | low | 0.2364 | 297.61 |
| `s_uniward` | 0.629 (0.602–0.670) | low | 0.1822 | 295.33 |

Consequences for the default policy: DCT, DWT and DCT-SVD stay excluded by rule (and are high tier anyway);
LSB replacement is high tier (0.802) and excluded. **PVD measured 0.793, i.e. medium tier, so the pre-set plan to
exclude it was not supported by the data and PVD remains allowed** (ranked below the low tier). The two
intervals overlap almost completely; the split between them is a consequence of the a-priori point-estimate
rule, not a meaningful difference. Tests in Python and Rust check that the policy's risk exclusions equal the
high-tier algorithms of the table.

## 3. Results (development container, 2026-11-19)

Source: `docs/samples/detectability-results.json` · transport `frame-v3/appwire-v1/bootstrap-v3/manifest-v2` · generator `procgen-1` · risk table `risk-table-1` · train 79 / test 60 covers (20 / 15 seeds × 4 families, 320×240 RGB) · features: 65 basic + 156 SRM-lite · wall time 1196.2 s · command `python3 scripts/eval_detectability.py --stage evaluate --train-seeds 20 --test-seeds 15 --width 320 --height 240 --workers 2`.

**Operational transport and diagnostics** (ROC-AUC on the untouched test split, 95 % seed-bootstrap interval; TPR at 1 % FPR; resolution of the FPR is 1/60)

| Condition | Payload (B) | Bits / sample | Test pairs | PSNR (dB) | AUC lr_basic | AUC lr_srm | AUC trees_srm | TPR@1% lr_basic | TPR@1% lr_srm | TPR@1% trees_srm |
|---|---|---|---|---|---|---|---|---|---|---|
| `transport_low` | 256 | 0.0089 | 60 | 70.3 | **0.556** (0.541–0.585) | **0.670** (0.638–0.716) | **0.664** (0.619–0.721) | 0.05 | 0.02 | 0.02 |
| `transport_med` | 1024 | 0.0356 | 60 | 67.6 | **0.566** (0.546–0.599) | **0.757** (0.711–0.818) | **0.754** (0.705–0.818) | 0.02 | 0.02 | 0.13 |
| `transport_high` | 3072 | 0.1067 | 60 | 54.3 | **0.716** (0.659–0.782) | **0.868** (0.817–0.923) | **0.852** (0.792–0.907) | 0.12 | 0.17 | 0.22 |
| `transport_med_previous_selector` | 1024 | 0.0356 | 60 | 63.9 | **0.579** (0.563–0.610) | **0.761** (0.712–0.821) | **0.775** (0.717–0.841) | 0.02 | 0.02 | 0.10 |
| `bootstrap_only_med` | 1024 | 0.0094 | 60 | 71.4 | **0.546** (0.534–0.571) | **0.646** (0.620–0.685) | **0.656** (0.615–0.713) | 0.02 | 0.02 | 0.05 |
| `transport_med_patches_only` | 1024 | 0.0356 | 60 | 70.0 | **0.553** (0.539–0.578) | **0.639** (0.612–0.680) | **0.654** (0.608–0.709) | 0.03 | 0.02 | 0.00 |

* `transport_low` patches by algorithm (test split): `s_uniward` 360.
* `transport_med` patches by algorithm (test split): `s_uniward` 647.
* `transport_high` patches by algorithm (test split): `pvd` 112, `s_uniward` 535.
* `transport_med_previous_selector` patches by algorithm (test split): `dct` 16, `lsb_matching` 199, `lsb_replacement` 71, `s_uniward` 352, `wow` 9.

**Single algorithm over the whole image, detector `lr_basic`** (AUC; measured rate in bits per sample when below the request)

| Algorithm | 0.02 b/s | 0.05 b/s | 0.1 b/s |
|---|---|---|---|
| `lsb_replacement` | 0.606 | 0.762 | 0.924 |
| `lsb_matching` | 0.542 | 0.572 | 0.632 |
| `pvd` | 0.728 | 0.776 | 0.808 |
| `edge_adaptive_lsb` | 0.529 | 0.553 @0.048 | 0.605 @0.089 |
| `dct` | 0.967 | 0.990 @0.031 | 0.988 @0.031 |
| `dwt` | 1.000 | 1.000 | 1.000 @0.083 |
| `dct_svd` | 0.917 @0.005 | 0.921 @0.005 | 0.917 @0.005 |
| `hugo` | 0.514 | 0.544 | 0.557 |
| `wow` | 0.540 | 0.564 | 0.567 |
| `s_uniward` | 0.538 | 0.551 | 0.562 |

**Single algorithm over the whole image, detector `lr_srm`** (AUC; measured rate in bits per sample when below the request)

| Algorithm | 0.02 b/s | 0.05 b/s | 0.1 b/s |
|---|---|---|---|
| `lsb_replacement` | 0.671 | 0.848 | 0.937 |
| `lsb_matching` | 0.628 | 0.796 | 0.905 |
| `pvd` | 0.743 | 0.816 | 0.924 |
| `edge_adaptive_lsb` | 0.639 | 0.759 @0.048 | 0.835 @0.089 |
| `dct` | 0.982 | 0.989 @0.031 | 0.988 @0.031 |
| `dwt` | 0.999 | 1.000 | 1.000 @0.083 |
| `dct_svd` | 0.961 @0.005 | 0.962 @0.005 | 0.963 @0.005 |
| `hugo` | 0.592 | 0.691 | 0.828 |
| `wow` | 0.576 | 0.665 | 0.800 |
| `s_uniward` | 0.583 | 0.687 | 0.840 |

**Single algorithm over the whole image, detector `trees_srm`** (AUC; measured rate in bits per sample when below the request)

| Algorithm | 0.02 b/s | 0.05 b/s | 0.1 b/s |
|---|---|---|---|
| `lsb_replacement` | 0.635 | 0.795 | 0.905 |
| `lsb_matching` | 0.619 | 0.768 | 0.874 |
| `pvd` | 0.798 | 0.871 | 0.958 |
| `edge_adaptive_lsb` | 0.636 | 0.749 @0.048 | 0.812 @0.089 |
| `dct` | 0.971 | 0.984 @0.031 | 0.983 @0.031 |
| `dwt` | 0.999 | 1.000 | 1.000 @0.083 |
| `dct_svd` | 0.941 @0.005 | 0.944 @0.005 | 0.943 @0.005 |
| `hugo` | 0.584 | 0.718 | 0.823 |
| `wow` | 0.634 | 0.714 | 0.821 |
| `s_uniward` | 0.598 | 0.706 | 0.824 |

**Per family and held-out family, `transport_med`** (per-family AUC of the model trained on all training families / AUC on a family whose covers were never in training)

| Detector | cells (all / held out) | clouds (all / held out) | strata (all / held out) | terrain (all / held out) | Held-out mean |
|---|---|---|---|---|---|
| `lr_basic` | 0.578 / 0.538 | 0.564 / 0.524 | 0.604 / 0.578 | 0.560 / 0.524 | 0.541 |
| `lr_srm` | 0.871 / 0.680 | 0.827 / 0.693 | 0.644 / 0.618 | 0.747 / 0.676 | 0.667 |
| `trees_srm` | 0.951 / 0.733 | 0.778 / 0.782 | 0.573 / 0.560 | 0.724 / 0.609 | 0.671 |

**Cover-only family classification** (test accuracy; chance 0.25): `lr_basic` 0.867, `lr_srm` 0.950, `trees_srm` 0.900.

## 4. What the results say

* **The aspiration of AUC ≤ 0.55 for the operational transport is not met.** With the SRM-lite detectors the
  transport is detected with AUC ≈ 0.67 at 256 bytes, ≈ 0.76 at 1024 bytes and ≈ 0.86 at 3072 bytes. TPR at
  1 % FPR stays low (≤ 0.22), i.e. these detectors cannot pick out stego images without false alarms, but they
  separate the populations clearly.
* **The gross bootstrap signature is gone.** The previous evaluation (bootstrap-v2, same `basic` features,
  2026-11-15) measured AUC 0.986 at 256 bytes, mostly from the plain-LSB carrier band in the top rows. With the
  keyed bootstrap-v3 carrier the same feature set reaches only 0.556 at 256 bytes and 0.566 at 1024 bytes. The
  protocols differ (5-fold CV then, train/test split now), so the comparison is indicative, not exact.
* **The carrier is still detectable by itself**: `bootstrap_only_med` (≈ 0.009 bits per sample of ±1 changes)
  reaches AUC ≈ 0.65 with SRM-lite, about the same as the patches alone (≈ 0.64–0.65). Both contribute; neither
  dominates. Keyed placement hides where the carrier is, not that pixels were changed.
* **Risk-aware selection did not measurably improve detectability** at 1024 bytes: 0.757 / 0.754 versus 0.761 /
  0.775 for the previous BM25-only behaviour — inside each other's intervals. It does remove DCT and LSB
  replacement from the plans and concentrates them on S-UNIWARD (with PVD at the high payload). The previous
  selector here already chose S-UNIWARD for about half the patches.
* **Per algorithm**: the transform QIM variants (DCT, DWT, DCT-SVD) are detected almost perfectly even at their
  small capacities; PVD is detected strongly; LSB replacement and LSB matching rise steeply with rate; the STC
  variants (HUGO, WOW, S-UNIWARD) are the least detectable but still reach AUC ≈ 0.82 at 0.10 bits per sample.
* **Held-out family**: AUC drops from the all-family numbers (e.g. `lr_srm` transport_med per-family 0.64–0.87,
  held-out mean 0.67), so part of what the detectors learn is family-specific. Family is easy to recognise from
  the cover alone (accuracy 0.87–0.95 against chance 0.25), which is why held-out-family results are reported.

## 5. Limits of this evaluation

* Synthetic procedural covers only; nothing transfers to photographs or to other generators.
* 79 training and 60 test covers; intervals are wide; differences inside an interval are not meaningful.
* Small classical detectors on a subset of rich-model features; full SRM with ensemble classifiers or CNN
  steganalysers, or more training covers (the generator is public), will detect more. No CNN was trained.
* One image size; three transport payloads; random payloads; the single-algorithm conditions embed over the
  whole image without carrier.
* The risk table is a whole-image single-algorithm proxy; per-patch detectability inside the transport differs.
* Confidence intervals reflect sampling of test seeds only, not model or feature choice.

## 6. Reproduce

```bash
pip install -r python-service/requirements-eval.txt                       # scikit-learn (evaluation only)
python3 scripts/eval_detectability.py --stage risk-table --val-seeds 20  # about 2 minutes here; writes risk_table.json
python3 scripts/eval_detectability.py --stage evaluate --train-seeds 20 --test-seeds 15 --workers 2   # about 20 minutes
python3 scripts/eval_detectability.py --stage evaluate --quick --out /tmp/x                         # smoke run, not meaningful
python3 scripts/render_eval_reports.py detectability                                               # tables from the JSON
```
Rebuilding the risk table changes the operational selector; publish it as a new version (`risk-table-2`) and update
`RISK_EXCLUDED` in `rust-core/src/transport/policy.rs` and `python-service/src/stego/patch/policy.py` if the tests say so.
