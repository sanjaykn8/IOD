# Detectability evaluation (offline)

**This is an evaluation aid. Nothing in it is a security claim, and no result here means "undetectable".**
The detector is deliberately small and transparent; stronger detectors exist and would do better.

Tool: `scripts/eval_detectability.py` (NumPy only; no scikit-learn, no pretrained model, no network).
Tables below are rendered from the measured JSON by `scripts/render_eval_reports.py detectability`.

## 1. Method

**Covers.** The operational generator (`procgen-1`) at the default profile size 320×240 RGB, every family,
with explicit *test* seeds (`SHA-256("IOD-DETECT-EVAL-v1|family|i")[:16]`; this script is the only place
seeds are chosen by hand). Covers that fail the operational quality gates are excluded and counted.

**Stego images.** Payload = uniformly random bytes (ciphertext-like), three kinds of condition:

* `patch_mixed` — the operational path: real planner (segmentation, measured capacities, knowledge-base
  selection per patch) and real patch-wise embedding of a random frame, **including** the in-image bootstrap
  carrier (preamble + manifest + CRC in the least-significant bits of the reserved top rows).
* `patch_mixed_below_carrier` — the same image pairs, but the detector only sees rows ≥ 16 of cover and stego,
  i.e. the carrier rows are hidden from it. This separates the trace of the patch embedding from the trace of
  the carrier.
* one condition per algorithm (ten) — that algorithm alone embeds random bytes over the whole image, with the
  parameter the planner would use, without carrier. If an algorithm's capacity is below the requested size
  the embedded size is its capacity (see the "Embedded" column).

**Features (65, per image, averaged over channels).** Truncated first-order residual co-occurrences
(7×7, horizontal and vertical, "SPAM-like"); fraction of ones, neighbour correlations and bit-0/bit-1
correlation of the LSB plane; pairs-of-values chi-square; histogram pair difference; centre of mass of the
histogram characteristic function; histogram smoothness; standard deviation, mean absolute value and kurtosis
of a 3×3 high-pass residual; first- and second-difference moments; 8×8 blockiness; LSB run length. Exact
definitions: `FEATURES` in the script.

**Detector.** Standardisation on the training fold, then L2-regularised logistic regression fitted with
Newton/IRLS, written in the script (λ = 1). Threshold 0.5.

**Splits.** A cover and its own stego image are never on different sides.
(a) grouped 5-fold by seed, out-of-fold scores pooled; (b) leave-one-family-out: train on three families, test
on the unseen fourth.

**Metrics.** ROC-AUC (Mann–Whitney, ties ½), accuracy, precision, recall, confusion matrix; 95 % percentile
bootstrap intervals from 1000 resamples of seeds. The building blocks (AUC, classifier, splits, features) are
unit-tested in `python-service/tests/test_eval_tools.py`.

## 2. Results (development container, 2026-11-15)

Source: `docs/samples/detectability-results.json` · generator `procgen-1` · 160 covers (40 test seeds × 4 families, 320×240 RGB, all passed the quality gates) · 65 features · grouped 5-fold by seed; leave-one-family-out · wall time 984.0 s.

**Payload 256 bytes** (0.0089 payload bits per cover sample for the transport)

| Condition | Pairs | Embedded (mean B) | PSNR (dB) | ROC-AUC | AUC 95 % CI | Accuracy | Acc. 95 % CI | Precision | Recall | Confusion (cover→cover / cover→stego / stego→cover / stego→stego) | Leave-one-family-out AUC (mean) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `patch_mixed` | 160 | 256 | 58.7 | **0.986** | 0.970–0.998 | 0.981 | 0.969–0.994 | 0.975 | 0.988 | 156 / 4 / 2 / 158 | 0.986 |
| `patch_mixed_below_carrier` | 160 | 256 | 58.7 | **0.611** | 0.593–0.637 | 0.575 | 0.550–0.606 | 0.573 | 0.588 | 90 / 70 / 66 / 94 | 0.612 |
| `lsb_replacement` | 160 | 256 | 71.7 | **0.527** | 0.521–0.538 | 0.525 | 0.509–0.544 | 0.524 | 0.544 | 81 / 79 / 73 / 87 | 0.530 |
| `lsb_matching` | 160 | 256 | 71.6 | **0.532** | 0.522–0.546 | 0.534 | 0.509–0.562 | 0.538 | 0.487 | 93 / 67 / 82 / 78 | 0.528 |
| `pvd` | 160 | 256 | 56.7 | **0.640** | 0.617–0.669 | 0.606 | 0.575–0.637 | 0.615 | 0.569 | 103 / 57 / 69 / 91 | 0.615 |
| `edge_adaptive_lsb` | 160 | 256 | 71.7 | **0.513** | 0.508–0.520 | 0.509 | 0.500–0.522 | 0.508 | 0.562 | 73 / 87 / 70 / 90 | 0.513 |
| `dct` | 160 | 256 | 51.6 | **0.859** | 0.826–0.891 | 0.778 | 0.738–0.819 | 0.770 | 0.794 | 122 / 38 / 33 / 127 | 0.835 |
| `dwt` | 160 | 256 | 60.3 | **0.975** | 0.954–0.992 | 0.959 | 0.938–0.978 | 0.951 | 0.969 | 152 / 8 / 5 / 155 | 0.941 |
| `dct_svd` | 160 | 150 | 51.4 | **0.896** | 0.866–0.925 | 0.838 | 0.800–0.872 | 0.838 | 0.838 | 134 / 26 / 26 / 134 | 0.883 |
| `hugo` | 160 | 256 | 75.3 | **0.511** | 0.504–0.518 | 0.500 | 0.491–0.509 | 0.500 | 0.494 | 81 / 79 / 81 / 79 | 0.505 |
| `wow` | 160 | 256 | 75.0 | **0.545** | 0.534–0.560 | 0.528 | 0.509–0.550 | 0.529 | 0.506 | 88 / 72 / 79 / 81 | 0.530 |
| `s_uniward` | 160 | 256 | 76.1 | **0.537** | 0.526–0.551 | 0.541 | 0.519–0.562 | 0.545 | 0.494 | 94 / 66 / 81 / 79 | 0.527 |

Algorithms the planner selected in `patch_mixed` at 256 bytes (patches over all covers): `dct` 254, `dct_svd` 3, `hugo` 1, `lsb_matching` 379, `s_uniward` 283, `wow` 40.
Leave-one-family-out AUC of `patch_mixed`: cells 1.000, clouds 0.987, strata 0.957, terrain 1.000.

**Payload 1536 bytes** (0.0533 payload bits per cover sample for the transport)

| Condition | Pairs | Embedded (mean B) | PSNR (dB) | ROC-AUC | AUC 95 % CI | Accuracy | Acc. 95 % CI | Precision | Recall | Confusion (cover→cover / cover→stego / stego→cover / stego→stego) | Leave-one-family-out AUC (mean) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `patch_mixed` | 160 | 1536 | 54.7 | **0.984** | 0.967–0.998 | 0.978 | 0.959–0.994 | 0.975 | 0.981 | 156 / 4 / 3 / 157 | 0.980 |
| `patch_mixed_below_carrier` | 160 | 1536 | 54.7 | **0.747** | 0.712–0.788 | 0.719 | 0.678–0.756 | 0.724 | 0.706 | 117 / 43 / 47 / 113 | 0.720 |
| `lsb_replacement` | 160 | 1536 | 63.9 | **0.758** | 0.729–0.788 | 0.691 | 0.653–0.728 | 0.676 | 0.731 | 104 / 56 / 43 / 117 | 0.716 |
| `lsb_matching` | 160 | 1536 | 63.9 | **0.584** | 0.569–0.605 | 0.566 | 0.541–0.594 | 0.568 | 0.550 | 93 / 67 / 72 / 88 | 0.568 |
| `pvd` | 160 | 1536 | 48.9 | **0.797** | 0.756–0.838 | 0.722 | 0.684–0.759 | 0.729 | 0.706 | 118 / 42 / 47 / 113 | 0.734 |
| `edge_adaptive_lsb` | 160 | 1462 | 64.2 | **0.576** | 0.566–0.592 | 0.531 | 0.512–0.553 | 0.529 | 0.569 | 79 / 81 / 69 / 91 | 0.571 |
| `dct` | 160 | 900 | 46.1 | **0.989** | 0.981–0.995 | 0.950 | 0.928–0.972 | 0.962 | 0.938 | 154 / 6 / 10 / 150 | 0.986 |
| `dwt` | 160 | 1536 | 52.5 | **1.000** | 1.000–1.000 | 1.000 | 1.000–1.000 | 1.000 | 1.000 | 160 / 0 / 0 / 160 | 1.000 |
| `dct_svd` | 160 | 150 | 51.5 | **0.898** | 0.868–0.927 | 0.844 | 0.806–0.878 | 0.835 | 0.856 | 133 / 27 / 23 / 137 | 0.880 |
| `hugo` | 160 | 1536 | 67.5 | **0.542** | 0.529–0.559 | 0.516 | 0.497–0.537 | 0.517 | 0.475 | 89 / 71 / 84 / 76 | 0.530 |
| `wow` | 160 | 1536 | 67.3 | **0.567** | 0.554–0.585 | 0.544 | 0.522–0.566 | 0.545 | 0.531 | 89 / 71 / 75 / 85 | 0.545 |
| `s_uniward` | 160 | 1536 | 68.3 | **0.554** | 0.542–0.568 | 0.519 | 0.503–0.534 | 0.520 | 0.494 | 87 / 73 / 81 / 79 | 0.549 |

Algorithms the planner selected in `patch_mixed` at 1536 bytes (patches over all covers): `dct` 238, `lsb_matching` 358, `lsb_replacement` 180, `s_uniward` 964, `wow` 57.
Leave-one-family-out AUC of `patch_mixed`: cells 1.000, clouds 0.966, strata 0.956, terrain 1.000.


## 3. What the results say

* **The operational transport is easily detected by this small detector** (AUC ≈ 0.98–0.99 at both payload
  sizes, including on a family it was not trained on). The cause is mainly the **bootstrap carrier**: when the
  carrier rows are hidden from the detector the AUC drops to about 0.61 at 256 bytes and 0.75 at 1536 bytes.
  The carrier is structured, plain LSB data (`bootstrap-v2`); this was already listed as a limitation of the
  transport and is unchanged by the cover generator. A generated cover does not hide it.
* **Below the carrier**, detectability grows with payload and is driven by which algorithms the knowledge base
  selects: on these smooth, correlated synthetic covers it often selects the quantisation-based `dct` variant
  for part of the patches, and that variant is itself well detected (single-algorithm AUC 0.86 → 0.99).
* **Per algorithm**, the quantisation-index-modulation transform variants (`dwt`, `dct`, `dct_svd`) are the most
  detectable (AUC 0.86–1.00) although their PSNR is not the lowest — PSNR does not predict detectability. `pvd`
  and, at the larger payload, `lsb_replacement` are clearly detected. `lsb_matching`, `edge_adaptive_lsb` and the
  STC-coded `hugo` / `wow` / `s_uniward` variants stay within 0.51–0.58 **for this detector at these rates**;
  their intervals mostly exclude 0.5, i.e. even this detector sees a small effect.
* Leave-one-family-out results are close to the grouped-by-seed ones: the detector's cues are not specific to
  one image family.

## 4. Limits of this evaluation

* Synthetic procedural covers only. Nothing transfers to photographs or to other generators.
* A linear model on 65 hand-made features with 128 training pairs per fold. Rich-model or convolutional
  steganalysers, or simply more training covers (the generator is public, so an adversary has unlimited
  covers), will detect more. Values near 0.5 are an upper bound on nothing.
* Only two payload sizes, one image size, default parameters, random payloads.
* The single-algorithm conditions embed over the whole image; inside the transport each algorithm works on a
  patch chosen for it, so per-algorithm numbers are not the per-patch detectability of the transport.
* Confidence intervals reflect the sampling of seeds only.
* The result is a property of this repository's algorithm *variants* (see `stego-algorithms.md`), not of the
  published algorithms they are named after.

## 5. Reproduce

```bash
python3 scripts/eval_detectability.py --seeds 40 --payloads 256,1536     # about 16 minutes on the development container
python3 scripts/eval_detectability.py --quick --out /tmp/x                # smoke run, not meaningful
python3 scripts/render_eval_reports.py detectability                      # tables from the JSON
```
