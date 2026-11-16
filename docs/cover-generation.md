# Payload-aware procedural cover generation

Generator `procgen-1` · quality heuristics `cover-quality-1` · default profile `raspberry_pi_5_cpu`

This document describes the cover source of the operational transport **as implemented**. It replaces
every earlier cover-acquisition path: the server-side OpenCV webcam, the browser webcam, the PNG upload,
the client-selected stored cover, the seeded "procedural" request and the automatic procedural fallback
were removed end to end (routes, backend trait, configuration, UI, types). The transport formats
(`frame-v2/appwire-v1/bootstrap-v2/manifest-v1`), the segmentation, the knowledge base and the ten
algorithm variants are unchanged — see `patchwise-transport.md`.

The educational workbench (`/api/learn/*`, "Algorithm Learning" tab) is a separate namespace and keeps
its own sample covers and its optional PNG upload. Nothing there reaches the operational transport.

## 1. What runs, and what does not

* The generator is plain, vectorised **NumPy** (float32) plus Pillow for PNG encoding. It runs inside
  the Python image service on the local CPU.
* **No** pretrained model of any kind (no image generator, LLM, SLM or embedding model), no model
  download, no network access, no cloud API, no GPU. Health reports `pretrained_models: false`,
  `network: false`.
* Every production cover is seeded with 16 bytes from the operating-system CSPRNG (`os.urandom`).
  The seed is never derived from the plaintext, the ciphertext, a key or the payload, and it is never
  stored, logged or returned. Only `seed_fingerprint = SHA-256("IOD-COVER-SEED-v1" ‖ seed)[:16 hex]`
  is recorded, to tell covers apart in diagnostics.
* An explicit seed exists only for tests: function arguments in the test-suite, the offline evaluation
  script, and the process-level variable `IOD_STEGO_GENERATOR_TEST_SEED` (health then reports
  `seeding: "test-fixed"` and the Lab shows a warning). No request field can set a seed.

## 2. Image families

An image is a pure function of (seed, width, height, mode, family, detail bias). All families share the
same building blocks: Perlin-style gradient noise on a freshly drawn, non-periodic lattice; fractal sums
of octaves, each with its own rotation and offset and a non-integer lacunarity (no axis-aligned or
repeated structure); low-frequency domain warping; and a procedurally drawn, coherent HSV palette
(analogous hues, moderate saturation, sometimes one accent).

| Family | Structure |
|---|---|
| `terrain` | warped fractal height field with a ridged component and soft hill-shading |
| `clouds` | stretched, twice-warped fractal density over a tilted tonal ramp |
| `strata` | folded layers: an irregular 1-D layer function evaluated along a warped coordinate |
| `cells` | Worley-like cellular pattern (nearest / second-nearest of about 10² jittered sites) with fractal modulation |

Finishing, identical for all families: tone range mapped without clipping, a small **spatially
correlated grain** (σ about 0.9–2.4 grey levels, strongest in mid-tones), quantisation to 8 bits inside
[4, 251]. The grain exists because a perfectly smooth synthetic gradient has banded, highly structured
low-order bit planes; the quality gates reject images dominated by grain. Default mode is RGB; `L`
(grey) is available. Feature sizes are scaled to `max(min(width, height), 240)` pixels, so a small
cover is a crop of a normally scaled scene.

These are synthetic images. They are built to be coherent and varied, not to be indistinguishable
from photographs.

## 3. Quality pre-screen (`cover-quality-1`)

Deterministic, documented **heuristics** computed on the candidate before any embedding
(`python-service/src/stego/generator/quality.py`). They are **not** a steganalysis detector and a high
score is not evidence of low detectability.

Hard gates — a candidate failing any of them is rejected with the reason shown:

| Metric | Gate | Rejects |
|---|---|---|
| `clipped_fraction` (samples ≤ 2 or ≥ 253) | ≤ 0.02 | saturated images |
| `flat_block_fraction` (8×8 luma blocks, σ < 0.35) | ≤ 0.25 | flat regions |
| `rms_contrast` (global luma σ) | ≥ 9 | washed-out images |
| `adjacent_correlation` (lag-1, mean of h/v) | ≥ 0.80 | noise-like images |
| `lag8_correlation` | ≥ 0.35 | no structure beyond a few pixels |
| `spectral_slope` (log–log radial power) | ≤ −1.6 | white/blue spectra |
| `periodic_peak_ratio` (strongest spectral line / ring median) | ≤ 1500 | stripes, gratings |
| `tile_similarity` (detail-band autocorrelation peak away from the origin) | ≤ 0.55 | tiling, repetition |
| `edge_density` (gradient ≥ 24) | ≤ 0.40 | edge clutter |
| `highpass_std` (residual of a 3×3 mean) | 0.35 … 9.0 | no fine detail / too much grain |
| `distinct_levels` | ≥ 48 | binary or posterised images |

Soft score in [0, 1]: weighted mean of trapezoid preferences over local variance (median and spread),
local entropy (mean and spread), gradient mean, edge density, lag-1 / lag-8 correlation and their
decay over scales, spectral slope, periodic peak, tile similarity, clipping, flat blocks, RMS contrast,
histogram fill, and for RGB colourfulness and inter-channel correlation. Weights and thresholds are the
`WEIGHTS`, `PREFERENCES` and `GATES` tables of that module; `min_quality_score` (default 0.70) is the
floor. All thresholds are local choices calibrated on this generator's output and on pathological
fixtures (flat, saturated, white noise, stripes, tiles, a black/white procedural image, a linear ramp),
which the tests require to be rejected.

## 4. Payload-aware selection

Inputs: the payload **length** and the configuration. Never payload bytes.

1. Memory pre-flight: `8 MB + 220 bytes/pixel` for the working image plus the candidates held, checked
   against `max_working_memory_mb` before any allocation (`GENERATOR_MEMORY_LIMIT`).
2. Embedding-rate limit: the payload may use at most `max_embedding_rate` (default 0.20) payload bits
   per cover sample. At 320×240 RGB that is 5760 bytes. Above it the request is rejected up front
   (`PATCH_CAPACITY_INSUFFICIENT`, reason `embedding_rate_above_limit`) unless
   `allow_payload_driven_resize` is set; then the smallest size of the fixed ladder
   (×1, 1.25, 1.5, 2, 2.5, 3, 4, rounded to multiples of 8, bounded by `max_width`/`max_height`/`max_pixels`)
   that satisfies the limit is used. Capacity is a hard constraint, not the objective: nothing makes a
   cover busier because the payload is larger.
3. Up to `max_candidates` candidates are generated, each with a fresh OS-random seed, with different
   families within one transmission.
4. Each candidate is pre-screened (section 3).
5. The **real planner** (segmentation, measured capacities, knowledge-base selection per patch, dry
   run) runs on the candidates that passed, best quality score first. The first that plans is the
   highest-quality feasible candidate among those evaluated and is selected.
6. If none is feasible and resize is allowed, the next ladder size is tried; otherwise the request
   fails with a structured error that carries the candidate table. There is **no fallback** to any
   other cover source and no relaxation of the gates.

Candidate outcomes: `selected`, `not_needed`, `rejected_quality`, `capacity_insufficient`,
`no_eligible_algorithm`, `not_planned_budget`, `not_evaluated_budget`, `planning_stopped_budget`.

Budget: `processing_budget_ms` is checked before each generation, pre-screen and planner run, and
between the planner's refinement levels. Work that has started completes; a plan that finishes after
the deadline is accepted and flagged `budget.exceeded` (the alternative would be discarding a valid
result). If the budget runs out before any candidate could be planned: `GENERATION_BUDGET_EXCEEDED`.

Texture is independent of the payload size: the generator parameters are drawn from the seed only
(a mild `detail_bias` is applied on later resize rounds, never as a function of the payload bytes).

## 5. Lifecycle of a cover

* **One fresh cover per transmission.** `plan`, `message`, `send` and every benchmark transaction
  generate their own. Two identical messages get different covers.
* The cover PNG is stored with a sidecar `<id>.gen.json` (generator version, profile, family,
  parameters, fingerprint, scores, cover SHA-256 — no seed).
* **Internal re-plan** (a patch failed to embed its chunk): the core sends `replan_cover_id`; the
  service loads that stored cover and plans again at a coarser level. Nothing is generated; the core
  rejects a response whose cover id or SHA-256 differs.
* **Encode** receives `{frame_b64, cover_id}` and loads that exact artifact; it cannot generate.
  A cover is usable for re-plan or encode only if its sidecar exists and its hash matches the PNG, so
  a file written into the artifact directory by anything else is refused.
* **The receiver** never generates, plans or segments: it reads the stego PNG and the manifest inside it.

## 6. Configuration

Three layers; each can only **tighten** the one above:

```text
hard ceilings (code)  >  process: profile + IOD_STEGO_GENERATOR_*  >  request: cover_generation {…}
```

Both the Rust core (`rust-core/src/transport/generator.rs`) and the Python service
(`python-service/src/stego/generator/profile.py`) implement the same bounds; the core resolves the
request and the service validates the result again. Set the same environment for both processes.

| Setting (request field) | Environment variable | `raspberry_pi_5_cpu` | `development_host` | Hard bound | Request may |
|---|---|---|---|---|---|
| `profile` | `IOD_STEGO_GENERATOR_PROFILE` | — | — | known profile | only name the active one |
| `width`, `height` | `…_WIDTH`, `…_HEIGHT` | 320 × 240 | 480 × 360 | 96 … max, multiples of 8 | change within the ceiling |
| `max_width`, `max_height` | `…_MAX_WIDTH`, `…_MAX_HEIGHT` | 640 × 480 | 1280 × 960 | ≤ 1920 × 1080 | lower |
| `max_pixels` | `…_MAX_PIXELS` | 307 200 | 1 228 800 | ≤ 2 073 600 | lower |
| `max_candidates` | `…_MAX_CANDIDATES` | 2 | 4 | 1 … 8 | lower |
| `processing_budget_ms` | `…_BUDGET_MS` | 2500 | 8000 | 200 … 30 000 | lower |
| `max_working_memory_mb` | `…_MAX_MEMORY_MB` | 96 | 512 | 16 … 1024 | lower |
| `min_quality_score` | `…_MIN_QUALITY` | 0.70 | 0.70 | 0 … 1 | raise |
| `max_embedding_rate` | `…_MAX_EMBED_RATE` | 0.20 | 0.20 | 0.001 … 1 | lower |
| `allow_payload_driven_resize` | `…_ALLOW_RESIZE` | false | false | — | set |
| `families` | `…_FAMILIES` | all four | all four | subset of the four | restrict |
| `workers` | `…_WORKERS` | 1 | 1 | 1 | — |
| `mode` | `…_MODE` | RGB | RGB | RGB or L | choose |

Unknown request fields — `seed`, `cover_id`, `source`, `file`, `image_b64`, `family`, `algorithm`,
`camera_index`, … — are rejected with `GENERATOR_CONFIG_INVALID` (400).

`raspberry_pi_5_cpu` is a **resource profile**: it enforces the sizes, counts, time and memory limits
judged conservative for a CPU-only Raspberry Pi 5. It does not emulate that device's speed. Timing
taken on any other machine is a *profile-constrained host benchmark*, never a Raspberry Pi result
(section 9).

## 7. Public API

`POST /api/stego/plan`, `/message`, `/send` and `/benchmark` accept an optional object:

```json
{"cover_generation": {"width": 400, "height": 304, "max_candidates": 1, "processing_budget_ms": 2000,
                      "allow_payload_driven_resize": true}}
```

Responses add `generation` (profile, config in effect, requested/actual size, family, fingerprint,
quality score, candidate table with scores / gates / rejection reasons / outcome / timings, stage
timings, budget, memory estimate, embedding rate) and the `cover` descriptor
`{artifact_id, source: "generated", width, height, mode, channels, sha256, generator_version, profile,
family, seed_fingerprint, quality_score}`.

Removed and now rejected: the top-level fields `cover`, `source`, `seed`, `cover_id`, `test_cover_id`,
`image_b64`, `camera_index` (400 `INVALID_REQUEST`), and the routes `POST /api/stego/camera/probe`,
`POST /api/stego/cover/upload` (404) with their Python counterparts and `/stego/capture`.

Error codes: `GENERATOR_CONFIG_INVALID` (400), `GENERATOR_MEMORY_LIMIT` (422), `COVER_QUALITY_REJECTED`
(422), `GENERATION_BUDGET_EXCEEDED` (422), `PATCH_CAPACITY_INSUFFICIENT` (422),
`COVER_GENERATION_FAILED` (500).

## 8. What is recorded

Per transmission event: generator profile and version, family, generation config in effect, seed
fingerprint, requested and actual size, resize flag, candidate table (family, size, score, gates,
rejection reasons, outcome, per-candidate timings), `cover_generate` / `cover_prescreen` /
`cover_selection_total` / `plan` / `load_cover` / `embed` / … timings, budget limit and use.
The report (`stego-report-3`) aggregates families, quality score, candidates per transmission, budget
overruns, resizes, generation failures and candidate rejection reasons, and names the host.

Three kinds of number are kept apart everywhere: **cover quality score** (heuristic, before
embedding), **distortion** (MSE / PSNR / SSIM between cover and stego) and **detector AUC** (offline
evaluation only, section 10). None of them is a statement about undetectability. Never recorded:
the raw seed, plaintext, AppWire or frame bytes, keys, MAC values.

## 9. Benchmark

`python3 scripts/bench_generator.py --profile raspberry_pi_5_cpu --runs 30` measures the operational
selection path (fresh cover per transaction) and writes
`docs/samples/generator-benchmark-<profile>-host.json` (or `…-on-pi5.json` when the device tree
identifies a Raspberry Pi 5). The same command is the repeatable procedure for a real device.
`POST /api/stego/benchmark` measures the whole stack and labels its result the same way.
Measured values are in `benchmarking.md`.

## 10. Detectability evaluation (offline)

`python3 scripts/eval_detectability.py` builds cover/stego pairs over families × test seeds × payload
sizes for the operational patch-wise transport and for each of the ten algorithms separately, extracts
about 65 transparent features, trains a small logistic-regression detector written in the script (NumPy
only) and reports ROC-AUC, accuracy, precision, recall, confusion matrix and bootstrap confidence
intervals, with splits by seed and by family. Method, results and limits are in
`detectability-evaluation.md`. It is an evaluation aid; no result of it is a security claim.

## 11. Limitations

* Synthetic covers. A procedural image is recognisable as synthetic; nothing here claims that the
  cover resembles a photograph or that the stego image is undetectable.
* The quality score is heuristic and calibrated on this generator only.
* The generator is public and deterministic given a seed. Secrecy rests on the AEAD and the frame MAC,
  not on the cover; an adversary can generate unlimited covers to train a detector.
* The embedding-rate limit and all thresholds are engineering choices, not derived security bounds.
* The memory figure is a pre-flight estimate from a measured bytes-per-pixel constant, not a live
  measurement or an enforced OS limit; the time budget is cooperative (checked between steps).
* No Raspberry Pi 5 measurement has been made (section 9).
