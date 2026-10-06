# Registration-Time Algorithm Selection

**Classification: REAL** (deterministic decision logic) **over REAL
measurements** (`stego.benchmark`, see `docs/steganography.md`).
`rag/selector.py`'s `select_algorithm()` is the **only** component in
the stego-selection subsystem that picks a winner. It consumes
exclusively the real `AlgorithmMeasurement` objects `stego.benchmark.
measure_all()` produced for THIS specific cover image and THIS
specific payload -- never anything from the RAG knowledge-base
retrieval in `rag/stego_knowledge.py`, which supplies explanatory text
only (`docs/rag-stego-selection.md`). Given the exact same
measurements and importance level, this function always returns the
exact same winner: no randomness, no LLM call, and ties never depend
on dict/list iteration order.

## Selection procedure

1. **Feasibility gate.** Any candidate with `feasible=False` (payload
   exceeds the image's real capacity, or a genuine round-trip/boundary
   failure) is dropped immediately -- it cannot win regardless of its
   other measurements. If zero candidates are feasible, the selector
   reports `winner_algorithm_id=None` with reason `"no candidate
   algorithm is feasible for this image/payload combination"`, and
   the HTTP API returns 422 rather than embedding with an infeasible
   choice.
2. **Per-metric normalization**, across the remaining feasible
   candidates only (never across infeasible ones, so a disqualified
   algorithm can't skew the scale):
   - `time_score`: 1.0 for the fastest (`embed_time_ms +
     extract_time_ms`), 0.0 for the slowest, linear in between (all
     1.0 if every candidate takes the same time).
   - `capacity_score`: 1.0 for the highest real `capacity_bytes`, 0.0
     for the lowest, linear in between.
   - `distortion_score`: real SSIM used directly (already in [0, 1],
     1.0 = identical to the cover) -- a deliberate simplification that
     does not additionally fold in MSE/PSNR into the score (both
     remain available on each measurement for display); SSIM alone
     already tracks structural/perceptual similarity well and keeps
     the formula auditable by hand.
3. **Weighted sum**: `score = w_time*time_score + w_capacity
   *capacity_score + w_distortion*distortion_score`, using the
   importance-level weight table below.
4. **Winner**: the feasible candidate with the highest score; exact
   ties break on `algorithm_id` ascending (alphabetical) -- never on
   measurement order.

## Importance weight tables

Registration payloads (drone enrollment credentials) default to
`CRITICAL`. All four tables are this project's own chosen defaults
(each sums to 1.0), intentionally configurable
(`select_algorithm(..., weights_override=...)`) rather than hardcoded
constants, since the "right" weighting is a deployment-policy
decision, not a fact this project claims to have derived empirically.

| importance | time | capacity | distortion |
|---|---|---|---|
| LOW | 0.50 | 0.35 | 0.15 |
| MEDIUM | 0.30 | 0.35 | 0.35 |
| HIGH | 0.20 | 0.30 | 0.50 |
| CRITICAL | 0.15 | 0.25 | 0.60 |

The trend is deliberate: as importance rises, weighting shifts away
from raw speed and toward minimizing visible distortion (registration
credentials are embedded once per drone, infrequently, so a slower
embed is an acceptable cost for a less-damaged stego image;
LOW-importance traffic might be embedded far more often, where speed
matters more and any single embed's distortion matters less).

## What calls this

`stego_api.py`'s `POST /stego/select-and-embed` (see
`docs/image-pipeline.md`) runs `measure_all()` then
`select_algorithm()` then embeds with the winner -- in that order, so
the selection is always made before the winner is actually used, never
after the fact. `rust-core/src/api/state.rs`'s
`register_drone_via_stego` is the live, cross-language caller during
R1/R3 (`docs/registration-stego.md`); `bin/register_stego_demo.rs`
exercises the identical call sequence as a standalone CLI demo.

## Tests

`python-service/tests/test_selector.py`: feasibility gating (an
infeasible candidate never wins even with a fabricated high score),
normalization correctness (including the all-equal-values edge case),
weight-table application per importance level, and the alphabetical
tie-break. Run with `cd python-service && pytest`.
