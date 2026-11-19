# Algorithm Learning workbench (educational)

The Steganography Lab has two tabs that never share state:

* **UAV Simulation — Patch-wise Operational Flow**: the real K4 image transport (`/api/stego/*`, `patchwise-transport.md`).
* **Algorithm Learning — Worked Calculations and Experiments**: this workbench (`/api/learn/*`).

## 1. Separation

```mermaid
flowchart TB
  subgraph OPS[Operational UAV flow]
    UIo[Lab tab: UAV Simulation] -->|/api/stego/*| N1[Node relay] --> R1[Rust pipeline: session, directional keys, manifest validation, Frame v3 + MAC, bootstrap-v3, replay]
    R1 -->|/stego/*| P1[Python: segmentation, knowledge base + BM25 per patch, 10 algorithms, artifact store]
    R1 --> E1[(SQLite stego_events)]
  end
  subgraph EDU[Educational workbench]
    UIe[Lab tab: Algorithm Learning] -->|/api/learn/*| N2[Node relay] --> R2[Rust learn.rs: TEST-ONLY envelope, verification, exports]
    R2 -->|/learn/*| P2[Python learn package: walkthroughs, isolated experiments, attacks]
    R2 --> E2[(SQLite learn_experiments)]
  end
  P1 -. same segmenter and algorithm library; knowledge base read-only .- P2
```

Guarantees (each enforced by a test):
* No session, group key, sequence number, replay window, `stego_events` row or operational artifact is read or written by the workbench (`rust-core/tests/learn_workbench.rs::learning_experiments_never_touch_operational_state`, `python-service/tests/test_learn_workbench.py`).
* The operational pipeline never imports or calls the workbench; the workbench never imports the operational service, codec, bootstrap or artifact store. It **reads** the production knowledge base to show what the selector would rank for a patch, and a test asserts the file and its parsed content are unchanged after experiments (`production_kb_modified: false` in every response).
* Rust only forwards whitelisted paths (`/learn/registry`, `/learn/walkthrough/<one of 10>`, `/learn/experiment`).
* Separate labels everywhere: UI tabs and banner, `"operational": false`, `"label": "Educational experiment - not a live UAV transmission"` in every response, record and export.

## 2. Views
1. **Walk me through the mathematics** — deterministic Step 1…n calculations on fixed inputs (the 8×8 hand matrix and the synthetic bytes `A6 3C 91 5E`), each step with formula, substituted values and result, plus "show detailed calculations" tables/matrices (DCT coefficients, Haar sub-bands, U/Σ/Vᵀ, cost maps, STC parity-check matrix and Viterbi choice). Every walkthrough ends with an extraction and exact-match check. HUGO, WOW and S-UNIWARD are labelled **teaching models** with their simplification stated (small patch, mini STC with h = 2 instead of 7); their numbers still come from the runtime cost functions and are cross-checked (HUGO cost = brute-force HUGO distortion; S-UNIWARD cost = direct relative change). Generated document: [`worked-examples.md`](worked-examples.md).
2. **Run actual example** — the cover (sample or uploaded PNG ≤ 512×512) is segmented with the **same adaptive region-growing segmenter as the transport**; one irregular patch is chosen (`most_textured`, `smoothest`, `largest`, `smallest` or an explicit id) and the algorithm embeds into that mask only: PNG encode, extraction from the decoded PNG, whole-image and patch-only metrics, changes outside the patch (must be 0), images (segmentation overlay, highlighted patch, stego, |difference|×64), click-to-inspect pixel values, verification, optional robustness suite.
3. **Compare all ten** — the same cover, the same patch and the same payload bytes for every algorithm; insufficient capacity is `rejected_capacity` and an unusable mask is `unsupported_geometry` (never shortened, never replaced). Metrics table, robustness matrix, per-algorithm detail.
4. **Per-patch survey** (in every experiment) — for each patch of the segmentation: pixels, gradient, complete 8×8 / 2×2 blocks, the capacity each algorithm measures on that mask, which algorithms report unsupported geometry and why, and the read-only knowledge-base top-1 for this payload. A row can be picked as the patch of the next run.

Every result row and export carries the exact repository variant; the banner and the Markdown export state that these are not canonical paper implementations.

## 3. Payload modes
* **Readable message → real encryption** (`aead_fixture`): the message (default `UAV_ID=D1 / TARGET=D2 / LAT=9.45 / LON=77.80 / ALT=120`) is UTF-8 serialised and sealed by the production `seal_message` + AppWire v1 code with a **test-only key** = HKDF-SHA256 of a public label (not secret, never used for UAV traffic, never displayed). The UI shows plaintext length, wire length (50-byte header + ciphertext incl. 16-byte tag), hex and binary previews. After extraction the Rust core decodes the AppWire and AEAD-opens it: `aead_verified` + `plaintext_matches`. The same AppWire bytes are embedded by all algorithms (the operational Frame v3 wrapper — 48 bytes plus the patch manifest, which travels in the bootstrap-v3 carrier — is reported but not included, so the comparison is fair).
* **Synthetic ciphertext** (`synthetic`): `A6 3C 91 5E`, MSB-first. Labelled as a synthetic byte sequence, **not** a real ciphertext; verification is `not_applicable_synthetic` (bit-exactness only).

## 4. Metrics (consistent definitions)
| Metric | Definition |
|---|---|
| MSE | mean over all pixel×channel samples of (cover − stego)² |
| PSNR | 10·log10(255²/MSE); `null` = identical images (infinite) |
| SSIM | mean SSIM, uniform 7×7 window, K1 = 0.01, K2 = 0.03, L = 255, over all windows and channels (numpy, `stego/metrics.py`) |
| Capacity | measured by the algorithm implementation on the chosen patch mask (no bootstrap in experiments) |
| Payload size | plaintext bytes (AEAD mode), wire bytes, overhead, bits, bits per patch sample |
| Embedding time | `perf_counter` around the patch embedding; cost-map setup reported separately for STC methods |
| Extraction time | PNG decode + patch extraction |
| Accuracy | matching bits / expected bits, matching bytes / expected bytes |
| BER | (wrong + missing bits) / expected bits; 1.0 when extraction fails |
| Robustness | per attack: oracle BER (direct extraction from the attacked image with the known patch mask, algorithm, length and parameter); outcome `recovered` / `partial` (BER ≤ 0.1) / `failed` (BER ≈ 0.5 is chance level). The operational transport would additionally need its bootstrap and manifest to survive |

## 5. Robustness experiment
Fixed attacks and seeds: none; JPEG q95/q75/q50; resize 50% and back (bilinear); crop 4 px (geometry change); Gaussian noise σ=1 (seed 11) and σ=3 (seed 12); salt-and-pepper 0.5% (seed 13); Gaussian blur 3×3 σ=0.8; brightness +2. Nothing is repaired.
Measured result for the sample comparison (`docs/samples/learning-patch-comparison-all-ten.md`, RGB 256×256, largest patch, 112-byte AEAD payload; nine algorithms ran, `dct_svd` was rejected for capacity):
* every algorithm that ran recovers exactly without an attack and changes nothing outside the patch;
* **every algorithm fails JPEG q95, q75 and q50, the 50 % resize and the 4-px crop** (oracle BER ≈ 0.38–0.53, or desynchronised);
* brightness +2 is survived by eight of nine (it preserves LSB parity away from 255 and does not change AC/HH coefficients); PVD is only partial;
* Gaussian noise σ=1: only `dct` recovers; `dwt` is partial; everything else fails. Blur and σ=3 noise: `dct` partial, the rest fail. 0.5 % salt-and-pepper: partial for the LSB methods, `dwt` and `s_uniward`.

These are empirical results for these exact parameters and this cover, not general robustness claims; transform-domain operation alone did not give JPEG robustness here.

## 6. Exports
`GET /api/learn/experiments/{id}/export?format=json|csv|md` — the stored record (images stripped, hashes kept). CSV cells are formula-injection neutralised. Samples: `docs/samples/learning-patch-comparison-all-ten.{json,csv,md}` (AEAD mode, largest patch, robustness).

## 7. How to run
Start the stack (`scripts/linux/run_demo.sh` or `scripts\windows\run_demo.ps1`), open `http://127.0.0.1:5173/steganography?view=learn`.
API: `GET /api/learn/registry`, `GET /api/learn/walkthrough/{alg}`, `POST /api/learn/experiment`, `GET /api/learn/experiments`, `GET /api/learn/experiments/{id}/export?format=…`.
Regenerate the worked examples: `python3 scripts/gen_worked_examples.py` (Windows: `python scripts\gen_worked_examples.py`).
Tests: `cd python-service && python -m pytest -q tests/test_learn_workbench.py`; `cd rust-core && cargo test --release --test learn_workbench`.

## 8. Limitations
* Teaching models for HUGO/WOW/S-UNIWARD are reduced illustrations (stated in each walkthrough).
* "Saved image" in experiments = an in-memory PNG encode/decode round trip (lossless); the workbench deliberately writes nothing to the operational artifact directory.
* Upload covers ≤ 512×512 PNG; images are inlined as data URIs (large responses, ~2 MB for a ten-algorithm comparison).
* Timings are host-simulation measurements.
