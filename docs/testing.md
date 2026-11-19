# Testing

```
cd rust-core
cargo test --release          # 115 unit + 16 integration + 1 e2e (+2 ignored ZK parameter runs)
cargo test                    # same suites in debug (slower, ~30 s)
cargo test --release --lib zk::tests::standard_params_smoke -- --ignored --nocapture
cargo run --release --bin iod-bench
cargo run --release --bin iod-vectors
```
Layout: unit tests live beside the code (`zkhash`, `zk`, `merkle`, `identity`, `crypto`, `puf`, `protocol/*`, `zero_trust`, `trace`, `storage`); `tests/protocol_integration.rs` holds integration tests 1–16; `tests/end_to_end.rs` is Register → M1–M8 → ALLOW → K1–K3 → AEAD → Revoke → rejection. Results and the area-to-test map are in `zk-test-results.md`. Windows PowerShell uses the same `cargo` commands.
Node: `cd node-server && npm ci && npx tsc --noEmit`. UI: `cd web-ui && npm ci && npx tsc --noEmit -p . && npx vite build`. Python service tests: see the last section.

## Current suites (2026-11-19: FIPS 203/204 suite, bootstrap-v3, risk-aware policy, UI redesign)

Commands (Linux/macOS; PowerShell uses the same commands, or `.\scripts\windows\test.ps1`):
```
cd rust-core && cargo test --release                      # unit, integration, e2e (spawns the Python service) and doc tests
cd python-service && python -m pytest -q
cd tools/stego-standalone && python -m unittest test_latent_image
cd node-server && npm ci && npm run build
cd web-ui && npm ci && npx tsc --noEmit -p . && npx eslint src && npm run build
# with the stack running (scripts/linux/run_demo.sh) and the dashboard on :5173:
python3 scripts/stego_smoke.py
bash scripts/linux/demo_scenario.sh
node scripts/ui_check.js <dir>                            # Playwright drive of the dashboard
node scripts/ui_screenshots.js docs/screenshots/ui         # 1440/1024/768/390 px, dark + light
# offline evaluation (docs/detectability-evaluation.md)
python3 scripts/eval_detectability.py --stage risk-table --val-seeds 20
python3 scripts/eval_detectability.py --stage evaluate --train-seeds 20 --test-seeds 15
```

Results on the development container, 2026-11-19 (release build, x86-64 Linux, 2 vCPU; no Raspberry Pi, no Docker,
no Windows):

| Suite | Result |
|---|---|
| `cargo test --release` lib | 177 passed, 2 ignored (ZK parameter runs) |
| `fips_kat` (NIST ACVP ML-KEM-768 / ML-DSA-44 vectors) | 7 passed |
| `fips_interop` (against PQClean ML-KEM / ML-DSA, dev-dependency only) | 5 passed |
| `crypto_suite_lifecycle` (new suite end to end, restart, key replacement, Round-3 database archived) | 3 passed |
| `protocol_integration` / `end_to_end` | 16 / 1 passed (M1–M8, K1–K3 semantics unchanged) |
| `stego_pipeline` (fake image backend) | 23 passed |
| `stego_e2e_python` (real Python service, real PNGs) | 7 passed |
| `learn_workbench` | 4 passed |
| Doc tests | 0 exist (reported, not a pass) |
| `python -m pytest -q` | 416 passed |
| `tools/stego-standalone` `test_latent_image` | 4 passed |
| `node-server` build; `web-ui` `tsc`, ESLint (0 errors, 21 warnings: react-refresh exports in generated UI components, one unused directive), production build | OK |
| `scripts/stego_smoke.py` | 83 checks, all passed |
| `scripts/linux/demo_scenario.sh` | completed (exit 0) |
| `scripts/ui_check.js` | completed; console errors only blocked Google Fonts requests, the intentional 422 for an oversized message and the intentional `/rag` 404 |
| `scripts/ui_screenshots.js` | 56 screenshots, no horizontal page overflow at any width; console errors only blocked Google Fonts requests |
| `scripts/eval_detectability.py` both stages | executed; results in `detectability-evaluation.md` |

What the new or changed tests establish:

* **FIPS suite**: ACVP keyGen/encaps/decaps (incl. implicit rejection, dk/ek checks) for ML-KEM-768 and keyGen/sigGen/
  sigVer for ML-DSA-44 from pinned vector files with recorded provenance; byte-level interop with PQClean in both
  directions; sizes 1184/2400(64)/1088/32 and 1312/2560(32)/2420; context binding; suite id signed into credentials,
  enrolment and envelopes; mixed or Round-3 identities rejected and archived at start-up (never reinterpreted).
* **Bootstrap-v3** (`transport/bootstrap.rs`, `test_patch_manifest.py`, `stego_pipeline.rs`, `stego_e2e_python.rs`):
  placement key/value stream/sync word/keystream derivations, prefix property of the value stream, CRC, bounded
  inflate and decompression-bomb rejection, reserve bound; Python pixel mapping, ±1 LSB matching bit I/O,
  legacy-v2 recognition, bounded decoding; manifest-v2 test vector byte for byte in both languages; discovery
  window edges, replay found during discovery, sequence mismatch, wrong recipient; 24 + 29 tamper cases including
  manifests rewritten inside a re-encrypted carrier with a **valid CRC** (→ `FRAME_AUTH_FAILED`); an independent
  pixel reader finds the sync word at the keyed positions and none with the wrong key; carrier pixels spread over
  > 120 rows and excluded from every patch; failures never advance the replay window.
* **Policy and risk table**: default policy excludes DCT/DWT/DCT-SVD and LSB replacement; the allow list only
  restricts; Rust rejects a planned manifest that uses an excluded algorithm (`POLICY_VIOLATION`); the policy's risk
  exclusions equal the high-tier rows of `risk_table.json` (checked in Rust and Python); risk-table validation;
  ranking order tier → changes/bit → ms/KiB → BM25 → id; nothing permitted fits → rejection, no fallback.
* **Evaluation tools**: AUC, TPR at 1 % FPR, classifiers, splits, feature determinism and the v3 stego builders
  (the operational builder's output is extracted again with its manifest and value stream).

Not run / not covered: **a Raspberry Pi 5 or any ARM device** (all timings are host measurements under the profile's
limits), Windows, Docker, debug-mode Rust tests, a CNN steganalyser (no deep-learning framework here), an automated
browser CI suite (the Playwright drives are scripts), FIPS 140-3 validation (the libraries are not validated modules),
and `tools/stego-standalone/test_text_vector` (needs a model download that is blocked offline).
