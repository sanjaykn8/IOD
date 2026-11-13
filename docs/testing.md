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

## Patch-wise steganography transport (current; 2026-11-13)

Earlier sections of this file's history described the whole-image transport (Frame v1); those tests were replaced.

Commands (Linux/macOS; PowerShell uses the same commands, or `.\scripts\windows\test.ps1`):
```
cd rust-core && cargo test --release
cd python-service && python -m pytest -q
cd tools/stego-standalone && python -m unittest test_latent_image
cd node-server && npm ci && npm run build
cd web-ui && npm ci && npx tsc --noEmit -p . && npm run build
# with the stack running (scripts/linux/run_demo.sh):
python3 scripts/stego_smoke.py
node scripts/ui_check.js <dir>      # optional browser drive, needs Playwright (see the script header)
```

Results on the development container (release build, no webcam, no Docker, no Windows):

| Suite | Result |
|---|---|
| `cargo test --release` lib | 141 passed, 2 ignored (ZK parameter runs) |
| `protocol_integration` / `end_to_end` | 16 / 1 passed (M1–M8, K1–K3 unchanged) |
| `stego_pipeline` (fake image backend) | 19 passed |
| `stego_e2e_python` (spawns the real Python service) | 6 passed |
| `learn_workbench` | 4 passed |
| `python -m pytest -q` | 318 passed |
| `tools/stego-standalone` `test_latent_image` | 4 passed |
| `node-server` `tsc` build, `web-ui` `tsc --noEmit` + production build | OK |
| `scripts/stego_smoke.py` (full stack through the gateway) | all 58 checks passed |
| `scripts/ui_check.js` (Playwright, Chromium) | plan preview, send D1→D2 and D2→D1, patch inspector, event detail, Knowledge Base page, retrieval preview, learning comparison: completed; only console errors were blocked external font requests and the intentional `/rag` 404 |

What the tests establish:

* **Segmentation** (`python-service/tests/test_patch_segmentation.py`): every pixel in exactly one region, dense ids, 4-connectivity of every region, determinism, count bounds, count varies with size and content, regions are not rectangles, minimum-size merge, coarser refinement levels and their bound, setting validation.
* **Manifest / bootstrap / frame structure** (`test_patch_manifest.py`, `rust-core/src/transport/manifest.rs`, `frame.rs`): the documented test vector byte for byte in both languages, round trip, 27 + 33 malformed-field cases, canonical RLE, CRC and semantic preamble checks, length overflow, MAC over header ‖ manifest ‖ wire, every single-byte flip rejected, wrong key/direction/channel, v1 frames rejected.
* **Algorithms on masks** (`test_patch_algorithms.py`): all ten on an irregular mask, gray and RGB, through PNG, with no change outside the mask; exact measured capacity and overflow rejection; two adjacent patches do not interfere; block methods touch only complete blocks; unsupported geometry is reported (no LSB substitution); STC changes concentrate in texture; edge-adaptive carrier set is independent of neighbouring patches.
* **Knowledge base / retrieval** (`test_patch_kb.py`): schema validation (14 broken variants), BM25 recomputed independently from the documented formula, filters before ranking, tie break, nothing eligible → no selection, determinism, no socket use, no LLM modules loaded.
* **Planner / codec** (`test_patch_planner_codec.py`): plan → embed → PNG → extract exact on five covers × three sizes, sequential contiguous chunks covering the payload once, reserved bootstrap rows untouched by patches, bounded refinement then rejection, no silent algorithm fallback, receiver does not call the segmenter, tampered carrier fails closed, tampered payload yields a different frame.
* **Service / HTTP** (`test_patch_service_api.py`, `test_stego_webcam.py`): saved PNG re-read from disk, inspection artifacts, validation of every request field, failed encode leaves no file, removed routes return 404, forbidden fields rejected.
* **Rust pipeline** (`tests/stego_pipeline.rs`): both directions; planning receives lengths only; receiver works from the file alone; 20 tamper cases on the stored image (algorithm id, parameter, image size, patch map, chunk lengths, swapped algorithms, swapped regions, unused→used patch, offset, length, unknown id, patch count, versions, map label, frame length/version/magic, ciphertext, tag, truncation, image header) → `FRAME_AUTH_FAILED` or a strict structural code, never a delivery; Rust rejects bad manifests even when the image service passes them on; MAC-valid frames with invalid manifests are rejected; replay/out-of-order; capacity and size rejections recorded; bounded re-plan (and no algorithm fallback); manifest validation before authentication; no secrets in events, reports or CSV.
* **Real end to end** (`tests/stego_e2e_python.rs`): both directions with real PNGs, an independent reader (`tests/helpers/tamper_png.py`, stdlib + numpy + Pillow, no project code) agrees with the manifest; a varied cover yields ≥ 4 irregular patches and ≥ 2 different algorithms; 32 pixel-level tamper cases incl. manifest rewrites **with a repaired CRC**; oversized message rejected after four refinement levels with no PNG written; browser-webcam cover; knowledge base served; old endpoints 404.
* **Learning workbench** (`test_learn_workbench.py`, `tests/learn_workbench.rs`): patch-level experiments, metrics recomputed from returned images, survey, isolation from the operational store, production knowledge base file unchanged.

Not run / not covered: a physical webcam, Windows, Docker, debug-mode Rust tests, an automated browser test runner
(the Playwright drive is a script, not a CI suite), steganalysis of any kind, and `tools/stego-standalone/test_text_vector`
(needs a model download that is blocked offline). ESLint: the repository's Prettier rules flag the dense one-line style
used throughout `web-ui` (pre-existing); with formatting rules off there are 8 errors, all in pre-existing legacy pages.
