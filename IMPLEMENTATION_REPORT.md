# Implementation report — knowledge-base-guided, patch-wise steganography transport

Date: 2026-11-13. Base: the ten-algorithm whole-image codebase (`iod_learn.zip`).
Format now: `frame-v2/appwire-v1/bootstrap-v2/manifest-v1`, segmentation `arg-cells-1`, selector `kb-bm25-1`,
knowledge base `patch-kb-1`. M1–M8 and K1–K3 were not touched. Specification: `docs/patchwise-transport.md`.

## 1. What was built

* **Sender**: Rust seals the message → Python acquires the cover, segments it into irregular patches (adaptive
  region growing), computes a feature vector and measured per-algorithm capacity for every patch, allocates
  sequential byte chunks, selects one algorithm per used patch from a static knowledge base (structured filters →
  BM25 → top-1), dry-runs every patch and returns a manifest → Rust validates the manifest, builds Frame v2 and
  MACs header ‖ manifest ‖ payload → Python embeds, saves the PNG, re-reads the saved file and compares.
* **Receiver**: reads only the saved PNG; Python takes the bootstrap preamble and manifest from the image, rebuilds
  the masks from the manifest (no segmentation), extracts the chunks; Rust verifies the MAC, parses the manifest
  strictly, then AppWire, channel/direction/replay and AEAD.
* **Both directions** (D1→D2, D2→D1) use the same path with direction-specific keys.
* **UI**: Steganography Lab (segmentation overlay with ids and colours, patch table, patch inspector with features
  and the full retrieval table, before/after/difference images, PSNR/SSIM/MSE, per-patch embed and extraction
  status, timeline, events, report, JSON/CSV export), Knowledge Base / Retrieval Monitor page, patch-aware
  Algorithm Learning tab.

## 2. Design decisions (and why)

| Decision | Reason |
|---|---|
| Regions are 4-connected unions of 4/8/16-px **cells** | irregular regions with a compact, canonical map (hundreds of bytes instead of a per-pixel map), 8×8 and 2×2 blocks align with patches, fast in numpy |
| Region count from image size **and** measured complexity, threshold found by bisection | no fixed count, no grid, deterministic |
| Manifest = fixed header + fixed-size patch table + RLE map | its size is known right after segmentation, so the bootstrap rows can be reserved before capacities are measured (no circular dependency) |
| Frame v2 header is not embedded; patches carry `AppWire ‖ tag` | the header is fully determined by the preamble; saves capacity; the receiver reassembles the exact frame for Rust |
| MAC over header ‖ manifest ‖ AppWire with a new domain string, same key derivation | authenticates every patch decision without changing the key schedule; v1 tags cannot verify |
| Manifest parsed strictly in **both** Rust and Python | Python needs it before touching pixels; Rust does not trust Python (validates before signing and again after verifying) |
| Parameters explicit in the manifest (incl. STC rate) | the receiver derives nothing from capacity guesses |
| Edge-adaptive gradient restricted to in-patch neighbours; cost maps computed on the cover, only patch samples changed | embedding one patch can never desynchronise another |
| Chunks allocated to the most textured patches first, ~48 bytes each, water-filled | spreads the payload over several patches and several algorithms while keeping the count small |
| No algorithm fallback: ineligible/failed → coarser re-segmentation (≤ 3 levels in the planner, ≤ 2 sender re-plans) → reject | required "no silent fallback"; every attempt is recorded |
| Dry run with pseudo-random bytes at planning time | Python must not see the frame before Rust authenticated the manifest; a real-payload failure is handled by the bounded re-plan |
| Removed request fields are rejected with 400, not ignored | an old client cannot believe it forced an algorithm or a priority |
| Events store a compact per-patch record; the full diagnostics only go to the API response | keeps SQLite rows small |
| Learning workbench reads the knowledge base but writes nothing operational | shows what the selector would do without being able to change it |

## 3. Files

### New
* Python: `src/stego/patch/{__init__,segment,features,region,kb,planner,manifest,render}.py`, `src/stego/kb/algorithm_kb.json`,
  `src/stego/codec.py` (rewritten), tests `test_patch_{segmentation,manifest,algorithms,kb,planner_codec,service_api}.py`,
  `test_stego_primitives.py` (STC / cost-map / transform unit tests kept from the old files).
* Rust: `src/transport/manifest.rs`.
* UI: `src/components/command/{stego-shared,stego-patches,kb-monitor}.tsx`, `src/routes/knowledge-base.tsx`.
* Docs: `docs/patchwise-transport.md`, `docs/benchmark-results-patchwise.json`, `docs/samples/patchwise-run-*`,
  `docs/samples/learning-patch-comparison-all-ten.*`, this report. Scripts: `scripts/ui_check.js`.

### Rewritten or substantially changed
* Python: `src/app.py`, `src/stego/{service,api,bootstrap,artifacts,errors,__init__}.py`, all of `src/stego/algorithms/*.py`
  except `costs.py` and `stc.py` (new mask contract), `src/learn/{experiment,walkthrough}.py`, `tests/test_learn_workbench.py`,
  `tests/test_stego_webcam.py`, `tests/stego_helpers.py`.
* Rust: `src/transport/{frame,pipeline,backend,fake,config,report,error,mod,wire}.rs`, `src/api/stego_routes.rs`, `src/learn.rs`,
  `tests/{stego_pipeline,stego_e2e_python,learn_workbench}.rs`, `tests/helpers/tamper_png.py`.
* Node: `src/api/routes.ts`, `src/config.ts`, `src/index.ts`, `Dockerfile`.
* UI: `stego-lab.tsx`, `learn-workbench.tsx`, `stego-tabs.tsx`, `app-shell.tsx`, `operations-pages.tsx`, `lib/{api,stego-api,stego-errors,learn-api}.ts`,
  `types/api.ts`, `styles.css`, `routes/steganography.tsx`, generated `routeTree.gen.ts`, legacy `App.tsx`, `services/api.ts`, `pages/SettingsPage.tsx`.
* Docs/scripts: `README.md`, `docs/{api,architecture,testing,IMPLEMENTATION_STATUS,stego-algorithms,learning-workbench,benchmarking,development,
  dependency-rationale,security-review,protocol,zk-test-results,worked-examples}.md`, `docker-compose.yml`, `scripts/stego_smoke.py`,
  `scripts/{linux,windows}/{run_demo,setup,test,demo_scenario}.*`.

### Removed (callers checked first; each had none left)
| Removed | Was |
|---|---|
| `python-service/src/rag/`, `src/llm/`, `src/state.py`, tests `test_fusion`, `test_mock_llm`, `test_rag_explain`, `test_retrieval`, `test_validation` | generic RAG flow (contribute / retrieve / validate / fuse / mock-LLM) and the stego explanation module |
| `python-service/src/stego/selector.py`, `tests/test_stego_selector.py` | whole-image selector `sel-policy-2` |
| Python routes `/rag/*`, `/stego/analyze`, `/stego/explain` | — |
| `rust-core/src/transport/explain.rs`; trait methods `analyze`, `explain`; `MessageRequest.algorithm`, `.priority`; config `policy` | explanation proxy, manual override, priority classes |
| Rust route `POST /api/stego/analyze`; request fields `priority`, `algorithm`, `param`, `policy` | replaced by `POST /api/stego/plan`, `GET /api/stego/kb` |
| `node-server/src/services/pythonClient.ts`, Node routes `/api/rag/*`, `IOD_PYTHON_BASE_URL` | the gateway no longer talks to Python at all |
| UI `routes/rag.tsx`, `RagPage` (router app and legacy app), RAG API client functions and types, selector candidate table, priority and algorithm controls, explanation panel | replaced by the Knowledge Base / Retrieval Monitor page |
| `docs/rag.md`, `docs/stego-transport.md`, `docs/stego-implementation-note.md`, `docs/benchmark-results-stego-*`, `docs/samples/learning-comparison-*`, `learning-synthetic-bw-cover.md` | described or measured the removed flow |
| Old tests `test_stego_algorithms`, `test_stego_new_algorithms`, `test_stego_bootstrap`, `test_stego_service_api`, `test_stego_boundaries` | written against the whole-image API; replaced by the `test_patch_*` suites (primitive tests were kept in `test_stego_primitives.py`). No test was disabled or skipped. |

Not removed: the legacy non-router dashboard (`web-ui/src/App.tsx`, `src/pages/*`) — only its RAG page was removed;
`tools/stego-standalone/` (independent older tool); the ZK, protocol, PUF and trace code.

## 4. Tests run (development container, release build)

| Suite | Result |
|---|---|
| `cargo test --release` — lib | 141 passed, 0 failed, 2 ignored (long ZK parameter runs, as before) |
| — `protocol_integration`, `end_to_end` | 16 passed, 1 passed |
| — `stego_pipeline` (fake image backend) | 19 passed |
| — `stego_e2e_python` (real Python service, real PNG files) | 6 passed |
| — `learn_workbench` | 4 passed |
| `python -m pytest -q` (python-service) | 318 passed |
| `python -m unittest test_latent_image` (tools/stego-standalone) | 4 passed |
| `node-server`: `npm run build` (tsc) | OK |
| `web-ui`: `npx tsc --noEmit -p .`, `npm run build` | OK |
| `scripts/stego_smoke.py` against the running stack through the gateway | 58 checks, all passed |
| `scripts/linux/demo_scenario.sh` against the running stack | completed (exit 0) |
| `scripts/ui_check.js` (Playwright/Chromium against the dev server) | completed: plan preview, send in both directions, 8/8 stages OK, patch inspector, event detail, Knowledge Base page, retrieval preview, ten-algorithm learning comparison; `/rag` → 404 |

Saved-PNG verification is real: the Python service re-reads the file it wrote, the Rust core reads and hashes the
same file, and the end-to-end tests open it with an independent reader.

## 5. Tests not run

* No physical webcam (server-side OpenCV adapter tested with a fake `cv2`; browser capture not re-driven in this round).
* No Windows run, no Docker build/run, no debug-mode Rust test run.
* No automated browser test suite exists in `web-ui`; the Playwright drive is a script, run once here.
* `tools/stego-standalone/test_text_vector` (needs a model download; blocked offline).
* No steganalysis or detectability experiment of any kind.
* ESLint: with the repository's Prettier rule the dense one-line style used across `web-ui` (old and new files) reports
  about 1 100 formatting errors; with formatting rules off there are 8 errors, all in pre-existing legacy pages.

## 6. Measured behaviour

`docs/benchmark-results-patchwise.json` (60 transactions, 60 delivered): 320×240 RGB varied cover — 16 patches, 9.3 used
on average, PSNR 63.3 dB, total p50 314 ms / p95 494 ms; 640×480 procedural fallback — 9 patches, 6.9 used, PSNR 55.7 dB,
total p50 471 ms / p95 646 ms. Algorithms actually used: `lsb_matching`, `wow`, `dct`, `s_uniward` on the varied cover;
`dwt`, `s_uniward`, `lsb_matching` on the (mostly saturated) procedural cover. Host measurements only.

Sample run: `docs/samples/patchwise-run-report.json` with `patchwise-run-{cover,segmentation,stego,difference}.png`.

## 7. Limitations

* Lossless PNG file handoff inside one host; not robust to recompression, resizing, cropping or filtering.
* No claim of undetectability for any algorithm. The bootstrap carrier and the patch map are visible LSB data.
* HUGO is an additive approximation without model correction; the STC uses custom (not the published optimised)
  sub-matrices; DWT/DCT/DCT-SVD are single concrete QIM variants.
* The knowledge base is hand-curated; all thresholds are local heuristics; reference DOIs were not machine-verified.
* On saturated covers (the procedural fallback) most patches map to the same entry (`dwt`), so algorithm diversity
  depends on the cover.
* No error correction or redundancy: one damaged used patch loses the frame.
* A real payload can fail a patch that passed the dry run; handled by ≤ 2 coarser re-plans, then a failure.
* Frame v1 images cannot be received; there is no migration tool (`docs/patchwise-transport.md` section 14).
* Plaintext loopback HTTP between Rust and Python (no TLS, by the project's no-ECC rule).

## 8. Start commands

If you extract this release over an older copy, run `scripts/windows/remove_stale_files.ps1` (or `scripts/linux/remove_stale_files.sh`) first; setup runs it automatically. Unzipping does not delete the files listed in section 3 as removed.

Linux/macOS:
```bash
./scripts/linux/setup.sh            # once: cargo build --release, npm install/build, Python venv
./scripts/linux/run_demo.sh         # Rust core :8787, Python image service :5001, Node gateway :4000
cd web-ui && npm run dev            # dashboard on http://127.0.0.1:5173
python3 scripts/stego_smoke.py      # optional end-to-end check
./scripts/linux/test.sh             # all automated suites
./scripts/linux/stop_demo.sh
```
Windows (PowerShell): `.\scripts\windows\setup.ps1`, `.\scripts\windows\run_demo.ps1`, `cd web-ui; npm run dev`,
`python scripts\stego_smoke.py`, `.\scripts\windows\test.ps1` (scripts mirror the Linux ones; not executed here).

In the dashboard: Drones → create two, Groups → create one and register both, Authentication → authenticate,
Secure Communication → establish the group key, then **Steganography Lab** → pick both drones → *Send as image*
(or *Preview plan*), and **Knowledge Base** for the entries and the retrieval monitor.
Environment variables: `docs/development.md`.
