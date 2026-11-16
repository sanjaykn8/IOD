# Implementation report — payload-aware procedural cover generation

Date: 2026-11-15. Base: the patch-wise, knowledge-base-guided transport of 2026-11-13 (`IOD-patchwise-stego-final.zip`).
Unchanged: M1–M8, K1–K3, the Rust-only cryptography, the transport formats `frame-v2/appwire-v1/bootstrap-v2/manifest-v1`,
segmentation `arg-cells-1`, selector `kb-bm25-1`, knowledge base `patch-kb-1`, the ten algorithm ids and variants.
Specifications: `docs/cover-generation.md` (this change), `docs/patchwise-transport.md` (transport),
`docs/detectability-evaluation.md` (offline evaluation).

## 1. What was built

* **Cover generator `procgen-1`** inside the Python image service (`python-service/src/stego/generator/`): four coherent
  image families (terrain, clouds, strata, cells) from multi-octave gradient noise, domain warping and procedural
  palettes; RGB by default; vectorised NumPy; 16-byte seed from the OS CSPRNG per production cover; only a seed
  fingerprint is recorded.
* **Quality pre-screen `cover-quality-1`**: eleven hard gates and a weighted score over local variance, local entropy,
  gradients/edges, adjacent and multi-scale correlation, spectrum and periodic peaks, clipping, flat regions, tile
  similarity, colour balance and contrast. Documented heuristics, not a steganalysis detector.
* **Payload-aware selection** (length only): memory pre-flight → embedding-rate check (optional payload-driven resize
  on a fixed ladder inside the ceiling) → bounded candidates → pre-screen → the real planner in descending quality
  order → the highest-quality feasible candidate. Structured failure with the candidate table otherwise; no fallback.
* **Resource profile `raspberry_pi_5_cpu`** (default) and `development_host`, with hard ceilings and tighten-only
  request settings enforced in **both** Rust and Python (`IOD_STEGO_GENERATOR_*`).
* **Lifecycle**: one fresh cover per transmission; an internal re-plan reuses the stored cover (`replan_cover_id`,
  no generation, same id and SHA-256 enforced by the core); encode loads that exact artifact; the receiver never
  generates or segments; each benchmark transaction generates its own cover.
* **Cameras and uploads removed end to end** from the operational flow (Python routes and OpenCV adapter, Rust routes,
  trait methods and configuration, Node relays and body-limit exception, UI components, types, optional dependency).
  The educational workbench (`/api/learn/*`) keeps its isolated sample covers and PNG upload.
* **Public API**: optional `cover_generation` object on `plan`, `message`, `send`, `benchmark`; `generation` diagnostics
  and a `generated` cover descriptor in responses; six error codes.
* **Dashboard**: "Generated Cover Configuration" (profile, width/height, budget, candidates, resize, fresh-cover note),
  "Generated cover" panel (preview, generator/family, sizes, score, candidates with gates / rejection reasons /
  outcome / timings, budget, memory estimate, fingerprint), failure view with the candidate table, events and report
  with generation statistics; Knowledge Base monitor runs on a fresh cover (seed input removed); Learning tab untouched.
* **Offline tools**: `scripts/eval_detectability.py` (own logistic regression, transparent features, seed/family
  splits, AUC/accuracy/precision/recall/confusion/CIs), `scripts/bench_generator.py` (timings, heap peak, quality
  report, host metadata), `scripts/render_eval_reports.py` (tables from the measured JSON).

**No pretrained model is used anywhere**: no pretrained image generator, LLM, SLM or embedding model, no model download,
no remote inference, no cloud API, no network access at runtime. The generator, the quality heuristics, the per-patch
selector (static knowledge base + BM25) and the evaluation detector are hand-written NumPy / standard-library code.
No dependency was added; the optional `opencv-python-headless` was removed. No ECC code or crate was introduced.

## 2. Design decisions (and why)

| Decision | Reason |
|---|---|
| Capacity is a hard constraint, quality the objective: candidates are planned best-score-first and the first feasible one wins | a larger payload must not buy a busier cover; no payload-proportional texture signature |
| `max_embedding_rate` (0.20 payload bits per cover sample) as an explicit quality constraint | without it a 40 kB payload "fitted" a 320×240 cover through high-rate PVD, which is conspicuous; the limit makes such requests fail or resize instead |
| Payload-driven resize is opt-in and uses a fixed ladder | the image size then reveals only a coarse length class, and the operator decides whether to allow it |
| A plan that finishes after the deadline is accepted and flagged; the budget is checked before each step | discarding a valid result wastes the work already done; bounded by `max_candidates` in any case |
| Request can only tighten; it cannot switch profile | the device owner sets the envelope through the environment; the same rule in Rust and Python means neither trusts the other |
| Raw seeds are never stored; sidecar holds a fingerprint and the cover hash | a seed would let anyone regenerate the cover; the PNG itself is the artifact that matters |
| Re-plan addresses the stored cover by id, and the core checks id + SHA-256 | makes "same cover" a verified property instead of an assumption |
| Covers need a matching generation sidecar to be planned or embedded | a file dropped into the shared directory is not a cover |
| Old cover fields are rejected (400) and old routes are gone (404) | an old client must not believe it is choosing the cover |
| Fine correlated grain (≈1–2 grey levels) as the last generation step | smooth synthetic gradients have banded low bit planes; the gates reject grain-dominated images |
| Feature sizes use `max(min(w, h), 240)` | small covers were miniatures failing the multi-scale gates; now they are crops of a normal scene |
| `/stego/capture` removed instead of redefined | nothing should be able to store a cover without a payload-aware plan |
| Detector, features and benchmark written from scratch in NumPy | the no-pretrained-model / no-new-dependency rule, and transparency of what is measured |

## 3. Files

### New
* Python: `src/stego/generator/{__init__,families,quality,profile,select}.py`; tests `tests/test_generator_{families,quality,select}.py`,
  `tests/test_eval_tools.py`.
* Rust: `src/transport/generator.rs`.
* UI: `src/components/command/stego-generation.tsx`.
* Scripts: `scripts/eval_detectability.py`, `scripts/bench_generator.py`, `scripts/render_eval_reports.py`.
* Docs: `docs/cover-generation.md`, `docs/detectability-evaluation.md`, `docs/samples/detectability-results.json`,
  `docs/samples/generator-benchmark-raspberry_pi_5_cpu-host.json`.

### Changed
* Python: `src/stego/{service,api,artifacts,config,errors,__init__,procedural}.py`, `src/stego/patch/planner.py` (budget hook),
  `src/learn/fixtures.py` (label only), `tests/test_patch_service_api.py` (rewritten for the generated-cover contract).
* Rust: `src/transport/{config,backend,fake,pipeline,report,error,mod}.rs`, `src/api/stego_routes.rs`,
  `tests/{stego_pipeline,stego_e2e_python,learn_workbench}.rs`, `tests/helpers/tamper_png.py`, `.env.example`.
* Node: `src/index.ts`, `src/api/routes.ts`.
* UI: `stego-lab.tsx`, `kb-monitor.tsx`, `lib/{stego-api,stego-errors}.ts`, `types/api.ts`, `styles.css`.
* Scripts / config: `scripts/stego_smoke.py`, `scripts/ui_check.js`, `scripts/{linux,windows}/demo_scenario.*`,
  `scripts/{linux,windows}/remove_stale_files.*`, `docker-compose.yml`, `python-service/.env.example`.
* Docs: `README.md`, `docs/{patchwise-transport,api,architecture,testing,benchmarking,threat-model,security-review,development,
  dependency-rationale,ecc-audit,troubleshooting,stego-algorithms,IMPLEMENTATION_STATUS}.md`, `docs/benchmark-results-patchwise.json`,
  `docs/samples/patchwise-run-*`, `tools/stego-standalone/README.md`, this report.

### Removed (callers checked first; each had none left)
| Removed | Was |
|---|---|
| `python-service/src/stego/cover.py`, `tests/test_stego_cover.py`, `tests/test_stego_webcam.py`, `requirements-camera.txt` | cover acquisition: OpenCV webcam adapter, upload validation, procedural fallback |
| Python routes `/stego/camera/probe`, `/stego/cover/upload`, `/stego/capture`; camera functions in `config.py` | — |
| Rust `StegoBackend::camera_probe`, `::cover_upload`; `StegoConfig.camera_index`, `.capture_timeout_ms`; `MessageRequest.cover`; routes `POST /api/stego/camera/probe`, `/cover/upload`; `cover_from` | replaced by `MessageRequest.cover_generation`, `StegoConfig.generator` |
| Node relays for those two routes and the 14 MB body limit | every operational route keeps the small default limit |
| UI `stego-webcam.tsx` (browser webcam, file upload), cover-source selector, webcam probe, reuse-cover option, KB-monitor seed input; types `StegoCoverRequest`, `StegoCoverSource`, `StegoUploadedCover`, `StegoCoverUploadResult`, `StegoCameraProbe`; `CAMERA_*` texts | replaced by the Generated Cover Configuration and diagnostics |
| Event fields `cover_fallback_reason`, timing `capture`; report `fallback_cover_count` | replaced by the generation fields; report schema `stego-report-3` |

Kept on purpose: `python-service/src/stego/procedural.py` (older black/white generator) is no longer imported by the
operational path; it remains for the standalone tool and one teaching sample of the workbench and is labelled so.
No test was disabled or skipped; tests of removed code were deleted with that code and replaced by tests of the new behaviour.

## 4. Tests run (development container: x86-64 Linux, release build)

| Suite / command | Result |
|---|---|
| `cargo test --release` — lib | 146 passed, 0 failed, 2 ignored (long ZK parameter runs, as before) |
| — `protocol_integration`, `end_to_end` (M1–M8, K1–K3) | 16 passed, 1 passed |
| — `stego_pipeline` (fake image backend) | 22 passed |
| — `stego_e2e_python` (real Python service, real PNG files, service-generated covers) | 7 passed |
| — `learn_workbench` | 4 passed |
| `python3 -m pytest -q` (python-service) | 399 passed |
| `python3 -m unittest test_latent_image` (tools/stego-standalone) | 4 passed |
| `node-server`: `npm run build` (tsc) | OK |
| `web-ui`: `npx tsc --noEmit -p .`, `npm run build` | OK |
| `python3 scripts/stego_smoke.py` against the running stack through the gateway | 83 checks, all passed |
| `scripts/linux/demo_scenario.sh` against the running stack | completed (exit 0) |
| `node scripts/ui_check.js` (Playwright/Chromium against the dev server) | completed: configuration panel, removed controls absent, invalid setting blocks the buttons, preview and send with candidate table, both directions delivered, 8/8 stages OK, structured over-limit failure, event detail, Knowledge Base monitor on a fresh cover, learning comparison |
| `python3 scripts/eval_detectability.py --seeds 40 --payloads 256,1536` | executed (984 s); results in section 7 |
| `python3 scripts/bench_generator.py --profile raspberry_pi_5_cpu --runs 30` | executed; results in section 6 |

Completion-gate items and where they are shown: bidirectional delivery on fresh covers —
`stego_e2e_python::both_directions_real_png_patchwise_on_fresh_generated_covers`, smoke, UI check; induced re-plan on
the same cover — `stego_pipeline::a_failed_patch_embedding_triggers_a_bounded_coarser_replan_not_an_algorithm_fallback`
(fake) and `stego_e2e_python::an_induced_replan_reuses_the_same_generated_cover_end_to_end` (real service); no camera or
upload reachable — `stego_e2e_python::cameras_uploads_and_client_chosen_covers_are_gone_from_the_image_service`,
`test_patch_service_api.py`, smoke (gateway 404 / 400), UI check.

## 5. Tests not run

* **No Raspberry Pi 5 (or any ARM device).** Every timing is a host measurement under the profile's limits.
* No Windows run, no Docker build/run, no debug-mode Rust test run. The PowerShell scripts were edited but not executed.
* No automated browser test suite exists in `web-ui`; the Playwright drive is a script, run here against the dev server.
* `tools/stego-standalone/test_text_vector` (needs a model download; blocked offline; unrelated to this change).
* No steganalysis beyond the small classical detector of section 7 (no rich models, no CNN detector, no photographs).
* ESLint: the repository's Prettier rule reports about 1 100 formatting errors for the dense one-line style used across
  `web-ui` (pre-existing; new files follow the same style).

## 6. Profile-constrained host benchmark (not a Raspberry Pi result)

Host: Intel Xeon @ 2.10 GHz, x86-64, 2 logical CPUs, 8 GB RAM; `is_raspberry_pi_5: false`. Profile `raspberry_pi_5_cpu`
(320×240 RGB, ≤ 2 candidates, 2500 ms, 96 MB, 1 worker), fresh cover per transaction.

Generator selection alone (`docs/samples/generator-benchmark-raspberry_pi_5_cpu-host.json`, 30 runs per size, all 120 succeeded,
none over budget): total mean / p95 = 271 / 339 ms at 96 B, 378 / 499 ms at 512 B, 499 / 684 ms at 2048 B, 717 / 923 ms at 5000 B;
of that, generating two candidates ≈ 151–168 ms and pre-screening ≈ 36–38 ms, the rest is the real planner. Python-heap
peak ≈ 12 MB (pre-flight estimate 24.6 MB, limit 96 MB). Quality report: 240 / 240 fresh covers passed the gates
(60 per family; score means 0.94–0.96, minimum 0.81).

Whole stack (`docs/benchmark-results-patchwise.json`, `POST /api/stego/benchmark`): 320×240, messages of 64 / 256 / 1024 B —
30 / 30 delivered, transaction total mean 589 ms (p50 588, p95 813), PSNR 57.5 dB, 11.3 patches (8 used), all four families
selected, algorithms `s_uniward`, `lsb_matching`, `dct`, `lsb_replacement`, `wow`; 4096-byte messages — 10 / 10, mean 1183 ms;
640×480 requested — 30 / 30, mean 2087 ms (p95 2535), selection alone 1455 ms (p95 1714) of the 2500 ms budget.

A Raspberry Pi 5 will be slower by a factor that was not measured; whether the 2500 ms budget holds there is not established.
Repeatable command for the device: `python3 scripts/bench_generator.py --profile raspberry_pi_5_cpu --runs 30`.

## 7. Detectability evaluation (offline; not a security claim)

Method: 160 generated covers (40 test seeds × 4 families, 320×240 RGB); random payloads of 256 and 1536 bytes; conditions:
the operational patch-wise transport, the same with the carrier rows hidden from the detector, and each of the ten algorithms
alone; 65 transparent features; standardisation + L2 logistic regression written in the script; grouped 5-fold by seed and
leave-one-family-out; bootstrap 95 % intervals. Full tables: `docs/detectability-evaluation.md`.

| Condition | AUC at 256 B (95 % CI) | AUC at 1536 B (95 % CI) |
|---|---|---|
| operational transport (`patch_mixed`) | 0.986 (0.970–0.998) | 0.984 (0.967–0.998) |
| transport, carrier rows hidden | 0.611 (0.593–0.637) | 0.747 (0.712–0.788) |
| `dwt` / `dct` / `dct_svd` alone | 0.975 / 0.859 / 0.896 | 1.000 / 0.989 / 0.898 |
| `pvd` / `lsb_replacement` alone | 0.640 / 0.527 | 0.797 / 0.758 |
| `lsb_matching` / `edge_adaptive_lsb` alone | 0.532 / 0.513 | 0.584 / 0.576 |
| `hugo` / `wow` / `s_uniward` alone | 0.511 / 0.545 / 0.537 | 0.542 / 0.567 / 0.554 |

Reading: **the transport as built is easily detected even by this small detector**, mainly because of the plain-LSB
bootstrap carrier of the (unchanged) `bootstrap-v2` format; below the carrier, detectability rises with payload and with
the share of patches for which the knowledge base selects the quantisation-based transform variants. Values near 0.5
only say that this weak detector, with 128 training pairs, saw little; they are not evidence of undetectability.

## 8. Limitations

* Generated covers are synthetic procedural images from a public generator: recognisable as synthetic, reproducible
  by an adversary in unlimited number. No claim of resemblance to photographs and **no claim of undetectability**.
* The transport is detectable (section 7). Reducing that would need a different bootstrap carrier and a revised
  knowledge base, i.e. a transport-format change, which was out of scope (formats and selection were to be preserved).
* The quality score and all thresholds (gates, embedding-rate limit, memory constant) are engineering heuristics
  calibrated on this generator, not derived bounds.
* `raspberry_pi_5_cpu` enforces limits only; device speed is not emulated and was not measured. The time budget is
  cooperative and the memory limit is a pre-flight estimate; neither is enforced by the operating system.
* A single candidate can fail a gate: 2 of 480 at 320×240 in a calibration sweep (0 of 240 in the benchmark's quality
  report), more often at sizes near 96 px. With two candidates a transmission failing for quality is rare but possible
  and is then a structured failure, not a retry loop.
* The Rust core and the Python service must be given the same `IOD_STEGO_GENERATOR_*` values; a mismatch surfaces as
  `GENERATOR_CONFIG_INVALID`.
* Unchanged from the transport: lossless PNG handoff inside one host; no error correction; HUGO is an additive
  approximation and the STC uses custom sub-matrices; hand-curated knowledge base; plaintext loopback HTTP between Rust
  and Python (no TLS, by the no-ECC rule); single-process simulator.

## 9. Start commands

If you extract this release over an older copy, run `scripts/windows/remove_stale_files.ps1` (or
`scripts/linux/remove_stale_files.sh`) first; setup runs it automatically. Unzipping does not delete the removed files.

Linux/macOS:
```bash
./scripts/linux/setup.sh            # once: cargo build --release, npm install/build, Python venv
./scripts/linux/run_demo.sh         # Rust core :8787, Python image service :5001, Node gateway :4000
cd web-ui && npm run dev            # dashboard on http://127.0.0.1:5173
python3 scripts/stego_smoke.py      # optional end-to-end check
./scripts/linux/test.sh             # all automated suites
python3 scripts/bench_generator.py  # generator benchmark + quality report (labels the host)
python3 scripts/eval_detectability.py --quick --out /tmp/x   # smoke run of the offline evaluation
./scripts/linux/stop_demo.sh
```
Windows (PowerShell): `.\scripts\windows\setup.ps1`, `.\scripts\windows\run_demo.ps1`, `cd web-ui; npm run dev`,
`python scripts\stego_smoke.py`, `.\scripts\windows\test.ps1` (scripts mirror the Linux ones; not executed here).

In the dashboard: Drones → create two, Groups → create one and register both, Authentication → authenticate,
Secure Communication → establish the group key, then **Steganography Lab** → pick both drones → adjust the
*Generated Cover Configuration* if wanted → *Send as image* (or *Preview plan*). Environment variables:
`docs/development.md`, `docs/cover-generation.md` §6.

## Appendix A — the patch-wise transport this change builds on (2026-11-13)

### A.1 Design decisions of the patch-wise transport

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

### A.2 Files of the patch-wise redesign

#### New
* Python: `src/stego/patch/{__init__,segment,features,region,kb,planner,manifest,render}.py`, `src/stego/kb/algorithm_kb.json`,
  `src/stego/codec.py` (rewritten), tests `test_patch_{segmentation,manifest,algorithms,kb,planner_codec,service_api}.py`,
  `test_stego_primitives.py` (STC / cost-map / transform unit tests kept from the old files).
* Rust: `src/transport/manifest.rs`.
* UI: `src/components/command/{stego-shared,stego-patches,kb-monitor}.tsx`, `src/routes/knowledge-base.tsx`.
* Docs: `docs/patchwise-transport.md`, `docs/benchmark-results-patchwise.json`, `docs/samples/patchwise-run-*`,
  `docs/samples/learning-patch-comparison-all-ten.*`, this report. Scripts: `scripts/ui_check.js`.

#### Rewritten or substantially changed
* Python: `src/app.py`, `src/stego/{service,api,bootstrap,artifacts,errors,__init__}.py`, all of `src/stego/algorithms/*.py`
  except `costs.py` and `stc.py` (new mask contract), `src/learn/{experiment,walkthrough}.py`, `tests/test_learn_workbench.py`,
  `tests/stego_helpers.py`.
* Rust: `src/transport/{frame,pipeline,backend,fake,config,report,error,mod,wire}.rs`, `src/api/stego_routes.rs`, `src/learn.rs`,
  `tests/{stego_pipeline,stego_e2e_python,learn_workbench}.rs`, `tests/helpers/tamper_png.py`.
* Node: `src/api/routes.ts`, `src/config.ts`, `src/index.ts`, `Dockerfile`.
* UI: `stego-lab.tsx`, `learn-workbench.tsx`, `stego-tabs.tsx`, `app-shell.tsx`, `operations-pages.tsx`, `lib/{api,stego-api,stego-errors,learn-api}.ts`,
  `types/api.ts`, `styles.css`, `routes/steganography.tsx`, generated `routeTree.gen.ts`, legacy `App.tsx`, `services/api.ts`, `pages/SettingsPage.tsx`.
* Docs/scripts: `README.md`, `docs/{api,architecture,testing,IMPLEMENTATION_STATUS,stego-algorithms,learning-workbench,benchmarking,development,
  dependency-rationale,security-review,protocol,zk-test-results,worked-examples}.md`, `docker-compose.yml`, `scripts/stego_smoke.py`,
  `scripts/{linux,windows}/{run_demo,setup,test,demo_scenario}.*`.

#### Removed (callers checked first; each had none left)
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

