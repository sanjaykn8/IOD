# IoD Secure Simulator

A locally-executable research simulation of a post-quantum secure
Internet-of-Drones authentication and communication architecture: PUF +
fuzzy extractor, ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204), a Poseidon2
Merkle membership tree, a transparent (non-ECC) ZK membership proof, the
full M1-M8 authentication handshake, K1-K4 GCS-assisted group-key
establishment, AEAD secure messaging, Zero Trust authorization, a Trace
Manager, a patch-wise, knowledge-base-guided image steganography transport
for application messages, and a full web dashboard — built across Rust
(security-critical core), Node.js/TypeScript (API gateway), Python (image
processing) and React (dashboard).

**Zero elliptic-curve cryptography anywhere in this project** — see
`docs/ecc-audit.md` for the full, methodical audit.

## Honest status before you read anything else

This is a research prototype, not a production system. **Protocol v2** replaced the
v1 witness-revealing "ZK" backend with a witness-hiding zk-STARK (hiding FRI,
Poseidon2/BabyBear, no ECC), made every key come from a GCS-signed ML-DSA
credential, gated group-key issue on a completed authentication session, and
hardened PID/replay/trace handling. Read `docs/IMPLEMENTATION_STATUS.md` (the
REAL/SIMULATED/PLACEHOLDER table and known limitations),
`docs/zk-security-analysis.md` (assumptions and what is *not* claimed) and
`docs/protocol.md` (including the v1→v2 correction note) before citing any
security property. Benchmarks are host-simulation measurements only.

## What's REAL, what's SIMULATED, what's PLACEHOLDER/FUTURE

| Component | Classification |
|---|---|
| ML-KEM-768 (FIPS 203), ML-DSA-44 (FIPS 204) | **REAL**, final standards (RustCrypto `ml-kem` / `ml-dsa`, pinned); NIST ACVP vectors and PQClean interop pass; suite `iod-fips203-mlkem768-fips204-mldsa44-v1`; **not FIPS 140-3 validated** (`docs/cryptography.md`) |
| Poseidon2/BabyBear hash, Merkle tree | **REAL** (Plonky3 Poseidon2 constants, 248-bit digest; not independently audited) |
| SRAM-PUF, fuzzy extractor | **SIMULATED** (necessarily — no physical silicon), with a real code-offset construction and a computed reliability table (`docs/puf.md`) |
| CRP-based PUF verification | **SIMULATED** (noise-free challenge-response; the noisy case is demonstrated at the seed-reconstruction layer instead) |
| ZK membership proof | **REAL witness-hiding zk-STARK** (Plonky3 `0.9.0-rc.1` hiding FRI; 128 b conjectured / 120 b proven) — see `docs/zk-design.md`; privacy tested structurally, RC library not independently audited |
| M1-M8 authentication, K1-K4 group key, AEAD messaging | **REAL**, fully implemented and tested |
| Zero Trust | **REAL** (deterministic, configurable, replaceable policy engine — not ML-based) |
| Trace Manager | **REAL** |
| SQLite persistence | **REAL** |
| Patch-wise stego transport (segmentation, risk-aware knowledge-base selection, operational algorithm policy, Frame v3, authenticated manifest, keyed bootstrap-v3 carrier) | **REAL** (simulation: file handoff, no radio link; detectable by classical detectors, see `docs/detectability-evaluation.md`) |
| Per-patch algorithm selection | **REAL**, deterministic: hard filters, then a versioned risk table measured on a validation split, then BM25; no LLM, no learned model at run time |
| Radio / UAV link, Raspberry Pi 5 measurements | **DEFERRED** (all timings are host measurements) |
| Node.js↔Rust live updates | **REAL SSE to the browser**, via internal polling on the Rust↔Node leg (documented toolchain-driven decision, see `docs/architecture.md`) |
| Docker configuration | **Best-effort, UNTESTED** — no Docker daemon was available in the development sandbox; the native (non-Docker) path is what was actually verified |

## Architecture

```
React (web-ui) -> Node.js gateway (node-server) -> Rust core HTTP API (iod-server)
                                   Rust core -> Python image service (python-service; no keys, loopback only)
```

Full diagram and the reasoning behind every architectural decision
(including why the Rust HTTP layer uses `tiny_http` instead of `axum`,
and why live updates are SSE-over-polling rather than native
WebSockets) in `docs/architecture.md`.

## Prerequisites

- **Rust** stable, tested with rustc/cargo 1.97.0 (Plonky3 needs a recent
  toolchain; the old 1.75 pins were removed). A C compiler is needed for
  PQClean and bundled SQLite (MSVC Build Tools on Windows).
- **Node.js** 18+ and npm.
- **Python** 3.9+ and pip.
- A C compiler (for `rusqlite`'s bundled SQLite build): `build-essential`
  on Linux, or the MSVC Build Tools on Windows.
- No Docker required for the verified path (see "Docker" above).

## Installation

**Linux/macOS:**
```bash
./scripts/linux/setup.sh
```

**Windows (PowerShell):**
```powershell
.\scripts\windows\setup.ps1
```

Both scripts build the Rust core, install and build the Node gateway,
create a Python virtualenv and install its dependencies, and install
and build the React dashboard.

## Build (after setup, or to rebuild after a code change)

**Linux/macOS:** `./scripts/linux/build.sh`
**Windows:** `.\scripts\windows\build.ps1`

## Database initialization

No manual step needed — `iod-server` creates `iod_simulation.db` (SQLite,
via `rusqlite`'s bundled build) automatically on first run if it doesn't
exist. Override the path with `IOD_DB_PATH` (see `configs/README.md`).

## Running

**One-command demo (Linux/macOS):**
```bash
./scripts/linux/run_demo.sh          # starts Rust core, Python image service, Node gateway
cd web-ui && npm run dev              # in another terminal: starts the dashboard
# open http://127.0.0.1:5173
./scripts/linux/stop_demo.sh          # when done
```

**One-command demo (Windows PowerShell):**
```powershell
.\scripts\windows\run_demo.ps1
cd web-ui; npm run dev
# open http://127.0.0.1:5173
.\scripts\windows\stop_demo.ps1
```

See `docs/development.md` for running each component manually in
separate terminals (useful for development with hot-reload).

## Scripted demonstration procedure

With the backend services running (`run_demo.sh`/`run_demo.ps1`):

```bash
./scripts/linux/demo_scenario.sh      # Linux/macOS
.\scripts\windows\demo_scenario.ps1   # Windows
```

This exercises, via the real HTTP API, exactly the walkthrough the
project was scoped around: create D1 and D2 → create a group → register
both → authenticate D1→D2 (real ALLOW) → establish a group key → send
and decrypt a secure message (carried in a PNG) → preview a patch plan → revoke D1 →
attempt authentication again (real denial) → inspect the audit log →
invoke the Trace Manager. **This exact script was run in this project's
development session and its full real output is captured in
`docs/IMPLEMENTATION_STATUS.md`.** The React dashboard (see below) walks
through the identical scenario visually.

## Using the web dashboard

Open `http://127.0.0.1:5173` after starting the dashboard dev server (or
serve `web-ui/dist/` after `npm run build` with any static file server).
Ten pages in grouped navigation (Overview; Fleet: Drones, Groups; Protocols: Authentication,
Secure communication; Analysis: Steganography lab, Knowledge base; Audit: Trace manager, Event log;
System), dark and light themes, designed to `docs/ui-design-system.md`. Every value comes from the
backend. The main flows are driven by `scripts/ui_check.js` (Playwright); screenshots at 1440, 1024,
768 and 390 px are in `docs/screenshots/ui/`.

## Steganography transport (application messages)

After M1–M8 and K1–K3 (unchanged), each application message is AEAD-sealed in Rust and wrapped as AppWire v1. For **every transmission** the Python image service generates a **fresh cover locally** — a procedural image (multi-scale gradient noise, domain warping, four families; NumPy only, seeded from the OS CSPRNG, **no pretrained model, no network, no camera, no upload**) chosen payload-aware: a bounded number of candidates is pre-screened with documented visual-coherence heuristics and the real planner picks the highest-quality candidate that can carry the payload *length* (`docs/cover-generation.md`; default resource profile `raspberry_pi_5_cpu`: 320×240, at most 2 candidates, 2500 ms — a limit profile, not an emulation of that device). The service then segments that cover into **irregular patches** by adaptive region growing, computes a feature vector per patch and selects **one algorithm per patch** (hard filters including the operational policy and measured capacity, then the versioned risk table — risk tier, changes per bit, cost — then BM25 over a static, curated knowledge base; no LLM, no embeddings, no network). The payload is cut into sequential chunks, one per used patch. Algorithms are restricted by the operational policy `low_detectability` (DCT/DWT/DCT-SVD excluded by rule, LSB replacement by the validation-split risk table; `all_algorithms` for comparisons). Rust validates the resulting **patch manifest**, builds **Frame v3** and authenticates manifest + payload with an HKDF-keyed HMAC-SHA256, and encrypts the compressed manifest into a **keyed bootstrap-v3 carrier** whose pixel positions derive from a per-frame placement key that never leaves Rust; Python (which never holds a key) embeds, writes the carrier at the positions its value stream maps to, saves the PNG and re-reads it. The receiver reads **only the saved file**: Rust locates the carrier by a bounded sequence-number search (sync word), decrypts and validates the manifest, Python extracts the patches with it (it never re-segments), and Rust verifies the MAC, the manifest, channel/direction/sequence/replay and the AEAD. Ten algorithm ids (LSB replacement, LSB matching, PVD, edge-adaptive LSB, DCT, Haar DWT, DCT-SVD, HUGO additive approximation, WOW, S-UNIWARD; the last three with custom-matrix syndrome-trellis codes) all work on patch masks. Both directions use images; there is no plaintext fallback, no single-algorithm fallback and no message priority class; failures are structured errors persisted as events. UI: **Steganography lab** (`/steganography`: overlay, patch inspector, per-patch selection, before/after/difference, exports), **Knowledge base** (`/knowledge-base`, incl. the risk table) and the separate educational **Algorithm Learning** tab (`docs/learning-workbench.md`, `docs/worked-examples.md`). Limits: PNG-lossless only, not robust to JPEG/resize, plaintext loopback hop, simulation. Exact formats, MAC coverage, test vectors and limitations: `docs/patchwise-transport.md`. What changed and what was removed: `IMPLEMENTATION_REPORT.md`.

Quick check: `python3 scripts/stego_smoke.py` (with services running; see the script header). Cover generator: `docs/cover-generation.md`; generator benchmark `python3 scripts/bench_generator.py`; offline detectability evaluation `python3 scripts/eval_detectability.py` (`docs/detectability-evaluation.md` — with SRM-inspired features the transport is detected with AUC ≈ 0.67 at 256 B up to ≈ 0.87 at 3 KB; the bootstrap-v2 band signature is gone, but the AUC ≤ 0.55 aspiration is **not met**; no undetectability is claimed). Standalone tool: `tools/stego-standalone/`.

## Tests

```bash
./scripts/linux/test.sh        # Linux/macOS: Rust + Python + React type-check/build
.\scripts\windows\test.ps1     # Windows
```

**Current results** (2026-11-19, see `docs/testing.md`): Rust `cargo test --release` = 177 lib + 7 FIPS KAT + 5 FIPS interop + 3 suite lifecycle + 16 protocol integration + 1 end-to-end + 23 stego pipeline + 7 stego e2e (real Python service) + 4 learning workbench; Python `pytest` = 416; plus the 83-check `scripts/stego_smoke.py`. Full checklist-to-test mapping (every item from "stale
timestamp" through "invalid AEAD authentication tag") in
`docs/testing.md`.

## Benchmarks

```bash
./scripts/linux/bench.sh       # Linux/macOS
.\scripts\windows\bench.ps1    # Windows
```

Real, measured (not fabricated) avg/p50/p95 latencies for every
primitive, plus concrete sizes (ML-KEM-768 keys/ciphertexts, ML-DSA-44
keys/signatures, ZK proof size). Full captured output and honest
interpretation guidance in `docs/benchmarking.md`.

## Test vectors

```bash
./scripts/linux/vectors.sh     # Linux/macOS
.\scripts\windows\vectors.ps1  # Windows
```

Writes `examples/test-vectors/generated_vectors.json`. Explicitly split
into a fully-deterministic section (verified byte-for-byte identical
across two runs) and a captured-real-run section (honestly documented as
non-reproducible, and why) — see
the top of `rust-core/src/bin/vectors.rs`.

## Known limitations

1. **Moderate anonymity only.** The ZK proof hides leaf index/path and `rho`
   from D2, but sessions are linkable (stable keys/credential id) and
   metadata is public; the GCS knows everything. See `docs/zk-security-analysis.md`.
2. **Device keys are not derived from the PUF.** ML-KEM/ML-DSA keys are generated
   once from OS entropy and persisted on-device (seed form). The libraries do offer
   the standard seeded key generation, but the PUF here is a software simulation,
   so it is deliberately not used as key material; physical PUF integration is
   deferred. See `docs/cryptography.md`.
3. **GCS knows every group's session key** (`K_G,M`) — a property of the
   frozen specification's own K1-K4 design, not an implementation
   defect. See `docs/threat-model.md`.
4. **No TLS between the four local services** — acceptable only because
   everything binds to `127.0.0.1`; would need addressing before any
   real networked deployment.
5. **Docker configuration is untested** (no Docker daemon in the
   development sandbox).
6. **Windows scripts are written carefully to mirror the tested Linux
   scripts and were manually re-reviewed line-by-line against actual
   PowerShell cmdlet semantics** (catching and fixing two real bugs in
   that review: a nonexistent `Start-Process -Environment` parameter,
   and `Invoke-RestMethod` throwing on the expected-error demo step —
   see `docs/IMPLEMENTATION_STATUS.md`), **but were not executable-tested
   on an actual Windows machine** in this session (none was available).
   Please report any remaining issues.
7. Builds with rustc 1.97 (Plonky3 `=0.9.0-rc.1`, `ml-kem =0.3.4`, `ml-dsa =0.1.2`
   pinned exactly). The algorithms are the final FIPS 203/204 ones and pass the NIST
   ACVP vectors, but the software is **not FIPS 140-3 validated**.
8. The steganography transport is a lossless-PNG file handoff inside one
   host; it is not robust to recompression and no steganalysis resistance
   is claimed: classical detectors separate transport images from covers
   (`docs/detectability-evaluation.md`, `docs/patchwise-transport.md` section 13).
9. The PUF is a software simulation; Raspberry Pi 5 measurements and the
   radio/UAV link are deferred.

## Documentation index

`docs/architecture.md` · `docs/protocol.md` · `docs/cryptography.md` ·
`docs/zk-specification.md` · `docs/zk-design.md` · `docs/zk-security-analysis.md` · `docs/zk-implementation.md` · `docs/zk-test-results.md` · `docs/paper-evidence.md` · `docs/puf.md` · `docs/merkle-tree.md` ·
`docs/zero-trust.md` · `docs/threat-model.md` ·
`docs/security-assumptions.md` · `docs/api.md` · `docs/development.md` ·
`docs/testing.md` · `docs/benchmarking.md` · `docs/troubleshooting.md` ·
`docs/research-notes.md` · `docs/dependency-rationale.md` ·
`docs/ecc-audit.md` · `docs/security-review.md` ·
`docs/patchwise-transport.md` · `docs/bootstrap-v3-design.md` · `docs/detectability-evaluation.md` · `docs/ui-design-system.md` · `docs/cover-generation.md` · `docs/stego-algorithms.md` · `docs/learning-workbench.md` · `docs/worked-examples.md` · `IMPLEMENTATION_REPORT.md` ·
`docs/IMPLEMENTATION_STATUS.md` (the complete, phase-by-phase build log)
