# IoD Secure Simulator

A locally-executable research simulation of a post-quantum secure
Internet-of-Drones authentication and communication architecture: PUF +
fuzzy extractor, ML-KEM-768/Kyber768 and ML-DSA-44/Dilithium2, a Poseidon
Merkle membership tree, a transparent (non-ECC) ZK membership proof, the
full M1-M8 authentication handshake, K1-K4 GCS-assisted group-key
establishment, AEAD secure messaging, Zero Trust authorization, a Trace
Manager, device registration (R1-R3) transported through real 2D image
steganography with RAG-assisted, measurement-grounded algorithm
selection, a collaborative RAG/mock-LLM simulation (now a secondary,
non-load-bearing subsystem -- see `docs/rag.md`), and a full web
dashboard — built across Rust (security-critical core), Node.js/
TypeScript (API gateway), Python (steganography + RAG), and React
(dashboard).

**Zero elliptic-curve cryptography anywhere in this project** — see
`docs/ecc-audit.md` for the full, methodical audit.

## Honest status before you read anything else

This is a research prototype, not a production system, and this README
will tell you exactly which parts are which. The single most important
document to read before citing this project's security properties is
`docs/zk-membership.md` — the implemented ZK proof backend is sound and
correctly binds the protocol's version/root, but it does **not** hide
the witness from the verifier (a documented, deliberate scope decision,
not an oversight). `docs/IMPLEMENTATION_STATUS.md` has the complete,
phase-by-phase REAL/SIMULATED/PLACEHOLDER breakdown, including every
real bug found and fixed during development and how it was caught.

## What's REAL, what's SIMULATED, what's PLACEHOLDER/FUTURE

| Component | Classification |
|---|---|
| ML-KEM-768/Kyber768, ML-DSA-44/Dilithium2 | **REAL** (audited PQClean-derived libraries; Round-3 API, see `docs/cryptography.md` for the exact standards mapping) |
| Poseidon hash, Merkle tree | **REAL** (from-scratch, non-ECC field; research-parameterized, not independently audited) |
| SRAM-PUF, fuzzy extractor | **SIMULATED** (necessarily — no physical silicon), with a real code-offset construction and a computed reliability table (`docs/puf.md`) |
| CRP-based PUF verification | **SIMULATED** (noise-free challenge-response; the noisy case is demonstrated at the seed-reconstruction layer instead) |
| ZK membership proof | **REAL soundness/binding, SIMULATED hiding** — see `docs/zk-membership.md`; this is the largest scope limitation in the project |
| M1-M8 authentication, K1-K4 group key, AEAD messaging | **REAL**, fully implemented and tested |
| Zero Trust | **REAL** (deterministic, configurable, replaceable policy engine — not ML-based) |
| Trace Manager | **REAL** |
| SQLite persistence | **REAL** |
| 2D steganography algorithms (Adaptive LSB, PVD, DCT, DWT, SVD) | **REAL** (real pixel embed/extract against real cover images; see `docs/steganography.md`) |
| Registration-time algorithm selection | **REAL selection logic over REAL measurements** (deterministic, importance-weighted; see `docs/algorithm-selection.md`) — the "RAG" in "RAG-assisted" is retrieval + narrative only, never the number-producing step |
| Registration-time RAG narrative/evidence | **SIMULATED retrieval** (word-overlap over a hand-written knowledge base, not embeddings), quoting only real numbers it is handed — see `docs/rag-stego-selection.md` |
| R1-R3 registration transported via steganography | **REAL** end-to-end (real ML-KEM-768/ML-DSA-44 keys, real KEM-then-AEAD sealing, real embed/extract), live via the dashboard's Registration (Stego) page and `iod-register-stego-demo` — see `docs/registration-stego.md` |
| Collaborative drone-contribution RAG pipeline (retrieval/validation/fusion) | **SIMULATED**, still present and tested, but superseded as of this stage for registration — see `docs/rag.md`'s "Historical subsystem" section |
| RAG retrieval (collaborative pipeline) | **SIMULATED** (word-overlap, not embeddings) |
| RAG Byzantine-ish validation (collaborative pipeline) | **SIMULATED** (a labeled heuristic, not a real BFT defense) |
| Mock LLM | **REAL** (genuinely deterministic, template-based; no network call) |
| Ollama LLM provider | **PLACEHOLDER/FUTURE** (interface only, `NotImplementedError`) |
| Node.js↔Rust live updates | **REAL SSE to the browser**, via internal polling on the Rust↔Node leg (documented toolchain-driven decision, see `docs/architecture.md`) |
| Docker configuration | **Best-effort, UNTESTED** — no Docker daemon was available in the development sandbox; the native (non-Docker) path is what was actually verified |

## Architecture

```
React (web-ui) -> Node.js gateway (node-server) -> Rust core HTTP API (iod-server)
                                                  -> Python RAG service (python-service)
```

Full diagram and the reasoning behind every architectural decision
(including why the Rust HTTP layer uses `tiny_http` instead of `axum`,
and why live updates are SSE-over-polling rather than native
WebSockets) in `docs/architecture.md`.

## Prerequisites

- **Rust** (stable toolchain; this project was developed and tested
  against rustc 1.75.0 — see `docs/dependency-rationale.md` for why some
  dependency versions are pinned, and `docs/troubleshooting.md` for how
  to relax those pins on a newer toolchain).
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
./scripts/linux/run_demo.sh          # starts Rust core, Python RAG, Node gateway
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
and decrypt a secure message → run the RAG simulation → revoke D1 →
attempt authentication again (real denial) → inspect the audit log →
invoke the Trace Manager. **This exact script was run in this project's
development session and its full real output is captured in
`docs/IMPLEMENTATION_STATUS.md`.** The React dashboard (see below) walks
through the identical scenario visually.

## Using the web dashboard

Open `http://127.0.0.1:5173` after starting the dashboard dev server (or
serve the production build after `npm run build` with any static file
server). Nine pages, all functional (not mockups): Overview, Drones,
Groups, Authentication, Secure Communication, **Registration (Stego)**,
Trace Manager, Event Log (live via SSE), and System. The Registration
(Stego) page runs the real R1-R3 flow end-to-end from the browser --
pick (or create) an unregistered drone, optionally supply your own R1/R3
cover images, and it drives a real RAG-assisted algorithm selection,
real embed/extract against `python-service`, and real registration,
showing every candidate algorithm's real measurements, the selector's
reasoning, and the resulting stego images (see `docs/registration-stego.md`).
It replaces the former RAG-chatbot page in primary navigation; that page
and its collaborative pipeline still exist and still work, reachable
directly, but are no longer load-bearing for registration (`docs/rag.md`).
Every control was actually driven end-to-end with a headless browser
(Playwright) during development — see `docs/testing.md` for the full
verification writeup and the one real UI bug it caught and fixed.

## Tests

```bash
./scripts/linux/test.sh        # Linux/macOS: Rust + Python + React type-check/build
.\scripts\windows\test.ps1     # Windows
```

**213 automated tests, all passing**: 132 Rust unit tests + 3 end-to-end
integration tests (including a full chained Stego Registration →
Authentication → Authorization → Group Key → Secure Message →
Revocation → denied Re-authentication run) + 3 dedicated
security-negative tests + 75 Python tests (steganography algorithms,
selector, benchmark, RAG knowledge, and the original collaborative RAG
pipeline). Full checklist-to-test mapping (every item from "stale
timestamp" through "invalid AEAD authentication tag") in
`docs/testing.md`.

## Benchmarks

```bash
./scripts/linux/bench.sh       # Linux/macOS
.\scripts\windows\bench.ps1    # Windows
```

Real, measured (not fabricated) avg/p50/p95 latencies for every
primitive, plus concrete sizes (Kyber768 keys/ciphertexts, Dilithium2
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
non-reproducible, and why) — see `docs/zk-membership.md`'s companion,
the top of `rust-core/src/bin/vectors.rs`.

## Known limitations

1. **The ZK membership proof does not hide the witness from the
   verifier.** See `docs/zk-membership.md`. This is the single largest
   scope limitation in the project.
2. **Deterministic PUF-seed-to-keypair regeneration is not literally
   achieved** — keys are generated once from real entropy and persisted
   on-device instead (the underlying pqcrypto library exposes no seeded
   keygen). See `docs/cryptography.md`.
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
7. Several Rust dependency versions are pinned to stay buildable on this
   project's rustc 1.75.0 development toolchain — see
   `docs/dependency-rationale.md` for the exact list and how to relax
   them on a newer toolchain.
8. RAG simulation state (both the collaborative pipeline and the
   registration-time selector's per-request measurements) is
   in-memory/process-lifetime only (not persisted to SQLite) — a
   documented simplification.
9. **Registration via steganography requires `python-service` to be
   reachable** (`IOD_STEGO_SERVICE_URL`, default `http://127.0.0.1:5001`)
   — unlike the plain (non-stego) registration path, which has no such
   dependency. If the service is down, the dashboard's Registration
   (Stego) page and `iod-register-stego-demo` fail with a clear error
   rather than silently falling back to a non-steganographic path. See
   `docs/registration-stego.md`.
10. The registration-time algorithm selector's importance weighting
    (`CRITICAL` by default) is a chosen deployment policy, not a fact
    the project claims to have derived empirically — see
    `docs/algorithm-selection.md`.

## Documentation index

`docs/architecture.md` · `docs/protocol.md` · `docs/cryptography.md` ·
`docs/zk-membership.md` · `docs/puf.md` · `docs/merkle-tree.md` ·
`docs/zero-trust.md` · `docs/rag.md` · `docs/threat-model.md` ·
`docs/security-assumptions.md` · `docs/api.md` · `docs/development.md` ·
`docs/testing.md` · `docs/benchmarking.md` · `docs/troubleshooting.md` ·
`docs/research-notes.md` · `docs/dependency-rationale.md` ·
`docs/ecc-audit.md` · `docs/security-review.md` ·
`docs/steganography.md` · `docs/rag-stego-selection.md` ·
`docs/registration-stego.md` · `docs/image-pipeline.md` ·
`docs/algorithm-selection.md` · `docs/data-and-evaluation.md` ·
`docs/migration-notes.md` · `docs/claims-and-limitations.md` ·
`docs/IMPLEMENTATION_STATUS.md` (the complete, phase-by-phase build log)
