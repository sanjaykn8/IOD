# IoD Secure Simulator

A locally-executable research simulation of a post-quantum secure
Internet-of-Drones authentication and communication architecture: PUF +
fuzzy extractor, ML-KEM-768/Kyber768 and ML-DSA-44/Dilithium2, a Poseidon
Merkle membership tree, a transparent (non-ECC) ZK membership proof, the
full M1-M8 authentication handshake, K1-K4 GCS-assisted group-key
establishment, AEAD secure messaging, Zero Trust authorization, a Trace
Manager, a collaborative RAG/mock-LLM simulation, and a full web
dashboard — built across Rust (security-critical core), Node.js/
TypeScript (API gateway), Python (RAG), and React (dashboard).

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
| ML-KEM-768/Kyber768, ML-DSA-44/Dilithium2 | **REAL** (audited PQClean-derived libraries; Round-3 API, see `docs/cryptography.md` for the exact standards mapping) |
| Poseidon2/BabyBear hash, Merkle tree | **REAL** (Plonky3 Poseidon2 constants, 248-bit digest; not independently audited) |
| SRAM-PUF, fuzzy extractor | **SIMULATED** (necessarily — no physical silicon), with a real code-offset construction and a computed reliability table (`docs/puf.md`) |
| CRP-based PUF verification | **SIMULATED** (noise-free challenge-response; the noisy case is demonstrated at the seed-reconstruction layer instead) |
| ZK membership proof | **REAL witness-hiding zk-STARK** (Plonky3 `0.9.0-rc.1` hiding FRI; 128 b conjectured / 120 b proven) — see `docs/zk-design.md`; privacy tested structurally, RC library not independently audited |
| M1-M8 authentication, K1-K4 group key, AEAD messaging | **REAL**, fully implemented and tested |
| Zero Trust | **REAL** (deterministic, configurable, replaceable policy engine — not ML-based) |
| Trace Manager | **REAL** |
| SQLite persistence | **REAL** |
| RAG retrieval | **SIMULATED** (word-overlap, not embeddings) |
| RAG Byzantine-ish validation | **SIMULATED** (a labeled heuristic, not a real BFT defense) |
| Mock LLM | **REAL** (genuinely deterministic, template-based; no network call) |
| Ollama LLM provider | **PLACEHOLDER/FUTURE** (interface only, `NotImplementedError`) |
| Steganography transport | **PLACEHOLDER/FUTURE** (interface only, per explicit project scope) |
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
serve `web-ui/dist/` after `npm run build` with any static file server).
Nine pages, all functional (not mockups): Dashboard, Drones, Groups,
Authentication, Secure Communication, RAG Simulation, Trace Manager,
Protocol Logs (live via SSE), and Settings. Every control was actually
driven end-to-end with a headless browser (Playwright) during
development — see `docs/testing.md` for the full verification writeup
and the one real UI bug it caught and fixed.

## Steganography transport (application messages)

After M1–M8 and K1–K3 (unchanged), each application message is AEAD-sealed in Rust, wrapped as AppWire v1 and a Frame v1 (header + wire + HKDF-keyed HMAC-SHA256 tag), embedded in a PNG by one of five algorithms (LSB replacement, LSB matching, PVD, edge-adaptive LSB, DCT), saved, and the receiver reads **only the saved file**. Both directions use images; there is no plaintext fallback, and failures are structured errors persisted as events. A deterministic policy selector (`sel-policy-1`) chooses the algorithm; RAG only explains the choice. UI: **Steganography Lab** (`/steganography`). Cover: webcam if available, else a procedural B/W image (the webcam path is **unverified on hardware**). Limits: PNG-lossless only, not robust to JPEG/resize, plaintext loopback hop, simulation. Full detail: `docs/stego-transport.md`.

Quick check: `python3 scripts/stego_smoke.py` (with services running; see the script header). Standalone tool: `tools/stego-standalone/`.

## Tests

```bash
./scripts/linux/test.sh        # Linux/macOS: Rust + Python + React type-check/build
.\scripts\windows\test.ps1     # Windows
```

**Current results** (see `docs/testing.md`): Rust `cargo test --release` = 133 lib + 16 protocol integration + 1 end-to-end + 15 stego pipeline + 5 stego e2e (real Python service); Python `pytest` = 428; plus the 38-check `scripts/stego_smoke.py`. Full checklist-to-test mapping (every item from "stale
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
non-reproducible, and why) — see
the top of `rust-core/src/bin/vectors.rs`.

## Known limitations

1. **Moderate anonymity only.** The ZK proof hides leaf index/path and `rho`
   from D2, but sessions are linkable (stable keys/credential id) and
   metadata is public; the GCS knows everything. See `docs/zk-security-analysis.md`.
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
7. v2 builds with rustc 1.97 (Plonky3 `=0.9.0-rc.1` is pinned exactly); the
   PQ crates are Round-3 Kyber768/Dilithium2, not final FIPS 203/204.
8. RAG simulation state is in-memory/process-lifetime only (not
   persisted to SQLite) — a documented simplification.

## Documentation index

`docs/architecture.md` · `docs/protocol.md` · `docs/cryptography.md` ·
`docs/zk-specification.md` · `docs/zk-design.md` · `docs/zk-security-analysis.md` · `docs/zk-implementation.md` · `docs/zk-test-results.md` · `docs/paper-evidence.md` · `docs/puf.md` · `docs/merkle-tree.md` ·
`docs/zero-trust.md` · `docs/rag.md` · `docs/threat-model.md` ·
`docs/security-assumptions.md` · `docs/api.md` · `docs/development.md` ·
`docs/testing.md` · `docs/benchmarking.md` · `docs/troubleshooting.md` ·
`docs/research-notes.md` · `docs/dependency-rationale.md` ·
`docs/ecc-audit.md` · `docs/security-review.md` ·
`docs/stego-transport.md` · `docs/stego-implementation-note.md` ·
`docs/IMPLEMENTATION_STATUS.md` (the complete, phase-by-phase build log)
