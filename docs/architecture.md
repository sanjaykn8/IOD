# Architecture

## Component overview

```
┌─────────────┐      HTTP/JSON       ┌──────────────────┐     HTTP/JSON    ┌──────────────────┐
│  React UI   │ ───────────────────► │  Node.js Gateway  │ ───────────────► │  Rust Core (HTTP) │
│  (web-ui)   │ ◄─────────────────── │  (node-server)    │ ◄─────────────── │  (iod-server)     │
└─────────────┘   SSE (live events)  └────────┬──────────┘                 └─────────┬─────────┘
                                               │ HTTP/JSON                            │
                                               ▼                                      ▼
                                     ┌──────────────────┐                   ┌──────────────────┐
                                     │ Python RAG service │                 │  SQLite (bundled) │
                                     │ (python-service)   │                 │  iod_simulation.db│
                                     └──────────────────┘                   └──────────────────┘
```

- **`rust-core/`** — all security-critical logic: PUF simulation, fuzzy
  extractor, ML-KEM-768/Kyber768, ML-DSA-44/Dilithium2, Poseidon,
  Merkle tree, the ZK membership proof, the full M1-M8 authentication
  protocol, K1-K4 group-key establishment, AEAD secure messaging, Zero
  Trust authorization, the Trace Manager, and SQLite persistence. Also
  builds `iod-server` (an HTTP JSON API over all of the above),
  `iod-bench` (benchmarks), and `iod-vectors` (test-vector generator).
- **`node-server/`** — a thin TypeScript/Express gateway. Holds no
  cryptographic or protocol logic; every `/api/*` route is a direct
  proxy to either the Rust core or the Python RAG service. Adds a
  Server-Sent-Events endpoint (`/api/events/stream`) that polls the Rust
  core's event log internally so the browser gets genuine incremental
  push updates even though the Rust↔Node leg is polling-based (see
  "Why tiny_http, not axum" below).
- **`python-service/`** — the collaborative RAG / mock-LLM simulation
  (contribution → retrieval → validation → fusion → generation). No
  cryptography, no external network calls, no paid API.
- **`web-ui/`** — a React + TypeScript (Vite) dashboard with 9 pages
  covering every control the project brief's "Web Dashboard" section
  requires. Talks only to the Node gateway.

## Why this split, and why Node is thin rather than absent

The project brief requires Rust as the primary/security-critical
implementation, Python for RAG, and a Node.js/TypeScript layer as part
of the architecture (a thin gateway is explicitly acceptable). Given
that, putting protocol/crypto logic in Rust and RAG logic in Python is
the natural fit; Node's role is deliberately minimized to orchestration
and gateway concerns (CORS, a single browser-facing origin, SSE
translation) rather than reimplementing anything Rust already does
correctly and safely.

## Why `tiny_http`, and SSE-via-polling

`tiny_http` is a small synchronous HTTP/1.1 server with a minimal dependency
chain (no TLS, no async runtime). It was originally chosen because the first
sandbox had rustc 1.75; the toolchain is now rustc 1.97 but the choice is kept
for simplicity (one `Mutex<SimulationState>`, single-operator simulator). The
Node gateway turns polling into SSE for the browser.
## Directory layout

```
rust-core/       crypto, protocol, PUF, Merkle, ZK, Zero Trust, Trace Manager, storage, HTTP API
  src/crypto/    field, poseidon, canonical encoding, kem, sign, aead, kdf, domains
  src/puf/       sram_puf (simulation), fuzzy_extractor, crp (challenge-response)
  src/identity/  leaf/commitment construction, PID derivation, device key management
  src/merkle/    generic Poseidon Merkle tree + group-level membership manager
  src/zkhash.rs  Poseidon2/BabyBear hash (see docs/zk-specification.md)
  src/zk/        STARK membership AIR, hiding-FRI config, prove/verify API (docs/zk-design.md)
  src/protocol/  messages, envelope (KEM+AEAD), transcript, registration, auth_flow (M1-M8),
                 group_key (K1-K4), secure_messaging, simulation (orchestrator), entities, events
  src/zero_trust/  replaceable policy engine
  src/trace/     Trace Manager
  src/storage/   SQLite persistence (snapshots + db)
  src/api/       HTTP API (views, state, server) — the ONLY place secret-shaped data could
                 leak to an external caller, and the only place explicitly audited against that
  src/bin/       server (HTTP API), bench (benchmarks), vectors (test-vector generator)
  tests/         integration tests against the public API (separate from in-module unit tests)
node-server/     Express gateway + SSE relay
python-service/  Flask RAG/mock-LLM service
web-ui/          React + TypeScript dashboard
docs/            this documentation set
examples/        generated test vectors
scripts/         cross-platform launch/build/test scripts
```

## Data flow: one authentication round, end to end

1. Browser → Node (`POST /api/authenticate`) → Rust (`POST /api/authenticate`).
2. Rust's `SimulationState::authenticate` calls
   `protocol::simulation::run_authentication`, which runs M1 through M8
   using the functions in `protocol::auth_flow`, logging each step.
3. Rust returns a `VerificationReport` (5 booleans + decision + reason
   code) via the `AuthResultView` DTO — never the underlying keys,
   proofs, or transcripts.
4. Node relays the JSON response verbatim.
5. React renders the checklist and, separately, fetches the session's
   event history to render the M1-M8 message sequence.
6. In parallel, the Rust core has already pushed every step into its
   event log and persisted it to SQLite; the browser's Protocol Logs
   page shows the same events live via the Node SSE relay.

## Steganography transport layer
Rust (`rust-core/src/transport/`, `api/stego_routes.rs`) is authoritative for AEAD, AppWire, Frame, MAC, replay and events. Python (`python-service/src/stego/`) hosts cover capture, the five embedding algorithms, selector trial-encodes, artifacts and RAG explanation. Node is a thin relay. React adds the Steganography Lab. Diagrams: `stego-transport.md`.
