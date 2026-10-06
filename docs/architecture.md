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
- **`python-service/`** — two subsystems, both Python-only (no
  cryptography, no external network calls, no paid API):
  - **`src/stego/`** — the five real 2D steganography algorithms
    (Adaptive LSB, PVD, DCT, DWT, SVD) plus a real measurement engine
    (`stego/benchmark.py`), exposed over HTTP (`stego_api.py`,
    `/stego/select-and-embed`, `/stego/extract`, `/stego/algorithms`).
    See `docs/steganography.md`.
  - **`src/rag/`** — as of this stage, RAG's PRIMARY role is
    registration-time, measurement-grounded algorithm selection
    (`rag/selector.py` + `rag/stego_knowledge.py`), consumed by
    `stego_api.py`. See `docs/rag-stego-selection.md` and
    `docs/algorithm-selection.md`. The original collaborative
    drone-contribution pipeline (`rag/{retrieval,validation,fusion}.py`,
    `llm/`) still exists and still passes its own tests, but is no
    longer load-bearing for registration — see `docs/rag.md`'s
    "Historical subsystem" section and `docs/claims-and-limitations.md`
    §9.
- **`web-ui/`** — a React + TypeScript (Vite) dashboard. The former
  RAG-chatbot page has been replaced by a Registration/Stego-Selection
  flow page (Capture → Payload → RAG Selection → Stego Preview →
  Registration Status) wired to the live stego endpoints through the
  Node gateway; every other page carries over unchanged. Talks only to
  the Node gateway.

## Why this split, and why Node is thin rather than absent

The project brief requires Rust as the primary/security-critical
implementation, Python for RAG, and a Node.js/TypeScript layer as part
of the architecture (a thin gateway is explicitly acceptable). Given
that, putting protocol/crypto logic in Rust and RAG logic in Python is
the natural fit; Node's role is deliberately minimized to orchestration
and gateway concerns (CORS, a single browser-facing origin, SSE
translation) rather than reimplementing anything Rust already does
correctly and safely.

## Why `tiny_http`, not `axum`/`tokio`, and why SSE-via-polling

This sandbox's Rust toolchain is rustc 1.75.0 (Dec 2023), installed via
`apt` because there is no network path available to `rustup`/
`static.rust-lang.org` to fetch a newer one. Current `axum`/`hyper`/
`tokio` release chains have moved their MSRV past 1.75, and several
other now-current crate versions (`zeroize` 1.9+, `getrandom` 0.4,
`uuid` 1.11+, `jobserver` 0.1.33+) also require a newer cargo/rustc than
what this sandbox has, forcing either version pins or a switch to
lower-MSRV alternatives (see `docs/dependency-rationale.md` for the
exact pins and the reasoning behind each one).

`tiny_http` is a small, synchronous HTTP/1.1 server with essentially no
transitive dependency chain reaching a high MSRV. The Rust core's HTTP
API therefore handles each request sequentially against a single
`Mutex<SimulationState>` — entirely adequate for a local research-demo
simulator driven by one browser tab, and much simpler to audit than an
async runtime introduced for no real benefit at this scale.

Because `tiny_http` has no WebSocket/SSE support of its own, live
updates use `GET /api/events?since=<cursor>` (an incremental log-fetch
endpoint) on the Rust side, which the Node gateway polls internally and
re-exposes as a genuine `text/event-stream` SSE connection to the
browser. The browser-facing contract is still real push-style
incremental updates; only the Rust↔Node leg is polling, and that is
documented here rather than hidden.

**On a machine with a current Rust toolchain**, swapping `tiny_http` for
`axum` with a native WebSocket handler would be a contained change
entirely within `rust-core/src/api/`; nothing in `protocol/`, `crypto/`,
`puf/`, `merkle/`, or `zk/` would need to change, since the API layer
only ever calls into those through their existing public functions.

## Directory layout

```
rust-core/       crypto, protocol, PUF, Merkle, ZK, Zero Trust, Trace Manager, storage, HTTP API
  src/crypto/    field, poseidon, canonical encoding, kem, sign, aead, kdf, domains
  src/puf/       sram_puf (simulation), fuzzy_extractor, crp (challenge-response)
  src/identity/  leaf/commitment construction, PID derivation, device key management
  src/merkle/    generic Poseidon Merkle tree + group-level membership manager
  src/zk/        ZK membership statement/witness/backend (see docs/zk-membership.md)
  src/protocol/  messages, envelope (KEM+AEAD), transcript, registration, registration_stego (R1-R3
                 over steganography), stego_client (Rust<->Python bridge trait + HTTP/mock impls),
                 auth_flow (M1-M8), group_key (K1-K4), secure_messaging, simulation (orchestrator),
                 entities, events
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
3. Rust returns a `VerificationReport` (6 booleans — freshness,
   zk_membership, signature, puf, root_version, and
   credential_consistency (spec 25-B, added this stage) — plus a
   decision + reason code) via the `AuthResultView` DTO — never the
   underlying keys, proofs, or transcripts.
4. Node relays the JSON response verbatim.
5. React renders the checklist and, separately, fetches the session's
   event history to render the M1-M8 message sequence.
6. In parallel, the Rust core has already pushed every step into its
   event log and persisted it to SQLite; the browser's Protocol Logs
   page shows the same events live via the Node SSE relay.
