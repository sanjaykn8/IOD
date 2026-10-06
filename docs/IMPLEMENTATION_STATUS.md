# Implementation Status

This file is updated after every phase. It is the single source of truth
for what is REAL, SIMULATED, or PLACEHOLDER/FUTURE in this repository.
Do not trust marketing language elsewhere over this file.

Legend:
- **REAL** — genuine implementation using real algorithms/libraries, not a stub.
- **SIMULATED** — a deliberately simplified but mathematically meaningful
  stand-in for something that would require production-grade infrastructure
  (e.g. real silicon) or a research-grade proof backend not realistically
  buildable in this sandbox. Clearly documented, not hidden.
- **PLACEHOLDER/FUTURE** — interface exists, real implementation
  deferred (e.g. the Ollama LLM provider). Steganography transport was
  in this category through Phase 10; it moved to REAL in Phase 11 (see
  below) and this line is updated to stop citing it as the example.

## Environment constraints discovered (affect several decisions below)

- Sandbox `rustc`/`cargo` = **1.75.0** (Dec 2023), installed via `apt`. No
  network path to rustup/static.rust-lang.org to get a newer toolchain.
  This forced several dependency downgrades/pins (see
  `rust-core/Cargo.toml` comments and `docs/dependency-rationale.md`).
- Chosen PQ crypto crates: `pqcrypto-kyber` 0.8.1 (Kyber768, NIST Round 3)
  and `pqcrypto-dilithium` 0.5.0 (Dilithium2, NIST Round 3) rather than
  the newer `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS 203/204) crates, whose
  build scripts require cargo ≥1.77. This is a faithful, real
  implementation of the exact algorithms the specification names
  ("Kyber768", "Dilithium2"); see `docs/cryptography.md` for the standards
  mapping to ML-KEM-768/ML-DSA-44 and the precise (minor) differences.

## Phase 1 — PUF + fuzzy extractor + crypto wrappers

**Status: COMPLETE.** 35/35 unit tests passing, re-run 5x with no flakiness.

| Component | Classification | Notes |
|---|---|---|
| Goldilocks prime field (`crypto::field`) | REAL | Hand-written, cross-checked against an independent `u128 % p` oracle over 2000 randomized cases. Not an ECC field — no curve group is ever formed. |
| Poseidon hash (`crypto::poseidon`) | REAL (research-parameterized) | From-scratch permutation over the field above. Round constants generated transparently via SHAKE256("IOD-POSEIDON-RC-V1", tag). Parameters (t=3, R_F=8, R_P=22, MDS via deterministic Cauchy matrix) are a reasonable, documented, conservative choice — **not** run through the formal Poseidon parameter-selection/security-margin tooling used in production deployments, and not independently audited. Suitable for this research prototype; not for production. |
| Canonical byte→field encoding (`crypto::canonical`) | REAL | Explicit length-prefixing of every variable-length field, fixed field order per record — closes the "ambiguous concatenation" issue called out in the spec. |
| ML-KEM-768/Kyber768 (`crypto::kem`) | REAL | Real PQClean-backed encapsulate/decapsulate via `pqcrypto-kyber`. Deterministic-seed-to-keypair (`KeyGen_from_seed`) is **not** exposed by this library; documented as a limitation with the practical workaround used (see file header comment and `docs/cryptography.md`). |
| ML-DSA-44/Dilithium2 (`crypto::sign`) | REAL | Real PQClean-backed sign/verify via `pqcrypto-dilithium`. Signing always operates on a pre-canonicalized byte transcript, never a raw JSON/serde value. |
| AEAD (`crypto::aead`, ChaCha20-Poly1305) | REAL | Documented nonce policy (`seq:4B \|\| random:8B`), sequence-number replay protection layered on top of the AEAD tag itself. |
| KDF/HMAC/SHAKE256 (`crypto::kdf`) | REAL | HKDF-SHA256, HMAC-SHA256 (constant-time compare), SHAKE256 transcript hashing with explicit per-segment length prefixes. |
| SRAM-PUF simulation (`puf::sram_puf`) | SIMULATED (necessarily — no real silicon) | Per-device "golden pattern" + independent per-bit noise (default 5%, realistic for real SRAM PUFs). Golden pattern is never persisted in the shared application DB — modeled as living only in the (simulated) device. |
| Fuzzy extractor (`puf::fuzzy_extractor`) | REAL construction, SIMULATED code choice | Genuine code-offset construction (Dodis-Ostrovsky-Reyzin-Smith) with a real strong-extractor hash step (SHAKE256). Error-correcting code is a **repetition code** (REPEAT=31, majority vote) rather than a production BCH/Reed-Solomon code — a deliberate simplification for auditability. Computed reliability: per-attempt full-256-bit-secret reconstruction failure probability < 10⁻⁶ at the default 5% PUF noise level (see module doc and `docs/puf.md`). This was verified empirically: the initial REPEAT=15 parameter set failed a 25-trial reliability test in this session; root-caused (not a logic bug — insufficient error-correction margin for the noise level) and fixed by increasing REPEAT to 31 with a formally computed reliability bound, not by weakening the test. |
| CRP-based PUF verification (`puf::crp`) | SIMULATED (documented) | Challenge-response modeled as deterministic (noise-free) `SHAKE256(golden_pattern \|\| challenge)`. The noisy-reconstruction problem is already demonstrated at the seed-derivation layer above; re-applying full fuzzy extraction here too is documented as a known future extension, not implemented, to avoid duplicating the same mechanism for no additional pedagogical value in this prototype. |

## Phase 2 — Poseidon canonical encoding + Merkle tree + witnesses

**Status: COMPLETE.** 58/58 unit tests passing (35 from Phase 1 + 23 new).

| Component | Classification | Notes |
|---|---|---|
| Group-ID → field mapping (`identity::group_id`) | REAL, documented correction | The spec's leaf formula folds a variable-length group ID `G` directly into Poseidon. We map `G` to a single canonical field element via a dedicated Poseidon domain over the length-prefixed byte encoding, then use that one element everywhere `G` appears (leaf, ZK public input, transcripts). Documented as an implementation-level correction that preserves the protocol's data flow/security property while removing "ambiguous concatenation." |
| Membership metadata (`identity::metadata`) | REAL | Canonical, length-prefixed, fixed-order encoding of `{role, issued_at_unix}`. |
| Leaf construction (`identity::leaf`) | REAL | `L = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)` exactly per spec, with canonical encoding closing the ambiguity gap. Tested: changing any one field changes the leaf. |
| PK commitment (`identity::commitment`) | REAL | `comm_PK = Poseidon(0x02, PK_KEM, PK_Dil)`. Verified distinct from the leaf domain even on identical raw bytes. Sources its bytes from the same `DeviceKeys` struct used for real Dilithium verification elsewhere — prevents proof/key splicing by construction. |
| PID derivation (`identity::pid`) | REAL | `SHAKE256(0x03 \|\| seed \|\| "PID" \|\| counter)`. Documented MODERATE anonymity model (PID rotates, but stable `comm_PK`/public keys delivered in `CredResp` still permit linkability — never described as unlinkable). |
| Device keys (`identity::keys`) | REAL keys, documented seed-derivation limitation | Same limitation as Phase 1's KEM/signature note: domain-separated seed material is genuinely derived and tested, but is not fed into the vendored PQClean keygen (no seeded API exposed). Keys are generated once and persisted only on-device. |
| Poseidon Merkle tree (`merkle::tree`) | REAL | Flat 1-indexed array binary tree, `Fp::ZERO` empty-leaf sentinel (documented, negligible collision risk with a real Poseidon leaf), witness generation + standalone `verify_witness` matching the spec's `PositionSwitcher` left/right convention. Tests include stale-witness-after-mutation and revocation-zeroes-leaf cases. |
| Group membership manager (`merkle::group_tree`) | REAL | One Merkle tree per group; register/revoke/re-register lifecycle; version (`V_G`) incremented on every mutation; `refresh_all_witnesses()` for the "regenerate affected witnesses" requirement; capacity-exceeded and double-registration/revoke-unknown error handling. |

## Phase 3 — ZK membership proof

**Status: COMPLETE.** 66/66 unit tests passing (58 from Phases 1-2 + 8 new).

| Component | Classification | Notes |
|---|---|---|
| `ZkStatement`/`ZkWitness`/`ZkProof` interface (`zk::statement`, `zk::witness`, `zk::backend`) | REAL interface | Clean trait-shaped separation so a future hiding backend (FRI-STARK / MPC-in-the-head) can be substituted without touching protocol call sites. |
| Algebraic relation checking (leaf recompute, PK-commitment recompute, Merkle-path fold) | REAL | Genuinely recomputed with real Poseidon/Merkle code, both when the (honest) prover generates a proof and independently when a verifier checks one. A prover cannot emit an accepting proof for an inconsistent witness (tested). |
| G_public/G_witness binding (spec correction #3) | REAL | The verifier's leaf recomputation uses `statement.g` directly — there is no separate witness-side "G" a malicious prover could splice in. |
| V_G actually binds the proof (spec correction #4/#5) | REAL | Fiat-Shamir challenge folds in `V_G`, recomputed by the verifier from **its own** trusted current version, not a value carried in the proof. Directly tested: a verifier with a newer `V_G` rejects a proof made against the old version, even though every other equation in that proof still holds. |
| Session/replay binding | REAL | Fiat-Shamir challenge binds the proof to the exact `(G,R_G,V_G,comm_PK)` tuple; tested against wrong root, wrong group, wrong commitment. |
| **Zero-knowledge hiding of the witness from the verifier** | **NOT ACHIEVED — SIMULATED, precisely documented** | This is the single largest research-grade simplification in the project. Achieving true hiding for a generic hash/Merkle relation without ECC-SNARKs requires a hash-based STARK (FRI), MPC-in-the-head, or lattice-based homomorphic commitments — each a standalone research undertaking too large and too easy to get subtly wrong to attempt safely in this session. The implemented backend performs real Fiat-Shamir-bound verification but transmits the full witness `opening` alongside the hiding commitment, so **whoever runs `verify()` (D2, in this protocol) learns `rho` and the Merkle path/index** in addition to the `PK_KEM`/`PK_Dil`/`metadata` that M3/`CredResp` already discloses to D2 by the specification's own design regardless of the ZK layer. See extensive header docs in `rust-core/src/zk/mod.rs` and `docs/zk-membership.md` for the full accounting of what's real vs. simulated, and the swap-in path for a real backend. |

## Phase 4 — full authentication protocol M1–M8

**Status: COMPLETE.** 95/95 unit+integration tests passing (66 from Phases 1-3 + 29 new), re-run 5x with no flakiness.

| Component | Classification | Notes |
|---|---|---|
| KEM-then-AEAD secure envelope (`protocol::envelope`) | REAL, documented correction | Fixes the spec pseudocode's literal (impossible) `Enc_KEM(pk, payload)` calls — implements real `encapsulate -> HKDF -> AEAD.seal`, used consistently for M2, M3, M6, K1, and the group-key envelopes. |
| Canonical signed transcripts (`protocol::transcript`, `protocol::messages::*::signing_bytes`) | REAL | Every Dilithium-signed object builds its signing bytes via explicit length-prefixed field concatenation, never raw JSON. |
| PID→DroneID resolution (`protocol::entities`, pre-registered pseudonym pool) | REAL, documented resolution of an underspecified mechanism | GCS never learns `s_D`; pools of pre-derived PIDs are pushed to GCS at registration and consumed one per session. |
| C_PUF challenge delivery (`CredD1.crp_challenge`) | REAL, documented resolution | GCS includes the drone's registered CRP challenge in `CredResp`, resolving another spec ambiguity (how D2 learns which challenge to forward to D1). |
| M1–M8 message functions (`protocol::auth_flow`) | REAL | Each message is its own testable function; PUF-MAC (`mac1`), ZK proof, and Dilithium signature (`sig1`) are all independently computed and independently re-verified by the counterparty, matching the spec's message sequence exactly. |
| Freshness / nonce-replay checks | REAL | Timestamp skew window (5 min) checked on `ts1/ts4/ts5`; GCS tracks used N2 values at the M6 step and rejects replays. |
| Root/version live-consistency check | REAL, added distinct from ZK binding | GCS reports its *live* `(R_G,V_G)` back to D2 inside the (signed) `PUFVerifyResp`, letting D2 detect a concurrent membership mutation without needing the whole tree — distinct from (and in addition to) the ZK proof's own Fiat-Shamir version binding. |
| Zero Trust (minimal, Phase-4 version) | REAL, to be extended in Phase 6 | Deterministic ALLOW/DENY over the 5 upstream booleans with per-failure reason codes. |
| End-to-end + security/negative tests (`protocol::simulation::tests`) | REAL | Happy path; revoked-D1 (rejected at M3 by GCS); stale witness after another member joins (rejected at M7's ZK check, then succeeds after a witness refresh); tampered `sig1`; altered `mac1`; reused N2; unknown PID; cross-group rejection; move-then-authenticate; revoke-then-reactivate. |

## Phase 5 — K1–K4 group key + AEAD secure messaging

**Status: COMPLETE** (implemented alongside Phase 4 in this session; included in the 95-test count above).

| Component | Classification | Notes |
|---|---|---|
| K1 GroupKeyReq | REAL, documented correction | Spec's K1 payload literally contains D1's permanent `DroneID` inside a message *sent by D2* — directly contradicting the project's own anonymity requirement. Corrected to carry D1's session PID instead, resolved by GCS via the same pseudonym pool as M2. |
| K1 response / K2 KeyDelivery / group-key decapsulation | REAL | GCS generates a fresh random `K_G,M`, wraps it individually for D1 and D2 via KEM-then-AEAD envelopes; D2 forwards D1's envelope with a Dilithium signature; both sides decapsulate to the identical key (tested). |
| K3 AEAD key derivation | REAL | `K_AEAD = HKDF(K_G,M, domain \|\| N1\|\|N2\|\|N6\|\|N7)`. |
| K4 secure messaging (`protocol::secure_messaging`) | REAL | AEAD seal/open over the transport abstraction; sequence-number replay protection; AD-tampering detection tested. |
| Transport abstraction (`transport` module) | REAL interface, PLACEHOLDER/FUTURE backend | `TransportProvider` trait with a `PassthroughTransport` implementation. Steganography is explicitly out of scope for this version — no stub or fake implementation was written, only the clean interface boundary the brief requires. |
| GCS-knows-the-group-key trust assumption | Documented | Stated plainly in code comments and carried into `docs/threat-model.md` (Phase 10). |

## Phase 6 — Zero Trust (full) + Trace Manager + SQLite

**Status: COMPLETE.** 107/107 unit+integration tests passing (95 from Phases 1-5 + 12 new).

| Component | Classification | Notes |
|---|---|---|
| `PolicyEngine` trait + `DefaultPolicy` (`zero_trust`) | REAL | Replaceable policy engine (tested: a custom `AlwaysDeny` policy swaps in without touching call sites). Extended with `mission_active`/`device_health_ok` structural inputs and an operation allowlist, on top of the Phase-4 core checks. Deterministic and configurable — explicitly not an ML/learned model, and never described as one. |
| Trace Manager (`trace`) | REAL | `flag_session` (suspicion event creation) and `request_trace` (authorization-gated PID→DroneID resolution). Only `requester_role == "administrator"` gets a resolution; every attempt — authorized or not — is appended to the audit trail. Privacy model preserved: ordinary drones can never resolve a PID. |
| SQLite persistence (`storage`) | REAL | `rusqlite` with the `bundled` feature (compiles its own SQLite, no system dependency, identical behavior on Windows/Linux). JSON-blob-per-entity schema (documented trade-off vs. a fully normalized relational schema — chosen for correctness-per-effort in a research prototype). Two structurally separate tables: `gcs_state` (server-side authoritative state — public keys, metadata, CRP *reference* responses, Merkle state, PID pool) vs. `drones_local` (each simulated drone's own device-local state, including private keys and the simulated PUF golden pattern) — modeling the real distinction between "what GCS legitimately knows" and "what only lives on the device." Round-trip tested for both, plus the append-only event/trace logs and a full `reset_all`. |

## Phase 7 — Node.js API gateway + Rust HTTP core service

**Status: COMPLETE.**

| Component | Classification | Notes |
|---|---|---|
| Rust HTTP API (`iod-server` binary, `rust-core/src/api/`) | REAL | `tiny_http`-based JSON API (see dependency-rationale doc for why not axum/tokio). Every response is built from a hand-written `*View` DTO (`api::views`) — there is no code path from a `DroneState`/`GcsState` (which hold private keys, PUF state, etc.) to an HTTP response body that bypasses these DTOs. Live-tested end to end: create group/drones, register, authenticate (real ALLOW with all 5 sub-checks), establish group key, send an AEAD-encrypted secure message, revoke, confirm denial on re-authentication, inspect event log, flag/trace a session, and persistence surviving a full process restart. |
| Node.js/TypeScript gateway (`node-server/`) | REAL | Thin Express proxy in front of the Rust API (and the Python RAG service, see Phase 8) — Node holds no cryptographic or protocol logic itself, per the "Rust is the security-critical implementation" requirement, while remaining a genuine required layer of the architecture. Adds a `GET /api/events/stream` Server-Sent-Events endpoint (polls Rust's `/api/events` internally) so the browser-facing contract is real SSE regardless of the Rust side's polling-based internal implementation. Verified end to end via curl through the full Node→Rust chain. |
| **Bug found and fixed during manual end-to-end testing**: duplicate/misordered persisted events | Fixed, verified | `SimulationState::authenticate()` originally re-persisted the *entire* recent in-memory event log (last 20 events) to SQLite on every call, instead of just the newly-added M1-M8 events — this produced duplicate, reversed-order rows in the `protocol_events` table (though the live in-memory log shown during that same process's lifetime was always correct). Root-caused, fixed (persist only the slice of events added since the call started, in original order), rebuilt, and reverified live: a fresh run now produces exactly 18 events in correct chronological order with zero duplicates, confirmed both by direct SQLite inspection and via `GET /api/events/history`. |

## Phase 8 — Python RAG / mock LLM

**Status: COMPLETE.** 13/13 pytest tests passing.

| Component | Classification | Notes |
|---|---|---|
| `LLMProvider` interface + `MockLLMProvider` (`llm/`) | REAL (mock is genuinely deterministic, not a stub that just returns a constant) | No network calls, no API key. Template-based generation over the fused context. |
| `OllamaLLMProvider` | PLACEHOLDER/FUTURE | Raises `NotImplementedError` from `generate()`; exists solely as the documented extension point — implements the same interface so swapping providers requires no changes to `app.py`. |
| Retrieval (`rag/retrieval.py`) | SIMULATED, documented | Word-overlap (Jaccard) relevance scoring, explicitly NOT embeddings/vector search — labeled as such in the module docstring. |
| Validation / Byzantine-ish scoring (`rag/validation.py`) | SIMULATED, documented | Flags contributions whose content is a similarity outlier vs. the rest of the batch; downweights trust score accordingly. Explicitly documented as a simple heuristic demonstration, not a real BFT defense with characterized error rates — this is exactly the "do not pretend a simple deterministic heuristic is a sophisticated Byzantine defense" requirement. |
| Fusion (`rag/fusion.py`) | REAL | Deterministic trust-ordered concatenation with an exclusion floor. |
| Flask HTTP service (`app.py`) | REAL | `/rag/contribute`, `/rag/run`, `/rag/state`, `/rag/reset`. Verified live end to end (including through the Node gateway): three contributions submitted (two consistent, one adversarial/off-topic), `/rag/run` correctly flagged and excluded the off-topic one and synthesized an answer from the other two. |

## Phase 9 — React dashboard

**Status: COMPLETE.** Built (tsc + vite build, zero errors) AND functionally verified end-to-end with a real headless browser (Playwright/Chromium) driving the live Node+Rust+Python stack — not just visual inspection or curl-only checks.

| Component | Classification | Notes |
|---|---|---|
| Vite + React + TypeScript app (`web-ui/`) | REAL, functional (not a mockup) | Strict-mode TypeScript compiles clean; production build succeeds. All 9 required pages implemented and wired to live API calls: Dashboard, Drones, Groups, Authentication, Secure Communication, RAG, Trace Manager, Protocol Logs, Settings. |
| Live updates | REAL | `LogsPage` uses a genuine `EventSource` SSE connection to the Node gateway's `/api/events/stream`; other pages use short-interval polling for state that isn't itself the event stream (drones/groups/RAG state) — documented as an explicit, reasonable choice, not a silent gap. |
| Secret redaction | REAL, structural | The frontend only ever renders fields present in the Rust API's `*View` DTOs (see Phase 7) — fingerprints, hex roots, booleans, reason codes. Confirmed by direct inspection of every rendered page during Playwright verification: no private key, PUF secret, shared secret, or AEAD key appears anywhere in the DOM. |
| **End-to-end verification via headless browser** | REAL | Using Playwright (already available in this sandbox) against the live 4-service stack: loaded the app (zero console errors), created a group and two drones, registered both (confirmed witness-refresh made their cached roots match), ran a full D1→D2 authentication (real ALLOW, all 5 sub-checks OK, full M1–M8 sequence rendered), established a group key and sent+decrypted an AEAD secure message, revoked D1 and confirmed a subsequent authentication attempt was cleanly denied ("D1 is revoked"), watched the live SSE protocol timeline update in real time, ran the RAG contribution/validation/fusion/mock-LLM pipeline, and exercised the Trace Manager's flag/audit views. Screenshots retained in this session's working directory. |
| **Bug found and fixed during this Playwright verification**: "Reactivate" button was wrongly enabled for never-registered drones | Fixed | Root cause: the disabled condition only checked `d.active`, not `d.registered`. Changed to `disabled={busy \|\| d.active \|\| !d.registered}`, rebuilt, reverified visually. |

## Phase 10 — integration testing, benchmarks, docs, ECC audit, packaging

Status: IN PROGRESS (continuing this session)

Completed so far in this phase:
- **ECC audit**: COMPLETE, see `docs/ecc-audit.md`. Full `cargo tree`/`npm ls --all`/`pip list` inspection across all three language runtimes, plus a compiled-binary `strings` scan. Zero ECC-related crates/packages found anywhere.
- **Benchmarks**: COMPLETE and executed for real (`cargo run --release --bin iod-bench`) — measures PUF reconstruction, ML-KEM-768 keygen/encapsulate/decapsulate, ML-DSA-44 keygen/sign/verify, Poseidon hashing, Merkle registration/witness-generation/verification, ZK proof generation/verification, AEAD seal/open, full end-to-end authentication, and group-key establishment, reporting avg/p50/p95 over real measured trials (100-1000 depending on operation speed) plus concrete sizes (Kyber768 PK 1184B/ciphertext 1088B, Dilithium2 PK 1312B/signature 2420B, ZK proof ~540B JSON-serialized). **A real bug was caught and fixed while first running this**: a copy-paste group-ID mismatch between leaf construction and the ZK statement caused a `LeafMismatch` panic; fixed and reverified. Numbers are honestly captioned as sandbox-VM measurements, not embedded-hardware-representative.
- **Test vectors**: COMPLETE (`cargo run --bin iod-vectors`), with an explicit, verified honesty split: "Section A" (fixed literal byte inputs, Poseidon/hash-chain outputs) was confirmed byte-for-byte IDENTICAL across two separate runs (genuinely reproducible); "Section B" (a captured real run with actual generated PQ keys and real timestamps/nonces) is explicitly documented as non-reproducible byte-for-byte, with the reasons stated (no seeded keygen in the pqcrypto library; real RNG for nonces/blinding/PUF noise), while its verification *results* are the reproducible/meaningful part. No private key or PUF seed appears in the output.
- **Additional integration/security tests** (`rust-core/tests/`, compiled against the crate's public API only — a different testing modality from the in-module unit tests): `end_to_end.rs` implements the exact "GCS + D1 + D2 + group + registration + authentication + authorization + group-key + secure message + logging" combination the brief requires, plus a revoke-then-deny end-to-end test; `security_negative.rs` adds public-API-level coverage for stale timestamp, a substituted/forged public key, and a malformed envelope — filling the specific gaps not already covered by the ~100 in-module unit tests. **Total automated tests: 112 Rust (107 unit + 2 end-to-end + 3 security-negative) + 13 Python = 125, all passing.**

Remaining in this phase: full documentation set, cross-platform scripts, `.env.example`/config, final security review, dependency-rationale doc, and packaging into a ZIP.

### Final completion of Phase 10

- **Documentation set: COMPLETE.** All 18 required docs written with
  real, specific content (not filler), each cross-referencing the
  others rather than duplicating: `architecture.md`, `protocol.md`,
  `cryptography.md`, `zk-membership.md`, `puf.md`, `merkle-tree.md`,
  `zero-trust.md`, `rag.md`, `threat-model.md`,
  `security-assumptions.md`, `api.md`, `development.md`, `testing.md`,
  `benchmarking.md`, `troubleshooting.md`, `research-notes.md`,
  `dependency-rationale.md`, `ecc-audit.md`, `security-review.md`.
- **Cross-platform scripts: COMPLETE for Linux (tested live), written
  carefully but UNTESTED for Windows** (no Windows environment
  available in this sandbox). `scripts/linux/{setup,build,test,bench,
  vectors,run_demo,stop_demo,demo_scenario}.sh` were all actually
  executed in this session; `scripts/windows/*.ps1` mirror them
  structurally and were reviewed carefully but not executed.
  **A real bug was found and fixed while testing `run_demo.sh`**: the
  release build of `iod-server` itself had never been produced (only
  `iod-bench`/`iod-vectors` had been built in release mode earlier in
  the session), and separately, `nohup` alone (without `setsid`) did
  not survive process detachment in this sandbox — both fixed, and the
  full `demo_scenario.sh` walkthrough was then run successfully against
  live services, producing real ALLOW/DENY decisions, a real encrypted
  message round-trip, real RAG output, and a real revoke-then-deny
  sequence.
- **`.env.example` + `configs/README.md`: COMPLETE** for all four
  components.
- **Docker: provided, explicitly UNTESTED** (no Docker daemon available
  in this sandbox) — `Dockerfile` for each of the four components plus
  a root `docker-compose.yml`, clearly commented as best-effort.
- **Root `README.md`: COMPLETE** — ties together prerequisites,
  install/build/run for both platforms, the one-command demo, the
  scripted demonstration procedure, dashboard usage, test/benchmark
  commands, the REAL/SIMULATED/PLACEHOLDER table, and known limitations.
- **Final test re-verification**: 125/125 automated tests passing
  (112 Rust + 13 Python) in the final pre-packaging run.

**All 10 phases are now complete.** See the per-phase tables above for
the full REAL/SIMULATED/PLACEHOLDER breakdown and every bug found and
fixed along the way.

### Post-delivery review pass (after the ZIP was first packaged)

Since PowerShell scripts could not be executed in this Linux sandbox
(no `pwsh` available), they were re-reviewed line-by-line by hand
against actual PowerShell cmdlet semantics rather than left
"written but never doubted." This caught two real bugs that automated
testing could not have caught here:

1. **`run_demo.ps1` used a `-Environment` parameter on `Start-Process`
   that does not exist** in either Windows PowerShell 5.1 or PowerShell
   7+ — this would have thrown a parameter-binding error immediately on
   first run. Fixed by setting `$env:VARNAME` in the current session
   before each `Start-Process` call (the child process inherits the
   parent's environment block automatically), which is the actually
   correct mechanism.
2. **`demo_scenario.ps1` did not account for `Invoke-RestMethod`
   throwing a terminating exception on any 4xx/5xx HTTP response**
   (unlike `curl`, which just prints the body regardless of status
   code). Since step "m/n" (re-authenticating a revoked drone) is
   *supposed* to return an error response, the original script would
   have crashed at exactly that step and never reached the audit-log or
   Trace-Manager steps afterward. Fixed with a `try/catch` that extracts
   and prints the JSON error body via `$_.ErrorDetails.Message`,
   matching the Linux script's graceful continuation.

Also added during this pass, both genuinely missing before: a
`.gitignore` (so `target/`, `node_modules/`, `venv/`, `dist/`, and
runtime `.db`/log files are never accidentally committed if this
becomes a git repository) and a root `LICENSE` file (MIT, consistent
with every dependency's own permissive license per
`docs/dependency-rationale.md`).

**Honesty note on the PowerShell fixes**: these were caught by careful
manual re-reading against known PowerShell cmdlet behavior, not by
execution — there is still no substitute for actually running these
scripts on a real Windows machine, which remains a stated limitation
(see the root README's "Known limitations").

## Known limitations carried forward (do not silently drop these)

1. Deterministic `seed -> ML-KEM/ML-DSA keypair` regeneration is not
   bit-for-bit reproducible purely from the PUF seed with the chosen
   library (see Phase 1 table). The registration flow instead generates
   keys once and manages their association with a PUF-seed epoch; this
   is documented, not hidden.
2. CRP verification does not apply fuzzy-extractor-style noise
   correction (see Phase 1 table) — documented simplification.
3. Poseidon parameters are a research choice, not a security-audited
   production parameter set.
4. Revoked Merkle leaf slots are zeroed but their index is reserved for
   possible re-registration of the *same* drone ID only — a different
   drone can never reuse a revoked slot's index, avoiding identity
   confusion, at the cost of the tree "filling up" faster under heavy
   churn. Documented trade-off, acceptable for a research prototype.

## Phase 11 — Registration redesign: real 2D steganography, RAG-assisted selection, twelve protocol security fixes

**Status: COMPLETE.** 213/213 automated tests passing (132 Rust lib +
3 Rust integration + 3 Rust security-negative + 75 Python), zero
regressions from Phase 10's count. Live, cross-service verification
performed in addition to the automated suites (see `docs/testing.md`'s
"Live cross-service verification" section).

| Component | Classification | Notes |
|---|---|---|
| 2D steganography algorithms (Adaptive LSB, PVD, DCT, DWT, SVD) | REAL | `python-service/src/stego/`. Real embed/extract against real pixel arrays; real per-image capacity; no fabricated numbers. See `docs/steganography.md`. |
| Steganography benchmark engine | REAL | `stego/benchmark.py`: real timing, real MSE/PSNR/SSIM, a real round-trip correctness gate per candidate. See `docs/steganography.md`/`docs/data-and-evaluation.md`. |
| Registration-time algorithm selector | REAL decision logic over REAL measurements | `rag/selector.py`: deterministic, importance-weighted, feasibility-gated, alphabetical tie-break. See `docs/algorithm-selection.md`. |
| Registration-time RAG narrative/evidence | SIMULATED retrieval (word-overlap), REAL numbers quoted | `rag/stego_knowledge.py`: architecturally unable to fabricate a measurement, since it never computes one. See `docs/rag-stego-selection.md`. |
| R1-R3 over steganography (`registration_stego.rs`) | REAL | Explicit KEM-then-AEAD-sealed wire messages, embedded/extracted via a real HTTP round trip to `python-service`. Two documented, necessary field additions beyond the spec's literal list (`rho`, `pid_pool`); one new integrity check this split enabled (D1 locally re-verifies R3's witness, no longer blind trust). See `docs/registration-stego.md`. |
| `StegoClient` (`HttpStegoClient` real, `MockStegoClient` crypto-only test double) | REAL (Http) / explicitly-labeled test double (Mock) | `protocol/stego_client.rs`. `MockStegoClient` never claims to be a steganography implementation — it carries bytes through unchanged, used only to test crypto/framing. |
| Live HTTP registration-via-steganography endpoint | REAL | `POST /api/drones/:id/register-stego` (`api/state.rs`'s `register_drone_via_stego`, `api/server.rs`'s route), proxied by the Node gateway at the same path. Actually run end-to-end against all three backend services together, not just unit-tested — see `docs/testing.md`. |
| Dashboard Registration (Stego) page | REAL, functional (not a mockup) | `web-ui/src/components/command/registration-page.tsx`, route `/registration`, now primary navigation (replacing the former RAG-chatbot page there). Drives the live endpoint above; shows every candidate's real measurements, the selector's winner and narrative, and both stego image previews. |
| Original collaborative RAG pipeline + its dashboard page | SIMULATED (unchanged), still REAL as implemented | Unchanged, still fully tested, still reachable at `/rag` -- no longer load-bearing for registration. See `docs/rag.md`'s "Historical subsystem" section. |
| Spec section 25 protocol fixes (A-K) | REAL (11 fixes) + 1 already-honest re-confirmation | See `docs/claims-and-limitations.md` §7 for the complete table with mechanism and test name per item, and `docs/security-review.md`'s re-review section for how they interact with the original 18-point security review. Residual, out-of-list gap (K2's self-asserted key, same shape as 25-A) disclosed in §7a, not fixed, not hidden. |
| Two new sequence diagrams (full-technical, compact-presentation) | REAL | `docs/diagrams/iod_{full,compact}_sequence.{mmd,svg,png}`. Strict notation rules (RAG shown registration-local only, R2 as GCS-internal, Trace Manager only in exception blocks) enforced and visually verified. |
| `docs/claims-and-limitations.md` | REAL | New, mandated REAL/SIMULATED/RESEARCH PROTOTYPE/PLACEHOLDER-FUTURE classification table, a finer-grained legend than this file's three-way one, covering every component touched this phase. |

### Bugs found and fixed during this phase

1. **Port default mismatch** (`bin/register_stego_demo.rs` defaulted
   to `5055`; every other part of the project — `python-service`'s own
   `IOD_PYTHON_PORT` default, `node-server/src/config.ts` — uses
   `5001`). Caught while wiring the live HTTP endpoint and writing
   `docs/registration-stego.md`'s run instructions; fixed in the demo
   binary and in `docs/claims-and-limitations.md`'s re-verification
   command, which had the same stale port.
2. **Dashboard `tsc -b` failure on dead, pre-existing code**
   (`web-ui/src/services/api.ts`, unreachable from any live route):
   `exactOptionalPropertyTypes` rejected `fetch`'s optional `headers`/
   `body` being assigned `undefined`, and `import.meta.env.VITE_API_BASE`
   tripped the index-signature-access rule. Neither was caused by this
   phase's changes, but both blocked a clean `tsc -b`, so both were
   fixed (matching the pattern the live `lib/api.ts` already used)
   rather than left as a pre-existing failure for the next person to
   debug.
3. **`web-ui`/`node-server`/`python-service` dependencies were not
   installed** in this phase's working environment (`node_modules`,
   the Python `venv`, and the TanStack Start route-tree generation
   output did not yet exist). Re-ran the project's own setup sequence
   (`npm install` x2, `python3 -m venv` + `pip install -r
   requirements.txt`, `vite build` once to regenerate `routeTree.gen.ts`
   before `tsc -b` could type-check the new `/registration` route) --
   not a code bug, but worth recording since it is exactly the kind of
   step `docs/troubleshooting.md` should cover for the next person.

### Honesty note on this phase's RAG framing

The spec's own language ("RAG-assisted drone registration") is easy to
misread as "RAG decides." It does not. `rag/selector.py` decides, from
measurements it did not produce; `rag/stego_knowledge.py` explains,
from a decision it did not make. Every doc this phase touched
(`docs/algorithm-selection.md`, `docs/rag-stego-selection.md`,
`docs/claims-and-limitations.md`) states this explicitly rather than
letting "RAG-assisted" imply more than it is.
