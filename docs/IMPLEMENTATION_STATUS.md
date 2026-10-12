# Implementation Status (protocol v2, post-quantum ZK + hardening phase)

Single source of truth for what is REAL, SIMULATED or PLACEHOLDER. Verified on 2026-10-12 with rustc 1.97.0 (Linux). Rollback point: git tag `baseline-upload` (v1 as uploaded); work branch `pq-zk-hardening`.

Legend: **REAL** genuine implementation · **SIMULATED** deliberate stand-in, documented · **PLACEHOLDER** interface only / not implemented.

## Phase 0 — audit
Baseline v1 built and tested before changes. Pre-existing defects found (all fixed in v2, see `security-review.md`): witness-revealing "ZK", 64-bit Poseidon, unsigned M4 key, unsigned M3/M6 failures, K1 with literal nonces/`[0u8;32]` and no session binding, reusable PIDs, role-string trace authorization. No regressions were introduced relative to baseline tests that still apply; v1-specific tests were replaced.

## Components
| Component | Status | Notes |
|---|---|---|
| Poseidon2/BabyBear hash, Digest, packing (`zkhash.rs`) | REAL | 248-bit digest; unit-tested; replaces Goldilocks Poseidon (deleted) |
| ZK membership proof (`zk/`) | **REAL (witness-hiding zk-STARK, hiding FRI)** | verifier gets only public inputs + proof; 128 b conjectured / 120 b proven (list) / 74 b (unique); Plonky3 0.9.0-rc.1 is a release candidate, not independently audited; privacy tested structurally only |
| Merkle trees (`merkle/`) | REAL | zero-digest sentinel for revoked leaves |
| Canonical encoding (`protocol/canon.rs`) | REAL | spec in `zk-specification.md` §2 |
| GCS ML-DSA trust anchor + signed credentials | REAL | `protocol/credentials.rs`; no ECC certificates |
| Enrollment R1–R3 | REAL protocol; CRP provisioning **SIMULATED** | PoP + PUF MAC + nonce; GCS table filled from the PUF simulator |
| M1–M8 | REAL | see `protocol.md`; all keys from credentials; M3/M6 results GCS-signed; M8 session-bound |
| K1–K4 | REAL | gated on a completed ALLOW session; GCS knows the key (documented) |
| PID lifecycle / replay protection | REAL | Active/Consumed/Expired; nonces persisted |
| Durable session record | REAL | `GcsState.sessions`, persisted; D1/D2 session objects are in memory only (K1 after a restart needs a new authentication) |
| PUF (`puf/`) | **SIMULATED** | golden pattern + noise; fuzzy extractor is a real code-offset construction over it; keys are NOT PUF-derived |
| ML-KEM-768 / ML-DSA-44 | REAL but **Round-3 Kyber768/Dilithium2** | not byte-compatible with FIPS 203/204; migration TODO |
| Zero Trust policy | REAL (simple rule engine) | authorization separate from authentication |
| Secure messaging (K4) | REAL | directional keys, AAD header, seq replay check; transport is a passthrough simulation |
| Trace Manager | REAL | admin token, reason, flagged-session rule, audit |
| Storage (SQLite JSON snapshots) | REAL | contains private keys and PUF pattern of the simulation (documented) |
| HTTP API / Node gateway / React UI | REAL; API shapes extended | trace needs `X-Admin-Token`; group-key/secure-message accept `session_id` (pair form still works); UI typechecks and builds; not manually clicked through in a browser |
| Benchmarks | REAL, host-simulation only | `benchmarking.md` |
| RAG service / steganography | **NOT TOUCHED** in this phase | out of scope; steganography is a PLACEHOLDER |

## Known limitations / TODO
GCS-known group key and `rho`; linkable sessions; ZK adds little to authenticity in the moderate model; CRP pool of 16 with no refill; Round-3 PQ crates; ~250 KB proofs and JSON wire inflation; no real network transport; no Windows run and no embedded hardware run; Python tests not re-run; `param_sweep` test not run; Poseidon2/Plonky3 cryptanalysis/audit status; trace flagging is unauthenticated.

## Verification
`cargo test --release` and `cargo test`: 115 unit + 16 integration + 1 e2e pass (details `zk-test-results.md`). Benchmarks: `benchmark-results-host-simulation.txt`. ECC audit: `ecc-audit.md`.

## Documents
`zk-specification.md`, `zk-design.md`, `zk-security-analysis.md`, `zk-implementation.md`, `zk-test-results.md`, `protocol.md`, `architecture.md`, `threat-model.md`, `security-assumptions.md`, `security-review.md`, `api.md`, `protocol-walkthrough.md`, `ecc-audit.md`, `dependency-rationale.md`, `benchmarking.md`, `testing.md`, `paper-evidence.md`.
