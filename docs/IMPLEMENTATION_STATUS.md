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
| Patch-wise stego transport: AppWire v1, **Frame v2** (HKDF-derived HMAC-SHA256 over header, patch manifest and payload), patch manifest v1, bootstrap v2, bounded re-plan, receiver pipeline (Rust) | REAL | application messages only (after M1–M8/K1–K3, which are unchanged); tested with a fake backend and the real Python service; Frame v1 images are rejected (no interoperability) |
| Adaptive region-growing segmentation `arg-cells-1`, patch features, sequential chunk allocation (Python) | REAL | deterministic; regions are unions of 4/8/16-px cells; parameters and thresholds are local heuristics |
| Stego image algorithms 1-5 (LSB replacement, LSB matching, PVD, edge-adaptive LSB, DCT) on patch masks | REAL | Python; lossless PNG handoff only, none is robust to JPEG/resize; DCT is excluded on saturated patches |
| DWT (`haar-l1-hh-qim-v1`), DCT-SVD (`dct8-svd-s1-qim-v1`) on complete blocks inside a patch | REAL (documented variants) | one concrete variant each; not robust to JPEG (measured) |
| HUGO | REAL, **named variant** | exact single-change HUGO costs (T=90, σ=1, γ=1; σ/γ not re-verified against the full paper text) + additive approximation + binary STC; **no model correction** |
| WOW, S-UNIWARD | REAL | genuine db8 filter-bank cost maps (aggregation exactly aligned; MATLAB conv2 'same' would shift by one pixel) + binary STC h=7 |
| Binary STC (h=7) | REAL | Viterbi verified optimal vs brute force; deterministic, non-optimised submatrices (coding loss vs published tables not quantified); public element permutation (no stego key) |
| Algorithm Learning workbench (walkthroughs, isolated experiments, robustness suite, exports) | REAL, EDUCATIONAL | separate `/api/learn/*` namespace and `learn_experiments` table; test-only AEAD key from a public label; HUGO/WOW/S-UNIWARD walkthroughs are labelled teaching models |
| Per-patch selection `kb-bm25-1` over the static knowledge base `patch-kb-1` | REAL, deterministic lookup | structured hard filters → BM25 → top-1; hand-curated entries; evidence notes separate published / implementation / local heuristic; reference DOIs not machine-verified; **no LLM, no learned model** |
| Payload-aware procedural cover generator `procgen-1` (four families, OS-CSPRNG seed, fresh cover per transmission) | REAL | NumPy only; no pretrained model, no network; covers are synthetic images, not photographs; raw seed never stored (fingerprint only) |
| Cover quality pre-screen `cover-quality-1` | REAL, HEURISTIC | documented gates + weighted score calibrated on this generator and on pathological fixtures; **not** a steganalysis detector |
| Resource profile `raspberry_pi_5_cpu` | REAL limits, **SIMULATED target** | sizes, candidate count, time and memory limits are enforced on the host in Rust and Python; device speed is not emulated; **no measurement on a Raspberry Pi 5 exists** (host figures are labelled profile-constrained host benchmarks) |
| Memory limit of the generator | REAL pre-flight estimate | `8 MB + 220 B/pixel` (constant measured with tracemalloc on the host); not an OS-enforced limit |
| Offline detectability evaluation (`scripts/eval_detectability.py`) | REAL measurement, weak detector | hand-made features + own logistic regression on synthetic covers; results are not a security claim and no undetectability is claimed |
| Camera / upload / client-selected cover paths | REMOVED | routes return 404, old request fields 400; OpenCV adapter and browser capture deleted. The educational workbench keeps its own, isolated PNG upload |
| Stego events / reports (`stego-report-3`) / Steganography Lab + Knowledge Base monitor UI | REAL | SQLite `stego_events` with per-patch records; CSV/JSON report, percentiles null when n<20; UI driven by Playwright, no physical-device test |
| Rust↔Python HTTP | REAL, plaintext loopback | hand-written std client; no TLS (would pull ECC crates); non-loopback needs `IOD_STEGO_ALLOW_NONLOOPBACK=1` |
| Legacy standalone stego tool | REAL, compatibility wrappers | `tools/stego-standalone/` |

## Known limitations / TODO
GCS-known group key and `rho`; linkable sessions; ZK adds little to authenticity in the moderate model; CRP pool of 16 with no refill; Round-3 PQ crates; ~250 KB proofs and JSON wire inflation; no real network transport; no Windows run and no embedded hardware run; Python tests not re-run; `param_sweep` test not run; Poseidon2/Plonky3 cryptanalysis/audit status; trace flagging is unauthenticated.

## Verification
2026-11-13, development container: `cargo test --release` lib 141 passed (2 ignored), protocol_integration 16, end_to_end 1, stego_pipeline 19, stego_e2e_python 6 (real Python service), learn_workbench 4. Python `pytest`: 318 passed. Standalone `test_latent_image`: 4 OK (`test_text_vector` needs a blocked model download). Node build, web-ui `tsc` + production build OK. `scripts/stego_smoke.py`: 58 checks passed. Details and what was not run: `testing.md`, `../IMPLEMENTATION_REPORT.md`.

## Documents
`patchwise-transport.md`, `stego-algorithms.md`, `learning-workbench.md`, `worked-examples.md`, `zk-specification.md`, `zk-design.md`, `zk-security-analysis.md`, `zk-implementation.md`, `zk-test-results.md`, `protocol.md`, `architecture.md`, `threat-model.md`, `security-assumptions.md`, `security-review.md`, `api.md`, `protocol-walkthrough.md`, `ecc-audit.md`, `dependency-rationale.md`, `benchmarking.md`, `testing.md`, `paper-evidence.md`.
