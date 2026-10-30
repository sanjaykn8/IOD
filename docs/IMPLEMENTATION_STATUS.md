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
| Stego transport: AppWire v1, Frame v1 (HKDF-derived HMAC-SHA256 metadata MAC), bootstrap, receiver pipeline (Rust) | REAL | application messages only (after M1–M8/K1–K3, which are unchanged); tested with a fake backend and the real Python service |
| Stego image algorithms 1-5 (LSB replacement, LSB matching, PVD, edge-adaptive LSB, DCT) | REAL | Python; lossless PNG handoff only, none is robust to JPEG/resize; DCT refuses saturated covers (e.g. the B/W fallback) |
| DWT (`haar-l1-hh-qim-v1`), DCT-SVD (`dct8-svd-s1-qim-v1`) | REAL (documented variants) | one concrete variant each; not robust to JPEG (measured) |
| HUGO | REAL, **named variant** | exact single-change HUGO costs (T=90, σ=1, γ=1; σ/γ not re-verified against the full paper text) + additive approximation + binary STC; **no model correction** |
| WOW, S-UNIWARD | REAL | genuine db8 filter-bank cost maps (aggregation exactly aligned; MATLAB conv2 'same' would shift by one pixel) + binary STC h=7 |
| Binary STC (h=7) | REAL | Viterbi verified optimal vs brute force; deterministic, non-optimised submatrices (coding loss vs published tables not quantified); public element permutation (no stego key) |
| Algorithm Learning workbench (walkthroughs, isolated experiments, robustness suite, exports) | REAL, EDUCATIONAL | separate `/api/learn/*` namespace and `learn_experiments` table; test-only AEAD key from a public label; HUGO/WOW/S-UNIWARD walkthroughs are labelled teaching models |
| Stego selector `sel-policy-2` | REAL | ten candidates; deterministic, trial-encode based; cost term is a static model, measured timings are never ranked |
| Browser webcam cover (getUserMedia -> PNG upload `/api/stego/cover/upload`) | REAL | verified end to end with Chromium's synthetic camera; **not run on a physical webcam**; needs a secure context (localhost/127.0.0.1); Python re-validates and re-encodes the PNG |
| Server-side OpenCV webcam cover | REAL adapter, **UNVERIFIED on hardware** | optional dependency; warm-up frames, BGR->RGB, timeout and error mapping tested with a fake `cv2`; no-device path (CAMERA_ABSENT) and procedural fallback verified |
| RAG explanation of stego choice | SIMULATED | word-overlap retrieval over a curated KB + template narrative; explanation-only, cannot select/rank/veto; outage never blocks delivery |
| Stego events / reports / Steganography Lab UI | REAL | SQLite `stego_events`; CSV/JSON report, percentiles null when n<20; UI driven by Playwright, no physical-device test |
| Rust↔Python HTTP | REAL, plaintext loopback | hand-written std client; no TLS (would pull ECC crates); non-loopback needs `IOD_STEGO_ALLOW_NONLOOPBACK=1` |
| Legacy standalone stego tool | REAL, compatibility wrappers | `tools/stego-standalone/` |

## Known limitations / TODO
GCS-known group key and `rho`; linkable sessions; ZK adds little to authenticity in the moderate model; CRP pool of 16 with no refill; Round-3 PQ crates; ~250 KB proofs and JSON wire inflation; no real network transport; no Windows run and no embedded hardware run; Python tests not re-run; `param_sweep` test not run; Poseidon2/Plonky3 cryptanalysis/audit status; trace flagging is unauthenticated.

## Verification
`cargo test --release` (2026-10-30): lib 136 passed (2 ignored), protocol_integration 16, end_to_end 1, stego_pipeline 15, stego_e2e_python 6 (all ten algorithms through the real Python service), learn_workbench 4. Python `pytest`: 674 passed (incl. 68 new-algorithm tests and 18 workbench tests). Standalone `test_latent_image`: 4 OK (`test_text_vector` needs a blocked model download). Node `tsc`, web-ui `tsc` + `vite build` OK. `scripts/stego_smoke.py`: 38/38 via Node→Rust→Python. The new stego tests were run in release mode only. No Windows or Docker run, no physical webcam (browser path checked with Chromium's fake camera device). Stego details: `stego-transport.md`; benchmark: `benchmark-results-stego-*`. Benchmarks: `benchmark-results-host-simulation.txt`. ECC audit: `ecc-audit.md`.

## Documents
`stego-transport.md`, `stego-algorithms.md`, `learning-workbench.md`, `worked-examples.md`, `stego-implementation-note.md`, `zk-specification.md`, `zk-design.md`, `zk-security-analysis.md`, `zk-implementation.md`, `zk-test-results.md`, `protocol.md`, `architecture.md`, `threat-model.md`, `security-assumptions.md`, `security-review.md`, `api.md`, `protocol-walkthrough.md`, `ecc-audit.md`, `dependency-rationale.md`, `benchmarking.md`, `testing.md`, `paper-evidence.md`.
