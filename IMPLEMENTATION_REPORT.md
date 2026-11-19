# Implementation report — FIPS 203/204 suite, bootstrap-v3, risk-aware policy, UI redesign

Date: 2026-11-19. Base: payload-aware cover generation of 2026-11-15. Research prototype; M1–M8 and K1–K3 semantics
unchanged; the PUF stays a simulator; Raspberry Pi measurements and the RF/UAV link are deferred. Every number below
was measured in the development container (x86-64, 2 vCPU, rustc 1.97, Python 3.13, Node 22) unless marked otherwise.

## 1. Phase A — final ML-KEM-768 / ML-DSA-44

* Replaced the Round-3 Kyber768 / Dilithium2 PQClean bindings with RustCrypto **`ml-kem =0.3.4`** and **`ml-dsa =0.1.2`**
  (pure ML-DSA, hedged signing, FIPS 204 context string = suite id). `kem.rs`, `sign.rs`, `keys.rs` keep their interfaces;
  no home-grown crypto or serialization; private keys stored as FIPS seeds (64 B / 32 B), expanded sizes asserted
  (pk 1184 / 1312, sk 2400 / 2560, ct 1088, sig 2420, ss 32). No ECC in `cargo tree -e all`.
* Suite **`iod-fips203-mlkem768-fips204-mldsa44-v1`** signed into credentials (v3), enrolment and envelopes, required in
  device keys and snapshots, shown in API views (`crypto_suite`, `kem_pk_fingerprint`, `sig_pk_fingerprint`, fingerprints
  v2) and `GET /api/system/crypto`. Mixed suites are rejected; Round-3 rows are archived to `legacy_snapshots` at start-up
  and never reinterpreted.
* Conformance: NIST ACVP vectors (`tests/fips_kat.rs`: ML-KEM keyGen/encaps/decaps incl. implicit rejection, dk/ek
  checks; ML-DSA keyGen/sigGen/sigVer; provenance and SHA-256 recorded) and byte-level interop with PQClean ML-KEM /
  ML-DSA (dev-dependency only; those crates are unmaintained, RUSTSEC-2026-0161/-0166). **Not FIPS 140-3 validated.**
* Host benchmark (`docs/benchmark-results-host-simulation.txt`): ML-KEM keygen / encaps / decaps 0.086 / 0.087 / 0.195 ms;
  ML-DSA keygen / sign / verify 0.19 / 0.86 (p50 0.68) / 0.16 ms; M1–M8 124 ms (was 112), K1–K3 6.9 ms (was 2.2).

## 2. Phase B — bootstrap-v3 and the operational policy

* Design note `docs/bootstrap-v3-design.md`: Option A (deterministic receiver reconstruction) rejected (cross-platform
  float reproducibility, raw seeds would leave the generator, receive cost); **Option B** implemented: a compact, keyed,
  distributed carrier. Transport id **`frame-v3/appwire-v1/bootstrap-v3/manifest-v2`**.
* Rust derives, per frame, a placement key (HKDF over the directional key, channel, direction, sequence number), a
  SHAKE-256 value stream, a 64-bit sync word and a keystream; the carrier is `sync | E(header) | E(DEFLATE(manifest) |
  CRC32)`. Python receives only value streams and encrypted bits, maps them to pixels and writes ±1 LSB matching; no
  key, sync word or keystream leaves Rust. No row band is reserved; manifest-v2 carries canonical `carrier_pixels`.
* Discovery without circular dependency: candidates `[max(1, L−63), L+W]` (W = 64 default, ≤ 1024); exactly one sync
  match required (`BOOTSTRAP_NOT_FOUND`, `BOOTSTRAP_AMBIGUOUS`, `REPLAY` before any decryption); bounded inflate; strict
  manifest parse; frame manifest must equal the decoded one; AppWire sequence must equal the discovered one
  (`SEQUENCE_MISMATCH`); failures never advance the replay window. CRC is documented and tested as non-authenticating.
  Retired v2 images give `BOOTSTRAP_VERSION_UNSUPPORTED`.
* Operational policy `low_detectability` (default) / `all_algorithms`; DCT, DWT, DCT-SVD excluded by rule; the risk table
  `risk-table-1` (validation split only) put **LSB replacement** in the high tier (AUC 0.802) and **PVD in the medium tier
  (0.793), so PVD was not excluded** as originally planned. Enforced in the planner, re-checked in Rust
  (`POLICY_VIOLATION`); the allow list only restricts; no fallback. Selector **`kb-risk-1`**: filters → risk tier →
  changes per bit → ms per KiB → BM25 → id. In practice S-UNIWARD wins wherever eligible.

## 3. Detectability (offline, `docs/detectability-evaluation.md`)

Train 79 / test 60 generated covers, untouched test split, detectors `lr_basic`, `lr_srm` (basic + 156 SRM-lite
features), `trees_srm` (extremely randomised trees). Operational transport AUC (lr_srm / trees_srm): **0.670 / 0.664 at
256 B, 0.757 / 0.754 at 1024 B, 0.868 / 0.852 at 3072 B**; TPR at 1 % FPR ≤ 0.22. Carrier alone 0.646 / 0.656, patches
alone 0.639 / 0.654. The previous BM25-only selection measured 0.761 / 0.775 at 1024 B (no meaningful difference). With
the old basic features the transport now scores 0.556 at 256 B (bootstrap-v2 measured 0.986). **The AUC ≤ 0.55 aspiration
is not met; no undetectability is claimed. No CNN was trained** (no deep-learning framework available).

## 4. Phase C — UI redesign

`docs/ui-design-system.md` (60-30-10 colour, 8-point spacing, Inter + selective JetBrains Mono, sentence case, disclosures
for technical depth, role labels without aliases). New token stylesheet and shared primitives; grouped navigation
(Overview; Fleet; Protocols; Analysis; Audit; System); every page rewritten or restructured: Overview and Drones show the
actual suite and both fingerprints; Authentication shows Initiator → Verifier, a decision, a compact M1–M8 timeline and
the checks; Secure communication uses From → To; the Steganography lab keeps all functions with settings, generation
diagnostics, benchmark and scope notes in disclosures; the Knowledge base shows the risk table and policy; System shows
the suite, sizes, conformance, simulated PUF, policy and bootstrap from the backend. Stale content removed (Round-3 and
witness-revealing-ZK claims on the old settings page, fake status labels, the unused legacy SPA entry). Dark and light.

## 5. Verification (commands and results)

| Command | Result |
|---|---|
| `cd rust-core && cargo test --release` | lib 177 passed (2 ignored ZK parameter runs); fips_kat 7; fips_interop 5; crypto_suite_lifecycle 3; protocol_integration 16; end_to_end 1; stego_pipeline 23; stego_e2e_python 7; learn_workbench 4; doc tests: none exist |
| `cd python-service && python3 -m pytest -q` | 416 passed |
| `cd tools/stego-standalone && python3 -m unittest test_latent_image` | 4 OK |
| `cd node-server && npm run build` | OK |
| `cd web-ui && npx tsc --noEmit -p . && npx eslint src && npm run build` | OK; ESLint 0 errors, 21 warnings |
| `python3 scripts/stego_smoke.py` (stack running) | 83 checks passed |
| `bash scripts/linux/demo_scenario.sh` | completed, exit 0 |
| `node scripts/ui_check.js <dir>` | completed (both directions delivered, 8/8 stages, patch inspector, KB, learning) |
| `node scripts/ui_screenshots.js docs/screenshots/ui` | 56 screenshots (10 pages × 4 widths dark, 8 core pages × 2 widths light); no horizontal page overflow |
| `python3 scripts/eval_detectability.py --stage risk-table --val-seeds 20` / `--stage evaluate --train-seeds 20 --test-seeds 15` | ≈ 2 / 20 min; results above |
| Whole-stack benchmark (`docs/benchmark-results-patchwise.json`) | 70/70 delivered; default 320×240 transaction 717 ms mean (was 589; extraction 52 ms vs 17 because of three receive calls) |

Browser console errors in the UI runs were only blocked Google Fonts requests (offline container), the intentional
422 for an oversized message and the intentional `/rag` 404.

## 6. Limitations and what was not done

* Not run: Raspberry Pi 5 / ARM, Windows, Docker, debug-mode Rust tests, CNN steganalysis, human UI review.
* The transport is detectable by classical detectors (section 3); keyed placement hides only where the carrier is.
* Receiving takes three image-service calls; a receiver more than the sync window behind cannot locate frames; after
  a core restart a new K1–K3 run is needed.
* `ml-dsa 0.1.2` is young and not independently audited; libraries are not FIPS 140-3 validated modules.
* The risk table is a whole-image, single-algorithm proxy with small samples; LSB replacement and PVD are separated by
  a point-estimate threshold although their intervals overlap.
* Synthetic covers only; small evaluation samples; wide confidence intervals.

## 7. Files

New: `rust-core/src/crypto/suite.rs`, `rust-core/src/transport/{bootstrap,policy}.rs`, `rust-core/tests/{fips_kat,fips_interop,
crypto_suite_lifecycle}.rs`, `rust-core/tests/kat/*.json`, `python-service/src/stego/patch/policy.py`,
`python-service/src/stego/kb/risk_table.json`, `python-service/requirements-eval.txt`, `scripts/ui_screenshots.js`,
`docs/{bootstrap-v3-design,ui-design-system}.md`, `docs/screenshots/ui/`, `docs/samples/detectability-raw-scores.csv`.
Rewritten: `kem.rs`, `sign.rs`, `python-service/src/stego/{bootstrap,codec}.py`, `scripts/eval_detectability.py`,
`web-ui/src/styles.css` and the command components, `docs/detectability-evaluation.md`. Removed: `web-ui/src/{App,main}.tsx`,
`web-ui/src/pages/`, `web-ui/src/services/`, `web-ui/index.html`, `web-ui/src/index.css` (unused legacy SPA entry).
Updated documentation: cryptography, protocol, patchwise-transport, api, architecture, security-review, dependency-rationale,
IMPLEMENTATION_STATUS, testing, benchmarking, README and others listed in `docs/IMPLEMENTATION_STATUS.md`.
