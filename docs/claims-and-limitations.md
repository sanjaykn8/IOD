# Claims and Limitations

This file is the **single mandated classification table** for the whole
system after the Stage-5 architectural pivot (steganographic
registration transport + RAG-assisted algorithm selection + the
section-25 protocol security fixes). Where `docs/IMPLEMENTATION_STATUS.md`
tells the phase-by-phase *history* of how each piece was built, this file
is the current, flat *answer* to one question per component: **what is
this, really?**

Every component in the repository is classified into exactly one of:

- **REAL** — a genuine implementation using real algorithms/libraries
  against real inputs. Not a stub, not a simulation of the underlying
  phenomenon.
- **SIMULATED** — a deliberately simplified, but mathematically
  meaningful, stand-in for something that would require production-grade
  infrastructure (real silicon, a security-audited parameter set, a
  production BFT network) that is not realistically buildable inside
  this research prototype. The simplification is documented, not hidden.
- **RESEARCH PROTOTYPE** — real, runnable code implementing a genuine
  technique, but at a level of rigor (parameter selection, adversarial
  testing, formal analysis) below what a production or peer-reviewed
  deployment would require. Distinct from SIMULATED: nothing here is
  standing in for something else — it *is* the thing, just not yet
  hardened.
- **PLACEHOLDER/FUTURE** — an interface or extension point exists; the
  real implementation behind it is deliberately deferred and never
  silently assumed to work.

No claim below is softened on a re-read. If a row looks weak, that is the
row being honest, not a bug in this document.

## 1. Cryptographic primitives (unchanged by the Stage-5 pivot)

| Component | Classification | Notes |
|---|---|---|
| Goldilocks field (`crypto::field`) | REAL | No ECC group ever formed. |
| Poseidon hash (`crypto::poseidon`) | RESEARCH PROTOTYPE | Real from-scratch permutation; round constants/MDS are a documented, reasonable choice, **not** run through production parameter-selection tooling or independently audited. |
| Canonical byte→field encoding (`crypto::canonical`) | REAL | 7-byte (56-bit) little-endian chunking, fixed below the field modulus by construction — see the injectivity fix and its two dedicated regression tests (`chunking_never_reaches_the_field_modulus_so_no_reduction_can_occur`, `many_random_byte_strings_round_trip_without_collision`). |
| ML-KEM-768/Kyber768, ML-DSA-44/Dilithium2 | REAL | PQClean-backed via `pqcrypto-kyber`/`pqcrypto-dilithium` (NIST Round-3 names; see `docs/cryptography.md` for the FIPS 203/204 standards mapping). Seeded/deterministic keygen is not exposed by the library — documented, not hidden. |
| AEAD (ChaCha20-Poly1305), KDF/HMAC/SHAKE256 | REAL | Unchanged from prior phases. |
| **No ECC anywhere** | REAL, verified | See `docs/ecc-audit.md` — `cargo tree`/`npm ls --all`/`pip list` plus a compiled-binary `strings` scan, zero ECC crates/packages found. Re-run after the Stage-5 dependency additions (`ureq`, `base64`, `scipy`, `PyWavelets`, `scikit-image`, `Pillow`) with the same zero result (see §8). |

## 2. PUF / fuzzy extractor (unchanged, now also feeds the leaf — see §4)

| Component | Classification | Notes |
|---|---|---|
| SRAM-PUF simulation (`puf::sram_puf`) | SIMULATED | No real silicon available; per-device golden pattern + per-bit noise. |
| Fuzzy extractor (`puf::fuzzy_extractor`) | REAL construction, SIMULATED code choice | Real code-offset construction; a repetition code stands in for a production BCH/Reed-Solomon code. Reliability bound computed and tested, not asserted. |
| CRP-based PUF verification (`puf::crp`) | SIMULATED | Deterministic (noise-free) challenge-response; documented future extension to apply fuzzy extraction here too. |

## 3. Zero-knowledge membership proof (unchanged)

| Component | Classification | Notes |
|---|---|---|
| `ZkStatement`/`ZkWitness`/`ZkProof` (`zk::*`) | REAL interface | Swappable backend trait shape. |
| Algebraic relation checking, V_G/session binding | REAL | Genuinely recomputed on both sides; tested against stale version, wrong root, wrong group, wrong commitment. |
| **Zero-knowledge hiding of the witness** | **NOT ACHIEVED — SIMULATED, precisely documented** | The backend transmits the full witness `opening` alongside the hiding commitment. D2 (who runs `verify()`) learns `rho` and the Merkle path/index, in addition to the `PK_KEM`/`PK_Dil`/metadata the specification's own M3 already discloses to D2 regardless of this layer. This is the single largest research-grade gap in the project (spec item K); see `rust-core/src/zk/mod.rs` and `docs/zk-membership.md`. **No code change was made or needed for item K in the Stage-5 security pass** — the honest disclosure already fully describes the gap; nothing in this pass added a false hiding claim to paper over it. |

## 4. Registration (R1–R3) — redesigned this stage

| Component | Classification | Notes |
|---|---|---|
| `protocol::registration` (direct, non-stego path) | REAL | Preserved unchanged — still used by every test/benchmark that doesn't need steganographic transport. |
| `protocol::registration_stego` (R1–R3 over steganography) | REAL | Same cryptographic primitives (KEM-then-AEAD `envelope::seal_for_recipient`/`open_as_recipient`) as M2/M3/K1, reused rather than reinvented. Full real cross-language round trip verified live (`iod-register-stego-demo`, see §6). |
| Leaf randomness `rho` ↔ PUF binding (spec 25-C) | REAL | `identity::leaf::derive_puf_bound_rho` makes `rho` an HKDF output keyed on the PUF-reconstructed seed (with a fresh salt for per-registration freshness) instead of independent randomness with zero tie to the physical device. Since `rho` feeds the same Poseidon leaf as `pk_kem`/`pk_dil`, one hash now provably ties together the PUF, the credential, Merkle membership, and the ML-DSA key — with **no change** to the leaf's arity/formula, so `L = Poseidon(PK_KEM, PK_Dil, G, metadata, rho)` stays accurate everywhere it's documented/diagrammed. Tested: freshness across repeated calls with the same seed, and seed-dependence. |
| R3 witness integrity (`d1_apply_enrollment_response`) | REAL | D1 calls `merkle::tree::verify_witness` on the witness GCS returns before accepting it — a genuine new check (the fused `register_drone` path never had this, even implicitly). Tested: `tampered_r3_witness_is_rejected_by_d1`. |
| `rho`/`pid_pool` additions to `EnrollmentRequest` | REAL, documented correction | Necessary data the spec's literal field list omits but the message cannot function without; documented inline per the project's "documented correction" convention. |

## 5. 2D steganography algorithms (`python-service/src/stego/`) — new this stage

| Component | Classification | Notes |
|---|---|---|
| Adaptive LSB | REAL | 3×3 local-variance bucketing on masked-luma (top 5 bits only, so encode/decode recompute identically — no circular dependency). |
| PVD (Wu–Tsai 2003) | REAL | Six-range table; embed clamps the pixel-pair split to the exact feasible interval, so boundary pixels (0/255) never force a spurious capacity failure. |
| DCT (8×8 block QIM) | REAL | `scipy.fft.dctn/idctn`, 8 fixed mid-frequency coefficients, self-verifying embed (see next row). |
| DWT (Haar, HH-subband QIM) | REAL | `pywt.dwt2/idwt2`, single level. |
| SVD (8×8 block, single-singular-value QIM) | REAL, with a documented fix | Reduced from an initially-attempted 2-bit/block (`S[1]`+`S[2]`) scheme after discovering a genuine order-swap corruption mode (see §7, bug log) to 1 bit/block with a full-step margin; swept and chosen `Q=10.0`. |
| Self-verifying embed (DCT/DWT/SVD) | REAL | Each `embed()` calls its own `extract()` and raises `StegoCapacityError` on any mismatch — **fail closed, never silently corrupt**, by construction, not by convention. |
| Benchmark engine (`stego.benchmark`) | REAL | Measures real embed/extract time, capacity, PSNR, SSIM on the actual current image+payload. Architecturally cannot fabricate a number — it only reports what it just measured. |

## 6. RAG-assisted algorithm selection — redesigned this stage

RAG's role changed from an independent "collaborative drone contribution"
chatbot subsystem (described, now historically, in the old
`docs/rag.md` content folded into §9 below) into a **registration-time
evidence-retrieval system** feeding a **deterministic, measurement-based
selector**. See `docs/rag-stego-selection.md` and `docs/algorithm-selection.md`
for the full design writeup; this table is the classification summary.

| Component | Classification | Notes |
|---|---|---|
| `rag.selector.select_algorithm` | REAL | Deterministic: feasibility gate (`capacity >= payload_size`) + importance-weighted scoring over real measurements only. Never touches an image or invents a number. Alphabetical tie-break for full reproducibility. Tested: determinism, per-importance-profile behavior, infeasible exclusion, tie-break. |
| `rag.stego_knowledge.retrieve_evidence` | SIMULATED retrieval, REAL narrative generation | Lexical (Jaccard) retrieval over the literature `.md` files in `python-service/knowledge/steganography/` — same honestly-labeled technique as the old RAG subsystem's retrieval step, explicitly not embeddings/vector search. |
| `rag.stego_knowledge.explain_selection` | REAL, constrained by construction | Only ever quotes fields out of the measurement dict it is handed — it has no code path that can emit a number it did not receive as input. This is the concrete mechanism behind "RAG must never invent performance numbers." |
| Knowledge base citations (`knowledge/steganography/`) | REAL | Real literature citations (Chan & Cheng 2004, Fridrich et al. 2001, Wu & Tsai 2003, Westfeld 2001 F5, Chen & Lin 2006, Bergman & Davidson 2005, Liu & Tan 2002, Johnson & Jajodia 1998), qualitative trade-off notes only — no literature-derived numbers are ever used as a stand-in for a real measurement. |
| Cross-language bridge (`protocol::stego_client::HttpStegoClient`) | REAL | Real `ureq`-based HTTP calls to the live Python service's `/stego/select-and-embed`/`/stego/extract` endpoints. |
| `MockStegoClient` | Explicitly NOT a steganography implementation | Pure-Rust passthrough test double used only by `registration_stego`'s crypto/framing unit tests, so those tests don't need a live Python process or an image codec. Never used to claim embed/extract correctness — that's §5's real-algorithm test suite and the live cross-language demo (§... below). |

## 7. Protocol security fixes — spec section 25

All twelve items are now addressed. Each row names the concrete,
tested mechanism — not just "fixed."

| Item | Classification | Mechanism |
|---|---|---|
| 25-A: trusted binding for D2's keys in M4 | REAL fix | GCS issues a `SignedPeerCert` (D2's own registered `pk_kem`/`pk_dil`, GCS-signed) piggybacked on M3; D2 forwards it unchanged in M4's `ChallengeMsg`; D1 verifies the GCS signature before trusting the key that checks `sig4`. Previously `pk_dil_d2` was bare and self-asserted. Tested: `spec_25a_a_self_asserted_d2_key_not_certified_by_gcs_is_rejected_at_m4`. |
| 25-B: M3/M5 consistency + comm_PK_D1 recomputation | REAL fix | New `credential_consistency_ok` check in `m7_verify_and_decide`: (1) recomputes `comm_pk_d1` from the SAME bundle's `pk_kem_d1`/`pk_dil_d1` and compares to the claimed `comm_pk_d1`; (2) checks those same keys against M3's `cred_d1`. Both independent of, and checked before, the ZK/signature booleans. Tested with a forged-but-self-consistent bundle that passes the OLD checks and is caught only by the new one: `spec_25b_forged_signing_key_with_untouched_comm_pk_is_caught_by_credential_consistency_not_by_zk_or_sig`. |
| 25-C: explicit PUF↔credential↔Merkle-member↔ML-DSA-key binding | REAL fix | See §4's `derive_puf_bound_rho` row. |
| 25-D: K1 bound to a genuinely-authenticated session | REAL fix (prior session) | `AuthSessionRecord` gates `establish_group_key` on a prior `Allow` for the exact pair. |
| 25-E: real session nonces in the K3 AEAD derivation | REAL fix (prior session) | Replaced hardcoded placeholder nonces with the real M1/M2/K1 nonces. |
| 25-F: PID lifecycle states ACTIVE/CONSUMED/EXPIRED | REAL fix | `GcsState::{pid_state, consume_pid, expire_pid}` plus `PidState`/`PidLifecycleError`. M2 (`gcs_receive_m2`) now consumes a pid1 (Active→Consumed) and rejects a replay of an already-consumed pid1 starting a second session; `resolve_pid` still serves legitimate same-session re-lookups (M6/K1/trace) for Active/Consumed, only Expired/unknown is refused everywhere. Tested: 9 unit tests in `entities::pid_lifecycle_tests` plus the protocol-level `spec_25f_replaying_an_already_consumed_pid1_to_start_a_second_session_is_rejected`. |
| 25-G: self-contained M8 verification | REAL fix | `AuthResultMsg` now carries the same GCS-issued `SignedPeerCert` (reused from M3) instead of an empty `pk_dil_d2` field the caller was expected to fill in by reaching into the other party's in-memory state. D1 verifies M8 using only the message plus `gcs.sign_pk`. Tested: `spec_25g_m8_is_verifiable_from_the_message_alone_and_rejects_an_uncertified_key`. |
| 25-H: no permanent DroneID on the secure-messaging wire | REAL fix (prior session) | `session_message_tags` derives two opaque SHAKE256 tags from the session AEAD key, replacing literal `drone_id` bytes in `SecureAppMessage.src_pid`/`dst_pid`. |
| 25-I: K1 rejects an unauthenticated pair | REAL fix (prior session), same mechanism as 25-D | |
| 25-J: canonical byte-to-field encoding injectivity | REAL fix (prior session) | 7-byte chunking, see §1. |
| 25-K: ZK hiding status honestly documented | Already satisfied, re-confirmed this pass | See §3. No code change was required or made. |

### 7a. Known residual gap of the same shape as 25-A, not in the item list

`protocol::group_key::KeyDeliveryMsg` (K2) still carries a bare,
self-asserted `pk_dil_d2: Vec<u8>` — the exact same trust-anchoring gap
25-A fixed for M4's `ChallengeMsg` and 25-G fixed for M8's
`AuthResultMsg`, but K2 was not named in the spec's item list and was
**not** fixed in this pass, to keep this stage's scope to the items
actually enumerated. The fix, when done, is mechanical: reuse the same
`SignedPeerCert` D2 already received at M3 (it's already threaded
through M4 and M8 for exactly this purpose) in place of K2's raw field.
Flagged here rather than silently left for someone to discover later.

## 8. Dependency / supply-chain honesty (re-verified this stage)

New dependencies added for the Stage-5 pivot: Rust `ureq`, `base64`;
Python `numpy`, `scipy`, `Pillow`, `scikit-image`, `PyWavelets`. All are
general-purpose numerics/imaging/HTTP libraries with no cryptographic or
ECC surface. The ECC audit's method (full dependency-tree enumeration +
binary `strings` scan) applies unchanged to the expanded dependency set;
see `docs/ecc-audit.md` for the methodology and re-run instructions.

## 9. Superseded component (kept, re-scoped, not deleted)

The original "collaborative drone-contribution RAG" subsystem
(`python-service/src/rag/{retrieval,validation,fusion}.py`,
`llm/mock_provider.py`, the old `/rag/contribute`/`/rag/run` endpoints,
and the dashboard's old RAG chatbot page) is **not removed from the
repository** — the code still runs and its own 13 pytest tests still
pass — but it is no longer the registration-time decision path and the
dashboard no longer presents it as the primary RAG experience (see
`docs/rag.md`'s "Historical subsystem" section and §... of this
document's UI notes). This is a deliberate choice: the project's own
ground rules say not to delete working, tested code unnecessarily. It is
reachable but no longer load-bearing for registration.

## 10. UI / web dashboard

| Component | Classification | Notes |
|---|---|---|
| Registration/Stego-Selection flow page | REAL, functional | Replaces the old RAG-chatbot page as the primary RAG-facing surface; wired to the live `/stego/select-and-embed` and `/stego/algorithms` endpoints through the Node gateway. See `docs/architecture.md`'s UI section. |
| Existing Dashboard/Drones/Groups/Authentication/Secure-Communication/Trace/Logs/Settings pages | REAL, unchanged | Carried over from the prior stage without modification; still live-wired. |

## How to re-verify any row in this table

- Crypto/protocol/registration/stego-client unit + integration tests:
  `cd rust-core && cargo test` (see `docs/testing.md` for the current
  total and the full regression list).
- Steganography algorithms, selector, benchmark, RAG knowledge, Flask
  API: `cd python-service && pytest`.
- Live cross-language registration demo (exercises §4, §5, §6 together
  against a real running Python service):
  `cd python-service && flask --app src/app.py run --port 5001 &`
  then `cd rust-core && cargo run --release --bin iod-register-stego-demo`
  (also now live via the dashboard's Registration (Stego) page -- see
  `docs/registration-stego.md`).
- ECC audit re-run: see `docs/ecc-audit.md`.
