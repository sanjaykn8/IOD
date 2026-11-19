# Dependency Rationale

Licenses were read from the registries (MIT and/or Apache-2.0 for every Rust crate listed; MIT for the Node/Python packages used).

| Dependency | Purpose | ECC? |
|---|---|---|
| `ml-kem =0.3.4` (features `alloc, getrandom, zeroize`) | ML-KEM-768, FIPS 203 final. RustCrypto, pure Rust, MSRV 1.87, Apache-2.0/MIT. Chosen 2026-11-19: implements the final standard (not Round-3), seed-form keys, FIPS 203 §7.2 modulus check, constant-time selection for implicit rejection; passes the NIST ACVP ML-KEM-768 vectors in `tests/fips_kat.rs`; no open RustSec advisory. | no |
| `ml-dsa =0.1.2` (features `alloc, getrandom, zeroize`; `pkcs8` off) | ML-DSA-44, FIPS 204 final. RustCrypto, pure Rust, MSRV 1.87. Contains the fixes for CVE-2026-22705 (Decompose timing, fixed rc.3) and CVE-2026-24850 (duplicate hint indices, fixed rc.4); passes the NIST ACVP ML-DSA-44 keyGen/sigGen/sigVer vectors. | no |
| `getrandom 0.4` (`sys_rng`) | OS RNG with the `rand_core 0.10` interface used by the two crates (hedged signing `rnd`, seeds) | no |
| dev-only: `pqcrypto-mlkem =0.1.1`, `pqcrypto-mldsa =0.1.2`, `pqcrypto-traits`, `hybrid-array`, `rand_core 0.10` | Independent PQClean C implementations of the final standards, used only as an interoperability oracle in `tests/fips_interop.rs`. Flagged unmaintained (RUSTSEC-2026-0161/-0166, PQClean archived), which is why they are not runtime dependencies. | no |
| removed: `pqcrypto-kyber 0.8.1`, `pqcrypto-dilithium 0.5.0` | NIST Round-3 Kyber768 / Dilithium2 used until 2026-11-19 | — |

Selection record for the PQ crates: versions, API and MSRV were read from crates.io and the crate sources; the advisories checked were RUSTSEC-2025-0144 / CVE-2026-22705, CVE-2026-24850 (ml-dsa, both fixed in the pinned version), RUSTSEC-2026-0161/-0166 (PQClean bindings, unmaintained) and the libcrux advisories (other crates). Using FIPS-specified algorithms does not make this software FIPS 140-3 validated.
| `sha3`, `sha2`, `hmac`, `hkdf` | SHAKE256 transcripts/digests, HKDF/HMAC | no |
| `chacha20poly1305 0.10` | AEAD for envelopes and channel messages | no |
| `rand 0.8` / `rand 0.10` | OS CSPRNG (0.10 is required by Plonky3's hiding PCS RNG) | no |
| `serde`, `serde_json`, `postcard` | JSON API/DTOs; postcard serializes the STARK proof | no |
| `rusqlite 0.31 (bundled)` | SQLite persistence; bundled to avoid a system SQLite on Windows/Linux | no |
| `tiny_http 0.12` | simple synchronous HTTP server (no TLS, localhost demo) | no |
| `p3-*` `=0.9.0-rc.1` | transparent STARK/hiding-FRI proof system, Poseidon2, BabyBear, Keccak commitments (pinned exactly because it is a release candidate with an unstable API) | no |
| `hex`, `thiserror`, `anyhow` | utilities | no |

Toolchain: the project originally targeted rustc 1.75 and pinned several crates for it. Those pins were removed; v2 is built and tested with **rustc 1.97.0**. Plonky3 0.9.0-rc.1 needs a recent toolchain.

Node gateway: `express`, `cors`, `node-fetch` (no crypto). Web UI: React/Vite/Tailwind stack (no crypto). Python service: `flask`, `flask-cors`, `numpy`, `Pillow`, `pytest`. The patch-wise redesign added no dependency: segmentation, BM25 and the manifest codec are plain numpy/stdlib; no LLM, embedding or vector-store package is used.

Alternatives rejected for the proof system: arkworks/Groth16/Halo2/KZG-based (elliptic curves — policy), custom homemade "commitment + Fiat–Shamir" (not zero knowledge).

## Steganography integration additions
* Rust: none. Base64 and the minimal HTTP/1.1 client are hand-written (std `TcpStream`, timeouts, size caps) to avoid new crates and any TLS stack (ECC risk).
* Python: `numpy` (pixel arrays, DCT), `Pillow` (lossless PNG I/O). Flask bumped 3.0.3 → 3.1.3 for the per-request body limit.

Cover generator: no new dependency and one fewer. The procedural generator, its quality heuristics, the offline detectability evaluation (own logistic regression) and the generator benchmark use only NumPy and the standard library — no scikit-learn, no ML framework, no pretrained model, no download. The optional `opencv-python-headless` (`requirements-camera.txt`) was removed together with the camera path.

Ten-algorithm update: no new dependencies (numpy only for STC, wavelet filters, SVD). PyWavelets is an optional test-time cross-check, not a requirement.
