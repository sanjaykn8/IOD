# Dependency Rationale

Licenses were read from the registries (MIT and/or Apache-2.0 for every Rust crate listed; MIT for the Node/Python packages used).

| Dependency | Purpose | ECC? |
|---|---|---|
| `pqcrypto-kyber 0.8.1`, `pqcrypto-dilithium 0.5.0`, `pqcrypto-traits` | Kyber768 / Dilithium2 (NIST Round 3 predecessors of ML-KEM-768 / ML-DSA-44), PQClean C sources. **Kept** because protocol and vectors use them; not byte-compatible with FIPS 203/204. TODO: migrate to `pqcrypto-mlkem/mldsa` (the new toolchain can build them). | no |
| `sha3`, `sha2`, `hmac`, `hkdf` | SHAKE256 transcripts/digests, HKDF/HMAC | no |
| `chacha20poly1305 0.10` | AEAD for envelopes and channel messages | no |
| `rand 0.8` / `rand 0.10` | OS CSPRNG (0.10 is required by Plonky3's hiding PCS RNG) | no |
| `serde`, `serde_json`, `postcard` | JSON API/DTOs; postcard serializes the STARK proof | no |
| `rusqlite 0.31 (bundled)` | SQLite persistence; bundled to avoid a system SQLite on Windows/Linux | no |
| `tiny_http 0.12` | simple synchronous HTTP server (no TLS, localhost demo) | no |
| `p3-*` `=0.9.0-rc.1` | transparent STARK/hiding-FRI proof system, Poseidon2, BabyBear, Keccak commitments (pinned exactly because it is a release candidate with an unstable API) | no |
| `hex`, `thiserror`, `anyhow` | utilities | no |

Toolchain: the project originally targeted rustc 1.75 and pinned several crates for it. Those pins were removed; v2 is built and tested with **rustc 1.97.0**. Plonky3 0.9.0-rc.1 needs a recent toolchain.

Node gateway: `express`, `cors`, `node-fetch` (no crypto). Web UI: React/Vite/Tailwind stack (no crypto). Python service: `flask`, `flask-cors`, `pytest` (RAG service unchanged in this phase).

Alternatives rejected for the proof system: arkworks/Groth16/Halo2/KZG-based (elliptic curves — policy), custom homemade "commitment + Fiat–Shamir" (not zero knowledge).

## Steganography integration additions
* Rust: none. Base64 and the minimal HTTP/1.1 client are hand-written (std `TcpStream`, timeouts, size caps) to avoid new crates and any TLS stack (ECC risk).
* Python: `numpy` (pixel arrays, DCT), `Pillow` (lossless PNG I/O). Flask bumped 3.0.3 → 3.1.3 for the per-request body limit. Optional `opencv-python-headless` (webcam), isolated in `requirements-camera.txt`.

Webcam update: no new dependencies. The browser path uses the standard `getUserMedia`/canvas APIs and the existing Pillow/numpy; `opencv-python-headless` stays optional for the server-side path.

Ten-algorithm update: no new dependencies (numpy only for STC, wavelet filters, SVD). PyWavelets is an optional test-time cross-check, not a requirement.
