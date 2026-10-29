# ECC Dependency Audit (re-run for protocol v2)

**Result: no elliptic-curve cryptography found in the Rust dependency graph (all edge kinds: normal, build, dev), in the three built binaries, in the Node gateway/React UI lockfiles, or in the Python service requirements.** This audit was run on 2026-10-12 with rustc 1.97.0 / cargo 1.97.0.

## Method
1. `cargo tree -e all --prefix none` in `rust-core/` → **334 package entries (118 distinct crate names)**, saved and searched by name.
2. Keyword search on crate names: `elliptic, ecdsa, ecdh, ed25519, x25519, curve25519, secp, bls12, bn254/bn256, p256/p384/p521, groth16, kzg, pairing, dalek, k256, halo2, bulletproof, ristretto, ark-, ecc`. **0 matches.** (A naive `ecc`/`ark-` search matches `keccak` and `stark`; those are the Keccak hash and the STARK proof system, not ECC. The Keccak crates present are `keccak`, `tiny-keccak`, `p3-keccak`.)
3. `strings -a` on `iod-server`, `iod-bench`, `iod-vectors` with the same keywords (excluding the substring in `Keccak256`): the only hits are 34 occurrences of the hex fragment `8ecc1` inside Rust symbol-mangling hashes — false positives; no ECC identifier.
4. `npm ls --all` for `node-server` and `web-ui`, and `package-lock.json` grep (`elliptic, secp, ed25519, curve25519, tweetnacl, noble, jsonwebtoken`): **0 matches**. `python-service/requirements.txt` = `flask, flask-cors, pytest` only.
5. Source policy: no ECC/ECDSA/ECDH/X25519 code, no TLS (the HTTP server is plain `tiny_http`, localhost), no certificates other than GCS ML-DSA credentials.

Reproduce (Linux/macOS): `cd rust-core && cargo tree -e all --prefix none | sed 's/ (.*//' | sort -u | grep -iE 'elliptic|ecdsa|ecdh|ed25519|x25519|curve25519|secp|bls12|bn254|k256|dalek|halo2|pairing'` (expect no output). Windows PowerShell: `cargo tree -e all --prefix none | Select-String -Pattern 'elliptic|ecdsa|ecdh|ed25519|x25519|curve25519|secp|bls12|bn254|k256|dalek|halo2|pairing'`.

## Direct Rust dependencies
`pqcrypto-kyber 0.8.1`, `pqcrypto-dilithium 0.5.0`, `pqcrypto-traits`, `sha3`, `sha2`, `hmac`, `hkdf`, `chacha20poly1305 0.10`, `rand 0.8 / 0.10`, `rand_core`, `serde`, `serde_json`, `postcard`, `rusqlite 0.31 (bundled SQLite)`, `tiny_http`, `hex`, `thiserror`, `anyhow`, and Plonky3 `=0.9.0-rc.1`: `p3-air, p3-baby-bear, p3-challenger, p3-commit, p3-dft, p3-field, p3-fri, p3-keccak, p3-matrix, p3-merkle-tree, p3-poseidon2, p3-poseidon2-air, p3-symmetric, p3-uni-stark`.
Plonky3's only field arithmetic used here is BabyBear and its degree-5 extension (a prime-field/polynomial structure, not a curve group).

## Caveats
* Absence of ECC in the dependency names and binary strings is strong but not a formal proof about vendored C code; PQClean sources are Kyber/Dilithium only.
* Cryptographic assumptions in use: lattice (Module-LWE/SIS), hash collision/preimage (SHAKE256, SHA-256, Keccak-256, Poseidon2), ChaCha20-Poly1305 (symmetric).

## Addendum: steganography transport (2026-10-29)
* **No new Rust dependencies**: `Cargo.toml` and `Cargo.lock` are byte-identical to the pre-integration tree (HKDF/HMAC/SHA-256 were already direct dependencies; base64 and the HTTP client are hand-written on std).
* **No TLS added** on the Rust→Python hop on purpose: rustls/ring would introduce ECC code. The hop is loopback HTTP unless `IOD_STEGO_ALLOW_NONLOOPBACK=1`.
* **Python** (`python-service/requirements.txt`): `flask 3.1.3`, `flask-cors`, `numpy`, `Pillow` (+ `pytest`). Optional `requirements-camera.txt`: `opencv-python-headless` (camera only). The stego code uses no asymmetric crypto; the optional OpenCV wheel bundles third-party libraries that were **not audited** for EC content. Pillow/numpy likewise were not inspected at binary level; the claim is about our code and declared dependencies.
