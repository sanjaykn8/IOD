# Dependency Rationale

All licenses below were queried directly from the crates.io/npm/PyPI
registries during this project's development (not assumed from memory).
Every dependency is permissively licensed (MIT and/or Apache-2.0 for
Rust; MIT for the Node/Python packages used), compatible with academic
and commercial use.

## Rust core (`rust-core/Cargo.toml`)

| Dependency | Purpose | License | Reason for selection | Security notes |
|---|---|---|---|---|
| `pqcrypto-kyber` 0.8.1 | ML-KEM-768 predecessor (Kyber768, NIST Round 3) | MIT OR Apache-2.0 | Audited PQClean-derived implementation; matches the spec's own "Kyber768" naming; builds on this sandbox's rustc 1.75 (the newer `pqcrypto-mlkem` does not — see "Pinned/substituted dependencies" below) | No ECC. Module-LWE hardness. |
| `pqcrypto-dilithium` 0.5.0 | ML-DSA-44 predecessor (Dilithium2, NIST Round 3) | MIT OR Apache-2.0 | Same rationale as above | No ECC. Module-LWE/SIS hardness. |
| `pqcrypto-traits` 0.3 | Shared traits for the above | MIT OR Apache-2.0 | Required by both pqcrypto crates | No ECC. |
| `sha3` 0.10 | SHAKE256, used for transcripts, PID derivation, Poseidon round constants | MIT OR Apache-2.0 | RustCrypto, widely used, standardized algorithm (FIPS 202) | No ECC. |
| `sha2` 0.10 | SHA-256, used inside HKDF/HMAC | MIT OR Apache-2.0 | RustCrypto | No ECC. |
| `hmac` 0.12 | HMAC-SHA256 for the PUF-MAC | MIT OR Apache-2.0 | RustCrypto, standard | No ECC. |
| `hkdf` 0.12 | HKDF-SHA256 for all domain-separated derivations | MIT OR Apache-2.0 | RustCrypto, standard (RFC 5869) | No ECC. |
| `chacha20poly1305` 0.10 | AEAD for secure messaging and KEM envelopes | Apache-2.0 OR MIT | RustCrypto, standardized (RFC 8439), fast in software without hardware AES support | No ECC. |
| `rand` / `rand_core` 0.8 | CSPRNG | MIT OR Apache-2.0 | Standard Rust ecosystem RNG | No ECC. |
| `serde` / `serde_json` 1 | Serialization for the JSON API and internal DTOs | MIT OR Apache-2.0 | De facto standard | Not cryptographic. |
| `rusqlite` 0.31 (feature `bundled`) | SQLite persistence | MIT | `bundled` compiles SQLite from source, avoiding a system SQLite dependency on either Windows or Linux | Not cryptographic. |
| `tiny_http` 0.12 | HTTP/1.1 server for the Rust API | MIT OR Apache-2.0 | Low MSRV, minimal dependency chain, builds on this sandbox's rustc 1.75 (unlike `axum`/`hyper`'s current release chains) | Plain HTTP only, no TLS — acceptable for this localhost-only demo (see `docs/threat-model.md`) |
| `hex` 0.4 | Hex encoding for fingerprints/IDs | MIT OR Apache-2.0 | Trivial utility | Not cryptographic. |
| `thiserror` / `anyhow` 1 | Error handling | MIT OR Apache-2.0 | Standard ergonomic error handling | Not cryptographic. |

### Pinned/substituted dependencies (and exactly why)

This sandbox's Rust toolchain is rustc 1.75.0 (Dec 2023) with no network
path to fetch a newer one. Several otherwise-current crate versions
require newer cargo/rustc, forcing the following:

| Crate | Pin | Reason |
|---|---|---|
| `zeroize` | `=1.7.0` | 1.9+ requires edition2024, unsupported by cargo 1.75 |
| `getrandom` | `=0.2.15` | 0.3/0.4 require a newer cargo/rustc |
| `jobserver` | `=0.1.32` | 0.1.35+ requires rustc ≥1.85 |
| `pqcrypto-kyber`/`pqcrypto-dilithium` | 0.8.1 / 0.5.0 (Round-3 API) instead of `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS 203/204) | The newer crates' build scripts use `cargo::` directives requiring cargo ≥1.77 |

None of this project's own code depends on the pinned versions
specifically — only on the stable trait/API surface those crates
expose, which is unchanged across the pinned and current versions. On a
machine with a newer Rust toolchain, these pins can be relaxed (see
`docs/troubleshooting.md`).

## Node.js gateway (`node-server/package.json`)

| Dependency | Purpose | License |
|---|---|---|
| `express` 4.19 | HTTP server/router | MIT |
| `cors` 2.8 | CORS headers for the browser-facing API | MIT |
| `node-fetch` 2.7 | HTTP client for proxying to Rust/Python | MIT |
| `typescript`, `ts-node`, `@types/*` (dev only) | Build tooling | Apache-2.0 / MIT |

No cryptography of any kind in this layer — see `docs/ecc-audit.md`.

## Python RAG service (`python-service/requirements.txt`)

| Dependency | Purpose | License |
|---|---|---|
| `flask` 3.0.3 | HTTP server | BSD-3-Clause |
| `flask-cors` 4.0.1 | CORS headers | MIT |
| `pytest` 8.2.0 (test only) | Test runner | MIT |

No cryptography of any kind in this layer — see `docs/ecc-audit.md`.

## React dashboard (`web-ui/package.json`)

| Dependency | Purpose | License |
|---|---|---|
| `react` / `react-dom` 18.3 | UI framework | MIT |
| `vite` 5.3 + `@vitejs/plugin-react` (dev) | Build tooling | MIT |
| `typescript` (dev) | Type checking | Apache-2.0 |

No cryptography of any kind in this layer.
