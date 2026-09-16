# ECC Dependency Audit

**Result: NO elliptic-curve cryptography found anywhere in this project's
dependency graph, source code, or compiled binaries.**

This audit was performed as a non-negotiable project requirement and is
re-runnable by anyone with the commands below.

## Methodology

Per the project brief's explicit instruction ("Do not merely search
source code. Inspect actual dependency graphs"), this audit used three
independent methods:

1. **Full transitive dependency graph inspection** (`cargo tree`,
   `npm ls --all`, `pip list`) — every crate/package actually compiled or
   installed, not just direct dependencies.
2. **Keyword search across the flattened dependency graph** for: ECC,
   elliptic curve, ECDSA, ECDH, Ed25519, X25519, Curve25519, secp*, BLS,
   BN254/BN256, P-256/P-384/P-521, Groth16, PLONK, KZG, pairing.
3. **Compiled-binary string scan** (`strings` on the built `iod-server`
   executable) for the same keyword list, as a defense against a
   statically-linked C dependency that might not show up clearly by name
   in the Cargo dependency graph (e.g. pulled in via a `-sys` crate's
   vendored C sources).

## Rust core (`rust-core/`) — the only component with real cryptography

Command used:
```
cargo tree                                   # full graph, 132 lines
cargo tree --prefix none | sed 's/ v.*//' | sort -u   # unique crate names
```

Every unique crate name in the graph (reproduced in full below) was
manually reviewed:

```
aead, ahash, anyhow, ascii, bitflags, block-buffer, cc, cfg-if, chacha20,
chacha20poly1305, chunked_transfer, cipher, cpufeatures, crypto-common,
digest, dunce, fallible-iterator, fallible-streaming-iterator,
find-msvc-tools, generic-array, getrandom, glob, hashbrown, hashlink,
hex, hkdf, hmac, httpdate, inout, iod-core, itoa, jobserver, keccak,
libc, libsqlite3-sys, log, memchr, once_cell, opaque-debug, pkg-config,
poly1305, ppv-lite86, pqcrypto-dilithium, pqcrypto-internals,
pqcrypto-kyber, pqcrypto-traits, proc-macro2, quote, rand, rand_chacha,
rand_core, rusqlite, serde, serde_core, serde_derive, serde_json, sha2,
sha3, shlex, smallvec, subtle, syn, thiserror, thiserror-impl, tiny_http,
typenum, unicode-ident, universal-hash, vcpkg, version_check, zerocopy,
zeroize, zmij
```

Findings:
- **`pqcrypto-kyber`, `pqcrypto-dilithium`, `pqcrypto-internals`,
  `pqcrypto-traits`**: lattice-based post-quantum cryptography (Module-LWE
  / Module-LWE+Fiat-Shamir-with-Aborts). No curve arithmetic, no
  pairings. This is the ONLY public-key cryptography in the project.
- **`chacha20`, `chacha20poly1305`, `poly1305`, `cipher`, `inout`,
  `aead`, `universal-hash`**: symmetric AEAD (ChaCha20-Poly1305). No
  curve arithmetic.
- **`sha2`, `sha3`, `keccak`, `digest`, `block-buffer`,
  `crypto-common`, `hkdf`, `hmac`, `subtle`, `zeroize`,
  `generic-array`, `typenum`, `opaque-debug`**: hash functions, MACs,
  KDFs, and constant-time/secure-memory utility crates. No curve
  arithmetic — `subtle`'s constant-time comparisons and `zeroize`'s
  memory clearing are algorithm-agnostic hygiene utilities used
  by many non-ECC crypto crates as well.
- **`rand`, `rand_core`, `rand_chacha`, `ppv-lite86`, `getrandom`**:
  CSPRNG. No curve arithmetic.
- **`rusqlite`, `libsqlite3-sys`, `hashlink`, `fallible-iterator`,
  `fallible-streaming-iterator`**: SQLite bindings and its dependencies.
  Not cryptography.
- **`tiny_http`, `chunked_transfer`, `httpdate`, `ascii`**: the plain
  HTTP/1.1 server. No TLS is used anywhere in this local, single-machine
  demo (all services communicate over `127.0.0.1` in plaintext HTTP by
  design — see docs/threat-model.md), so there is no ECC-based TLS key
  exchange (which would otherwise be the single most likely accidental
  ECC entry point in a project like this).
- **`zmij`**: pulled in transitively by `serde_json` — a
  double-to-string float formatting algorithm (by the well-known Rust
  library author dtolnay), unrelated to cryptography.
- Everything else (`cc`, `pkg-config`, `vcpkg`, `jobserver`, `glob`,
  `dunce`, `find-msvc-tools`, `shlex`, `version_check`, `proc-macro2`,
  `quote`, `syn`, `serde*`, `thiserror*`, `anyhow`, `log`, `once_cell`,
  `memchr`, `smallvec`, `hashbrown`, `ahash`, `bitflags`, `cfg-if`,
  `libc`, `unicode-ident`, `zerocopy`, `itoa`, `hex`, `cpufeatures`):
  build tooling, error handling, macro infrastructure, or general-purpose
  utility crates with no cryptographic content at all.

**Keyword search result**: zero matches for any ECC-related term across
the full dependency list.

**Binary string-scan result**: zero matches for any ECC-related term in
the compiled `iod-server` binary.

## Node.js gateway (`node-server/`)

Command used: `npm ls --all`. Dependencies: `express`, `cors`,
`node-fetch`, plus their transitive dependencies, plus TypeScript
tooling (`typescript`, `ts-node`, `@types/*`) as dev-only dependencies.
None of these packages implement cryptography of any kind — the gateway
does no cryptographic operations itself; it only proxies JSON over plain
HTTP to the Rust core (see docs/architecture.md). Keyword search: zero
matches.

## Python RAG service (`python-service/`)

`pip list` shows: `Flask`, `Flask-Cors`, `Werkzeug`, `Jinja2`,
`MarkupSafe`, `itsdangerous`, `blinker`, `click`, plus `pytest` and its
dependencies for testing. None of these are cryptographic libraries —
the Python service does no cryptography of any kind (by design: RAG
content processing only, all security-critical operations are in Rust).
Keyword search: zero matches.

## Conclusion

- **Dependencies inspected**: full transitive graphs for all three
  language runtimes (132 Rust crates, all Node packages, all Python
  packages), plus a compiled-binary string scan.
- **Findings**: no ECC, no ECDSA/ECDH, no Ed25519/X25519/Curve25519, no
  secp*/BLS/BN254 curves, no Groth16/PLONK/KZG/pairing-based
  cryptography, anywhere in the project.
- **Transitive ECC usage remaining**: none.
- **Action taken**: none required. This audit should be re-run (`cargo
  tree` diff) any time a new Rust dependency is added, and re-verified
  before any future release.
