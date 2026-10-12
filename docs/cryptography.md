# Cryptography

No claim in this document should be read as "mathematically proven
secure" or "quantum secure" without the specific qualification attached
to it. Distinctions used throughout: **REAL** (genuine implementation of
a real algorithm/library), **SIMULATED** (a documented, necessary
simplification), **research-parameterized** (a real construction with
parameters chosen for auditability/clarity rather than run through
production parameter-selection tooling).

## Key Encapsulation: Kyber768 → ML-KEM-768

- **What's implemented**: `pqcrypto-kyber` 0.8.1, wrapping the audited
  PQClean C reference implementation of Kyber768 (NIST Round 3).
- **Standards mapping**: Kyber768 (Round 3) is the direct algorithmic
  predecessor of ML-KEM-768 (FIPS 203, finalized August 2024). The
  differences are small but real: FIPS 203 made minor changes to the
  encoding of intermediate values in the FO transform relative to the
  Round-3 submission. This project uses Round-3 Kyber768, not
  final-FIPS-203 ML-KEM-768.
- **Why not the newer `pqcrypto-mlkem` crate (which implements FIPS 203
  directly)**: its build script requires cargo ≥1.77; this sandbox has
  1.75.0 with no path to a newer toolchain (see
  `docs/dependency-rationale.md`).
- **Security basis**: Module-LWE (Module Learning With Errors) hardness.
  Believed post-quantum secure (no known efficient quantum algorithm)
  at the time of writing; this is a computational hardness assumption,
  not a proof.
- **Used as a KEM, not textbook encryption**: see `docs/protocol.md`
  correction #1.
- **Deterministic key generation limitation**: the specification's
  pseudocode implies a drone can regenerate identical Kyber768 keys on
  demand purely from its PUF-reconstructed seed. `pqcrypto-kyber`'s
  `keypair()` draws randomness directly from the OS CSPRNG with no
  seed-injection point. This project's domain-separated seed material
  (`identity::keys::derive_device_keys`) is genuinely derived and tested
  as distinct per-primitive, but is NOT fed into the actual keygen call
  — keys are generated once at registration using real device entropy
  and persisted only in the drone's own local device-state table (never
  sent to or stored at GCS). The security property the specification
  actually cares about (GCS never holds long-term drone private keys) is
  preserved; only the specific "zero persistent storage, regenerate
  every boot" mechanism is not literally achievable with this library.

## Digital Signatures: Dilithium2 → ML-DSA-44

- **What's implemented**: `pqcrypto-dilithium` 0.5.0 (NIST Round 3).
- **Standards mapping**: direct predecessor of ML-DSA-44 (FIPS 204,
  August 2024); minor encoding differences exist between Round-3
  Dilithium2 and final ML-DSA-44.
- **Security basis**: Module-LWE / Module-SIS hardness (Fiat-Shamir with
  Aborts construction). Believed post-quantum secure.
- **Canonical signing**: every signed object is built via
  `crypto::kdf::length_prefixed_concat` (or, for the main auth
  transcript, `protocol::transcript::build_auth_transcript`) —
  Dilithium always signs an unambiguous byte string, never a raw
  JSON/serde dump.

## Hashing: Poseidon2/BabyBear (algebraic) and SHAKE256 (transcripts)

- **Poseidon2** (`zkhash.rs`): Poseidon2 over BabyBear (`p = 2013265921`),
  width 16, S-box x^7, 8 full + 13 partial rounds, Plonky3 constants; digest
  = 8 field elements (248 bits); byte strings are packed injectively, 3 bytes
  per element. This replaced the v1 hand-written 64-bit Goldilocks Poseidon
  (≈2^32 collision resistance). No curve group is ever formed. Collision
  resistance ≈2^124 classical / ≈2^83 quantum (BHT); see `zk-design.md`.
- **SHAKE256**: transcripts, `comm_PK`, `G`, metadata and session digests, always
  over length-prefixed canonical inputs (`protocol/canon.rs`).

## AEAD: ChaCha20-Poly1305

- **What's implemented**: RustCrypto's `chacha20poly1305` crate.
  Standardized (RFC 8439).
- **Nonce policy**: `seq:4B (big-endian) || random:8B`. Every AEAD key
  in this system is either (a) derived fresh per KEM envelope (so a
  fixed `seq=1` is always safe — a new key every call), or (b) a
  per-session `K_AEAD` for application messages, where `seq` is a
  strictly-increasing counter tracked per (sender, receiver) pair, with
  the random suffix as defense-in-depth against counter-tracking bugs.
  Nonce reuse under the same key is checked directly in
  `crypto::aead::tests::nonces_are_not_reused_across_many_seals`.
- **Replay protection**: layered on top of the AEAD tag itself — the
  receiver rejects any sequence number not strictly greater than the
  last one seen.

## KDF: HKDF-SHA256

Used for every domain-separated derivation (`crypto::domains` lists
every domain string in one place, specifically so a reviewer can see at
a glance that no two semantically-different derivations share a domain
tag). HMAC-SHA256 is used for the PUF-MAC (`mac1`), with a
constant-time comparison in `crypto::kdf::hmac_verify`.

## GCS never holds private drone keys

`api::state`/`protocol::entities::DronePublicRecord` (the GCS-side
record) contains only: public keys, public metadata, `rho` (public leaf
randomness — not a secret, per the spec's own leaf construction), and
the CRP *reference response* (needed for PUF-MAC verification, but never
the drone's raw PUF golden pattern or reconstructed seed). Private keys
and PUF simulation state live only in each drone's own local snapshot
table (`storage::db`'s `drones_local` table) — see `docs/puf.md` and
`docs/security-review.md` for the full accounting of this boundary.

## Group key trust assumption

GCS generates `K_G,M` itself (per the frozen spec's design) and
therefore knows every group's session key. This is stated here plainly,
not hidden — see `docs/threat-model.md`.
