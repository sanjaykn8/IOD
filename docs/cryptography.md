# Cryptography

No claim in this document should be read as "mathematically proven
secure" or "quantum secure" without the specific qualification attached
to it. Distinctions used throughout: **REAL** (genuine implementation of
a real algorithm/library), **SIMULATED** (a documented, necessary
simplification), **research-parameterized** (a real construction with
parameters chosen for auditability/clarity rather than run through
production parameter-selection tooling).

## Cryptographic suite

Active and only accepted suite: **`iod-fips203-mlkem768-fips204-mldsa44-v1`**
(`rust-core/src/crypto/suite.rs`). It replaced the NIST Round-3 Kyber768 /
Dilithium2 suite on 2026-11-19.

| Material | ML-KEM-768 (FIPS 203) | ML-DSA-44 (FIPS 204) |
|---|---:|---:|
| Public key | 1,184 B | 1,312 B |
| Private key, expanded encoding (tests only) | 2,400 B | 2,560 B |
| Private key, stored form (seed) | 64 B (`d‖z`) | 32 B (`ξ`) |
| Ciphertext / signature | 1,088 B | 2,420 B |
| Shared secret | 32 B | — |

All sizes are asserted in tests (`crypto::kem`, `crypto::sign`, `tests/fips_kat.rs`,
`tests/fips_interop.rs`).

**Not FIPS 140-3 validated.** The application implements algorithms specified in
FIPS 203 and FIPS 204 with libraries whose output matches the NIST ACVP vectors;
neither the libraries nor this software have undergone CMVP module validation.

### Why the suite is explicit

Round-3 Kyber768 and ML-KEM-768 have identical public-key (1,184 B) and
ciphertext (1,088 B) lengths; Dilithium2 and ML-DSA-44 have identical public-key
(1,312 B) and signature (2,420 B) lengths. Length checks cannot distinguish them,
so the suite is carried and bound explicitly:

* signed into every credential (`CredentialBody::suite`, credential version 3) and
  every enrollment body; verification rejects any other suite (`CredentialError::Suite`);
* used as the **FIPS 204 context string** of every ML-DSA signature, so a signature
  made under any other context (or none) does not verify;
* mixed into the HKDF `info` of every KEM-envelope key and recorded on the envelope;
  an envelope labelled with another suite is refused before decapsulation;
* stored in every persisted identity snapshot. There is no negotiation and no fallback.

### Legacy (Round-3) state

Identities written before the migration have no `suite` field and hold Round-3
key bytes. They are **never converted or reinterpreted**. At start-up
`Database::quarantine_incompatible` moves such rows (and any row of another suite,
or whose stored public key does not re-derive from its private seed) into the
`legacy_snapshots` table and deletes them from the live tables; when the GCS row is
archived, every drone row is archived too, because the credentials name a trust
anchor that no longer exists. The simulation then starts with a fresh GCS identity
and the drones must be registered again. `GET /api/system/crypto` reports the suite
and what was archived. `POST /api/reset` clears the archive as well.

## Key Encapsulation: ML-KEM-768 (FIPS 203)

- **Implementation**: RustCrypto `ml-kem` **=0.3.4** (pure Rust, `#![no_std]`,
  constant-time helpers via `ctutils`), wrapped in `crypto::kem`.
- **Encodings**: public key = FIPS 203 `ek`; decoding runs the crate's FIPS 203 §7.2
  modulus check (non-canonical keys rejected, ACVP `encapsulationKeyCheck` vectors
  pass). Private key stored as the 64-byte seed `d‖z` (FIPS 203 §3.3 allows storing
  the seed instead of `dk`; it is the crate's preferred form and needs no input check).
- **Implicit rejection**: FIPS 203 decapsulation of a modified ciphertext of the
  right length returns the pseudo-random value `J(z‖c)` instead of an error. The
  wrapper returns it unchanged; the envelope's AEAD tag under the derived key is
  what rejects such messages (`protocol::envelope` test
  `tampered_kem_ciphertext_is_caught_by_the_aead_after_implicit_rejection`). Only a
  ciphertext of the wrong length is a decoding error.
- **Used as a KEM, not textbook encryption**: `encapsulate` yields `(ct, ss)`; the
  envelope derives `K = HKDF(ss, info = "IOD-SEED-ENVELOPE-KEY-v1" ‖ 0 ‖ suite)` and
  seals with ChaCha20-Poly1305. There is no `encrypt(pk, plaintext)` function.
- **Security basis**: Module-LWE hardness; a computational assumption, not a proof.

## Digital Signatures: ML-DSA-44 (FIPS 204)

- **Implementation**: RustCrypto `ml-dsa` **=0.1.2** (pure Rust), wrapped in
  `crypto::sign`. Versions before 0.1.0-rc.3 had a timing side channel in Decompose
  (CVE-2026-22705 / RUSTSEC-2025-0144) and before 0.1.0-rc.4 accepted duplicate hint
  indices (CVE-2026-24850); 0.1.2 contains both fixes.
- **Mode**: pure ML-DSA (FIPS 204 Algorithms 2/3), no pre-hash; **hedged** signing
  (fresh 32-byte `rnd` from the OS RNG); context string = suite id.
- **Encodings**: public key 1,312 B; signature 2,420 B; private key stored as the
  32-byte seed `ξ` (FIPS 204 §3.6.3). Malformed public keys or signatures make
  `verify_transcript` return `false`; nothing panics.
- **Canonical signing**: every signed object is a length-prefixed canonical byte
  string (`protocol::canon`, `protocol::transcript`), never a raw JSON dump.
- **Security basis**: Module-LWE / Module-SIS (Fiat–Shamir with aborts).

## Conformance and interoperability tests

| Test | What it checks |
|---|---|
| `tests/fips_kat.rs` | NIST ACVP vectors for the exact parameter sets: ML-KEM-768 keyGen (25), encapsulation (25), decapsulation incl. modified ciphertexts / implicit rejection (10), decapsulation-key check (10), encapsulation-key check (10); ML-DSA-44 keyGen (25), sigGen (90: external/pure, internal, external-μ × deterministic/hedged), sigVer (45: valid, modified z / hint / commitment / message). Pre-hash groups are not used by the system and are not included. Vector files: `rust-core/tests/kat/` with source URL and SHA-256 of the NIST file. |
| `tests/fips_interop.rs` | Both directions against PQClean's independent C implementations (`pqcrypto-mlkem`, `pqcrypto-mldsa`, test-only): encapsulate/decapsulate, identical implicit-rejection secret for a tampered ciphertext, signatures with the suite context accepted and other contexts refused, seed-form keys matching the expanded keys PQClean uses. |
| `crypto::kem`, `crypto::sign` unit tests | sizes, agreement, wrong key, tampered ciphertext, altered transcript / key / signature, malformed encodings, legacy-length private keys refused, context binding, redacted `Debug`. |
| `tests/crypto_suite_lifecycle.rs` | registration → M1–M8 → K1–K3 → K4 image message, persistence and restart, key replacement (revoke + reactivate), Round-3 database archived at start-up. |

## Key generation and the PUF

Device keys are generated at registration from the **operating-system CSPRNG**
and persisted in seed form only in the drone's own local state (never at the GCS).
The libraries expose the standard deterministic entry points
(`ML-KEM.KeyGen_internal(d, z)`, `ML-DSA.KeyGen_internal(ξ)`, wrapped as
`kem::keypair_from_seed` / `sign::keypair_from_seed`, used by the KATs), but they are
deliberately **not** connected to the simulated PUF: doing so would present a
software simulation as hardware-rooted key material. The HKDF-derived per-domain
seed material from the PUF seed is still computed and tested, and the
`*_from_seed` functions are the seam for future physical-PUF provisioning
(deferred).

## Performance note (development host, not Raspberry Pi)

`docs/benchmark-results-host-simulation.txt` (x86-64 Xeon 2.1 GHz, release build):
ML-KEM-768 keygen / encaps / decaps 0.086 / 0.087 / 0.195 ms; ML-DSA-44 keygen /
sign / verify 0.19 / 0.86 (p50 0.68) / 0.16 ms. The previous PQClean Round-3 build
was faster on the same class of host (sign ≈0.05 ms); the pure-Rust crates trade
speed for memory safety and maintenance. Whole-protocol totals moved from about
112 to 124 ms for M1–M8 (dominated by the ZK proof) and from about 2.2 to 6.9 ms
for K1–K3.

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
