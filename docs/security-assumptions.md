# Security Assumptions (protocol v2)

1. **GCS is trusted and honest-but-available**: knows every drone's identity, `rho`, CRPs and the group key `K_G,M`. Compromise of the GCS breaks anonymity and key secrecy.
2. **Pinned trust anchors**: the GCS ML-DSA and ML-KEM public keys are installed at R3 over an authenticated enrollment (proof of possession + PUF MAC); the first-contact channel is assumed not to be man-in-the-middled.
3. **Post-quantum primitives**: Kyber768 (Module-LWE), Dilithium2 (Module-LWE/SIS), SHAKE256/SHA-256/HKDF/HMAC, ChaCha20-Poly1305. The libraries are Round-3 versions, not final FIPS 203/204.
4. **ZK proof**: soundness from Poseidon2-BabyBear collision/preimage resistance (≈2^124 classical, ≈2^83 BHT) and Keccak-256 (≈2^128 / ≈2^85), FRI soundness (128 bits conjectured / 120 proven list-decoding / 74 unique-decoding), Fiat–Shamir in the random-oracle model; zero knowledge is statistical from hiding FRI. Poseidon2 and the Plonky3 `0.9.0-rc.1` hiding mode are young and not independently audited. See `zk-security-analysis.md`.
5. **PUF**: the SRAM PUF is a *simulator* (golden pattern + bit-flip noise); the fuzzy extractor is a real code-offset construction over it. CRP provisioning at the GCS is simulated. Keys are **not** derived from the PUF.
6. **Clocks** within ±5 min of each other.
7. **Moderate anonymity**: sessions linkable by stable keys/credentials; metadata public.
8. Randomness: OS CSPRNG (`rand`, `getrandom`).
9. The host and storage are trusted: the SQLite snapshot contains private keys and the simulated PUF pattern (documented simulation shortcut).
