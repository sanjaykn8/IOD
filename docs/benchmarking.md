# Benchmarking

## Running

```bash
cd rust-core
cargo run --release --bin iod-bench
```

Always use `--release` — debug-mode numbers are dominated by missing
optimizations and are not representative of even relative cost between
operations.

## What is measured

PUF fuzzy-extractor reconstruction, ML-KEM-768 keygen/encapsulate/
decapsulate, ML-DSA-44 keygen/sign/verify, Poseidon hashing, Merkle
registration/witness-generation/verification, ZK proof generation/
verification, AEAD seal/open, full end-to-end authentication (M1-M8
including registration), and group-key establishment (K1-K4). Each
operation is timed individually across 50-1000 trials (fewer for
slower/more complex operations) using `std::time::Instant`, and
avg/p50/p95 are computed from the actual measured samples — nothing in
this output is an assumed or estimated figure.

## A real result, captured in this session

```
PUF fuzzy-extractor reconstruction            avg=  0.061631ms  p50=  0.049261ms  p95=  0.067382ms  (n=200)
ML-KEM-768 (Kyber768) key generation          avg=  0.017616ms  p50=  0.014148ms  p95=  0.029325ms  (n=100)
ML-KEM-768 encapsulate                        avg=  0.015165ms  p50=  0.013668ms  p95=  0.019748ms  (n=200)
ML-KEM-768 decapsulate                        avg=  0.017629ms  p50=  0.015183ms  p95=  0.024097ms  (n=200)
  -> Kyber768 public key size                 1184 bytes
  -> Kyber768 ciphertext size                 1088 bytes
ML-DSA-44 (Dilithium2) key generation         avg=  0.032417ms  p50=  0.027675ms  p95=  0.054279ms  (n=100)
ML-DSA-44 sign                                avg=  0.042811ms  p50=  0.040688ms  p95=  0.064357ms  (n=100)
ML-DSA-44 verify                              avg=  0.033075ms  p50=  0.029577ms  p95=  0.049753ms  (n=100)
  -> Dilithium2 public key size               1312 bytes
  -> Dilithium2 signature size                2420 bytes
Poseidon hash (8 field elements)              avg=  0.009542ms  p50=  0.008955ms  p95=  0.012194ms  (n=1000)
Merkle registration (single leaf, depth=12)   avg=  0.030907ms  p50=  0.028382ms  p95=  0.036048ms  (n=200)
Merkle witness generation (depth=12, 500 members) avg=  0.000193ms  p50=  0.000103ms  p95=  0.000116ms  (n=500)
Merkle witness verification (depth=12)        avg=  0.028998ms  p50=  0.026793ms  p95=  0.033654ms  (n=1000)
ZK membership proof generation (depth=10)     avg=  0.112268ms  p50=  0.109739ms  p95=  0.128532ms  (n=200)
ZK membership proof verification (depth=10)   avg=  0.109705ms  p50=  0.106462ms  p95=  0.125219ms  (n=200)
  -> ZK proof size                            543 bytes (JSON-serialized)
AEAD (ChaCha20-Poly1305) seal (256B)          avg=  0.002210ms  p50=  0.002005ms  p95=  0.002162ms  (n=1000)
AEAD (ChaCha20-Poly1305) open (256B)          avg=  0.002068ms  p50=  0.001963ms  p95=  0.002057ms  (n=1000)
Full end-to-end authentication (M1-M8, incl. registration) avg=  4.981547ms  p50=  4.957460ms  p95=  5.353850ms  (n=50)
Group-key establishment (K1-K4)               avg=  1.678100ms  p50=  1.661745ms  p95=  1.910263ms  (n=50)
```

## Interpreting these numbers honestly

These were measured on a shared sandbox VM's CPU, in a single process,
with no isolation from other load on the host. They demonstrate:

- **Relative cost** between operations (e.g., ZK proof gen/verify is
  roughly 3-7x the cost of a single ML-DSA sign/verify in this
  implementation, dominated by the Poseidon Merkle-path recomputation
  and canonical encoding, not by any expensive proof-system machinery —
  consistent with this being a disclosure-based proof rather than a
  real succinct/hiding ZK system).
- **Correctness of the measurement methodology** (real trials, real
  percentiles, real sizes).

They do **NOT** demonstrate real embedded-drone-hardware performance,
which would differ substantially due to CPU architecture (many drone
flight controllers use ARM Cortex-M/A-class cores, not x86_64 server
cores), clock speed, absence of a hypervisor, and different memory/cache
behavior. Re-run `iod-bench` directly on target hardware before making
any real deployment sizing decision.

## Message/proof sizes (also measured, not estimated)

| Object | Size |
|---|---|
| Kyber768 public key | 1184 bytes |
| Kyber768 ciphertext | 1088 bytes |
| Dilithium2 public key | 1312 bytes |
| Dilithium2 signature | 2420 bytes |
| ZK proof (JSON-serialized, depth=10 tree) | ~540 bytes |

Note the ZK proof's `opening` (see `docs/zk-membership.md`) is included
in this size — a real hiding backend would typically be either larger
(a STARK proof) or a different shape entirely (an MPC-in-the-head
transcript), so this number should not be used to estimate a future
hiding backend's bandwidth cost.
