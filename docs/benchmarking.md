# Benchmarks (host-simulation measurements)

**Every number below was measured by `rust-core/src/bin/bench.rs` on the host described in the header. They are HOST-SIMULATION measurements — not Raspberry Pi, flight-controller or drone-hardware numbers — and exclude any network.** Repetitions: 15–5000 per row (stated as `n=`). Statistics: average / p50 / p95 of wall-clock `Instant` deltas. Re-run: `cargo run --release --bin iod-bench` (`IOD_BENCH_QUICK=1` for a short run). Raw output is kept in `docs/benchmark-results-host-simulation.txt`.

Reading notes:
* ZK prove time is almost independent of tree depth (4/8/12) because the trace is padded to ≥256 rows by the hiding-FRI budget; proof size is ≈250 KB. Public-input size is 54 field elements (216 B).
* "Security parameters" printed per depth come from Plonky3's estimator: conjectured 128 b, proven list-decoding 120 b, proven unique-decoding 74 b.
* Wire sizes are of the JSON simulation encoding (byte arrays as number lists, proof as hex), which inflates them roughly 2–3× versus a binary encoding; they are not protocol-minimum sizes.
* CRP pool (16) forced the benchmark to revoke/re-enroll D1 every 12 sessions; those enrollments are not in the M1–M8 rows.
* Peak RSS is the process high-water mark (`VmHWM`) on Linux.

```
=== IoD Secure Simulator benchmarks: HOST-SIMULATION MEASUREMENTS ===
NOT Raspberry Pi / drone-hardware numbers.
CPU      : Intel(R) Xeon(R) Processor @ 2.10GHz (2 logical cores)
RAM      : MemTotal:        8222320 kB
OS       : Linux 6.18.44-fc-v114 x86_64
rustc    : rustc 1.97.0 (2d8144b78 2026-07-07)
build    : release
libs     : pqcrypto-kyber 0.8.1 (Kyber768), pqcrypto-dilithium 0.5.0 (Dilithium2), plonky3 =0.9.0-rc.1 (BabyBear, Poseidon2, hiding FRI), chacha20poly1305, sha3, hkdf
quick    : false

--- PUF (simulated SRAM PUF + fuzzy extractor) ---
PUF fuzzy-extractor reconstruction                   avg=    0.0447 ms  p50=    0.0419 ms  p95=    0.0606 ms  (n=200)

--- ML-KEM-768 (Kyber768) / ML-DSA-44 (Dilithium2) ---
ML-KEM-768 keygen                                    avg=    0.0148 ms  p50=    0.0140 ms  p95=    0.0183 ms  (n=200)
ML-KEM-768 encapsulate                               avg=    0.0149 ms  p50=    0.0136 ms  p95=    0.0200 ms  (n=500)
ML-KEM-768 decapsulate                               avg=    0.0160 ms  p50=    0.0149 ms  p95=    0.0217 ms  (n=500)
  sizes: pk=1184 B, ct=1088 B
ML-DSA-44 keygen                                     avg=    0.0293 ms  p50=    0.0273 ms  p95=    0.0453 ms  (n=200)
ML-DSA-44 sign (256 B transcript)                    avg=    0.0533 ms  p50=    0.0502 ms  p95=    0.0635 ms  (n=500)
ML-DSA-44 verify                                     avg=    0.0334 ms  p50=    0.0306 ms  p95=    0.0457 ms  (n=500)
  sizes: pk=1312 B, sig=2420 B

--- AEAD / hash / Merkle ---
ChaCha20-Poly1305 seal (256 B)                       avg=    0.0026 ms  p50=    0.0022 ms  p95=    0.0024 ms  (n=2000)
ChaCha20-Poly1305 open (256 B)                       avg=    0.0021 ms  p50=    0.0019 ms  p95=    0.0023 ms  (n=2000)
Poseidon2 node hash (2x8 limbs -> 8)                 avg=    0.0014 ms  p50=    0.0013 ms  p95=    0.0018 ms  (n=5000)
Poseidon2 leaf hash (6 permutations)                 avg=    0.0083 ms  p50=    0.0075 ms  p95=    0.0106 ms  (n=2000)
Merkle witness generation (depth 12)                 avg=    0.0001 ms  p50=    0.0001 ms  p95=    0.0001 ms  (n=1000)
Merkle witness verification (depth 12)               avg=    0.0199 ms  p50=    0.0176 ms  p95=    0.0270 ms  (n=2000)

--- ZK membership proof (Plonky3 hiding FRI; Poseidon2/BabyBear AIR) ---
[depth 4] depth=4 trace=256x339 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 4)                                  avg=   97.7722 ms  p50=   95.9745 ms  p95=  122.0503 ms  (n=30)
ZK verify (depth 4)                                  avg=    4.3046 ms  p50=    3.9579 ms  p95=    5.9779 ms  (n=100)
  proof size = 246772 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.3 MB
[depth 8] depth=8 trace=256x343 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 8)                                  avg=  100.6073 ms  p50=   99.9668 ms  p95=  120.7922 ms  (n=30)
ZK verify (depth 8)                                  avg=    4.4206 ms  p50=    4.0503 ms  p95=    7.3624 ms  (n=100)
  proof size = 249233 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.3 MB
[depth 12] depth=12 trace=256x347 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 12)                                 avg=  101.0554 ms  p50=   98.9599 ms  p95=  117.7026 ms  (n=15)
ZK verify (depth 12)                                 avg=    4.3226 ms  p50=    4.0494 ms  p95=    5.7180 ms  (n=100)
  proof size = 248046 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.3 MB

--- Protocol (depth 8, standard ZK parameters), per-message stage timings ---
R1-R3 registration (incl. keygen, 16 CRPs, 64 PIDs)  avg=    0.6086 ms  p50=    0.5974 ms  p95=    0.7621 ms  (n=20)
M1 D1 builds CommReq                                 avg=    0.0578 ms  p50=    0.0562 ms  p95=    0.0984 ms  (n=20)
M2 D2 builds+seals CredReq                           avg=    0.2666 ms  p50=    0.2407 ms  p95=    0.4629 ms  (n=20)
M2/M3 GCS checks, signs, seals                       avg=    0.7016 ms  p50=    0.6178 ms  p95=    1.0160 ms  (n=20)
M3/M4 D2 verifies M3, signs M4                       avg=    0.6407 ms  p50=    0.6247 ms  p95=    0.9088 ms  (n=20)
M4 D1 verifies M4 (GCS+D2 cred+sig4)                 avg=    0.1760 ms  p50=    0.1499 ms  p95=    0.2591 ms  (n=20)
M5 D1 ZK prove + MAC + sign                          avg=  103.9047 ms  p50=  100.3490 ms  p95=  141.0709 ms  (n=20)
M6 D2 builds+signs+seals request                     avg=    0.2048 ms  p50=    0.1778 ms  p95=    0.4970 ms  (n=20)
M6 GCS verifies (MAC, PID, CRP, membership)          avg=    0.2853 ms  p50=    0.2873 ms  p95=    0.4323 ms  (n=20)
M7 D2 verifies ZK + sigs + decides                   avg=    5.5179 ms  p50=    4.9682 ms  p95=    8.4653 ms  (n=20)
M8 D2 signs; D1 verifies + confirms                  avg=    0.2439 ms  p50=    0.2090 ms  p95=    0.4894 ms  (n=20)
TOTAL M1-M8 (sequential, no network)                 avg=  112.0011 ms  p50=  107.8350 ms  p95=  153.1483 ms  (n=20)
TOTAL K1-K3 (sequential, no network)                 avg=    2.2090 ms  p50=    2.0792 ms  p95=    3.1391 ms  (n=20)
  message sizes (JSON on the wire): M2=35990 B, M3=100075 B, M4=53766 B, M5=506416 B, M6resp=9073 B, M8=9019 B
  peak RSS of this process = 14.4 MB

Reminder: host-simulation measurements only; no network, no embedded hardware.
```

## Steganography transport benchmark (host simulation, 2026-10-29)
Files: `benchmark-results-stego-host-simulation.txt`, `benchmark-results-stego-natural-cover.json`. 200 transactions: 180 delivered, 20 DCT refusals on the B/W cover. End-to-end p50 ≈ 348–364 ms, p95 ≈ 377–404 ms (measured, this host, includes PNG write/read and Python calls). PSNR ≈ 69 dB (LSB family), 49 dB (PVD), 53.6 dB (DCT). Reports give percentiles only when n ≥ 20; estimated costs in the selector are a static model and are labelled estimated, never mixed with measured timings.
