# Benchmarks (host-simulation measurements)

**Every number below was measured by `rust-core/src/bin/bench.rs` on the host described in the header. They are HOST-SIMULATION measurements — not Raspberry Pi, flight-controller or drone-hardware numbers — and exclude any network.** Repetitions: 15–5000 per row (stated as `n=`). Statistics: average / p50 / p95 of wall-clock `Instant` deltas. Re-run: `cargo run --release --bin iod-bench` (`IOD_BENCH_QUICK=1` for a short run). Raw output is kept in `docs/benchmark-results-host-simulation.txt`.

Reading notes:
* ZK prove time is almost independent of tree depth (4/8/12) because the trace is padded to ≥256 rows by the hiding-FRI budget; proof size is ≈250 KB. Public-input size is 54 field elements (216 B).
* "Security parameters" printed per depth come from Plonky3's estimator: conjectured 128 b, proven list-decoding 120 b, proven unique-decoding 74 b.
* Wire sizes are of the JSON simulation encoding (byte arrays as number lists, proof as hex), which inflates them roughly 2–3× versus a binary encoding; they are not protocol-minimum sizes.
* CRP pool (16) forced the benchmark to revoke/re-enroll D1 every 12 sessions; those enrollments are not in the M1–M8 rows.
* Peak RSS is the process high-water mark (`VmHWM`) on Linux.

Run of 2026-11-19 after the FIPS 203/204 migration (`ml-kem 0.3.4`, `ml-dsa 0.1.2`). The pure-Rust crates are slower than the PQClean Round-3 build used before (ML-DSA-44 sign 0.86 ms mean vs ≈0.05 ms; M1–M8 total 124 ms vs 112 ms; K1–K3 6.9 ms vs 2.2 ms on the same class of host).

```
=== IoD Secure Simulator benchmarks: HOST-SIMULATION MEASUREMENTS ===
NOT Raspberry Pi / drone-hardware numbers.
CPU      : Intel(R) Xeon(R) Processor @ 2.10GHz (2 logical cores)
RAM      : MemTotal:        8216648 kB
OS       : Linux 6.18.44-fc-v653 x86_64
rustc    : rustc 1.97.0 (2d8144b78 2026-07-07)
build    : release
suite    : iod-fips203-mlkem768-fips204-mldsa44-v1
libs     : ml-kem 0.3.4 (ML-KEM-768, FIPS 203), ml-dsa 0.1.2 (ML-DSA-44, FIPS 204, hedged, ctx = suite id), plonky3 =0.9.0-rc.1 (BabyBear, Poseidon2, hiding FRI), chacha20poly1305, sha3, hkdf
quick    : false

--- PUF (simulated SRAM PUF + fuzzy extractor) ---
PUF fuzzy-extractor reconstruction                   avg=    0.0713 ms  p50=    0.0755 ms  p95=    0.0911 ms  (n=200)

--- ML-KEM-768 (FIPS 203) / ML-DSA-44 (FIPS 204) ---
ML-KEM-768 keygen                                    avg=    0.0858 ms  p50=    0.0829 ms  p95=    0.1085 ms  (n=200)
ML-KEM-768 encapsulate                               avg=    0.0867 ms  p50=    0.0851 ms  p95=    0.1000 ms  (n=500)
ML-KEM-768 decapsulate                               avg=    0.1946 ms  p50=    0.1883 ms  p95=    0.2292 ms  (n=500)
  sizes: pk=1184 B, sk(seed)=64 B, ct=1088 B
ML-DSA-44 keygen                                     avg=    0.1923 ms  p50=    0.1893 ms  p95=    0.2070 ms  (n=200)
ML-DSA-44 sign (256 B transcript)                    avg=    0.8551 ms  p50=    0.6760 ms  p95=    1.8360 ms  (n=500)
ML-DSA-44 verify                                     avg=    0.1553 ms  p50=    0.1492 ms  p95=    0.1845 ms  (n=500)
  sizes: pk=1312 B, sk(seed)=32 B, sig=2420 B

--- AEAD / hash / Merkle ---
ChaCha20-Poly1305 seal (256 B)                       avg=    0.0022 ms  p50=    0.0020 ms  p95=    0.0022 ms  (n=2000)
ChaCha20-Poly1305 open (256 B)                       avg=    0.0021 ms  p50=    0.0020 ms  p95=    0.0020 ms  (n=2000)
Poseidon2 node hash (2x8 limbs -> 8)                 avg=    0.0013 ms  p50=    0.0013 ms  p95=    0.0013 ms  (n=5000)
Poseidon2 leaf hash (6 permutations)                 avg=    0.0082 ms  p50=    0.0074 ms  p95=    0.0090 ms  (n=2000)
Merkle witness generation (depth 12)                 avg=    0.0001 ms  p50=    0.0001 ms  p95=    0.0001 ms  (n=1000)
Merkle witness verification (depth 12)               avg=    0.0156 ms  p50=    0.0151 ms  p95=    0.0164 ms  (n=2000)

--- ZK membership proof (Plonky3 hiding FRI; Poseidon2/BabyBear AIR) ---
[depth 4] depth=4 trace=256x339 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 4)                                  avg=  108.5563 ms  p50=   99.5710 ms  p95=  157.0296 ms  (n=30)
ZK verify (depth 4)                                  avg=    3.7538 ms  p50=    3.7065 ms  p95=    4.1051 ms  (n=100)
  proof size = 245384 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.4 MB
[depth 8] depth=8 trace=256x343 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 8)                                  avg=   99.6959 ms  p50=   94.3968 ms  p95=  126.4340 ms  (n=30)
ZK verify (depth 8)                                  avg=    4.3642 ms  p50=    4.0565 ms  p95=    6.3726 ms  (n=100)
  proof size = 246292 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.4 MB
[depth 12] depth=12 trace=256x347 log_blowup=3 queries=70 query_pow=16 batch_pow=10 ext_degree=5 field=BabyBear(31b) | conjectured=128b proven(unique)=74b proven(list)=120b
ZK prove  (depth 12)                                 avg=  109.8179 ms  p50=  100.6139 ms  p95=  154.6246 ms  (n=15)
ZK verify (depth 12)                                 avg=    4.1799 ms  p50=    4.0276 ms  p95=    4.8613 ms  (n=100)
  proof size = 253853 B ; public inputs = 54 field elements (54 x 4 B = 216 B); peak RSS so far = 14.4 MB

--- Protocol (depth 8, standard ZK parameters), per-message stage timings ---
R1-R3 registration (incl. keygen, 16 CRPs, 64 PIDs)  avg=    2.8315 ms  p50=    2.8455 ms  p95=    5.3006 ms  (n=20)
M1 D1 builds CommReq                                 avg=    0.0687 ms  p50=    0.0652 ms  p95=    0.0910 ms  (n=20)
M2 D2 builds+seals CredReq                           avg=    1.2171 ms  p50=    0.9977 ms  p95=    2.6272 ms  (n=20)
M2/M3 GCS checks, signs, seals                       avg=    2.1382 ms  p50=    1.8551 ms  p95=    4.1256 ms  (n=20)
M3/M4 D2 verifies M3, signs M4                       avg=    1.9806 ms  p50=    1.7143 ms  p95=    4.9026 ms  (n=20)
M4 D1 verifies M4 (GCS+D2 cred+sig4)                 avg=    0.5477 ms  p50=    0.5078 ms  p95=    0.9114 ms  (n=20)
M5 D1 ZK prove + MAC + sign                          avg=  107.1082 ms  p50=  100.8116 ms  p95=  152.8629 ms  (n=20)
M6 D2 builds+signs+seals request                     avg=    1.1580 ms  p50=    1.1320 ms  p95=    2.0135 ms  (n=20)
M6 GCS verifies (MAC, PID, CRP, membership)          avg=    1.7256 ms  p50=    1.5617 ms  p95=    3.9537 ms  (n=20)
M7 D2 verifies ZK + sigs + decides                   avg=    6.0086 ms  p50=    5.5173 ms  p95=    9.1723 ms  (n=20)
M8 D2 signs; D1 verifies + confirms                  avg=    2.3234 ms  p50=    2.4282 ms  p95=    4.0236 ms  (n=20)
TOTAL M1-M8 (sequential, no network)                 avg=  124.2796 ms  p50=  118.9729 ms  p95=  177.5170 ms  (n=20)
TOTAL K1-K3 (sequential, no network)                 avg=    6.8538 ms  p50=    6.6885 ms  p95=    9.9889 ms  (n=20)
  message sizes (JSON on the wire): M2=36121 B, M3=100448 B, M4=53814 B, M5=499663 B, M6resp=9089 B, M8=8939 B
  peak RSS of this process = 14.5 MB

Reminder: host-simulation measurements only; no network, no embedded hardware.

real	0m12.687s
user	0m12.549s
sys	0m0.040s
```

## Cover generator (profile-constrained host benchmark, 2026-11-15)

Source: `docs/samples/generator-benchmark-raspberry_pi_5_cpu-host.json`. **profile-constrained host benchmark (raspberry_pi_5_cpu): the profile's limits were enforced on THIS host; NOT a measurement of the profile's target hardware.**

Host: Intel(R) Xeon(R) Processor @ 2.10GHz · x86_64 · 2 logical CPUs · 8024 MB RAM · Python 3.13.18 · NumPy 2.5.3 · `is_raspberry_pi_5: false`.
Profile `raspberry_pi_5_cpu`: 320×240 RGB, ceiling 640×480, ≤ 2 candidates, budget 2500 ms, memory ≤ 96 MB, 1 worker, seeding `os-random`, a fresh cover per transaction.

| Payload (B) | OK / runs | Selection total ms | Generate ms | Pre-screen ms | Planner ms | Candidates generated | Planner runs | Quality score | Over budget | Heap peak MB (max) | Failures |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 96 | 30 / 30 | 270.97 (p50 260.033, p95 338.719) | 151.299 (p50 150.325, p95 179.9) | 35.81 (p50 34.906, p95 40.755) | 83.701 (p50 72.7, p95 148.153) | 2.0 | 1.0 | 0.97 | 0 | 12.097 | — |
| 512 | 30 / 30 | 378.324 (p50 359.034, p95 499.021) | 157.517 (p50 153.543, p95 196.855) | 38.468 (p50 36.162, p95 48.584) | 182.169 (p50 175.299, p95 268.203) | 2.0 | 1.0 | 0.97 | 0 | 12.459 | — |
| 2048 | 30 / 30 | 498.71 (p50 497.857, p95 683.796) | 156.364 (p50 148.881, p95 197.222) | 37.345 (p50 35.951, p95 42.964) | 304.833 (p50 302.479, p95 479.066) | 2.0 | 1.0 | 0.965 | 0 | 12.097 | — |
| 5000 | 30 / 30 | 717.072 (p50 685.652, p95 923.166) | 168.042 (p50 164.868, p95 211.149) | 37.322 (p50 35.468, p95 49.149) | 511.54 (p50 486.226, p95 688.177) | 2.0 | 1.0 | 0.978 | 0 | 12.098 | — |

Generator quality report (320×240 RGB, fresh OS-random covers, score floor 0.7):

| Family | Passed / covers | Score mean (min – max) | Rejection reasons | Generate ms | Pre-screen ms | adjacent corr. | lag-8 corr. | spectral slope | high-pass σ | RMS contrast | flat blocks | clipped |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `terrain` | 60 / 60 | 0.958 (0.883 – 1.0) | — | 69.276 (p50 69.736, p95 97.562) | 18.586 (p50 17.79, p95 24.781) | 0.98617 | 0.81899 | -3.65652 | 2.60725 | 37.66857 | 0.0 | 0.0 |
| `clouds` | 60 / 60 | 0.95 (0.837 – 1.0) | — | 96.955 (p50 92.959, p95 116.033) | 17.745 (p50 17.058, p95 21.735) | 0.99459 | 0.90178 | -3.58959 | 1.74938 | 40.42892 | 4e-05 | 0.0 |
| `strata` | 60 / 60 | 0.956 (0.869 – 0.997) | — | 77.136 (p50 75.959, p95 92.224) | 17.36 (p50 17.024, p95 21.65) | 0.98141 | 0.70749 | -3.49067 | 3.53874 | 39.56268 | 0.0 | 0.0 |
| `cells` | 60 / 60 | 0.94 (0.806 – 1.0) | — | 66.637 (p50 64.349, p95 87.644) | 18.192 (p50 17.096, p95 23.717) | 0.98648 | 0.66255 | -3.66409 | 2.63951 | 40.86375 | 0.0 | 0.0 |


Reading: at the default 320×240 the two candidates cost about 150–170 ms to generate and 36–38 ms to pre-screen;
the rest is the real planner, which grows with the payload. Every run stayed inside the 2500 ms budget and far below
the 96 MB memory limit (pre-flight estimate 24.55 MB for two held candidates; measured Python-heap peak about 12 MB).
**No Raspberry Pi 5 was available.** These figures say what the profile's limits cost on this x86-64 host; a Raspberry
Pi 5 will be slower by an unmeasured factor, and whether the 2500 ms budget holds there is not established. To measure
the device, run the same command on it (`python3 scripts/bench_generator.py --profile raspberry_pi_5_cpu --runs 30`);
the output file is then named `…-on-pi5.json` and labelled as a device measurement.

## Patch-wise steganography transport on generated covers (development container, 2026-11-19)

Source: `benchmark-results-patchwise.json` — `POST /api/stego/benchmark` through the whole stack (Rust core → Python
image service over loopback HTTP), release build, alternating directions, **a fresh generated cover per transaction**,
profile `raspberry_pi_5_cpu`, transport `frame-v3/appwire-v1/bootstrap-v3/manifest-v2`, policy `low_detectability`,
selector `kb-risk-1`. Host: Intel(R) Xeon(R) Processor @ 2.10GHz, x86_64, 2 logical CPUs, `is_raspberry_pi_5: false` —
a profile-constrained host benchmark, not a Raspberry Pi measurement. Message sizes 64 / 256 / 1024 bytes × 10 iterations
(first and third row) and 4096 bytes × 10 (second row). Times in ms: mean (p50 / p95); percentiles are omitted below 20 samples.

| Run | Delivered | Patches | Used | Cover quality score | PSNR | SSIM | Generate | Pre-screen | Planner | Selection total | Embed | Extract | Transaction total | Over budget |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raspberry_pi_5_cpu default (320x240 RGB) | 30 / 30 | 10.7 | 7.5 | 0.963 | 69.3 dB | 0.99995 | 145 (141 / 180) | 32.7 (31.8 / 39.9) | 215 (188 / 336) | 393 (373 / 516) | 162 (130 / 300) | 52.4 (51.9 / 56.8) | 717 (661 / 944) | 0 |
| raspberry_pi_5_cpu, 4096-byte messages | 10 / 10 | 11.6 | 11.6 | 0.970 | 49.1 dB | 0.99703 | 143 | 33.4 | 469 | 645 | 421 | 53.8 | 1231 | 0 |
| raspberry_pi_5_cpu, 640x480 requested | 30 / 30 | 17.8 | 9.8 | 0.970 | 72.7 dB | 0.99997 | 683 (702 / 795) | 145 (141 / 175) | 613 (552 / 819) | 1442 (1396 / 1761) | 350 (285 / 600) | 86.2 (83.9 / 104.5) | 2240 (2078 / 2742) | 0 |

Algorithms actually used (patches / payload bytes) and cover families selected:

* raspberry_pi_5_cpu default (320x240 RGB): `s_uniward` 225 / 16380; families cells 8, clouds 7, strata 8, terrain 7.
* raspberry_pi_5_cpu, 4096-byte messages: `pvd` 35 / 12540, `s_uniward` 81 / 29400; families cells 1, clouds 1, strata 3, terrain 5.
* raspberry_pi_5_cpu, 640x480 requested: `s_uniward` 295 / 16380; families cells 12, clouds 2, strata 3, terrain 13.

Compared with 2026-11-15 (bootstrap-v2, `kb-bm25-1`): PSNR rose from 57.5 to 69.3 dB at the default size because the
selector now prefers S-UNIWARD over DCT / LSB replacement; the 4096-byte row fell to 49.1 dB because PVD fills patches
where S-UNIWARD lacks capacity. **Extraction grew from ≈ 17 to ≈ 52 ms** (three service calls for discovery, carrier read
and extraction instead of one) and the transaction total from ≈ 589 to ≈ 717 ms. At 640×480 the selection uses about
1.4 s of the 2.5 s budget on this host.
