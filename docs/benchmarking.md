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

## Patch-wise steganography transport on generated covers (development container, 2026-11-15)

Source: `benchmark-results-patchwise.json` — `POST /api/stego/benchmark` through the whole stack (Rust core → Python
image service over loopback HTTP), release build, alternating directions, **a fresh generated cover per transaction**,
profile `raspberry_pi_5_cpu`. Host: Intel(R) Xeon(R) Processor @ 2.10GHz, x86_64, 2 logical CPUs, `is_raspberry_pi_5: false` —
a profile-constrained host benchmark, not a Raspberry Pi measurement. Message sizes 64 / 256 / 1024 bytes × 10 iterations
(first and third row) and 4096 bytes × 10 (second row). Times in ms: mean (p50 / p95); percentiles are omitted below 20 samples.

| Run | Delivered | Patches | Used | Cover quality score | PSNR | SSIM | Generate | Pre-screen | Planner | Selection total | Embed | Extract | Transaction total | Over budget |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| raspberry_pi_5_cpu default (320x240 RGB) | 30 / 30 | 11.3 | 8.0 | 0.967 | 57.5 dB | 0.99873 | 163 (161 / 209) | 37 (35 / 48) | 158 (152 / 264) | 359 (356 / 512) | 105 (97 / 231) | 17.4 (17.0 / 20.5) | 589 (588 / 813) | 0 |
| raspberry_pi_5_cpu, 4096-byte messages | 10 / 10 | 11.5 | 11.5 | 0.968 | 55.1 dB | 0.99858 | 166 | 37 | 451 | 653 | 398 | 20.3 | 1183 | 0 |
| raspberry_pi_5_cpu, 640x480 requested | 30 / 30 | 19.3 | 9.6 | 0.962 | 58.0 dB | 0.99908 | 762 (763 / 901) | 156 (154 / 174) | 537 (546 / 766) | 1455 (1457 / 1714) | 252 (255 / 445) | 30.0 (28.0 / 40.1) | 2087 (2097 / 2535) | 0 |

Algorithms actually used (patches / payload bytes) and cover families selected:

* raspberry_pi_5_cpu default (320x240 RGB): `dct` 53 / 3496, `lsb_matching` 79 / 4524, `lsb_replacement` 17 / 1515, `s_uniward` 88 / 6652, `wow` 3 / 193; families cells 6, clouds 8, strata 8, terrain 8.
* raspberry_pi_5_cpu, 4096-byte messages: `dct` 1 / 262, `hugo` 2 / 646, `lsb_matching` 25 / 8511, `lsb_replacement` 22 / 7763, `pvd` 5 / 2607, `s_uniward` 58 / 21479, `wow` 2 / 672; families cells 2, clouds 3, strata 3, terrain 2.
* raspberry_pi_5_cpu, 640x480 requested: `dct` 162 / 8827, `lsb_matching` 22 / 1060, `s_uniward` 101 / 6316, `wow` 4 / 177; families cells 8, clouds 4, strata 9, terrain 9.

Rust-side work (AEAD seal/open, MAC and manifest verification) remains below 0.2 ms per transaction; the time is image
processing in Python. Cover generation and pre-screening scale with the pixel count (about ×4.2–4.7 from 320×240 to 640×480
here); the planner scales with pixels and payload. At 640×480 the selection uses about 1.5 s of the 2.5 s budget on this host.

The three kinds of figure must not be confused: the **cover quality score** is a heuristic about the cover before
embedding; **PSNR / SSIM** measure cover-versus-stego distortion; **detector AUC** comes only from the offline evaluation
in `detectability-evaluation.md` (where the transport is easily detected). None of them supports a claim of
undetectability. These are measurements of this implementation on this host, not of UAV hardware or a radio link.

## Ten algorithms on one patch (educational workbench, 2026-11-13)
From `docs/samples/learning-patch-comparison-all-ten.md` (256×256 RGB sample, largest patch = 25 088 pixels, 112-byte AEAD
payload, single run): embedding 0.17 ms (LSB replacement) to 149 ms (HUGO; WOW and S-UNIWARD ≈ 60 ms incl. cost maps),
extraction 1.8–3.6 ms; whole-image PSNR 53.5 dB (PVD) to 79.3 dB (S-UNIWARD); `dct_svd` was rejected for capacity (392 bits
in that patch). Single runs, not statistics.
