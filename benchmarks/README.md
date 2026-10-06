# Benchmark exports

- `stego_benchmark.csv` / `.json` — per-algorithm steganography
  measurements (`python-service/venv/bin/python benchmarks/stego_bench.py`).
  Covers: 2 bundled 512x512 RGB covers x payloads 1024 / 8192 / 50007 B
  (50007 B = real sealed R1 request size) x 5 algorithms, 10 trials each;
  avg/p50/p95 embed/extract ms; real capacity, MSE, PSNR, SSIM.
  Infeasible rows (payload > real capacity) report zeros by design.
- `crypto_benchmark_output.txt` — `cargo run --release --bin iod-bench`
  output (ML-KEM-768, ML-DSA-44, Poseidon, Merkle, ZK, AEAD, M1-M8, K1-K4).

Hardware: shared sandbox VM, single process. These show relative cost and
methodology only — not drone-hardware performance. See
`docs/benchmarking.md` and `docs/data-and-evaluation.md`.
