# Testing

```
cd rust-core
cargo test --release          # 115 unit + 16 integration + 1 e2e (+2 ignored ZK parameter runs)
cargo test                    # same suites in debug (slower, ~30 s)
cargo test --release --lib zk::tests::standard_params_smoke -- --ignored --nocapture
cargo run --release --bin iod-bench
cargo run --release --bin iod-vectors
```
Layout: unit tests live beside the code (`zkhash`, `zk`, `merkle`, `identity`, `crypto`, `puf`, `protocol/*`, `zero_trust`, `trace`, `storage`); `tests/protocol_integration.rs` holds integration tests 1–16; `tests/end_to_end.rs` is Register → M1–M8 → ALLOW → K1–K3 → AEAD → Revoke → rejection. Results and the area-to-test map are in `zk-test-results.md`. Windows PowerShell uses the same `cargo` commands.
Node: `cd node-server && npm ci && npx tsc --noEmit`. UI: `cd web-ui && npm ci && npx tsc --noEmit -p . && npx vite build`. Python service tests: not re-run in this phase (unchanged).

## Steganography transport tests (added 2026-10-29)
Results from this host (release mode): `cargo test --release` → lib 133 passed (2 ignored), `protocol_integration` 16, `end_to_end` 1, `stego_pipeline` 15 (fake backend), `stego_e2e_python` 6 (spawns the real Python service with `IOD_STEGO_CAMERA=disabled`; fails if python/numpy/Pillow/Flask are missing unless `IOD_E2E_ALLOW_SKIP=1`).
Python: `cd python-service && python -m pytest -q` → 443 passed. Standalone: `python -m unittest tools/stego-standalone/test_latent_image.py` (4 OK; `test_text_vector` needs a HuggingFace model download and fails offline).
Smoke: start Rust, Node and Python (`scripts/linux/run_demo.sh` / `scripts\windows\run_demo.ps1`), then `python3 scripts/stego_smoke.py` → 38/38.
Covered: both directions × five algorithms, pixel-level tamper, truncation, garbage, blank, JPEG recompression, bootstrap CRC/alg/version/length attacks, replay, wrong channel/direction, MAC failure before AEAD, RAG outage, oversize message vs capacity, history filters/injection-shaped values.
Not covered: physical webcam, Windows, Docker, debug-mode run of the new tests.
Windows: same `cargo`/`pytest` commands in PowerShell; `.\scripts\windows\test.ps1`.

### Webcam tests (added 2026-10-30)
Python: `python -m pytest -q tests/test_stego_webcam.py` (14: upload round trip, lossless, labels, bad base64/GIF/garbage PNG/JPEG, RGBA conversion, size limits, id validation, HTTP route, fake-`cv2` adapter warm-up/BGR->RGB/error mapping). Rust: `stego_e2e_python::browser_webcam_frame_upload_becomes_the_cover_and_is_labelled`. Totals now: Python 443 passed; Rust `stego_e2e_python` 6.
Full-stack browser check (manual, reproducible): start the services, then run Chromium with `--use-fake-device-for-media-stream --use-fake-ui-for-media-stream`, open `/steganography`, **Start browser webcam -> Capture frame as cover -> Send as image**. Verified with Playwright: 640x480 RGB cover, message delivered, event `cover_source = browser_webcam`. A physical webcam was not available.
