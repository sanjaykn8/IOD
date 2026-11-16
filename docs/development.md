# Development Guide

## Prerequisites

- Rust stable (tested with 1.97.0); `cargo` and `rustc` on `PATH`.
- Node.js 18+ and `npm`.
- Python 3.9+ and `pip` (a virtualenv is recommended and is what
  `scripts/*/setup.*` create).
- No system SQLite install needed — `rusqlite`'s `bundled` feature
  compiles SQLite from source as part of the Rust build.
- No Docker required (see project root README for optional Docker
  usage).

## Repository layout

See `docs/architecture.md`, "Directory layout."

## Building each component

```bash
# Rust core (library + iod-server + iod-bench + iod-vectors)
cd rust-core
cargo build --release

# Node gateway
cd node-server
npm install
npm run build      # tsc -> dist/

# Python image service
cd python-service
python3 -m venv venv
./venv/bin/pip install -r requirements.txt   # venv/Scripts/pip.exe on Windows

# React dashboard
cd web-ui
npm install
npm run build       # tsc -b && vite build -> dist/
```

## Running each component for local development

```bash
# Terminal 1 — Rust core HTTP API
cd rust-core
IOD_DB_PATH=iod_simulation.db IOD_BIND_ADDR=127.0.0.1:8787 ./target/release/iod-server
# Windows (PowerShell):
#   $env:IOD_DB_PATH="iod_simulation.db"; $env:IOD_BIND_ADDR="127.0.0.1:8787"; .\target\release\iod-server.exe

# Terminal 2 — Python image service
cd python-service
./venv/bin/python src/app.py            # venv\Scripts\python.exe src\app.py on Windows

# Terminal 3 — Node gateway
cd node-server
npm start                                # or: npm run dev  (ts-node, no build step)

# Terminal 4 — React dashboard (dev server with hot reload)
cd web-ui
npm run dev
```

Then open `http://127.0.0.1:5173` (dev) or serve `web-ui/dist/` with any
static file server for a production build.

See `scripts/linux/run_demo.sh` / `scripts/windows/run_demo.ps1` for a
one-command version of the above.

## Adding a new Rust module

Follow the existing pattern: one `mod.rs` per directory that only
re-exports submodules; keep cryptographic primitives in `crypto/`;
domain-separation tags belong in `crypto::domains`, nowhere else, so a
reviewer can audit every distinct cryptographic purpose in one file.
Every new primitive should get: a doc comment stating what's REAL vs.
SIMULATED (if applicable), and unit tests in the same file's
`#[cfg(test)] mod tests` block covering at least the happy path and one
tamper/negative case.

## Code style

- Rust: standard `rustfmt` conventions (not auto-enforced by CI in this
  repo, but consistent throughout).
- TypeScript: `strict: true` in both `tsconfig.json` files; no `any`
  escapes except where an external library's types are incomplete
  (`node-fetch`'s response typing).
- Python: no enforced formatter; keep functions small and docstring
  every module with what's REAL vs. SIMULATED where relevant, matching
  the Rust side's documentation discipline.

## Regenerating test vectors / running benchmarks

See `docs/testing.md` and `docs/benchmarking.md`.

## Environment variables of the patch-wise steganography transport

Both processes must see the **same artifact directory** (the run scripts export one absolute path for both; when you
start the processes by hand, set `IOD_STEGO_ARTIFACT_DIR` to the same absolute path in the Rust and the Python terminal).

| Variable | Process | Default | Meaning |
|---|---|---|---|
| `IOD_STEGO_ARTIFACT_DIR` | Rust, Python | `./data/stego-artifacts` (relative to each process!) | shared directory for cover/stego/inspection PNGs |
| `IOD_PYTHON_URL` | Rust | `http://127.0.0.1:5001` | image service (loopback only unless `IOD_STEGO_ALLOW_NONLOOPBACK=1`) |
| `IOD_PYTHON_HOST`, `IOD_PYTHON_PORT` | Python | `127.0.0.1`, `5001` | bind address |
| `IOD_STEGO_MAX_FRAME_BYTES`, `IOD_STEGO_MAX_WIDTH`, `IOD_STEGO_MAX_HEIGHT`, `IOD_STEGO_HTTP_TIMEOUT_MS` | Rust | see `transport/config.rs` | limits sent with every request |
| `IOD_STEGO_SEG_*`, `IOD_STEGO_TARGET_CHUNK_BYTES`, `IOD_STEGO_MAX_REPLANS` | Rust | see `patchwise-transport.md` section 7 | segmentation settings, chunk size, re-plan bound |
| `IOD_STEGO_GENERATOR_PROFILE` | Rust, Python (same value) | `raspberry_pi_5_cpu` | cover-generation resource profile (`raspberry_pi_5_cpu`, `development_host`) |
| `IOD_STEGO_GENERATOR_WIDTH`, `_HEIGHT`, `_MAX_WIDTH`, `_MAX_HEIGHT`, `_MAX_PIXELS`, `_MAX_CANDIDATES`, `_BUDGET_MS`, `_MAX_MEMORY_MB`, `_MIN_QUALITY`, `_MAX_EMBED_RATE`, `_ALLOW_RESIZE`, `_FAMILIES`, `_WORKERS`, `_MODE` | Rust, Python (same values) | profile values | overrides of the profile, bounded by hard ceilings; see `cover-generation.md` §6. An invalid value stops the process at start-up |
| `IOD_STEGO_GENERATOR_TEST_SEED` | Python | unset | **test only**: fixed seed sequence for reproducible covers; health reports `seeding: "test-fixed"` |
| `IOD_STEGO_RETENTION_MAX_ARTIFACTS` | Python | `0` (keep all) | artifact retention |

No variable carries a key or a secret; do not put secrets in a `.env` file for this project (none is needed).
The knowledge base is the source-controlled file `python-service/src/stego/kb/algorithm_kb.json`; it is validated when
the Python service starts and the service refuses to start with an invalid file.
