# Development Guide

## Prerequisites

- Rust (stable toolchain; developed and tested against 1.75.0 — see
  `docs/dependency-rationale.md` for why some dependency versions are
  pinned). `cargo` and `rustc` on `PATH`.
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

# Python RAG service
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

# Terminal 2 — Python RAG service
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
