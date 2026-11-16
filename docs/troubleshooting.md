# Troubleshooting

## Rust build fails with "requires rustc X.YY or newer" for some transitive dependency

This project was developed against rustc 1.75.0 (historical; v2 uses rustc 1.97) and several dependency
versions are pinned in `rust-core/Cargo.toml` specifically to stay
buildable on that toolchain (see `docs/dependency-rationale.md`). If
you're on a newer Rust toolchain (which is fine and expected for most
users), these pins should still work; if a *new* transitive dependency
update breaks the build on your machine, run:

```bash
cd rust-core
cargo update -p <offending-crate> --precise <a version compatible with your toolchain>
```

If you have Rust ≥1.77 available, you can also switch `pqcrypto-kyber`/
`pqcrypto-dilithium` back to `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS
203/204-final implementations) and relax the `zeroize`/`getrandom`/
`uuid`/`jobserver` pins — none of this project's own code depends on the
pinned versions specifically, only on the trait/API surface those crates
expose, which is stable across the pinned and current versions.

## `cargo build` fails trying to compile SQLite (`libsqlite3-sys`)

`rusqlite`'s `bundled` feature compiles SQLite's C amalgamation as part
of the build, which needs a C compiler. Install `build-essential` (Linux)
or the Visual Studio Build Tools / MSVC toolchain (Windows) — see
`scripts/*/setup.*` for the exact commands used in this repo's own setup.

## Port already in use (8787, 4000, 5001, or 5173)

Another instance of a service (from a previous run) may still be
listening. On Linux/macOS: `pkill -f iod-server`, `pkill -f "node dist/index.js"`,
`pkill -f "python.*app.py"`. On Windows: use Task Manager or
`Stop-Process` for the relevant `iod-server.exe`/`node.exe`/`python.exe`
process. Alternatively, set `IOD_BIND_ADDR`, `IOD_NODE_PORT`, or
`IOD_PYTHON_PORT` to a free port (see `.env.example`).

## Node gateway reports `rust_core_reachable: false` from `/api/health`

The Rust `iod-server` process isn't running or isn't reachable at
`IOD_RUST_BASE_URL` (default `http://127.0.0.1:8787`). Start it first;
the Node gateway has no dependency-ordering enforcement of its own (a
documented simplification — `scripts/*/run_demo.*` starts services in
the correct order with short delays between them).

## Authentication always denies with `PUF_VERIFICATION_FAILED`

Check that both drones are registered to the SAME group — GCS's M6 check
looks up the CRP reference by drone identity, not by group, so this
specific reason code shouldn't be caused by a group mismatch (that fails
earlier, at M2, with a different error) — but it CAN happen if a drone
was revoked and reactivated (a reactivation calls `register_drone` again,
which regenerates a NEW PUF-derived key/CRP reference internally); make
sure you're testing against the freshest state (`GET /api/drones/:id`)
rather than a stale cached value from before a revoke/reactivate cycle.

## React dev server shows a blank page or network errors in the console

Confirm all three backend services are running and reachable (`curl
http://127.0.0.1:4000/api/health`). The dashboard's `VITE_API_BASE`
environment variable (see `web-ui/.env.example` if present, or the
default in `web-ui/src/services/api.ts`) must point at the Node gateway,
not directly at Rust or Python.

## SQLite database seems to have stale/duplicate data

Use the Settings page's "Reset Simulation" button, or `POST
/api/reset`, or simply delete the `iod_simulation.db` file while the
Rust server is stopped (a fresh one is created automatically on next
start).

## Python `pip install` fails on `Flask-Cors` or similar

Ensure you're using the project's virtualenv (`python-service/venv`),
not a system Python — the setup scripts create this automatically. If
building from scratch, Python 3.9+ is required.

## Cover generation errors in the Steganography Lab

There is no camera or upload any more: every transmission generates its own cover inside the Python image service.

* `GENERATOR_CONFIG_INVALID` (400): a setting is outside the active profile. Requests can only tighten it (see the limits printed next to each field, or `GET /api/stego/status` → `config.cover_generation`). Width and height must be multiples of 8. Fields such as `cover`, `seed`, `cover_id` are no longer accepted.
* `PATCH_CAPACITY_INSUFFICIENT` with reason `embedding_rate_above_limit`: the message is larger than 0.20 payload bits per cover sample allows at the requested size (5760 bytes at 320×240 RGB). Shorten it, raise width/height within the ceiling, or tick *Payload-driven resize*.
* `COVER_QUALITY_REJECTED`: every candidate failed a coherence gate or the score floor; the candidate table lists the reasons. Rare at the default size — send again (a new cover is drawn) or allow two candidates.
* `GENERATION_BUDGET_EXCEEDED`: the processing budget ran out before a candidate could be planned (slow or busy machine, large cover). Lower the size or the candidate count, or raise `IOD_STEGO_GENERATOR_BUDGET_MS` for both services.
* `GENERATOR_MEMORY_LIMIT`: the pre-flight estimate for this size × candidates exceeds `max_working_memory_mb`.
* The Rust core or the Python service refuses to start with "generator configuration: …": an `IOD_STEGO_GENERATOR_*` variable is out of bounds. Both processes must be given the **same** values; if they differ the service rejects the core's requests with `GENERATOR_CONFIG_INVALID`.
* Health shows `seeding: "test-fixed"`: `IOD_STEGO_GENERATOR_TEST_SEED` is set. Unset it outside tests.
* After upgrading over an older copy run `scripts/windows/remove_stale_files.ps1` (or the Linux script): it deletes the removed camera/upload modules (`stego/cover.py`, `stego-webcam.tsx`, their tests).

## Build fails with `pythonClient.ts ... pythonBaseUrl` or `"RagPage" is not exported`

The release was extracted **over** an older copy. Unzipping never deletes files, so modules that the
patch-wise redesign removed (for example `node-server/src/services/pythonClient.ts` and
`web-ui/src/routes/rag.tsx`) are still on disk and still compiled. Run the cleanup, then setup again:

```powershell
.\scripts\windows\remove_stale_files.ps1      # Linux/macOS: ./scripts/linux/remove_stale_files.sh
.\scripts\windows\setup.ps1
```

`setup.ps1` / `setup.sh` now run this cleanup automatically, stop at the first failing step, and install the
exact dependency versions from `package-lock.json` (`npm ci`). Do not run `npm audit fix --force`: it upgrades
packages past the tested versions (major versions of vite, zod and typescript-eslint). If you already did, restore
`web-ui/package.json` and `web-ui/package-lock.json` from the release zip before running setup. The reported
advisories are in development tooling (linter dependencies), not in code that runs in the dashboard or services.
