#!/usr/bin/env bash
# Rebuilds every component (assumes setup.sh has already been run once
# so dependencies are installed).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "== Rust core =="
cd "$ROOT_DIR/rust-core" && cargo build --release

echo "== Node gateway =="
cd "$ROOT_DIR/node-server" && npm run build

echo "== React dashboard =="
cd "$ROOT_DIR/web-ui" && npm run build

echo "Build complete."
