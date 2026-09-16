#!/usr/bin/env bash
# Runs every automated test suite in the project.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "== Rust: unit + integration + security-negative tests =="
cd "$ROOT_DIR/rust-core" && cargo test

echo ""
echo "== Python: RAG pipeline unit tests =="
cd "$ROOT_DIR/python-service" && ./venv/bin/python -m pytest tests/ -v

echo ""
echo "== React: type-check + production build =="
cd "$ROOT_DIR/web-ui" && npx tsc -b && npx vite build

echo ""
echo "All test suites passed."
