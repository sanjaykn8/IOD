#!/usr/bin/env bash
# Runs the real, measured benchmark suite (release mode).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR/rust-core"
cargo run --release --bin iod-bench
