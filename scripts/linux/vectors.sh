#!/usr/bin/env bash
# Regenerates the protocol test vectors (examples/test-vectors/generated_vectors.json).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR/rust-core"
mkdir -p "$ROOT_DIR/examples/test-vectors"
cargo run --release --bin iod-vectors -- "$ROOT_DIR/examples/test-vectors"
