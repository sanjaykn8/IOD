#!/usr/bin/env bash
# One-time setup: builds the Rust core, installs Node dependencies,
# creates the Python virtualenv and installs its dependencies, and
# installs React dashboard dependencies.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "== Checking prerequisites =="
command -v cargo >/dev/null || { echo "cargo not found - install Rust (https://rustup.rs, or your distro's rustc/cargo package)"; exit 1; }
command -v node >/dev/null || { echo "node not found - install Node.js 18+"; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found - install Python 3.9+"; exit 1; }

echo "== Building Rust core (this also downloads and compiles all Rust dependencies) =="
cd "$ROOT_DIR/rust-core"
cargo build --release

echo "== Installing Node gateway dependencies =="
cd "$ROOT_DIR/node-server"
npm install
npm run build

echo "== Setting up Python RAG service =="
cd "$ROOT_DIR/python-service"
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "== Installing React dashboard dependencies =="
cd "$ROOT_DIR/web-ui"
npm install
npm run build

echo ""
echo "Setup complete. Next: ./scripts/linux/run_demo.sh"
