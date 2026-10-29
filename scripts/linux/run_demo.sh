#!/usr/bin/env bash
# One-command demo launch: starts the Rust core, Python RAG service, and
# Node gateway (in that dependency order, with short delays), then
# prints the dashboard URL. Run scripts/linux/setup.sh first if you
# haven't already. Leaves all three services running in the background;
# use scripts/linux/stop_demo.sh to stop them.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PID_DIR="$ROOT_DIR/.demo-pids"
mkdir -p "$PID_DIR"

IOD_DB_PATH="${IOD_DB_PATH:-$ROOT_DIR/iod_simulation.db}"
IOD_BIND_ADDR="${IOD_BIND_ADDR:-127.0.0.1:8787}"
IOD_PYTHON_PORT="${IOD_PYTHON_PORT:-5001}"
IOD_NODE_PORT="${IOD_NODE_PORT:-4000}"
# Shared directory for the saved steganographic PNGs: the Rust core reads what
# the Python image service writes. Both processes MUST use the same path.
export IOD_STEGO_ARTIFACT_DIR="${IOD_STEGO_ARTIFACT_DIR:-$ROOT_DIR/data/stego-artifacts}"
export IOD_PYTHON_URL="${IOD_PYTHON_URL:-http://127.0.0.1:$IOD_PYTHON_PORT}"
mkdir -p "$IOD_STEGO_ARTIFACT_DIR"

echo "== Starting Rust core (iod-server) on $IOD_BIND_ADDR, db=$IOD_DB_PATH =="
cd "$ROOT_DIR/rust-core"
IOD_DB_PATH="$IOD_DB_PATH" IOD_BIND_ADDR="$IOD_BIND_ADDR" \
  nohup setsid ./target/release/iod-server > "$ROOT_DIR/.demo-rust.log" 2>&1 &
echo $! > "$PID_DIR/rust.pid"
sleep 1

echo "== Starting Python RAG service on 127.0.0.1:$IOD_PYTHON_PORT =="
cd "$ROOT_DIR/python-service"
IOD_PYTHON_PORT="$IOD_PYTHON_PORT" \
  nohup setsid ./venv/bin/python src/app.py > "$ROOT_DIR/.demo-python.log" 2>&1 &
echo $! > "$PID_DIR/python.pid"
sleep 1

echo "== Starting Node gateway on 127.0.0.1:$IOD_NODE_PORT =="
cd "$ROOT_DIR/node-server"
IOD_NODE_PORT="$IOD_NODE_PORT" IOD_RUST_BASE_URL="http://$IOD_BIND_ADDR" \
  IOD_PYTHON_BASE_URL="http://127.0.0.1:$IOD_PYTHON_PORT" \
  nohup setsid node dist/index.js > "$ROOT_DIR/.demo-node.log" 2>&1 &
echo $! > "$PID_DIR/node.pid"
sleep 1

echo ""
echo "All backend services started. PIDs recorded in $PID_DIR/"
echo "Logs: $ROOT_DIR/.demo-{rust,python,node}.log"
echo ""
echo "Now start the dashboard:"
echo "  cd $ROOT_DIR/web-ui && npm run dev"
echo "Then open http://127.0.0.1:5173"
echo ""
echo "Or, to serve the pre-built production dashboard instead of the dev server:"
echo "  npx serve $ROOT_DIR/web-ui/dist -l 5173"
echo ""
echo "Stop all backend services with: ./scripts/linux/stop_demo.sh"
