#!/usr/bin/env bash
# Stops the background services started by run_demo.sh.
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PID_DIR="$ROOT_DIR/.demo-pids"

for name in rust python node; do
  pidfile="$PID_DIR/$name.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if kill "$pid" 2>/dev/null; then
      echo "Stopped $name (pid $pid)"
    else
      echo "$name (pid $pid) was not running"
    fi
    rm -f "$pidfile"
  fi
done
