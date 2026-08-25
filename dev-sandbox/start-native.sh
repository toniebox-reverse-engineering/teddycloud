#!/bin/bash
# Start TeddyCloud natively (for devcontainer when Docker is not available)
# Uses same dev-sandbox/run/ as Docker.
set -e
cd "$(dirname "$0")/.."
BIN="$(pwd)/bin/teddycloud"
RUN_DIR="$(pwd)/dev-sandbox/run"
PID_FILE="$(pwd)/dev-sandbox/.teddycloud-native.pid"

if [ ! -f "$BIN" ]; then
  echo "Error: bin/teddycloud not found. Run 'make build' first."
  exit 1
fi

if [ ! -d "$RUN_DIR" ]; then
  echo "Error: dev-sandbox/run not found. Run 'make dev-sandbox-up' first (auto-setup)."
  exit 1
fi

# Stop if already running
if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PID_FILE"
fi

"$BIN" --base_path "$RUN_DIR" &
echo $! > "$PID_FILE"
echo "TeddyCloud started (PID $(cat "$PID_FILE")). Open http://localhost"
