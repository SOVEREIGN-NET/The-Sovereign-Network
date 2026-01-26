#!/usr/bin/env bash
set -euo pipefail
# start/stop/restart helper for the local zhtp node used in tests
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NODE_PID_FILE="$E2E_DIR/node.pid"
NODE_LOG="$E2E_DIR/tmp/node.log"

start_node() {
  echo "Starting zhtp node..."
  if [ -f "$NODE_PID_FILE" ]; then
    pid=$(cat "$NODE_PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && ps -p "$pid" >/dev/null 2>&1; then
      echo "Node already running (pid $pid)"
      return 0
    fi
  fi
  # Use run-node.sh to start in background
  (cd "$ROOT_DIR" && ./run-node.sh > "$NODE_LOG" 2>&1 &)
  sleep 1
  # find process by name
  pid=$(pgrep -f "zhtp" | head -n1 || true)
  if [ -n "$pid" ]; then
    echo "$pid" > "$NODE_PID_FILE"
    echo "Node started (pid $pid)"
  else
    echo "Failed to start node; check $NODE_LOG"; return 1
  fi
}

stop_node() {
  echo "Stopping zhtp node..."
  if [ -f "$NODE_PID_FILE" ]; then
    pid=$(cat "$NODE_PID_FILE" || true)
    if [ -n "$pid" ] && ps -p "$pid" >/dev/null 2>&1; then
      kill "$pid" || true
      sleep 1
      if ps -p "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" || true
      fi
    fi
    rm -f "$NODE_PID_FILE" || true
  else
    # try to pkill as fallback
    pkill -f "zhtp" || true
  fi
  echo "Node stopped"
}

restart_node() {
  stop_node
  start_node
}
