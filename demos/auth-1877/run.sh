#!/usr/bin/env bash
# AUTH-1877 Demo — fully self-contained, run from anywhere
# Auto-installs Rust if not present, then builds and runs the demo.
# Usage: ./demos/auth-1877/run.sh   (from repo root or any path)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"
NODE_URL="http://localhost:9334"
DATA_DIR="$DEMO_DIR/data"
NODE_PID=""

cd "$REPO_ROOT"

# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "--- Shutting down demo node ---"
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID"
    wait "$NODE_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
  echo "Done."
}
trap cleanup EXIT INT TERM

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   AUTH-1877  End-to-End Demo              ║"
echo "║   Mobile + Web Auth Delegation            ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Rust / cargo
# ─────────────────────────────────────────────────────────────────────────────
echo "[DEP] Checking Rust toolchain..."

# Source cargo env if present (covers cases where rustup was already installed
# but the shell hasn't been restarted)
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

if ! command -v cargo &>/dev/null; then
  echo "      cargo not found — downloading rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal

  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"

  if ! command -v cargo &>/dev/null; then
    echo "ERROR: Rust installation succeeded but cargo still not found."
    echo "       Close this terminal, open a new one, and re-run."
    exit 1
  fi
  echo "      Rust installed."
else
  echo "      Found: $(cargo --version)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Build
# ─────────────────────────────────────────────────────────────────────────────
echo "[1/4] Building zhtp node and demo example..."
echo "      (first build ~5 min; subsequent builds are incremental)"
cargo build --release -p zhtp 2>&1 | grep -E "^error|Compiling|Finished" | sed 's/^/      /' || true

NODE_BIN="$REPO_ROOT/target/release/zhtp"
if [ ! -f "$NODE_BIN" ]; then
  echo "ERROR: Build failed — binary not found at $NODE_BIN"
  exit 1
fi
echo "      Build complete."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Start demo node
# ─────────────────────────────────────────────────────────────────────────────
echo "[2/4] Starting demo node  (chain: auth-demo  port: 9334)..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

"$NODE_BIN" \
  --config "$DEMO_DIR/node.toml" \
  --data-dir "$DATA_DIR" \
  > "$DEMO_DIR/node.log" 2>&1 &
NODE_PID=$!
echo "      PID $NODE_PID   logs: demos/auth-1877/node.log"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Wait for node ready
# ─────────────────────────────────────────────────────────────────────────────
printf "[3/4] Waiting for node on %s" "$NODE_URL"
READY=0
for i in $(seq 1 45); do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo ""
    echo "ERROR: Node exited unexpectedly. Last log lines:"
    tail -25 "$DEMO_DIR/node.log" 2>/dev/null || true
    exit 1
  fi
  if curl -sf -o /dev/null -X POST "$NODE_URL/api/v1/auth/mobile/challenge" \
      -H "Content-Type: application/json" \
      -d '{"capabilities":[]}' 2>/dev/null; then
    READY=1
    break
  fi
  printf "."
  sleep 2
done

echo ""
if [ "$READY" -eq 0 ]; then
  echo "ERROR: Node did not become ready after 90s. Last log lines:"
  tail -25 "$DEMO_DIR/node.log" 2>/dev/null || true
  exit 1
fi
echo "      Node ready."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — CLI demo (real Dilithium5 keys)
# ─────────────────────────────────────────────────────────────────────────────
echo "[4/4] Running CLI demo (real Dilithium5 keys)..."
echo ""
NODE_URL="$NODE_URL" cargo run --release --example mobile_auth_demo --package zhtp
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Browser demo
# ─────────────────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════╗"
echo "║  Browser demo available at:              ║"
echo "║  $NODE_URL/auth-demo"
echo "╚══════════════════════════════════════════╝"
echo ""

# Try to open browser (non-fatal if it fails)
if command -v xdg-open &>/dev/null; then
  xdg-open "$NODE_URL/auth-demo" &>/dev/null &
elif command -v open &>/dev/null; then
  open "$NODE_URL/auth-demo" &>/dev/null &
fi

echo "Node is running. Press Ctrl+C to stop and clean up."
echo ""
wait "$NODE_PID"
