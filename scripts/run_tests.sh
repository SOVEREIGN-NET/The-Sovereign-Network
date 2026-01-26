#!/usr/bin/env bash
set -euo pipefail

# Lightweight test runner for the workspace
echo "[run_tests] Starting workspace tests"

if [ -z "${RUST_LOG:-}" ]; then
  export RUST_LOG=info
  echo "[run_tests] RUST_LOG not set; defaulting to $RUST_LOG"
else
  echo "[run_tests] RUST_LOG=$RUST_LOG"
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[run_tests] cargo not found on PATH" >&2
  exit 2
fi

cargo test --workspace -- --nocapture
rc=$?
if [ $rc -ne 0 ]; then
  echo "[run_tests] Tests failed with exit code $rc" >&2
  exit $rc
fi

echo "[run_tests] All tests passed"
exit 0
