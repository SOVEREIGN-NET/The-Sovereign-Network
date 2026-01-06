#!/usr/bin/env bash
set -euo pipefail
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

assert_equal() {
  a=$1
  b=$2
  msg=${3:-"assert_equal failed"}
  if [ "$a" != "$b" ]; then
    echo "$msg: expected '$b' but got '$a'"
    echo "Collecting debug info..."
    echo "Last CLI output:"
    sed -n '1,200p' "$E2E_DIR/tmp/last_cli_output.json" || true
    exit 6
  fi
}

assert_contains() {
  hay=$1
  needle=$2
  if ! echo "$hay" | grep -qF "$needle"; then
    echo "assert_contains failed: missing '$needle'"
    exit 7
  fi
}
