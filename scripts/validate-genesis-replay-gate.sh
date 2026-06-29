#!/usr/bin/env bash
# GENESIS-2 (#2730): g4 replay acceptance gate (CI synthetic path).
#
# Proves wipe-and-replay via genesis bootstrap matches live SOV + CBE treasury
# state. The full g4 74k+ fixture is a manual gate — see docs/arch/genesis-bootstrap-surface.md §6.
set -euo pipefail

echo "[genesis-replay-gate] Starting GENESIS-2 acceptance suite"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[genesis-replay-gate] cargo not found on PATH" >&2
  exit 2
fi

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "[genesis-replay-gate] GATE: ${name}"
  echo "[genesis-replay-gate] CMD : $*"
  "$@"
}

run_gate \
  "Genesis bootstrap checkpoint (SOV shell + allocations + CBE 20B)" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    test_genesis_bootstrap_checkpoint_balances -- --nocapture

run_gate \
  "Wipe-and-replay parity (export → fresh sled → import_blocks)" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    test_genesis_bootstrap_wipe_replay_parity -- --nocapture

echo ""
echo "[genesis-replay-gate] All GENESIS-2 CI gates passed"
echo "[genesis-replay-gate] Manual g4 fixture (>=74010):"
echo "  export G4_REPLAY_BLOCKS_PATH=/path/to/blocks.bin"
echo "  export G4_REPLAY_SNAPSHOT_PATH=/path/to/checkpoint.json"
echo "  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \\"
echo "    test_g4_checkpoint_replay_acceptance -- --ignored --nocapture"