#!/usr/bin/env bash
# GENESIS-2 (#2730): replay acceptance gate (CI synthetic path).
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
  "Genesis bootstrap checkpoint (SOV shell + allocations + legacy CBE 20B)" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    test_genesis_bootstrap_checkpoint_balances -- --nocapture

run_gate \
  "SOV-native wipe-and-replay parity" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    test_sov_native_wipe_replay_parity -- --nocapture

run_gate \
  "DAO TokenCreation + custom-token wipe-and-replay parity" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    test_dao_token_creation_wipe_replay_parity -- --nocapture

run_gate \
  "replay_gate comparator unit tests" \
  cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \
    replay_gate::tests -- --nocapture

echo ""
echo "[genesis-replay-gate] All GENESIS-2 CI gates passed"
echo "[genesis-replay-gate] Manual g4 fixture (testnet maintainer, pre-deploy):"
echo "  cargo run -p tools --bin export_replay_fixture -- <sled-path> <out-dir> --to-height 74010"
echo "  G4_REPLAY_BLOCKS_PATH=<out>/blocks.v1.bin G4_REPLAY_SNAPSHOT_PATH=<out>/checkpoint.json \\"
echo "    cargo test --locked -p lib-blockchain --test g4_replay_acceptance_tests \\"
echo "      test_g4_checkpoint_replay_acceptance -- --ignored --nocapture"