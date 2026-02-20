#!/usr/bin/env bash
set -euo pipefail

echo "[token-dao-gates] Starting TOKEN-DAO readiness gate suite"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[token-dao-gates] cargo not found on PATH" >&2
  exit 2
fi

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "[token-dao-gates] GATE: ${name}"
  echo "[token-dao-gates] CMD : $*"
  "$@"
}

# ContractExecution token mutation rejection.
run_gate \
  "ContractExecution burn rejection" \
  cargo test -p lib-blockchain --test token_regression_tests test_contract_execution_burn_rejected -- --nocapture

run_gate \
  "ContractExecution transfer rejection" \
  cargo test -p lib-blockchain --test token_regression_tests test_contract_execution_transfer_rejected -- --nocapture

# Restart equivalence / replay protection / cross-node convergence / crash safety.
run_gate \
  "Token restart snapshot + nonce restoration" \
  cargo test -p lib-blockchain --test token_snapshot_restart_tests test_restart_restores_token_snapshot_and_nonces -- --nocapture

run_gate \
  "Nonce replay rejection after restart" \
  cargo test -p lib-blockchain --test token_regression_tests test_replay_protection_rejects_duplicate_nonce -- --nocapture

run_gate \
  "Cross-node deterministic token reconstruction" \
  cargo test -p lib-blockchain --test token_snapshot_restart_tests test_cross_node_loads_converge_to_identical_token_state -- --nocapture

run_gate \
  "Crash safety to last committed block" \
  cargo test -p lib-blockchain --test token_snapshot_restart_tests test_uncommitted_block_does_not_leak_token_state_after_restart -- --nocapture

# Contract deploy + DAO lifecycle deterministic replay.
run_gate \
  "Contract + DAO multinode replay convergence" \
  cargo test -p lib-blockchain --test contract_dao_multinode_e2e test_multinode_contract_dao_lifecycle_sync_and_replay_convergence -- --nocapture

echo ""
echo "[token-dao-gates] All TOKEN-DAO readiness gates passed"
