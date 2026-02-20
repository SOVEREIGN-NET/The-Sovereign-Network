#!/usr/bin/env bash
set -euo pipefail

echo "[dao-ready-gates] Starting DAO-READY release gate suite"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[dao-ready-gates] cargo not found on PATH" >&2
  exit 2
fi

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "[dao-ready-gates] GATE: ${name}"
  echo "[dao-ready-gates] CMD : $*"
  "$@"
}

# Canonical token mutation path enforcement.
run_gate \
  "ContractExecution burn rejection" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_contract_execution_burn_rejected -- --nocapture

run_gate \
  "ContractExecution transfer rejection" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_contract_execution_transfer_rejected -- --nocapture

# Token mint authorization parity.
run_gate \
  "TokenMint creator authorization accepted" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_mint_custom_token_by_creator -- --nocapture

run_gate \
  "TokenMint unauthorized signer rejected" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_mint_custom_token_unauthorized_rejected -- --nocapture

# Treasury-kernel enforcement.
run_gate \
  "TreasuryKernel mint missing auth rejected" \
  cargo test --locked -p lib-blockchain --lib test_execute_authorized_mint_missing_auth_fails -- --nocapture

run_gate \
  "TreasuryKernel burn delay enforced" \
  cargo test --locked -p lib-blockchain --lib test_execute_authorized_burn_before_delay_fails -- --nocapture

# Restart/replay/cross-node/crash safety.
run_gate \
  "Token restart snapshot + nonce restoration" \
  cargo test --locked -p lib-blockchain --test token_snapshot_restart_tests test_restart_restores_token_snapshot_and_nonces -- --nocapture

run_gate \
  "Nonce replay rejection after restart" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_replay_protection_rejects_duplicate_nonce -- --nocapture

run_gate \
  "Cross-node deterministic token reconstruction" \
  cargo test --locked -p lib-blockchain --test token_snapshot_restart_tests test_cross_node_loads_converge_to_identical_token_state -- --nocapture

run_gate \
  "Crash safety to last committed block" \
  cargo test --locked -p lib-blockchain --test token_snapshot_restart_tests test_uncommitted_block_does_not_leak_token_state_after_restart -- --nocapture

# Contract deploy/call and DAO lifecycle determinism.
run_gate \
  "Contract + DAO multinode replay convergence" \
  cargo test --locked -p lib-blockchain --test contract_dao_multinode_e2e test_multinode_contract_dao_lifecycle_sync_and_replay_convergence -- --nocapture

run_gate \
  "DAO proposal tx integration path" \
  cargo test --locked -p lib-blockchain --test consensus_integration_tests test_dao_proposal_creation -- --nocapture

run_gate \
  "DAO vote tx integration path" \
  cargo test --locked -p lib-blockchain --test consensus_integration_tests test_dao_vote_creation -- --nocapture

echo ""
echo "[dao-ready-gates] All DAO-READY release gates passed"
