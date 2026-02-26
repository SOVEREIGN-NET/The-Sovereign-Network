#!/usr/bin/env bash
set -euo pipefail

echo "[oracle-v1-gates] Starting Oracle v1 determinism/safety gate suite"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[oracle-v1-gates] cargo not found on PATH" >&2
  exit 2
fi

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "[oracle-v1-gates] GATE: ${name}"
  echo "[oracle-v1-gates] CMD : $*"
  "$@"
}

# Baseline guard must remain green.
run_gate \
  "ContractExecution transfer rejection" \
  cargo test --locked -p lib-blockchain --test token_regression_tests test_contract_execution_transfer_rejected -- --nocapture

# Oracle finalization + admission determinism.
run_gate \
  "Oracle precheck parity with execution admission" \
  cargo test --locked -p lib-blockchain oracle_precheck_matches_execution_admission -- --nocapture

run_gate \
  "Oracle first-threshold-wins finalization" \
  cargo test --locked -p lib-blockchain oracle_finalizes_first_price_to_threshold_and_rejects_conflicts -- --nocapture

run_gate \
  "Oracle duplicate/out-of-epoch attestation handling" \
  cargo test --locked -p lib-blockchain oracle_ignores_out_of_epoch_and_duplicate_attestations -- --nocapture

# Replay/restart determinism.
run_gate \
  "Cross-node replay reconstructs identical finalized prices" \
  cargo test --locked -p lib-blockchain oracle_replay_reconstructs_identical_finalized_prices -- --nocapture

run_gate \
  "Duplicate/replay slashing evidence remains deterministic after restart" \
  cargo test --locked -p lib-blockchain oracle_slashing_restart_replay_is_deterministic -- --nocapture

# Crash safety / persistence boundary for oracle state writes.
run_gate \
  "Oracle state round-trip persistence" \
  cargo test --locked -p lib-blockchain --test oracle_state_persistence_tests oracle_state_round_trip_persists_finalized_prices -- --nocapture

run_gate \
  "Oracle unsaved updates do not survive restart" \
  cargo test --locked -p lib-blockchain --test oracle_state_persistence_tests oracle_state_unsaved_updates_do_not_survive_restart -- --nocapture

# Graduation oracle gate determinism.
run_gate \
  "CBE graduation requires finalized, fresh oracle price and threshold" \
  cargo test --locked -p lib-blockchain --test oracle_cbe_graduation_gating_tests -- --nocapture

# Runtime/API side-path hard-disable verification.
run_gate \
  "Runtime/API buy path cannot auto-graduate" \
  cargo test --locked -p zhtp buy_handler_does_not_auto_graduate_token -- --nocapture

echo ""
echo "[oracle-v1-gates] All Oracle v1 determinism/safety gates passed"
