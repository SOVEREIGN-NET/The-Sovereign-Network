#!/usr/bin/env bash
# Observer-admission release gate.
#
# Runs the canonical observer-admission integration test suite plus the
# in-crate unit tests for the policy / rate-limit / abuse-counter modules.
# Wired into `scripts/validate-dao-ready-gates.sh` for the DAO-READY gate.
set -euo pipefail

echo "[observer-admission] Starting observer-admission release gate suite"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[observer-admission] cargo not found on PATH" >&2
  exit 2
fi

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "[observer-admission] GATE: ${name}"
  echo "[observer-admission] CMD : $*"
  "$@"
}

# Integration tests — end-to-end through executor + storage + policy.
run_gate \
  "Replay determinism for admission tx sequence" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests replay_determinism_for_admission_tx_sequence -- --nocapture

run_gate \
  "Duplicate registration rejected" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests duplicate_registration_rejected -- --nocapture

run_gate \
  "Invalid sponsor binding rejected" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests invalid_sponsor_binding_rejected -- --nocapture

run_gate \
  "Anonymous sponsor rejected by policy" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests anonymous_sponsor_rejected_by_policy -- --nocapture

run_gate \
  "Sponsor quota enforced for Basic tier" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests sponsor_quota_enforced_for_basic_tier -- --nocapture

run_gate \
  "Pending observer cannot bootstrap" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests pending_observer_cannot_bootstrap -- --nocapture

run_gate \
  "Status transitions A->S->A (suspend / reauthorize)" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests status_transitions_active_suspend_reauthorize -- --nocapture

run_gate \
  "Status transitions revoke paths (A->R, S->R, P->R) deny bootstrap" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests status_transitions_revoke_paths_all_deny_bootstrap -- --nocapture

run_gate \
  "Trusted sync source enforcement via evaluate_admission" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests trusted_sync_source_enforcement_via_evaluate_admission -- --nocapture

run_gate \
  "Expired record denied bootstrap" \
  cargo test --locked -p lib-blockchain --test observer_admission_integration_tests expired_record_denied_bootstrap -- --nocapture

# Unit tests for the canonical observer module (policy / rate_limit / abuse).
run_gate \
  "Observer module unit suite (policy + rate_limit + abuse)" \
  cargo test --locked -p lib-blockchain --lib observer

echo ""
echo "[observer-admission] All observer-admission release gates passed"
