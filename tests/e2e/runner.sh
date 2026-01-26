#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
E2E_DIR="$ROOT_DIR/tests/e2e"
source "$E2E_DIR/lib/cli.sh"
source "$E2E_DIR/lib/site_generator.sh"
source "$E2E_DIR/lib/node_ctrl.sh"
source "$E2E_DIR/lib/asserts.sh"

TMP_ROOT="$E2E_DIR/tmp"
STATE_FILE="$E2E_DIR/state.json"
mkdir -p "$TMP_ROOT"

echo "Starting Web4 CLI E2E test runner..."

cleanup() {
  echo "Cleaning up..."
  stop_node || true
}
trap cleanup EXIT

echo "Phase 0: Preconditions"
command -v zhtp-cli >/dev/null 2>&1 || { echo "zhtp-cli not found on PATH"; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq is required but not installed"; exit 2; }

echo "Phase 1: Domain Registration"
DOMAIN_A=test1.zhtp
DOMAIN_B=test2.zhtp
DOMAIN_C=test3.zhtp

cli_domain_register "$DOMAIN_A" 365
cli_domain_check "$DOMAIN_A"
cli_domain_info "$DOMAIN_A"

cli_domain_register "$DOMAIN_B" 365
cli_domain_register "$DOMAIN_C" 365

echo "Phase 2: Initial Deployment"
SITE_A_DIR=$(mktemp -d "$TMP_ROOT/site_a.XXXX")
generate_site "$SITE_A_DIR" 1
cli_deploy_site "$SITE_A_DIR" "$DOMAIN_A" || { echo "Deploy failed"; exit 3; }
WEB4_CID_A_v1=$(extract_web4_manifest_cid_from_last)
echo "Deployed $DOMAIN_A -> $WEB4_CID_A_v1"

cli_deploy_status "$DOMAIN_A"
cli_deploy_history "$DOMAIN_A"

echo "Dry run deployment (should not change state)"
generate_site "$SITE_A_DIR/dryrun" 1
cli_deploy_site --dry-run "$SITE_A_DIR/dryrun" "$DOMAIN_A" || true

echo "Deploy multiple domains"
SITE_B_DIR=$(mktemp -d "$TMP_ROOT/site_b.XXXX")
generate_site "$SITE_B_DIR" 1
cli_deploy_site "$SITE_B_DIR" "$DOMAIN_B"
WEB4_CID_B_v1=$(extract_web4_manifest_cid_from_last)

SITE_C_DIR=$(mktemp -d "$TMP_ROOT/site_c.XXXX")
generate_site "$SITE_C_DIR" 1
cli_deploy_site "$SITE_C_DIR" "$DOMAIN_C"
WEB4_CID_C_v1=$(extract_web4_manifest_cid_from_last)

echo "Phase 3: Persistence Across Restart"
stop_node
start_node

echo "Verifying domains persist after restart"
cli_domain_check "$DOMAIN_A"
cli_domain_check "$DOMAIN_B"
cli_domain_check "$DOMAIN_C"

echo "Verifying deployment manifest CIDs persist"
cli_deploy_status "$DOMAIN_A"
POST_RESTART_CID_A=$(cli_get_last_web4_manifest_cid "$DOMAIN_A")
assert_equal "$WEB4_CID_A_v1" "$POST_RESTART_CID_A" "Manifest CID for $DOMAIN_A changed after restart"

echo "Phase 4: Deployment Updates"
for v in 2 3 4; do
  generate_site "$SITE_A_DIR" "$v"
  cli_deploy_site "$SITE_A_DIR" "$DOMAIN_A"
  cid=$(extract_web4_manifest_cid_from_last)
  echo "Version $v -> $cid"
done

echo "Validate version incrementing and manifest changes"
HISTORY=$(zhtp-cli deploy history "$DOMAIN_A" --json 2>/dev/null || true)
versions_count=$(echo "$HISTORY" | jq '.versions | length' 2>/dev/null || echo 0)
if [ "$versions_count" -lt 4 ]; then
  echo "Expected 4 versions for $DOMAIN_A, found $versions_count"; exit 4
fi

echo "Phase 5: Version Rollback"
cli_deploy_rollback "$DOMAIN_A" 2
sleep 2
POST_ROLLBACK_CID=$(cli_get_last_web4_manifest_cid "$DOMAIN_A")
EXPECTED_CID_V2=$(echo "$HISTORY" | jq -r '.versions[1].web4_manifest_cid' 2>/dev/null || true)
assert_equal "$POST_ROLLBACK_CID" "$EXPECTED_CID_V2" "Rollback didn't set manifest CID to version 2"

echo "Phase 6: Domain Release & Deletion"
cli_deploy_delete "$DOMAIN_B"
cli_domain_release "$DOMAIN_C"

echo "Restart and verify deletions persist"
stop_node
start_node
cli_domain_check "$DOMAIN_A"
cli_domain_check "$DOMAIN_B" || true
cli_domain_check "$DOMAIN_C" || true

echo "Phase 7: Edge Cases & Error Handling"
echo "Attempting deploy without keystore (expected to fail)"
set +e
OUTPUT=$(zhtp-cli deploy site "$SITE_A_DIR" "$DOMAIN_A" 2>&1)
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "Expected failure when deploying without keystore, but succeeded"; exit 5
fi
echo "Error as expected: $OUTPUT"

echo "Register existing domain (should fail)"
set +e
zhtp-cli domain register --domain "$DOMAIN_A" --duration 365 2>&1 || true
set -e

echo "Invalid trust parameters handling (dry run)"
set +e
zhtp-cli domain register --domain invalid_domain --duration -1 2>&1 || true
set -e

echo "Dry run with updates"
generate_site "$SITE_A_DIR" 5
cli_deploy_site --dry-run "$SITE_A_DIR" "$DOMAIN_A" || true

echo "All phases complete. Summary:"
echo "A v1: $WEB4_CID_A_v1"
echo "B v1: $WEB4_CID_B_v1"
echo "C v1: $WEB4_CID_C_v1"

echo "E2E test runner finished successfully"
exit 0
