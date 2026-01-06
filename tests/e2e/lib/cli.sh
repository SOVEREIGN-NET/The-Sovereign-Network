#!/usr/bin/env bash
set -euo pipefail
# CLI wrappers for zhtp-cli
E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR="$E2E_DIR/tmp"
mkdir -p "$TMP_DIR"
LAST_OUTPUT="$TMP_DIR/last_cli_output.json"

run_cli() {
  # usage: run_cli <args...>
  (set -o pipefail; zhtp-cli "$@") > "$LAST_OUTPUT" 2>&1 || return $?
}

extract_web4_manifest_cid_from_last() {
  if [ -f "$LAST_OUTPUT" ]; then
    jq -r '(.web4_manifest_cid // .result.web4_manifest_cid // .manifest.web4_manifest_cid // .web4ManifestCid) | select(.!=null)' "$LAST_OUTPUT" 2>/dev/null || true
  fi
}

cli_domain_register() {
  domain=$1
  duration=$2
  echo "Registering domain $domain"
  run_cli domain register --domain "$domain" --duration "$duration" --keystore ~/.zhtp/keystore || true
}

cli_domain_check() {
  domain=$1
  echo "Checking domain $domain"
  run_cli domain check --domain "$domain" || true
}

cli_domain_info() {
  domain=$1
  echo "Domain info $domain"
  run_cli domain info --domain "$domain" || true
}

cli_deploy_site() {
  # usage: cli_deploy_site [--dry-run] <site_dir> <domain>
  if [ "$1" = "--dry-run" ]; then
    shift
    dry=1
  else
    dry=0
  fi
  site_dir=$1
  domain=$2
  echo "Deploying site $site_dir -> $domain (dry=$dry)"
  if [ "$dry" -eq 1 ]; then
    run_cli deploy site --dry-run "$site_dir" --domain "$domain" --keystore ~/.zhtp/keystore || true
  else
    run_cli deploy site "$site_dir" --domain "$domain" --keystore ~/.zhtp/keystore || true
  fi
}

cli_deploy_status() {
  domain=$1
  echo "Deployment status for $domain"
  run_cli deploy status "$domain" --json || true
}

cli_deploy_history() {
  domain=$1
  echo "Deployment history for $domain"
  run_cli deploy history "$domain" --json || true
}

cli_deploy_delete() {
  domain=$1
  echo "Deleting deployment for $domain"
  run_cli deploy delete --domain "$domain" --keystore ~/.zhtp/keystore || true
}

cli_domain_release() {
  domain=$1
  echo "Releasing domain $domain"
  run_cli domain release --domain "$domain" --keystore ~/.zhtp/keystore || true
}

cli_deploy_rollback() {
  domain=$1
  to_version=$2
  echo "Rolling back $domain to version $to_version"
  run_cli deploy rollback --domain "$domain" --to-version "$to_version" --keystore ~/.zhtp/keystore || true
}

cli_get_last_web4_manifest_cid() {
  domain=$1
  out=$(zhtp-cli deploy status "$domain" --json 2>/dev/null || true)
  echo "$out" | jq -r '(.web4_manifest_cid // .result.web4_manifest_cid // .manifest.web4_manifest_cid // .current.web4_manifest_cid) // empty' || true
}
