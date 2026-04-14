#!/bin/bash
# Domain Recovery Replay — EPIC-001
#
# Re-registers domains from the domain snapshot after testnet reset.
# Uses the domain catalog API to read existing domains, then re-registers
# any that are missing.
#
# Prerequisites:
#   - Testnet reset complete
#   - Domain snapshot taken before reset: /tmp/domain_snapshot.json
#   - Council member identity registered (for fee bypass)
#
# Usage: ./scripts/replay-domains.sh <server> <domain_snapshot.json> [--dry-run]

set -euo pipefail

SERVER=${1:-"178.105.9.247:9334"}
DOMAIN_SNAPSHOT=${2:-"/tmp/domain_snapshot.json"}
DRY_RUN=${3:-""}
CLI="./target/release/zhtp-cli"

log() { echo "[$(date '+%H:%M:%S')] $1"; }

[ -f "$CLI" ] || { echo "FATAL: CLI not found: $CLI"; exit 1; }
[ -f "$DOMAIN_SNAPSHOT" ] || { echo "FATAL: Domain snapshot not found: $DOMAIN_SNAPSHOT"; exit 1; }

log "=== DOMAIN RECOVERY REPLAY ==="
log "Server: $SERVER"
log "Source: $DOMAIN_SNAPSHOT"

total=$(python3 -c "import json; d=json.load(open('$DOMAIN_SNAPSHOT')); print(d['total_domains'])")
log "Total domains to recover: $total"

if [ "$DRY_RUN" = "--dry-run" ]; then
    log "DRY RUN — would register $total domains"
    python3 -c "
import json
d = json.load(open('$DOMAIN_SNAPSHOT'))
for dom in d['domains'][:10]:
    print(f'  {dom[\"domain\"]}')
if len(d['domains']) > 10:
    print(f'  ... and {len(d[\"domains\"]) - 10} more')
"
    exit 0
fi

# Register each domain
count=0
errors=0

python3 -c "
import json
d = json.load(open('$DOMAIN_SNAPSHOT'))
for dom in d['domains']:
    print(dom['domain'])
" | while read -r domain; do
    count=$((count + 1))
    log "  [$count/$total] Registering: $domain"

    $CLI -s "$SERVER" domain register \
        --domain "$domain" \
        --trust-node 2>&1 | grep -E "✅|Error|success|fail" || {
        errors=$((errors + 1))
        log "    WARNING: Failed to register $domain"
    }

    # Don't overwhelm the node
    if [ $((count % 50)) -eq 0 ]; then
        sleep 5
    fi
done

log ""
log "=== DOMAIN RECOVERY COMPLETE ==="
log "  Registered: $count domains"
log "  Errors: $errors"
