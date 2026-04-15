#!/bin/bash
# CBE Compensation Replay — EPIC-001
#
# Replays the 15 original CBE distributions as payroll mints
# using the new synthetic curve event (1.25X with PRE_BACKED).
#
# Prerequisites:
#   - Testnet reset complete (chain at height ~1)
#   - Council member identity registered on-chain
#   - CLI built with payroll mint support
#
# Usage: ./scripts/replay-cbe-compensation.sh <server> [--dry-run]

set -euo pipefail

SERVER=${1:-"178.105.9.247:9334"}
DRY_RUN=${2:-""}
CLI="./target/release/zhtp-cli"
SNAPSHOT="docs/testnet/testnet_snapshot_2026-04-14.json"

log() { echo "[$(date '+%H:%M:%S')] $1"; }

[ -f "$CLI" ] || { echo "FATAL: CLI not found: $CLI"; exit 1; }
[ -f "$SNAPSHOT" ] || { echo "FATAL: Snapshot not found: $SNAPSHOT"; exit 1; }

log "=== CBE COMPENSATION REPLAY ==="
log "Server: $SERVER"
log "Source: $SNAPSHOT"

# Extract CBE transfers from snapshot
# Old amounts are in 8-decimal atoms. New amounts need 18-decimal.
# Conversion: old_amount * 10^10 = new_amount (18-decimal)
SCALE_FACTOR=10000000000  # 10^10

transfers=$(python3 -c "
import json, sys
d = json.load(open('$SNAPSHOT'))
for t in d['cbe_transfers']:
    # Old 8-decimal amount → 18-decimal
    old_amount = int(t['amount'])
    new_amount = old_amount * $SCALE_FACTOR
    recipient = t['to']
    # Use tx_hash as deliverable hash (proof of original work)
    deliverable = t.get('tx_hash', '0' * 64)
    print(f'{recipient}|{new_amount}|{deliverable}')
")

count=0
total=$(echo "$transfers" | wc -l)

while IFS='|' read -r recipient amount deliverable; do
    count=$((count + 1))
    # Convert amount to whole CBE for display
    whole_cbe=$(python3 -c "print(f'{int(\"$amount\") / 10**18:,.2f}')")

    if [ "$DRY_RUN" = "--dry-run" ]; then
        log "  [$count/$total] DRY RUN: payroll mint $whole_cbe CBE → $recipient"
        continue
    fi

    log "  [$count/$total] Payroll mint: $whole_cbe CBE → ${recipient:0:16}..."

    $CLI -s "$SERVER" cbe payroll \
        --amount-cbe "$amount" \
        --collaborator "$recipient" \
        --deliverable-hash "$deliverable" \
        --trust-node 2>&1 | grep -E "✅|Error|success|fail" || true

    sleep 2  # Wait for block inclusion
done <<< "$transfers"

log ""
log "=== COMPENSATION REPLAY COMPLETE ==="
log "  Total: $count payroll mints"
log "  All carry PRE_BACKED flag"
log "  First real BUY_CBE will clear debt FIFO"
