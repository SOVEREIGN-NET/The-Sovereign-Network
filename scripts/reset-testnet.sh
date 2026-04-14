#!/bin/bash
# Testnet Reset Script — EPIC-001
#
# This script executes the full testnet reset procedure.
# Run from the repo root on a machine with SSH access to all validators.
#
# Prerequisites:
#   - EPIC-001 PR merged to development
#   - Binary built: cargo build --release -p zhtp -p zhtp-cli
#   - Snapshots taken: docs/testnet/testnet_snapshot_2026-04-14.json
#   - Domain snapshot taken (run domain_snapshot tool first)
#
# Usage: ./scripts/reset-testnet.sh [--dry-run]

set -euo pipefail

DRY_RUN=${1:-""}
NODES="zhtp-g1 zhtp-g2 zhtp-g3"
BINARY="target/release/zhtp"
CLI="target/release/zhtp-cli"

log() { echo "[$(date '+%H:%M:%S')] $1"; }
die() { echo "FATAL: $1" >&2; exit 1; }

# ── Preflight checks ────────────────────────────────────────────────────────

log "=== PREFLIGHT CHECKS ==="

[ -f "$BINARY" ] || die "Binary not found: $BINARY — run: cargo build --release -p zhtp"
[ -f "$CLI" ] || die "CLI not found: $CLI — run: cargo build --release -p zhtp-cli"
[ -f "docs/testnet/testnet_snapshot_2026-04-14.json" ] || die "Snapshot not found"

for node in $NODES; do
    ssh -o ConnectTimeout=5 $node "echo ok" >/dev/null 2>&1 || die "Cannot reach $node"
    log "  $node: reachable"
done

if [ "$DRY_RUN" = "--dry-run" ]; then
    log "DRY RUN — would execute the following:"
    log "  1. Stop all 3 validators"
    log "  2. Clear sled data on all nodes"
    log "  3. Deploy new binary to all nodes"
    log "  4. Start bootstrap leader (g1)"
    log "  5. Start followers (g2, g3)"
    log "  6. Verify chain advancing"
    exit 0
fi

# ── Step 1: Stop all validators simultaneously ──────────────────────────────

log "=== STEP 1: Stopping all validators ==="
for node in $NODES; do
    ssh $node "systemctl stop zhtp" &
done
wait
sleep 2

for node in $NODES; do
    status=$(ssh $node "systemctl is-active zhtp" 2>/dev/null || echo "inactive")
    if [ "$status" = "active" ]; then
        die "$node is still running!"
    fi
    log "  $node: stopped"
done

# ── Step 2: Clear chain data ────────────────────────────────────────────────

log "=== STEP 2: Clearing sled data ==="
for node in $NODES; do
    ssh $node "rm -rf /opt/zhtp/data/testnet/sled && echo 'cleared'"
    log "  $node: sled cleared"
done

# ── Step 3: Deploy new binary ───────────────────────────────────────────────

log "=== STEP 3: Deploying binary ==="
for node in $NODES; do
    rsync -az "$BINARY" $node:/opt/zhtp/zhtp
    ssh $node "chmod +x /opt/zhtp/zhtp"
    log "  $node: deployed"
done

# ── Step 4: Start bootstrap leader ──────────────────────────────────────────

log "=== STEP 4: Starting bootstrap leader (zhtp-g1) ==="
ssh zhtp-g1 "systemctl start zhtp"
sleep 5

status=$(ssh zhtp-g1 "systemctl is-active zhtp" 2>/dev/null || echo "failed")
if [ "$status" != "active" ]; then
    ssh zhtp-g1 "journalctl -u zhtp -n 20 --no-pager" 2>&1
    die "zhtp-g1 failed to start!"
fi
log "  zhtp-g1: active"

# ── Step 5: Start followers ─────────────────────────────────────────────────

log "=== STEP 5: Starting followers ==="
for node in zhtp-g2 zhtp-g3; do
    ssh $node "systemctl start zhtp"
    sleep 3
    status=$(ssh $node "systemctl is-active zhtp" 2>/dev/null || echo "failed")
    if [ "$status" != "active" ]; then
        ssh $node "journalctl -u zhtp -n 20 --no-pager" 2>&1
        die "$node failed to start!"
    fi
    log "  $node: active"
done

# ── Step 6: Verify chain advancing ─────────────────────────────────────────

log "=== STEP 6: Verifying consensus ==="
sleep 10
ssh zhtp-g3 "journalctl -u zhtp -n 10 --no-pager" 2>&1 | grep -i "Block committed\|height\|finalized" | tail -3
log "  Chain is advancing"

log ""
log "=== TESTNET RESET COMPLETE ==="
log ""
log "Next steps:"
log "  1. Run domain recovery: ./scripts/replay-domains.sh"
log "  2. Run CBE compensation replay: ./scripts/replay-cbe-compensation.sh"
log "  3. Redeploy sites"
