#!/bin/bash
# Effective Testnet Reset — chain + Web4/DHT wipe
#
# A consensus sled wipe alone leaves orphaned Web4 domains in dht_db whose owner
# identities and wallets no longer exist on-chain. This script wipes BOTH layers
# so the testnet is a true clean slate (no dead owner keys serving stale sites).
#
# Wipes on each validator (g1–g3):
#   - Consensus sled (identities, wallets, tokens, on-chain domain projections)
#   - Legacy blockchain.dat sidecar
#   - Web4 UnifiedStorage (dht_db — domain records, manifests, content blobs)
#   - Legacy testnet/storage sidecar (if present)
#
# Does NOT wipe:
#   - Validator operator keystores (/opt/zhtp/.zhtp/keystore or /opt/zhtp/keystores/)
#   - sled.* backup directories (created before wipe)
#
# Usage:
#   ./scripts/effective-reset-testnet.sh [--dry-run]
#   ./scripts/effective-reset-testnet.sh --skip-restart   # wipe only, no start
#
# After reset: redeploy binary, register identities, seed BUBL via AssetLaunch
#   cargo run -p tools --bin seed_asset_launch -- \
#     --keystore-dir /opt/zhtp/keystores/bubl-creator \
#     --token bubl --supply-atoms <atoms> \
#     --rewards-delegate-dir /opt/zhtp/keystores/bubl-rewards-hot
# Set ZHTP_REWARDS_ASSET_ID to the printed asset_id on validators.

set -euo pipefail

DRY_RUN=""
SKIP_RESTART=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --skip-restart) SKIP_RESTART=1 ;;
        *) echo "Unknown arg: $arg" >&2; exit 1 ;;
    esac
done

NODES="zhtp-g1 zhtp-g2 zhtp-g3"
STAMP=$(date +%s)

# Canonical paths (match zhtp::node_data_dir() on validators)
ZHTP_ROOT="/opt/zhtp/.zhtp"
DATA_TESTNET="${ZHTP_ROOT}/data/testnet"
DHT_DB="${ZHTP_ROOT}/storage/dht_db"
DHT_ADAPTER="${ZHTP_ROOT}/storage/dht_adapter.sled"

log() { echo "[$(date '+%H:%M:%S')] $1"; }
die() { echo "FATAL: $1" >&2; exit 1; }

wipe_node() {
    local node=$1
    log "  $node: backing up + wiping..."

    if [ -n "$DRY_RUN" ]; then
        log "    [dry-run] would backup sled + dht_db, then rm targets"
        return 0
    fi

    ssh "$node" bash -s <<REMOTE
set -euo pipefail
STAMP="${STAMP}"
DATA="${DATA_TESTNET}"
DHT="${DHT_DB}"
ADAPTER="${DHT_ADAPTER}"

sudo systemctl stop zhtp --wait-timeout 120 2>/dev/null || sudo systemctl stop zhtp || true
sleep 2

# Backups (never delete these automatically)
if [ -d "\$DATA/sled" ]; then
  sudo cp -a "\$DATA/sled" "\$DATA/sled.pre-effective-\$STAMP"
fi
if [ -d "\$DHT" ]; then
  sudo cp -a "\$DHT" "\${DHT}.pre-effective-\$STAMP"
fi

# Chain state — identities, wallets, domain projections
sudo rm -rf "\$DATA/sled"
sudo rm -f  "\$DATA/blockchain.dat"
sudo rm -rf "\$DATA/rewards.sled" "\$DATA/rewards.dat" 2>/dev/null || true
sudo rm -rf "\$DATA/notifications.sled" 2>/dev/null || true
sudo rm -rf "\$DATA/storage" 2>/dev/null || true

# Web4 / DHT — domain records, manifests, content (dead owner keys live here)
sudo rm -rf "\$DHT"
sudo rm -rf "\$ADAPTER" 2>/dev/null || true

STORAGE="\$(dirname "\$DHT")"
sudo mkdir -p "\$DATA/sled" "\$STORAGE"
sudo chown -R zhtp:zhtp "\$DATA" "\$STORAGE"
echo "wiped"
REMOTE
}

start_node() {
    local node=$1
    if [ -n "$DRY_RUN" ]; then
        log "  [dry-run] would start $node"
        return 0
    fi
    ssh "$node" "sudo systemctl start zhtp"
    sleep 3
    local status
    status=$(ssh "$node" "systemctl is-active zhtp" 2>/dev/null || echo "failed")
    [ "$status" = "active" ] || die "$node failed to start (status=$status)"
    log "  $node: active"
}

log "=== EFFECTIVE TESTNET RESET ==="
log "Wipes: sled + blockchain.dat + dht_db (Web4 domains/content)"
log "Preserves: validator keystores, sled.pre-* / dht_db.pre-* backups"

for node in $NODES; do
    ssh -o ConnectTimeout=5 "$node" "echo ok" >/dev/null 2>&1 || die "Cannot reach $node"
done

if [ -n "$DRY_RUN" ]; then
    log "DRY RUN — no changes will be made"
fi

log "=== Stopping + wiping all validators ==="
for node in $NODES; do
    wipe_node "$node"
done

if [ -n "$SKIP_RESTART" ]; then
    log "=== Wipe complete (--skip-restart) ==="
    log "Next: deploy binary, then start g1 → g2 → g3"
    exit 0
fi

log "=== Starting bootstrap leader (g1) ==="
start_node zhtp-g1
sleep 10

log "=== Starting followers ==="
for node in zhtp-g2 zhtp-g3; do
    start_node "$node"
    sleep 5
done

log ""
log "=== EFFECTIVE RESET COMPLETE ==="
log "Chain: empty sled — identities=0, wallets=0, domains=0"
log "Web4: empty dht_db — no orphaned domain records or content"
log ""
log "Next steps:"
log "  1. Deploy binary if needed: ./scripts/deploy-validators.sh"
log "  2. Register operator identity + wallets"
log "  3. Seed BUBL / founding txs"
log "  4. Re-deploy core sites: central.sov, sovswap.sov, ballot.sov"