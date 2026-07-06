#!/bin/bash
# Purge Web4 domains from DHT storage (keeps a allowlist)
#
# Requires Council-role keystore and running validators with admin/purge endpoint.
# For a full wipe including dead owner keys, prefer effective-reset-testnet.sh.
#
# Usage:
#   ./scripts/purge-domains.sh [--dry-run] [--keep central.sov,sovswap.sov,ballot.sov]
#   ./scripts/purge-domains.sh --server 77.42.74.80:9334 --keystore ~/.zhtp/keystore

set -euo pipefail

DRY_RUN=""
KEEP="central.sov,sovswap.sov,ballot.sov"
SERVER="${ZHTP_SERVER:-77.42.74.80:9334}"
KEYSTORE="${ZHTP_KEYSTORE:-$HOME/.zhtp/keystore}"
CLI="./target/release/zhtp-cli"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --keep) KEEP="$2"; shift 2 ;;
        --server) SERVER="$2"; shift 2 ;;
        --keystore) KEYSTORE="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { echo "[$(date '+%H:%M:%S')] $1"; }
die() { echo "FATAL: $1" >&2; exit 1; }

[ -f "$CLI" ] || die "Build CLI first: cargo build --release -p zhtp-cli"
[ -d "$KEYSTORE" ] || die "Keystore not found: $KEYSTORE (need Council role)"

log "=== DOMAIN PURGE ==="
log "Server:  $SERVER"
log "Keep:    $KEEP"
log "Dry-run: ${DRY_RUN:-no}"

ARGS=(domain purge --keep "$KEEP" --keystore "$KEYSTORE" --trust-node -s "$SERVER")
if [ -n "$DRY_RUN" ]; then
    ARGS+=(--dry-run)
fi

"$CLI" "${ARGS[@]}"

log "=== PURGE COMPLETE ==="
log "Re-run on each validator if DHT counts diverged (g1 had 52 vs g2/g3 43)."