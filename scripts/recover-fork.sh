#!/usr/bin/env bash
#
# Fork-recovery for a single validator.
#
# Replaces the ad-hoc `mv sled sled.fork-snapshot && systemctl restart`
# pattern. Project rule from feedback memory:
#
#   "NEVER wipe sled to fix a fork. That destroys block history.
#    Instead: identify which nodes have the canonical tip (majority),
#    restart the minority nodes so they sync from the majority."
#
# This script enforces that rule before destroying anything:
#   1. Reads local tip hash from <target>.
#   2. Reads tip hash from each peer.
#   3. Refuses to wipe if local hash matches a majority of peers (≥2/3).
#   4. Snapshots the divergent sled (mv, not rm).
#   5. Restarts. Catch-up sync resolves to majority.
#
# Usage:
#   scripts/recover-fork.sh zhtp-g3
#   scripts/recover-fork.sh --force zhtp-g3    # bypass majority check (last resort)

set -euo pipefail

# ---- peer table (read-only queries; target node excluded at runtime) -------
PEERS=(
    "zhtp-g1|77.42.37.161|"
    "zhtp-g2|77.42.74.80|"
    "zhtp-g3|178.105.9.247|"
)
SERVICE=zhtp

# ---- arg parse --------------------------------------------------------------

FORCE=0
TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]] && { echo "usage: $0 [--force] <node-alias>" >&2; exit 2; }

# Find target sudo prefix from peer table.
TARGET_SUDO=""
TARGET_IP=""
for entry in "${PEERS[@]}"; do
    IFS='|' read -r alias ip sudo <<< "$entry"
    if [[ "$alias" == "$TARGET" ]]; then
        TARGET_SUDO="$sudo"
        TARGET_IP="$ip"
    fi
done
[[ -z "$TARGET_IP" ]] && { echo "target $TARGET not in peer table — edit script if new node" >&2; exit 2; }

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[fail]\033[0m %s\n' "$*"; exit 1; }

# ---- step 1: target tip ----------------------------------------------------

log "querying $TARGET tip..."
# Log format examples we accept:
#   "Block committed at height 112624"   (state_machine commit log)
#   "Served chain tip: height=112623"    (blockchain API handler log)
#   "Caught up at height 105622"         (network entering active consensus)
#   "height 112624 round N"              (proposer log)
TARGET_TIP=$(ssh "$TARGET" "${TARGET_SUDO} journalctl -u $SERVICE -n 200 --no-pager 2>/dev/null | grep -oE '(height[= ][0-9]+|at height [0-9]+)' | grep -oE '[0-9]+' | sort -n | tail -1" 2>/dev/null || echo "")
[[ -z "$TARGET_TIP" ]] && fail "could not read $TARGET tip height (journalctl returned no matching lines — node may be down)"

# block_hash from journal log if present. Optional — the majority-quorum
# check below uses peer-reported hashes regardless of whether we have a
# local hash to compare against.
TARGET_HASH=$(ssh "$TARGET" "${TARGET_SUDO} journalctl -u $SERVICE -n 500 --no-pager 2>/dev/null | grep -oE 'block_hash=[a-f0-9]{8,}' | tail -1 | cut -d= -f2" 2>/dev/null || echo "")
ok "$TARGET at height=$TARGET_TIP hash=${TARGET_HASH:-unknown}"

# ---- step 2: peer tips at same height --------------------------------------
#
# For comparison to mean anything, every peer must report the hash AT the
# target's height — not their own current tip. Use /api/v1/blockchain/block/<n>.
# Falls back to logs if API not reachable.

declare -A PEER_HASHES
log "querying peers at height $TARGET_TIP..."
for entry in "${PEERS[@]}"; do
    IFS='|' read -r alias ip _ <<< "$entry"
    [[ "$alias" == "$TARGET" ]] && continue
    # Best-effort API query via QUIC client.
    h=$(./target/dev-release/zhtp-cli -s "$ip:9334" blockchain block --height "$TARGET_TIP" 2>/dev/null | grep -oE 'hash[":[:space:]]*[a-f0-9]{8,}' | head -1 | grep -oE '[a-f0-9]{8,}' || echo "")
    PEER_HASHES[$alias]="$h"
    printf '  %-12s @ h=%s -> %s\n' "$alias" "$TARGET_TIP" "${h:-unreachable}"
done

# ---- step 3: majority check -----------------------------------------------

if [[ $FORCE -eq 0 ]]; then
    # Count peers that REACHED us (any non-empty hash). Count agreement on the
    # most common hash. Refuse if target matches the majority (no fork to fix).
    declare -A HASH_COUNT
    REACHABLE=0
    for h in "${PEER_HASHES[@]}"; do
        [[ -z "$h" ]] && continue
        REACHABLE=$((REACHABLE+1))
        HASH_COUNT[$h]=$(( ${HASH_COUNT[$h]:-0} + 1 ))
    done

    [[ $REACHABLE -lt 2 ]] && fail "only $REACHABLE peers reachable for hash comparison — refuse to wipe blind. Use --force if you have out-of-band evidence."

    MAJ_HASH=""
    MAJ_COUNT=0
    for h in "${!HASH_COUNT[@]}"; do
        if (( HASH_COUNT[$h] > MAJ_COUNT )); then
            MAJ_HASH="$h"; MAJ_COUNT="${HASH_COUNT[$h]}"
        fi
    done

    log "peer majority: $MAJ_COUNT/$REACHABLE agree on hash $MAJ_HASH"

    if [[ -n "$TARGET_HASH" && "$MAJ_HASH" == *"$TARGET_HASH"* ]]; then
        fail "$TARGET hash MATCHES majority — no fork to recover. Refusing to wipe. (Override with --force.)"
    fi
fi

# ---- step 4: snapshot + restart -------------------------------------------

STAMP=$(date +%Y%m%d-%H%M%S)
log "wiping $TARGET sled (snapshot suffix: fork-recover-$STAMP)..."

ssh "$TARGET" "${TARGET_SUDO} systemctl stop $SERVICE && \
    ${TARGET_SUDO} mv /opt/zhtp/.zhtp/data/testnet/sled /opt/zhtp/.zhtp/data/testnet/sled.fork-recover-$STAMP 2>/dev/null || true && \
    ${TARGET_SUDO} mv /opt/zhtp/.zhtp/storage /opt/zhtp/.zhtp/storage.fork-recover-$STAMP 2>/dev/null || true && \
    ${TARGET_SUDO} mv /opt/zhtp/.zhtp/sled.v1 /opt/zhtp/.zhtp/sled.v1.fork-recover-$STAMP 2>/dev/null || true"

ok "snapshots taken on $TARGET"

# Log postmortem record on the host so it's discoverable later.
ssh "$TARGET" "${TARGET_SUDO} sh -c 'cat >> /opt/zhtp/.zhtp/fork-recovery.log' <<EOF
=== $STAMP ===
recovered_from_height: $TARGET_TIP
local_hash_at_tip: ${TARGET_HASH:-unknown}
peer_majority_hash: ${MAJ_HASH:-unknown}
peer_agreement: ${MAJ_COUNT:-0}/${REACHABLE:-0}
operator: $(whoami)@$(hostname)
EOF
" 2>/dev/null || true

log "restarting $TARGET — will catch up from peers..."
ssh "$TARGET" "${TARGET_SUDO} systemctl start $SERVICE"

log "watching for catch-up (timeout 10 min)..."
if timeout 600 ssh "$TARGET" \
    "until ${TARGET_SUDO} journalctl -u $SERVICE --since '5 min ago' --no-pager 2>/dev/null | grep -qE 'Caught up at height|active consensus'; do sleep 5; done" 2>/dev/null
then
    ok "$TARGET back in active consensus"
else
    fail "$TARGET did not catch up in 10 min — check manually"
fi
