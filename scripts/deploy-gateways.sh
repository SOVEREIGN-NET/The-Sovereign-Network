#!/usr/bin/env bash
#
# Gateway deploy wrapper. Modeled on deploy-validators.sh.
#
# Gateways are observer-mode (no BFT) so no halt-consensus needed, BUT the
# Jun-17 2026 incident proved the binary backup + verify steps are mandatory:
# I overwrote a working gw1 binary with one that has a historical-sync bug
# and almost bricked the node because there was no backup.
#
# Usage:
#   scripts/deploy-gateways.sh <binary-path>
#   scripts/deploy-gateways.sh --dry-run <binary-path>
#   scripts/deploy-gateways.sh --only gw1 <binary-path>     # one gateway only
#
# What it does, in order:
#   1. md5sum the local binary.
#   2. For each gateway, in series (NOT parallel — bulk gateway rollout is
#      what took mobile offline in the Jun-17 incident):
#        a. cp /opt/zhtp/zhtp /opt/zhtp/zhtp.bak.<timestamp>
#        b. verify backup exists with same md5 as the currently-running binary
#        c. rsync new binary to /tmp/zhtp.new
#        d. md5 verify the rsync
#        e. mv into place, chmod, systemctl restart
#        f. wait up to 60s for zhtp.service to enter active state
#        g. attempt a QUIC CLI test against the node (blockchain status)
#        h. if test fails → STOP, do not proceed to next gateway
#   3. Print final cluster state.
#
# The script refuses to proceed past a gateway that fails its post-deploy
# health check. This is what the user wants: never two gateways down at once.

set -euo pipefail

# ---- node table -------------------------------------------------------------
#
# Format: ssh-alias|ip|sudo
GATEWAYS=(
    "zhtp-gateway|91.98.113.188|sudo"
    "zhtp-gateway-2|57.128.30.74|sudo"
)

REMOTE_BIN=/opt/zhtp/zhtp
SERVICE=zhtp
RESTART_WAIT_SECS=60
HEALTH_TIMEOUT=30

# ---- arg parse --------------------------------------------------------------

DRY_RUN=0
ONLY=""
BINARY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --only)    ONLY="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        -*)        echo "unknown flag: $1" >&2; exit 2 ;;
        *)         BINARY="$1"; shift ;;
    esac
done

[[ -z "$BINARY" ]] && { echo "usage: $0 [--dry-run] [--only <alias>] <binary-path>" >&2; exit 2; }
[[ -f "$BINARY" ]] || { echo "binary not found: $BINARY" >&2; exit 2; }

# locate zhtp-cli for post-deploy health checks
CLI=./target/release/zhtp-cli
[[ -x "$CLI" ]] || CLI=./target/dev-release/zhtp-cli
[[ -x "$CLI" ]] || { echo "no zhtp-cli binary found in target/release or target/dev-release" >&2; exit 2; }

# ---- helpers ----------------------------------------------------------------

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[fail]\033[0m %s\n' "$*"; exit 1; }

# ---- step 1: local md5 ------------------------------------------------------

LOCAL_MD5=$(md5sum "$BINARY" | awk '{print $1}')
log "local binary md5: $LOCAL_MD5  ($BINARY)"
[[ $DRY_RUN -eq 1 ]] && log "DRY RUN — printing planned actions, no changes."

# ---- step 2: per-gateway serial deploy -------------------------------------

for entry in "${GATEWAYS[@]}"; do
    IFS='|' read -r alias ip sudo <<< "$entry"

    if [[ -n "$ONLY" && "$alias" != "$ONLY" && "$alias" != "zhtp-$ONLY" ]]; then
        log "skipping $alias (--only $ONLY)"
        continue
    fi

    log "==== $alias ($ip) ===="

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  ssh $alias \"$sudo cp $REMOTE_BIN ${REMOTE_BIN}.bak.\$(date +%Y%m%d-%H%M%S)-deploy\""
        echo "  scp $BINARY $alias:/tmp/zhtp.new"
        echo "  ssh $alias \"$sudo md5sum /tmp/zhtp.new\"   # must equal $LOCAL_MD5"
        echo "  ssh $alias \"$sudo mv /tmp/zhtp.new $REMOTE_BIN && $sudo chmod +x $REMOTE_BIN && $sudo systemctl restart $SERVICE\""
        echo "  health check via $CLI -s $ip:9334 blockchain status"
        continue
    fi

    # 2a. backup
    BAK_NAME="${REMOTE_BIN}.bak.$(date +%Y%m%d-%H%M%S)-deploy"
    log "backing up running binary → $BAK_NAME"
    ssh "$alias" "${sudo} cp $REMOTE_BIN $BAK_NAME"

    # 2b. verify backup
    BAK_MD5=$(ssh "$alias" "${sudo} md5sum $BAK_NAME" | awk '{print $1}')
    RUNNING_MD5=$(ssh "$alias" "${sudo} md5sum $REMOTE_BIN" | awk '{print $1}')
    if [[ "$BAK_MD5" != "$RUNNING_MD5" ]]; then
        fail "backup md5 mismatch on $alias — refusing to overwrite"
    fi
    ok "backup verified ($BAK_MD5)"

    # 2c. rsync to /tmp
    log "rsync new binary to $alias:/tmp/zhtp.new"
    scp -q "$BINARY" "$alias:/tmp/zhtp.new"

    # 2d. md5 verify the rsync
    PUSHED_MD5=$(ssh "$alias" "${sudo} md5sum /tmp/zhtp.new" | awk '{print $1}')
    if [[ "$PUSHED_MD5" != "$LOCAL_MD5" ]]; then
        ssh "$alias" "${sudo} rm /tmp/zhtp.new"
        fail "pushed binary md5 mismatch on $alias (got $PUSHED_MD5, expected $LOCAL_MD5)"
    fi
    ok "pushed binary md5 verified"

    # 2e. move into place + restart
    log "swapping binary and restarting $SERVICE"
    ssh "$alias" "${sudo} mv /tmp/zhtp.new $REMOTE_BIN && ${sudo} chmod +x $REMOTE_BIN && ${sudo} systemctl restart $SERVICE"

    # 2f. wait for active state
    log "waiting up to ${RESTART_WAIT_SECS}s for $SERVICE to become active"
    DEADLINE=$(( $(date +%s) + RESTART_WAIT_SECS ))
    while (( $(date +%s) < DEADLINE )); do
        if ssh "$alias" "${sudo} systemctl is-active $SERVICE" 2>/dev/null | grep -q '^active$'; then
            break
        fi
        sleep 2
    done
    if ! ssh "$alias" "${sudo} systemctl is-active $SERVICE" 2>/dev/null | grep -q '^active$'; then
        fail "$SERVICE did not reach active state on $alias — ABORTING (other gateways NOT touched)"
    fi
    ok "service active on $alias"

    # 2g. QUIC health check
    log "QUIC health check against $ip:9334 (timeout ${HEALTH_TIMEOUT}s)"
    if timeout "$HEALTH_TIMEOUT" "$CLI" -s "$ip:9334" blockchain status >/dev/null 2>&1; then
        ok "$alias responds to inbound QUIC"
    else
        warn "$alias does NOT respond to inbound QUIC after restart"
        warn "ROLLBACK: restoring $BAK_NAME"
        ssh "$alias" "${sudo} cp $BAK_NAME $REMOTE_BIN && ${sudo} systemctl restart $SERVICE"
        sleep 10
        if timeout "$HEALTH_TIMEOUT" "$CLI" -s "$ip:9334" blockchain status >/dev/null 2>&1; then
            ok "$alias recovered after rollback"
        else
            fail "$alias still broken after rollback — manual intervention required"
        fi
        fail "deploy aborted on $alias — fix binary, then retry (other gateways NOT touched)"
    fi

    log "$alias deploy complete"
    echo
done

ok "all selected gateways deployed and verified"
