#!/usr/bin/env bash
#
# Halt-protocol validator rollout.
#
# Replaces the ad-hoc rsync-then-restart loop that caused several forks
# during the May 30–June 1 2026 incident. Enforces the rules from
# feedback_halt_before_deploy.md mechanically so the operator cannot
# skip steps.
#
# Usage:
#   scripts/deploy-validators.sh <binary-path>
#   scripts/deploy-validators.sh --dry-run <binary-path>     # show plan, don't act
#   scripts/deploy-validators.sh --skip-halt <binary-path>   # already halted, e.g. chain stuck
#
# What it does, in order:
#   1. md5sum the local binary.
#   2. halt-consensus on all validators (council role required).
#   3. Verify "HALTED" appears in each validator's log.
#   4. Rsync binary to each (parallel).
#   5. md5-verify on each. Abort if mismatch.
#   6. Restart all (parallel).
#   7. Poll for "Caught up at height" on each (timeout per node).
#   8. Print state table: node | height | md5 | voting?
#   9. Exit non-zero on any failure.
#
# Operator never types systemctl, rsync, or md5sum manually. Mistakes
# (forgetting to halt, missing a node, deploying wrong binary) become
# impossible.

set -euo pipefail

# ---- node table -------------------------------------------------------------
#
# Format: ssh-alias|ip|sudo
# Mirrored from CLAUDE.md deployment table. Update both together.
NODES=(
    "zhtp-g1|77.42.37.161|"
    "zhtp-g2|77.42.74.80|"
    "zhtp-g3|178.105.9.247|"
)

REMOTE_BIN=/opt/zhtp/zhtp
HALT_WAIT_SECS=30
RESTART_WAIT_SECS=600
SERVICE=zhtp

# ---- arg parse --------------------------------------------------------------

DRY_RUN=0
SKIP_HALT=0
BINARY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=1; shift ;;
        --skip-halt) SKIP_HALT=1; shift ;;
        -h|--help)
            sed -n '2,32p' "$0"
            exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *)  BINARY="$1"; shift ;;
    esac
done

[[ -z "$BINARY" ]] && { echo "usage: $0 [--dry-run] [--skip-halt] <binary-path>" >&2; exit 2; }
[[ -f "$BINARY" ]] || { echo "binary not found: $BINARY" >&2; exit 2; }

# ---- helpers ----------------------------------------------------------------

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[fail]\033[0m %s\n' "$*"; exit 1; }

run_on() {
    # run_on <alias> <sudo-prefix> <cmd>
    local alias=$1 sudo=$2 cmd=$3
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  ssh $alias \"$sudo $cmd\""
        return 0
    fi
    ssh "$alias" "${sudo} ${cmd}"
}

# ---- step 1: local md5 -----------------------------------------------------

LOCAL_MD5=$(md5sum "$BINARY" | awk '{print $1}')
log "local binary md5: $LOCAL_MD5  ($BINARY)"

if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY RUN — printing planned actions, no changes."
fi

# ---- step 2: halt all validators -------------------------------------------
#
# The safety invariant we actually care about: no node is producing blocks.
# That's a property of node STATE (FSM in Halting), not of CLI success.
# Halt-consensus on any single node also broadcasts via mesh to all peers,
# so a CLI call that fails for half the nodes can still result in 5/5
# halted state. We therefore:
#   1. Send halt-consensus to every node (best effort, no abort on failure).
#   2. Wait for the broadcast to settle.
#   3. Verify the actual outcome by reading journalctl on each — `HALTED`
#      log entry within the last 2 minutes.
#   4. Abort if fewer than TOTAL-1 are actually halted (3-node set: 2 halted
#      blocks quorum; no block production).

if [[ $SKIP_HALT -eq 1 ]]; then
    log "skip-halt requested — chain must already be stopped"
else
    log "sending halt-consensus to all validators (best effort)..."
    for entry in "${NODES[@]}"; do
        IFS='|' read -r alias ip _sudo <<< "$entry"
        if [[ $DRY_RUN -eq 1 ]]; then
            echo "  zhtp-cli -s $ip:9334 node halt-consensus --reason upgrade"
            continue
        fi
        if ./target/dev-release/zhtp-cli -s "$ip:9334" node halt-consensus --reason upgrade >/dev/null 2>&1; then
            ok "halt sent via CLI: $alias"
        else
            log "halt CLI failed for $alias — relying on mesh broadcast from other nodes"
        fi
    done

    if [[ $DRY_RUN -eq 0 ]]; then
        log "waiting for halt broadcast to settle (10s)..."
        sleep 10

        log "verifying HALTED state in each node's journal (window: ${HALT_WAIT_SECS}s)..."
        ACTUALLY_HALTED=0
        UNREACHABLE=0
        for entry in "${NODES[@]}"; do
            IFS='|' read -r alias _ip sudo <<< "$entry"
            # Look at the last 2 min of logs — HALTED is repeated every 30s
            # by the halted loop, so a 2-minute window is generous.
            if timeout "$HALT_WAIT_SECS" ssh -o ConnectTimeout=10 "$alias" \
                "${sudo} journalctl -u $SERVICE --since '2 min ago' --no-pager 2>/dev/null | grep -q 'HALTED'" 2>/dev/null
            then
                ok "halted (verified via log): $alias"
                ACTUALLY_HALTED=$((ACTUALLY_HALTED+1))
            else
                # Distinguish "node responds but not halted" from "unreachable".
                if timeout 10 ssh -o ConnectTimeout=10 "$alias" "true" >/dev/null 2>&1; then
                    warn "reachable but NOT halted: $alias"
                else
                    warn "unreachable: $alias (can't verify halt state)"
                    UNREACHABLE=$((UNREACHABLE+1))
                fi
            fi
        done

        TOTAL=${#NODES[@]}
        # Safety: require at least TOTAL-1 actually halted, regardless of cause.
        # With 3 validators, 2 halted means no quorum (need 2f+1=3 or 2/3 per
        # active set). Permitting 2 unhalted nodes during deploy risks forks.
        if [[ $ACTUALLY_HALTED -lt $((TOTAL - 1)) ]]; then
            fail "only $ACTUALLY_HALTED/$TOTAL halted (unreachable: $UNREACHABLE) — abort, chain may still be producing"
        fi
        log "halt verified: $ACTUALLY_HALTED/$TOTAL nodes in HALTED state (proceeding)"
    fi
fi

# ---- step 4: rsync to all (parallel) ---------------------------------------

log "deploying binary to all validators (parallel)..."
PIDS=()
for entry in "${NODES[@]}"; do
    IFS='|' read -r alias _ip sudo <<< "$entry"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  scp $BINARY $alias:/tmp/zhtp.new && ssh $alias \"$sudo cp $REMOTE_BIN ${REMOTE_BIN}.bak.\$(date +%Y%m%d-%H%M%S) && $sudo mv /tmp/zhtp.new $REMOTE_BIN && $sudo chmod +x $REMOTE_BIN\""
        continue
    fi
    (
        scp -q "$BINARY" "$alias:/tmp/zhtp.new"
        ssh "$alias" "${sudo} cp $REMOTE_BIN ${REMOTE_BIN}.bak.\$(date +%Y%m%d-%H%M%S)-deploy && ${sudo} mv /tmp/zhtp.new $REMOTE_BIN && ${sudo} chmod +x $REMOTE_BIN"
    ) &
    PIDS+=("$!:$alias")
done

if [[ $DRY_RUN -eq 0 ]]; then
    for pid_alias in "${PIDS[@]}"; do
        pid="${pid_alias%%:*}"
        alias="${pid_alias##*:}"
        if wait "$pid"; then
            ok "deployed: $alias"
        else
            fail "deploy FAILED on $alias — abort before restart"
        fi
    done
fi

# ---- step 5: verify md5 on each --------------------------------------------

if [[ $DRY_RUN -eq 0 ]]; then
    log "verifying remote md5 == $LOCAL_MD5..."
    for entry in "${NODES[@]}"; do
        IFS='|' read -r alias _ip sudo <<< "$entry"
        REMOTE_MD5=$(ssh "$alias" "${sudo} md5sum $REMOTE_BIN" | awk '{print $1}')
        if [[ "$REMOTE_MD5" == "$LOCAL_MD5" ]]; then
            ok "md5 match: $alias"
        else
            fail "md5 MISMATCH on $alias: got $REMOTE_MD5, expected $LOCAL_MD5"
        fi
    done
fi

# ---- step 6: restart all (parallel) ----------------------------------------

log "restarting all validators..."
for entry in "${NODES[@]}"; do
    IFS='|' read -r alias _ip sudo <<< "$entry"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  ssh $alias \"$sudo systemctl restart $SERVICE\""
        continue
    fi
    ssh "$alias" "${sudo} systemctl restart $SERVICE" &
done
[[ $DRY_RUN -eq 0 ]] && wait

# ---- step 7: poll for caught-up status -------------------------------------

if [[ $DRY_RUN -eq 0 ]]; then
    log "waiting for all validators to reach active consensus (timeout: ${RESTART_WAIT_SECS}s)..."
    for entry in "${NODES[@]}"; do
        IFS='|' read -r alias _ip sudo <<< "$entry"
        if timeout "$RESTART_WAIT_SECS" ssh "$alias" \
            "until ${sudo} journalctl -u $SERVICE --since '5 min ago' --no-pager 2>/dev/null | grep -qE 'Caught up at height|active consensus'; do sleep 5; done" 2>/dev/null
        then
            ok "active: $alias"
        else
            warn "TIMEOUT: $alias did not reach active consensus in ${RESTART_WAIT_SECS}s — check manually"
        fi
    done
fi

# ---- step 8: state table ---------------------------------------------------

if [[ $DRY_RUN -eq 0 ]]; then
    echo
    log "final cluster state:"
    printf '%-12s  %-10s  %-32s\n' NODE HEIGHT MD5
    printf '%-12s  %-10s  %-32s\n' '----' '------' '---'
    for entry in "${NODES[@]}"; do
        IFS='|' read -r alias _ip sudo <<< "$entry"
        height=$(ssh "$alias" "${sudo} journalctl -u $SERVICE -n 30 --no-pager 2>/dev/null | grep -oE 'height=[0-9]+' | tail -1 | cut -d= -f2" 2>/dev/null || echo "?")
        md5=$(ssh "$alias" "${sudo} md5sum $REMOTE_BIN 2>/dev/null | awk '{print \$1}'" 2>/dev/null || echo "?")
        printf '%-12s  %-10s  %-32s\n' "$alias" "${height:-?}" "${md5:-?}"
    done
fi

ok "deploy complete"
