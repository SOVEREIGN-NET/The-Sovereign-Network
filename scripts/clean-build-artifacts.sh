#!/usr/bin/env bash
#
# Prune local Cargo artifacts and remote validator binary backups.
#
# Local target/ grows without bound (debug alone is often 80GB+). Deploy
# scripts also accumulate zhtp.bak.* on each validator. Run this after
# deploys and when disk is tight.
#
# Usage:
#   scripts/clean-build-artifacts.sh              # local prune (safe default)
#   scripts/clean-build-artifacts.sh --remote     # prune validator backups only
#   scripts/clean-build-artifacts.sh --all        # local + remote
#   scripts/clean-build-artifacts.sh --aggressive # local: cargo clean (rebuild required)
#   scripts/clean-build-artifacts.sh --dry-run
#
# Safe local default removes:
#   target/debug, target/doc, target/tmp, target/incremental (if present)
# Keeps: target/dev-release, target/release (deploy profiles), target/rpi
#
# Remote default keeps the newest KEEP_REMOTE_BACKUPS zhtp.bak.* per node.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEEP_REMOTE_BACKUPS=3
REMOTE_BIN_DIR=/opt/zhtp

NODES=(
    "zhtp-g1|77.42.37.161|"
    "zhtp-g2|77.42.74.80|"
    "zhtp-g3|178.105.9.247|"
)

DRY_RUN=0
DO_LOCAL=0
DO_REMOTE=0
AGGRESSIVE=0

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }

usage() {
    sed -n '2,20p' "$0"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)     DRY_RUN=1; shift ;;
        --local)       DO_LOCAL=1; shift ;;
        --remote)      DO_REMOTE=1; shift ;;
        --all)         DO_LOCAL=1; DO_REMOTE=1; shift ;;
        --aggressive)  DO_LOCAL=1; AGGRESSIVE=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# Default: local safe prune when no scope flag given.
if [[ $DO_LOCAL -eq 0 && $DO_REMOTE -eq 0 ]]; then
    DO_LOCAL=1
fi

human_size() {
    du -sh "$1" 2>/dev/null | awk '{print $1}'
}

remove_path() {
    local path=$1
    if [[ ! -e "$path" ]]; then
        return 0
    fi
    local before
    before=$(human_size "$path")
    if [[ $DRY_RUN -eq 1 ]]; then
        log "would remove $path ($before)"
        return 0
    fi
    rm -rf "$path"
    ok "removed $path (was $before)"
}

prune_local_safe() {
    log "local safe prune under $ROOT/target"
    if [[ ! -d target ]]; then
        warn "no target/ directory — nothing to prune"
        return 0
    fi
    log "target/ before: $(human_size target)"

    if [[ $AGGRESSIVE -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            log "would run: cargo clean (entire target/)"
        else
            cargo clean
            ok "cargo clean complete — rebuild before next deploy"
        fi
        return 0
    fi

    remove_path target/debug
    remove_path target/doc
    remove_path target/tmp
    remove_path target/.rustc_info.json.bak

    # Orphan incremental dirs from profile experiments.
    if [[ -d target/incremental ]]; then
        remove_path target/incremental
    fi

    if [[ -d target ]]; then
        log "target/ after: $(human_size target)"
    fi
}

prune_remote_backups_on_node() {
    local alias=$1
    local sudo=$2
    local keep=$((KEEP_REMOTE_BACKUPS + 1))

    if [[ $DRY_RUN -eq 1 ]]; then
        local preview
        preview=$(ssh "$alias" "${sudo} ls -1t ${REMOTE_BIN_DIR}/zhtp.bak.* 2>/dev/null | tail -n +${keep}" 2>/dev/null || true)
        if [[ -z "$preview" ]]; then
            ok "$alias: would keep all backups"
        else
            log "$alias: would delete:"
            echo "$preview" | sed 's/^/  /'
        fi
        return 0
    fi

    local out
    out=$(ssh "$alias" "${sudo} sh -c '
        total=\$(ls -1 ${REMOTE_BIN_DIR}/zhtp.bak.* 2>/dev/null | wc -l)
        stale=\$(ls -1t ${REMOTE_BIN_DIR}/zhtp.bak.* 2>/dev/null | tail -n +${keep})
        deleted=\$(printf \"%s\n\" \"\$stale\" | sed \"/^$/d\" | wc -l)
        printf \"%s\n\" \"\$stale\" | sed \"/^$/d\" | xargs -r rm -f
        echo kept=${KEEP_REMOTE_BACKUPS} deleted=\$deleted total=\$total
    '" 2>/dev/null) || {
        warn "remote prune failed: $alias"
        return 1
    }
    ok "$alias: $out"
}

prune_remote_backups() {
    log "pruning remote ${REMOTE_BIN_DIR}/zhtp.bak.* (keep newest $KEEP_REMOTE_BACKUPS per node)"
    for entry in "${NODES[@]}"; do
        IFS='|' read -r alias _ip sudo <<< "$entry"
        prune_remote_backups_on_node "$alias" "$sudo" || true
    done
}

[[ $DO_LOCAL -eq 1 ]] && prune_local_safe
[[ $DO_REMOTE -eq 1 ]] && prune_remote_backups

ok "cleanup complete"