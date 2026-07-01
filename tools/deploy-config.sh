#!/usr/bin/env bash
#
# deploy-config.sh — push shared config to all nodes, preserving node-local sections.
#
# Usage:
#   ./tools/deploy-config.sh                 # deploy shared config to all nodes
#   ./tools/deploy-config.sh zhtp-g1 zhtp-g2 # deploy to specific nodes only
#   ./tools/deploy-config.sh --restart       # deploy + restart all nodes
#   ./tools/deploy-config.sh --restart zhtp-g1  # deploy + restart specific node
#
# Config structure:
#   tools/node-configs/shared.toml            — shared across all nodes
#   tools/node-configs/<node>.local.toml      — node-specific overrides
#
# Local override format:
#   - Lines starting with "# SED: old -> new" apply sed replacements on shared config
#   - Non-comment, non-empty lines are appended as extra TOML sections
#
# Example (zhtp-gateway.local.toml):
#   # SED: validator_enabled = true -> validator_enabled = false
#   [zdns]
#   enabled = true
#   port = 53
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SHARED_CONFIG="$SCRIPT_DIR/node-configs/shared.toml"
LOCAL_DIR="$SCRIPT_DIR/node-configs"

ALL_NODES=(zhtp-g1 zhtp-g2 zhtp-g3)
SUDO_NODES=()  # g1–g3 deploy without sudo

DO_RESTART=false
if [[ "${1:-}" == "--restart" ]]; then
    DO_RESTART=true
    shift
fi

if [[ $# -gt 0 ]]; then
    NODES=("$@")
else
    NODES=("${ALL_NODES[@]}")
fi

if [[ ! -f "$SHARED_CONFIG" ]]; then
    echo "ERROR: $SHARED_CONFIG not found."
    exit 1
fi

needs_sudo() {
    local node="$1"
    for s in "${SUDO_NODES[@]}"; do
        [[ "$s" == "$node" ]] && return 0
    done
    return 1
}

run_remote() {
    local node="$1"
    shift
    if needs_sudo "$node"; then
        ssh "$node" "sudo $*"
    else
        ssh "$node" "$*"
    fi
}

for node in "${NODES[@]}"; do
    echo "--- $node ---"

    # Start with shared config
    cp "$SHARED_CONFIG" /tmp/config_merged.toml

    # Apply node-local overrides
    local_file="$LOCAL_DIR/${node}.local.toml"
    if [[ -f "$local_file" ]]; then
        # Process SED directives: "# SED: old -> new"
        while IFS= read -r line; do
            if [[ "$line" =~ ^#\ SED:\ (.+)\ -\>\ (.+)$ ]]; then
                old="${BASH_REMATCH[1]}"
                new="${BASH_REMATCH[2]}"
                sed -i "s|${old}|${new}|g" /tmp/config_merged.toml
                echo "  SED: $old -> $new"
            fi
        done < "$local_file"

        # Append non-comment, non-empty lines (extra TOML sections like [zdns])
        grep -v '^#' "$local_file" | grep -v '^$' >> /tmp/config_merged.toml 2>/dev/null || true
    fi

    # Validate TOML
    if command -v python3 &>/dev/null; then
        if ! python3 -c "import tomllib; tomllib.load(open('/tmp/config_merged.toml','rb'))" 2>/dev/null; then
            echo "  ERROR: merged config is invalid TOML. Skipping $node."
            continue
        fi
        echo "  TOML valid."
    fi

    # Backup + deploy
    scp -q /tmp/config_merged.toml "$node:/tmp/config_new.toml"
    run_remote "$node" "cp /opt/zhtp/config.toml /opt/zhtp/config.toml.bak && cp /tmp/config_new.toml /opt/zhtp/config.toml"
    echo "  Config deployed."
done

if $DO_RESTART; then
    echo ""
    echo "Restarting nodes..."
    for node in "${NODES[@]}"; do
        run_remote "$node" "systemctl restart zhtp"
        echo "  $node restarted."
    done
    sleep 3
    echo ""
    echo "Verifying..."
    for node in "${NODES[@]}"; do
        status=$(run_remote "$node" "systemctl is-active zhtp" 2>/dev/null)
        echo "  $node: $status"
    done
else
    echo ""
    echo "Configs deployed. Restart when ready:"
    echo "  for node in ${NODES[*]}; do ssh \$node 'systemctl restart zhtp'; done"
fi
