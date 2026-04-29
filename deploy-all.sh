#!/bin/bash
set -euo pipefail

BINARY="target/debug/zhtp"
NODES=(zhtp-g1 zhtp-g2 zhtp-g3 zhtp-gateway)
SUDO_NODES=(zhtp-g4 zhtp-g5 zhtp-gateway-2)
ALL_NODES=("${NODES[@]}" "${SUDO_NODES[@]}")

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: $BINARY not found. Build first: cargo build --release -p zhtp"
    exit 1
fi

restart_node() {
    local node="$1"
    if [[ " ${SUDO_NODES[*]} " =~ " ${node} " ]]; then
        ssh "$node" "sudo systemctl restart zhtp"
        ssh "$node" "sudo systemctl is-active zhtp"
    else
        ssh "$node" "systemctl restart zhtp"
        ssh "$node" "systemctl is-active zhtp"
    fi
}

echo "=== Deploying to all nodes ==="
for node in "${ALL_NODES[@]}"; do
    echo "--- $node ---"
    rsync -az --progress "$BINARY" "$node:/opt/zhtp/zhtp"
    ssh "$node" "chmod +x /opt/zhtp/zhtp"
    restart_node "$node"
    echo "  $node: deployed + restarted"
done

echo ""
echo "=== All nodes deployed ==="
