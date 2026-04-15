#!/bin/bash
# Domain Snapshot — extract all domains via the catalog API
#
# Uses zhtp-cli to fetch the domain catalog from a running node
# and saves it as JSON for replay after reset.
#
# Usage: ./scripts/snapshot-domains.sh <server> <output_file>

set -euo pipefail

SERVER=${1:-"178.105.9.247:9334"}
OUTPUT=${2:-"docs/testnet/domain_snapshot_$(date +%Y-%m-%d).json"}
CLI="./target/release/zhtp-cli"

echo "Fetching domain catalog from $SERVER..."

# The CLI doesn't have a direct catalog command, but we can use
# the blockchain handler or make a raw request. For now, use SSH
# to query the node's in-memory state directly via journalctl.

# Alternative: query the node's API from localhost
ssh zhtp-g3 "curl -s http://127.0.0.1:9334/api/v1/web4/domains/catalog 2>/dev/null" > "$OUTPUT" 2>/dev/null || {
    echo "Direct HTTP failed (expected — node uses QUIC, not HTTP)"
    echo "Domains must be extracted from sled storage backend."
    echo "The domain records are stored via UnifiedStorage (sled blobs)."
    echo ""
    echo "For now: domains will need to be re-registered manually from the app."
    echo "Existing domain owners can re-register their domains after reset."
    exit 1
}
