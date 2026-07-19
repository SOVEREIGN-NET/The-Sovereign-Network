#!/usr/bin/env bash
#
# Convenience wrapper — validators only (g1–g3).
# Gateways / g4 / g5 are retired; do not add them back.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BINARY="${1:-target/dev-release/zhtp}"

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: $BINARY not found. Build first:" >&2
    echo "  cargo build --profile dev-release -p zhtp -p zhtp-cli" >&2
    exit 1
fi

exec "$ROOT/scripts/deploy-validators.sh" "$BINARY"
