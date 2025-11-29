#!/bin/bash
set -e

CONFIG_FILE="${1:-zhtp/configs/test-node1.toml}"

echo "🚀 Starting ZHTP Orchestrator Node..."
echo "📋 Config: $CONFIG_FILE"
echo ""

if [ ! -f "target/release/zhtp-orchestrator" ]; then
    echo "❌ Binary not found. Building first..."
    ./build.sh
fi

echo "▶️  Launching node..."
./target/release/zhtp-orchestrator --config "$CONFIG_FILE"
