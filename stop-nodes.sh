#!/bin/bash

echo "🛑 Stopping ZHTP Nodes..."

# Find and stop all zhtp processes
ZHTP_PIDS=$(pgrep -f "zhtp" | tr '\n' ' ')

if [ -z "$ZHTP_PIDS" ]; then
    echo "ℹ️  No ZHTP nodes running"
    exit 0
fi

echo "Found processes: $ZHTP_PIDS"
pkill -f "zhtp"

sleep 2

# Verify
if pgrep -f zhtp > /dev/null; then
    echo "⚠️  Some processes still running, force killing..."
    pkill -9 -f zhtp
    sleep 1
fi

if ! pgrep -f zhtp > /dev/null; then
    echo "✅ All ZHTP nodes stopped"
else
    echo "❌ Failed to stop all nodes"
    echo "Remaining processes:"
    ps aux | grep -E "[z]htp"
fi
