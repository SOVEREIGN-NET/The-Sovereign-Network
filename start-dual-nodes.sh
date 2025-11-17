#!/bin/bash

echo "🚀 Starting ZHTP Dual Node Setup with Environment Variables"
echo ""

# Create directories
mkdir -p data-dev data-prod logs

# Stop any existing nodes
echo "Stopping existing nodes..."
pkill zhtp 2>/dev/null
sleep 2

# Start Dev Node (all ports + 1)
echo "Starting Dev Node (API: 8001, P2P: 19848, Bind: 7001, Metrics: 9001)..."
ZHTP_NODE_NAME="dev-node" \
ZHTP_API_PORT=8001 \
ZHTP_P2P_PORT=19848 \
ZHTP_BIND_PORT=7001 \
ZHTP_METRICS_PORT=9001 \
./target/release/zhtp > logs/dev-console.log 2>&1 &
DEV_PID=$!
echo "Dev Node PID: $DEV_PID"

sleep 3

# Start Prod Node (default ports)
echo "Starting Prod Node (API: 8000, P2P: 19847, Bind: 7000, Metrics: 9000)..."
ZHTP_NODE_NAME="prod-node" \
ZHTP_API_PORT=8000 \
ZHTP_P2P_PORT=19847 \
ZHTP_BIND_PORT=7000 \
ZHTP_METRICS_PORT=9000 \
./target/release/zhtp > logs/prod-console.log 2>&1 &
PROD_PID=$!
echo "Prod Node PID: $PROD_PID"

sleep 5

# Check status
echo ""
echo "=== Node Status ==="
if ps -p $DEV_PID > /dev/null 2>&1; then
    echo "✅ Dev Node: Running (PID $DEV_PID)"
    DEV_STATUS=$(curl -s http://localhost:8001/api/status 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "   API: http://localhost:8001/api/status ✓"
        echo "   $DEV_STATUS"
    else
        echo "   API: http://localhost:8001/api/status (starting...)"
    fi
else
    echo "❌ Dev Node: Failed to start"
    echo "   Check logs: tail logs/dev-console.log"
fi

echo ""

if ps -p $PROD_PID > /dev/null 2>&1; then
    echo "✅ Prod Node: Running (PID $PROD_PID)"
    PROD_STATUS=$(curl -s http://localhost:8000/api/status 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "   API: http://localhost:8000/api/status ✓"
        echo "   $PROD_STATUS"
    else
        echo "   API: http://localhost:8000/api/status (starting...)"
    fi
else
    echo "❌ Prod Node: Failed to start"
    echo "   Check logs: tail logs/prod-console.log"
fi

echo ""
echo "📊 Logs:"
echo "   Dev:  tail -f logs/dev-console.log"
echo "   Prod: tail -f logs/prod-console.log"
echo ""
echo "💡 Monitor both: ./monitor-nodes.sh"
echo "🛑 Stop both: ./stop-nodes.sh"
