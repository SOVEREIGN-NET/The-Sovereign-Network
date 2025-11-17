#!/bin/bash

echo "📊 ZHTP Dual Node Monitor"
echo "=========================="
echo ""

# Dev Node Status
echo "🔧 DEV NODE (Port 8001)"
DEV_STATUS=$(curl -s http://localhost:8001/api/status 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$DEV_STATUS" | jq . 2>/dev/null || echo "$DEV_STATUS"
else
    echo "❌ Dev node not responding on port 8001"
fi

echo ""

# Prod Node Status
echo "🏭 PROD NODE (Port 8000)"
PROD_STATUS=$(curl -s http://localhost:8000/api/status 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$PROD_STATUS" | jq . 2>/dev/null || echo "$PROD_STATUS"
else
    echo "❌ Prod node not responding on port 8000"
fi

echo ""
echo "=== Process Status ==="
ps aux | grep -E "[z]htp" | awk '{printf "PID: %-8s CPU: %-6s MEM: %-6s CMD: %s\n", $2, $3"%", $4"%", $11}'

echo ""
echo "=== Resource Usage ==="
echo "Memory:"
free -h | grep -E "Mem|Swap"
echo ""
echo "Disk:"
df -h | grep -E "Filesystem|/home"
