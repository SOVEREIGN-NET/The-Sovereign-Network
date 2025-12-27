#!/bin/bash
# Quick feature validation - checks core feature combinations only

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ZHTP-CLI Feature Validation (Quick)"
echo "=========================================="
echo ""

echo "[FEATURES DEFINED]"
echo "✓ edge, full-blockchain, rpi, minimal-blockchain"
echo "✓ validator, basic-blockchain, lib-blockchain, relay"
echo ""

echo "[TESTING RECOMMENDED COMBINATIONS]"
passed=0
failed=0

recommended=(
    "Developer Setup|full-blockchain,validator"
    "Relay Network|full-blockchain,relay"
    "Edge Device|minimal-blockchain,edge"
    "Raspberry Pi|minimal-blockchain,rpi"
    "Basic Setup|basic-blockchain"
)

for config in "${recommended[@]}"; do
    IFS='|' read -r name features_str <<< "$config"
    printf "%-25s (%-35s) ... " "$name" "$features_str"
    if cargo check -p zhtp-cli --features "$features_str" --quiet 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((passed++))
    else
        echo -e "${RED}✗${NC}"
        ((failed++))
    fi
done

echo ""
echo "[TESTING OVERLAPPING COMBINATIONS]"
echo "Note: Cargo does not enforce mutually exclusive features"

overlapping=(
    "Full+Basic Blockchains|full-blockchain,basic-blockchain"
    "Basic+Minimal Blockchains|basic-blockchain,minimal-blockchain"
)

for config in "${overlapping[@]}"; do
    IFS='|' read -r name features_str <<< "$config"
    printf "%-30s (%-35s) ... " "$name" "$features_str"
    if cargo check -p zhtp-cli --features "$features_str" --quiet 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((passed++))
    else
        echo -e "${RED}✗${NC}"
        ((failed++))
    fi
done

echo ""
echo "=========================================="
echo "Feature Validation Summary"
echo "=========================================="
echo "Recommended combinations: 5"
echo "Overlapping combinations: 2"
echo ""
echo "Results: ${GREEN}$passed passed${NC}, ${RED}$failed failed${NC}"
echo ""

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All feature tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some feature tests failed${NC}"
    exit 1
fi
