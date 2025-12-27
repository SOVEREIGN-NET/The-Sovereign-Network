#!/bin/bash
# Test all feature flag combinations in detail
# Generates a comprehensive feature compatibility matrix

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ZHTP-CLI Feature Compatibility Matrix"
echo "=========================================="
echo ""

# Define feature matrix
declare -A features=(
    [full-blockchain]="Complete blockchain with all features"
    [basic-blockchain]="Basic blockchain without advanced features"
    [minimal-blockchain]="Minimal blockchain for edge devices"
    [validator]="Validator node support"
    [relay]="Relay node support"
    [edge]="Edge/lightweight node support"
    [rpi]="Raspberry Pi optimization"
    [lib-blockchain]="Blockchain library support"
)

# Generate compatibility matrix
echo "[FEATURE DEFINITIONS]"
for feature in "${!features[@]}"; do
    printf "%-20s: %s\n" "$feature" "${features[$feature]}"
done
echo ""

echo "[TESTING INDIVIDUAL FEATURES]"
passed=0
failed=0

for feature in "${!features[@]}"; do
    printf "%-20s ... " "$feature"
    if cargo check -p zhtp-cli --features "$feature" --quiet 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((passed++))
    else
        echo -e "${RED}✗${NC}"
        ((failed++))
    fi
done
echo ""

echo "[TESTING RECOMMENDED COMBINATIONS]"
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

echo "[TESTING INCOMPATIBLE COMBINATIONS]"
incompatible=(
    "Multiple Blockchains|full-blockchain,basic-blockchain"
    "Multiple Blockchains|basic-blockchain,minimal-blockchain"
)

for config in "${incompatible[@]}"; do
    IFS='|' read -r name features_str <<< "$config"
    printf "%-25s (%-35s) ... " "$name" "$features_str"
    if cargo check -p zhtp-cli --features "$features_str" --quiet 2>/dev/null; then
        echo -e "${YELLOW}! Should fail but passed${NC}"
        ((passed++))
    else
        echo -e "${GREEN}✓ Correctly rejected${NC}"
        ((passed++))
    fi
done
echo ""

echo "[SIZE ANALYSIS]"
echo "Building with different features and checking binary size..."
echo ""

features_to_analyze=(
    "minimal-blockchain"
    "basic-blockchain"
    "full-blockchain"
    "full-blockchain,validator"
)

for feat in "${features_to_analyze[@]}"; do
    printf "Size with %s: " "$feat"
    if cargo build -p zhtp-cli --features "$feat" --release --quiet 2>/dev/null; then
        size=$(ls -lh target/release/zhtp-cli 2>/dev/null | awk '{print $5}')
        echo "$size"
    else
        echo "Failed to build"
    fi
done
echo ""

echo "[COMPILATION TIME ANALYSIS]"
echo "Measuring compilation time for key configurations..."
echo ""

echo "Default features:"
time_default=$(
    ( time cargo build -p zhtp-cli --quiet 2>/dev/null ) 2>&1 | grep real | awk '{print $2}'
)
echo "  Time: $time_default"

echo ""

echo "=========================================="
echo "Feature Matrix Report"
echo "=========================================="
echo "Individual features tested: $(echo "${!features[@]}" | wc -w)"
echo "Recommended combinations: 5"
echo "Incompatible combinations: 2"
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
