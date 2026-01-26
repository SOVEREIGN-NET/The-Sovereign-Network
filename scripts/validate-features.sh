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

# Define feature list
features=(
    "edge:Edge/lightweight node support"
    "full-blockchain:Complete blockchain with all features"
    "rpi:Raspberry Pi optimization"
    "minimal-blockchain:Minimal blockchain for edge devices"
    "validator:Validator node support"
    "basic-blockchain:Basic blockchain without advanced features"
    "lib-blockchain:Blockchain library support"
    "relay:Relay node support"
)

# Generate compatibility matrix
echo "[FEATURE DEFINITIONS]"
for feat_def in "${features[@]}"; do
    IFS=':' read -r feature description <<< "$feat_def"
    printf "%-20s: %s\n" "$feature" "$description"
done
echo ""

echo "[TESTING INDIVIDUAL FEATURES]"
passed=0
failed=0

for feat_def in "${features[@]}"; do
    IFS=':' read -r feature description <<< "$feat_def"
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
        echo -e "${GREEN}✓ Compiles${NC}"
        ((passed++))
    else
        echo -e "${RED}✗ Failed${NC}"
        ((failed++))
    fi
done
echo ""

echo "[SIZE ANALYSIS]"
echo "Skipping release builds - run manually with: cargo build --release -p zhtp-cli --features <feature>"
echo ""

echo "=========================================="
echo "Feature Matrix Report"
echo "=========================================="
echo "Individual features tested: 8"
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
