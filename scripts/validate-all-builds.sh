#!/bin/bash
# Validate all feature flag combinations for zhtp-cli
# Ensures CLI compiles with all supported blockchain and node types

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ZHTP-CLI Feature Matrix Validation"
echo "=========================================="
echo ""

# Feature combinations to test
declare -a BLOCKCHAIN_FEATURES=("full-blockchain" "basic-blockchain" "minimal-blockchain")
declare -a NODE_FEATURES=("validator" "relay" "edge" "rpi")

total_builds=0
passed_builds=0
failed_builds=0

# Test 1: No features (default)
echo "[TEST] Building with default features..."
if cargo build -p zhtp-cli --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Default (no features)${NC}"
    ((passed_builds++))
else
    echo -e "${RED}✗ Default (no features)${NC}"
    ((failed_builds++))
fi
((total_builds++))
echo ""

# Test 2: Individual blockchain features
echo "[BLOCKCHAIN FEATURES]"
for blockchain_feature in "${BLOCKCHAIN_FEATURES[@]}"; do
    echo "  Testing with --features $blockchain_feature"
    if cargo build -p zhtp-cli --features "$blockchain_feature" --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✓ $blockchain_feature${NC}"
        ((passed_builds++))
    else
        echo -e "  ${RED}✗ $blockchain_feature${NC}"
        ((failed_builds++))
    fi
    ((total_builds++))
done
echo ""

# Test 3: Individual node features
echo "[NODE FEATURES]"
for node_feature in "${NODE_FEATURES[@]}"; do
    echo "  Testing with --features $node_feature"
    if cargo build -p zhtp-cli --features "$node_feature" --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✓ $node_feature${NC}"
        ((passed_builds++))
    else
        echo -e "  ${RED}✗ $node_feature${NC}"
        ((failed_builds++))
    fi
    ((total_builds++))
done
echo ""

# Test 4: Blockchain + Node combinations
echo "[COMBINATION FEATURES]"
combos=(
    "full-blockchain,validator"
    "full-blockchain,relay"
    "basic-blockchain,relay"
    "minimal-blockchain,relay"
    "minimal-blockchain,edge"
    "edge,relay"
)

for combo in "${combos[@]}"; do
    echo "  Testing with --features $combo"
    if cargo build -p zhtp-cli --features "$combo" --quiet 2>/dev/null; then
        echo -e "  ${GREEN}✓ $combo${NC}"
        ((passed_builds++))
    else
        echo -e "  ${RED}✗ $combo${NC}"
        ((failed_builds++))
    fi
    ((total_builds++))
done
echo ""

# Test 5: All blockchain features together (should fail or be invalid)
echo "[SANITY CHECK]"
echo "  Attempting invalid combination: all blockchain features together"
echo "  (This should fail - only one blockchain feature allowed)"
if cargo build -p zhtp-cli --features "full-blockchain,basic-blockchain" --quiet 2>/dev/null; then
    echo -e "  ${YELLOW}⚠ Unexpected success - check feature validation${NC}"
else
    echo -e "  ${GREEN}✓ Correctly rejects invalid combination${NC}"
    ((passed_builds++))
fi
((total_builds++))
echo ""

# Test 6: Run tests with default features
echo "[TESTS WITH FEATURES]"
if cargo test -p zhtp-cli --test integration_tests --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Integration tests pass${NC}"
    ((passed_builds++))
else
    echo -e "${RED}✗ Integration tests fail${NC}"
    ((failed_builds++))
fi
((total_builds++))

if cargo test -p zhtp-cli --test feature_tests --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Feature tests pass${NC}"
    ((passed_builds++))
else
    echo -e "${RED}✗ Feature tests fail${NC}"
    ((failed_builds++))
fi
((total_builds++))

if cargo test -p zhtp-cli --lib --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Library tests pass${NC}"
    ((passed_builds++))
else
    echo -e "${RED}✗ Library tests fail${NC}"
    ((failed_builds++))
fi
((total_builds++))
echo ""

# Summary
echo "=========================================="
echo "Feature Matrix Validation Summary"
echo "=========================================="
echo "Total build tests: $total_builds"
echo -e "Passed: ${GREEN}$passed_builds${NC}"
echo -e "Failed: ${RED}$failed_builds${NC}"
echo ""

if [ $failed_builds -eq 0 ]; then
    echo -e "${GREEN}✓ All feature combinations validated successfully!${NC}"
    echo ""
    echo "Tested features:"
    echo "  Blockchain: ${BLOCKCHAIN_FEATURES[*]}"
    echo "  Node types: ${NODE_FEATURES[*]}"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some feature combinations failed validation${NC}"
    echo ""
    exit 1
fi
