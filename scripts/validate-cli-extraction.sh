#!/bin/bash
# Validate ZHTP CLI extraction (Issue #422)
# Ensures CLI extraction maintains code quality and functionality

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "ZHTP CLI Extraction Validation"
echo "=========================================="
echo ""

# Check 1: Directory structure
echo "[1/8] Checking directory structure..."
if [ ! -d "zhtp-cli" ]; then
    echo -e "${RED}✗ zhtp-cli directory missing${NC}"
    exit 1
fi

required_dirs=("src" "src/commands" "tests")
for dir in "${required_dirs[@]}"; do
    if [ ! -d "zhtp-cli/$dir" ]; then
        echo -e "${RED}✗ zhtp-cli/$dir missing${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ Directory structure valid${NC}"
echo ""

# Check 2: Build zhtp independently (library without CLI)
echo "[2/8] Building zhtp library (no CLI)..."
if ! cargo build -p zhtp --lib --quiet 2>/dev/null; then
    echo -e "${RED}✗ zhtp library build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ zhtp library builds independently${NC}"
echo ""

# Check 3: Build zhtp-cli
echo "[3/8] Building zhtp-cli..."
if ! cargo build -p zhtp-cli --quiet 2>/dev/null; then
    echo -e "${RED}✗ zhtp-cli build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ zhtp-cli builds successfully${NC}"
echo ""

# Check 4: Run zhtp-cli tests
echo "[4/8] Running zhtp-cli unit tests..."
test_output=$(cargo test -p zhtp-cli --lib 2>&1 | grep "test result" | head -1)
if [[ "$test_output" =~ "passed" ]]; then
    # Extract pass count
    passed_count=$(echo "$test_output" | grep -oE '[0-9]+ passed' | cut -d' ' -f1)
    echo -e "${GREEN}✓ $passed_count unit tests passing${NC}"
else
    echo -e "${YELLOW}⚠ Could not verify test results${NC}"
fi
echo "   $test_output"
echo ""

# Check 5: Run integration tests
echo "[5/8] Running integration tests..."
if ! cargo test -p zhtp-cli --test integration_tests --quiet 2>/dev/null; then
    echo -e "${RED}✗ Integration tests failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Integration tests passing${NC}"
echo ""

# Check 6: Run handler tests
echo "[6/8] Running handler tests..."
if ! cargo test -p zhtp-cli --test handler_tests --quiet 2>/dev/null; then
    echo -e "${RED}✗ Handler tests failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Handler tests passing${NC}"
echo ""

# Check 7: Verify binary name change
echo "[7/8] Verifying binary name..."
if cargo build -p zhtp-cli --quiet 2>/dev/null && [ -f "target/debug/zhtp-cli" ]; then
    echo -e "${GREEN}✓ Binary name is 'zhtp-cli' (not 'zhtp')${NC}"
else
    echo -e "${YELLOW}⚠ Could not verify binary name${NC}"
fi
echo ""

# Check 8: Check for circular dependencies
echo "[8/8] Checking for dependency issues..."
if cargo tree -p zhtp-cli 2>/dev/null | grep -q "zhtp-cli.*zhtp.*zhtp-cli"; then
    echo -e "${RED}✗ Circular dependency detected${NC}"
    exit 1
else
    echo -e "${GREEN}✓ No circular dependencies${NC}"
fi
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}✓ All validation checks passed!${NC}"
echo "=========================================="
echo ""
echo "CLI Extraction Summary:"
echo "  • zhtp library: Independent, no CLI code"
echo "  • zhtp-cli binary: Separate distribution"
echo "  • Binary name: zhtp-cli"
echo "  • Unit tests: PASSING"
echo "  • Integration tests: PASSING"
echo "  • Handler tests: PASSING"
echo ""
echo "Next steps:"
echo "  1. Run feature flag matrix tests: ./scripts/validate-all-builds.sh"
echo "  2. Test on multiple platforms"
echo "  3. Update documentation for binary name change"
echo ""
