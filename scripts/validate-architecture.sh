#!/bin/bash

# Main Architecture Validation Script
# Runs all architecture enforcement checks for The Sovereign Network

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "🏗️  Running Architecture Enforcement Checks..."
echo "============================================"

ERRORS_FOUND=0

# Run core purity validation
if ! ./scripts/architecture/validate-core-purity.sh; then
    echo "❌ Core purity validation failed"
    ERRORS_FOUND=$((ERRORS_FOUND + 1))
else
    echo "✅ Core purity validation passed"
fi

echo ""

# Run dependency validation
if ! ./scripts/architecture/validate-dependencies.sh; then
    echo "❌ Dependency validation failed"
    ERRORS_FOUND=$((ERRORS_FOUND + 1))
else
    echo "✅ Dependency validation passed"
fi

echo ""

# Run forbidden imports check
if ! ./scripts/architecture/check-forbidden-imports.sh; then
    echo "❌ Forbidden imports check failed"
    ERRORS_FOUND=$((ERRORS_FOUND + 1))
else
    echo "✅ Forbidden imports check passed"
fi

echo ""
echo "============================================"

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "🎉 All architecture enforcement checks passed!"
    echo "✅ Architecture compliance: VALID"
    exit 0
else
    echo "💥 Found $ERRORS_FOUND architecture violations!"
    echo "❌ Architecture compliance: INVALID"
    exit 1
fi
