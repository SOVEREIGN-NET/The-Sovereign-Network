#!/bin/bash

# Smart Architecture Validation Script
# Wrapper that runs the full architecture validation suite

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Running Smart Architecture Validation..."

echo ""
if ./scripts/validate-architecture.sh; then
    echo ""
    echo "🎉 Architecture Compliance: VALID"
    exit 0
else
    echo ""
    echo "💥 Architecture Compliance: INVALID"
    exit 1
fi
