#!/bin/bash
echo '🔍 Running MrCakes931 Pre-Push Security Audit...'

# Run Cargo Audit
if command -v cargo-audit &> /dev/null; then
    cargo audit || { echo '❌ Rust Dependency Audit Failed'; exit 1; }
fi

# Run NPM Audit in sdk-ts
if [ -d 'sdk-ts' ]; then
    cd sdk-ts && npm audit || { echo '❌ TS Dependency Audit Failed'; exit 1; }
    cd ..
fi

echo '✅ Security checks passed. Proceeding with push.'
