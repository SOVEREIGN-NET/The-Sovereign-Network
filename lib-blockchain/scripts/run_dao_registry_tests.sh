#!/usr/bin/env bash
set -euo pipefail

# Run only DAO registry related tests
cargo test -p lib-blockchain --lib --test-threads=1 -- --nocapture --test-threads=1

echo "DAO registry tests completed"
