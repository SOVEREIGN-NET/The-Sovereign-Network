#!/usr/bin/env bash
set -euo pipefail

# Run lib-network mesh integration tests (ALPHA-STEP2). These tests are gated
# behind the `allow-net-tests` feature to avoid accidental execution in CI.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

echo "Running mesh integration tests for lib-network..."

# Use a single thread for deterministic runs unless you want concurrent scheduling
RUST_TEST_THREADS=1 cargo test -p lib-network --test mesh_integration --features allow-net-tests -- --nocapture

echo "Done."
#!/usr/bin/env bash
set -euo pipefail

# Runs the lib-network mesh integration tests.
# Feature-guarded; enable with `--features allow-net-tests` to allow network integration tests.

cd "$(dirname "$0")/.."
echo "Running mesh integration tests for lib-network (feature: allow-net-tests)"

cargo test -p lib-network --test mesh_integration --features allow-net-tests -- --nocapture

echo "Finished mesh integration tests."
