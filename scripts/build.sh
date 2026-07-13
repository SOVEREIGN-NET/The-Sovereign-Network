#!/bin/bash
set -e

echo "🔨 Building Sovereign Network Mono-Repo..."

# Check for Rust installation
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi

echo "📦 Building all workspace crates..."
cargo build --release --workspace

echo "✅ Build complete!"
echo ""
echo "Binary location: target/release/zhtp"
echo ""
echo "Prune stale artifacts: scripts/clean-build-artifacts.sh"
echo "  (removes target/debug etc.; keeps release + dev-release profiles)"
echo ""
echo "To run a node:"
echo "  ./run-node.sh"
echo "  or"
echo "  ./target/release/zhtp --config zhtp/configs/test-node1.toml"
