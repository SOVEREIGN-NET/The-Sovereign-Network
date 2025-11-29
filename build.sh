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
echo "Binary location: target/release/zhtp-orchestrator"
echo ""
echo "To run a node:"
echo "  ./run-node.sh"
echo "  or"
echo "  ./target/release/zhtp-orchestrator --config zhtp/configs/test-node1.toml"
