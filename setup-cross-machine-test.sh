#!/bin/bash

# ZHTP Cross-Machine Test Setup Script
# Run this on both machines to prepare for testing

echo ""
echo "🚀 ZHTP Cross-Machine Test Setup"
echo "================================"
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Please run this script from the ZHTP directory"
    echo "Current directory: $(pwd)"
    echo "Expected files: Cargo.toml, src/main.rs"
    exit 1
fi

echo "✅ Found ZHTP project files"
echo ""

# Check Rust installation
echo "🔍 Checking Rust installation..."
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Please install Rust from https://rustup.rs/"
    exit 1
fi
echo "✅ Rust is installed ($(cargo --version))"

# Get system info
echo ""
echo "📊 System Information:"
echo "Computer Name: $(hostname)"
echo "User: $(whoami)"
echo "OS: $(uname -s)"
echo "Current Directory: $(pwd)"
echo ""

# Build the project
echo "🔨 Building ZHTP (this may take a few minutes)..."
if ! cargo build --release; then
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi
echo "✅ Build completed successfully"

# Check network connectivity
echo ""
echo "🌐 Network Configuration:"
if command -v ip &> /dev/null; then
    ip addr show | grep "inet " | grep -v "127.0.0.1"
elif command -v ifconfig &> /dev/null; then
    ifconfig | grep "inet " | grep -v "127.0.0.1"
else
    echo "Network interface information not available"
fi
echo ""

# Create test directory
mkdir -p test-results

# Generate machine-specific identifier
echo "$(hostname)-$(whoami)-$(date)" > test-results/machine-id.txt

# Make scripts executable
chmod +x run-zhtp.sh
chmod +x setup-cross-machine-test.sh

echo ""
echo "🎯 Setup Complete! Next Steps:"
echo ""
echo "1. Run this script on the second machine"
echo "2. On Machine A (Primary): ./run-zhtp.sh"
echo "3. Wait for 'HTTP API Server listening on port 8000'"
echo "4. On Machine B (Secondary): ./run-zhtp.sh"
echo "5. Wait for 'Bootstrap connections completed'"
echo "6. Open browsers on both machines: http://localhost:8000/"
echo "7. Follow the Cross-Machine Testing Guide"
echo ""
echo "Machine ID: $(cat test-results/machine-id.txt)"
echo ""

# Optional: Open the testing guide
echo "📖 Testing guide available at: CROSS_MACHINE_TESTING_GUIDE.md"
echo ""
echo "🚀 Ready for cross-machine testing!"
echo "Run './run-zhtp.sh' to start your ZHTP node"
echo ""
