#!/bin/bash
# ZHTP Node Quick Start Script
# Helps users quickly deploy different types of ZHTP nodes

set -e

echo " ZHTP Node Quick Start"
echo "========================"
echo

# Check if zhtp binary exists
if ! command -v zhtp &> /dev/null && ! [ -f "./target/release/zhtp" ] && ! [ -f "./target/debug/zhtp" ]; then
    echo "ZHTP binary not found. Please build the project first:"
    echo "   cargo build --release"
    exit 1
fi

# Determine zhtp binary path
ZHTP_BIN="zhtp"
if [ -f "./target/release/zhtp" ]; then
    ZHTP_BIN="./target/release/zhtp"
elif [ -f "./target/debug/zhtp" ]; then
    ZHTP_BIN="./target/debug/zhtp"
fi

echo "Available Node Types:"
echo "1) Full Node      - Complete blockchain functionality"
echo "2) Validator Node - Consensus participation (requires staking)"
echo "3) Storage Node   - Distributed storage services"
echo "4) Edge Node      - Mesh networking and ISP bypass"
echo "5) Dev Node       - Development and testing"
echo

read -p "Select node type (1-5): " choice

case $choice in
    1)
        NODE_TYPE="full"
        echo "🖥️ Starting Full Node..."
        echo "This node will run all ZHTP components and provide complete blockchain functionality."
        ;;
    2)
        NODE_TYPE="validator"
        echo "⚡ Starting Validator Node..."
        echo " WARNING: Validator nodes require staking ZHTP tokens and high uptime!"
        echo "Make sure you have:"
        echo "- At least 10,000 ZHTP tokens for staking"
        echo "- Stable internet connection"
        echo "- Dedicated server hardware"
        read -p "Continue? (y/N): " confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
        ;;
    3)
        NODE_TYPE="storage"
        echo "💾 Starting Storage Node..."
        echo "This node will provide distributed storage services to the network."
        echo "Make sure you have sufficient disk space (1TB+ recommended)."
        ;;
    4)
        NODE_TYPE="edge"
        echo "Starting Edge Node..."
        echo "This node will run in pure mesh mode for ISP bypass."
        echo " This mode requires mesh hardware (Bluetooth, WiFi Direct, or LoRaWAN)."
        ;;
    5)
        NODE_TYPE="dev"
        echo "Starting Development Node..."
        echo "This node uses relaxed security settings for development and testing."
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo
echo "Starting ZHTP Node..."
echo "Configuration: ./configs/${NODE_TYPE}-node.toml"
echo "Press Ctrl+C to stop the node"
echo

# Start the node
exec $ZHTP_BIN --node-type $NODE_TYPE