#!/bin/bash
# ZHTP Linux Build Script
# Automatically installs dependencies and builds ZHTP on Linux

set -e  # Exit on error

echo "==================================="
echo "ZHTP Linux Build Script"
echo "==================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This script is for Linux only"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
fi

echo "Detected OS: $OS $VER"
echo ""

# Install system dependencies based on distribution
echo "Step 1: Installing system dependencies..."

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Raspbian"* ]]; then
    echo "Installing packages for Debian/Ubuntu/Raspbian..."
    sudo apt update
    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        bluetooth \
        bluez \
        libbluetooth-dev \
        libudev-dev
    
elif [[ "$OS" == *"Fedora"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"CentOS"* ]]; then
    echo "Installing packages for Fedora/RHEL/CentOS..."
    sudo dnf install -y \
        gcc \
        pkg-config \
        openssl-devel \
        bluez \
        bluez-libs-devel \
        systemd-devel
    
elif [[ "$OS" == *"Arch"* ]]; then
    echo "Installing packages for Arch Linux..."
    sudo pacman -S --needed \
        base-devel \
        pkg-config \
        openssl \
        bluez \
        bluez-libs \
        systemd
else
    echo "Warning: Unknown distribution. Please manually install:"
    echo "  - build-essential / gcc"
    echo "  - pkg-config"
    echo "  - openssl development headers"
    echo "  - bluez and bluetooth development headers"
    echo "  - systemd development headers (libudev)"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "✓ System dependencies installed"
echo ""

# Check for Rust
echo "Step 2: Checking Rust installation..."
if ! command -v cargo &> /dev/null; then
    echo "Rust is not installed. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✓ Rust installed"
else
    echo "✓ Rust is already installed ($(rustc --version))"
fi
echo ""

# Enable Bluetooth service
echo "Step 3: Enabling Bluetooth service..."
if systemctl is-active --quiet bluetooth; then
    echo "✓ Bluetooth service is already running"
else
    echo "Starting Bluetooth service..."
    sudo systemctl start bluetooth
    sudo systemctl enable bluetooth
    echo "✓ Bluetooth service started and enabled"
fi
echo ""

# Build ZHTP
echo "Step 4: Building ZHTP..."
echo "This may take several minutes on first build..."
echo ""

# Detect if we're on a Raspberry Pi or low-memory system
TOTAL_MEM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_GB=$((TOTAL_MEM / 1024 / 1024))

echo "Detected RAM: ${TOTAL_MEM_GB}GB"

# Configure build based on available memory
if [ "$TOTAL_MEM_GB" -lt 2 ]; then
    echo "Low memory system detected (<2GB). Applying optimizations..."
    
    # Check if swap is enabled
    SWAP_SIZE=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
    if [ "$SWAP_SIZE" -lt 2097152 ]; then  # Less than 2GB swap
        echo ""
        echo "WARNING: Insufficient swap space detected!"
        echo "Current swap: $((SWAP_SIZE / 1024 / 1024))GB"
        echo ""
        echo "Creating 4GB swap file for compilation..."
        
        if [ ! -f /swapfile ]; then
            sudo fallocate -l 4G /swapfile
            sudo chmod 600 /swapfile
            sudo mkswap /swapfile
            sudo swapon /swapfile
            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
            echo "✓ Swap space created and enabled"
        else
            sudo swapon /swapfile
            echo "✓ Existing swap file enabled"
        fi
        echo ""
    fi
    
    # Use Raspberry Pi optimized profile with single job
    echo "Building with Raspberry Pi optimized profile (low memory mode)..."
    echo "Note: WASM contract runtime disabled to save memory during compilation"
    cargo build --profile rpi --features "linux-bluetooth,rpi" --no-default-features -j 1
    
    BUILD_DIR="rpi"
    BINARY_PATH="./target/rpi/zhtp"
else
    echo "Sufficient memory detected. Building with standard release profile..."
    
    # Use the linux-bluetooth feature for Linux builds with full blockchain
    cargo build --release --features linux-bluetooth
    
    BUILD_DIR="release"
    BINARY_PATH="./target/release/zhtp"
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "==================================="
    echo "✓ Build successful!"
    echo "==================================="
    echo ""
    echo "Binary location: ${BINARY_PATH}"
    echo ""
    echo "To run ZHTP:"
    echo "  ${BINARY_PATH} serve --port 8080"
    echo ""
    echo "For help:"
    echo "  ${BINARY_PATH} --help"
    echo ""
else
    echo ""
    echo "==================================="
    echo "✗ Build failed"
    echo "==================================="
    echo ""
    echo "Please check the error messages above."
    exit 1
fi
