#!/bin/bash
# Build ZHTP XCFramework for iOS
#
# This script builds the ZHTP mobile library for iOS device and simulator,
# then creates a universal XCFramework that can be imported into Xcode projects.
#
# Prerequisites:
# - macOS with Xcode installed
# - Rust with iOS targets installed
#
# Usage: ./build_ios.sh [debug|release]

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BUILD_TYPE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/target/ios"
FRAMEWORK_NAME="ZhtpFramework"
LIB_NAME="zhtp_mobile"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Building lib-client for iOS ($BUILD_TYPE)                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED} This script must be run on macOS with Xcode installed${NC}"
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED} Rust is not installed. Install from https://rustup.rs${NC}"
    exit 1
fi

# Check if Xcode is installed
if ! command -v xcodebuild &> /dev/null; then
    echo -e "${RED} Xcode is not installed${NC}"
    echo -e "   Install from: https://developer.apple.com/xcode/"
    exit 1
fi

echo -e "${GREEN} Xcode found: $(xcodebuild -version | head -n 1)${NC}"

# Add iOS targets if not installed
echo ""
echo -e "${BLUE} Checking Rust iOS targets...${NC}"
TARGETS=(
    "aarch64-apple-ios"          # Device (ARM64)
    "aarch64-apple-ios-sim"      # Simulator (Apple Silicon)
    "x86_64-apple-ios"           # Simulator (Intel)
)

for target in "${TARGETS[@]}"; do
    if rustup target list | grep -q "$target (installed)"; then
        echo -e "${GREEN} $target already installed${NC}"
    else
        echo -e "${YELLOW}⚙ Installing $target...${NC}"
        rustup target add "$target"
    fi
done

# Clean previous builds
echo ""
echo -e "${BLUE}🧹 Cleaning previous builds...${NC}"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Set build flags
if [ "$BUILD_TYPE" = "release" ]; then
    BUILD_FLAG="--release"
    PROFILE="release"
else
    BUILD_FLAG=""
    PROFILE="debug"
fi

cd "$PROJECT_DIR"

# Build for each architecture
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                Building for iOS Targets                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

# iOS Device (ARM64)
echo ""
echo -e "${BLUE} Building for iOS device (aarch64-apple-ios)...${NC}"
IPHONEOS_DEPLOYMENT_TARGET=14.0 cargo build --target aarch64-apple-ios $BUILD_FLAG --package lib-client --lib
echo -e "${GREEN} iOS device build complete${NC}"

# iOS Simulator (Apple Silicon)
echo ""
echo -e "${BLUE} Building for iOS simulator ARM64 (aarch64-apple-ios-sim)...${NC}"
IPHONEOS_DEPLOYMENT_TARGET=14.0 cargo build --target aarch64-apple-ios-sim $BUILD_FLAG --package lib-client --lib
echo -e "${GREEN} iOS simulator ARM64 build complete${NC}"

# iOS Simulator (Intel)
echo ""
echo -e "${BLUE} Building for iOS simulator x86_64 (x86_64-apple-ios)...${NC}"
IPHONEOS_DEPLOYMENT_TARGET=14.0 cargo build --target x86_64-apple-ios $BUILD_FLAG --package lib-client --lib
echo -e "${GREEN} iOS simulator x86_64 build complete${NC}"

# Create fat library for simulator (ARM64 + x86_64)
echo ""
echo -e "${BLUE} Creating universal simulator library...${NC}"
mkdir -p "$OUTPUT_DIR/simulator"
lipo -create \
    "$PROJECT_DIR/target/aarch64-apple-ios-sim/$PROFILE/libzhtp_client.a" \
    "$PROJECT_DIR/target/x86_64-apple-ios/$PROFILE/libzhtp_client.a" \
    -output "$OUTPUT_DIR/simulator/libzhtp_client.a"
echo -e "${GREEN} Universal simulator library created${NC}"

# Copy device library
echo ""
echo -e "${BLUE} Copying device library...${NC}"
mkdir -p "$OUTPUT_DIR/device"
cp "$PROJECT_DIR/target/aarch64-apple-ios/$PROFILE/libzhtp_client.a" "$OUTPUT_DIR/device/"
echo -e "${GREEN} Device library copied${NC}"

# Generate C header file
echo ""
echo -e "${BLUE} Generating C header file...${NC}"
cat > "$OUTPUT_DIR/zhtp.h" << 'EOF'
#ifndef ZHTP_H
#define ZHTP_H

#include <stdint.h>
#include <stdbool.h>

// Core ZHTP functions
char* zhtp_init_node(const char* device_type, bool enable_multipeer, bool enable_bluetooth, bool enable_mdns, uint16_t port);
char* zhtp_start_node(void);
char* zhtp_stop_node(void);
char* zhtp_get_status(void);
char* zhtp_discover_peers(uint64_t timeout_secs);
char* zhtp_connect_to_peer(const char* peer_address, const char* peer_id);
char* zhtp_send_message(const char* peer_id, const char* message);
char* zhtp_get_connected_peers(void);
void zhtp_free_string(char* s);

// iOS callbacks
void zhtp_on_multipeer_peer_discovered(const char* peer_id, const char* display_name);
void zhtp_on_bluetooth_peripheral_discovered(const char* peripheral_uuid, const char* peripheral_name, int32_t rssi);
void zhtp_on_multipeer_state_changed(bool is_connected, const char* peer_id);
void zhtp_on_bluetooth_state_changed(bool is_connected, const char* peripheral_uuid);
void zhtp_on_multipeer_data_received(const uint8_t* data, size_t data_len, const char* peer_id);
void zhtp_on_bluetooth_data_received(const uint8_t* data, size_t data_len, const char* peripheral_uuid);

#endif // ZHTP_H
EOF
echo -e "${GREEN} Header file generated${NC}"

# Create module map
cat > "$OUTPUT_DIR/module.modulemap" << EOF
module $FRAMEWORK_NAME {
    header "zhtp.h"
    export *
}
EOF

# Create framework for device
echo ""
echo -e "${BLUE}🏗️  Creating device framework...${NC}"
DEVICE_FRAMEWORK="$OUTPUT_DIR/${FRAMEWORK_NAME}-device.framework"
mkdir -p "$DEVICE_FRAMEWORK/Headers"
mkdir -p "$DEVICE_FRAMEWORK/Modules"
cp "$OUTPUT_DIR/device/libzhtp_client.a" "$DEVICE_FRAMEWORK/$FRAMEWORK_NAME"
cp "$OUTPUT_DIR/zhtp.h" "$DEVICE_FRAMEWORK/Headers/"
cp "$OUTPUT_DIR/module.modulemap" "$DEVICE_FRAMEWORK/Modules/"

# Create Info.plist for device framework
cat > "$DEVICE_FRAMEWORK/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>net.sovereign.zhtp</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$FRAMEWORK_NAME</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF
echo -e "${GREEN} Device framework created${NC}"

# Create framework for simulator
echo ""
echo -e "${BLUE}🏗️  Creating simulator framework...${NC}"
SIMULATOR_FRAMEWORK="$OUTPUT_DIR/${FRAMEWORK_NAME}-simulator.framework"
mkdir -p "$SIMULATOR_FRAMEWORK/Headers"
mkdir -p "$SIMULATOR_FRAMEWORK/Modules"
cp "$OUTPUT_DIR/simulator/libzhtp_client.a" "$SIMULATOR_FRAMEWORK/$FRAMEWORK_NAME"
cp "$OUTPUT_DIR/zhtp.h" "$SIMULATOR_FRAMEWORK/Headers/"
cp "$OUTPUT_DIR/module.modulemap" "$SIMULATOR_FRAMEWORK/Modules/"
cp "$DEVICE_FRAMEWORK/Info.plist" "$SIMULATOR_FRAMEWORK/"
echo -e "${GREEN} Simulator framework created${NC}"

# Create XCFramework
echo ""
echo -e "${BLUE} Creating XCFramework...${NC}"
XCFRAMEWORK="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
    -framework "$DEVICE_FRAMEWORK" \
    -framework "$SIMULATOR_FRAMEWORK" \
    -output "$XCFRAMEWORK"
echo -e "${GREEN} XCFramework created${NC}"

# Clean up intermediate files
echo ""
echo -e "${BLUE}🧹 Cleaning up intermediate files...${NC}"
rm -rf "$DEVICE_FRAMEWORK"
rm -rf "$SIMULATOR_FRAMEWORK"
rm -rf "$OUTPUT_DIR/device"
rm -rf "$OUTPUT_DIR/simulator"
rm "$OUTPUT_DIR/zhtp.h"
rm "$OUTPUT_DIR/module.modulemap"

# Display framework size
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Framework Size                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
du -sh "$XCFRAMEWORK" | awk '{print "  Total: " $1}'

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             iOS Build Completed Successfully!             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN} Output: $XCFRAMEWORK${NC}"
echo ""
echo -e "${BLUE}To use in Xcode:${NC}"
echo ""
echo -e "  1. Drag $FRAMEWORK_NAME.xcframework into your Xcode project"
echo -e "  2. Select your target → General → Frameworks, Libraries, and Embedded Content"
echo -e "  3. Set the framework to ${YELLOW}\"Embed & Sign\"${NC}"
echo -e "  4. Add to your Swift code:"
echo -e "     ${YELLOW}import $FRAMEWORK_NAME${NC}"
echo ""
echo -e "${GREEN} Done!${NC}"
