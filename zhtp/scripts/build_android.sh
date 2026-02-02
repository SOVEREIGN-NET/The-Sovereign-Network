#!/bin/bash
# Build ZHTP for Android
#
# This script builds the ZHTP mobile library for all Android architectures
# and creates the proper jniLibs directory structure for Android Studio.
#
# Prerequisites:
# - Android NDK installed (set ANDROID_NDK_HOME or NDK_HOME)
# - Rust with Android targets installed
# - cargo-ndk plugin
#
# Usage: ./build_android.sh [debug|release]

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
OUTPUT_DIR="$PROJECT_DIR/target/android"
MIN_SDK_VERSION=26  # Android 8.0 (Oreo)

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    Building lib-client for Android ($BUILD_TYPE)                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED} Rust is not installed. Install from https://rustup.rs${NC}"
    exit 1
fi

# Check if Android NDK is set
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo -e "${RED} Android NDK not found!${NC}"
    echo -e "${YELLOW}   Set ANDROID_NDK_HOME or NDK_HOME environment variable:${NC}"
    echo ""
    echo -e "   ${BLUE}export ANDROID_NDK_HOME=/path/to/android-ndk${NC}"
    echo ""
    echo -e "   Common locations:"
    echo -e "   - Linux: ~/Android/Sdk/ndk/25.2.9519653"
    echo -e "   - macOS: ~/Library/Android/sdk/ndk/25.2.9519653"
    echo -e "   - Windows: %LOCALAPPDATA%\\Android\\Sdk\\ndk\\25.2.9519653"
    exit 1
fi

NDK_PATH="${ANDROID_NDK_HOME:-$NDK_HOME}"
echo -e "${GREEN} Using Android NDK: $NDK_PATH${NC}"

# Add Android targets if not installed
echo ""
echo -e "${BLUE} Checking Rust Android targets...${NC}"
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "i686-linux-android"
    "x86_64-linux-android"
)

for target in "${TARGETS[@]}"; do
    if rustup target list | grep -q "$target (installed)"; then
        echo -e "${GREEN} $target already installed${NC}"
    else
        echo -e "${YELLOW}⚙ Installing $target...${NC}"
        rustup target add "$target"
    fi
done

# Install cargo-ndk if not present
if ! command -v cargo-ndk &> /dev/null; then
    echo ""
    echo -e "${BLUE} Installing cargo-ndk...${NC}"
    cargo install cargo-ndk
fi

# Clean previous builds
echo ""
echo -e "${BLUE}🧹 Cleaning previous builds...${NC}"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/jniLibs"

# Set build flags
if [ "$BUILD_TYPE" = "release" ]; then
    BUILD_FLAG="--release"
    PROFILE="release"
else
    BUILD_FLAG=""
    PROFILE="debug"
fi

# Build for each architecture
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 Building for Android ABIs                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

cd "$PROJECT_DIR"

# ARM64 (primary target - modern devices)
echo ""
echo -e "${BLUE} Building for ARM64 (aarch64-linux-android)...${NC}"
cargo ndk \
    --target aarch64-linux-android \
    --platform $MIN_SDK_VERSION \
    build $BUILD_FLAG --package lib-client --lib

mkdir -p "$OUTPUT_DIR/jniLibs/arm64-v8a"
cp "target/aarch64-linux-android/$PROFILE/libzhtp_client.so" "$OUTPUT_DIR/jniLibs/arm64-v8a/libquic_jni.so"
echo -e "${GREEN} ARM64 build complete${NC}"

# ARMv7 (older devices)
echo ""
echo -e "${BLUE} Building for ARMv7 (armv7-linux-androideabi)...${NC}"
cargo ndk \
    --target armv7-linux-androideabi \
    --platform $MIN_SDK_VERSION \
    build $BUILD_FLAG --package lib-client --lib

mkdir -p "$OUTPUT_DIR/jniLibs/armeabi-v7a"
cp "target/armv7-linux-androideabi/$PROFILE/libzhtp_client.so" "$OUTPUT_DIR/jniLibs/armeabi-v7a/libquic_jni.so"
echo -e "${GREEN} ARMv7 build complete${NC}"

# x86_64 (emulator)
echo ""
echo -e "${BLUE} Building for x86_64 (emulator)...${NC}"
cargo ndk \
    --target x86_64-linux-android \
    --platform $MIN_SDK_VERSION \
    build $BUILD_FLAG --package lib-client --lib

mkdir -p "$OUTPUT_DIR/jniLibs/x86_64"
cp "target/x86_64-linux-android/$PROFILE/libzhtp_client.so" "$OUTPUT_DIR/jniLibs/x86_64/libquic_jni.so"
echo -e "${GREEN} x86_64 build complete${NC}"

# x86 (older emulator)
echo ""
echo -e "${BLUE} Building for x86 (older emulator)...${NC}"
cargo ndk \
    --target i686-linux-android \
    --platform $MIN_SDK_VERSION \
    build $BUILD_FLAG --package lib-client --lib

mkdir -p "$OUTPUT_DIR/jniLibs/x86"
cp "target/i686-linux-android/$PROFILE/libzhtp_client.so" "$OUTPUT_DIR/jniLibs/x86/libquic_jni.so"
echo -e "${GREEN} x86 build complete${NC}"

# Display library sizes
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Library Sizes                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
du -h "$OUTPUT_DIR/jniLibs/arm64-v8a/libquic_jni.so" | awk '{print "  ARM64:   " $1}'
du -h "$OUTPUT_DIR/jniLibs/armeabi-v7a/libquic_jni.so" | awk '{print "  ARMv7:   " $1}'
du -h "$OUTPUT_DIR/jniLibs/x86_64/libquic_jni.so" | awk '{print "  x86_64:  " $1}'
du -h "$OUTPUT_DIR/jniLibs/x86/libquic_jni.so" | awk '{print "  x86:     " $1}'

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Android Build Completed Successfully!          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN} Output: $OUTPUT_DIR/jniLibs${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo ""
echo -e "  1. Libraries have been built and are ready at:"
echo -e "     ${YELLOW}$OUTPUT_DIR/jniLibs${NC}"
echo ""
echo -e "  2. Copy to mobile app:"
echo -e "     ${YELLOW}cp -r $OUTPUT_DIR/jniLibs/* /Users/supertramp/Dev/SovereignNetworkMobile/android/app/src/main/jniLibs/${NC}"
echo ""
echo -e "${GREEN} Done!${NC}"
