#!/bin/bash
set -e

BINARY_PATH="../target/release/zhtp"
APP_NAME="ZHTP.app"
APP_DIR="../target/release/$APP_NAME"

echo "Creating macOS app bundle for Bluetooth permissions..."

# Remove old bundle if exists
rm -rf "$APP_DIR"

# Create bundle structure
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy binary
cp "$BINARY_PATH" "$APP_DIR/Contents/MacOS/zhtp"

# Copy Info.plist
cp "Info.plist" "$APP_DIR/Contents/Info.plist"

# Make binary executable
chmod +x "$APP_DIR/Contents/MacOS/zhtp"

echo "✅ App bundle created at: $APP_DIR"
echo ""
echo "To run with Bluetooth permissions:"
echo "  open -a \"$APP_DIR\" --args node start"
echo ""
echo "Or run the binary directly from the bundle:"
echo "  \"$APP_DIR/Contents/MacOS/zhtp\" node start"
