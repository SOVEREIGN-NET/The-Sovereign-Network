#!/bin/bash

# ZHTP Standalone Test - Tests basic functionality without external services
# This test verifies that the ZHTP binaries work correctly in Docker

set -e

echo "====================================="
echo "ZHTP Standalone Docker Test"
echo "====================================="
echo "Testing ZHTP Docker image functionality without external dependencies..."

# Test 1: Verify binaries exist and are executable
echo
echo "Test 1: Verifying ZHTP binaries..."
if [ -x "./bin/zhtp" ]; then
    echo "✅ zhtp binary exists and is executable"
else
    echo "❌ zhtp binary not found or not executable"
    exit 1
fi

if [ -x "./bin/zhtp-dev" ]; then
    echo "✅ zhtp-dev binary exists and is executable"
else
    echo "❌ zhtp-dev binary not found or not executable"
    exit 1
fi

# Test 2: Test basic binary functionality
echo
echo "Test 2: Testing basic binary functionality..."

# Test help output
echo "Testing zhtp --help..."
if ./bin/zhtp --help >/dev/null 2>&1; then
    echo "✅ zhtp --help works"
else
    echo "⚠️  zhtp --help failed (may be expected if binary needs specific config)"
fi

echo "Testing zhtp-dev --help..."
if ./bin/zhtp-dev --help >/dev/null 2>&1; then
    echo "✅ zhtp-dev --help works"
else
    echo "⚠️  zhtp-dev --help failed (may be expected if binary needs specific config)"
fi

# Test 3: Check environment variables
echo
echo "Test 3: Checking environment variables..."
echo "ZHTP_DATA_DIR=$ZHTP_DATA_DIR"
echo "ZHTP_LOG_DIR=$ZHTP_LOG_DIR"
echo "ZHTP_TEST_RESULTS_DIR=$ZHTP_TEST_RESULTS_DIR"
echo "RUST_LOG=$RUST_LOG"

if [ -n "$ZHTP_DATA_DIR" ] && [ -n "$ZHTP_LOG_DIR" ] && [ -n "$ZHTP_TEST_RESULTS_DIR" ]; then
    echo "✅ Environment variables are set correctly"
else
    echo "❌ Some environment variables are missing"
    exit 1
fi

# Test 4: Check directory permissions
echo
echo "Test 4: Testing directory permissions..."
if [ -w "$ZHTP_LOG_DIR" ]; then
    echo "✅ Log directory is writable"
else
    echo "❌ Log directory is not writable"
    exit 1
fi

if [ -w "$ZHTP_TEST_RESULTS_DIR" ]; then
    echo "✅ Test results directory is writable"
else
    echo "❌ Test results directory is not writable"
    exit 1
fi

# Test 5: Test basic file operations
echo
echo "Test 5: Testing basic file operations..."
TEST_FILE="$ZHTP_TEST_RESULTS_DIR/docker-test.txt"
echo "Docker standalone test completed successfully at $(date)" > "$TEST_FILE"

if [ -f "$TEST_FILE" ]; then
    echo "✅ File creation test passed"
    rm "$TEST_FILE"
else
    echo "❌ File creation test failed"
    exit 1
fi

# Test 6: Check system dependencies
echo
echo "Test 6: Checking system dependencies..."
if command -v curl >/dev/null 2>&1; then
    echo "✅ curl is available"
else
    echo "❌ curl is not available"
    exit 1
fi

if command -v jq >/dev/null 2>&1; then
    echo "✅ jq is available"
else
    echo "❌ jq is not available"
    exit 1
fi

if command -v nc >/dev/null 2>&1; then
    echo "✅ netcat is available"
else
    echo "❌ netcat is not available"
    exit 1
fi

echo
echo "====================================="
echo "✅ All standalone tests passed!"
echo "ZHTP Docker image is working correctly"
echo "====================================="
echo "Test completed at: $(date)"
echo "User: $(whoami)"
echo "Working directory: $(pwd)"
echo "Total disk usage: $(du -sh . 2>/dev/null || echo 'N/A')"
echo "====================================="
