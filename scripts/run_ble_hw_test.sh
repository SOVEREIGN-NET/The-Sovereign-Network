#!/usr/bin/env bash
set -euo pipefail

# Simple macOS helper to capture BLE-related system logs while running lib-network tests.
# This does not drive hardware itself; it wraps cargo tests and records logs so
# teammates with a BLE peripheral (e.g., Android phone running nRF Connect) can
# send back artifacts.
#
# Usage:
#   DEVICE_NAME="MyBLEPeripheral" ./scripts/run_ble_hw_test.sh
# Output:
#   - logs/ble_hw_test_<timestamp>.log: macOS unified log filtered for Bluetooth/CoreBluetooth
#   - cargo test output in the terminal
#
# Prereqs:
#   - Run on macOS with Xcode CLT installed (for cargo/rustup)
#   - BLE radio enabled; nearby BLE peripheral advertising (phone app is fine)

mkdir -p logs
TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="logs/ble_hw_test_${TS}.log"

echo "==> Starting macOS Bluetooth log capture to ${LOG_FILE}"
echo "    Tip: open the BLE peripheral app on your phone and start advertising."
echo "    Device hint (optional): ${DEVICE_NAME:-<not set>}"

# Start log capture in background
log stream --info --style compact --predicate 'subsystem BEGINSWITH "com.apple.bluetooth" OR category CONTAINS "CoreBluetooth"' > "${LOG_FILE}" &
LOG_PID=$!

cleanup() {
  echo "==> Stopping log capture (pid ${LOG_PID})"
  kill "${LOG_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Running cargo tests for lib-network (no hardware-driving test yet; this is a log capture harness)"
cargo test -p lib-network --locked -- --nocapture || true

echo "==> Done. Log saved to ${LOG_FILE}"
echo "    Please send the log file along with the device name/UUID used."
