# Issue 141: BLE GATT Adapter Notes

## Current status
- Mac CI lane added in `.github/workflows/ci.yml` to build on `macos-14` and run `cargo test -p lib-network --locked -- --nocapture`.
- No functional GATT/UHP code changes yet; acceptance criteria still unmet (fragmentation/reassembly, AsyncRead/Write integration, UHP verification, reject unverified peers).

## Mac testing coverage
- Scope: workspace build + `lib-network` tests on macOS runner.
- Command executed in CI: `cargo build --workspace --locked` then `cargo test -p lib-network --locked -- --nocapture`.
- Purpose: catch macOS-specific build/link issues in BLE/GATT code paths.
- Not covered: real BLE hardware I/O, CoreBluetooth runtime behavior, UHP end-to-end.

## Gaps to close for full acceptance
1) Implement/verify GATT fragmentation/reassembly wiring to UHP (use `GattStream` and UHP framing).  
2) AsyncRead/AsyncWrite adapters hooked to platform BLE handlers.  
3) UHP verification and rejection of unverified peers in BLE handlers.  
4) Integration tests (mocked) and, if possible, hardware validation on a macOS host/VM with BLE.

## Next steps (recommended)
- Flesh out GATT adapter to UHP framing and add unit/integration tests.  
- Add mocked CoreBluetooth side tests (feature-gated) to validate read/write paths.  
- If hardware available, run manual BLE pairing test on macOS host with debug logging enabled.  
- Keep macOS CI lane to ensure ongoing compatibility.  
- Hardware test helper added:
  - Script: `scripts/run_ble_hw_test.sh` (macOS) captures Bluetooth logs and runs `cargo test -p lib-network`.
  - Android setup guide: `docs/ANDROID_BLE_PERIPHERAL_SETUP.md` for turning a phone into a BLE peripheral.
  - Ask testers to send back `logs/ble_hw_test_<timestamp>.log` plus device name/UUID.

## Mock BLE simulation (no hardware)
- Helper: `lib-network/src/protocols/bluetooth/mock.rs`.
- How to use in tests: `let mut link = MockGattLink::new(247, central_verifier, peripheral_verifier);` then drive traffic with `link.central.send_frame(...)` / `link.peripheral.recv_frame(...)`.
- Simulates a full GATT link with fragmentation, reassembly, and optional verification hooks so UHP-over-GATT paths can be exercised in CI without CoreBluetooth hardware.

## Notes
- Changes are local; nothing pushed.  
- The macOS CI lane satisfies “we can build/test on macOS runners,” but not the feature acceptance criteria.  
