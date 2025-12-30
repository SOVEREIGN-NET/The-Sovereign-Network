# Bluetooth Device-to-Device Test Guide (lib-network)

Purpose: Validate real-world message delivery between two devices using Bluetooth transport.

## Scope
- Device A: macOS
- Device B: Linux
- Transport: Bluetooth (BLE or Classic depending on the implementation)
- Focus: MessageBroadcaster behavior, routing, identity verification

## Prerequisites
- Bluetooth enabled on both devices.
- Devices are paired or trusted as required by the OS.
- Repo checked out on both devices.
- Required Bluetooth permissions granted to the node process.

## Build and Run
1) Build the node on both devices:
   ```bash
   cargo build -p zhtp --release
   ```
2) Ensure Bluetooth is enabled and the `DISABLE_BLUETOOTH` environment variable is NOT set.
3) Start the node on Device A (macOS) with logging enabled:
   ```bash
   RUST_LOG=info ./target/release/zhtp node start --port 9001 --dev
   ```
4) Start the node on Device B (Linux) with logging enabled:
   ```bash
   RUST_LOG=info ./target/release/zhtp node start --port 9002 --dev
   ```

## Test Steps
1) Confirm Bluetooth discovery and connection.
   - Verify each node sees the other as a peer via Bluetooth.
2) Confirm identity verification.
   - Ensure the peer is marked verified and not in bootstrap mode.
3) Send a consensus message from A to B using MessageBroadcaster.
4) Repeat from B to A.
5) Test with a forced disconnect during broadcast.
   - Turn off Bluetooth on one device during broadcast and confirm best-effort behavior.

## Expected Results
- Bluetooth link is established and peers are discovered.
- Validator messages are sent only to verified peers.
- Self-send is skipped or rejected.
- Broadcast continues to remaining peers if one fails.
- Broadcast results are telemetry only (no consensus gating).

## Observability
- Check logs for Bluetooth transport initialization and routing events.
- Confirm errors are logged but do not abort the broadcast.

## Test Harness (Small, CLI-Based)
Use the built-in network commands as a lightweight harness for device-to-device validation.

1) Confirm discovery on each device:
   ```bash
   ./target/release/zhtp network peers
   ```
2) Ping the other node from each device:
   ```bash
   ./target/release/zhtp network ping <OTHER_IP:OTHER_PORT> -c 5
   ```
3) Tail logs during a consensus broadcast from your consensus layer to confirm:
   - Verified peers receive messages.
   - Unverified peers are skipped.
   - Self-send is not attempted.

## Triggering ValidatorMessage (Current Repo State)
There is no CLI or API endpoint that sends `ValidatorMessage` directly.

What exists today:
- `lib-network` defines `MessageBroadcaster`, but it is not wired into `lib-consensus`.
- `lib-consensus` has `ValidatorProtocol::broadcast_*`, but `broadcast_message()` is a TODO and not connected to networking.

Implication:
- You cannot trigger real validator message delivery via CLI yet.
- For now, validator messages are only reachable through a custom test harness or by wiring `MessageBroadcaster` into consensus.

If you want to add a local harness:
- Create a small Rust binary that constructs a `ValidatorMessage` and calls `MeshMessageBroadcaster::broadcast_to_validators()` with explicit public keys.
- Use that harness while running two nodes over Bluetooth to validate delivery semantics.

## Troubleshooting
- No discovery: verify pairing, OS permissions, and Bluetooth adapter state.
- Messages not delivered: verify identity verification and that Bluetooth transport is enabled.
- Unstable link: reduce distance, disable power saving, and re-pair devices.

## Notes
- Bluetooth MTU is smaller than WiFi; expect lower throughput and higher latency.
