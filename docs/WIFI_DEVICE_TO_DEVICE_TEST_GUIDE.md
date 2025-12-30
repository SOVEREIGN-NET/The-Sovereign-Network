# WiFi Device-to-Device Test Guide (lib-network)

Purpose: Validate real-world message delivery between two devices on the same subnet using QUIC over WiFi.

## Scope
- Device A: macOS
- Device B: Linux
- Transport: WiFi (QUIC)
- Focus: MessageBroadcaster behavior, routing, identity verification

## Prerequisites
- Both devices on the same subnet, no VPN.
- Repo checked out on both devices.
- Firewalls allow UDP on the QUIC port used by the node (default 9334).
- Each device can resolve the other by IP.

## Build and Run
1) Build the node on both devices:
   ```bash
   cargo build -p zhtp --release
   ```
2) Start the node on Device A (macOS) with logging enabled and Bluetooth disabled to isolate WiFi:
   ```bash
   DISABLE_BLUETOOTH=1 RUST_LOG=info ./target/release/zhtp node start --port 9001 --dev
   ```
3) Start the node on Device B (Linux) with logging enabled and Bluetooth disabled:
   ```bash
   DISABLE_BLUETOOTH=1 RUST_LOG=info ./target/release/zhtp node start --port 9002 --dev
   ```

## Test Steps
1) Confirm peer discovery.
   - On each device:
     ```bash
     ./target/release/zhtp network peers
     ```
   - From logs, verify each node sees the other as a peer.
2) Confirm identity verification.
   - Ensure the peer is marked verified and not in bootstrap mode.
3) Send a consensus message from A to B using MessageBroadcaster.
   - Use the consensus layer or the test harness section below to send a ValidatorMessage to B's public key.
4) Repeat from B to A.
5) Broadcast to multiple validators (if available) and confirm partial delivery is allowed.

## Expected Results
- Peers are discovered and connected on QUIC.
- Validator messages are sent only to verified peers.
- Self-send is skipped or rejected.
- Broadcast continues even if a target is unreachable.
- Broadcast results are telemetry only (no consensus gating).

## Observability
- Look for logs indicating broadcast attempts, success, failures, and skipped peers.
- Confirm no consensus logic blocks on delivery.

## Test Harness (Small, CLI-Based)
Use the built-in network commands as a lightweight harness for device-to-device validation.

1) Ping the other node from each device:
   ```bash
   ./target/release/zhtp network ping <OTHER_IP:OTHER_PORT> -c 5
   ```
2) Run the connectivity test on each device:
   ```bash
   ./target/release/zhtp network test
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
- Use that harness while running two nodes on WiFi to validate delivery semantics.

## Troubleshooting
- No discovery: confirm same subnet, firewall rules, and correct ports.
- Messages not delivered: confirm identity verification and target public keys.
- Unexpected self-send: verify broadcaster self-check behavior.

## Notes
- If needed, capture packet traces on UDP 9334 to verify traffic.
