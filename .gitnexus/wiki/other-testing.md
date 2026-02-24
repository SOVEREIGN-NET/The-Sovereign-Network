# Other — testing

# Other — Testing Module Documentation

## Overview

The **Other — Testing** module encompasses two primary components: the **Identity E2E Runbook** and the **Smoke Test Plan**. This module is designed to validate the identity messaging flow and ensure the integrity of the codebase through quick, reliable tests. 

### Purpose

- **Identity E2E Runbook**: To validate the end-to-end messaging flow of identity operations, including fan-out, store-and-forward, and receipt handling using local, in-memory stores.
- **Smoke Test Plan**: To provide a fast and reliable gate that checks workspace builds and critical paths before merging changes into the `development` branch.

## Identity E2E Runbook

### Key Components

1. **Simulation Options**: The runbook provides multiple ways to simulate identity messaging:
   - **CLI Simulation**: Using the `zhtp-cli` command to simulate message sending.
   - **Tool Simulation**: Running a dedicated simulation binary from the `tools` crate.
   - **Node API**: Interacting with the identity API to check pending envelopes and delivery acknowledgments.

2. **Expected Outputs**: Each simulation option has specific expected outputs that confirm the correct functioning of the identity messaging flow.

### Simulation Options

#### Option A: CLI Simulation
```bash
zhtp-cli identity simulate-message --devices 2
```
- **Expected Outputs**:
  - Reports queued envelopes.
  - Prints ciphertext length for device-0.
  - Prints receipt envelope payload count.
  - Prints store-and-forward acknowledgment result.
  - Prints pending count for device-0.

#### Option B: Tool Simulation
```bash
cargo run -p tools --bin identity_e2e_sim
```
- **Expected Outputs**:
  - Prints `queued: 1`.
  - Prints `pending for phone-1: 1`.
  - Prints `receipt envelope payloads: 1`.
  - Prints `delivery ack removed: true`.

#### Option C: Node API (Pending Envelopes)
```http
POST /api/v1/network/identity/pending
{
  "recipient_did": "did:zhtp:recipient",
  "device_id": "device-0"
}
```
- **Expected Outputs**:
  - `status: "success"`.
  - `envelopes` contains opaque `IdentityEnvelope` entries for the device.

#### Option D: CLI (Pending Envelopes)
```bash
zhtp-cli identity pending did:zhtp:recipient device-0
```
- **Expected Outputs**:
  - Prints JSON response with `envelopes`.

#### Option E: Node API (Delivery Ack)
```http
POST /api/v1/network/identity/ack
{
  "recipient_did": "did:zhtp:recipient",
  "device_id": "device-0",
  "message_id": 42,
  "retain_until_ttl": false
}
```
- **Expected Outputs**:
  - `status: "success"`.
  - `acknowledged: true`.

#### Option F: CLI (Delivery Ack)
```bash
zhtp-cli identity ack did:zhtp:recipient device-0 42
```
- **Expected Outputs**:
  - Prints JSON response with `acknowledged`.

### Notes
- The runbook uses an in-memory DID store, eliminating the need for network transport.
- For TTL/retention behavior, refer to `lib-network/src/identity_store_forward.rs` tests.

## Smoke Test Plan

### Purpose

The Smoke Test Plan is designed to ensure that the workspace builds and critical paths are functioning correctly before merging changes. It aims to keep the runtime under a few minutes to facilitate continuous integration.

### What the Smoke Test Runs

1. **Workspace Build**: 
   ```bash
   cargo test --workspace --tests --no-run
   ```
   - Compiles all tests without executing them.

2. **Core Crates Quick Execution**: 
   - Validates runtime wiring with minimal tests:
   ```bash
   cargo test -p lib-blockchain --tests -- --nocapture --test-threads=1
   cargo test -p zhtp --tests -- --nocapture --test-threads=1
   ```

3. **Optional Checks**: 
   - When time allows, run:
   ```bash
   cargo check -p lib-network -p lib-identity
   ```

4. **Integration Readiness Check**: 
   ```bash
   cargo test -p integration-tests -- --nocapture
   ```

### When to Run

- On every PR via CI (fast lane).
- Locally before pushing changes that affect interfaces across crates.

### Adding New Smoke Cases

- Prefer minimal assertions that exercise the hot path without heavy fixtures.
- Place new smoke-focused tests in existing suites, marking heavier tests with `#[ignore]`.
- Keep per-crate additions under ~30s runtime; if longer, document in the test and mark `#[ignore]`.
- Name tests with a `smoke_` prefix for clarity.

### CI Integration Notes

- Use `--no-run` for broad coverage to keep builds fast and network-independent.
- Avoid tests requiring external services or networks; if unavoidable, mark as ignored and document setup.
- If the smoke set exceeds time budgets, consider splitting into `smoke` (always on) and `full` (manual/cron) tests.

### Mesh Identity Integration (Manual)

- After changes to mesh identity or handshake code, run:
```bash
cargo test -p lib-network --test mesh_network_integration
```
- This verifies NodeId determinism and key binding across mesh nodes.

### Runtime Identity Environment

- **Environment Variable**: `ZHTP_DEVICE_NAME` can be used to override the device name for deterministic NodeId derivation during startup.

## Conclusion

The **Other — Testing** module is crucial for maintaining the integrity of the identity messaging system and ensuring that the codebase remains stable and functional. By utilizing both the Identity E2E Runbook and the Smoke Test Plan, developers can effectively validate their changes and contribute to the project with confidence.