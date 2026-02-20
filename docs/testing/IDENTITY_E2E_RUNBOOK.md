# Identity E2E Runbook (Local)

## Purpose
Validate identity messaging flow end‑to‑end (fan‑out + store‑and‑forward + receipts) using local, in‑memory stores.

## Prerequisites
- Workspace builds
- `tools` crate built (optional)

## Option A: CLI Simulation
```
zhtp-cli identity simulate-message --devices 2
```
Expected:
- Reports queued envelopes
- Prints ciphertext length for device-0
- Prints receipt envelope payload count
- Prints store-and-forward acknowledgement result
- Prints pending count for device-0

## Option B: Tool Simulation
```
cargo run -p tools --bin identity_e2e_sim
```
Expected:
- Prints `queued: 1`
- Prints `pending for phone-1: 1`
- Prints `receipt envelope payloads: 1`
- Prints `delivery ack removed: true`

## Option C: Node API (Pending Envelopes)
```
POST /api/v1/network/identity/pending
{
  "recipient_did": "did:zhtp:recipient",
  "device_id": "device-0"
}
```
Expected:
- `status: "success"`
- `envelopes` contains opaque `IdentityEnvelope` entries for the device

## Option D: CLI (Pending Envelopes)
```
zhtp-cli identity pending did:zhtp:recipient device-0
```
Expected:
- Prints JSON response with `envelopes`

## Option E: Node API (Delivery Ack)
```
POST /api/v1/network/identity/ack
{
  "recipient_did": "did:zhtp:recipient",
  "device_id": "device-0",
  "message_id": 42,
  "retain_until_ttl": false
}
```
Expected:
- `status: "success"`
- `acknowledged: true`

## Option F: CLI (Delivery Ack)
```
zhtp-cli identity ack did:zhtp:recipient device-0 42
```
Expected:
- Prints JSON response with `acknowledged`

## Notes
- Uses in‑memory DID store only.
- No network transport required.
- For TTL/retention behavior, see `lib-network/src/identity_store_forward.rs` tests.
