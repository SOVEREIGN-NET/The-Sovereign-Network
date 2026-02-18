# Client Implementation Requirements (Identity Messaging MVP)

Status: Draft
Date: 2026-02-01
Spec: docs/specs/identity-device-model-v1.md (LOCKED)
Plan: docs/plans/identity-device-model-phase2-3-mvp.md

## Scope
This document captures the client-side work required to complete the Phase 2–3 MVP. It describes what the client must implement to send, receive, and acknowledge identity messages using the existing node/API capabilities.

## 1) Client Responsibilities (Required)

### 1.1 DID + Device State
- Maintain the user DID and seed phrase locally.
- Maintain active device list (device_id + signing + encryption keys).
- On startup, load local device keys; no server can reconstruct missing keys.

### 1.2 Send to DID (Fan-out)
- Resolve recipient DID to its device registry (active devices only).
- For each active device, encrypt the same plaintext payload using that device encryption public key.
- Construct an `IdentityEnvelope` with one `DevicePayload` per device.
- Select TTL per message (0/24h/7d/30d). Default is 7d.
- Transmit envelope to the network (see 2.1 Transmission Path below).

### 1.3 Receive + Decrypt
- For each incoming envelope, locate the `DevicePayload` matching the local `device_id`.
- Decrypt ciphertext with the local device encryption private key.
- Deserialize payload into `IdentityPayload` (user message, control message, receipt, etc.).

### 1.4 Delivery Acknowledgement
- On successful decryption, send an acknowledgement to the node (store-and-forward delete).
- This is a node-level ack only; it does not reveal plaintext.
- Use the `POST /api/v1/network/identity/ack` endpoint.

### 1.5 Delivery Receipt (End-to-End)
- Create a `DeliveryReceipt` signed by the device signing key.
- Encrypt it to the sender DID (same fan-out method) and send as an `IdentityEnvelope`.
- Sender marks the message delivered when the receipt decrypts.

---

## 2) Client ↔ Node Integration

### 2.1 Transmission Path (Required)
The client must send `IdentityEnvelope` objects over the network. One of the following must be implemented:
- **A)** Direct mesh message send via QUIC (preferred, in-protocol).
- **B)** Client API endpoint to submit an envelope to the node for routing (requires server-side endpoint).

**Current state:**
- Envelope types and serialization are implemented in `lib-protocols` / `lib-network`.
- No dedicated client API endpoint exists for submit yet; only pending/ack endpoints are provided.

### 2.2 Pending Pull (Already available)
- `POST /api/v1/network/identity/pending`
- Body: `{ "recipient_did": "...", "device_id": "..." }`
- Response: `IdentityEnvelope[]` (opaque ciphertexts)

### 2.3 Delivery Ack (Already available)
- `POST /api/v1/network/identity/ack`
- Body: `{ "recipient_did": "...", "device_id": "...", "message_id": 42, "retain_until_ttl": false }`
- Response: `acknowledged: true|false`

---

## 3) Message Formats (Client-Side)

### 3.1 Envelope
- `IdentityEnvelope` includes per-device ciphertexts.
- Client must treat the envelope as opaque for devices it doesn’t own.

### 3.2 Payload
- `IdentityPayload::UserMessage` for user messages.
- `IdentityPayload::ControlMessage` for device updates.
- `IdentityPayload::DeliveryReceipt` for delivery acknowledgements to sender.

### 3.3 Receipt
- `DeliveryReceipt` is signed by device signing key.
- Receipt is encrypted to sender DID via same fan-out method.

---

## 4) Minimal Client Flow (MVP)

### 4.1 Send
1) Resolve DID → active devices.
2) Encrypt payload per device.
3) Build `IdentityEnvelope`.
4) Transmit to node/mesh.

### 4.2 Receive
1) Pull pending envelopes for device.
2) Decrypt matching ciphertext.
3) Process payload.
4) Post delivery ack to node.
5) Send encrypted delivery receipt to sender DID.

---

## 5) Tests the Client Should Implement
- Send to DID with 2 devices → both decrypt.
- Offline device: envelope pulled later within TTL.
- Delivery ack removes envelope from node store.
- Delivery receipt decrypts on sender and marks delivered.

---

## 6) Open Items (Client/Protocol)
- **Envelope submission endpoint** (if not sending over QUIC directly).
- **Sealed-sender routing** (Phase 4, not MVP).
- **Read receipts** (Phase 6, not MVP).
