# Phase 2–3 MVP: DID Fan‑Out + Store‑and‑Forward + Delivery Receipts

Status: DRAFT (MVP scope)
Spec: docs/specs/identity-device-model-v1.md (LOCKED)
Date: 2026-02-01

## Scope
Deliver the minimal end‑to‑end slice that enables:
- Send to DID → per‑device encryption fan‑out
- Offline store‑and‑forward with TTL + delete‑on‑ack
- End‑to‑end encrypted delivery receipts

## Non‑Goals
- Sealed sender + layered routing (Phase 4)
- Groups (Phase 5)
- Read receipts (Phase 6)
- PoUW stamp (Phase 7)

---

## 1. Message Envelope (MVP)

### 1.1 Envelope Structure
```
Envelope {
  message_id: u64
  sender_did: string
  created_at: u64
  ttl: enum { 0, 24h, 7d, 30d }
  payloads: [DevicePayload]
}

DevicePayload {
  device_id: string
  ciphertext: bytes
}
```

- payloads length equals number of active devices for recipient DID.
- ciphertext is opaque to nodes.

### 1.2 Delivery Receipt
```
DeliveryReceipt {
  message_id: u64
  device_id: string
  delivered_at: u64
  receipt_sig: bytes (device signing key)
}
```

Receipt is encrypted end‑to‑end back to sender devices.

---

## 2. Client Flow (Send to DID)
Checklist:
- [x] Resolve recipient DID → device registry.
- [x] For each active device, encrypt payload with device encryption key.
- [x] Build Envelope (IdentityEnvelope with per-device payloads).
- [ ] Transmit envelope over network transport (client-side integration).

## 3. Node Flow (Store‑and‑Forward)
Checklist:
- [x] On receipt, enqueue envelope by recipient DID.
- [x] Enforce TTL expiry (hard delete on expiry).
- [ ] If recipient device online, deliver immediately (push).
- [x] On delivery ack, delete envelope unless sender requested retain‑until‑TTL.

## 4. Device Flow (Receipt)
Checklist:
- [x] On decryptable payload, create DeliveryReceipt + envelope to sender DID.
- [ ] Sender client marks message delivered on receipt decrypt (client integration).

---

## 5. Data Structures + Storage

- Node queue key: recipient DID
- Queue entry: envelope + expires_at
- Bounded queue with eviction by TTL or size

---

## 6. Tests (MVP)

- [x] Send to DID with 2 devices → per-device payloads generated.
- [x] Offline device: envelope stored and delivered later within TTL (store‑and‑forward tests).
- [x] TTL expiry deletes envelope.
- [x] Delivery ack triggers deletion.

---

## 7. Integration Points

- Use Phase 1 DID resolver for device registry.
- Use existing session encryption primitives for payload encryption.
