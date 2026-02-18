# Phase 1 Design: DID Device Registry + Resolution

Status: DRAFT (design)
Spec: docs/specs/identity-device-model-v1.md (LOCKED)
Date: 2026-02-01

## Scope
Implements DID document device registry and signed updates, plus storage and resolution with caching.

## Goals
- Represent authorized device keys inside DID documents.
- Allow DID‑signed device add/remove updates.
- Provide deterministic, verifiable updates with replay protection.
- Resolve DID → current device registry with bounded cache TTL.

## Non‑Goals
- Messaging fan‑out or encryption (Phase 2).
- Store‑and‑forward queues (Phase 3).
- Group semantics.

---

## 1. Data Model

### 1.1 Device Entry
Each device entry in the DID document contains:
- device_id: string (unique per DID)
- signing_key: multibase (public)
- encryption_key: multibase (public)
- status: active | removed
- added_at: unix seconds
- removed_at: unix seconds | null

### 1.2 DID Document Extension
Add new top‑level field to DID document:
- device_registry: [DeviceEntry]

### 1.3 DID Document Update (DID‑Signed)
Define update envelope:
```
DIDDocumentUpdate {
  did: string
  prev_hash: bytes32
  new_hash: bytes32
  version: u64
  timestamp: u64
  diff: DeviceRegistryDiff
  signature: bytes (DID signing key)
}
```

DeviceRegistryDiff:
- adds: [DeviceEntry]  (status must be active)
- removes: [device_id] (status set to removed, removed_at set)

### 1.4 Versioning + Replay Protection
- version must monotonically increase (u64).
- prev_hash must match current doc hash.
- signature verified against DID root verification key.

---

## 2. API Surfaces

### 2.1 Public Library API (lib-identity)
- `fn add_device_to_did(identity: &ZhtpIdentity, device_id: &str, signing_pk: &[u8], encryption_pk: &[u8]) -> Result<DIDDocumentUpdate>`
- `fn remove_device_from_did(identity: &ZhtpIdentity, device_id: &str) -> Result<DIDDocumentUpdate>`
- `fn apply_did_update(doc: DidDocument, update: DIDDocumentUpdate) -> Result<DidDocument>`
- `fn validate_did_update(doc: &DidDocument, update: &DIDDocumentUpdate) -> Result<bool>`
- `fn resolve_did(did: &str) -> Result<DidDocument>` (existing stub to implement)

### 2.2 Node / Registry API
- `PUT /did/{did}/document` (store full doc)
- `POST /did/{did}/update` (apply signed update)
- `GET /did/{did}/document` (resolve latest)

Note: transport layer remains opaque; no plaintext leakage.

---

## 3. Storage + Resolution

### 3.1 Storage Backend Options
Choose one:
1) DHT (preferred if operational): store by DID hash key.
2) Chain registry (if on‑chain doc hash exists).
3) Local registry (dev only).

### 3.2 Cache
- Resolver caches DID docs with TTL (e.g., 1h default).
- Cache is content only, not authoritative.

---

## 4. Validation Rules

- DID document must include root verification key.
- Device entry device_id must be unique.
- Adds may not overwrite existing active device_id.
- Removes must target an active device_id.
- Update signature must verify against DID root key.
- Update version must increment exactly by 1 (or allow >1 if ordered by timestamp, choose one policy).

---

## 5. Tests

- Add device creates valid update and updates doc.
- Remove device marks status removed.
- Replay update rejected (version or prev_hash mismatch).
- Invalid signature rejected.
- Resolve returns expected device registry.

---

## 6. Implementation Notes

- DID hash: use existing `DidDocument::to_hash()` implementation.
- Device key multibase encoding: reuse existing multibase helper.
- Keep changes localized in `lib-identity/src/did/*` and add APIs in `lib-identity/src/lib.rs`.

