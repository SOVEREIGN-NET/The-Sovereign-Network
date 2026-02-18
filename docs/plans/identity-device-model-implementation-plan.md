# Identity & Device Model v1 — End-to-End Implementation Plan

Status: DRAFT (execution plan)
Spec: docs/specs/identity-device-model-v1.md (LOCKED)
Date: 2026-02-01

## Goal
Deliver full end‑to‑end implementation of the Identity & Device Model spec, including prerequisites (propedeutics), with tests and operational safeguards.

## Guiding Invariants (Non‑Negotiable)
- Nodes never decrypt content.
- Nodes never hold long‑term message history.
- No key escrow exists.
- Recovery restores identity, not data.
- Groups are capped and rekey on membership change.
- Spam resistance is economic and protocol‑level, not semantic.
- Rewards tied to verifiable useful work only.

## Phase 0 — Discovery + Gap Audit (Immediate)
Checklist:
- [ ] Map current DID/DID‑document code paths and confirm storage/resolution approach (if any).  
  - Targets: `lib-identity/src/did/*`, `lib-identity/src/identity/lib_identity.rs`
- [ ] Map device registry usage and update flow.  
  - Targets: `lib-identity/src/identity/lib_identity.rs` (add/remove)
- [ ] Map existing encryption primitives and handshake layers.  
  - Targets: `lib-client/src/session.rs`, `lib-client/src/handshake.rs`, `lib-network/*`, `lib-crypto/*`
- [ ] Map message routing and delivery status (TTL, acks).  
  - Targets: `lib-network/src/types/mesh_message.rs`, `lib-network/src/routing/message_routing.rs`
- [ ] Map existing PoUW/WorkProof usage and interfaces.  
  - Targets: `lib-consensus/src/proofs/work_proof.rs`, `docs/dapps_auth/*`
- [ ] Confirm any existing group semantics for messaging (likely none).  
  - Targets: `lib-crypto/docs/examples.md`, `lib-network/*` (WiFi Direct “groups”)

Deliverable:
- [ ] Gap report (bullet list: implemented / partial / missing) embedded in this plan under Phase 0 notes.

## Phase 1 — Propedeutics: Core Data Models + Storage
### 1.1 DID Document Extension (Device Registry)
Checklist:
- [ ] Define DID document schema extension for device registry:
  - device_id
  - device public keys (sign + encryption)
  - status (active/removed)
  - added_at / removed_at
  - signature over update
- [ ] Add canonical serialization for DID doc updates (stable hashing).
- [ ] Implement DID document update operation (device add/remove) requiring DID signature.
- [ ] Implement DID document validation for device registry updates.

### 1.2 DID Document Storage + Resolution
Checklist:
- [ ] Decide storage backend (DHT or chain or local registry).
- [ ] Implement DID doc publish/store path.
- [ ] Implement DID doc resolve path (`resolve_did`) with caching and TTL (content cache only).
- [ ] Implement update versioning & replay protection (monotonic version or hash chain).

### 1.3 Device Registry API
Checklist:
- [ ] Add public API for device add/remove operations that emit signed DID doc updates.
- [ ] Add API to list active devices (filter removed).
- [ ] Add API to fetch device keys by DID + device_id.

Deliverables:
- [ ] DID doc device registry schema + versioning
- [ ] Update/resolve implementation with tests
- [ ] Public API surfaces for device management

## Phase 2 — E2E Encryption Model (Per‑Device Fan‑Out)
### 2.1 Envelope + Payload Model
Checklist:
- [ ] Define opaque message envelope structure:
  - per‑device encrypted payloads (N recipients)
  - routing metadata (next hop only)
  - message_id, created_at, TTL, PoUW stamp
  - optional sealed‑sender field (Phase 1)
- [ ] Define control message types (device add/remove, group updates).
- [ ] Define receipt message types (delivery/read).

### 2.2 Encryption Workflow
Checklist:
- [ ] Implement “send to DID” fan‑out:
  - resolve DID → active devices → encrypt per device key
- [ ] Ensure nodes only route opaque blobs.
- [ ] Implement device key rotation handling (new device = new recipient set).

Deliverables:
- [ ] Envelope spec + serialization
- [ ] Fan‑out encryption implementation + tests

## Phase 3 — Store‑and‑Forward + TTL Semantics
Checklist:
- [ ] Implement node‑side message queue (bounded) with TTL expiry.
- [ ] Add delete‑on‑ack semantics unless sender requests retention to TTL.
- [ ] Add delivery acknowledgement protocol:
  - device confirms decryptable receipt
  - send E2E receipt back to sender
- [ ] Add receipt storage local to client (never node‑archived).

Deliverables:
- [ ] Store‑and‑forward queue with TTL enforcement
- [ ] Delivery ack flow (device‑level)
- [ ] Tests for TTL expiry and ack deletion

## Phase 4 — Routing Privacy Phases
### 4.1 Phase 0 (Baseline)
Checklist:
- [ ] Confirm current routing metadata visibility (sender pseudonymous ID, recipient routing ID).
- [ ] Ensure no plaintext or group semantics leak in routing metadata.

### 4.2 Phase 1 (Sealed Sender + Layered Routing)
Checklist:
- [ ] Implement sealed‑sender envelope format.
- [ ] Implement layered routing encryption (next‑hop only).
- [ ] Add padding/batching options.

Deliverables:
- [ ] Sealed‑sender implementation
- [ ] Layered routing encryption with tests

## Phase 5 — Groups (Capped + Epoch Rekey)
Checklist:
- [ ] Define group ID, admin key model, signed group state updates.
- [ ] Implement epoch‑based sender key (rekey on add/remove/device change).
- [ ] Enforce hard caps (default 16, max 32) in client logic.
- [ ] Implement group membership changes as encrypted control messages.
- [ ] Ensure nodes cannot enumerate group membership.

Deliverables:
- [ ] Group state machine + epoch rekey
- [ ] Control messages for membership changes
- [ ] Tests for membership change, rekey, and caps

## Phase 6 — Receipts (Delivery / Read)
Checklist:
- [ ] Define receipt payloads (delivery, read) as E2E encrypted messages.
- [ ] Receipt creation on successful decrypt (delivery) and user open (read).
- [ ] Receipt verification + client UX integration.

Deliverables:
- [ ] Receipt schema + flows
- [ ] Tests for delivery/read receipt creation

## Phase 7 — PoUW Stamp (Per‑Message)
Checklist:
- [ ] Define PoUW stamp format bound to:
  - sender device key
  - network challenge
  - message hash
- [ ] Implement client‑side stamp generation per message/batch.
- [ ] Implement node‑side stamp verification (cheap).
- [ ] Integrate with reward pipeline (abstract for now).

Deliverables:
- [ ] PoUW stamp schema
- [ ] Client stamp generation
- [ ] Node verification path + tests

## Phase 8 — Recovery Model + Security Audits
Checklist:
- [ ] Verify recovery restores DID control only.
- [ ] Confirm no message recovery path exists without surviving device keys.
- [ ] Audit storage to ensure no long‑term ciphertext retention beyond TTL.

Deliverables:
- [ ] Recovery behavior tests
- [ ] Storage retention tests

## Phase 9 — End‑to‑End Test Harness
Checklist:
- [ ] Build integration tests with multi‑device identities:
  - device add/remove
  - per‑device encryption fan‑out
  - offline store‑and‑forward + TTL
  - delivery/read receipts
  - group rekey on membership change
  - PoUW stamp generation/verification
- [ ] Provide CLI or harness for simulated nodes/devices.

Deliverables:
- [ ] Automated E2E tests
- [ ] Minimal manual test runbook

## Phase 10 — Rollout + Ops
Checklist:
- [ ] Feature flags for routing privacy phase 1.
- [ ] Monitoring for queue size, TTL expiry, receipt rates.
- [ ] Backward compatibility for older clients (if required).

Deliverables:
- [ ] Operational docs + flags
- [ ] Metrics + dashboards (if applicable)

---

## Phase 0 Notes (Gap Summary)
- DID document exists but has no device registry and no resolution implementation.
- Device add/remove exists in identity struct but no DID‑signed update flow.
- E2E encryption exists in session primitives but not per‑device fan‑out by DID.
- Store‑and‑forward queue with TTL delete‑on‑ack is missing.
- Group semantics for messaging are missing.
- PoUW WorkProof exists (consensus) but no per‑message stamp.

