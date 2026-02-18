# Identity and Device Model v1 (Locked)

Status: LOCKED — do not edit without explicit spec change approval.
Date locked: 2026-02-01

## 1. Identity and Device Model

### 1.1 DID as Root Identity
- Each user is identified by a single DID.
- The DID is controlled by a seed phrase held only by the user.
- The DID document contains:
  - Root verification key (derived from seed).
  - A registry of authorized device keys.
  - Optional service endpoints.
- Invariant: Control of the DID implies control of future communications only. Past messages remain unrecoverable without surviving device keys.

### 1.2 Multi-Device Support
- A DID may authorize multiple devices.
- Each device has:
  - A unique asymmetric keypair.
  - A device ID registered under the DID.
- Adding or removing a device requires a DID-signed update.
- Removal semantics:
  - Removed devices stop receiving future messages.
  - Past messages encrypted to that device remain readable only if that device key still exists.

## 2. Cryptography and Message Model

### 2.1 End-to-End Encryption
- All messages are encrypted end-to-end.
- Encryption targets device keys, not DIDs directly.
- Sending to a DID = encrypt once per active device.
- Nodes:
  - Never see plaintext.
  - Never hold keys.
  - Never perform cryptographic operations beyond envelope routing.

### 2.2 Message Types
- User message
- Control message (device add/remove, group updates)
- Receipt (delivery / read)
- Group state update
- All messages are opaque blobs to the network.

## 3. Message Delivery and Offline Handling

### 3.1 Store-and-Forward
- Nodes MAY temporarily store encrypted messages for offline recipients.
- Storage is bounded by TTL.

### 3.2 TTL (Time-to-Live)
- Sender selects TTL per message:
  - 0 (no store, online only)
  - 24h
  - 7d (default)
  - 30d (hard maximum)
- Nodes MUST delete messages after TTL expiry.
- Nodes MUST delete messages immediately after successful delivery acknowledgement, unless sender explicitly requested retention until TTL.
- Invariant: Nodes never archive messages beyond TTL. No exceptions.

### 3.3 Delivery Semantics
- “Delivered” = recipient device confirms decryptable receipt.
- Node-level delivery does not imply user receipt.
- Receipts are end-to-end encrypted.

## 4. Metadata and Routing Privacy

### 4.1 Phase 0 (Baseline)
- Nodes can see:
  - Immediate sender pseudonymous identifier.
  - Immediate recipient routing identifier.
  - Message size and timing.
- Nodes cannot see:
  - Real-world identity.
  - Message content.
  - Group membership semantics.

### 4.2 Phase 1 (Private Routing Target)
- Sealed-sender envelopes.
- Layered encryption for routing (next-hop only).
- Optional padding and batching.
- Nodes cannot determine sender or final recipient, only next hop.
- Design goal: Nodes operate as blind routers with bounded queues.

## 5. Groups (Capped, Secure by Construction)

### 5.1 Group Scope
- Groups are explicitly capped.
- Default cap: 16 members.
- Absolute maximum: 32 members.
- Larger groups are out of scope by design.

### 5.2 Group Identity
- A group has:
  - Group ID.
  - Group admin key (may be a DID or a derived group key).
- Group state is not stored globally. It is reconstructed from signed group messages.

### 5.3 Group Encryption Model
- Epoch-based group sender key.
- On:
  - Member add
  - Member remove
  - Device change
  - → New epoch, new sender key.
- Old members:
  - Cannot decrypt future messages.
  - May retain access to messages from epochs they were part of.

### 5.4 Group Membership Changes
- Changes must be signed by the group admin key.
- Membership updates are distributed as encrypted control messages.
- Nodes do not understand group semantics.
- Invariant: No node can enumerate group members or know group size.

## 6. Abuse, Spam, and DoS (Zero-Knowledge Compatible)

### 6.1 Network-Level Protections (No Content Access)
- Nodes MAY enforce:
  - Rate limits per connection.
  - Message size caps.
  - Concurrent stream limits.
  - Replay protection (nonces).
  - Queue limits and eviction policies.
- Nodes MUST NOT:
  - Inspect message content.
  - Apply semantic moderation.
  - Selectively censor based on plaintext.

### 6.2 User-Level Abuse Control
- Abuse responsibility stays with the user:
  - Allowlists / contact-approval inbox.
  - Blocklists (local).
  - Invite-only mode.
  - Silent drop of unwanted senders.

## 7. Proof of Useful Work (PoUW)

### 7.1 Purpose
- PoUW exists to:
  - Price spam.
  - Protect the network.
  - Reward real participation.

### 7.2 PoUW Stamp
- Each message or batch includes a PoUW stamp:
  - Computed by the sender device.
  - Verifiable cheaply by nodes.
  - Bound to:
    - Sender device key.
    - Recent network challenge.
    - Message hash.

### 7.3 Accepted Work Types
- Message relay (routing).
- Store-and-forward storage.
- Receipt propagation.
- Validation of PoUW stamps from peers.
- Light consensus participation (if applicable to the wider network).

### 7.4 Reward Model (Abstract)
- Reward =
  - base_rate(work_type) × correctness × timeliness × reputation × energy_cap
- Correctness: invalid work = zero reward.
- Timeliness: late relay/storage decays reward.
- Reputation: long-term honest participation multiplier.
- Energy cap: prevents farming on low-cost abusive setups.

### 7.5 Mobile Participation
- Phones MAY:
  - Compute PoUW stamps.
  - Relay messages opportunistically.
  - Store encrypted payloads temporarily.
  - Verify stamps from others.
- Phones MUST:
  - Respect energy caps.
  - Never be forced into continuous work.

## 8. Recovery Model

### 8.1 Account Recovery
- Recovery restores control of the DID via seed phrase.
- User can re-authorize devices.

### 8.2 Message Recovery
- No message recovery exists.
- No node, admin, or protocol path can recover old messages without surviving device keys.
- Invariant: Loss of all device keys = permanent loss of message history.

## 9. Legal and Compliance Posture

- Nodes operate as:
  - Blind relays.
  - Temporary ciphertext buffers.
- Nodes do not possess:
  - Decryption keys.
  - Message content.
  - Long-term message archives.
- Abuse reports:
  - Handled off-protocol (user-provided plaintext/screenshots).
  - Network itself remains content-agnostic.

## 10. Hard Protocol Invariants (Non-Negotiable)

- Nodes never decrypt content.
- Nodes never hold long-term message history.
- No key escrow exists.
- Recovery restores identity, not data.
- Groups are capped and rekey on membership change.
- Spam resistance is economic and protocol-level, not semantic.
- Rewards are tied to verifiable useful work only.
