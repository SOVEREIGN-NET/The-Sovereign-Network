# MessageBroadcaster Trait - Architecture & Design

## Overview

The `MessageBroadcaster` trait provides a clean, decentralized network abstraction for broadcasting pre-signed consensus messages (proposals, votes, commits) to validators across the mesh network. It enforces a strict separation of concerns: **consensus layer owns authority and signing; network layer owns only message delivery**.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                        CONSENSUS LAYER (lib-consensus)                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ ValidatorProtocol                                                  │    │
│  │  • Validates proposals                                             │    │
│  │  • Signs messages with ValidatorMessage wrapper                   │    │
│  │  • Determines target validators (stake-derived, epoch-scoped)     │    │
│  │  • Decides consensus outcomes based on quorum                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              │ Creates + Signs                              │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ ValidatorMessage (enum)                                            │    │
│  │  - Propose { signature, ... }                                      │    │
│  │  - Vote { signature, ... }                                         │    │
│  │  - Commit { signature, ... }                                       │    │
│  │  - RoundChange { signature, ... }                                  │    │
│  │  - Heartbeat { signature, ... }                                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
└──────────────────────────────┼──────────────────────────────────────────────┘
                               │
                               │ AUTHORITY BOUNDARY
                               │ (Pre-signed, Consensus-owned)
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                      NETWORK LAYER (lib-network)                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ MessageBroadcaster Trait                                           │    │
│  │  • Takes ValidatorMessage (already signed)                         │    │
│  │  • Takes target PublicKeys (from consensus layer)                 │    │
│  │  • Routes messages via MeshMessageRouter                          │    │
│  │  • Returns BroadcastResult (telemetry only)                       │    │
│  │                                                                    │    │
│  │  🚫 NEVER:                                                         │    │
│  │     - Constructs ValidatorMessage                                 │    │
│  │     - Signs or verifies signatures                                │    │
│  │     - Determines who is a validator                               │    │
│  │     - Makes consensus decisions                                   │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              │ Routes via MeshMessageRouter                 │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ MeshMessageRouter                                                  │    │
│  │  • Wraps in ZhtpMeshMessage::ValidatorMessage                     │    │
│  │  • Routes through QUIC/multi-protocol mesh                        │    │
│  │  • Handles network delivery (gossip-based)                        │    │
│  │  • Best-effort, partial delivery expected                         │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ PeerRegistry                                                       │    │
│  │  • Lookup validators by PublicKey                                 │    │
│  │  • Filter by is_verified() (bootstrap_mode=false)                │    │
│  │  • Provide peer endpoints for routing                             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                               │
                               │ BroadcastResult (Telemetry)
                               ▼
                    { attempted, delivered,
                      failed, skipped,
                      failed_validators }

                 ⚠️  NON-AUTHORITATIVE
                     DO NOT USE FOR:
                     • Consensus decisions
                     • Slashing calculations
                     • Quorum determination
                     • Liveness inference
```

---

## Trait Interface

```rust
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Broadcast to multiple validators (best-effort)
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,      // Pre-signed by consensus
        target_validators: &[PublicKey], // From consensus layer
    ) -> Result<BroadcastResult>;

    /// Send to single validator (point-to-point)
    async fn send_to_validator(
        &self,
        validator_pubkey: &PublicKey,
        message: ValidatorMessage,
    ) -> Result<()>;

    /// Query reachable validators
    async fn reachable_validator_count(
        &self,
        target_validators: &[PublicKey],
    ) -> Result<usize>;

    /// Check if single validator reachable
    async fn is_validator_reachable(
        &self,
        validator_pubkey: &PublicKey,
    ) -> Result<bool>;
}
```

---

## Message Flow - Single Broadcast Operation

```
Consensus Layer                     Network Layer                   Peer Registry
    │                                   │                               │
    │  broadcast_to_validators()        │                               │
    │──────────────────────────────────>│                               │
    │   message: ValidatorMessage       │                               │
    │   target: [pk1, pk2, pk3, ...]    │                               │
    │                                   │                               │
    │                                   │  find_validators()            │
    │                                   │──────────────────────────────>│
    │                                   │  PublicKeys: [pk1, pk2, ...]  │
    │                                   │                               │
    │                                   │  Return UnifiedPeerIds        │
    │                                   │<──────────────────────────────│
    │                                   │  (filtered: is_verified())    │
    │                                   │                               │
    │                           ┌───────┴──────────┐                    │
    │                           │ for each peer:   │                    │
    │                           │ • Skip self      │                    │
    │                           │ • Verify status  │                    │
    │                           │ • Route message  │                    │
    │                           └───────┬──────────┘                    │
    │                                   │                               │
    │                                   │  route_message()              │
    │                                   │  ZhtpMeshMessage             │
    │                                   ├──────────────────────────────>│
    │                                   │  (QUIC/mesh delivery)         │
    │                                   │  (gossip-based)               │
    │                                   │<──────────────────────────────│
    │                                   │  Ok() or Err()                │
    │                                   │                               │
    │  BroadcastResult                  │                               │
    │<──────────────────────────────────┤                               │
    │  attempted: 3                     │                               │
    │  delivered: 2                     │                               │
    │  failed: 1                        │                               │
    │  skipped: 0                       │                               │
    │  failed_validators: [pk3]         │                               │
    │                                   │                               │
    │  ⚠️  TELEMETRY ONLY               │                               │
    │      Not used for decisions       │                               │
    │                                   │                               │
```

---

## Authority Boundary - What Belongs Where

### ❌ WRONG (Violates Authority Boundary)

```rust
// DON'T: Network layer constructing consensus messages
impl MessageBroadcaster for MeshMessageBroadcaster {
    async fn broadcast_proposal(&self, proposal: ConsensusProposal) -> Result<()> {
        // ❌ Network layer should never touch raw consensus types
        let msg = ValidatorMessage::Propose(ProposeMessage {
            proposal,
            signature: PostQuantumSignature::default(), // ❌ Signing in network?!
        });
        self.broadcast_to_validators(msg, ...).await
    }
}
```

### ✅ CORRECT (Clean Separation)

```rust
// Consensus layer owns message construction and signing
impl ValidatorProtocol {
    async fn broadcast_proposal(&self, proposal: ConsensusProposal) -> Result<()> {
        // Create and sign the message
        let msg = ValidatorMessage::Propose(ProposeMessage {
            proposal,
            signature: self.sign_message(&proposal)?, // ✅ Consensus signs
        });

        // Determine target validators (stake-derived, epoch-scoped)
        let targets = self.get_target_validators()?;

        // Pass pre-signed message to network layer for delivery only
        self.broadcaster
            .broadcast_to_validators(msg, &targets)
            .await?;

        Ok(())
    }
}

// Network layer: routing only, never touches signatures
#[async_trait]
impl MessageBroadcaster for MeshMessageBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage, // ✅ Already signed
        target_validators: &[PublicKey],
    ) -> Result<BroadcastResult> {
        // ✅ Just route pre-signed messages, no construction/signing
        // ...
    }
}
```

---

## Broadcast Result - Telemetry Semantics

```
┌─────────────────────────────────────────────────────────┐
│           BroadcastResult: Non-Authoritative             │
│                                                         │
│  attempted: 10    → Number of validators targeted       │
│  delivered: 8     → Successfully routed to              │
│  failed: 1        → Network delivery failures           │
│  skipped: 1       → Not found in PeerRegistry           │
│  failed_validators: [id3] → Who failed                 │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  This is TELEMETRY (metrics/monitoring)                │
│                                                         │
│  ✅ USE FOR:                                            │
│    • Logging and monitoring                            │
│    • Metrics collection                                │
│    • Retry logic in application code                   │
│    • Network diagnostics                               │
│                                                         │
│  🚫 NEVER USE FOR:                                      │
│    • Consensus voting decisions                        │
│    • Slashing or punishment logic                      │
│    • Quorum determination                              │
│    • Validator liveness assumptions                    │
│    • Authority or role changes                         │
│                                                         │
│  WHY:                                                   │
│    • Reflects transient network failures              │
│    • Not validator authority                           │
│    • Best-effort delivery, partial failure normal     │
│    • Probabilistic, not deterministic                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation Variants

### 1. Production: MeshMessageBroadcaster

```
┌──────────────────────────────────┐
│  MeshMessageBroadcaster          │
├──────────────────────────────────┤
│  • Uses real PeerRegistry        │
│  • Routes via MeshMessageRouter  │
│  • Verifies peers: is_verified() │
│  • Prevents self-send loops      │
│  • Gossip-based delivery         │
│                                  │
│  Flow:                           │
│  1. Find validators by pubkey    │
│  2. Filter: verified peers only  │
│  3. Skip self                    │
│  4. Route via mesh               │
│  5. Track delivery (telemetry)   │
└──────────────────────────────────┘
```

### 2. Testing: MockMessageBroadcaster

```
┌────────────────────────────────────────────────┐
│      MockMessageBroadcaster                    │
├────────────────────────────────────────────────┤
│  • Records all broadcasts/sends                │
│  • Simulates network partitions                │
│  • Simulates delivery failures                 │
│  • No actual routing                           │
│                                                │
│  Configuration:                                │
│  ┌──────────────────────────────────────────┐ │
│  │ set_reachable(Some({pk1, pk2}))          │ │
│  │  → Only pk1, pk2 are reachable           │ │
│  │  → Others are "partitioned"              │ │
│  └──────────────────────────────────────────┘ │
│                                                │
│  ┌──────────────────────────────────────────┐ │
│  │ set_fail_on({pk3})                       │ │
│  │  → Delivery to pk3 always fails          │ │
│  │  → Simulate flaky peer                   │ │
│  └──────────────────────────────────────────┘ │
│                                                │
│  Enables:                                      │
│  ✓ Partition testing                          │
│  ✓ Failure scenarios                          │
│  ✓ Deterministic test behavior               │
│  ✓ Recording for assertions                   │
└────────────────────────────────────────────────┘
```

---

## Guard Rails & Constraints

### Guard MB-6: Self-Send Prevention

```
Validator A wants to broadcast to [A, B, C, D]

broadcast_to_validators(msg, [pubkey_A, pubkey_B, pubkey_C, pubkey_D])
                                    │
                                    ▼
                           find_validators()
                           Returns: [A_peer, B_peer, C_peer, D_peer]
                                    │
                                    ▼
                           Loop: for each peer
                                    │
                   ┌────────────────┼────────────────┐
                   ▼                ▼                ▼
                A_peer          B_peer          C_peer
                   │                │                │
         if A_peer == self.local_peer_id
                   │
                   ✓ SKIP  (don't route back to self)
                   │
                Prevents:
                • Self re-entrancy
                • Duplicate processing
                • Misleading telemetry
```

### Guard MB-5: Peer Verification

```
Find validators by public key:

1. Lookup in PeerRegistry by PublicKey
   └─> Returns PeerEntry { peer_id, ... }

2. Check: peer_id.is_verified()

   is_verified() == true  (bootstrap_mode == false)
      ✓ Verified peer, can receive consensus messages

   is_verified() == false (bootstrap_mode == true)
      ✗ Bootstrap peer, excluded from consensus

Why:
• Bootstrap-mode peers are still joining the network
• Not yet part of consensus security assumptions
• Only fully-verified peers can participate
• Prevents accidental consensus with partial peers
```

### Guard MB-1/MB-7: Message Opaqueness

```
When serializing ValidatorMessage:

        Before (WRONG):
        ┌─────────────────────────────────────┐
        │ match ValidatorMessage {            │
        │   Propose(_) → MessageType::29,     │
        │   Vote(_) → MessageType::30,        │
        │   Commit(_) → MessageType::31,      │
        │   RoundChange(_) → MessageType::32, │
        │   Heartbeat(_) → MessageType::33,   │
        │ }                                   │
        │ ❌ Network layer interpreting      │
        │    consensus semantics             │
        └─────────────────────────────────────┘

        After (CORRECT):
        ┌──────────────────────────────────┐
        │ MessageType::ConsensusMessage (29) │
        │                                   │
        │ ✓ Treat ValidatorMessage as      │
        │   opaque bytes                   │
        │ ✓ Never branch on message kind   │
        │ ✓ Network layer is agnostic      │
        │ ✓ Consensus layer owns semantics│
        └──────────────────────────────────┘

Invariant:
  lib-network knows this is a consensus message,
  but NEVER which specific kind.
  That's a consensus-layer concern.
```

---

## Testing Scenarios Enabled

### Scenario 1: All Validators Reachable
```rust
let mock = MockMessageBroadcaster::new(5);
let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3]).await?;

assert_eq!(result.attempted, 3);
assert_eq!(result.delivered, 3);
assert_eq!(result.failed, 0);
```

### Scenario 2: Network Partition (50% reachable)
```rust
let mock = MockMessageBroadcaster::new(5);
mock.set_reachable(Some({pk1, pk3})).await; // Only 2 of 3 reachable

let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3]).await?;

assert_eq!(result.attempted, 3);
assert_eq!(result.delivered, 2);
assert_eq!(result.skipped, 1);    // pk2 unreachable
```

### Scenario 3: Mixed Failures
```rust
let mock = MockMessageBroadcaster::new(5);
mock.set_fail_on({pk3}).await; // pk3 will fail

let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3, pk4]).await?;

assert_eq!(result.attempted, 4);
assert_eq!(result.delivered, 3);  // pk1, pk2, pk4
assert_eq!(result.failed, 1);     // pk3 failed
```

### Scenario 4: Both Partition AND Failures
```rust
let mock = MockMessageBroadcaster::new(5);
mock.set_reachable(Some({pk1, pk2, pk3})).await; // Partition
mock.set_fail_on({pk2}).await;                   // pk2 will fail

let result = mock.broadcast_to_validators(msg, &[pk1, pk2, pk3, pk4]).await?;

assert_eq!(result.attempted, 4);
assert_eq!(result.delivered, 2);   // pk1, pk3
assert_eq!(result.failed, 1);      // pk2 (reachable but failed)
assert_eq!(result.skipped, 1);     // pk4 (unreachable, partition)
```

---

## Performance Characteristics

### Current Implementation
- **Sequential broadcast:** ⏱️ ~10-20ms per validator @ 100ms network latency
- **Suitable for:** <100 validators
- **Example:** 100 validators @ 100ms = ~1-2 seconds (sequential)

### Future Optimization (Issue #520)
```rust
// Parallel broadcasting using tokio::spawn
// ⏱️ ~100ms for 100 validators @ 100ms latency
// Suitable for: >100 validators
// Gateway nodes with 1000+ validators

for validator in validators {
    let broadcaster = self.clone();
    let msg = message.clone();

    tokio::spawn(async move {
        broadcaster.route_to_single(validator, msg).await
    });
}
```

---

## Security Invariants

| Invariant | Enforced By | Impact |
|-----------|------------|--------|
| **Authority Boundary** | Trait signature, documentation | Consensus owns signing, network owns routing only |
| **No Self-Send Loops** | Guard MB-6 check | Prevents re-entrancy, duplicate processing |
| **Verified Peers Only** | Guard MB-5 `is_verified()` | Bootstrap-mode peers excluded from consensus |
| **Opaque Messages** | Guard MB-1/MB-7, single MessageType | Network layer never interprets message kind |
| **Non-Authoritative Telemetry** | BroadcastResult documentation | Results only for metrics, not decisions |
| **Best-Effort Delivery** | Trait semantics | Partial failure expected, consensus independent |

---

## Key Design Decisions

### 1. PublicKey, Not PeerTier

**Decision:** Validators identified by PublicKey (from consensus layer), not PeerTier::Tier1

**Why:**
- PeerTier is a network/routing concern (bandwidth, capability)
- Validator status is a consensus authority concern
- Validators may be offline but still authorized
- Tier1 peers may be relays/gateways, not validators
- PoS validators are epoch-scoped, not static network tiers

### 2. ValidatorMessage Only

**Decision:** Accept only fully-signed ValidatorMessage, never raw consensus types

**Why:**
- Clean authority boundary
- Message already validated by consensus
- Network layer has zero responsibility for signing
- Prevents signature-related bugs in network code
- Enables future slashing/equivocation proofs

### 3. BroadcastResult (Non-Fatal, Best-Effort)

**Decision:** Return structured telemetry, not simple Ok/Err

**Why:**
- Gossip-based networks expect partial delivery
- Treating broadcast as transactional is wrong
- Consensus correctness MUST NOT depend on broadcast success
- Need detailed telemetry for monitoring/diagnostics
- Explicit non-authoritative documentation prevents misuse

### 4. Opaque Message Type

**Decision:** Single ConsensusMessage type, never branch on kind

**Why:**
- Enforces that network layer is semantically agnostic
- Prevents future consensus-layer changes from breaking network
- Message kind is a consensus concern, not networking
- Enables transparent protocol upgrades
- Simplifies serialization/routing logic

---

## Related Issues & Follow-Up Work

| Issue | Title | Status | Scope |
|-------|-------|--------|-------|
| #519 | Define MessageBroadcaster trait | ✅ COMPLETE | Core trait + implementations |
| #520 | Parallel broadcasting | 📋 DEFERRED | Optimization for 100+ validators |
| #521 | Error classification | 📋 DEFERRED | Distinguish transient vs permanent |
| #522 | Rate limiting | 📋 DEFERRED | Throttle broadcast to prevent spam |
| #523 | Message versioning | 📋 DEFERRED | Future consensus protocol compatibility |

---

## References

- **Trait Definition:** `lib-network/src/message_broadcaster.rs`
- **Integration Point:** `lib-consensus/src/validators/validator_protocol.rs` (future)
- **Type Definitions:** `lib-network/src/types/mesh_message.rs`
- **Architecture Issue:** #519 - Peer-to-Peer Message Broadcasting
