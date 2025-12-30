# MessageBroadcaster - Guards & Security

## Overview

The MessageBroadcaster implementation includes four critical guard rails and one major architectural constraint. These prevent common mistakes and enforce the separation between consensus authority and network delivery.

---

## Guard 1: Self-Send Prevention (MB-6)

### Problem It Solves

```
Broadcaster at Node A wants to send to [A, B, C, D]

WITHOUT GUARD:
    A sends to A (itself)
    A receives from itself
    A processes its own message again
    ❌ Re-entrancy, duplicate processing, corrupted telemetry
```

### Implementation

```rust
// In broadcast_to_validators()
for validator in validators {
    // GUARD MB-6: Prevent self-send to avoid loops and re-entrancy
    if validator == self.local_peer_id {
        skipped += 1;
        continue;
    }
    // ... route to other validators
}

// In send_to_validator()
// GUARD MB-6: Prevent self-send to avoid loops and re-entrancy
if validator.peer_id == self.local_peer_id {
    return Err(anyhow!(
        "Cannot send to self: {}",
        validator.peer_id.did()
    ));
}
```

### What It Guards Against

| Threat | Mechanism | Result |
|--------|-----------|--------|
| **Re-Entrancy** | A calls itself, A processes own message recursively | Stack overflow, state corruption |
| **Duplicate Processing** | A counts itself in delivery metrics | Inflated `delivered` count |
| **Validator Confusion** | A thinks it reached itself when partition-blocked | Wrong quorum math |

### Testing

```rust
#[tokio::test]
async fn test_broadcast_skips_self() {
    let mock = MockMessageBroadcaster::new(3);
    let local_pk = PublicKey::generate();
    let other_pks = vec![pk1, pk2, local_pk, pk3];

    let result = broadcaster.broadcast_to_validators(msg, &other_pks).await?;

    // local_pk should be skipped
    assert_eq!(result.attempted, 4);
    assert_eq!(result.delivered, 3);
    assert_eq!(result.skipped, 1);
}
```

---

## Guard 2: Peer Verification (MB-5)

### Problem It Solves

```
Peer Registry contains two types of peers:

1. VERIFIED (is_verified() = true, bootstrap_mode = false)
   ✓ Full handshake complete
   ✓ Authenticated identity
   ✓ Can participate in consensus

2. BOOTSTRAP (is_verified() = false, bootstrap_mode = true)
   ✗ Still joining the network
   ✗ Identity not yet verified
   ✗ Should NOT participate in consensus

WITHOUT GUARD:
    Broadcast to bootstrap-mode peers
    ❌ Unverified peers vote in consensus
    ❌ Violates security assumptions
```

### Implementation

```rust
// In find_validators()
// GUARD MB-5: Only returns verified peers (is_verified() == true).
// Bootstrap-mode peers are excluded to prevent unverified peers from
// participating in consensus message delivery.
async fn find_validators(
    &self,
    target_validators: &[PublicKey],
) -> Vec<UnifiedPeerId> {
    let registry = self.peer_registry.read().await;

    target_validators
        .iter()
        .filter_map(|pubkey| {
            registry.find_by_public_key(pubkey)
                .map(|entry| entry.peer_id.clone())
        })
        .filter(|peer| peer.is_verified()) // GUARD MB-5: Only verified peers
        .collect()
}

// In send_to_validator()
// GUARD MB-5: Strengthen peer verification - only verified peers can receive
if !validator.peer_id.is_verified() {
    return Err(anyhow!(
        "Cannot send to unverified validator: {}",
        validator.peer_id.did()
    ));
}
```

### Verification Flow

```
PublicKey → PeerRegistry.find_by_public_key()
    ↓
PeerEntry { peer_id, ... }
    ↓
peer_id.is_verified()
    ├─ true  (bootstrap_mode = false)
    │    ↓
    │  ✓ ACCEPT: Route message
    │
    └─ false (bootstrap_mode = true)
         ↓
       ✗ REJECT: Peer not fully verified
```

### State Transitions

```
New Peer Joins Network
    │
    ├─ Initiates handshake
    ├─ Sets bootstrap_mode = true
    ├─ is_verified() = false
    │
    ├─ Handshake completes
    ├─ Identity verified
    ├─ Sets bootstrap_mode = false
    ├─ is_verified() = true
    │
    └─ ✓ Now can receive consensus messages
```

### Testing

```rust
#[tokio::test]
async fn test_broadcast_filters_bootstrap_mode_peers() {
    let broadcaster = setup_broadcaster();
    let verified_pk = PublicKey::generate();
    let bootstrap_pk = PublicKey::generate();

    // Add verified peer
    peer_registry.add(verified_pk, bootstrap_mode=false);

    // Add bootstrap peer
    peer_registry.add(bootstrap_pk, bootstrap_mode=true);

    let result = broadcaster.broadcast_to_validators(
        msg,
        &[verified_pk, bootstrap_pk],
    ).await?;

    // Only verified peer should receive
    assert_eq!(result.attempted, 2);
    assert_eq!(result.delivered, 1); // Only verified_pk
    assert_eq!(result.skipped, 1);   // bootstrap_pk skipped
}
```

---

## Guard 3: Message Opaqueness (MB-1/MB-7)

### Problem It Solves

```
ValidatorMessage enum has 5 variants:
- Propose(ProposeMessage)
- Vote(VoteMessage)
- Commit(CommitMessage)
- RoundChange(RoundChangeMessage)
- Heartbeat(HeartbeatMessage)

WITHOUT GUARD:
Network layer could branch on message kind:

match message {
    ValidatorMessage::Propose(_) => {
        // ❌ Consensus interpretation in network layer!
        // ❌ Network layer knows too much about consensus
    }
    ...
}

PROBLEMS:
    ❌ Network code must update if consensus adds message types
    ❌ Network code might misinterpret message semantics
    ❌ Network decisions based on consensus concerns
    ❌ Tight coupling between layers
```

### Implementation: Opaque Type

```rust
// MessageType enum - lib-network only cares about one type now
pub enum MessageType {
    // ... other network message types ...

    /// Opaque consensus message (Proposal, Vote, Commit, etc.)
    /// lib-network treats this as opaque bytes and never interprets message kind
    ConsensusMessage = 29,
}

// Serialization - always uses same type
fn serialize_with_type(&self) -> Result<(MessageType, Vec<u8>)> {
    match self {
        Self::ValidatorMessage(msg) => {
            // INVARIANT MB-1/MB-7: Treat as opaque bytes
            // lib-network never branches on message kind (Propose, Vote, etc.)
            // That's a consensus-layer concern, not networking's
            (MessageType::ConsensusMessage, bincode::serialize(&msg)?)
        }
        // ... other cases ...
    }
}

// Deserialization - no interpretation
fn deserialize_from_type(
    message_type: MessageType,
    payload: &[u8],
) -> Result<Self> {
    match message_type {
        MessageType::ConsensusMessage => {
            // INVARIANT MB-1/MB-7: Treat as opaque bytes
            // lib-network never branches on message kind
            let msg = bincode::deserialize(payload)?;
            Ok(Self::ValidatorMessage(msg))
        }
        // ... other cases ...
    }
}
```

### Architectural Benefit

```
OLD (WRONG): Network layer branches on message kind
┌────────────────────────────────────────┐
│ Network Layer (lib-network)            │
├────────────────────────────────────────┤
│ match ValidatorMessage {               │
│   Propose(_) => ...,                   │
│   Vote(_) => ...,                      │
│   Commit(_) => ...,                    │
│   ...                                  │
│ }                                      │
│                                        │
│ ❌ Couples network to consensus impl  │
│ ❌ Must update on consensus changes  │
│ ❌ Risk of semantic bugs              │
└────────────────────────────────────────┘

NEW (CORRECT): Network layer treats as opaque
┌────────────────────────────────────────┐
│ Network Layer (lib-network)            │
├────────────────────────────────────────┤
│ // MessageType::ConsensusMessage(29)  │
│ // Serialize/deserialize as bytes     │
│ // Never interpret contents            │
│                                        │
│ ✓ Truly protocol-agnostic             │
│ ✓ Consensus changes don't affect      │
│ ✓ Network can version independently   │
│ ✓ Zero semantic coupling              │
└────────────────────────────────────────┘
```

### Testing

```rust
#[test]
fn test_consensus_message_opaque() {
    let propose = ValidatorMessage::Propose(...);
    let vote = ValidatorMessage::Vote(...);

    let (propose_type, propose_bytes) = ZhtpMeshMessage::ValidatorMessage(propose)
        .serialize_with_type()?;
    let (vote_type, vote_bytes) = ZhtpMeshMessage::ValidatorMessage(vote)
        .serialize_with_type()?;

    // Both should serialize to same MessageType
    assert_eq!(propose_type, MessageType::ConsensusMessage);
    assert_eq!(vote_type, MessageType::ConsensusMessage);

    // Different message kinds produce different bytes
    assert_ne!(propose_bytes, vote_bytes);

    // But network layer never sees those differences
    // Network just routes opaque bytes by type
}
```

---

## Guard 4: Documentation - Non-Authoritative Telemetry

### Problem It Solves

```
BroadcastResult { delivered, failed, failed_validators, ... }

WITHOUT GUARD:
    Consensus layer reads failed_validators
    Makes slashing decision based on network telemetry
    ❌ Slashes validator for transient network failure
    ❌ Treats network delivery as authority indicator
    ❌ Violates Byzantine properties

CONSENSUS LAYER WRONG DECISION:
    if result.failed > quorum_threshold {
        slash_validators(&result.failed_validators)?;
    }
    // ❌ Network delivery != validator misbehavior
```

### Documentation Implementation

```rust
/// IdentityIds of validators that failed (for retry/monitoring)
///
/// **INFORMATIONAL ONLY**
///
/// This field is telemetry and MUST NOT be used for:
/// - Consensus decisions or voting logic
/// - Slashing or punishment calculations
/// - Quorum determination
/// - Authority or validator liveness inference
///
/// It reflects transient network failures, not validator authority.
/// All network delivery information is best-effort and probabilistic.
pub failed_validators: Vec<IdentityId>,
```

### Why Each Restriction Matters

| Forbidden Use | Why It's Wrong |
|---------------|----------------|
| **Consensus decisions** | Network is non-deterministic. Votes must be explicit, on-chain. |
| **Slashing calculations** | Delivery failure ≠ Byzantine behavior. Different punishment scopes. |
| **Quorum determination** | Quorum comes from on-chain validator set, not network connectivity. |
| **Liveness inference** | Validator might be offline but still authorized. Epochs change. |

### Correct vs Incorrect Usage

```rust
// ❌ WRONG: Using for consensus decisions
if broadcaster.reachable_validator_count(&targets).await? >= quorum {
    // ❌ DON'T: Network connectivity isn't consensus authority
    consensus.mark_voting_complete()?;
}

// ✅ CORRECT: Using for observability
let result = broadcaster.broadcast_to_validators(msg, targets).await?;
metrics.record_broadcast_success_rate(result.delivered as f64 / result.attempted as f64);

// ❌ WRONG: Using failed list for slashing
for failed_id in result.failed_validators {
    slash_validator(&failed_id)?; // ❌ Wrong scope!
}

// ✅ CORRECT: Using for retry logic in application code
if result.failed > 0 {
    // Application can decide to retry, but not consensus
    try_broadcast_later(&result.failed_validators).await?;
}
```

### Testing for Misuse

```rust
#[test]
fn test_failed_validators_not_used_for_consensus_decisions() {
    let mock = MockMessageBroadcaster::new(10);
    mock.set_fail_on({pk1, pk2, pk3}).await;

    let result = broadcaster.broadcast_to_validators(msg, targets).await?;

    // These validators failed network delivery
    assert_eq!(result.failed, 3);

    // But consensus does NOT slashing them!
    // Consensus only slashes for on-chain violations
    consensus.assert_no_slashing_executed();
}
```

---

## Constraint 1: Authority Boundary (Architectural)

### What It Means

```
CONSENSUS LAYER owns:
├─ Proposal construction
├─ Message signing
├─ Validator set determination
├─ Quorum/voting logic
├─ Authority decisions
└─ Correctness

NETWORK LAYER owns:
├─ Peer routing
├─ Message delivery
├─ Telemetry collection
├─ Connection management
└─ Best-effort delivery
```

### Enforcement

```
API Boundary:
    ValidatorMessage (consensus-signed)
        ↓
    MessageBroadcaster.broadcast_to_validators()
        ↓
    BroadcastResult (telemetry, non-binding)

Invariants:
✓ ValidatorMessage is signed before entering network layer
✓ Network layer never constructs messages
✓ Network layer never verifies signatures
✓ Network layer never infers validator status
✓ Results are explicitly non-authoritative
```

### Violation Detection

```
Signs of Boundary Violation:
❌ Network code imports consensus types
❌ Network code signing/verifying messages
❌ Network code determining quorum
❌ Network code making authority decisions
❌ Network code using telemetry for consensus

Prevention:
✓ Public API accepts only ValidatorMessage
✓ Documentation emphasizes signing happens before
✓ No signing code in network layer
✓ BroadcastResult explicitly non-authoritative
✓ Mock supports partition/failure testing
```

---

## Full Security Matrix

| Component | Guard | Implementation | Test |
|-----------|-------|-----------------|------|
| **Self-Send** | MB-6 | Equality check in loop | test_broadcast_skips_self |
| **Bootstrap Filter** | MB-5 | is_verified() check | test_filters_bootstrap_mode |
| **Message Opaqueness** | MB-1/MB-7 | Single MessageType | test_message_opaque |
| **Telemetry Warning** | Doc | Explicit MUST NOT list | test_failed_validators_not_for_consensus |
| **Authority Boundary** | Trait API | ValidatorMessage type | test_no_raw_consensus_types |

---

## Security Testing Checklist

- [ ] Broadcast to self is skipped
- [ ] Bootstrap-mode peers are excluded
- [ ] Only verified peers receive messages
- [ ] Point-to-point send rejects self
- [ ] Point-to-point send rejects unverified
- [ ] Message type is always opaque
- [ ] No branching on message kind
- [ ] failed_validators used for telemetry only
- [ ] Mock partition testing works
- [ ] Mock failure simulation works
- [ ] Tests verify all guards are triggered

---

## Integration Verification

When integrating MessageBroadcaster into ValidatorProtocol:

```rust
// Verify in code review:

// ✓ ValidatorProtocol creates broadcaster
let broadcaster = Arc::new(MeshMessageBroadcaster::new(...));

// ✓ Protocol creates AND SIGNS message
let msg = ValidatorMessage::Propose(ProposalData {
    proposal,
    signature: self.sign_message(&proposal)?,  // ✓ Here, not in network
});

// ✓ Only then pass to network layer
broadcaster.broadcast_to_validators(msg, targets).await?;

// ✗ NOT: broadcaster.broadcast_proposal(proposal)
// ✗ NOT: broadcaster.route_raw_proposal(proposal)

// ✓ Telemetry only in observability, never consensus
let result = broadcaster.broadcast_to_validators(...).await?;
metrics.inc_broadcast_failures(result.failed);  // ✓ OK

// ✗ Never: if result.failed > 0 { consensus_update() }
```
