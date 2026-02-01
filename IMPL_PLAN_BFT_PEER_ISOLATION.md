# Implementation Plan: Byzantine Fault Tolerance - Peer Isolation & Reputation

**Branch:** `feat/bft-peer-isolation`
**Status:** FINALIZED (Locked after dry-run validation & architectural decisions)
**Created:** 2026-02-01
**Last Updated:** 2026-02-01
**Version:** 2.0 (Post dry-run, post-decision)

🔒 **LOCKED** - Architectural decisions finalized, dry-run findings incorporated, ready for implementation

---

## Problem Statement

The current Byzantine Fault Detection system detects malicious validator behavior but **does NOT isolate malicious peers at the network level**. Result:

- ❌ Peer sends 1000 invalid votes → Detected → Slashed → Still sending invalid votes
- ❌ Reputation system exists but is never updated by validation layer
- ❌ No connection between "validation failure" and "which peer sent it"
- ❌ Malicious peers face no network-level consequences until stake exhausted

**Current Code Paths:**
- Validation fails → Message dropped → No peer recorded → Peer continues → Repeat infinitely

**Desired Behavior:**
- Validation fails → Peer reported → Reputation decrements → Peer rate-limited → Peer banned → Isolated

---

## Dry-Run Validation & Critical Gaps

**Date:** 2026-02-01
**Reference:** See `DRYRUN_VALIDATION_REPORT.md` for complete analysis

### 7 Critical Gaps Identified

The implementation plan uncovered **7 critical architectural gaps** that must be addressed:

1. ❌ **ValidatorMessage lacks peer_id field** - Network layer never passes sender information to consensus
2. ❌ **disconnect_peer() doesn't exist** - No method to sever connections or ban peers from network layer
3. ❌ **No consensus→network feedback channel** - ConsensusEngine can't tell MeshRouter about bad peers
4. ❌ **peer_id never captured** - Hardcoded to None at validation point (network.rs:403)
5. ❌ **No peer↔validator mapping** - Can't verify validator's votes come from registered peer
6. ❌ **Hardcoded rate limits** - All thresholds are magic numbers, can't adjust per-peer dynamically
7. ❌ **Silent vote rejection** - Invalid votes dropped with no reporting mechanism

### Revised Effort Estimate

- **Original Estimate:** 10-15 hours
- **Revised Estimate:** 25-35 hours (with 2 new foundational phases)
- **Change:** +50% due to peer infrastructure gaps

---

## Finalized Architectural Decisions

The following 4 critical architectural decisions have been **locked** to address dry-run gaps:

### Decision 1: Where does peer_id come from? ✅ LOCKED

**Decision:** Use cryptographic Node ID derived from transport identity

```
peer_id := hash(transport_static_public_key)
```

Where `transport_static_public_key` is the static public key from QUIC/UHP handshake.

**Rationale:**
- ✅ Stable across reconnections (unlike IP:port)
- ✅ Spoof-resistant (requires key possession)
- ✅ Already present in handshake surface (no new infrastructure)
- ✅ Matches "zero-knowledge nodes" principle
- ❌ IP:port discarded as identity (used only for logging)

**Implementation:**
```rust
pub struct PeerId(pub Hash);

impl PeerId {
    pub fn from_transport_key(key: &PublicKey) -> Self {
        Self(Hash::hash(key.as_bytes()))
    }
}
```

---

### Decision 2: Who owns the peer↔validator mapping? ✅ LOCKED

**Decision:** Shared registry, owned by consensus (policy) and populated by network (facts)

**Architecture:**
```
Shared Registry (lib-identity or lib-consensus/types)
├─ peer_id → Vec<(validator_id, valid_from, valid_to)>
└─ validator_id → Vec<(peer_id, valid_from, valid_to)>

Read by: Network layer (validation)
Read by: Consensus layer (penalties)
Written by: Registration transaction (governance control)
Updated by: Height-based timeout
```

**Minimum Interface:**
```rust
pub trait PeerValidatorRegistry: Send + Sync {
    async fn is_peer_valid_for_validator(
        &self,
        peer_id: &PeerId,
        validator_id: &IdentityId,
        height: u64,
    ) -> bool;

    async fn register_peer(
        &self,
        validator_id: IdentityId,
        peer_id: PeerId,
        valid_from_height: u64,
        valid_to_height: u64,
        proof: SignedRegistration,
    ) -> Result<()>;

    async fn get_peers_for_validator(
        &self,
        validator_id: &IdentityId,
        height: u64,
    ) -> Vec<PeerId>;
}
```

**Rationale:**
- ✅ Shared registry allows both layers to verify relationships
- ✅ Consensus controls policy (who can be validator)
- ✅ Network provides facts (peer connected with key)
- ✅ Registration via transaction creates audit trail
- ✅ Height bounds prevent permanent drift

---

### Decision 3: Validator on multiple peers? ✅ LOCKED

**Decision:** Allow one-to-many with explicit allowlist and hard cap

**Rules:**
```
Default Policy:
  validator → {peer_id} is a small set
  Max: 2–3 active peer_ids per validator per epoch

Requirements:
  - Each peer_id must be registered with signed proof
  - Registration includes valid_from_height, valid_to_height bounds
  - Rotation rate-limited: max 1 rotation per epoch (governance override allowed)
```

**Example:**
```rust
Validator Alice:
  - peer_id_1 (primary): blocks 1000-1050
  - peer_id_2 (secondary): blocks 1000-1050
  - peer_id_3 (backup): blocks 1050-1100  ← rotation

pub const MAX_PEERS_PER_VALIDATOR: usize = 3;
pub const MAX_ROTATIONS_PER_EPOCH: usize = 1;
```

**Rationale:**
- 1-to-1 is operationally brittle (no redundancy, no migration)
- Unbounded 1-to-many is abusable (Sybil surface too large)
- Bounded allowlist gives redundancy + geo-redundancy without trust explosion
- Height bounds allow rotation without on-chain transactions per change

---

### Decision 4: How to handle peer_id in signature verification? ✅ LOCKED

**Decision:** Track and penalize mismatches, don't reject

**Rule:**

1. **Cryptographic invalidity → REJECT + HIGH penalty**
   - Invalid signature: Reject, penalize with High severity
   - Not a validator: Reject, penalize with Medium severity
   - Wrong height/round: Reject, penalize with Low/Medium severity

2. **Valid signature but peer mismatch → ACCEPT for consensus + PENALIZE separately**
   - Signature valid, but validator V received from peer_id N not registered for V
   - **Action:** Accept message (don't reject consensus)
   - **Action:** Apply "peer mismatch penalty" to peer_id N with Low severity
   - **Record:** Forensic evidence of mismatch
   - **Escalation:** Repeated mismatches escalate from Low → Medium → High

**Rationale:**
```
✅ Pros of "track not reject":
   - Handles legitimate relays (forwarded votes)
   - Doesn't partition honest validators during migrations
   - Separates consensus correctness from peer isolation strategy
   - Allows forensic analysis before banning

❌ Danger of hard rejection:
   - Honest validator temporarily unreachable → all votes rejected
   - Validator migrating between data centers → votes rejected
   - Relay nodes legitimately forwarding → rejected
   - Network partition → orphans validator set
```

**Severity Mapping (Finalized):**

```rust
pub enum ValidationFailureType {
    // Cryptographic failures → REJECT
    InvalidSignature,              // High (-50 reputation)
    NotAValidator,                 // Medium (-20 reputation)
    Equivocation,                  // High (-50 reputation)
    DoubleSigning,                 // High (-50 reputation)

    // Consensus rule violations → REJECT
    WrongHeightOrRound,            // Low/Medium (-5 / -20)
    InvalidBlockProposal,          // High (-50 reputation)

    // Network anomalies → TRACK
    ReplayAttack,                  // Medium (-20 reputation)
    PeerMismatch,                  // Low (-5) escalates to Medium/High
    LivenessViolation,             // Medium (-20 reputation)
}

pub enum PeerPenaltySeverity {
    Low,      // -5 reputation
    Medium,   // -20 reputation
    High,     // -50 reputation (threshold → ban at 2 High events)
}
```

---

## Solution Overview

Wire three disconnected systems together:

1. **Validation Layers** → Report peer_id with failures
2. **Reputation System** → Update based on validation reports
3. **Network Layer** → Enforce isolation (disconnect/rate-limit)

### Data Flow

```
Network Input (Peer A sends vote)
    ↓
ConsensusEngine.validate_remote_vote(vote, peer_id=A)
    ↓ (validation fails)
PeerValidationReporter.report_validation_failure(peer_id=A, ...)
    ↓
MeshPeerValidator.update_peer_reputation(A, -50)
    ↓ (threshold exceeded)
MeshRouter.disconnect_peer(A) + mark_as_banned(A)
    ↓
Future messages from A rejected immediately
```

---

## Implementation Phases (Updated Post Dry-Run)

⚠️ **IMPORTANT:** Two new foundational phases (Phase 0 and Phase 4) were added based on dry-run findings. They are **CRITICAL PATH** and must complete before subsequent phases can begin.

### Phase 0 (NEW): Message Structure & Peer ID Threading

**Status:** ⬜ Not Started
**Estimated:** Medium (5-8 hours)
**Blocker:** NONE - This is the critical path foundation
**Dependency:** Must complete before Phase 1

**Goal:** Thread peer_id through the message envelope from network reception to consensus validation

**Files to Modify:**
- `lib-consensus/src/types/mod.rs` - ValidatorMessage enum
- `zhtp/src/server/mesh/mod.rs` - Message entry point, capture peer_id
- `zhtp/src/server/mesh/core.rs` - Track peer_id at reception
- `lib-consensus/src/engines/consensus_engine/network.rs` - Pass peer_id through handlers

**Tasks:**

1. **Extend ValidatorMessage enum** (types/mod.rs:405)
   ```rust
   pub enum ValidatorMessage {
       Propose { proposal: ConsensusProposal, peer_id: PeerId },
       Vote { vote: ConsensusVote, peer_id: PeerId },
       Heartbeat { message: HeartbeatMessage, peer_id: PeerId },
   }
   ```

2. **Capture peer_id at network reception** (mesh/mod.rs)
   - Determine sender's PeerId from handshake
   - Calculate PeerId = hash(transport_static_public_key)
   - Pass to message construction

3. **Thread peer_id through consensus handlers** (network.rs)
   - `on_message(msg: ValidatorMessage)` now has msg.peer_id available
   - Pass to `on_prevote()`, `on_precommit()`, `on_commit_vote()`
   - Pass to `on_proposal()`

4. **Update record_message_signature()** (network.rs:403)
   - Change: `None` → `Some(msg.peer_id.clone())`
   - Now Byzantine detector gets peer attribution

**Testing:**
- Unit test: ValidatorMessage with peer_id serializes/deserializes
- Unit test: peer_id matches transport key hash
- Integration test: Vote from peer flows through with peer_id intact

**High Risk:** Message schema changes affect serialization. Need wire format versioning.

---

### Phase 1B: Foundation (Core Trait & Types)

**Status:** ⬜ Not Started
**Estimated:** Low (1-2 hours)
**Blocker:** Phase 0 must complete

**Goal:** Create the interface for validation layers to report peer failures

**Files to Create:**
- `lib-consensus/src/peer_validator.rs` - Core trait and types
- `lib-consensus/src/types/peer_id.rs` - PeerId struct definition

**Tasks:**

1. **Create PeerId struct** (types/peer_id.rs):
   ```rust
   pub struct PeerId(pub Hash);  // Hash of transport static public key

   impl PeerId {
       pub fn from_transport_key(key: &PublicKey) -> Self { ... }
       pub fn to_string(&self) -> String { ... }
   }
   ```

2. **Create `PeerValidationFailure` struct:**
   - `peer_id: PeerId`
   - `failure_type: ValidationFailureType` (enum)
   - `severity: PeerPenaltySeverity` (Low/Medium/High)
   - `context: String` (for diagnostics)
   - `timestamp: u64`

3. **Create `ValidationFailureType` enum:**
   - `InvalidSignature`
   - `NotAValidator`
   - `WrongHeightOrRound`
   - `Equivocation`
   - `ReplayAttack`
   - `InvalidBlockProposal`
   - `DoubleSigning`
   - `LivenessViolation`
   - `PeerMismatch` (NEW - for off-path peer issues)

4. **Create `PeerPenaltySeverity` enum:**
   - `Low` (-5 reputation)
   - `Medium` (-20 reputation)
   - `High` (-50 reputation)

5. **Create `PeerValidationReporter` async trait:**
   ```rust
   pub trait PeerValidationReporter: Send + Sync {
       async fn report_validation_failure(&self, failure: PeerValidationFailure);
       async fn report_failures_batch(&self, failures: Vec<PeerValidationFailure>);
       async fn is_peer_banned(&self, peer_id: &PeerId) -> bool;
       async fn get_peer_reputation(&self, peer_id: &PeerId) -> i32;
   }
   ```

**Testing:**
- Create MockPeerValidator for testing
- Unit tests for penalty calculation
- Unit tests for enum invariants

---

### Phase 2: Wire Into Consensus Validation

**Goal:** Make validation layers report peer failures with peer attribution

**Files to Modify:**
- `lib-consensus/src/engines/consensus_engine/mod.rs` - Add peer_validator field
- `lib-consensus/src/engines/consensus_engine/validation.rs` - Modify validation methods

**Tasks:**
1. Add to `ConsensusEngine` struct:
   ```rust
   peer_validator: Arc<dyn PeerValidationReporter>
   ```

2. Modify `verify_vote_signature()`:
   - Add parameter: `peer_id: Option<&IdentityId>`
   - On signature invalid → report via peer_validator
   - Pass peer_id through to all validation calls

3. Modify `validate_remote_vote()`:
   - Add parameter: `peer_id: Option<&IdentityId>`
   - Check `is_peer_banned(peer_id)` at start → reject if banned
   - Report failures with peer_id for:
     - Invalid signature
     - Not a validator
     - Wrong height/round
     - Vote type mismatch

4. Modify `validate_proposal()` similarly:
   - Add peer_id parameter
   - Report invalid proposals with peer attribution

**Call Sites to Update:**
- `handle_validator_message()` - Pass peer_id
- `process_vote()` - Accept peer_id in signature
- `process_proposal()` - Accept peer_id in signature
- Any other vote/proposal processing paths

**Testing:**
- Unit test: Invalid signature reported with peer_id
- Unit test: Not-validator vote rejected and reported
- Unit test: Peer ban prevents vote processing
- Integration test: Multiple failures accumulate
- Integration test: Banned peer's messages rejected immediately

**Status:** ⬜ Not Started
**Estimated:** Medium (2-3 hours)
**Blocker:** Phase 0, Phase 1B must complete

---

### Phase 3: Implement Network Layer Peer Validator

**Status:** ⬜ Not Started
**Estimated:** Medium (2-3 hours)
**Blocker:** Phase 0, Phase 1B must complete

**Goal:** Connect reputation changes to actual network isolation

**Files to Create:**
- `zhtp/src/server/mesh/peer_validator_impl.rs` - MeshPeerValidator implementation

**Files to Modify:**
- `zhtp/src/server/monitoring.rs` - Extend PeerReputation struct

**Tasks:**

1. **Extend `PeerReputation` struct** (monitoring.rs):
   ```rust
   pub struct PeerReputation {
       pub peer_id: PeerId,              // NEW: Use PeerId, not String
       pub score: i32,                   // -100 to 100
       pub banned: bool,                 // NEW
       pub ban_reason: Option<String>,   // NEW
       pub equivocation_count: u32,      // NEW
       pub replay_attacks: u32,          // NEW
       pub last_failure_timestamp: u64,  // NEW
   }
   ```

2. **Create `MeshPeerValidator` struct:**
   - `mesh_router: Arc<MeshRouter>`
   - `ban_threshold: i32` (default: 0 reputation)
   - `rate_limit_threshold: i32` (default: 50 reputation)

3. Implement `PeerValidationReporter` for `MeshPeerValidator`:
   - `report_validation_failure()`:
     - Update peer reputation
     - Calculate new reputation score
     - If score ≤ rate_limit_threshold: Set stricter rate limit (10 req/min)
     - If score ≤ ban_threshold: Disconnect peer + mark banned

   - `report_failures_batch()`: Loop and report each

   - `is_peer_banned()`: Check peer_reputations HashMap for banned flag

   - `get_peer_reputation()`: Return calculated reputation score

4. Implement `disconnect_peer()` helper:
   - Call `quic_protocol.disconnect_peer(peer_id)`
   - Call `bluetooth_protocol.disconnect_peer(peer_id)` if available
   - Remove from `connections` registry
   - Mark ban_reason with reason string

5. Implement reputation scoring formula:
   - Base score: 100
   - Per failure: Multiply success_rate by 0.95 (exponential decay)
   - Calculate as: `base + (success_rate * 50) - (failure_count * 5)`
   - Clamp to [0, 100]

**Testing:**
- Unit test: Reputation decrements on failure
- Unit test: Rate limit applied at threshold
- Unit test: Peer disconnected at ban threshold
- Integration test: 5 equivocation failures → peer banned
- Integration test: Banned peer's future messages rejected immediately

**Status:** ⬜ Not Started
**Estimated:** Medium (2-3 hours)
**Blocker:** Phase 0, Phase 1B, Phase 2 must complete

---

### Phase 4 (NEW): Peer↔Validator Mapping Registry

**Status:** ⬜ Not Started
**Estimated:** High (5-7 hours)
**Blocker:** Phase 0, Phase 1B must complete
**Critical Path:** YES

**Goal:** Create the shared registry for peer↔validator relationships (addresses Dry-Run Gap 5)

**Files to Create:**
- `lib-identity/src/peer_validator_registry.rs` - PeerValidatorRegistry trait & implementation
- `lib-consensus/src/peer_validator_registry_impl.rs` - Consensus-side implementation

**Files to Modify:**
- `lib-identity/src/lib.rs` - Export PeerValidatorRegistry
- `lib-consensus/src/lib.rs` - Export registry implementation

**Tasks:**

1. **Create PeerValidatorRegistry trait** (lib-identity):
   ```rust
   pub trait PeerValidatorRegistry: Send + Sync {
       /// Check if peer is valid for this validator at this height
       async fn is_peer_valid_for_validator(
           &self,
           peer_id: &PeerId,
           validator_id: &IdentityId,
           height: u64,
       ) -> bool;

       /// Register a peer for a validator with proof
       async fn register_peer(
           &self,
           validator_id: IdentityId,
           peer_id: PeerId,
           valid_from_height: u64,
           valid_to_height: u64,
           proof: SignedRegistration,
       ) -> Result<()>;

       /// Get all registered peers for a validator at a height
       async fn get_peers_for_validator(
           &self,
           validator_id: &IdentityId,
           height: u64,
       ) -> Vec<PeerId>;

       /// Check rotation rate (prevent spam)
       async fn can_rotate_peer(
           &self,
           validator_id: &IdentityId,
           current_epoch: u64,
       ) -> bool;
   }
   ```

2. **Create PeerRegistration struct:**
   ```rust
   pub struct PeerRegistration {
       pub validator_id: IdentityId,
       pub peer_id: PeerId,
       pub valid_from_height: u64,
       pub valid_to_height: u64,
       pub signature: PostQuantumSignature,  // Signed by validator
   }

   pub const MAX_PEERS_PER_VALIDATOR: usize = 3;
   pub const MAX_ROTATIONS_PER_EPOCH: usize = 1;
   ```

3. **Implement in-memory registry:**
   - HashMap: validator_id → Vec<(peer_id, valid_from, valid_to)>
   - HashMap: peer_id → Vec<(validator_id, valid_from, valid_to)>
   - Track rotation timestamps per validator

4. **Integrate with consensus:**
   - Load registry snapshot at each height
   - Make queryable by validation layer
   - Update via signed registration transactions

5. **Validation enforcement points:**
   - Network layer: When vote/proposal arrives from peer N claiming to be validator V, check registry
   - Consensus layer: When reporting peer failure, check if peer is registered for that validator
   - Penalty escalation: Repeated PeerMismatch events trigger increasing severity

**Testing:**
- Unit test: Register peer for validator
- Unit test: Query valid peers at height
- Unit test: Rotation rate limiting works
- Integration test: Unregistered peer votes rejected or penalized
- Integration test: Validator can rotate peers within limits

---

### Phase 5: Wire Into Byzantine Fault Detector

**Goal:** Make Byzantine Fault Detection cause network-level isolation

**Files to Modify:**
- `lib-consensus/src/byzantine/fault_detector.rs` - Add network isolation to fault processing

**Tasks:**
1. Modify `process_faults()` or create `process_faults_with_isolation()`:
   - Accept `peer_validator: Arc<dyn PeerValidationReporter>`
   - For each fault detected:
     - Slash validator on-chain (existing behavior)
     - NEW: Report to peer_validator with appropriate severity
     - Use mapping:
       - DoubleSign → High severity (-50 reputation)
       - InvalidProposal → High severity (-50 reputation)
       - Liveness → Medium severity (-20 reputation)

2. Include evidence string:
   - `PeerValidationFailure::new(..., context=fault.evidence)`

**Testing:**
- Integration test: Double-sign detected → peer isolated
- Integration test: Invalid proposal detected → peer rate-limited
- Integration test: Liveness violation detected → peer reputation updated

**Status:** ⬜ Not Started
**Estimated:** Low complexity
**Blocker:** Phase 1 + Phase 3 must complete

---

### Phase 6: Wire Into Node Runtime

**Status:** ⬜ Not Started
**Estimated:** Low (1-2 hours)
**Blocker:** Phase 0, Phase 1B, Phase 2, Phase 3, Phase 4, Phase 5 must complete

**Goal:** Inject peer validator into consensus component at startup

**Files to Modify:**
- `zhtp/src/runtime/components/consensus.rs` - Wire peer_validator into ConsensusComponent

**Tasks:**
1. Modify `ConsensusComponent::new()`:
   - Create `MeshPeerValidator` instance
   - Pass to `ConsensusEngine::new()` as peer_validator

2. Modify `ConsensusComponent::handle_validator_message()`:
   - Extract peer_id from message source
   - Pass peer_id to `validate_remote_vote(vote, Some(peer_id))`
   - Do same for proposal handling

3. Ensure all message handlers pass peer_id context:
   - Vote messages
   - Proposal messages
   - Any other validator messages

**Testing:**
- Integration test: Network message from peer → peer tracked
- Integration test: Invalid message from peer → peer reputation updated
- End-to-end test: Malicious peer → isolated after N failures

**Status:** ⬜ Not Started
**Estimated:** Low complexity
**Blocker:** Phase 1-4 must complete

---

### Phase 7: Testing & Validation

**Status:** ⬜ Not Started
**Estimated:** Medium-High (3-4 hours)
**Blocker:** Phase 0-6 must complete

**Goal:** Comprehensive test coverage for entire system

**Files to Create:**
- `tests/integration/peer_isolation.rs` - Integration tests
- `tests/integration/byzantine_peer_scenarios.rs` - Adversarial scenarios

**Test Cases:**

1. **Equivocation Scenario:**
   - Peer A sends two different votes for same (height, round)
   - Should be detected
   - Should cause reputation drop
   - After 3+ equivocations: Peer should be banned

2. **Signature Attack Scenario:**
   - Peer B sends 10 votes with invalid signatures
   - Each should be reported
   - Peer should be rate-limited at 3 failures
   - Peer should be banned at 5 failures

3. **Replay Attack Scenario:**
   - Peer C sends same vote 5 times
   - First vote processed (if valid)
   - Subsequent 4 detectable as replays
   - Peer reputation should decrease

4. **Double Proposal Scenario:**
   - Peer D proposes two different blocks at same height
   - Should be slashed on-chain
   - Should be reported to peer validator
   - Should cause network isolation

5. **Recovery Scenario:**
   - Banned peer comes back online with new connection
   - Previous ban flag should prevent reentry
   - Should require governance vote to unban

6. **Load Test Scenario:**
   - 1000 malicious votes from 10 peers
   - System should isolate all 10 within 10 seconds
   - Should not degrade performance

**Status:** ⬜ Not Started
**Estimated:** Medium-High complexity
**Blocker:** Phase 1-5 must complete

---

## Reputation Scoring Formula (Reference)

```
Initial Score: 100

Update on validation failure:
  reputation_score = 100 + (success_rate * 50) - (failure_count * 5)
  Where: success_rate *= 0.95 per failure

Thresholds:
  - 50 reputation: Rate limit threshold
    Action: Reduce requests_per_minute from 1000 to 10
    Action: Delay message processing by 100ms
    Action: Increase DNS lookup timeout

  - 0 reputation: Ban threshold
    Action: Disconnect from QUIC + Bluetooth
    Action: Remove from peer registry
    Action: Mark as banned in reputation
    Action: Reject all incoming messages
    Action: Record forensic evidence

Recovery (Future):
  - +1 reputation per successful message (capped at 100)
  - Slow exponential decay after 24 hours inactivity
  - Requires governance vote to unban peer at 0 reputation
```

---

## Critical Code Locations Reference

### Validation Layer (Consensus)
- `lib-consensus/src/engines/consensus_engine/validation.rs:90` - `verify_vote_signature()`
- `lib-consensus/src/engines/consensus_engine/validation.rs:149` - `validate_remote_vote()`
- `lib-consensus/src/engines/consensus_engine/mod.rs` - ConsensusEngine struct

### Network Layer (Mesh)
- `zhtp/src/server/mesh/core.rs:94` - MeshRouter struct
- `zhtp/src/server/mesh/monitoring.rs` - PeerReputation, peer_reputations HashMap
- `zhtp/src/server/mesh/mod.rs` - handle_mesh_message() entry point

### Byzantine Detection
- `lib-consensus/src/byzantine/fault_detector.rs` - ByzantineFaultDetector
- `lib-consensus/src/byzantine/fault_detector.rs:200+` - Fault processing

### Node Runtime
- `zhtp/src/runtime/components/consensus.rs` - ConsensusComponent initialization
- `zhtp/src/runtime/mod.rs` - RuntimeOrchestrator startup sequence

---

## Dependency Tree (Critical Path)

```
Phase 0: Message Structure & peer_id Threading (CRITICAL)
    ├─ ValidatorMessage enum + PeerId capture
    └─ (Required by ALL subsequent phases)

Phase 1B: Foundation Traits (FOUNDATION)
    ├─ PeerId struct definition
    ├─ PeerValidationReporter trait
    ├─ ValidationFailureType enum
    └─ PeerPenaltySeverity enum

Phase 2: Wire Into Consensus Validation
    ├─ Add peer_validator to ConsensusEngine
    └─ Report failures with peer attribution

Phase 3: Network Layer Peer Validator (ISOLATION ENFORCEMENT)
    ├─ PeerReputation updates
    ├─ disconnect_peer() implementation
    └─ MeshPeerValidator trait implementation

Phase 4: Peer↔Validator Mapping Registry (CRITICAL PATH)
    ├─ PeerValidatorRegistry trait
    ├─ Peer registration system
    └─ Rotation rate limiting

Phase 5: Wire Into Byzantine Fault Detector (BFT INTEGRATION)
    ├─ process_faults_with_isolation()
    └─ Fault → peer penalty routing

Phase 6: Wire Into Node Runtime (INTEGRATION)
    ├─ ConsensusComponent initialization
    └─ End-to-end wiring

Phase 7: Testing & Validation (QA)
    ├─ Integration tests
    └─ Adversarial scenarios
```

**Critical Path Dependency:**
```
Phase 0 → Phase 1B ┐
                   ├→ Phase 2 ┐
Phase 0 → Phase 4 ┘           ├→ Phase 3 ┐
                               ↓         ├→ Phase 5 ┐
                                         ↓         ├→ Phase 6 → Phase 7
                                                   ↓
                                          (Phase 3 from feedback)
```

**Note:** Phase 4 (peer mapping) can start after Phase 0 and Phase 1B complete, in parallel with Phase 2 and Phase 3, but MUST complete before Phase 6.

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Peer validator panics | Consensus crashes | Add try-catch around peer_validator calls |
| Reputation drift | Unfair bans | Add audit logging for all reputation changes |
| Performance degradation | Network slowdown | Profile with 10k peers before merge |
| Innocent peer banned | Network partition | Require 3+ failures before rate limit, 5+ before ban |
| Ban not reversible | Permanent partition | Implement governance vote for appeal |

---

## Success Criteria

✅ **Phase 0:** ValidatorMessage includes peer_id, no serialization breaks
✅ **Phase 1B:** Traits compile, unit tests pass, mocks work
✅ **Phase 2:** Validation failures reported with peer attribution, consensus tests pass
✅ **Phase 3:** Reputation updates correctly, disconnect_peer() works reliably
✅ **Phase 4:** Peer↔validator registration working, queries return correct results
✅ **Phase 5:** Byzantine faults trigger peer penalties, no consensus impact
✅ **Phase 6:** Full system wired, node starts successfully, end-to-end works
✅ **Phase 7:** Integration tests pass, adversarial scenarios handled, no regressions

**Performance Baseline:**
- Peer isolation within 2-3 seconds of ban threshold
- No impact on honest peer latency (< 5% worst case)
- Peer connection overhead < 1% CPU
- Registry lookups < 1ms (cached)

---

## Related Issues & PRs

- **Issue #1040:** Token persistence (related: state management)
- **Gap 6:** Peer reputation system (THIS ISSUE)
- **Byzantine Fault Detection:** Existing detection without isolation

---

## Notes

- This is not a protocol change - purely network layer enforcement
- Validator set changes still controlled by governance (on-chain)
- Peer isolation is in-network enforcement, not consensus-level
- Honest validators may be temporarily isolated (false positives) - acceptable cost
- Recovery requires either: (1) prove peer identity is different, or (2) governance vote

---

## Timeline Estimate (DO NOT COMMIT TO DATES)

Revised estimates based on dry-run findings:

- **Phase 0** (Message Structure): Medium, ~5-8 hours ⚠️ **CRITICAL PATH**
- **Phase 1B** (Foundation): Fast, ~1-2 hours
- **Phase 2** (Wire Consensus): Medium, ~2-3 hours
- **Phase 3** (Network Isolation): Medium, ~2-3 hours
- **Phase 4** (Peer Mapping): High, ~5-7 hours ⚠️ **CRITICAL PATH**
- **Phase 5** (BFT Integration): Medium, ~1-2 hours
- **Phase 6** (Runtime Wiring): Fast, ~1-2 hours
- **Phase 7** (Testing): Variable, ~3-4 hours

**Total Estimate:** 25-35 hours (vs original 10-15 hours)

**Rationale for increase:**
- +8 hours: Phase 0 (message schema changes not originally planned)
- +7 hours: Phase 4 (peer mapping registry not originally planned)
- +3 hours: Serialization testing, wire format compatibility
- +2 hours: Integration complexity from new critical path

**Timeline is highly dependent on unforeseen complications during integration, especially around message schema changes.

---

## Next Steps

1. ✅ **Dry-run validation complete** - DRYRUN_VALIDATION_REPORT.md documents findings
2. ✅ **Architectural decisions locked** - 4 decisions finalized above
3. ✅ **Plan updated with findings** - This document now includes all gaps
4. 📋 **Ready for implementation** - Start with Phase 0 (critical path)

## Implementation Order (Recommended)

**Start immediately:**
1. Phase 0 - Message structure (MUST complete first)
2. Phase 1B - Foundation traits (can start once Phase 0 design approved)

**Start in parallel after Phase 0 + 1B foundation:**
- Phase 2 - Consensus validation wiring
- Phase 3 - Network isolation implementation
- Phase 4 - Peer mapping registry (highest risk, start early)

**Sequential after 2, 3, 4 complete:**
- Phase 5 - BFT integration
- Phase 6 - Runtime wiring
- Phase 7 - Testing

---

## Plan Status

✅ **FINALIZED & LOCKED**

This plan has incorporated:
- ✅ Dry-run validation against real codebase
- ✅ 7 critical gaps identified and addressed
- ✅ 4 architectural decisions made and locked
- ✅ Revised effort estimate (25-35 hours)
- ✅ Critical path identified (Phase 0, Phase 4)
- ✅ High-risk areas highlighted (message schema, peer mapping)

**Ready for code review and implementation.**

---

**Branch:** `feat/bft-peer-isolation`
**Tracking:** Use this file as single source of truth for implementation status
**Related:** See `DRYRUN_VALIDATION_REPORT.md` for detailed findings and analysis
