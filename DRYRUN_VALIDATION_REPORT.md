# Dry-Run Validation Report: BFT Peer Isolation Implementation

**Date:** 2026-02-01
**Branch:** `feat/bft-peer-isolation`
**Status:** CRITICAL GAPS IDENTIFIED

---

## Executive Summary

The implementation plan **assumes 7 architectural components that don't exist or work differently than planned.** This report identifies what actually exists, where gaps are, and what must be built before implementation can proceed.

**Result:** Plan is **30-40% accurate**, with significant architectural mismatches that will block the original approach.

---

## CRITICAL GAPS FOUND

### 🔴 Gap 1: ValidatorMessage Has NO peer_id Field

**Assumption:** ValidatorMessage carries sender peer information

**Reality:**
```rust
pub enum ValidatorMessage {
    Propose { proposal: ConsensusProposal },
    Vote { vote: ConsensusVote },
    Heartbeat { message: HeartbeatMessage },
}
```

**Problem:** When a vote arrives at consensus layer, there's **no information about which network peer sent it**. Only the validator identity (`vote.voter`) is present.

**Impact:** Can't attribute "which peer sent this invalid vote" without modifying the message structure at the network parsing layer (before consensus ever sees it).

**Required Change:** Add `peer_id: String` field to each variant:
```rust
pub enum ValidatorMessage {
    Vote { vote: ConsensusVote, peer_id: String },
    // ...
}
```

**Effort:** Medium - affects network → consensus boundary

---

### 🔴 Gap 2: No disconnect_peer() Method Exists

**Assumption:** MeshRouter has `disconnect_peer(peer_id)` method

**Reality:** Searched entire codebase - **method does not exist** in:
- lib-consensus/src/
- zhtp/src/server/
- lib-network/src/

**What exists:**
- `peer_reputations: HashMap<String, PeerReputation>` (can read/write)
- `peer_rate_limits: HashMap<String, PeerRateLimit>` (can read/write)

**What's missing:**
- Method to actually sever TCP/QUIC connections
- Method to remove from active connection pool
- Method to block reconnection attempts
- Method to notify other network components

**Required Change:** Create `disconnect_peer()` that:
1. Closes QUIC connection (via `QuicMeshProtocol.disconnect()`)
2. Closes Bluetooth connection (if available)
3. Removes from peer registry
4. Marks as banned in peer_reputations

**Effort:** Medium - needs to interact with multiple transport protocols

---

### 🔴 Gap 3: No Consensus→Network Feedback Channel

**Assumption:** ConsensusEngine can call peer_validator to report failures

**Reality:** ConsensusEngine has **zero connection** to MeshRouter or peer reputation system

**Current one-way flow:**
```
Network → Consensus (via mpsc channel)
Consensus → Blockchain (via storage)
Consensus → DAO (via DaoEngine)

But:
Consensus → Network: ❌ DOES NOT EXIST
```

**What needs to exist:**
```rust
pub trait PeerValidator: Send + Sync {
    async fn report_validation_failure(&self, peer_id: &str, failure_type: ...) -> Result<()>;
    async fn disconnect_peer(&self, peer_id: &str) -> Result<()>;
}
```

**Problem:** If consensus detects a peer is Byzantine, it can't tell the network layer to isolate it. It can only slash on-chain.

**Required Change:** Add trait injection to ConsensusEngine, wire it from runtime component initialization

**Effort:** Low-Medium - pattern already established (broadcaster, fee_router, etc.)

---

### 🔴 Gap 4: No peer_id Captured From Network

**Assumption:** Network layer already tracks which peer sent each message

**Reality:** Line 403 of network.rs:
```rust
self.byzantine_detector.record_message_signature(
    vote.id.clone(),
    vote.voter.clone(),
    vote.signature.clone(),
    payload_hash,
    message_type,
    current_time,
    None,  // ← peer_id is ALWAYS None
);
```

The **only place peer_id could be captured is hardcoded to None**.

**Problem:** Even if we wire feedback, we can't attribute the vote to a specific network peer because we never recorded it.

**Required Change:**
1. Capture peer_id at network layer (ZHTP MeshRouter)
2. Pass it through to ValidatorMessage (Gap 1)
3. Thread it through consensus handlers
4. Pass to `record_message_signature()` at line 403

**Effort:** Medium - requires tracing peer identity from packet reception through deserialization

---

### 🔴 Gap 5: No peer↔validator Mapping

**Assumption:** Can map from network peer_id to validator IdentityId

**Reality:** **NO MAPPING FUNCTION EXISTS**

**The problem:**
- Network layer tracks peers by: `String` (IP address or node_id)
- Consensus layer tracks validators by: `Hash` (IdentityId - cryptographic)
- There is no registry saying "peer 192.168.1.10:9000 is validator 0xABC..."

**Scenario:**
- Validator Alice (IdentityId=0xABC...) runs on peer A.1.2.3:5000
- Her vote arrives from peer A.1.2.3:5000 - we accept it
- But if a vote from Alice arrives from peer X.Y.Z.W:PORT (maybe relayed?), we can't detect the mismatch
- If we ban peer A.1.2.3:5000, Alice's votes from other peers still get through

**Required Change:** Create identity registry:
```rust
pub struct PeerValidatorRegistry {
    peer_to_validators: HashMap<String, Vec<IdentityId>>,
    validator_to_peers: HashMap<IdentityId, Vec<String>>,
}
```

Validators must register "I am on peer X" at startup, with cryptographic proof.

**Effort:** High - architectural change, requires consensus layer to know about network topology

---

### 🔴 Gap 6: Hardcoded Rate Limits & Thresholds

**Assumption:** Can dynamically adjust rate limits based on peer reputation

**Reality:** All values hardcoded as magic numbers:

**ZHTP Rate Limit (core.rs:15-57):**
```rust
if self.request_count >= 100 {  // ← 100 hardcoded
    return false;
}
// Window: 30 seconds hardcoded
```

**Consensus Timeouts (types/mod.rs:274-276):**
```rust
propose_timeout: 3000,      // 3 seconds
prevote_timeout: 1000,      // 1 second
precommit_timeout: 1000,    // 1 second
```

**Reputation Thresholds (monitoring.rs:26, 43, 49, 72):**
```rust
score: 50                        // Initial score
.min(100)                       // Max hardcoded
.max(-100)                      // Min hardcoded
score <= -50 || violations >= 10  // Ban threshold hardcoded
```

**Byzantine Detector (fault_detector.rs:102-105):**
```rust
replay_cache_max_size: 10_000
replay_detection_window_secs: 300
forensic_max_records: 50_000
forensic_ttl_secs: 86_400
partition_check_interval_secs: 10
```

**Problem:** Can't say "for peer X, reduce rate limit from 100 to 10" - the limit is hardcoded in `check_and_increment()` with no way to override per-peer.

**Required Change:**
1. Make all thresholds configurable in ConsensusConfig
2. Change rate limit checking to look up per-peer overrides
3. Create reputation→rate_limit mapping table

**Effort:** Medium - config propagation and lookup changes

---

### 🔴 Gap 7: Silent Vote Rejection with No Feedback

**Assumption:** Validation failures are reported via trait callback

**Reality:** Invalid votes are silently dropped:

```rust
// state_machine.rs:847
if !self.validate_remote_vote(&vote).await? {
    return Ok(());  // ← SILENT DROP
}
```

**What happens:**
- ✅ Vote dropped (not stored)
- ✅ Logged with `tracing::warn!(...)`
- ❌ No Byzantine evidence recorded
- ❌ No peer reported
- ❌ No feedback to network layer
- ❌ No reputation update

**Problem:** There's no mechanism to route validation failures to a punishment layer. Even if we add `peer_validator`, validation failures aren't connected to it.

**Required Change:** Add reporting before the return:
```rust
if !self.validate_remote_vote(&vote).await? {
    if let Some(peer_id) = &vote.peer_id {  // From Gap 1
        self.peer_validator.report_validation_failure(
            peer_id,
            ValidationFailureType::InvalidSignature,
            // ...
        ).await;
    }
    return Ok(());
}
```

**Effort:** Low - once gaps 1 and 3 are fixed

---

## Revised Implementation Plan: What Must Change

### Phase 0 (NEW): Message Structure & Peer ID Threading

**Before any other phase can start**, must:

1. **Extend ValidatorMessage enum** to include peer_id
   - File: `lib-consensus/src/types/mod.rs:405`
   - All 3 variants need `peer_id: String` field
   - Effort: 1-2 hours

2. **Capture peer_id at network reception**
   - File: `zhtp/src/server/mesh/mod.rs` (entry point)
   - Must know: which peer_id is sending which message
   - Effort: 2-3 hours

3. **Thread peer_id through consensus handlers**
   - File: `lib-consensus/src/engines/consensus_engine/network.rs`
   - All message handlers must pass peer_id through to validators
   - Effort: 1-2 hours

4. **Update record_message_signature() call**
   - File: `lib-consensus/src/engines/consensus_engine/network.rs:403`
   - Actually pass the peer_id instead of None
   - Effort: 30 minutes

**Total Phase 0 Effort:** 5-8 hours (blocking all other phases)

---

### Phase 1 (REVISED): Foundation + Message Schema

**Original Phase 1** (peer_validator trait) is now Phase 1B

**Phase 1A:** Message structure changes (from Phase 0 above)

**Phase 1B:** Create peer_validator trait
   - File: `lib-consensus/src/peer_validator.rs`
   - Same as original plan
   - Effort: 1-2 hours

---

### Phase 2: Create disconnect_peer() Implementation

**New phase** - disconnecting peers requires transport-layer work:

1. **Create disconnect_peer() in MeshRouter**
   - File: `zhtp/src/server/mesh/core.rs`
   - Close QUIC connections via QuicMeshProtocol
   - Close Bluetooth connections if active
   - Remove from peer registry
   - Mark as banned
   - Effort: 2-3 hours

2. **Create PeerValidator trait implementation in MeshRouter**
   - File: `zhtp/src/server/mesh/peer_validator_impl.rs`
   - Wire disconnect_peer() calls
   - Update reputation on failures
   - Effort: 2-3 hours

**Effort:** 4-6 hours

---

### Phase 3: Wire Into Consensus Validation

Similar to original plan but now with peer_id available:
- Effort: 2-3 hours (unchanged)

---

### Phase 4: Create peer↔validator Mapping (NEW)

This is a **NEW critical phase** for architectural correctness:

1. **Create PeerValidatorRegistry**
   - Track: which peers can represent which validators
   - Validate: peers must prove their identity
   - Effort: 3-4 hours

2. **Enforce at message receipt**
   - Check: incoming message peer_id matches validator's registered peer
   - Detect: votes from unregistered peer-validator pairs
   - Penalty: reputation hit for mismatch attempts
   - Effort: 2-3 hours

**Effort:** 5-7 hours

---

### Phase 5: Make Thresholds Configurable

Move hardcoded values to ConsensusConfig:
- Effort: 1-2 hours

---

### Revised Total Effort

**Original estimate:** ~10-15 hours
**Revised estimate:** ~25-35 hours

**Key difference:** Must build peer identification infrastructure (Phase 0, Phase 4) that wasn't originally considered.

---

## What the Original Plan Got Right

✅ **Reputation scoring formula** - Still valid
✅ **BFT fault detection integration** - Still valid approach
✅ **Consensus validation points** - Still correct locations
✅ **Component injection pattern** - Already used, we follow it
✅ **Test strategy** - Good adversarial scenarios

---

## What the Original Plan Missed

❌ **Message structure changes** - ValidatorMessage needs peer_id field
❌ **peer↔validator mapping** - No infrastructure exists
❌ **Transport layer disconnection** - Not in consensus layer
❌ **Hardcoded threshold extraction** - Major refactor needed
❌ **Peer identity registration** - Completely missing from architecture

---

## Architectural Decisions Before Implementation

### Decision 1: Where does peer_id come from?

**Options:**
1. **Network IP + Port** (current plan) - Simple but can be spoofed if network is compromised
2. **Node ID** (cryptographic hash) - Better but requires node registration
3. **Public key hash** - Combines network + crypto identity

**Recommendation:** Use **Node ID** - require validators to prove they own a specific node identity at startup

### Decision 2: Who owns the peer↔validator mapping?

**Options:**
1. **Consensus layer** - Knows about validators, manages mapping
2. **Network layer** - Knows about peers, manages mapping
3. **Shared registry** - Both layers read from it

**Recommendation:** **Shared registry in lib-identity** - both layers can query it, validators register their network identity at boot

### Decision 3: What if validator is on multiple peers?

**Options:**
1. **One-to-one only** - Validator must have single IP/node
2. **One-to-many with allowlist** - Validator can list approved peers
3. **Geo-redundancy** - Multiple peers allowed if in same region

**Recommendation:** **One-to-many with explicit registration** - validators can run replicas but must register them on-chain

### Decision 4: How to handle peer_id in vote signature verification?

**Issue:** Currently `validate_remote_vote()` only verifies the vote signature, not where it came from

**Options:**
1. **Verify peer_id matches registered validator** - Add to validation checks
2. **Just track it for reputation** - Don't fail validation, just penalize reputation
3. **Hybrid** - Warn and penalize, don't reject

**Recommendation:** **Option 2** - honest validator might relay vote from different peer, don't reject but track mismatch

---

## Acceptance Criteria for Dry-Run

✅ **All assumptions validated** - What exists, what doesn't, what's hardcoded
✅ **Gaps documented** - 7 critical gaps identified
✅ **Revised estimate** - 25-35 hours realistic
✅ **Phase 0 identified** - Must be done first
✅ **Architecture decisions clear** - Ready to make decisions
✅ **Implementation blockers known** - Can now plan around them

---

## Recommended Next Steps

1. **Make Decisions** - Above 4 architectural decisions need approval
2. **Update IMPL_PLAN** - Incorporate Phase 0 and Phase 4, adjust estimates
3. **Code Review** - Get feedback on message structure changes (biggest risk)
4. **Start Phase 0** - Adding peer_id to ValidatorMessage (most critical path item)

---

## Risk Assessment (Revised)

| Risk | Severity | Mitigation |
|------|----------|-----------|
| **Message schema change breaks serialization** | High | Need careful versioning, wire format tests |
| **peer↔validator mapping not enforced consistently** | High | Add explicit checks everywhere peer_id used |
| **Honest validators run on multiple peers (geo-redundancy)** | Medium | Support one-to-many with explicit registration |
| **Peer_id is not truly unique** (NAT/proxy issues) | Medium | Prefer node_id over IP, cryptographic proof |
| **Hardcoded thresholds scattered everywhere** | Medium | Audit all files, centralize in config |
| **disconnect_peer() breaks legitimate relays** | Low | Document intended use, allow governance override |

---

## Files That Will Need Changes

### Must modify:
- `lib-consensus/src/types/mod.rs` - ValidatorMessage structure (HIGH RISK)
- `lib-consensus/src/engines/consensus_engine/network.rs` - Thread peer_id through
- `lib-consensus/src/engines/consensus_engine/validation.rs` - Report failures
- `zhtp/src/server/mesh/core.rs` - Capture peer_id at receipt
- `zhtp/src/server/mesh/mod.rs` - Entry point handling (HIGH RISK)

### Will create:
- `lib-consensus/src/peer_validator.rs` - Trait definition
- `lib-consensus/src/peer_validator_registry.rs` - peer↔validator mapping
- `zhtp/src/server/mesh/peer_validator_impl.rs` - Implementation
- `zhtp/src/server/mesh/peer_disconnector.rs` - Transport-level isolation

### Should refactor:
- `lib-consensus/src/types/mod.rs` - Extract hardcoded thresholds to config
- `zhtp/src/server/monitoring.rs` - Make reputation configurable

---

## Conclusion

The implementation plan is **architecturally sound** but **underestimated critical infrastructure gaps**. Must build peer identification infrastructure before Byzantine isolation can work effectively. With these gaps addressed, the original approach is still valid.

**Recommendation:** Proceed with implementation, but allocate additional time for Phase 0 (message structure) and Phase 4 (peer mapping).
