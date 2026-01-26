# UBI as a Treasury Kernel Client
## Architecture and Integration Design
## Issue #844 Prep Phase - Task 6

**Status**: Design Documentation (No Implementation Yet)
**Last Updated**: January 26, 2026
**Related**: ADR-0017 (Execution Boundary), UBI Economics Specification, UBI Role-Gating Design

---

## Overview

This document specifies the architectural relationship between:
- **UBI Distribution Contract**: Records citizen intent to claim UBI
- **Treasury Kernel**: Validates, gates, and executes UBI claims
- **Citizen Role Registry**: Verifies citizenship eligibility

**Core Principle** (ADR-0017):
> UBI defines economic intent. Treasury Kernel enforces economic law.
> UBI is a client of the Kernel, not the other way around.

---

## System Architecture

### Component Topology

```
                    [Citizen]
                       |
                    Claims intent
                       |
                       v
           +------- UBI Contract ------+
           |                           |
           v                           v
    [record_claim_intent]      [query_status]
           |                           |
      emit: UbiClaimRecorded     Read-only queries
           |
           +------> Event Stream ----+
                                     |
                                     v
                    [Treasury Kernel]
                          |
            +----------+--+--+----------+
            |          |     |          |
            v          v     v          v
        [Validate]  [Gate] [Mint]  [Record]
            |          |     |          |
      Role check   Dedup   Mint   Emit events
      Revoked?     check   1000
      Eligible?    Pool
           |          |     |          |
           +----------+-----+----------+
                       |
                       v
                   [Events]
            - UbiDistributed (success)
            - UbiClaimRejected (failure)
            - UbiPoolStatus (summary)
```

### Information Flow

```
1. INTENT RECORDING (UBI Contract)
   Citizen calls: record_claim_intent(citizen_id, amount, epoch)
   UBI emits: UbiClaimRecorded event
   State change: None (immutable intent)

2. POLLING (Treasury Kernel, epoch boundary)
   Kernel queries: Find all UbiClaimRecorded events for current_epoch
   State change: None (read-only from UBI perspective)

3. VALIDATION (Treasury Kernel)
   Kernel checks:
     - CitizenRegistry lookup (is registered?)
     - Revocation check (citizen.revoked == false?)
     - Eligibility check (current_epoch >= citizenship_epoch?)
     - Dedup check (already_claimed[citizen][epoch] == false?)
     - Pool check (total_distributed[epoch] < 1M?)
   State change: None (read-only validation)

4. EXECUTION (Treasury Kernel)
   Kernel calls: mint(citizen_id, 1000)
   State changes:
     - Token balance increased
     - already_claimed[citizen][epoch] = true
     - total_distributed[epoch] += 1000
   Event: Kernel emits UbiDistributed

5. AUDIT (Governance monitoring)
   Governance queries:
     - UbiDistributed events (who got paid?)
     - UbiClaimRejected events (who failed and why?)
     - UbiPoolStatus events (pool utilization?)
   State change: None (read-only audit)
```

---

## UBI Contract Interface (Passive Client)

### Public Methods

```rust
pub trait UbiClient {
    /// Record citizen's intent to claim UBI
    ///
    /// # Parameters
    /// - citizen_id: Verified citizen identifier [u8; 32]
    /// - amount: Requested amount (always 1000 in current spec)
    /// - epoch: Epoch for which claim is made
    ///
    /// # Behavior
    /// - Minimal validation (optional, amount check only)
    /// - Emits UbiClaimRecorded event
    /// - No state modification (intent only)
    /// - Returns immediately (non-blocking)
    ///
    /// # Security
    /// - Caller must be authenticated (implicit via citizen_id)
    /// - No authorization check (all citizens can record intent)
    fn record_claim_intent(
        &mut self,
        citizen_id: [u8; 32],
        amount: u64,
        epoch: EpochIndex,
    ) -> Result<(), Error>;

    /// Query whether citizen has already claimed in this epoch
    ///
    /// # Parameters
    /// - citizen_id: Verified citizen identifier
    /// - epoch: Epoch to query
    ///
    /// # Returns
    /// - true: citizen has claimed in this epoch (read from Kernel state)
    /// - false: citizen has not claimed yet
    ///
    /// # Note
    /// This is a convenience query. Kernel maintains canonical dedup state.
    /// UBI contract doesn't enforce dedup (Kernel does).
    fn has_claimed_this_epoch(
        &self,
        citizen_id: [u8; 32],
        epoch: EpochIndex,
    ) -> bool;

    /// Query current pool utilization for epoch
    ///
    /// # Parameters
    /// - epoch: Epoch to query
    ///
    /// # Returns
    /// - total_distributed: How much SOV distributed so far
    /// - remaining_capacity: 1,000,000 - total_distributed
    ///
    /// # Note
    /// This is a convenience query. Kernel maintains canonical pool state.
    fn get_pool_status(&self, epoch: EpochIndex) -> PoolStatus;
}
```

### Events Emitted by UBI

```rust
/// Event: Citizen records intent to claim UBI
///
/// Emitted by: UBI Contract
/// Triggers: Kernel polls and validates
/// Used by: Governance audit trail
#[event]
pub struct UbiClaimRecorded {
    /// Citizen identity (verified by caller)
    pub citizen_id: [u8; 32],

    /// Amount being claimed (1000 in current spec)
    pub amount: u64,

    /// Epoch for which claim is made
    pub epoch: EpochIndex,

    /// Block height when claim was recorded
    pub timestamp: u64,
}
```

### Guarantees Provided by UBI Contract

1. **Intent Immutability**: Once claimed, intent record is never modified
2. **Event Ordering**: Claims are ordered by block height
3. **No Double Emission**: Same claim cannot be emitted twice
4. **ABI Compatibility**: Events use [u8; 32] and u64 for cross-language support

---

## Treasury Kernel Interface (Active Executor)

### Public Methods

```rust
pub trait TreasuryKernel {
    /// Process UBI distributions for current epoch
    ///
    /// # Called By
    /// - Consensus engine at epoch boundaries (height % 60_480 == 0)
    /// - Manual governance trigger (optional, for recovery)
    ///
    /// # Execution Steps
    /// 1. Read current_epoch from block height
    /// 2. Query UbiClaimRecorded events for current_epoch
    /// 3. For each claim:
    ///    a. Validate eligibility (role-gating)
    ///    b. Check dedup (already_claimed?)
    ///    c. Check pool capacity (total_distributed < 1M?)
    ///    d. If all pass: mint(citizen_id, 1000)
    ///    e. Record result (event)
    /// 4. Emit UbiPoolStatus summary
    ///
    /// # Atomicity
    /// All state changes for this epoch are atomic:
    /// - All mints succeed or all fail
    /// - Dedup state committed atomically with mint
    /// - Pool state updated atomically
    ///
    /// # Idempotency
    /// Safe to call multiple times (dedup prevents double-minting)
    fn process_ubi_distributions(&mut self, current_epoch: u64) -> Result<()>;

    /// Mint SOV tokens to citizen
    ///
    /// # Called By
    /// - Treasury Kernel only (no other caller permitted)
    /// - During process_ubi_distributions
    ///
    /// # Parameters
    /// - citizen_id: [u8; 32] (must be registered citizen)
    /// - amount: u64 (must be 1000 for UBI)
    ///
    /// # Validation (Kernel enforces)
    /// - citizen_id must be in CitizenRegistry
    /// - citizen.revoked must be false
    /// - current_epoch >= citizen.citizenship_epoch
    /// - already_claimed[citizen_id][epoch] == false
    /// - total_distributed[epoch] + amount <= 1,000,000
    ///
    /// # State Changes
    /// - Token balance: citizen.balance += amount
    /// - Dedup state: already_claimed[citizen_id][epoch] = true
    /// - Pool state: total_distributed[epoch] += amount
    ///
    /// # Atomicity
    /// All state changes are atomic (single operation or none)
    fn mint(&mut self, citizen_id: [u8; 32], amount: u64) -> Result<()>;

    /// Record epoch distribution summary
    ///
    /// # Called By
    /// - Treasury Kernel at end of process_ubi_distributions
    ///
    /// # Emitted Event
    /// UbiPoolStatus {
    ///     epoch,
    ///     citizens_eligible,
    ///     total_distributed,
    ///     remaining_capacity,
    /// }
    ///
    /// # Used By
    /// - Governance monitoring
    /// - Economic analysis
    /// - Audit trail
    fn record_pool_status(
        &mut self,
        epoch: u64,
        citizens_eligible: u64,
        total_distributed: u64,
        remaining_capacity: u64,
    ) -> Result<()>;
}
```

### Events Emitted by Kernel

```rust
/// Event: Treasury Kernel executed UBI distribution
///
/// Emitted by: Treasury Kernel (only on successful mint)
/// Triggers: None (immutable record)
/// Used by: Governance audit trail, verification
#[event]
pub struct UbiDistributed {
    /// Citizen who received payment
    pub citizen_id: [u8; 32],

    /// Amount actually paid (should be 1000)
    pub amount: u64,

    /// Epoch for which distribution was made
    pub epoch: EpochIndex,

    /// Kernel transaction ID (uniquely identifies this mint)
    /// Format: blake3(kernel_state || citizen_id || epoch || amount)
    pub kernel_txid: [u8; 32],
}

/// Event: UBI claim was rejected
///
/// Emitted by: Treasury Kernel (only on validation failure)
/// Triggers: None (immutable record)
/// Used by: Governance audit trail (citizens don't see)
#[event]
pub struct UbiClaimRejected {
    /// Citizen who attempted the claim
    pub citizen_id: [u8; 32],

    /// Epoch for which claim was attempted
    pub epoch: EpochIndex,

    /// Why claim was rejected (1-5, see below)
    pub reason_code: u8,

    /// Block height when rejection was recorded
    pub timestamp: u64,
}

/// Reason Codes (Kernel only - not exposed to citizens)
/// 1 = NotACitizen (not in CitizenRegistry)
/// 2 = AlreadyRevoked (citizen.revoked == true)
/// 3 = AlreadyClaimedEpoch (already_claimed[citizen][epoch] == true)
/// 4 = PoolExhausted (total_distributed >= 1,000,000)
/// 5 = EligibilityNotMet (current_epoch < citizenship_epoch)

/// Event: UBI pool status at epoch boundary
///
/// Emitted by: Treasury Kernel at end of process_ubi_distributions
/// Triggers: None (immutable record)
/// Used by: Governance monitoring, economic analysis
#[event]
pub struct UbiPoolStatus {
    /// Epoch for which this status applies
    pub epoch: EpochIndex,

    /// How many citizens were eligible to claim
    pub citizens_eligible: u64,

    /// Total amount actually distributed
    pub total_distributed: u64,

    /// Remaining pool capacity (1,000,000 - total_distributed)
    pub remaining_capacity: u64,
}
```

### Guarantees Provided by Kernel

1. **Exclusive Minting Authority**: Only Kernel can call mint
2. **Deterministic Validation**: All nodes validate the same way
3. **Atomicity**: All state changes per epoch are atomic
4. **Idempotency**: Safe to call multiple times (dedup prevents double-minting)
5. **Crash Recovery**: Can resume from checkpoint without duplication
6. **Pool Enforcement**: Hard limit 1,000,000 SOV per epoch is never exceeded
7. **Audit Trail**: All distributions and rejections are recorded

---

## Integration Points

### 1. Event Polling

**Kernel → UBI Contract**

```rust
// Kernel periodically polls UBI contract for claims:
let current_epoch = block_height / BLOCKS_PER_EPOCH;
let events = ubi_contract.query_events(
    event_type: UbiClaimRecorded,
    epoch: current_epoch,
    from_block: last_polled_block,
);

// Events are immutable history
for event in events {
    // Kernel validates and processes
}
```

### 2. State Sharing (Read-Only from UBI Perspective)

**Kernel ↔ UBI Contract**

```rust
// UBI contract has read-only access to:
// - already_claimed[citizen][epoch] (for query_has_claimed)
// - total_distributed[epoch] (for query_pool_status)

// Kernel maintains these as canonical state
// UBI contract queries them for convenience

// UBI contract has ZERO write access to Kernel state
```

### 3. CitizenRegistry Integration

**Kernel uses CitizenRegistry**

```rust
// Kernel validates against:
// - CitizenRegistry.is_registered(citizen_id)
// - citizen_role.revoked
// - citizen_role.citizenship_epoch

// CitizenRegistry is maintained by governance
// Kernel reads (does not modify)
```

### 4. Role-Gating Delegation

**UBI passes validation to Kernel**

UBI Contract does NOT validate:
- ❌ Is citizen registered?
- ❌ Is citizen revoked?
- ❌ Is citizen eligible?
- ❌ Has citizen already claimed?
- ❌ Is pool exhausted?

Kernel DOES validate:
- ✅ CitizenRegistry lookup
- ✅ Revocation check
- ✅ Eligibility check
- ✅ Dedup check
- ✅ Pool check

**Design**: Clear separation of concerns (intent vs. execution)

---

## Call Sequence Diagram

```
EPOCH BOUNDARY (height % 60_480 == 0)
|
+-- Consensus Engine detects epoch boundary
|
+-- Triggers: Kernel.process_ubi_distributions(current_epoch)
    |
    +-- Kernel: Calculate current_epoch = height / 60_480
    |
    +-- Kernel: Query UbiClaimRecorded events
    |   |
    |   +-- UBI Contract: Return all events for current_epoch (immutable)
    |
    +-- For each event:
    |   |
    |   +-- Kernel: Lookup citizen in CitizenRegistry
    |   |   |
    |   |   +-- CitizenRegistry: Return citizen_role or None
    |   |
    |   +-- Kernel: Validate eligibility (5 checks)
    |   |
    |   +-- If valid:
    |   |   |
    |   |   +-- Kernel: Call mint(citizen_id, 1000)
    |   |   |
    |   |   +-- Token Contract: Increase balance
    |   |   |
    |   |   +-- Kernel: Update already_claimed[citizen][epoch] = true
    |   |   |
    |   |   +-- Kernel: Update total_distributed[epoch] += 1000
    |   |   |
    |   |   +-- Kernel: Emit UbiDistributed event
    |   |
    |   +-- If invalid:
    |       |
    |       +-- Kernel: Emit UbiClaimRejected event
    |
    +-- Kernel: Compute pool status
    |
    +-- Kernel: Emit UbiPoolStatus event
    |
    +-- Kernel: Return success
    |
+-- Epoch N+1 begins
```

---

## Passive vs. Active Design

### Why UBI is Passive

UBI Contract is **passive** because:

1. **No Minting Power**: Cannot mint tokens (Kernel does)
2. **No Enforcement**: Cannot enforce dedup or pool cap (Kernel does)
3. **No Execution Loop**: No active processing (Kernel runs loop)
4. **No Authority**: Cannot override governance decisions (Kernel enforces)

**Method Signatures**:
```rust
impl UbiClient for UbiDistributor {
    // Only two operations: record (write event) and query (read state)
    fn record_claim_intent(...) -> Result<()>;
    fn has_claimed_this_epoch(...) -> bool;
    fn get_pool_status(...) -> PoolStatus;
}
```

### Why Kernel is Active

Treasury Kernel is **active** because:

1. **Owns Minting Authority**: Only Kernel can mint
2. **Validates Everything**: All role-gating happens here
3. **Runs Processing Loop**: process_ubi_distributions at epoch boundary
4. **Enforces Constraints**: Hard limits, dedup, revocation

**Method Signatures**:
```rust
impl TreasuryKernel {
    // Active execution: validation, minting, recording
    fn process_ubi_distributions(&mut self, epoch: u64) -> Result<()>;
    fn mint(&mut self, citizen_id: [u8; 32], amount: u64) -> Result<()>;
    fn record_pool_status(...) -> Result<()>;
}
```

---

## Failure Modes and Recovery

### Scenario 1: UBI Contract Emits Malformed Event

**Problem**: Event has invalid citizen_id or amount

**Recovery**:
1. Kernel validates event structure on poll (catches malformed)
2. If malformed: log error, skip event (no mint)
3. Emit: UbiClaimRejected with reason "malformed event"

### Scenario 2: CitizenRegistry Unavailable

**Problem**: Kernel cannot check citizenship

**Recovery**:
1. Kernel pauses UBI distribution (fails process_ubi_distributions)
2. Governance investigates registry
3. After fix: retry distribution (idempotent, no double-mint)

### Scenario 3: Kernel Crashes Mid-Mint

**Problem**: Some citizens minted, some not

**Recovery**:
1. On restart: Load already_claimed state from storage
2. Kernel resumes processing
3. already_claimed prevents double-minting for completed citizens
4. Incomplete claims are re-processed

### Scenario 4: Pool Capacity Exceeded

**Problem**: More claims than 1M SOV can satisfy

**Solution** (not recovery):
1. Process claims in order
2. When pool capacity reached: stop minting
3. Remaining claims: Emit UbiClaimRejected (reason_code=4)
4. Next epoch: Fresh 1M SOV pool

---

## Governance Checkpoints

### Before Activation

- [ ] UBI Contract is audited and deployed
- [ ] Treasury Kernel is fully implemented and audited
- [ ] CitizenRegistry has >100 registered citizens
- [ ] Test run on testnet: 10 epochs of distributions
- [ ] Event schemas verified (ABI-compatible)

### During Operation

- [ ] Weekly monitor: UbiDistributed events
- [ ] Weekly monitor: UbiPoolStatus events
- [ ] Monthly audit: UbiClaimRejected patterns
- [ ] Monthly audit: Eligible population size

### Adjustment Triggers

| Event | Action | Authority |
|-------|--------|-----------|
| Too many rejections | Investigate CitizenRegistry | Governance |
| Pool always exhausted | Governance votes to increase pool | Governance |
| Eligible count drops | Investigate revocation patterns | Governance |
| Technical issues | Pause distribution, debug | Governance + Operators |

---

## Future Extensions

Once basic UBI is operational:

1. **Graduated UBI**: Different payouts for different roles
2. **Conditional UBI**: Claim only if citizen has other roles
3. **Pooled UBI**: Separate pools for different sectors
4. **Means Testing**: Reduce payout if high balance
5. **Activity Requirements**: Claim only if recent activity

**Implementation**: These are Kernel modifications, not UBI contract changes.

---

## Success Criteria for Prep Phase

✅ UBI as Kernel client fully architected (this doc)
✅ Passive client vs. active executor clearly defined
✅ Interface specifications complete
✅ Event schemas documented
✅ Integration points specified
✅ Call sequence flow defined
✅ Failure modes and recovery strategies outlined
✅ Governance checkpoints established

**Next Step**: When Treasury Kernel is implemented, this architecture becomes the implementation reference.

---

## References

- **ADR-0017**: Execution Boundary (Treasury Kernel Primacy)
- **UBI_ECONOMICS_SPECIFICATION.md**: Economic parameters and constraints
- **UBI_ROLE_GATING_DESIGN.md**: Detailed eligibility validation
- **UBI Event Schemas**: `/lib-blockchain/src/contracts/ubi_distribution/types.rs`
- **Issue #844**: UBI Distribution (Prep Phase)
