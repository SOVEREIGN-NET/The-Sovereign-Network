# UBI Role-Gating Design
## Issue #844 Prep Phase - Task 5

**Status**: Design Documentation (No Implementation Yet)
**Last Updated**: January 26, 2026
**Related**: UBI Economics Specification, ADR-0017 (Execution Boundary)

---

## Overview

Role-gating is the mechanism by which Treasury Kernel verifies that a citizen is eligible to receive UBI. This document specifies:

- How Kernel checks citizenship (CitizenRegistry lookup)
- What makes a citizen eligible for UBI
- How revocation prevents future claims
- Integration points with Citizen Role system
- Privacy and security considerations

**Core Principle**:
> Citizens who are registered, not revoked, and past their citizenship epoch are eligible to claim UBI.

---

## Citizen Eligibility Criteria

All of the following must be TRUE for a citizen to be eligible:

| Criterion | Check | Enforcer | Consequence if Failed |
|-----------|-------|----------|----------------------|
| **Is Registered** | citizen_id exists in CitizenRegistry | Kernel | Reason code 1 (NotACitizen) |
| **Not Revoked** | citizen.revoked == false | Kernel | Reason code 2 (AlreadyRevoked) |
| **Citizenship Epoch Passed** | current_epoch >= citizen.citizenship_epoch | Kernel | Reason code 5 (EligibilityNotMet) |
| **Not Already Claimed** | already_claimed[citizen_id][epoch] == false | Kernel | Reason code 3 (AlreadyClaimedEpoch) |
| **Pool Has Capacity** | total_distributed[epoch] < 1,000,000 | Kernel | Reason code 4 (PoolExhausted) |

**Decision Logic**:
```
if citizen_id not in CitizenRegistry:
    reject(NotACitizen)
else if citizen.revoked == true:
    reject(AlreadyRevoked)
else if current_epoch < citizen.citizenship_epoch:
    reject(EligibilityNotMet)
else if already_claimed[citizen_id][epoch] == true:
    reject(AlreadyClaimedEpoch)
else if total_distributed[epoch] >= 1,000,000:
    reject(PoolExhausted)
else:
    approve_for_mint()
```

---

## CitizenRegistry Integration

### What Treasury Kernel Queries

Kernel performs these lookups on CitizenRegistry:

```rust
// 1. Get citizen profile
citizen_record = CitizenRegistry.get(citizen_id)?;

// 2. Check registration status
is_registered = (citizen_record is Some)

// 3. Check revocation status
is_revoked = citizen_record.revoked

// 4. Check eligibility epoch
citizenship_epoch = citizen_record.citizenship_epoch

// 5. Get all active citizens (for full distribution)
active_citizens = CitizenRegistry.get_active_citizens(current_epoch)
```

### CitizenRegistry Guarantees

Kernel relies on CitizenRegistry to provide:

1. **Immutability of citizenship_epoch**: Once set, cannot be changed (prevents backdating)
2. **One-way revocation**: revoked field is immutable once set to true
3. **Atomicity of registration**: Once registered, data is consistent (no partial state)
4. **Append-only audit trail**: citizen_list is never modified (only appended to)

### Error Handling

If CitizenRegistry lookup fails:
- **Missing citizen**: Not in registry → Reason code 1 (NotACitizen)
- **Corrupted record**: Returned but invalid → Kernel panics (safety boundary)
- **Registry unavailable**: Cannot proceed → Distribution paused (operator intervention)

---

## Eligibility Timeline

Citizens move through states over time:

```
BEFORE citizenship_epoch:
  Status: NOT ELIGIBLE
  Reason: Has not yet reached citizenship epoch
  Action: Kernel rejects with reason code 5

AT citizenship_epoch (block >= citizenship_epoch * blocks_per_epoch):
  Status: ELIGIBLE
  Action: Citizen can claim starting this epoch

AFTER citizenship_epoch:
  Status: ELIGIBLE (until revoked)
  Action: Citizen continues to claim

WHEN REVOKED (governance decision):
  Status: INELIGIBLE (permanent)
  Reason: revoked == true
  Action: Kernel rejects with reason code 2

AFTER REVOCATION:
  Status: INELIGIBLE FOREVER
  Reason: Revocation is one-way
  Action: Only governance can create new registration (new citizen)
```

**Example Timeline**:

```
Block 0:          Citizen X registered with citizenship_epoch = 10
Block 0-604799:   X not eligible (epoch 0-9)
Block 604800:     Epoch 10 starts - X becomes eligible
Block 605000:     X claims UBI ✓ (epoch 10, eligible)
Block 665280:     Epoch 11 starts - X still eligible
Block 665400:     X claims UBI ✓ (epoch 11, eligible)
Block 700000:     Governance votes to revoke X
Block 700001:     X revoked (revoked = true, revoked_epoch = 11)
Block 725760:     Epoch 12 starts - X NOT eligible
Block 725800:     X tries to claim - Kernel rejects (AlreadyRevoked)
FOREVER:          X cannot claim again (revocation permanent)
```

---

## Deduplication State Management

Kernel tracks which citizens claimed in each epoch:

```rust
// Persisted state
already_claimed: Map<(citizen_id, epoch), bool>
```

### Dedup Lifecycle

1. **Epoch N starts**: all entries for epoch N are false (or absent)
2. **Citizen X claims in epoch N**: already_claimed[(X, N)] = true
3. **Citizen X tries again in epoch N**: Kernel checks already_claimed[(X, N)], finds true, rejects
4. **Epoch N+1 starts**: new epoch, already_claimed[(X, N+1)] = false (fresh start)

### Crash Recovery

If Kernel crashes during distribution:

```
Before crash:   already_claimed[(citizen_123, 5)] = false
Claim processed: already_claimed[(citizen_123, 5)] = true
Kernel crashes
Restart:        already_claimed[(citizen_123, 5)] = true (persisted)
Resumed dist:   Kernel checks already_claimed[(citizen_123, 5)], skips (no double-mint)
```

**Design Guarantee**: Dedup state must be persisted atomically with mint operation.

---

## Pool Capacity Tracking

Kernel tracks cumulative distribution per epoch:

```rust
// Persisted state
total_distributed: Map<epoch, u64>
```

### Pool Lifecycle

1. **Epoch N starts**: total_distributed[N] = 0
2. **First citizen claims**: total_distributed[N] += 1000 (now 1,000)
3. **Citizen 1000 claims**: total_distributed[N] = 1,000,000 (exactly at cap)
4. **Citizen 1001 tries to claim**: Check: 1,000,000 + 1,000 > 1,000,000? YES → REJECT
5. **Epoch N+1 starts**: total_distributed[N+1] = 0 (fresh pool)

### Why Hard Limit

The 1,000,000 SOV cap is **hardcoded and immutable** because:

1. **Economic sustainability**: Fixed annual commitment (~52M SOV)
2. **Governance alignment**: Voted on, not subject to change without re-deployment
3. **Validator agreement**: All nodes enforce same cap deterministically
4. **Pool protection**: Prevents budget overruns

---

## Role-Gating in Execution Flow

### Phase 1: Kernel Polls for Claims

At epoch boundary, Kernel scans for UbiClaimRecorded events:

```
Block height % 60_480 == 0?  (epoch boundary)
  YES: Initiate UBI distribution
  1. Read current_epoch = block_height / 60_480
  2. Query all UbiClaimRecorded events for epoch
  3. Collect citizens who intent to claim
```

### Phase 2: Kernel Validates Each Claim

For each citizen in claims:

```
1. ROLE-GATING CHECK: CitizenRegistry lookup
   - citizen = CitizenRegistry.get(citizen_id)?
   - If None: reject(NotACitizen) → reason_code = 1

2. REVOCATION CHECK
   - If citizen.revoked == true: reject(AlreadyRevoked) → reason_code = 2

3. ELIGIBILITY CHECK (citizenship_epoch)
   - If current_epoch < citizen.citizenship_epoch:
       reject(EligibilityNotMet) → reason_code = 5

4. DEDUP CHECK
   - If already_claimed[(citizen_id, epoch)] == true:
       reject(AlreadyClaimedEpoch) → reason_code = 3

5. CAPACITY CHECK
   - If total_distributed[epoch] >= 1_000_000:
       reject(PoolExhausted) → reason_code = 4

6. All checks passed: MINT
   - mint(citizen_id, 1000)
   - already_claimed[(citizen_id, epoch)] = true
   - total_distributed[epoch] += 1000
   - Emit: UbiDistributed { citizen_id, amount: 1000, epoch, kernel_txid }
```

### Phase 3: Recording Results

For governance audit trail:

```
// Every claim (accepted or rejected) generates an event

If ACCEPTED:
  Emit: UbiDistributed {
    citizen_id: [u8; 32],
    amount: 1000,
    epoch: current_epoch,
    kernel_txid: blake3(kernel_state || citizen_id || epoch || 1000)
  }

If REJECTED:
  Emit: UbiClaimRejected {
    citizen_id: [u8; 32],
    epoch: current_epoch,
    reason_code: 1-5,
    timestamp: block_height
  }
```

---

## Privacy via Silent Failure

Citizens never see WHY their claim was rejected:

### What Citizen Sees
```
Response to claim attempt:
  "No UBI available this epoch"
  (same message for ALL rejection reasons)
```

### What Governance Sees
```
UbiClaimRejected events emitted:
  citizen_id: [u8; 32]
  epoch: u64
  reason_code: 1 (NotACitizen) |
               2 (AlreadyRevoked) |
               3 (AlreadyClaimedEpoch) |
               4 (PoolExhausted) |
               5 (EligibilityNotMet)
  timestamp: block_height
```

### Rationale for Privacy
- Prevents information leakage (citizens cannot fingerprint their status)
- Protects revoked citizens' privacy (no public record of who's excluded)
- Reduces social pressure (cannot distinguish rejection reasons)
- Prevents gaming (attackers cannot probe citizenship status)

---

## Security Considerations

### 1. CitizenRegistry Integrity

**Assumption**: CitizenRegistry is maintained by governance and cannot be corrupted.

**Verification**:
- All writes go through governance approval process
- CitizenRegistry uses append-only audit trail (citizen_list)
- Immutable fields (citizenship_epoch, revocation) prevent tampering
- Root registry (RootRegistry) vouches for CitizenRegistry authenticity

### 2. Revocation Cannot Be Reversed

**Design Constraint**: Once citizen.revoked = true, it stays true forever.

**Implementation** (enforced by CitizenRegistry):
```rust
pub fn revoke(&mut self, citizen_id: [u8; 32], revoked_epoch: u64) -> Result<()> {
    let mut citizen = self.citizens.get_mut(&citizen_id)?;

    // Revocation is one-way
    if citizen.revoked {
        return Err(AlreadyRevoked);  // Cannot un-revoke
    }

    citizen.revoked = true;
    citizen.revoked_epoch = Some(revoked_epoch);
    self.active_count -= 1;  // Decrement active count

    self.citizen_list.push(citizen_id);  // Append-only audit
    Ok(())
}
```

### 3. Citizenship Epoch Immutable

**Design Constraint**: citizenship_epoch is set at registration and never changes.

**Implementation** (enforced by CitizenRegistry):
```rust
pub struct CitizenRole {
    pub citizenship_epoch: u64,  // Immutable after creation
    // ... other fields
}

pub fn register(
    &mut self,
    citizen_id: [u8; 32],
    citizenship_epoch: u64,
) -> Result<()> {
    // citizenship_epoch is set once, never modified
    if self.citizens.contains_key(&citizen_id) {
        return Err(AlreadyRegistered);
    }

    let citizen = CitizenRole {
        citizenship_epoch,  // Set at creation
        // ...
    };

    self.citizens.insert(citizen_id, citizen);
    Ok(())
}
```

**Consequence**: Cannot backdate claims to past epochs.

### 4. Dedup is Permanent Per Epoch

**Design Constraint**: once claimed in epoch N, cannot claim again in epoch N.

**Implementation** (enforced by Kernel, persisted storage):
```rust
// After minting for citizen in epoch:
already_claimed[(citizen_id, epoch)] = true  // Permanent for this epoch

// On retry in same epoch:
if already_claimed[(citizen_id, epoch)] == true {
    return Err(AlreadyClaimedEpoch)
}

// On new epoch:
already_claimed[(citizen_id, next_epoch)] = false  // Fresh start
```

### 5. No Backdating Possible

**Constraint**: Citizens can only claim for current and future epochs, not past.

**Mechanism**: Kernel only processes claims for `current_epoch`:
```rust
fn process_ubi_distributions(current_epoch: u64) {
    // Only processes claims for current_epoch
    // Kernel ignores or rejects claims for past epochs

    for event in find_claims_for_epoch(current_epoch) {
        // Process only current_epoch claims
    }
}
```

**Result**: No citizen can receive retroactive UBI.

---

## Integration with UBI Contract

UBI contract and Treasury Kernel have clear separation:

### UBI Contract Responsibility
```rust
pub fn record_claim_intent(
    &mut self,
    citizen_id: [u8; 32],
    amount: u64,
    epoch: EpochIndex,
) -> Result<()> {
    // Minimal validation (optional)
    if amount == 0 {
        return Err(ZeroAmount);
    }

    // Record intent as event
    emit(UbiClaimRecorded {
        citizen_id,
        amount,
        epoch,
        timestamp: block_height,
    });

    Ok(())
}
```

### Kernel Responsibility
```rust
pub fn process_ubi_distributions(current_epoch: u64) {
    // 1. Poll for UbiClaimRecorded events
    let events = poll_for_claims(current_epoch);

    // 2. For each claim, validate eligibility (role-gating)
    for claim in events {
        if is_eligible_for_ubi(claim.citizen_id, current_epoch) {
            // 3. Mint
            mint(claim.citizen_id, 1000);

            // 4. Record success
            emit(UbiDistributed {
                citizen_id: claim.citizen_id,
                amount: 1000,
                epoch: current_epoch,
                kernel_txid: compute_kernel_txid(),
            });
        } else {
            // Record rejection (for governance)
            emit(UbiClaimRejected {
                citizen_id: claim.citizen_id,
                epoch: current_epoch,
                reason_code: get_rejection_reason(...),
                timestamp: block_height,
            });
        }
    }
}
```

---

## Governance Monitoring

### What Governance Monitors

1. **Distribution Events**: UbiDistributed emitted → verify amount, citizen, epoch
2. **Rejection Patterns**: UbiClaimRejected events → audit rejections by reason code
3. **Pool Status**: UbiPoolStatus at epoch end → verify capacity usage
4. **Revocation Rate**: How many citizens revoked per epoch
5. **Eligible Population**: How many citizens are currently eligible

### Red Flag Scenarios

| Scenario | Indicator | Action |
|----------|-----------|--------|
| Systematic rejections | reason_code pattern | Investigate CitizenRegistry |
| Pool always exhausted | remaining_capacity always 0 | Increase cap or reduce payout |
| No claims recorded | zero UbiClaimRecorded events | Communication issue |
| Dedup failures | reason_code 3 persistent | Storage corruption |
| Eligible count drops | active_count decreases | Mass revocation? |

---

## Failure Modes and Recovery

### Scenario 1: CitizenRegistry Corrupted

**Problem**: Kernel cannot verify eligibility.

**Recovery**:
1. Pause UBI distribution (stop processing claims)
2. Investigate CitizenRegistry state
3. Governance votes to restore (and from what backup)
4. Resume distribution after fix

### Scenario 2: Dedup State Lost

**Problem**: Kernel doesn't know who already claimed.

**Recovery**:
1. Reconstruct from UbiDistributed events
2. already_claimed[(citizen_id, epoch)] = true for each event
3. Resume distribution

### Scenario 3: Kernel Crashes Mid-Distribution

**Problem**: Some citizens minted, some not.

**Recovery**:
1. On restart, Kernel checks already_claimed
2. Citizens who minted have already_claimed[(id, epoch)] = true
3. Kernel resumes from checkpoint (skips already-minted)
4. No double-minting possible

---

## Success Criteria for Prep Phase

✅ Role-gating mechanism fully designed (this doc)
✅ Eligibility criteria explicit and testable
✅ Integration points documented
✅ Failure modes identified and recovery strategies defined
✅ Privacy via silent failure specified
✅ Security assumptions documented
✅ Governance monitoring strategy defined

**Next Step**: When Treasury Kernel is implemented, this design becomes the reference specification for implementation.

---

## References

- **ADR-0017**: Execution Boundary (Treasury Kernel Primacy)
- **UBI_ECONOMICS_SPECIFICATION.md**: Overall UBI design
- **CitizenRole**: `/lib-blockchain/src/contracts/governance/citizen_role.rs`
- **Issue #844**: UBI Distribution (Prep Phase)
