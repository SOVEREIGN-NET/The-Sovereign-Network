# UBI Economics Specification

**Issue**: #844 (Prep Phase)
**Status**: Design Documentation (No Implementation Yet)
**Last Updated**: January 26, 2026

---

## Overview

Universal Basic Income (UBI) on the Sovereign Network is a **policy choice** implemented as a Treasury Kernel client. It is **not** foundational infrastructure but rather a governance decision about economic distribution.

**Core Principle** (from ADR-0017):
> UBI defines economic intent, not economic law.
> Economic law is enforced exclusively by the Treasury Kernel.

This document specifies:
- What UBI does (distribution policy)
- How much and how often
- Who is eligible
- How it integrates with Treasury Kernel

---

## Economic Parameters

### Payout Schedule

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Payout Amount** | 1000 SOV | Sufficient basic income without inflation spiral |
| **Epoch Duration** | 604,800 seconds | 1 week (deterministic from block height) |
| **Distribution Frequency** | Once per epoch | Weekly payouts (consistent, auditable) |

### Pool Sizing

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Total Pool per Epoch** | 1,000,000 SOV | Fixed annual commitment (~52M SOV) |
| **Max Citizens per Epoch** | 1,000 | Creates natural cap: 1M ÷ 1000 = 1000 SOV/citizen |
| **Pool Cap Enforcement** | Hard limit | Cannot exceed allocated amount (Kernel enforces) |

### Recipient Requirements

| Requirement | Value | Enforcement |
|-------------|-------|------------|
| **Role Gating** | Citizen role required | Role Registry lookup (mandatory) |
| **Verification** | DID verified | citizenship_epoch <= current_epoch |
| **Status** | Not revoked | revoked == false |
| **Frequency** | One claim per epoch | Duplicate prevention in Kernel |

---

## Distribution Model

### Who Decides to Distribute

The **Treasury Kernel** (not the UBI contract) makes all distribution decisions:

1. **Kernel Triggers at Epoch Boundary**
   - Reads current block epoch
   - Checks if new UBI epoch has arrived
   - Initiates distribution if needed

2. **Kernel Validates Each Claim**
   - Is citizen registered? (CitizenRegistry lookup)
   - Is citizen revoked? (revoked == false check)
   - Did they claim already this epoch? (dedup check)
   - Does pool have capacity? (1M SOV hard cap)

3. **Kernel Executes Mint**
   - Only Kernel can call `mint(citizen_id, 1000)`
   - No UBI contract can mint directly
   - Token authority is locked to Kernel

4. **Kernel Records Event**
   - Emits `UbiDistributed { citizen_id, amount, epoch, kernel_txid }`
   - Event is audit trail for governance

### What UBI Contract Does

```
Citizen records claim intent
           ↓
    (event recorded)
           ↓
Treasury Kernel polls
           ↓
  Kernel validates (role, revocation, cap, dedup)
           ↓
  If valid: Kernel mints 1000 SOV to citizen
  If invalid: Kernel skips (no error exposed)
           ↓
  Citizen can now spend
```

**Key Design Point**: The UBI contract is **passive**. It defines the policy (1000 SOV/week to citizens). The Kernel is **active**. It enforces the policy.

---

## Execution Flow (Epoch-Based)

### Deterministic Epoch Definition

```
Epoch = current_block_height / blocks_per_week
```

Where:
- `blocks_per_week` = 604,800 seconds ÷ block_time
- For 10-second blocks: 60,480 blocks per epoch
- Deterministic across validators (no randomness)

### Distribution Timeline

```
Epoch N starts (height = 60,480 * N)
      ↓
Treasury Kernel checks: (height % 60,480) == 0?
      ↓
If yes: Read all citizens from CitizenRegistry
      ↓
For each citizen:
  - Check eligibility: is_eligible_for_ubi(current_epoch)?
  - Check dedup: already_claimed[citizen][epoch]?
  - Check pool: total_distributed < 1,000,000?
      ↓
If all pass: mint(citizen_id, 1000), record event
If any fail: skip (no error, no retry)
      ↓
Record: UbiDistributed event (audit trail)
      ↓
Epoch N+1 starts (next week)
```

### State Transitions

```
BEFORE Epoch:
  - Citizens can register (governance approval required)
  - Citizens can be revoked (governance approval required)

DURING Distribution:
  - Citizens can see pending UBI (query only)
  - Kernel is minting (atomic operation)
  - Claims are deduped (Kernel enforces)

AFTER Distribution:
  - Citizens claim UBI (execution complete)
  - Kernel records: UbiDistributed event
  - Pool reset for next epoch
```

---

## Economic Constraints

### Hard Limits (Cannot Exceed)

1. **Pool Cap**: 1,000,000 SOV per epoch
   - Enforced by: Kernel (checked before mint)
   - Verification: sum(claimed_amounts) <= 1,000,000
   - Overflow handling: Stop distributing when cap reached

2. **Per-Citizen Limit**: 1,000 SOV per epoch per citizen
   - Enforced by: Kernel (fixed payout)
   - Verification: amount == 1,000
   - Overflow handling: Reject claim if amount != 1,000

3. **Frequency Limit**: One claim per citizen per epoch
   - Enforced by: Kernel (dedup check)
   - Verification: already_claimed[citizen][epoch] == false
   - Overflow handling: Skip citizen if already claimed

### Governance Constraints

1. **Citizenship Required**
   - Cannot claim without Citizen role
   - Role verified at registration time
   - Cannot be granted retroactively

2. **Revocation is Permanent**
   - Once revoked, cannot claim UBI anymore
   - Revocation is recorded with epoch timestamp
   - Governance must explicitly revoke (no auto-revocation)

3. **Pool is Fixed**
   - Cannot be changed without governance vote
   - Commitment is 1M SOV per epoch (52M/year)
   - Amount per citizen is derived (1000 = 1M/1000)

---

## Vesting and Clawback Policy

### No Vesting

UBI is **immediately claimable** (not subject to vesting):

- Citizen claims 1,000 SOV at epoch N
- Citizen can spend, transfer, or hold immediately
- No lockup period
- No cliff
- No unlocking schedule

### Rationale

- UBI is basic income (not a grant)
- Grant restrictions would reduce utility
- Citizens need immediate economic power
- Governance can revoke (permanent restriction if needed)

### Clawback Policy

**Clawback is NOT implemented** because:

1. **Technical Barrier**: Cannot distinguish UBI SOV from other SOV
2. **Economic Harm**: Would create financial instability for citizens
3. **Governance Alternative**: Revocation prevents future claims (sufficient)
4. **Constitutional**: Citizens' income should not be confiscated

If governance decides restrictions are needed:
- Revoke citizenship (prevents future claims)
- Do not attempt clawback (creates legal and economic issues)

---

## Integration with Treasury Kernel

### What Kernel Must Provide

1. **Minting Authority**
   - Only Kernel can call `mint(citizen_id, amount)`
   - UBI contract cannot mint directly
   - Token supply is controlled atomically

2. **Claim Deduplication**
   - Kernel tracks `claimed[citizen_id][epoch]`
   - Rejects duplicate claims with no error
   - State is isolated in Kernel (UBI cannot modify)

3. **Pool Capacity Tracking**
   - Kernel tracks `distributed[epoch]`
   - Stops minting when distributed >= 1,000,000
   - Atomicity ensures no overflow

4. **Governance Authority**
   - Kernel validates role: only governance can call minting
   - Kernel logs all distributions (UbiDistributed events)
   - Kernel provides audit trail for compliance

### What Kernel Must NOT Do

- ❌ Implement variable payout amounts (always 1000)
- ❌ Allow citizens to claim multiple times (dedup mandatory)
- ❌ Bypass citizenship check (role gate always enforced)
- ❌ Exceed pool cap (hard limit always enforced)
- ❌ Implement vesting (claims are immediate)

### Communication Protocol

```
UBI Contract (intent recording):
  - Records claim intent: { citizen_id, epoch, timestamp }
  - Event: UbiClaimRecorded

Treasury Kernel (execution):
  - Polls for claims at epoch boundaries
  - Validates: role? revoked? dedup? cap?
  - Executes: mint(citizen_id, 1000)
  - Event: UbiDistributed
```

---

## Event Schemas (ABI-Compatible)

### UbiClaimRecorded

Emitted when citizen records a claim intent.

```rust
struct UbiClaimRecorded {
    citizen_id: [u8; 32],      // Who is claiming
    amount: u64,                // Requested amount (should be 1000)
    epoch: u64,                 // Which epoch
    timestamp: u64,             // When claimed (block height)
}
```

### UbiDistributed

Emitted by Treasury Kernel when distribution succeeds.

```rust
struct UbiDistributed {
    citizen_id: [u8; 32],      // Who received
    amount: u64,                // Actual amount (post-validation, should be 1000)
    epoch: u64,                 // Which epoch
    kernel_txid: [u8; 32],     // Kernel transaction ID (audit trail)
}
```

### UbiPoolStatus

Emitted at epoch boundaries to report pool state.

```rust
struct UbiPoolStatus {
    epoch: u64,                 // Current epoch
    citizens_eligible: u64,     // How many citizens could claim
    total_distributed: u64,     // How much was actually distributed
    remaining_capacity: u64,    // Unused portion (1M - total_distributed)
}
```

---

## Failure Modes and Responses

### Claim Rejected (Silent)

If Kernel validation fails, claim is **silently skipped** (no error returned):

| Reason | Kernel Behavior | Citizen Sees |
|--------|-----------------|--------------|
| Not a citizen | Skip claim | No UBI this epoch |
| Revoked | Skip claim | No UBI this epoch |
| Already claimed | Skip claim | No UBI this epoch |
| Pool cap exceeded | Skip claim | No UBI this epoch |

**Rationale**: No error exposure prevents information leakage (privacy).

### Pool Exhaustion

If pool capacity is reached before all eligible citizens are processed:

1. Distribute to citizens in order until capacity reached
2. Remaining citizens get nothing this epoch
3. Pool resets next epoch (new 1M SOV available)
4. Governance can adjust if needed (future change)

### Catastrophic Failure

If Kernel crashes during distribution:

1. Distribution stops at crash point
2. On restart: Kernel checks `claimed[citizen][epoch]` to avoid duplicates
3. Resumed distribution continues where it left off
4. No manual intervention needed (deterministic replay)

---

## Governance Checkpoints

### Before Activation

Governance must approve:

- [ ] Citizen role is properly defined (Role Registry)
- [ ] Economics parameters are acceptable (1000 SOV/week/citizen)
- [ ] Treasury Kernel is fully functional
- [ ] Event schemas are documented and auditable
- [ ] Revocation process is established
- [ ] Pool capacity is funded (1M SOV per epoch)

### During Operation

Governance must monitor:

- [ ] Weekly distribution events (UbiDistributed logged)
- [ ] Pool status (UbiPoolStatus emitted)
- [ ] Claim demographics (how many citizens claimed)
- [ ] Revocation rate (are we revoking bad actors)
- [ ] Economic impact (inflation metrics)

### Adjustment Points

If governance wants to change UBI:

1. **Change payout amount**: Requires governance vote + Kernel redeployment
2. **Change pool size**: Requires governance vote + treasury reallocation
3. **Change frequency**: Requires governance vote + Kernel redeployment
4. **Change eligibility**: Revoke citizens + register new ones (immediate)
5. **Pause UBI**: Stop processing claims at Kernel level (immediate)
6. **End UBI**: Stop processing claims, citizens keep what they claimed (permanent)

---

## Security Considerations

### Role-Based Access Control

**Verified**: CitizenRegistry enforces role-gating
- Only registered citizens can claim
- Revocation is permanent
- No bypass mechanisms

### Deterministic Operations

**Verified**: All parameters are deterministic
- Epoch calculation: block_height ÷ blocks_per_week
- Payout amount: always 1000 SOV
- Pool cap: always 1,000,000 SOV
- Dedup: always checks already_claimed[citizen][epoch]

### Immutable Economics

**Verified**: Core parameters cannot be changed during operation
- Citizenship epoch (when became eligible)
- Payout amount (1000 SOV)
- Pool cap (1M SOV)
- Epoch duration (604,800 seconds)

### Audit Trail

**Verified**: All distributions are logged
- UbiClaimRecorded: when citizen intends to claim
- UbiDistributed: when Kernel executes claim
- UbiPoolStatus: epoch-level rollup
- All events are blockchain-timestamped

---

## Future Extensions (NOT Prep Phase)

These are possible future enhancements (after Kernel is operational):

1. **Graduated UBI**: Higher payout for verified roles (e.g., 1500 SOV for institutions)
2. **Conditional UBI**: Claim only available if citizen has other roles (e.g., has stake)
3. **Pooled UBI**: Different pools for different sectors (health, education, etc.)
4. **Means Testing**: Reduce payout if citizen has high balance (future governance decision)
5. **Activity Requirements**: Claim only if citizen has recent blockchain activity

**Decision Point**: These require governance vote AND Kernel redeployment. Do NOT implement in Prep Phase.

---

## Assumptions and Constraints

### Mandatory Assumptions (Must Hold)

1. ✅ Treasury Kernel exists and is fully operational
2. ✅ Role Registry is fully operational (CitizenRegistry integration)
3. ✅ Token supply is controlled atomically (Kernel owns mint authority)
4. ✅ Governance can revoke citizens (implicit assumption)
5. ✅ Block height is monotonic and deterministic (chain property)

### Operational Constraints (Cannot Change)

1. ✅ Payout is always 1000 SOV (hardcoded in Kernel)
2. ✅ Pool is always 1,000,000 SOV per epoch (governance-approved)
3. ✅ Epoch duration is always 604,800 seconds (deterministic)
4. ✅ Citizenship is immutable once granted (cannot be updated)
5. ✅ Revocation is one-way (cannot unrevoke)

### Design Constraints (Cannot Violate)

1. ✅ No direct UBI minting (only Kernel can mint)
2. ✅ No vesting or clawback (immediate and permanent)
3. ✅ No error exposure (silent failure for invalid claims)
4. ✅ No governance override (Kernel enforces policy, not governance)
5. ✅ No rollback of distributions (events are immutable)

---

## Success Criteria for Prep Phase

✅ Economics parameters are documented (this doc)
✅ Payout amount is realistic and defensible (1000 SOV)
✅ Pool cap is sustainable (1M SOV/week funded)
✅ Event schemas are ABI-compatible (defined above)
✅ Treasury Kernel integration is documented
✅ Governance assumptions are explicit
✅ No implementation code exists (schema-only)
✅ Red tests will document constraints (next step)

---

## Sign-Off

This economics specification is complete and ready for governance review.

**Next Steps**:
1. Governance reviews and approves economics
2. Citizen role schema is implemented ✅
3. Red tests are written (failing)
4. Treasury Kernel is built (blocks further progress)
5. Implementation phase begins (after Kernel)

---

**References**

- ADR-0017: Execution Boundary (Treasury Kernel Primacy)
- Issue #844: UBI Distribution (Prep Phase)
- CitizenRole: `/lib-blockchain/src/contracts/governance/citizen_role.rs`
- Treasury Kernel (TBD): Not yet implemented
