# Issue #844: UBI Distribution — Prep-Only Until Treasury Kernel

**Status:** 🚫 DO NOT IMPLEMENT YET — PREP ONLY
**Blocker:** Treasury Kernel must exist first
**Related:** #840 (mega-ticket), #841 (storage), #843 (ABI), ADR-0017

---

## Strategic Context

UBI is **not foundational**—it is a **client of the Treasury Kernel**.

UBI is:
- A scheduled payout
- From a designated pool
- To role-gated recipients (citizens)
- Governed by caps and epochs

That makes UBI:
- ✅ A policy choice (can be added later)
- ❌ NOT a primitive (must not be hardcoded now)
- ✅ A Treasury Kernel client
- ❌ NOT an independent economic system

**Implementing UBI now would:**
- ❌ Bypass the Treasury Kernel architecture
- ❌ Create direct mint paths that violate governance
- ❌ Lock in current economics (impossible to change)
- ❌ Create technical debt that must be deleted later

**Therefore:** UBI prep can start, but full implementation is blocked.

---

## Decision: Preparation vs. Implementation

### SAFE TO DO NOW (Prep Phase)

These are design-only, governance-setup, and failing-test activities:

- ✅ Define Citizen role in Role Registry terms
- ✅ Define UBI economics (amount, epoch, caps)
- ✅ Define UBI ABI (event schemas, method signatures)
- ✅ Write failing tests (red tests)
- ✅ Document UBI as Treasury Kernel client
- ✅ Design role-gating approach
- ✅ Plan epoch-based distribution

### BLOCKED UNTIL TREASURY KERNEL EXISTS

These are implementation activities that must wait:

- ❌ Actual distribution logic
- ❌ Scheduling/execution code
- ❌ Token movement
- ❌ Claim mechanisms
- ❌ Pool management
- ❌ Cap enforcement
- ❌ Payout ledger

---

## Prep Phase: What to Implement Now

### 1. Define Citizen Role (Role Registry)

Create a role definition for "Citizen":

```rust
pub struct CitizenRole {
  /// Unique citizen identifier (linked to identity)
  pub citizen_id: [u8; 32],

  /// Role type (always "citizen")
  pub role_type: "citizen",

  /// Citizenship epoch (when became citizen)
  pub citizenship_epoch: u64,

  /// Revocation status (for ex-citizens)
  pub revoked: bool,
  pub revoked_epoch: Option<u64>,

  /// Metadata
  pub verified_at: u64,
}
```

**Scope:**
- Define in Role Registry schema
- Do NOT implement distribution logic
- Do NOT implement gate-checking

---

### 2. Define UBI Economics (Design Document)

Document (do not code):

```markdown
# UBI Economics

## Parameters
- Payout amount: 1000 SOV per epoch
- Epoch duration: 604800 seconds (1 week)
- Total pool: 1M SOV per epoch
- Max citizens: 1000 (creates 1M cap)
- Recipient: Citizens only (role-gated)

## Execution Model (Trust Kernel)
1. At epoch boundary, Treasury Kernel reads all Citizens
2. For each Citizen, check if eligible this epoch
3. If eligible, record intent: `UbiDistribution { citizen_id, amount, epoch }`
4. Kernel validates: amount <= cap, citizen is valid
5. Kernel mints: `mint(citizen_id, amount)`
6. Kernel records: `UbiDistributed` event

## No Vesting
- UBI is immediately claimable
- No lock-up period
- No cliff
```

**Scope:**
- Design document only
- Do NOT code the logic
- Do NOT assume direct minting
- Do NOT bypass Kernel

---

### 3. Define UBI ABI (Event Schemas)

Define ABI-compatible event schemas:

```rust
/// Event: Citizen requests UBI
pub struct UbiClaimRecorded {
  pub citizen_id: [u8; 32],     // Fixed size, deterministic
  pub amount: u64,               // Requested amount
  pub epoch: u64,                // Which epoch
  pub timestamp: u64,            // When requested
}

/// Event: Treasury Kernel distributes UBI
pub struct UbiDistributed {
  pub citizen_id: [u8; 32],     // Who received
  pub amount: u64,               // How much (post-validation)
  pub epoch: u64,                // Which epoch
  pub kernel_txid: [u8; 32],    // Kernel transaction ID (audit trail)
}

/// Event: UBI pool status
pub struct UbiPoolStatus {
  pub epoch: u64,                // Current epoch
  pub citizens_eligible: u64,    // How many citizens qualified
  pub total_distributed: u64,    // Total amount distributed
  pub remaining_capacity: u64,   // Unused portion of pool
}
```

**Scope:**
- Define ABI-compatible structures
- Do NOT implement event emission
- Do NOT implement pool logic
- Ensure Kernel can consume these events

---

### 4. Write Failing Red Tests

Create tests that FAIL (intentionally):

```rust
#[test]
#[should_panic(expected = "UBI must go through Treasury Kernel")]
fn ubi_cannot_mint_directly() {
  // ❌ This must NOT work
  // claim_ubi(citizen_id, amount);

  // ✅ Instead, this should record intent
  // storage.record_intent(UbiClaim { ... });
}

#[test]
#[should_panic(expected = "UBI respects epoch caps")]
fn ubi_respects_caps() {
  // ❌ Cannot exceed pool cap
  let pool_cap = 1_000_000;

  // Try to claim more than cap
  for i in 0..2000 {  // 2M > 1M cap
    claim_ubi(citizen_id(i), 1000);  // MUST FAIL
  }
}

#[test]
#[should_panic(expected = "UBI requires Treasury Kernel")]
fn ubi_requires_kernel() {
  // ❌ This architecture must be enforced
  // (Test passes when Kernel layer rejects non-Kernel execution)
}

#[test]
#[should_panic(expected = "Citizenship required")]
fn ubi_requires_citizenship() {
  // ❌ Non-citizens cannot claim
  claim_ubi(non_citizen_id, 1000);  // MUST FAIL
}
```

**Scope:**
- Write tests that assert correct behavior
- Tests FAIL because impl is not ready
- These become acceptance tests for Phase C
- Do NOT implement the logic to make them pass

---

### 5. Design Role-Gating Approach

Document (do not code):

```markdown
# Role-Gating for UBI

## How to Verify Citizenship

When Treasury Kernel processes UBI:

1. Look up `citizen_id` in Role Registry
2. Check role: `role_type == "citizen"`
3. Check status: `revoked == false`
4. Check epoch: `citizenship_epoch <= current_epoch`
5. If all pass: citizen is eligible

## Gate Points

- [x] Role Registry lookup (future)
- [x] Status check (future)
- [x] Epoch verification (future)
- [ ] Implement now (NO)
```

---

### 6. Document UBI as Treasury Kernel Client

Create architecture document:

```markdown
# UBI as Treasury Kernel Client

UBI is NOT:
- An autonomous system
- A minting authority
- A policy executor
- A direct value transfer mechanism

UBI IS:
- A request/intent system
- A policy definition (economics)
- A Treasury Kernel consumer
- A Citizen role client

## Execution Flow

```
Citizen → Records UBI claim → Storage
                                ↓
                          Treasury Kernel polls
                                ↓
                    Kernel validates: citizen? cap? epoch?
                                ↓
                    Kernel decides: approve or reject
                                ↓
                    Kernel executes: mint + record event
                                ↓
                    Citizen can now spend
```

This is the ONLY valid flow.
```

---

## Implementation Checklist (PREP PHASE ONLY)

### Phase A: Design (DO NOW)

- [ ] Citizen role defined in Role Registry schema
- [ ] UBI economics documented (no code)
- [ ] Event schemas designed (ABI-compatible)
- [ ] Red tests written (intentionally failing)
- [ ] Role-gating approach designed
- [ ] Treasury Kernel client architecture documented
- [ ] Assumption: Kernel will handle all execution

### Phase B: Documentation (DO NOW)

- [ ] UBI specification document
- [ ] Treasury Kernel integration guide (conceptual)
- [ ] Epoch-based distribution explained (no code)
- [ ] Cap enforcement explained (no code)
- [ ] Role-gating algorithm explained (no code)

### Phase C: Architecture Review (DO NOW)

- [ ] Review with Treasury Kernel owner
- [ ] Confirm Kernel will own execution
- [ ] Confirm governance gates are sufficient
- [ ] Confirm event schemas are auditable

### Phase D: BLOCKED (DO NOT DO YET)

- ❌ Implement distribution logic
- ❌ Implement scheduling
- ❌ Implement pool management
- ❌ Implement claim mechanisms
- ❌ Implement cap enforcement
- ❌ Implement epoch tracking
- ❌ Implement minting (Kernel will do this)

---

## Success Criteria for Prep Phase

✅ Citizen role is defined and documented
✅ UBI economics are clear (design doc)
✅ Event schemas are ABI-compatible
✅ Red tests demonstrate correct constraints
✅ Treasury Kernel primacy is documented
✅ No implementation code exists (except schemas)
✅ Assumptions about Kernel are made explicit

---

## Failure Modes (Would Require Restart)

❌ Implementation starts before Kernel exists
❌ Direct minting is attempted
❌ Distribution logic is coded
❌ Governance gates are bypassed
❌ UBI is not documented as Kernel client
❌ Red tests are made to pass prematurely

---

## Timeline

### NOW (Prep Phase)
- Design-only
- Documentation
- Failing tests
- Governance review

### MILESTONE 3-5 (Blocked)
- Treasury Kernel exists
- Mint authority is locked
- Vesting + cap ledger is active
- Role Registry is operational

### AFTER MILESTONE 5 (Implementation)
- Implement distribution logic
- Implement pool management
- Implement claim mechanism
- Make red tests pass

---

## Dependency Chain

```
#841 (Storage)
    ↓ (foundation)
#843 (ABI)
    ↓ (event schemas)
#844 (UBI) - PREP PHASE ← YOU ARE HERE
    ↓ (waits for Kernel)
Treasury Kernel (not yet open)
    ↓ (Kernel exists)
#844 (UBI) - IMPLEMENTATION PHASE
```

**DO NOT skip steps.**

---

## Governance Constraint (FROM ADR-0017)

**Quote this in every review:**

> UBI defines economic intent, not economic law.
> Economic law is enforced exclusively by the Treasury Kernel.

---

## What to Do This Week

1. [ ] Read ADR-0017 (Execution Boundary)
2. [ ] Define Citizen role in Role Registry schema
3. [ ] Write UBI economics specification (design doc)
4. [ ] Design ABI-compatible event schemas
5. [ ] Write 5+ failing red tests
6. [ ] Document UBI as Kernel client
7. [ ] Get governance sign-off on prep scope

What NOT to do:

1. ❌ Write distribution code
2. ❌ Implement scheduling
3. ❌ Implement minting
4. ❌ Implement pool management
5. ❌ Implement epoch tracking
6. ❌ Make red tests pass

---

## Sign-Off

This prep phase is COMPLETE when:

- [ ] Citizen role is in Role Registry schema
- [ ] UBI economics are documented
- [ ] Event schemas are designed
- [ ] Red tests exist and fail as expected
- [ ] Treasury Kernel client assumption is clear
- [ ] No implementation code exists
- [ ] Governance reviews and approves prep scope

Only then should work transition to implementation phase (blocked until Kernel).

---

## One-Liner

> **UBI is a Treasury Kernel client, not an independent system.**
> **Prep now, implement after Treasury Kernel exists.**
