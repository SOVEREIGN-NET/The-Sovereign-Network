# ADR-0017: Execution Boundary & Treasury Kernel Primacy

**Status:** REQUIRED CONSTRAINT (blocks #840 mega-ticket)
**Date:** 2026-01-23
**Author:** Architecture Review
**Relates to:** #840 (Contract Deployment), #841 (Persistent Storage), #843 (ABI), #844 (UBI)

---

## Context

The ZHTP blockchain is transitioning from a permissionless, policy-agnostic architecture to a **governed, policy-enforcing** system. This requires a clear separation between:

1. **Intent Recording** (what contracts want to happen)
2. **Execution** (what actually happens to token state)
3. **Governance** (who decides if execution is valid)

Without this separation, we risk:
- ❌ Multiple economic execution paths
- ❌ Hardcoded policies that create technical debt
- ❌ Bypassed governance constraints
- ❌ Non-auditable decision chains

---

## Decision

### Core Principle

**One-line rule (VERBATIM):**

> **#841 defines economic intent, not economic law. Economic law is enforced exclusively by the Treasury Kernel.**

### Architectural Constraint

All work under #840 (mega-ticket) MUST satisfy:

```
Intent Recording ─────> Storage Layer ─────> Treasury Kernel ─────> Economic Effects
   (Contracts)      (#841 Persistent)     (Future layer)        (Mint/burn/lock)
                        ↓
                    Event Audit Trail
                    (for Compensation DAO)
```

### Core Rules (MANDATORY)

#### 1. Execution Boundary (BLOCKING)

**No contract code may directly mutate token balances.**

```rust
// ❌ FORBIDDEN in any contract
balance[addr] -= amount;           // Direct mutation
mint_token(amount);                // Direct mint
transfer(from, to, amount);        // Direct transfer
lock_stake(amount);                // Direct lock

// ✅ ALLOWED in any contract
TransactionIntent {
  op: Transfer { from, to, amount }  // Declarative intent only
}
```

**Acceptance Criterion:**
- Grep for `balance[` in contract code returns 0 results
- No contract calls `TokenContract::mint()` or `TokenContract::burn()`
- All economic operations deferred to Treasury Kernel

---

#### 2. Policy Neutrality (MANDATORY)

**No contract may encode economic policy.**

Disallowed (Policy):
```rust
// ❌ Fee percentages
fee: 5,  // embedded

// ❌ Allocation ratios
allocation: 0.3,  // hardcoded

// ❌ Vesting rules
vesting_period: 86400,  // months encoded

// ❌ Compensation logic
compensation = base * multiplier * role_factor  // encoded policy
```

Allowed (Intent):
```rust
// ✅ Requested amount (not guaranteed)
UbiClaim {
  amount: 1000,        // what they're claiming
  citizen_id: ...,     // who they are
  epoch: 42,           // when
}

// ✅ Role context (for audit, not policy)
Proposal {
  proposer_role: "council",  // classification only
  description: "...",        // human readable
}

// ✅ Pool reference (not enforcement)
Distribution {
  pool_id: [u8; 32],  // pointer, not control
}
```

**Acceptance Criterion:**
- No percentage, multiplier, or vesting constant appears in contract logic
- All policy decisions go to Treasury Kernel
- Policy changes require Treasury Kernel update, not contract recompile

---

#### 3. Mint/Burn Must Be Privileged (MANDATORY)

**If minting or burning appears in any contract, it MUST be:**
- Marked as `kernel_only`
- Marked as `requires_governance`
- Marked as `delayed_effect` (not immediate)

Even if enforcement is not yet wired, the marker must exist:

```rust
// Example: Future UBI claim might request mint
UbiDistribution {
  citizen_id: ...,
  amount: 1000,
  kind: MintIntent {           // NOT an actual mint
    kernel_only: true,         // Marker
    requires_governance: true, // Marker
    delayed_effect: true,      // Marker
  }
}
```

**Acceptance Criterion:**
- Any mint/burn operation in a contract is explicitly marked privileged
- Runtime can validate that only Treasury Kernel can execute these
- Non-privileged actors receive error if they attempt execution

---

#### 4. ABI Compatibility (REQUIRED, NON-BLOCKING)

**All transaction definitions MUST be compatible with ABI standardization (#843).**

This does NOT require ABI implementation now, only structural compatibility:

```rust
// ✅ Compatible with ABI
pub struct Transfer {
  pub from: [u8; 32],      // Fixed size, deterministic
  pub to: [u8; 32],        // Fixed size, deterministic
  pub amount: u64,         // Numeric, no ambiguity
}

// ❌ NOT compatible with ABI
pub struct Transfer {
  pub from: String,        // Variable size, free-text
  pub to: String,          // Variable size, free-text
  pub amount: String,      // String-encoded, ambiguous
  pub reason: String,      // Free-text, non-deterministic
}
```

**Compatibility Checklist:**
- ✅ Fixed-size types (enums, fixed arrays, u64)
- ✅ No free-text reason strings (use enums or codes)
- ✅ Stable field ordering
- ✅ Deterministic encoding
- ✅ Explicit enum variants (not string-based)

**Acceptance Criterion:**
- ABI team can auto-generate schema from transaction types
- All types pass ABI compatibility validator (TBD)
- Events are structured, not free-text

---

### Explicit Non-Goals for #841 (MUST BE STATED IN PR)

PR #841 deliberately does NOT implement:

- ❌ Token vesting
- ❌ Compensation allocation
- ❌ UBI distribution
- ❌ Treasury enforcement
- ❌ Caps or rate limits
- ❌ Governance gatekeeping
- ❌ Economic policy of any kind

These are owned by:
- **Treasury Kernel** (value movement)
- **Compensation Engine** (reward calculation)
- **Role Registry** (identity classification)
- **Metric Book** (on-chain metrics)

---

## Sequencing & Dependencies

### Phase A: Start Immediately (NOW)

**Issue #841** ✅
- Persistent storage (COMPLETE)
- Architectural constraints applied
- PR updated with non-goals
- Execution boundary documented

**Issue #843** ⏳ START NEXT
- ABI standardization
- Must assume Treasury Kernel exists
- Must not assume legacy mint paths
- Design-only, not implementation

### Phase B: Blocked Until Treasury Kernel (NOT YET)

**Issue #844** 🚫 PREP ONLY
- UBI design-only
- Red tests (failing assertions)
- No implementation of distribution logic
- No minting or scheduling

### Phase C: After Treasury Kernel (TBD)

**Issue #844** ▶️ FULL IMPLEMENTATION
- UBI as Treasury Kernel client
- Epoch-based distribution
- Capped pool management
- Role-gated recipients

---

## Governance Guardrails

### Constraint Enforcement

**For each PR/issue under #840:**

1. **Pre-merge checklist:**
   ```
   - [ ] No direct balance mutation (grep `balance[` = 0)
   - [ ] No hardcoded policy (grep policy constants = 0)
   - [ ] All mint/burn marked privileged
   - [ ] ABI-compatible structures
   - [ ] PR references Treasury Kernel primacy
   - [ ] Execution boundary documented in code
   ```

2. **Code review questions:**
   - "Does this code directly mutate a balance?"
   - "Does this code encode economic policy?"
   - "Does this code assume it executes in Treasury Kernel?"
   - "Could this code be refactored as a declarative intent?"

3. **Automated checks (TBD):**
   - Grep for forbidden patterns
   - ABI compatibility validator
   - Treasury Kernel primacy verifier

---

## Impact Analysis

### On #841 (Persistent Storage)

**No changes required.** Already compliant:
- ✅ Pure infrastructure
- ✅ No economic logic
- ✅ Policy-neutral
- ✅ ABI-compatible structures

**Updates needed:**
- Add execution boundary comments ✓ (done)
- Update PR description (pending)

### On #843 (ABI Standardization)

**Design constraint:**
- Assume Treasury Kernel exists
- Do NOT lock to legacy paths
- Make room for privilege markers
- Design for auditable execution

**Related changes:**
- ABI schema must accommodate `kernel_only` flags
- Event signatures must be deterministic
- No free-text fields in events

### On #844 (UBI Distribution)

**Blocking constraint:**
- Cannot implement until Treasury Kernel exists
- CAN design in prep phase
- MUST write red tests (failing assertions)
- MUST NOT implement distribution logic

**Related changes:**
- Define Citizen role in Role Registry terms
- Define UBI ABI in terms of Kernel operations
- Write tests that assert "UBI goes through Kernel"

---

## Monitoring & Compliance

### Success Criteria

✅ All code under #840 passes governance checklist
✅ PR #841 references Treasury Kernel primacy
✅ PR #843 designs with Kernel assumptions
✅ PR #844 implements prep-only work (design + red tests)
✅ No economic policy hardcoded anywhere
✅ Single execution path: Intent → Storage → Kernel → Effect

### Failure Modes (Would Require Rollback)

❌ Code bypasses Treasury Kernel
❌ Multiple economic execution paths exist
❌ Policy is hardcoded (fees, vesting, allocations)
❌ Mint/burn not marked privileged
❌ Non-ABI-compatible structures in events

---

## Related Documents

- [#840 Mega-ticket](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/840)
- [#841 Persistent Storage](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/841)
- [#843 ABI Standardization](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/843)
- [#844 UBI Distribution](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/844)
- [Treasury Kernel Architecture (TBD)]()
- [Compensation DAO Design (TBD)]()

---

## Implementation Notes

### For Contract Authors

```rust
// DO THIS: Intent-based
pub enum ContractTransaction {
  UbiClaim { citizen_id: [u8; 32], amount: u64, epoch: u64 },
  DaoProposal { proposer: [u8; 32], description: String },
}

// NOT THIS: Effect-based
pub fn claim_ubi(citizen_id: [u8; 32], amount: u64) {
  balance[citizen_id] += amount;  // ❌ FORBIDDEN
}
```

### For Storage Layer (This ADR)

```rust
// DO THIS: Record intent
storage.set(
  key("ubi_claim", citizen_id),
  serde_json::to_vec(&UbiClaim { amount, epoch })?,
)?;

// NOT THIS: Execute effect
// (Never happens at storage layer)
```

### For Treasury Kernel (Future)

```rust
// DO THIS: Execute intents via kernel
for claim in claims {
  validate_citizenship(claim.citizen_id)?;
  validate_epoch_cap(claim.epoch)?;
  mint_ubi(claim.citizen_id, claim.amount)?;
  emit_audit_event(claim)?;
}
```

---

## Appendix: One-Liner Principle

**MEMORIZE AND QUOTE THIS:**

> **#841 defines economic intent, not economic law.**
> **Economic law is enforced exclusively by the Treasury Kernel.**

Use this phrase in:
- Code reviews
- PR descriptions
- Architecture discussions
- Governance decisions

---

## Approval Checklist

- [ ] Architecture team approves execution boundary
- [ ] Treasury Kernel lead confirms this is their responsibility
- [ ] ABI team confirms compatibility requirements
- [ ] UBI team confirms prep-only scope
- [ ] Governance agrees to enforcement checkpoints
