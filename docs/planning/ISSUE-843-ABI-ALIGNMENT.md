# Issue #843: ABI Standardization — Alignment with Treasury Kernel

**Status:** START IMMEDIATELY (parallel with #841)
**Blocker:** Must respect ADR-0017 (Execution Boundary & Treasury Kernel Primacy)
**Related:** #840 (mega-ticket), #841 (persistent storage), #844 (UBI)

---

## Strategic Context

ABI standardization is **foundational infrastructure** for the new economic architecture:

- Treasury Kernel needs deterministic, auditable interfaces
- Compensation DAO needs stable event schemas
- Role Registry needs typed role operations
- Metric Book needs encoded metric definitions

**Without ABI, the new system is:**
- Brittle (no type safety)
- Hard to audit (no schema)
- Hard to test (no determinism)
- Impossible to SDK against cleanly

**Therefore:** ABI must be implemented ASAP, in parallel with #841.

---

## Design Constraint (CRITICAL)

**ABI for #843 must be designed ASSUMING Treasury Kernel exists,**
**EVEN THOUGH it is not yet implemented.**

This means:

✅ Design ABI for Treasury Kernel operations
✅ Assume Kernel is the authoritative executor
✅ Design for privilege markers (`kernel_only`, `governance_gated`)
✅ Design for deferred execution semantics

❌ Do NOT lock ABI to legacy permissionless paths
❌ Do NOT assume direct mint/balance operations in contracts
❌ Do NOT encode current lib-economy semantics

---

## Scope: What to Implement Now

### Phase 1: Core ABI Specification (SAFE)

**1.1 ABI Schema Format**

Define format for:
- Method signatures with parameter types
- Event schemas with field types
- Privilege markers
- Versioning strategy
- Evolution/deprecation rules

Example structure (conceptual):
```json
{
  "contract": "UBI",
  "version": "1.0.0",
  "methods": [
    {
      "name": "claim",
      "parameters": [
        { "name": "citizen_id", "type": "Bytes32" },
        { "name": "amount", "type": "U64" },
        { "name": "epoch", "type": "U64" }
      ],
      "returns": "ClaimResult",
      "privilege": { "kernel_only": true, "governance_gated": true },
      "semantics": "intent"  // Not executed, just recorded
    }
  ],
  "events": [
    {
      "name": "ClaimRecorded",
      "fields": [
        { "name": "citizen_id", "type": "Bytes32" },
        { "name": "amount", "type": "U64" },
        { "name": "epoch", "type": "U64" }
      ]
    }
  ]
}
```

**1.2 Type System**

Define atomic types:
- Bytes32, Bytes (variable)
- U8, U16, U32, U64, U128
- Bool
- Enum (fixed variants)
- Struct (fixed fields, fixed order)

Disallow:
- String (use Enum or Bytes instead)
- Free-text fields
- Dynamic collections (except Bytes)

**1.3 Encoding/Decoding Rules**

Specify:
- Deterministic serialization (e.g., bincode with fixed ordering)
- Backward compatibility strategy
- Checksum/validation approach
- Namespace isolation

**1.4 Build-Time ABI Generation**

Tool that:
- Reads Rust contract definitions
- Validates ABI compatibility
- Generates ABI JSON
- Produces TypeScript SDK (future)

---

### Phase 2: Event Schema Standardization (SAFE)

**2.1 Event Signature Definition**

Every event must:
- Have deterministic name
- Have typed, fixed-order fields
- Be hashable/signable
- Be searchable by event type

Example:
```rust
pub struct ClaimRecorded {
  pub citizen_id: [u8; 32],
  pub amount: u64,
  pub epoch: u64,
}
// ABI: ClaimRecorded(Bytes32, U64, U64)
```

**2.2 Event Registry**

Central registry of:
- All event signatures
- Version history
- Deprecation markers
- Contract ownership

**2.3 Audit Trail Queries**

Support for:
- Query events by type
- Query events by actor
- Query events by date range
- Replay events for validation

---

### Phase 3: Privilege Markers (SAFE, NON-BLOCKING)

**3.1 Define Privilege Levels**

```rust
pub struct PrivilegeMarker {
  pub kernel_only: bool,         // Only Treasury Kernel can execute
  pub governance_gated: bool,    // Requires governance approval
  pub delayed_effect: bool,      // Effect is deferred, not immediate
  pub requires_role: Option<Role>, // Specific role required
}
```

**3.2 Marker Propagation**

ABI layer can validate:
- Non-kernel actors cannot call `kernel_only` methods
- Governance approval is captured before execution
- Deferred effects are tracked separately

**Note:** Actual enforcement is TBD (may require changes to executor).

---

### Phase 4: Runtime Validation Hooks (SAFE)

**4.1 ABI Validator**

Function that:
- Takes a transaction/event
- Validates against ABI schema
- Returns success or detailed error

```rust
pub fn validate_transaction(abi: &AbiSchema, tx: &Transaction) -> Result<(), ValidationError> {
  // Validate all fields match schema
  // Validate no extra fields
  // Validate types match
  // Return error with path if invalid
}
```

**4.2 Type Checker**

Ensure:
- Parameters match declared types
- No implicit conversions
- Strict enum variants
- No string coercion

---

## Scope: What NOT to Implement Yet

❌ Do NOT implement Treasury Kernel execution layer
❌ Do NOT implement cross-contract calls yet
❌ Do NOT implement dynamic upgradeable ABI
❌ Do NOT implement ABI discovery protocol
❌ Do NOT implement SDK generation

These are out of scope for #843.

---

## Contracts That MUST Be ABI-Compatible

These are the contracts that will drive ABI design:

1. **Treasury Kernel** (future)
   - Methods: `execute_intent()`, `validate_operation()`, `record_effect()`
   - Events: `OperationExecuted`, `EffectRecorded`, `GovernanceDecision`

2. **Compensation Engine** (future)
   - Methods: `calculate_reward()`, `validate_contribution()`
   - Events: `RewardCalculated`, `ContributionRecorded`

3. **Role Registry** (future)
   - Methods: `assign_role()`, `revoke_role()`
   - Events: `RoleAssigned`, `RoleRevoked`

4. **Metric Book** (future)
   - Methods: `record_metric()`, `query_metric()`
   - Events: `MetricRecorded`

5. **UBI Contract** (future, as Kernel client)
   - Methods: `claim_ubi()` (deferred to Kernel)
   - Events: `UbiClaimRecorded`, `UbiDistributed`

---

## Design Principles

### Principle 1: Determinism

All event schemas must be:
- Byte-for-byte reproducible
- Hashable identically
- Encoded in fixed order
- No variable-length ambiguity

### Principle 2: Auditability

All events must support:
- Searchability (by type, actor, time)
- Replaceability (full audit trail)
- Non-repudiation (signed events)
- Chain-of-custody (who recorded, when)

### Principle 3: Extensibility

Schemas must support:
- Versioning (add fields, mark deprecated)
- Migration (old → new event mapping)
- Namespace isolation (no collision)
- Backward compatibility (old clients can read new events)

### Principle 4: Kernel Primacy

All ABI must assume:
- Treasury Kernel is authoritative executor
- Contracts record intent, not effect
- Execution is deferred
- Privilege markers are mandatory

---

## Implementation Checklist

### Stage 1: Specification (Week 1)

- [ ] ABI schema format documented
- [ ] Type system defined and validated
- [ ] Encoding rules specified
- [ ] Example schemas for 3-5 representative contracts
- [ ] Backward compatibility strategy defined

### Stage 2: Tooling (Week 2)

- [ ] Build-time ABI generator (reads Rust contracts)
- [ ] ABI validator (checks transaction against schema)
- [ ] JSON schema output
- [ ] Documentation generator

### Stage 3: Integration (Week 3)

- [ ] Apply ABI to #841 storage structures
- [ ] Validate all contract types are ABI-compatible
- [ ] Write tests for ABI validation
- [ ] Create ADR for ABI (reference ADR-0017)

### Stage 4: Documentation (Week 4)

- [ ] ABI specification guide
- [ ] Privilege marker documentation
- [ ] Event schema best practices
- [ ] Migration guide for SDK generation

---

## Success Criteria

✅ ABI schema can express all contract intents
✅ All types are deterministically encodable
✅ Event schemas are auditable and searchable
✅ Privilege markers exist and propagate
✅ No contract can mutate balances via ABI
✅ Treasury Kernel assumptions are enforced
✅ ABI is forward-compatible with #844 (UBI)

---

## Risk Assessment

### Risk: ABI is too rigid

**Mitigation:**
- Design versioning from day 1
- Support field addition (append-only)
- Plan for deprecation
- Test with 10+ example schemas

### Risk: Privilege markers are not enforced

**Mitigation:**
- Document that enforcement is deferred
- Implement validation hook now
- Executor changes planned for Phase 2
- Audit layer can detect violations

### Risk: ABI is not compatible with SDK

**Mitigation:**
- Design with TypeScript code-gen in mind
- Use standard types (u64, not BigInt)
- No variable-length arrays
- Explicit enum variants

---

## Related Documents

- **ADR-0017:** Execution Boundary & Treasury Kernel Primacy
- **#840:** Contract Deployment Infrastructure (mega-ticket)
- **#841:** Persistent Contract Storage (foundation)
- **#844:** UBI Distribution (blocked until Kernel)

---

## Next Steps

1. **Review and approve ADR-0017** (Execution Boundary)
2. **Create ABI specification draft** (with team)
3. **Validate against Treasury Kernel requirements** (when available)
4. **Implement build-time ABI generator**
5. **Update #841 storage to be ABI-compatible** (should be no-op)

---

## One-Liner

> **ABI standardizes intent recording, not economic execution.**
> **Execution remains the exclusive domain of the Treasury Kernel.**
