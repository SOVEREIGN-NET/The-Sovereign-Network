# Treasury Kernel Integration Guide

## Overview

The Treasury Kernel is the exclusive enforcer of economic law (ADR-0017). This guide explains how contracts can integrate with the Kernel to safely execute economic operations.

**Current Status**: Phase 1 (UBI Distribution)
- ✅ UBI passive client implementation
- ✅ 5-check validation pipeline
- ✅ Crash recovery guarantees
- 🔄 Future: Compensation engine, Metrics book, Vesting

## The Passive Client Pattern

The Treasury Kernel implements a **passive client pattern**:

```
Contract          Treasury Kernel
   |                    |
   |-- record intent -->|
   |                    |
   |<-- events returned |
   |                    |
   | (no minting here)  |-- validate --┐
   |                    |              |
   |                    |<- validate ->|-- mint
   |                    |
   |<-- emit events ----|
```

### Contract Responsibilities

1. **Record Intent** (contract)
   - Receive user requests
   - Minimal validation (no state-changing decisions)
   - Emit intent event for Kernel to process

2. **Process Asynchronously** (Kernel)
   - Poll for intent events at epoch boundaries
   - Validate using comprehensive rules
   - Mint/execute only if validation passes
   - Emit results for governance audit trail

### Example: UBI Distribution Flow

```rust
// Step 1: Citizen records intent (UBI contract)
ubi_contract.record_claim_intent(citizen_id, amount, epoch)?;
// → Emits UbiClaimRecorded event

// Step 2: Kernel processes at epoch boundary (Treasury Kernel)
kernel.process_ubi_distributions(block_height, executor)?;
// → Polls UbiClaimRecorded events
// → Validates each claim (5 checks)
// → Mints or rejects each claim
// → Emits UbiDistributed or UbiClaimRejected
// → Emits UbiPoolStatus summary

// Step 3: Governance monitors events (any contract)
let stats = kernel.get_processing_stats();
// → See success/rejection rates
// → Audit why claims were rejected
```

## Integration Steps for New Clients

### Step 1: Define Intent Event

Create an intent event that captures the user's request:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompensationClaimRecorded {
    pub worker_id: [u8; 32],
    pub work_proof_id: [u8; 32],  // Link to completed work
    pub amount_requested: u64,     // SOV requested
    pub epoch: u64,
    pub timestamp: u64,            // Will be filled by executor
}
```

### Step 2: Implement Intent Recording

Make it super minimal - just event recording:

```rust
pub fn record_compensation_claim(
    &mut self,
    worker_id: [u8; 32],
    work_proof_id: [u8; 32],
    amount_requested: u64,
    epoch: u64,
) -> Result<(), Error> {
    // Minimal validation: amount must be positive
    if amount_requested == 0 {
        return Err(Error::ZeroAmount);
    }

    let event = CompensationClaimRecorded {
        worker_id,
        work_proof_id,
        amount_requested,
        epoch,
        timestamp: 0, // Executor sets this
    };

    // Store for Kernel to query
    self.claim_events
        .entry(epoch)
        .or_insert_with(Vec::new)
        .push(event);

    Ok(())
}
```

### Step 3: Implement Query Method

Kernel needs to retrieve all claims for processing:

```rust
pub fn query_compensation_claims(&self, epoch: u64) -> Vec<CompensationClaimRecorded> {
    self.claim_events
        .get(&epoch)
        .cloned()
        .unwrap_or_default()
}
```

### Step 4: Extend Treasury Kernel

Add validation and minting methods to Kernel:

```rust
impl TreasuryKernel {
    pub fn process_compensation_distributions(
        &mut self,
        current_height: u64,
        compensation_contract: &CompensationContract,
        work_registry: &WorkRegistry,
        executor: &mut ContractExecutor,
    ) -> Result<u64> {
        let current_epoch = self.current_epoch(current_height);
        let claims = compensation_contract.query_compensation_claims(current_epoch);

        let mut successes = 0;
        for claim in claims {
            match self.validate_compensation_claim(&claim, work_registry, current_epoch) {
                Ok(_) => {
                    self.mint_compensation(&claim, executor)?;
                    successes += 1;
                }
                Err(reason) => {
                    self.emit_compensation_rejected(&claim, reason)?;
                }
            }
        }

        Ok(successes)
    }
}
```

## Validation Best Practices

### Keep Validation Deterministic

Validation rules must be **identical on all validators**:

✅ **Good**: Check if citizen is in registry (same data on all nodes)
❌ **Bad**: Generate random rejection, check system time

### Validate at Kernel, Not Contract

- ❌ Don't: Have contract validate everything before recording
- ✅ Do: Contract records intent, Kernel validates comprehensively

This separation ensures:
- Consistent validation across validators
- Clear authority boundaries
- Easy audit trail of decisions

### Order Checks by Impact

Run cheaper checks before expensive ones:

```
1. Existence check (O(1) lookup)
2. Status check (O(1) field read)
3. Eligibility check (O(1) comparison)
4. Dedup check (O(1) map lookup)
5. Capacity check (O(1) addition)
```

## Event Emission Patterns

### Success Event

Emitted when validation passes and minting succeeds:

```rust
pub struct CompensationMinted {
    pub worker_id: [u8; 32],
    pub work_proof_id: [u8; 32],
    pub amount: u64,
    pub epoch: u64,
    pub kernel_txid: [u8; 32],  // Deterministic ID
}
```

### Rejection Event

Emitted when validation fails (reason is NOT shown to user):

```rust
pub struct CompensationRejected {
    pub worker_id: [u8; 32],
    pub epoch: u64,
    pub reason_code: u8,     // 1-5 internally
    pub timestamp: u64,       // Block height
}
```

Reason codes should be:
- Deterministic (same inputs → same code)
- Consistent across validators (use enum repr)
- Privacy-preserving (no details to user)

## Crash Recovery Guarantees

### Critical: Dedup Must Survive Crashes

The Kernel persists dedup state to prevent double-minting:

```rust
// Kernel state includes:
pub struct KernelState {
    pub already_claimed: HashMap<[u8; 32], HashMap<u64, bool>>,
    pub last_processed_epoch: Option<u64>,
    // ... more state
}
```

After crash recovery:
1. Kernel loads persisted state
2. Dedup map is intact
3. Reprocessing claims finds them already marked claimed
4. Double-minting is prevented

**Your contract must not validate dedup** - Kernel owns this.

## Security Model

### Minting Authority

Only the Kernel can mint tokens:

```rust
pub fn verify_minting_authority(
    caller: &PublicKey,
    kernel_address: &PublicKey,
) -> Result<(), String> {
    if caller == kernel_address {
        Ok(())
    } else {
        Err("Only Treasury Kernel can mint tokens".to_string())
    }
}
```

No exceptions. No delegation. No workarounds.

### Silent Failures

Rejected claims don't tell the user why (privacy):

```
User submits claim
↓
Kernel validates in silence
↓
Success: User gets tokens ✓
Rejection: User gets nothing (no explanation)
↓
Governance can audit why in events
```

This prevents:
- Information leakage about governance rules
- Social engineering ("fix my revocation")
- Gaming the system ("retry another way")

### Deterministic Transaction IDs

All minting operations produce deterministic transaction IDs:

```rust
let kernel_txid = KernelState::compute_kernel_txid(
    &worker_id,
    epoch,
    amount
);
```

Benefits:
- **Idempotency**: Replaying same operation produces same ID
- **Recovery**: Restarting doesn't create duplicate transactions
- **Auditability**: Every mint is traceable to specific worker/epoch/amount

## Testing Your Integration

### Unit Tests

Test intent recording independently:

```rust
#[test]
fn test_record_compensation_claim() {
    let mut contract = CompensationContract::new();
    contract.record_compensation_claim([1u8; 32], [2u8; 32], 1000, 100)?;

    let claims = contract.query_compensation_claims(100);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].amount_requested, 1000);
}
```

### Integration Tests

Test with Kernel validation:

```rust
#[test]
fn test_compensation_distribution_flow() {
    let mut kernel = TreasuryKernel::new(...);
    let mut contract = CompensationContract::new();
    let mut work_registry = WorkRegistry::new();

    // Register completed work
    work_registry.record_work([1u8; 32], 100)?;

    // Record claim
    contract.record_compensation_claim([1u8; 32], [2u8; 32], 1000, 100)?;

    // Process distribution
    kernel.process_compensation_distributions(60480, &contract, &work_registry, &executor)?;

    // Verify result
    let stats = kernel.get_processing_stats();
    assert_eq!(stats.total_claims_processed, 1);
}
```

### Crash Recovery Tests

Verify dedup prevents double-mint:

```rust
#[test]
fn test_crash_recovery_prevents_double_mint() {
    let mut kernel = TreasuryKernel::new(...);
    let mut contract = CompensationContract::new();

    // First processing
    contract.record_compensation_claim([1u8; 32], [2u8; 32], 1000, 100)?;
    kernel.process_compensation_distributions(60480, &contract, ...)?;

    // Simulate crash and recovery
    let bytes = kernel.state().to_bytes()?;
    let mut recovered = TreasuryKernel::from_bytes(&bytes)?;

    // Second processing (claim replayed)
    contract.record_compensation_claim([1u8; 32], [2u8; 32], 1000, 100)?;
    let (successes, rejections) = recovered.process_compensation_distributions(...)?;

    // Second claim should be rejected (already claimed)
    assert_eq!(rejections, 1);
}
```

## Performance Expectations

Based on Phase 1 UBI implementation:

| Operation | Time | Notes |
|-----------|------|-------|
| Process 1000 claims | <5s | Requirement from plan |
| Serialize 1000 citizen state | <100ms | bincode determinism |
| Deserialize and recover | <100ms | Quick crash recovery |
| Dedup lookup (1M checks) | <1s | Constant-time hash lookups |
| Pool tracking (500 checks) | <100ms | Simple arithmetic |

Scale up costs linearly with claim volume.

## API Reference

### TreasuryKernel Methods

```rust
// State access
pub fn state(&self) -> &KernelState
pub fn state_mut(&mut self) -> &mut KernelState

// Epoch calculation
pub fn current_epoch(&self, block_height: u64) -> u64

// Statistics
pub fn get_stats(&self) -> KernelStats

// Recovery
pub fn resume_after_crash(&mut self, block_height: u64) -> Result<()>
```

### KernelState Methods (for validation)

```rust
// Dedup
pub fn has_claimed(&self, citizen_id: &[u8; 32], epoch: u64) -> bool
pub fn mark_claimed(&mut self, citizen_id: [u8; 32], epoch: u64)

// Pool tracking
pub fn get_distributed(&self, epoch: u64) -> u64
pub fn check_pool_capacity(&self, epoch: u64, amount: u64) -> bool
pub fn add_distributed(&mut self, epoch: u64, amount: u64) -> Result<()>

// Statistics
pub fn record_success(&mut self)
pub fn record_rejection(&mut self, reason: RejectionReason)

// Persistence
pub fn to_bytes(&self) -> Result<Vec<u8>>
pub fn from_bytes(data: &[u8]) -> Result<Self>
pub fn is_valid(&self) -> bool
pub fn needs_recovery(&self, current_epoch: u64) -> bool
```

## Conclusion

The Treasury Kernel provides:
- ✅ Exclusive minting authority
- ✅ Deterministic validation
- ✅ Crash recovery guarantees
- ✅ Complete audit trail
- ✅ Privacy-preserving rejections
- ✅ Sub-5-second performance

By following the passive client pattern, your contract can safely integrate with the Kernel and leverage these guarantees.
