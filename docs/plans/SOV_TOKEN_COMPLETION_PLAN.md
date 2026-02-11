# SOV Token Completion Plan

## Executive Summary

This plan addresses three critical gaps in the SOV token implementation:

1. **UTXO Amount Extraction** - Treasury balance calculation uses placeholder
2. **Treasury Kernel Phase 5** - UBI minting not wired to token contract
3. **Fee Auto-Deduction** - Fees validated but not automatically deducted from transfers

---

## Issue 1: UTXO Amount Extraction

### Location
`lib-blockchain/src/blockchain.rs:2759`

### Current Code
```rust
if output.recipient.as_bytes() == treasury_pubkey.as_bytes() {
    // In a real ZK system, we'd need to decrypt the commitment
    // For now, we track balance separately
    // TODO: Implement proper UTXO amount extraction
    balance += 1; // Placeholder
}
```

### Analysis

The system uses **two parallel balance tracking mechanisms**:

1. **UTXO-based** (privacy-preserving): Amounts hidden behind Pedersen commitments
2. **Account-based** (TokenContract): `HashMap<PublicKey, u64>` with clear balances

**Root Cause**: The UTXO system was designed for ZK privacy, but treasury balance queries need clear amounts.

### Solution Options

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A: Use TokenContract** | Query `TokenContract::balance_of()` instead of scanning UTXOs | Simple, already works | Different source of truth |
| **B: Treasury-specific UTXOs** | Mark treasury UTXOs as non-private (clear amounts) | Consistent UTXO model | Breaks privacy uniformity |
| **C: Maintain separate ledger** | Track treasury balance in dedicated field | Fast queries | Sync complexity |

### Recommended: Option A

The TokenContract already tracks balances accurately. Replace UTXO scanning with:

```rust
pub fn get_treasury_balance(&self) -> u64 {
    // Use TokenContract as source of truth for treasury balance
    if let Some(token) = &self.sov_token {
        token.balance_of(&self.treasury_pubkey)
    } else {
        0
    }
}
```

### Implementation Steps

1. [ ] Add `sov_token: Option<TokenContract>` field to `Blockchain` struct
2. [ ] Initialize token contract reference during blockchain setup
3. [ ] Replace UTXO scanning in `get_treasury_balance()` with `token.balance_of()`
4. [ ] Remove the TODO placeholder code
5. [ ] Add test for treasury balance query consistency

### Files to Modify
- `lib-blockchain/src/blockchain.rs`

---

## Issue 2: Treasury Kernel Phase 5 Integration

### Location
`lib-blockchain/src/contracts/treasury_kernel/README.md:148-163`

### Current Code (ubi_engine.rs)
```rust
// In ubi_engine.rs process_ubi_claims()
// TODO: Call executor.get_or_load_sov()
// TODO: Call token.mint_kernel_only(&kernel_address, &recipient, 1000)
// TODO: Call self.emit_ubi_distributed(...)
```

### Analysis

The Treasury Kernel has **complete logic** for UBI distribution but the actual token minting is not wired:

- `KernelState::process_ubi_claims()` - Validates and processes claims
- `TokenContract::mint_kernel_only()` - Exists and works
- **Missing**: The connection between them

### Solution

Wire the Treasury Kernel to actually mint tokens via the TokenContract.

### Implementation Steps

1. [ ] Add `token: &mut TokenContract` parameter to `process_ubi_claims()`
2. [ ] Add `kernel_address: PublicKey` parameter for authority verification
3. [ ] Call `token.mint_kernel_only()` after successful validation
4. [ ] Emit `UbiDistributed` event after successful mint
5. [ ] Handle mint failures gracefully (don't panic, record error)
6. [ ] Update tests to verify actual minting occurs

### New Method Signature
```rust
pub fn process_ubi_claims(
    &mut self,
    claims: &[UbiClaimRecorded],
    citizen_registry: &CitizenRegistry,
    current_epoch: u64,
    token: &mut TokenContract,        // NEW
    kernel_address: &PublicKey,       // NEW
) -> Result<(u64, u64), KernelError>  // Changed return type
```

### Minting Integration
```rust
// After validation passes:
match token.mint_kernel_only(kernel_address, &recipient_pubkey, claim.amount) {
    Ok(()) => {
        self.record_success();
        self.emit_ubi_distributed(claim, current_epoch);
        successes += 1;
    }
    Err(e) => {
        self.record_mint_failure(claim, e);
        rejections += 1;
    }
}
```

### Files to Modify
- `lib-blockchain/src/contracts/treasury_kernel/ubi_engine.rs`
- `lib-blockchain/src/contracts/treasury_kernel/mod.rs` (integration point)
- `lib-blockchain/src/contracts/treasury_kernel/events.rs` (event emission)

---

## Issue 3: Fee Auto-Deduction

### Location
Multiple files in `lib-blockchain/src/transaction/` and `lib-blockchain/src/blockchain.rs`

### Current State

| Component | Status |
|-----------|--------|
| Fee field on Transaction | Implemented |
| Fee validation (min fee check) | Implemented |
| Fee calculation | Implemented |
| Fee collection at block finalization | Implemented |
| **Fee deduction from sender balance** | **NOT IMPLEMENTED** |
| Fee distribution (45/30/15/10) | Implemented |

### Analysis

The fee lifecycle has a gap:

```
1. User creates transaction with fee field    [OK]
2. Transaction validated (fee >= min_fee)     [OK]
3. Transaction included in block              [OK]
4. Block finalized                            [OK]
5. Fees collected from block                  [OK]
6. Fees distributed to pools                  [OK]

MISSING: Step between 2 and 3 where fee is DEDUCTED from sender's balance
```

### Why This Matters

Currently, fees are **declared** but not **enforced**:
- User can set `fee: 1000` but never actually lose 1000 tokens
- The fee collection sums `tx.fee` fields but doesn't debit accounts
- This is essentially "free" transactions

### Solution

Add fee deduction during transaction execution in the UTXO/balance update phase.

### Implementation Steps

1. [ ] Add `deduct_fee()` method to `TokenContract`
2. [ ] Call `deduct_fee()` during transaction application in `Blockchain::apply_transaction()`
3. [ ] Ensure fee deduction happens BEFORE outputs are created
4. [ ] Handle insufficient balance for fee (reject transaction)
5. [ ] Add fee deduction to transaction receipt
6. [ ] Update tests to verify fees are actually deducted

### Fee Deduction Logic
```rust
// In blockchain.rs apply_transaction() or similar:
pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<()> {
    // Skip fee deduction for system transactions
    if tx.inputs.is_empty() {
        return self.apply_system_transaction(tx);
    }

    // 1. Verify sender has sufficient balance (amount + fee)
    let sender = self.get_sender_from_inputs(&tx.inputs)?;
    let total_required = self.calculate_output_total(&tx.outputs) + tx.fee;

    if self.get_balance(&sender) < total_required {
        return Err(InsufficientBalance);
    }

    // 2. Deduct fee from sender
    self.debit_balance(&sender, tx.fee)?;

    // 3. Add fee to pending collection
    self.pending_fees += tx.fee;

    // 4. Process inputs/outputs as normal
    self.process_inputs(&tx.inputs)?;
    self.create_outputs(&tx.outputs)?;

    Ok(())
}
```

### Files to Modify
- `lib-blockchain/src/blockchain.rs` - Add fee deduction in `apply_transaction()`
- `lib-blockchain/src/contracts/tokens/core.rs` - Add `deduct_fee()` method
- `lib-blockchain/src/transaction/validation.rs` - Verify balance covers amount + fee

---

## Implementation Order

### Phase 1: Fee Deduction (Highest Priority)
**Why first**: Without this, the economic model doesn't work. Users can transact for free.

1. Add `deduct_fee()` to TokenContract
2. Wire fee deduction into transaction application
3. Test fee deduction works end-to-end

### Phase 2: Treasury Kernel Minting
**Why second**: UBI distribution is a core feature but needs working fees first.

1. Wire `mint_kernel_only()` into `process_ubi_claims()`
2. Add event emission
3. Integration test with actual minting

### Phase 3: UTXO Amount Extraction
**Why third**: This is mostly cleanup - the TokenContract already works.

1. Replace UTXO scanning with TokenContract query
2. Remove placeholder code
3. Document the balance tracking approach

---

## Testing Strategy

### Unit Tests
- [ ] Fee deduction reduces sender balance
- [ ] Fee deduction fails on insufficient balance
- [ ] UBI minting increases recipient balance
- [ ] Treasury balance query returns correct amount

### Integration Tests
- [ ] Full transaction flow with fee deduction
- [ ] UBI distribution at epoch boundary
- [ ] Fee collection and distribution (45/30/15/10)

### Regression Tests
- [ ] Existing transfer tests still pass
- [ ] System transactions (no fee) still work
- [ ] Genesis funding still works

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Fee deduction breaks existing txs | High | Feature flag, gradual rollout |
| Minting authority bypass | Critical | Extensive testing of kernel authority |
| Balance inconsistency | Medium | Single source of truth (TokenContract) |
| Performance regression | Low | Benchmark before/after |

---

## Success Criteria

1. **Fee Deduction**: After a transfer, sender balance = previous - amount - fee
2. **UBI Minting**: After epoch boundary, citizen balance increases by UBI amount
3. **Treasury Balance**: Query returns accurate balance without placeholder

---

## Estimated Effort

| Task | Complexity | Estimate |
|------|------------|----------|
| Fee Deduction | Medium | 2-3 hours |
| Treasury Kernel Wiring | Medium | 2-3 hours |
| UTXO Cleanup | Low | 1 hour |
| Testing | Medium | 2-3 hours |
| **Total** | | **7-10 hours** |

---

## References

- `lib-blockchain/src/contracts/tokens/core.rs` - TokenContract implementation
- `lib-blockchain/src/contracts/treasury_kernel/` - Treasury Kernel module
- `lib-blockchain/src/contracts/economics/fee_router.rs` - Fee distribution
- `lib-consensus/src/types/mod.rs` - FeeCollector trait
- `docs/adr/ADR-0017-execution-boundary-treasury-primacy.md` - Treasury architecture
