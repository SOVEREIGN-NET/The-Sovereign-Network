# Other — plans

# Other — Plans Module Documentation

## Overview

The **Other — Plans** module is designed to address critical gaps in the implementation of the SOV token, particularly focusing on three main issues: UTXO amount extraction, treasury kernel integration for UBI minting, and automatic fee deduction from transactions. This documentation outlines the purpose of the module, its key components, and how it integrates with the broader codebase.

## Purpose

The module aims to enhance the functionality and reliability of the SOV token system by:

1. **Improving Treasury Balance Calculation**: By implementing accurate UTXO amount extraction.
2. **Integrating UBI Minting**: Ensuring that the treasury kernel can mint tokens as part of the UBI distribution process.
3. **Automating Fee Deduction**: Enforcing transaction fees to maintain the economic integrity of the token system.

## Key Components

### 1. UTXO Amount Extraction

#### Location
- **File**: `lib-blockchain/src/blockchain.rs`
- **Line**: 2759

#### Current Implementation
The current implementation uses a placeholder for treasury balance calculation, which does not accurately reflect the UTXO amounts due to privacy-preserving mechanisms.

#### Proposed Solution
Replace the placeholder with a call to the `TokenContract::balance_of()` method to retrieve the actual treasury balance.

```rust
pub fn get_treasury_balance(&self) -> u64 {
    if let Some(token) = &self.sov_token {
        token.balance_of(&self.treasury_pubkey)
    } else {
        0
    }
}
```

### 2. Treasury Kernel Phase 5 Integration

#### Location
- **File**: `lib-blockchain/src/contracts/treasury_kernel/ubi_engine.rs`

#### Current Implementation
The treasury kernel has the logic for UBI distribution but lacks the connection to the token minting process.

#### Proposed Solution
Modify the `process_ubi_claims()` method to include a call to `TokenContract::mint_kernel_only()` after validating claims.

```rust
pub fn process_ubi_claims(
    &mut self,
    claims: &[UbiClaimRecorded],
    citizen_registry: &CitizenRegistry,
    current_epoch: u64,
    token: &mut TokenContract,
    kernel_address: &PublicKey,
) -> Result<(u64, u64), KernelError> {
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
}
```

### 3. Fee Auto-Deduction

#### Location
- **Files**: Multiple files in `lib-blockchain/src/transaction/` and `lib-blockchain/src/blockchain.rs`

#### Current Implementation
While the fee field is implemented and validated, the actual deduction from the sender's balance is missing.

#### Proposed Solution
Add a `deduct_fee()` method to the `TokenContract` and call it during the transaction application phase.

```rust
pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<()> {
    // Verify sender has sufficient balance (amount + fee)
    let sender = self.get_sender_from_inputs(&tx.inputs)?;
    let total_required = self.calculate_output_total(&tx.outputs) + tx.fee;

    if self.get_balance(&sender) < total_required {
        return Err(InsufficientBalance);
    }

    // Deduct fee from sender
    self.debit_balance(&sender, tx.fee)?;
    self.pending_fees += tx.fee;

    // Process inputs/outputs as normal
    self.process_inputs(&tx.inputs)?;
    self.create_outputs(&tx.outputs)?;

    Ok(())
}
```

## Integration with the Codebase

The **Other — Plans** module interacts with several components of the codebase:

- **TokenContract**: The module relies on the `TokenContract` for balance queries and minting operations.
- **Treasury Kernel**: The treasury kernel is responsible for UBI distribution and must be integrated with the token minting process.
- **Transaction Processing**: The module modifies how transactions are applied to ensure that fees are deducted correctly.

### Call Graph

```mermaid
graph TD;
    A[apply_transaction()] --> B[deduct_fee()]
    A --> C[process_inputs()]
    A --> D[create_outputs()]
    E[process_ubi_claims()] --> F[mint_kernel_only()]
    E --> G[emit_ubi_distributed()]
```

## Implementation Order

1. **Fee Deduction**: Highest priority to ensure economic integrity.
2. **Treasury Kernel Minting**: Integrate UBI minting after fee deduction is in place.
3. **UTXO Cleanup**: Replace placeholder code with accurate balance queries.

## Testing Strategy

### Unit Tests
- Verify that fee deduction reduces the sender's balance.
- Ensure UBI minting increases the recipient's balance.
- Confirm that treasury balance queries return accurate amounts.

### Integration Tests
- Test the full transaction flow with fee deduction.
- Validate UBI distribution at epoch boundaries.

### Regression Tests
- Ensure existing transfer tests pass without issues.

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Fee deduction breaks existing transactions | High | Feature flag for gradual rollout |
| Minting authority bypass | Critical | Extensive testing of kernel authority |
| Balance inconsistency | Medium | Single source of truth via TokenContract |

## Success Criteria

1. After a transfer, the sender's balance should reflect the deduction of both the amount and the fee.
2. UBI minting should correctly increase the balance of recipients after each epoch.
3. Treasury balance queries should return accurate amounts without using placeholder values.

## Estimated Effort

| Task | Complexity | Estimate |
|------|------------|----------|
| Fee Deduction | Medium | 2-3 hours |
| Treasury Kernel Wiring | Medium | 2-3 hours |
| UTXO Cleanup | Low | 1 hour |
| Testing | Medium | 2-3 hours |
| **Total** | | **7-10 hours** |

## References

- `lib-blockchain/src/contracts/tokens/core.rs` - TokenContract implementation
- `lib-blockchain/src/contracts/treasury_kernel/` - Treasury Kernel module
- `lib-blockchain/src/contracts/economics/fee_router.rs` - Fee distribution logic

This documentation serves as a comprehensive guide for developers looking to understand and contribute to the **Other — Plans** module, ensuring clarity on its purpose, implementation, and integration within the broader codebase.