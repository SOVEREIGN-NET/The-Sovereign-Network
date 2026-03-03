# Fee Model v2 Architecture (FEES-15)

## Overview

The ZHTP Fee Model v2 provides pure, deterministic fee computation for all transaction types. The design follows the "types in lib-types, behavior in domain crates" architecture pattern.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT CODE                                     │
│  (Transaction builders, wallets, dApps)                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FEE ESTIMATION API                                 │
│  (lib-fees)                                                                   │
│  • estimate_native_transfer_fee()                                            │
│  • estimate_token_transfer_fee()                                             │
│  • estimate_contract_call_fee()                                              │
│  • estimate_fee_range()                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FEE COMPUTATION ENGINE                               │
│  (lib-fees::model_v2)                                                         │
│                                                                               │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │  FeeInput       │───▶│  compute_fee_v2 │───▶│  FeeResult      │          │
│  │  (tx metadata)  │    │  (pure function)│    │  (u64 fee)      │          │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
│           │                      │                      │                    │
│           ▼                      ▼                      ▼                    │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │ TxKindExt       │    │ FeeInputExt     │    │ verify_fee()    │          │
│  │ SigSchemeExt    │    │                 │    │                 │          │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│   PURE DATA TYPES     │  │   PURE DATA TYPES     │  │   BLOCKCHAIN STATE    │
│   (lib-types::fees)   │  │   (lib-types::fees)   │  │   (lib-blockchain)    │
│                       │  │                       │  │                       │
│   TxKind              │  │   FeeParams           │  │   Governance          │
│   ├─ NativeTransfer   │  │   ├─ base_fee_per_byte│  │   Parameters          │
│   ├─ TokenTransfer    │  │   ├─ fee_per_exec_unit│  │                       │
│   ├─ ContractCall     │  │   ├─ fee_per_state_*  │  │   FeeParams::from_    │
│   ├─ DataUpload       │  │   ├─ fee_per_signature│  │   blockchain()        │
│   ├─ Governance       │  │   ├─ minimum_fee      │  │                       │
│   ├─ Staking          │  │   ├─ maximum_fee      │  │   Validation:         │
│   ├─ Unstaking        │  │   └─ validate()       │  │   min < max, etc.     │
│   ├─ ValidatorReg     │  │                       │  │                       │
│   └─ ValidatorExit    │  │   FeeDeficit          │  │                       │
│                       │  │   FeeInput            │  │                       │
│   SigScheme           │  │                       │  │                       │
│   ├─ Ed25519          │  │   SigScheme           │  │                       │
│   ├─ Dilithium5       │  │                       │  │                       │
│   └─ Hybrid           │  │                       │  │                       │
└───────────────────────┘  └───────────────────────┘  └───────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLOCK EXECUTOR INTEGRATION                           │
│  (lib-blockchain::execution)                                                  │
│                                                                               │
│  Transaction Validation:                                                      │
│  ```rust                                                                      │
│  let required = compute_fee_v2(&input, &params);                              │
│  if tx.fee < required {                                                       │
│      return Err(FeeDeficit { ... });                                          │
│  }                                                                            │
│  ```                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### lib-types::fees

**Purpose**: Canonical location for all fee-related pure data types.

**Types**:
- `TxKind` - Transaction classification enum
- `SigScheme` - Signature scheme enum  
- `FeeParams` - Governance-set fee parameters
- `FeeInput` - Transaction-derived input for fee calculation
- `FeeDeficit` - Error type for insufficient fees
- `FeeParamsError` - Validation error types

**Invariants**:
- All types are `Serialize + Deserialize`
- All types are `Clone + PartialEq + Eq`
- No fee computation or domain-level business rules; only data types and lightweight, side-effect-free validation helpers (e.g., `FeeParams::validate()`)

### lib-fees

**Purpose**: Fee computation logic and behavior.

**Key Functions**:
- `compute_fee_v2()` - Pure fee computation
- `verify_fee()` - Fee verification with deficit reporting
- `estimate_*_fee()` - Client-side fee estimation helpers

**Extension Traits**:
- `TxKindExt` - Per-transaction-type multipliers
- `SigSchemeExt` - Per-signature-scheme multipliers
- `FeeInputExt` - Helper methods for FeeInput

**Invariants**:
- All functions are pure (no side effects)
- All arithmetic uses u128 internally to prevent overflow
- Results are deterministic across all platforms

## Fee Calculation Flow

```
Transaction
    │
    ▼
┌─────────────────┐
│  Extract        │
│  FeeInput       │
│  from tx        │
└─────────────────┘
    │
    ▼
┌─────────────────┐     ┌─────────────────┐
│  Load           │────▶│  Validate       │
│  FeeParams      │     │  FeeParams      │
│  from gov       │     │  (min < max)    │
└─────────────────┘     └─────────────────┘
    │                           │
    │                           ▼
    │                   ┌─────────────────┐
    │                   │  Invalid?       │
    │                   │  Use defaults   │
    │                   └─────────────────┘
    │                           │
    └───────────────────────────┘
    │
    ▼
┌─────────────────┐
│  compute_fee_v2 │
│  (pure function)│
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  Compare with   │
│  tx.fee         │
└─────────────────┘
    │
    ├── tx.fee >= required ──▶ ACCEPT
    │
    └── tx.fee < required ───▶ REJECT (FeeDeficit)
```

## Governance Integration

Fee parameters can be updated through governance proposals:

```rust
// In governance execution handler
pub fn update_fee_params(blockchain: &mut Blockchain, new_params: FeeParams) -> Result<(), Error> {
    // Validate new parameters
    new_params.validate()?;
    
    // Update blockchain state
    blockchain.fee_params = new_params;
    
    Ok(())
}
```

## Testing Strategy

1. **Golden Vector Tests** - Fixed input/output pairs for regression detection
2. **Property-Based Tests** - Monotonicity, overflow safety
3. **Benchmarks** - Performance regression detection
4. **Integration Tests** - BlockExecutor fee validation

## See Also

- [Fee Model Specification](./SPEC.md) - Detailed fee calculation formulas
- [lib-fees documentation](../../lib-fees/src/lib.rs) - API documentation
- [lib-types fees documentation](../../lib-types/src/fees.rs) - Type definitions
