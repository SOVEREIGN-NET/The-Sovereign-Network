# Fee Model v2 Specification (FEES-16)

## Version
- **Version**: 2.0
- **Last Updated**: 2026-03-03
- **Status**: Production

## Overview

The ZHTP Fee Model v2 defines a deterministic, pure function for computing transaction fees based on resource consumption. All fees are calculated in integer arithmetic using u64/u128 types.

## Fee Formula

### Complete Formula

```
fee = clamp(adjusted_fee, minimum_fee, maximum_fee)

where:
    adjusted_fee = base_fee * kind_multiplier / 10000
    base_fee = byte_fee + exec_fee + state_fee + sig_fee
    
    byte_fee = total_bytes * base_fee_per_byte
    exec_fee = exec_units * fee_per_exec_unit
    state_fee = state_read_fee + state_write_fee + state_write_byte_fee
    state_read_fee = state_reads * fee_per_state_read
    state_write_fee = state_writes * fee_per_state_write
    state_write_byte_fee = state_write_bytes * fee_per_state_write_byte
    sig_fee = sig_count * fee_per_signature * sig_scheme_multiplier / 10000
    
    total_bytes = envelope_bytes + payload_bytes + effective_witness_bytes
    effective_witness_bytes = min(witness_bytes, witness_cap[kind])
```

### Parameter Definitions

#### FeeParams (Governance-Set)

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `base_fee_per_byte` | u64 | Fee per byte of transaction data | 1 |
| `fee_per_exec_unit` | u64 | Fee per VM execution unit | 10 |
| `fee_per_state_read` | u64 | Fee per state read operation | 100 |
| `fee_per_state_write` | u64 | Fee per state write operation | 500 |
| `fee_per_state_write_byte` | u64 | Fee per byte written to state | 10 |
| `fee_per_signature` | u64 | Base fee per signature | 1,000 |
| `minimum_fee` | u64 | Minimum fee for any transaction | 1,000 |
| `maximum_fee` | u64 | Maximum fee (sanity cap) | 1,000,000,000 |

#### FeeInput (Transaction-Derived)

| Parameter | Type | Description |
|-----------|------|-------------|
| `kind` | TxKind | Transaction type |
| `sig_scheme` | SigScheme | Signature scheme used |
| `sig_count` | u8 | Number of signatures |
| `envelope_bytes` | u32 | Transaction envelope size |
| `payload_bytes` | u32 | Transaction payload size |
| `witness_bytes` | u32 | Witness data size (will be capped) |
| `exec_units` | u32 | VM execution units |
| `state_reads` | u32 | Number of state reads |
| `state_writes` | u32 | Number of state writes |
| `state_write_bytes` | u32 | Total bytes written to state |

### Transaction Type Multipliers

#### Witness Caps (DoS Prevention)

| TxKind | Cap (bytes) | Rationale |
|--------|-------------|-----------|
| NativeTransfer | 1,024 | Simple Ed25519 signatures |
| TokenTransfer | 2,048 | Token proofs + signatures |
| ContractCall | 65,536 | Complex contract proofs |
| DataUpload | 131,072 | Large data proofs |
| Governance | 4,096 | Governance proofs |
| Staking | 2,048 | Delegation proofs |
| Unstaking | 2,048 | Withdrawal proofs |
| ValidatorRegistration | 4,096 | Validator key material |
| ValidatorExit | 2,048 | Exit proofs |

#### Base Multipliers (Complexity Adjustment)

| TxKind | Multiplier (bps) | Multiplier (x) | Rationale |
|--------|------------------|----------------|-----------|
| NativeTransfer | 10,000 | 1.0x | Baseline |
| TokenTransfer | 12,000 | 1.2x | Token validation |
| ContractCall | 15,000 | 1.5x | VM execution |
| DataUpload | 20,000 | 2.0x | Storage commitment |
| Governance | 5,000 | 0.5x | Subsidized |
| Staking | 12,000 | 1.2x | Delegation |
| Unstaking | 12,000 | 1.2x | Withdrawal |
| ValidatorRegistration | 13,000 | 1.3x | Key validation |
| ValidatorExit | 12,000 | 1.2x | Registry cleanup |

### Signature Scheme Multipliers

| SigScheme | Multiplier (bps) | Size (bytes) | Rationale |
|-----------|------------------|--------------|-----------|
| Ed25519 | 10,000 | 64 | Baseline |
| Dilithium5 | 50,000 | 4,627 | Post-quantum |
| Hybrid | 55,000 | 4,691 | Both schemes |

## Validation Rules

Fee parameters must satisfy:

1. `minimum_fee <= maximum_fee`
2. `base_fee_per_byte > 0`
3. `fee_per_state_read > 0`
4. `fee_per_state_write > 0`
5. `fee_per_state_write_byte > 0`
6. `fee_per_signature > 0`
7. `fee_per_exec_unit > 0`

## Examples

### Example 1: Simple Transfer

```rust
let input = FeeInput {
    kind: TxKind::NativeTransfer,
    sig_scheme: SigScheme::Ed25519,
    sig_count: 1,
    envelope_bytes: 100,
    payload_bytes: 32,
    witness_bytes: 64,
    exec_units: 0,
    state_reads: 2,
    state_writes: 2,
    state_write_bytes: 32,
};

let params = FeeParams::default();
let fee = compute_fee_v2(&input, &params);
// fee ≈ 2,400 units
```

Calculation:
- total_bytes = 100 + 32 + 64 = 196
- byte_fee = 196 * 1 = 196
- exec_fee = 0 * 10 = 0
- state_read_fee = 2 * 100 = 200
- state_write_fee = 2 * 500 = 1,000
- state_write_byte_fee = 32 * 10 = 320
- state_fee = 1,520
- sig_fee = 1 * 1,000 * 10000 / 10000 = 1,000
- base_fee = 196 + 0 + 1,520 + 1,000 = 2,716
- adjusted = 2,716 * 10000 / 10000 = 2,716
- clamped = max(2,716, 1,000) = 2,716

### Example 2: Contract Call

```rust
let input = FeeInput {
    kind: TxKind::ContractCall,
    sig_scheme: SigScheme::Dilithium5,
    sig_count: 1,
    envelope_bytes: 300,
    payload_bytes: 256,
    witness_bytes: 4627,
    exec_units: 1000,
    state_reads: 5,
    state_writes: 3,
    state_write_bytes: 128,
};

let params = FeeParams::default();
let fee = compute_fee_v2(&input, &params);
// fee ≈ 48,000 units
```

### Example 3: Data Upload

```rust
let input = FeeInput {
    kind: TxKind::DataUpload,
    sig_scheme: SigScheme::Hybrid,
    sig_count: 1,
    envelope_bytes: 1000,
    payload_bytes: 1024,
    witness_bytes: 4691,
    exec_units: 500,
    state_reads: 2,
    state_writes: 10,
    state_write_bytes: 1024,
};

let params = FeeParams::default();
let fee = compute_fee_v2(&input, &params);
// fee ≈ 115,000 units
```

## Overflow Safety

All arithmetic uses u128 internally:

```rust
// Use u128 internally to prevent overflow
let byte_fee: u128 = (total_bytes as u128)
    .saturating_mul(params.base_fee_per_byte as u128);

// Clamp to u64 range before conversion
let clamped: u128 = adjusted_fee.max(min_fee).min(max_fee);
clamped as u64  // Safe: clamped <= max_fee <= u64::MAX
```

## Determinism

The fee function is deterministic:

1. **Pure function**: Same inputs always produce same output
2. **No floating point**: All arithmetic is integer
3. **No external state**: Only uses FeeInput and FeeParams
4. **Cross-platform**: Identical results on all architectures

## Governance Updates

Fee parameters can be updated through governance:

1. Proposal submitted with new FeeParams
2. Proposal passes voting
3. New params validated (`FeeParams::validate()`)
4. Parameters activated at next epoch boundary

## Version History

- **v2.0** (2026-03-03): Current version
  - Added ValidatorRegistration and ValidatorExit TxKinds
  - Added FeeParams validation
  - Added fee estimation helpers
  - Added comprehensive documentation

- **v1.0** (2026-02-01): Initial release
  - Basic fee computation
  - Support for NativeTransfer, TokenTransfer, ContractCall, DataUpload, Governance

## References

- [Fee Model Architecture](./ARCHITECTURE.md)
- [lib-fees API](../../lib-fees/src/lib.rs)
- [lib-types fees](../../lib-types/src/fees.rs)
