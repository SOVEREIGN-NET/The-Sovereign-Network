# lib-fees Deep Audit Report
## Branch: development (commit 0d7245d3)
## Date: 2026-02-28
## Scope: Hardcoded values, stubs, TODOs, errors, bugs, garbage code

---

## Executive Summary

| Category | Count | Assessment |
|----------|-------|------------|
| Hardcoded Fee Parameters | 18 | Should be governance-configurable |
| TODO/FIXME Comments | 0 | ✅ Clean |
| Stub Implementations | 0 | ✅ Clean |
| Dangerous unwrap/expect | 0 | ✅ Clean (tests only) |
| unsafe blocks | 0 | ✅ Clean |
| Code Quality | Excellent | Well-designed crate |

**Overall Assessment:** lib-fees is a well-designed, clean crate with excellent practices. The only issues are hardcoded parameters that should be governance-configurable.

---

## 🟡 FINDINGS (Minor Improvements)

### 1. Hardcoded Fee Parameters in FeeParams::default()
**Location:** `model_v2.rs:193-206`

**Current Code:**
```rust
impl Default for FeeParams {
    fn default() -> Self {
        Self {
            base_fee_per_byte: 1,
            fee_per_exec_unit: 10,
            fee_per_state_read: 100,
            fee_per_state_write: 500,
            fee_per_state_write_byte: 10,
            fee_per_signature: 1_000,
            minimum_fee: 1_000,
            maximum_fee: 1_000_000_000,
        }
    }
}
```

**Issue:** All fee parameters are hardcoded. Cannot adjust without code changes.

**Recommendation:** Make FeeParams load from blockchain governance state.

---

### 2. Hardcoded Witness Caps
**Location:** `model_v2.rs:43-50`

**Current Code:**
```rust
pub const fn witness_cap(self) -> u32 {
    match self {
        TxKind::NativeTransfer => 1_024,      // 1KB
        TxKind::TokenTransfer => 2_048,       // 2KB
        TxKind::ContractCall => 65_536,       // 64KB
        TxKind::DataUpload => 131_072,        // 128KB
        TxKind::Governance => 4_096,          // 4KB
    }
}
```

**Issue:** Witness size caps are hardcoded. May need adjustment for different network conditions.

---

### 3. Hardcoded Transaction Kind Multipliers
**Location:** `model_v2.rs:56-64`

**Current Code:**
```rust
pub const fn base_multiplier_bps(self) -> u32 {
    match self {
        TxKind::NativeTransfer => 10_000,   // 1.0x
        TxKind::TokenTransfer => 12_000,    // 1.2x
        TxKind::ContractCall => 15_000,     // 1.5x
        TxKind::DataUpload => 20_000,       // 2.0x
        TxKind::Governance => 5_000,        // 0.5x
    }
}
```

**Issue:** Multipliers are hardcoded. Cannot adjust fee structure without code changes.

---

### 4. Hardcoded Signature Scheme Multipliers
**Location:** `model_v2.rs:87-93`

**Current Code:**
```rust
pub const fn size_multiplier_bps(self) -> u32 {
    match self {
        SigScheme::Ed25519 => 10_000,     // 1.0x
        SigScheme::Dilithium5 => 50_000,  // 5.0x
        SigScheme::Hybrid => 55_000,      // 5.5x
    }
}
```

**Issue:** Signature scheme cost multipliers are hardcoded.

---

### 5. Hardcoded Signature Sizes
**Location:** `model_v2.rs:96-103`

**Current Code:**
```rust
pub const fn signature_size(self) -> u32 {
    match self {
        SigScheme::Ed25519 => 64,
        SigScheme::Dilithium5 => 4_627,
        SigScheme::Hybrid => 4_691,  // 64 + 4627
    }
}
```

**Issue:** Signature sizes are hardcoded. May change with different implementations.

---

### 6. Limited Transaction Kinds
**Location:** `model_v2.rs:25-36`

**Current Code:**
```rust
pub enum TxKind {
    NativeTransfer = 0,
    TokenTransfer = 1,
    ContractCall = 2,
    DataUpload = 3,
    Governance = 4,
}
```

**Issue:** Only 5 transaction kinds. Missing: Staking, Unstaking, ValidatorRegistration, etc.

---

### 7. Testing Parameters Not Realistic
**Location:** `model_v2.rs:209-222`

**Current Code:**
```rust
pub fn for_testing() -> Self {
    Self {
        base_fee_per_byte: 1,
        fee_per_exec_unit: 1,
        fee_per_state_read: 1,
        fee_per_state_write: 1,
        fee_per_state_write_byte: 1,
        fee_per_signature: 1,
        minimum_fee: 0,
        maximum_fee: u64::MAX,
    }
}
```

**Issue:** Testing params have all-1 values which doesn't test realistic scenarios.

---

## ✅ POSITIVE FINDINGS

### 1. No unsafe Code
**Status:** ✅ Clean - No `unsafe` blocks found.

### 2. No unwrap/expect in Production Code
**Status:** ✅ Clean - All unwrap calls are in `#[cfg(test)]` modules.

### 3. No TODO/FIXME Comments
**Status:** ✅ Clean - No outstanding task markers.

### 4. Overflow-Safe Arithmetic
**Status:** ✅ Clean - Uses u128 intermediates and saturating arithmetic.

**Evidence:**
```rust
let byte_fee: u128 = total_bytes.saturating_mul(params.base_fee_per_byte as u128);
```

### 5. Pure Deterministic Function
**Status:** ✅ Clean - `compute_fee_v2` is pure with no side effects.

### 6. Comprehensive Golden Vector Tests
**Status:** ✅ Excellent - 14 golden vector tests ensure deterministic fees.

### 7. Well Documented
**Status:** ✅ Excellent - Every function has detailed documentation.

### 8. No Stubs or Placeholders
**Status:** ✅ Clean - All functions are fully implemented.

---

## 📊 CODE QUALITY METRICS

| Metric | Value | Assessment |
|--------|-------|------------|
| Total Lines | 1,174 | Small, focused crate |
| Test Coverage | Excellent | Golden vectors + unit tests |
| Documentation | Excellent | All public APIs documented |
| unsafe blocks | 0 | ✅ Safe |
| unwrap/expect (production) | 0 | ✅ Safe |
| unwrap/expect (tests) | ~20 | ✅ Acceptable |
| Hardcoded params | 18 | 🟡 Should be configurable |

---

## 🎯 RECOMMENDATIONS

### High Priority
1. **Add governance integration** - Load FeeParams from blockchain state
2. **Add more transaction kinds** - Staking, ValidatorRegistration, etc.

### Medium Priority
3. **Document parameter rationale** - Why 1.0x, 1.2x, 1.5x multipliers?
4. **Add fee parameter validation** - Ensure minimum < maximum, etc.

### Low Priority
5. **Make testing params more realistic** - Use values closer to production
6. **Add fee estimation helpers** - Pre-compute fees for common transactions

---

## CONCLUSION

lib-fees is a **well-designed, production-ready crate** with excellent practices:

- ✅ Pure, deterministic fee computation
- ✅ No unsafe code
- ✅ No unwrap/expect in production
- ✅ Overflow-safe arithmetic
- ✅ Comprehensive golden vector tests
- ✅ Excellent documentation

The only improvements needed are:
1. Making parameters governance-configurable
2. Adding more transaction kinds

This is the highest quality crate among those audited.

---

*Report generated by automated analysis of lib-fees/src/*
