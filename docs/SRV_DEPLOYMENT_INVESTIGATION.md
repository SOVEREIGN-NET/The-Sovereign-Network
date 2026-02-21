# SRV Contract Deployment Investigation

## Executive Summary

This document investigates optimal deployment locations for the **SOV Reference Value (SRV)** contract within The Sovereign Network codebase.

**Recommendation**: Deploy SRV as a **governance-parameterized state variable** within the existing Treasury Kernel infrastructure, rather than as a standalone contract.

---

## Deployment Options Analysis

### Option 1: Treasury Kernel Extension (RECOMMENDED)

**Location**: `lib-blockchain/src/contracts/treasury_kernel/`

#### Rationale

The Treasury Kernel is already the central authority for:
- UBI distribution calculations
- Treasury balance mutations
- Governance-authorized mint/burn operations

#### Integration Points

| File | Purpose |
|------|---------|
| `lib-blockchain/src/contracts/treasury_kernel/state.rs` | Add SRV to kernel state |
| `lib-blockchain/src/contracts/treasury_kernel/governance_executor.rs` | Handle SRV update proposals |
| `lib-blockchain/src/contracts/treasury_kernel/interface.rs` | Extend interface for SRV queries |

#### Advantages

- ✅ Single source of truth for economic calculations
- ✅ Already has governance integration
- ✅ Direct access to circulating supply data
- ✅ Atomic updates with treasury operations
- ✅ No new contract deployment required

#### Implementation

```rust
// In lib-blockchain/src/contracts/treasury_kernel/state.rs

/// SRV Configuration and State
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRVState {
    /// Current SRV value in USD (8 decimal places for precision)
    pub current_srv: u64,  // e.g., 2180000 = $0.0218
    /// Total committed value in USD cents
    pub committed_value_usd: u64,
    /// Stability multiplier (basis points: 10000 = 1.0)
    pub stability_multiplier_bps: u16,
    /// Last update block height
    pub last_update_height: u64,
    /// Update history (last N updates)
    pub update_history: Vec<SRVUpdateRecord>,
}

impl SRVState {
    /// Calculate SRV from inputs
    pub fn calculate_srv(
        committed_value_usd: u64,
        circulating_supply_sov: u64,
        stability_multiplier_bps: u16,
    ) -> Result<u64, KernelOpError> {
        if circulating_supply_sov == 0 {
            return Err(KernelOpError::InsufficientBalance);
        }
        
        // SRV = (Committed_Value / Circulating_SOV) * Multiplier
        // Using integer math for determinism: result in cents (8 decimals)
        let raw_srv = (committed_value_usd as u128)
            .checked_mul(100_000_000) // Convert to 8 decimal precision
            .ok_or(KernelOpError::Overflow)?
            .checked_mul(stability_multiplier_bps as u128)
            .ok_or(KernelOpError::Overflow)?
            .checked_div(circulating_supply_sov as u128)
            .ok_or(KernelOpError::Overflow)?
            .checked_div(10_000) // Divide by basis points denominator
            .ok_or(KernelOpError::Overflow)?;
            
        Ok(raw_srv as u64)
    }
}
```

---

### Option 2: Standalone SRV Contract

**Location**: `lib-blockchain/src/contracts/srv/`

#### Rationale

A dedicated contract for SRV provides clean separation of concerns.

#### File Structure

```
lib-blockchain/src/contracts/
└── srv/
    ├── mod.rs          # Module exports
    ├── contract.rs     # Core SRV contract
    ├── governance.rs   # Governance integration
    └── types.rs        # SRV-specific types
```

#### Advantages

- ✅ Clean separation from treasury logic
- ✅ Can be upgraded independently
- ✅ Explicit governance interface

#### Disadvantages

- ❌ Additional contract to maintain
- ❌ Cross-contract calls for UBI calculations
- ❌ State synchronization complexity
- ❌ More complex genesis initialization

#### When to Consider

- If SRV logic becomes significantly complex
- If multiple token types need SRV-like valuation
- If external oracle integration is required

---

### Option 3: DAO Treasury Extension

**Location**: `lib-blockchain/src/contracts/dao/dao_treasury.rs`

#### Rationale

DAO Treasury already handles:
- Budget allocations
- Spending proposals
- USD-equivalent accounting

#### Advantages

- ✅ Natural fit for treasury-linked valuation
- ✅ Existing proposal flow

#### Disadvantages

- ❌ DAO Treasury is per-sector (5 DAOs)
- ❌ SRV should be network-wide, not DAO-specific
- ❌ Creates inconsistency across DAOs

#### Verdict

❌ **Not Recommended** - SRV must be global, not per-DAO.

---

### Option 4: Token Contract Extension

**Location**: `lib-blockchain/src/contracts/tokens/core.rs`

#### Rationale

SRV is fundamentally about SOV token valuation.

#### Advantages

- ✅ Close to token supply data
- ✅ Natural semantic fit

#### Disadvantages

- ❌ Token contract should remain simple (transfer/balance)
- ❌ Governance updates would require token contract governance
- ❌ Mixing accounting with token mechanics

#### Verdict

❌ **Not Recommended** - Violates separation of concerns.

---

## Recommended Implementation Plan

### Phase 1: Treasury Kernel Integration

1. **Add SRV types** to `treasury_kernel/types.rs`:
   - `SRVState`
   - `SRVUpdateRecord`
   - `SRVUpdateProposal`

2. **Add SRV state** to `treasury_kernel/state.rs`:
   - Initialize with genesis values
   - Store current SRV
   - Track update history

3. **Extend governance executor** in `treasury_kernel/governance_executor.rs`:
   - Handle `SRVUpdate` proposal type
   - Validate new SRV values
   - Apply smoothing rules

### Phase 2: Governance Integration

1. **Add SRV proposal type** to governance contract:
   ```rust
   pub enum ProposalPayload {
       // ... existing variants
       SRVUpdate(SRVUpdateProposal),
   }
   ```

2. **Create proposal validation**:
   - Verify committed value data sources
   - Validate stability multiplier range
   - Check against max change limits

### Phase 3: Consumption

1. **UBI Engine** uses SRV for calculations:
   ```rust
   // In treasury_kernel/ubi_engine.rs
   pub fn calculate_ubi_amount(
       &self,
       srv_state: &SRVState,
       recipient_status: &CitizenStatus,
   ) -> u64 {
       // Use SRV for USD-equivalent UBI calculations
   }
   ```

2. **Treasury reporting** exposes SRV:
   ```rust
   pub fn get_treasury_value_usd(&self, srv_state: &SRVState) -> u64 {
       self.sov_balance.saturating_mul(srv_state.current_srv) / 100_000_000
   }
   ```

---

## Genesis Configuration

```rust
// In blockchain genesis initialization
pub struct GenesisConfig {
    // ... existing fields
    
    /// Initial SRV configuration
    pub srv_config: SRVGenesisConfig,
}

pub struct SRVGenesisConfig {
    /// Initial committed value in USD cents
    pub initial_committed_value_usd: u64,  // $1,090,000 = 109000000
    /// Initial circulating supply (for calculation verification)
    pub initial_circulating_supply: u64,   // 50,000,000 SOV
    /// Initial stability multiplier (basis points)
    pub initial_stability_multiplier_bps: u16,  // 10000 = 1.0
    /// Resulting SRV value
    pub initial_srv: u64,  // 2180000 = $0.0218
}

impl Default for SRVGenesisConfig {
    fn default() -> Self {
        Self {
            initial_committed_value_usd: 109_000_000,  // $1,090,000
            initial_circulating_supply: 50_000_000_000_000_000,  // 50M SOV (8 decimals)
            initial_stability_multiplier_bps: 10_000,  // 1.0
            initial_srv: 2_180_000,  // $0.0218 (8 decimals)
        }
    }
}
```

---

## Governance Update Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SRV UPDATE WORKFLOW                              │
└─────────────────────────────────────────────────────────────────────────┘

  Citizen/Delegate
         │
         ▼
  ┌──────────────┐
  │ 1. Submit    │──▶ Requires: 100k CBE voting power
  │    Proposal  │
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ 2. Voting    │──▶ 7-day voting period
  │    Period    │──▶ 50% quorum required
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ 3. Finalize  │──▶ Check quorum + majority
  │    Voting    │
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ 4. Timelock  │──▶ 2-day delay
  │              │
  └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ 5. Execute   │──▶ Apply smoothing
  │    Update    │──▶ Record in history
  └──────────────┘    ──▶ Update SRV state
```

---

## Security Considerations

### 1. Deterministic Calculation

All SRV calculations must use **integer math only** to ensure cross-node consensus:

```rust
// ✅ CORRECT: Integer math
let srv = (committed_value * 100_000_000 * multiplier_bps)
    / (circulating_supply * 10_000);

// ❌ WRONG: Floating point
let srv = (committed_value as f64 / circulating_supply as f64) * multiplier;
```

### 2. Rate Limiting

Prevent governance attacks through smoothing:

```rust
pub fn validate_update(&self, proposed_srv: u64) -> Result<(), SRVError> {
    let max_change = self.current_srv / 100; // 1% max
    let diff = if proposed_srv > self.current_srv {
        proposed_srv - self.current_srv
    } else {
        self.current_srv - proposed_srv
    };
    
    if diff > max_change {
        return Err(SRVError::ChangeExceedsLimit);
    }
    Ok(())
}
```

### 3. Emergency Override

Include emergency pause mechanism:

```rust
pub struct SRVState {
    // ... fields
    pub emergency_paused: bool,
    pub pause_authority: [u8; 32],
}
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `lib-blockchain/src/contracts/treasury_kernel/types.rs` | Add SRV types |
| `lib-blockchain/src/contracts/treasury_kernel/state.rs` | Add SRV state management |
| `lib-blockchain/src/contracts/treasury_kernel/governance_executor.rs` | Add SRV proposal handling |
| `lib-blockchain/src/contracts/treasury_kernel/ubi_engine.rs` | Consume SRV for calculations |
| `lib-blockchain/src/contracts/governance/governance.rs` | Add SRV proposal category |
| `lib-blockchain/src/blockchain/genesis.rs` | Initialize SRV at genesis |

---

## Conclusion

The **Treasury Kernel Extension** approach is optimal because:

1. **Single Source of Truth**: SRV is inherently tied to treasury operations
2. **Existing Governance**: No new governance infrastructure needed
3. **Atomic Updates**: SRV changes can be bundled with treasury operations
4. **Minimal Complexity**: Leverages existing patterns and abstractions
5. **Deterministic**: Integer-math calculations ensure consensus

---

## Next Steps

1. ✅ Create SRV specification document (this PR)
2. 🔄 Implement SRV types in Treasury Kernel
3. ⏳ Add genesis configuration
4. ⏳ Implement governance proposal flow
5. ⏳ Integrate with UBI Engine
6. ⏳ Write comprehensive tests
