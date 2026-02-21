# SOV Reference Value (SRV) Specification

## Definition

**SRV<sub>t</sub>** is the protocol-defined internal valuation of 1 SOV expressed in USD terms for accounting, UBI distribution, DAO budgeting, and treasury reporting.

> **Important**: SRV is **NOT** a market price. It is a protocol-internal reference value.

---

## Core Formula (Phase 0 – Pre-Liquidity)

```
SRV_t = (Total_Committed_Value_t / Circulating_SOV_t) × Stability_Multiplier
```

### Variables

| Variable | Description |
|----------|-------------|
| **Total_Committed_Value<sub>t</sub>** | Total USD-equivalent value of smart contract obligations and treasury-indexed commitments |
| **Circulating_SOV<sub>t</sub>** | Total distributed and unlocked SOV |
| **Stability_Multiplier** | Governance-defined damping coefficient (0 < m ≤ 1) |

---

## Initialization Constants

### Supply Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SUPPLY` | 1,000,000,000,000 SOV | Maximum SOV supply cap |
| `CIRC_0` | 50,000,000 SOV | Initial circulating supply |
| `Base_Users` | 10,000 | Initial verified users |
| `Onboarding_Grant` | 5,000 SOV | SOV granted per user at sign-in |

### Initial Committed Value

```
Total_Committed_Value_0 = $1,090,000
```

### Initial SRV Calculation

```
SRV_0 = 1,090,000 / 50,000,000
SRV_0 = 0.0218 USD
```

**Result**: ~2.18 cents per SOV at genesis.

### Stability Multiplier

| Phase | Value | Description |
|-------|-------|-------------|
| Initial | `1.0` | No damping applied |
| Smoothing (optional) | `0.95` | 5% smoothing factor |

---

## Implementable Form

All values use integer arithmetic to guarantee determinism across nodes.
Units: `committed_value` in cents (USD × 100), `circulating_supply` in atomic
SOV units (10⁻⁸), `stability_multiplier` in basis points (10,000 = 1.00×),
`srv` output in atomic SOV units per cent of committed value.

### Rust Structure

```rust
/// Inputs required for SRV calculation (all integer, no floating point).
pub struct SRVInputs {
    /// Total committed value in USD cents (e.g. $1 000 000 → 100_000_000)
    pub committed_value_cents: u128,
    /// Circulating SOV supply in atomic units (10⁻⁸ SOV per unit)
    pub circulating_supply_atomic: u128,
    /// Governance-defined stability multiplier in basis points
    /// (10_000 = 1.00×, 9_000 = 0.90×, max 10_000)
    pub stability_multiplier_bps: u32,
}

impl SRVInputs {
    /// Calculate SRV in atomic units per cent of committed value.
    ///
    /// Formula (integer):
    ///   raw_srv = committed_value_cents * stability_multiplier_bps
    ///             / (circulating_supply_atomic * 10_000)
    pub fn calculate_srv(&self) -> Result<u128, SRVError> {
        if self.circulating_supply_atomic == 0 {
            return Err(SRVError::InvalidCirculatingSupply);
        }
        if self.stability_multiplier_bps == 0 || self.stability_multiplier_bps > 10_000 {
            return Err(SRVError::InvalidStabilityMultiplier);
        }

        // Core formula — multiply before divide to preserve precision.
        let numerator = self.committed_value_cents
            .saturating_mul(self.stability_multiplier_bps as u128);
        let denominator = self.circulating_supply_atomic
            .saturating_mul(10_000);

        Ok(numerator / denominator)
    }
}
```

---

## Smoothing Rule (Recommended)

To prevent abrupt jumps in SRV, apply rate limiting using integer basis points:

```
SRV_t = SRV_(t-1) × (10_000 + clamp(delta_bps, -ε_bps, +ε_bps)) / 10_000

Where:
  delta_bps = (raw_SRV_t - SRV_(t-1)) * 10_000 / SRV_(t-1)
  ε_bps     = 100 (max 1% change per adjustment period)
```

### Rust Implementation

```rust
/// Apply smoothing to prevent SRV jumps (integer, basis-point arithmetic).
/// `max_change_bps`: ε expressed in basis points (e.g. 100 = 1%).
pub fn apply_smoothing(previous_srv: u128, raw_srv: u128, max_change_bps: i64) -> u128 {
    if previous_srv == 0 {
        return raw_srv;
    }
    let delta_bps = (raw_srv as i128 - previous_srv as i128)
        .saturating_mul(10_000)
        / previous_srv as i128;
    let clamped = delta_bps.clamp(-max_change_bps as i128, max_change_bps as i128);
    ((previous_srv as i128).saturating_mul(10_000 + clamped) / 10_000) as u128
}
```

---

## Economic Representation

### SRV Represents

- ✅ Internal accounting weight of 1 SOV
- ✅ Share of committed economic obligations
- ✅ Treasury-backed proportional claim
- ✅ System monetary base ratio

### SRV Does NOT Represent

- ❌ Executable trade price
- ❌ External liquidity valuation
- ❌ Speculative market price

---

## Required Data Feeds

To calculate SRV deterministically, the following inputs are required:

### 1. Real-Time Circulating SOV

| Component | Source |
|-----------|--------|
| Total distributed | Token contract state |
| Minus locked | Staking/vesting contracts |
| Minus burned | Token contract burn log |

### 2. Total Committed Value

| Component | Source |
|-----------|--------|
| Treasury asset valuation | Treasury Kernel |
| DAO allocations in USD | DAO Treasury contracts |
| Contractual obligations | Smart contract registry |

### 3. Governance Parameters

| Parameter | Update Mechanism |
|-----------|------------------|
| Stability_Multiplier | Governance proposal |
| Adjustment frequency | Governance proposal |

### 4. Adjustment Frequency Options

- **Daily**: 24-hour adjustment windows
- **Weekly**: 7-day adjustment windows
- **Block-based**: Every N blocks

> **Note**: Without these four inputs, SRV cannot be computed.

---

## Clean Initial State (Genesis Configuration)

```yaml
# Genesis SRV Configuration
srv_genesis:
  base_users: 10_000
  onboarding_grant_sov: 5_000
  committed_value_usd: 1_090_000
  stability_multiplier: 1.0
  initial_srv: 0.0218  # $0.0218 USD
  
# Update Policy
srv_updates:
  mode: "governance_only"  # Only governance can update
  smoothing_enabled: true
  max_change_per_period: 0.01  # 1%
  update_frequency: "weekly"
```

---

## Strategic Properties

This design ensures:

1. **Stability**: SRV changes are bounded and predictable
2. **Defensibility**: Math is transparent and auditable
3. **Coherence**: Narrative aligns with protocol economics
4. **Transition-Readiness**: Can evolve toward AMM integration later

---

## Governance Update Process

### SRV Update Proposal Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Proposal       │────▶│  Voting Period  │────▶│   Timelock      │
│  Creation       │     │  (7 days)       │     │   (2 days)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  SRV Update     │
                                               │  Execution      │
                                               └─────────────────┘
```

### Required Proposal Data

```rust
pub struct SRVUpdateProposal {
    /// New committed value in USD
    pub new_committed_value_usd: f64,
    /// New stability multiplier (if changed)
    pub new_stability_multiplier: Option<f64>,
    /// Rationale for the update
    pub rationale: String,
    /// Effective block height
    pub effective_height: u64,
}
```

---

## Integration Points

| System | SRV Usage |
|--------|-----------|
| **UBI Distribution** | Calculate per-citizen UBI amounts |
| **DAO Budgeting** | Internal accounting for DAO proposals |
| **Treasury Reporting** | USD-equivalent treasury valuations |
| **Fee Calculation** | Optional: dynamic fee adjustment |

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-02-20 | Initial SRV specification |

---

## See Also

- [Token Constants](../lib-blockchain/src/contracts/tokens/constants.rs)
- [DAO Treasury](../lib-blockchain/src/contracts/dao/dao_treasury.rs)
- [Governance Contract](../lib-blockchain/src/contracts/governance/governance.rs)
- [Treasury Kernel Interface](../lib-blockchain/src/contracts/treasury_kernel/interface.rs)
