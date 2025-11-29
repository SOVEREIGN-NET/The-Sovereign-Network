# Treasury Economics Module

Complete documentation for DAO treasury management and welfare fund operations.

## Module Purpose

The `treasury_economics` module manages the DAO treasury, handling:
- DAO fee collection and allocation
- UBI distribution calculations
- Welfare fund management
- Treasury sustainability analysis
- Efficiency tracking

## Module Structure

```
treasury_economics/
├── mod.rs                      - Module exports and DaoTreasury
└── treasury_calculations.rs    - Treasury calculation functions (157 lines)
```

## DaoTreasury Structure

```rust
pub struct DaoTreasury {
    pub treasury_balance: u64,              // Current total balance
    pub ubi_allocated: u64,                 // Allocated for UBI (40%)
    pub welfare_allocated: u64,             // Allocated for welfare (30%)
    pub development_allocated: u64,         // Allocated for development (30%)
    pub total_dao_fees_collected: u64,      // Lifetime fees collected
    pub total_ubi_distributed: u64,         // Lifetime UBI distributed
    pub total_welfare_distributed: u64,     // Lifetime welfare distributed
    pub total_development_spent: u64,       // Lifetime development spent
}
```

## Fund Allocation Formula

Every DAO fee received is automatically allocated:

```rust
UBI:         40% of DAO fees
Welfare:     30% of DAO fees
Development: 30% of DAO fees
```

### Example
```
DAO fee received: 1000 ZHTP
    → UBI allocated:    400 ZHTP
    → Welfare allocated: 300 ZHTP
    → Development:      300 ZHTP
```

## Core Operations

### Receiving Fees

```rust
let mut treasury = DaoTreasury::new();
treasury.receive_dao_fee(200)?; // Receive 200 ZHTP from transaction
treasury.allocate_funds()?;      // Allocate to UBI/welfare/dev
```

### Calculating UBI

```rust
use lib_economy::treasury_economics::calculate_optimal_ubi_per_citizen;

let total_citizens = 10000;
let target_monthly_ubi = 1000; // Target 1000 ZHTP per citizen

let (actual_ubi, can_meet_target) = calculate_optimal_ubi_per_citizen(
    &treasury,
    total_citizens,
    target_monthly_ubi,
);

if can_meet_target {
    println!(" Full target UBI: {} ZHTP", actual_ubi);
} else {
    println!("⚠ Reduced UBI: {} ZHTP (insufficient funds)", actual_ubi);
}
```

### Tracking Efficiency

```rust
use lib_economy::treasury_economics::{
    calculate_ubi_efficiency,
    calculate_welfare_efficiency,
};

let ubi_efficiency = calculate_ubi_efficiency(&treasury);
let welfare_efficiency = calculate_welfare_efficiency(&treasury);

println!("UBI efficiency: {:.1}%", ubi_efficiency * 100.0);
println!("Welfare efficiency: {:.1}%", welfare_efficiency * 100.0);
```

### Sustainability Analysis

```rust
use lib_economy::treasury_economics::calculate_treasury_sustainability;

let monthly_burn = 100000; // 100k ZHTP per month expected
let metrics = calculate_treasury_sustainability(&treasury, monthly_burn);

println!("Sustainability: {}", serde_json::to_string_pretty(&metrics)?);
// Output: {"months_sustainable": 24, "status": "healthy", ...}
```

## Treasury Calculation Functions

### `calculate_optimal_ubi_per_citizen()`

```rust
pub fn calculate_optimal_ubi_per_citizen(
    treasury: &DaoTreasury,
    total_citizens: u64,
    target_monthly_ubi: u64
) -> (u64, bool)
```

Calculates the optimal UBI amount per citizen given current treasury state.

**Returns**: `(actual_ubi_per_citizen, can_meet_target)`

### `calculate_welfare_efficiency()`

```rust
pub fn calculate_welfare_efficiency(treasury: &DaoTreasury) -> f64
```

Calculates efficiency ratio: `distributed / expected`

Returns 0.0 to 1.0 (0% to 100%)

### `calculate_ubi_efficiency()`

```rust
pub fn calculate_ubi_efficiency(treasury: &DaoTreasury) -> f64
```

Calculates UBI distribution efficiency ratio.

### `calculate_treasury_sustainability()`

```rust
pub fn calculate_treasury_sustainability(
    treasury: &DaoTreasury,
    monthly_burn_rate: u64
) -> serde_json::Value
```

Returns JSON with:
- `months_sustainable`: How many months treasury can sustain current burn
- `allocation_ratio_percent`: % of treasury allocated
- `sustainability_status`: "healthy", "moderate", or "concerning"

### `calculate_ubi_funding_gap()`

```rust
pub fn calculate_ubi_funding_gap(
    treasury: &DaoTreasury,
    total_citizens: u64,
    target_monthly_ubi: u64
) -> Result<serde_json::Value>
```

Returns funding gap analysis and months to close gap.

## Complete Example

```rust
use lib_economy::{DaoTreasury, Transaction, Priority};
use lib_economy::treasury_economics::*;

fn monthly_treasury_cycle() -> anyhow::Result<()> {
    let mut treasury = DaoTreasury::new();
    
    // Simulate one month of transactions
    println!("=== Treasury Monthly Cycle ===\n");
    
    // Week 1: Collect fees
    for _ in 0..500 {
        treasury.receive_dao_fee(20)?;
    }
    treasury.allocate_funds()?;
    println!("Week 1: {} ZHTP collected", treasury.total_dao_fees_collected);
    
    // Week 2: More fees
    for _ in 0..750 {
        treasury.receive_dao_fee(20)?;
    }
    treasury.allocate_funds()?;
    println!("Week 2: {} ZHTP total collected", treasury.total_dao_fees_collected);
    
    // Calculate UBI distribution
    let citizens = 1000;
    let target_ubi = 1000;
    let (ubi_amount, can_meet) = calculate_optimal_ubi_per_citizen(
        &treasury,
        citizens,
        target_ubi,
    );
    
    println!("\n=== Month End Summary ===");
    println!("Total collected: {} ZHTP", treasury.total_dao_fees_collected);
    println!("UBI allocated (40%): {} ZHTP", treasury.ubi_allocated);
    println!("Welfare allocated (30%): {} ZHTP", treasury.welfare_allocated);
    println!("Development (30%): {} ZHTP", treasury.development_allocated);
    
    if can_meet {
        println!("\n Can provide full target UBI");
        println!("UBI per citizen ({} citizens): {} ZHTP", citizens, ubi_amount);
    } else {
        println!("\n⚠ Reduced UBI");
        println!("UBI per citizen ({} citizens): {} ZHTP", citizens, ubi_amount);
    }
    
    // Distribute UBI
    for _ in 0..citizens {
        treasury.distribute_ubi(ubi_amount)?;
    }
    
    println!("\n UBI distributed to {} citizens", citizens);
    println!("Remaining UBI allocation: {} ZHTP", treasury.ubi_allocated);
    
    // Check sustainability
    let sustainability = calculate_treasury_sustainability(&treasury, 100000);
    println!("\nSustainability: {}", serde_json::to_string_pretty(&sustainability)?);
    
    Ok(())
}
```

## Treasury States

### Healthy Treasury
- Months sustainable ≥ 12
- Efficiency ratios > 0.8
- Can meet target UBI

### Moderate Treasury
- Months sustainable 6-12
- Efficiency ratios 0.5-0.8
- May need reduced UBI

### Concerning Treasury
- Months sustainable < 6
- Efficiency ratios < 0.5
- Cannot meet target UBI

## Best Practices

1. **Regular Allocation**: Call `allocate_funds()` after every `receive_dao_fee()`
2. **Monitor Sustainability**: Check sustainability metrics monthly
3. **Adjust UBI**: Reduce UBI target if treasury becomes concerning
4. **Track Efficiency**: Monitor efficiency ratios to ensure proper distribution
5. **Audit Regularly**: Verify allocation percentages match expectations

## Related Documentation

- [Models](./models.md) - Economic model and DAO treasury implementation
- [API Reference](./API_REFERENCE.md#treasury-economics-module) - Complete API
- [Examples](./EXAMPLES.md#treasury-operations) - Usage examples
