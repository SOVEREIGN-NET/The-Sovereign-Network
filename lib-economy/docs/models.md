# Models Module Documentation

The `models` module contains core economic models and calculations for the Sovereign Network economy.

## Overview

The models module implements:
- **EconomicModel**: Core economic parameters and fee calculation
- **TokenReward**: Infrastructure service reward calculations  
- **DaoTreasury**: DAO treasury management and fund allocation

## Module Structure

```
models/
├── mod.rs              - Module organization
├── economic_model.rs   - Economic model implementation (197 lines)
├── token_reward.rs     - Token reward calculations (216 lines)
└── dao_treasury.rs     - Treasury management (Full)
```

---

## EconomicModel

### Purpose

Central economic model managing network-wide parameters including:
- Base rates for infrastructure services
- Fee calculation formulas
- Dynamic parameter adjustment
- DAO fee processing

### Structure

```rust
pub struct EconomicModel {
    pub base_routing_rate: u64,        // 1 SOV per MB
    pub base_storage_rate: u64,        // 10 SOV per GB
    pub base_compute_rate: u64,        // Minimal compute rate
    pub base_fee_per_byte: u64,        // Transaction fee per byte
    pub dao_fee_rate: u64,             // 200 (2%)
    pub quality_multiplier: f64,       // 0.5 (50% bonus)
    pub uptime_multiplier: f64,        // 0.3 (30% bonus)
}
```

### Default Values

```rust
EconomicModel {
    base_routing_rate: 1,              // 1 SOV per MB routed
    base_storage_rate: 10,             // 10 SOV per GB stored
    base_compute_rate: 1,              // 1 SOV per compute unit
    base_fee_per_byte: 1,              // 1 SOV per byte tx size
    dao_fee_rate: 200,                 // 2% (200 basis points)
    quality_multiplier: 0.5,           // 50% bonus for quality
    uptime_multiplier: 0.3,            // 30% bonus for uptime
}
```

### Methods

#### `new() -> Self`

Create economic model with default parameters.

```rust
let model = EconomicModel::new();
assert_eq!(model.dao_fee_rate, 200); // 2%
```

#### `adjust_parameters(&mut self, network_load: f64) -> Result<()>`

Dynamically adjust parameters based on network conditions.

**Parameters:**
- `network_load`: Network utilization (0.0 to 1.0)

**Behavior:**
- High load (> 0.8): Increase base rates 20%
- Normal load (0.3-0.8): Standard rates
- Low load (< 0.3): Decrease base rates 20%

**Example:**
```rust
let mut model = EconomicModel::new();

// High network load
model.adjust_parameters(0.85)?;
// base_routing_rate increased to 1.2

// Low network load  
model.adjust_parameters(0.25)?;
// base_routing_rate decreased to 0.8
```

#### `calculate_fee(&self, tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64)`

Calculate transaction fees.

**Returns:** `(base_fee, dao_fee, total_fee)`

**Formula:**
```rust
base_fee = tx_size * base_fee_per_byte * priority_multiplier
dao_fee = (amount * dao_fee_rate) / 10000
total_fee = base_fee + dao_fee
```

**Priority Multipliers:**
- `Low`: 0.5x
- `Normal`: 1.0x
- `High`: 2.0x
- `Urgent`: 5.0x

**Example:**
```rust
let model = EconomicModel::new();
let (base, dao, total) = model.calculate_fee(
    250,              // 250 bytes
    10000,           // 10000 SOV
    Priority::Normal
);
// base_fee = 250 SOV
// dao_fee = 200 SOV (2% of 10000)
// total_fee = 450 SOV
```

#### `process_network_fees(&self, base_fee: u64) -> Result<()>`

Process infrastructure fees (routing, storage, compute rewards).

#### `process_dao_fees(&mut self, dao_fee: u64) -> Result<()>`

Process DAO fees for treasury allocation.

---

## TokenReward

### Purpose

Calculate rewards for infrastructure services based on actual work performed.

### Structure

```rust
pub struct TokenReward {
    pub routing_reward: u64,      // Routing work rewards
    pub storage_reward: u64,      // Storage work rewards
    pub compute_reward: u64,      // Compute work rewards
    pub quality_bonus: u64,       // Quality bonus (>95% quality)
    pub uptime_bonus: u64,        // Uptime bonus (>99% uptime)
    pub total_reward: u64,        // Sum of all rewards
    pub currency: String,         // Always "SOV"
}
```

### Methods

#### `calculate(work: &WorkMetrics, model: &EconomicModel) -> Result<Self>`

Calculate comprehensive infrastructure rewards.

**Work Metrics:**
```rust
WorkMetrics {
    routing_work: u64,      // Bytes routed
    storage_work: u64,      // Bytes stored
    compute_work: u64,      // Compute units
    quality_score: f64,     // 0.0 to 1.0
    uptime_hours: u64,      // Hours of uptime
}
```

**Calculation:**
```rust
// Routing: 1 SOV per MB
routing_reward = (routing_work / 1_000_000) * base_routing_rate

// Storage: 10 SOV per GB per month
storage_reward = (storage_work / 1_000_000_000) * base_storage_rate

// Compute: Minimal processing fee
compute_reward = compute_work * base_compute_rate

// Quality bonus (>95% quality)
if quality_score > 0.95 {
    quality_bonus = (routing + storage + compute) * 0.5
} else {
    quality_bonus = 0
}

// Uptime bonus (>99% uptime = >23.76 hours/day)
if uptime_hours >= 24 && quality_score > 0.99 {
    uptime_bonus = (routing + storage + compute) * 0.3
} else {
    uptime_bonus = 0
}

total_reward = routing + storage + compute + quality_bonus + uptime_bonus
```

**Example:**
```rust
let work = WorkMetrics {
    routing_work: 5_000_000_000,    // 5 GB routed
    storage_work: 50_000_000_000,   // 50 GB stored
    compute_work: 100,               // 100 compute units
    quality_score: 0.96,            // 96% quality
    uptime_hours: 24,               // 24 hours
};

let model = EconomicModel::new();
let reward = TokenReward::calculate(&work, &model)?;

// Expected:
// routing_reward = 5000 SOV (5 GB * 1000 MB/GB * 1)
// storage_reward = 500 SOV (50 GB * 10)
// compute_reward = 100 SOV (100 * 1)
// quality_bonus = 2800 SOV ((5000+500+100) * 0.5)
// uptime_bonus = 1680 SOV ((5000+500+100) * 0.3)
// total_reward = 10080 SOV
```

#### `calculate_isp_bypass(work: &IspBypassWork) -> Result<Self>`

Calculate ISP replacement rewards.

**ISP Work Metrics:**
```rust
IspBypassWork {
    bandwidth_shared_gb: u64,    // GB bandwidth shared
    packets_routed_mb: u64,      // MB packets routed
    uptime_hours: u64,           // Hours online
    connection_quality: f64,     // 0.0 to 1.0
    users_served: u64,           // Number of users
}
```

**Calculation:**
```rust
// Bandwidth: 100 SOV per GB
bandwidth_reward = bandwidth_shared_gb * ISP_BYPASS_CONNECTIVITY_RATE

// Routing: 1 SOV per MB
routing_reward = packets_routed_mb * ISP_BYPASS_MESH_RATE

// Uptime: 10 SOV per hour
uptime_bonus = uptime_hours * ISP_BYPASS_UPTIME_BONUS

// Quality bonus (>90% quality)
if connection_quality > 0.9 {
    quality_bonus = (bandwidth + routing + uptime) * 0.5
} else {
    quality_bonus = 0
}

total_reward = bandwidth + routing + uptime + quality_bonus
```

**Example:**
```rust
let work = IspBypassWork {
    bandwidth_shared_gb: 100,        // 100 GB bandwidth
    packets_routed_mb: 5000,         // 5 GB packets
    uptime_hours: 24,                // 24 hours
    connection_quality: 0.95,        // 95% quality
    users_served: 10,                // 10 users
};

let reward = TokenReward::calculate_isp_bypass(&work)?;

// Expected:
// bandwidth_reward = 10000 SOV (100 * 100)
// routing_reward = 5000 SOV (5000 * 1)
// uptime_bonus = 240 SOV (24 * 10)
// quality_bonus = 7620 SOV ((10000+5000+240) * 0.5)
// total_reward = 22860 SOV
```

#### `combine(&mut self, other: &TokenReward)`

Combine multiple reward sources.

```rust
let mut reward1 = TokenReward::calculate(&work1, &model)?;
let reward2 = TokenReward::calculate(&work2, &model)?;

reward1.combine(&reward2);
// reward1 now contains sum of both rewards
```

---

## DaoTreasury

### Purpose

Manage DAO treasury operations including:
- Receiving DAO fees from transactions
- Allocating funds (40% UBI, 30% welfare, 30% development)
- Tracking distributions
- Calculating sustainability metrics

### Structure

```rust
pub struct DaoTreasury {
    pub treasury_balance: u64,              // Current balance
    pub ubi_allocated: u64,                 // Allocated for UBI
    pub welfare_allocated: u64,             // Allocated for welfare
    pub development_allocated: u64,         // Allocated for development
    pub total_dao_fees_collected: u64,      // Total fees collected
    pub total_ubi_distributed: u64,         // Total UBI distributed
    pub total_welfare_distributed: u64,     // Total welfare distributed
    pub total_development_spent: u64,       // Total development spent
}
```

### Methods

#### `new() -> Self`

Create new treasury with zero balances.

```rust
let treasury = DaoTreasury::new();
assert_eq!(treasury.treasury_balance, 0);
```

#### `receive_dao_fee(&mut self, amount: u64) -> Result<()>`

Receive DAO fee from transaction.

```rust
let mut treasury = DaoTreasury::new();
treasury.receive_dao_fee(100)?;
treasury.receive_dao_fee(200)?;
// total_dao_fees_collected = 300
// treasury_balance = 300
```

#### `allocate_funds(&mut self) -> Result<()>`

Allocate received fees according to allocation percentages.

**Allocation:**
- 40% to UBI
- 30% to Welfare
- 30% to Development

```rust
let mut treasury = DaoTreasury::new();
treasury.receive_dao_fee(1000)?;
treasury.allocate_funds()?;

// ubi_allocated = 400 (40% of 1000)
// welfare_allocated = 300 (30% of 1000)
// development_allocated = 300 (30% of 1000)
```

#### `calculate_ubi_per_citizen(&self, total_citizens: u64) -> u64`

Calculate UBI amount per citizen.

```rust
let treasury = DaoTreasury::new();
// ... receive and allocate fees ...
let ubi = treasury.calculate_ubi_per_citizen(1000);
// If ubi_allocated = 10000, ubi = 10 SOV per citizen
```

#### `distribute_ubi(&mut self, amount: u64) -> Result<()>`

Record UBI distribution.

```rust
treasury.distribute_ubi(1000)?;
// total_ubi_distributed += 1000
// ubi_allocated -= 1000
```

#### `distribute_welfare(&mut self, amount: u64) -> Result<()>`

Record welfare distribution.

```rust
treasury.distribute_welfare(500)?;
// total_welfare_distributed += 500
// welfare_allocated -= 500
```

---

## Economic Calculations

### Fee Transparency

Every transaction clearly shows fee breakdown:

```rust
let model = EconomicModel::new();
let (base_fee, dao_fee, total_fee) = model.calculate_fee(
    250,              // tx_size
    10000,           // amount
    Priority::Normal
);

println!("Base fee (infrastructure): {} SOV", base_fee);
println!("DAO fee (2% of amount): {} SOV", dao_fee);
println!("Total fee: {} SOV", total_fee);
```

### Dynamic Adjustment

Economic model adjusts to network conditions:

```rust
let mut model = EconomicModel::new();

// Monitor network load
let network_load = measure_network_utilization();

// Adjust parameters
model.adjust_parameters(network_load)?;

// Fees automatically adjust based on load
```

### Reward Fairness

Rewards are proportional to actual work:

```rust
// Small node
let small_work = WorkMetrics {
    routing_work: 100_000_000,    // 100 MB
    storage_work: 1_000_000_000,  // 1 GB
    ...
};
let small_reward = TokenReward::calculate(&small_work, &model)?;

// Large node
let large_work = WorkMetrics {
    routing_work: 10_000_000_000,  // 10 GB
    storage_work: 100_000_000_000, // 100 GB
    ...
};
let large_reward = TokenReward::calculate(&large_work, &model)?;

// large_reward ~= small_reward * 100
```

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_calculation() {
        let model = EconomicModel::new();
        let (base, dao, total) = model.calculate_fee(250, 10000, Priority::Normal);
        
        assert_eq!(dao, 200); // 2% of 10000
        assert_eq!(total, base + dao);
    }

    #[test]
    fn test_reward_calculation() {
        let work = WorkMetrics {
            routing_work: 1_000_000,
            storage_work: 1_000_000_000,
            compute_work: 10,
            quality_score: 0.95,
            uptime_hours: 24,
        };
        
        let model = EconomicModel::new();
        let reward = TokenReward::calculate(&work, &model).unwrap();
        
        assert!(reward.total_reward > 0);
    }

    #[test]
    fn test_treasury_allocation() {
        let mut treasury = DaoTreasury::new();
        treasury.receive_dao_fee(1000).unwrap();
        treasury.allocate_funds().unwrap();
        
        assert_eq!(treasury.ubi_allocated, 400);
        assert_eq!(treasury.welfare_allocated, 300);
        assert_eq!(treasury.development_allocated, 300);
    }
}
```

---

## Best Practices

### 1. Always Calculate Total Cost

```rust
// ✗ Wrong
let cost = amount;

//  Correct
let (_, _, fee) = model.calculate_fee(tx_size, amount, priority);
let cost = amount + fee;
```

### 2. Process DAO Fees Immediately

```rust
// After transaction
let (_, dao_fee, _) = model.calculate_fee(...);
treasury.receive_dao_fee(dao_fee)?;
treasury.allocate_funds()?;
```

### 3. Combine Rewards Periodically

```rust
// Accumulate daily rewards
let mut total_reward = TokenReward::default();

for hour in 0..24 {
    let hourly_work = measure_work();
    let hourly_reward = TokenReward::calculate(&hourly_work, &model)?;
    total_reward.combine(&hourly_reward);
}

// Distribute once per day
distribute_reward(total_reward)?;
```

---

## Integration

### With Blockchain

```rust
use lib_blockchain::Transaction as BlockchainTx;

// Create economic transaction
let tx = Transaction::new_payment(from, to, amount, Priority::Normal)?;

// Record on blockchain
let blockchain_tx = BlockchainTx {
    data: serialize(&tx)?,
    fees: tx.total_fee,
    dao_contribution: tx.dao_fee,
};
lib_blockchain::add_transaction(blockchain_tx)?;
```

### With Wallets

```rust
use lib_economy::MultiWalletManager;

// Calculate reward
let reward = TokenReward::calculate(&work, &model)?;

// Credit to rewards wallet
let mut manager = MultiWalletManager::new(identity)?;
let rewards_wallet = manager.get_wallet_by_type(WalletType::Rewards)?;
manager.deposit(rewards_wallet, reward.total_reward)?;
```

---

## Related Documentation

- [API Reference](./API_REFERENCE.md#models-module) - Complete API
- [Examples](./EXAMPLES.md#infrastructure-rewards) - Usage examples
- [Treasury Economics](./treasury_economics.md) - Treasury details
- [Transactions](./transactions.md) - Transaction system
