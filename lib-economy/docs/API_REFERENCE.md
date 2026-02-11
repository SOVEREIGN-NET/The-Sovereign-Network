# lib-economy API Reference

Complete API documentation for all public types, functions, and modules in lib-economy.

## Table of Contents

- [Economic Constants](#economic-constants)
- [Models Module](#models-module)
- [Wallets Module](#wallets-module)
- [Treasury Economics Module](#treasury-economics-module)
- [Transactions Module](#transactions-module)
- [Incentives Module](#incentives-module)
- [Supply Module](#supply-module)
- [Pricing Module](#pricing-module)
- [Types Module](#types-module)
- [Distribution Module](#distribution-module)
- [Rewards Module](#rewards-module)

---

## Economic Constants

### Fee and Rate Constants

```rust
/// Mandatory DAO fee rate (2% = 200 basis points)
pub const DEFAULT_DAO_FEE_RATE: u64 = 200;

///  connectivity reward (100 SOV per GB bandwidth)
pub const ISP_BYPASS_CONNECTIVITY_RATE: u64 = 100;

///  mesh routing reward (1 SOV per MB packets routed)
pub const ISP_BYPASS_MESH_RATE: u64 = 1;

///  uptime bonus (10 SOV per hour)
pub const ISP_BYPASS_UPTIME_BONUS: u64 = 10;

/// Minimum peers required for mesh connectivity rewards
pub const MESH_CONNECTIVITY_THRESHOLD: u32 = 3;

/// Minimum staking amount (1000 SOV)
pub const MIN_STAKING_AMOUNT: u64 = 1000;
```

### Treasury Allocation Constants

```rust
/// UBI allocation percentage (40% of DAO fees)
pub const UBI_ALLOCATION_PERCENTAGE: u64 = 40;

/// Welfare allocation percentage (30% of DAO fees)
pub const WELFARE_ALLOCATION_PERCENTAGE: u64 = 30;

/// Development allocation percentage (30% of DAO fees)
pub const DEVELOPMENT_ALLOCATION_PERCENTAGE: u64 = 30;
```

---

## Models Module

### EconomicModel

Core economic model managing network-wide economic parameters.

```rust
pub struct EconomicModel {
    pub base_routing_rate: u64,
    pub base_storage_rate: u64,
    pub base_compute_rate: u64,
    pub base_fee_per_byte: u64,
    pub dao_fee_rate: u64,
    pub quality_multiplier: f64,
    pub uptime_multiplier: f64,
}
```

#### Methods

##### `new() -> Self`
Create new economic model with default parameters.

**Example:**
```rust
let model = EconomicModel::new();
assert_eq!(model.dao_fee_rate, 200); // 2%
```

##### `adjust_parameters(&mut self, network_load: f64) -> Result<()>`
Adjust economic parameters based on network load.

**Parameters:**
- `network_load`: Network utilization (0.0 to 1.0)

**Returns:** `Result<()>`

**Example:**
```rust
let mut model = EconomicModel::new();
model.adjust_parameters(0.75)?; // 75% network load
```

##### `calculate_fee(&self, tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64)`
Calculate transaction fees (base fee, DAO fee, total fee).

**Parameters:**
- `tx_size`: Transaction size in bytes
- `amount`: Transaction amount in SOV
- `priority`: Transaction priority level

**Returns:** `(base_fee, dao_fee, total_fee)`

**Example:**
```rust
let model = EconomicModel::new();
let (base_fee, dao_fee, total_fee) = model.calculate_fee(
    250,                  // 250 bytes
    10000,               // 10000 SOV
    Priority::Normal
);
assert_eq!(dao_fee, 200); // 2% of 10000 = 200 SOV
```

##### `process_network_fees(&self, base_fee: u64) -> Result<()>`
Process network infrastructure fees.

**Parameters:**
- `base_fee`: Base fee amount

**Returns:** `Result<()>`

##### `process_dao_fees(&mut self, dao_fee: u64) -> Result<()>`
Process DAO fees for treasury allocation.

**Parameters:**
- `dao_fee`: DAO fee amount

**Returns:** `Result<()>`

### TokenReward

Token reward structure for infrastructure services.

```rust
pub struct TokenReward {
    pub routing_reward: u64,
    pub storage_reward: u64,
    pub compute_reward: u64,
    pub quality_bonus: u64,
    pub uptime_bonus: u64,
    pub total_reward: u64,
    pub currency: String,
}
```

#### Methods

##### `calculate(work: &WorkMetrics, model: &EconomicModel) -> Result<Self>`
Calculate comprehensive token rewards based on useful work.

**Parameters:**
- `work`: Work metrics (routing, storage, compute)
- `model`: Economic model for rates

**Returns:** `Result<TokenReward>`

**Example:**
```rust
let work = WorkMetrics {
    routing_work: 1_000_000_000,    // 1 GB routed
    storage_work: 10_000_000_000,   // 10 GB stored
    compute_work: 100,               // 100 compute units
    quality_score: 0.95,
    uptime_hours: 24,
};

let model = EconomicModel::new();
let reward = TokenReward::calculate(&work, &model)?;
println!("Total reward: {} SOV", reward.total_reward);
```

##### `calculate_isp_bypass(work: &IspBypassWork) -> Result<Self>`
Calculate  specific rewards.

**Parameters:**
- `work`:  work metrics

**Returns:** `Result<TokenReward>`

**Example:**
```rust
let work = IspBypassWork {
    bandwidth_shared_gb: 100,
    packets_routed_mb: 5000,
    uptime_hours: 23,
    connection_quality: 0.95,
    users_served: 10,
};

let reward = TokenReward::calculate_isp_bypass(&work)?;
```

##### `combine(&mut self, other: &TokenReward)`
Combine multiple reward sources.

**Parameters:**
- `other`: Another reward to combine

**Example:**
```rust
let mut reward1 = TokenReward::calculate(&work1, &model)?;
let reward2 = TokenReward::calculate(&work2, &model)?;
reward1.combine(&reward2);
```

### DaoTreasury

DAO treasury management structure.

```rust
pub struct DaoTreasury {
    pub treasury_balance: u64,
    pub ubi_allocated: u64,
    pub welfare_allocated: u64,
    pub development_allocated: u64,
    pub total_dao_fees_collected: u64,
    pub total_ubi_distributed: u64,
    pub total_welfare_distributed: u64,
    pub total_development_spent: u64,
}
```

#### Methods

##### `new() -> Self`
Create new DAO treasury with zero balances.

##### `receive_dao_fee(&mut self, amount: u64) -> Result<()>`
Receive DAO fee from transaction.

**Parameters:**
- `amount`: DAO fee amount

**Returns:** `Result<()>`

##### `allocate_funds(&mut self) -> Result<()>`
Allocate received fees to UBI, welfare, and development.

**Returns:** `Result<()>`

**Formula:**
```rust
ubi = received_fees * 40 / 100
welfare = received_fees * 30 / 100
development = received_fees * 30 / 100
```

##### `calculate_ubi_per_citizen(&self, total_citizens: u64) -> u64`
Calculate UBI amount per citizen.

**Parameters:**
- `total_citizens`: Total number of verified citizens

**Returns:** UBI per citizen in SOV

##### `distribute_ubi(&mut self, amount: u64) -> Result<()>`
Distribute UBI funds.

**Parameters:**
- `amount`: Amount to distribute

**Returns:** `Result<()>`

##### `distribute_welfare(&mut self, amount: u64) -> Result<()>`
Distribute welfare funds.

**Parameters:**
- `amount`: Amount to distribute

**Returns:** `Result<()>`

---

## Wallets Module

### WalletType

Enumeration of specialized wallet types.

```rust
pub enum WalletType {
    Personal,      // Daily spending
    Business,      // Business operations
    Investment,    // Long-term holdings
    Savings,       // Protected savings
    Rewards,       // Infrastructure rewards
    Staking,       // Network consensus
    Governance,    // DAO voting
    Escrow,        // Multi-party contracts
    Development,   // Development funding
    Donation,      // Charitable contributions
}
```

### Wallet

Individual wallet structure.

```rust
pub struct Wallet {
    pub wallet_id: [u8; 32],
    pub name: String,
    pub wallet_type: WalletType,
    pub balance: u64,
    pub owner_identity: [u8; 32],
    pub created_at: u64,
    pub last_activity: u64,
    pub transaction_count: u64,
    pub status: WalletStatus,
}
```

#### Methods

##### `new(name: &str, wallet_type: WalletType, owner: [u8; 32]) -> Self`
Create new wallet.

**Parameters:**
- `name`: Wallet name
- `wallet_type`: Type of wallet
- `owner`: Owner identity address

**Returns:** `Wallet`

##### `deposit(&mut self, amount: u64) -> Result<()>`
Deposit funds into wallet.

##### `withdraw(&mut self, amount: u64) -> Result<()>`
Withdraw funds from wallet.

##### `get_balance(&self) -> u64`
Get current wallet balance.

### MultiWalletManager

Manages multiple wallets for a single identity.

```rust
pub struct MultiWalletManager {
    pub identity_address: [u8; 32],
    pub wallets: Vec<Wallet>,
    pub default_wallet: Option<[u8; 32]>,
    pub total_balance: u64,
}
```

#### Methods

##### `new(identity_address: [u8; 32]) -> Result<Self>`
Create new multi-wallet manager for an identity.

**Example:**
```rust
let manager = MultiWalletManager::new(identity_address)?;
```

##### `create_wallet(&mut self, name: &str, wallet_type: WalletType) -> Result<[u8; 32]>`
Create a new wallet.

**Parameters:**
- `name`: Wallet name
- `wallet_type`: Type of wallet

**Returns:** `Result<wallet_id>`

**Example:**
```rust
let wallet_id = manager.create_wallet("My Personal Wallet", WalletType::Personal)?;
```

##### `get_wallet(&self, wallet_id: &[u8; 32]) -> Option<&Wallet>`
Get wallet by ID.

##### `get_wallet_mut(&mut self, wallet_id: &[u8; 32]) -> Option<&mut Wallet>`
Get mutable wallet reference.

##### `list_wallets(&self) -> Vec<&Wallet>`
List all wallets.

##### `get_total_balance(&self) -> u64`
Get total balance across all wallets.

##### `transfer_between_wallets(&mut self, from: &[u8; 32], to: &[u8; 32], amount: u64) -> Result<()>`
Transfer funds between wallets.

**Example:**
```rust
manager.transfer_between_wallets(
    &personal_wallet_id,
    &savings_wallet_id,
    5000, // 5000 SOV
)?;
```

##### `set_default_wallet(&mut self, wallet_id: [u8; 32]) -> Result<()>`
Set default wallet for transactions.

##### `deactivate_wallet(&mut self, wallet_id: &[u8; 32]) -> Result<()>`
Deactivate a wallet.

##### `archive_wallet(&mut self, wallet_id: &[u8; 32]) -> Result<()>`
Archive a wallet (no more transactions).

---

## Treasury Economics Module

### Treasury Calculation Functions

#### `calculate_optimal_ubi_per_citizen(treasury: &DaoTreasury, total_citizens: u64, target_monthly_ubi: u64) -> (u64, bool)`

Calculate optimal UBI distribution amount per citizen.

**Parameters:**
- `treasury`: DAO treasury reference
- `total_citizens`: Total number of verified citizens
- `target_monthly_ubi`: Target UBI amount per citizen per month

**Returns:** `(actual_ubi_per_citizen, can_meet_target)`

**Example:**
```rust
let (ubi_amount, can_meet) = calculate_optimal_ubi_per_citizen(
    &treasury,
    10000,    // 10,000 citizens
    1000,     // Target 1000 SOV per month
);

if can_meet {
    println!("Can provide full target UBI: {} SOV", ubi_amount);
} else {
    println!("Reduced UBI: {} SOV", ubi_amount);
}
```

#### `calculate_welfare_efficiency(treasury: &DaoTreasury) -> f64`

Calculate welfare funding efficiency score (0.0 to 1.0).

**Returns:** Efficiency ratio (distributed / expected)

#### `calculate_ubi_efficiency(treasury: &DaoTreasury) -> f64`

Calculate UBI distribution efficiency score (0.0 to 1.0).

**Returns:** Efficiency ratio (distributed / expected)

#### `calculate_treasury_sustainability(treasury: &DaoTreasury, monthly_burn_rate: u64) -> serde_json::Value`

Calculate treasury sustainability metrics.

**Parameters:**
- `treasury`: DAO treasury reference
- `monthly_burn_rate`: Expected monthly spending

**Returns:** JSON object with sustainability metrics

**Example:**
```rust
let sustainability = calculate_treasury_sustainability(&treasury, 100000);
println!("Sustainability: {}", sustainability);
// Output: {"months_sustainable": 24, "status": "healthy", ...}
```

#### `calculate_ubi_funding_gap(treasury: &DaoTreasury, total_citizens: u64, target_monthly_ubi: u64) -> Result<serde_json::Value>`

Calculate funding gap for target UBI amount.

**Returns:** JSON with gap analysis

---

## Transactions Module

### Transaction

Core transaction structure.

```rust
pub struct Transaction {
    pub tx_id: [u8; 32],
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub base_fee: u64,
    pub dao_fee: u64,
    pub total_fee: u64,
    pub tx_type: TransactionType,
    pub timestamp: u64,
    pub block_height: u64,
    pub dao_fee_proof: Option<[u8; 32]>,
}
```

#### Methods

##### `new(from: [u8; 32], to: [u8; 32], amount: u64, tx_type: TransactionType, tx_size: u64, priority: Priority) -> Result<Self>`

Create new transaction with automatic fee calculation.

**Example:**
```rust
let tx = Transaction::new(
    sender_address,
    recipient_address,
    10000,                      // 10000 SOV
    TransactionType::Payment,
    250,                        // 250 bytes
    Priority::Normal,
)?;

println!("Base fee: {}", tx.base_fee);
println!("DAO fee: {}", tx.dao_fee);
println!("Total fee: {}", tx.total_fee);
```

##### `new_payment(from: [u8; 32], to: [u8; 32], amount: u64, priority: Priority) -> Result<Self>`

Create payment transaction (convenience method).

##### `new_reward(to: [u8; 32], amount: u64) -> Result<Self>`

Create reward transaction (fee-free).

##### `new_ubi_distribution(to: [u8; 32], amount: u64) -> Result<Self>`

Create UBI distribution transaction (fee-free).

##### `new_welfare_distribution(to: [u8; 32], amount: u64) -> Result<Self>`

Create welfare distribution transaction (fee-free).

### TransactionType

```rust
pub enum TransactionType {
    Payment,
    Reward,
    UbiDistribution,
    WelfareDistribution,
    Staking,
    InfrastructureService,
}
```

#### Methods

##### `is_fee_exempt(&self) -> bool`

Check if transaction type is fee-exempt.

---

## Incentives Module

### NetworkParticipationRewards

Network participation reward structure.

```rust
pub struct NetworkParticipationRewards {
    pub bandwidth_sharing_rewards: u64,
    pub mesh_networking_rewards: u64,
    pub connectivity_provision_rewards: u64,
    pub anti_sybil_bonuses: u64,
    pub total_participation_rewards: u64,
}
```

#### Methods

##### `calculate(work: &IspBypassWork, peers_connected: u32) -> Result<Self>`

Calculate network participation rewards.

**Example:**
```rust
let work = IspBypassWork {
    bandwidth_shared_gb: 50,
    packets_routed_mb: 2500,
    uptime_hours: 24,
    connection_quality: 0.9,
    users_served: 8,
};

let rewards = NetworkParticipationRewards::calculate(&work, 5)?;
```

##### `calculate_mesh_maintenance(peers_connected: u32, mesh_uptime_hours: u64) -> Result<u64>`

Calculate mesh discovery and maintenance rewards.

---

## Supply Module

### SupplyManager

Manages token supply based on post-scarcity economics.

```rust
pub struct SupplyManager {
    pub current_supply: u64,
    pub max_supply: u64, // u64::MAX
}
```

#### Methods

##### `new() -> Self`
Create new supply manager.

##### `calculate_mint_amount(&self, infrastructure_usage: u64, network_activity: u64) -> u64`

Calculate new tokens to mint.

**Formula:**
```rust
base_mint = infrastructure_usage * 10
activity_bonus = network_activity * 5
total = base_mint + activity_bonus
```

##### `mint_tokens(&mut self, amount: u64) -> Result<(), String>`

Mint new tokens (utility-based).

##### `get_supply_stats(&self) -> (u64, u64, f64)`

Get supply statistics `(current, max, utilization)`.

---

## Pricing Module

### Dynamic Pricing Functions

#### `calculate_dynamic_price(base_price: u64, network_congestion: f64, priority: Priority) -> u64`

Calculate dynamic price based on network conditions.

**Example:**
```rust
let price = calculate_dynamic_price(
    100,                 // Base price
    0.75,               // 75% congestion
    Priority::High,
);
```

#### `calculate_price_adjustment(supply: u64, demand: u64) -> f64`

Calculate price adjustment based on supply and demand.

#### `get_infrastructure_pricing() -> (u64, u64, u64)`

Get pricing for infrastructure services.

**Returns:** `(routing_price, storage_price, bandwidth_price)`

---

## Types Module

### Priority

Transaction priority enumeration.

```rust
pub enum Priority {
    Low,      // 0.5x fee multiplier
    Normal,   // 1.0x fee multiplier
    High,     // 2.0x fee multiplier
    Urgent,   // 5.0x fee multiplier
}
```

### WorkMetrics

Infrastructure work tracking.

```rust
pub struct WorkMetrics {
    pub routing_work: u64,      // Bytes routed
    pub storage_work: u64,      // Bytes stored
    pub compute_work: u64,      // Compute units
    pub quality_score: f64,     // 0.0 to 1.0
    pub uptime_hours: u64,      // Hours of uptime
}
```

#### Methods

##### `qualifies_for_quality_bonus(&self) -> bool`
Check if work qualifies for quality bonus (score > 0.95).

##### `qualifies_for_uptime_bonus(&self) -> bool`
Check if work qualifies for uptime bonus (uptime > 0.99).

### IspBypassWork

ISP replacement work metrics.

```rust
pub struct IspBypassWork {
    pub bandwidth_shared_gb: u64,
    pub packets_routed_mb: u64,
    pub uptime_hours: u64,
    pub connection_quality: f64,
    pub users_served: u64,
}
```

---

## Distribution Module

### Status:  STUB - Implementation Needed

#### `distribute_ubi_to_citizens() -> Result<()>`

**Current:** Empty placeholder returning `Ok(())`

**Needed Implementation:**
- Citizen verification and tracking
- Periodic distribution scheduling
- Transaction creation for each distribution
- Distribution history tracking
- Anti-fraud mechanisms

---

## Rewards Module

### Status:  EMPTY - Implementation Needed

**Current:** Empty file

**Needed Implementation:**
- Aggregate rewards from multiple sources (TokenReward, NetworkParticipation, etc.)
- Historical reward tracking
- Distribution scheduling and execution
- Reward verification and proof generation
- Reward claim mechanisms

---

## Error Types

```rust
pub enum EconomicError {
    InsufficientBalance,
    InvalidWalletType,
    WalletNotFound,
    InvalidAmount,
    InvalidFeeCalculation,
    TreasuryInsufficientFunds,
    InvalidIdentity,
}
```

## Usage Patterns

### Complete Transaction Flow

```rust
// 1. Create multi-wallet manager
let mut manager = MultiWalletManager::new(identity_address)?;

// 2. Create personal wallet
let wallet_id = manager.create_wallet("Personal", WalletType::Personal)?;

// 3. Create transaction
let tx = Transaction::new_payment(
    identity_address,
    recipient_address,
    10000,
    Priority::Normal,
)?;

// 4. Process fees
let model = EconomicModel::new();
let mut treasury = DaoTreasury::new();
treasury.receive_dao_fee(tx.dao_fee)?;
treasury.allocate_funds()?;
```

### Infrastructure Reward Flow

```rust
// 1. Track work
let work = WorkMetrics {
    routing_work: 1_000_000_000,  // 1 GB routed
    storage_work: 10_000_000_000, // 10 GB stored
    compute_work: 100,
    quality_score: 0.96,
    uptime_hours: 24,
};

// 2. Calculate rewards
let model = EconomicModel::new();
let reward = TokenReward::calculate(&work, &model)?;

// 3. Create reward transaction
let tx = Transaction::new_reward(node_address, reward.total_reward)?;

// 4. Credit rewards wallet
let wallet_id = manager.get_wallet_by_type(WalletType::Rewards)?;
manager.deposit(wallet_id, reward.total_reward)?;
```

## Related Documentation

- [INDEX.md](./INDEX.md) - Module listing
- [OVERVIEW.md](./OVERVIEW.md) - Architecture overview
- [EXAMPLES.md](./EXAMPLES.md) - Usage examples
- [models.md](./models.md) - Models module details
- [wallets.md](./wallets.md) - Wallets module details
- [treasury_economics.md](./treasury_economics.md) - Treasury details
