# lib-economy Quick Reference

Fast lookup guide for common operations and key concepts.

##  Quick Links

- **[Full API Reference](./API_REFERENCE.md)** - Complete API documentation
- **[Examples](./EXAMPLES.md)** - Code examples and tutorials
- **[Architecture](./OVERVIEW.md)** - System design and philosophy

---

##  Economic Constants

```rust
DAO_FEE_RATE = 2% (200 basis points)     // Mandatory DAO contribution
ISP_CONNECTIVITY = 100 SOV/GB           // Bandwidth sharing reward
ISP_MESH_RATE = 1 SOV/MB               // Packet routing reward
ISP_UPTIME = 10 SOV/hour               // Uptime bonus
MESH_THRESHOLD = 3 peers                 // Min peers for rewards
MIN_STAKING = 1000 SOV                  // Minimum stake
UBI_ALLOCATION = 40%                     // UBI from DAO fees
WELFARE_ALLOCATION = 30%                 // Welfare from DAO fees
DEVELOPMENT_ALLOCATION = 30%             // Dev from DAO fees
```

---

##  Quick Start

```rust
use lib_economy::*;

// 1. Setup
let model = EconomicModel::new();
let mut manager = MultiWalletManager::new(identity)?;
let wallet = manager.create_wallet("Personal", WalletType::Personal)?;

// 2. Create transaction
let tx = Transaction::new_payment(from, to, 1000, Priority::Normal)?;

// 3. Calculate rewards
let rewards = TokenReward::calculate(&work_metrics, &model)?;
```

---

##  Transaction Types

| Type | Fee Exempt | Use Case |
|------|-----------|----------|
| `Payment` |  | Regular transfers |
| `Reward` |  | Infrastructure rewards |
| `UbiDistribution` |  | UBI payments |
| `WelfareDistribution` |  | Welfare payments |
| `Staking` |  | Network staking |
| `InfrastructureService` |  | Service payments |

---

## 🏦 Wallet Types (10 Types)

```rust
WalletType::Personal       // Daily spending
WalletType::Business       // Business operations
WalletType::Investment     // Long-term holdings
WalletType::Savings        // Protected savings
WalletType::Rewards        // Infrastructure earnings
WalletType::Staking        // Network participation
WalletType::Governance     // DAO voting
WalletType::Escrow         // Multi-party contracts
WalletType::Development    // Development funding
WalletType::Donation       // Charitable giving
```

---

##  Fee Calculation

```rust
// Base fee
base_fee = tx_size * BASE_FEE_PER_BYTE * priority_multiplier

// DAO fee (2% of amount)
dao_fee = (amount * 200) / 10000

// Total fee
total_fee = base_fee + dao_fee
```

### Priority Multipliers

```
Low:    0.5x (50% discount)
Normal: 1.0x (standard rate)
High:   2.0x (double rate)
Urgent: 5.0x (5x rate)
```

---

## 🏗️ Infrastructure Rewards

### Calculation Formula

```rust
// Routing: 1 SOV per MB
routing = (bytes_routed / 1_000_000) * 1

// Storage: 10 SOV per GB
storage = (bytes_stored / 1_000_000_000) * 10

// Compute: Minimal rate
compute = compute_units * base_rate

// Bonuses
quality_bonus = (quality > 0.95) ? base * 0.5 : 0
uptime_bonus = (uptime > 0.99) ? base * 0.3 : 0
```

### Example Daily Rewards

| Activity | Amount | Rate | Reward |
|----------|--------|------|--------|
| Route 5 GB | 5000 MB | 1 SOV/MB | 5000 SOV |
| Store 50 GB | 50 GB | 10 SOV/GB | 500 SOV |
| 96% quality | - | 50% bonus | 2750 SOV |
| **Total** | - | - | **8250 SOV/day** |

---

##  Treasury Allocation

```
Every transaction pays 2% DAO fee
    ↓
Treasury receives fees
    ↓
Automatic allocation:
    → 40% to UBI fund
    → 30% to Welfare fund
    → 30% to Development fund
```

### Example: 1000 SOV DAO fee

```
UBI:         400 SOV (40%)
Welfare:     300 SOV (30%)
Development: 300 SOV (30%)
```

---

##  Common Operations

### Create Wallet

```rust
let wallet_id = manager.create_wallet("Name", WalletType::Personal)?;
```

### Send Payment

```rust
let tx = Transaction::new_payment(from, to, amount, Priority::Normal)?;
```

### Calculate Rewards

```rust
let reward = TokenReward::calculate(&work, &model)?;
```

### Transfer Between Wallets

```rust
manager.transfer_between_wallets(&from_id, &to_id, amount)?;
```

### Check Balance

```rust
let balance = manager.get_total_balance();
```

### Process DAO Fee

```rust
treasury.receive_dao_fee(fee)?;
treasury.allocate_funds()?;
```

### Calculate UBI

```rust
let ubi = treasury.calculate_ubi_per_citizen(total_citizens);
```

---

##  Status Checks

### Wallet Status

```rust
pub enum WalletStatus {
    Active,      // Normal operation
    Inactive,    // Temporarily disabled
    Frozen,      // Locked by system
    Archived,    // No longer in use
}
```

### Transaction Priority

```rust
pub enum Priority {
    Low,      // Cheap, slower
    Normal,   // Standard
    High,     // Expensive, faster
    Urgent,   // Very expensive, fastest
}
```

---

##  Implementation Status

###  Fully Implemented (85%)

-  Economic model and fee calculation
-  Multi-wallet system (10 types)
-  Treasury management
-  Transaction system
-  Token rewards calculation
-  Network participation incentives
-  Supply management
-  Dynamic pricing
-  Type definitions
-  WASM compatibility
-  Integration utilities

###  Stub/Empty (15%)

-  **UBI Distribution** (stub) - `distribution/ubi_distribution.rs`
  - Current: Placeholder function
  - Needed: Full citizen tracking and distribution logic

-  **Reward Calculator** (empty) - `rewards/reward_calculator.rs`
  - Current: Empty file
  - Needed: Reward aggregation and distribution system

---

##  Work Metrics

### Infrastructure Work

```rust
WorkMetrics {
    routing_work: u64,      // Bytes routed
    storage_work: u64,      // Bytes stored
    compute_work: u64,      // Compute units
    quality_score: f64,     // 0.0 to 1.0
    uptime_hours: u64,      // Hours online
}
```

###  Work

```rust
IspBypassWork {
    bandwidth_shared_gb: u64,    // GB bandwidth shared
    packets_routed_mb: u64,      // MB packets routed
    uptime_hours: u64,           // Hours online
    connection_quality: f64,     // 0.0 to 1.0
    users_served: u64,           // Number of users
}
```

---

## 🎓 Learning Path

### Beginner

1. Read [README.md](./README.md) - Understand core concepts
2. Review [EXAMPLES.md](./EXAMPLES.md#quick-start) - Basic setup
3. Study wallet creation and basic transactions

### Intermediate

1. Explore [multi-wallet system](./wallets.md) - Advanced wallet management
2. Learn [fee calculation](./models.md#fee-calculation) - Understanding costs
3. Practice [infrastructure rewards](./EXAMPLES.md#infrastructure-rewards)

### Advanced

1. Study [treasury operations](./treasury_economics.md) - DAO mechanics
2. Implement [network participation](./incentives.md) - Earn rewards
3. Understand [economic model](./OVERVIEW.md) - Post-scarcity design

---

## 🐛 Common Issues

### Issue: Insufficient Balance

```rust
// ✗ Error
manager.withdraw(&wallet_id, amount)?;

//  Solution
if wallet.balance >= amount {
    manager.withdraw(&wallet_id, amount)?;
}
```

### Issue: Wallet Not Found

```rust
// ✗ Error
let wallet = manager.get_wallet(&wallet_id).unwrap();

//  Solution
let wallet = manager.get_wallet(&wallet_id)
    .ok_or(anyhow::anyhow!("Wallet not found"))?;
```

### Issue: Incorrect Fee Calculation

```rust
// ✗ Wrong
let total = amount; // Forgot fees!

//  Correct
let tx = Transaction::new_payment(from, to, amount, priority)?;
let total = amount + tx.total_fee;
```

---

## 📐 Formulas Reference

### Monthly UBI Calculation

```
ubi_per_citizen = ubi_allocated / total_citizens
```

### Treasury Sustainability

```
months_sustainable = total_allocated / monthly_burn_rate
```

### Dynamic Pricing

```
final_price = base_price * (1 + congestion) * priority_multiplier
```

### Reward Totals

```
total_reward = routing + storage + compute + quality_bonus + uptime_bonus
```

---

##  Module Dependencies

```
lib-economy
├── lib-identity     (wallet ownership)
├── lib-blockchain   (transaction storage)
├── lib-crypto       (hashing, signing)
└── lib-network      (metrics collection)
```

---

## 📚 Module Documentation

| Module | Purpose | Status | Documentation |
|--------|---------|--------|---------------|
| **models** | Economic calculations |  Complete | [models.md](./models.md) |
| **wallets** | Multi-wallet system |  Complete | [wallets.md](./wallets.md) |
| **treasury_economics** | DAO treasury |  Complete | [treasury_economics.md](./treasury_economics.md) |
| **transactions** | Transaction system |  Complete | [transactions.md](./transactions.md) |
| **incentives** | Network rewards |  Complete | [incentives.md](./incentives.md) |
| **distribution** | UBI distribution |  Stub | [distribution.md](./distribution.md) |
| **rewards** | Reward calculator |  Empty | [rewards.md](./rewards.md) |
| **supply** | Supply management |  Complete | [supply.md](./supply.md) |
| **pricing** | Dynamic pricing |  Complete | [pricing.md](./pricing.md) |
| **types** | Type definitions |  Complete | [types.md](./types.md) |
| **wasm** | WASM compatibility |  Complete | [wasm.md](./wasm.md) |
| **integration** | Testing utilities |  Complete | [integration.md](./integration.md) |

---

##  Key Takeaways

1. **Post-Scarcity**: Unlimited tokens minted based on utility
2. **ISP Replacement**: Fair compensation for infrastructure
3. **DAO Welfare**: 2% of all transactions fund UBI/welfare
4. **10 Wallet Types**: Specialized wallets for different activities
5. **Anti-Sybil**: Rewards quality infrastructure, not node count
6. **Fee Transparency**: Clear breakdown (base + DAO)
7. **Identity-Based**: Wallets tied to verified identities

---

## 📞 Need Help?

- **API Details**: See [API_REFERENCE.md](./API_REFERENCE.md)
- **Code Examples**: See [EXAMPLES.md](./EXAMPLES.md)
- **Architecture**: See [OVERVIEW.md](./OVERVIEW.md)
- **Module Specific**: See individual module docs

---

**Implementation Status: 85% Complete** (11/13 modules fully implemented)

 **Stub Modules**: `distribution/ubi_distribution.rs`, `rewards/reward_calculator.rs`
