# lib-economy Examples

Practical examples and tutorials for using lib-economy in various scenarios.

## Table of Contents

- [Quick Start](#quick-start)
- [Multi-Wallet Management](#multi-wallet-management)
- [Transaction Processing](#transaction-processing)
- [Infrastructure Rewards](#infrastructure-rewards)
- [Treasury Operations](#treasury-operations)
- [Network Participation](#network-participation)
- [ Rewards](#isp-bypass-rewards)
- [UBI Distribution](#ubi-distribution)
- [Dynamic Pricing](#dynamic-pricing)
- [Complete Economic Flows](#complete-economic-flows)

---

## Quick Start

### Basic Setup

```rust
use lib_economy::{
    EconomicModel,
    MultiWalletManager,
    DaoTreasury,
    Transaction,
    Priority,
    WalletType,
};

fn main() -> anyhow::Result<()> {
    // Initialize economic model
    let model = EconomicModel::new();
    
    // Create wallet manager for an identity
    let identity_address = [1u8; 32]; // Your identity address
    let mut wallet_manager = MultiWalletManager::new(identity_address)?;
    
    // Create a personal wallet
    let wallet_id = wallet_manager.create_wallet(
        "My Personal Wallet",
        WalletType::Personal,
    )?;
    
    println!(" Setup complete!");
    Ok(())
}
```

---

## Multi-Wallet Management

### Creating Specialized Wallets

```rust
use lib_economy::{MultiWalletManager, WalletType};

fn setup_diverse_wallets(identity: [u8; 32]) -> anyhow::Result<()> {
    let mut manager = MultiWalletManager::new(identity)?;
    
    // Create wallets for different purposes
    let personal = manager.create_wallet("Daily Spending", WalletType::Personal)?;
    let business = manager.create_wallet("Business Account", WalletType::Business)?;
    let savings = manager.create_wallet("Emergency Fund", WalletType::Savings)?;
    let rewards = manager.create_wallet("Infrastructure Earnings", WalletType::Rewards)?;
    let staking = manager.create_wallet("Network Staking", WalletType::Staking)?;
    
    println!("Created {} wallets", manager.wallets.len());
    
    // Set default wallet
    manager.set_default_wallet(personal)?;
    
    Ok(())
}
```

### Transferring Between Wallets

```rust
fn move_funds_to_savings(manager: &mut MultiWalletManager) -> anyhow::Result<()> {
    // Find wallets
    let personal_wallet = manager.get_wallet_by_type(WalletType::Personal)?;
    let savings_wallet = manager.get_wallet_by_type(WalletType::Savings)?;
    
    // Transfer 5000 ZHTP from personal to savings
    manager.transfer_between_wallets(
        &personal_wallet.wallet_id,
        &savings_wallet.wallet_id,
        5000,
    )?;
    
    println!(" Transferred 5000 ZHTP to savings");
    Ok(())
}
```

### Checking Wallet Balances

```rust
fn check_all_balances(manager: &MultiWalletManager) {
    println!("\n=== Wallet Balances ===");
    
    for wallet in manager.list_wallets() {
        println!(
            "{:?}: {} ZHTP ({})",
            wallet.wallet_type,
            wallet.balance,
            wallet.name
        );
    }
    
    println!("\nTotal Balance: {} ZHTP", manager.get_total_balance());
}
```

---

## Transaction Processing

### Creating a Payment Transaction

```rust
use lib_economy::{Transaction, Priority, TransactionType};

fn send_payment(
    sender: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
) -> anyhow::Result<Transaction> {
    // Create payment with normal priority
    let tx = Transaction::new_payment(
        sender,
        recipient,
        amount,
        Priority::Normal,
    )?;
    
    println!("Transaction created:");
    println!("  Amount: {} ZHTP", tx.amount);
    println!("  Base fee: {} ZHTP", tx.base_fee);
    println!("  DAO fee (2%): {} ZHTP", tx.dao_fee);
    println!("  Total fee: {} ZHTP", tx.total_fee);
    println!("  Total cost: {} ZHTP", tx.amount + tx.total_fee);
    
    Ok(tx)
}
```

### Priority-Based Transactions

```rust
fn compare_priorities() -> anyhow::Result<()> {
    let sender = [1u8; 32];
    let recipient = [2u8; 32];
    let amount = 10000;
    
    let priorities = vec![
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Urgent,
    ];
    
    println!("\n=== Fee Comparison for 10,000 ZHTP ===");
    
    for priority in priorities {
        let tx = Transaction::new_payment(sender, recipient, amount, priority)?;
        println!(
            "{:?}: {} ZHTP total fee (base: {}, DAO: {})",
            priority,
            tx.total_fee,
            tx.base_fee,
            tx.dao_fee
        );
    }
    
    Ok(())
}
```

### Fee-Free Transactions (UBI/Welfare)

```rust
fn create_ubi_distribution(recipient: [u8; 32]) -> anyhow::Result<Transaction> {
    // UBI distributions are fee-free
    let tx = Transaction::new_ubi_distribution(recipient, 1000)?;
    
    assert_eq!(tx.base_fee, 0);
    assert_eq!(tx.dao_fee, 0);
    assert_eq!(tx.total_fee, 0);
    
    println!(" UBI distribution: 1000 ZHTP (no fees)");
    Ok(tx)
}
```

---

## Infrastructure Rewards

### Calculating Node Rewards

```rust
use lib_economy::{TokenReward, WorkMetrics, EconomicModel};

fn calculate_node_rewards() -> anyhow::Result<()> {
    // Track infrastructure work for 24 hours
    let work = WorkMetrics {
        routing_work: 5_000_000_000,    // 5 GB routed
        storage_work: 50_000_000_000,   // 50 GB stored
        compute_work: 500,               // 500 compute units
        quality_score: 0.96,            // 96% quality
        uptime_hours: 24,               // 24 hours uptime
    };
    
    let model = EconomicModel::new();
    let reward = TokenReward::calculate(&work, &model)?;
    
    println!("\n=== Daily Infrastructure Rewards ===");
    println!("Routing (5 GB): {} ZHTP", reward.routing_reward);
    println!("Storage (50 GB): {} ZHTP", reward.storage_reward);
    println!("Compute: {} ZHTP", reward.compute_reward);
    println!("Quality bonus (96%): {} ZHTP", reward.quality_bonus);
    println!("Uptime bonus: {} ZHTP", reward.uptime_bonus);
    println!("\nTotal: {} ZHTP", reward.total_reward);
    
    Ok(())
}
```

### Monthly Reward Projection

```rust
fn project_monthly_rewards() -> anyhow::Result<()> {
    let daily_work = WorkMetrics {
        routing_work: 2_000_000_000,    // 2 GB/day
        storage_work: 100_000_000_000,  // 100 GB stored
        compute_work: 200,
        quality_score: 0.95,
        uptime_hours: 24,
    };
    
    let model = EconomicModel::new();
    let daily_reward = TokenReward::calculate(&daily_work, &model)?;
    let monthly_reward = daily_reward.total_reward * 30;
    
    println!("\n=== Monthly Projection ===");
    println!("Daily reward: {} ZHTP", daily_reward.total_reward);
    println!("Monthly reward (30 days): {} ZHTP", monthly_reward);
    
    Ok(())
}
```

### Combining Multiple Reward Sources

```rust
fn combine_rewards() -> anyhow::Result<()> {
    let model = EconomicModel::new();
    
    // Morning shift rewards
    let morning_work = WorkMetrics {
        routing_work: 1_000_000_000,
        storage_work: 50_000_000_000,
        compute_work: 100,
        quality_score: 0.95,
        uptime_hours: 12,
    };
    
    // Evening shift rewards
    let evening_work = WorkMetrics {
        routing_work: 1_500_000_000,
        storage_work: 50_000_000_000,
        compute_work: 150,
        quality_score: 0.97,
        uptime_hours: 12,
    };
    
    let mut morning_reward = TokenReward::calculate(&morning_work, &model)?;
    let evening_reward = TokenReward::calculate(&evening_work, &model)?;
    
    // Combine rewards
    morning_reward.combine(&evening_reward);
    
    println!("Combined daily reward: {} ZHTP", morning_reward.total_reward);
    
    Ok(())
}
```

---

## Treasury Operations

### Receiving and Allocating DAO Fees

```rust
use lib_economy::DaoTreasury;

fn process_dao_fees() -> anyhow::Result<()> {
    let mut treasury = DaoTreasury::new();
    
    // Simulate receiving fees from multiple transactions
    let transactions_fees = vec![20, 50, 100, 200, 30]; // DAO fees in ZHTP
    
    for fee in transactions_fees {
        treasury.receive_dao_fee(fee)?;
    }
    
    // Allocate funds
    treasury.allocate_funds()?;
    
    println!("\n=== Treasury Status ===");
    println!("Total fees collected: {} ZHTP", treasury.total_dao_fees_collected);
    println!("UBI allocated (40%): {} ZHTP", treasury.ubi_allocated);
    println!("Welfare allocated (30%): {} ZHTP", treasury.welfare_allocated);
    println!("Development (30%): {} ZHTP", treasury.development_allocated);
    println!("Treasury balance: {} ZHTP", treasury.treasury_balance);
    
    Ok(())
}
```

### Calculating UBI Distribution

```rust
use lib_economy::treasury_economics::calculate_optimal_ubi_per_citizen;

fn calculate_ubi_amounts(treasury: &DaoTreasury) -> anyhow::Result<()> {
    let total_citizens = 10000;
    let target_monthly_ubi = 1000; // Target 1000 ZHTP per citizen per month
    
    let (actual_ubi, can_meet_target) = calculate_optimal_ubi_per_citizen(
        treasury,
        total_citizens,
        target_monthly_ubi,
    );
    
    println!("\n=== UBI Calculation ===");
    println!("Total verified citizens: {}", total_citizens);
    println!("Target monthly UBI: {} ZHTP", target_monthly_ubi);
    
    if can_meet_target {
        println!(" Can provide full target: {} ZHTP per citizen", actual_ubi);
    } else {
        println!("⚠ Reduced UBI: {} ZHTP per citizen", actual_ubi);
        println!("  (Insufficient treasury funds)");
    }
    
    println!("\nTotal monthly distribution: {} ZHTP", actual_ubi * total_citizens);
    
    Ok(())
}
```

### Treasury Sustainability Analysis

```rust
use lib_economy::treasury_economics::calculate_treasury_sustainability;

fn analyze_sustainability(treasury: &DaoTreasury) -> anyhow::Result<()> {
    let monthly_burn_rate = 100000; // Expected 100k ZHTP per month
    
    let metrics = calculate_treasury_sustainability(treasury, monthly_burn_rate);
    
    println!("\n=== Treasury Sustainability ===");
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    
    Ok(())
}
```

---

## Network Participation

### Bandwidth Sharing Rewards

```rust
use lib_economy::{NetworkParticipationRewards, IspBypassWork};

fn calculate_bandwidth_rewards() -> anyhow::Result<()> {
    // Node sharing bandwidth for 
    let work = IspBypassWork {
        bandwidth_shared_gb: 100,        // 100 GB bandwidth shared
        packets_routed_mb: 5000,         // 5 GB packets routed
        uptime_hours: 23,                // 95.8% uptime
        connection_quality: 0.92,        // 92% quality
        users_served: 8,                 // 8 active users
    };
    
    let peers_connected = 5; // 5 mesh peers
    
    let rewards = NetworkParticipationRewards::calculate(&work, peers_connected)?;
    
    println!("\n=== Network Participation Rewards ===");
    println!("Bandwidth sharing: {} ZHTP", rewards.bandwidth_sharing_rewards);
    println!("Mesh networking: {} ZHTP", rewards.mesh_networking_rewards);
    println!("Connectivity provision: {} ZHTP", rewards.connectivity_provision_rewards);
    println!("Anti-Sybil bonuses: {} ZHTP", rewards.anti_sybil_bonuses);
    println!("\nTotal: {} ZHTP", rewards.total_participation_rewards);
    
    Ok(())
}
```

### Mesh Maintenance Rewards

```rust
use lib_economy::incentives::calculate_mesh_maintenance;

fn calculate_mesh_rewards() -> anyhow::Result<()> {
    let scenarios = vec![
        (5, 24, "Excellent"),  // 5 peers, 24 hours, 100% uptime
        (3, 23, "Good"),       // 3 peers, 23 hours, 95%+ uptime
        (2, 20, "Insufficient"), // Below threshold
    ];
    
    println!("\n=== Mesh Maintenance Scenarios ===");
    
    for (peers, uptime_hours, description) in scenarios {
        let reward = calculate_mesh_maintenance(peers, uptime_hours)?;
        println!(
            "{}: {} peers, {} hours = {} ZHTP",
            description, peers, uptime_hours, reward
        );
    }
    
    Ok(())
}
```

---

##  Rewards

### Complete  Scenario

```rust
use lib_economy::{TokenReward, IspBypassWork};

fn isp_bypass_node_rewards() -> anyhow::Result<()> {
    // Home node acting as ISP replacement
    let daily_work = IspBypassWork {
        bandwidth_shared_gb: 50,         // 50 GB/day bandwidth
        packets_routed_mb: 2500,         // 2.5 GB packets routed
        uptime_hours: 24,                // 24 hours
        connection_quality: 0.95,        // 95% quality
        users_served: 12,                // Serving 12 neighbors
    };
    
    let reward = TokenReward::calculate_isp_bypass(&daily_work)?;
    
    println!("\n===  Node (Daily) ===");
    println!("Bandwidth shared: {} GB", daily_work.bandwidth_shared_gb);
    println!("Packets routed: {} MB", daily_work.packets_routed_mb);
    println!("Uptime: {} hours", daily_work.uptime_hours);
    println!("Quality: {}%", daily_work.connection_quality * 100.0);
    println!("Users served: {}", daily_work.users_served);
    println!("\n=== Rewards ===");
    println!("Routing: {} ZHTP", reward.routing_reward);
    println!("Quality bonus: {} ZHTP", reward.quality_bonus);
    println!("Uptime bonus: {} ZHTP", reward.uptime_bonus);
    println!("\nTotal: {} ZHTP/day", reward.total_reward);
    println!("Monthly estimate: {} ZHTP", reward.total_reward * 30);
    
    Ok(())
}
```

---

## UBI Distribution

### Status:  Stub Implementation

The UBI distribution module is currently a stub and needs full implementation. Here's the intended usage:

```rust
// INTENDED USAGE (not yet implemented)
use lib_economy::distribution::distribute_ubi_to_citizens;

fn monthly_ubi_distribution() -> anyhow::Result<()> {
    // This currently returns Ok(()) without doing anything
    // Full implementation needed:
    // - Verify citizen eligibility
    // - Calculate individual UBI amounts
    // - Create distribution transactions
    // - Track distribution history
    
    distribute_ubi_to_citizens()?;
    
    Ok(())
}
```

### Workaround: Manual UBI Distribution

```rust
fn manual_ubi_distribution(
    treasury: &mut DaoTreasury,
    citizens: Vec<[u8; 32]>,
) -> anyhow::Result<()> {
    let ubi_per_citizen = treasury.calculate_ubi_per_citizen(citizens.len() as u64);
    
    println!("\n=== Manual UBI Distribution ===");
    println!("Citizens: {}", citizens.len());
    println!("UBI per citizen: {} ZHTP", ubi_per_citizen);
    
    for citizen_address in citizens {
        // Create UBI distribution transaction
        let tx = Transaction::new_ubi_distribution(citizen_address, ubi_per_citizen)?;
        
        // Process transaction (would be done by consensus layer)
        treasury.distribute_ubi(ubi_per_citizen)?;
        
        println!(" Distributed {} ZHTP to {}", ubi_per_citizen, hex::encode(&citizen_address[..8]));
    }
    
    Ok(())
}
```

---

## Dynamic Pricing

### Network Congestion Pricing

```rust
use lib_economy::pricing::{calculate_dynamic_price, Priority};

fn demonstrate_dynamic_pricing() {
    let base_price = 100; // 100 ZHTP base fee
    
    let congestion_levels = vec![
        (0.0, "No congestion"),
        (0.25, "Light load"),
        (0.50, "Medium load"),
        (0.75, "Heavy load"),
        (1.0, "Full capacity"),
    ];
    
    println!("\n=== Dynamic Pricing (Normal Priority) ===");
    
    for (congestion, description) in congestion_levels {
        let price = calculate_dynamic_price(base_price, congestion, Priority::Normal);
        println!("{}: {} ZHTP", description, price);
    }
}
```

### Priority Impact on Pricing

```rust
fn priority_pricing_comparison() {
    let base_price = 100;
    let congestion = 0.5; // 50% network load
    
    let priorities = vec![
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Urgent,
    ];
    
    println!("\n=== Priority Pricing (50% Congestion) ===");
    
    for priority in priorities {
        let price = calculate_dynamic_price(base_price, congestion, priority);
        println!("{:?}: {} ZHTP", priority, price);
    }
}
```

---

## Complete Economic Flows

### Node Operator Daily Workflow

```rust
fn node_operator_daily_flow() -> anyhow::Result<()> {
    // Setup
    let identity = [1u8; 32];
    let mut manager = MultiWalletManager::new(identity)?;
    let rewards_wallet = manager.create_wallet("Node Rewards", WalletType::Rewards)?;
    let model = EconomicModel::new();
    
    // 1. Track daily infrastructure work
    let work = WorkMetrics {
        routing_work: 3_000_000_000,
        storage_work: 75_000_000_000,
        compute_work: 300,
        quality_score: 0.96,
        uptime_hours: 24,
    };
    
    // 2. Calculate rewards
    let reward = TokenReward::calculate(&work, &model)?;
    
    // 3. Credit rewards to wallet
    manager.deposit(&rewards_wallet, reward.total_reward)?;
    
    println!("\n=== Node Operator Daily Summary ===");
    println!("Infrastructure rewards: {} ZHTP", reward.total_reward);
    println!("Rewards wallet balance: {} ZHTP", 
        manager.get_wallet(&rewards_wallet).unwrap().balance);
    
    // 4. Transfer some to savings
    let savings_wallet = manager.create_wallet("Savings", WalletType::Savings)?;
    let save_amount = reward.total_reward / 2;
    manager.transfer_between_wallets(&rewards_wallet, &savings_wallet, save_amount)?;
    
    println!("\n Transferred {} ZHTP to savings", save_amount);
    
    Ok(())
}
```

### Citizen Receiving UBI

```rust
fn citizen_ubi_flow() -> anyhow::Result<()> {
    // Citizen identity
    let identity = [1u8; 32];
    let mut manager = MultiWalletManager::new(identity)?;
    let personal_wallet = manager.create_wallet("Personal", WalletType::Personal)?;
    
    // Receive monthly UBI (1000 ZHTP)
    let ubi_amount = 1000;
    let ubi_tx = Transaction::new_ubi_distribution(identity, ubi_amount)?;
    
    // Credit UBI to personal wallet
    manager.deposit(&personal_wallet, ubi_amount)?;
    
    println!("\n=== Citizen UBI Receipt ===");
    println!(" Received {} ZHTP UBI", ubi_amount);
    println!("Personal wallet balance: {} ZHTP",
        manager.get_wallet(&personal_wallet).unwrap().balance);
    
    // Use UBI for payment
    let recipient = [2u8; 32];
    let payment_amount = 300;
    
    let payment_tx = Transaction::new_payment(
        identity,
        recipient,
        payment_amount,
        Priority::Normal,
    )?;
    
    let total_cost = payment_amount + payment_tx.total_fee;
    manager.withdraw(&personal_wallet, total_cost)?;
    
    println!("\n=== Payment Made ===");
    println!("Amount: {} ZHTP", payment_amount);
    println!("Fees: {} ZHTP (base: {}, DAO: {})",
        payment_tx.total_fee, payment_tx.base_fee, payment_tx.dao_fee);
    println!("Remaining balance: {} ZHTP",
        manager.get_wallet(&personal_wallet).unwrap().balance);
    
    Ok(())
}
```

### Treasury Monthly Cycle

```rust
fn treasury_monthly_cycle() -> anyhow::Result<()> {
    let mut treasury = DaoTreasury::new();
    
    // Simulate one month of transactions
    println!("\n=== Treasury Monthly Cycle ===");
    
    // Week 1: 10,000 ZHTP in DAO fees
    for _ in 0..500 {
        treasury.receive_dao_fee(20)?;
    }
    treasury.allocate_funds()?;
    println!("Week 1: {} ZHTP collected", treasury.total_dao_fees_collected);
    
    // Week 2: 15,000 ZHTP in DAO fees
    for _ in 0..750 {
        treasury.receive_dao_fee(20)?;
    }
    treasury.allocate_funds()?;
    println!("Week 2: {} ZHTP collected", treasury.total_dao_fees_collected);
    
    // Calculate UBI distribution
    let citizens = 1000;
    let ubi_per_citizen = treasury.calculate_ubi_per_citizen(citizens);
    
    println!("\n=== Month End Summary ===");
    println!("Total collected: {} ZHTP", treasury.total_dao_fees_collected);
    println!("UBI allocated: {} ZHTP", treasury.ubi_allocated);
    println!("Welfare allocated: {} ZHTP", treasury.welfare_allocated);
    println!("Development: {} ZHTP", treasury.development_allocated);
    println!("\nUBI per citizen ({} citizens): {} ZHTP", citizens, ubi_per_citizen);
    
    // Distribute UBI
    for _ in 0..citizens {
        treasury.distribute_ubi(ubi_per_citizen)?;
    }
    
    println!("\n UBI distributed to {} citizens", citizens);
    println!("Remaining UBI allocation: {} ZHTP", treasury.ubi_allocated);
    
    Ok(())
}
```

---

## Testing Utilities

### Mock Economic Environment

```rust
use lib_economy::testing::*;

fn setup_test_environment() -> anyhow::Result<()> {
    // Create mock economic model
    let model = create_mock_economic_model();
    
    // Create mock treasury with funds
    let treasury = create_mock_treasury_with_balance(1_000_000);
    
    // Create mock wallet manager
    let manager = create_mock_wallet_manager([1u8; 32], 10)?;
    
    println!(" Test environment ready");
    
    Ok(())
}
```

---

## Best Practices

### 1. Always Check Balances Before Transactions

```rust
fn safe_transfer(manager: &mut MultiWalletManager, from: &[u8; 32], to: &[u8; 32], amount: u64) -> anyhow::Result<()> {
    let wallet = manager.get_wallet(from).ok_or(anyhow::anyhow!("Wallet not found"))?;
    
    if wallet.balance < amount {
        return Err(anyhow::anyhow!("Insufficient balance"));
    }
    
    manager.transfer_between_wallets(from, to, amount)?;
    Ok(())
}
```

### 2. Handle Fee Calculations Explicitly

```rust
fn calculate_total_cost(amount: u64, priority: Priority) -> anyhow::Result<u64> {
    let tx = Transaction::new_payment([0u8; 32], [0u8; 32], amount, priority)?;
    Ok(amount + tx.total_fee)
}
```

### 3. Use Appropriate Wallet Types

```rust
//  Good: Specialized wallets
manager.create_wallet("Daily", WalletType::Personal)?;
manager.create_wallet("Company", WalletType::Business)?;
manager.create_wallet("Emergency", WalletType::Savings)?;

// ✗ Bad: Everything in one wallet
// Less organized, harder to track different economic activities
```

---

## Related Documentation

- [API_REFERENCE.md](./API_REFERENCE.md) - Complete API documentation
- [OVERVIEW.md](./OVERVIEW.md) - Architecture and design
- [models.md](./models.md) - Economic model details
- [wallets.md](./wallets.md) - Multi-wallet system
- [treasury_economics.md](./treasury_economics.md) - Treasury operations
