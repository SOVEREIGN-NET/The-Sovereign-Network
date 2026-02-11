# Wallets Module Documentation

The `wallets` module provides a comprehensive multi-wallet system for managing diverse economic activities with specialized wallet types.

## Overview

The wallets module implements:
- **10 specialized wallet types** for different use cases
- **Identity-integrated** wallet management
- **Multi-wallet coordination** for single identities
- **Transaction history** and balance tracking
- **Wallet lifecycle** management

## Module Structure

```
wallets/
├── mod.rs              - Module organization
└── multi_wallet.rs     - Multi-wallet manager (896 lines)
```

---

## WalletType Enumeration

### 10 Specialized Wallet Types

```rust
pub enum WalletType {
    Personal,      // Daily spending and transactions
    Business,      // Business operations and contracts
    Investment,    // Long-term holdings and investments
    Savings,       // Protected savings with restrictions
    Rewards,       // Infrastructure service rewards
    Staking,       // Network consensus participation
    Governance,    // DAO voting and governance
    Escrow,        // Multi-party contract escrow
    Development,   // Development and creator funding
    Donation,      // Charitable contributions and tips
}
```

### Wallet Type Purposes

#### Personal Wallet
- **Purpose**: Day-to-day spending
- **Use Cases**: Payments, purchases, regular transfers
- **Restrictions**: None
- **Typical Balance**: Low to medium

#### Business Wallet
- **Purpose**: Business operations
- **Use Cases**: Business transactions, invoicing, payroll
- **Restrictions**: May require business identity verification
- **Typical Balance**: Medium to high

#### Investment Wallet
- **Purpose**: Long-term holdings
- **Use Cases**: Asset accumulation, investment positions
- **Restrictions**: May have withdrawal delays
- **Typical Balance**: High

#### Savings Wallet
- **Purpose**: Protected savings
- **Use Cases**: Emergency funds, protected reserves
- **Restrictions**: Limited withdrawals, time locks possible
- **Typical Balance**: Medium to high

#### Rewards Wallet
- **Purpose**: Infrastructure rewards
- **Use Cases**: Routing rewards, storage rewards, bonuses
- **Restrictions**: Automatic deposits only
- **Typical Balance**: Varies based on infrastructure work

#### Staking Wallet
- **Purpose**: Network staking
- **Use Cases**: Consensus participation, validator stakes
- **Restrictions**: Locked during staking period
- **Typical Balance**: Minimum 1000 SOV

#### Governance Wallet
- **Purpose**: DAO participation
- **Use Cases**: Voting, proposals, governance actions
- **Restrictions**: May require minimum balance for voting
- **Typical Balance**: Varies

#### Escrow Wallet
- **Purpose**: Multi-party contracts
- **Use Cases**: Escrow services, conditional payments
- **Restrictions**: Locked until conditions met
- **Typical Balance**: Contract-dependent

#### Development Wallet
- **Purpose**: Development funding
- **Use Cases**: Open source contributions, creator rewards
- **Restrictions**: None
- **Typical Balance**: Varies

#### Donation Wallet
- **Purpose**: Charitable giving
- **Use Cases**: Tips, donations, charitable contributions
- **Restrictions**: Outgoing only
- **Typical Balance**: Low

---

## Wallet Structure

```rust
pub struct Wallet {
    pub wallet_id: [u8; 32],              // Unique wallet identifier
    pub name: String,                      // User-defined name
    pub wallet_type: WalletType,          // Type of wallet
    pub balance: u64,                     // Current balance in SOV
    pub owner_identity: [u8; 32],         // Owner's identity address
    pub created_at: u64,                  // Creation timestamp
    pub last_activity: u64,               // Last transaction timestamp
    pub transaction_count: u64,           // Total transactions
    pub status: WalletStatus,             // Current status
}
```

### WalletStatus

```rust
pub enum WalletStatus {
    Active,      // Normal operation
    Inactive,    // Temporarily disabled
    Frozen,      // Locked by system/security
    Archived,    // No longer in use, read-only
}
```

### Wallet Methods

#### `new(name: &str, wallet_type: WalletType, owner: [u8; 32]) -> Self`

Create new wallet.

```rust
let wallet = Wallet::new(
    "My Personal Wallet",
    WalletType::Personal,
    identity_address,
);
```

#### `deposit(&mut self, amount: u64) -> Result<()>`

Deposit funds into wallet.

```rust
wallet.deposit(1000)?; // Deposit 1000 SOV
assert_eq!(wallet.balance, 1000);
```

#### `withdraw(&mut self, amount: u64) -> Result<()>`

Withdraw funds from wallet.

```rust
wallet.withdraw(500)?; // Withdraw 500 SOV
assert_eq!(wallet.balance, 500);
```

#### `get_balance(&self) -> u64`

Get current balance.

```rust
let balance = wallet.get_balance();
println!("Balance: {} SOV", balance);
```

#### `is_active(&self) -> bool`

Check if wallet is active.

```rust
if wallet.is_active() {
    // Perform operation
}
```

---

## MultiWalletManager

### Purpose

Manages multiple wallets for a single identity, enabling:
- Creating and managing specialized wallets
- Transferring between wallets
- Tracking total balance across all wallets
- Setting default wallet for transactions
- Wallet lifecycle management

### Structure

```rust
pub struct MultiWalletManager {
    pub identity_address: [u8; 32],        // Owner identity
    pub wallets: Vec<Wallet>,              // All wallets
    pub default_wallet: Option<[u8; 32]>,  // Default wallet ID
    pub total_balance: u64,                // Sum of all balances
}
```

### Creating a Manager

```rust
use lib_economy::{MultiWalletManager, WalletType};

fn setup_wallet_system(identity: [u8; 32]) -> anyhow::Result<()> {
    // Create manager for identity
    let mut manager = MultiWalletManager::new(identity)?;
    
    // Create initial wallets
    let personal = manager.create_wallet("Daily Spending", WalletType::Personal)?;
    let savings = manager.create_wallet("Emergency Fund", WalletType::Savings)?;
    let rewards = manager.create_wallet("Node Rewards", WalletType::Rewards)?;
    
    // Set default wallet
    manager.set_default_wallet(personal)?;
    
    println!(" Wallet system ready with {} wallets", manager.wallets.len());
    Ok(())
}
```

### Core Methods

#### `new(identity_address: [u8; 32]) -> Result<Self>`

Create new wallet manager for an identity.

```rust
let manager = MultiWalletManager::new(identity_address)?;
```

#### `create_wallet(&mut self, name: &str, wallet_type: WalletType) -> Result<[u8; 32]>`

Create new wallet and return its ID.

```rust
let wallet_id = manager.create_wallet(
    "My Business Account",
    WalletType::Business,
)?;
```

#### `get_wallet(&self, wallet_id: &[u8; 32]) -> Option<&Wallet>`

Get immutable wallet reference.

```rust
if let Some(wallet) = manager.get_wallet(&wallet_id) {
    println!("Balance: {}", wallet.balance);
}
```

#### `get_wallet_mut(&mut self, wallet_id: &[u8; 32]) -> Option<&mut Wallet>`

Get mutable wallet reference.

```rust
if let Some(wallet) = manager.get_wallet_mut(&wallet_id) {
    wallet.deposit(1000)?;
}
```

#### `list_wallets(&self) -> Vec<&Wallet>`

List all wallets.

```rust
for wallet in manager.list_wallets() {
    println!("{}: {} SOV", wallet.name, wallet.balance);
}
```

#### `get_wallet_by_type(&self, wallet_type: WalletType) -> Option<&Wallet>`

Find first wallet of specific type.

```rust
if let Some(rewards_wallet) = manager.get_wallet_by_type(WalletType::Rewards) {
    println!("Rewards balance: {}", rewards_wallet.balance);
}
```

#### `get_total_balance(&self) -> u64`

Get total balance across all wallets.

```rust
let total = manager.get_total_balance();
println!("Total holdings: {} SOV", total);
```

### Transfer Operations

#### `transfer_between_wallets(&mut self, from: &[u8; 32], to: &[u8; 32], amount: u64) -> Result<()>`

Transfer funds between wallets (same identity).

```rust
// Move 5000 SOV from personal to savings
manager.transfer_between_wallets(
    &personal_wallet_id,
    &savings_wallet_id,
    5000,
)?;
```

#### `deposit(&mut self, wallet_id: &[u8; 32], amount: u64) -> Result<()>`

Deposit funds to specific wallet.

```rust
manager.deposit(&rewards_wallet_id, 1000)?;
```

#### `withdraw(&mut self, wallet_id: &[u8; 32], amount: u64) -> Result<()>`

Withdraw funds from specific wallet.

```rust
manager.withdraw(&personal_wallet_id, 500)?;
```

### Wallet Management

#### `set_default_wallet(&mut self, wallet_id: [u8; 32]) -> Result<()>`

Set default wallet for transactions.

```rust
manager.set_default_wallet(personal_wallet_id)?;
```

#### `get_default_wallet(&self) -> Option<&Wallet>`

Get default wallet reference.

```rust
if let Some(wallet) = manager.get_default_wallet() {
    println!("Default wallet: {}", wallet.name);
}
```

#### `deactivate_wallet(&mut self, wallet_id: &[u8; 32]) -> Result<()>`

Temporarily deactivate wallet.

```rust
manager.deactivate_wallet(&old_wallet_id)?;
```

#### `activate_wallet(&mut self, wallet_id: &[u8; 32]) -> Result<()>`

Reactivate deactivated wallet.

```rust
manager.activate_wallet(&wallet_id)?;
```

#### `archive_wallet(&mut self, wallet_id: &[u8; 32]) -> Result<()>`

Archive wallet (permanent, read-only).

```rust
manager.archive_wallet(&unused_wallet_id)?;
```

---

## Common Patterns

### Organized Financial Management

```rust
fn setup_organized_finances(identity: [u8; 32]) -> anyhow::Result<MultiWalletManager> {
    let mut manager = MultiWalletManager::new(identity)?;
    
    // Create wallets for different purposes
    let personal = manager.create_wallet("Daily", WalletType::Personal)?;
    let business = manager.create_wallet("Company", WalletType::Business)?;
    let savings = manager.create_wallet("Emergency", WalletType::Savings)?;
    let investment = manager.create_wallet("Long-term", WalletType::Investment)?;
    let rewards = manager.create_wallet("Node Earnings", WalletType::Rewards)?;
    
    // Set personal as default
    manager.set_default_wallet(personal)?;
    
    Ok(manager)
}
```

### Automatic Savings Transfer

```rust
fn auto_save_rewards(manager: &mut MultiWalletManager) -> anyhow::Result<()> {
    // Find rewards and savings wallets
    let rewards = manager.get_wallet_by_type(WalletType::Rewards)
        .ok_or(anyhow::anyhow!("No rewards wallet"))?;
    let savings = manager.get_wallet_by_type(WalletType::Savings)
        .ok_or(anyhow::anyhow!("No savings wallet"))?;
    
    let rewards_id = rewards.wallet_id;
    let savings_id = savings.wallet_id;
    let rewards_balance = rewards.balance;
    
    // Transfer 50% of rewards to savings
    if rewards_balance > 0 {
        let save_amount = rewards_balance / 2;
        manager.transfer_between_wallets(&rewards_id, &savings_id, save_amount)?;
        println!(" Auto-saved {} SOV to savings", save_amount);
    }
    
    Ok(())
}
```

### Monthly Balance Report

```rust
fn generate_balance_report(manager: &MultiWalletManager) {
    println!("\n=== Monthly Balance Report ===");
    println!("Identity: {}\n", hex::encode(&manager.identity_address[..8]));
    
    for wallet in manager.list_wallets() {
        if wallet.status == WalletStatus::Active {
            println!(
                "{:12} {:20} {:>12} SOV",
                format!("{:?}", wallet.wallet_type),
                wallet.name,
                wallet.balance
            );
        }
    }
    
    println!("{}", "-".repeat(50));
    println!(
        "{:33} {:>12} SOV\n",
        "TOTAL",
        manager.get_total_balance()
    );
}
```

### Wallet Consolidation

```rust
fn consolidate_to_investment(manager: &mut MultiWalletManager) -> anyhow::Result<()> {
    let investment = manager.get_wallet_by_type(WalletType::Investment)
        .ok_or(anyhow::anyhow!("No investment wallet"))?;
    let investment_id = investment.wallet_id;
    
    // Find wallets with excess funds
    let personal = manager.get_wallet_by_type(WalletType::Personal).unwrap();
    let rewards = manager.get_wallet_by_type(WalletType::Rewards).unwrap();
    
    // Transfer excess from personal (keep minimum 1000 SOV)
    if personal.balance > 1000 {
        let excess = personal.balance - 1000;
        manager.transfer_between_wallets(&personal.wallet_id, &investment_id, excess)?;
    }
    
    // Transfer all rewards
    if rewards.balance > 0 {
        manager.transfer_between_wallets(&rewards.wallet_id, &investment_id, rewards.balance)?;
    }
    
    Ok(())
}
```

---

## Security Features

### Identity Verification

All wallets are tied to verified identities:

```rust
// Wallet creation requires identity
let manager = MultiWalletManager::new(verified_identity)?;

// All wallets owned by this identity
for wallet in manager.list_wallets() {
    assert_eq!(wallet.owner_identity, verified_identity);
}
```

### Wallet Status Protection

Frozen or archived wallets cannot be modified:

```rust
// Attempt to withdraw from frozen wallet
if wallet.status == WalletStatus::Frozen {
    return Err(anyhow::anyhow!("Wallet is frozen"));
}

// Archived wallets are read-only
if wallet.status == WalletStatus::Archived {
    return Err(anyhow::anyhow!("Wallet is archived"));
}
```

### Balance Validation

All operations validate sufficient balance:

```rust
fn safe_withdraw(wallet: &mut Wallet, amount: u64) -> anyhow::Result<()> {
    if wallet.balance < amount {
        return Err(anyhow::anyhow!("Insufficient balance"));
    }
    wallet.withdraw(amount)
}
```

---

## Performance Considerations

### Wallet Lookup Optimization

```rust
// Indexed by wallet_id for O(log n) lookup
impl MultiWalletManager {
    fn find_wallet_index(&self, wallet_id: &[u8; 32]) -> Option<usize> {
        self.wallets.iter().position(|w| &w.wallet_id == wallet_id)
    }
}
```

### Total Balance Caching

```rust
// Total balance is cached and updated incrementally
impl MultiWalletManager {
    pub fn deposit(&mut self, wallet_id: &[u8; 32], amount: u64) -> Result<()> {
        // Update wallet
        let wallet = self.get_wallet_mut(wallet_id)?;
        wallet.deposit(amount)?;
        
        // Update cached total
        self.total_balance += amount;
        
        Ok(())
    }
}
```

---

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wallet() {
        let identity = [1u8; 32];
        let mut manager = MultiWalletManager::new(identity).unwrap();
        
        let wallet_id = manager.create_wallet("Test", WalletType::Personal).unwrap();
        
        let wallet = manager.get_wallet(&wallet_id).unwrap();
        assert_eq!(wallet.name, "Test");
        assert_eq!(wallet.wallet_type, WalletType::Personal);
        assert_eq!(wallet.balance, 0);
    }

    #[test]
    fn test_transfer_between_wallets() {
        let identity = [1u8; 32];
        let mut manager = MultiWalletManager::new(identity).unwrap();
        
        let wallet1 = manager.create_wallet("W1", WalletType::Personal).unwrap();
        let wallet2 = manager.create_wallet("W2", WalletType::Savings).unwrap();
        
        // Deposit to wallet1
        manager.deposit(&wallet1, 1000).unwrap();
        
        // Transfer to wallet2
        manager.transfer_between_wallets(&wallet1, &wallet2, 400).unwrap();
        
        assert_eq!(manager.get_wallet(&wallet1).unwrap().balance, 600);
        assert_eq!(manager.get_wallet(&wallet2).unwrap().balance, 400);
    }

    #[test]
    fn test_total_balance() {
        let identity = [1u8; 32];
        let mut manager = MultiWalletManager::new(identity).unwrap();
        
        let w1 = manager.create_wallet("W1", WalletType::Personal).unwrap();
        let w2 = manager.create_wallet("W2", WalletType::Savings).unwrap();
        
        manager.deposit(&w1, 500).unwrap();
        manager.deposit(&w2, 300).unwrap();
        
        assert_eq!(manager.get_total_balance(), 800);
    }
}
```

---

## Integration

### With Transactions

```rust
use lib_economy::{Transaction, Priority};

fn send_payment_from_wallet(
    manager: &mut MultiWalletManager,
    wallet_id: &[u8; 32],
    recipient: [u8; 32],
    amount: u64,
) -> anyhow::Result<Transaction> {
    // Check balance
    let wallet = manager.get_wallet(wallet_id)
        .ok_or(anyhow::anyhow!("Wallet not found"))?;
    
    // Create transaction
    let tx = Transaction::new_payment(
        wallet.owner_identity,
        recipient,
        amount,
        Priority::Normal,
    )?;
    
    // Deduct from wallet (amount + fees)
    let total_cost = amount + tx.total_fee;
    manager.withdraw(wallet_id, total_cost)?;
    
    Ok(tx)
}
```

### With Rewards

```rust
use lib_economy::TokenReward;

fn credit_infrastructure_rewards(
    manager: &mut MultiWalletManager,
    reward: &TokenReward,
) -> anyhow::Result<()> {
    // Find or create rewards wallet
    let rewards_wallet = match manager.get_wallet_by_type(WalletType::Rewards) {
        Some(w) => w.wallet_id,
        None => manager.create_wallet("Infrastructure Rewards", WalletType::Rewards)?,
    };
    
    // Credit rewards
    manager.deposit(&rewards_wallet, reward.total_reward)?;
    
    println!(" Credited {} SOV to rewards wallet", reward.total_reward);
    Ok(())
}
```

---

## Best Practices

1. **Create Specialized Wallets**: Use appropriate wallet types for different activities
2. **Set Default Wallet**: Always set a default wallet for convenience
3. **Regular Transfers**: Move rewards to savings/investment periodically
4. **Check Balances**: Always verify sufficient balance before operations
5. **Archive Unused**: Archive old wallets to keep management clean
6. **Monitor Total**: Track total balance across all wallets
7. **Identity Verification**: Ensure identity is verified before creating wallets

---

## Related Documentation

- [API Reference](./API_REFERENCE.md#wallets-module) - Complete API
- [Examples](./EXAMPLES.md#multi-wallet-management) - Usage examples
- [Models](./models.md) - Economic model integration
- [Transactions](./transactions.md) - Transaction creation
