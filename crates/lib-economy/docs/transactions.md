# Transactions Module

Complete documentation for the transaction system.

## Overview

The transactions module provides comprehensive transaction creation, validation, and fee processing with full DAO integration.

## Module Structure

```
transactions/
├── mod.rs                - Module organization
├── transaction.rs        - Core transaction structure (159 lines)
├── creation.rs          - Transaction creation utilities
├── validation.rs        - Transaction validation logic
├── fee_processing.rs    - Fee calculation and processing
├── dao_fee_proofs.rs    - DAO fee proof generation
└── priority_fees.rs     - Priority-based fee adjustments
```

## Transaction Structure

```rust
pub struct Transaction {
    pub tx_id: [u8; 32],                    // Unique transaction ID
    pub from: [u8; 32],                     // Sender address
    pub to: [u8; 32],                       // Recipient address
    pub amount: u64,                        // Amount in ZHTP
    pub base_fee: u64,                      // Infrastructure fee
    pub dao_fee: u64,                       // Mandatory DAO fee (2%)
    pub total_fee: u64,                     // base_fee + dao_fee
    pub tx_type: TransactionType,           // Type of transaction
    pub timestamp: u64,                     // Creation timestamp
    pub block_height: u64,                  // Block height (set by consensus)
    pub dao_fee_proof: Option<[u8; 32]>,    // Proof of correct DAO fee
}
```

## Transaction Types

```rust
pub enum TransactionType {
    Payment,                    // Regular payment (with fees)
    Reward,                     // Infrastructure reward (fee-free)
    UbiDistribution,           // UBI payment (fee-free)
    WelfareDistribution,       // Welfare payment (fee-free)
    Staking,                   // Network staking (with fees)
    InfrastructureService,     // Service payment (with fees)
}
```

### Fee-Exempt Types

```rust
impl TransactionType {
    pub fn is_fee_exempt(&self) -> bool {
        matches!(self, 
            TransactionType::Reward |
            TransactionType::UbiDistribution |
            TransactionType::WelfareDistribution
        )
    }
}
```

## Creating Transactions

### Payment Transaction

```rust
use lib_economy::{Transaction, Priority};

// Create payment
let tx = Transaction::new_payment(
    sender_address,
    recipient_address,
    10000,              // 10000 ZHTP
    Priority::Normal,
)?;

println!("Amount: {} ZHTP", tx.amount);
println!("Base fee: {} ZHTP", tx.base_fee);
println!("DAO fee (2%): {} ZHTP", tx.dao_fee);
println!("Total cost: {} ZHTP", tx.amount + tx.total_fee);
```

### Reward Transaction

```rust
// Create reward transaction (fee-free)
let tx = Transaction::new_reward(
    node_address,
    5000,  // 5000 ZHTP reward
)?;

assert_eq!(tx.base_fee, 0);
assert_eq!(tx.dao_fee, 0);
assert_eq!(tx.total_fee, 0);
```

### UBI Distribution

```rust
// Create UBI distribution (fee-free)
let tx = Transaction::new_ubi_distribution(
    citizen_address,
    1000,  // 1000 ZHTP UBI
)?;

assert_eq!(tx.tx_type, TransactionType::UbiDistribution);
assert_eq!(tx.total_fee, 0);
```

### Welfare Distribution

```rust
// Create welfare distribution (fee-free)
let tx = Transaction::new_welfare_distribution(
    recipient_address,
    2000,  // 2000 ZHTP welfare
)?;

assert_eq!(tx.total_fee, 0);
```

## Transaction Priority

```rust
pub enum Priority {
    Low,      // 0.5x fee (50% discount)
    Normal,   // 1.0x fee (standard)
    High,     // 2.0x fee (double)
    Urgent,   // 5.0x fee (5x cost)
}
```

### Priority Comparison

```rust
fn compare_priorities() -> anyhow::Result<()> {
    let amount = 10000;
    
    let low = Transaction::new_payment(from, to, amount, Priority::Low)?;
    let normal = Transaction::new_payment(from, to, amount, Priority::Normal)?;
    let high = Transaction::new_payment(from, to, amount, Priority::High)?;
    let urgent = Transaction::new_payment(from, to, amount, Priority::Urgent)?;
    
    println!("Low:    {} ZHTP fee", low.total_fee);
    println!("Normal: {} ZHTP fee", normal.total_fee);
    println!("High:   {} ZHTP fee", high.total_fee);
    println!("Urgent: {} ZHTP fee", urgent.total_fee);
    
    Ok(())
}
```

## Fee Calculation

### Formula

```rust
// Base infrastructure fee
base_fee = tx_size * BASE_FEE_PER_BYTE * priority_multiplier

// DAO fee (2% of amount, always)
dao_fee = (amount * 200) / 10000

// Total fee
total_fee = base_fee + dao_fee
```

### Example Calculation

```rust
// 10,000 ZHTP payment, 250 bytes, Normal priority
let tx_size = 250;
let amount = 10000;
let priority = Priority::Normal; // 1.0x multiplier

base_fee = 250 * 1 * 1.0 = 250 ZHTP
dao_fee = (10000 * 200) / 10000 = 200 ZHTP
total_fee = 250 + 200 = 450 ZHTP

Total cost = 10000 + 450 = 10450 ZHTP
```

## DAO Fee Proof

Every transaction with a DAO fee includes a proof:

```rust
// DAO fee proof generation
let dao_fee_proof = hash_blake3(
    &format!("dao_fee_proof_{}_{}", dao_fee, timestamp).as_bytes()
);

// Verification
let expected_dao_fee = (amount * 200) / 10000;
assert_eq!(dao_fee, expected_dao_fee);
```

## Transaction Validation

### Validation Checks

```rust
pub fn validate_transaction(tx: &Transaction) -> Result<()> {
    // 1. Check addresses
    if tx.from == [0u8; 32] && !tx.tx_type.is_network_transaction() {
        return Err(anyhow::anyhow!("Invalid sender"));
    }
    
    // 2. Check amount
    if tx.amount == 0 {
        return Err(anyhow::anyhow!("Zero amount"));
    }
    
    // 3. Verify DAO fee
    if !tx.tx_type.is_fee_exempt() {
        let expected_dao_fee = (tx.amount * 200) / 10000;
        if tx.dao_fee != expected_dao_fee {
            return Err(anyhow::anyhow!("Incorrect DAO fee"));
        }
    }
    
    // 4. Verify total fee
    if tx.total_fee != tx.base_fee + tx.dao_fee {
        return Err(anyhow::anyhow!("Incorrect total fee"));
    }
    
    Ok(())
}
```

## Complete Transaction Flow

```rust
use lib_economy::{Transaction, Priority, EconomicModel, DaoTreasury};

fn complete_transaction_flow(
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
) -> anyhow::Result<()> {
    // 1. Create transaction
    let tx = Transaction::new_payment(from, to, amount, Priority::Normal)?;
    
    println!("Transaction created:");
    println!("  TX ID: {}", hex::encode(&tx.tx_id[..8]));
    println!("  Amount: {} ZHTP", tx.amount);
    println!("  Fees: {} ZHTP (base: {}, DAO: {})", 
        tx.total_fee, tx.base_fee, tx.dao_fee);
    
    // 2. Validate transaction
    validate_transaction(&tx)?;
    println!(" Transaction validated");
    
    // 3. Process fees
    let model = EconomicModel::new();
    model.process_network_fees(tx.base_fee)?;
    
    let mut treasury = DaoTreasury::new();
    treasury.receive_dao_fee(tx.dao_fee)?;
    treasury.allocate_funds()?;
    println!(" Fees processed");
    
    // 4. Record on blockchain (would be done by consensus layer)
    // blockchain::record_transaction(tx)?;
    
    println!(" Transaction complete");
    Ok(())
}
```

## Integration with Wallets

```rust
use lib_economy::MultiWalletManager;

fn send_from_wallet(
    manager: &mut MultiWalletManager,
    wallet_id: &[u8; 32],
    recipient: [u8; 32],
    amount: u64,
    priority: Priority,
) -> anyhow::Result<Transaction> {
    // Get wallet
    let wallet = manager.get_wallet(wallet_id)
        .ok_or(anyhow::anyhow!("Wallet not found"))?;
    
    // Create transaction
    let tx = Transaction::new_payment(
        wallet.owner_identity,
        recipient,
        amount,
        priority,
    )?;
    
    // Check balance (amount + fees)
    let total_cost = amount + tx.total_fee;
    if wallet.balance < total_cost {
        return Err(anyhow::anyhow!("Insufficient balance"));
    }
    
    // Deduct from wallet
    manager.withdraw(wallet_id, total_cost)?;
    
    println!(" Sent {} ZHTP (+ {} fee) from wallet", amount, tx.total_fee);
    Ok(tx)
}
```

## Best Practices

1. **Always include fees in balance checks**
   ```rust
   let total_cost = amount + tx.total_fee;
   if balance < total_cost { return Err(...); }
   ```

2. **Validate transactions before processing**
   ```rust
   validate_transaction(&tx)?;
   // Then process
   ```

3. **Use appropriate priority for use case**
   - `Low`: Background tasks, non-urgent
   - `Normal`: Standard transactions
   - `High`: Important, time-sensitive
   - `Urgent`: Critical, immediate processing

4. **Process DAO fees immediately**
   ```rust
   treasury.receive_dao_fee(tx.dao_fee)?;
   treasury.allocate_funds()?;
   ```

5. **Check transaction type for fee exemptions**
   ```rust
   if tx.tx_type.is_fee_exempt() {
       assert_eq!(tx.total_fee, 0);
   }
   ```

## Related Documentation

- [API Reference](./API_REFERENCE.md#transactions-module) - Complete API
- [Models](./models.md) - Fee calculation details
- [Wallets](./wallets.md) - Wallet integration
- [Examples](./EXAMPLES.md#transaction-processing) - Usage examples
