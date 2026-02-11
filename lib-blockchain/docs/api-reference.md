# API Reference - lib-blockchain

Complete API documentation for the ZHTP blockchain library.

## Core Types

### Blockchain

Main blockchain structure providing state management and block processing.

```rust
pub struct Blockchain {
    pub height: u64,
    pub blocks: Vec<Block>,
    pub difficulty: Difficulty,
    pub nullifier_set: HashSet<Hash>,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub pending_transactions: Vec<Transaction>,
    // ... additional fields
}
```

#### Methods

##### `new() -> Result<Self>`
Creates a new blockchain with genesis block.

```rust
let blockchain = Blockchain::new()?;
```

##### `add_pending_transaction(&mut self, transaction: Transaction) -> Result<()>`
Adds a transaction to the mempool after validation.

```rust
blockchain.add_pending_transaction(transaction)?;
```

##### `mine_pending_block(&mut self) -> Result<Block>`
Creates a new block from pending transactions.

```rust
let new_block = blockchain.mine_pending_block()?;
```

##### `add_block(&mut self, block: Block) -> Result<()>`
Adds a validated block to the blockchain.

```rust
blockchain.add_block(block)?;
```

##### `verify_transaction(&self, transaction: &Transaction) -> Result<bool>`
Verifies a transaction against blockchain state.

```rust
let is_valid = blockchain.verify_transaction(&transaction)?;
```

##### `get_balance(&self, address: &[u8; 32]) -> u64`
Gets the balance for an address (simplified for public interface).

```rust
let balance = blockchain.get_balance(&address);
```

---

### Block

Individual blockchain block containing header and transactions.

```rust
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}
```

#### Methods

##### `new(header: BlockHeader, transactions: Vec<Transaction>) -> Self`
Creates a new block.

```rust
let block = Block::new(header, transactions);
```

##### `hash(&self) -> Hash`
Calculates the block hash.

```rust
let block_hash = block.hash();
```

##### `height(&self) -> u64`
Returns the block height.

```rust
let height = block.height();
```

##### `verify(&self, previous_block: Option<&Block>) -> Result<bool>`
Verifies block validity.

```rust
let is_valid = block.verify(previous_block)?;
```

---

### BlockHeader

Block metadata including merkle root and difficulty.

```rust
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: Hash,
    pub merkle_root: Hash,
    pub timestamp: u64,
    pub difficulty: Difficulty,
    pub height: u64,
    pub transaction_count: u32,
    pub block_size: u64,
    pub cumulative_difficulty: Difficulty,
}
```

#### Methods

##### `new(...) -> Self`
Creates a new block header.

```rust
let header = BlockHeader::new(
    1,              // version
    previous_hash,
    merkle_root,
    timestamp,
    difficulty,
    height,
    tx_count,
    block_size,
    cumulative_difficulty,
);
```

##### `hash(&self) -> Hash`
Calculates the header hash.

```rust
let header_hash = header.hash();
```

---

### Transaction

Zero-knowledge transaction with inputs, outputs, and proofs.

```rust
pub struct Transaction {
    pub version: u32,
    pub transaction_type: TransactionType,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub signature: Signature,
    pub memo: Vec<u8>,
    pub identity_data: Option<IdentityTransactionData>,
    pub wallet_data: Option<WalletTransactionData>,
}
```

#### Methods

##### `new(...) -> Self`
Creates a new transaction.

```rust
let transaction = Transaction::new(
    inputs,
    outputs,
    fee,
    signature,
    memo,
);
```

##### `new_transfer(...) -> Result<Self>`
Creates a transfer transaction.

```rust
let tx = Transaction::new_transfer(
    from_address,
    to_address,
    amount,
    fee,
    &keypair,
)?;
```

##### `new_identity_registration(...) -> Self`
Creates an identity registration transaction.

```rust
let tx = Transaction::new_identity_registration(
    identity_data,
    inputs,
    signature,
    memo,
);
```

##### `hash(&self) -> Hash`
Calculates the transaction hash.

```rust
let tx_hash = transaction.hash();
```

##### `verify(&self) -> Result<bool>`
Verifies transaction validity.

```rust
let is_valid = transaction.verify()?;
```

---

### TransactionInput

Transaction input with ZK proof.

```rust
pub struct TransactionInput {
    pub previous_output: Hash,
    pub output_index: u32,
    pub nullifier: Hash,
    pub zk_proof: ZkTransactionProof,
}
```

---

### TransactionOutput

Transaction output with commitment and note.

```rust
pub struct TransactionOutput {
    pub commitment: Hash,
    pub note: Hash,
    pub recipient: PublicKey,
}
```

#### Methods

##### `new(...) -> Self`
Creates a new transaction output.

```rust
let output = TransactionOutput::new(
    commitment,
    note,
    recipient,
);
```

---

## Smart Contract Types

### TokenContract

Multi-token contract supporting SOV native and custom tokens.

```rust
pub struct TokenContract {
    pub token_name: String,
    pub token_symbol: String,
    pub total_supply: u64,
    pub decimals: u8,
    pub is_deflationary: bool,
    pub balances: HashMap<[u8; 32], u64>,
    pub allowances: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,
    // ... additional fields
}
```

#### Methods

##### `new(...) -> Result<Self>`
Creates a new token contract.

```rust
let token = TokenContract::new(
    "MyToken".to_string(),
    "MTK".to_string(),
    1_000_000,  // supply
    18,         // decimals
    false,      // not deflationary
)?;
```

##### `zhtp_native_token() -> Self`
Creates the SOV native token contract.

```rust
let zhtp = TokenContract::zhtp_native_token();
```

##### `transfer(&mut self, from: [u8; 32], to: [u8; 32], amount: u64) -> Result<()>`
Transfers tokens between addresses.

```rust
token.transfer(from_address, to_address, amount)?;
```

##### `approve(&mut self, owner: [u8; 32], spender: [u8; 32], amount: u64) -> Result<()>`
Approves token allowance.

```rust
token.approve(owner_address, spender_address, allowance)?;
```

##### `mint(&mut self, to: [u8; 32], amount: u64) -> Result<()>`
Mints new tokens (if allowed).

```rust
token.mint(recipient_address, mint_amount)?;
```

##### `burn(&mut self, from: [u8; 32], amount: u64) -> Result<()>`
Burns tokens (if deflationary).

```rust
token.burn(holder_address, burn_amount)?;
```

---

### Web4Contract

Decentralized website hosting contract.

```rust
pub struct Web4Contract {
    pub domains: HashMap<String, DomainInfo>,
    pub manifests: HashMap<String, WebsiteManifest>,
    // ... additional fields
}
```

#### Methods

##### `new() -> Self`
Creates a new Web4 contract.

```rust
let web4 = Web4Contract::new();
```

##### `register_domain(&mut self, domain: &str, owner: [u8; 32]) -> Result<()>`
Registers a .zhtp domain.

```rust
web4.register_domain("example.zhtp", owner_address)?;
```

##### `deploy_manifest(&mut self, domain: &str, manifest: WebsiteManifest) -> Result<()>`
Deploys a website manifest.

```rust
web4.deploy_manifest("example.zhtp", manifest)?;
```

##### `resolve_content(&self, domain: &str, path: &str) -> Result<Hash>`
Resolves website content.

```rust
let content_hash = web4.resolve_content("example.zhtp", "/index.html")?;
```

---

### ContractCall

Smart contract execution call.

```rust
pub struct ContractCall {
    pub contract_address: [u8; 32],
    pub method_name: String,
    pub parameters: Vec<u8>,
    pub gas_limit: u64,
    pub call_permissions: CallPermissions,
}
```

#### Methods

##### `new(...) -> Self`
Creates a new contract call.

```rust
let call = ContractCall::new(
    contract_address,
    "transfer".to_string(),
    parameters,
    100_000, // gas limit
    CallPermissions::default(),
);
```

##### `deploy_token_contract(contract: TokenContract) -> Self`
Creates a token contract deployment call.

```rust
let call = ContractCall::deploy_token_contract(token_contract);
```

##### `transfer_tokens(...) -> Self`
Creates a token transfer call.

```rust
let call = ContractCall::transfer_tokens(
    contract_address,
    to_address,
    amount,
);
```

---

## Integration Types

### EconomicTransactionProcessor

Processes economic transactions (UBI, rewards, fees).

```rust
pub struct EconomicTransactionProcessor {
    // ... internal fields
}
```

#### Methods

##### `new() -> Self`
Creates a new economic processor.

```rust
let processor = EconomicTransactionProcessor::new();
```

##### `process_economic_transaction(&mut self, ...) -> Result<Transaction>`
Processes an economic transaction.

```rust
let blockchain_tx = processor.process_economic_transaction(
    &economy_tx,
    &system_keypair,
).await?;
```

##### `create_ubi_distributions_for_blockchain(&mut self, ...) -> Result<Vec<Transaction>>`
Creates UBI distribution transactions.

```rust
let ubi_txs = processor.create_ubi_distributions_for_blockchain(
    &citizens,
    &system_keypair,
).await?;
```

##### `create_network_reward_transactions(&mut self, ...) -> Result<Vec<Transaction>>`
Creates network reward transactions.

```rust
let reward_txs = processor.create_network_reward_transactions(
    &rewards,
    &system_keypair,
).await?;
```

---

### BlockchainConsensusCoordinator

Coordinates blockchain with consensus engine.

```rust
pub struct BlockchainConsensusCoordinator {
    // ... internal fields
}
```

#### Methods

##### `new(...) -> Result<Self>`
Creates a new consensus coordinator.

```rust
let coordinator = BlockchainConsensusCoordinator::new(
    blockchain,
    mempool,
    consensus_config,
).await?;
```

##### `register_as_validator(&mut self, ...) -> Result<()>`
Registers this node as a validator.

```rust
coordinator.register_as_validator(
    identity,
    stake_amount,
    storage_capacity,
    &consensus_keypair,
    commission_rate,
).await?;
```

##### `start_consensus_coordinator(&mut self) -> Result<()>`
Starts the consensus coordination loops.

```rust
coordinator.start_consensus_coordinator().await?;
```

##### `get_consensus_status(&self) -> Result<ConsensusStatus>`
Gets current consensus status.

```rust
let status = coordinator.get_consensus_status().await?;
```

---

### BlockchainStorageManager

Manages persistent blockchain storage.

```rust
pub struct BlockchainStorageManager {
    // ... internal fields
}
```

#### Methods

##### `new(config: BlockchainStorageConfig) -> Result<Self>`
Creates a new storage manager.

```rust
let manager = BlockchainStorageManager::new(config).await?;
```

##### `store_blockchain_state(&mut self, blockchain: &Blockchain) -> Result<StorageOperationResult>`
Stores complete blockchain state.

```rust
let result = manager.store_blockchain_state(&blockchain).await?;
```

##### `retrieve_blockchain_state(&mut self, content_hash: ContentHash) -> Result<Blockchain>`
Retrieves blockchain state from storage.

```rust
let blockchain = manager.retrieve_blockchain_state(content_hash).await?;
```

##### `backup_blockchain(&mut self, blockchain: &Blockchain) -> Result<Vec<StorageOperationResult>>`
Creates complete blockchain backup.

```rust
let results = manager.backup_blockchain(&blockchain).await?;
```

---

## Utility Types

### Hash

32-byte hash used throughout the blockchain.

```rust
pub struct Hash([u8; 32]);
```

#### Methods

##### `new(data: [u8; 32]) -> Self`
Creates a new hash.

```rust
let hash = Hash::new(data);
```

##### `from_slice(data: &[u8]) -> Self`
Creates hash from slice (takes first 32 bytes).

```rust
let hash = Hash::from_slice(&data);
```

##### `as_bytes(&self) -> &[u8; 32]`
Returns hash as byte array.

```rust
let bytes = hash.as_bytes();
```

##### `default() -> Self`
Creates zero hash.

```rust
let zero_hash = Hash::default();
```

---

### Difficulty

Blockchain difficulty for proof-of-work.

```rust
pub struct Difficulty(u64);
```

#### Methods

##### `from_bits(bits: u64) -> Self`
Creates difficulty from bits.

```rust
let difficulty = Difficulty::from_bits(0x1d00ffff);
```

##### `as_target(&self) -> [u8; 32]`
Converts to target hash.

```rust
let target = difficulty.as_target();
```

---

### TransactionType

Enumeration of transaction types.

```rust
pub enum TransactionType {
    Transfer,
    IdentityRegistration,
    IdentityUpdate,
    IdentityRevocation,
    ContractDeployment,
    ContractExecution,
    SessionCreation,
    SessionTermination,
    ContentUpload,
    UbiDistribution,
    WalletRegistration,
}
```

#### Methods

##### `is_identity_transaction(&self) -> bool`
Checks if transaction relates to identity.

```rust
let is_identity = tx_type.is_identity_transaction();
```

##### `is_contract_transaction(&self) -> bool`
Checks if transaction relates to contracts.

```rust
let is_contract = tx_type.is_contract_transaction();
```

##### `description(&self) -> &'static str`
Returns human-readable description.

```rust
let desc = tx_type.description();
```

---

## Configuration Types

### BlockchainStorageConfig

Configuration for blockchain storage operations.

```rust
pub struct BlockchainStorageConfig {
    pub auto_persist_state: bool,
    pub persist_frequency: u64,
    pub enable_erasure_coding: bool,
    pub storage_tier: StorageTier,
    pub enable_compression: bool,
    pub enable_encryption: bool,
    pub max_cache_size: usize,
    pub enable_backup: bool,
}
```

#### Methods

##### `default() -> Self`
Creates default storage configuration.

```rust
let config = BlockchainStorageConfig::default();
```

---

## Error Types

### BlockchainError

Main error type for blockchain operations.

```rust
pub enum BlockchainError {
    InvalidTransaction(String),
    InvalidBlock(String),
    InvalidSignature(String),
    InsufficientFunds,
    DuplicateNullifier,
    ContractExecutionFailed(String),
    StorageError(String),
    ConsensusError(String),
    // ... additional variants
}
```

---

## Constants

### Blockchain Constants

```rust
pub const INITIAL_DIFFICULTY: u64 = 0x00000FFF;
pub const MAX_BLOCK_SIZE: usize = 1_048_576; // 1MB
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1000;
pub const TARGET_BLOCK_TIME: u64 = 10; // seconds
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016; // blocks (fallback if consensus coordinator unavailable)
```

### Contract Constants

```rust
pub const GAS_TOKEN: u64 = 2000;
pub const GAS_MESSAGING: u64 = 3000;
pub const GAS_CONTACT: u64 = 1500;
pub const GAS_GROUP: u64 = 2500;
pub const GAS_FILE: u64 = 3000;
pub const GAS_GOVERNANCE: u64 = 2500;
```

### Token Constants

```rust
pub const SOV_DECIMALS: u8 = 8;
pub const ZHTP_INITIAL_SUPPLY: u64 = 21_000_000_00_000_000; // 21M SOV
pub const ZHTP_BURN_RATE: u32 = 100; // 1% burn rate
```

---

## Feature Flags

The library supports several feature flags:

- `contracts`: Enable smart contract platform
- `wasm-runtime`: Enable WASM execution
- `testing`: Enable test utilities
- `consensus-integration`: Enable consensus integration
- `storage-integration`: Enable storage integration

```toml
[dependencies]
lib-blockchain = { path = "../lib-blockchain", features = ["contracts", "wasm-runtime"] }
```

---

## Examples

### Basic Blockchain Usage

```rust
use lib_blockchain::{Blockchain, Transaction, TransactionType};
use lib_crypto::generate_keypair;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize blockchain
    let mut blockchain = Blockchain::new()?;
    
    // Generate keypair
    let keypair = generate_keypair()?;
    
    // Create transaction
    let transaction = Transaction::new_transfer(
        sender_address,
        recipient_address,
        1000, // amount
        10,   // fee
        &keypair,
    )?;
    
    // Add to blockchain
    blockchain.add_pending_transaction(transaction)?;
    let new_block = blockchain.mine_pending_block()?;
    
    println!("Mined block at height: {}", new_block.height());
    Ok(())
}
```

### Smart Contract Deployment

```rust
use lib_blockchain::contracts::{TokenContract, ContractCall};

#[tokio::main]
async fn main() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Create token contract
    let token = TokenContract::new(
        "MyToken".to_string(),
        "MTK".to_string(),
        1_000_000,
        18,
        false,
    )?;
    
    // Deploy contract
    let call = ContractCall::deploy_token_contract(token);
    let result = blockchain.execute_contract_call(call, &deployer_keypair)?;
    
    println!("Contract deployed: {}", result.success);
    Ok(())
}
```

### Web4 Website Deployment

```rust
use lib_blockchain::contracts::{Web4Contract, WebsiteManifest};

#[tokio::main]
async fn main() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Deploy Web4 contract
    let web4 = Web4Contract::new();
    let call = ContractCall::deploy_web4_contract(web4);
    blockchain.execute_contract_call(call, &deployer_keypair)?;
    
    // Register domain
    let domain_call = ContractCall::register_web4_domain(
        contract_address,
        "mysite.zhtp".to_string(),
    );
    blockchain.execute_contract_call(domain_call, &owner_keypair)?;
    
    // Deploy manifest
    let manifest = WebsiteManifest::new("mysite.zhtp", content_hash);
    let manifest_call = ContractCall::deploy_web4_manifest(
        contract_address,
        "mysite.zhtp".to_string(),
        manifest,
    );
    blockchain.execute_contract_call(manifest_call, &owner_keypair)?;
    
    println!("Website deployed at mysite.zhtp");
    Ok(())
}
```
