# lib-blockchain Architecture Guide

## Overview

The `lib-blockchain` module implements a comprehensive blockchain system for the Zero Hash Transfer Protocol (ZHTP). This guide details the architecture, design decisions, and component interactions within the blockchain system.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        lib-blockchain                           │
├─────────────────────────────────────────────────────────────────┤
│  Core Blockchain Layer                                         │
│  ├─ Blockchain Engine (blockchain.rs)                         │
│  ├─ Block System (block/)                                     │
│  ├─ Transaction System (transaction/)                         │
│  └─ Mempool (mempool.rs)                                      │
├─────────────────────────────────────────────────────────────────┤
│  Smart Contract Platform (contracts/)                          │
│  ├─ Token Contracts (tokens/)                                 │
│  ├─ Web4 Contracts (web4/)                                    │
│  ├─ Messaging Contracts (messaging/)                          │
│  ├─ File Sharing (files/)                                     │
│  └─ Contract Runtime (executor/, runtime/)                    │
├─────────────────────────────────────────────────────────────────┤
│  Integration Layer (integration/)                              │
│  ├─ Enhanced ZK Crypto (enhanced_zk_crypto.rs)               │
│  ├─ Economic Integration (economic_integration.rs)            │
│  ├─ Consensus Integration (consensus_integration.rs)          │
│  └─ Storage Integration (storage_integration.rs)             │
├─────────────────────────────────────────────────────────────────┤
│  Type System (types/)                                         │
│  ├─ Transaction Types                                         │
│  ├─ Contract Types                                            │
│  ├─ Hash Utilities                                            │
│  └─ Difficulty Management                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
              ┌─────▼─────┐ ┌───▼────┐ ┌───▼─────┐
              │lib-crypto │ │lib-proofs│ │lib-storage│
              │           │ │          │ │           │
              │- Key Mgmt │ │- ZK Proofs│ │- DHT      │
              │- Signing  │ │- Plonky2  │ │- Erasure  │
              │- Hashing  │ │- Circuits │ │- Backup   │
              └───────────┘ └──────────┘ └───────────┘
                    │           │           │
              ┌─────▼─────┐ ┌───▼────┐ ┌───▼─────┐
              │lib-identity││lib-economy││lib-consensus│
              │           │ │          │ │           │
              │- DID      │ │- UBI     │ │- Validators│
              │- Privacy  │ │- Rewards │ │- DAO      │
              │- Creds    │ │- Fees    │ │- Voting   │
              └───────────┘ └──────────┘ └───────────┘
```

## Core Components

### 1. Blockchain Engine (`blockchain.rs`)

The main blockchain implementation providing:

- **State Management**: Tracks blockchain height, difficulty, nullifier set, UTXO set
- **Block Processing**: Validates and adds blocks to the chain
- **Transaction Processing**: Validates transactions and manages the mempool
- **Identity Registry**: Manages on-chain identity registrations
- **Smart Contract Integration**: Coordinates with the contract platform
- **Economic Features**: Integrates UBI distribution and economic incentives

Key Features:
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

### 2. Block System (`block/`)

Implements the block structure and validation:

- **Block Structure**: Header with metadata and transaction list
- **Proof of Work**: Difficulty-based mining with adjustable targets
- **Merkle Trees**: Transaction commitment with efficient verification
- **Validation**: Comprehensive block and header validation

Block Header Structure:
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

### 3. Transaction System (`transaction/`)

Implements zero-knowledge transactions:

- **ZK Transactions**: Private transactions using ZK-SNARKs
- **UTXO Model**: Unspent transaction output tracking
- **Identity Integration**: Support for identity and wallet data
- **Multi-Type Support**: Transfer, identity, contract, and system transactions

Transaction Structure:
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

### 4. Smart Contract Platform (`contracts/`)

Comprehensive smart contract system:

- **Multi-Contract Support**: Tokens, Web4, messaging, files, governance
- **WASM Runtime**: WebAssembly execution with gas metering
- **Gas System**: Prevent infinite loops and resource abuse
- **State Management**: Persistent contract state with versioning
- **Event System**: Contract events and logging

Contract Architecture:
```
┌─────────────────────────────────────────────────┐
│           Smart Contract Platform              │
├─────────────────────────────────────────────────┤
│  Contract Types                                 │
│  ├─ TokenContract (ZHTP + Custom Tokens)      │
│  ├─ Web4Contract (Decentralized Websites)     │
│  ├─ MessagingContract (Encrypted Messaging)   │
│  ├─ FileContract (File Sharing)               │
│  └─ GovernanceContract (DAO Voting)           │
├─────────────────────────────────────────────────┤
│  Runtime Environment                            │
│  ├─ WASM Executor (wasmtime integration)      │
│  ├─ Gas Metering (resource management)        │
│  ├─ Sandbox (isolated execution)              │
│  └─ State Manager (persistent storage)        │
├─────────────────────────────────────────────────┤
│  Contract API                                   │
│  ├─ Deploy Contract                            │
│  ├─ Execute Contract                           │
│  ├─ Query State                                │
│  └─ Handle Events                              │
└─────────────────────────────────────────────────┘
```

## Integration Layer

### 1. Enhanced ZK Crypto Integration

Provides production-ready zero-knowledge proof integration:

- **ZK Proofs**: Integrates lib-proofs for actual ZK proof generation/verification
- **Multiple Proof Systems**: Supports Plonky2, STARK, and other proof systems
- **Transaction Privacy**: Hide amounts, participants, and transaction graphs
- **Nullifier Management**: Prevent double-spending without revealing history

### 2. Economic Integration

Connects blockchain with lib-economy for:

- **UBI Distribution**: Automated Universal Basic Income to verified citizens
- **Network Rewards**: Incentivize infrastructure providers and validators
- **Fee Distribution**: Split transaction fees between network and UBI funding
- **Treasury Management**: DAO-controlled treasury for community funds
- **Economic Validation**: Ensure economic rules and constraints

### 3. Consensus Integration

Coordinates with lib-consensus for:

- **Validator Management**: Register and manage blockchain validators
- **Block Production**: Coordinate block proposal and validation
- **DAO Governance**: On-chain governance with proposal and voting
- **Reward Distribution**: Distribute consensus rewards to participants
- **Byzantine Fault Tolerance**: Handle malicious validators and network partitions

### 4. Storage Integration

Provides persistent storage through lib-storage:

- **Blockchain State Persistence**: Store complete blockchain state
- **Block Archival**: Long-term block storage with retrieval
- **UTXO Set Management**: Efficient UTXO set storage and updates
- **Identity Data Storage**: Secure identity data with access control
- **Backup and Recovery**: Erasure-coded backup with disaster recovery

## Data Flow Architecture

### Transaction Processing Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │───▶│   Mempool   │───▶│  Validator  │
│ Creates TX  │    │ Validates   │    │ Creates     │
│             │    │ & Stores    │    │ Block       │
└─────────────┘    └─────────────┘    └─────────────┘
                            │                   │
                            ▼                   ▼
                   ┌─────────────┐    ┌─────────────┐
                   │ZK Validator │    │ Blockchain  │
                   │Checks Proofs│    │ Adds Block  │
                   │& Nullifiers │    │ & Updates   │
                   └─────────────┘    └─────────────┘
```

### Smart Contract Execution Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Contract    │───▶│ WASM        │───▶│ State       │
│ Call TX     │    │ Runtime     │    │ Manager     │
└─────────────┘    └─────────────┘    └─────────────┘
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Gas         │    │ Sandbox     │    │ Event       │
│ Metering    │    │ Execution   │    │ Emission    │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Privacy Architecture

### Zero-Knowledge Transaction Privacy

The blockchain implements comprehensive privacy through zero-knowledge proofs:

1. **Amount Privacy**: Transaction amounts are hidden using commitments
2. **Participant Privacy**: Sender and receiver identities are protected
3. **Balance Privacy**: Account balances are private with ZK proofs
4. **Graph Privacy**: Transaction relationships are obscured
5. **Optional Transparency**: Identity revelation for compliance

Privacy Components:
```
┌─────────────────────────────────────────────────┐
│              ZK Privacy System                  │
├─────────────────────────────────────────────────┤
│  Commitment Scheme                              │
│  ├─ Pedersen Commitments (amounts)             │
│  ├─ Nullifier Generation (double-spend prev)   │
│  ├─ Note Encryption (recipient data)           │
│  └─ Merkle Tree (UTXO membership)             │
├─────────────────────────────────────────────────┤
│  Proof Generation                               │
│  ├─ Range Proofs (positive amounts)            │
│  ├─ Balance Proofs (input >= output + fee)     │
│  ├─ Spend Proofs (ownership verification)      │
│  └─ Nullifier Proofs (unique spending)         │
├─────────────────────────────────────────────────┤
│  Verification                                   │
│  ├─ Plonky2 Verifier (fast verification)      │
│  ├─ STARK Verifier (post-quantum security)    │
│  ├─ Bulletproofs (range proof verification)   │
│  └─ Groth16 (legacy support)                  │
└─────────────────────────────────────────────────┘
```

## Web4 Decentralized Web Architecture

Web4 enables hosting decentralized websites on the blockchain:

### Domain System
- **Domain Registration**: Register .zhtp domains on-chain
- **Ownership Management**: Transfer and update domain ownership
- **Subdomain Support**: Create hierarchical domain structures
- **Expiration Handling**: Automatic domain expiration and renewal

### Content Management
- **DHT Integration**: Store website content in distributed hash table
- **Content Addressing**: Use content hashes for immutable references
- **Manifest System**: Deploy website manifests with routing information
- **Version Control**: Support multiple website versions

### Routing System
- **Gateway Nodes**: Serve Web4 websites to regular browsers
- **DNS Integration**: Bridge .zhtp domains with traditional DNS
- **CDN Support**: Cache and distribute content globally
- **Performance Optimization**: Optimize content delivery

Web4 Architecture:
```
┌─────────────────────────────────────────────────┐
│              Web4 System                        │
├─────────────────────────────────────────────────┤
│  Domain Layer                                   │
│  ├─ Domain Registration (on-chain)             │
│  ├─ Ownership Management (smart contracts)     │
│  ├─ Subdomain Routing (hierarchical)           │
│  └─ Expiration Handling (automatic)            │
├─────────────────────────────────────────────────┤
│  Content Layer                                  │
│  ├─ DHT Storage (distributed content)          │
│  ├─ Content Hashing (immutable references)     │
│  ├─ Manifest Management (routing info)         │
│  └─ Version Control (content updates)          │
├─────────────────────────────────────────────────┤
│  Gateway Layer                                  │
│  ├─ HTTP Gateway (browser compatibility)       │
│  ├─ DNS Bridge (traditional DNS support)       │
│  ├─ CDN Integration (performance)               │
│  └─ Caching System (fast content delivery)     │
└─────────────────────────────────────────────────┘
```

## Consensus Architecture

### Adaptive Difficulty Adjustment

The blockchain uses governance-controlled difficulty parameters through `DifficultyConfig`:

- **Configurable Parameters**: Target timespan, adjustment interval, and adjustment factors
- **Default Settings**: 14-day timespan, 2016-block interval, 4x max adjustment (Bitcoin-style)
- **Governance Updates**: Parameters can be modified via DAO proposals
- **Audit Trail**: `last_updated_at_height` tracks parameter changes

```rust
pub struct DifficultyConfig {
    pub target_timespan: u64,         // Default: 14 days
    pub adjustment_interval: u64,      // Default: 2016 blocks
    pub min_adjustment_factor: u64,    // Default: 4
    pub max_adjustment_factor: u64,    // Default: 4
    pub last_updated_at_height: u64,
}
```

**Key Methods:**
- `target_block_time()` - Calculates target seconds per block (default: 600s)
- `clamp_timespan()` - Prevents extreme difficulty changes
- `validate()` - Ensures parameters are within safe ranges

## Economic Architecture

### Universal Basic Income System

The blockchain includes a built-in UBI system:

- **Citizen Verification**: Link UBI to verified identity system
- **Automated Distribution**: Regular UBI payments to eligible citizens
- **Funding Mechanism**: Fund UBI through transaction fees and inflation
- **Economic Modeling**: Balance UBI amount with economic stability

### Network Incentives

Reward network participants for maintaining infrastructure:

- **Validator Rewards**: Compensate block validators and producers
- **Storage Rewards**: Incentivize distributed storage providers
- **Network Rewards**: Reward routing and connectivity providers
- **Development Rewards**: Fund core development through treasury

Economic Flow:
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Transaction  │───▶│Fee Split    │───▶│Distribution │
│Fees         │    │70% Network  │    │Mechanisms   │
│             │    │30% UBI Fund │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Network      │    │UBI Treasury │    │Reward       │
│Operations   │    │Management   │    │Distribution │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Performance Considerations

### Scalability

- **Parallel Processing**: Multi-threaded transaction validation
- **Efficient Data Structures**: Optimized hash maps and trees
- **Caching Strategy**: Intelligent caching of frequently accessed data
- **Batch Processing**: Process multiple transactions efficiently

### Storage Optimization

- **Compression**: Compress blockchain data before storage
- **Erasure Coding**: Distribute data across multiple nodes
- **Pruning**: Remove old data while maintaining security
- **Indexing**: Fast lookup of transactions and blocks

### Network Efficiency

- **Delta Sync**: Sync only new blocks and transactions
- **Compression**: Compress network messages
- **Batching**: Batch multiple operations together
- **Connection Pooling**: Reuse network connections

## Security Model

### Cryptographic Security

- **Post-Quantum Cryptography**: Dilithium and Kyber for quantum resistance
- **Zero-Knowledge Proofs**: Privacy without sacrificing verifiability  
- **Multi-Signature Support**: Multi-sig transactions for enhanced security
- **Key Rotation**: Support for key updates and rotation

### Smart Contract Security

- **Sandboxed Execution**: Isolated WASM runtime environment
- **Gas Limits**: Prevent infinite loops and resource exhaustion
- **Input Validation**: Validate all contract inputs and parameters
- **State Consistency**: Ensure consistent contract state updates

### Network Security

- **Byzantine Fault Tolerance**: Handle up to 1/3 malicious validators
- **Eclipse Attack Prevention**: Prevent network isolation attacks
- **Sybil Resistance**: Stake and identity requirements for participation
- **DDoS Protection**: Rate limiting and traffic management

## Development Guidelines

### Code Organization

- **Modular Design**: Separate concerns into distinct modules
- **Feature Gates**: Use Cargo features for optional functionality
- **Documentation**: Comprehensive documentation for all public APIs
- **Testing**: Unit tests and integration tests for all components

### Performance Guidelines

- **Avoid Cloning**: Use references where possible to avoid unnecessary copying
- **Async/Await**: Use async functions for I/O operations
- **Memory Management**: Efficient memory usage and cleanup
- **Profiling**: Regular performance profiling and optimization

### Security Guidelines

- **Input Validation**: Validate all external inputs
- **Error Handling**: Proper error handling without information leakage
- **Cryptographic Best Practices**: Use proven cryptographic libraries
- **Code Review**: Thorough review of all code changes

## Future Architecture

### Planned Enhancements

- **Layer 2 Scaling**: Payment channels and state channels
- **Cross-Chain Bridges**: Interoperability with other blockchains
- **Enhanced Privacy**: Private smart contracts and ZK-rollups
- **Mobile Optimization**: Lightweight clients for mobile devices
- **Quantum Resistance**: Enhanced post-quantum cryptography