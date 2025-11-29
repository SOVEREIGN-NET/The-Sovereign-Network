# ZHTP Blockchain (lib-blockchain)

A comprehensive blockchain implementation for the Zero Hash Transfer Protocol (ZHTP), providing zero-knowledge transactions, smart contracts, decentralized websites (Web4), and full ecosystem integration.

## Overview

`lib-blockchain` is the core blockchain component of the ZHTP ecosystem, implementing a privacy-focused blockchain with advanced features including:

- **Zero-Knowledge Transactions**: Private transactions using ZK-SNARKs and Plonky2 proofs
- **Smart Contract Platform**: WASM-based smart contracts with gas metering
- **Multi-Token System**: Native ZHTP token and custom token support
- **Web4 Decentralized Websites**: Blockchain-based website hosting with DHT integration
- **Identity Integration**: DID-based identity system with privacy preservation
- **Economic System**: Built-in UBI, DAO governance, and economic incentives
- **Consensus Coordination**: Hybrid consensus with stake, storage, and work proofs
- **Distributed Storage**: Integration with erasure-coded distributed storage

## Architecture

The blockchain is built with a modular architecture consisting of several key components:

### Core Components

- **Blockchain Engine** (`blockchain.rs`): Main blockchain logic with state management
- **Block System** (`block/`): Block structures and validation
- **Transaction System** (`transaction/`): ZK transaction processing
- **Mempool** (`mempool.rs`): Transaction pool management

### Smart Contract Platform

- **Contracts** (`contracts/`): Multi-contract platform supporting:
  - Token contracts (ZHTP native + custom tokens)
  - Web4 website hosting contracts
  - Messaging and communication contracts
  - File sharing and storage contracts
  - DAO governance contracts

### Integration Layer

- **Enhanced ZK Crypto** (`integration/enhanced_zk_crypto.rs`): ZK proof integration
- **Economic Integration** (`integration/economic_integration.rs`): UBI, rewards, and fees
- **Consensus Integration** (`integration/consensus_integration.rs`): Validator and DAO coordination
- **Storage Integration** (`integration/storage_integration.rs`): Persistent state and backup

## Features

### Zero-Knowledge Privacy

- **Private Transactions**: Hide transaction amounts and participants using ZK proofs
- **Nullifier Prevention**: Prevent double-spending without revealing transaction history
- **Identity Privacy**: Optional identity revelation with cryptographic proofs
- **Balance Privacy**: Private balance tracking with ZK commitments

### Smart Contract Capabilities

- **WASM Runtime**: Execute smart contracts using WebAssembly
- **Gas System**: Prevent infinite loops and resource abuse
- **Multi-Contract Support**: Deploy multiple contract types
- **State Management**: Persistent contract state with versioning
- **Event System**: Contract events and logging

### Economic Features

- **Universal Basic Income**: Automated UBI distribution to verified citizens
- **DAO Treasury**: Decentralized fund management with voting
- **Network Rewards**: Incentivize infrastructure providers
- **Fee Distribution**: Split fees between network operation and UBI funding
- **Deflationary Mechanisms**: Token burning for certain operations

### Web4 Decentralized Websites

- **Domain System**: Register and manage decentralized domains
- **Content Routing**: Route website requests through DHT storage
- **Manifest Management**: Deploy and update website manifests
- **Access Control**: Control website access with smart contracts

## Quick Start

### Basic Usage

```rust
use lib_blockchain::{Blockchain, Transaction, TransactionType};
use lib_crypto::generate_keypair;

// Initialize blockchain
let mut blockchain = Blockchain::new()?;

// Create and add transaction
let keypair = generate_keypair()?;
let transaction = Transaction::new_transfer(
    from_address,
    to_address, 
    amount,
    fee,
    &keypair
)?;

blockchain.add_pending_transaction(transaction)?;
blockchain.mine_pending_block()?;
```

### Smart Contract Deployment

```rust
use lib_blockchain::contracts::{TokenContract, ContractCall};

// Deploy token contract
let contract = TokenContract::new(
    "MyToken".to_string(),
    "MTK".to_string(),
    1000000, // initial supply
    18,      // decimals
    false,   // not deflationary
)?;

let call = ContractCall::deploy_contract(contract);
blockchain.execute_contract_call(call, &deployer_keypair)?;
```

### Web4 Website Deployment

```rust
use lib_blockchain::contracts::Web4Contract;

// Deploy Web4 website
let web4_contract = Web4Contract::new();
let domain = "example.zhtp";
let manifest = WebsiteManifest::new(domain, content_hash);

web4_contract.register_domain(domain, &owner_keypair)?;
web4_contract.deploy_manifest(domain, manifest, &owner_keypair)?;
```

## Integration

### With lib-crypto

```rust
use lib_crypto::{generate_keypair, sign_message};

// Generate keypair for transactions
let keypair = generate_keypair()?;

// Sign transaction
let tx_hash = transaction.hash();
let signature = sign_message(&keypair, tx_hash.as_bytes())?;
```

### With lib-proofs

```rust
use lib_proofs::{ZkTransactionProof, initialize_zk_system};

// Initialize ZK system
let zk_system = initialize_zk_system()?;

// Create ZK transaction proof
let zk_proof = ZkTransactionProof::prove_transaction(
    sender_balance,
    amount,
    fee,
    secret_seed,
    nullifier_seed,
)?;
```

### With lib-storage

```rust
use lib_storage::UnifiedStorageSystem;

// Store blockchain state
let storage_manager = BlockchainStorageManager::new(config).await?;
let result = storage_manager.store_blockchain_state(&blockchain).await?;
```

## Configuration

### Blockchain Configuration

```rust
use lib_blockchain::BlockchainConfig;

let config = BlockchainConfig {
    enable_zk_proofs: true,
    enable_smart_contracts: true,
    enable_web4: true,
    max_block_size: 1_048_576, // 1MB
    target_block_time: 10,     // 10 seconds
    initial_difficulty: 0x00000FFF,
    // ... other options
};
```

### Storage Configuration

```rust
use lib_blockchain::storage::BlockchainStorageConfig;

let storage_config = BlockchainStorageConfig {
    auto_persist_state: true,
    persist_frequency: 100,    // Every 100 blocks
    enable_erasure_coding: true,
    enable_encryption: true,
    max_cache_size: 100 * 1024 * 1024, // 100MB
    // ... other options
};
```

## API Reference

### Core Types

- **`Blockchain`**: Main blockchain structure with state management
- **`Block`**: Individual blockchain block with header and transactions
- **`Transaction`**: ZK transaction with inputs, outputs, and proofs
- **`BlockHeader`**: Block metadata with merkle root and difficulty
- **`TransactionInput/Output`**: Transaction components with commitments

### Contract Types

- **`TokenContract`**: Multi-token contract supporting ZHTP and custom tokens
- **`Web4Contract`**: Decentralized website hosting contract
- **`ContractCall`**: Smart contract execution call with gas limits
- **`ContractResult`**: Contract execution result with events and state changes

### Integration Types

- **`EconomicTransactionProcessor`**: Process economic transactions (UBI, rewards)
- **`BlockchainConsensusCoordinator`**: Coordinate with consensus engine
- **`BlockchainStorageManager`**: Manage persistent storage and backup
- **`EnhancedTransactionValidator`**: Validate transactions with ZK proofs

## Examples

See the `/examples` directory for complete examples:

- **Basic Blockchain**: Simple blockchain usage
- **Token Contracts**: Deploy and interact with token contracts
- **Web4 Websites**: Host decentralized websites
- **ZK Transactions**: Create private transactions
- **Economic Integration**: UBI and reward distribution

## Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run with features enabled
cargo test --features "contracts,wasm-runtime"

# Run specific module tests
cargo test blockchain::tests
cargo test contracts::tests
```

## Performance

The blockchain is designed for high performance:

- **Zero-Knowledge Proofs**: Optimized with Plonky2 for fast proving/verification
- **WASM Execution**: High-performance WebAssembly runtime
- **Parallel Processing**: Multi-threaded transaction validation
- **Efficient Storage**: Compressed and erasure-coded storage
- **Caching**: Intelligent caching for frequently accessed data

## Security

Security features include:

- **Zero-Knowledge Privacy**: Cryptographically private transactions
- **Post-Quantum Cryptography**: Dilithium and Kyber for quantum resistance
- **Smart Contract Sandboxing**: Isolated WASM execution environment
- **Gas Limits**: Prevent resource exhaustion attacks
- **Signature Verification**: Multi-algorithm signature support
- **Access Control**: Fine-grained permission system

## Roadmap

Upcoming features:

- **Layer 2 Scaling**: Payment channels and state channels
- **Cross-Chain Bridges**: Interoperability with other blockchains
- **Advanced ZK Features**: Private smart contracts and ZK-rollups
- **Mobile Support**: Optimized mobile blockchain clients
- **Enhanced Web4**: Advanced website features and CDN integration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Documentation

- [Architecture Guide](architecture.md) - Detailed system architecture
- [API Reference](api-reference.md) - Complete API documentation  
- [Smart Contracts Guide](smart-contracts.md) - Contract development guide
- [Web4 Guide](web4-guide.md) - Decentralized website hosting
- [Integration Guide](integration-guide.md) - Integration with other components
- [Performance Guide](performance-guide.md) - Optimization and benchmarking

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support:

- GitHub Issues: Report bugs and feature requests
- Documentation: Comprehensive guides and API reference
- Examples: Working code examples for common use cases