<<<<<<< HEAD
# ZHTP Unified Storage System Documentation

Welcome to the comprehensive documentation for the ZHTP Unified Storage System (`lib-storage`). This system provides a sophisticated multi-layer storage architecture that combines distributed hash table (DHT) networking with economic incentives and zero-knowledge privacy.

## 📚 Documentation Structure

### Core Documentation
- **[Architecture Overview](architecture/OVERVIEW.md)** - High-level system architecture and design principles
- **[API Reference](api/README.md)** - Complete API documentation with examples
- **[Getting Started](guides/GETTING_STARTED.md)** - Quick start guide and basic usage

### Module Documentation
- **[DHT Foundation Layer](modules/dht/README.md)** - Distributed hash table implementation
- **[Economic Storage Layer](modules/economic/README.md)** - Market mechanisms and incentives
- **[Content Management](modules/content/README.md)** - High-level content operations
- **[Type System](modules/types/README.md)** - Core data structures and types

### Usage Guides
- **[Storage Operations](guides/STORAGE_OPERATIONS.md)** - Basic storage and retrieval operations
- **[Economic Features](guides/ECONOMIC_FEATURES.md)** - Using contracts, payments, and incentives
- **[Identity Integration](guides/IDENTITY_INTEGRATION.md)** - Working with ZHTP identities
- **[Zero-Knowledge Features](guides/ZERO_KNOWLEDGE.md)** - Privacy and cryptographic features

### Examples
- **[Basic Usage](examples/basic_usage.md)** - Simple storage operations
- **[Economic Storage](examples/economic_storage.md)** - Contract-based storage
- **[Identity Storage](examples/identity_storage.md)** - Secure credential storage
- **[Smart Contracts](examples/smart_contracts.md)** - DHT-based smart contract deployment

## 🏗️ System Overview

The ZHTP Unified Storage System is organized into five main phases:

### Phase A: Core Types System  COMPLETED
Defines all data structures, enums, and type aliases used throughout the system.

### Phase B: DHT Foundation Layer  COMPLETED  
Provides networking and routing foundation using Kademlia algorithm with cryptographic integrity.

### Phase C: Economic Storage Layer  COMPLETED
Adds market mechanisms, dynamic pricing, contracts, and incentive systems on top of DHT.

### Phase D: Content Management Layer  COMPLETED
High-level content operations with metadata management, encryption, and access control.

### Phase E: Integration Layer  COMPLETED
Unified API that orchestrates all subsystems through the `UnifiedStorageSystem`.

##  Key Features

- **Distributed Storage**: Kademlia DHT with automatic replication and fault tolerance
- **Economic Incentives**: Dynamic pricing, storage contracts, and performance-based rewards
- **Zero-Knowledge Privacy**: Cryptographic proofs for all storage operations
- **Identity Integration**: Seamless integration with ZHTP identity system
- **Smart Contract Support**: Store and execute WASM smart contracts in DHT
- **Multi-Tier Storage**: Optimized storage tiers (Hot, Warm, Cold, Archive)
- **Erasure Coding**: Reed-Solomon encoding for data redundancy
- **Automatic SLA Enforcement**: Self-enforcing contracts with penalties and rewards

##  Technical Specifications

- **Language**: Rust 2021 Edition
- **Cryptography**: Post-quantum algorithms via `lib-crypto`
- **Zero-Knowledge**: Plonky2, Groth16, Nova, STARK proofs via `lib-proofs`
- **Identity**: ZHTP identity system via `lib-identity`
- **Network**: Async UDP-based messaging with Tokio
- **Storage**: Content-addressed storage with BLAKE3 hashing
- **Economics**: Token-based payments with escrow and reputation

## 📖 Quick Start

```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig, UploadRequest};

// Initialize storage system
let config = UnifiedStorageConfig::default();
let mut system = UnifiedStorageSystem::new(config).await?;

// Upload content
let upload_request = UploadRequest {
    content: b"Hello, ZHTP Storage!".to_vec(),
    filename: "hello.txt".to_string(),
    // ... other fields
};

let content_hash = system.upload_content(upload_request, identity).await?;
println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
```

## 🤝 Contributing

Please refer to the main SOVEREIGN_NET contributing guidelines for information about contributing to this documentation and the storage system.

##  License

This project is licensed under the MIT License - see the LICENSE file for details.

---

=======
# ZHTP Unified Storage System Documentation

Welcome to the comprehensive documentation for the ZHTP Unified Storage System (`lib-storage`). This system provides a sophisticated multi-layer storage architecture that combines distributed hash table (DHT) networking with economic incentives and zero-knowledge privacy.

## 📚 Documentation Structure

### Core Documentation
- **[Architecture Overview](architecture/OVERVIEW.md)** - High-level system architecture and design principles
- **[API Reference](api/README.md)** - Complete API documentation with examples
- **[Getting Started](guides/GETTING_STARTED.md)** - Quick start guide and basic usage

### Module Documentation
- **[DHT Foundation Layer](modules/dht/README.md)** - Distributed hash table implementation
- **[Economic Storage Layer](modules/economic/README.md)** - Market mechanisms and incentives
- **[Content Management](modules/content/README.md)** - High-level content operations
- **[Type System](modules/types/README.md)** - Core data structures and types

### Usage Guides
- **[Storage Operations](guides/STORAGE_OPERATIONS.md)** - Basic storage and retrieval operations
- **[Economic Features](guides/ECONOMIC_FEATURES.md)** - Using contracts, payments, and incentives
- **[Identity Integration](guides/IDENTITY_INTEGRATION.md)** - Working with ZHTP identities
- **[Zero-Knowledge Features](guides/ZERO_KNOWLEDGE.md)** - Privacy and cryptographic features

### Examples
- **[Basic Usage](examples/basic_usage.md)** - Simple storage operations
- **[Economic Storage](examples/economic_storage.md)** - Contract-based storage
- **[Identity Storage](examples/identity_storage.md)** - Secure credential storage
- **[Smart Contracts](examples/smart_contracts.md)** - DHT-based smart contract deployment

## 🏗️ System Overview

The ZHTP Unified Storage System is organized into five main phases:

### Phase A: Core Types System  COMPLETED
Defines all data structures, enums, and type aliases used throughout the system.

### Phase B: DHT Foundation Layer  COMPLETED  
Provides networking and routing foundation using Kademlia algorithm with cryptographic integrity.

### Phase C: Economic Storage Layer  COMPLETED
Adds market mechanisms, dynamic pricing, contracts, and incentive systems on top of DHT.

### Phase D: Content Management Layer  COMPLETED
High-level content operations with metadata management, encryption, and access control.

### Phase E: Integration Layer  COMPLETED
Unified API that orchestrates all subsystems through the `UnifiedStorageSystem`.

##  Key Features

- **Distributed Storage**: Kademlia DHT with automatic replication and fault tolerance
- **Economic Incentives**: Dynamic pricing, storage contracts, and performance-based rewards
- **Zero-Knowledge Privacy**: Cryptographic proofs for all storage operations
- **Identity Integration**: Seamless integration with ZHTP identity system
- **Smart Contract Support**: Store and execute WASM smart contracts in DHT
- **Multi-Tier Storage**: Optimized storage tiers (Hot, Warm, Cold, Archive)
- **Erasure Coding**: Reed-Solomon encoding for data redundancy
- **Automatic SLA Enforcement**: Self-enforcing contracts with penalties and rewards

##  Technical Specifications

- **Language**: Rust 2021 Edition
- **Cryptography**: Post-quantum algorithms via `lib-crypto`
- **Zero-Knowledge**: Plonky2, Groth16, Nova, STARK proofs via `lib-proofs`
- **Identity**: ZHTP identity system via `lib-identity`
- **Network**: Async UDP-based messaging with Tokio
- **Storage**: Content-addressed storage with BLAKE3 hashing
- **Economics**: Token-based payments with escrow and reputation

## 📖 Quick Start

```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig, UploadRequest};

// Initialize storage system
let config = UnifiedStorageConfig::default();
let mut system = UnifiedStorageSystem::new(config).await?;

// Upload content
let upload_request = UploadRequest {
    content: b"Hello, ZHTP Storage!".to_vec(),
    filename: "hello.txt".to_string(),
    // ... other fields
};

let content_hash = system.upload_content(upload_request, identity).await?;
println!("Content stored with hash: {}", hex::encode(content_hash.as_bytes()));
```

## 🤝 Contributing

Please refer to the main SOVEREIGN_NET contributing guidelines for information about contributing to this documentation and the storage system.

##  License

This project is licensed under the MIT License - see the LICENSE file for details.

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
For detailed technical information, start with the [Architecture Overview](architecture/OVERVIEW.md) or jump directly to the [API Reference](api/README.md) for implementation details.