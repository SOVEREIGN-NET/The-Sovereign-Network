# lib-proofs

## Overview

`lib-proofs` provides a comprehensive zero-knowledge proof system for the SOVEREIGN_NET ecosystem. Built with production-ready Plonky2 backend, it offers privacy-preserving cryptographic proofs for transactions, identity verification, range validation, and more.

## Core Features

- **Unified Plonky2 Backend**: All proof types use the same high-performance recursive SNARK system
- **Transaction Privacy**: Zero-knowledge transaction validation with balance and nullifier proofs
- **Identity Proofs**: Selective disclosure of identity attributes without revealing personal information
- **Range Proofs**: Prove values are within bounds without revealing exact values
- **Merkle Proofs**: Zero-knowledge inclusion proofs for data structures
- **Recursive Aggregation**: Batch multiple proofs for scalability
- **Storage Access**: Privacy-preserving access control proofs
- **Routing Privacy**: Anonymous routing proofs for mesh networks
- **Data Integrity**: Tamper-proof data validation proofs

## Quick Start

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof, ZkTransactionProof};

// Initialize the ZK proof system
let zk_system = ZkProofSystem::new()?;

// Generate a range proof
let range_proof = ZkRangeProof::generate(100, 0, 1000, [1u8; 32])?;
assert!(range_proof.verify()?);

// Generate a transaction proof
let tx_proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)?;
assert!(zk_system.verify_transaction(&tx_proof)?);
```

## Architecture

```
src/
├── plonky2/           # Core Plonky2 integration and circuits
├── types/             # ZK proof type definitions
├── transaction/       # Transaction privacy proofs
├── identity/          # Identity and credential proofs  
├── range/             # Range and bound proofs
├── merkle/            # Merkle tree inclusion proofs
├── provers/           # Proof generation modules
├── verifiers/         # Proof verification modules
├── circuits/          # Custom circuit builders
├── recursive/         # Recursive proof aggregation
├── state/             # State transition proofs
└── zk_integration/    # Integration with lib-crypto
```

## Proof Types

### Transaction Proofs
```rust
// Prove transaction validity without revealing balances
let tx_proof = zk_system.prove_transaction(
    sender_balance: 1000,
    amount: 100, 
    fee: 10,
    sender_secret: 12345,
    nullifier_seed: 67890,
)?;
```

### Identity Proofs
```rust
// Prove age ≥ 18 and jurisdiction without revealing exact age or identity
let id_proof = zk_system.prove_identity(
    identity_secret: 54321,
    age: 25,              // Actual age (private)
    jurisdiction: 840,    // US jurisdiction code
    credential: 9999,     // Credential hash
    min_age: 18,         // Requirement (public)
    required_jurisdiction: 840, // Required jurisdiction (public)
    verification_level: 1,
)?;
```

### Range Proofs
```rust
// Prove value is in range [0, 1000] without revealing exact value
let range_proof = ZkRangeProof::generate(500, 0, 1000, blinding_factor)?;
assert!(range_proof.verify()?);
```

### Storage Access Proofs
```rust
// Prove authorization to access data without revealing credentials
let access_proof = zk_system.prove_storage_access(
    access_key: 11111,
    requester_secret: 22222,
    data_hash: 33333,
    permission_level: 5,    // Actual permission (private)
    required_permission: 3, // Minimum required (public)
)?;
```

## Building

```bash
cargo build --release
cargo test
cargo bench
```

## Features

- `default` - Standard ZK proof system
- `production` - Optimized circuits for production use
- `dev` - Development utilities and test helpers

## Security

This library implements production-grade zero-knowledge proofs using Plonky2, designed to provide cryptographic privacy and integrity guarantees. All implementations include proper constraint systems and verification procedures.

## Documentation

- **[Getting Started](docs/getting_started.md)** - Installation and basic usage
- **[API Reference](docs/api_reference.md)** - Complete API documentation
- **[Integration Guide](docs/integration.md)** - Integration with SOVEREIGN_NET ecosystem
- **[Circuit Documentation](docs/circuits.md)** - Available circuits and constraints
- **[Performance Guide](docs/performance.md)** - Optimization and benchmarking
- **[Examples](docs/examples.md)** - Comprehensive usage examples
- **[TODO](TODO.md)** - Known issues and planned improvements

## Performance

Typical performance on modern hardware:
- Transaction proof generation: ~50-100ms
- Identity proof generation: ~30-80ms
- Range proof generation: ~20-50ms
- Proof verification: ~5-15ms
- Recursive aggregation: ~100-200ms for 10 proofs

## License

MIT License - see LICENSE file for details.