# Proofs — docs

# Documentation for the **Proofs — docs** Module

## Overview

The **Proofs** module provides a comprehensive framework for generating and verifying zero-knowledge proofs (ZK proofs) using the Plonky2 proof system. This module is designed to facilitate privacy-preserving computations across various applications, including financial transactions, identity verification, and data integrity checks. By leveraging zero-knowledge proofs, users can prove the validity of information without revealing the underlying data.

## Purpose

The primary purpose of the **Proofs** module is to enable developers to create and manage zero-knowledge proofs efficiently. It abstracts the complexities of cryptographic operations and provides a user-friendly API for generating proofs, verifying them, and integrating them into larger systems.

## Key Components

### 1. Core Types

#### ZkProof

The `ZkProof` struct represents a unified zero-knowledge proof structure. It encapsulates all necessary components for a proof, including the proof system, proof data, public inputs, and verification keys.

```rust
pub struct ZkProof {
    pub proof_system: String,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub verification_key: Vec<u8>,
    pub plonky2_proof: Option<Plonky2Proof>,
    pub proof: Vec<u8>, // Legacy compatibility
}
```

**Methods**:
- `new()`: Creates a new ZK proof.
- `from_plonky2()`: Constructs a ZK proof from a Plonky2 proof.
- `from_public_inputs()`: Generates a ZK proof from public inputs.
- `verify()`: Verifies the proof.
- `is_empty()`: Checks if the proof is empty.
- `size()`: Returns the size of the proof in bytes.

#### ZkProofSystem

The `ZkProofSystem` struct serves as the main interface for generating and verifying zero-knowledge proofs. It encapsulates the internal logic required to manage different proof types and their respective constraints.

```rust
pub struct ZkProofSystem {
    // Internal implementation details
}
```

**Methods**:
- `new()`: Initializes the proof system.
- `prove_transaction()`: Generates a transaction proof.
- `verify_transaction()`: Verifies a transaction proof.
- `prove_identity()`: Generates an identity proof.
- `verify_identity()`: Verifies an identity proof.
- `prove_range()`: Generates a range proof.
- `verify_range()`: Verifies a range proof.
- `prove_storage_access()`: Generates a storage access proof.
- `verify_storage_access()`: Verifies a storage access proof.
- `prove_routing()`: Generates a routing proof.
- `verify_routing()`: Verifies a routing proof.
- `prove_data_integrity()`: Generates a data integrity proof.
- `verify_data_integrity()`: Verifies a data integrity proof.

### 2. Specialized Proof Types

#### ZkRangeProof

The `ZkRangeProof` struct provides a high-level interface for generating and verifying range proofs. It allows users to prove that a secret value lies within a specified range without revealing the value itself.

```rust
pub struct ZkRangeProof {
    pub proof: ZkProof,
    pub commitment: [u8; 32],
    pub min_value: u64,
    pub max_value: u64,
}
```

**Methods**:
- `generate()`: Generates a range proof with an explicit blinding factor.
- `generate_simple()`: Generates a range proof with a random blinding factor.
- `verify()`: Verifies the range proof.

#### ZkTransactionProof

The `ZkTransactionProof` struct provides a high-level interface for transaction proofs, encapsulating multiple components of a transaction into a single proof.

```rust
pub struct ZkTransactionProof {
    pub amount_proof: ZkProof,
    pub balance_proof: ZkProof,
    pub nullifier_proof: ZkProof,
}
```

**Methods**:
- `prove_transaction()`: Generates a complete transaction proof.
- `verify()`: Verifies all components of the transaction proof.

### 3. Integration Module

The integration module provides functions for integrating the proof system with external libraries, such as cryptographic libraries.

**Key Functions**:
- `create_zk_system()`: Creates a production ZK proof system instance.
- `prove_identity()`: Generates an identity proof using a private key.
- `prove_range()`: Generates a range proof using the integrated system.
- `prove_storage_access()`: Generates a storage access proof.

### 4. Circuit Types

The module also defines circuit types used in the proof generation process, including `Plonky2Proof` and `CircuitBuilder`. These types are essential for constructing custom circuits and managing the proof generation process.

```rust
pub struct Plonky2Proof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u64>,
    pub verification_key_hash: [u8; 32],
    pub proof_system: String,
    pub generated_at: u64,
    pub circuit_id: String,
    pub private_input_commitment: [u8; 32],
}
```

## Execution Flow

The execution flow of the **Proofs** module can be summarized as follows:

1. **Initialization**: A `ZkProofSystem` instance is created using `ZkProofSystem::new()`.
2. **Proof Generation**: Depending on the use case (transaction, identity, range, etc.), the appropriate proof generation method is called (e.g., `prove_transaction()`).
3. **Proof Verification**: The generated proof can be verified using the corresponding verification method (e.g., `verify_transaction()`).
4. **Integration**: The generated proofs can be integrated into larger systems, such as decentralized applications or privacy-preserving protocols.

### Mermaid Diagram

```mermaid
graph TD;
    A[ZkProofSystem] -->|prove_transaction()| B[ZkTransactionProof]
    A -->|prove_identity()| C[ZkIdentityProof]
    A -->|prove_range()| D[ZkRangeProof]
    A -->|prove_storage_access()| E[ZkStorageAccessProof]
    B -->|verify()| F[Verification]
    C -->|verify()| F
    D -->|verify()| F
    E -->|verify()| F
```

## Error Handling

The module employs comprehensive error handling using the `anyhow` crate. All functions return `anyhow::Result<T>`, allowing for detailed error reporting and context propagation.

### Common Error Types

- **System Initialization Errors**: Issues during the initialization of the ZK system.
- **Constraint Violations**: Input values that do not satisfy proof constraints.
- **Verification Failures**: Proof verification failures.
- **Circuit Errors**: Errors during circuit construction or compilation.

## Performance Considerations

### Typical Performance Metrics

| Operation | Time | Notes |
|-----------|------|-------|
| System initialization | ~10-50ms | One-time setup cost |
| Transaction proof | ~50-100ms | Depends on circuit complexity |
| Identity proof | ~30-80ms | Age and jurisdiction verification |
| Range proof | ~20-50ms | Value bound verification |
| Storage access proof | ~25-60ms | Permission verification |
| Routing proof | ~40-90ms | Network routing validation |
| Data integrity proof | ~35-75ms | Data validation |
| Proof verification | ~5-15ms | All proof types |

### Memory Usage

- ZK system: ~10-50MB (circuit compilation)
- Individual proofs: ~1-10KB each
- Batch operations: Linear with batch size

### Optimization Tips

1. **Reuse ZkProofSystem**: Initialize once, use many times.
2. **Batch operations**: Generate multiple proofs together when possible.
3. **Use appropriate proof types**: Choose the simplest proof that meets requirements.
4. **Profile your use case**: Measure actual performance in your application.

## Conclusion

The **Proofs** module is a powerful tool for developers looking to implement zero-knowledge proofs in their applications. With its comprehensive API, specialized proof types, and integration capabilities, it provides a robust foundation for privacy-preserving computations. By following the guidelines and examples provided in this documentation, developers can effectively leverage the capabilities of the **Proofs** module to enhance the privacy and security of their systems.