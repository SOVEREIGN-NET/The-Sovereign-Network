# API Reference

Complete API documentation for lib-proofs zero-knowledge proof system.

## Core Types

### ZkProof

The unified zero-knowledge proof structure.

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

#### Methods

##### `new()`
```rust
pub fn new(
    proof_system: String,
    proof_data: Vec<u8>,
    public_inputs: Vec<u8>,
    verification_key: Vec<u8>,
    plonky2_proof: Option<Plonky2Proof>,
) -> Self
```
Create a new ZK proof with the specified components.

##### `from_plonky2()`
```rust
pub fn from_plonky2(plonky2_proof: Plonky2Proof) -> Self
```
Create a ZkProof from a Plonky2 proof (preferred method).

##### `from_public_inputs()`
```rust
pub fn from_public_inputs(public_inputs: Vec<u64>) -> anyhow::Result<Self>
```
Generate a ZkProof from public inputs using the internal proof system.

##### `verify()`
```rust
pub fn verify(&self) -> anyhow::Result<bool>
```
Verify this proof using the unified ZK system.

**Returns**: `Ok(true)` if proof is valid, `Ok(false)` if invalid, `Err()` for system errors.

##### `is_empty()`
```rust
pub fn is_empty(&self) -> bool
```
Check if the proof is empty/uninitialized.

##### `size()`
```rust
pub fn size(&self) -> usize
```
Get the proof size in bytes.

---

## ZK Proof System

### ZkProofSystem

The main interface for generating and verifying zero-knowledge proofs.

```rust
pub struct ZkProofSystem {
    // Internal implementation details
}
```

#### Initialization

##### `new()`
```rust
pub fn new() -> Result<Self>
```
Initialize the production ZK proof system with all circuit types.

**Example**:
```rust
let zk_system = ZkProofSystem::new()?;
```

#### Transaction Proofs

##### `prove_transaction()`
```rust
pub fn prove_transaction(
    &self,
    sender_balance: u64,
    amount: u64,
    fee: u64,
    sender_secret: u64,
    nullifier_seed: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge transaction proof.

**Parameters**:
- `sender_balance`: Sender's account balance (private)
- `amount`: Transaction amount (public)
- `fee`: Transaction fee (public)
- `sender_secret`: Sender's private key material (private)
- `nullifier_seed`: Unique nullifier to prevent double-spending (private)

**Returns**: `Plonky2Proof` that proves transaction validity without revealing private data.

**Constraints**:
- `amount + fee <= sender_balance`
- `amount > 0`
- All values must be non-negative

**Example**:
```rust
let proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)?;
```

##### `verify_transaction()`
```rust
pub fn verify_transaction(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a transaction proof.

**Returns**: `true` if proof is valid and constraints are satisfied.

#### Identity Proofs

##### `prove_identity()`
```rust
pub fn prove_identity(
    &self,
    identity_secret: u64,
    age: u64,
    jurisdiction_hash: u64,
    credential_hash: u64,
    min_age: u64,
    required_jurisdiction: u64,
    verification_level: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge identity proof with selective disclosure.

**Parameters**:
- `identity_secret`: Private identity key (private)
- `age`: Actual age (private)
- `jurisdiction_hash`: Jurisdiction identifier (private)
- `credential_hash`: Credential identifier (private)
- `min_age`: Minimum age requirement (public)
- `required_jurisdiction`: Required jurisdiction (public, 0 = no requirement)
- `verification_level`: Required verification level (public)

**Returns**: Proof that age ≥ min_age and jurisdiction matches (if required).

**Example**:
```rust
let proof = zk_system.prove_identity(54321, 25, 840, 9999, 18, 840, 1)?;
```

##### `verify_identity()`
```rust
pub fn verify_identity(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify an identity proof.

#### Range Proofs

##### `prove_range()`
```rust
pub fn prove_range(
    &self,
    value: u64,
    blinding_factor: u64,
    min_value: u64,
    max_value: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge range proof.

**Parameters**:
- `value`: The actual value (private)
- `blinding_factor`: Random blinding factor (private)
- `min_value`: Minimum allowed value (public)
- `max_value`: Maximum allowed value (public)

**Returns**: Proof that `min_value <= value <= max_value`.

**Example**:
```rust
let proof = zk_system.prove_range(500, 12345, 0, 1000)?;
```

##### `verify_range()`
```rust
pub fn verify_range(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a range proof.

#### Storage Access Proofs

##### `prove_storage_access()`
```rust
pub fn prove_storage_access(
    &self,
    access_key: u64,
    requester_secret: u64,
    data_hash: u64,
    permission_level: u64,
    required_permission: u64,
) -> Result<Plonky2Proof>
```

Generate a proof of authorization to access data.

**Parameters**:
- `access_key`: Access key identifier (private)
- `requester_secret`: Requester's secret credential (private)
- `data_hash`: Hash of data being accessed (public)
- `permission_level`: Requester's actual permission level (private)
- `required_permission`: Minimum required permission (public)

**Returns**: Proof that `permission_level >= required_permission`.

##### `verify_storage_access()`
```rust
pub fn verify_storage_access(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a storage access proof.

#### Routing Proofs

##### `prove_routing()`
```rust
pub fn prove_routing(
    &self,
    source_node: u64,
    destination_node: u64,
    hop_count: u64,
    bandwidth_available: u64,
    latency_metric: u64,
    routing_secret: u64,
    max_hops: u64,
    min_bandwidth: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge routing proof for mesh networks.

**Parameters**:
- `source_node`: Source node identifier (private)
- `destination_node`: Destination node identifier (private)
- `hop_count`: Number of hops in route (private)
- `bandwidth_available`: Available bandwidth (private)
- `latency_metric`: Route latency (private)
- `routing_secret`: Routing authentication secret (private)
- `max_hops`: Maximum allowed hops (public)
- `min_bandwidth`: Minimum required bandwidth (public)

**Returns**: Proof of valid routing without revealing network topology.

##### `verify_routing()`
```rust
pub fn verify_routing(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a routing proof.

#### Data Integrity Proofs

##### `prove_data_integrity()`
```rust
pub fn prove_data_integrity(
    &self,
    data_hash: u64,
    chunk_count: u64,
    total_size: u64,
    checksum: u64,
    owner_secret: u64,
    timestamp: u64,
    max_chunk_count: u64,
    max_size: u64,
) -> Result<Plonky2Proof>
```

Generate a proof of data integrity and ownership.

**Parameters**:
- `data_hash`: Hash of the data (private)
- `chunk_count`: Number of data chunks (private)
- `total_size`: Total data size (private)
- `checksum`: Data checksum (private)
- `owner_secret`: Owner's secret key (private)
- `timestamp`: Data creation timestamp (private)
- `max_chunk_count`: Maximum allowed chunks (public)
- `max_size`: Maximum allowed size (public)

**Returns**: Proof of data integrity within bounds.

##### `verify_data_integrity()`
```rust
pub fn verify_data_integrity(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a data integrity proof.

---

## Specialized Proof Types

### ZkRangeProof

High-level interface for range proofs.

```rust
pub struct ZkRangeProof {
    pub proof: ZkProof,
    pub commitment: [u8; 32],
    pub min_value: u64,
    pub max_value: u64,
}
```

#### Methods

##### `generate()`
```rust
pub fn generate(
    value: u64,
    min_value: u64,
    max_value: u64,
    blinding: [u8; 32]
) -> Result<Self>
```

Generate a range proof with explicit blinding factor.

##### `generate_simple()`
```rust
pub fn generate_simple(
    value: u64,
    min_value: u64,
    max_value: u64
) -> Result<Self>
```

Generate a range proof with random blinding factor.

##### `generate_positive()`
```rust
pub fn generate_positive(value: u64, blinding: [u8; 32]) -> Result<Self>
```

Generate a proof that value > 0.

##### `generate_bounded_pow2()`
```rust
pub fn generate_bounded_pow2(
    value: u64,
    max_bits: u8,
    blinding: [u8; 32]
) -> Result<Self>
```

Generate a proof that value fits in the specified number of bits.

##### `verify()`
```rust
pub fn verify(&self) -> Result<bool>
```

Verify the range proof.

##### `range_size()`
```rust
pub fn range_size(&self) -> u64
```

Get the size of the range (max - min + 1).

### ZkTransactionProof

High-level interface for transaction proofs.

```rust
pub struct ZkTransactionProof {
    pub amount_proof: ZkProof,
    pub balance_proof: ZkProof,
    pub nullifier_proof: ZkProof,
}
```

#### Methods

##### `new()`
```rust
pub fn new(
    amount_proof: ZkProof,
    balance_proof: ZkProof,
    nullifier_proof: ZkProof,
) -> Self
```

Create a new transaction proof from component proofs.

##### `prove_transaction()`
```rust
pub fn prove_transaction(
    sender_balance: u64,
    receiver_balance: u64,
    amount: u64,
    fee: u64,
    sender_blinding: [u8; 32],
    receiver_blinding: [u8; 32],
    nullifier: [u8; 32],
) -> anyhow::Result<Self>
```

Generate a complete transaction proof.

##### `verify()`
```rust
pub fn verify(&self) -> anyhow::Result<bool>
```

Verify all components of the transaction proof.

---

## ZK Integration Module

Functions for integrating with lib-crypto.

### `create_zk_system()`
```rust
pub fn create_zk_system() -> Result<ZkProofSystem>
```

Create a production ZK proof system instance.

### `prove_identity()`
```rust
pub fn prove_identity(
    private_key: &PrivateKey,
    age: u64,
    jurisdiction_hash: u64,
    credential_hash: u64,
    min_age: u64,
    required_jurisdiction: u64,
) -> Result<Plonky2Proof>
```

Generate identity proof using lib-crypto private key.

### `prove_range()`
```rust
pub fn prove_range(
    value: u64,
    blinding_factor: u64,
    min_value: u64,
    max_value: u64,
) -> Result<Plonky2Proof>
```

Generate range proof using integrated system.

### `prove_storage_access()`
```rust
pub fn prove_storage_access(
    access_key: u64,
    requester_secret: u64,
    data_hash: u64,
    permission_level: u64,
    required_permission: u64,
) -> Result<Plonky2Proof>
```

Generate storage access proof.

### `prove_ring_membership()`
```rust
pub fn prove_ring_membership(
    ring_members: &[Vec<u8>],
    secret_index: usize,
    secret_key: &[u8]
) -> Result<Plonky2Proof>
```

Prove membership in a ring without revealing which member.

### `prove_pqc_key_properties()`
```rust
pub fn prove_pqc_key_properties(private_key: &PrivateKey) -> Result<Plonky2Proof>
```

Prove properties of post-quantum cryptographic keys.

---

## Circuit Types

### Plonky2Proof

Core proof structure used throughout the system.

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

### CircuitBuilder

For constructing custom circuits.

```rust
pub struct CircuitBuilder {
    pub config: CircuitConfig,
    pub gates: Vec<CircuitGate>,
    pub public_inputs: Vec<usize>,
    pub constraints: Vec<CircuitConstraint>,
}
```

#### Methods

##### `new()`
```rust
pub fn new(config: CircuitConfig) -> Self
```

Create a new circuit builder.

##### `add_gate()`
```rust
pub fn add_gate(&mut self, gate: CircuitGate)
```

Add a gate to the circuit.

##### `add_public_input()`
```rust
pub fn add_public_input(&mut self, wire_index: Option<usize>) -> usize
```

Add a public input to the circuit.

##### `add_constraint()`
```rust
pub fn add_constraint(&mut self, constraint: CircuitConstraint)
```

Add a constraint to the circuit.

##### `build()`
```rust
pub fn build(self) -> Result<ZkCircuit>
```

Build the final circuit.

---

## Error Handling

All functions return `anyhow::Result<T>` for comprehensive error handling.

### Common Error Types

- **System Initialization Errors**: ZK system failed to initialize
- **Constraint Violations**: Input values don't satisfy proof constraints
- **Verification Failures**: Proof verification failed
- **Circuit Errors**: Circuit construction or compilation failed

### Error Handling Pattern

```rust
use anyhow::{Result, Context};

fn robust_proof_generation() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK system")?;
    
    let proof = zk_system.prove_range(500, 12345, 0, 1000)
        .context("Failed to generate range proof")?;
    
    let is_valid = zk_system.verify_range(&proof)
        .context("Failed to verify range proof")?;
    
    if !is_valid {
        anyhow::bail!("Range proof verification failed");
    }
    
    Ok(())
}
```

---

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

1. **Reuse ZkProofSystem**: Initialize once, use many times
2. **Batch operations**: Generate multiple proofs together when possible
3. **Use appropriate proof types**: Choose the simplest proof that meets requirements
# API Reference

Complete API documentation for lib-proofs zero-knowledge proof system.

## Core Types

### ZkProof

The unified zero-knowledge proof structure.

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

#### Methods

##### `new()`
```rust
pub fn new(
    proof_system: String,
    proof_data: Vec<u8>,
    public_inputs: Vec<u8>,
    verification_key: Vec<u8>,
    plonky2_proof: Option<Plonky2Proof>,
) -> Self
```
Create a new ZK proof with the specified components.

##### `from_plonky2()`
```rust
pub fn from_plonky2(plonky2_proof: Plonky2Proof) -> Self
```
Create a ZkProof from a Plonky2 proof (preferred method).

##### `from_public_inputs()`
```rust
pub fn from_public_inputs(public_inputs: Vec<u64>) -> anyhow::Result<Self>
```
Generate a ZkProof from public inputs using the internal proof system.

##### `verify()`
```rust
pub fn verify(&self) -> anyhow::Result<bool>
```
Verify this proof using the unified ZK system.

**Returns**: `Ok(true)` if proof is valid, `Ok(false)` if invalid, `Err()` for system errors.

##### `is_empty()`
```rust
pub fn is_empty(&self) -> bool
```
Check if the proof is empty/uninitialized.

##### `size()`
```rust
pub fn size(&self) -> usize
```
Get the proof size in bytes.

---

## ZK Proof System

### ZkProofSystem

The main interface for generating and verifying zero-knowledge proofs.

```rust
pub struct ZkProofSystem {
    // Internal implementation details
}
```

#### Initialization

##### `new()`
```rust
pub fn new() -> Result<Self>
```
Initialize the production ZK proof system with all circuit types.

**Example**:
```rust
let zk_system = ZkProofSystem::new()?;
```

#### Transaction Proofs

##### `prove_transaction()`
```rust
pub fn prove_transaction(
    &self,
    sender_balance: u64,
    amount: u64,
    fee: u64,
    sender_secret: u64,
    nullifier_seed: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge transaction proof.

**Parameters**:
- `sender_balance`: Sender's account balance (private)
- `amount`: Transaction amount (public)
- `fee`: Transaction fee (public)
- `sender_secret`: Sender's private key material (private)
- `nullifier_seed`: Unique nullifier to prevent double-spending (private)

**Returns**: `Plonky2Proof` that proves transaction validity without revealing private data.

**Constraints**:
- `amount + fee <= sender_balance`
- `amount > 0`
- All values must be non-negative

**Example**:
```rust
let proof = zk_system.prove_transaction(1000, 100, 10, 12345, 67890)?;
```

##### `verify_transaction()`
```rust
pub fn verify_transaction(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a transaction proof.

**Returns**: `true` if proof is valid and constraints are satisfied.

#### Identity Proofs

##### `prove_identity()`
```rust
pub fn prove_identity(
    &self,
    identity_secret: u64,
    age: u64,
    jurisdiction_hash: u64,
    credential_hash: u64,
    min_age: u64,
    required_jurisdiction: u64,
    verification_level: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge identity proof with selective disclosure.

**Parameters**:
- `identity_secret`: Private identity key (private)
- `age`: Actual age (private)
- `jurisdiction_hash`: Jurisdiction identifier (private)
- `credential_hash`: Credential identifier (private)
- `min_age`: Minimum age requirement (public)
- `required_jurisdiction`: Required jurisdiction (public, 0 = no requirement)
- `verification_level`: Required verification level (public)

**Returns**: Proof that age ≥ min_age and jurisdiction matches (if required).

**Example**:
```rust
let proof = zk_system.prove_identity(54321, 25, 840, 9999, 18, 840, 1)?;
```

##### `verify_identity()`
```rust
pub fn verify_identity(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify an identity proof.

#### Range Proofs

##### `prove_range()`
```rust
pub fn prove_range(
    &self,
    value: u64,
    blinding_factor: u64,
    min_value: u64,
    max_value: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge range proof.

**Parameters**:
- `value`: The actual value (private)
- `blinding_factor`: Random blinding factor (private)
- `min_value`: Minimum allowed value (public)
- `max_value`: Maximum allowed value (public)

**Returns**: Proof that `min_value <= value <= max_value`.

**Example**:
```rust
let proof = zk_system.prove_range(500, 12345, 0, 1000)?;
```

##### `verify_range()`
```rust
pub fn verify_range(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a range proof.

#### Storage Access Proofs

##### `prove_storage_access()`
```rust
pub fn prove_storage_access(
    &self,
    access_key: u64,
    requester_secret: u64,
    data_hash: u64,
    permission_level: u64,
    required_permission: u64,
) -> Result<Plonky2Proof>
```

Generate a proof of authorization to access data.

**Parameters**:
- `access_key`: Access key identifier (private)
- `requester_secret`: Requester's secret credential (private)
- `data_hash`: Hash of data being accessed (public)
- `permission_level`: Requester's actual permission level (private)
- `required_permission`: Minimum required permission (public)

**Returns**: Proof that `permission_level >= required_permission`.

##### `verify_storage_access()`
```rust
pub fn verify_storage_access(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a storage access proof.

#### Routing Proofs

##### `prove_routing()`
```rust
pub fn prove_routing(
    &self,
    source_node: u64,
    destination_node: u64,
    hop_count: u64,
    bandwidth_available: u64,
    latency_metric: u64,
    routing_secret: u64,
    max_hops: u64,
    min_bandwidth: u64,
) -> Result<Plonky2Proof>
```

Generate a zero-knowledge routing proof for mesh networks.

**Parameters**:
- `source_node`: Source node identifier (private)
- `destination_node`: Destination node identifier (private)
- `hop_count`: Number of hops in route (private)
- `bandwidth_available`: Available bandwidth (private)
- `latency_metric`: Route latency (private)
- `routing_secret`: Routing authentication secret (private)
- `max_hops`: Maximum allowed hops (public)
- `min_bandwidth`: Minimum required bandwidth (public)

**Returns**: Proof of valid routing without revealing network topology.

##### `verify_routing()`
```rust
pub fn verify_routing(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a routing proof.

#### Data Integrity Proofs

##### `prove_data_integrity()`
```rust
pub fn prove_data_integrity(
    &self,
    data_hash: u64,
    chunk_count: u64,
    total_size: u64,
    checksum: u64,
    owner_secret: u64,
    timestamp: u64,
    max_chunk_count: u64,
    max_size: u64,
) -> Result<Plonky2Proof>
```

Generate a proof of data integrity and ownership.

**Parameters**:
- `data_hash`: Hash of the data (private)
- `chunk_count`: Number of data chunks (private)
- `total_size`: Total data size (private)
- `checksum`: Data checksum (private)
- `owner_secret`: Owner's secret key (private)
- `timestamp`: Data creation timestamp (private)
- `max_chunk_count`: Maximum allowed chunks (public)
- `max_size`: Maximum allowed size (public)

**Returns**: Proof of data integrity within bounds.

##### `verify_data_integrity()`
```rust
pub fn verify_data_integrity(&self, proof: &Plonky2Proof) -> Result<bool>
```

Verify a data integrity proof.

---

## Specialized Proof Types

### ZkRangeProof

High-level interface for range proofs.

```rust
pub struct ZkRangeProof {
    pub proof: ZkProof,
    pub commitment: [u8; 32],
    pub min_value: u64,
    pub max_value: u64,
}
```

#### Methods

##### `generate()`
```rust
pub fn generate(
    value: u64,
    min_value: u64,
    max_value: u64,
    blinding: [u8; 32]
) -> Result<Self>
```

Generate a range proof with explicit blinding factor.

##### `generate_simple()`
```rust
pub fn generate_simple(
    value: u64,
    min_value: u64,
    max_value: u64
) -> Result<Self>
```

Generate a range proof with random blinding factor.

##### `generate_positive()`
```rust
pub fn generate_positive(value: u64, blinding: [u8; 32]) -> Result<Self>
```

Generate a proof that value > 0.

##### `generate_bounded_pow2()`
```rust
pub fn generate_bounded_pow2(
    value: u64,
    max_bits: u8,
    blinding: [u8; 32]
) -> Result<Self>
```

Generate a proof that value fits in the specified number of bits.

##### `verify()`
```rust
pub fn verify(&self) -> Result<bool>
```

Verify the range proof.

##### `range_size()`
```rust
pub fn range_size(&self) -> u64
```

Get the size of the range (max - min + 1).

### ZkTransactionProof

High-level interface for transaction proofs.

```rust
pub struct ZkTransactionProof {
    pub amount_proof: ZkProof,
    pub balance_proof: ZkProof,
    pub nullifier_proof: ZkProof,
}
```

#### Methods

##### `new()`
```rust
pub fn new(
    amount_proof: ZkProof,
    balance_proof: ZkProof,
    nullifier_proof: ZkProof,
) -> Self
```

Create a new transaction proof from component proofs.

##### `prove_transaction()`
```rust
pub fn prove_transaction(
    sender_balance: u64,
    receiver_balance: u64,
    amount: u64,
    fee: u64,
    sender_blinding: [u8; 32],
    receiver_blinding: [u8; 32],
    nullifier: [u8; 32],
) -> anyhow::Result<Self>
```

Generate a complete transaction proof.

##### `verify()`
```rust
pub fn verify(&self) -> anyhow::Result<bool>
```

Verify all components of the transaction proof.

---

## ZK Integration Module

Functions for integrating with lib-crypto.

### `create_zk_system()`
```rust
pub fn create_zk_system() -> Result<ZkProofSystem>
```

Create a production ZK proof system instance.

### `prove_identity()`
```rust
pub fn prove_identity(
    private_key: &PrivateKey,
    age: u64,
    jurisdiction_hash: u64,
    credential_hash: u64,
    min_age: u64,
    required_jurisdiction: u64,
) -> Result<Plonky2Proof>
```

Generate identity proof using lib-crypto private key.

### `prove_range()`
```rust
pub fn prove_range(
    value: u64,
    blinding_factor: u64,
    min_value: u64,
    max_value: u64,
) -> Result<Plonky2Proof>
```

Generate range proof using integrated system.

### `prove_storage_access()`
```rust
pub fn prove_storage_access(
    access_key: u64,
    requester_secret: u64,
    data_hash: u64,
    permission_level: u64,
    required_permission: u64,
) -> Result<Plonky2Proof>
```

Generate storage access proof.

### `prove_ring_membership()`
```rust
pub fn prove_ring_membership(
    ring_members: &[Vec<u8>],
    secret_index: usize,
    secret_key: &[u8]
) -> Result<Plonky2Proof>
```

Prove membership in a ring without revealing which member.

### `prove_pqc_key_properties()`
```rust
pub fn prove_pqc_key_properties(private_key: &PrivateKey) -> Result<Plonky2Proof>
```

Prove properties of post-quantum cryptographic keys.

---

## Circuit Types

### Plonky2Proof

Core proof structure used throughout the system.

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

### CircuitBuilder

For constructing custom circuits.

```rust
pub struct CircuitBuilder {
    pub config: CircuitConfig,
    pub gates: Vec<CircuitGate>,
    pub public_inputs: Vec<usize>,
    pub constraints: Vec<CircuitConstraint>,
}
```

#### Methods

##### `new()`
```rust
pub fn new(config: CircuitConfig) -> Self
```

Create a new circuit builder.

##### `add_gate()`
```rust
pub fn add_gate(&mut self, gate: CircuitGate)
```

Add a gate to the circuit.

##### `add_public_input()`
```rust
pub fn add_public_input(&mut self, wire_index: Option<usize>) -> usize
```

Add a public input to the circuit.

##### `add_constraint()`
```rust
pub fn add_constraint(&mut self, constraint: CircuitConstraint)
```

Add a constraint to the circuit.

##### `build()`
```rust
pub fn build(self) -> Result<ZkCircuit>
```

Build the final circuit.

---

## Error Handling

All functions return `anyhow::Result<T>` for comprehensive error handling.

### Common Error Types

- **System Initialization Errors**: ZK system failed to initialize
- **Constraint Violations**: Input values don't satisfy proof constraints
- **Verification Failures**: Proof verification failed
- **Circuit Errors**: Circuit construction or compilation failed

### Error Handling Pattern

```rust
use anyhow::{Result, Context};

fn robust_proof_generation() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK system")?;
    
    let proof = zk_system.prove_range(500, 12345, 0, 1000)
        .context("Failed to generate range proof")?;
    
    let is_valid = zk_system.verify_range(&proof)
        .context("Failed to verify range proof")?;
    
    if !is_valid {
        anyhow::bail!("Range proof verification failed");
    }
    
    Ok(())
}
```

---

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

1. **Reuse ZkProofSystem**: Initialize once, use many times
2. **Batch operations**: Generate multiple proofs together when possible
3. **Use appropriate proof types**: Choose the simplest proof that meets requirements
4. **Profile your use case**: Measure actual performance in your application