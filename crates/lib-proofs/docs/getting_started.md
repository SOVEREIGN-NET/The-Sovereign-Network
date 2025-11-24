# Getting Started with lib-proofs

This guide will help you get up and running with the SOVEREIGN_NET zero-knowledge proof system.

## Installation

Add lib-proofs to your `Cargo.toml`:

```toml
[dependencies]
lib-proofs = { path = "../lib-proofs" }
lib-crypto = { path = "../lib-crypto" }
anyhow = "1.0"
```

For development and testing:
```toml
[dev-dependencies]
lib-proofs = { path = "../lib-proofs", features = ["dev"] }
tokio = { version = "1.0", features = ["full"] }
```

## Basic Usage

### 1. Initialize the ZK Proof System

```rust
use lib_proofs::ZkProofSystem;
use anyhow::Result;

fn main() -> Result<()> {
    // Initialize the production ZK proof system
    let zk_system = ZkProofSystem::new()?;
    
    println!("ZK proof system initialized successfully!");
    Ok(())
}
```

### 2. Generate Your First Proof

#### Range Proof Example
```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};

fn range_proof_example() -> Result<()> {
    // Prove that your balance is between $1,000 and $50,000
    // without revealing the exact amount
    let actual_balance = 25000; // This remains private
    let blinding_factor = [42u8; 32]; // Random blinding
    
    let proof = ZkRangeProof::generate(
        actual_balance,
        1000,    // min_value (public)
        50000,   // max_value (public)
        blinding_factor,
    )?;
    
    // Verify the proof
    let is_valid = proof.verify()?;
    assert!(is_valid);
    
    println!("Range proof verified: balance is in valid range!");
    Ok(())
}
```

#### Transaction Proof Example
```rust
use lib_proofs::ZkProofSystem;

fn transaction_proof_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Prove transaction validity without revealing balances
    let tx_proof = zk_system.prove_transaction(
        1000,  // sender_balance (private)
        100,   // amount (public)
        10,    // fee (public)
        12345, // sender_secret (private)
        67890, // nullifier_seed (private)
    )?;
    
    // Verify the transaction proof
    let is_valid = zk_system.verify_transaction(&tx_proof)?;
    assert!(is_valid);
    
    println!("Transaction proof verified: transaction is valid!");
    Ok(())
}
```

### 3. Identity Proofs

```rust
use lib_proofs::zk_integration;
use lib_crypto::KeyPair;

fn identity_proof_example() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Prove you're over 18 and from the US without revealing
    // your exact age or identity
    let identity_proof = zk_integration::prove_identity(
        &keypair.private_key,
        25,   // actual_age (private)
        840,  // jurisdiction_hash - US (private)
        9999, // credential_hash (private)
        18,   // min_age_requirement (public)
        840,  // required_jurisdiction (public)
    )?;
    
    println!("Identity proof generated successfully!");
    println!("Proof confirms: age ≥ 18 and valid jurisdiction");
    Ok(())
}
```

### 4. Storage Access Proofs

```rust
use lib_proofs::ZkProofSystem;

fn storage_access_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Prove you have permission to access data without
    // revealing your identity or exact permission level
    let access_proof = zk_system.prove_storage_access(
        11111, // access_key (private)
        22222, // requester_secret (private)
        33333, // data_hash (public)
        5,     // your_permission_level (private)
        3,     // required_permission_level (public)
    )?;
    
    let is_valid = zk_system.verify_storage_access(&access_proof)?;
    assert!(is_valid);
    
    println!("Storage access proof verified: access granted!");
    Ok(())
}
```

## Advanced Usage

### Batch Proof Generation

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};

fn batch_proof_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Generate multiple proofs efficiently
    let values = vec![100, 200, 300, 400, 500];
    let mut proofs = Vec::new();
    
    for value in values {
        let proof = ZkRangeProof::generate_simple(value, 0, 1000)?;
        proofs.push(proof);
    }
    
    // Verify all proofs
    for (i, proof) in proofs.iter().enumerate() {
        let is_valid = proof.verify()?;
        assert!(is_valid);
        println!("Proof {} verified successfully", i + 1);
    }
    
    println!("All {} proofs verified!", proofs.len());
    Ok(())
}
```

### Recursive Proof Aggregation

```rust
use lib_proofs::{ZkProofSystem, types::ZkProof};

fn recursive_aggregation_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Generate multiple transaction proofs
    let mut tx_proofs = Vec::new();
    for i in 0..5 {
        let proof = zk_system.prove_transaction(
            1000 + i * 100, // varying balances
            50 + i * 10,    // varying amounts
            5,              // fixed fee
            12345 + i,      // varying secrets
            67890 + i,      // varying nullifiers
        )?;
        tx_proofs.push(proof);
    }
    
    // TODO: Implement recursive aggregation
    // let aggregated_proof = zk_system.aggregate_proofs(&tx_proofs)?;
    
    println!("Generated {} transaction proofs for aggregation", tx_proofs.len());
    Ok(())
}
```

## Error Handling

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};
use anyhow::{Result, Context};

fn robust_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK proof system")?;
    
    // This will fail because value is out of range
    let invalid_proof = ZkRangeProof::generate_simple(1500, 0, 1000);
    
    match invalid_proof {
        Ok(proof) => {
            println!("Proof generated: {:?}", proof);
        },
        Err(e) => {
            println!("Expected error: {}", e);
            // Handle the error appropriately
        }
    }
    
    // This will succeed
    let valid_proof = ZkRangeProof::generate_simple(500, 0, 1000)
        .context("Failed to generate valid range proof")?;
    
    let is_valid = valid_proof.verify()
        .context("Failed to verify range proof")?;
    
    assert!(is_valid);
    println!("Valid proof generated and verified successfully!");
    
    Ok(())
}
```

## Performance Considerations

### Proof Generation Optimization

```rust
use std::time::Instant;
use lib_proofs::ZkRangeProof;

fn performance_example() -> Result<()> {
    let start = Instant::now();
    
    // Generate multiple proofs and measure performance
    let mut proofs = Vec::new();
    for i in 0..100 {
        let proof = ZkRangeProof::generate_simple(i * 10, 0, 1000)?;
        proofs.push(proof);
    }
    
    let generation_time = start.elapsed();
    println!("Generated 100 proofs in {:?}", generation_time);
    println!("Average: {:?} per proof", generation_time / 100);
    
    // Measure verification time
    let start = Instant::now();
    for proof in &proofs {
        let _valid = proof.verify()?;
    }
    let verification_time = start.elapsed();
    println!("Verified 100 proofs in {:?}", verification_time);
    println!("Average: {:?} per verification", verification_time / 100);
    
    Ok(())
}
```

### Memory Usage Optimization

```rust
use lib_proofs::ZkRangeProof;

fn memory_efficient_example() -> Result<()> {
    // Generate proofs one at a time to minimize memory usage
    for i in 0..1000 {
        let proof = ZkRangeProof::generate_simple(i, 0, 2000)?;
        let is_valid = proof.verify()?;
        assert!(is_valid);
        
        // Proof is automatically dropped here, freeing memory
        if i % 100 == 0 {
            println!("Processed {} proofs", i + 1);
        }
    }
    
    println!("All proofs processed with minimal memory usage");
    Ok(())
}
```

## Integration with SOVEREIGN_NET

### Blockchain Integration

```rust
use lib_proofs::ZkProofSystem;
use lib_crypto::KeyPair;

fn blockchain_integration_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    let keypair = KeyPair::generate()?;
    
    // Generate a transaction proof for blockchain submission
    let tx_proof = zk_system.prove_transaction(
        1000, // sender balance
        100,  // amount to send
        10,   // transaction fee
        12345, // sender secret
        67890, // nullifier
    )?;
    
    // In a blockchain integration, you would:
    // 1. Serialize the proof
    // 2. Submit to the blockchain
    // 3. Blockchain verifies the proof on-chain
    
    println!("Transaction proof ready for blockchain submission");
    println!("Proof size: {} bytes", tx_proof.proof.len());
    
    Ok(())
}
```

## Next Steps

1. **Read the [API Reference](api_reference.md)** for complete function documentation
2. **Check out [Examples](examples.md)** for more comprehensive use cases  
3. **Review [Integration Guide](integration.md)** for SOVEREIGN_NET ecosystem usage
4. **Study [Circuit Documentation](circuits.md)** for custom circuit development
5. **See [Performance Guide](performance.md)** for optimization strategies

## Common Issues

### Build Issues
```bash
# Make sure you have the latest Rust toolchain
rustup update

# Clean and rebuild if you encounter issues
cargo clean
cargo build --release
```

### Performance Issues
- Use `--release` flag for production builds
- Consider proof batching for multiple operations
- Profile your specific use case with the built-in benchmarks

### Integration Issues
- Ensure compatible versions of lib-crypto and lib-proofs
- Check the [Integration Guide](integration.md) for ecosystem-specific patterns
- Review the [TODO.md](../TODO.md) for known integration issues

## Getting Help

- Check the [API Reference](api_reference.md) for detailed function documentation
- Review [Examples](examples.md) for your specific use case
- See [TODO.md](../TODO.md) for known issues and limitations
# Getting Started with lib-proofs

This guide will help you get up and running with the SOVEREIGN_NET zero-knowledge proof system.

## Installation

Add lib-proofs to your `Cargo.toml`:

```toml
[dependencies]
lib-proofs = { path = "../lib-proofs" }
lib-crypto = { path = "../lib-crypto" }
anyhow = "1.0"
```

For development and testing:
```toml
[dev-dependencies]
lib-proofs = { path = "../lib-proofs", features = ["dev"] }
tokio = { version = "1.0", features = ["full"] }
```

## Basic Usage

### 1. Initialize the ZK Proof System

```rust
use lib_proofs::ZkProofSystem;
use anyhow::Result;

fn main() -> Result<()> {
    // Initialize the production ZK proof system
    let zk_system = ZkProofSystem::new()?;
    
    println!("ZK proof system initialized successfully!");
    Ok(())
}
```

### 2. Generate Your First Proof

#### Range Proof Example
```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};

fn range_proof_example() -> Result<()> {
    // Prove that your balance is between $1,000 and $50,000
    // without revealing the exact amount
    let actual_balance = 25000; // This remains private
    let blinding_factor = [42u8; 32]; // Random blinding
    
    let proof = ZkRangeProof::generate(
        actual_balance,
        1000,    // min_value (public)
        50000,   // max_value (public)
        blinding_factor,
    )?;
    
    // Verify the proof
    let is_valid = proof.verify()?;
    assert!(is_valid);
    
    println!("Range proof verified: balance is in valid range!");
    Ok(())
}
```

#### Transaction Proof Example
```rust
use lib_proofs::ZkProofSystem;

fn transaction_proof_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Prove transaction validity without revealing balances
    let tx_proof = zk_system.prove_transaction(
        1000,  // sender_balance (private)
        100,   // amount (public)
        10,    // fee (public)
        12345, // sender_secret (private)
        67890, // nullifier_seed (private)
    )?;
    
    // Verify the transaction proof
    let is_valid = zk_system.verify_transaction(&tx_proof)?;
    assert!(is_valid);
    
    println!("Transaction proof verified: transaction is valid!");
    Ok(())
}
```

### 3. Identity Proofs

```rust
use lib_proofs::zk_integration;
use lib_crypto::KeyPair;

fn identity_proof_example() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Prove you're over 18 and from the US without revealing
    // your exact age or identity
    let identity_proof = zk_integration::prove_identity(
        &keypair.private_key,
        25,   // actual_age (private)
        840,  // jurisdiction_hash - US (private)
        9999, // credential_hash (private)
        18,   // min_age_requirement (public)
        840,  // required_jurisdiction (public)
    )?;
    
    println!("Identity proof generated successfully!");
    println!("Proof confirms: age ≥ 18 and valid jurisdiction");
    Ok(())
}
```

### 4. Storage Access Proofs

```rust
use lib_proofs::ZkProofSystem;

fn storage_access_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Prove you have permission to access data without
    // revealing your identity or exact permission level
    let access_proof = zk_system.prove_storage_access(
        11111, // access_key (private)
        22222, // requester_secret (private)
        33333, // data_hash (public)
        5,     // your_permission_level (private)
        3,     // required_permission_level (public)
    )?;
    
    let is_valid = zk_system.verify_storage_access(&access_proof)?;
    assert!(is_valid);
    
    println!("Storage access proof verified: access granted!");
    Ok(())
}
```

## Advanced Usage

### Batch Proof Generation

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};

fn batch_proof_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Generate multiple proofs efficiently
    let values = vec![100, 200, 300, 400, 500];
    let mut proofs = Vec::new();
    
    for value in values {
        let proof = ZkRangeProof::generate_simple(value, 0, 1000)?;
        proofs.push(proof);
    }
    
    // Verify all proofs
    for (i, proof) in proofs.iter().enumerate() {
        let is_valid = proof.verify()?;
        assert!(is_valid);
        println!("Proof {} verified successfully", i + 1);
    }
    
    println!("All {} proofs verified!", proofs.len());
    Ok(())
}
```

### Recursive Proof Aggregation

```rust
use lib_proofs::{ZkProofSystem, types::ZkProof};

fn recursive_aggregation_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    
    // Generate multiple transaction proofs
    let mut tx_proofs = Vec::new();
    for i in 0..5 {
        let proof = zk_system.prove_transaction(
            1000 + i * 100, // varying balances
            50 + i * 10,    // varying amounts
            5,              // fixed fee
            12345 + i,      // varying secrets
            67890 + i,      // varying nullifiers
        )?;
        tx_proofs.push(proof);
    }
    
    // TODO: Implement recursive aggregation
    // let aggregated_proof = zk_system.aggregate_proofs(&tx_proofs)?;
    
    println!("Generated {} transaction proofs for aggregation", tx_proofs.len());
    Ok(())
}
```

## Error Handling

```rust
use lib_proofs::{ZkProofSystem, ZkRangeProof};
use anyhow::{Result, Context};

fn robust_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()
        .context("Failed to initialize ZK proof system")?;
    
    // This will fail because value is out of range
    let invalid_proof = ZkRangeProof::generate_simple(1500, 0, 1000);
    
    match invalid_proof {
        Ok(proof) => {
            println!("Proof generated: {:?}", proof);
        },
        Err(e) => {
            println!("Expected error: {}", e);
            // Handle the error appropriately
        }
    }
    
    // This will succeed
    let valid_proof = ZkRangeProof::generate_simple(500, 0, 1000)
        .context("Failed to generate valid range proof")?;
    
    let is_valid = valid_proof.verify()
        .context("Failed to verify range proof")?;
    
    assert!(is_valid);
    println!("Valid proof generated and verified successfully!");
    
    Ok(())
}
```

## Performance Considerations

### Proof Generation Optimization

```rust
use std::time::Instant;
use lib_proofs::ZkRangeProof;

fn performance_example() -> Result<()> {
    let start = Instant::now();
    
    // Generate multiple proofs and measure performance
    let mut proofs = Vec::new();
    for i in 0..100 {
        let proof = ZkRangeProof::generate_simple(i * 10, 0, 1000)?;
        proofs.push(proof);
    }
    
    let generation_time = start.elapsed();
    println!("Generated 100 proofs in {:?}", generation_time);
    println!("Average: {:?} per proof", generation_time / 100);
    
    // Measure verification time
    let start = Instant::now();
    for proof in &proofs {
        let _valid = proof.verify()?;
    }
    let verification_time = start.elapsed();
    println!("Verified 100 proofs in {:?}", verification_time);
    println!("Average: {:?} per verification", verification_time / 100);
    
    Ok(())
}
```

### Memory Usage Optimization

```rust
use lib_proofs::ZkRangeProof;

fn memory_efficient_example() -> Result<()> {
    // Generate proofs one at a time to minimize memory usage
    for i in 0..1000 {
        let proof = ZkRangeProof::generate_simple(i, 0, 2000)?;
        let is_valid = proof.verify()?;
        assert!(is_valid);
        
        // Proof is automatically dropped here, freeing memory
        if i % 100 == 0 {
            println!("Processed {} proofs", i + 1);
        }
    }
    
    println!("All proofs processed with minimal memory usage");
    Ok(())
}
```

## Integration with SOVEREIGN_NET

### Blockchain Integration

```rust
use lib_proofs::ZkProofSystem;
use lib_crypto::KeyPair;

fn blockchain_integration_example() -> Result<()> {
    let zk_system = ZkProofSystem::new()?;
    let keypair = KeyPair::generate()?;
    
    // Generate a transaction proof for blockchain submission
    let tx_proof = zk_system.prove_transaction(
        1000, // sender balance
        100,  // amount to send
        10,   // transaction fee
        12345, // sender secret
        67890, // nullifier
    )?;
    
    // In a real blockchain integration, you would:
    // 1. Serialize the proof
    // 2. Submit to the blockchain
    // 3. Blockchain verifies the proof on-chain
    
    println!("Transaction proof ready for blockchain submission");
    println!("Proof size: {} bytes", tx_proof.proof.len());
    
    Ok(())
}
```

## Next Steps

1. **Read the [API Reference](api_reference.md)** for complete function documentation
2. **Check out [Examples](examples.md)** for more comprehensive use cases  
3. **Review [Integration Guide](integration.md)** for SOVEREIGN_NET ecosystem usage
4. **Study [Circuit Documentation](circuits.md)** for custom circuit development
5. **See [Performance Guide](performance.md)** for optimization strategies

## Common Issues

### Build Issues
```bash
# Make sure you have the latest Rust toolchain
rustup update

# Clean and rebuild if you encounter issues
cargo clean
cargo build --release
```

### Performance Issues
- Use `--release` flag for production builds
- Consider proof batching for multiple operations
- Profile your specific use case with the built-in benchmarks

### Integration Issues
- Ensure compatible versions of lib-crypto and lib-proofs
- Check the [Integration Guide](integration.md) for ecosystem-specific patterns
- Review the [TODO.md](../TODO.md) for known integration issues

## Getting Help

- Check the [API Reference](api_reference.md) for detailed function documentation
- Review [Examples](examples.md) for your specific use case
- See [TODO.md](../TODO.md) for known issues and limitations
- Study the source code for advanced usage patterns