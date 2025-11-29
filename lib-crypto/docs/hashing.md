# Hashing Module

Implementation of cryptographic hash functions: BLAKE3 for high performance and SHA-3 family for standards compliance. Provides secure, collision-resistant hashing for digital signatures, data integrity, and key derivation.

## Overview

The hashing module provides:
- **BLAKE3**: High-performance cryptographic hash function
- **SHA-3 Family**: NIST-standardized hash functions (SHA3-256, SHA3-512)
- **Keyed Hashing**: MAC and PRF capabilities
- **Streaming**: Efficient processing of large data

## BLAKE3

### Algorithm Overview
- **Performance**: Extremely fast on modern hardware
- **Security**: Based on BLAKE2, resistant to length extension attacks
- **Parallelization**: Native support for parallel processing
- **Versatility**: Hash, MAC, KDF, and PRF in one algorithm

### Basic Usage

```rust
use lib_crypto::hashing::{hash_blake3, blake3_keyed, blake3_derive_key};

fn blake3_examples() {
    let data = b"Data to hash with BLAKE3";
    
    // Simple hash
    let hash = hash_blake3(data);
    println!("BLAKE3 hash: {:?}", hash);
    
    // Keyed hash (MAC)
    let key = b"32-byte-secret-key-for-blake3-mac";
    let mac = blake3_keyed(data, key);
    println!("BLAKE3 MAC: {:?}", mac);
    
    // Key derivation
    let context = b"SOVEREIGN_NET_SESSION_KEY";
    let derived = blake3_derive_key(key, context);
    println!("Derived key: {:?}", derived);
}
```

### Performance Examples

```rust
use std::time::Instant;
use lib_crypto::hashing::hash_blake3;

fn blake3_performance() {
    let data_sizes = vec![1024, 10_240, 102_400, 1_048_576]; // 1KB to 1MB
    
    for size in data_sizes {
        let data = vec![0u8; size];
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _hash = hash_blake3(&data);
        }
        let elapsed = start.elapsed();
        
        let throughput = (size * 1000) as f64 / elapsed.as_secs_f64() / 1_000_000.0;
        println!("BLAKE3 {:.0}KB: {:.1} MB/s", size as f64 / 1024.0, throughput);
    }
}
```

### Streaming Interface

```rust
use lib_crypto::hashing::Blake3Hasher;

fn blake3_streaming() -> Result<()> {
    let mut hasher = Blake3Hasher::new();
    
    // Process data in chunks
    let chunks = vec![
        b"First chunk of data",
        b"Second chunk of data", 
        b"Final chunk of data",
    ];
    
    for chunk in chunks {
        hasher.update(chunk);
    }
    
    let hash = hasher.finalize();
    println!("Streaming BLAKE3 hash: {:?}", hash);
    
    Ok(())
}
```

## SHA-3 Family

### Algorithm Overview
- **Standardization**: NIST FIPS 202 approved
- **Security**: Based on Keccak sponge construction
- **Resistance**: Immune to length extension attacks
- **Variants**: SHA3-256, SHA3-512 with different output sizes

### Basic Usage

```rust
use lib_crypto::hashing::{hash_sha3_256, hash_sha3_512};

fn sha3_examples() {
    let data = b"Data to hash with SHA-3";
    
    // SHA3-256 (32-byte output)
    let hash256 = hash_sha3_256(data);
    println!("SHA3-256: {:?}", hash256);
    
    // SHA3-512 (64-byte output) 
    let hash512 = hash_sha3_512(data);
    println!("SHA3-512: {:?}", hash512);
}
```

### Standards Compliance

```rust
use lib_crypto::hashing::*;

fn standards_compliance() {
    let test_vector = b"abc";
    
    // NIST test vectors
    let sha3_256_expected = hash_sha3_256(test_vector);
    let sha3_512_expected = hash_sha3_512(test_vector);
    
    println!("SHA3-256('abc'): {:?}", sha3_256_expected);
    println!("SHA3-512('abc'): {:?}", sha3_512_expected);
    
    // These should match published NIST test vectors
}
```

## Integrated Usage

### With Digital Signatures

```rust
use lib_crypto::{KeyPair, hashing::hash_blake3};

fn signature_integration() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let document = b"Important document content";
    
    // Hash document before signing (good practice for large documents)
    let document_hash = hash_blake3(document);
    
    // Sign the hash instead of full document
    let signature = keypair.sign(&document_hash)?;
    
    // Verify by hashing and checking signature
    let verify_hash = hash_blake3(document);
    let is_valid = keypair.verify(&signature, &verify_hash)?;
    assert!(is_valid);
    
    println!("Document signature verified via hash");
    Ok(())
}
```

### With Key Derivation

```rust
use lib_crypto::hashing::{hash_blake3, blake3_derive_key};

fn key_derivation_example() -> Result<()> {
    let master_secret = b"high-entropy-master-secret-key-32b";
    
    // Derive different keys for different purposes
    let signing_key = blake3_derive_key(master_secret, b"SIGNING_KEY_V1");
    let encryption_key = blake3_derive_key(master_secret, b"ENCRYPTION_KEY_V1");
    let auth_key = blake3_derive_key(master_secret, b"AUTH_KEY_V1");
    
    // Keys are cryptographically independent
    assert_ne!(signing_key, encryption_key);
    assert_ne!(signing_key, auth_key);
    assert_ne!(encryption_key, auth_key);
    
    println!("Derived independent keys from master secret");
    Ok(())
}
```

### With Data Integrity

```rust
use lib_crypto::hashing::hash_blake3;
use std::collections::HashMap;

fn data_integrity_system() -> Result<()> {
    // Integrity checking system
    let mut integrity_db = HashMap::new();
    
    let files = vec![
        ("config.json", b"{'setting': 'value'}"),
        ("data.bin", b"binary data content"),
        ("readme.txt", b"Documentation content"),
    ];
    
    // Store hashes for integrity verification
    for (filename, content) in &files {
        let hash = hash_blake3(content);
        integrity_db.insert(*filename, hash);
        println!("Stored hash for {}: {:?}", filename, hash);
    }
    
    // Later: verify file integrity
    for (filename, content) in &files {
        let current_hash = hash_blake3(content);
        let stored_hash = integrity_db.get(filename).unwrap();
        
        if current_hash == *stored_hash {
            println!("{}: Integrity verified ", filename);
        } else {
            println!("{}: INTEGRITY FAILURE ✗", filename);
        }
    }
    
    Ok(())
}
```

## Performance Comparison

```rust
use std::time::Instant;
use lib_crypto::hashing::*;

fn hash_performance_comparison() {
    let data = vec![0u8; 1_048_576]; // 1MB test data
    let iterations = 100;
    
    // BLAKE3 benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _hash = hash_blake3(&data);
    }
    let blake3_time = start.elapsed();
    
    // SHA3-256 benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _hash = hash_sha3_256(&data);
    }
    let sha3_256_time = start.elapsed();
    
    // SHA3-512 benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _hash = hash_sha3_512(&data);
    }
    let sha3_512_time = start.elapsed();
    
    println!("Performance (1MB × {} iterations):", iterations);
    println!("BLAKE3:    {:?}", blake3_time);
    println!("SHA3-256:  {:?}", sha3_256_time);
    println!("SHA3-512:  {:?}", sha3_512_time);
    
    // BLAKE3 is typically 2-5x faster than SHA3
}
```

## Security Considerations

### Hash Function Selection

```rust
use lib_crypto::hashing::*;

fn hash_selection_guide() {
    let data = b"Example data for hashing";
    
    // Use BLAKE3 for:
    // - High performance requirements
    // - Modern applications
    // - Key derivation
    let blake3_hash = hash_blake3(data);
    
    // Use SHA3 for:
    // - Standards compliance requirements
    // - Regulatory environments
    // - Legacy system compatibility
    let sha3_hash = hash_sha3_256(data);
    
    println!("BLAKE3 (performance): {:?}", blake3_hash);
    println!("SHA3-256 (standards): {:?}", sha3_hash);
}
```

### Collision Resistance

```rust
use lib_crypto::hashing::hash_blake3;

fn collision_resistance_example() {
    // Both hash functions provide strong collision resistance
    let data1 = b"First message";
    let data2 = b"Second message"; 
    
    let hash1 = hash_blake3(data1);
    let hash2 = hash_blake3(data2);
    
    // Extremely unlikely to be equal (2^-128 probability for different inputs)
    assert_ne!(hash1, hash2);
    
    // Same input always produces same output (deterministic)
    let hash1_repeat = hash_blake3(data1);
    assert_eq!(hash1, hash1_repeat);
    
    println!("Collision resistance and determinism verified");
}
```

## Advanced Features

### Message Authentication Codes (MAC)

```rust
use lib_crypto::hashing::blake3_keyed;

fn mac_examples() -> Result<()> {
    let secret_key = b"shared-secret-key-32-bytes-long!";
    let message = b"Message to authenticate";
    
    // Create MAC
    let mac = blake3_keyed(message, secret_key);
    
    // Verify MAC (receiver with same key)
    let verify_mac = blake3_keyed(message, secret_key);
    assert_eq!(mac, verify_mac);
    
    // Different key produces different MAC
    let wrong_key = b"different-key-32-bytes-long----!";
    let wrong_mac = blake3_keyed(message, wrong_key);
    assert_ne!(mac, wrong_mac);
    
    println!("MAC authentication verified");
    Ok(())
}
```

### Custom Hash Contexts

```rust
use lib_crypto::hashing::Blake3Hasher;

fn custom_hash_contexts() -> Result<()> {
    // Different contexts for domain separation
    let contexts = vec![
        "SOVEREIGN_NET_TRANSACTION_V1",
        "SOVEREIGN_NET_IDENTITY_V1", 
        "SOVEREIGN_NET_STORAGE_V1",
    ];
    
    let data = b"Same input data";
    
    for context in contexts {
        let mut hasher = Blake3Hasher::new();
        hasher.update(context.as_bytes());
        hasher.update(b"::");
        hasher.update(data);
        
        let hash = hasher.finalize();
        println!("Hash for {}: {:?}", context, hash);
    }
    
    // Each context produces different hash for same data
    // This prevents cross-domain attacks
    
    Ok(())
}
```

## Integration Examples

### Blockchain Integration

```rust
use lib_crypto::hashing::hash_blake3;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Block {
    prev_hash: [u8; 32],
    transactions: Vec<String>,
    nonce: u64,
}

fn blockchain_hashing() -> Result<()> {
    let block = Block {
        prev_hash: [0u8; 32],
        transactions: vec![
            "Alice -> Bob: 10 coins".to_string(),
            "Bob -> Charlie: 5 coins".to_string(),
        ],
        nonce: 12345,
    };
    
    // Serialize and hash block
    let serialized = bincode::serialize(&block)?;
    let block_hash = hash_blake3(&serialized);
    
    println!("Block hash: {:?}", block_hash);
    
    // Hash can be used as unique block identifier
    // and for proof-of-work validation
    
    Ok(())
}
```

### Merkle Tree Construction

```rust
use lib_crypto::hashing::hash_blake3;

fn merkle_tree_example() -> Result<()> {
    let transactions = vec![
        b"tx1: Alice -> Bob",
        b"tx2: Bob -> Charlie", 
        b"tx3: Charlie -> Dave",
        b"tx4: Dave -> Alice",
    ];
    
    // Hash leaf nodes
    let mut level: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| hash_blake3(tx))
        .collect();
    
    // Build tree bottom-up
    while level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in level.chunks(2) {
            let mut combined = Vec::new();
            combined.extend_from_slice(&chunk[0]);
            if chunk.len() > 1 {
                combined.extend_from_slice(&chunk[1]);
            } else {
                // Odd number - duplicate last hash
                combined.extend_from_slice(&chunk[0]);
            }
            
            next_level.push(hash_blake3(&combined));
        }
        
        level = next_level;
    }
    
    let merkle_root = level[0];
    println!("Merkle root: {:?}", merkle_root);
    
    Ok(())
}
```

## Best Practices

### 1. Algorithm Selection

```rust
use lib_crypto::hashing::*;

fn algorithm_selection() {
    // Choose BLAKE3 for:
    println!("Use BLAKE3 for:");
    println!("- New applications requiring high performance");
    println!("- Streaming data processing");
    println!("- Key derivation functions");
    println!("- Internal system hashing");
    
    // Choose SHA3 for:
    println!("\nUse SHA3 for:");
    println!("- Regulatory compliance requirements");
    println!("- Interoperability with other systems");
    println!("- Long-term archival data");
    println!("- Standards-mandated applications");
}
```

### 2. Performance Optimization

```rust
use lib_crypto::hashing::{Blake3Hasher, hash_blake3};

fn performance_optimization() -> Result<()> {
    let large_data = vec![0u8; 10_000_000]; // 10MB
    
    // For small data: direct function call
    if large_data.len() < 1024 {
        let _hash = hash_blake3(&large_data);
    }
    
    // For large data: streaming interface (more memory efficient)
    let mut hasher = Blake3Hasher::new();
    for chunk in large_data.chunks(8192) {
        hasher.update(chunk);
    }
    let _hash = hasher.finalize();
    
    println!("Large data hashed efficiently");
    Ok(())
}
```

### 3. Security Guidelines

```rust
use lib_crypto::hashing::{hash_blake3, blake3_keyed};

fn security_guidelines() {
    let sensitive_data = b"Password or other sensitive data";
    
    // Don't use plain hashing for passwords
    let _weak = hash_blake3(sensitive_data);
    
    // Use keyed hashing with salt for passwords
    let salt = b"random-salt-16-bytes"; 
    let _better = blake3_keyed(sensitive_data, salt);
    
    // Even better: use dedicated password hashing (Argon2, etc.)
    println!("Use appropriate hashing method for use case");
    
    // Always use domain separation for different contexts
    let context = b"SOVEREIGN_NET_AUTH_V1";
    let mut contextualized = Vec::new();
    contextualized.extend_from_slice(context);
    contextualized.extend_from_slice(b"::");
    contextualized.extend_from_slice(sensitive_data);
    
    let _domain_separated = hash_blake3(&contextualized);
}
```

The hashing module provides efficient and secure hash functions for all cryptographic needs within the SOVEREIGN_NET ecosystem, balancing performance and standards compliance.
