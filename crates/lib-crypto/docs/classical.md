# Classical Module

Implementation of classical cryptographic algorithms: Ed25519 digital signatures and Curve25519 operations. These provide compatibility with existing systems and serve as fallback options during the post-quantum transition period.

## Overview

The classical module provides:
- **Ed25519**: Fast, secure digital signatures
- **Curve25519**: Elliptic curve operations for ring signatures
- **Compatibility**: Integration with legacy systems
- **Performance**: High-speed operations for current use

## Ed25519 Digital Signatures

### Algorithm Overview
- **Type**: Edwards curve digital signature scheme
- **Security**: Based on elliptic curve discrete logarithm problem
- **Performance**: Very fast signing and verification
- **Key Size**: 32-byte public keys, 32-byte private keys
- **Signature Size**: 64 bytes

### Usage Examples

```rust
use lib_crypto::classical::{ed25519_keypair, ed25519_sign, ed25519_verify};

fn ed25519_example() -> Result<()> {
    // Generate Ed25519 keypair
    let (public_key, private_key) = ed25519_keypair()?;
    
    let message = b"Classical cryptography message";
    
    // Sign message
    let signature = ed25519_sign(message, &private_key)?;
    
    // Verify signature
    let is_valid = ed25519_verify(message, &signature, &public_key)?;
    assert!(is_valid);
    
    println!("Ed25519 signature size: {} bytes", signature.len());
    println!("Ed25519 public key size: {} bytes", public_key.len());
    
    Ok(())
}
```

### Performance Characteristics

```rust
use std::time::Instant;
use lib_crypto::classical::*;

fn ed25519_benchmarks() -> Result<()> {
    let (pk, sk) = ed25519_keypair()?;
    let message = b"Benchmark message";
    
    // Signing benchmark - very fast
    let start = Instant::now();
    for _ in 0..10000 {
        let _sig = ed25519_sign(message, &sk)?;
    }
    println!("10,000 Ed25519 signs: {:?}", start.elapsed());
    // Typical: ~100-200ms
    
    // Verification benchmark - extremely fast
    let signature = ed25519_sign(message, &sk)?;
    let start = Instant::now();
    for _ in 0..10000 {
        let _valid = ed25519_verify(message, &signature, &pk)?;
    }
    println!("10,000 Ed25519 verifications: {:?}", start.elapsed());
    // Typical: ~150-300ms
    
    Ok(())
}
```

## Curve25519 Operations

### Algorithm Overview
- **Type**: Montgomery curve operations
- **Purpose**: Ring signature support, key agreement
- **Security**: ~128-bit classical security
- **Performance**: Fast elliptic curve operations

### Usage Examples

```rust
use lib_crypto::classical::{
    curve25519_scalar_mult, generate_key_image,
    scalar_to_point, point_to_bytes
};

fn curve25519_example() -> Result<()> {
    let private_key = b"example_private_key_32_bytes____";
    let base_point = [9u8; 32]; // Standard Curve25519 base point
    
    // Scalar multiplication
    let public_point = curve25519_scalar_mult(private_key, &base_point)?;
    
    // Key image generation (for ring signatures)
    let key_image = generate_key_image(private_key)?;
    
    println!("Public point: {:?}", public_point);
    println!("Key image: {:?}", key_image);
    
    // Point operations
    let point = scalar_to_point(private_key);
    let point_bytes = point_to_bytes(&point);
    
    Ok(())
}
```

## Integration with KeyPair

### Classical Signatures via KeyPair

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn keypair_classical() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Message for classical signature";
    
    // Use Ed25519 through KeyPair interface
    let signature = keypair.sign_ed25519(message)?;
    assert_eq!(signature.algorithm, SignatureAlgorithm::Ed25519);
    
    // Verify
    let is_valid = keypair.verify(&signature, message)?;
    assert!(is_valid);
    
    // Access raw Ed25519 keys
    let ed25519_pk = &keypair.public_key.ed25519_pk;
    let ed25519_sk = &keypair.private_key.ed25519_sk;
    
    println!("Ed25519 public key length: {}", ed25519_pk.len());
    
    Ok(())
}
```

## Compatibility Features

### Legacy System Integration

```rust
use lib_crypto::classical::*;
use base64;

fn legacy_integration() -> Result<()> {
    let (public_key, private_key) = ed25519_keypair()?;
    let message = b"Legacy system message";
    
    // Sign with Ed25519
    let signature = ed25519_sign(message, &private_key)?;
    
    // Encode for legacy systems (Base64, hex, etc.)
    let pk_base64 = base64::encode(&public_key);
    let sig_base64 = base64::encode(&signature);
    
    println!("Public key (Base64): {}", pk_base64);
    println!("Signature (Base64): {}", sig_base64);
    
    // Decode and verify
    let decoded_pk = base64::decode(&pk_base64)?;
    let decoded_sig = base64::decode(&sig_base64)?;
    
    let is_valid = ed25519_verify(message, &decoded_sig, &decoded_pk)?;
    assert!(is_valid);
    
    Ok(())
}
```

### Cross-Platform Compatibility

```rust
use lib_crypto::classical::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct LegacySignature {
    public_key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
}

fn cross_platform_example() -> Result<()> {
    let (pk, sk) = ed25519_keypair()?;
    let message = b"Cross-platform message";
    let signature = ed25519_sign(message, &sk)?;
    
    // Create portable format
    let legacy_sig = LegacySignature {
        public_key: pk.to_vec(),
        signature: signature.to_vec(),
        message: message.to_vec(),
    };
    
    // Serialize to JSON for transmission
    let json = serde_json::to_string(&legacy_sig)?;
    
    // Deserialize and verify
    let restored: LegacySignature = serde_json::from_str(&json)?;
    let is_valid = ed25519_verify(
        &restored.message,
        &restored.signature, 
        &restored.public_key
    )?;
    assert!(is_valid);
    
    Ok(())
}
```

## Security Considerations

### Quantum Vulnerability

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn quantum_considerations() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Security planning message";
    
    // Ed25519 is vulnerable to quantum attacks
    let classical_sig = keypair.sign_ed25519(message)?;
    
    // Use for current compatibility, but plan migration
    println!("Ed25519 provides ~128-bit classical security");
    println!("Vulnerable to Shor's algorithm on quantum computers");
    
    // For future-proofing, use post-quantum
    let pq_sig = keypair.sign(message)?;
    
    match pq_sig.algorithm {
        SignatureAlgorithm::Dilithium2 => {
            println!("Dilithium provides quantum-resistant security");
        },
        _ => {},
    }
    
    Ok(())
}
```

### Migration Strategy

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn migration_strategy() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let document = b"Important document";
    
    // Phase 1: Dual signatures for transition
    let classical_sig = keypair.sign_ed25519(document)?;
    let pq_sig = keypair.sign(document)?;
    
    // Store both signatures
    let signatures = vec![classical_sig, pq_sig];
    
    // Phase 2: Verification supports both
    for signature in &signatures {
        match signature.algorithm {
            SignatureAlgorithm::Ed25519 => {
                println!("Verifying classical signature");
                assert!(keypair.verify(signature, document)?);
            },
            SignatureAlgorithm::Dilithium2 => {
                println!("Verifying post-quantum signature");
                assert!(keypair.verify(signature, document)?);
            },
            _ => {},
        }
    }
    
    // Phase 3: Eventually drop classical support
    // (when quantum computers become practical threat)
    
    Ok(())
}
```

## Performance Optimization

### High-Throughput Applications

```rust
use lib_crypto::classical::*;
use rayon::prelude::*;

fn high_throughput_signing() -> Result<()> {
    let (pk, sk) = ed25519_keypair()?;
    
    // Generate many messages to sign
    let messages: Vec<Vec<u8>> = (0..10000)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    
    // Parallel signing (Ed25519 is very fast)
    let signatures: Vec<_> = messages
        .par_iter()
        .map(|msg| ed25519_sign(msg, &sk))
        .collect::<Result<Vec<_>, _>>()?;
    
    // Parallel verification
    let verification_results: Vec<bool> = messages
        .par_iter()
        .zip(signatures.par_iter())
        .map(|(msg, sig)| ed25519_verify(msg, sig, &pk).unwrap_or(false))
        .collect();
    
    let all_valid = verification_results.iter().all(|&x| x);
    assert!(all_valid);
    
    println!("Processed {} signatures successfully", signatures.len());
    Ok(())
}
```

### Memory-Efficient Operations

```rust
use lib_crypto::classical::*;

fn memory_efficient_operations() -> Result<()> {
    let (pk, sk) = ed25519_keypair()?;
    
    // Process messages without storing all signatures
    let mut verified_count = 0;
    
    for i in 0..10000 {
        let message = format!("Stream message {}", i);
        let signature = ed25519_sign(message.as_bytes(), &sk)?;
        
        if ed25519_verify(message.as_bytes(), &signature, &pk)? {
            verified_count += 1;
        }
        
        // Signature memory freed at end of loop iteration
    }
    
    println!("Verified {} signatures in streaming fashion", verified_count);
    Ok(())
}
```

## Ring Signature Support

### Curve25519 for Ring Signatures

```rust
use lib_crypto::{
    classical::{generate_key_image, scalar_to_point, curve25519_scalar_mult},
    advanced::RingContext,
    KeyPair
};

fn ring_signature_classical() -> Result<()> {
    // Ring signatures use Curve25519 operations
    let keypair = KeyPair::generate()?;
    
    // Generate key image for double-spend prevention
    let key_image = generate_key_image(&keypair.private_key.ed25519_sk)?;
    
    // Key image is deterministic for same private key
    let key_image2 = generate_key_image(&keypair.private_key.ed25519_sk)?;
    assert_eq!(key_image, key_image2);
    
    // Use in ring signature context
    let ring = vec![keypair.public_key.clone()];
    let message = b"Anonymous message";
    
    let mut ring_context = RingContext::new(ring, message.to_vec());
    ring_context.set_signer(0, keypair.private_key.clone())?;
    
    let ring_signature = ring_context.sign()?;
    
    println!("Ring signature key image: {:?}", ring_signature.key_image);
    
    Ok(())
}
```

## Best Practices

### 1. When to Use Classical Crypto

```rust
// Use Ed25519 for:
// - High-performance applications
// - Legacy system compatibility  
// - Short-term security needs (pre-quantum threat)
// - Development and testing

use lib_crypto::KeyPair;

fn appropriate_classical_usage() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // High-frequency trading system (performance critical)
    let trade_data = b"BUY 1000 SHARES";
    let fast_signature = keypair.sign_ed25519(trade_data)?;
    
    // API authentication (compatibility required)
    let api_request = b"GET /user/profile";
    let compat_signature = keypair.sign_ed25519(api_request)?;
    
    Ok(())
}
```

### 2. Security Guidelines

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn security_guidelines() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let sensitive_document = b"Classified document";
    
    // For sensitive, long-term data: use post-quantum
    let secure_sig = keypair.sign(sensitive_document)?;
    assert_eq!(secure_sig.algorithm, SignatureAlgorithm::Dilithium2);
    
    // For current operational needs: classical is acceptable
    let operational_data = b"Daily report";
    let operational_sig = keypair.sign_ed25519(operational_data)?;
    
    // Always verify signatures regardless of algorithm
    assert!(keypair.verify(&secure_sig, sensitive_document)?);
    assert!(keypair.verify(&operational_sig, operational_data)?);
    
    Ok(())
}
```

### 3. Performance vs Security Tradeoffs

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| Blockchain consensus | Ed25519 | High throughput needed |
| Document signing | Dilithium2 | Long-term security |
| API authentication | Ed25519 | Legacy compatibility |
| Secure messaging | Both | Hybrid approach |
| IoT devices | Ed25519 | Resource constraints |
| Government systems | Dilithium2 | Regulatory requirements |

### 4. Error Handling

```rust
use lib_crypto::classical::*;
use anyhow::{Result, Context};

fn robust_classical_operations() -> Result<()> {
    // Handle keypair generation
    let (pk, sk) = ed25519_keypair()
        .context("Failed to generate Ed25519 keypair")?;
    
    let message = b"Test message";
    
    // Handle signing
    let signature = ed25519_sign(message, &sk)
        .context("Failed to sign with Ed25519")?;
    
    // Handle verification
    match ed25519_verify(message, &signature, &pk) {
        Ok(true) => println!("Ed25519 signature verified"),
        Ok(false) => return Err(anyhow::anyhow!("Invalid Ed25519 signature")),
        Err(e) => return Err(e).context("Ed25519 verification error"),
    }
    
    Ok(())
}
```

The classical module provides essential compatibility and performance options while the ecosystem transitions to post-quantum cryptography. Use classical algorithms where appropriate, but plan for eventual migration to quantum-resistant alternatives.
