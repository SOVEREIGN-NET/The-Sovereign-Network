# KeyPair Module

The KeyPair module is the primary interface for cryptographic operations in lib-crypto. It provides a unified API for key generation, digital signatures, encryption/decryption, and zero-knowledge proof generation.

## Overview

The KeyPair module consists of:
- **Generation**: Secure key pair creation with post-quantum algorithms
- **Operations**: Signing, verification, encryption, decryption
- **Derivation**: Key derivation from master seeds
- **Integration**: Zero-knowledge proof interfaces

## Core Structure

### KeyPair

The main structure combining post-quantum and classical cryptographic keys:

```rust
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}
```

**Key Components:**
- **CRYSTALS-Dilithium**: Post-quantum digital signatures
- **CRYSTALS-Kyber**: Post-quantum key encapsulation  
- **Ed25519**: Classical signatures for compatibility
- **Master Seed**: For key derivation and backup

## Key Generation

### Basic Generation

Generate a new quantum-resistant key pair:

```rust
use lib_crypto::KeyPair;
use anyhow::Result;

fn generate_keypair() -> Result<()> {
    // Generate new keypair with cryptographically secure randomness
    let keypair = KeyPair::generate()?;
    
    // Keypair automatically contains:
    // - CRYSTALS-Dilithium keys (post-quantum signatures)
    // - CRYSTALS-Kyber keys (post-quantum encryption)
    // - Ed25519 keys (classical compatibility)
    // - Unique key ID derived from all public keys
    
    println!("Generated key ID: {:?}", keypair.public_key.key_id);
    Ok(())
}
```

### Key Validation

All generated keypairs are automatically validated:

```rust
use lib_crypto::KeyPair;

fn validated_generation() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Internal validation checks:
    // No weak keys (all-zero private keys)
    // Cryptographic consistency between public/private keys
    // Test signature/verification roundtrip
    
    // Manual validation (already done internally)
    keypair.validate()?;
    
    Ok(())
}
```

### Performance Characteristics

```rust
use std::time::Instant;
use lib_crypto::KeyPair;

fn benchmark_generation() -> Result<()> {
    let start = Instant::now();
    
    for _ in 0..10 {
        let _keypair = KeyPair::generate()?;
    }
    
    let elapsed = start.elapsed();
    println!("10 keypair generations: {:?}", elapsed);
    // Typical: ~50-100ms for 10 keypairs
    
    Ok(())
}
```

## Digital Signatures

### Post-Quantum Signatures (Default)

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn post_quantum_signing() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Important document to sign";
    
    // Default: CRYSTALS-Dilithium Level 2
    let signature = keypair.sign(message)?;
    assert_eq!(signature.algorithm, SignatureAlgorithm::Dilithium2);
    
    // Verify signature
    let is_valid = keypair.verify(&signature, message)?;
    assert!(is_valid);
    
    // Signature includes metadata
    println!("Signature algorithm: {:?}", signature.algorithm);
    println!("Signature timestamp: {}", signature.timestamp);
    println!("Signature size: {} bytes", signature.signature.len());
    
    Ok(())
}
```

### Classical Signatures (Compatibility)

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn classical_signing() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Legacy system compatibility";
    
    // Ed25519 for compatibility with classical systems
    let signature = keypair.sign_ed25519(message)?;
    assert_eq!(signature.algorithm, SignatureAlgorithm::Ed25519);
    
    // Verify with same keypair
    let is_valid = keypair.verify(&signature, message)?;
    assert!(is_valid);
    
    // Ed25519 signatures are smaller and faster
    println!("Ed25519 signature size: {} bytes", signature.signature.len());
    
    Ok(())
}
```

### Batch Signing

```rust
use lib_crypto::KeyPair;

fn batch_signing() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let messages = vec![
        b"Document 1".as_slice(),
        b"Document 2".as_slice(), 
        b"Document 3".as_slice(),
    ];
    
    // Sign multiple messages efficiently
    let mut signatures = Vec::new();
    for message in &messages {
        signatures.push(keypair.sign(message)?);
    }
    
    // Verify all signatures
    for (signature, message) in signatures.iter().zip(messages.iter()) {
        assert!(keypair.verify(signature, message)?);
    }
    
    println!("Signed and verified {} messages", messages.len());
    Ok(())
}
```

## Encryption and Decryption

### Hybrid Post-Quantum Encryption

Combines CRYSTALS-Kyber (post-quantum) with ChaCha20-Poly1305 (symmetric):

```rust
use lib_crypto::KeyPair;

fn hybrid_encryption() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let plaintext = b"This is secret data that needs protection";
    let associated_data = b"public metadata, version info, etc.";
    
    // Encrypt: CRYSTALS-Kyber + ChaCha20-Poly1305
    let ciphertext = keypair.encrypt(plaintext, associated_data)?;
    
    // Ciphertext structure:
    // [Kyber Ciphertext][Nonce][ChaCha20-Poly1305 Ciphertext]
    println!("Ciphertext size: {} bytes", ciphertext.len());
    
    // Decrypt
    let decrypted = keypair.decrypt(&ciphertext, associated_data)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    // Associated data must match for successful decryption
    let wrong_ad = b"different metadata";
    assert!(keypair.decrypt(&ciphertext, wrong_ad).is_err());
    
    Ok(())
}
```

### Key Encapsulation Mechanism (KEM)

Lower-level access to the KEM for custom protocols:

```rust
use lib_crypto::KeyPair;

fn kem_operations() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Encapsulate: Generate shared secret + ciphertext
    let encapsulation = keypair.encapsulate()?;
    
    println!("KEM ciphertext size: {} bytes", encapsulation.ciphertext.len());
    println!("Shared secret: {:?}", encapsulation.shared_secret);
    
    // Decapsulate: Recover shared secret from ciphertext
    let recovered_secret = keypair.decapsulate(&encapsulation)?;
    assert_eq!(encapsulation.shared_secret, recovered_secret);
    
    // Use shared secret for custom symmetric encryption
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&recovered_secret));
    
    Ok(())
}
```

## Zero-Knowledge Proof Integration

### Identity Proofs

Prove identity properties without revealing personal information:

```rust
use lib_crypto::KeyPair;

fn identity_proofs() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Prove: "I am over 18 and from jurisdiction 840 (USA)"
    // Without revealing exact age or specific identity
    let proof = keypair.prove_identity(
        25,    // actual age (private)
        840,   // jurisdiction hash (public)
        12345, // credential hash (private)
        18,    // minimum age requirement (public)
        840,   // required jurisdiction (public)
    )?;
    
    // The proof confirms the claim without revealing:
    // - Exact age (only that it's ≥ 18)
    // - Specific identity credentials
    // - Other personal information
    
    println!("Identity proof generated successfully");
    Ok(())
}
```

### Range Proofs

Prove a value is within a range without revealing the value:

```rust
use lib_crypto::KeyPair;

fn range_proofs() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Prove: "My account balance is between $1000 and $50000"
    // Without revealing the exact balance
    let balance = 25000; // Actual balance (private)
    
    let proof = keypair.prove_range(
        balance, // secret value
        1000,    // minimum (public)
        50000,   // maximum (public)  
    )?;
    
    // Verifier can confirm the balance is in range
    // without learning the exact amount
    
    println!("Range proof generated for value in [1000, 50000]");
    Ok(())
}
```

### Storage Access Proofs

Prove authorization to access data without revealing credentials:

```rust
use lib_crypto::KeyPair;

fn storage_access_proofs() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Prove: "I have permission to access this data"
    // Without revealing identity or specific permissions
    let proof = keypair.prove_storage_access(
        0x1234567890abcdef, // data hash (public)
        5,                   // my permission level (private)
        3,                   // required permission level (public)
    )?;
    
    // The proof confirms access rights without revealing:
    // - Identity of requester
    // - Specific permission level (only that it's sufficient)
    // - Other access credentials
    
    println!("Storage access proof generated");
    Ok(())
}
```

## Advanced Key Operations

### Key Derivation

Derive additional keys from the master seed:

```rust
use lib_crypto::keypair::KeyPair;

fn key_derivation() -> Result<()> {
    let master_keypair = KeyPair::generate()?;
    
    // Derive child keys for different purposes
    let signing_key = KeyPair::derive_from_seed(
        &master_keypair.private_key.master_seed,
        b"signing-key-v1",
        0, // index
    )?;
    
    let encryption_key = KeyPair::derive_from_seed(
        &master_keypair.private_key.master_seed,
        b"encryption-key-v1", 
        1, // index
    )?;
    
    // Derived keys are cryptographically independent
    assert_ne!(signing_key.public_key.key_id, encryption_key.public_key.key_id);
    
    // But deterministically derivable from the same seed
    let signing_key2 = KeyPair::derive_from_seed(
        &master_keypair.private_key.master_seed,
        b"signing-key-v1",
        0,
    )?;
    assert_eq!(signing_key.public_key.key_id, signing_key2.public_key.key_id);
    
    Ok(())
}
```

### Key Serialization and Storage

```rust
use lib_crypto::KeyPair;
use serde_json;

fn key_storage() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Serialize public key (safe to store/transmit)
    let public_json = serde_json::to_string(&keypair.public_key)?;
    
    // NEVER serialize private keys to persistent storage in plaintext!
    // This is just for demonstration
    let private_json = serde_json::to_string(&keypair.private_key)?;
    
    // Restore from JSON
    let restored_public: PublicKey = serde_json::from_str(&public_json)?;
    
    // In production, encrypt private keys before storage
    // Or use hardware security modules (HSMs)
    
    println!("Public key restored successfully");
    Ok(())
}
```

## Error Handling

### Common Errors

```rust
use lib_crypto::{KeyPair, CryptoError};
use anyhow::{Result, Context};

fn error_handling_examples() -> Result<()> {
    // Key generation errors (rare, usually system-level issues)
    let keypair = KeyPair::generate()
        .context("Failed to generate keypair - check system entropy")?;
    
    let message = b"Test message";
    
    // Signing errors (very rare with valid keypairs)
    let signature = keypair.sign(message)
        .context("Failed to sign message")?;
    
    // Verification errors (returns false for invalid, error for system issues)
    match keypair.verify(&signature, message) {
        Ok(true) => println!("Signature valid"),
        Ok(false) => println!("Signature invalid"),
        Err(e) => return Err(e).context("Verification system error"),
    }
    
    // Encryption errors
    let plaintext = b"data";
    let ciphertext = keypair.encrypt(plaintext, b"metadata")
        .context("Encryption failed")?;
    
    // Decryption errors (common with wrong keys/data)
    match keypair.decrypt(&ciphertext, b"wrong_metadata") {
        Ok(decrypted) => println!("Decrypted: {:?}", decrypted),
        Err(e) => println!("Decryption failed (expected): {}", e),
    }
    
    Ok(())
}
```

## Performance Optimization

### Benchmarking Operations

```rust
use std::time::Instant;
use lib_crypto::KeyPair;

fn performance_benchmarks() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Benchmark message";
    let plaintext = b"Benchmark encryption data";
    
    // Signature performance
    let start = Instant::now();
    for _ in 0..1000 {
        let _sig = keypair.sign(message)?;
    }
    println!("1000 signatures: {:?}", start.elapsed());
    
    // Verification performance
    let signature = keypair.sign(message)?;
    let start = Instant::now();
    for _ in 0..1000 {
        let _valid = keypair.verify(&signature, message)?;
    }
    println!("1000 verifications: {:?}", start.elapsed());
    
    // Encryption performance
    let start = Instant::now();
    for _ in 0..100 {
        let _ct = keypair.encrypt(plaintext, b"metadata")?;
    }
    println!("100 encryptions: {:?}", start.elapsed());
    
    // KEM performance (faster than full encryption)
    let start = Instant::now();
    for _ in 0..1000 {
        let _encap = keypair.encapsulate()?;
    }
    println!("1000 KEM operations: {:?}", start.elapsed());
    
    Ok(())
}
```

### Memory Usage Optimization

```rust
use lib_crypto::KeyPair;

fn memory_optimization() -> Result<()> {
    // Reuse keypairs instead of regenerating
    let keypair = KeyPair::generate()?;
    
    // Process multiple operations with same keypair
    let messages = vec![b"msg1", b"msg2", b"msg3"];
    for msg in messages {
        let _signature = keypair.sign(msg)?;
        // Much faster than generating new keypairs each time
    }
    
    // For batch operations, consider parallel processing
    use rayon::prelude::*;
    
    let large_message_set: Vec<&[u8]> = (0..1000)
        .map(|_| b"message".as_slice())
        .collect();
    
    let signatures: Vec<_> = large_message_set
        .par_iter()
        .map(|msg| keypair.sign(msg))
        .collect::<Result<Vec<_>, _>>()?;
    
    println!("Processed {} signatures in parallel", signatures.len());
    
    Ok(())
}
```

## Security Considerations

### Key Lifecycle Management

```rust
use lib_crypto::KeyPair;

fn secure_key_lifecycle() -> Result<()> {
    // 1. Secure Generation
    let keypair = KeyPair::generate()?; // Uses cryptographically secure RNG
    
    // 2. Validation
    keypair.validate()?; // Automatic validation
    
    // 3. Usage
    let message = b"Important message";
    let signature = keypair.sign(message)?;
    
    // 4. Storage (if needed)
    // Never store private keys in plaintext!
    // Use encryption, HSMs, or secure key management systems
    
    // 5. Memory Management
    // Private key memory is automatically zeroed when keypair is dropped
    drop(keypair); // Explicit drop for demonstration
    
    Ok(())
}
```

### Side-Channel Protection

The implementation includes basic side-channel protections:

- **Constant-time operations** for critical cryptographic functions
- **Secure memory management** with automatic zeroization
- **No secret-dependent branching** in key operations
- **Protected against timing attacks** in verification

### Algorithm Security Levels

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn security_levels() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Security level demonstration";
    
    // NIST Security Level 1 (equivalent to AES-128)
    let dilithium2_sig = keypair.sign(message)?; // Dilithium2
    
    // Classical security (vulnerable to quantum attacks)
    let ed25519_sig = keypair.sign_ed25519(message)?; // Ed25519
    
    // Choose based on threat model:
    // - Dilithium2: Post-quantum security, larger signatures
    // - Ed25519: Classical security, smaller signatures, faster
    
    println!("Dilithium2 signature size: {} bytes", dilithium2_sig.signature.len());
    println!("Ed25519 signature size: {} bytes", ed25519_sig.signature.len());
    
    Ok(())
}
```

## Best Practices

### 1. Key Generation
- Always generate keys with `KeyPair::generate()`
- Never use weak randomness or predictable seeds
- Validate keypairs in critical applications

### 2. Algorithm Selection
```rust
// For new applications (quantum-resistant)
let signature = keypair.sign(message)?; // Dilithium2

// For legacy compatibility
let signature = keypair.sign_ed25519(message)?; // Ed25519

// For anonymity
use lib_crypto::advanced::RingContext;
let ring_sig = ring_context.sign()?; // Ring signature
```

### 3. Error Handling
```rust
// Always handle errors appropriately
match keypair.verify(&signature, message) {
    Ok(true) => { /* Valid signature */ },
    Ok(false) => { /* Invalid signature - reject */ },
    Err(e) => { /* System error - log and handle */ },
}
```

### 4. Performance
- Reuse keypairs for multiple operations
- Use Ed25519 for high-throughput applications
- Consider parallel processing for batch operations
- Profile your specific use case

### 5. Security
- Never store private keys in plaintext
- Use appropriate algorithm for threat model
- Keep library updated for security patches
- Consider hardware security modules for high-value keys
