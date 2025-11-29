# Post-Quantum Module

Implementation of NIST-standardized post-quantum cryptographic algorithms: CRYSTALS-Dilithium for digital signatures and CRYSTALS-Kyber for key encapsulation mechanism (KEM).

## Overview

The post-quantum module provides:
- **CRYSTALS-Dilithium**: Quantum-resistant digital signatures
- **CRYSTALS-Kyber**: Quantum-resistant key encapsulation
- **Security Levels**: Multiple parameter sets for different security requirements
- **Standards Compliance**: NIST PQC standardized implementations

Both algorithms are designed to be secure against attacks by both classical and quantum computers.

## CRYSTALS-Dilithium (Digital Signatures)

### Algorithm Overview
- **Type**: Lattice-based digital signature scheme
- **Security**: Based on Module Learning With Errors (M-LWE) problem
- **Standardization**: NIST PQC Round 3 winner, FIPS 204 draft
- **Quantum Resistance**: Secure against Shor's algorithm

### Security Levels

```rust
use lib_crypto::post_quantum::{DilithiumLevel, dilithium_keypair};

// Level 2 (default) - equivalent to AES-128
let (pk2, sk2) = dilithium_keypair(DilithiumLevel::Level2)?;

// Level 5 - equivalent to AES-256  
let (pk5, sk5) = dilithium_keypair(DilithiumLevel::Level5)?;
```

**Parameter Comparison:**
| Level | Security | Public Key | Secret Key | Signature | Performance |
|-------|----------|------------|------------|-----------|-------------|
| 2     | AES-128  | 1,312 B    | 2,528 B    | 2,420 B   | Faster      |
| 5     | AES-256  | 2,592 B    | 4,864 B    | 4,595 B   | Slower      |

### Usage Examples

**Direct Dilithium Operations:**
```rust
use lib_crypto::post_quantum::{
    dilithium_keypair, dilithium_sign, dilithium_verify,
    DilithiumLevel
};

fn dilithium_example() -> Result<()> {
    // Generate Dilithium keypair
    let (public_key, secret_key) = dilithium_keypair(DilithiumLevel::Level2)?;
    
    let message = b"Message to sign with post-quantum cryptography";
    
    // Sign message
    let signature = dilithium_sign(message, &secret_key)?;
    
    // Verify signature
    let is_valid = dilithium_verify(message, &signature, &public_key)?;
    assert!(is_valid);
    
    println!("Dilithium signature size: {} bytes", signature.len());
    Ok(())
}
```

**Integrated with KeyPair:**
```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn keypair_dilithium() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Post-quantum secure message";
    
    // Default signature uses Dilithium2
    let signature = keypair.sign(message)?;
    assert_eq!(signature.algorithm, SignatureAlgorithm::Dilithium2);
    
    // Verify with KeyPair API
    let is_valid = keypair.verify(&signature, message)?;
    assert!(is_valid);
    
    Ok(())
}
```

### Performance Characteristics

```rust
use std::time::Instant;
use lib_crypto::post_quantum::*;

fn dilithium_benchmarks() -> Result<()> {
    let (pk, sk) = dilithium_keypair(DilithiumLevel::Level2)?;
    let message = b"Benchmark message for Dilithium";
    
    // Signing benchmark
    let start = Instant::now();
    for _ in 0..1000 {
        let _sig = dilithium_sign(message, &sk)?;
    }
    println!("1000 Dilithium signs: {:?}", start.elapsed());
    // Typical: ~1-2 seconds
    
    // Verification benchmark
    let signature = dilithium_sign(message, &sk)?;
    let start = Instant::now();
    for _ in 0..1000 {
        let _valid = dilithium_verify(message, &signature, &pk)?;
    }
    println!("1000 Dilithium verifications: {:?}", start.elapsed());
    // Typical: ~500ms-1s
    
    Ok(())
}
```

## CRYSTALS-Kyber (Key Encapsulation)

### Algorithm Overview
- **Type**: Lattice-based key encapsulation mechanism
- **Security**: Based on Module Learning With Errors (M-LWE) problem
- **Standardization**: NIST PQC Round 3 winner, FIPS 203 draft
- **Purpose**: Establish shared secrets for symmetric encryption

### Security Levels

```rust
use lib_crypto::post_quantum::{KyberLevel, kyber_keypair};

// Level 512 (default) - equivalent to AES-128
let (pk512, sk512) = kyber_keypair(KyberLevel::Kyber512)?;

// Level 768 - equivalent to AES-192
let (pk768, sk768) = kyber_keypair(KyberLevel::Kyber768)?;

// Level 1024 - equivalent to AES-256
let (pk1024, sk1024) = kyber_keypair(KyberLevel::Kyber1024)?;
```

**Parameter Comparison:**
| Level | Security | Public Key | Secret Key | Ciphertext | Performance |
|-------|----------|------------|------------|------------|-------------|
| 512   | AES-128  | 800 B      | 1,632 B    | 768 B      | Fastest     |
| 768   | AES-192  | 1,184 B    | 2,400 B    | 1,088 B    | Medium      |
| 1024  | AES-256  | 1,568 B    | 3,168 B    | 1,568 B    | Slowest     |

### Usage Examples

**Direct Kyber Operations:**
```rust
use lib_crypto::post_quantum::{
    kyber_keypair, kyber_encapsulate, kyber_decapsulate,
    KyberLevel
};

fn kyber_example() -> Result<()> {
    // Generate Kyber keypair
    let (public_key, secret_key) = kyber_keypair(KyberLevel::Kyber512)?;
    
    // Encapsulate: Generate shared secret + ciphertext
    let (shared_secret, ciphertext) = kyber_encapsulate(&public_key)?;
    
    // Decapsulate: Recover shared secret from ciphertext
    let recovered_secret = kyber_decapsulate(&ciphertext, &secret_key)?;
    
    assert_eq!(shared_secret, recovered_secret);
    
    println!("Kyber shared secret: {:?}", shared_secret);
    println!("Kyber ciphertext size: {} bytes", ciphertext.len());
    
    Ok(())
}
```

**Integrated with KeyPair:**
```rust
use lib_crypto::KeyPair;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Aead};

fn keypair_kyber() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Use KeyPair's high-level encryption (includes Kyber)
    let plaintext = b"Secret data protected by post-quantum crypto";
    let metadata = b"public associated data";
    
    let ciphertext = keypair.encrypt(plaintext, metadata)?;
    let decrypted = keypair.decrypt(&ciphertext, metadata)?;
    
    assert_eq!(plaintext, &decrypted[..]);
    
    // Or use lower-level KEM operations
    let encapsulation = keypair.encapsulate()?;
    let recovered_secret = keypair.decapsulate(&encapsulation)?;
    
    // Use shared secret for custom symmetric crypto
    let key = Key::from_slice(&recovered_secret);
    let cipher = ChaCha20Poly1305::new(key);
    
    Ok(())
}
```

### Performance Characteristics

```rust
use std::time::Instant;
use lib_crypto::post_quantum::*;

fn kyber_benchmarks() -> Result<()> {
    let (pk, sk) = kyber_keypair(KyberLevel::Kyber512)?;
    
    // Encapsulation benchmark
    let start = Instant::now();
    for _ in 0..1000 {
        let (_secret, _ciphertext) = kyber_encapsulate(&pk)?;
    }
    println!("1000 Kyber encapsulations: {:?}", start.elapsed());
    // Typical: ~300-500ms
    
    // Decapsulation benchmark
    let (_secret, ciphertext) = kyber_encapsulate(&pk)?;
    let start = Instant::now();
    for _ in 0..1000 {
        let _recovered = kyber_decapsulate(&ciphertext, &sk)?;
    }
    println!("1000 Kyber decapsulations: {:?}", start.elapsed());
    // Typical: ~200-400ms
    
    Ok(())
}
```

## Hybrid Security

### Combining Post-Quantum with Classical

```rust
use lib_crypto::{KeyPair, classical::ed25519_sign};

fn hybrid_approach() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Hybrid security message";
    
    // Post-quantum signature (primary)
    let pq_signature = keypair.sign(message)?;
    
    // Classical signature (backup/compatibility)
    let classical_signature = keypair.sign_ed25519(message)?;
    
    // Both signatures can be verified independently
    assert!(keypair.verify(&pq_signature, message)?);
    assert!(keypair.verify(&classical_signature, message)?);
    
    // In protocols, you might include both:
    // - PQ signature for quantum resistance
    // - Classical signature for current interoperability
    
    Ok(())
}
```

### Migration Strategy

```rust
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn migration_strategy() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Migration example";
    
    // Current phase: Support both algorithms
    let pq_sig = keypair.sign(message)?;          // Future-proof
    let classical_sig = keypair.sign_ed25519(message)?; // Current compatibility
    
    // Verification supports both
    match signature.algorithm {
        SignatureAlgorithm::Dilithium2 | SignatureAlgorithm::Dilithium5 => {
            // Handle post-quantum signature
            println!("Processing post-quantum signature");
        },
        SignatureAlgorithm::Ed25519 => {
            // Handle classical signature
            println!("Processing classical signature");
        },
        _ => return Err(anyhow::anyhow!("Unsupported signature algorithm")),
    }
    
    Ok(())
}
```

## Security Considerations

### Quantum Threat Timeline

```rust
// Current recommendations based on quantum threat assessment
use lib_crypto::{KeyPair, SignatureAlgorithm};

fn security_planning() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // For data that must remain secure beyond 2030
    let long_term_sig = keypair.sign(b"Long-term document")?;
    assert_eq!(long_term_sig.algorithm, SignatureAlgorithm::Dilithium2);
    
    // For current interoperability (2024-2028)
    let current_sig = keypair.sign_ed25519(b"Current document")?;
    assert_eq!(current_sig.algorithm, SignatureAlgorithm::Ed25519);
    
    // Recommendation: Start using PQ for new systems
    // Maintain classical support for legacy systems
    
    Ok(())
}
```

### Implementation Security

The post-quantum implementations include:

1. **Constant-Time Operations**: Protect against timing attacks
2. **Secure Memory Management**: Automatic zeroization of secrets
3. **Side-Channel Resistance**: Basic protections against power analysis
4. **Randomness Quality**: Uses cryptographically secure RNG

```rust
use lib_crypto::post_quantum::*;

fn security_features() -> Result<()> {
    // All operations use secure randomness
    let (pk, sk) = dilithium_keypair(DilithiumLevel::Level2)?;
    
    // Memory is automatically protected
    {
        let message = b"Sensitive message";
        let signature = dilithium_sign(message, &sk)?;
        // signature memory protected via ZeroizeOnDrop
    } // <- Memory automatically zeroed here
    
    // Implementations resist basic side-channel attacks
    let message1 = b"Message 1";
    let message2 = b"Different length message 2";
    
    // Both operations should take similar time (constant-time)
    let sig1 = dilithium_sign(message1, &sk)?;
    let sig2 = dilithium_sign(message2, &sk)?;
    
    Ok(())
}
```

## Algorithm Parameters

### Dilithium Parameters

```rust
use lib_crypto::post_quantum::DilithiumConstants;

// Internal parameters (for reference)
const DILITHIUM2_PARAMS: DilithiumConstants = DilithiumConstants {
    k: 4,           // Matrix height
    l: 4,           // Matrix width  
    eta: 2,         // Secret key coefficient range
    tau: 39,        // Number of ±1's in c
    beta: 78,       // Reject bound for signatures
    gamma1: 17,     // Challenge range
    gamma2: 88,     // Low-order rounding range
};
```

### Kyber Parameters

```rust
use lib_crypto::post_quantum::KyberConstants;

// Internal parameters (for reference)
const KYBER512_PARAMS: KyberConstants = KyberConstants {
    n: 256,         // Ring dimension
    q: 3329,        // Modulus
    k: 2,           // Module rank
    eta1: 3,        // Noise parameter
    eta2: 2,        // Noise parameter
    du: 10,         // Rounding parameter
    dv: 4,          // Rounding parameter
};
```

## Integration Examples

### With SOVEREIGN_NET Components

```rust
use lib_crypto::KeyPair;

// Example: Blockchain integration
fn blockchain_integration() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Transaction signing with post-quantum security
    let transaction_data = b"Transfer 100 tokens to address...";
    let signature = keypair.sign(transaction_data)?;
    
    // Signature can be verified by blockchain nodes
    let is_valid = keypair.verify(&signature, transaction_data)?;
    assert!(is_valid);
    
    // Key ID used for account identification
    let account_id = keypair.public_key.key_id;
    println!("Account ID: {:?}", account_id);
    
    Ok(())
}

// Example: Network protocol integration  
fn network_integration() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Establish secure channel with post-quantum KEM
    let encapsulation = keypair.encapsulate()?;
    
    // Send public ciphertext, keep shared secret
    let session_key = encapsulation.shared_secret;
    
    // Use for symmetric encryption of network traffic
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    
    Ok(())
}
```

## Best Practices

### 1. Algorithm Selection
```rust
// For new applications
use lib_crypto::{KeyPair, SignatureAlgorithm::Dilithium2};

// For maximum security
use lib_crypto::{KeyPair, SignatureAlgorithm::Dilithium5};

// For legacy compatibility
use lib_crypto::{KeyPair, SignatureAlgorithm::Ed25519};
```

### 2. Performance Optimization
- Use Kyber512 for most applications (good security/performance balance)
- Use Dilithium2 for typical signature needs
- Consider caching keypairs for batch operations
- Profile your specific use case

### 3. Security Guidelines
- Always use the latest version of the library
- Prefer post-quantum algorithms for new systems
- Maintain classical support during transition period
- Monitor NIST PQC standardization updates

### 4. Error Handling
```rust
use lib_crypto::post_quantum::*;

fn robust_pq_operations() -> Result<()> {
    // Handle key generation errors
    let (pk, sk) = dilithium_keypair(DilithiumLevel::Level2)
        .context("Failed to generate Dilithium keypair")?;
    
    let message = b"Important message";
    
    // Handle signing errors
    let signature = dilithium_sign(message, &sk)
        .context("Failed to create Dilithium signature")?;
    
    // Handle verification
    match dilithium_verify(message, &signature, &pk) {
        Ok(true) => println!("Signature verified successfully"),
        Ok(false) => return Err(anyhow::anyhow!("Invalid signature")),
        Err(e) => return Err(e).context("Signature verification failed"),
    }
    
    Ok(())
}
```

The post-quantum module provides the foundation for quantum-resistant cryptography in the SOVEREIGN_NET ecosystem, implementing standardized algorithms with production-ready security and performance characteristics.
