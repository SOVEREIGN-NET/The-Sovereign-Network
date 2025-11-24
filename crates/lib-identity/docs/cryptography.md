# Cryptography Module

Post-quantum cryptographic operations and key management for ZHTP identity system.

## Overview

The cryptography module provides quantum-resistant cryptographic operations, leveraging implementations from lib-crypto. All operations use NIST-standardized post-quantum algorithms for long-term security.

## Integration with lib-crypto

This module integrates with lib-crypto to provide:
- **CRYSTALS-Dilithium** signatures (not stubs)
- **CRYSTALS-Kyber** key encapsulation
- **Quantum-resistant key generation**
- **Secure memory management**

## Key Generation

### PostQuantumKeypair

```rust
pub struct PostQuantumKeypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub algorithm: String,
    pub security_level: u32,
    pub key_id: String,
}
```

### Generating Keys

```rust
use lib_identity::cryptography::{generate_pq_keypair, KeyGenParams};

// Basic key generation (uses default Dilithium hybrid)
let keypair = generate_pq_keypair(None)?;

// Advanced key generation with specific security level
let params = KeyGenParams {
    algorithm: "CRYSTALS-Dilithium".to_string(),
    security_level: 5, // Highest security (Dilithium5)
    seed: None,        // Use secure random seed
    key_derivation: None,
};

let keypair = generate_pq_keypair(Some(params))?;
```

### Security Levels

- **Level 2**: CRYSTALS-Dilithium2 (NIST Level I security)
- **Level 5**: CRYSTALS-Dilithium5 (NIST Level V security - highest)
- **Hybrid**: Full lib-crypto keypair (Dilithium + Kyber + Ed25519)

### Key Validation

```rust
use lib_identity::cryptography::validate_keypair;

// Validate keypair using cryptographic operations
let is_valid = validate_keypair(&keypair)?;

if is_valid {
    println!("Keypair is cryptographically valid");
} else {
    println!("Keypair validation failed");
}
```

## Digital Signatures

### PostQuantumSignature

```rust
pub struct PostQuantumSignature {
    pub signature: Vec<u8>,
    pub algorithm: String,
    pub security_level: u32,
    pub signature_type: String,
    pub timestamp: u64,
}
```

### Signing Operations

```rust
use lib_identity::cryptography::{sign_with_identity, SignatureParams};

let message = b"Important identity transaction";

// Basic signing
let signature = sign_with_identity(&keypair, message, None)?;

// Advanced signing with context
let params = SignatureParams {
    context: Some("ZHTP-Identity-Verification".to_string()),
    domain_separation: Some("CitizenshipProof".to_string()),
    randomization: true,
};

let signature = sign_with_identity(&keypair, message, Some(params))?;
```

### Signature Verification

```rust
use lib_identity::cryptography::verify_signature;

// Verify signature using lib-crypto operations
let is_valid = verify_signature(
    &keypair.public_key,
    message,
    &signature,
    Some(params)
)?;

if is_valid {
    println!("Signature is cryptographically valid");
} else {
    println!("Signature verification failed");
}
```

## Key Derivation

### Hierarchical Deterministic Keys

```rust
use lib_identity::cryptography::derive_child_key;

// Derive child key for specific purpose
let child_keypair = derive_child_key(
    &master_keypair,
    "m/identity/credentials/0"
)?;

// Derive key for specific credential type
let credential_keypair = derive_child_key(
    &master_keypair,
    &format!("m/identity/credential/{}", credential_type)
)?;
```

### Key Derivation Paths

Standard derivation paths for ZHTP identity:
- `m/identity/master` - Master identity key
- `m/identity/credentials/{type}` - Credential-specific keys
- `m/identity/recovery/{method}` - Recovery-specific keys
- `m/identity/wallet/{id}` - Wallet integration keys

## Cryptographic Algorithms

### CRYSTALS-Dilithium (Signatures)

**Dilithium2** (Security Level 2):
- Public key: 1312 bytes
- Private key: 2528 bytes  
- Signature: 2420 bytes
- Security: NIST Level I

**Dilithium5** (Security Level 5):
- Public key: 2592 bytes
- Private key: 4864 bytes
- Signature: 4595 bytes  
- Security: NIST Level V (highest)

### CRYSTALS-Kyber (Key Encapsulation)

Used in hybrid mode for complete post-quantum security:
- **Kyber512**: 128-bit security level
- **Key encapsulation**: Secure key exchange
- **Integration**: Automatic in lib-crypto KeyPair

### Classical Compatibility

Hybrid approach includes Ed25519 for current compatibility:
- **Ed25519 signatures**: Classical elliptic curve
- **Backward compatibility**: Works with existing systems
- **Future migration**: Smooth transition to post-quantum only

## Security Features

### Memory Protection

```rust
use zeroize::Zeroize;

// All sensitive data automatically zeroized
impl Drop for PostQuantumKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
        // Other sensitive fields zeroized automatically
    }
}
```

### Side-Channel Protection

- **Constant-time operations**: Prevents timing attacks
- **Secure random generation**: Cryptographically secure entropy
- **Memory protection**: Automatic cleanup of sensitive data

### Validation and Integrity

```rust
use lib_identity::cryptography::validate_keypair;

// Comprehensive validation including:
// - Key format validation
// - Cryptographic consistency check  
// - Test signature/verification cycle
let validation_result = validate_keypair(&keypair)?;
```

## Cryptography Integration

### lib-crypto Integration

All operations use lib-crypto implementations:

```rust
// This uses CRYSTALS-Dilithium from lib-crypto
use lib_crypto::post_quantum::{dilithium2_sign, dilithium2_verify};

let signature = dilithium2_sign(message, &keypair.private_key)?;
let is_valid = dilithium2_verify(message, &signature, &keypair.public_key)?;
```

### No More Stubs

Previous stub implementations replaced with:
- NIST-standardized algorithms
- Production-ready cryptographic libraries
- Proper security guarantees
- Full test coverage

## Usage Examples

### Identity Key Setup

```rust
use lib_identity::cryptography::*;

// Generate master identity keypair
let master_keypair = generate_pq_keypair(Some(KeyGenParams {
    algorithm: "CRYSTALS-Dilithium-Hybrid".to_string(),
    security_level: 5,
    seed: None,
    key_derivation: None,
}))?;

// Derive credential signing key
let credential_key = derive_child_key(
    &master_keypair,
    "m/identity/credentials/age_verification"
)?;

// Sign identity document
let identity_doc = b"ZHTP Identity Document v1.0";
let signature = sign_with_identity(&master_keypair, identity_doc, None)?;

// Verify signature
let is_valid = verify_signature(
    &master_keypair.public_key,
    identity_doc,
    &signature,
    None
)?;

assert!(is_valid);
```

### Credential Cryptography

```rust
use lib_identity::cryptography::*;

// Generate credential-specific keypair
let credential_keypair = generate_pq_keypair(Some(KeyGenParams {
    algorithm: "CRYSTALS-Dilithium5".to_string(),
    security_level: 5,
    seed: None,
    key_derivation: Some("credential_signing".to_string()),
}))?;

// Sign credential with domain separation
let credential_data = b"Age verification: over 18";
let signature = sign_with_identity(
    &credential_keypair,
    credential_data,
    Some(SignatureParams {
        context: Some("ZHTP-Credential".to_string()),
        domain_separation: Some("AgeVerification".to_string()),
        randomization: true,
    })
)?;

// Validate credential signature
let validation = verify_signature(
    &credential_keypair.public_key,
    credential_data,
    &signature,
    Some(SignatureParams {
        context: Some("ZHTP-Credential".to_string()),
        domain_separation: Some("AgeVerification".to_string()),
        randomization: true,
    })
)?;

assert!(validation);
```

## Error Handling

### Cryptographic Errors

```rust
pub enum CryptographicError {
    KeyGenerationFailed(String),
    SigningFailed(String),
    VerificationFailed(String),
    InvalidKeyFormat,
    UnsupportedAlgorithm,
    LibCryptoError(lib_crypto::Error),
}
```

### Error Recovery

```rust
use lib_identity::cryptography::{generate_pq_keypair, CryptographicError};

match generate_pq_keypair(params) {
    Ok(keypair) => {
        // Use keypair
    },
    Err(CryptographicError::KeyGenerationFailed(msg)) => {
        // Retry with different parameters
        let fallback_keypair = generate_pq_keypair(fallback_params)?;
    },
    Err(CryptographicError::LibCryptoError(e)) => {
        // Handle underlying lib-crypto error
        eprintln!("lib-crypto error: {}", e);
    },
    Err(e) => {
        // Handle other errors
        eprintln!("Cryptographic error: {:?}", e);
    }
}
```

## Performance Considerations

### Algorithm Performance

**CRYSTALS-Dilithium2**:
- Key generation: ~0.1ms
- Signing: ~0.2ms  
- Verification: ~0.1ms

**CRYSTALS-Dilithium5**:
- Key generation: ~0.2ms
- Signing: ~0.4ms
- Verification: ~0.2ms

### Optimization Tips

- Use Dilithium2 for high-throughput applications
- Use Dilithium5 for maximum security requirements
- Cache public keys for repeated verification
- Use batch operations when possible

## Testing

### Cryptographic Test Vectors

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium2_operations() {
        let keypair = generate_pq_keypair(Some(KeyGenParams {
            security_level: 2,
            ..Default::default()
        })).unwrap();

        let message = b"test message";
        let signature = sign_with_identity(&keypair, message, None).unwrap();
        let is_valid = verify_signature(
            &keypair.public_key,
            message,
            &signature,
            None
        ).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_key_derivation() {
        let master = generate_pq_keypair(None).unwrap();
        let child = derive_child_key(&master, "m/test/path").unwrap();
        
        // Child key should be different from master
        assert_ne!(master.public_key, child.public_key);
        assert_ne!(master.private_key, child.private_key);
    }
}
```
