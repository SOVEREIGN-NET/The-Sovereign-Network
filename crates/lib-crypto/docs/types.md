# Types Module

Core cryptographic type definitions for the lib-crypto library. This module provides the fundamental data structures used throughout the SOVEREIGN_NET cryptographic ecosystem.

## Overview

The types module defines:
- **Key Types**: Public and private key representations
- **Signature Types**: Digital signature structures and algorithm identifiers
- **Hash Types**: Cryptographic hash representations
- **Encapsulation Types**: Key encapsulation mechanism results

All types are designed for:
- **Serialization**: Serde support for storage and network transmission
- **Security**: Automatic memory zeroization for sensitive data
- **Compatibility**: Cross-platform and network-safe representations
- **Performance**: Efficient memory layout and operations

## Core Types

### PublicKey

Represents a multi-algorithm public key containing post-quantum and classical keys.

```rust
use lib_crypto::types::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub dilithium_pk: Vec<u8>,    // CRYSTALS-Dilithium public key
    pub kyber_pk: Vec<u8>,        // CRYSTALS-Kyber public key  
    pub ed25519_pk: Vec<u8>,      // Ed25519 public key
    pub key_id: [u8; 32],         // Unique key identifier
}
```

**Usage:**
```rust
use lib_crypto::KeyPair;

let keypair = KeyPair::generate()?;
let public_key = &keypair.public_key;

// Access different key components
println!("Key ID: {:?}", public_key.key_id);
println!("Dilithium key length: {}", public_key.dilithium_pk.len());
println!("Kyber key length: {}", public_key.kyber_pk.len());
println!("Ed25519 key length: {}", public_key.ed25519_pk.len());

// Serialize for storage or transmission
let serialized = serde_json::to_string(public_key)?;
```

**Key Features:**
- Multi-algorithm support for hybrid security
- Unique key ID derived from all component keys
- Serde serialization support
- Zero-copy operations where possible

### PrivateKey

Represents the corresponding private key material with automatic memory protection.

```rust
use lib_crypto::types::PrivateKey;

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    pub dilithium_sk: Vec<u8>,    // CRYSTALS-Dilithium secret key
    pub kyber_sk: Vec<u8>,        // CRYSTALS-Kyber secret key
    pub ed25519_sk: Vec<u8>,      // Ed25519 secret key
    pub master_seed: Vec<u8>,     // Master seed for key derivation
}
```

**Security Features:**
- Automatic memory zeroization on drop via `ZeroizeOnDrop`
- Secure random generation of all key material
- Protected master seed for key derivation
- No accidental cloning (must be explicit)

**Usage:**
```rust
use lib_crypto::KeyPair;

let keypair = KeyPair::generate()?;

// Private key is automatically protected
// Memory is zeroed when keypair goes out of scope

// For key derivation or backup (use carefully!)
let master_seed = &keypair.private_key.master_seed;
```

### Signature

Digital signature structure supporting multiple algorithms.

```rust
use lib_crypto::types::{Signature, SignatureAlgorithm};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub signature: Vec<u8>,           // Signature bytes
    pub public_key: PublicKey,        // Signer's public key
    pub algorithm: SignatureAlgorithm, // Algorithm used
    pub timestamp: u64,               // Creation timestamp
}
```

**Supported Algorithms:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Dilithium2,      // CRYSTALS-Dilithium Level 2 (post-quantum)
    Dilithium5,      // CRYSTALS-Dilithium Level 5 (highest security)
    Ed25519,         // Ed25519 (classical, for compatibility)
    RingSignature,   // Ring signature (anonymous)
}
```

**Usage Examples:**

**Basic Signing:**
```rust
use lib_crypto::KeyPair;

let keypair = KeyPair::generate()?;
let message = b"Document to sign";

// Sign with default algorithm (Dilithium2)
let signature = keypair.sign(message)?;
assert_eq!(signature.algorithm, SignatureAlgorithm::Dilithium2);

// Sign with specific algorithm
let ed25519_sig = keypair.sign_ed25519(message)?;
assert_eq!(ed25519_sig.algorithm, SignatureAlgorithm::Ed25519);
```

**Signature Verification:**
```rust
// Verify signature
let is_valid = keypair.verify(&signature, message)?;
assert!(is_valid);

// Check signature metadata
println!("Signed at timestamp: {}", signature.timestamp);
println!("Algorithm used: {:?}", signature.algorithm);
println!("Signer key ID: {:?}", signature.public_key.key_id);
```

### Hash

Cryptographic hash representation supporting multiple algorithms.

```rust
use lib_crypto::types::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash {
    pub hash: Vec<u8>,           // Hash bytes
    pub algorithm: HashAlgorithm, // Algorithm used
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Blake3,     // BLAKE3 (recommended)
    Sha3_256,   // SHA-3 256-bit
    Sha3_512,   // SHA-3 512-bit
}
```

**Usage:**
```rust
use lib_crypto::hashing::{hash_blake3, hash_sha3_256};
use lib_crypto::types::{Hash, HashAlgorithm};

let data = b"Data to hash";

// Create hash objects
let blake3_hash = Hash {
    hash: hash_blake3(data).to_vec(),
    algorithm: HashAlgorithm::Blake3,
};

let sha3_hash = Hash {
    hash: hash_sha3_256(data).to_vec(),
    algorithm: HashAlgorithm::Sha3_256,
};

// Compare hashes
assert_ne!(blake3_hash, sha3_hash); // Different algorithms
```

### Encapsulation

Key Encapsulation Mechanism (KEM) result for post-quantum encryption.

```rust
use lib_crypto::types::Encapsulation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,      // KEM ciphertext
    pub shared_secret: [u8; 32],  // Derived shared secret
    pub kdf_info: Vec<u8>,        // Key derivation info
}
```

**Usage:**
```rust
use lib_crypto::KeyPair;

let keypair = KeyPair::generate()?;

// Encapsulate a shared secret
let encapsulation = keypair.encapsulate()?;

// The encapsulation contains:
// - ciphertext: Can be sent over public channel
// - shared_secret: Used for symmetric encryption (keep secret!)
// - kdf_info: Parameters used for key derivation

// Decapsulate on the other side
let recovered_secret = keypair.decapsulate(&encapsulation)?;
assert_eq!(encapsulation.shared_secret, recovered_secret);
```

## Type Aliases

For convenience and compatibility:

```rust
// Backwards compatibility
pub type PostQuantumSignature = Signature;

// Common usage patterns
type KeyId = [u8; 32];
type SharedSecret = [u8; 32];
```

## Serialization

All types support Serde serialization:

### JSON Serialization
```rust
use serde_json;
use lib_crypto::KeyPair;

let keypair = KeyPair::generate()?;

// Serialize public key to JSON
let json = serde_json::to_string(&keypair.public_key)?;
let restored: PublicKey = serde_json::from_str(&json)?;

// Serialize signature
let message = b"Test message";
let signature = keypair.sign(message)?;
let sig_json = serde_json::to_string(&signature)?;
```

### Binary Serialization
```rust
use bincode;

// More efficient for storage/transmission
let binary = bincode::serialize(&keypair.public_key)?;
let restored: PublicKey = bincode::deserialize(&binary)?;
```

## Memory Management

### Automatic Zeroization

Sensitive types implement `ZeroizeOnDrop`:

```rust
use lib_crypto::{KeyPair, PrivateKey};

{
    let keypair = KeyPair::generate()?;
    // Private key material is in memory
} // <- Private key memory is automatically zeroed here
```

### Manual Zeroization

For explicit control:

```rust
use zeroize::Zeroize;

let mut sensitive_data = vec![1, 2, 3, 4];
// Use sensitive_data...
sensitive_data.zeroize(); // Explicitly zero the memory
```

## Error Handling

Types integrate with the library's error handling:

```rust
use lib_crypto::{KeyPair, CryptoError};
use anyhow::Result;

fn type_operations() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Operations return Results for error handling
    let signature = keypair.sign(b"message")?;
    let is_valid = keypair.verify(&signature, b"message")?;
    
    if !is_valid {
        anyhow::bail!("Signature verification failed");
    }
    
    Ok(())
}
```

## Performance Considerations

### Memory Layout
- Types are optimized for minimal memory overhead
- Vec<u8> used for variable-length cryptographic material
- Fixed-size arrays for keys and hashes where appropriate

### Cloning Costs
- Public keys: Relatively cheap to clone
- Private keys: More expensive due to larger key material
- Signatures: Moderate cost, includes public key

### Serialization Performance
- Binary formats (bincode) preferred for performance
- JSON suitable for debugging and APIs
- Consider compression for large key sets

## Integration Notes

### With Other SOVEREIGN_NET Components
- All types implement required traits for ecosystem integration
- Key IDs provide consistent identification across components
- Serialization formats are compatible across the ecosystem

### Thread Safety
- All types are `Send + Sync` where appropriate
- No internal mutability in core types
- Safe to share across threads

### Backwards Compatibility
- Type aliases maintain API compatibility
- Serialization format versioning for upgrades
- Migration helpers for type evolution

## Best Practices

1. **Key ID Usage**: Always use key IDs for key identification, not hash of public key
2. **Algorithm Selection**: Prefer post-quantum algorithms for new applications
3. **Serialization**: Use binary formats for production, JSON for debugging
4. **Memory**: Let automatic zeroization handle sensitive data cleanup
5. **Verification**: Always check signature verification results
6. **Timestamps**: Use signature timestamps for replay protection
