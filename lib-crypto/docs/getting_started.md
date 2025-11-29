# Getting Started with lib-crypto

This guide will help you get up and running with the SOVEREIGN_NET post-quantum cryptography library.

## Installation

Add lib-crypto to your `Cargo.toml`:

```toml
[dependencies]
lib-crypto = { path = "../lib-crypto" }
```

For development and testing:
```toml
[dev-dependencies]
lib-crypto = { path = "../lib-crypto", features = ["dev"] }
```

## Basic Usage

### 1. Key Generation

Generate a quantum-resistant keypair:

```rust
use lib_crypto::KeyPair;
use anyhow::Result;

fn main() -> Result<()> {
    // Generate a new post-quantum keypair
    let keypair = KeyPair::generate()?;
    
    // The keypair contains:
    // - CRYSTALS-Dilithium keys for signatures
    // - CRYSTALS-Kyber keys for encryption
    // - Ed25519 keys for classical compatibility
    
    println!("Generated keypair with ID: {:?}", keypair.public_key.key_id);
    Ok(())
}
```

### 2. Digital Signatures

Sign and verify messages:

```rust
use lib_crypto::KeyPair;

fn example_signing() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Hello, post-quantum world!";
    
    // Sign with CRYSTALS-Dilithium (default)
    let signature = keypair.sign(message)?;
    
    // Verify the signature
    let is_valid = keypair.verify(&signature, message)?;
    assert!(is_valid);
    
    // Sign with Ed25519 for compatibility
    let ed25519_sig = keypair.sign_ed25519(message)?;
    let is_valid = keypair.verify(&ed25519_sig, message)?;
    assert!(is_valid);
    
    Ok(())
}
```

### 3. Encryption

Encrypt and decrypt data using hybrid post-quantum cryptography:

```rust
use lib_crypto::KeyPair;

fn example_encryption() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let plaintext = b"This is secret data";
    let associated_data = b"public metadata";
    
    // Encrypt using CRYSTALS-Kyber + ChaCha20-Poly1305
    let ciphertext = keypair.encrypt(plaintext, associated_data)?;
    
    // Decrypt
    let decrypted = keypair.decrypt(&ciphertext, associated_data)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}
```

### 4. Cryptographic Hashing

Use secure hash functions:

```rust
use lib_crypto::hashing::{hash_blake3, hash_sha3_256};

fn example_hashing() {
    let data = b"Data to hash";
    
    // BLAKE3 (recommended for performance)
    let blake3_hash = hash_blake3(data);
    
    // SHA-3 (for compatibility/standards compliance)
    let sha3_hash = hash_sha3_256(data);
    
    println!("BLAKE3: {:?}", blake3_hash);
    println!("SHA-3: {:?}", sha3_hash);
}
```

## Advanced Features

### Ring Signatures (Anonymous Signing)

```rust
use lib_crypto::advanced::RingContext;

fn example_ring_signature() -> Result<()> {
    // Generate multiple keypairs for the ring
    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;
    
    let ring = vec![
        keypair1.public_key.clone(),
        keypair2.public_key.clone(),
        keypair3.public_key.clone(),
    ];
    
    let message = b"Anonymous message";
    
    // Create ring context and sign with keypair2 (index 1)
    let mut context = RingContext::new(ring.clone(), message.to_vec());
    context.set_signer(1, keypair2.private_key.clone())?;
    
    let ring_signature = context.sign()?;
    
    // Verify (observer cannot determine which key signed)
    let is_valid = lib_crypto::advanced::verify_ring_signature(
        &ring_signature, 
        message, 
        &ring
    )?;
    assert!(is_valid);
    
    Ok(())
}
```

### Multi-Signatures (Shared Control)

```rust
use lib_crypto::advanced::MultiSig;

fn example_multisig() -> Result<()> {
    // Create 3 keypairs, require 2 signatures (2-of-3)
    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;
    
    let public_keys = vec![
        keypair1.public_key.clone(),
        keypair2.public_key.clone(),
        keypair3.public_key.clone(),
    ];
    
    let message = b"Multi-signature message";
    
    // Create multi-signature context
    let multisig = MultiSig::new(public_keys.clone(), 2)?; // 2-of-3 threshold
    
    // Sign with first two keys
    let sig1 = keypair1.sign(message)?;
    let sig2 = keypair2.sign(message)?;
    
    let signatures = vec![sig1, sig2];
    
    // Verify multi-signature
    let is_valid = multisig.verify(message, &signatures)?;
    assert!(is_valid);
    
    Ok(())
}
```

## Error Handling

lib-crypto uses `anyhow::Result` for error handling:

```rust
use lib_crypto::{KeyPair, CryptoError};
use anyhow::{Result, Context};

fn robust_example() -> Result<()> {
    let keypair = KeyPair::generate()
        .context("Failed to generate keypair")?;
    
    let message = b"Test message";
    
    let signature = keypair.sign(message)
        .context("Failed to sign message")?;
    
    let is_valid = keypair.verify(&signature, message)
        .context("Failed to verify signature")?;
    
    if !is_valid {
        anyhow::bail!("Signature verification failed");
    }
    
    println!("All operations completed successfully!");
    Ok(())
}
```

## Performance Considerations

### Benchmarking

```rust
use std::time::Instant;
use lib_crypto::KeyPair;

fn benchmark_operations() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let message = b"Benchmark message";
    
    // Benchmark signing
    let start = Instant::now();
    for _ in 0..1000 {
        let _signature = keypair.sign(message)?;
    }
    let signing_time = start.elapsed();
    println!("1000 signatures took: {:?}", signing_time);
    
    // Benchmark verification
    let signature = keypair.sign(message)?;
    let start = Instant::now();
    for _ in 0..1000 {
        let _valid = keypair.verify(&signature, message)?;
    }
    let verify_time = start.elapsed();
    println!("1000 verifications took: {:?}", verify_time);
    
    Ok(())
}
```

### Optimization Tips

1. **Reuse KeyPairs**: Key generation is expensive, reuse when possible
2. **Batch Operations**: Sign multiple messages with the same key for efficiency
3. **Choose Algorithms**: Use Ed25519 for compatibility, Dilithium for quantum resistance
4. **Memory Management**: Sensitive data is automatically zeroed via `ZeroizeOnDrop`

## Security Best Practices

1. **Key Storage**: Never store private keys in plaintext
2. **Randomness**: The library uses cryptographically secure randomness
3. **Side Channels**: Implementations include basic side-channel protections
4. **Algorithm Choice**: Prefer post-quantum algorithms for long-term security
5. **Verification**: Always verify signatures and check return values
6. **Updates**: Keep the library updated for security patches

## Next Steps

- Read the [Security Guide](security.md) for detailed security considerations
- Explore the [Integration Guide](integration.md) for SOVEREIGN_NET ecosystem usage
- Check [Examples](examples.md) for more comprehensive code samples
- Review module-specific documentation for advanced features

## Common Issues

### Compilation Errors
```bash
# Ensure Rust toolchain is up to date
rustup update

# Clean and rebuild
cargo clean
cargo build
```

### Performance Issues
- Use `--release` flag for production builds
- Consider algorithm choice based on performance requirements
- Profile your specific use case with `cargo bench`

### Integration Issues
- Check that all SOVEREIGN_NET components use compatible versions
- Review [Integration Guide](integration.md) for ecosystem-specific patterns
