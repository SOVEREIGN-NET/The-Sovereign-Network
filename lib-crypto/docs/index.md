# Documentation Index

Complete documentation for lib-crypto v0.1.0 - Comprehensive cryptographic library for the SOVEREIGN_NET ecosystem.

## 📚 Documentation Structure

### Core Documentation
- **[README.md](README.md)** - Overview, quick start, and basic usage
- **[Getting Started](getting_started.md)** - Installation, setup, and first steps
- **[Types](types.md)** - Core types, structures, and interfaces

### Module Documentation
- **[KeyPair](keypair.md)** - Key generation, management, and operations
- **[Post-Quantum](post_quantum.md)** - CRYSTALS-Dilithium/Kyber algorithms
- **[Classical](classical.md)** - Ed25519 signatures and Curve25519 operations
- **[Advanced](advanced.md)** - Ring signatures, multi-signatures, hybrid encryption
- **[Hashing](hashing.md)** - BLAKE3 and SHA-3 hash functions
- **[Symmetric](symmetric.md)** - ChaCha20-Poly1305 and hybrid encryption
- **[Random](random.md)** - Cryptographically secure random number generation
- **[Verification](verification.md)** - Signature and proof verification

### Guides and Best Practices
- **[Security Guide](security.md)** - Security practices and threat mitigation
- **[Integration Guide](integration.md)** - Application integration patterns
- **[Examples](examples.md)** - Comprehensive usage examples

## Quick Reference

### Basic Operations

```rust
use lib_crypto::*;

// Generate keypair
let keypair = KeyPair::generate()?;

// Sign message
let message = b"Hello, SOVEREIGN_NET!";
let signature = keypair.sign(message)?;
let is_valid = keypair.verify(&signature, message)?;

// Encrypt data
let data = b"Confidential information";
let encrypted = keypair.encrypt(data, b"metadata")?;
let decrypted = keypair.decrypt(&encrypted, b"metadata")?;
```

### Post-Quantum Cryptography

```rust
use lib_crypto::post_quantum::*;

// CRYSTALS-Dilithium signatures
let pq_keypair = DilithiumKeyPair::generate()?;
let signature = pq_keypair.sign(message)?;
let is_valid = dilithium_verify(&signature, message, &pq_keypair.public_key)?;

// CRYSTALS-Kyber key encapsulation
let kyber_keypair = KyberKeyPair::generate()?;
let encapsulation = kyber_keypair.encapsulate()?;
let shared_secret = kyber_keypair.decapsulate(&encapsulation)?;
```

### Advanced Signatures

```rust
use lib_crypto::advanced::*;

// Ring signatures (anonymous)
let ring_keypairs: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate()).collect();
let ring_public_keys: Vec<_> = ring_keypairs.iter().map(|kp| kp.public_key()).collect();
let ring_context = RingContext::new(&ring_public_keys);
let ring_signature = ring_context.sign(message, &ring_keypairs[2], 2)?;

// Multi-signatures (threshold)
let threshold_scheme = ThresholdScheme::new(3, 5)?;
let partial_sigs: Vec<_> = ring_keypairs[0..3].iter().enumerate()
    .map(|(i, kp)| threshold_scheme.partial_sign(kp, message, i))
    .collect();
let multi_signature = threshold_scheme.combine_signatures(&partial_sigs)?;
```

### Symmetric Encryption

```rust
use lib_crypto::symmetric::*;

// ChaCha20-Poly1305 AEAD
let key = generate_chacha20_key();
let nonce = generate_nonce();
let plaintext = b"Symmetric encryption example";
let associated_data = b"public metadata";

let ciphertext = encrypt_chacha20poly1305(plaintext, associated_data, &key, &nonce)?;
let decrypted = decrypt_chacha20poly1305(&ciphertext, associated_data, &key, &nonce)?;
```

### Hashing

```rust
use lib_crypto::hashing::*;

// BLAKE3 (preferred)
let hash = blake3_hash(b"data to hash")?;
let derived_key = blake3_derive_key(b"master key", b"context info");

// SHA-3
let sha3_hash = sha3_256_hash(b"data to hash")?;
let sha3_derived = sha3_kdf(b"master key", b"salt", b"info", 32)?;
```

## Use Case Navigation

### By Application Type

| Application | Recommended Modules | Key Features |
|-------------|-------------------|--------------|
| **Web Applications** | KeyPair, Symmetric, Hashing | Session management, data protection |
| **Blockchain** | KeyPair, Advanced, Post-Quantum | Transaction signing, consensus |
| **Messaging** | KeyPair, Symmetric, Advanced | E2E encryption, authentication |
| **IoT/Embedded** | Classical, Symmetric, Random | Lightweight crypto, secure comms |
| **Enterprise** | Post-Quantum, Verification, Security | Quantum-ready, compliance |

### By Security Requirement

| Security Level | Algorithms | Modules |
|---------------|-----------|---------|
| **Current (2024)** | Ed25519, ChaCha20-Poly1305, BLAKE3 | KeyPair, Symmetric, Hashing |
| **Long-term** | CRYSTALS-Dilithium, CRYSTALS-Kyber | Post-Quantum |
| **Anonymous** | Ring signatures, ZK proofs | Advanced, Verification |
| **Multi-party** | Threshold signatures, Multi-sig | Advanced |

### By Performance Need

| Performance | Algorithms | Use Cases |
|------------|-----------|-----------|
| **High-speed** | Ed25519, ChaCha20, BLAKE3 | Real-time systems, high throughput |
| **Balanced** | Hybrid (Classical+PQ) | General applications |
| **Future-proof** | Pure Post-Quantum | Long-term storage, critical systems |

## 📖 Learning Path

### Beginner (New to Cryptography)
1. **[Getting Started](getting_started.md)** - Basic concepts and setup
2. **[KeyPair](keypair.md)** - Core signing and encryption
3. **[Examples](examples.md)** - Hello Crypto World, Basic Operations
4. **[Security Guide](security.md)** - Essential security practices

### Intermediate (Some Crypto Experience)
1. **[Types](types.md)** - Understanding the type system
2. **[Symmetric](symmetric.md)** - AEAD encryption patterns
3. **[Hashing](hashing.md)** - Hash functions and KDFs
4. **[Verification](verification.md)** - Signature verification
5. **[Integration Guide](integration.md)** - Application patterns

### Advanced (Crypto Developer)
1. **[Post-Quantum](post_quantum.md)** - Quantum-resistant algorithms
2. **[Advanced](advanced.md)** - Ring sigs, multi-sigs, hybrid crypto
3. **[Random](random.md)** - Secure randomness and entropy
4. **[Classical](classical.md)** - Low-level primitives
5. **[Security Guide](security.md)** - Advanced threat mitigation

## Development Resources

### API Documentation
- **[Types Reference](types.md#api-reference)** - Complete type definitions
- **[Error Handling](getting_started.md#error-handling)** - Error types and patterns
- **[Performance](integration.md#performance-optimization)** - Optimization strategies

### Testing and Validation
- **[Examples](examples.md#testing-integration)** - Test framework and patterns
- **[Security Testing](security.md#security-testing)** - Validation approaches
- **[Benchmarks](examples.md#performance-benchmarks)** - Performance measurements

### Integration Support
- **[Web Apps](integration.md#web-application-integration)** - Session management, APIs
- **[Blockchain](integration.md#blockchain-integration)** - Transaction signing, consensus
- **[Microservices](integration.md#microservices-integration)** - Service authentication
- **[Database](integration.md#database-integration)** - Data encryption at rest

##  Quick Start Commands

```bash
# Add to Cargo.toml
[dependencies]
lib-crypto = { path = "../lib-crypto", version = "0.1.0" }
anyhow = "1.0"

# Run examples
cargo run --example hello_crypto_world
cargo run --example secure_messaging
cargo run --example document_signing

# Run tests
cargo test
cargo test --release  # Performance tests

# Build documentation
cargo doc --open
```

##  Security Considerations

### Immediate Threats (2024)
- **Classical attacks**: Mitigated by Ed25519, ChaCha20-Poly1305
- **Side-channel attacks**: Constant-time implementations
- **Network attacks**: AEAD encryption, signature verification

### Future Threats (2030+)
- **Quantum attacks**: CRYSTALS-Dilithium, CRYSTALS-Kyber
- **Advanced persistent threats**: Hybrid cryptosystems
- **Zero-knowledge requirements**: Ring signatures, ZK proofs

### Implementation Security
- **Memory safety**: Rust's memory safety + zeroization
- **Timing attacks**: Constant-time algorithms
- **Entropy**: System randomness + proper seeding

##  Support and Contributing

### Getting Help
- **Documentation**: Start with [Getting Started](getting_started.md)
- **Examples**: Check [Examples](examples.md) for your use case
- **Security**: Review [Security Guide](security.md) for best practices

### Contributing
- **Code**: Follow patterns in existing modules
- **Documentation**: Update relevant .md files
- **Testing**: Add tests for new functionality
- **Security**: Security review for all crypto code

### Version Compatibility
- **Current**: v0.1.0 - Initial comprehensive implementation
- **API Stability**: Core APIs stable, advanced features may evolve
- **Migration**: See migration guides for version updates

---

**SOVEREIGN_NET lib-crypto v0.1.0** - Comprehensive cryptographic library providing classical and post-quantum security for decentralized networks.

*Last updated: 2024 - Comprehensive documentation covering all modules and use cases*
