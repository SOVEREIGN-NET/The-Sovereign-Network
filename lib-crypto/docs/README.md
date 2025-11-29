# lib-crypto Documentation

Complete documentation for the SOVEREIGN_NET post-quantum cryptography library.

## Table of Contents

### Core Modules
- **[Types](types.md)** - Core cryptographic types and data structures
- **[KeyPair](keypair.md)** - Key generation, management, and operations
- **[Post-Quantum](post_quantum.md)** - CRYSTALS-Dilithium and Kyber implementations
- **[Classical](classical.md)** - Ed25519 and Curve25519 operations
- **[Symmetric](symmetric.md)** - ChaCha20-Poly1305 encryption
- **[Hashing](hashing.md)** - BLAKE3 and SHA-3 cryptographic hashing

### Advanced Features
- **[Advanced Signatures](advanced.md)** - Ring signatures and multi-signatures
- **[Zero-Knowledge Integration](zk_integration.md)** - ZK proof system interfaces
- **[Verification](verification.md)** - Signature verification and validation

### Supporting Modules
- **[Random](random.md)** - Cryptographically secure randomness
- **[Key Derivation](kdf.md)** - HKDF and key derivation functions
- **[Utils](utils.md)** - Utility functions and compatibility layers

### Guides
- **[Getting Started](getting_started.md)** - Quick start guide and basic usage
- **[Security Guide](security.md)** - Best practices and security considerations
- **[Integration Guide](integration.md)** - How to integrate with other SOVEREIGN_NET components
- **[Examples](examples.md)** - Comprehensive code examples

## Quick Navigation

### By Use Case
- **Digital Signatures**: [KeyPair](keypair.md#signing), [Post-Quantum](post_quantum.md#dilithium), [Classical](classical.md#ed25519)
- **Encryption**: [KeyPair](keypair.md#encryption), [Symmetric](symmetric.md), [Post-Quantum](post_quantum.md#kyber)
- **Hashing**: [Hashing](hashing.md)
- **Privacy**: [Advanced Signatures](advanced.md#ring-signatures), [ZK Integration](zk_integration.md)
- **Key Management**: [KeyPair](keypair.md), [KDF](kdf.md), [Random](random.md)

### By Security Level
- **Post-Quantum**: [Post-Quantum](post_quantum.md), [KeyPair](keypair.md#post-quantum-operations)
- **Classical**: [Classical](classical.md), [KeyPair](keypair.md#classical-compatibility)
- **Hybrid**: [KeyPair](keypair.md#hybrid-encryption), [Symmetric](symmetric.md#hybrid)

## Documentation Standards

All documentation includes:
- **API Reference** - Function signatures and parameters
- **Usage Examples** - Practical code examples
- **Security Notes** - Important security considerations
- **Performance Notes** - Benchmarks and optimization tips
- **Integration Tips** - How to use with other modules

## Contributing to Documentation

When contributing to lib-crypto, please update the relevant documentation:
1. Add examples for new features
2. Document security implications
3. Update integration guides as needed
4. Include performance considerations

## Version

This documentation is for lib-crypto version 0.1.0, part of the SOVEREIGN_NET ecosystem.
