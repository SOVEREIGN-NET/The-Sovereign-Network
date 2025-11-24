# lib-crypto

## Overview

`lib-crypto` provides quantum-resistant cryptographic primitives and operations for secure communications, digital signatures, key management, and privacy-preserving protocols. Built with production-ready implementations of NIST-standardized post-quantum algorithms.

## Core Features

- **Post-Quantum Cryptography**: CRYSTALS-Dilithium signatures and CRYSTALS-Kyber key encapsulation
- **Classical Compatibility**: Ed25519 signatures and Curve25519 operations
- **Symmetric Encryption**: ChaCha20-Poly1305 AEAD
- **Cryptographic Hashing**: BLAKE3 and SHA-3 family
- **Advanced Signatures**: Ring signatures for anonymity and multi-signatures for shared control
- **Secure Memory**: Automatic zeroization of sensitive data
- **Zero-Knowledge Integration**: Trait interfaces for ZK proof systems

## Quick Start

```rust
use lib_crypto::KeyPair;

// Generate quantum-resistant keypair
let keypair = KeyPair::generate()?;

// Sign and verify
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message)?;
assert!(keypair.verify(&signature, message)?);

// Encrypt and decrypt
let plaintext = b"Secret message";
let ciphertext = keypair.encrypt(plaintext, b"metadata")?;
let decrypted = keypair.decrypt(&ciphertext, b"metadata")?;
```

## Architecture

```
src/
├── types/           # Core cryptographic types
├── keypair/         # Key generation and operations
├── post_quantum/    # CRYSTALS-Dilithium & Kyber
├── classical/       # Ed25519 & Curve25519
├── symmetric/       # Symmetric encryption
├── hashing/         # Cryptographic hashing
├── advanced/        # Ring & multi-signatures
├── random/          # Secure randomness
├── verification/    # Signature verification
└── zk_integration/  # Zero-knowledge interfaces
```

## Building

```bash
cargo build --release
cargo test
cargo bench
```

## Security

This library implements NIST-standardized post-quantum cryptographic algorithms designed to resist both classical and quantum computer attacks. All implementations include proper memory management and side-channel protections.

## Documentation

Comprehensive documentation and usage examples will be provided in the upcoming crypto documentation package.


