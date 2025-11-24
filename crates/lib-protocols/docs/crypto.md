# Crypto Module

This module provides cryptographic functions and utilities for ZHTP protocols, integrating with the `lib-crypto` package for post-quantum cryptography and zero-knowledge proofs.

## Main Types
- `ZhtpCrypto`: Holds the server keypair and protocol crypto config.
- `CryptoConfig`: Configures post-quantum, ZK, hash, and signature algorithms.

## Key Features
- Post-quantum signature support (e.g., CRYSTALS-Dilithium)
- BLAKE3 hashing
- Zero-knowledge proof validation (via `lib-proofs`)
- Keypair generation and signature verification

## Example Usage
```rust
let crypto = ZhtpCrypto::new()?;
let hash = crypto.hash_content(b"data");
let valid = crypto.verify_protocol_signature(&data, &sig, &pubkey)?;
```
