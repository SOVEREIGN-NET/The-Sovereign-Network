# lib-identity

## Overview

`lib-identity` provides zero-knowledge identity management and verification for the ZHTP network. Built with quantum-resistant cryptography and privacy-preserving protocols for secure citizen onboarding, credential management, and selective disclosure.

## Core Features

- **Zero-Knowledge Credentials**: Privacy-preserving identity verification and attestation
- **Quantum-Resistant Security**: Integration with CRYSTALS-Dilithium and Kyber algorithms
- **Device-Level Identity**: Deterministic NodeId derivation for multi-device support
- **Citizen Onboarding**: Complete digital identity lifecycle management
- **Selective Disclosure**: Reveal only necessary identity attributes
- **Biometric Recovery**: Secure identity recovery mechanisms
- **Cross-Package Integration**: Seamless compatibility with ZHTP ecosystem
- **Privacy-First**: All operations designed for maximum privacy protection

## Quick Start

```rust
use lib_identity::{IdentityManager, ZhtpIdentity};

// Create identity manager
let mut manager = IdentityManager::new();

// Generate new quantum-resistant identity
let identity = manager.create_identity("citizen_123").await?;

// Issue zero-knowledge credential
let credential = manager.issue_credential(
    &identity.id,
    CredentialType::AgeVerification,
    age_data
).await?;

// Verify identity with selective disclosure
let proof = identity.generate_age_proof(18).await?;
assert!(manager.verify_age_requirement(&proof, 18).await?);
```

## Architecture

**Seed-Anchored Identity**: This library implements a seed-based deterministic identity model where the cryptographic seed is the root of trust. See [ADR-0001](docs/adr/0001-seed-anchored-identity.md) for the complete architecture decision and rationale.

```
src/
├── types/              # Core identity types and structures
├── identity/           # Identity creation and management
├── cryptography/       # Post-quantum key operations
├── credentials/        # ZK credentials and attestations
├── privacy/            # Zero-knowledge proofs and verification
├── citizenship/        # Citizen onboarding and status
├── recovery/           # Biometric and phrase recovery
├── reputation/         # Identity scoring and trust
├── verification/       # Identity verification systems
├── wallets/            # Wallet integration
├── did/                # Decentralized identity documents
└── integration/        # Cross-package compatibility
```

## Building

```bash
cargo build --release
cargo test
cargo bench
```

## Security

This library implements zero-knowledge identity protocols with quantum-resistant cryptography. All identity operations preserve privacy through selective disclosure and use NIST-standardized post-quantum algorithms for long-term security.

## Documentation

Comprehensive documentation and usage examples will be provided in the upcoming identity documentation package.
