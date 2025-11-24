# lib-identity Documentation

Comprehensive documentation for the ZHTP Identity Management Library.

## Table of Contents

### Core Modules
- [**Types**](types.md) - Core identity types and data structures
- [**Identity**](identity.md) - Identity creation, management, and operations
- [**Cryptography**](cryptography.md) - Post-quantum cryptographic operations

### Credential System
- [**Credentials**](credentials.md) - Zero-knowledge credentials and attestations
- [**Privacy**](privacy.md) - Zero-knowledge proofs and selective disclosure
- [**Verification**](verification.md) - Identity verification systems

### Citizen Services
- [**Citizenship**](citizenship.md) - Citizen onboarding and status management
- [**Recovery**](recovery.md) - Biometric and phrase-based recovery systems
- [**Reputation**](reputation.md) - Identity scoring and trust systems

### Integration
- [**Wallets**](wallets.md) - Wallet integration and management
- [**DID**](did.md) - Decentralized identity documents (W3C DID)
- [**Integration**](integration.md) - Cross-package compatibility and APIs

## Quick Navigation

### Getting Started
1. [Identity Creation](identity.md#identity-creation)
2. [Credential Issuance](credentials.md#credential-issuance)
3. [Privacy Proofs](privacy.md#generating-proofs)

### Common Use Cases
- [Citizen Onboarding](citizenship.md#onboarding-process)
- [Age Verification](privacy.md#age-verification)
- [Selective Disclosure](credentials.md#selective-disclosure)
- [Identity Recovery](recovery.md#recovery-methods)

### Advanced Topics
- [Zero-Knowledge Circuits](privacy.md#zk-circuits)
- [Post-Quantum Security](cryptography.md#post-quantum-algorithms)
- [Cross-Package Integration](integration.md#package-integration)

## Architecture Overview

```
lib-identity/
├── types/              # Core data structures
├── identity/           # Identity management core
├── cryptography/       # Post-quantum operations
├── credentials/        # ZK credential system
├── privacy/            # Zero-knowledge proofs
├── verification/       # Verification systems
├── citizenship/        # Citizen services
├── recovery/           # Recovery mechanisms
├── reputation/         # Trust and scoring
├── wallets/            # Wallet integration
├── did/                # DID document generation
└── integration/        # Cross-package APIs
```

## Key Concepts

### Zero-Knowledge Identity
All identity operations preserve privacy through selective disclosure, allowing users to prove attributes without revealing unnecessary information.

### Quantum-Resistant Security
Built on CRYSTALS-Dilithium and Kyber algorithms for long-term security against quantum computer attacks.

### Decentralized Architecture
Compatible with W3C DID standards and designed for decentralized identity networks.

### Privacy-First Design
Every feature designed with privacy as the primary consideration, not an afterthought.
