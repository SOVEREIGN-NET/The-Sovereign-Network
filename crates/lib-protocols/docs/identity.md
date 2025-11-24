# Identity Module

This module bridges the `lib-identity` package with ZHTP protocols, providing protocol-level identity management, authentication, and zero-knowledge identity proofs.

## Main Types
- `ProtocolIdentityService`: Manages identity sessions, verification, and config.
- `IdentityServiceConfig`: Configures caching, ZK proofs, verification, MFA, and reputation.
- `ProtocolIdentityProof`: ZK proof, credential, and attestation for protocol use.

## Key Features
- Zero-knowledge identity proofs
- Multi-factor authentication and session management
- Attribute attestation and reputation tracking

## Example Usage
```rust
let service = ProtocolIdentityService::new(...);
// Use service to verify identities and manage sessions
```
