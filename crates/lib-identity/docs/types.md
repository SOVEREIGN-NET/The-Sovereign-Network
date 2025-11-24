# Types Module

Core identity types and data structures for the ZHTP identity system.

## Overview

The types module defines fundamental data structures used throughout the identity system, including identity IDs, verification parameters, wallet types, and credential structures.

## Core Types

### IdentityId

```rust
pub type IdentityId = String;
```

Unique identifier for ZHTP identities. Used as the primary key for all identity operations.

**Usage:**
```rust
use lib_identity::types::IdentityId;

let identity_id: IdentityId = "citizen_12345".to_string();
```

### CredentialType

```rust
pub enum CredentialType {
    AgeVerification,
    CitizenshipStatus,
    EducationLevel,
    ProfessionalLicense,
    ReputationScore,
    BiometricHash,
    Custom(String),
}
```

Defines the types of credentials that can be issued and verified within the system.

**Examples:**
- `AgeVerification`: Proves user is above/below certain age without revealing exact age
- `CitizenshipStatus`: Confirms citizenship without revealing personal details
- `Custom(String)`: Allows for extensible credential types

### AttestationType

```rust
pub enum AttestationType {
    SelfAttestation,
    ThirdPartyAttestation,
    GovernmentAttestation,
    BiometricAttestation,
    ZeroKnowledgeAttestation,
}
```

Specifies the source and method of credential attestation.

### IdentityProofParams

```rust
pub struct IdentityProofParams {
    pub proof_type: String,
    pub required_attributes: Vec<String>,
    pub privacy_level: PrivacyLevel,
    pub verification_method: String,
}
```

Parameters for generating zero-knowledge identity proofs with selective disclosure.

## Verification Types

### IdentityVerification

```rust
pub struct IdentityVerification {
    pub identity_id: IdentityId,
    pub verification_type: String,
    pub proof_data: Vec<u8>,
    pub timestamp: u64,
    pub verifier_signature: Vec<u8>,
}
```

Results of identity verification operations, including cryptographic proofs.

### VerificationResult

```rust
pub struct VerificationResult {
    pub success: bool,
    pub verification_data: HashMap<String, String>,
    pub proof_validity: bool,
    pub trust_score: f64,
    pub verification_timestamp: u64,
}
```

Comprehensive verification results including trust scoring and proof validation.

## Privacy Types

### PrivacyLevel

```rust
pub enum PrivacyLevel {
    Public,      // No privacy protection
    Basic,       // Hash-based privacy
    Enhanced,    // Zero-knowledge proofs
    Maximum,     // Full selective disclosure
}
```

Defines the level of privacy protection for identity operations.

### SelectiveDisclosure

```rust
pub struct SelectiveDisclosure {
    pub revealed_attributes: Vec<String>,
    pub hidden_attributes: Vec<String>,
    pub proof_of_hidden: Vec<u8>,
}
```

Structure for selective disclosure operations, allowing users to prove possession of attributes without revealing them.

## Wallet Integration Types

### WalletId

```rust
pub type WalletId = String;
```

Identifier linking identities to blockchain wallets for transaction signing and asset management.

### WalletConnection

```rust
pub struct WalletConnection {
    pub wallet_id: WalletId,
    pub connection_type: String,
    pub public_key: Vec<u8>,
    pub connection_timestamp: u64,
}
```

Represents the connection between an identity and a blockchain wallet.

## Usage Examples

### Creating Identity Parameters

```rust
use lib_identity::types::*;

let proof_params = IdentityProofParams {
    proof_type: "age_verification".to_string(),
    required_attributes: vec!["age".to_string()],
    privacy_level: PrivacyLevel::Enhanced,
    verification_method: "zk_proof".to_string(),
};
```

### Working with Credentials

```rust
use lib_identity::types::CredentialType;

match credential_type {
    CredentialType::AgeVerification => {
        // Handle age verification credential
    },
    CredentialType::Custom(custom_type) => {
        // Handle custom credential type
    },
    _ => {
        // Handle other credential types
    }
}
```

### Selective Disclosure

```rust
use lib_identity::types::SelectiveDisclosure;

let disclosure = SelectiveDisclosure {
    revealed_attributes: vec!["over_18".to_string()],
    hidden_attributes: vec!["exact_age".to_string(), "birthdate".to_string()],
    proof_of_hidden: zk_proof_data,
};
```

## Type Safety

All types in this module are designed for:

- **Memory Safety**: No unsafe operations, automatic cleanup
- **Thread Safety**: All types implement Send + Sync where appropriate
- **Serialization**: Serde support for all public types
- **Zero-Copy**: Efficient data handling with minimal allocations

## Security Considerations

- All sensitive data types implement `Zeroize` for secure memory cleanup
- Identity IDs use cryptographically secure random generation
- Proof parameters include integrity checks and validation
- Wallet connections require cryptographic verification
