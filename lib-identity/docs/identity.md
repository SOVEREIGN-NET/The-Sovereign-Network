# Identity Module

Core identity management system providing secure identity creation, lifecycle management, and operations.

## Overview

The identity module serves as the foundation of the ZHTP identity system, handling identity creation, management, and core operations. It provides quantum-resistant security and privacy-preserving functionality.

## Core Components

### ZhtpIdentity

The main identity structure representing a complete ZHTP identity.

```rust
pub struct ZhtpIdentity {
    pub id: IdentityId,
    pub public_key: Vec<u8>,
    pub private_data: PrivateIdentityData,
    pub attestations: Vec<IdentityAttestation>,
    pub created_at: u64,
    pub last_updated: u64,
}
```

**Key Features:**
- Quantum-resistant cryptographic keys
- Privacy-preserving private data storage
- Attestation system for credential verification
- Audit trail with creation and update timestamps

### IdentityManager

Central management system for all identity operations.

```rust
pub struct IdentityManager {
    identities: HashMap<IdentityId, ZhtpIdentity>,
    private_data: HashMap<IdentityId, PrivateIdentityData>,
    verification_cache: HashMap<String, VerificationResult>,
}
```

## Identity Creation

### Basic Identity Creation

```rust
use lib_identity::identity::{IdentityManager, ZhtpIdentity};

let mut manager = IdentityManager::new();

// Create new identity with quantum-resistant keys
let identity = manager.create_identity("citizen_123").await?;

println!("Created identity: {}", identity.id);
println!("Public key: {:?}", identity.public_key);
```

### Advanced Identity Creation

```rust
use lib_identity::identity::{IdentityManager, IdentityCreationParams};

let params = IdentityCreationParams {
    identity_type: "citizen".to_string(),
    security_level: 5, // Highest security
    enable_biometric: true,
    recovery_method: RecoveryMethod::BiometricAndPhrase,
};

let identity = manager.create_identity_with_params("citizen_123", params).await?;
```

## Identity Operations

### Identity Retrieval

```rust
// Get identity by ID
let identity = manager.get_identity("citizen_123").await?;

// Get multiple identities
let identities = manager.get_identities(vec!["citizen_123", "citizen_456"]).await?;

// List all identities (admin operation)
let all_identities = manager.list_all_identities().await?;
```

### Identity Updates

```rust
// Update identity metadata
manager.update_identity_metadata(
    "citizen_123",
    "last_login",
    "2024-01-15T10:30:00Z"
).await?;

// Add attestation to identity
let attestation = IdentityAttestation {
    attestation_type: AttestationType::GovernmentAttestation,
    issuer: "government_authority".to_string(),
    data: attestation_data,
    timestamp: current_timestamp(),
};

manager.add_attestation("citizen_123", attestation).await?;
```

### Identity Validation

```rust
// Validate identity integrity
let is_valid = manager.validate_identity("citizen_123").await?;

// Verify identity signatures
let signature_valid = manager.verify_identity_signature(
    "citizen_123",
    message,
    signature
).await?;

// Check identity status
let status = manager.get_identity_status("citizen_123").await?;
```

## Private Data Management

### PrivateIdentityData

Secure storage for sensitive identity information.

```rust
pub struct PrivateIdentityData {
    encrypted_personal_info: Vec<u8>,
    biometric_templates: Vec<u8>,
    recovery_seeds: Vec<u8>,
    access_history: Vec<AccessRecord>,
}
```

### Accessing Private Data

```rust
// Access private data with authorization
let private_data = manager.get_private_data(
    "citizen_123",
    authorization_token
).await?;

// Update private data securely
manager.update_private_data(
    "citizen_123",
    updated_data,
    authorization_token
).await?;
```

## Activity Tracking

### Activity Monitoring

```rust
// Track identity usage
manager.track_activity(
    "citizen_123",
    ActivityType::CredentialRequest,
    metadata
).await?;

// Get activity history
let history = manager.get_activity_history("citizen_123").await?;

// Generate activity report
let report = manager.generate_activity_report(
    "citizen_123",
    start_date,
    end_date
).await?;
```

### Security Monitoring

```rust
// Check for suspicious activity
let alerts = manager.check_security_alerts("citizen_123").await?;

// Monitor access patterns
let access_analysis = manager.analyze_access_patterns("citizen_123").await?;

// Generate security report
let security_report = manager.generate_security_report("citizen_123").await?;
```

## Integration Examples

### Citizen Onboarding Integration

```rust
use lib_identity::identity::IdentityManager;
use lib_identity::citizenship::CitizenshipVerifier;

let mut manager = IdentityManager::new();
let mut verifier = CitizenshipVerifier::new();

// Create identity during onboarding
let identity = manager.create_identity("new_citizen_789").await?;

// Verify citizenship status
let citizenship_proof = verifier.verify_citizenship_eligibility(
    &identity,
    citizenship_documents
).await?;

if citizenship_proof.is_valid {
    // Complete citizen onboarding
    manager.activate_citizen_status("new_citizen_789").await?;
}
```

### Credential Integration

```rust
use lib_identity::identity::IdentityManager;
use lib_identity::credentials::CredentialFactory;

let manager = IdentityManager::new();
let credential_factory = CredentialFactory::new();

// Issue credential to identity
let credential = credential_factory.create_age_verification_credential(
    identity.id.clone(),
    age_data,
    &identity.public_key
).await?;

// Store credential reference in identity
manager.add_credential_reference(
    &identity.id,
    credential.credential_id
).await?;
```

## Security Features

### Quantum-Resistant Cryptography

All identity operations use post-quantum cryptographic algorithms:

- **CRYSTALS-Dilithium**: Digital signatures
- **CRYSTALS-Kyber**: Key encapsulation
- **BLAKE3**: Cryptographic hashing

### Privacy Protection

- **Zero-Knowledge Proofs**: Prove attributes without revealing them
- **Selective Disclosure**: Control what information is shared
- **Encrypted Storage**: All sensitive data encrypted at rest
- **Access Control**: Fine-grained permission system

### Audit Trail

Complete audit trail for all identity operations:

```rust
// Get audit trail for identity
let audit_trail = manager.get_audit_trail("citizen_123").await?;

// Verify audit trail integrity
let integrity_check = manager.verify_audit_trail("citizen_123").await?;
```

## Error Handling

### Common Error Types

```rust
pub enum IdentityError {
    IdentityNotFound(IdentityId),
    InvalidSignature,
    CryptographicError(String),
    AccessDenied,
    InvalidProof,
    StorageError(String),
}
```

### Error Handling Example

```rust
use lib_identity::identity::{IdentityManager, IdentityError};

match manager.get_identity("citizen_123").await {
    Ok(identity) => {
        // Process identity
    },
    Err(IdentityError::IdentityNotFound(id)) => {
        println!("Identity not found: {}", id);
    },
    Err(IdentityError::AccessDenied) => {
        println!("Access denied to identity");
    },
    Err(e) => {
        println!("Other error: {:?}", e);
    }
}
```

## Performance Considerations

- **Lazy Loading**: Identity data loaded on-demand
- **Caching**: Frequently accessed identities cached in memory
- **Batch Operations**: Efficient bulk operations for multiple identities
- **Async Operations**: Non-blocking I/O for all operations

## Testing

### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_creation() {
        let mut manager = IdentityManager::new();
        
        let identity = manager.create_identity("test_citizen").await.unwrap();
        
        assert_eq!(identity.id, "test_citizen");
        assert!(!identity.public_key.is_empty());
        assert!(identity.created_at > 0);
    }

    #[tokio::test]
    async fn test_identity_validation() {
        let mut manager = IdentityManager::new();
        let identity = manager.create_identity("test_citizen").await.unwrap();
        
        let is_valid = manager.validate_identity(&identity.id).await.unwrap();
        assert!(is_valid);
    }
}
```
