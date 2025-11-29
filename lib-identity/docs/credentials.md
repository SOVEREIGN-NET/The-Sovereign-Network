# Credentials Module

Zero-knowledge credential system providing privacy-preserving identity attestations and verifiable credentials.

## Overview

The credentials module implements a complete zero-knowledge credential system where users can prove attributes about themselves without revealing the underlying data. Built on quantum-resistant cryptography and integrated with lib-proofs for ZK operations.

## Core Components

### ZkCredential

The fundamental structure for zero-knowledge credentials.

```rust
pub struct ZkCredential {
    pub credential_id: String,
    pub subject: IdentityId,
    pub issuer: IdentityId,
    pub credential_type: CredentialType,
    pub zk_proof: ZeroKnowledgeProof,
    pub metadata: CredentialMetadata,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}
```

**Key Features:**
- **Zero-Knowledge Proofs**: Prove attributes without revealing them
- **Selective Disclosure**: Choose which attributes to reveal
- **Quantum-Resistant**: Built on post-quantum cryptography
- **Verifiable**: Cryptographically verifiable without trusted third parties

### CredentialFactory

Central system for creating and managing credentials.

```rust
pub struct CredentialFactory {
    pub trusted_issuers: HashMap<IdentityId, Vec<CredentialType>>,
    pub verification_keys: HashMap<IdentityId, Vec<u8>>,
    pub creation_stats: CredentialCreationStats,
}
```

## Credential Creation

### Age Verification Credential

```rust
use lib_identity::credentials::{CredentialFactory, CredentialType};

let mut factory = CredentialFactory::new();

// Create age verification credential (proves over 18 without revealing exact age)
let age_credential = factory.create_age_verification_credential(
    subject_id.clone(),
    age_data,
    &issuer_public_key
).await?;

println!("Created age credential: {}", age_credential.credential_id);
assert_eq!(age_credential.credential_type, CredentialType::AgeVerification);
```

### Citizenship Credential

```rust
// Create citizenship credential (proves citizenship without revealing personal details)
let citizenship_credential = factory.create_citizenship_credential(
    subject_id.clone(),
    citizenship_data,
    &government_issuer_key
).await?;

// Credential includes ZK proof of citizenship validity
assert!(!citizenship_credential.zk_proof.is_empty());
```

### Professional License Credential

```rust
// Create professional license credential
let license_credential = factory.create_professional_license_credential(
    subject_id.clone(),
    license_data,
    &licensing_authority_key
).await?;
```

## Credential Verification

### Basic Verification

```rust
use lib_identity::credentials::verification::{verify_credential, VerificationParams};

// Verify credential cryptographic validity
let verification_result = verify_credential(
    &credential,
    &issuer_public_key,
    None
).await?;

if verification_result.success {
    println!("Credential is valid");
    println!("Trust score: {}", verification_result.trust_score);
} else {
    println!("Credential verification failed");
}
```

### Selective Disclosure Verification

```rust
use lib_identity::credentials::verification::verify_selective_disclosure;

// Verify only specific attributes
let disclosure_params = SelectiveDisclosureParams {
    required_attributes: vec!["over_18".to_string()],
    hidden_attributes: vec!["exact_age".to_string(), "birthdate".to_string()],
    verification_level: VerificationLevel::Standard,
};

let disclosure_result = verify_selective_disclosure(
    &credential,
    disclosure_params,
    &verifier_context
).await?;

// User proved they're over 18 without revealing exact age
assert!(disclosure_result.attributes_proven.contains("over_18"));
assert!(!disclosure_result.revealed_data.contains_key("exact_age"));
```

## Credential Types

### Age Verification

Proves age-related attributes without revealing exact age or birthdate.

```rust
// Supported age proofs:
// - Over/under specific age
// - Within age range
// - Age bracket membership
let age_proof_params = AgeProofParams {
    minimum_age: Some(18),
    maximum_age: Some(65),
    prove_exact_age: false, // Keep exact age private
};
```

### Citizenship Status

Proves citizenship or residency status without revealing personal details.

```rust
// Supported citizenship proofs:
// - Valid citizenship
// - Residency status  
// - Voting eligibility
// - Tax status
let citizenship_params = CitizenshipProofParams {
    prove_citizenship: true,
    prove_voting_rights: false,
    hide_personal_details: true,
};
```

### Education Credentials

Proves educational achievements without revealing institutional details.

```rust
// Supported education proofs:
// - Degree completion
// - Certification status
// - Skill verification
// - Professional qualifications
let education_params = EducationProofParams {
    degree_level: Some(DegreeLevel::Bachelor),
    field_of_study: None, // Keep private
    certification_valid: true,
};
```

### Reputation Score

Proves reputation level without revealing specific interactions or history.

```rust
// Supported reputation proofs:
// - Minimum reputation score
// - Reputation bracket
// - Trustworthiness level
// - Community standing
let reputation_params = ReputationProofParams {
    minimum_score: 750,
    prove_exact_score: false,
    include_history: false,
};
```

## Zero-Knowledge Proofs

### Integration with lib-proofs

All credentials use zero-knowledge proofs from lib-proofs:

```rust
use lib_proofs::ZeroKnowledgeProof;

// Generate ZK proof for credential attribute
let zk_proof = ZeroKnowledgeProof::new(
    "Age-Verification".to_string(),
    proof_data,
    public_inputs,
    verification_key,
    plonky2_proof,
);

// Verify ZK proof
let is_valid = zk_proof.verify()?;
```

### Proof Generation

```rust
use lib_identity::credentials::zk_proofs::{generate_age_proof, generate_citizenship_proof};

// Generate age verification proof
let age_proof = generate_age_proof(
    user_age,
    minimum_required_age,
    &user_private_key
).await?;

// Generate citizenship proof  
let citizenship_proof = generate_citizenship_proof(
    citizenship_data,
    &citizenship_private_key,
    &government_verification_key
).await?;
```

### Proof Verification

```rust
use lib_identity::credentials::zk_proofs::{verify_age_proof, verify_citizenship_proof};

// Verify age proof without learning exact age
let age_verification = verify_age_proof(
    &age_proof,
    minimum_required_age,
    &user_public_key
).await?;

// Verify citizenship proof without learning personal details
let citizenship_verification = verify_citizenship_proof(
    &citizenship_proof,
    &government_public_key
).await?;
```

## Attestation System

### IdentityAttestation

Cryptographic attestations for credential validity.

```rust
pub struct IdentityAttestation {
    pub attestation_type: AttestationType,
    pub issuer: IdentityId,
    pub subject: IdentityId,
    pub credential_reference: String,
    pub attestation_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}
```

### Creating Attestations

```rust
use lib_identity::credentials::attestation::{create_attestation, AttestationParams};

// Create government attestation for citizenship
let attestation = create_attestation(
    AttestationType::GovernmentAttestation,
    "government_authority",
    "citizen_123",
    &citizenship_credential,
    &government_signing_key
).await?;

// Add attestation to credential
credential.add_attestation(attestation).await?;
```

### Verifying Attestations

```rust
use lib_identity::credentials::attestation::verify_attestation;

// Verify attestation signature and validity
let attestation_valid = verify_attestation(
    &attestation,
    &issuer_public_key,
    &current_context
).await?;

if attestation_valid {
    println!("Attestation is cryptographically valid");
    println!("Issued by: {}", attestation.issuer);
    println!("Type: {:?}", attestation.attestation_type);
}
```

## Credential Lifecycle

### Issuance Workflow

```rust
use lib_identity::credentials::{CredentialFactory, IssuanceWorkflow};

let mut workflow = IssuanceWorkflow::new();

// Step 1: Validate identity eligibility
let eligibility = workflow.check_eligibility(
    &subject_identity,
    CredentialType::AgeVerification
).await?;

// Step 2: Generate credential if eligible
if eligibility.eligible {
    let credential = workflow.issue_credential(
        subject_identity.id,
        CredentialType::AgeVerification,
        credential_data,
        &issuer_keys
    ).await?;
    
    // Step 3: Record issuance
    workflow.record_issuance(&credential).await?;
}
```

### Renewal and Expiration

```rust
use lib_identity::credentials::lifecycle::{renew_credential, check_expiration};

// Check if credential needs renewal
let expires_soon = check_expiration(&credential, days_ahead: 30)?;

if expires_soon {
    // Renew credential with updated data
    let renewed_credential = renew_credential(
        &credential,
        updated_data,
        &issuer_keys
    ).await?;
    
    println!("Credential renewed: {}", renewed_credential.credential_id);
}
```

### Revocation

```rust
use lib_identity::credentials::lifecycle::revoke_credential;

// Revoke credential (creates cryptographic proof of revocation)
let revocation_proof = revoke_credential(
    &credential,
    RevocationReason::CompromisedKey,
    &issuer_keys
).await?;

// Check if credential is revoked
let is_revoked = check_revocation_status(&credential.credential_id).await?;
```

## Privacy Features

### Selective Disclosure

Users control exactly what information is revealed:

```rust
use lib_identity::credentials::privacy::{SelectiveDisclosure, DisclosurePolicy};

// Define disclosure policy
let policy = DisclosurePolicy {
    reveal_attributes: vec!["over_18".to_string()],
    hide_attributes: vec!["exact_age".to_string(), "birthdate".to_string()],
    proof_of_hidden: true,
};

// Apply selective disclosure
let disclosed_credential = credential.apply_selective_disclosure(policy).await?;

// Verifier sees proof of being over 18, but not exact age
assert!(disclosed_credential.proven_attributes.contains("over_18"));
assert!(disclosed_credential.hidden_attributes.contains("exact_age"));
```

### Unlinkability

Credentials can be presented unlinkably across different interactions:

```rust
use lib_identity::credentials::privacy::generate_unlinkable_presentation;

// Generate unlinkable presentation
let presentation = generate_unlinkable_presentation(
    &credential,
    &presentation_context,
    &user_keys
).await?;

// Each presentation is unlinkable to previous ones
assert_ne!(presentation.presentation_id, previous_presentation.presentation_id);
```

### Zero-Knowledge Predicates

Prove complex predicates without revealing underlying data:

```rust
use lib_identity::credentials::predicates::{ZkPredicate, PredicateProof};

// Prove: (age >= 18 AND age <= 65) WITHOUT revealing exact age
let age_range_predicate = ZkPredicate::new("age_in_range")
    .add_constraint("age >= 18")
    .add_constraint("age <= 65")
    .hide_witness("age");

let predicate_proof = credential.prove_predicate(
    age_range_predicate,
    &user_private_data
).await?;

// Verifier can check predicate without learning age
let predicate_valid = verify_predicate_proof(
    &predicate_proof,
    &user_public_key
).await?;
```

## Integration Examples

### Identity Manager Integration

```rust
use lib_identity::{IdentityManager, credentials::CredentialFactory};

let mut identity_manager = IdentityManager::new();
let mut credential_factory = CredentialFactory::new();

// Create identity and issue credentials
let identity = identity_manager.create_identity("citizen_123").await?;

let age_credential = credential_factory.create_age_verification_credential(
    identity.id.clone(),
    user_age_data,
    &government_key
).await?;

// Link credential to identity
identity_manager.add_credential_reference(
    &identity.id,
    &age_credential.credential_id
).await?;
```

### Wallet Integration

```rust
use lib_identity::{credentials::ZkCredential, wallets::WalletManager};

let mut wallet_manager = WalletManager::new();

// Store credential in user's wallet
wallet_manager.store_credential(
    &user_wallet_id,
    &age_credential
).await?;

// Present credential from wallet
let presentation = wallet_manager.present_credential(
    &user_wallet_id,
    &age_credential.credential_id,
    presentation_context
).await?;
```

## Testing

### Credential Test Suite

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_age_credential_creation() {
        let mut factory = CredentialFactory::new();
        
        let credential = factory.create_age_verification_credential(
            "test_subject".to_string(),
            AgeData { age: 25 },
            &test_issuer_key()
        ).await.unwrap();
        
        assert_eq!(credential.credential_type, CredentialType::AgeVerification);
        assert!(!credential.zk_proof.is_empty());
    }

    #[tokio::test]
    async fn test_selective_disclosure() {
        let credential = create_test_credential().await;
        
        let policy = DisclosurePolicy {
            reveal_attributes: vec!["over_18".to_string()],
            hide_attributes: vec!["exact_age".to_string()],
            proof_of_hidden: true,
        };
        
        let disclosed = credential.apply_selective_disclosure(policy).await.unwrap();
        
        assert!(disclosed.proven_attributes.contains("over_18"));
        assert!(!disclosed.revealed_data.contains_key("exact_age"));
    }
}
```
