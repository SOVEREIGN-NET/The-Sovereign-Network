# DID (Decentralized Identifiers) Module

Comprehensive W3C DID implementation providing decentralized identifier management, DID document handling, and resolution capabilities for the Sovereign Network.

## Overview

The DID module implements the W3C Decentralized Identifiers (DIDs) specification, providing a standardized way to create, manage, and resolve decentralized identifiers. It enables interoperability with other DID-compatible systems while maintaining sovereignty and privacy.

## Core Components

### DIDManager

Central management system for DID operations.

```rust
pub struct DIDManager {
    pub did_registry: DIDRegistry,
    pub did_resolvers: HashMap<String, Box<dyn DIDResolver>>,
    pub did_methods: HashMap<String, Box<dyn DIDMethod>>,
    pub verification_suite: VerificationSuite,
    pub document_store: DIDDocumentStore,
}
```

**Key Features:**
- **W3C Compliant**: Full compliance with W3C DID specification
- **Multiple Methods**: Support for various DID methods (did:sov, did:key, did:web, etc.)
- **Decentralized Resolution**: Distributed DID resolution without central authority
- **Cryptographic Verification**: Strong cryptographic verification of DID operations
- **Interoperability**: Compatible with external DID ecosystems

### DID Document Structure

```rust
pub struct DIDDocument {
    pub context: Vec<String>,
    pub id: DID,
    pub controller: Option<Vec<DID>>,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<VerificationRelationship>,
    pub assertion_method: Vec<VerificationRelationship>,
    pub key_agreement: Vec<VerificationRelationship>,
    pub capability_invocation: Vec<VerificationRelationship>,
    pub capability_delegation: Vec<VerificationRelationship>,
    pub service: Vec<Service>,
    pub also_known_as: Vec<String>,
    pub metadata: DIDDocumentMetadata,
}

pub struct DIDCreationResult {
    pub did: DID,
    pub document: DIDDocument,
    pub seed_phrase: String,           // 20-word mnemonic for recovery
    pub seed_commitment: SeedCommitment, // Hash committed to blockchain
    pub master_key: ExtendedPrivateKey,  // HD master key derived from seed
    pub creation_proof: CreationProof,
    pub status: DIDCreationStatus,
}

pub struct SeedCommitment {
    pub commitment_hash: String,     // SHA-256 hash of seed phrase
    pub salt: String,               // Random salt for commitment
    pub commitment_method: String,  // "sha256_salted"
}
```

## DID Creation and Management

### Creating DIDs with Sovereign Method

```rust
use lib_identity::did::{DIDManager, DIDCreationRequest, DIDMethod};
use lib_crypto::mnemonic::{generate_mnemonic, MnemonicWordCount};

let mut did_manager = DIDManager::new();

// Generate 20-word mnemonic seed phrase for DID recovery
let did_seed_phrase = generate_mnemonic(MnemonicWordCount::Twenty)?;
println!("CRITICAL: Store this 20-word seed phrase securely!");
println!("DID Recovery Seed: {}", did_seed_phrase.phrase);
println!("This seed phrase can restore your entire DID and all associated keys");

// Create Sovereign Network DID (did:sov) with seed phrase
let did_creation = did_manager.create_did(
    DIDCreationRequest {
        method: DIDMethod::Sovereign,
        controller_identity: user_identity.id.clone(),
        seed_phrase: did_seed_phrase.clone(),
        initial_keys: vec![
            KeyDescriptor {
                key_type: KeyType::Ed25519VerificationKey2020,
                derivation_path: "m/44'/888'/0'/0/0".to_string(), // DID signing key
                purposes: vec![
                    VerificationPurpose::Authentication,
                    VerificationPurpose::AssertionMethod,
                ],
            },
            KeyDescriptor {
                key_type: KeyType::X25519KeyAgreementKey2020,
                derivation_path: "m/44'/888'/0'/1/0".to_string(), // DID encryption key
                purposes: vec![
                    VerificationPurpose::KeyAgreement,
                ],
            },
        ],
        services: vec![
            ServiceDescriptor {
                service_type: "SovereignIdentityService".to_string(),
                service_endpoint: "https://identity.sovereign.network/users/123".to_string(),
                properties: service_properties,
            },
        ],
        options: DIDCreationOptions {
            network_registration: true,
            backup_creation: true,
            metadata_inclusion: true,
            seed_phrase_backup: true, // Backup seed phrase securely
        },
    }
).await?;

match did_creation.status {
    DIDCreationStatus::Success => {
        println!("DID created successfully");
        println!("DID: {}", did_creation.did);
        println!("Seed Phrase: {}", did_creation.seed_phrase);
        println!(" IMPORTANT: The seed phrase above allows FULL RECOVERY of this DID");
        println!("   - Write it down on paper and store securely");  
        println!("   - Never share or store digitally");
        println!("   - You can transfer this DID to any device with this seed");
        
        println!("\nDID Document:");
        println!("{}", serde_json::to_string_pretty(&did_creation.document)?);
        
        // Register DID on Sovereign Network
        let registration_result = did_manager.register_did(
            DIDRegistrationRequest {
                did: did_creation.did.clone(),
                document: did_creation.document.clone(),
                proof: did_creation.creation_proof.clone(),
                seed_commitment: did_creation.seed_commitment.clone(), // Commit seed hash to chain
                registration_options: RegistrationOptions {
                    public_registration: true,
                    backup_nodes: 3,
                    verification_required: true,
                },
            }
        ).await?;
        
        println!("DID registered on network: {}", registration_result.transaction_id);
        println!("Seed phrase backup stored securely (encrypted)");
    },
    DIDCreationStatus::Failed => {
        println!("DID creation failed: {}", did_creation.error_message);
    }
}
```

### Creating Key-Based DIDs

```rust
use lib_identity::did::methods::DidKey;

// Create did:key method DID (self-contained, no network required)
let key_did_creation = did_manager.create_key_did(
    KeyDIDCreationRequest {
        key_type: KeyType::Ed25519VerificationKey2020,
        public_key: user_public_key_bytes,
        additional_purposes: vec![
            VerificationPurpose::Authentication,
            VerificationPurpose::AssertionMethod,
        ],
    }
).await?;

println!("Key-based DID created: {}", key_did_creation.did);
println!("Self-contained DID - no network registration required");

// The DID is immediately resolvable from the identifier itself
let resolved_document = did_manager.resolve_did(&key_did_creation.did).await?;
println!("DID resolved successfully from identifier");
```

### Web-Based DIDs

```rust
use lib_identity::did::methods::DidWeb;

// Create did:web method DID (hosted on web server)
let web_did_creation = did_manager.create_web_did(
    WebDIDCreationRequest {
        domain: "identity.mycompany.com".to_string(),
        path: Some("users/alice".to_string()),
        document: prepared_did_document,
        hosting_options: WebHostingOptions {
            https_required: true,
            backup_hosting: vec![
                "backup1.mycompany.com".to_string(),
                "backup2.mycompany.com".to_string(),
            ],
            content_integrity: true,
        },
    }
).await?;

// Resulting DID: did:web:identity.mycompany.com:users:alice
println!("Web DID created: {}", web_did_creation.did);
println!("Document will be accessible at: https://identity.mycompany.com/.well-known/did.json");
```

## DID Recovery and Transfer

### Recovering DID from Seed Phrase

```rust
use lib_identity::did::recovery::{DIDRecovery, SeedPhraseRecovery};

let did_recovery = DIDRecovery::new();

// Recover DID from 20-word seed phrase
let did_recovery_result = did_recovery.recover_from_seed_phrase(
    SeedPhraseRecoveryRequest {
        seed_phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual".to_string(),
        recovery_options: RecoveryOptions {
            derive_all_keys: true,
            restore_services: true,
            verify_on_network: true,
            update_registration: false, // Don't update until user confirms
        },
        target_device: DeviceInfo {
            device_id: current_device_id(),
            device_type: DeviceType::Mobile,
            security_level: SecurityLevel::High,
        },
    }
).await?;

match did_recovery_result.status {
    RecoveryStatus::Success => {
        println!(" DID recovered successfully from seed phrase!");
        println!("Recovered DID: {}", did_recovery_result.recovered_did);
        println!("All keys restored: {}", did_recovery_result.keys_recovered.len());
        
        // Display recovered keys and services
        println!("Recovered verification methods:");
        for key in &did_recovery_result.keys_recovered {
            println!("- {}: {} ({})", key.key_id, key.key_type, key.purpose);
        }
        
        println!("Recovered services:");
        for service in &did_recovery_result.services_recovered {
            println!("- {}: {}", service.service_type, service.service_endpoint);
        }
        
        // Confirm recovery and update device registration
        let recovery_confirmation = did_recovery.confirm_recovery(
            RecoveryConfirmation {
                recovery_session_id: did_recovery_result.recovery_session_id,
                new_device_info: current_device_info(),
                update_network_registration: true,
            }
        ).await?;
        
        println!("DID recovery confirmed and registered on new device");
    },
    RecoveryStatus::InvalidSeedPhrase => {
        println!("Invalid seed phrase - please check and try again");
    },
    RecoveryStatus::NetworkVerificationFailed => {
        println!("Seed phrase valid but network verification failed");
        println!("DID may have been revoked or network unreachable");
    },
    RecoveryStatus::Failed => {
        println!("DID recovery failed: {}", did_recovery_result.error_message);
    }
}
```

### Transferring DID Between Devices

```rust
use lib_identity::did::transfer::{DIDTransfer, DeviceTransfer};

let did_transfer = DIDTransfer::new();

// Initiate DID transfer from current device to new device
let transfer_request = did_transfer.initiate_device_transfer(
    DeviceTransferRequest {
        source_did: current_did.clone(),
        source_device_id: current_device_id(),
        target_device_info: TargetDeviceInfo {
            device_id: new_device_id.clone(),
            device_type: DeviceType::Desktop,
            device_public_key: new_device_public_key,
            security_attestation: device_security_proof,
        },
        transfer_method: TransferMethod::SecureChannel, // or QRCode, NFC
        authorization: DeviceAuthorization {
            require_biometric: true,
            require_pin: true,
            require_seed_phrase_confirm: true,
        },
    }
).await?;

println!("DID transfer initiated");
println!("Transfer ID: {}", transfer_request.transfer_id);
println!("Secure transfer code: {}", transfer_request.transfer_code);

// On target device, accept the transfer
let transfer_acceptance = did_transfer.accept_device_transfer(
    DeviceTransferAcceptance {
        transfer_id: transfer_request.transfer_id.clone(),
        transfer_code: transfer_request.transfer_code.clone(),
        target_device_confirmation: DeviceConfirmation {
            device_id: new_device_id,
            private_key_proof: new_device_private_key_proof,
            security_validation: security_validation_data,
        },
        seed_phrase_verification: user_entered_seed_phrase, // User must enter seed phrase
    }
).await?;

if transfer_acceptance.transfer_successful {
    println!("DID successfully transferred to new device");
    println!("New device is now authorized for DID: {}", transfer_acceptance.transferred_did);
    
    // Original device can optionally be deauthorized
    let deauthorization = did_transfer.deauthorize_source_device(
        DeviceDeauthorization {
            transfer_id: transfer_request.transfer_id,
            source_device_id: current_device_id(),
            immediate_deauth: false, // Keep active for 24 hours as backup
            wipe_local_keys: true,
        }
    ).await?;
    
    println!("Source device deauthorization scheduled");
} else {
    println!("DID transfer failed: {}", transfer_acceptance.error_message);
}
```

### Seed Phrase Security Best Practices

```rust
use lib_identity::did::security::{SeedPhraseSecurity, SecureSeedStorage};

let seed_security = SeedPhraseSecurity::new();

// Generate cryptographically secure seed phrase
let secure_seed = seed_security.generate_secure_seed_phrase(
    SecureSeedGeneration {
        word_count: MnemonicWordCount::Twenty, // 20 words = ~264 bits entropy
        language: SeedLanguage::English,
        entropy_source: EntropySource::TrueRandom, // Hardware RNG
        checksum_validation: true,
    }
).await?;

println!("Generated secure 20-word seed phrase:");
println!("Entropy: {} bits", secure_seed.entropy_bits);
println!("Language: {}", secure_seed.language);
println!("Seed: {}", secure_seed.phrase);

// Validate seed phrase security
let security_assessment = seed_security.assess_seed_phrase_security(
    &secure_seed.phrase
).await?;

println!("Seed phrase security assessment:");
println!("- Entropy level: {} bits", security_assessment.entropy_bits);
println!("- Dictionary compliance: {}", security_assessment.dictionary_compliant);
println!("- Checksum valid: {}", security_assessment.checksum_valid);
println!("- Security rating: {:?}", security_assessment.security_rating);

// Provide security recommendations
println!(" Seed Phrase Security Recommendations:");
println!("1. Write seed phrase on paper - never store digitally");
println!("2. Store in multiple secure locations (safe deposit box, fireproof safe)");
println!("3. Never photograph or screenshot the seed phrase");
println!("4. Consider using a seed phrase backup device (steel backup)");
println!("5. Test recovery process periodically with a test wallet");
println!("6. Never share seed phrase - anyone with it controls your DID");
println!("7. Use BIP39 passphrase for additional security layer if desired");

// Generate QR code for secure manual backup
let backup_qr = seed_security.generate_backup_qr_code(
    QRBackupRequest {
        seed_phrase: secure_seed.phrase.clone(),
        encryption_password: user_backup_password,
        error_correction: QRErrorCorrection::High,
        size: QRSize::Large,
    }
).await?;

println!("Encrypted QR backup generated for manual storage");
println!("QR contains encrypted seed - password required for recovery");
```

## DID Resolution and Verification

### Universal DID Resolution

```rust
use lib_identity::did::resolution::{DIDResolver, ResolutionOptions, ResolutionMetadata};

// Resolve any DID regardless of method
let resolution_result = did_manager.resolve_did_with_metadata(
    DIDResolutionRequest {
        did: target_did.clone(),
        resolution_options: ResolutionOptions {
            accept: "application/did+ld+json".to_string(),
            version_id: None, // Latest version
            version_time: None, // Current time
            no_cache: false,
            enable_experimental_public_key_types: false,
        },
        resolver_preferences: ResolverPreferences {
            preferred_methods: vec!["sovereign".to_string(), "key".to_string()],
            timeout: Duration::seconds(30),
            retry_attempts: 3,
        },
    }
).await?;

match resolution_result.resolution_metadata.error {
    None => {
        println!("DID resolved successfully");
        println!("DID: {}", resolution_result.did_document.id);
        println!("Controller: {:?}", resolution_result.did_document.controller);
        println!("Verification methods: {}", resolution_result.did_document.verification_method.len());
        
        // Validate document integrity
        let validation_result = did_manager.validate_did_document(
            &resolution_result.did_document,
            ValidationOptions {
                check_cryptographic_integrity: true,
                verify_controller_proofs: true,
                validate_service_endpoints: false,
                check_expiration: true,
            }
        ).await?;
        
        if validation_result.valid {
            println!("DID document validation: PASSED");
        } else {
            println!("DID document validation: FAILED");
            for error in &validation_result.errors {
                println!("- {}", error);
            }
        }
    },
    Some(error) => {
        println!("DID resolution failed: {}", error);
    }
}
```

### Batch DID Resolution

```rust
use lib_identity::did::resolution::BatchResolver;

// Resolve multiple DIDs efficiently
let batch_resolution = did_manager.resolve_dids_batch(
    BatchResolutionRequest {
        dids: vec![did1, did2, did3, did4, did5],
        resolution_options: ResolutionOptions::default(),
        parallel_resolution: true,
        fail_fast: false, // Continue even if some fail
    }
).await?;

println!("Batch resolution completed");
println!("Successful resolutions: {}", batch_resolution.successful_count);
println!("Failed resolutions: {}", batch_resolution.failed_count);

for (did, result) in &batch_resolution.results {
    match result {
        Ok(document) => {
            println!("✓ {}: Resolved", did);
        },
        Err(error) => {
            println!("✗ {}: {}", did, error);
        }
    }
}
```

## DID Document Management

### Updating DID Documents

```rust
use lib_identity::did::document::{DIDDocumentUpdate, DocumentUpdateOperation};

// Update DID document with new verification methods
let document_update = did_manager.update_did_document(
    DIDDocumentUpdateRequest {
        did: user_did.clone(),
        operations: vec![
            DocumentUpdateOperation::AddVerificationMethod {
                verification_method: VerificationMethod {
                    id: format!("{}#key-2", user_did),
                    method_type: "Ed25519VerificationKey2020".to_string(),
                    controller: user_did.clone(),
                    public_key_multibase: encode_multibase_key(&new_public_key),
                },
                purposes: vec![
                    VerificationPurpose::Authentication,
                    VerificationPurpose::AssertionMethod,
                ],
            },
            DocumentUpdateOperation::AddService {
                service: Service {
                    id: format!("{}#messaging", user_did),
                    service_type: "SecureMessaging".to_string(),
                    service_endpoint: ServiceEndpoint::Map(service_endpoint_map),
                },
            },
            DocumentUpdateOperation::RemoveVerificationMethod {
                method_id: format!("{}#old-key-1", user_did),
            },
        ],
        proof: create_update_proof(&user_private_key, &operations).await?,
        update_options: UpdateOptions {
            immediate_propagation: true,
            version_increment: VersionIncrement::Minor,
            backup_previous_version: true,
        },
    }
).await?;

match document_update.status {
    UpdateStatus::Success => {
        println!("DID document updated successfully");
        println!("New version: {}", document_update.new_version);
        println!("Update transaction: {}", document_update.transaction_id);
        
        // Propagate update to network
        let propagation_result = did_manager.propagate_document_update(
            &document_update.transaction_id
        ).await?;
        
        println!("Update propagated to {} nodes", propagation_result.propagated_nodes);
    },
    UpdateStatus::Failed => {
        println!("DID document update failed: {}", document_update.error_message);
    }
}
```

### Document Version Management

```rust
use lib_identity::did::versioning::{DocumentVersioning, VersionHistory};

// Get document version history
let version_history = did_manager.get_document_version_history(
    &user_did
).await?;

println!("DID document version history:");
for version in &version_history.versions {
    println!("Version {}: {} ({})", 
        version.version_number,
        version.update_timestamp,
        version.update_type
    );
    println!("  Changes: {}", version.change_summary);
    println!("  Transaction: {}", version.transaction_id);
}

// Retrieve specific version
let historical_document = did_manager.resolve_did_version(
    DIDVersionRequest {
        did: user_did.clone(),
        version: DocumentVersion::Specific("1.2.0".to_string()),
        include_metadata: true,
    }
).await?;

println!("Retrieved historical document version 1.2.0");

// Compare versions
let version_diff = did_manager.compare_document_versions(
    DocumentComparisonRequest {
        did: user_did.clone(),
        version_a: DocumentVersion::Specific("1.1.0".to_string()),
        version_b: DocumentVersion::Latest,
        diff_format: DiffFormat::Detailed,
    }
).await?;

println!("Version comparison:");
for change in &version_diff.changes {
    println!("- {:?}: {}", change.change_type, change.description);
}
```

## Authentication and Authorization

### DID-Based Authentication

```rust
use lib_identity::did::authentication::{DIDAuth, AuthenticationChallenge};

let did_auth = DIDAuth::new();

// Create authentication challenge
let auth_challenge = did_auth.create_authentication_challenge(
    AuthenticationRequest {
        challenger_did: service_provider_did.clone(),
        challenge_purpose: "service_access".to_string(),
        required_verification_methods: vec![
            VerificationPurpose::Authentication,
        ],
        challenge_expiry: Duration::minutes(10),
        nonce: generate_secure_nonce(),
    }
).await?;

println!("Authentication challenge created");
println!("Challenge ID: {}", auth_challenge.challenge_id);
println!("Challenge: {}", auth_challenge.challenge_string);

// User responds to challenge
let auth_response = did_auth.respond_to_challenge(
    AuthenticationResponse {
        challenge_id: auth_challenge.challenge_id.clone(),
        user_did: user_did.clone(),
        signature: sign_challenge(&auth_challenge.challenge_string, &user_private_key).await?,
        verification_method_id: format!("{}#key-1", user_did),
        additional_proofs: vec![], // Optional additional proofs
    }
).await?;

// Verify authentication response
let verification_result = did_auth.verify_authentication_response(
    &auth_response,
    &auth_challenge
).await?;

if verification_result.authenticated {
    println!("DID authentication successful");
    println!("Authenticated DID: {}", verification_result.authenticated_did);
    println!("Verification method: {}", verification_result.verification_method_used);
    println!("Authentication level: {:?}", verification_result.authentication_level);
} else {
    println!("DID authentication failed: {}", verification_result.failure_reason);
}
```

### Capability-Based Authorization

```rust
use lib_identity::did::authorization::{CapabilityInvocation, DelegatedCapability};

// Delegate capability to another DID
let capability_delegation = did_manager.delegate_capability(
    CapabilityDelegationRequest {
        delegator_did: user_did.clone(),
        delegate_did: service_agent_did.clone(),
        capability: Capability {
            action: "update_profile".to_string(),
            resource: format!("did:sov:profile:{}", user_did),
            constraints: CapabilityConstraints {
                expiry: Some(current_timestamp() + Duration::hours(24)),
                usage_limit: Some(5),
                conditions: vec![
                    "only_during_business_hours".to_string(),
                ],
            },
        },
        delegation_proof: create_delegation_proof(&user_private_key).await?,
    }
).await?;

println!("Capability delegated successfully");
println!("Delegation ID: {}", capability_delegation.delegation_id);

// Service agent invokes delegated capability
let capability_invocation = did_manager.invoke_delegated_capability(
    CapabilityInvocationRequest {
        invoker_did: service_agent_did.clone(),
        delegation_id: capability_delegation.delegation_id.clone(),
        invocation_target: format!("did:sov:profile:{}", user_did),
        invocation_proof: create_invocation_proof(&service_agent_private_key).await?,
        action_parameters: action_parameters,
    }
).await?;

match capability_invocation.status {
    InvocationStatus::Success => {
        println!("Capability invocation successful");
        println!("Action performed: {}", capability_invocation.action_performed);
    },
    InvocationStatus::Unauthorized => {
        println!("Capability invocation unauthorized: {}", capability_invocation.error_message);
    },
    InvocationStatus::Expired => {
        println!("Delegated capability has expired");
    }
}
```

## Service Integration

### Service Endpoint Management

```rust
use lib_identity::did::services::{ServiceManager, ServiceEndpoint, ServiceRegistration};

let service_manager = ServiceManager::new();

// Register identity services in DID document
let service_registration = service_manager.register_services(
    ServiceRegistrationRequest {
        did: user_did.clone(),
        services: vec![
            ServiceDefinition {
                service_id: "identity-hub".to_string(),
                service_type: "IdentityHub".to_string(),
                service_endpoint: ServiceEndpoint::Uri("https://hub.sovereign.network/user123".to_string()),
                properties: HashMap::from([
                    ("version".to_string(), "1.0".to_string()),
                    ("protocols".to_string(), "DIDComm, HTTPS".to_string()),
                ]),
            },
            ServiceDefinition {
                service_id: "secure-messaging".to_string(),
                service_type: "DIDCommMessaging".to_string(),
                service_endpoint: ServiceEndpoint::Map(HashMap::from([
                    ("uri".to_string(), "https://messaging.sovereign.network/user123".to_string()),
                    ("accept".to_string(), "didcomm/v2".to_string()),
                    ("routingKeys".to_string(), "[\"did:key:z6Mkfriq...\"]".to_string()),
                ])),
                properties: HashMap::new(),
            },
            ServiceDefinition {
                service_id: "credential-repository".to_string(),
                service_type: "CredentialRepository".to_string(),
                service_endpoint: ServiceEndpoint::Uri("https://credentials.sovereign.network/user123".to_string()),
                properties: HashMap::from([
                    ("supportedCredentialTypes".to_string(), "VerifiableCredential,ZkCredential".to_string()),
                ]),
            },
        ],
        registration_options: ServiceRegistrationOptions {
            immediate_update: true,
            verify_endpoints: true,
            backup_registration: true,
        },
    }
).await?;

println!("Services registered in DID document");
for service_result in &service_registration.registration_results {
    println!("Service '{}': {}", 
        service_result.service_id, 
        if service_result.success { "Success" } else { "Failed" }
    );
}
```

### Service Discovery and Resolution

```rust
use lib_identity::did::discovery::{ServiceDiscovery, ServiceQuery};

let service_discovery = ServiceDiscovery::new();

// Discover services by type
let discovered_services = service_discovery.discover_services(
    ServiceDiscoveryRequest {
        service_type: "CredentialRepository".to_string(),
        search_scope: SearchScope::Network,
        filters: ServiceFilters {
            supported_protocols: Some(vec!["HTTPS".to_string(), "DIDComm".to_string()]),
            geographic_region: None,
            reputation_threshold: Some(8.0),
            availability_requirement: Some(99.5), // 99.5% uptime
        },
        max_results: 10,
    }
).await?;

println!("Discovered {} credential repository services", discovered_services.len());

for service in &discovered_services {
    println!("Service: {}", service.service_id);
    println!("  DID: {}", service.owner_did);
    println!("  Endpoint: {}", service.service_endpoint);
    println!("  Reputation: {:.1}/10", service.reputation_score);
    println!("  Availability: {:.1}%", service.availability_percentage);
}

// Query specific service from DID
let service_query = service_discovery.query_did_services(
    DIDServiceQuery {
        did: target_did.clone(),
        service_type: Some("SecureMessaging".to_string()),
        service_properties: HashMap::from([
            ("protocols".to_string(), "DIDComm".to_string()),
        ]),
    }
).await?;

if let Some(messaging_service) = service_query.services.first() {
    println!("Found secure messaging service:");
    println!("Endpoint: {}", messaging_service.service_endpoint);
    println!("Supported protocols: {:?}", messaging_service.properties);
}
```

## Interoperability and Standards

### Cross-Network DID Resolution

```rust
use lib_identity::did::interop::{CrossNetworkResolver, ExternalDIDMethod};

// Resolve DIDs from other networks
let cross_network_resolver = CrossNetworkResolver::new();

// Configure external network resolvers
cross_network_resolver.add_external_resolver(
    ExternalResolverConfig {
        method: "ion".to_string(),
        network: "Microsoft ION".to_string(),
        resolver_endpoint: "https://ion.msidentity.com/api/v1.0/identifiers/".to_string(),
        authentication: None,
        timeout: Duration::seconds(10),
    }
).await?;

cross_network_resolver.add_external_resolver(
    ExternalResolverConfig {
        method: "ethr".to_string(),
        network: "Ethereum".to_string(),
        resolver_endpoint: "https://dev.uniresolver.io/1.0/identifiers/".to_string(),
        authentication: None,
        timeout: Duration::seconds(15),
    }
).await?;

// Resolve external DID
let external_did = "did:ion:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
let external_resolution = cross_network_resolver.resolve_external_did(
    external_did
).await?;

if external_resolution.success {
    println!("External DID resolved successfully");
    println!("Network: {}", external_resolution.source_network);
    println!("Document retrieved with {} verification methods", 
        external_resolution.document.verification_method.len()
    );
} else {
    println!("External DID resolution failed: {}", external_resolution.error_message);
}
```

### DID Communication Protocol Integration

```rust
use lib_identity::did::communication::{DIDComm, MessageEncryption};

let didcomm = DIDComm::new();

// Send secure message using DIDComm
let secure_message = didcomm.send_message(
    DIDCommMessageRequest {
        sender_did: user_did.clone(),
        recipient_did: recipient_did.clone(),
        message_type: "https://didcomm.org/basicmessage/2.0/message".to_string(),
        message_body: serde_json::json!({
            "content": "Hello from Sovereign Network! This is a secure DIDComm message.",
            "timestamp": current_timestamp(),
            "message_id": generate_message_id(),
        }),
        encryption: MessageEncryption::AnoncryptOnly,
        routing: MessageRouting::Direct,
    }
).await?;

println!("DIDComm message sent successfully");
println!("Message ID: {}", secure_message.message_id);

// Receive and decrypt DIDComm message
let received_message = didcomm.receive_message(
    incoming_message_data,
    MessageReceiveOptions {
        recipient_did: user_did.clone(),
        recipient_private_key: user_private_key.clone(),
        verify_sender: true,
    }
).await?;

if received_message.verified {
    println!("Received verified DIDComm message");
    println!("From: {}", received_message.sender_did);
    println!("Content: {}", received_message.message_body);
} else {
    println!("Message verification failed");
}
```

## Testing and Validation

### DID System Testing

```rust
#[cfg(test)]
mod did_tests {
    use super::*;

    #[tokio::test]
    async fn test_did_creation_and_resolution() {
        let mut did_manager = DIDManager::new();
        
        // Create DID
        let creation_result = did_manager.create_did(
            create_test_did_request()
        ).await.unwrap();
        
        assert_eq!(creation_result.status, DIDCreationStatus::Success);
        assert!(creation_result.did.starts_with("did:sov:"));
        
        // Resolve created DID
        let resolution_result = did_manager.resolve_did(
            &creation_result.did
        ).await.unwrap();
        
        assert_eq!(resolution_result.did_document.id, creation_result.did);
        assert!(!resolution_result.did_document.verification_method.is_empty());
    }

    #[tokio::test]
    async fn test_document_update_and_versioning() {
        let mut did_manager = DIDManager::new();
        
        let did = create_test_did().await.unwrap();
        
        // Update document
        let update_result = did_manager.update_did_document(
            create_test_document_update(&did)
        ).await.unwrap();
        
        assert_eq!(update_result.status, UpdateStatus::Success);
        
        // Check version history
        let version_history = did_manager.get_document_version_history(&did).await.unwrap();
        assert!(version_history.versions.len() >= 2); // Initial + update
    }

    #[tokio::test]
    async fn test_authentication_flow() {
        let did_auth = DIDAuth::new();
        
        let challenge = did_auth.create_authentication_challenge(
            create_test_auth_request()
        ).await.unwrap();
        
        let response = create_test_auth_response(&challenge).await.unwrap();
        
        let verification = did_auth.verify_authentication_response(
            &response, &challenge
        ).await.unwrap();
        
        assert!(verification.authenticated);
    }
}
```

## Integration Examples

### Complete DID Identity System

```rust
use lib_identity::{IdentityManager, did::*, credentials::*, wallets::*};

async fn setup_complete_did_identity_system(
    identity_manager: &mut IdentityManager,
    user_identity: &Identity,
) -> Result<DIDIdentitySystem, Box<dyn std::error::Error>> {
    
    let mut did_manager = DIDManager::new();
    
    // 1. Generate secure 20-word seed phrase for DID
    let did_seed_phrase = generate_mnemonic(MnemonicWordCount::Twenty)?;
    
    println!("GENERATED DID RECOVERY SEED PHRASE:");
    println!("   {}", did_seed_phrase.phrase);
    println!(" CRITICAL: Store this seed phrase securely!");
    println!("   - Write it down on paper and store in multiple secure locations");
    println!("   - This phrase can recover your entire DID on any device");
    println!("   - Never share or store digitally");
    
    // 2. Create primary Sovereign DID with seed phrase
    let primary_did = did_manager.create_did(
        DIDCreationRequest {
            method: DIDMethod::Sovereign,
            controller_identity: user_identity.id.clone(),
            seed_phrase: did_seed_phrase.clone(),
            initial_keys: generate_hierarchical_keys_from_seed(&did_seed_phrase),
            services: create_default_services(&user_identity.id),
            options: DIDCreationOptions {
                network_registration: true,
                backup_creation: true,
                metadata_inclusion: true,
                seed_phrase_backup: true,
            },
        }
    ).await?;
    
    // 3. Create backup key-based DID (deterministic from seed)
    let backup_seed = derive_backup_seed(&did_seed_phrase, "backup_did")?;
    let backup_did = did_manager.create_key_did(
        KeyDIDCreationRequest {
            key_type: KeyType::Ed25519VerificationKey2020,
            seed_phrase: Some(backup_seed),
            additional_purposes: vec![
                VerificationPurpose::Authentication,
            ],
        }
    ).await?;
    
    // 3. Register DIDs on network
    let registration_results = register_dids_on_network(
        &mut did_manager,
        vec![&primary_did.did, &backup_did.did]
    ).await?;
    
    // 4. Setup service endpoints
    let service_endpoints = configure_did_services(
        &mut did_manager,
        &primary_did.did,
        &user_identity.id
    ).await?;
    
    // 5. Configure authentication and authorization
    let auth_config = setup_did_authentication(
        &mut did_manager,
        &primary_did.did
    ).await?;
    
    // 6. Setup cross-network interoperability
    let interop_config = configure_did_interoperability(
        &mut did_manager
    ).await?;
    
    // 7. Create seed phrase backup package
    let seed_backup = create_seed_backup_package(&did_seed_phrase, &primary_did).await?;
    
    let did_identity_system = DIDIdentitySystem {
        primary_did: primary_did.did,
        backup_did: backup_did.did,
        seed_phrase: did_seed_phrase.clone(),
        seed_backup_package: seed_backup,
        service_endpoints,
        auth_config,
        interop_config,
        registration_results,
        setup_completed_at: current_timestamp(),
    };
    
    println!("Complete DID identity system configured with seed phrase recovery");
    println!("Primary DID: {}", did_identity_system.primary_did);
    println!("Backup DID: {}", did_identity_system.backup_did);
    println!("Service endpoints: {}", did_identity_system.service_endpoints.len());
    println!("Seed phrase: {}", did_seed_phrase.phrase);
    println!(" STORE YOUR SEED PHRASE SECURELY - Required for DID recovery!");
    
    Ok(did_identity_system)
}
```
