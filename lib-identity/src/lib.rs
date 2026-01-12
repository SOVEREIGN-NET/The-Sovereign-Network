//! ZHTP Identity Management Package
//! 
//! Zero-knowledge identity system with quantum-resistant cryptography and privacy-preserving
//! identity verification. Supports complete citizen onboarding with automatic UBI, DAO governance,
//! and Web4 service access.
//! 
//! ## Primary API
//! 
//! Use `IdentityManager::create_citizen_identity()` for complete citizen onboarding with:
//! - Soulbound ZK-DID (1:1 per human)
//! - Quantum-resistant wallets with 20-word seed phrases  
//! - DAO governance registration
//! - UBI payout registration
//! - Web4 service access
//! - Privacy-preserving credentials

// Core modules
pub mod types;
pub mod identity;
pub mod credentials;
pub mod citizenship;
pub mod wallets;
pub mod did;
pub mod reputation;
pub mod recovery;
pub mod guardian;
pub mod privacy;
pub mod cryptography;
pub mod auth;
pub mod economics;
pub mod integration;
pub mod verification;

// ============================================================================
// PUBLIC API EXPORTS
// ============================================================================
//
// This section defines the public API surface for lib-identity.
// All types, functions, and modules that external crates can access.

// ----------------------------------------------------------------------------
// Core Modules (accessible as lib_identity::module_name::Type)
// ----------------------------------------------------------------------------

// Note: No 'compat' module exists in this codebase. 
// The system uses direct types without compatibility adapters.

// ----------------------------------------------------------------------------
// Type Re-exports (accessible as lib_identity::Type)
// ----------------------------------------------------------------------------

// Types module - Core identity and node types
pub use types::{
    // Identity types
    IdentityId,          // ✓ Hash-based identity identifier
    IdentityType,        // ✓ Human, Agent, Contract, Organization, Device
    AccessLevel,         // ✓ FullCitizen, Visitor, Organization, Device, Restricted
    PrivateIdentityData, // ✓ Private data (never transmitted)
    
    // Credential types
    CredentialType,      // ✓ Credential type enumeration
    AttestationType,     // ✓ Attestation types
    
    // Proof parameters
    IdentityProofParams, // ✓ Zero-knowledge proof parameters
    
    // Verification types
    IdentityVerification, // ✓ Verification results
    VerificationLevel,    // ✓ Verification level (None, Basic, Standard, Full)
    VerificationResult,   // ✓ Detailed verification result
    
    // Node ID for DHT routing (32-byte deterministic identifier)
    NodeId,              // ✓ Derived from DID + device name
    DhtPeerIdentity,     // ✓ Unified peer identity (NodeId + PublicKey + DID)
};

// Identity module - Core identity structures
pub use identity::{
    ZhtpIdentity,        // ✓ Main identity struct (updated with multi-device support)
    IdentityManager,     // ✓ Identity management and citizen onboarding
};

// Credentials module - Zero-knowledge credentials
pub use credentials::{
    ZkCredential,        // ✓ Zero-knowledge credential
    IdentityAttestation, // ✓ Identity attestations
};

// Citizenship module - Citizen onboarding and services
pub use citizenship::{
    CitizenshipResult,   // ✓ Onboarding results
    DaoRegistration,     // ✓ DAO governance registration
    UbiRegistration,     // ✓ UBI payout registration
    Web4Access,          // ✓ Web4 service access
    WelcomeBonus,        // ✓ Welcome bonus for new citizens
};

// DID module - Decentralized identifiers
pub use did::{
    DidDocument,         // ✓ DID document structure
    ServiceEndpoint,     // ✓ Service endpoints
    VerificationMethod,  // ✓ Verification methods
};

// Recovery module - Identity recovery mechanisms
pub use recovery::{
    RecoveryPhraseManager,    // ✓ Recovery phrase management
    RecoveryPhrase,           // ✓ 20-word recovery phrases
    PhraseGenerationOptions,  // ✓ Phrase generation options
    EntropySource,            // ✓ Entropy sources for phrases
    SocialRecoveryManager,    // ✓ Social recovery orchestration
    RecoveryRequest,          // ✓ Recovery request tracking
    RecoveryStatus,           // ✓ Recovery status states
};

// Guardian module - Guardian-based social recovery
pub use guardian::{
    Guardian,           // ✓ Guardian entity
    GuardianConfig,     // ✓ Guardian configuration
    GuardianStatus,     // ✓ Guardian state
};

// Wallets module - Wallet management (verified export)
pub use wallets::{
    WalletManager,       // ✓ Multi-wallet manager (verified exported)
    QuantumWallet,       // ✓ Quantum-resistant wallet
    WalletType,          // ✓ Standard, Savings, Staking, etc.
    WalletId,            // ✓ Wallet identifier (Hash type alias)
    WalletSummary,       // ✓ Wallet summary information
    
    // DAO wallet types
    DaoWalletProperties,      // ✓ DAO wallet properties and transparency
    DaoGovernanceSettings,    // ✓ DAO governance configuration
    DaoHierarchyInfo,         // ✓ DAO parent/child relationships
    TransparencyLevel,        // ✓ DAO transparency levels
    PublicTransactionEntry,   // ✓ DAO public transaction log entries
    
    // Content ownership types
    ContentOwnershipRecord,    // ✓ Content ownership tracking
    ContentOwnershipStatistics,// ✓ Wallet content statistics
    ContentTransfer,           // ✓ Content transfer records
    ContentTransferType,       // ✓ Sale, Gift, Auction, etc.
    ContentMetadataSnapshot,   // ✓ Content metadata for ownership
    
    // Wallet password management
    WalletPasswordManager,     // ✓ Per-wallet password protection
    WalletPasswordError,       // ✓ Password error types
    WalletPasswordValidation,  // ✓ Password validation results
};

// Auth module - Authentication and password management
pub use auth::{
    PasswordManager,     // ✓ Password hashing and validation
    PasswordError,       // ✓ Password error types
    PasswordValidation,  // ✓ Password validation results
    PasswordStrength,    // ✓ Password strength levels (Weak, Medium, Strong)
    SessionToken,        // ✓ Session tokens
};

// ----------------------------------------------------------------------------
// External Dependencies Re-exports
// ----------------------------------------------------------------------------

// Cryptography library (contains KeyPair with Dilithium keys)
pub use lib_crypto as crypto;

// KeyPair re-export for convenience
// Note: This is the keypair type used throughout ZHTP. It contains:
//   - public_key.dilithium_pk: CRYSTALS-Dilithium post-quantum signature keys
//   - public_key.kyber_pk: CRYSTALS-Kyber post-quantum encryption keys
// There is NO separate "DilithiumKeyPair" type - KeyPair contains Dilithium internally.
pub use lib_crypto::KeyPair;  // ✓ Quantum-resistant keypair (includes Dilithium)

// Zero-knowledge proofs library
pub use lib_proofs::{
    ZeroKnowledgeProof,  // ✓ ZK proof structure
    ZkProof,             // ✓ ZK proof trait
};

// Utility functions
use anyhow::Result;

/// Initialize the identity system with proper configuration
pub async fn initialize_identity_system() -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System");
    Ok(IdentityManager::new())
}













/// Create a node identity with attached wallet (for network nodes)
/// 
/// This creates a proper identity with a wallet attached to it.
/// Wallets cannot exist without an identity in ZHTP.
/// Create a user/person identity with multiple wallets
/// This creates a Person/Organization identity that can own nodes
/// Automatically creates: Primary, Savings, and Staking wallets
/// Returns: (identity_id, primary_wallet_id, seed_phrase)
pub async fn create_user_identity_with_wallet(
    user_name: String,
    wallet_name: String,
    wallet_alias: Option<String>,
) -> Result<(IdentityId, WalletId, String)> {
    use crate::identity::IdentityManager;
    use crate::wallets::WalletType;
    use lib_crypto::Hash;
    
    tracing::info!("Creating user identity '{}' with multiple wallets", user_name);
    
    // Generate real cryptographic keypair (not random seed)
    let keypair = lib_crypto::generate_keypair()?;
    let public_key = keypair.public_key.dilithium_pk.clone();
    
    // Create identity ID from real public key
    let identity_id = Hash::from_bytes(&public_key);
    
    // Create a Human or Organization identity (can own nodes and have wallets)
    let mut identity = ZhtpIdentity::from_legacy_fields(
        identity_id.clone(),
        IdentityType::Human,
        public_key.to_vec(),
        keypair.private_key.clone(),
        "primary".to_string(),  // Default device name for user identity
        lib_proofs::ZeroKnowledgeProof {
            proof_system: "UserIdentity".to_string(),
            proof_data: vec![0u8; 32],
            public_inputs: public_key.to_vec(),
            verification_key: vec![0u8; 32],
            plonky2_proof: None,
            proof: vec![],
        },
        WalletManager::new(identity_id.clone()),
    )?;

    // Set user-specific fields
    identity.reputation = 100;
    identity.access_level = AccessLevel::FullCitizen;
    identity.metadata = std::collections::HashMap::from([(
        "user_name".to_string(),
        user_name.clone(),
    )]);
    
    // Create PRIMARY wallet (main wallet for transactions and node rewards)
    let (primary_wallet_id, seed_phrase_struct) = identity.wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Standard,
        wallet_name.clone(),
        wallet_alias.clone(),
    ).await?;
    
    tracing::info!(
        "✓ Created PRIMARY wallet {} for identity {}",
        hex::encode(&primary_wallet_id.0),
        hex::encode(&identity_id.0)
    );
    
    // Create SAVINGS wallet (for long-term storage)
    let savings_name = format!("{} - Savings", wallet_name);
    let (savings_wallet_id, _) = identity.wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Standard,
        savings_name,
        Some("savings".to_string()),
    ).await?;
    
    tracing::info!(
        "✓ Created SAVINGS wallet {} for identity {}",
        hex::encode(&savings_wallet_id.0),
        hex::encode(&identity_id.0)
    );
    
    // Create STAKING wallet (for staking and governance)
    let staking_name = format!("{} - Staking", wallet_name);
    let (staking_wallet_id, _) = identity.wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Standard,
        staking_name,
        Some("staking".to_string()),
    ).await?;
    
    tracing::info!(
        "✓ Created STAKING wallet {} for identity {}",
        hex::encode(&staking_wallet_id.0),
        hex::encode(&identity_id.0)
    );
    
    // Store the identity
    let mut manager = IdentityManager::new();
    manager.add_identity(identity);
    
    // Convert RecoveryPhrase to string (20 words joined by spaces)
    let seed_phrase_string = seed_phrase_struct.words.join(" ");
    
    tracing::info!(
        "✓ Created user identity {} with 3 wallets (Primary: {}, Savings: {}, Staking: {})",
        hex::encode(&identity_id.0),
        hex::encode(&primary_wallet_id.0),
        hex::encode(&savings_wallet_id.0),
        hex::encode(&staking_wallet_id.0)
    );
    
    // Return the primary wallet ID and its seed phrase
    Ok((identity_id, primary_wallet_id, seed_phrase_string))
}

/// Create a node/device identity owned by a user
/// This creates a Device identity for networking, with no wallets
/// Rewards go to the owner's designated wallet
pub async fn create_node_device_identity(
    owner_identity_id: IdentityId,
    reward_wallet_id: WalletId,
    node_name: String,
) -> Result<IdentityId> {
    use crate::identity::IdentityManager;
    use lib_crypto::Hash;
    
    tracing::info!(
        "Creating node device '{}' owned by identity {}",
        node_name,
        hex::encode(&owner_identity_id.0)
    );
    
    // Generate real cryptographic keypair for the node
    let keypair = lib_crypto::generate_keypair()?;
    let public_key = keypair.public_key.dilithium_pk.clone();
    
    // Create node identity ID from real public key
    let node_identity_id = Hash::from_bytes(&public_key);
    
    // Create a Device identity (for DHT/networking, owned by user)
    let mut node_identity = ZhtpIdentity::from_legacy_fields(
        node_identity_id.clone(),
        IdentityType::Device,
        public_key.to_vec(),
        keypair.private_key.clone(),
        node_name.clone(),  // Use node name as device name
        lib_proofs::ZeroKnowledgeProof {
            proof_system: "NodeDevice".to_string(),
            proof_data: vec![0u8; 32],
            public_inputs: public_key.to_vec(),
            verification_key: vec![0u8; 32],
            plonky2_proof: None,
            proof: vec![],
        },
        WalletManager::new(node_identity_id.clone()),
    )?;

    // Set device-specific fields
    node_identity.reputation = 100;
    node_identity.access_level = AccessLevel::FullCitizen;
    node_identity.metadata = std::collections::HashMap::from([
        ("node_name".to_string(), node_name.clone()),
        ("owner_identity".to_string(), hex::encode(&owner_identity_id.0)),
    ]);
    node_identity.owner_identity_id = Some(owner_identity_id.clone());
    node_identity.reward_wallet_id = Some(reward_wallet_id);
    
    // Store the node identity
    let mut manager = IdentityManager::new();
    manager.add_identity(node_identity);
    
    tracing::info!(
        "Created node device {} owned by {}",
        hex::encode(&node_identity_id.0),
        hex::encode(&owner_identity_id.0)
    );
    
    Ok(node_identity_id)
}

/// DEPRECATED: Use create_user_identity_with_wallet instead
/// This name is confusing - "node" identity implies a device, but it was creating user identities
#[deprecated(
    since = "0.2.0",
    note = "Use create_user_identity_with_wallet for users or create_node_device_identity for nodes"
)]
pub async fn create_node_identity_with_wallet(
    node_name: String,
    wallet_name: String,
    wallet_alias: Option<String>,
) -> Result<(IdentityId, WalletId, String)> {
    // Redirect to the proper function
    create_user_identity_with_wallet(node_name, wallet_name, wallet_alias).await
}

/// Demonstrate hierarchical DAO wallet functionality
/// This showcases advanced DAO-to-DAO ownership and control structures
pub async fn demonstrate_hierarchical_dao_system() -> Result<String> {
    use crate::wallets::dao_hierarchy_demo;

    tracing::info!(" Starting hierarchical DAO system demonstration");

    dao_hierarchy_demo::demonstrate_dao_hierarchy()?;

    Ok("Hierarchical DAO system demonstration completed successfully. Check logs for detailed output.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_system_initialization() {
        let manager = initialize_identity_system().await.unwrap();
        assert_eq!(manager.list_identities().len(), 0);
    }
}
