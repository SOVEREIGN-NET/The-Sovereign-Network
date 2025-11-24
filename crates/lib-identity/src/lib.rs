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
pub mod privacy;
pub mod cryptography;
pub mod auth;
pub mod economics;
pub mod integration;
pub mod verification;

// Re-exports for external use
pub use types::*;
pub use identity::{ZhtpIdentity, PrivateIdentityData, IdentityManager};
pub use credentials::{ZkCredential, IdentityAttestation, CredentialType, AttestationType};
pub use citizenship::{CitizenshipResult, DaoRegistration, UbiRegistration, Web4Access, WelcomeBonus};
pub use types::{AccessLevel, IdentityProofParams};
pub use types::IdentityVerification;
pub use did::{
    DidDocument, ServiceEndpoint, VerificationMethod
};
pub use recovery::{RecoveryPhrase, generate_recovery_phrase, validate_recovery_phrase, restore_identity_from_phrase, RecoveryKey};
pub use wallets::{IdentityWallets, QuantumWallet, WalletType, WalletId, WalletSummary};
pub use auth::{IdentityPasswordAuth, PasswordError, PasswordValidation, SessionToken};

// External dependencies re-exports
pub use lib_crypto as crypto;
pub use lib_proofs::{ZeroKnowledgeProof, ZkProof};

// Utility functions
use anyhow::Result;
use rand;

/// Initialize the identity system with proper configuration
pub async fn initialize_identity_system() -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System");
    Ok(IdentityManager::new())
}

/// Initialize the identity system with pre-populated genesis identities
/// This is used when starting a node with identities created during genesis/startup
/// Note: This only registers public identity data - private keys must be added separately
pub async fn initialize_identity_system_with_identities_and_private_data(
    identities_with_private_data: Vec<(ZhtpIdentity, PrivateIdentityData)>
) -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System with {} genesis identities (with private keys)", identities_with_private_data.len());
    let mut manager = IdentityManager::new();
    
    for (identity, private_data) in identities_with_private_data {
        tracing::info!(
            "Registering genesis identity: {} (type: {:?}) WITH private key",
            hex::encode(&identity.id.0[..8]),
            identity.identity_type
        );
        manager.add_identity_with_private_data(identity, private_data);
    }
    
    Ok(manager)
}

/// Initialize the identity system with pre-populated genesis identities (public data only)
/// This is used when starting a node with identities created during genesis/startup
/// WARNING: Identities registered this way cannot sign transactions (no private keys)
pub async fn initialize_identity_system_with_identities(identities: Vec<ZhtpIdentity>) -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System with {} genesis identities", identities.len());
    let mut manager = IdentityManager::new();
    
    for identity in identities {
        tracing::info!(
            "Registering genesis identity: {} (type: {:?})",
            hex::encode(&identity.id.0[..8]),
            identity.identity_type
        );
        manager.add_identity(identity);
    }
    
    Ok(manager)
}













/// Create a node identity with attached wallet (for network nodes)
/// 
/// This creates a proper identity with a wallet attached to it.
/// Wallets cannot exist without an identity in ZHTP.
/// Create a user/person identity with multiple wallets
/// This creates a Person/Organization identity that can own nodes
/// Automatically creates: Primary, Savings, and Staking wallets
/// Returns: (identity, primary_wallet_id, seed_phrase)
/// The identity object is returned so the caller can register it with IdentityManager
pub async fn create_user_identity_with_wallet(
    user_name: String,
    wallet_name: String,
    wallet_alias: Option<String>,
) -> Result<(ZhtpIdentity, WalletId, String, PrivateIdentityData)> {
    use crate::identity::IdentityManager;
    use crate::wallets::WalletType;
    use lib_crypto::Hash;
    
    tracing::info!("Creating user identity '{}' with multiple wallets", user_name);
    
    // Generate real cryptographic keypair (not random seed)
    let keypair = lib_crypto::generate_keypair()?;
    let public_key = keypair.public_key.dilithium_pk.clone();
    let private_key = keypair.private_key.dilithium_sk.clone();
    let master_seed = keypair.private_key.master_seed.clone();
    
    // Create identity ID from real public key
    let identity_id = Hash::from_bytes(&public_key);
    
    // Create a Human or Organization identity (can own nodes and have wallets)
    let mut identity = ZhtpIdentity {
        id: identity_id.clone(),
        identity_type: IdentityType::Human,  // User identity, not device
        public_key: public_key.to_vec(),
        ownership_proof: lib_proofs::ZeroKnowledgeProof {
            proof_system: "UserIdentity".to_string(),
            proof_data: vec![0u8; 32],
            public_inputs: public_key.to_vec(),
            verification_key: vec![0u8; 32],
            plonky2_proof: None,
            proof: vec![],
        },
        credentials: std::collections::HashMap::new(),
        reputation: 100,
        age: None,
        access_level: AccessLevel::FullCitizen,
        metadata: std::collections::HashMap::from([(
            "user_name".to_string(),
            user_name.clone(),
        )]),
        private_data_id: Some(identity_id.clone()),
        wallet_manager: IdentityWallets::new(identity_id.clone()),
        attestations: Vec::new(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        recovery_keys: vec![],
        did_document_hash: None,
        owner_identity_id: None,     // Users don't have owners
        reward_wallet_id: None,       // Users don't need this (nodes do)
        encrypted_master_seed: None,
        next_wallet_index: 0,
        password_hash: None,
        master_seed_phrase: None,
    };
    
    // Create PRIMARY wallet (main wallet for transactions and node rewards)
    let (primary_wallet_id, seed_phrase_struct) = identity.wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Primary,
        wallet_name.clone(),
        wallet_alias.clone(),
    ).await?;
    
    tracing::info!(
        " Created PRIMARY wallet {} for identity {}",
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
        " Created SAVINGS wallet {} for identity {}",
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
        " Created STAKING wallet {} for identity {}",
        hex::encode(&staking_wallet_id.0),
        hex::encode(&identity_id.0)
    );
    
    // Convert RecoveryPhrase to string (20 words joined by spaces)
    let seed_phrase_string = seed_phrase_struct.words.join(" ");
    
    tracing::info!(
        " Created user identity {} with 3 wallets (Primary: {}, Savings: {}, Staking: {})",
        hex::encode(&identity_id.0),
        hex::encode(&primary_wallet_id.0),
        hex::encode(&savings_wallet_id.0),
        hex::encode(&staking_wallet_id.0)
    );
    
    // Create private data for identity manager using the PrivateIdentityData::new method
    // Convert master_seed Vec<u8> to [u8; 64]
    let seed_array: [u8; 64] = if master_seed.len() >= 64 {
        master_seed[..64].try_into().unwrap()
    } else if master_seed.len() == 64 {
        master_seed.as_slice().try_into().unwrap()
    } else {
        return Err(anyhow::anyhow!("Master seed must be at least 64 bytes, got {}", master_seed.len()));
    };
    
    let private_data = PrivateIdentityData::new(
        private_key.clone(),
        public_key.clone(),
        seed_array,
        vec![seed_phrase_string.clone()], // Store the seed phrase as a recovery option
    );
    
    // Return the full identity object AND private data so caller can register it with IdentityManager
    // The identity is NOT added to a manager here - that's the caller's responsibility
    Ok((identity, primary_wallet_id, seed_phrase_string, private_data))
}

/// Create a node/device identity owned by a user
/// This creates a Device identity for networking, with no wallets
/// Rewards go to the owner's designated wallet
/// Returns the full ZhtpIdentity object AND private data so caller can register it with IdentityManager
pub async fn create_node_device_identity(
    owner_identity_id: IdentityId,
    reward_wallet_id: WalletId,
    node_name: String,
) -> Result<(ZhtpIdentity, PrivateIdentityData)> {
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
    let private_key = keypair.private_key.dilithium_sk.clone();
    let master_seed = keypair.private_key.master_seed.clone();
    
    // Create node identity ID from real public key
    let node_identity_id = Hash::from_bytes(&public_key);
    
    // Create a Device identity (for DHT/networking, owned by user)
    let node_identity = ZhtpIdentity {
        id: node_identity_id.clone(),
        identity_type: IdentityType::Device,  // Device/node identity
        public_key: public_key.to_vec(),
        ownership_proof: lib_proofs::ZeroKnowledgeProof {
            proof_system: "NodeDevice".to_string(),
            proof_data: vec![0u8; 32],
            public_inputs: public_key.to_vec(),
            verification_key: vec![0u8; 32],
            plonky2_proof: None,
            proof: vec![],
        },
        credentials: std::collections::HashMap::new(),
        reputation: 100,
        age: None,
        access_level: AccessLevel::FullCitizen,
        metadata: std::collections::HashMap::from([
            ("node_name".to_string(), node_name.clone()),
            ("owner_identity".to_string(), hex::encode(&owner_identity_id.0)),
        ]),
        private_data_id: Some(node_identity_id.clone()),
        wallet_manager: IdentityWallets::new(node_identity_id.clone()),  // Empty wallet manager
        attestations: Vec::new(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        recovery_keys: vec![],
        did_document_hash: None,
        owner_identity_id: Some(owner_identity_id.clone()),  // Owned by user
        reward_wallet_id: Some(reward_wallet_id),     // Rewards go here
        encrypted_master_seed: None,
        next_wallet_index: 0,
        password_hash: None,
        master_seed_phrase: None,
    };
    
    tracing::info!(
        "Created node device {} owned by {}",
        hex::encode(&node_identity_id.0),
        hex::encode(&owner_identity_id.0)
    );
    
    // Create private data for identity manager
    // Convert master_seed Vec<u8> to [u8; 64]
    let seed_array: [u8; 64] = if master_seed.len() >= 64 {
        master_seed[..64].try_into().unwrap()
    } else if master_seed.len() == 64 {
        master_seed.as_slice().try_into().unwrap()
    } else {
        return Err(anyhow::anyhow!("Master seed must be at least 64 bytes, got {}", master_seed.len()));
    };
    
    let private_data = PrivateIdentityData::new(
        private_key.clone(),
        public_key.clone(),
        seed_array,
        vec![], // No recovery phrases for device identities
    );
    
    // Return the full identity object AND private data so caller can register it with IdentityManager
    // The identity is NOT added to a manager here - that's the caller's responsibility
    Ok((node_identity, private_data))
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
    // Redirect to the proper function (ignore private_data since this is deprecated)
    let (identity, wallet_id, seed_phrase, _private_data) = create_user_identity_with_wallet(node_name, wallet_name, wallet_alias).await?;
    // Return just the IDs for backward compatibility
    Ok((identity.id, wallet_id, seed_phrase))
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
