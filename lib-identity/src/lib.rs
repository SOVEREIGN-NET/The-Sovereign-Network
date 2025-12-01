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
pub use recovery::{RecoveryPhraseManager, RecoveryPhrase, PhraseGenerationOptions, EntropySource};
pub use wallets::{WalletManager, QuantumWallet, WalletType, WalletId, WalletSummary};
pub use auth::{PasswordManager, PasswordError, PasswordValidation, SessionToken};

// External dependencies re-exports
pub use lib_crypto as crypto;
pub use lib_proofs::{ZeroKnowledgeProof, ZkProof};

// Utility functions
use anyhow::{anyhow, Result};
use lib_proofs::types::ProofType;

/// Initialize the identity system with proper configuration
pub async fn initialize_identity_system() -> Result<IdentityManager> {
    tracing::info!("Initializing ZHTP Identity Management System");
    Ok(IdentityManager::new())
}

/// Initialize identity system with a predefined set of identities
pub async fn initialize_identity_system_with_identities(
    identities: Vec<ZhtpIdentity>,
) -> Result<IdentityManager> {
    tracing::info!("Initializing identity system with {} identities", identities.len());
    let mut manager = IdentityManager::new();
    for identity in identities {
        manager.add_identity(identity);
    }
    Ok(manager)
}

/// Initialize identity system with identities and their private data
pub async fn initialize_identity_system_with_identities_and_private_data(
    identities_with_private: Vec<(ZhtpIdentity, PrivateIdentityData)>,
) -> Result<IdentityManager> {
    tracing::info!(
        "Initializing identity system with {} identities (private data included)",
        identities_with_private.len()
    );
    let mut manager = IdentityManager::new();
    for (identity, private_data) in identities_with_private {
        manager.add_identity_with_private_data(identity, private_data);
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
/// Returns: (identity_id, primary_wallet_id, seed_phrase)
pub async fn create_user_identity_with_wallet(
    user_name: String,
    wallet_name: String,
    wallet_alias: Option<String>,
) -> Result<(ZhtpIdentity, WalletId, String, PrivateIdentityData)> {
    use crate::wallets::WalletType;
    use lib_crypto::Hash;

    tracing::info!("Creating user identity '{}' with multiple wallets", user_name);

    // Generate real cryptographic keypair (not random seed)
    let keypair = lib_crypto::generate_keypair()?;
    let identity_id = Hash::from_bytes(&keypair.public_key.dilithium_pk);

    // Build ownership proof envelope
    let ownership_proof = lib_proofs::ProofEnvelope::new(
        ProofType::SignaturePopV1,
        None,
        Some(keypair.public_key.dilithium_pk.clone()),
        identity_id.0.to_vec(),
        vec![0u8; 32],
    );

    // Create the identity with deterministic fields
    let mut identity = ZhtpIdentity::from_legacy_fields(
        identity_id.clone(),
        IdentityType::Human,
        keypair.public_key.dilithium_pk.clone(),
        keypair.private_key.clone(),
        "primary".to_string(),
        ownership_proof,
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
    
    // Convert RecoveryPhrase to string (20 words joined by spaces)
    let seed_phrase_string = seed_phrase_struct.words.join(" ");
    
    tracing::info!(
        "✓ Created user identity {} with 3 wallets (Primary: {}, Savings: {}, Staking: {})",
        hex::encode(&identity_id.0),
        hex::encode(&primary_wallet_id.0),
        hex::encode(&savings_wallet_id.0),
        hex::encode(&staking_wallet_id.0)
    );
    
    let seed_array = to_seed_array(&keypair.private_key.master_seed)?;
    let private_data = PrivateIdentityData::new(
        keypair.private_key.dilithium_sk.clone(),
        keypair.public_key.dilithium_pk.clone(),
        seed_array,
        vec![seed_phrase_string.clone()],
    );

    Ok((identity, primary_wallet_id, seed_phrase_string, private_data))
}

/// Create a node/device identity owned by a user
/// This creates a Device identity for networking, with no wallets
/// Rewards go to the owner's designated wallet
pub async fn create_node_device_identity(
    owner_identity_id: IdentityId,
    reward_wallet_id: WalletId,
    node_name: String,
) -> Result<(ZhtpIdentity, PrivateIdentityData)> {
    use lib_crypto::Hash;

    tracing::info!(
        "Creating node device '{}' owned by identity {}",
        node_name,
        hex::encode(&owner_identity_id.0)
    );

    // Generate real cryptographic keypair for the node
    let keypair = lib_crypto::generate_keypair()?;
    let node_identity_id = Hash::from_bytes(&keypair.public_key.dilithium_pk);

    let ownership_proof = lib_proofs::ProofEnvelope::new(
        ProofType::DeviceDelegationV1,
        None,
        Some(keypair.public_key.dilithium_pk.clone()),
        node_identity_id.0.to_vec(),
        vec![0u8; 32],
    );

    let mut node_identity = ZhtpIdentity::from_legacy_fields(
        node_identity_id.clone(),
        IdentityType::Device,
        keypair.public_key.dilithium_pk.clone(),
        keypair.private_key.clone(),
        node_name.clone(),
        ownership_proof,
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
    
    tracing::info!(
        "Created node device {} owned by {}",
        hex::encode(&node_identity_id.0),
        hex::encode(&owner_identity_id.0)
    );

    let seed_array = to_seed_array(&keypair.private_key.master_seed)?;
    let private_data = PrivateIdentityData::new(
        keypair.private_key.dilithium_sk.clone(),
        keypair.public_key.dilithium_pk.clone(),
        seed_array,
        vec![],
    );

    Ok((node_identity, private_data))
}

fn to_seed_array(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() < 32 {
        return Err(anyhow!("master seed must be at least 32 bytes"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    Ok(seed)
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
    let (identity, wallet_id, seed_phrase, _private_data) =
        create_user_identity_with_wallet(node_name, wallet_name, wallet_alias).await?;
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
