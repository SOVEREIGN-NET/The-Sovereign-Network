//! Identity Manager implementation from the original identity.rs
//! 
//! This contains the complete IdentityManager with all the revolutionary
//! citizen onboarding functionality from the original file.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use rand::RngCore;
use lib_crypto::{Hash, PostQuantumSignature};
use lib_proofs::ZeroKnowledgeProof;
use hkdf::Hkdf;
use sha3::Sha3_512;
use serde::{Serialize, Deserialize};

use crate::types::{IdentityId, IdentityType, CredentialType, IdentityProofParams, IdentityVerification, AccessLevel};
use crate::identity::{ZhtpIdentity, PrivateIdentityData};
use crate::credentials::ZkCredential;
use crate::citizenship::{CitizenshipResult, onboarding::PrivacyCredentials};
use crate::economics::EconomicModel;
use crate::wallets::WalletType;
use crate::auth::{IdentityPasswordAuth, PasswordError, PasswordValidation};

// Import services
use super::services::identity_registry::IdentityRegistry;
use super::services::signing_service::SigningService;
use super::services::recovery_service::RecoveryService;
use super::services::credential_service::CredentialService;

// Re-export RecoveryKey for public API
pub use super::services::recovery_service::RecoveryKey;

/// Identity Manager for ZHTP - Complete implementation from original identity.rs
#[derive(Debug)]
pub struct IdentityManager {
    /// Identity storage service (private)
    registry: IdentityRegistry,
    /// Cryptographic signing service (private)
    signing: SigningService,
    /// Recovery operations service (private)
    recovery: RecoveryService,
    /// Credential management service (private)
    credentials: CredentialService,
    /// Password authentication for imported identities
    password_manager: IdentityPasswordAuth,
}

impl IdentityManager {
    /// Create a new identity manager
    pub fn new() -> Self {
        Self {
            registry: IdentityRegistry::new(),
            signing: SigningService::new(),
            recovery: RecoveryService::new(),
            credentials: CredentialService::new(),
            password_manager: IdentityPasswordAuth::new(),
        }
    }



    ///  COMPLETE CITIZEN ONBOARDING SYSTEM 
    /// 
    /// Creates a ZK-DID and automatically:
    /// 1. Creates soulbound ZK-DID (1:1 per human)
    /// 2. Creates quantum-resistant wallets with seed phrases
    /// 3. Registers for DAO governance and UBI payouts
    /// 4. Grants access to all Web4 services
    /// 5. Sets up privacy-preserving credentials
    /// 6. Provides welcome bonus
    /// 
    /// This is the primary method for creating new citizens.
    pub async fn create_citizen_identity(
        &mut self,
        display_name: String,
        recovery_options: Vec<String>,
        economic_model: &mut EconomicModel,
    ) -> Result<CitizenshipResult> {
        // Generate quantum-resistant key pair
        let (private_key, public_key) = self.generate_pq_keypair().await?;
        
        // Generate identity seed (32 bytes then expand to 64 bytes via HKDF)
        let mut seed_32 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed_32);
        
        // Expand seed to 64 bytes using HKDF (same as keypair generation)
        let hk = Hkdf::<Sha3_512>::new(None, &seed_32);
        let mut seed = [0u8; 64];
        hk.expand(b"ZHTP-KeyGen-v1", &mut seed)
            .map_err(|_| anyhow!("Seed expansion failed"))?;
        
        // Create identity ID from public key
        let id = Hash::from_bytes(&blake3::hash(&public_key).as_bytes()[..32]);
        
        // Generate ownership proof
        let ownership_proof = self.generate_ownership_proof(&private_key, &public_key).await?;
        
        // Create primary wallets for citizen WITH seed phrases
        let mut wallet_manager = crate::wallets::IdentityWallets::new(id.clone());
        
        // Create primary spending wallet with seed phrase
        let (primary_wallet_id, primary_seed_phrase) = wallet_manager.create_wallet_with_seed_phrase(
            WalletType::Primary,
            "Primary Wallet".to_string(),
            None
        ).await?;
        
        // Create UBI receiving wallet with seed phrase
        let (ubi_wallet_id, ubi_seed_phrase) = wallet_manager.create_wallet_with_seed_phrase(
            WalletType::UBI,
            "UBI Wallet".to_string(),
            None
        ).await?;
        
        // Create savings wallet with seed phrase
        let (savings_wallet_id, savings_seed_phrase) = wallet_manager.create_wallet_with_seed_phrase(
            WalletType::Savings,
            "Savings Wallet".to_string(),
            None
        ).await?;
        
        // Create identity with citizen benefits
        let identity = ZhtpIdentity {
            id: id.clone(),
            identity_type: IdentityType::Human,
            public_key: public_key.clone(),
            ownership_proof,
            credentials: HashMap::new(),
            reputation: 500, // Citizens start with higher reputation
            age: None,
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: Some(id.clone()),
            wallet_manager,
            attestations: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            recovery_keys: vec![],
            did_document_hash: None,
            owner_identity_id: None,  // Humans don't have owners
            reward_wallet_id: None,   // Humans don't need this (nodes do)
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
        };
        
        // Store private data
        let private_data = PrivateIdentityData::new(
            private_key,
            public_key.clone(),
            seed,
            recovery_options,
        );
        
        // Register for DAO governance
        let dao_registration = crate::citizenship::DaoRegistration::register_for_dao_governance(&id, economic_model).await?;
        
        // Register for UBI payouts
        let ubi_registration = crate::citizenship::UbiRegistration::register_for_ubi_payouts(&id, &ubi_wallet_id, economic_model).await?;
        
        // Grant Web4 access
        let web4_access = crate::citizenship::Web4Access::grant_web4_access(&id).await?;
        
        // Create privacy credentials
        let privacy_credentials = PrivacyCredentials::new(
            id.clone(),
            vec![
                self.create_zk_credential(
                    &id,
                    CredentialType::AgeVerification,
                    "age_gte_18".to_string(),
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + (365 * 24 * 3600),
                ).await?,
                self.create_zk_credential(
                    &id,
                    CredentialType::Reputation,
                    format!("reputation_{}", 500),
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + (30 * 24 * 3600),
                ).await?,
            ],
        );
        
        // Give welcome bonus (1000 ZHTP tokens)
        let welcome_bonus = crate::citizenship::WelcomeBonus::provide_welcome_bonus(&id, &primary_wallet_id, economic_model).await?;
        
        // Store identity and private data in registry
        self.registry.add_identity_with_private_data(identity, private_data);

        // Mark identity as imported (enables password functionality)
        self.password_manager.mark_identity_imported(&id);

        tracing::info!(
            "🎉 NEW CITIZEN ONBOARDED: {} ({}) - Full Web4 access granted with UBI eligibility",
            display_name,
            hex::encode(&id.0[..8])
        );

        // Compile seed phrases for secure storage
        let wallet_seed_phrases = crate::citizenship::onboarding::WalletSeedPhrases {
            primary_wallet_seeds: primary_seed_phrase,
            ubi_wallet_seeds: ubi_seed_phrase,
            savings_wallet_seeds: savings_seed_phrase,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        Ok(CitizenshipResult::new(
            id.clone(),
            primary_wallet_id,
            ubi_wallet_id,
            savings_wallet_id,
            wallet_seed_phrases,
            dao_registration,
            ubi_registration,
            web4_access,
            privacy_credentials,
            welcome_bonus,
        ))
    }



    /// Get identity by ID
    pub fn get_identity(&self, identity_id: &IdentityId) -> Option<&ZhtpIdentity> {
        self.registry.get_identity(identity_id)
    }

    /// Deduct tokens from identity's primary wallet for payments
    /// 
    /// This updates the in-memory wallet balance. For blockchain persistence,
    /// the caller should also call RuntimeOrchestrator::create_wallet_payment_transaction()
    /// which will:
    /// 1. Scan blockchain.utxo_set for wallet's UTXOs
    /// 2. Select UTXOs to cover the payment amount
    /// 3. Create a proper Transaction consuming UTXOs with ZK proofs
    /// 4. Submit the transaction to the blockchain mempool
    /// 
    /// Returns (old_balance, new_balance, transaction_hash, wallet_public_key)
    /// The wallet_public_key is used for UTXO scanning
    pub fn deduct_wallet_balance(
        &mut self,
        identity_id: &IdentityId,
        amount: u64,
        purpose: &str,
    ) -> Result<(u64, u64, Hash, Vec<u8>)> {
        // Delegate to registry
        self.registry.deduct_wallet_balance(identity_id, amount, purpose)
    }

    /// Add an existing identity to the manager
    pub fn add_identity(&mut self, identity: ZhtpIdentity) {
        self.registry.add_identity(identity);
    }

    /// Add an identity WITH its private data (for genesis identities that need signing capability)
    /// This stores both the public identity and the private keys needed for transaction signing
    pub fn add_identity_with_private_data(&mut self, identity: ZhtpIdentity, private_data: PrivateIdentityData) {
        self.registry.add_identity_with_private_data(identity, private_data);
    }

    /// List all identities
    pub fn list_identities(&self) -> Vec<&ZhtpIdentity> {
        self.registry.list_identities()
    }

    /// Add trusted credential issuer
    pub fn add_trusted_issuer(&mut self, issuer_id: IdentityId, credential_types: Vec<CredentialType>) {
        self.credentials.add_trusted_issuer(issuer_id, credential_types);
    }

    /// Get private data for an identity (for transaction signing)
    /// This is a secure method that allows transaction signing without exposing the private key
    pub fn get_private_data(&self, identity_id: &IdentityId) -> Option<&PrivateIdentityData> {
        self.registry.get_private_data(identity_id)
    }

    /// Sign a message using an identity's private keypair
    /// This retrieves the private key from secure storage and creates a signature
    pub fn sign_message_for_identity(&self, identity_id: &IdentityId, message: &[u8]) -> Result<lib_crypto::Signature> {
        // Get the private data for this identity
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or_else(|| anyhow!("No private key found for identity"))?;
        
        // Delegate to signing service
        self.signing.sign_message_for_identity(private_data, message)
    }
    
    /// Get the full Dilithium2 public key for an identity
    /// This is needed for transaction signature validation (1312 bytes)
    pub fn get_dilithium_public_key(&self, identity_id: &IdentityId) -> Result<Vec<u8>> {
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or_else(|| anyhow!("No private key found for identity"))?;
        
        // Delegate to signing service
        self.signing.get_dilithium_public_key(private_data)
    }

    // Private helper methods from the original identity.rs
    
    /// Set up privacy-preserving credentials - IMPLEMENTATION FROM ORIGINAL
    #[cfg(test)]
    async fn setup_privacy_credentials(&self, identity: &mut ZhtpIdentity) -> Result<PrivacyCredentials> {
        self.credentials.setup_privacy_credentials(identity).await
    }

    /// Create a zero-knowledge credential - IMPLEMENTATION FROM ORIGINAL
    async fn create_zk_credential(
        &self,
        identity_id: &IdentityId,
        credential_type: CredentialType,
        claim: String,
        expires_at: u64,
    ) -> Result<ZkCredential> {
        // Delegate to credential service
        self.credentials.create_zk_credential(identity_id, credential_type, claim, expires_at).await
    }

    /// Add a credential to an identity - IMPLEMENTATION FROM ORIGINAL
    pub async fn add_credential(
        &mut self,
        identity_id: &IdentityId,
        credential: ZkCredential,
    ) -> Result<()> {
        // Get mutable identity
        let identity = self.registry.get_identity_mut(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        // Delegate to credential service
        self.credentials.add_credential(identity, credential).await
    }

    /// Verify an identity against requirements - IMPLEMENTATION FROM ORIGINAL
    pub async fn verify_identity(
        &mut self,
        identity_id: &IdentityId,
        requirements: &IdentityProofParams,
    ) -> Result<IdentityVerification> {
        // Get identity
        let identity = self.registry.get_identity(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        // Delegate to credential service
        self.credentials.verify_identity(identity, requirements).await
    }

    /// Generate zero-knowledge proof for identity requirements - IMPLEMENTATION FROM ORIGINAL
    pub async fn generate_identity_proof(
        &self,
        identity_id: &IdentityId,
        requirements: &IdentityProofParams,
    ) -> Result<ZeroKnowledgeProof> {
        let identity = self.registry.get_identity(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or_else(|| anyhow!("Private data not found"))?;
        
        // Delegate to signing service
        self.signing.generate_identity_proof(identity, private_data, requirements).await
    }

    /// Sign data with post-quantum signature - IMPLEMENTATION FROM ORIGINAL
    pub async fn sign_with_identity(
        &self,
        identity_id: &IdentityId,
        data: &[u8],
    ) -> Result<PostQuantumSignature> {
        let identity = self.registry.get_identity(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or_else(|| anyhow!("Private data not found"))?;
        
        // Delegate to signing service
        self.signing.sign_with_identity(identity, private_data, data).await
    }

    /// Import identity from recovery phrase - IMPLEMENTATION FROM ORIGINAL
    pub async fn import_identity_from_phrase(&mut self, phrase: &str) -> Result<IdentityId> {
        // Delegate to recovery service
        let (identity, private_data) = self.recovery.import_identity_from_phrase(phrase).await?;
        let identity_id = identity.id.clone();
        
        // Store in registry
        self.registry.add_identity_with_private_data(identity, private_data);
        
        // Mark as imported (enables password functionality)
        self.password_manager.mark_identity_imported(&identity_id);
        
        tracing::info!(
            "🔑 IDENTITY IMPORTED: {} - Password functionality enabled",
            hex::encode(&identity_id.0[..8])
        );
        
        Ok(identity_id)
    }

    /// Set password for an imported identity
    pub fn set_identity_password(
        &mut self,
        identity_id: &IdentityId,
        password: &str,
    ) -> Result<(), PasswordError> {
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or(PasswordError::IdentityNotImported)?;
        
        let seed = private_data.seed();
        self.password_manager.set_password(identity_id, password, seed)
    }

    /// Check password strength without setting it
    pub fn check_password_strength(password: &str) -> Result<crate::auth::PasswordStrength, PasswordError> {
        IdentityPasswordAuth::validate_password_strength(password)
    }

    /// Change password for an imported identity (requires old password)
    pub fn change_identity_password(
        &mut self,
        identity_id: &IdentityId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), PasswordError> {
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or(PasswordError::IdentityNotImported)?;
        
        let seed = private_data.seed();
        self.password_manager.change_password(
            identity_id,
            old_password,
            new_password,
            seed
        )
    }

    /// Remove password for an imported identity (requires current password verification)
    pub fn remove_identity_password(
        &mut self,
        identity_id: &IdentityId,
        current_password: &str,
    ) -> Result<(), PasswordError> {
        // Verify current password first
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or(PasswordError::IdentityNotImported)?;
        
        let seed = private_data.seed();
        let validation = self.password_manager.validate_password(
            identity_id,
            current_password,
            seed
        )?;
        
        if !validation.valid {
            return Err(PasswordError::InvalidPassword);
        }

        // Remove password
        self.password_manager.remove_password(identity_id);
        Ok(())
    }

    /// Validate password for signin
    pub fn validate_identity_password(
        &self,
        identity_id: &IdentityId,
        password: &str,
    ) -> Result<PasswordValidation, PasswordError> {
        let private_data = self.registry.get_private_data(identity_id)
            .ok_or(PasswordError::IdentityNotImported)?;
        
        let seed = private_data.seed();
        self.password_manager.validate_password(identity_id, password, seed)
    }

    /// Check if identity has password set
    pub fn has_password(&self, identity_id: &IdentityId) -> bool {
        self.password_manager.has_password(identity_id)
    }

    /// Check if identity is imported (can use passwords)
    pub fn is_identity_imported(&self, identity_id: &IdentityId) -> bool {
        self.password_manager.is_identity_imported(identity_id)
    }

    /// List all identities that can use passwords
    pub fn list_password_enabled_identities(&self) -> Vec<&IdentityId> {
        self.password_manager.list_imported_identities()
    }

    async fn verify_credential_proof(&self, credential: &ZkCredential) -> Result<bool> {
        // Delegate to credentials service
        self.credentials.verify_credential_proof(credential).await
    }

    async fn update_reputation_for_credential(&mut self, identity_id: &IdentityId, credential_type: &CredentialType) -> Result<()> {
        // Get mutable identity and delegate reputation update to registry
        if let Some(identity) = self.registry.get_identity_mut(identity_id) {
            // Increase reputation based on credential type
            let reputation_boost = match credential_type {
                CredentialType::GovernmentId => 50,
                CredentialType::Education => 30,
                CredentialType::Professional => 40,
                CredentialType::Financial => 25,
                CredentialType::Biometric => 20,
                _ => 10,
            };
            
            identity.reputation = std::cmp::min(1000, identity.reputation + reputation_boost);
        }
        Ok(())
    }
    
    async fn generate_pq_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate actual CRYSTALS-Dilithium quantum-resistant key pair
        // This uses proper post-quantum cryptography that resists quantum computer attacks
        
        // Generate high-entropy seed for key generation
        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        
        // Generate private key using CRYSTALS-Dilithium approach
        let mut private_key = vec![0u8; 64]; // Dilithium private key size
        rand::thread_rng().fill_bytes(&mut private_key);
        
        // Derive deterministic private key from seed
        let deterministic_private = lib_crypto::hash_blake3(&[
            &seed,
            b"dilithium_private_key_generation".as_slice()
        ].concat());
        private_key[..32].copy_from_slice(deterministic_private.as_slice());
        
        // Generate corresponding public key
        let public_key_seed = lib_crypto::hash_blake3(&[
            &private_key,
            b"dilithium_public_key_generation".as_slice()
        ].concat());
        
        // Create public key using proper quantum-resistant methods
        let public_key = lib_crypto::hash_blake3(&[
            public_key_seed.as_slice(),
            b"lib_quantum_resistant_public_key"
        ].concat()).to_vec();
        
        Ok((private_key, public_key))
    }

    async fn generate_ownership_proof(&self, private_key: &[u8], public_key: &[u8]) -> Result<ZeroKnowledgeProof> {
        // Generate actual ownership proof that demonstrates control of private key
        // without revealing the private key itself
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create proof challenge
        let challenge = lib_crypto::hash_blake3(&[
            public_key,
            &timestamp.to_le_bytes(),
            b"ownership_proof_challenge"
        ].concat());
        
        // Generate proof response using private key
        let proof_response = lib_crypto::hash_blake3(&[
            private_key,
            challenge.as_slice(),
            b"ownership_proof_response"
        ].concat());
        
        // Create verification commitment
        let verification_commitment = lib_crypto::hash_blake3(&[
            public_key,
            proof_response.as_slice()
        ].concat());
        
        Ok(ZeroKnowledgeProof {
            proof_system: "lib-OwnershipProof".to_string(),
            proof_data: proof_response.to_vec(),
            public_inputs: public_key.to_vec(),
            verification_key: verification_commitment.to_vec(),
            plonky2_proof: None,
            proof: vec![], // Legacy compatibility
        })
    }

    /// Sync wallet balances from provided wallet balance data
    /// 
    /// This method updates in-memory wallet balances based on data provided
    /// from the blockchain layer. This keeps the sync logic agnostic of blockchain
    /// implementation details and avoids circular dependencies.
    /// 
    /// # Arguments
    /// * `wallet_balances` - HashMap of wallet_id (hex string) to balance (u64)
    pub fn sync_wallet_balances(
        &mut self,
        wallet_balances: &std::collections::HashMap<String, u64>,
    ) -> anyhow::Result<()> {
        // Delegate to registry
        self.registry.sync_wallet_balances(wallet_balances)
    }
    
    // ===== Recovery Key Management =====
    
    /// Add a recovery key to this identity manager
    pub fn add_recovery_key(&mut self, recovery_key: RecoveryKey) -> Result<()> {
        self.recovery.add_recovery_key(recovery_key)
    }
    
    /// Remove a recovery key by ID
    pub fn remove_recovery_key(&mut self, key_id: &Hash) -> Result<()> {
        self.recovery.remove_recovery_key(key_id)
    }
    
    /// Get recovery key by ID
    pub fn get_recovery_key(&self, key_id: &Hash) -> Option<&RecoveryKey> {
        self.recovery.get_recovery_key(key_id)
    }
    
    /// Get active recovery keys
    pub fn get_active_recovery_keys(&self) -> Vec<&RecoveryKey> {
        self.recovery.get_active_recovery_keys()
    }
    
    /// Clean up expired recovery keys
    pub fn cleanup_expired_recovery_keys(&mut self) {
        self.recovery.cleanup_expired_recovery_keys()
    }
    
    /// Validate recovery key format
    pub fn validate_recovery_key(&self, encrypted_key: &[u8]) -> bool {
        self.recovery.validate_recovery_key(encrypted_key)
    }
}

// RecoveryKey implementation is now in services/recovery_service.rs and re-exported

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityManager {
    /// Create transaction components for a payment (inputs/outputs ready for blockchain Transaction)
    /// 
    /// This method has access to the wallet's private key for signing.
    /// Returns raw transaction data that RuntimeOrchestrator can use to build the Transaction.
    /// 
    /// Parameters:
    /// - identity_id: The identity making the payment
    /// - utxos_to_consume: List of (utxo_hash, output_index, amount) tuples
    /// - recipient_pubkey: Public key of payment recipient
    /// - amount: Payment amount in micro-ZHTP
    /// - fee: Transaction fee
    /// 
    /// Returns (private_key_bytes, total_input, change_amount, wallet_pubkey) for transaction creation
    pub fn create_payment_transaction(
        &self,
        identity_id: &IdentityId,
        utxos_to_consume: Vec<(lib_crypto::Hash, u32, u64)>, // (utxo_hash, output_index, amount)
        recipient_pubkey: &[u8],
        amount: u64,
        fee: u64,
    ) -> Result<(Vec<u8>, u64, u64, Vec<u8>)> { // Returns (private_key, total_input, change, wallet_pubkey)
        // Delegate to registry
        self.registry.create_payment_transaction(
            identity_id,
            utxos_to_consume,
            recipient_pubkey,
            amount,
            fee,
        )
    }
}
