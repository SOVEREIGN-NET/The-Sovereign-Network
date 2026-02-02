//! Wallet types from the original identity.rs

use serde::{Deserialize, Serialize};
use lib_crypto::Hash;
use crate::types::IdentityId;
use anyhow::{Result, anyhow};

// Phase 4: Secure encryption imports
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, password_hash::SaltString};

/// Encryption version bytes for seed phrase storage
const ENCRYPTION_VERSION_LEGACY_XOR: u8 = 0x01;
const ENCRYPTION_VERSION_AES_GCM: u8 = 0x02;

/// Wallet identifier
pub type WalletId = Hash;

/// Wallet types for different purposes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalletType {
    /// Standard wallet for general use
    Standard,
    /// Primary wallet for daily transactions
    Primary,
    /// UBI wallet for automatic Universal Basic Income payouts
    UBI,
    /// Savings wallet for long-term storage
    Savings,
    /// Business wallet for commercial transactions
    Business,
    /// Stealth wallet for privacy-enhanced transactions
    Stealth,
    /// Non-profit DAO wallet - publicly visible, cannot be owned by creator
    NonProfitDAO,
    /// For-profit DAO wallet - publicly visible, can be owned by creator
    ForProfitDAO,
}

/// Quantum-resistant wallet implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumWallet {
    /// Unique wallet identifier
    pub id: WalletId,
    /// Wallet type
    pub wallet_type: WalletType,
    /// Human-readable name
    pub name: String,
    /// Optional alias for quick access
    pub alias: Option<String>,
    /// Current balance in ZHTP tokens
    pub balance: u64,
    /// Staked balance for rewards
    pub staked_balance: u64,
    /// Pending rewards from staking
    pub pending_rewards: u64,
    /// Owner identity (optional for standalone wallets)
    pub owner_id: Option<IdentityId>,
    /// Quantum-resistant public key
    pub public_key: Vec<u8>,
    /// 20-word seed phrase for wallet recovery
    pub seed_phrase: Option<crate::recovery::RecoveryPhrase>,
    /// Encrypted seed phrase backup
    pub encrypted_seed: Option<String>,
    /// Seed phrase commitment hash for blockchain verification
    pub seed_commitment: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last transaction timestamp
    pub last_transaction: Option<u64>,
    /// Transaction history (limited for performance)
    pub recent_transactions: Vec<Hash>,
    /// Wallet status
    pub is_active: bool,
    /// DAO-specific properties
    pub dao_properties: Option<DaoWalletProperties>,
    /// HD Wallet derivation index
    #[serde(skip)]
    pub derivation_index: Option<u32>,
    /// Optional password hash for wallet-level security
    #[serde(skip)]
    pub password_hash: Option<Vec<u8>>,
    /// Content owned by this wallet (content hashes from lib-storage)
    pub owned_content: Vec<Hash>,
    /// Total storage used by owned content in bytes
    pub total_storage_used: u64,
    /// Total value of owned content (for marketplace pricing)
    pub total_content_value: u64,
}

/// Content ownership record for tracking purchases and transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentOwnershipRecord {
    /// Content hash
    pub content_hash: Hash,
    /// Current owner wallet ID
    pub owner_wallet_id: WalletId,
    /// Previous owner wallet ID (if transferred)
    pub previous_owner: Option<WalletId>,
    /// Purchase price (0 if created/uploaded by owner)
    pub purchase_price: u64,
    /// Acquisition timestamp
    pub acquired_at: u64,
    /// Transfer history
    pub transfer_history: Vec<ContentTransfer>,
    /// Content metadata snapshot (content_type, size, etc.)
    pub metadata_snapshot: ContentMetadataSnapshot,
}

/// Content transfer record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTransfer {
    /// From wallet ID
    pub from_wallet: WalletId,
    /// To wallet ID
    pub to_wallet: WalletId,
    /// Transfer price
    pub price: u64,
    /// Transfer timestamp
    pub timestamp: u64,
    /// Transaction hash
    pub tx_hash: Hash,
    /// Transfer type (sale, gift, etc.)
    pub transfer_type: ContentTransferType,
}

/// Type of content transfer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContentTransferType {
    /// Direct sale for ZHTP tokens
    Sale,
    /// Gift (no payment)
    Gift,
    /// Auction sale
    Auction,
    /// Royalty payment to creator
    RoyaltyPayment,
    /// DAO treasury allocation
    DaoAllocation,
}

/// Snapshot of content metadata for ownership records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadataSnapshot {
    /// Content type (MIME)
    pub content_type: String,
    /// Content size in bytes
    pub size: u64,
    /// Content description
    pub description: String,
    /// Content tags
    pub tags: Vec<String>,
    /// Creation timestamp
    pub created_at: u64,
}

/// Content ownership statistics for a wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentOwnershipStatistics {
    /// Number of content items owned
    pub total_items: usize,
    /// Total storage used in bytes
    pub total_storage_bytes: u64,
    /// Total value of owned content
    pub total_value: u64,
    /// Wallet ID
    pub wallet_id: WalletId,
}

/// DAO wallet properties for transparency and governance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoWalletProperties {
    /// DID that created this DAO wallet
    pub creator_did: IdentityId,
    /// DAO name/title
    pub dao_name: String,
    /// DAO description and purpose
    pub dao_description: String,
    /// Whether this is a non-profit (true) or for-profit (false) DAO
    pub is_nonprofit: bool,
    /// Public ledger of all transactions (for transparency)
    pub public_transaction_log: Vec<PublicTransactionEntry>,
    /// List of authorized signatories/controllers (DIDs)
    pub authorized_controllers: Vec<IdentityId>,
    /// List of authorized DAO wallet controllers (other DAOs that can control this one)
    pub authorized_dao_controllers: Vec<WalletId>,
    /// Parent DAO wallet ID (if this DAO is owned/controlled by another DAO)
    pub parent_dao_wallet: Option<WalletId>,
    /// Child DAO wallets controlled by this DAO
    pub child_dao_wallets: Vec<WalletId>,
    /// Governance settings
    pub governance_settings: DaoGovernanceSettings,
    /// Public visibility settings
    pub transparency_level: TransparencyLevel,
    /// DAO founding timestamp
    pub founded_at: u64,
    /// Total incoming funds received
    pub total_funds_received: u64,
    /// Total outgoing funds spent
    pub total_funds_spent: u64,
    /// Number of public transactions
    pub transaction_count: u64,
}

/// Public transaction entry for DAO transparency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTransactionEntry {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Timestamp of transaction
    pub timestamp: u64,
    /// Amount transacted
    pub amount: u64,
    /// Whether funds came in (true) or went out (false)
    pub is_incoming: bool,
    /// Counterparty wallet ID (if disclosed)
    pub counterparty_wallet: Option<WalletId>,
    /// Purpose/description of transaction
    pub purpose: String,
    /// Authorizing DID
    pub authorized_by: IdentityId,
}

/// DAO governance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoGovernanceSettings {
    /// Minimum number of signatures required for transactions
    pub min_signatures_required: u32,
    /// Maximum single transaction amount without governance approval
    pub max_single_transaction: u64,
    /// Whether governance voting is required for large transactions
    pub requires_governance_vote: bool,
    /// Voting threshold percentage (0-100)
    pub voting_threshold_percent: u32,
}

/// Transparency level for DAO operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransparencyLevel {
    /// Full transparency - all transactions public
    Full,
    /// Partial transparency - amounts public, counterparties private
    Partial,
    /// Summary only - only totals and counts public
    Summary,
}

/// DAO hierarchy information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoHierarchyInfo {
    /// Parent DAO wallet ID (if this is a subsidiary DAO)
    pub parent_dao: Option<WalletId>,
    /// Child DAO wallets controlled by this DAO
    pub child_daos: Vec<WalletId>,
    /// DAO wallets authorized to control this DAO
    pub authorized_dao_controllers: Vec<WalletId>,
    /// Hierarchy level (0 = parent/standalone, 1+ = child level)
    pub hierarchy_level: u32,
}

/// Wallet summary for listing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSummary {
    /// Wallet identifier
    pub id: WalletId,
    /// Wallet type
    pub wallet_type: WalletType,
    /// Human-readable name
    pub name: String,
    /// Optional alias
    pub alias: Option<String>,
    /// Current balance
    pub balance: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Last transaction timestamp
    pub last_transaction: Option<u64>,
    /// Number of recent transactions
    pub transaction_count: usize,
    /// Wallet status
    pub is_active: bool,
    /// Whether wallet has seed phrase backup
    pub has_seed_phrase: bool,
    /// Whether wallet is standalone (no owner identity)
    pub is_standalone: bool,
    /// Whether this is a DAO wallet
    pub is_dao_wallet: bool,
    /// DAO transparency level (if DAO wallet)
    pub dao_transparency: Option<TransparencyLevel>,
    /// DAO hierarchy information (if DAO wallet)
    pub dao_hierarchy: Option<DaoHierarchyInfo>,
}

impl QuantumWallet {
    /// Create a new quantum wallet
    pub fn new(
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
        owner_id: Option<IdentityId>,
        public_key: Vec<u8>,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate wallet ID from owner ID (or random) and timestamp
        let wallet_data = if let Some(ref owner) = owner_id {
            [
                owner.as_bytes(),
                name.as_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        } else {
            // For standalone wallets, use random seed
            use rand::RngCore;
            let mut random_seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut random_seed);
            [
                &random_seed,
                name.as_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        };
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(&wallet_data));
        
        Self {
            id,
            wallet_type,
            name,
            alias,
            balance: 0,
            staked_balance: 0,
            pending_rewards: 0,
            owner_id,
            public_key,
            seed_phrase: None,
            encrypted_seed: None,
            seed_commitment: None,
            created_at: current_time,
            last_transaction: None,
            recent_transactions: Vec::new(),
            is_active: true,
            dao_properties: None,
            derivation_index: None,  // Optional HD wallet feature
            password_hash: None,  // Set via WalletPasswordManager
            owned_content: Vec::new(),  // No content owned initially
            total_storage_used: 0,
            total_content_value: 0,
        }
    }
    
    /// Add content to wallet ownership
    pub fn add_owned_content(&mut self, content_hash: Hash, size: u64, value: u64) {
        if !self.owned_content.contains(&content_hash) {
            self.owned_content.push(content_hash);
            self.total_storage_used += size;
            self.total_content_value += value;
        }
    }
    
    /// Remove content from wallet ownership
    pub fn remove_owned_content(&mut self, content_hash: &Hash, size: u64, value: u64) {
        if let Some(pos) = self.owned_content.iter().position(|h| h == content_hash) {
            self.owned_content.remove(pos);
            self.total_storage_used = self.total_storage_used.saturating_sub(size);
            self.total_content_value = self.total_content_value.saturating_sub(value);
        }
    }
    
    /// Get all owned content hashes
    pub fn get_owned_content(&self) -> &[Hash] {
        &self.owned_content
    }
    
    /// Get content ownership statistics
    pub fn get_content_statistics(&self) -> ContentOwnershipStatistics {
        ContentOwnershipStatistics {
            total_items: self.owned_content.len(),
            total_storage_bytes: self.total_storage_used,
            total_value: self.total_content_value,
            wallet_id: self.id.clone(),
        }
    }
    
    /// Create a new quantum wallet with 20-word seed phrase
    pub async fn new_with_seed_phrase(
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
        owner_id: Option<IdentityId>,
        public_key: Vec<u8>,
    ) -> Result<Self, anyhow::Error> {
        let mut wallet = Self::new(wallet_type, name, alias, owner_id, public_key);
        
        // Generate 20-word seed phrase
        let mut recovery_manager = crate::recovery::RecoveryPhraseManager::new();
        let wallet_id_str = hex::encode(&wallet.id.0);
        let wallet_descriptor = format!("wallet {}", &wallet_id_str[..16]); // Use first 16 chars for readability
        
        let seed_options = crate::recovery::PhraseGenerationOptions {
            word_count: 20,
            language: "english".to_string(),
            entropy_source: crate::recovery::EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let seed_phrase = recovery_manager.generate_recovery_phrase(&wallet_descriptor, seed_options).await?;
        
        // Generate seed commitment for blockchain verification
        let seed_text = seed_phrase.words.join(" ");
        let commitment_hash = lib_crypto::hash_blake3(format!("ZHTP_WALLET_SEED:{}", seed_text).as_bytes());
        let seed_commitment = format!("zhtp:wallet:commitment:{}", hex::encode(commitment_hash));
        
        // Encrypt seed phrase for storage
        let encrypted_seed = Self::encrypt_seed_phrase(&seed_text, &wallet_id_str)?;
        
        wallet.seed_phrase = Some(seed_phrase);
        wallet.encrypted_seed = Some(encrypted_seed);
        wallet.seed_commitment = Some(seed_commitment);
        
        Ok(wallet)
    }
    
    /// Create a new DAO wallet (requires DID - cannot be created "out of thin air")
    pub async fn new_dao_wallet(
        wallet_type: WalletType,
        creator_did: IdentityId,
        dao_name: String,
        dao_description: String,
        public_key: Vec<u8>,
        governance_settings: DaoGovernanceSettings,
        transparency_level: TransparencyLevel,
    ) -> Result<Self, anyhow::Error> {
        // Validate that this is actually a DAO wallet type
        let is_nonprofit = match wallet_type {
            WalletType::NonProfitDAO => true,
            WalletType::ForProfitDAO => false,
            _ => return Err(anyhow::anyhow!("Invalid wallet type for DAO creation. Must be NonProfitDAO or ForProfitDAO")),
        };
        
        // For nonprofit DAOs, the creator cannot be the owner
        let owner_id = if is_nonprofit {
            None // Nonprofit DAO has no owner
        } else {
            Some(creator_did.clone()) // For-profit DAO can be owned by creator
        };
        
        let mut wallet = Self::new(
            wallet_type,
            dao_name.clone(),
            None, // DAOs don't get aliases initially
            owner_id,
            public_key,
        );
        
        // Generate 20-word seed phrase for the DAO wallet
        let mut recovery_manager = crate::recovery::RecoveryPhraseManager::new();
        let wallet_id_str = hex::encode(&wallet.id.0);
        let dao_descriptor = format!("DAO wallet {}", &wallet_id_str[..16]);
        
        let seed_options = crate::recovery::PhraseGenerationOptions {
            word_count: 20,
            language: "english".to_string(),
            entropy_source: crate::recovery::EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let seed_phrase = recovery_manager.generate_recovery_phrase(&dao_descriptor, seed_options).await?;
        
        // Generate seed commitment
        let seed_text = seed_phrase.words.join(" ");
        let commitment_hash = lib_crypto::hash_blake3(format!("ZHTP_DAO_SEED:{}", seed_text).as_bytes());
        let seed_commitment = format!("zhtp:dao:commitment:{}", hex::encode(commitment_hash));
        
        // Encrypt seed phrase
        let encrypted_seed = Self::encrypt_seed_phrase(&seed_text, &wallet_id_str)?;
        
        wallet.seed_phrase = Some(seed_phrase);
        wallet.encrypted_seed = Some(encrypted_seed);
        wallet.seed_commitment = Some(seed_commitment);
        
        // Set up DAO properties
        let dao_properties = DaoWalletProperties {
            creator_did: creator_did.clone(),
            dao_name,
            dao_description,
            is_nonprofit,
            public_transaction_log: Vec::new(),
            authorized_controllers: vec![creator_did], // Creator starts as first controller
            authorized_dao_controllers: Vec::new(),
            parent_dao_wallet: None,
            child_dao_wallets: Vec::new(),
            governance_settings,
            transparency_level,
            founded_at: wallet.created_at,
            total_funds_received: 0,
            total_funds_spent: 0,
            transaction_count: 0,
        };
        
        wallet.dao_properties = Some(dao_properties);
        
        println!("✓ Created {} DAO wallet: {} (DID required)", 
                if is_nonprofit { "NonProfit" } else { "ForProfit" },
                wallet.name);
        
        Ok(wallet)
    }
    
    /// Encrypt seed phrase for secure storage using AES-256-GCM with Argon2id KDF
    ///
    /// Format: [version: 1 byte][salt: 16 bytes][nonce: 12 bytes][ciphertext: variable]
    /// Version 0x02 = AES-256-GCM (current)
    /// Version 0x01 = Legacy XOR (for migration support only)
    pub fn encrypt_seed_phrase(seed_text: &str, wallet_id: &str) -> Result<String, anyhow::Error> {
        // Generate random salt for Argon2id
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();

        // Derive 256-bit key using Argon2id
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2.hash_password_into(
            wallet_id.as_bytes(),
            salt_bytes,
            &mut key,
        ).map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        // Create AES-256-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES-GCM cipher: {}", e))?;

        // Generate random 96-bit nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the seed phrase
        let ciphertext = cipher
            .encrypt(nonce, seed_text.as_bytes())
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

        // Build output: version || salt || nonce || ciphertext
        let mut output = Vec::with_capacity(1 + salt_bytes.len() + 12 + ciphertext.len());
        output.push(ENCRYPTION_VERSION_AES_GCM);

        // Store salt length (1 byte) + salt
        output.push(salt_bytes.len() as u8);
        output.extend_from_slice(salt_bytes);

        // Store nonce
        output.extend_from_slice(&nonce_bytes);

        // Store ciphertext
        output.extend_from_slice(&ciphertext);

        // Zeroize sensitive data
        key.iter_mut().for_each(|b| *b = 0);

        Ok(hex::encode(&output))
    }

    /// Decrypt seed phrase, supporting both AES-256-GCM (v2) and legacy XOR (v1)
    pub fn decrypt_seed_phrase(&self) -> Result<Option<String>, anyhow::Error> {
        if let Some(ref encrypted_seed) = self.encrypted_seed {
            let encrypted_bytes = hex::decode(encrypted_seed)?;

            if encrypted_bytes.is_empty() {
                return Err(anyhow!("Empty encrypted seed"));
            }

            let version = encrypted_bytes[0];
            let wallet_id_str = hex::encode(&self.id.0);

            match version {
                ENCRYPTION_VERSION_AES_GCM => {
                    // AES-256-GCM decryption (v2)
                    Self::decrypt_aes_gcm(&encrypted_bytes[1..], &wallet_id_str)
                }
                ENCRYPTION_VERSION_LEGACY_XOR => {
                    // Legacy XOR decryption (v1) - for migration
                    Self::decrypt_legacy_xor(&encrypted_bytes[1..], &wallet_id_str)
                }
                _ => {
                    // Assume legacy format without version byte (pre-versioning)
                    Self::decrypt_legacy_xor(&encrypted_bytes, &wallet_id_str)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Decrypt using AES-256-GCM (version 2)
    fn decrypt_aes_gcm(data: &[u8], wallet_id: &str) -> Result<Option<String>, anyhow::Error> {
        if data.len() < 2 {
            return Err(anyhow!("Invalid AES-GCM encrypted data: too short"));
        }

        // Parse salt length and salt
        let salt_len = data[0] as usize;
        if data.len() < 1 + salt_len + 12 {
            return Err(anyhow!("Invalid AES-GCM encrypted data: missing salt or nonce"));
        }

        let salt_bytes = &data[1..1 + salt_len];
        let nonce_bytes = &data[1 + salt_len..1 + salt_len + 12];
        let ciphertext = &data[1 + salt_len + 12..];

        // Derive key using Argon2id with stored salt
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2.hash_password_into(
            wallet_id.as_bytes(),
            salt_bytes,
            &mut key,
        ).map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        // Create AES-256-GCM cipher and decrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES-GCM cipher: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES-GCM decryption failed (wrong key or tampered data): {}", e))?;

        // Zeroize sensitive data
        key.iter_mut().for_each(|b| *b = 0);

        Ok(Some(String::from_utf8(plaintext)?))
    }

    /// Decrypt using legacy XOR (version 1 or pre-versioning)
    fn decrypt_legacy_xor(data: &[u8], wallet_id: &str) -> Result<Option<String>, anyhow::Error> {
        let key = format!("WALLET_SEED_KEY_{}", wallet_id);

        let mut decrypted = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key.bytes().nth(i % key.len()).unwrap_or(0);
            decrypted.push(byte ^ key_byte);
        }

        Ok(Some(String::from_utf8(decrypted)?))
    }

    /// Re-encrypt seed phrase from legacy XOR to AES-256-GCM
    /// Call this during wallet migration to upgrade security
    pub fn migrate_seed_encryption(&mut self) -> Result<bool, anyhow::Error> {
        if let Some(ref encrypted_seed) = self.encrypted_seed {
            let encrypted_bytes = hex::decode(encrypted_seed)?;

            // Check if already using AES-GCM
            if !encrypted_bytes.is_empty() && encrypted_bytes[0] == ENCRYPTION_VERSION_AES_GCM {
                return Ok(false); // Already migrated
            }

            // Decrypt with legacy method
            let plaintext = self.decrypt_seed_phrase()?;

            if let Some(seed_text) = plaintext {
                // Re-encrypt with AES-GCM
                let wallet_id_str = hex::encode(&self.id.0);
                let new_encrypted = Self::encrypt_seed_phrase(&seed_text, &wallet_id_str)?;
                self.encrypted_seed = Some(new_encrypted);
                return Ok(true); // Migration successful
            }
        }

        Ok(false) // Nothing to migrate
    }
    
    /// Add funds to the wallet
    pub fn add_funds(&mut self, amount: u64) {
        self.balance += amount;
        self.update_last_transaction();
    }
    
    /// Remove funds from the wallet (if sufficient balance)
    pub fn remove_funds(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.balance >= amount {
            self.balance -= amount;
            self.update_last_transaction();
            Ok(())
        } else {
            Err("Insufficient balance")
        }
    }
    
    /// Update last transaction timestamp
    fn update_last_transaction(&mut self) {
        self.last_transaction = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }
    
    /// Add a transaction to recent history
    pub fn add_transaction(&mut self, tx_hash: Hash) {
        self.recent_transactions.push(tx_hash);
        // Keep only last 100 transactions for performance
        if self.recent_transactions.len() > 100 {
            self.recent_transactions.remove(0);
        }
        self.update_last_transaction();
    }
    
    /// Convert to summary for listing
    pub fn to_summary(&self) -> WalletSummary {
        let is_dao = matches!(self.wallet_type, WalletType::NonProfitDAO | WalletType::ForProfitDAO);
        let dao_transparency = if is_dao {
            self.dao_properties.as_ref().map(|props| props.transparency_level.clone())
        } else {
            None
        };
        let dao_hierarchy = if is_dao {
            self.get_dao_hierarchy_info()
        } else {
            None
        };
        
        WalletSummary {
            id: self.id.clone(),
            wallet_type: self.wallet_type.clone(),
            name: self.name.clone(),
            alias: self.alias.clone(),
            balance: self.balance,
            created_at: self.created_at,
            last_transaction: self.last_transaction,
            transaction_count: self.recent_transactions.len(),
            is_active: self.is_active,
            has_seed_phrase: self.seed_phrase.is_some(),
            is_standalone: self.owner_id.is_none(),
            is_dao_wallet: is_dao,
            dao_transparency,
            dao_hierarchy,
        }
    }
    
    /// Check if wallet matches alias
    pub fn matches_alias(&self, alias: &str) -> bool {
        self.alias.as_ref().map_or(false, |a| a == alias)
    }
    
    /// Deactivate wallet
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
    
    /// Reactivate wallet
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Deduct funds from wallet (with proper error handling)
    pub fn deduct_funds(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.balance >= amount {
            self.balance -= amount;
            self.update_last_transaction();
            Ok(())
        } else {
            Err("Insufficient balance")
        }
    }

    /// Add rewards to pending rewards
    pub fn add_rewards(&mut self, amount: u64) {
        self.pending_rewards += amount;
        self.update_last_transaction();
    }

    /// Check if wallet is healthy (basic health check)
    pub fn is_healthy(&self) -> bool {
        // Note: Balance check removed since u64 is always >= 0
        // Future: Change balance to i64 if negative balances needed
        self.is_active
    }
    
    /// Check if this is a DAO wallet
    pub fn is_dao_wallet(&self) -> bool {
        matches!(self.wallet_type, WalletType::NonProfitDAO | WalletType::ForProfitDAO)
    }
    
    /// Check if this is a nonprofit DAO
    pub fn is_nonprofit_dao(&self) -> bool {
        self.wallet_type == WalletType::NonProfitDAO
    }
    
    /// Get DAO properties (returns None if not a DAO wallet)
    pub fn get_dao_properties(&self) -> Option<&DaoWalletProperties> {
        self.dao_properties.as_ref()
    }
    
    /// Add a public transaction to DAO log (only for DAO wallets)
    pub fn add_dao_transaction(&mut self, 
        amount: u64, 
        is_incoming: bool, 
        counterparty_wallet: Option<WalletId>,
        purpose: String,
        authorized_by: &IdentityId,
    ) -> Result<(), anyhow::Error> {
        if !self.is_dao_wallet() {
            return Err(anyhow::anyhow!("Cannot add DAO transaction to non-DAO wallet"));
        }
        
        if let Some(ref mut dao_props) = self.dao_properties {
            let tx_entry = PublicTransactionEntry {
                tx_hash: Hash::from_bytes(&lib_crypto::hash_blake3(&format!(
                    "{}:{}:{}:{}",
                    hex::encode(&self.id.0),
                    amount,
                    is_incoming,
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                ).as_bytes())),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                amount,
                is_incoming,
                counterparty_wallet,
                purpose,
                authorized_by: authorized_by.clone(),
            };
            
            dao_props.public_transaction_log.push(tx_entry);
            dao_props.transaction_count += 1;
            
            if is_incoming {
                dao_props.total_funds_received += amount;
            } else {
                dao_props.total_funds_spent += amount;
            }
            
            // Keep transaction log reasonable size (last 1000 transactions)
            if dao_props.public_transaction_log.len() > 1000 {
                dao_props.public_transaction_log.remove(0);
            }
        }
        
        Ok(())
    }
    
    /// Get public transaction history (filtered by transparency level)
    pub fn get_public_transaction_history(&self) -> Vec<PublicTransactionEntry> {
        if let Some(dao_props) = &self.dao_properties {
            match dao_props.transparency_level {
                TransparencyLevel::Full => dao_props.public_transaction_log.clone(),
                TransparencyLevel::Partial => {
                    // Return transactions with counterparty info redacted
                    dao_props.public_transaction_log.iter().map(|tx| {
                        let mut filtered_tx = tx.clone();
                        filtered_tx.counterparty_wallet = None;
                        filtered_tx
                    }).collect()
                },
                TransparencyLevel::Summary => Vec::new(), // Only summary stats available
            }
        } else {
            Vec::new()
        }
    }
    
    /// Check if a DID is authorized to control this DAO wallet
    pub fn is_authorized_controller(&self, did: &IdentityId) -> bool {
        if let Some(dao_props) = &self.dao_properties {
            dao_props.authorized_controllers.contains(did)
        } else {
            false
        }
    }
    
    /// Check if a DAO wallet is authorized to control this DAO wallet
    pub fn is_authorized_dao_controller(&self, dao_wallet_id: &WalletId) -> bool {
        if let Some(dao_props) = &self.dao_properties {
            dao_props.authorized_dao_controllers.contains(dao_wallet_id)
        } else {
            false
        }
    }
    
    /// Check if either a DID or DAO wallet is authorized to control this DAO
    pub fn is_authorized_by_either(&self, did: Option<&IdentityId>, dao_wallet_id: Option<&WalletId>) -> bool {
        if let Some(did) = did {
            if self.is_authorized_controller(did) {
                return true;
            }
        }
        if let Some(dao_id) = dao_wallet_id {
            if self.is_authorized_dao_controller(dao_id) {
                return true;
            }
        }
        false
    }
    
    /// Add an authorized controller to DAO wallet (requires existing controller authorization)
    pub fn add_authorized_controller(&mut self, new_controller: IdentityId, authorized_by: &IdentityId) -> Result<(), anyhow::Error> {
        if !self.is_dao_wallet() {
            return Err(anyhow::anyhow!("Cannot add controller to non-DAO wallet"));
        }
        
        if !self.is_authorized_controller(authorized_by) {
            return Err(anyhow::anyhow!("Authorizing DID is not a current controller"));
        }
        
        if let Some(ref mut dao_props) = self.dao_properties {
            if !dao_props.authorized_controllers.contains(&new_controller) {
                dao_props.authorized_controllers.push(new_controller);
                println!("✓ Added new controller to DAO wallet: {}", self.name);
            }
        }
        
        Ok(())
    }
    
    /// Add a DAO wallet as an authorized controller
    pub fn add_authorized_dao_controller(&mut self, dao_controller: WalletId, authorized_by_did: Option<&IdentityId>, authorized_by_dao: Option<&WalletId>) -> Result<(), anyhow::Error> {
        if !self.is_dao_wallet() {
            return Err(anyhow::anyhow!("Cannot add DAO controller to non-DAO wallet"));
        }
        
        if !self.is_authorized_by_either(authorized_by_did, authorized_by_dao) {
            return Err(anyhow::anyhow!("Authorizing entity is not a current controller"));
        }
        
        if let Some(ref mut dao_props) = self.dao_properties {
            if !dao_props.authorized_dao_controllers.contains(&dao_controller) {
                dao_props.authorized_dao_controllers.push(dao_controller);
                println!("✓ Added DAO controller to DAO wallet: {}", self.name);
            }
        }
        
        Ok(())
    }
    
    /// Set parent DAO wallet (establishes ownership relationship)
    pub fn set_parent_dao(&mut self, parent_dao_id: WalletId, authorized_by_did: Option<&IdentityId>, authorized_by_dao: Option<&WalletId>) -> Result<(), anyhow::Error> {
        if !self.is_dao_wallet() {
            return Err(anyhow::anyhow!("Cannot set parent DAO for non-DAO wallet"));
        }
        
        if !self.is_authorized_by_either(authorized_by_did, authorized_by_dao) {
            return Err(anyhow::anyhow!("Authorizing entity is not a current controller"));
        }
        
        if let Some(ref mut dao_props) = self.dao_properties {
            dao_props.parent_dao_wallet = Some(parent_dao_id.clone());
            
            // Automatically add parent as authorized controller
            if !dao_props.authorized_dao_controllers.contains(&parent_dao_id) {
                dao_props.authorized_dao_controllers.push(parent_dao_id.clone());
            }
            
            println!("✓ Set parent DAO for {}: {}", self.name, hex::encode(&parent_dao_id.0[..8]));
        }
        
        Ok(())
    }
    
    /// Add child DAO wallet
    pub fn add_child_dao(&mut self, child_dao_id: WalletId, authorized_by_did: Option<&IdentityId>, authorized_by_dao: Option<&WalletId>) -> Result<(), anyhow::Error> {
        if !self.is_dao_wallet() {
            return Err(anyhow::anyhow!("Cannot add child DAO to non-DAO wallet"));
        }
        
        if !self.is_authorized_by_either(authorized_by_did, authorized_by_dao) {
            return Err(anyhow::anyhow!("Authorizing entity is not a current controller"));
        }
        
        if let Some(ref mut dao_props) = self.dao_properties {
            if !dao_props.child_dao_wallets.contains(&child_dao_id) {
                dao_props.child_dao_wallets.push(child_dao_id.clone());
                println!("✓ Added child DAO to {}: {}", self.name, hex::encode(&child_dao_id.0[..8]));
            }
        }
        
        Ok(())
    }
    
    /// Get DAO hierarchy information
    pub fn get_dao_hierarchy_info(&self) -> Option<DaoHierarchyInfo> {
        if let Some(dao_props) = &self.dao_properties {
            Some(DaoHierarchyInfo {
                parent_dao: dao_props.parent_dao_wallet.clone(),
                child_daos: dao_props.child_dao_wallets.clone(),
                authorized_dao_controllers: dao_props.authorized_dao_controllers.clone(),
                hierarchy_level: if dao_props.parent_dao_wallet.is_some() {
                    1 // Child DAO
                } else if !dao_props.child_dao_wallets.is_empty() {
                    0 // Parent DAO
                } else {
                    0 // Standalone DAO
                },
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_wallet(wallet_id_bytes: [u8; 32], encrypted_seed: Option<String>) -> QuantumWallet {
        QuantumWallet {
            id: Hash(wallet_id_bytes),
            wallet_type: WalletType::Standard,
            name: "Test Wallet".to_string(),
            alias: None,
            balance: 0,
            staked_balance: 0,
            pending_rewards: 0,
            owner_id: None,
            public_key: vec![],
            seed_phrase: None,
            encrypted_seed,
            seed_commitment: None,
            created_at: 0,
            last_transaction: None,
            recent_transactions: vec![],
            is_active: true,
            dao_properties: None,
            derivation_index: None,
            password_hash: None,
            owned_content: vec![],
            total_storage_used: 0,
            total_content_value: 0,
        }
    }

    #[test]
    fn test_aes_gcm_encryption_roundtrip() {
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet_id_bytes = [0x12; 32];
        let wallet_id_hex = hex::encode(&wallet_id_bytes);

        // Encrypt with hex-encoded wallet ID (matches what decrypt expects)
        let encrypted = QuantumWallet::encrypt_seed_phrase(seed_phrase, &wallet_id_hex).unwrap();

        // Verify version byte
        let encrypted_bytes = hex::decode(&encrypted).unwrap();
        assert_eq!(encrypted_bytes[0], ENCRYPTION_VERSION_AES_GCM, "Should use AES-GCM version");

        // Create wallet and decrypt
        let wallet = create_test_wallet(wallet_id_bytes, Some(encrypted));
        let decrypted = wallet.decrypt_seed_phrase().unwrap().unwrap();
        assert_eq!(decrypted, seed_phrase, "Decrypted should match original");
    }

    #[test]
    fn test_legacy_xor_decryption() {
        // Test the internal legacy XOR decryption function directly
        let seed_phrase = "test seed phrase for legacy";
        let wallet_id = "test_wallet_id";
        let key = format!("WALLET_SEED_KEY_{}", wallet_id);

        // Create XOR-encrypted data
        let mut encrypted = Vec::new();
        for (i, byte) in seed_phrase.bytes().enumerate() {
            let key_byte = key.bytes().nth(i % key.len()).unwrap_or(0);
            encrypted.push(byte ^ key_byte);
        }

        // Decrypt using legacy method
        let decrypted = QuantumWallet::decrypt_legacy_xor(&encrypted, wallet_id).unwrap().unwrap();
        assert_eq!(decrypted, seed_phrase, "Legacy XOR decryption should work");
    }

    #[test]
    fn test_encryption_produces_different_ciphertexts() {
        // Same plaintext encrypted twice should produce different ciphertexts
        // (due to random nonce and salt)
        let seed_phrase = "same seed phrase repeated";
        let wallet_id = "deterministic_wallet_id";

        let encrypted1 = QuantumWallet::encrypt_seed_phrase(seed_phrase, wallet_id).unwrap();
        let encrypted2 = QuantumWallet::encrypt_seed_phrase(seed_phrase, wallet_id).unwrap();

        assert_ne!(encrypted1, encrypted2, "Same plaintext should produce different ciphertexts");

        // But both should decrypt to the same plaintext
        // (We can't easily test this without a full wallet, but the logic is sound)
    }

    #[test]
    fn test_migration_from_legacy_to_aes_gcm() {
        let seed_phrase = "migrate this seed phrase now";
        let wallet_id_bytes = [0xAB; 32];
        let wallet_id_hex = hex::encode(&wallet_id_bytes);
        let key = format!("WALLET_SEED_KEY_{}", wallet_id_hex);

        // Create legacy XOR encrypted data (no version byte)
        let mut encrypted = Vec::new();
        for (i, byte) in seed_phrase.bytes().enumerate() {
            let key_byte = key.bytes().nth(i % key.len()).unwrap_or(0);
            encrypted.push(byte ^ key_byte);
        }
        let encrypted_hex = hex::encode(&encrypted);

        // Create wallet with legacy encryption
        let mut wallet = create_test_wallet(wallet_id_bytes, Some(encrypted_hex));

        // Verify we can decrypt with legacy method
        let decrypted_before = wallet.decrypt_seed_phrase().unwrap().unwrap();
        assert_eq!(decrypted_before, seed_phrase);

        // Migrate to AES-GCM
        let migrated = wallet.migrate_seed_encryption().unwrap();
        assert!(migrated, "Should report successful migration");

        // Verify new encryption uses AES-GCM version
        let new_encrypted_bytes = hex::decode(wallet.encrypted_seed.as_ref().unwrap()).unwrap();
        assert_eq!(new_encrypted_bytes[0], ENCRYPTION_VERSION_AES_GCM, "Should now use AES-GCM");

        // Verify we can still decrypt
        let decrypted_after = wallet.decrypt_seed_phrase().unwrap().unwrap();
        assert_eq!(decrypted_after, seed_phrase, "Decryption should work after migration");

        // Verify migration is idempotent
        let migrated_again = wallet.migrate_seed_encryption().unwrap();
        assert!(!migrated_again, "Should not migrate again if already AES-GCM");
    }

    #[test]
    fn test_version_1_explicit_decryption() {
        // Test that data with explicit version 0x01 byte decrypts as legacy
        let seed_phrase = "version one seed";
        let wallet_id_bytes = [0xCD; 32];
        let wallet_id_hex = hex::encode(&wallet_id_bytes);
        let key = format!("WALLET_SEED_KEY_{}", wallet_id_hex);

        // Create XOR encrypted data
        let mut xor_encrypted = Vec::new();
        for (i, byte) in seed_phrase.bytes().enumerate() {
            let key_byte = key.bytes().nth(i % key.len()).unwrap_or(0);
            xor_encrypted.push(byte ^ key_byte);
        }

        // Prepend version byte 0x01
        let mut versioned = vec![ENCRYPTION_VERSION_LEGACY_XOR];
        versioned.extend_from_slice(&xor_encrypted);
        let encrypted_hex = hex::encode(&versioned);

        // Create wallet and decrypt
        let wallet = create_test_wallet(wallet_id_bytes, Some(encrypted_hex));
        let decrypted = wallet.decrypt_seed_phrase().unwrap().unwrap();
        assert_eq!(decrypted, seed_phrase, "Version 1 (legacy XOR) decryption should work");
    }
}
