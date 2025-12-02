//! Wallet manager integration from the original identity.rs
//! 
//! This provides the WalletManager that was integrated into ZhtpIdentity

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use lib_crypto::Hash;
use crate::types::IdentityId;
use super::wallet_types::{WalletType, WalletId, QuantumWallet, WalletSummary};
use super::wallet_password::{WalletPasswordManager, WalletPasswordError, WalletPasswordValidation};

/// Integrated wallet manager for identity-based wallet management
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletManager {
    /// Owner identity ID (optional for standalone wallet manager)
    pub owner_id: Option<IdentityId>,
    /// Map of wallet ID to wallet
    pub wallets: HashMap<WalletId, QuantumWallet>,
    /// Map of alias to wallet ID for quick lookup
    pub alias_map: HashMap<String, WalletId>,
    /// Total balance across all wallets
    pub total_balance: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Optional password protection for individual wallets
    #[serde(skip)]
    pub wallet_password_manager: WalletPasswordManager,
    /// Optional master seed for deterministic wallet recovery (not serialized)
    #[serde(skip)]
    pub master_seed: Option<[u8; 64]>,
}

impl WalletManager {
    /// Create a new wallet manager for an identity
    pub fn new(owner_id: IdentityId) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            owner_id: Some(owner_id),
            wallets: HashMap::new(),
            alias_map: HashMap::new(),
            total_balance: 0,
            created_at: current_time,
            wallet_password_manager: WalletPasswordManager::new(),
            master_seed: None,
        }
    }

    /// Create a new wallet manager seeded for deterministic recovery
    pub fn from_master_seed(owner_id: IdentityId, master_seed: [u8; 64]) -> Self {
        let mut manager = Self::new(owner_id);
        manager.master_seed = Some(master_seed);
        manager
    }
    
    /// DEPRECATED: Standalone wallets are no longer allowed
    /// All wallets must be attached to an identity
    /// Use WalletManager::new(identity_id) instead
    #[deprecated(
        since = "0.2.0",
        note = "Wallets must be attached to an identity. Use WalletManager::new(identity_id) instead."
    )]
    pub fn new_standalone() -> Self {
        panic!("Standalone wallets are not allowed. All wallets must be attached to an identity. Use WalletManager::new(identity_id) instead.");
    }
    
    // Note: Basic wallet creation removed - use create_wallet_with_seed_phrase() for all wallets
    // This ensures consistent seed phrase support across all wallet types
    
    /// Create a new wallet with 20-word seed phrase
    pub async fn create_wallet_with_seed_phrase(
        &mut self,
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
    ) -> Result<(WalletId, crate::recovery::RecoveryPhrase)> {
        // Check if alias already exists
        if let Some(ref alias) = alias {
            if self.alias_map.contains_key(alias) {
                return Err(anyhow!("Wallet alias '{}' already exists", alias));
            }
        }
        
        // Generate quantum-resistant public key
        let mut public_key = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut public_key);
        
        // Create the wallet with seed phrase
        let wallet = QuantumWallet::new_with_seed_phrase(
            wallet_type.clone(),
            name.clone(),
            alias.clone(),
            self.owner_id.clone(),
            public_key,
        ).await?;
        
        let wallet_id = wallet.id.clone();
        let seed_phrase = wallet.seed_phrase.clone().unwrap();
        
        // Store wallet
        self.wallets.insert(wallet_id.clone(), wallet);
        
        // Store alias mapping if provided
        if let Some(alias) = alias {
            self.alias_map.insert(alias, wallet_id.clone());
        }
        
        println!("WALLET 20-WORD SEED PHRASE:");
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│ {}   │", seed_phrase.words.join(" "));
        println!("└─────────────────────────────────────────────────────────────┘");
        println!(" CRITICAL SECURITY NOTICE:");
        println!("   • Write down these 20 words in the exact order shown");
        println!("   • Store in multiple secure, offline locations");
        println!("   • This phrase can recover your entire wallet on any device");
        println!("   • Never share, email, or store digitally");
        println!("   • Loss of this phrase = permanent loss of wallet access");
        
        if let Some(ref owner_id) = self.owner_id {
            tracing::info!(
                "Created wallet {} with seed phrase for identity {}",
                hex::encode(&wallet_id.0[..8]),
                hex::encode(&owner_id.0[..8])
            );
        } else {
            tracing::info!(
                "Created standalone wallet {} with seed phrase",
                hex::encode(&wallet_id.0[..8])
            );
        }

        // Emit wallet creation event for blockchain registration
        // The higher-level orchestrator (ZHTP server) will handle blockchain recording
        let owner_display = self.owner_id.as_ref().map(|id| hex::encode(&id.0[..8]));
        tracing::info!(
            " WALLET_CREATED_EVENT: wallet_id={}, type={:?}, name={}, owner_id={:?}",
            hex::encode(&wallet_id.0[..8]),
            wallet_type,
            name,
            owner_display
        );
        
        Ok((wallet_id, seed_phrase))
    }
    
    /// Recover wallet from 20-word seed phrase
    pub async fn recover_wallet_from_seed_phrase(
        &mut self,
        seed_words: &[String],
        wallet_name: String,
        alias: Option<String>,
    ) -> Result<WalletId> {
        if seed_words.len() != 20 {
            return Err(anyhow!("Exactly 20 seed phrase words required for wallet recovery"));
        }
        
        // Reconstruct seed phrase
        let seed_phrase = crate::recovery::RecoveryPhrase {
            words: seed_words.to_vec(),
            entropy: vec![], // Would be reconstructed in implementation
            checksum: String::new(), // Would be validated in implementation
            language: "english".to_string(),
            word_count: 20,
        };
        
        // Generate deterministic wallet from seed phrase
        let seed_text = seed_words.join(" ");
        let wallet_seed = lib_crypto::hash_blake3(seed_text.as_bytes());
        
        // Generate quantum-resistant public key from seed
        let mut public_key = vec![0u8; 32];
        public_key.copy_from_slice(&wallet_seed[..32]);
        
        // Create recovered wallet
        let mut wallet = QuantumWallet::new(
            WalletType::Standard, // Default type for recovered wallets
            wallet_name,
            alias.clone(),
            self.owner_id.clone(),
            public_key,
        );
        
        // Set seed phrase information
        wallet.seed_phrase = Some(seed_phrase);
        wallet.encrypted_seed = Some(QuantumWallet::encrypt_seed_phrase(&seed_text, &hex::encode(&wallet.id.0))?);
        
        // Generate seed commitment
        let commitment_hash = lib_crypto::hash_blake3(format!("ZHTP_WALLET_SEED:{}", seed_text).as_bytes());
        wallet.seed_commitment = Some(format!("zhtp:wallet:commitment:{}", hex::encode(commitment_hash)));
        
        let wallet_id = wallet.id.clone();
        
        // Store wallet
        self.wallets.insert(wallet_id.clone(), wallet);
        
        // Store alias mapping if provided
        if let Some(alias) = alias {
            self.alias_map.insert(alias, wallet_id.clone());
        }
        
        println!("Wallet recovered successfully from seed phrase");
        println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
        
        Ok(wallet_id)
    }
    
    /// Get wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&QuantumWallet> {
        self.wallets.get(wallet_id)
    }
    
    /// Get mutable wallet by ID
    pub fn get_wallet_mut(&mut self, wallet_id: &WalletId) -> Option<&mut QuantumWallet> {
        self.wallets.get_mut(wallet_id)
    }
    
    /// Get wallet by alias
    pub fn get_wallet_by_alias(&self, alias: &str) -> Option<&QuantumWallet> {
        self.alias_map.get(alias)
            .and_then(|wallet_id| self.wallets.get(wallet_id))
    }
    
    /// Get mutable wallet by alias
    pub fn get_wallet_by_alias_mut(&mut self, alias: &str) -> Option<&mut QuantumWallet> {
        let wallet_id = self.alias_map.get(alias).cloned();
        wallet_id.and_then(move |id| self.wallets.get_mut(&id))
    }
    
    /// List all wallets
    pub fn list_wallets(&self) -> Vec<WalletSummary> {
        self.wallets.values()
            .map(|wallet| wallet.to_summary())
            .collect()
    }
    
    /// Transfer funds between wallets
    pub fn transfer_between_wallets(
        &mut self,
        from_wallet: &WalletId,
        to_wallet: &WalletId,
        amount: u64,
        purpose: String,
    ) -> Result<Hash> {
        // Verify both wallets exist and belong to this identity
        if !self.wallets.contains_key(from_wallet) {
            return Err(anyhow!("Source wallet not found"));
        }
        if !self.wallets.contains_key(to_wallet) {
            return Err(anyhow!("Destination wallet not found"));
        }
        
        // Check source wallet has sufficient funds
        let source_balance = self.wallets[from_wallet].balance;
        if source_balance < amount {
            return Err(anyhow!("Insufficient funds in source wallet"));
        }
        
        // Generate transaction hash
        let tx_data = [
            from_wallet.as_bytes(),
            to_wallet.as_bytes(),
            &amount.to_le_bytes(),
            purpose.as_bytes(),
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_le_bytes(),
        ].concat();
        let tx_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&tx_data));
        
        // Perform the transfer
        self.wallets.get_mut(from_wallet).unwrap().remove_funds(amount).map_err(|e| anyhow!(e))?;
        self.wallets.get_mut(to_wallet).unwrap().add_funds(amount);
        
        // Add transaction to both wallets' history
        self.wallets.get_mut(from_wallet).unwrap().add_transaction(tx_hash.clone());
        self.wallets.get_mut(to_wallet).unwrap().add_transaction(tx_hash.clone());
        
        if let Some(ref owner_id) = self.owner_id {
            tracing::info!(
                "Transferred {} ZHTP from wallet {} to wallet {} for identity {} (purpose: {})",
                amount,
                hex::encode(&from_wallet.0[..8]),
                hex::encode(&to_wallet.0[..8]),
                hex::encode(&owner_id.0[..8]),
                purpose
            );
        } else {
            tracing::info!(
                "Transferred {} ZHTP from wallet {} to wallet {} (purpose: {})",
                amount,
                hex::encode(&from_wallet.0[..8]),
                hex::encode(&to_wallet.0[..8]),
                purpose
            );
        }
        
        Ok(tx_hash)
    }    /// Remove wallet (only if balance is zero)
    pub fn remove_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get(wallet_id) {
            if wallet.balance > 0 {
                return Err(anyhow!("Cannot remove wallet with non-zero balance"));
            }
            
            // Remove alias mapping if exists
            if let Some(ref alias) = wallet.alias {
                self.alias_map.remove(alias);
            }
        }
        
        // Remove wallet
        self.wallets.remove(wallet_id);
        // Recalculate total balance
        self.total_balance = self.wallets.values().map(|w| w.balance).sum();
        
        Ok(())
    }
    
    /// Deactivate wallet
    pub fn deactivate_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.deactivate();
            Ok(())
        } else {
            Err(anyhow!("Wallet not found"))
        }
    }
    
    /// Reactivate wallet
    pub fn reactivate_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.activate();
            Ok(())
        } else {
            Err(anyhow!("Wallet not found"))
        }
    }
    
    /// Get standalone wallet count
    pub fn standalone_wallet_count(&self) -> usize {
        self.wallets.values()
            .filter(|wallet| wallet.owner_id.is_none())
            .count()
    }
    
    /// Export wallet seed phrase (for backup)
    pub fn export_wallet_seed_phrase(&self, wallet_id: &WalletId) -> Result<Option<Vec<String>>> {
        if let Some(wallet) = self.wallets.get(wallet_id) {
            if let Some(ref seed_phrase) = wallet.seed_phrase {
                Ok(Some(seed_phrase.words.clone()))
            } else {
                Ok(None)
            }
        } else {
            Err(anyhow!("Wallet not found"))
        }
    }
    
    /// Check if wallet has seed phrase backup
    pub fn wallet_has_seed_phrase(&self, wallet_id: &WalletId) -> bool {
        self.wallets.get(wallet_id)
            .map(|wallet| wallet.seed_phrase.is_some())
            .unwrap_or(false)
    }
    
    /// Create a new DAO wallet (requires DID - cannot create standalone DAO wallets)
    pub async fn create_dao_wallet(
        &mut self,
        wallet_type: WalletType,
        creator_did: IdentityId,
        dao_name: String,
        dao_description: String,
        governance_settings: super::wallet_types::DaoGovernanceSettings,
        transparency_level: super::wallet_types::TransparencyLevel,
    ) -> Result<WalletId> {
        // Validate that we can create DAO wallets (require DID)
        if self.owner_id.is_none() {
            return Err(anyhow!("DAO wallets cannot be created without a DID. Standalone managers cannot create DAO wallets."));
        }
        
        // Validate wallet type is actually a DAO type
        if !matches!(wallet_type, WalletType::NonProfitDAO | WalletType::ForProfitDAO) {
            return Err(anyhow!("Invalid wallet type. Must be NonProfitDAO or ForProfitDAO"));
        }
        
        // Generate quantum-resistant public key
        let mut public_key = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut public_key);
        
        // Create the DAO wallet
        let wallet = QuantumWallet::new_dao_wallet(
            wallet_type.clone(),
            creator_did.clone(),
            dao_name.clone(),
            dao_description,
            public_key,
            governance_settings,
            transparency_level,
        ).await?;
        
        let wallet_id = wallet.id.clone();
        
        // Store wallet
        self.wallets.insert(wallet_id.clone(), wallet);
        
        // Log the DAO wallet creation
        match wallet_type {
            WalletType::NonProfitDAO => {
                tracing::info!(
                    "Created NonProfit DAO wallet {} by creator DID {} (no ownership)",
                    hex::encode(&wallet_id.0[..8]),
                    hex::encode(&creator_did.0[..8])
                );
            },
            WalletType::ForProfitDAO => {
                tracing::info!(
                    "Created ForProfit DAO wallet {} owned by creator DID {}",
                    hex::encode(&wallet_id.0[..8]),
                    hex::encode(&creator_did.0[..8])
                );
            },
            _ => unreachable!(),
        }
        
        Ok(wallet_id)
    }
    
    /// Get all DAO wallets
    pub fn get_dao_wallets(&self) -> Vec<&QuantumWallet> {
        self.wallets.values()
            .filter(|wallet| wallet.is_dao_wallet())
            .collect()
    }
    
    /// Get DAO wallets by type
    pub fn get_dao_wallets_by_type(&self, is_nonprofit: bool) -> Vec<&QuantumWallet> {
        self.wallets.values()
            .filter(|wallet| {
                if is_nonprofit {
                    wallet.wallet_type == WalletType::NonProfitDAO
                } else {
                    wallet.wallet_type == WalletType::ForProfitDAO
                }
            })
            .collect()
    }
    
    /// Add funds to DAO wallet with public transaction logging
    pub fn add_funds_to_dao_wallet(
        &mut self,
        wallet_id: &WalletId,
        amount: u64,
        counterparty_wallet: Option<WalletId>,
        purpose: String,
        authorized_by_did: Option<IdentityId>,
        authorized_by_dao: Option<WalletId>,
    ) -> Result<()> {
        if authorized_by_did.is_none() && authorized_by_dao.is_none() {
            return Err(anyhow!("Must provide either authorizing DID or DAO wallet"));
        }
        
        let wallet = self.wallets.get_mut(wallet_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        if !wallet.is_dao_wallet() {
            return Err(anyhow!("Cannot add DAO transaction to non-DAO wallet"));
        }
        
        // Validate authorization before any mutations
        if let Some(ref auth_dao_id) = authorized_by_dao {
            // Separate scope for checking authorization DAO
            {
                let auth_dao = self.wallets.get(auth_dao_id)
                    .ok_or_else(|| anyhow!("Authorizing DAO wallet not found"))?;
                if !auth_dao.is_dao_wallet() {
                    return Err(anyhow!("Authorizing wallet is not a DAO wallet"));
                }
            }
        }
        
        // Now we can safely get the wallet and check authorization
        let wallet = self.wallets.get_mut(wallet_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        // Check authorization (either by DID or by another DAO)
        if !wallet.is_authorized_by_either(authorized_by_did.as_ref(), authorized_by_dao.as_ref()) {
            return Err(anyhow!("Authorizing entity is not an authorized controller of this DAO"));
        }
        
        // Add funds to wallet
        wallet.add_funds(amount);
        
        // Log the public transaction (use DID if available, otherwise use the first authorized DID)
        let auth_did = authorized_by_did.clone().unwrap_or_else(|| {
            // If no DID provided, use the first authorized DID from the wallet
            wallet.dao_properties.as_ref().unwrap().authorized_controllers[0].clone()
        });
        
        wallet.add_dao_transaction(
            amount,
            true, // incoming
            counterparty_wallet,
            purpose,
            &auth_did,
        )?;
        
        self.calculate_total_balance();
        
        let auth_did_clone = authorized_by_did.clone();
        if let Some(did) = auth_did_clone {
            tracing::info!(
                "Added {} ZHTP to DAO wallet {} (authorized by DID {})",
                amount,
                hex::encode(&wallet_id.0[..8]),
                hex::encode(&did.0[..8])
            );
        } else if let Some(dao_id) = authorized_by_dao {
            tracing::info!(
                "Added {} ZHTP to DAO wallet {} (authorized by DAO {})",
                amount,
                hex::encode(&wallet_id.0[..8]),
                hex::encode(&dao_id.0[..8])
            );
        }
        
        Ok(())
    }
    
    /// Remove funds from DAO wallet with public transaction logging
    pub fn remove_funds_from_dao_wallet(
        &mut self,
        wallet_id: &WalletId,
        amount: u64,
        counterparty_wallet: Option<WalletId>,
        purpose: String,
        authorized_by_did: Option<IdentityId>,
        authorized_by_dao: Option<WalletId>,
    ) -> Result<()> {
        if authorized_by_did.is_none() && authorized_by_dao.is_none() {
            return Err(anyhow!("Must provide either authorizing DID or DAO wallet"));
        }
        
        // Validate authorization DAO first if provided
        if let Some(ref auth_dao_id) = authorized_by_dao {
            // Separate scope for checking authorization DAO
            {
                let auth_dao = self.wallets.get(auth_dao_id)
                    .ok_or_else(|| anyhow!("Authorizing DAO wallet not found"))?;
                if !auth_dao.is_dao_wallet() {
                    return Err(anyhow!("Authorizing wallet is not a DAO wallet"));
                }
            }
        }
        
        // Now get the target wallet
        let wallet = self.wallets.get_mut(wallet_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        if !wallet.is_dao_wallet() {
            return Err(anyhow!("Cannot add DAO transaction to non-DAO wallet"));
        }
        
        // Check authorization (either by DID or by another DAO)
        if !wallet.is_authorized_by_either(authorized_by_did.as_ref(), authorized_by_dao.as_ref()) {
            return Err(anyhow!("Authorizing entity is not an authorized controller of this DAO"));
        }
        
        // Check DAO governance rules
        if let Some(dao_props) = wallet.get_dao_properties() {
            if amount > dao_props.governance_settings.max_single_transaction {
                return Err(anyhow!(
                    "Transaction amount {} exceeds maximum single transaction limit {}",
                    amount,
                    dao_props.governance_settings.max_single_transaction
                ));
            }
        }
        
        // Remove funds from wallet
        wallet.remove_funds(amount).map_err(|e| anyhow!(e))?;
        
        // Log the public transaction (use DID if available, otherwise use the first authorized DID)
        let auth_did = authorized_by_did.clone().unwrap_or_else(|| {
            // If no DID provided, use the first authorized DID from the wallet
            wallet.dao_properties.as_ref().unwrap().authorized_controllers[0].clone()
        });
        
        wallet.add_dao_transaction(
            amount,
            false, // outgoing
            counterparty_wallet,
            purpose,
            &auth_did,
        )?;
        
        self.calculate_total_balance();
        
        if let Some(did) = authorized_by_did {
            tracing::info!(
                "Removed {} ZHTP from DAO wallet {} (authorized by DID {})",
                amount,
                hex::encode(&wallet_id.0[..8]),
                hex::encode(&did.0[..8])
            );
        } else if let Some(dao_id) = authorized_by_dao {
            tracing::info!(
                "Removed {} ZHTP from DAO wallet {} (authorized by DAO {})",
                amount,
                hex::encode(&wallet_id.0[..8]),
                hex::encode(&dao_id.0[..8])
            );
        }
        
        Ok(())
    }
    
    /// Get public transaction history for a DAO wallet
    pub fn get_dao_public_transactions(&self, wallet_id: &WalletId) -> Result<Vec<super::wallet_types::PublicTransactionEntry>> {
        let wallet = self.wallets.get(wallet_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        if !wallet.is_dao_wallet() {
            return Err(anyhow!("Wallet is not a DAO wallet"));
        }
        
        Ok(wallet.get_public_transaction_history())
    }
    
    /// Add authorized controller to DAO wallet
    pub fn add_dao_controller(
        &mut self,
        wallet_id: &WalletId,
        new_controller: IdentityId,
        authorized_by: IdentityId,
    ) -> Result<()> {
        let wallet = self.wallets.get_mut(wallet_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        wallet.add_authorized_controller(new_controller, &authorized_by)?;
        
        Ok(())
    }
    
    /// Establish parent-child relationship between two DAO wallets
    /// 
    /// Business Rules:
    /// - Non-profit DAOs cannot own or control for-profit DAOs
    /// - For-profit DAOs can own/control both non-profit and for-profit DAOs
    /// - Both parent and child must authorize the relationship
    pub fn establish_dao_hierarchy(
        &mut self,
        parent_dao_id: &WalletId,
        child_dao_id: &WalletId,
        authorized_by: IdentityId,
    ) -> Result<()> {
        // Verify parent DAO exists and is a DAO wallet
        if !self.wallets.get(parent_dao_id)
            .map(|w| w.is_dao_wallet())
            .unwrap_or(false) {
            return Err(anyhow!("Parent wallet is not a DAO wallet"));
        }
        
        // Verify child DAO exists and is a DAO wallet
        if !self.wallets.get(child_dao_id)
            .map(|w| w.is_dao_wallet())
            .unwrap_or(false) {
            return Err(anyhow!("Child wallet is not a DAO wallet"));
        }
        
        // Verify authorization on parent DAO
        if !self.wallets.get(parent_dao_id).unwrap().is_authorized_controller(&authorized_by) {
            return Err(anyhow!("Not authorized to modify parent DAO"));
        }
        
        // Verify authorization on child DAO
        if !self.wallets.get(child_dao_id).unwrap().is_authorized_controller(&authorized_by) {
            return Err(anyhow!("Not authorized to modify child DAO"));
        }
        
        // Business rule: Non-profit DAOs cannot own for-profit DAOs
        let parent_wallet_type = self.wallets.get(parent_dao_id).unwrap().wallet_type.clone();
        let child_wallet_type = self.wallets.get(child_dao_id).unwrap().wallet_type.clone();
        
        if parent_wallet_type == WalletType::NonProfitDAO && child_wallet_type == WalletType::ForProfitDAO {
            return Err(anyhow!(
                "Non-profit DAO cannot own or control a for-profit DAO. \
                This violates organizational governance rules."
            ));
        }
        
        // Set up parent-child relationship
        let parent_wallet = self.wallets.get_mut(parent_dao_id).unwrap();
        parent_wallet.add_child_dao(child_dao_id.clone(), Some(&authorized_by), None)?;
        
        let child_wallet = self.wallets.get_mut(child_dao_id).unwrap();
        child_wallet.set_parent_dao(parent_dao_id.clone(), Some(&authorized_by), None)?;
        
        tracing::info!(
            "Established DAO hierarchy: parent {} -> child {}",
            hex::encode(&parent_dao_id.0[..8]),
            hex::encode(&child_dao_id.0[..8])
        );
        
        Ok(())
    }
    
    /// Add a DAO as an authorized controller of another DAO
    /// 
    /// Business Rules:
    /// - Non-profit DAOs cannot be authorized as controllers of for-profit DAOs
    /// - For-profit DAOs can be controllers of both non-profit and for-profit DAOs
    /// - Target DAO must authorize the controller addition
    pub fn authorize_dao_controller(
        &mut self,
        target_dao_id: &WalletId,
        controller_dao_id: &WalletId,
        authorized_by: IdentityId,
    ) -> Result<()> {
        // Verify target DAO exists and is a DAO wallet
        if !self.wallets.get(target_dao_id)
            .map(|w| w.is_dao_wallet())
            .unwrap_or(false) {
            return Err(anyhow!("Target wallet is not a DAO wallet"));
        }
        
        // Verify controller DAO exists and is a DAO wallet
        if !self.wallets.get(controller_dao_id)
            .map(|w| w.is_dao_wallet())
            .unwrap_or(false) {
            return Err(anyhow!("Controller wallet is not a DAO wallet"));
        }
        
        // Verify authorization on target DAO
        if !self.wallets.get(target_dao_id).unwrap().is_authorized_controller(&authorized_by) {
            return Err(anyhow!("Not authorized to modify target DAO"));
        }
        
        // Business rule: Non-profit DAOs cannot control for-profit DAOs
        let controller_wallet_type = self.wallets.get(controller_dao_id).unwrap().wallet_type.clone();
        let target_wallet_type = self.wallets.get(target_dao_id).unwrap().wallet_type.clone();
        
        if controller_wallet_type == WalletType::NonProfitDAO && target_wallet_type == WalletType::ForProfitDAO {
            return Err(anyhow!(
                "Non-profit DAO cannot be authorized as controller of a for-profit DAO. \
                This violates organizational governance rules."
            ));
        }
        
        // Add DAO controller authorization
        let target_wallet = self.wallets.get_mut(target_dao_id).unwrap();
        target_wallet.add_authorized_dao_controller(controller_dao_id.clone(), Some(&authorized_by), None)?;
        
        tracing::info!(
            "Added DAO {} as authorized controller of DAO {}",
            hex::encode(&controller_dao_id.0[..8]),
            hex::encode(&target_dao_id.0[..8])
        );
        
        Ok(())
    }
    
    /// Get DAO hierarchy information
    pub fn get_dao_hierarchy_info(&self, dao_id: &WalletId) -> Result<super::wallet_types::DaoHierarchyInfo> {
        let wallet = self.wallets.get(dao_id)
            .ok_or_else(|| anyhow!("DAO wallet not found"))?;
        
        if !wallet.is_dao_wallet() {
            return Err(anyhow!("Wallet is not a DAO wallet"));
        }
        
        let dao_props = wallet.get_dao_properties()
            .ok_or_else(|| anyhow!("DAO properties not found"))?;
        
        // Calculate hierarchy level by traversing up the chain
        let mut hierarchy_level = 0;
        let mut current_parent = dao_props.parent_dao_wallet.clone();
        while let Some(parent_id) = current_parent {
            hierarchy_level += 1;
            if let Some(parent_wallet) = self.wallets.get(&parent_id) {
                if let Some(parent_props) = parent_wallet.get_dao_properties() {
                    current_parent = parent_props.parent_dao_wallet.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        Ok(super::wallet_types::DaoHierarchyInfo {
            parent_dao: dao_props.parent_dao_wallet.clone(),
            child_daos: dao_props.child_dao_wallets.clone(),
            authorized_dao_controllers: dao_props.authorized_dao_controllers.clone(),
            hierarchy_level,
        })
    }

    // ============================================================================
    // WALLET PASSWORD PROTECTION - Optional security for individual wallets
    // ============================================================================

    /// Set password for a specific wallet (optional security layer)
    pub fn set_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<(), WalletPasswordError> {
        // Verify wallet exists
        let wallet = self.wallets.get(wallet_id)
            .ok_or(WalletPasswordError::WalletNotFound)?;
        
        // Get wallet seed from seed phrase or generate deterministic seed
        let wallet_seed = if let Some(seed_phrase) = &wallet.seed_phrase {
            lib_crypto::hash_blake3(seed_phrase.to_string().as_bytes())
        } else {
            // Fallback: derive seed from wallet ID
            lib_crypto::hash_blake3(&[wallet_id.0.as_slice(), b"wallet_seed"].concat())
        };
        
        self.wallet_password_manager.set_wallet_password(wallet_id, password, &wallet_seed)
    }

    /// Change password for a wallet (requires old password)
    pub fn change_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), WalletPasswordError> {
        // Verify wallet exists
        let wallet = self.wallets.get(wallet_id)
            .ok_or(WalletPasswordError::WalletNotFound)?;
        
        // Get wallet seed
        let wallet_seed = if let Some(seed_phrase) = &wallet.seed_phrase {
            lib_crypto::hash_blake3(seed_phrase.to_string().as_bytes())
        } else {
            lib_crypto::hash_blake3(&[wallet_id.0.as_slice(), b"wallet_seed"].concat())
        };
        
        self.wallet_password_manager.change_wallet_password(
            wallet_id,
            old_password,
            new_password,
            &wallet_seed
        )
    }

    /// Remove password from a wallet (requires current password)
    pub fn remove_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        current_password: &str,
    ) -> Result<(), WalletPasswordError> {
        // Verify wallet exists
        let wallet = self.wallets.get(wallet_id)
            .ok_or(WalletPasswordError::WalletNotFound)?;
        
        // Get wallet seed
        let wallet_seed = if let Some(seed_phrase) = &wallet.seed_phrase {
            lib_crypto::hash_blake3(seed_phrase.to_string().as_bytes())
        } else {
            lib_crypto::hash_blake3(&[wallet_id.0.as_slice(), b"wallet_seed"].concat())
        };
        
        self.wallet_password_manager.remove_wallet_password(
            wallet_id,
            current_password,
            &wallet_seed
        )
    }

    /// Validate wallet password (use before wallet operations)
    pub fn validate_wallet_password(
        &self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<WalletPasswordValidation, WalletPasswordError> {
        // Verify wallet exists
        let wallet = self.wallets.get(wallet_id)
            .ok_or(WalletPasswordError::WalletNotFound)?;
        
        // Get wallet seed
        let wallet_seed = if let Some(seed_phrase) = &wallet.seed_phrase {
            lib_crypto::hash_blake3(seed_phrase.to_string().as_bytes())
        } else {
            lib_crypto::hash_blake3(&[wallet_id.0.as_slice(), b"wallet_seed"].concat())
        };
        
        self.wallet_password_manager.validate_password(wallet_id, password, &wallet_seed)
    }

    /// Check if wallet has password protection enabled
    pub fn wallet_has_password(&self, wallet_id: &WalletId) -> bool {
        self.wallet_password_manager.has_password(wallet_id)
    }

    /// Get list of all password-protected wallets
    pub fn list_password_protected_wallets(&self) -> Vec<&WalletId> {
        self.wallet_password_manager.list_password_protected_wallets()
    }

    /// Get count of password-protected wallets
    pub fn password_protected_wallet_count(&self) -> usize {
        self.wallet_password_manager.password_protected_count()
    }
}
