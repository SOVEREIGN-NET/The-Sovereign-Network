//! Identity Registry Service
//!
//! Private service responsible for storage and retrieval of identity data.
//! This service provides CRUD operations for identities and their associated private data.

use std::collections::HashMap;
use anyhow::{Result, anyhow};

use crate::types::IdentityId;
use crate::identity::{ZhtpIdentity, PrivateIdentityData};

/// Private service for identity storage operations
/// 
/// This service manages the storage of public identity data and private cryptographic
/// data. It provides simple CRUD operations without business logic.
#[derive(Debug)]
pub(crate) struct IdentityRegistry {
    /// Public identity data (accessible to network)
    identities: HashMap<IdentityId, ZhtpIdentity>,
    /// Private cryptographic data (kept secure, never exposed to network)
    private_data: HashMap<IdentityId, PrivateIdentityData>,
}

impl IdentityRegistry {
    /// Create a new empty identity registry
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            private_data: HashMap::new(),
        }
    }

    // ===== Read Operations =====

    /// Get immutable reference to an identity by ID
    pub fn get_identity(&self, identity_id: &IdentityId) -> Option<&ZhtpIdentity> {
        self.identities.get(identity_id)
    }

    /// Get mutable reference to an identity by ID
    /// 
    /// Used when services need to modify identity data (e.g., adding credentials,
    /// updating reputation, recording transactions)
    pub fn get_identity_mut(&mut self, identity_id: &IdentityId) -> Option<&mut ZhtpIdentity> {
        self.identities.get_mut(identity_id)
    }

    /// Get private data for an identity
    /// 
    /// Returns the private cryptographic data needed for signing operations.
    /// This should only be accessed by services that need to perform cryptographic operations.
    pub fn get_private_data(&self, identity_id: &IdentityId) -> Option<&PrivateIdentityData> {
        self.private_data.get(identity_id)
    }

    /// List all registered identities
    /// 
    /// Returns a vector of references to all identities in the registry.
    /// Useful for queries, reporting, and administrative operations.
    pub fn list_identities(&self) -> Vec<&ZhtpIdentity> {
        self.identities.values().collect()
    }

    /// Check if an identity exists in the registry
    pub fn contains_identity(&self, identity_id: &IdentityId) -> bool {
        self.identities.contains_key(identity_id)
    }

    /// Check if private data exists for an identity
    pub fn has_private_data(&self, identity_id: &IdentityId) -> bool {
        self.private_data.contains_key(identity_id)
    }

    /// Get the number of identities in the registry
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    // ===== Write Operations =====

    /// Add a public identity to the registry
    /// 
    /// Use this for identities that don't need signing capability (e.g., remote
    /// identities discovered from the network).
    pub fn add_identity(&mut self, identity: ZhtpIdentity) {
        let identity_id = identity.id.clone();
        self.identities.insert(identity_id, identity);
    }

    /// Add an identity with its private cryptographic data
    /// 
    /// Use this for locally-owned identities that need signing capability
    /// (e.g., genesis identities, imported identities, newly created citizens).
    pub fn add_identity_with_private_data(
        &mut self,
        identity: ZhtpIdentity,
        private_data: PrivateIdentityData,
    ) {
        let identity_id = identity.id.clone();
        self.identities.insert(identity_id.clone(), identity);
        self.private_data.insert(identity_id, private_data);
    }

    /// Remove an identity from the registry
    /// 
    /// Removes both public identity data and private data (if present).
    /// Returns the removed identity if it existed.
    pub fn remove_identity(&mut self, identity_id: &IdentityId) -> Option<ZhtpIdentity> {
        // Remove private data if present
        self.private_data.remove(identity_id);
        // Remove and return public identity
        self.identities.remove(identity_id)
    }

    // ===== Bulk Operations =====

    /// Sync wallet balances from blockchain data
    /// 
    /// This method updates in-memory wallet balances based on data provided
    /// from the blockchain layer. It keeps the sync logic agnostic of blockchain
    /// implementation details and avoids circular dependencies.
    /// 
    /// # Arguments
    /// * `wallet_balances` - HashMap of wallet_id (hex string) to balance (u64)
    pub fn sync_wallet_balances(
        &mut self,
        wallet_balances: &HashMap<String, u64>,
    ) -> Result<()> {
        let mut total_synced = 0u64;
        let mut wallets_updated = 0usize;

        tracing::info!("🔄 Starting wallet balance sync from blockchain data...");
        tracing::debug!("Received {} wallet balance entries from blockchain", wallet_balances.len());

        // Iterate through all identities
        for (identity_id, identity) in self.identities.iter_mut() {
            let identity_id_hex = hex::encode(&identity_id.0[..8]);
            
            // Iterate through all wallets owned by this identity
            for (wallet_id, wallet) in identity.wallet_manager.wallets.iter_mut() {
                let wallet_id_hex = hex::encode(&wallet_id.0[..8]);
                let wallet_id_full_hex = hex::encode(&wallet_id.0);
                let old_balance = wallet.balance;

                // Query provided balance data for this wallet
                let new_balance = wallet_balances.get(&wallet_id_full_hex)
                    .copied()
                    .unwrap_or(old_balance);

                // Update balance if changed
                if new_balance != old_balance {
                    wallet.balance = new_balance;
                    total_synced += new_balance;
                    wallets_updated += 1;

                    tracing::info!(
                        "  ✓ Synced wallet {} ({:?}) for identity {}: {} ZHTP → {} ZHTP",
                        wallet_id_hex,
                        wallet.wallet_type,
                        identity_id_hex,
                        old_balance,
                        new_balance
                    );
                }
            }
        }

        if wallets_updated > 0 {
            tracing::info!(
                "✅ Wallet balance sync complete: {} wallets updated, {} ZHTP total synced",
                wallets_updated,
                total_synced
            );
        } else {
            tracing::warn!("⚠️  Wallet balance sync found no changes to apply");
            tracing::info!("   This is normal if genesis didn't fund user wallets or no transactions occurred");
        }

        Ok(())
    }

    /// Deduct balance from an identity's primary wallet
    /// 
    /// This updates the in-memory wallet balance. For blockchain persistence,
    /// the caller should also create a proper blockchain transaction.
    /// 
    /// Returns (old_balance, new_balance, transaction_hash, wallet_public_key)
    pub fn deduct_wallet_balance(
        &mut self,
        identity_id: &IdentityId,
        amount: u64,
        purpose: &str,
    ) -> Result<(u64, u64, lib_crypto::Hash, Vec<u8>)> {
        let identity = self.identities.get_mut(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        // Get primary wallet
        let primary_wallet = identity.wallet_manager.wallets.values_mut().next()
            .ok_or_else(|| anyhow!("No wallet found for identity"))?;
        
        // Check balance
        if primary_wallet.balance < amount {
            return Err(anyhow!(
                "Insufficient balance: {} ZHTP available, {} ZHTP required",
                primary_wallet.balance,
                amount
            ));
        }
        
        let old_balance = primary_wallet.balance;
        primary_wallet.balance -= amount;
        let new_balance = primary_wallet.balance;
        let wallet_pubkey = primary_wallet.public_key.clone();
        
        // Generate transaction hash
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let tx_hash_bytes = lib_crypto::hash_blake3(&[
            b"wallet_payment:",
            purpose.as_bytes(),
            &amount.to_le_bytes(),
            &current_time.to_le_bytes(),
            identity_id.0.as_slice(),
        ].concat());
        let tx_hash = lib_crypto::Hash::from_bytes(&tx_hash_bytes);
        
        // Record transaction in wallet
        primary_wallet.recent_transactions.push(tx_hash.clone());
        primary_wallet.last_transaction = Some(current_time);
        
        tracing::info!(
            "💳 Deducted {} ZHTP from wallet {} (balance: {} → {}) for: {}",
            amount,
            hex::encode(&primary_wallet.id.0[..8]),
            old_balance,
            new_balance,
            purpose
        );
        
        tracing::warn!(
            "⚠️  UTXO CONSUMPTION NOT IMPLEMENTED: This is in-memory accounting only. 
            Caller should create blockchain transaction consuming UTXOs for wallet pubkey: {}",
            hex::encode(&wallet_pubkey[..8])
        );
        
        Ok((old_balance, new_balance, tx_hash, wallet_pubkey))
    }

    /// Get payment transaction components for blockchain transaction creation
    /// 
    /// This method provides access to the wallet's private key for signing transactions.
    /// Returns (private_key_bytes, total_input, change_amount, wallet_pubkey)
    pub fn create_payment_transaction(
        &self,
        identity_id: &IdentityId,
        utxos_to_consume: Vec<(lib_crypto::Hash, u32, u64)>, // (utxo_hash, output_index, amount)
        _recipient_pubkey: &[u8],
        amount: u64,
        fee: u64,
    ) -> Result<(Vec<u8>, u64, u64, Vec<u8>)> {
        let identity = self.identities.get(identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        
        let private_data = self.private_data.get(identity_id)
            .ok_or_else(|| anyhow!("Private identity data not found"))?;
        
        // Get the wallet's private key
        let private_key_bytes = private_data.private_key().to_vec();
        
        // Calculate total input amount
        let total_input: u64 = utxos_to_consume.iter().map(|(_, _, amt)| amt).sum();
        
        // Calculate change amount
        let change = total_input.saturating_sub(amount + fee);
        
        // Get wallet public key for change output
        let primary_wallet = identity.wallet_manager.wallets.values().next()
            .ok_or_else(|| anyhow!("No wallet found"))?;
        let wallet_pubkey = primary_wallet.public_key.clone();
        
        Ok((private_key_bytes, total_input, change, wallet_pubkey))
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ZhtpIdentity;
    use crate::types::{IdentityType, AccessLevel};
    use lib_crypto::Hash;
    use lib_proofs::ZeroKnowledgeProof;

    fn create_test_identity(id_byte: u8) -> ZhtpIdentity {
        let id = Hash::from_bytes(&[id_byte; 32]);
        ZhtpIdentity {
            id: id.clone(),
            identity_type: IdentityType::Human,
            public_key: vec![1, 2, 3],
            ownership_proof: ZeroKnowledgeProof {
                proof_system: "test".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            credentials: HashMap::new(),
            reputation: 100,
            age: None,
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: Some(id.clone()),
            wallet_manager: crate::wallets::IdentityWallets::new(id),
            attestations: Vec::new(),
            created_at: 0,
            last_active: 0,
            recovery_keys: vec![],
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
        }
    }

    fn create_test_private_data() -> PrivateIdentityData {
        PrivateIdentityData::new(
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            [0u8; 64],
            vec![],
        )
    }

    #[test]
    fn test_new_registry() {
        let registry = IdentityRegistry::new();
        assert_eq!(registry.identity_count(), 0);
    }

    #[test]
    fn test_add_and_get_identity() {
        let mut registry = IdentityRegistry::new();
        let identity = create_test_identity(1);
        let id = identity.id.clone();

        registry.add_identity(identity);

        assert_eq!(registry.identity_count(), 1);
        assert!(registry.contains_identity(&id));
        assert!(registry.get_identity(&id).is_some());
        assert!(!registry.has_private_data(&id));
    }

    #[test]
    fn test_add_identity_with_private_data() {
        let mut registry = IdentityRegistry::new();
        let identity = create_test_identity(1);
        let private_data = create_test_private_data();
        let id = identity.id.clone();

        registry.add_identity_with_private_data(identity, private_data);

        assert_eq!(registry.identity_count(), 1);
        assert!(registry.contains_identity(&id));
        assert!(registry.has_private_data(&id));
        assert!(registry.get_private_data(&id).is_some());
    }

    #[test]
    fn test_get_identity_mut() {
        let mut registry = IdentityRegistry::new();
        let identity = create_test_identity(1);
        let id = identity.id.clone();

        registry.add_identity(identity);

        // Modify through mutable reference
        if let Some(identity) = registry.get_identity_mut(&id) {
            identity.reputation = 500;
        }

        // Verify modification
        assert_eq!(registry.get_identity(&id).unwrap().reputation, 500);
    }

    #[test]
    fn test_list_identities() {
        let mut registry = IdentityRegistry::new();
        
        registry.add_identity(create_test_identity(1));
        registry.add_identity(create_test_identity(2));
        registry.add_identity(create_test_identity(3));

        let identities = registry.list_identities();
        assert_eq!(identities.len(), 3);
    }

    #[test]
    fn test_remove_identity() {
        let mut registry = IdentityRegistry::new();
        let identity = create_test_identity(1);
        let private_data = create_test_private_data();
        let id = identity.id.clone();

        registry.add_identity_with_private_data(identity, private_data);
        assert_eq!(registry.identity_count(), 1);
        assert!(registry.has_private_data(&id));

        let removed = registry.remove_identity(&id);
        assert!(removed.is_some());
        assert_eq!(registry.identity_count(), 0);
        assert!(!registry.has_private_data(&id));
    }

    #[test]
    fn test_contains_identity() {
        let mut registry = IdentityRegistry::new();
        let identity = create_test_identity(1);
        let id = identity.id.clone();

        assert!(!registry.contains_identity(&id));
        registry.add_identity(identity);
        assert!(registry.contains_identity(&id));
    }
}
