//! Wallet-Content Integration
//! Links content ownership with wallet management

use anyhow::{Result, anyhow};
use lib_crypto::Hash;
use lib_identity::wallets::wallet_types::{WalletId, ContentOwnershipRecord, ContentTransfer, ContentTransferType, ContentMetadataSnapshot};
use crate::types::ContentHash;
use crate::types::storage_types::ContentMetadata;
use std::collections::HashMap;

/// Manager for tracking content ownership by wallets
#[derive(Debug)]
pub struct WalletContentManager {
    /// Content ownership records (content_hash -> ownership record)
    ownership_records: HashMap<ContentHash, ContentOwnershipRecord>,
    /// Wallet content index (wallet_id -> Vec<content_hash>)
    wallet_content_index: HashMap<WalletId, Vec<ContentHash>>,
}

impl WalletContentManager {
    /// Create new wallet content manager
    pub fn new() -> Self {
        Self {
            ownership_records: HashMap::new(),
            wallet_content_index: HashMap::new(),
        }
    }
    
    /// Associate content with a wallet (after upload)
    pub fn register_content_ownership(
        &mut self,
        content_hash: ContentHash,
        wallet_id: WalletId,
        metadata: &ContentMetadata,
        purchase_price: u64,
    ) -> Result<()> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Create metadata snapshot
        let metadata_snapshot = ContentMetadataSnapshot {
            content_type: metadata.content_type.clone(),
            size: metadata.size,
            description: metadata.description.clone(),
            tags: metadata.tags.clone(),
            created_at: metadata.created_at,
        };
        
        // Create ownership record
        let ownership_record = ContentOwnershipRecord {
            content_hash: content_hash.clone(),
            owner_wallet_id: wallet_id.clone(),
            previous_owner: None,
            purchase_price,
            acquired_at: current_time,
            transfer_history: Vec::new(),
            metadata_snapshot,
        };
        
        // Store ownership record
        self.ownership_records.insert(content_hash.clone(), ownership_record);
        
        // Update wallet content index
        self.wallet_content_index
            .entry(wallet_id)
            .or_insert_with(Vec::new)
            .push(content_hash);
        
        Ok(())
    }
    
    /// Transfer content ownership from one wallet to another
    pub fn transfer_content_ownership(
        &mut self,
        content_hash: &ContentHash,
        from_wallet: WalletId,
        to_wallet: WalletId,
        price: u64,
        tx_hash: Hash,
        transfer_type: ContentTransferType,
    ) -> Result<()> {
        // Get ownership record
        let ownership_record = self.ownership_records.get_mut(content_hash)
            .ok_or_else(|| anyhow!("Content not found in ownership records"))?;
        
        // Verify current owner
        if ownership_record.owner_wallet_id != from_wallet {
            return Err(anyhow!("Transfer from wallet does not own this content"));
        }
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Create transfer record
        let transfer = ContentTransfer {
            from_wallet: from_wallet.clone(),
            to_wallet: to_wallet.clone(),
            price,
            timestamp: current_time,
            tx_hash,
            transfer_type,
        };
        
        // Update ownership record
        ownership_record.previous_owner = Some(from_wallet.clone());
        ownership_record.owner_wallet_id = to_wallet.clone();
        ownership_record.purchase_price = price;
        ownership_record.acquired_at = current_time;
        ownership_record.transfer_history.push(transfer);
        
        // Update wallet content indices
        // Remove from old wallet
        if let Some(content_list) = self.wallet_content_index.get_mut(&from_wallet) {
            content_list.retain(|h| h != content_hash);
        }
        
        // Add to new wallet
        self.wallet_content_index
            .entry(to_wallet)
            .or_insert_with(Vec::new)
            .push(content_hash.clone());
        
        Ok(())
    }
    
    /// Get all content owned by a wallet
    pub fn get_wallet_content(&self, wallet_id: &WalletId) -> Vec<ContentHash> {
        self.wallet_content_index
            .get(wallet_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Get ownership record for content
    pub fn get_ownership_record(&self, content_hash: &ContentHash) -> Option<&ContentOwnershipRecord> {
        self.ownership_records.get(content_hash)
    }
    
    /// Get owner wallet for content
    pub fn get_content_owner(&self, content_hash: &ContentHash) -> Option<WalletId> {
        self.ownership_records
            .get(content_hash)
            .map(|record| record.owner_wallet_id.clone())
    }
    
    /// Verify wallet owns content
    pub fn verify_ownership(&self, content_hash: &ContentHash, wallet_id: &WalletId) -> bool {
        self.ownership_records
            .get(content_hash)
            .map(|record| &record.owner_wallet_id == wallet_id)
            .unwrap_or(false)
    }
    
    /// Get content statistics for a wallet
    pub fn get_wallet_content_statistics(&self, wallet_id: &WalletId) -> WalletContentStatistics {
        let content_list = self.get_wallet_content(wallet_id);
        
        let mut total_size = 0u64;
        let mut total_value = 0u64;
        let mut content_types: HashMap<String, usize> = HashMap::new();
        
        for content_hash in &content_list {
            if let Some(record) = self.ownership_records.get(content_hash) {
                total_size += record.metadata_snapshot.size;
                total_value += record.purchase_price;
                *content_types.entry(record.metadata_snapshot.content_type.clone()).or_insert(0) += 1;
            }
        }
        
        WalletContentStatistics {
            wallet_id: wallet_id.clone(),
            total_items: content_list.len(),
            total_storage_bytes: total_size,
            total_value,
            content_types,
        }
    }
    
    /// Get all transfers for content
    pub fn get_content_transfer_history(&self, content_hash: &ContentHash) -> Vec<ContentTransfer> {
        self.ownership_records
            .get(content_hash)
            .map(|record| record.transfer_history.clone())
            .unwrap_or_default()
    }
}

/// Content statistics for a wallet
#[derive(Debug, Clone)]
pub struct WalletContentStatistics {
    pub wallet_id: WalletId,
    pub total_items: usize,
    pub total_storage_bytes: u64,
    pub total_value: u64,
    pub content_types: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_content_ownership_registration() {
        let mut manager = WalletContentManager::new();
        let content_hash = Hash::from_bytes(b"test_content_hash_32_bytes_long!");
        let wallet_id = Hash::from_bytes(b"test_wallet_id_32_bytes_long!!!!");
        
        let metadata = ContentMetadata {
            hash: content_hash.clone(),
            content_hash: content_hash.clone(),
            size: 1024,
            content_type: "text/plain".to_string(),
            description: "Test content".to_string(),
            tags: vec!["test".to_string()],
            created_at: 12345678,
            // ... other fields would be here
            owner: lib_identity::ZhtpIdentity::new(
                lib_identity::types::IdentityType::Human,
                vec![0u8; 32],
                lib_proofs::ZeroKnowledgeProof::new(
                    "test".to_string(),
                    vec![],
                    vec![],
                    vec![],
                    None,
                ),
            ).unwrap(),
            filename: "test.txt".to_string(),
            tier: crate::types::dht_types::StorageTier::Hot,
            encryption: crate::types::storage_types::EncryptionLevel::None,
            access_pattern: crate::types::storage_types::AccessPattern::Frequent,
            replication_factor: 3,
            total_chunks: 1,
            is_encrypted: false,
            is_compressed: false,
            access_control: vec![],
            cost_per_day: 100,
            last_accessed: 12345678,
            access_count: 0,
            expires_at: None,
            checksum: content_hash.clone(),
        };
        
        manager.register_content_ownership(content_hash.clone(), wallet_id.clone(), &metadata, 0).unwrap();
        
        // Verify ownership
        assert!(manager.verify_ownership(&content_hash, &wallet_id));
        
        // Verify wallet content
        let wallet_content = manager.get_wallet_content(&wallet_id);
        assert_eq!(wallet_content.len(), 1);
        assert_eq!(wallet_content[0], content_hash);
    }
}
