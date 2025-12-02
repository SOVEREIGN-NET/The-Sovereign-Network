use anyhow::Result;
use std::path::PathBuf;
use lib_crypto::hash_blake3;
use crate::protocols::NetworkProtocol;
use crate::mesh::server::{ZhtpMeshServer, NetworkConfig};

/// Create a test mesh server for development with implementations
pub async fn create_test_mesh_server() -> Result<ZhtpMeshServer> {
    use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
    use lib_identity::{ZhtpIdentity, IdentityType, NodeId};
    
    // Create a proper identity using new_unified (seed-anchored architecture)
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),  // age
        Some("US".to_string()),  // jurisdiction
        "test-device",  // primary device
        None,  // random seed
    )?;
    
    // Use the identity's NodeId (already derived from DID + device)
    let node_id = identity.node_id;
    
    let storage_config = UnifiedStorageConfig::default();
    let storage = UnifiedStorageSystem::new(storage_config).await?;
    
    let protocols = vec![
        NetworkProtocol::BluetoothLE,
        NetworkProtocol::WiFiDirect,
        NetworkProtocol::LoRaWAN,
    ];
    
    // Use the identity's public key
    let owner_key = identity.public_key.clone();
    ZhtpMeshServer::new(node_id, owner_key, storage, protocols).await
}

/// Test storage system that implements the UnifiedStorageSystem interface
/// This is a minimal implementation for testing purposes
pub struct TestStorageSystem {
    config: TestStorageConfig,
}

pub struct TestStorageConfig {
    pub node_id: [u8; 32],
    pub storage_path: PathBuf,
    pub capacity: u64,
    pub replication_factor: usize,
    pub addresses: Vec<String>,
    pub k_bucket_size: usize,
    pub dht_replication: usize,
    pub erasure_data_chunks: usize,
    pub erasure_parity_chunks: usize,
    pub chunk_size: usize,
}

impl TestStorageSystem {
    pub fn new(config: TestStorageConfig) -> Result<Self> {
        // Create storage directory if it doesn't exist
        if !config.storage_path.exists() {
            std::fs::create_dir_all(&config.storage_path)?;
        }
        
        Ok(TestStorageSystem { config })
    }
    
    /// Store data in the test storage system
    pub async fn store(&mut self, key: &[u8], data: &[u8]) -> Result<()> {
        let key_hex = hex::encode(key);
        let file_path = self.config.storage_path.join(format!("{}.dat", key_hex));
        tokio::fs::write(file_path, data).await?;
        Ok(())
    }
    
    /// Retrieve data from the test storage system
    pub async fn retrieve(&self, key: &[u8]) -> Result<Vec<u8>> {
        let key_hex = hex::encode(key);
        let file_path = self.config.storage_path.join(format!("{}.dat", key_hex));
        let data = tokio::fs::read(file_path).await?;
        Ok(data)
    }
    
    /// Check if data exists in the test storage system
    pub async fn exists(&self, key: &[u8]) -> bool {
        let key_hex = hex::encode(key);
        let file_path = self.config.storage_path.join(format!("{}.dat", key_hex));
        file_path.exists()
    }
    
    /// Get storage statistics
    pub async fn get_stats(&self) -> TestStorageStats {
        TestStorageStats {
            total_capacity: self.config.capacity,
            used_capacity: 0, // Simplified for testing
            available_capacity: self.config.capacity,
            stored_chunks: 0,
            active_nodes: 1,
        }
    }
}

/// Test storage statistics
pub struct TestStorageStats {
    pub total_capacity: u64,
    pub used_capacity: u64,
    pub available_capacity: u64,
    pub stored_chunks: u64,
    pub active_nodes: usize,
}

/// Test economic model that implements the EconomicModel interface
/// This is a minimal implementation for testing purposes
pub struct TestEconomicModel {
    total_supply: u64,
    circulating_supply: u64,
    dao_treasury: u64,
}

impl TestEconomicModel {
    pub fn new() -> Self {
        TestEconomicModel {
            total_supply: 21_000_000_000, // 21 billion tokens
            circulating_supply: 1_000_000_000, // 1 billion in circulation
            dao_treasury: 100_000_000, // 100 million in treasury
        }
    }
    
    /// Transfer tokens between accounts
    pub async fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<()> {
        // Simplified transfer logic for testing
        println!("Test transfer: {} tokens from {} to {}", amount, from, to);
        Ok(())
    }
    
    /// Get account balance
    pub async fn get_balance(&self, account: &str) -> u64 {
        // Simplified balance for testing
        match account {
            "test_account" => 1000,
            "ubi_pool" => 50_000_000,
            _ => 0,
        }
    }
    
    /// Calculate transaction fee
    pub fn calculate_fee(&self, transaction_size: usize) -> u64 {
        // Simple fee calculation: 1 token per KB
        (transaction_size / 1024) as u64 + 1
    }
    
    /// Get economic statistics
    pub fn get_stats(&self) -> TestEconomicStats {
        TestEconomicStats {
            total_supply: self.total_supply,
            circulating_supply: self.circulating_supply,
            dao_treasury: self.dao_treasury,
            ubi_distributed_total: 10_000_000,
            active_participants: 1000,
        }
    }
}

/// Test economic statistics
pub struct TestEconomicStats {
    pub total_supply: u64,
    pub circulating_supply: u64,
    pub dao_treasury: u64,
    pub ubi_distributed_total: u64,
    pub active_participants: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mesh_server_creation() {
        let server = create_test_mesh_server().await;
        assert!(server.is_ok(), "Test mesh server creation should succeed");
    }
    
    #[tokio::test]
    async fn test_storage_system() {
        // Test with storage system
        use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};
        
        let config = UnifiedStorageConfig::default();
        let storage = UnifiedStorageSystem::new(config).await.unwrap();
        
        // Basic functionality test with storage
        let stats = storage.get_statistics().await.unwrap();
        assert!(stats.storage_stats.total_uploads == 0); // Fresh system
    }
    
    #[tokio::test]
    async fn test_economic_model() {
        let mut economics = TestEconomicModel::new();
        
        // Test balance check
        let balance = economics.get_balance("test_account").await;
        assert_eq!(balance, 1000);
        
        // Test transfer
        let result = economics.transfer("test_account", "other_account", 100).await;
        assert!(result.is_ok());
        
        // Test fee calculation
        let fee = economics.calculate_fee(2048); // 2KB transaction
        assert_eq!(fee, 3); // 2KB/1KB + 1 = 3 tokens
        
        // Test statistics
        let stats = economics.get_stats();
        assert_eq!(stats.total_supply, 21_000_000_000);
    }
}
