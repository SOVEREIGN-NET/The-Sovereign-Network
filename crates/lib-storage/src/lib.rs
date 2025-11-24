//! ZHTP Unified Storage System
//! 
//! A sophisticated multi-layer storage system combining DHT networking with economic storage.
//! The DHT provides the foundation for peer discovery, routing, and basic key-value operations,
//! while the storage layer adds economics, contracts, erasure coding, and tiered storage on top.
//!
//! Phase Implementation Status:
//! - Phase A: Types and module structure COMPLETED
//! - Phase B: DHT foundation layer COMPLETED  
//! - Phase C: Economic storage layer COMPLETED
//! - Phase D: Content management layer COMPLETED
//! - Phase E: Integration layer COMPLETED

// Core type definitions (Phase A - COMPLETED)
pub mod types;

// DHT foundation layer (Phase B - COMPLETED)
pub mod dht;

// Economic storage layer (Phase C - COMPLETED)
pub mod economic;

// Content management layer (Phase D - COMPLETED)
pub mod content;

// Wallet-Content integration layer
pub mod wallet_content_integration;

// Erasure coding module
pub mod erasure;

// Storage proof system (Phase F - NEW)
pub mod proofs;

// Data integrity layer (Phase F - NEW)
pub mod integrity;

// Multi-level caching system (Phase F - NEW)
pub mod cache;

// Storage optimization (Phase F - NEW)
pub mod optimization;

// Distributed consistency (Phase F - NEW)
pub mod consistency;

// Re-export core types (avoiding conflicts)
pub use types::{
    dht_types::*, storage_types::*, stats_types::*
};

// Re-export economic types explicitly to avoid conflicts  
pub use types::economic_types::{
    EconomicManagerConfig, EconomicStats, EconomicStorageRequest, EconomicQuote,
    StorageRequirements, PaymentPreferences, QualityRequirements, BudgetConstraints
};

// Re-export DHT and content management
pub use dht::*;
pub use economic::{
    pricing::*, market::*, reputation::*, payments::*, incentives::*, 
    quality::*, penalties::*, rewards::*, manager::*
};
pub use content::{ContentManager, UploadRequest, DownloadRequest, SearchQuery, AccessControlSettings, ContentStorageRequirements};
pub use wallet_content_integration::{WalletContentManager, WalletContentStatistics};
pub use erasure::*;
pub use proofs::{StorageProof, RetrievalProof, generate_storage_proof, generate_retrieval_proof};
pub use integrity::{IntegrityManager, IntegrityMetadata, IntegrityStatus, ChecksumAlgorithm};
pub use cache::{CacheManager, CacheEntry, EvictionPolicy, CacheStats};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::ZhtpIdentity;

// Import specific types from our own modules
use crate::types::{NodeId, ContentHash};

/// Unified storage system that integrates all components
#[derive(Debug)]
pub struct UnifiedStorageSystem {
    /// DHT network manager
    dht_manager: dht::node::DhtNodeManager,
    /// DHT storage
    dht_storage: dht::storage::DhtStorage,
    /// Economic manager
    economic_manager: economic::manager::EconomicStorageManager,
    /// Content manager
    content_manager: content::ContentManager,
    /// Erasure coding
    erasure_coding: erasure::ErasureCoding,
    /// System configuration
    config: UnifiedStorageConfig,
    /// System statistics
    stats: UnifiedStorageStats,
}

/// Configuration for unified storage system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageConfig {
    /// Node configuration
    pub node_id: NodeId,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Economic configuration
    pub economic_config: EconomicManagerConfig,
    /// Storage configuration
    pub storage_config: StorageConfig,
    /// Erasure coding configuration
    pub erasure_config: ErasureConfig,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage size in bytes
    pub max_storage_size: u64,
    /// Default storage tier
    pub default_tier: StorageTier,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable encryption
    pub enable_encryption: bool,
}

/// Erasure coding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureConfig {
    /// Number of data shards
    pub data_shards: usize,
    /// Number of parity shards
    pub parity_shards: usize,
}

/// Unified storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStorageStats {
    /// DHT statistics
    pub dht_stats: DhtStats,
    /// Economic statistics
    pub economic_stats: EconomicStats,
    /// Storage statistics
    pub storage_stats: StorageStats,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total stored content
    pub total_content_count: u64,
    /// Total storage used
    pub total_storage_used: u64,
    /// Total uploads
    pub total_uploads: u64,
    /// Total downloads
    pub total_downloads: u64,
}

impl UnifiedStorageSystem {
    /// Create new unified storage system
    pub async fn new(config: UnifiedStorageConfig) -> Result<Self> {
        let node_id = config.node_id.clone();
        
        // Initialize DHT components
        let dht_manager = dht::node::DhtNodeManager::new(
            node_id.clone(),
            config.addresses.clone(),
        )?;

        let dht_storage = dht::storage::DhtStorage::new(
            node_id.clone(),
            config.storage_config.max_storage_size,
        );

        // Initialize economic manager
        let economic_manager = economic::manager::EconomicStorageManager::new(
            config.economic_config.clone(),
        );

        // Initialize content manager
        let content_manager = content::ContentManager::new(
            dht::storage::DhtStorage::new(
                node_id.clone(),
                config.storage_config.max_storage_size,
            ),
            config.economic_config.clone(),
        )?;

        // Initialize erasure coding
        let erasure_coding = erasure::ErasureCoding::new(
            config.erasure_config.data_shards,
            config.erasure_config.parity_shards,
        )?;

        // Initialize statistics
        let stats = UnifiedStorageStats {
            dht_stats: DhtStats {
                total_nodes: 1,
                total_connections: 0,
                total_messages_sent: 0,
                total_messages_received: 0,
                routing_table_size: 0,
                storage_utilization: 0.0,
                network_health: 1.0,
            },
            economic_stats: EconomicStats {
                total_contracts: 0,
                total_storage: 0,
                total_value_locked: 0,
                average_contract_value: 0,
                total_penalties: 0,
                total_rewards: 0,
            },
            storage_stats: StorageStats {
                total_content_count: 0,
                total_storage_used: 0,
                total_uploads: 0,
                total_downloads: 0,
            },
        };

        Ok(Self {
            dht_manager,
            dht_storage,
            economic_manager,
            content_manager,
            erasure_coding,
            config: config.clone(),
            stats,
        })
    }

    /// Upload content with full economic integration
    pub async fn upload_content(
        &mut self,
        request: UploadRequest,
        uploader: ZhtpIdentity,
    ) -> Result<ContentHash> {
        // Upload through content manager
        let content_hash = self.content_manager.upload_content(request, uploader).await?;

        // Update statistics
        self.stats.storage_stats.total_uploads += 1;
        self.stats.storage_stats.total_content_count += 1;

        Ok(content_hash)
    }

    /// Download content with access control
    pub async fn download_content(
        &mut self,
        request: DownloadRequest,
    ) -> Result<Vec<u8>> {
        // Download through content manager
        let content = self.content_manager.download_content(request).await?;

        // Update statistics
        self.stats.storage_stats.total_downloads += 1;

        Ok(content)
    }

    /// Search for content across the unified storage system
    pub async fn search_content(
        &self,
        query: SearchQuery,
        requester: ZhtpIdentity,
    ) -> Result<Vec<ContentMetadata>> {
        // Direct return since we now have unified ContentMetadata
        self.content_manager.search_content(query, requester).await
    }

    /// Store data with erasure coding
    pub async fn store_with_erasure_coding(
        &mut self,
        data: Vec<u8>,
        storage_requirements: StorageRequirements,
        uploader: ZhtpIdentity,
    ) -> Result<ContentHash> {
        // Encode data with erasure coding
        let encoded_shards = self.erasure_coding.encode(&data)?;

        // Create upload request
        let upload_request = UploadRequest {
            content: data,
            filename: "erasure_coded_data".to_string(),
            mime_type: "application/octet-stream".to_string(),
            description: "Data stored with Reed-Solomon erasure coding".to_string(),
            tags: vec!["erasure-coded".to_string()],
            encrypt: true,
            compress: true,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: storage_requirements.duration_days,
                quality_requirements: storage_requirements.quality_requirements,
                budget_constraints: storage_requirements.budget_constraints,
            },
        };

        // Upload content
        let content_hash = self.upload_content(upload_request, uploader).await?;

        // Store encoded shards separately for redundancy
        let shards_data = bincode::serialize(&encoded_shards)?;
        let shards_hash = Hash::from_bytes(&blake3::hash(&shards_data).as_bytes()[..32]);
        
        self.dht_storage.store_data(shards_hash, shards_data).await?;

        Ok(content_hash)
    }

    /// Get storage quote for economic planning
    pub async fn get_storage_quote(&mut self, request: EconomicStorageRequest) -> Result<EconomicQuote> {
        self.economic_manager.process_storage_request(request).await
    }

    /// Get system statistics
    pub async fn get_statistics(&mut self) -> Result<UnifiedStorageStats> {
        // Update economic stats
        self.stats.economic_stats = self.economic_manager.get_statistics().await?;

        // Update DHT stats
        self.stats.dht_stats = self.dht_manager.get_statistics();

        // Storage stats are updated in real-time during operations

        Ok(self.stats.clone())
    }

    /// Add peer to DHT network
    pub async fn add_peer(&mut self, peer_address: String) -> Result<()> {
        // Parse peer info and add to DHT
        let node_info = DhtNode {
            id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
            addresses: vec![peer_address],
            public_key: PostQuantumSignature {
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: [0u8; 32],
                },
                timestamp: 0,
            },
            storage_info: Some(StorageCapabilities {
                available_space: 1_000_000_000, // 1GB available
                total_capacity: 1_000_000_000, // 1GB total capacity
                price_per_gb_day: 100, // 100 tokens per GB per day
                supported_tiers: vec![StorageTier::Hot, StorageTier::Warm, StorageTier::Cold],
                region: "unknown".to_string(),
                uptime: 0.99, // 99% uptime
            }),
            reputation: 50, // Default reputation (out of 100)
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.dht_manager.add_node(node_info).await?;
        Ok(())
    }

    /// Perform system maintenance
    pub async fn perform_maintenance(&mut self) -> Result<()> {
        // Monitor contracts for performance
        let active_contracts = self.economic_manager.get_statistics().await?.total_contracts;
        
        for i in 0..active_contracts {
            let contract_id = Hash::from_bytes(&[i as u8; 32]); // Simplified for demo
            let _ = self.economic_manager.monitor_contract_performance(contract_id).await;
        }

        // Cleanup expired data
        self.dht_storage.cleanup_expired().await?;

        // Update network health metrics
        self.update_network_health().await?;

        Ok(())
    }

    /// Update network health metrics
    async fn update_network_health(&mut self) -> Result<()> {
        let total_nodes = self.dht_manager.get_statistics().total_nodes;
        let total_connections = self.dht_manager.get_statistics().total_connections;

        // Simple health calculation
        let connection_ratio = if total_nodes > 0 {
            total_connections as f64 / total_nodes as f64
        } else {
            0.0
        };

        self.stats.dht_stats.network_health = connection_ratio.min(1.0).max(0.0);
        Ok(())
    }

    /// Get node information
    pub fn get_node_info(&self) -> &DhtNode {
        self.dht_manager.local_node()
    }

    /// Get configuration
    pub fn get_config(&self) -> &UnifiedStorageConfig {
        &self.config
    }

    /// Get DHT content by hex hash string (for Web4 content retrieval)
    /// CRITICAL FIX: Content is stored in content_manager's dht_storage, not self.dht_storage!
    pub async fn get_dht_content_by_hex(&mut self, content_hash_hex: &str) -> Result<Option<Vec<u8>>> {
        // FIXED: Query the SAME dht_storage instance that upload_content() stores to
        // Content is stored via content_manager.dht_storage, so we must query from there
        self.content_manager.get_from_dht_storage(content_hash_hex).await
    }

    /// Update configuration
    pub fn update_config(&mut self, config: UnifiedStorageConfig) {
        self.config = config;
    }

    // ========================================================================
    // Identity Storage Integration - Critical Missing Feature from Original
    // ========================================================================

    /// Store identity credentials in the unified storage system
    pub async fn store_identity_credentials(
        &mut self,
        identity_id: &lib_identity::IdentityId,
        credentials: &lib_identity::ZhtpIdentity,
        passphrase: &str,
    ) -> Result<()> {
        self.content_manager.store_identity_credentials(identity_id, credentials, passphrase).await
    }

    /// Retrieve identity credentials from unified storage
    pub async fn retrieve_identity_credentials(
        &mut self,
        identity_id: &lib_identity::IdentityId,
        passphrase: &str,
    ) -> Result<lib_identity::ZhtpIdentity> {
        self.content_manager.retrieve_identity_credentials(identity_id, passphrase).await
    }

    /// Check if identity exists in storage
    pub async fn identity_exists(&mut self, identity_id: &lib_identity::IdentityId) -> Result<bool> {
        self.content_manager.identity_exists(identity_id).await
    }

    /// Migrate identity from blockchain to unified storage
    pub async fn migrate_identity_from_blockchain(
        &mut self, 
        identity_id: &lib_identity::IdentityId,
        lib_identity: &lib_identity::ZhtpIdentity,
        passphrase: &str,
    ) -> Result<()> {
        self.content_manager.migrate_identity_from_blockchain(identity_id, lib_identity, passphrase).await
    }
}

impl Default for UnifiedStorageConfig {
    fn default() -> Self {
        Self {
            node_id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
            addresses: vec!["127.0.0.1:33445".to_string()], // Bind to localhost only for local mesh operation
            economic_config: EconomicManagerConfig::default(),
            storage_config: StorageConfig {
                max_storage_size: 100_000_000_000, // 100GB
                default_tier: StorageTier::Hot,
                enable_compression: true,
                enable_encryption: true,
            },
            erasure_config: ErasureConfig {
                data_shards: 4,
                parity_shards: 2,
            },
        }
    }
}

impl Default for StorageStats {
    fn default() -> Self {
        Self {
            total_content_count: 0,
            total_storage_used: 0,
            total_uploads: 0,
            total_downloads: 0,
        }
    }
}

/// Type alias for backward compatibility
pub type UnifiedStorageManager = UnifiedStorageSystem;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use lib_identity::IdentityId;
    use crate::types::{PenaltyType, STORAGE_PRICE_PER_GB_DAY, MIN_REPLICATION, MAX_REPLICATION};
    
    #[test]
    fn test_type_definitions() {
        // Test basic type instantiation to ensure all types are properly exported
        let storage_tier = StorageTier::Hot;
        let access_level = AccessLevel::Private;
        let encryption_level = EncryptionLevel::QuantumResistant;
        let access_pattern = AccessPattern::Frequent;
        let penalty_type = PenaltyType::DataLoss;
        
        // Verify enums work correctly
        assert_eq!(storage_tier, StorageTier::Hot);
        assert_eq!(access_level, AccessLevel::Private);
        
        // Test type constants
        assert_eq!(STORAGE_PRICE_PER_GB_DAY, 100);
        assert_eq!(MIN_REPLICATION, 3);
        assert_eq!(MAX_REPLICATION, 12);
    }

    #[tokio::test]
    async fn test_unified_storage_system_creation() {
        let config = UnifiedStorageConfig::default();
        let system = UnifiedStorageSystem::new(config).await;
        
        assert!(system.is_ok());
        let system = system.unwrap();
        assert_eq!(system.get_config().erasure_config.data_shards, 4);
    }

    #[tokio::test]
    async fn test_upload_request_creation() {
        let request = UploadRequest {
            content: b"test data".to_vec(),
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            description: "Test file".to_string(),
            tags: vec!["test".to_string()],
            encrypt: true,
            compress: false,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 30,
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };

        assert_eq!(request.filename, "test.txt");
        assert_eq!(request.content.len(), 9);
        assert!(request.encrypt);
    }

    #[test]
    fn test_economic_manager_config() {
        let config = EconomicManagerConfig::default();
        assert_eq!(config.default_duration_days, 30);
        assert_eq!(config.base_price_per_gb_day, 100);
        assert!(config.enable_escrow);
    }
    
    #[test]
    fn test_config_creation() {
        let config = UnifiedStorageConfig::default();
        
        assert_eq!(config.erasure_config.data_shards, 4);
        assert_eq!(config.erasure_config.parity_shards, 2);
        assert!(config.addresses.contains(&"127.0.0.1:33445".to_string()));
    }
    
    #[test]
    fn test_stats_creation() {
        let stats = StorageStats::default();
        
        assert_eq!(stats.total_content_count, 0);
        assert_eq!(stats.total_storage_used, 0);
    }
    
    #[test]
    fn test_health_creation() {
        let stats = UnifiedStorageStats {
            dht_stats: DhtStats {
                total_nodes: 1,
                total_connections: 0,
                total_messages_sent: 0,
                total_messages_received: 0,
                routing_table_size: 0,
                storage_utilization: 0.0,
                network_health: 1.0,
            },
            economic_stats: EconomicStats::default(),
            storage_stats: StorageStats::default(),
        };
        
        assert_eq!(stats.dht_stats.total_nodes, 1);
        assert_eq!(stats.storage_stats.total_content_count, 0);
    }

    #[tokio::test]
    async fn test_unified_storage_identity_integration() {
        let config = UnifiedStorageConfig::default();
        let mut system = UnifiedStorageSystem::new(config).await.unwrap();
        
        // Create test identity using helper
        let identity_id = IdentityId::from_bytes(&[3u8; 32]);
        let test_identity = create_test_identity_for_lib(identity_id.clone(), 1122334455);
        let passphrase = "unified_system_test";

        // Test storage through unified system
        let store_result = system.store_identity_credentials(&identity_id, &test_identity, passphrase).await;
        assert!(store_result.is_ok(), "Unified system should store identity successfully");

        // Test existence check
        let exists = system.identity_exists(&identity_id).await.unwrap();
        assert!(exists, "Identity should exist in unified system");

        // Test retrieval
        let retrieved = system.retrieve_identity_credentials(&identity_id, passphrase).await;
        assert!(retrieved.is_ok(), "Should retrieve identity from unified system");
        
        let retrieved_identity = retrieved.unwrap();
        assert_eq!(retrieved_identity.id, test_identity.id);
    }

    /// Helper function to create test identity for lib tests
    fn create_test_identity_for_lib(identity_id: IdentityId, created_at: u64) -> ZhtpIdentity {
        use lib_identity::types::{IdentityType, AccessLevel};
        use lib_identity::wallets::WalletManager;
        use lib_proofs::ZeroKnowledgeProof;
        use std::collections::HashMap;

        ZhtpIdentity {
            id: identity_id.clone(),
            identity_type: IdentityType::Human,
            public_key: vec![11, 22, 33, 44, 55],
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
            age: Some(30),
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: None,
            wallet_manager: WalletManager::new(identity_id),
            did_document_hash: None,
            attestations: vec![],
            created_at,
            last_active: created_at,
            recovery_keys: vec![],
        }
    }
}
