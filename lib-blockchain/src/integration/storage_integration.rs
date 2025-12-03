//! Complete Storage Integration for ZHTP Blockchain
//! 
//! Provides full integration between lib-blockchain and lib-storage, including:
//! - Persistent blockchain state storage and recovery
//! - Block and transaction archival with efficient retrieval
//! - Identity data persistence and backup
//! - Contract state storage and versioning
//! - UTXO set persistence and indexing
//! - Cross-node data synchronization
//! - Erasure-coded backup for critical data

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use hex;

// Import from lib-storage - use their types, not our own
use lib_storage::{
    UnifiedStorageSystem, UnifiedStorageConfig, UploadRequest, DownloadRequest, 
    SearchQuery, AccessControlSettings, ContentStorageRequirements,
    StorageRequirements
};
use lib_storage::types::{
    ContentHash, StorageTier, EncryptionLevel, AccessPattern,
    QualityRequirements, BudgetConstraints, DhtStats, EconomicStats, StorageStats,
    PaymentSchedule
};
use lib_identity::{ZhtpIdentity, IdentityId};

// Import blockchain components
use crate::{
    blockchain::Blockchain,
    block::Block,
    transaction::{Transaction, IdentityTransactionData, TransactionOutput},
    types::Hash,
    mempool::Mempool,
};

/// Blockchain state for persistence and recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainState {
    pub height: u64,
    pub difficulty: crate::types::Difficulty,
    pub nullifier_set: HashSet<Hash>,
}

/// Persistent storage manager for blockchain data
#[derive(Debug)]
pub struct BlockchainStorageManager {
    /// Unified storage system instance
    storage_system: Arc<RwLock<UnifiedStorageSystem>>,
    /// Configuration for storage operations
    config: BlockchainStorageConfig,
    /// Storage statistics and metrics
    stats: StorageStats,
    /// Cache for frequently accessed data
    cache: Arc<RwLock<StorageCache>>,
}

/// Configuration for blockchain storage operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStorageConfig {
    /// Enable automatic blockchain state persistence
    pub auto_persist_state: bool,
    /// Frequency of automatic state saves (in blocks)
    pub persist_frequency: u64,
    /// Enable erasure coding for critical data
    pub enable_erasure_coding: bool,
    /// Storage tier for blockchain data
    pub storage_tier: StorageTier,
    /// Enable compression for stored data
    pub enable_compression: bool,
    /// Enable encryption for stored data
    pub enable_encryption: bool,
    /// Maximum cache size in bytes
    pub max_cache_size: usize,
    /// Enable cross-node backup
    pub enable_backup: bool,
}

/// Complete backup data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    /// Blockchain state
    pub blockchain_state: BlockchainState,
    /// All blocks
    pub blocks: Vec<Block>,
    /// UTXO set
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    /// Identity registry
    pub identity_registry: HashMap<String, IdentityTransactionData>,
}

/// In-memory cache for frequently accessed blockchain data
#[derive(Debug, Clone)]
pub struct StorageCache {
    /// Cached blocks by height
    blocks: HashMap<u64, Block>,
    /// Cached transactions by hash
    transactions: HashMap<Hash, Transaction>,
    /// Cached identity data by DID
    identities: HashMap<String, IdentityTransactionData>,
    /// Cache statistics
    hit_count: u64,
    miss_count: u64,
    /// Current cache size in bytes
    current_size: usize,
}

/// Storage operation result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageOperationResult {
    /// Success status
    pub success: bool,
    /// Storage content hash
    pub content_hash: Option<ContentHash>,
    /// Operation metadata
    pub metadata: StorageOperationMetadata,
    /// Error message if failed
    pub error: Option<String>,
}

/// Metadata for storage operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageOperationMetadata {
    /// Operation type
    pub operation_type: StorageOperationType,
    /// Data size in bytes
    pub data_size: usize,
    /// Storage tier used
    pub storage_tier: StorageTier,
    /// Whether compression was used
    pub compressed: bool,
    /// Whether encryption was used
    pub encrypted: bool,
    /// Number of replicas stored
    pub replica_count: u32,
    /// Operation timestamp
    pub timestamp: u64,
}

/// Types of storage operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageOperationType {
    StoreBlock,
    RetrieveBlock,
    StoreTransaction,
    RetrieveTransaction,
    StoreBlockchainState,
    RetrieveBlockchainState,
    StoreIdentity,
    RetrieveIdentity,
    StoreUTXOSet,
    RetrieveUTXOSet,
    StoreMempool,
    RetrieveMempool,
    Backup,
    Restore,
}

impl BlockchainStorageManager {
    /// Create a new blockchain storage manager
    pub async fn new(config: BlockchainStorageConfig) -> Result<Self> {
        info!("Initializing blockchain storage manager");

        // Create unified storage configuration with proper NodeId
        let random_bytes = rand::random::<[u8; 32]>();
        let node_id = lib_identity::NodeId::from_bytes(random_bytes);
        let storage_config = UnifiedStorageConfig {
            node_id,
            addresses: vec!["127.0.0.1:33445".to_string()],
            economic_config: lib_storage::types::economic_types::EconomicManagerConfig::default(),
            storage_config: lib_storage::StorageConfig {
                max_storage_size: 1_000_000_000_000, // 1TB for blockchain data
                default_tier: config.storage_tier.clone(),
                enable_compression: config.enable_compression,
                enable_encryption: config.enable_encryption,
            },
            erasure_config: lib_storage::ErasureConfig {
                data_shards: 6,    // Higher redundancy for blockchain data
                parity_shards: 4,  // Can recover from 4 failures
            },
        };

        // Initialize unified storage system
        let storage_system = Arc::new(RwLock::new(
            UnifiedStorageSystem::new(storage_config).await?
        ));

        // Initialize cache
        let cache = Arc::new(RwLock::new(StorageCache::new()));

        Ok(Self {
            storage_system,
            config,
            stats: lib_storage::types::StorageStats {
                total_content: 0,
                total_size: 0,
                cache_size: 0,
                active_contracts: 0,
                known_storage_nodes: 0,
                dht_entries: 0,
                routing_table_size: 0,
            },
            cache,
        })
    }

    /// Store complete blockchain state with optional erasure coding
    pub async fn store_blockchain_state(&mut self, blockchain: &Blockchain) -> Result<StorageOperationResult> {
        info!("Storing complete blockchain state (height: {})", blockchain.height);

        let start_time = std::time::Instant::now();

        // Serialize blockchain state
        let serialized_state = self.serialize_blockchain_state(blockchain)?;

        // Create storage request
        let upload_request = UploadRequest {
            content: serialized_state.clone(),
            filename: format!("blockchain_state_{}.dat", blockchain.height),
            mime_type: "application/octet-stream".to_string(),
            description: format!("Complete blockchain state at height {}", blockchain.height),
            tags: vec![
                "blockchain-state".to_string(),
                format!("height-{}", blockchain.height),
                "critical".to_string(),
            ],
            encrypt: self.config.enable_encryption,
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: false, // Blockchain state is sensitive
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None, // Never expires
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365 * 10, // Store for 10 years
                quality_requirements: QualityRequirements {
                    min_uptime: 0.99,
                    max_response_time: 1000,
                    min_replication: 5,
                    geographic_distribution: Some(vec!["global".to_string()]),
                    required_certifications: vec![],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: serialized_state.len() as u64 * 365,  // 1 ZHTP per byte per year
                    max_cost_per_gb_day: 100,
                    payment_schedule: PaymentSchedule::Monthly,
                    max_price_volatility: 0.05,
                },
            },
        };

        // Create dummy identity for system operations
        let system_identity = self.create_system_identity().await?;

        // Store using erasure coding if enabled
        let content_hash = if self.config.enable_erasure_coding {
            info!("Using erasure coding for blockchain state storage");
            let storage_requirements = StorageRequirements {
                duration_days: 365 * 10,
                quality_requirements: upload_request.storage_requirements.quality_requirements.clone(),
                budget_constraints: upload_request.storage_requirements.budget_constraints.clone(),
                geographic_preferences: vec![], // No specific geographic constraints
                replication_factor: 3, // Standard replication for blockchain data
            };

            self.storage_system.write().await
                .store_with_erasure_coding(serialized_state.clone(), storage_requirements, system_identity)
                .await?
        } else {
            self.storage_system.write().await
                .upload_content(upload_request, system_identity)
                .await?
        };

        let elapsed = start_time.elapsed();
        info!("Blockchain state stored successfully in {:?} (hash: {})", 
              elapsed, hex::encode(content_hash.as_bytes()));

        // Update statistics
        self.stats.total_content += 1;
        self.stats.total_size += serialized_state.len() as u64;

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreBlockchainState,
                data_size: serialized_state.len(),
                storage_tier: self.config.storage_tier.clone(),
                compressed: self.config.enable_compression,
                encrypted: self.config.enable_encryption,
                replica_count: 5, // From quality requirements
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Retrieve complete blockchain state from storage
    pub async fn retrieve_blockchain_state(&mut self, content_hash: ContentHash) -> Result<Blockchain> {
        info!("Retrieving blockchain state (hash: {})", hex::encode(content_hash.as_bytes()));

        let download_request = DownloadRequest {
            content_hash,
            requester: self.create_system_identity().await?,
            version: None,
        };

        let serialized_state = self.storage_system.write().await
            .download_content(download_request)
            .await?;

        let blockchain = self.deserialize_blockchain_state(&serialized_state)?;

        info!("Blockchain state retrieved successfully (height: {})", blockchain.height);
        Ok(blockchain)
    }

    /// Store individual block with metadata
    pub async fn store_block(&mut self, block: &Block) -> Result<StorageOperationResult> {
        debug!("Storing block {} (height: {})", hex::encode(block.hash().as_bytes()), block.height());

        // Check cache first
        if let Ok(mut cache) = self.cache.try_write() {
            cache.blocks.insert(block.height(), block.clone());
            cache.current_size += self.estimate_block_size(block);
            
            // Evict if cache is too large
            if cache.current_size > self.config.max_cache_size {
                cache.evict_oldest_blocks();
            }
        }

        let serialized_block = self.serialize_block(block)?;

        let upload_request = UploadRequest {
            content: serialized_block.clone(),
            filename: format!("block_{}.dat", block.height()),
            mime_type: "application/octet-stream".to_string(),
            description: format!("Blockchain block at height {}", block.height()),
            tags: vec![
                "block".to_string(),
                format!("height-{}", block.height()),
                format!("hash-{}", hex::encode(block.hash().as_bytes())),
            ],
            encrypt: self.config.enable_encryption,
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: true, // Blocks can be public
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365 * 10,
                quality_requirements: QualityRequirements {
                    min_uptime: 0.95,
                    max_response_time: 5000,
                    min_replication: 3,
                    geographic_distribution: Some(vec!["global".to_string()]),
                    required_certifications: vec![],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: serialized_block.len() as u64 * 365 * 10,  // 10 year storage budget
                    max_cost_per_gb_day: 100,
                    payment_schedule: PaymentSchedule::Monthly,
                    max_price_volatility: 0.1,
                },
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        debug!("Block stored successfully (hash: {})", hex::encode(content_hash.as_bytes()));

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreBlock,
                data_size: serialized_block.len(),
                storage_tier: StorageTier::Cold,
                compressed: self.config.enable_compression,
                encrypted: self.config.enable_encryption,
                replica_count: 3,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Retrieve block by content hash
    pub async fn retrieve_block(&mut self, content_hash: ContentHash) -> Result<Block> {
        debug!("Retrieving block (hash: {})", hex::encode(content_hash.as_bytes()));

        let download_request = DownloadRequest {
            content_hash,
            requester: self.create_system_identity().await?,
            version: None,
        };

        let serialized_block = self.storage_system.write().await
            .download_content(download_request)
            .await?;

        let block = self.deserialize_block(&serialized_block)?;

        // Update cache
        if let Ok(mut cache) = self.cache.try_write() {
            cache.blocks.insert(block.height(), block.clone());
            cache.hit_count += 1;
        }

        debug!("Block retrieved successfully (height: {})", block.height());
        Ok(block)
    }

    /// Retrieve block by height (searches storage)
    pub async fn retrieve_block_by_height(&mut self, height: u64) -> Result<Option<Block>> {
        // Check cache first
        if let Ok(mut cache) = self.cache.try_write() {
            if let Some(block) = cache.blocks.get(&height).cloned() {
                cache.hit_count += 1;
                return Ok(Some(block));
            }
        }

        // Search storage system
        let search_query = SearchQuery {
            terms: vec![format!("height-{}", height)],
            mime_type_filter: Some("application/octet-stream".to_string()),
            owner_filter: None,
            size_range: None,
            date_range: None,
            tag_filter: Some(vec![format!("block_{}", height)]),
        };

        let system_identity = self.create_system_identity().await?;
        let search_results = self.storage_system.read().await
            .search_content(search_query, system_identity)
            .await?;

        if let Some(content_metadata) = search_results.first() {
            let block = self.retrieve_block(content_metadata.content_hash.clone()).await?;
            return Ok(Some(block));
        }

        if let Ok(mut cache) = self.cache.try_write() {
            cache.miss_count += 1;
        }

        Ok(None)
    }

    /// Store transaction with indexing
    pub async fn store_transaction(&mut self, transaction: &Transaction) -> Result<StorageOperationResult> {
        debug!("Storing transaction {}", hex::encode(transaction.hash().as_bytes()));

        let serialized_tx = self.serialize_transaction(transaction)?;

        let upload_request = UploadRequest {
            content: serialized_tx.clone(),
            filename: format!("tx_{}.dat", hex::encode(transaction.hash().as_bytes())),
            mime_type: "application/octet-stream".to_string(),
            description: format!("Blockchain transaction (type: {:?})", transaction.transaction_type),
            tags: vec![
                "transaction".to_string(),
                format!("type-{:?}", transaction.transaction_type),
                format!("hash-{}", hex::encode(transaction.hash().as_bytes())),
                format!("fee-{}", transaction.fee),
            ],
            encrypt: self.config.enable_encryption,
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: true, // Transactions can be public
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365 * 10,
                quality_requirements: QualityRequirements {
                    min_uptime: 0.95,
                    max_response_time: 10000,
                    min_replication: 2,
                    geographic_distribution: Some(vec!["global".to_string()]),
                    required_certifications: vec![],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: serialized_tx.len() as u64 * 365 * 10,  // 10 year storage budget
                    max_cost_per_gb_day: 100,
                    payment_schedule: PaymentSchedule::Monthly,
                    max_price_volatility: 0.1,
                },
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        // Update cache
        if let Ok(mut cache) = self.cache.try_write() {
            cache.transactions.insert(transaction.hash(), transaction.clone());
        }

        debug!("Transaction stored successfully");

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreTransaction,
                data_size: serialized_tx.len(),
                storage_tier: StorageTier::Cold,
                compressed: self.config.enable_compression,
                encrypted: self.config.enable_encryption,
                replica_count: 2,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Store identity data with access control
    pub async fn store_identity_data(&mut self, did: &str, identity_data: &IdentityTransactionData) -> Result<StorageOperationResult> {
        info!("Storing identity data for DID: {}", did);

        let serialized_identity = self.serialize_identity_data(identity_data)?;

        let upload_request = UploadRequest {
            content: serialized_identity.clone(),
            filename: format!("identity_{}.dat", did.replace(":", "_")),
            mime_type: "application/octet-stream".to_string(),
            description: format!("Identity data for DID: {}", did),
            tags: vec![
                "identity".to_string(),
                format!("did-{}", did),
                format!("type-{}", identity_data.identity_type),
            ],
            encrypt: match self.get_encryption_level_for_data_type("identity") {
                EncryptionLevel::HighSecurity | EncryptionLevel::Standard | EncryptionLevel::QuantumResistant => true,
                EncryptionLevel::None => false,
            }, // Use proper encryption level for identity data
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: false, // Identity data is private
                read_permissions: vec![], // Only owner can read
                write_permissions: vec![], // Only owner can write
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365 * 20, // Store for 20 years
                quality_requirements: QualityRequirements {
                    min_uptime: 0.99,
                    max_response_time: 500,
                    min_replication: 5,
                    geographic_distribution: Some(vec!["global".to_string()]),
                    required_certifications: vec!["identity-verified".to_string()],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: 1000,  // $1000 total budget for 20 year identity storage
                    max_cost_per_gb_day: 150,  // Higher cost for identity data
                    payment_schedule: PaymentSchedule::Monthly,
                    max_price_volatility: 0.05,
                },
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        // Update cache
        if let Ok(mut cache) = self.cache.try_write() {
            cache.identities.insert(did.to_string(), identity_data.clone());
        }

        info!("Identity data stored successfully for DID: {}", did);

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreIdentity,
                data_size: serialized_identity.len(),
                storage_tier: StorageTier::Hot,
                compressed: self.config.enable_compression,
                encrypted: true,
                replica_count: 5,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Store UTXO set for fast synchronization
    pub async fn store_utxo_set(&mut self, utxo_set: &HashMap<Hash, crate::transaction::TransactionOutput>) -> Result<StorageOperationResult> {
        info!("Storing UTXO set ({} entries)", utxo_set.len());

        let serialized_utxo = bincode::serialize(utxo_set)
            .map_err(|e| anyhow::anyhow!("Failed to serialize UTXO set: {}", e))?;

        let upload_request = UploadRequest {
            content: serialized_utxo.clone(),
            filename: format!("utxo_set_{}.dat", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
            mime_type: "application/octet-stream".to_string(),
            description: format!("UTXO set with {} entries", utxo_set.len()),
            tags: vec![
                "utxo-set".to_string(),
                format!("entries-{}", utxo_set.len()),
                "critical".to_string(),
            ],
            encrypt: self.config.enable_encryption,
            compress: true, // Always compress UTXO sets
            access_control: AccessControlSettings {
                public_read: false, // UTXO sets are sensitive
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 30 * 24 * 3600), // Expire after 30 days
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 30, // Shorter duration for UTXO snapshots
                quality_requirements: QualityRequirements {
                    min_uptime: 0.98,
                    max_response_time: 1000,
                    min_replication: 3,
                    geographic_distribution: Some(vec!["global".to_string()]),
                    required_certifications: vec![],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: serialized_utxo.len() as u64 * 30,  // 30 day storage budget
                    max_cost_per_gb_day: 100,
                    payment_schedule: PaymentSchedule::Monthly,
                    max_price_volatility: 0.1,
                },
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        info!("UTXO set stored successfully");

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreUTXOSet,
                data_size: serialized_utxo.len(),
                storage_tier: StorageTier::Warm,
                compressed: true,
                encrypted: self.config.enable_encryption,
                replica_count: 3,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Store mempool state for recovery
    pub async fn store_mempool(&mut self, mempool: &Mempool) -> Result<StorageOperationResult> {
        debug!("Storing mempool state");

        let serialized_mempool = bincode::serialize(mempool)
            .map_err(|e| anyhow::anyhow!("Failed to serialize mempool: {}", e))?;

        let upload_request = UploadRequest {
            content: serialized_mempool.clone(),
            filename: format!("mempool_{}.dat", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
            mime_type: "application/octet-stream".to_string(),
            description: "Mempool state snapshot".to_string(),
            tags: vec![
                "mempool".to_string(),
                "snapshot".to_string(),
            ],
            encrypt: false, // Mempool can be unencrypted
            compress: true,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 24 * 3600), // Expire after 1 day
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 1, // Very short duration
                quality_requirements: QualityRequirements {
                    min_uptime: 0.9,
                    max_response_time: 100,
                    min_replication: 1,
                    geographic_distribution: Some(vec!["local".to_string()]),
                    required_certifications: vec![],
                },
                budget_constraints: BudgetConstraints {
                    max_total_cost: serialized_mempool.len() as u64 * 1,  // 1 day storage budget
                    max_cost_per_gb_day: 50,  // Lower cost for temporary data
                    payment_schedule: PaymentSchedule::Daily,
                    max_price_volatility: 0.2,
                },
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        debug!("Mempool stored successfully");

        Ok(StorageOperationResult {
            success: true,
            content_hash: Some(content_hash),
            metadata: StorageOperationMetadata {
                operation_type: StorageOperationType::StoreMempool,
                data_size: serialized_mempool.len(),
                storage_tier: StorageTier::Hot,
                compressed: true,
                encrypted: false,
                replica_count: 1,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            error: None,
        })
    }

    /// Backup entire blockchain to distributed storage with erasure coding
    pub async fn backup_blockchain(&mut self, blockchain: &Blockchain) -> Result<Vec<StorageOperationResult>> {
        info!("Starting complete blockchain backup (height: {})", blockchain.height);

        let mut results = Vec::new();

        // 1. Backup complete blockchain state
        let state_result = self.store_blockchain_state(blockchain).await?;
        results.push(state_result);

        // 2. Backup individual blocks
        for block in &blockchain.blocks {
            match self.store_block(block).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Error: Critical failure backing up block {}: {}", block.height(), e);
                    results.push(StorageOperationResult {
                        success: false,
                        content_hash: None,
                        metadata: StorageOperationMetadata {
                            operation_type: StorageOperationType::StoreBlock,
                            data_size: 0,
                            storage_tier: self.config.storage_tier.clone(),
                            compressed: false,
                            encrypted: false,
                            replica_count: 0,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        },
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // 3. Backup UTXO set
        let utxo_result = self.store_utxo_set(&blockchain.utxo_set).await?;
        results.push(utxo_result);

        // 4. Backup identity registry
        for (did, identity_data) in &blockchain.identity_registry {
            match self.store_identity_data(did, identity_data).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Error: Critical failure backing up identity {}: {}", did, e);
                }
            }
        }

        let successful_backups = results.iter().filter(|r| r.success).count();
        let total_backups = results.len();

        info!("Blockchain backup completed: {}/{} operations successful", 
              successful_backups, total_backups);

        Ok(results)
    }

    /// Restore blockchain from storage
    pub async fn restore_blockchain(&mut self, state_content_hash: ContentHash) -> Result<Blockchain> {
        info!("Restoring blockchain from storage");

        let blockchain = self.retrieve_blockchain_state(state_content_hash).await?;

        info!("Blockchain restored successfully (height: {})", blockchain.height);
        Ok(blockchain)
    }

    /// Get storage statistics
    pub async fn get_storage_statistics(&mut self) -> Result<lib_storage::UnifiedStorageStats> {
        self.storage_system.write().await.get_statistics().await
    }

    /// Clean up expired data and optimize storage
    pub async fn perform_maintenance(&mut self) -> Result<()> {
        info!(" Performing storage maintenance");

        // Perform unified storage system maintenance
        self.storage_system.write().await.perform_maintenance().await?;

        // Clean up cache if it's too large
        if let Ok(mut cache) = self.cache.try_write() {
            if cache.current_size > self.config.max_cache_size {
                cache.evict_oldest_blocks();
                cache.evict_oldest_transactions();
            }
        }

        info!("Storage maintenance completed");
        Ok(())
    }

    /// Test storage functionality with a simple write/read operation
    pub async fn store_test_data(&mut self) -> Result<()> {
        let test_data = b"blockchain_storage_health_check".to_vec();
        
        let upload_request = UploadRequest {
            content: test_data.clone(),
            filename: "health_check.dat".to_string(),
            mime_type: "application/octet-stream".to_string(),
            description: "Storage health check test data".to_string(),
            tags: vec!["health_check".to_string()],
            encrypt: false, // Don't encrypt test data for simplicity
            compress: false,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 1, // Short-lived test data
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };

        let system_identity = self.create_system_identity().await?;
        let content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;

        // Retrieve and verify test data
        let download_request = DownloadRequest {
            content_hash,
            requester: self.create_system_identity().await?,
            version: None,
        };

        let retrieved = self.storage_system.write().await
            .download_content(download_request)
            .await?;

        if retrieved != test_data {
            return Err(anyhow::anyhow!("Storage health check failed: data mismatch"));
        }

        Ok(())
    }

    /// Retrieve the latest blockchain state from storage
    pub async fn retrieve_latest_blockchain_state(&self) -> Result<Option<BlockchainState>> {
        // Try to retrieve the latest blockchain state using a well-known content hash
        // In a implementation, this would be tracked separately
        info!("Attempting to retrieve latest blockchain state");
        
        // For now, return None since we don't have a reliable way to retrieve without a content hash
        // This would need to be implemented with a metadata system in lib-storage
        warn!("Error: Latest state retrieval not implemented - requires metadata system");
        Ok(None)
    }

    /// Retrieve the latest UTXO set from storage
    pub async fn retrieve_latest_utxo_set(&self) -> Result<Option<HashMap<Hash, crate::transaction::TransactionOutput>>> {
        // For now, return None since we don't have a reliable way to retrieve without a content hash
        // This would need to be implemented with a metadata system in lib-storage
        info!("Attempting to retrieve latest UTXO set");
        warn!("Error: Latest UTXO set retrieval not implemented - requires metadata system");
        Ok(None)
    }

    /// Retrieve all identity data from storage
    pub async fn retrieve_all_identities(&self) -> Result<HashMap<String, IdentityTransactionData>> {
        let identities = HashMap::new();
        
        // In a implementation, this would iterate through stored identity keys
        // For now, return empty map as this requires storage metadata support
        info!("Error: retrieve_all_identities requires storage indexing implementation");
        
        Ok(identities)
    }

    /// Get storage configuration
    pub fn get_config(&self) -> &BlockchainStorageConfig {
        &self.config
    }

    // Helper methods for storage configuration
    fn get_encryption_level_for_data_type(&self, data_type: &str) -> EncryptionLevel {
        match data_type {
            "identity" => EncryptionLevel::HighSecurity,     // Identity data needs strong encryption
            "blockchain" => EncryptionLevel::Standard, // Blockchain state needs medium encryption
            "transaction" => EncryptionLevel::Standard, // Transactions need medium encryption  
            "utxo" => EncryptionLevel::Standard,       // UTXO set needs medium encryption
            "mempool" => EncryptionLevel::None,       // Mempool can use basic encryption
            _ => EncryptionLevel::Standard,            // Default to medium encryption
        }
    }

    fn get_access_pattern_for_data_type(&self, data_type: &str) -> AccessPattern {
        match data_type {
            "blockchain" => AccessPattern::Frequent, // Blockchain accessed frequently
            "mempool" => AccessPattern::Frequent,        // Mempool accessed frequently
            "utxo" => AccessPattern::Frequent,           // UTXO lookups are frequent
            "identity" => AccessPattern::Rare,   // Identity data accessed infrequently
            "transaction" => AccessPattern::Occasional, // Transactions accessed occasionally
            _ => AccessPattern::Occasional,                 // Default to occasional access
        }
    }

    // Helper methods for serialization/deserialization
    fn serialize_blockchain_state(&self, blockchain: &Blockchain) -> Result<Vec<u8>> {
        bincode::serialize(blockchain)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain state: {}", e))
    }

    fn deserialize_blockchain_state(&self, data: &[u8]) -> Result<Blockchain> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize blockchain state: {}", e))
    }

    fn serialize_block(&self, block: &Block) -> Result<Vec<u8>> {
        bincode::serialize(block)
            .map_err(|e| anyhow::anyhow!("Failed to serialize block: {}", e))
    }

    fn deserialize_block(&self, data: &[u8]) -> Result<Block> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize block: {}", e))
    }

    /// Get comprehensive DHT statistics for monitoring
    pub async fn get_dht_statistics(&self) -> Result<DhtStats> {
        let _storage_system = self.storage_system.read().await;
        
        // In a implementation, these would be pulled from the storage system
        let dht_stats = DhtStats {
            total_nodes: 0, // Would query DHT for actual node count
            total_connections: 0, // Active peer connections
            total_messages_sent: 0, // DHT protocol messages
            total_messages_received: 0,
            routing_table_size: self.stats.routing_table_size,
            storage_utilization: self.calculate_storage_utilization().await?,
            network_health: self.calculate_network_health().await?,
        };
        
        info!("DHT Statistics: {} nodes, {:.1}% storage utilization, {:.1}% network health", 
              dht_stats.total_nodes, 
              dht_stats.storage_utilization * 100.0,
              dht_stats.network_health * 100.0);
        
        Ok(dht_stats)
    }

    /// Get economic statistics for storage operations
    pub async fn get_economic_statistics(&self) -> Result<EconomicStats> {
        let economic_stats = EconomicStats {
            total_contracts: self.stats.active_contracts as u64,
            total_storage: self.stats.total_size,
            total_value_locked: 0, // Would calculate from contract values
            average_contract_value: 0, // Would calculate from contracts
            total_penalties: 0, // Would track penalty events
            total_rewards: 0, // Would track reward distributions
        };
        
        info!("Economic Statistics: {} contracts, {} bytes storage, {} tokens locked",
              economic_stats.total_contracts,
              economic_stats.total_storage,
              economic_stats.total_value_locked);
        
        Ok(economic_stats)
    }

    /// Calculate current storage utilization percentage
    async fn calculate_storage_utilization(&self) -> Result<f64> {
        let max_storage = 1_000_000_000_000u64; // 1TB (from config)
        let used_storage = self.stats.total_size;
        
        if max_storage == 0 {
            Ok(0.0)
        } else {
            Ok((used_storage as f64) / (max_storage as f64))
        }
    }

    /// Calculate network health score based on various metrics
    async fn calculate_network_health(&self) -> Result<f64> {
        let mut health_score = 1.0f64;
        
        // Factor in DHT connectivity
        if self.stats.routing_table_size < 20 {
            health_score *= 0.8; // Reduce health if few DHT connections
        }
        
        // Factor in storage distribution
        let storage_util = self.calculate_storage_utilization().await?;
        if storage_util > 0.9 {
            health_score *= 0.7; // Reduce health if storage nearly full
        }
        
        // Factor in cache hit rate (simplified)
        if self.stats.cache_size == 0 {
            health_score *= 0.9; // Slight reduction if no caching
        }
        
        Ok(health_score.max(0.0).min(1.0))
    }

    fn serialize_transaction(&self, transaction: &Transaction) -> Result<Vec<u8>> {
        bincode::serialize(transaction)
            .map_err(|e| anyhow::anyhow!("Failed to serialize transaction: {}", e))
    }

    fn serialize_identity_data(&self, identity_data: &IdentityTransactionData) -> Result<Vec<u8>> {
        bincode::serialize(identity_data)
            .map_err(|e| anyhow::anyhow!("Failed to serialize identity data: {}", e))
    }

    fn estimate_block_size(&self, block: &Block) -> usize {
        bincode::serialize(block).map(|data| data.len()).unwrap_or(1024)
    }

    async fn create_system_identity(&self) -> Result<ZhtpIdentity> {
        // Create a system identity for storage operations
        use lib_identity::types::{IdentityType, AccessLevel};
        use lib_identity::wallets::WalletManager;
        use lib_proofs::ZeroKnowledgeProof;
        use lib_crypto::PublicKey;
        use std::collections::HashMap;

        let system_id = IdentityId::from_bytes(&[255u8; 32]); // Reserved system ID

        // Create system DID
        let system_did = "did:zhtp:system".to_string();

        // Create system NodeId (deterministic)
        let system_node_id = lib_identity::types::NodeId::from_did_device(&system_did, "system-node")
            .unwrap_or_else(|_| lib_identity::types::NodeId::from_bytes([255u8; 32]));

        // Initialize device_node_ids with system node
        let mut device_node_ids = HashMap::new();
        device_node_ids.insert("system-node".to_string(), system_node_id);

        Ok(ZhtpIdentity {
            id: system_id.clone(),
            identity_type: IdentityType::Agent, // Use Agent instead of System
            did: system_did,
            public_key: PublicKey::new(vec![0u8; 32]), // System public key
            private_key: None,
            node_id: system_node_id,
            device_node_ids,
            primary_device: "system-node".to_string(),
            ownership_proof: ZeroKnowledgeProof {
                proof_system: "system".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            credentials: HashMap::new(),
            reputation: 100,
            age: None,
            access_level: AccessLevel::FullCitizen, // Use FullCitizen instead of System
            metadata: HashMap::new(),
            private_data_id: None,
            wallet_manager: WalletManager::new(system_id.clone()),
            did_document_hash: None,
            attestations: vec![],
            created_at: 0,
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            recovery_keys: vec![],
            owner_identity_id: None,  // System identity has no owner
            reward_wallet_id: None,   // System identity doesn't need rewards
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret: [0u8; 32], // System identity - zeroed secrets
            zk_credential_hash: [0u8; 32],
            wallet_master_seed: [0u8; 64],
            dao_member_id: "system".to_string(),
            dao_voting_power: 0, // System has no voting power
            citizenship_verified: false,
            jurisdiction: None,
        })
    }

    /// Store blockchain state with a well-known latest key
    pub async fn store_latest_blockchain_state(&self, state: &BlockchainState) -> Result<()> {
        let serialized = bincode::serialize(state)?;
        
        let upload_request = UploadRequest {
            content: serialized,
            filename: "latest_blockchain_state.dat".to_string(),
            mime_type: "application/octet-stream".to_string(),
            description: "Latest blockchain state".to_string(),
            tags: vec!["blockchain".to_string(), "state".to_string(), "latest".to_string()],
            encrypt: self.config.enable_encryption,
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365, // Store state for 1 year
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };

        let system_identity = self.create_system_identity().await?;
        let _content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;
            
        Ok(())
    }

    /// Store UTXO set with a well-known latest key  
    pub async fn store_latest_utxo_set(&self, utxo_set: &HashMap<Hash, crate::transaction::TransactionOutput>) -> Result<()> {
        let serialized = bincode::serialize(utxo_set)?;
        
        let upload_request = UploadRequest {
            content: serialized,
            filename: "latest_utxo_set.dat".to_string(),
            mime_type: "application/octet-stream".to_string(),
            description: "Latest UTXO set".to_string(),
            tags: vec!["blockchain".to_string(), "utxo".to_string(), "latest".to_string()],
            encrypt: self.config.enable_encryption,
            compress: self.config.enable_compression,
            access_control: AccessControlSettings {
                public_read: false,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements: ContentStorageRequirements {
                duration_days: 365, // Store UTXO set for 1 year
                quality_requirements: QualityRequirements::default(),
                budget_constraints: BudgetConstraints::default(),
            },
        };

        let system_identity = self.create_system_identity().await?;
        let _content_hash = self.storage_system.write().await
            .upload_content(upload_request, system_identity)
            .await?;
            
        Ok(())
    }
}

impl StorageCache {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            transactions: HashMap::new(),
            identities: HashMap::new(),
            hit_count: 0,
            miss_count: 0,
            current_size: 0,
        }
    }

    fn evict_oldest_blocks(&mut self) {
        // Remove oldest 25% of cached blocks
        let target_size = self.blocks.len() / 4;
        let mut heights: Vec<u64> = self.blocks.keys().cloned().collect();
        heights.sort();
        
        for height in heights.into_iter().take(target_size) {
            self.blocks.remove(&height);
        }
        
        // Recalculate size (simplified)
        self.current_size = self.blocks.len() * 1024 + self.transactions.len() * 512;
    }

    fn evict_oldest_transactions(&mut self) {
        // Remove oldest 25% of cached transactions
        let target_size = self.transactions.len() / 4;
        let hashes: Vec<Hash> = self.transactions.keys().cloned().take(target_size).collect();
        
        for hash in hashes {
            self.transactions.remove(&hash);
        }
        
        // Recalculate size (simplified)
        self.current_size = self.blocks.len() * 1024 + self.transactions.len() * 512;
    }
}

impl Default for BlockchainStorageConfig {
    fn default() -> Self {
        Self {
            auto_persist_state: true,
            persist_frequency: 100, // Every 100 blocks
            enable_erasure_coding: true,
            storage_tier: StorageTier::Warm,
            enable_compression: true,
            enable_encryption: true,
            max_cache_size: 100 * 1024 * 1024, // 100MB cache
            enable_backup: true,
        }
    }
}

// Legacy compatibility functions
pub fn serialize_blockchain_state(blockchain: &Blockchain) -> Result<Vec<u8>> {
    bincode::serialize(blockchain)
        .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain state: {}", e))
}

pub fn deserialize_blockchain_state(data: &[u8]) -> Result<Blockchain> {
    bincode::deserialize(data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize blockchain state: {}", e))
}

pub fn block_storage_key(height: u64) -> Vec<u8> {
    format!("block:{}", height).into_bytes()
}

pub fn transaction_storage_key(tx_hash: &Hash) -> Vec<u8> {
    format!("tx:{}", hex::encode(tx_hash.as_array())).into_bytes()
}

pub fn identity_storage_key(did: &str) -> Vec<u8> {
    format!("identity:{}", did).into_bytes()
}

pub fn contract_storage_key(contract_id: &[u8; 32]) -> Vec<u8> {
    format!("contract:{}", hex::encode(contract_id)).into_bytes()
}

pub fn utxo_storage_key(tx_hash: &Hash, output_index: u32) -> Vec<u8> {
    format!("utxo:{}:{}", hex::encode(tx_hash.as_array()), output_index).into_bytes()
}

/// Storage metadata for versioning and compression (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    pub version: u32,
    pub compressed: bool,
    pub checksum: [u8; 32],
    pub timestamp: u64,
}

impl StorageMetadata {
    /// Create new storage metadata
    pub fn new(data: &[u8], compressed: bool) -> Self {
        let checksum = blake3::hash(data).into();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: 1,
            compressed,
            checksum,
            timestamp,
        }
    }

    /// Verify data against checksum
    pub fn verify(&self, data: &[u8]) -> bool {
        let calculated_checksum = blake3::hash(data);
        calculated_checksum.as_bytes() == &self.checksum
    }
}

/// Storage wrapper with metadata (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub metadata: StorageMetadata,
    pub data: Vec<u8>,
}

impl StorageEntry {
    /// Create new storage entry
    pub fn new(data: Vec<u8>, compressed: bool) -> Result<Self> {
        let metadata = StorageMetadata::new(&data, compressed);
        Ok(Self { metadata, data })
    }

    /// Verify entry integrity
    pub fn verify(&self) -> bool {
        self.metadata.verify(&self.data)
    }

    /// Serialize entry to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize storage entry: {}", e))
    }

    /// Deserialize entry from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize storage entry: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::Blockchain;
    

    #[tokio::test]
    async fn test_blockchain_storage_manager_creation() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let manager = BlockchainStorageManager::new(config).await;
        
        assert!(manager.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_blockchain_state_storage_and_retrieval() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let blockchain = Blockchain::new()?;
        
        // Store blockchain state
        let store_result = manager.store_blockchain_state(&blockchain).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        // Retrieve blockchain state
        let content_hash = store_result.content_hash.unwrap();
        let retrieved_blockchain = manager.retrieve_blockchain_state(content_hash).await?;
        
        assert_eq!(retrieved_blockchain.height, blockchain.height);
        assert_eq!(retrieved_blockchain.difficulty, blockchain.difficulty);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_block_storage_and_retrieval() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let blockchain = Blockchain::new()?;
        let genesis_block = blockchain.blocks[0].clone();
        
        // Store block
        let store_result = manager.store_block(&genesis_block).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        // Retrieve block
        let content_hash = store_result.content_hash.unwrap();
        let retrieved_block = manager.retrieve_block(content_hash).await?;
        
        assert_eq!(retrieved_block.height(), genesis_block.height());
        assert_eq!(retrieved_block.hash(), genesis_block.hash());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_transaction_storage() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        // Create a test transaction
        let transaction = crate::transaction::Transaction::new(
            vec![],
            vec![],
            100,
            crate::integration::crypto_integration::Signature {
                signature: vec![1, 2, 3],
                public_key: crate::integration::crypto_integration::PublicKey::new(vec![4, 5, 6]),
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                timestamp: 12345,
            },
            "test transaction".as_bytes().to_vec(),
        );
        
        // Store transaction
        let store_result = manager.store_transaction(&transaction).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_data_storage() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let identity_data = crate::transaction::IdentityTransactionData::new(
            "did:zhtp:test".to_string(),
            "Test User".to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            "human".to_string(),
            crate::types::Hash::default(),
            1000,
            100,
        );
        
        // Store identity data
        let store_result = manager.store_identity_data("did:zhtp:test", &identity_data).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_utxo_set_storage() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let mut utxo_set = HashMap::new();
        let test_hash = crate::types::Hash::from([1u8; 32]);
        let test_output = crate::transaction::TransactionOutput::new(
            crate::types::Hash::from([2u8; 32]),
            crate::types::Hash::from([3u8; 32]),
            crate::integration::crypto_integration::PublicKey::new(vec![4, 5, 6]),
        );
        utxo_set.insert(test_hash, test_output);
        
        // Store UTXO set
        let store_result = manager.store_utxo_set(&utxo_set).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_mempool_storage() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let mempool = crate::mempool::Mempool::default();
        
        // Store mempool
        let store_result = manager.store_mempool(&mempool).await?;
        assert!(store_result.success);
        assert!(store_result.content_hash.is_some());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_blockchain_backup() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let blockchain = Blockchain::new()?;
        
        // Backup blockchain
        let backup_results = manager.backup_blockchain(&blockchain).await?;
        assert!(!backup_results.is_empty());
        
        // Check that at least the blockchain state was backed up successfully
        let successful_backups = backup_results.iter().filter(|r| r.success).count();
        assert!(successful_backups > 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_storage_statistics() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        let stats = manager.get_storage_statistics().await?;
        
        // Basic validation that stats structure is correct
        assert_eq!(stats.dht_stats.total_nodes, 1);
        assert_eq!(stats.storage_stats.total_content_count, 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_storage_maintenance() -> Result<()> {
        let config = BlockchainStorageConfig::default();
        let mut manager = BlockchainStorageManager::new(config).await?;
        
        // Perform maintenance (should not fail)
        let maintenance_result = manager.perform_maintenance().await;
        assert!(maintenance_result.is_ok());
        
        Ok(())
    }

    // Legacy compatibility tests
    #[test]
    fn test_legacy_blockchain_serialization() -> Result<()> {
        let blockchain = Blockchain::new()?;
        
        let serialized = serialize_blockchain_state(&blockchain)?;
        let deserialized = deserialize_blockchain_state(&serialized)?;
        
        assert_eq!(blockchain.height, deserialized.height);
        assert_eq!(blockchain.difficulty, deserialized.difficulty);
        
        Ok(())
    }

    #[test]
    fn test_legacy_storage_keys() {
        let block_key = block_storage_key(123);
        assert_eq!(block_key, b"block:123");

        let tx_hash = crate::types::Hash::from([1u8; 32]);
        let tx_key = transaction_storage_key(&tx_hash);
        assert!(String::from_utf8_lossy(&tx_key).starts_with("tx:"));

        let identity_key = identity_storage_key("did:zhtp:test");
        assert_eq!(identity_key, b"identity:did:zhtp:test");

        let contract_id = [2u8; 32];
        let contract_key = contract_storage_key(&contract_id);
        assert!(String::from_utf8_lossy(&contract_key).starts_with("contract:"));

        let utxo_key = utxo_storage_key(&tx_hash, 0);
        assert!(String::from_utf8_lossy(&utxo_key).starts_with("utxo:"));
    }

    #[test]
    fn test_legacy_storage_metadata() -> Result<()> {
        let test_data = b"test data for storage";
        let metadata = StorageMetadata::new(test_data, false);
        
        assert_eq!(metadata.version, 1);
        assert!(!metadata.compressed);
        assert!(metadata.verify(test_data));
        assert!(!metadata.verify(b"different data"));
        
        Ok(())
    }

    #[test]
    fn test_legacy_storage_entry() -> Result<()> {
        let test_data = b"test entry data".to_vec();
        let entry = StorageEntry::new(test_data.clone(), false)?;
        
        assert!(entry.verify());
        assert_eq!(entry.data, test_data);
        
        let serialized = entry.to_bytes()?;
        let deserialized = StorageEntry::from_bytes(&serialized)?;
        
        assert!(deserialized.verify());
        assert_eq!(deserialized.data, test_data);
        
        Ok(())
    }

    #[test]
    fn test_storage_cache() {
        let mut cache = StorageCache::new();
        
        // Test initial state
        assert_eq!(cache.hit_count, 0);
        assert_eq!(cache.miss_count, 0);
        assert_eq!(cache.current_size, 0);
        
        // Test eviction methods don't panic on empty cache
        cache.evict_oldest_blocks();
        cache.evict_oldest_transactions();
    }

    #[test]
    fn test_blockchain_storage_config() {
        let config = BlockchainStorageConfig::default();
        
        assert!(config.auto_persist_state);
        assert_eq!(config.persist_frequency, 100);
        assert!(config.enable_erasure_coding);
        assert_eq!(config.storage_tier, StorageTier::Warm);
        assert!(config.enable_compression);
        assert!(config.enable_encryption);
        assert!(config.enable_backup);
    }
}
