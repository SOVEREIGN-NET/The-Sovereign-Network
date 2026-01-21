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

// Storage backend abstractions (Phase G - NEW)
pub mod backend;

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
pub use backend::{BackendStats, BatchOp, StorageBackend, StorageKey, SledBackend, SledTree};
pub use erasure::*;
pub use proofs::{StorageProof, RetrievalProof, generate_storage_proof, generate_retrieval_proof};
pub use integrity::{IntegrityManager, IntegrityMetadata, IntegrityStatus, ChecksumAlgorithm};
pub use cache::{CacheManager, CacheEntry, EvictionPolicy, CacheStats};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::ZhtpIdentity;

// Import specific types from our own modules
use crate::types::{NodeId, ContentHash};
use std::path::Path;

/// Unified storage system that integrates all components
///
/// # DB-010: Generic over StorageBackend
///
/// UnifiedStorageSystem is now generic over `StorageBackend`, allowing both:
/// - **In-memory storage** (HashMapBackend) - default, fast but volatile
/// - **Persistent storage** (SledBackend) - durable across restarts
///
/// # Usage
///
/// Create in-memory instance (backward compatible):
/// ```ignore
/// let system = UnifiedStorageSystem::new(config).await?;
/// ```
///
/// Create persistent instance:
/// ```ignore
/// let system = UnifiedStorageSystem::new_persistent(
///     config,
///     "/path/to/db".into(),
/// ).await?;
/// ```
#[derive(Debug)]
pub struct UnifiedStorageSystem<B: dht::backend::StorageBackend = dht::backend::HashMapBackend> {
    /// DHT network manager
    dht_manager: dht::node::DhtNodeManager,
    /// DHT storage (generic over backend)
    dht_storage: dht::storage::DhtStorage<B>,
    /// Economic manager
    economic_manager: economic::manager::EconomicStorageManager,
    /// Content manager (uses in-memory storage for content metadata)
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
    /// Path for DHT storage persistence (if None, storage is in-memory only)
    #[serde(default)]
    pub dht_persist_path: Option<std::path::PathBuf>,
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

impl UnifiedStorageSystem<dht::backend::HashMapBackend> {
    /// Create new unified storage system with in-memory storage (backward compatible)
    ///
    /// This is the default constructor for UnifiedStorageSystem. It uses in-memory
    /// storage (HashMapBackend) which is fast but volatile - all data is lost on restart.
    ///
    /// For persistent storage, use [`UnifiedStorageSystem::new_persistent()`].
    ///
    /// **MIGRATION (Ticket #145):** Creates DhtPeerIdentity from NodeId for DHT initialization
    pub async fn new(config: UnifiedStorageConfig) -> Result<Self> {
        let node_id = config.node_id.clone();

        // Create DhtPeerIdentity from NodeId (simplified version)
        // In production, this would come from ZhtpIdentity
        let peer_identity = types::dht_types::placeholder_peer_identity(node_id.clone());
        // Initialize DHT components
        let dht_manager = dht::node::DhtNodeManager::new(
            peer_identity.clone(),
            config.addresses.clone(),
        )?;

        // Initialize DHT storage with in-memory backend (HashMapBackend)
        let dht_storage = dht::storage::DhtStorage::new(
            node_id.clone(),
            config.storage_config.max_storage_size,
        );

        if let Some(path) = &config.storage_config.dht_persist_path {
            tracing::warn!(
                "DHT persistence path {:?} is configured but UnifiedStorageSystem::new() uses in-memory storage. \
                 For persistent storage, use UnifiedStorageSystem::new_persistent(). \
                 Tracked as [DB-010] Phase 4.",
                path
            );
        } else {
            tracing::info!(
                "DHT storage is in-memory only - data will be lost on restart. \
                 For production use with persistence, call UnifiedStorageSystem::new_persistent()."
            );
        }

        // Initialize economic manager
        let economic_manager = economic::manager::EconomicStorageManager::new(
            config.economic_config.clone(),
        );

        // Initialize content manager with in-memory storage
        let content_dht_storage = dht::storage::DhtStorage::new(
            node_id.clone(),
            config.storage_config.max_storage_size,
        );
        let content_manager = content::ContentManager::new(
            content_dht_storage,
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
                replay_rejections: 0,
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

    /// Get the node's stable identity-derived NodeId
    pub fn get_node_id(&self) -> NodeId {
        self.config.node_id
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

    /// Get storage quote for economic planning
    pub async fn get_storage_quote(&mut self, request: EconomicStorageRequest) -> Result<EconomicQuote> {
        self.economic_manager.process_storage_request(request).await
    }

    /// Add peer to DHT network
    ///
    /// **MIGRATION (Ticket #145):** Creates DhtPeerIdentity from NodeId
    pub async fn add_peer(&mut self, peer_address: String, node_id: NodeId) -> Result<()> {
        // Create DhtPeerIdentity from NodeId
        let peer_identity = types::dht_types::placeholder_peer_identity(node_id.clone());
        
        // Parse peer info and add to DHT
        let node_info = DhtNode {
            peer: peer_identity,
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

/// Persistent unified storage system with SledBackend
///
/// # DB-010: Persistent Storage Implementation
///
/// Provides factory methods to create UnifiedStorageSystem with persistent storage
/// (SledBackend) instead of in-memory storage. All DHT data is persisted across restarts.
impl UnifiedStorageSystem<dht::backend::SledBackend> {
    /// Create new unified storage system with persistent SledBackend storage
    ///
    /// This constructor initializes UnifiedStorageSystem with persistent storage
    /// using the sled embedded database. All DHT data is automatically persisted
    /// and restored on the next initialization with the same database path.
    ///
    /// # Arguments
    ///
    /// * `config` - Unified storage configuration
    /// * `db_path` - Path to sled database directory (will be created if missing)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let system = UnifiedStorageSystem::new_persistent(
    ///     config,
    ///     "./data/dht".into(),
    /// ).await?;
    /// ```
    pub async fn new_persistent<P: AsRef<Path>>(
        config: UnifiedStorageConfig,
        db_path: P,
    ) -> Result<Self> {
        let node_id = config.node_id.clone();

        // Create DhtPeerIdentity from NodeId (simplified version)
        let peer_identity = types::dht_types::DhtPeerIdentity {
            node_id: node_id.clone(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            did: String::from("did:zhtp:placeholder"),
            device_id: String::from("default"),
        };

        // Initialize DHT components
        let dht_manager = dht::node::DhtNodeManager::new(
            peer_identity.clone(),
            config.addresses.clone(),
        )?;

        // Initialize DHT storage with persistent SledBackend
        let dht_storage = dht::storage::DhtStorage::new_persistent(
            node_id.clone(),
            config.storage_config.max_storage_size,
            db_path,
        )?;

        tracing::info!(
            "Initialized persistent DHT storage with SledBackend - data will persist across restarts"
        );

        // Initialize economic manager
        let economic_manager = economic::manager::EconomicStorageManager::new(
            config.economic_config.clone(),
        );

        // Initialize content manager with in-memory storage (content metadata layer)
        // Note: Content storage is separate and can be made persistent in future phases
        let content_dht_storage = dht::storage::DhtStorage::new(
            node_id.clone(),
            config.storage_config.max_storage_size,
        );
        let content_manager = content::ContentManager::new(
            content_dht_storage,
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
                replay_rejections: 0,
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
}

// ============================================================================
// Generic methods available for ALL storage backends (HashMapBackend, SledBackend)
// ============================================================================

impl<B: dht::backend::StorageBackend + Send + Sync + 'static> UnifiedStorageSystem<B> {
    // ========================================================================
    // Web4 Domain Storage Integration - Domain Records Persistence (Generic)
    // ========================================================================

    /// Store a Web4 domain record in DHT storage (works with any backend)
    /// Uses key format: `web4/domain/{domain}`
    pub async fn store_domain_record(&mut self, domain: &str, record_data: &[u8]) -> Result<()> {
        // NAMESPACE GUARD: UnifiedStorageSystem only stores domain data, not blockchain
        if domain.starts_with("block_header:") || domain.starts_with("tx_idx:") {
            return Err(anyhow!(
                "NAMESPACE VIOLATION: UnifiedStorageSystem tried to store blockchain key '{}'. \
                This indicates cross-namespace pollution. Ensure MeshRouter uses separate DHT file.",
                domain
            ));
        }

        let key = format!("web4/domain/{}", domain);
        tracing::info!("Storing domain record for {} ({} bytes)", domain, record_data.len());
        self.dht_storage.store(key, record_data.to_vec(), None).await
    }

    /// Retrieve a Web4 domain record from DHT storage (works with any backend)
    /// Returns None if the domain is not found
    pub async fn get_domain_record(&mut self, domain: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("web4/domain/{}", domain);
        self.dht_storage.get(&key).await
    }

    /// Delete a Web4 domain record from DHT storage (works with any backend)
    pub async fn delete_domain_record(&mut self, domain: &str) -> Result<()> {
        let key = format!("web4/domain/{}", domain);
        tracing::info!("Deleting domain record for {}", domain);
        self.dht_storage.remove(&key).await?;
        Ok(())
    }

    /// List all Web4 domain records from DHT storage (works with any backend)
    /// Returns a list of (domain_name, record_data) tuples
    pub async fn list_domain_records(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        let prefix = "web4/domain/";
        let mut records = Vec::new();

        // Get all keys with the web4/domain/ prefix
        for key in self.dht_storage.list_keys_with_prefix(prefix).await? {
            if let Some(data) = self.dht_storage.get(&key).await? {
                // Extract domain name from key
                let domain = key.strip_prefix(prefix).unwrap_or(&key).to_string();
                records.push((domain, data));
            }
        }

        tracing::info!("Listed {} domain records from DHT storage", records.len());
        Ok(records)
    }

    // ========================================================================
    // Identity Storage Integration (Generic)
    // ========================================================================

    /// Store an identity record in DHT storage for fast lookups (works with any backend)
    /// Uses key format: `identity/{identity_id}`
    /// Payload is versioned: { "v": 1, "data": {...} }
    /// Also writes to backup file ~/.zhtp/backup/identities.json
    pub async fn store_identity_record(&mut self, identity_id: &str, record_data: &[u8]) -> Result<()> {
        let key = format!("identity/{}", identity_id);

        // Wrap in versioned envelope for future compatibility
        let versioned = serde_json::json!({
            "v": 1,
            "data": serde_json::from_slice::<serde_json::Value>(record_data)
                .unwrap_or_else(|_| serde_json::Value::String(hex::encode(record_data)))
        });
        let versioned_data = serde_json::to_vec(&versioned)
            .map_err(|e| anyhow::anyhow!("Failed to serialize versioned identity: {}", e))?;

        tracing::info!("Storing identity record {} ({} bytes, v1)", identity_id, versioned_data.len());

        // Write to backup file (shadow copy for safety)
        if let Err(e) = self.append_to_identity_backup(identity_id, &versioned).await {
            tracing::warn!("Failed to write identity backup (non-fatal): {}", e);
        }

        self.dht_storage.store(key, versioned_data, None).await
    }

    /// Append identity to backup JSON file (~/.zhtp/backup/identities.json)
    /// This is a shadow copy for safety - not referenced by application code
    async fn append_to_identity_backup(&self, identity_id: &str, data: &serde_json::Value) -> Result<()> {
        use std::io::{BufReader, BufWriter};

        let backup_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zhtp")
            .join("backup");

        // Create backup directory if needed
        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create backup dir: {}", e))?;

        let backup_path = backup_dir.join("identities.json");

        // Load existing backup or create new
        let mut backup: serde_json::Map<String, serde_json::Value> = if backup_path.exists() {
            let file = std::fs::File::open(&backup_path)
                .map_err(|e| anyhow::anyhow!("Failed to open backup: {}", e))?;
            let reader = BufReader::new(file);
            serde_json::from_reader(reader).unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

        // Add/update identity with timestamp
        let entry = serde_json::json!({
            "data": data,
            "backed_up_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        backup.insert(identity_id.to_string(), entry);

        // Write back atomically (write to temp, then rename)
        let temp_path = backup_dir.join("identities.json.tmp");
        let file = std::fs::File::create(&temp_path)
            .map_err(|e| anyhow::anyhow!("Failed to create temp backup: {}", e))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &backup)
            .map_err(|e| anyhow::anyhow!("Failed to write backup: {}", e))?;

        std::fs::rename(&temp_path, &backup_path)
            .map_err(|e| anyhow::anyhow!("Failed to finalize backup: {}", e))?;

        tracing::debug!("Identity {} backed up to {:?}", identity_id, backup_path);
        Ok(())
    }

    /// Retrieve an identity record from DHT storage (works with any backend)
    /// Returns None if identity not found, unwraps versioned payload
    pub async fn get_identity_record(&mut self, identity_id: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("identity/{}", identity_id);
        match self.dht_storage.get(&key).await? {
            Some(versioned_data) => {
                // Parse versioned envelope
                let envelope: serde_json::Value = serde_json::from_slice(&versioned_data)
                    .map_err(|e| anyhow::anyhow!("Failed to parse identity envelope: {}", e))?;

                let version = envelope.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
                if version != 1 {
                    tracing::warn!("Unknown identity record version {}, attempting to parse", version);
                }

                // Extract data field
                if let Some(data) = envelope.get("data") {
                    let data_bytes = serde_json::to_vec(data)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize identity data: {}", e))?;
                    Ok(Some(data_bytes))
                } else {
                    // Fallback: treat entire payload as data (legacy)
                    Ok(Some(versioned_data))
                }
            }
            None => Ok(None)
        }
    }

    // ========================================================================
    // System Statistics (Generic)
    // ========================================================================

    /// Get system statistics (works with any backend)
    pub async fn get_statistics(&mut self) -> Result<UnifiedStorageStats> {
        // Update economic stats
        self.stats.economic_stats = self.economic_manager.get_statistics().await?;

        // Update DHT stats
        self.stats.dht_stats = self.dht_manager.get_statistics();

        // Storage stats are updated in real-time during operations
        Ok(self.stats.clone())
    }

    // ========================================================================
    // DHT Index Management - Enables "load all" operations for persistence
    // ========================================================================
    // Key formats:
    // - idx/identities                      -> JSON array of identity_id strings
    // - idx/wallets/by_identity/{id}        -> JSON array of wallet_id strings
    // - wallet/{identity_id}/{wallet_id}    -> wallet metadata
    // - wallet_private/{identity_id}/{wallet_id} -> encrypted private data (existing)

    /// Add an identity ID to the global identity index
    ///
    /// Uses a HashSet internally for O(1) duplicate detection.
    /// Returns true if the identity was newly added, false if already present.
    pub async fn add_to_identity_index(&mut self, identity_id: &str) -> Result<()> {
        use std::collections::HashSet;

        if identity_id.is_empty() {
            return Err(anyhow::anyhow!("identity_id cannot be empty"));
        }

        let index_key = "idx/identities";

        // Load existing index or create empty set
        let mut ids: HashSet<String> = match self.dht_storage.get(index_key).await? {
            Some(data) => {
                // Parse as array, convert to HashSet
                let vec: Vec<String> = serde_json::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Corrupted identity index: {}", e))?;
                vec.into_iter().collect()
            }
            None => HashSet::new(),
        };

        // Add if not already present (HashSet.insert returns true if new)
        if ids.insert(identity_id.to_string()) {
            // Convert back to Vec for JSON serialization (HashSet order is arbitrary but that's fine)
            let vec: Vec<String> = ids.into_iter().collect();
            let data = serde_json::to_vec(&vec)
                .map_err(|e| anyhow::anyhow!("Failed to serialize identity index: {}", e))?;
            self.dht_storage.store(index_key.to_string(), data, None).await?;
            tracing::debug!("Added identity {} to index (total: {})", identity_id, vec.len());
        }

        Ok(())
    }

    /// Remove an identity ID from the global identity index
    pub async fn remove_from_identity_index(&mut self, identity_id: &str) -> Result<()> {
        use std::collections::HashSet;

        if identity_id.is_empty() {
            return Err(anyhow::anyhow!("identity_id cannot be empty"));
        }

        let index_key = "idx/identities";

        let mut ids: HashSet<String> = match self.dht_storage.get(index_key).await? {
            Some(data) => {
                let vec: Vec<String> = serde_json::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Corrupted identity index: {}", e))?;
                vec.into_iter().collect()
            }
            None => {
                tracing::debug!("Identity index not found, nothing to remove");
                return Ok(());
            }
        };

        if ids.remove(identity_id) {
            if ids.is_empty() {
                // Delete empty index instead of storing []
                self.dht_storage.remove(index_key).await?;
                tracing::debug!("Removed last identity from index, deleted key");
            } else {
                let vec: Vec<String> = ids.into_iter().collect();
                let data = serde_json::to_vec(&vec)?;
                self.dht_storage.store(index_key.to_string(), data, None).await?;
                tracing::debug!("Removed identity {} from index", identity_id);
            }
        }

        Ok(())
    }

    /// List all identity IDs from the index
    pub async fn list_identity_ids(&mut self) -> Result<Vec<String>> {
        let index_key = "idx/identities";

        match self.dht_storage.get(index_key).await? {
            Some(data) => {
                let ids: Vec<String> = serde_json::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Corrupted identity index: {}", e))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Rebuild the identity index from existing DHT keys
    ///
    /// This is a migration function that scans all `identity/` prefixed keys
    /// in the DHT storage and rebuilds the index. Used when the index is empty
    /// but identities exist in storage (e.g., identities created before indexing).
    ///
    /// Returns the number of identities indexed.
    pub async fn rebuild_identity_index_from_dht(&mut self) -> Result<u32> {
        use std::collections::HashSet;

        // Get all keys with "identity/" prefix
        let identity_keys = self.dht_storage.keys_with_prefix("identity/")?;

        if identity_keys.is_empty() {
            tracing::debug!("No identity keys found in DHT storage");
            return Ok(0);
        }

        // Extract identity IDs from keys (format: "identity/{identity_id}")
        let mut identity_ids = HashSet::new();
        for key in &identity_keys {
            if let Some(id) = key.strip_prefix("identity/") {
                if !id.is_empty() {
                    identity_ids.insert(id.to_string());
                }
            }
        }

        if identity_ids.is_empty() {
            tracing::debug!("No valid identity IDs found in DHT keys");
            return Ok(0);
        }

        let count = identity_ids.len() as u32;
        tracing::info!("🔄 Migration: Found {} identities in DHT storage, rebuilding index...", count);

        // Store as JSON array
        let ids_vec: Vec<String> = identity_ids.into_iter().collect();
        let data = serde_json::to_vec(&ids_vec)?;
        self.dht_storage.store("idx/identities".to_string(), data, None).await?;

        tracing::info!("✅ Migration complete: Indexed {} identities from DHT storage", count);
        Ok(count)
    }

    /// Add a wallet ID to an identity's wallet index
    pub async fn add_to_wallet_index(&mut self, identity_id: &str, wallet_id: &str) -> Result<()> {
        use std::collections::HashSet;

        if identity_id.is_empty() || wallet_id.is_empty() {
            return Err(anyhow::anyhow!("identity_id and wallet_id cannot be empty"));
        }

        let index_key = format!("idx/wallets/by_identity/{}", identity_id);

        let mut wallet_ids: HashSet<String> = match self.dht_storage.get(&index_key).await? {
            Some(data) => {
                let vec: Vec<String> = serde_json::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Corrupted wallet index for {}: {}", identity_id, e))?;
                vec.into_iter().collect()
            }
            None => HashSet::new(),
        };

        if wallet_ids.insert(wallet_id.to_string()) {
            let vec: Vec<String> = wallet_ids.into_iter().collect();
            let data = serde_json::to_vec(&vec)?;
            self.dht_storage.store(index_key, data, None).await?;
            tracing::debug!("Added wallet {} to identity {} index", wallet_id, identity_id);
        }

        Ok(())
    }

    /// List all wallet IDs for a given identity
    pub async fn list_wallet_ids_for_identity(&mut self, identity_id: &str) -> Result<Vec<String>> {
        let index_key = format!("idx/wallets/by_identity/{}", identity_id);

        match self.dht_storage.get(&index_key).await? {
            Some(data) => {
                let ids: Vec<String> = serde_json::from_slice(&data)
                    .map_err(|e| anyhow::anyhow!("Corrupted wallet index for {}: {}", identity_id, e))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Store wallet metadata record (public info, not private data)
    pub async fn store_wallet_record(&mut self, identity_id: &str, wallet_id: &str, data: &[u8]) -> Result<()> {
        let key = format!("wallet/{}/{}", identity_id, wallet_id);

        // Wrap in versioned envelope
        let versioned = serde_json::json!({
            "v": 1,
            "data": serde_json::from_slice::<serde_json::Value>(data)
                .unwrap_or_else(|_| serde_json::Value::String(hex::encode(data)))
        });
        let versioned_data = serde_json::to_vec(&versioned)?;

        tracing::info!("Storing wallet record {}/{} ({} bytes, v1)", identity_id, wallet_id, versioned_data.len());
        self.dht_storage.store(key, versioned_data, None).await
    }

    /// Retrieve wallet metadata record
    pub async fn get_wallet_record(&mut self, identity_id: &str, wallet_id: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("wallet/{}/{}", identity_id, wallet_id);

        match self.dht_storage.get(&key).await? {
            Some(versioned_data) => {
                // Parse versioned envelope
                let envelope: serde_json::Value = serde_json::from_slice(&versioned_data)?;

                if let Some(data) = envelope.get("data") {
                    let data_bytes = serde_json::to_vec(data)?;
                    Ok(Some(data_bytes))
                } else {
                    // Fallback: treat entire payload as data (legacy)
                    Ok(Some(versioned_data))
                }
            }
            None => Ok(None),
        }
    }

    /// Store wallet private data (encrypted) - convenience wrapper
    pub async fn store_wallet_private_record(&mut self, identity_id: &str, wallet_id: &str, data: &[u8]) -> Result<()> {
        let key = format!("wallet_private/{}/{}", identity_id, wallet_id);
        tracing::info!("Storing wallet private data {}/{} ({} bytes)", identity_id, wallet_id, data.len());
        self.dht_storage.store(key, data.to_vec(), None).await
    }

    /// Retrieve wallet private data (encrypted)
    pub async fn get_wallet_private_record(&mut self, identity_id: &str, wallet_id: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("wallet_private/{}/{}", identity_id, wallet_id);
        self.dht_storage.get(&key).await
    }

    // ========================================================================
    // Content Retrieval (Generic)
    // ========================================================================

    /// Get DHT content by hex hash string (works with any backend)
    /// CRITICAL FIX: Content is stored in content_manager's dht_storage, not self.dht_storage!
    pub async fn get_dht_content_by_hex(&mut self, content_hash_hex: &str) -> Result<Option<Vec<u8>>> {
        // FIXED: Query the SAME dht_storage instance that upload_content() stores to
        // Content is stored via content_manager.dht_storage, so we must query from there
        self.content_manager.get_from_dht_storage(content_hash_hex).await
    }

    // ========================================================================
    // Erasure Coding Storage (Generic)
    // ========================================================================

    /// Store data with erasure coding (works with any backend)
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

        // Upload content via content_manager
        let content_hash = self.content_manager.upload_content(upload_request, uploader).await?;

        // Store encoded shards separately for redundancy
        let shards_data = bincode::serialize(&encoded_shards)?;
        let shards_hash = Hash::from_bytes(&blake3::hash(&shards_data).as_bytes()[..32]);

        self.dht_storage.store_data(shards_hash, shards_data).await?;

        Ok(content_hash)
    }
}

impl Default for UnifiedStorageConfig {
    fn default() -> Self {
        Self {
            node_id: NodeId::from_bytes(rand::random::<[u8; 32]>()),
            addresses: vec!["127.0.0.1:33445".to_string()], // Bind to localhost only for local mesh operation
            economic_config: EconomicManagerConfig::default(),
            storage_config: StorageConfig {
                max_storage_size: 100_000_000_000, // 100GB
                default_tier: StorageTier::Hot,
                enable_compression: true,
                enable_encryption: true,
                dht_persist_path: None, // Default has no persistence - runtime initialization sets this
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

/// Type alias for persistent storage using SledBackend
///
/// Use this type when you need storage that persists across restarts.
/// Create instances with `UnifiedStorageSystem::new_persistent()`.
pub type PersistentStorageSystem = UnifiedStorageSystem<dht::backend::SledBackend>;

#[cfg(test)]
mod tests {
    use super::*;
    
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
                replay_rejections: 0,
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
    // TODO: Create a GitHub issue to track re-enabling this test.
    // It is currently ignored because ZhtpIdentity secure deserialization is restricted,
    // and a solution needs to be implemented and verified.
    #[ignore = "ZhtpIdentity secure deserialization currently restricted"]
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
        use lib_crypto::{PrivateKey, PublicKey};
        use lib_identity::types::IdentityType;
        use lib_proofs::ZeroKnowledgeProof;

        let public_key = PublicKey {
            dilithium_pk: vec![1, 2, 3],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        };
        let private_key = PrivateKey {
            dilithium_sk: vec![4, 5, 6],
            kyber_sk: vec![],
            master_seed: vec![7, 8, 9],
        };
        let ownership_proof = ZeroKnowledgeProof::new(
            "test".to_string(),
            vec![],
            vec![],
            vec![],
            None,
        );

        let mut identity = ZhtpIdentity::new(
            IdentityType::Human,
            public_key,
            private_key,
            "laptop".to_string(),
            Some(30),
            Some("us".to_string()),
            true,
            ownership_proof,
        )
        .expect("valid test identity");

        identity.id = identity_id;
        identity.created_at = created_at;
        identity.last_active = created_at;
        identity
    }
}
