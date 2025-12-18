//! Content Management Module
//! 
//! High-level content management with access control, versioning, and search capabilities.
//! Integrates with DHT storage and economic manager for contract creation.
//! Enhanced with encryption and key management using lib-crypto.

use crate::types::*;
use crate::types::economic_types::{EconomicManagerConfig, PaymentSchedule, DisputeResolution,
                                   QualityRequirements, BudgetConstraints, EconomicStorageRequest, 
                                   PaymentPreferences, EscrowPreferences}; // Explicit import
use crate::dht::storage::DhtStorage;
use crate::economic::manager::EconomicStorageManager;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_crypto::{Hash, KeyPair, encrypt_data, decrypt_data, derive_keys, hash_blake3};
use lib_identity::ZhtpIdentity;
use log::info;

/// High-level content manager with encryption and key management
#[derive(Debug)]
pub struct ContentManager {
    /// DHT storage backend
    dht_storage: DhtStorage,
    /// Economic manager for contracts
    economic_manager: EconomicStorageManager,
    /// Content metadata
    content_metadata: HashMap<ContentHash, ContentMetadata>,
    /// Access control lists
    access_control: HashMap<ContentHash, AccessControlList>,
    /// Content versions
    content_versions: HashMap<ContentHash, Vec<ContentVersion>>,
    /// Search index
    search_index: HashMap<String, Vec<ContentHash>>,
    /// Master encryption keypair for this storage node
    master_keypair: KeyPair,
    /// Content encryption keys (per content hash)
    content_keys: HashMap<ContentHash, [u8; 32]>,
    /// Key derivation info for reproducible key generation
    key_derivation_salt: [u8; 32],
    /// Wallet-content ownership manager
    wallet_content_manager: crate::wallet_content_integration::WalletContentManager,
}

/// Access control list for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlList {
    /// Content hash
    pub content_hash: ContentHash,
    /// Owner (full access)
    pub owner: ZhtpIdentity,
    /// Read permissions
    pub read_permissions: Vec<ZhtpIdentity>,
    /// Write permissions
    pub write_permissions: Vec<ZhtpIdentity>,
    /// Public read access
    pub public_read: bool,
    /// Access expiry timestamp
    pub expires_at: Option<u64>,
}

/// Content version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentVersion {
    /// Version number
    pub version: u32,
    /// Content hash for this version
    pub content_hash: ContentHash,
    /// Timestamp of this version
    pub created_at: u64,
    /// Version description
    pub description: String,
    /// Size of this version
    pub size: u64,
}

/// Upload request configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequest {
    /// File content
    pub content: Vec<u8>,
    /// Filename
    pub filename: String,
    /// MIME type
    pub mime_type: String,
    /// Description
    pub description: String,
    /// Tags for search
    pub tags: Vec<String>,
    /// Enable encryption
    pub encrypt: bool,
    /// Enable compression
    pub compress: bool,
    /// Access control settings
    pub access_control: AccessControlSettings,
    /// Storage requirements
    pub storage_requirements: ContentStorageRequirements,
}

/// Access control settings for upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlSettings {
    /// Public read access
    pub public_read: bool,
    /// Read permissions
    pub read_permissions: Vec<ZhtpIdentity>,
    /// Write permissions
    pub write_permissions: Vec<ZhtpIdentity>,
    /// Access expiry timestamp
    pub expires_at: Option<u64>,
}

/// Storage requirements for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentStorageRequirements {
    /// Storage duration in days
    pub duration_days: u32,
    /// Quality requirements
    pub quality_requirements: QualityRequirements,
    /// Budget constraints
    pub budget_constraints: BudgetConstraints,
}

/// Download request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequest {
    /// Content hash to download
    pub content_hash: ContentHash,
    /// Requesting user identity
    pub requester: ZhtpIdentity,
    /// Specific version (None for latest)
    pub version: Option<u32>,
}

/// Search query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Search terms
    pub terms: Vec<String>,
    /// MIME type filter
    pub mime_type_filter: Option<String>,
    /// Owner filter
    pub owner_filter: Option<ZhtpIdentity>,
    /// Size range filter (min, max)
    pub size_range: Option<(u64, u64)>,
    /// Date range filter (start, end timestamps)
    pub date_range: Option<(u64, u64)>,
    /// Tag filter
    pub tag_filter: Option<Vec<String>>,
}

impl ContentManager {
    /// Create new content manager with encryption capabilities
    pub fn new(
        dht_storage: DhtStorage,
        economic_config: EconomicManagerConfig,
    ) -> Result<Self> {
        // Generate master keypair for this storage node
        let master_keypair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate master keypair: {}", e))?;
        
        // Generate key derivation salt
        let mut salt = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        
        Ok(Self {
            dht_storage,
            economic_manager: EconomicStorageManager::new(economic_config),
            content_metadata: HashMap::new(),
            access_control: HashMap::new(),
            content_versions: HashMap::new(),
            search_index: HashMap::new(),
            master_keypair,
            content_keys: HashMap::new(),
            key_derivation_salt: salt,
            wallet_content_manager: crate::wallet_content_integration::WalletContentManager::new(),
        })
    }
    
    /// Create new content manager with existing keypair
    pub fn new_with_keypair(
        dht_storage: DhtStorage,
        economic_config: EconomicManagerConfig,
        master_keypair: KeyPair,
        key_derivation_salt: [u8; 32],
    ) -> Self {
        Self {
            dht_storage,
            economic_manager: EconomicStorageManager::new(economic_config),
            content_metadata: HashMap::new(),
            access_control: HashMap::new(),
            content_versions: HashMap::new(),
            search_index: HashMap::new(),
            master_keypair,
            content_keys: HashMap::new(),
            key_derivation_salt,
            wallet_content_manager: crate::wallet_content_integration::WalletContentManager::new(),
        }
    }
    
    /// Get master public key for key exchange
    pub fn get_master_public_key(&self) -> &lib_crypto::PublicKey {
        &self.master_keypair.public_key
    }
    
    /// Generate or retrieve content encryption key
    fn get_or_create_content_key(&mut self, content_hash: &ContentHash) -> Result<[u8; 32]> {
        if let Some(key) = self.content_keys.get(content_hash) {
            return Ok(*key);
        }
        
        // Derive deterministic key for this content
        let key_info = [
            b"ZHTP-content-key-v1",
            content_hash.as_bytes(),
            &self.key_derivation_salt,
        ].concat();
        
        let derived_key = derive_keys(&self.master_keypair.private_key.dilithium_sk[..32], &key_info, 32)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&derived_key[..32]);
        
        // Cache the key
        self.content_keys.insert(content_hash.clone(), key_array);
        
        Ok(key_array)
    }

    /// Upload content with access control and economic contract
    pub async fn upload_content(
        &mut self,
        request: UploadRequest,
        uploader: ZhtpIdentity,
    ) -> Result<ContentHash> {
        // Calculate hash of ORIGINAL content before processing
        let original_hash = Hash::from_bytes(&blake3::hash(&request.content).as_bytes()[..32]);
        let original_size = request.content.len();
        
        info!(" 📤 Uploading content: {} bytes", original_size);
        info!("    Original hash: {}", hex::encode(original_hash.as_bytes()));
        info!("    Compress: {}, Encrypt: {}", request.compress, request.encrypt);
        
        // Process content (compression, encryption)
        let processed_content = self.process_content_for_upload(&request).await?;
        
        // Calculate hash of PROCESSED content (what's actually stored in DHT)
        let content_hash = Hash::from_bytes(&blake3::hash(&processed_content).as_bytes()[..32]);
        let processed_size = processed_content.len();

        info!("  Processed content: {} bytes", processed_size);
        info!("    Storage hash: {}", hex::encode(content_hash.as_bytes()));
        if request.compress || request.encrypt {
            info!("      Storage hash differs from original due to processing!");
        }
        
        // If content was encrypted, the key was stored under the pre-encryption hash.
        // We need to also register it under the final (post-encryption) hash for retrieval.
        if request.encrypt {
            // Get the pre-encryption hash (after possible compression)
            let pre_encryption_content = if request.compress {
                self.compress_content(&request.content).await?
            } else {
                request.content.clone()
            };
            let pre_encryption_hash = Hash::from_bytes(&blake3::hash(&pre_encryption_content).as_bytes()[..32]);
            
            // Copy encryption key from pre-encryption hash to post-encryption hash
            if let Some(key) = self.content_keys.get(&pre_encryption_hash).cloned() {
                self.content_keys.insert(content_hash.clone(), key);
                info!("    Registered encryption key under storage hash for decryption");
            }
        }

        // Create economic storage request
        let _economic_request = EconomicStorageRequest {
            content: processed_content.clone(),
            filename: request.filename.clone(),
            content_type: request.mime_type.clone(),
            description: request.description.clone(),
            preferred_tier: StorageTier::Hot, // Default tier since StorageRequirements doesn't have preferred_tier
            requirements: StorageRequirements {
                duration_days: request.storage_requirements.duration_days,
                quality_requirements: request.storage_requirements.quality_requirements.clone(),
                budget_constraints: request.storage_requirements.budget_constraints.clone(),
                replication_factor: 3, // Default replication
                geographic_preferences: vec![], // No specific preferences
            },
            payment_preferences: PaymentPreferences {
                escrow_preferences: EscrowPreferences {
                    use_escrow: true,
                    release_threshold: 0.8,
                    dispute_resolution: DisputeResolution::Arbitration,
                },
                payment_schedule: PaymentSchedule::Monthly,
                max_upfront_percentage: 0.5,
            },
            requester: uploader.clone(),
        };

        // TESTING MODE: Skip provider registration and economic contracts - store directly in DHT
        info!(" TEST MODE: Bypassing storage provider registration, storing directly in DHT");
        
        // Skip economic manager for testing
        // let quote = self.economic_manager.process_storage_request(economic_request).await?;
        // let _contract_id = self.economic_manager.create_contract(quote, content_hash.clone(), processed_content.len() as u64).await?;

        // Store content directly in DHT (no provider requirements)
        let hex_hash = hex::encode(content_hash.as_bytes());
        info!(" Storing {} bytes directly in DHT storage (test mode) with hash: {}", processed_content.len(), hex_hash);
        self.dht_storage.store_data(content_hash.clone(), processed_content.clone()).await?;
        info!("  Content stored in DHT with hex key: {}", hex_hash);

        // Create metadata
        let upload_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let metadata = ContentMetadata {
            hash: content_hash.clone(),
            content_hash: content_hash.clone(),
            filename: request.filename.clone(),
            size: request.content.len() as u64,
            content_type: request.mime_type.clone(),
            created_at: upload_time,
            last_accessed: upload_time,
            owner: uploader.clone(),
            description: request.description.clone(),
            tags: request.tags.clone(),
            is_encrypted: request.encrypt,
            is_compressed: request.compress,
            tier: StorageTier::Hot, // Default to hot storage
            encryption: if request.encrypt { EncryptionLevel::Standard } else { EncryptionLevel::None },
            access_pattern: AccessPattern::Frequent, // Default access pattern
            replication_factor: 3, // Default replication
            access_count: 0,
            expires_at: None,
            cost_per_day: 100, // Default cost
            access_control: vec![AccessLevel::Private], // Default to private
            total_chunks: 1, // Single chunk for now
            checksum: content_hash.clone(), // Use content hash as checksum
        };

        // Extract wallet ID for content ownership registration (before uploader is moved)
        let owner_wallet_id = uploader.wallet_manager.wallets.values().next().map(|w| w.id.clone());
        
        // Create access control
        let acl = AccessControlList {
            content_hash: content_hash.clone(),
            owner: uploader,
            read_permissions: request.access_control.read_permissions,
            write_permissions: request.access_control.write_permissions,
            public_read: request.access_control.public_read,
            expires_at: request.access_control.expires_at,
        };

        // Store metadata and ACL
        self.content_metadata.insert(content_hash.clone(), metadata);
        self.access_control.insert(content_hash.clone(), acl);

        // Create initial version
        let version = ContentVersion {
            version: 1,
            content_hash: content_hash.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            description: "Initial version".to_string(),
            size: request.content.len() as u64,
        };

        self.content_versions.insert(content_hash.clone(), vec![version]);

        // Update search index
        self.update_search_index(&content_hash, &request.tags, &request.filename).await?;

        // Store metadata in DHT for distributed access
        if let Err(e) = self.store_metadata_in_dht(&content_hash).await {
            log::warn!("Failed to store metadata in DHT: {}", e);
        }

        // Register content ownership with uploader's wallet
        if let Some(wallet_id) = owner_wallet_id {
            // Get the metadata we just stored
            if let Some(metadata) = self.content_metadata.get(&content_hash) {
                // Register ownership (no purchase price for uploads)
                if let Err(e) = self.wallet_content_manager.register_content_ownership(
                    content_hash.clone(),
                    wallet_id,
                    metadata,
                    0, // No purchase price for uploads
                ) {
                    log::warn!("Failed to register content ownership: {}", e);
                }
            }
        }

        Ok(content_hash)
    }

    /// Store content metadata in DHT for distributed access
    async fn store_metadata_in_dht(&mut self, content_hash: &ContentHash) -> Result<()> {
        // Get metadata from local cache
        let metadata = self.content_metadata.get(content_hash)
            .ok_or_else(|| anyhow!("Metadata not found for content hash"))?;
        
        // Serialize metadata to binary
        let serialized_metadata = bincode::serialize(metadata)
            .map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
        
        // Create DHT key for metadata: hash("metadata:{content_hash}")
        let metadata_key_bytes = [b"metadata:", content_hash.as_bytes()].concat();
        let metadata_hash = hash_blake3(&metadata_key_bytes);
        let metadata_key = Hash::from_bytes(&metadata_hash[..32]);
        
        // Store in DHT
        self.dht_storage.store_data(metadata_key, serialized_metadata).await?;
        
        info!(" Stored metadata for content {} in DHT", hex::encode(&content_hash.as_bytes()[..8]));
        Ok(())
    }

    /// Retrieve content metadata from DHT or local cache
    pub async fn get_content_metadata(&mut self, content_hash: &ContentHash) -> Result<ContentMetadata> {
        // Try local cache first
        if let Some(metadata) = self.content_metadata.get(content_hash) {
            return Ok(metadata.clone());
        }
        
        // Retrieve from DHT
        let metadata_key_bytes = [b"metadata:", content_hash.as_bytes()].concat();
        let metadata_hash = hash_blake3(&metadata_key_bytes);
        let metadata_key = Hash::from_bytes(&metadata_hash[..32]);
        
        let serialized_metadata = self.dht_storage.retrieve_data(metadata_key).await?
            .ok_or_else(|| anyhow!("Metadata not found in DHT for content hash"))?;
        
        // Deserialize metadata
        let metadata: ContentMetadata = bincode::deserialize(&serialized_metadata)
            .map_err(|e| anyhow!("Failed to deserialize metadata: {}", e))?;
        
        // Cache locally
        self.content_metadata.insert(content_hash.clone(), metadata.clone());
        
        info!("📥 Retrieved metadata for content {} from DHT", hex::encode(&content_hash.as_bytes()[..8]));
        Ok(metadata)
    }

    /// Calculate storage cost based on size, tier, and replication
    pub fn calculate_storage_cost(&self, size: u64, tier: &StorageTier, replication_factor: u8, duration_days: u32) -> u64 {
        // Base cost per GB per day
        let base_cost_per_gb_day = match tier {
            StorageTier::Hot => 100,      // 100 ZHTP per GB per day
            StorageTier::Warm => 50,      // 50 ZHTP per GB per day
            StorageTier::Cold => 10,      // 10 ZHTP per GB per day
            StorageTier::Archive => 1,    // 1 ZHTP per GB per day
        };
        
        // Calculate size in GB
        let size_gb = (size as f64) / (1024.0 * 1024.0 * 1024.0);
        
        // Apply replication multiplier
        let replication_multiplier = replication_factor as f64;
        
        // Calculate total cost
        let cost_per_day = (size_gb * base_cost_per_gb_day as f64 * replication_multiplier).ceil() as u64;
        let total_cost = cost_per_day * duration_days as u64;
        
        // Minimum cost of 1 ZHTP per day
        total_cost.max(duration_days as u64)
    }

    /// Download content with access control checks
    pub async fn download_content(
        &mut self,
        request: DownloadRequest,
    ) -> Result<Vec<u8>> {
        // Check access permissions
        if !self.check_read_permission(&request.content_hash, &request.requester).await? {
            return Err(anyhow!("Access denied"));
        }

        // Get content hash for specific version if requested
        let content_hash = if let Some(version) = request.version {
            self.get_version_hash(&request.content_hash, version)?
        } else {
            request.content_hash.clone()
        };

        // Update metadata access tracking
        if let Some(metadata) = self.content_metadata.get_mut(&content_hash) {
            metadata.last_accessed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            metadata.access_count += 1;
            
            // Update in DHT (don't fail download if this fails)
            if let Err(e) = self.store_metadata_in_dht(&content_hash).await {
                log::warn!("Failed to update metadata in DHT: {}", e);
            }
        }

        // Retrieve from DHT
        let content = self.dht_storage.retrieve_data(content_hash.clone()).await?
            .ok_or_else(|| anyhow!("Content not found"))?;

        // Process content (decompression, decryption)
        let processed_content = self.process_content_for_download(&content_hash, content).await?;

        Ok(processed_content)
    }

    /// Search for content
    pub async fn search_content(
        &self,
        query: SearchQuery,
        requester: ZhtpIdentity,
    ) -> Result<Vec<ContentMetadata>> {
        let mut results = Vec::new();

        // Search by terms
        let mut candidate_hashes = Vec::new();
        
        if query.terms.is_empty() {
            // No search terms, get all content
            candidate_hashes.extend(self.content_metadata.keys().cloned());
        } else {
            // Search in index
            for term in &query.terms {
                if let Some(hashes) = self.search_index.get(term) {
                    candidate_hashes.extend(hashes.iter().cloned());
                }
            }
        }

        // Remove duplicates without sorting
        candidate_hashes.dedup();

        // Apply filters and access control
        for content_hash in candidate_hashes {
            if let Some(metadata) = self.content_metadata.get(&content_hash) {
                // Check access permissions
                if !self.check_read_permission(&content_hash, &requester).await? {
                    continue;
                }

                // Apply filters
                if let Some(mime_filter) = &query.mime_type_filter {
                    if &metadata.content_type != mime_filter {
                        continue;
                    }
                }

                if let Some(owner_filter) = &query.owner_filter {
                    if &metadata.owner != owner_filter {
                        continue;
                    }
                }

                if let Some((min_size, max_size)) = query.size_range {
                    if metadata.size < min_size || metadata.size > max_size {
                        continue;
                    }
                }

                if let Some((start_date, end_date)) = query.date_range {
                    if metadata.created_at < start_date || metadata.created_at > end_date {
                        continue;
                    }
                }

                if let Some(tag_filter) = &query.tag_filter {
                    let has_all_tags = tag_filter.iter().all(|tag| metadata.tags.contains(tag));
                    if !has_all_tags {
                        continue;
                    }
                }

                results.push(metadata.clone());
            }
        }

        Ok(results)
    }

    /// Update content (creates new version)
    pub async fn update_content(
        &mut self,
        content_hash: ContentHash,
        new_content: Vec<u8>,
        description: String,
        updater: ZhtpIdentity,
    ) -> Result<ContentHash> {
        // Check write permissions
        if !self.check_write_permission(&content_hash, &updater).await? {
            return Err(anyhow!("Write access denied"));
        }

        // Store content size for later use
        let content_size = new_content.len();

        // Process new content
        let processed_content = if let Some(metadata) = self.content_metadata.get(&content_hash) {
            if metadata.is_compressed {
                self.compress_content(&new_content).await?
            } else {
                new_content.clone()
            }
        } else {
            return Err(anyhow!("Content not found"));
        };

        let new_content_hash = Hash::from_bytes(&blake3::hash(&processed_content).as_bytes()[..32]);

        // Store new version in DHT
        self.dht_storage.store_data(new_content_hash.clone(), processed_content).await?;

        // Create new version entry
        let versions = self.content_versions.get_mut(&content_hash)
            .ok_or_else(|| anyhow!("Content versions not found"))?;

        let version_number = versions.len() as u32 + 1;
        let new_version = ContentVersion {
            version: version_number,
            content_hash: new_content_hash.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            description,
            size: content_size as u64,
        };

        versions.push(new_version);

        Ok(new_content_hash)
    }

    /// Delete content (with access control)
    pub async fn delete_content(
        &mut self,
        content_hash: ContentHash,
        deleter: ZhtpIdentity,
    ) -> Result<()> {
        // Check if user is owner
        if let Some(acl) = self.access_control.get(&content_hash) {
            if acl.owner != deleter {
                return Err(anyhow!("Only owner can delete content"));
            }
        } else {
            return Err(anyhow!("Content not found"));
        }

        // Remove from DHT
        self.dht_storage.remove_data(content_hash.clone()).await?;

        // Remove all versions from DHT
        if let Some(versions) = self.content_versions.get(&content_hash) {
            for version in versions {
                self.dht_storage.remove_data(version.content_hash.clone()).await?;
            }
        }

        // Remove metadata
        self.content_metadata.remove(&content_hash);
        self.access_control.remove(&content_hash);
        self.content_versions.remove(&content_hash);

        // Remove from search index
        self.remove_from_search_index(&content_hash).await?;

        Ok(())
    }

    /// Get content metadata
    pub fn get_metadata(&self, content_hash: &ContentHash) -> Option<&ContentMetadata> {
        self.content_metadata.get(content_hash)
    }

    /// Get content versions
    pub fn get_versions(&self, content_hash: &ContentHash) -> Option<&Vec<ContentVersion>> {
        self.content_versions.get(content_hash)
    }

    /// Check read permission
    async fn check_read_permission(&self, content_hash: &ContentHash, requester: &ZhtpIdentity) -> Result<bool> {
        if let Some(acl) = self.access_control.get(content_hash) {
            // Check expiry
            if let Some(expires_at) = acl.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > expires_at {
                    return Ok(false);
                }
            }

            // Check permissions
            Ok(acl.public_read 
                || &acl.owner == requester 
                || acl.read_permissions.contains(requester)
                || acl.write_permissions.contains(requester))
        } else {
            Ok(false)
        }
    }

    /// Check write permission
    async fn check_write_permission(&self, content_hash: &ContentHash, requester: &ZhtpIdentity) -> Result<bool> {
        if let Some(acl) = self.access_control.get(content_hash) {
            Ok(&acl.owner == requester || acl.write_permissions.contains(requester))
        } else {
            Ok(false)
        }
    }

    /// Process content for upload with encryption
    async fn process_content_for_upload(&mut self, request: &UploadRequest) -> Result<Vec<u8>> {
        let mut content = request.content.clone();

        if request.compress {
            content = self.compress_content(&content).await?;
        }

        if request.encrypt {
            // Pre-calculate content hash for key derivation
            let content_hash_bytes = hash_blake3(&content);
            let content_hash = Hash::from_bytes(&content_hash_bytes[..32]);
            
            // Get or create encryption key for this content
            let encryption_key = self.get_or_create_content_key(&content_hash)?;
            
            // Encrypt using ChaCha20-Poly1305
            content = encrypt_data(&content, &encryption_key)
                .map_err(|e| anyhow!("Content encryption failed: {}", e))?;
        }

        Ok(content)
    }

    /// Process content for download with decryption
    async fn process_content_for_download(&mut self, content_hash: &ContentHash, content: Vec<u8>) -> Result<Vec<u8>> {
        let mut processed = content;

        // Get metadata before borrowing self mutably
        let (is_encrypted, is_compressed) = if let Some(metadata) = self.content_metadata.get(content_hash) {
            (metadata.is_encrypted, metadata.is_compressed)
        } else {
            (false, false)
        };

        if is_encrypted {
            processed = self.decrypt_content(&processed, content_hash).await?;
        }

        if is_compressed {
            processed = self.decompress_content(&processed).await?;
        }

        Ok(processed)
    }

    /// Compress content using LZ4 compression
    async fn compress_content(&self, content: &[u8]) -> Result<Vec<u8>> {
        // Use LZ4 compression for fast compression/decompression
        let compressed = lz4_flex::compress_prepend_size(content);
        Ok(compressed)
    }

    /// Decompress content using LZ4 decompression
    async fn decompress_content(&self, content: &[u8]) -> Result<Vec<u8>> {
        // Use LZ4 decompression
        let decompressed = lz4_flex::decompress_size_prepended(content)
            .map_err(|e| anyhow::anyhow!("Decompression failed: {}", e))?;
        Ok(decompressed)
    }

    /// Decrypt content using ChaCha20-Poly1305 decryption
    async fn decrypt_content(&mut self, content: &[u8], content_hash: &ContentHash) -> Result<Vec<u8>> {
        // Get content-specific encryption key
        let encryption_key = self.get_or_create_content_key(content_hash)?;
        
        // Decrypt using ChaCha20-Poly1305
        decrypt_data(content, &encryption_key)
            .map_err(|e| anyhow!("Content decryption failed: {}", e))
    }

    /// Update search index
    async fn update_search_index(&mut self, content_hash: &ContentHash, tags: &[String], filename: &str) -> Result<()> {
        // Index tags
        for tag in tags {
            self.search_index.entry(tag.to_lowercase())
                .or_insert_with(Vec::new)
                .push(content_hash.clone());
        }

        // Index filename words
        for word in filename.split_whitespace() {
            self.search_index.entry(word.to_lowercase())
                .or_insert_with(Vec::new)
                .push(content_hash.clone());
        }

        Ok(())
    }

    /// Remove from search index
    async fn remove_from_search_index(&mut self, content_hash: &ContentHash) -> Result<()> {
        for hashes in self.search_index.values_mut() {
            hashes.retain(|h| h != content_hash);
        }

        // Remove empty entries
        self.search_index.retain(|_, hashes| !hashes.is_empty());

        Ok(())
    }

    /// Export encryption keys for backup/migration
    pub fn export_content_keys(&self) -> Vec<(ContentHash, [u8; 32])> {
        self.content_keys.iter().map(|(hash, key)| (hash.clone(), *key)).collect()
    }
    
    /// Import encryption keys from backup/migration
    pub fn import_content_keys(&mut self, keys: Vec<(ContentHash, [u8; 32])>) {
        for (hash, key) in keys {
            self.content_keys.insert(hash, key);
        }
    }
    
    /// Rotate master key (generates new keypair and re-encrypts all content keys)
    pub fn rotate_master_key(&mut self) -> Result<()> {
        // Generate new master keypair
        let new_keypair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate new master keypair: {}", e))?;
        
        // Re-derive all content keys with new master key
        let mut new_content_keys = HashMap::new();
        for (content_hash, _old_key) in &self.content_keys {
            let key_info = [
                b"ZHTP-content-key-v1",
                content_hash.as_bytes(),
                &self.key_derivation_salt,
            ].concat();
            
            let derived_key = derive_keys(&new_keypair.private_key.dilithium_sk[..32], &key_info, 32)?;
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&derived_key[..32]);
            
            new_content_keys.insert(content_hash.clone(), key_array);
        }
        
        // Update with new keypair and keys
        self.master_keypair = new_keypair;
        self.content_keys = new_content_keys;
        
        Ok(())
    }
    
    /// Get key derivation salt for backup
    pub fn get_key_derivation_salt(&self) -> [u8; 32] {
        self.key_derivation_salt
    }

    // ========================================================================
    // Identity Storage Integration - Connecting with DHT storage
    // ========================================================================

    /// Store identity credentials in the unified storage system (DHT)
    pub async fn store_identity_credentials(
        &mut self,
        identity_id: &lib_identity::IdentityId,
        credentials: &lib_identity::ZhtpIdentity,
        passphrase: &str,
    ) -> Result<()> {
        // Prepare a safe serialized view + private key for reconstruction
        // Build SerializedView inline to avoid forbidden direct deserialization
        #[derive(serde::Serialize)]
        struct PrivateKeyBlob {
            dilithium_sk: Vec<u8>,
            kyber_sk: Vec<u8>,
            master_seed: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        struct IdentityBlob {
            json_view: String,
            private_key: PrivateKeyBlob,
        }
        #[derive(serde::Serialize)]
        struct SerializedViewCompat {
            id: lib_identity::IdentityId,
            identity_type: lib_identity::types::IdentityType,
            did: String,
            public_key: lib_crypto::PublicKey,
            node_id: lib_identity::types::NodeId,
            device_node_ids: std::collections::HashMap<String, lib_identity::types::NodeId>,
            primary_device: String,
            ownership_proof: lib_proofs::ZeroKnowledgeProof,
            credentials: std::collections::HashMap<lib_identity::types::CredentialType, lib_identity::credentials::ZkCredential>,
            reputation: u64,
            age: Option<u64>,
            access_level: lib_identity::types::AccessLevel,
            metadata: std::collections::HashMap<String, String>,
            private_data_id: Option<lib_identity::IdentityId>,
            wallet_manager: lib_identity::wallets::WalletManager,
            attestations: Vec<lib_identity::credentials::IdentityAttestation>,
            created_at: u64,
            last_active: u64,
            recovery_keys: Vec<Vec<u8>>,
            did_document_hash: Option<lib_crypto::Hash>,
            owner_identity_id: Option<lib_identity::IdentityId>,
            reward_wallet_id: Option<lib_identity::wallets::WalletId>,
            dao_member_id: String,
            dao_voting_power: u64,
            citizenship_verified: bool,
            jurisdiction: Option<String>,
        }

        // Extract private key; required for safe reconstruction
        let private_key = credentials.private_key.clone().ok_or_else(|| anyhow::anyhow!("Identity missing private key for storage"))?;
        let private_key_blob = PrivateKeyBlob {
            dilithium_sk: private_key.dilithium_sk.clone(),
            kyber_sk: private_key.kyber_sk.clone(),
            master_seed: private_key.master_seed.clone(),
        };

        let serialized_view = SerializedViewCompat {
            id: credentials.id.clone(),
            identity_type: credentials.identity_type.clone(),
            did: credentials.did.clone(),
            public_key: credentials.public_key.clone(),
            node_id: credentials.node_id.clone(),
            device_node_ids: credentials.device_node_ids.clone(),
            primary_device: credentials.primary_device.clone(),
            ownership_proof: credentials.ownership_proof.clone(),
            credentials: credentials.credentials.clone(),
            reputation: credentials.reputation,
            age: credentials.age,
            access_level: credentials.access_level.clone(),
            metadata: credentials.metadata.clone(),
            private_data_id: credentials.private_data_id.clone(),
            wallet_manager: credentials.wallet_manager.clone(),
            attestations: credentials.attestations.clone(),
            created_at: credentials.created_at,
            last_active: credentials.last_active,
            recovery_keys: credentials.recovery_keys.clone(),
            did_document_hash: credentials.did_document_hash.clone(),
            owner_identity_id: credentials.owner_identity_id.clone(),
            reward_wallet_id: credentials.reward_wallet_id.clone(),
            dao_member_id: credentials.dao_member_id.clone(),
            dao_voting_power: credentials.dao_voting_power,
            citizenship_verified: credentials.citizenship_verified,
            jurisdiction: credentials.jurisdiction.clone(),
        };

        let json_view = serde_json::to_string(&serialized_view)?;
        let blob = IdentityBlob { json_view, private_key: private_key_blob };
        let credentials_data = bincode::serialize(&blob)?;
        let encryption_key = self.derive_key_from_passphrase(passphrase, identity_id.as_bytes())?;
        let encrypted_credentials = encrypt_data(&credentials_data, &encryption_key)?;

        // Create storage key for the identity using content hash approach
        let storage_hash = hash_blake3(&[b"identity:", identity_id.as_bytes()].concat());
        let content_hash = Hash::from_bytes(&storage_hash[..32]);

        // Store in DHT for distributed access
        self.dht_storage.store_data(content_hash, encrypted_credentials).await?;

        println!("Stored identity credentials for ID: {}", hex::encode(identity_id.as_bytes()));
        Ok(())
    }

    /// Retrieve identity credentials from unified storage (DHT)
    pub async fn retrieve_identity_credentials(
        &mut self,
        identity_id: &lib_identity::IdentityId,
        passphrase: &str,
    ) -> Result<lib_identity::ZhtpIdentity> {
        // Create storage key
        let storage_hash = hash_blake3(&[b"identity:", identity_id.as_bytes()].concat());
        let content_hash = Hash::from_bytes(&storage_hash[..32]);

        // Try to retrieve from DHT
        if let Some(encrypted_data) = self.dht_storage.retrieve_data(content_hash).await? {
            // Decrypt the credentials
            let decryption_key = self.derive_key_from_passphrase(passphrase, identity_id.as_bytes())?;
            let decrypted_data = decrypt_data(&encrypted_data, &decryption_key)
                .map_err(|e| anyhow!("Failed to decrypt identity credentials: {}. Wrong passphrase?", e))?;

            // Deserialize safe blob and reconstruct identity using lib-identity API
            #[derive(serde::Deserialize)]
            struct PrivateKeyBlob {
                dilithium_sk: Vec<u8>,
                kyber_sk: Vec<u8>,
                master_seed: Vec<u8>,
            }
            #[derive(serde::Deserialize)]
            struct IdentityBlob {
                json_view: String,
                private_key: PrivateKeyBlob,
            }
            // First try structured blob; fallback to direct serialized view + private_key
            let identity = if let Ok(blob) = bincode::deserialize::<IdentityBlob>(&decrypted_data) {
                let private_key = lib_crypto::PrivateKey {
                    dilithium_sk: blob.private_key.dilithium_sk,
                    kyber_sk: blob.private_key.kyber_sk,
                    master_seed: blob.private_key.master_seed,
                };
                lib_identity::ZhtpIdentity::from_serialized(&blob.json_view, &private_key)?
            } else {
                // Backward-compatibility: assume decrypted_data is a concatenation of SerializedView followed by PrivateKey
                // Attempt to parse SerializedView directly, then extract a PrivateKey from tail if present
                // If this fails, return a clear error
                // Try interpret entire buffer as SerializedView and require an external private key is unavailable here
                return Err(anyhow::anyhow!("Failed to parse identity blob; storage format mismatch. Please re-store credentials."));
            };

            println!("Retrieved identity credentials for ID: {}", hex::encode(identity_id.as_bytes()));
            return Ok(identity);
        }

        // Not found in storage system
        Err(anyhow!("Identity credentials not found in storage"))
    }

    /// Check if identity exists in storage
    pub async fn identity_exists(&mut self, identity_id: &lib_identity::IdentityId) -> Result<bool> {
        let storage_hash = hash_blake3(&[b"identity:", identity_id.as_bytes()].concat());
        let content_hash = Hash::from_bytes(&storage_hash[..32]);

        // Check if identity data exists in DHT
        match self.dht_storage.retrieve_data(content_hash.clone()).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // If there's an error, assume it doesn't exist
        }
    }

    /// Migrate identity from blockchain to unified storage (called from protocols layer)
    pub async fn migrate_identity_from_blockchain(
        &mut self, 
        identity_id: &lib_identity::IdentityId,
        lib_identity: &lib_identity::ZhtpIdentity,
        passphrase: &str,
    ) -> Result<()> {
        // Store the provided ZhtpIdentity in unified storage
        self.store_identity_credentials(identity_id, lib_identity, passphrase).await?;
        
        println!("Successfully migrated identity from blockchain to unified storage");
        Ok(())
    }

    /// Derive encryption key from passphrase using proper key derivation
    fn derive_key_from_passphrase(&self, passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
        // Use Blake3 for key derivation (acts similar to PBKDF2)
        let mut key_material = Vec::new();
        key_material.extend_from_slice(passphrase.as_bytes());
        key_material.extend_from_slice(salt);
        key_material.extend_from_slice(b"ZHTP-IDENTITY-KEY-V1");
        
        // Multiple rounds of hashing for key strengthening
        let mut derived_key = hash_blake3(&key_material);
        for _ in 0..10000 { // 10,000 rounds for key strengthening
            derived_key = hash_blake3(&[&derived_key[..], &key_material].concat());
        }
        
        Ok(derived_key.to_vec())
    }

    /// Get version hash
    fn get_version_hash(&self, content_hash: &ContentHash, version: u32) -> Result<ContentHash> {
        if let Some(versions) = self.content_versions.get(content_hash) {
            if let Some(ver) = versions.iter().find(|v| v.version == version) {
                Ok(ver.content_hash.clone())
            } else {
                Err(anyhow!("Version not found"))
            }
        } else {
            Err(anyhow!("Content not found"))
        }
    }
    
    /// Get direct access to DHT storage (for UnifiedStorageSystem to query the correct instance)
    pub async fn get_from_dht_storage(&mut self, key: &str) -> Result<Option<Vec<u8>>> {
        self.dht_storage.get(key).await
    }
}

impl Default for ContentManager {
    fn default() -> Self {
        Self::new(
            DhtStorage::new_default(),
            EconomicManagerConfig::default(),
        ).expect("Failed to create default ContentManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityId;

    #[tokio::test]
    async fn test_content_manager_creation() {
        let manager = ContentManager::default();
        assert_eq!(manager.content_metadata.len(), 0);
    }

    #[tokio::test]
    async fn test_upload_request_creation() {
        let request = UploadRequest {
            content: b"test content".to_vec(),
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            description: "Test file".to_string(),
            tags: vec!["test".to_string()],
            encrypt: false,
            compress: false,
            access_control: AccessControlSettings {
                public_read: true,
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
        assert_eq!(request.content.len(), 12);
    }

    #[tokio::test]
    // NOTE: This test requires ZhtpIdentity secure deserialization to be fixed
    // Track in dedicated issue for proper implementation
    #[ignore = "ZhtpIdentity secure deserialization currently restricted"]
    async fn test_identity_storage_round_trip() -> Result<()> {
        let mut manager = ContentManager::default();
        
        // Create test identity using a simple structure
        let identity_id = IdentityId::from_bytes(&[1u8; 32]);
        let test_identity = create_test_identity(identity_id.clone(), 1234567890);
        let passphrase = "test_passphrase_123";

        // Store identity
        let store_result = manager.store_identity_credentials(&identity_id, &test_identity, passphrase).await;
        assert!(store_result.is_ok(), "Failed to store identity: {:?}", store_result);

        // Check existence
        let exists = manager.identity_exists(&identity_id).await.unwrap();
        assert!(exists, "Identity should exist after storage");

        // Retrieve identity
        let retrieved = manager.retrieve_identity_credentials(&identity_id, passphrase).await;
        assert!(retrieved.is_ok(), "Failed to retrieve identity: {:?}", retrieved);
        
        let retrieved_identity = retrieved.unwrap();
        assert_eq!(retrieved_identity.id, test_identity.id);
        assert_eq!(retrieved_identity.created_at, test_identity.created_at);

        // Test wrong passphrase
        let wrong_passphrase_result = manager.retrieve_identity_credentials(&identity_id, "wrong_passphrase").await;
        assert!(wrong_passphrase_result.is_err(), "Should fail with wrong passphrase");

        Ok(())
    }

    #[tokio::test]
    // NOTE: This test requires ZhtpIdentity secure deserialization to be fixed
    // Track in dedicated issue for proper implementation
    #[ignore = "ZhtpIdentity secure deserialization currently restricted"]
    async fn test_identity_migration() -> Result<()> {
        let mut manager = ContentManager::default();
        
        let identity_id = IdentityId::from_bytes(&[2u8; 32]);
        let test_identity = create_test_identity(identity_id.clone(), 9876543210);
        let passphrase = "migration_test_passphrase";

        // Test migration
        let migration_result = manager.migrate_identity_from_blockchain(&identity_id, &test_identity, passphrase).await;
        assert!(migration_result.is_ok(), "Migration should succeed");

        // Verify the migrated identity can be retrieved
        let retrieved = manager.retrieve_identity_credentials(&identity_id, passphrase).await.unwrap();
        assert_eq!(retrieved.id, test_identity.id);
        assert_eq!(retrieved.created_at, test_identity.created_at);

        Ok(())
    }

    /// Helper function to create test identity with all required fields
    fn create_test_identity(identity_id: IdentityId, created_at: u64) -> ZhtpIdentity {
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
            Some(25),
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
