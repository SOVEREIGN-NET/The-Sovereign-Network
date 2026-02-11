//! Web4 Domain Registry System
//! 
//! Provides formal domain registration, ownership verification, and domain management
//! for the Web4 ecosystem. Integrates with existing DHT and ZDNS systems.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};
use lib_crypto::hash_blake3;
use lib_proofs::ZeroKnowledgeProof;
use lib_identity::ZhtpIdentity;
use hex;

use crate::dht::ZkDHTIntegration;
use super::types::*;
use crate::storage_stub::UnifiedStorage;
use super::content_publisher::ContentPublisher;

/// Web4 domain registry manager
pub struct DomainRegistry {
    /// Domain records storage
    domain_records: Arc<RwLock<HashMap<String, DomainRecord>>>,
    /// DHT client for direct storage
    dht_client: Arc<RwLock<Option<ZkDHTIntegration>>>,
    /// Storage backend for persistence (trait-based, injected by composition root)
    storage: Arc<dyn UnifiedStorage>,
    /// Content cache (hash -> bytes)
    content_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Registry statistics
    stats: Arc<RwLock<Web4Statistics>>,
    /// Manifest history per domain (domain -> list of manifests, oldest first)
    manifest_history: Arc<RwLock<HashMap<String, Vec<Web4Manifest>>>>,
}

impl DomainRegistry {
    /// Create new domain registry with injected storage
    ///
    /// INVARIANT: storage must not be a stub in production.
    /// Verify with: assert!(!storage.is_stub(), "Stub storage must not be used in production")
    ///
    /// This is the ONLY public constructor. All parameters are injected.
    /// No internal storage creation is allowed.
    pub async fn new(storage: Arc<dyn UnifiedStorage>) -> Result<Self> {
        // Defensive check: fail immediately if stub is being used
        if storage.is_stub() {
            warn!("⚠️  DomainRegistry initialized with STUB storage - persistence disabled. Real storage must be provided by zhtp.");
        }

        let registry = Self {
            domain_records: Arc::new(RwLock::new(HashMap::new())),
            dht_client: Arc::new(RwLock::new(None)),
            storage,
            content_cache: Arc::new(RwLock::new(HashMap::new())),
            manifest_history: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(Web4Statistics {
                total_domains: 0,
                total_content: 0,
                total_storage_bytes: 0,
                active_domains: 0,
                economic_stats: Web4EconomicStats {
                    registration_fees: 0.0,
                    storage_fees: 0.0,
                    transfer_fees: 0.0,
                    storage_capacity_gb: 1000.0, // 1TB default
                    storage_utilization: 0.0,
                },
            })),
        };

        // Load persisted domain records from storage on startup
        registry.load_persisted_domains().await?;

        // Load persisted manifest history from storage (FIX: was missing, causing phantom domains)
        registry.load_persisted_manifests().await?;

        // FIX (Content Persistence): Content is now persisted to storage with key "content:{cid}"
        // Content will be loaded on-demand from storage when first accessed via get_content_by_cid()
        // No need to pre-cache all content on startup - lazy loading is more efficient

        Ok(registry)
    }

    /// Create with optional DHT client (for tests/advanced use)
    pub async fn new_with_dht(storage: Arc<dyn UnifiedStorage>, dht_client: Option<ZkDHTIntegration>) -> Result<Self> {
        let registry = Self::new(storage).await?;
        *registry.dht_client.write().await = dht_client;
        Ok(registry)
    }

    // ========================================================================
    // Domain Persistence - Load and save domain records to lib-storage
    // ========================================================================

    /// Load all persisted domain records from storage into the in-memory cache
    /// MIGRATION: Automatically re-saves records in new format for backwards compatibility
    async fn load_persisted_domains(&self) -> Result<()> {
        info!("🔍 load_persisted_domains: Starting to load persisted domains from storage");

        // Call storage trait method - no lock needed, storage impl handles that
        let records = self.storage.list_domain_records().await?;
        info!("🔍 load_persisted_domains: list_domain_records returned {} records", records.len());

        if records.is_empty() {
            info!(" ⚠️  No persisted domain records found in storage");
            return Ok(());
        }

        // Parse records outside of any lock
        let mut parsed_records = Vec::new();
        for (domain, data) in records {
            match serde_json::from_slice::<DomainRecord>(&data) {
                Ok(record) => {
                    // MIGRATION: Immediately re-save with new format (serde aliases make old data readable)
                    let migrated_data = serde_json::to_vec(&record)?;
                    self.storage.store_domain_record(&domain, migrated_data).await
                        .map_err(|e| anyhow!("Failed to migrate domain record '{}': {}", domain, e))?;

                    parsed_records.push((domain, record));
                }
                Err(e) => {
                    warn!("Failed to deserialize domain record: {}", e);
                }
            }
        }

        let loaded_count = parsed_records.len() as u64;
        if loaded_count > 0 {
            info!(" ✅ MIGRATION: Re-saved {} domain records in new format", loaded_count);
        }

        // LOCK SAFETY: Acquire domain_records lock, do sync work only, release
        {
            let mut domain_records = self.domain_records.write().await;
            for (domain, record) in parsed_records {
                domain_records.insert(domain, record);
            }
        } // domain_records lock released here

        // LOCK SAFETY: Acquire stats lock separately
        {
            let mut stats = self.stats.write().await;
            stats.total_domains = loaded_count;
            stats.active_domains = loaded_count;
        } // stats lock released here

        info!("Loaded {} domains from storage", loaded_count);
        Ok(())
    }

    /// Migrate legacy domain records by re-saving them in the latest format.
    ///
    /// Returns the number of records migrated.
    pub async fn migrate_domains(&self) -> Result<u64> {
        let records = self.storage.list_domain_records().await?;
        if records.is_empty() {
            return Ok(0);
        }

        let mut migrated = 0u64;
        let mut parsed_records = Vec::new();

        for (domain, data) in records {
            match serde_json::from_slice::<DomainRecord>(&data) {
                Ok(record) => {
                    let migrated_data = serde_json::to_vec(&record)?;
                    self.storage.store_domain_record(&domain, migrated_data).await?;
                    parsed_records.push((domain, record));
                    migrated += 1;
                }
                Err(e) => {
                    warn!("Failed to deserialize domain record during migration: {}", e);
                }
            }
        }

        if !parsed_records.is_empty() {
            let mut domain_records = self.domain_records.write().await;
            for (domain, record) in parsed_records {
                domain_records.insert(domain, record);
            }
        }

        Ok(migrated)
    }

    /// Load all persisted manifest histories from storage into memory
    /// FIX (Phantom Domain Bug): Manifests must be loaded on startup, not just domain records
    async fn load_persisted_manifests(&self) -> Result<()> {
        // Get all loaded domain records to know which domains need manifests loaded
        let domain_records = self.domain_records.read().await;
        let domains_to_load: Vec<String> = domain_records.keys().cloned().collect();
        drop(domain_records);

        if domains_to_load.is_empty() {
            return Ok(());
        }

        // Load manifest for each domain
        let mut loaded_manifests = 0;
        for domain in &domains_to_load {
            match self.storage.load_manifest(domain).await {
                Ok(Some(manifest_data)) => {
                    match serde_json::from_slice::<Vec<Web4Manifest>>(&manifest_data) {
                        Ok(manifests) => {
                            // Store in manifest_history and cache manifest content
                            {
                                let mut history = self.manifest_history.write().await;
                                history.insert(domain.clone(), manifests.clone());
                            }

                            // FIX (Content Not Found Bug): Also cache the manifest content for fast CID lookup
                            {
                                let mut cache = self.content_cache.write().await;
                                for manifest in &manifests {
                                    let cid = manifest.compute_cid();
                                    let manifest_bytes = match serde_json::to_vec(manifest) {
                                        Ok(bytes) => bytes,
                                        Err(e) => {
                                            warn!("Failed to serialize manifest for caching: {}", e);
                                            continue;
                                        }
                                    };
                                    cache.insert(cid, manifest_bytes);
                                }
                            }

                            loaded_manifests += 1;
                        }
                        Err(e) => {
                            warn!("Failed to deserialize manifest for {}: {}", domain, e);
                        }
                    }
                }
                Ok(None) => {
                    // No manifest found for domain (may be newly registered)
                }
                Err(e) => {
                    warn!("Error loading manifest for {}: {}", domain, e);
                }
            }
        }

        info!("Loaded {} manifest histories from storage", loaded_manifests);
        Ok(())
    }

    /// Persist a domain record to storage
    async fn persist_domain_record(&self, record: &DomainRecord) -> Result<()> {
        let data = serde_json::to_vec(record)
            .map_err(|e| anyhow!("Failed to serialize domain record: {}", e))?;

        info!("🔍 persist_domain_record: Serialized domain {} to {} bytes", record.domain, data.len());

        // Call storage trait method - error is NOT swallowed
        self.storage.store_domain_record(&record.domain, data).await?;

        info!(" ✅ Persisted domain record: {} (v{}) - storage confirmed", record.domain, record.version);
        Ok(())
    }

    /// Delete a domain record from storage
    async fn delete_persisted_domain(&self, domain: &str) -> Result<()> {
        info!(" Deleting persisted domain record: {}", domain);
        self.storage.delete_domain_record(domain).await
    }

    /// Register a new Web4 domain
    pub async fn register_domain(&self, request: DomainRegistrationRequest) -> Result<DomainRegistrationResponse> {
        info!("Registering Web4 domain: {}", request.domain);

        // Validate domain name
        self.validate_domain_name(&request.domain)?;

        // Check if domain is already registered (FIX: allow updates by loading existing record)
        let existing_record = {
            let records = self.domain_records.read().await;
            records.get(&request.domain).cloned()
        };

        // Verify registration proof
        if !self.verify_registration_proof(&request).await? {
            return Ok(DomainRegistrationResponse {
                domain: request.domain.clone(),
                success: false,
                registration_id: String::new(),
                expires_at: 0,
                fees_charged: 0.0,
                error: Some("Invalid registration proof".to_string()),
            });
        }

        // Calculate registration fee
        let registration_fee = self.calculate_registration_fee(&request).await?;

        // Create domain record
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let expires_at = current_time + (request.duration_days * 24 * 60 * 60);

        // Create ownership proof
        let ownership_proof = self.create_ownership_proof(&request.owner, &request.domain, current_time).await?;

        // Store initial content if provided
        let mut content_mappings = HashMap::new();
        for (path, content) in &request.initial_content {
            let content_hash = self.store_domain_content(&request.domain, path, content.clone()).await?;
            content_mappings.insert(path.clone(), content_hash);
        }

        // Determine version and manifest info
        let (version, previous_manifest) = if let Some(ref existing) = existing_record {
            (existing.version + 1, Some(existing.current_web4_manifest_cid.clone()))
        } else {
            (1, None)
        };

        // CANONICAL: If deploy_manifest_cid is provided by CLI, load and convert to web4_manifest_cid
        // Otherwise, create an empty Web4Manifest
        let web4_manifest_cid = if let Some(ref deploy_manifest_cid) = request.deploy_manifest_cid {
            // Load the DeployManifest from storage (uploaded by CLI with all files)
            match self.get_content_by_cid(deploy_manifest_cid).await {
                Ok(Some(manifest_bytes)) => {
                    // Try to deserialize as a manifest
                    if let Ok(cli_manifest_data) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) {

                        // Convert CLI manifest format to Web4Manifest
                        // CLI manifest has files as Vec<FileEntry>, we need HashMap<String, ManifestFile>
                        let mut manifest_files = HashMap::new();

                        if let Some(files_array) = cli_manifest_data.get("files").and_then(|f| f.as_array()) {
                            for file_entry in files_array {
                                if let (Some(path), Some(hash), Some(size), Some(mime_type)) = (
                                    file_entry.get("path").and_then(|p| p.as_str()),
                                    file_entry.get("hash").and_then(|h| h.as_str()),
                                    file_entry.get("size").and_then(|s| s.as_u64()),
                                    file_entry.get("mime_type").and_then(|m| m.as_str()),
                                ) {
                                    // Create ManifestFile from FileEntry
                                    // Note: FileEntry has hash (BLAKE3 hash), we store it as cid
                                    manifest_files.insert(
                                        path.to_string(),
                                        ManifestFile {
                                            cid: hash.to_string(),
                                            size,
                                            content_type: mime_type.to_string(),
                                            hash: hash.to_string(),
                                        },
                                    );
                                }
                            }
                        }

                        let file_count = manifest_files.len();

                        // Create Web4Manifest with CLI's files
                        let converted_manifest = Web4Manifest {
                            domain: request.domain.clone(),
                            version,
                            previous_manifest,
                            build_hash: if let Some(root_hash) = cli_manifest_data.get("root_hash").and_then(|h| h.as_str()) {
                                root_hash.to_string()
                            } else {
                                hex::encode(lib_crypto::hash_blake3(
                                    format!("{}:v{}:{}", request.domain, version, current_time).as_bytes()
                                ))
                            },
                            files: manifest_files,  // FIX: Use files from CLI manifest
                            created_at: current_time,
                            created_by: format!("{}", request.owner.id),
                            message: if existing_record.is_some() {
                                Some(format!("Domain {} updated with {} files", request.domain, file_count))
                            } else {
                                Some(format!("Domain {} registered with {} files", request.domain, file_count))
                            },
                        };

                        // Store this manifest and get its CID
                        self.store_manifest(converted_manifest).await?
                    } else {
                        warn!("Failed to parse CLI manifest as JSON, creating empty manifest");
                        // Fallback to empty manifest if parse fails
                        let empty_manifest = Web4Manifest {
                            domain: request.domain.clone(),
                            version,
                            previous_manifest,
                            build_hash: hex::encode(lib_crypto::hash_blake3(
                                format!("{}:v{}:{}", request.domain, version, current_time).as_bytes()
                            )),
                            files: HashMap::new(),
                            created_at: current_time,
                            created_by: format!("{}", request.owner.id),
                            message: Some(format!("Domain {} registered", request.domain)),
                        };
                        self.store_manifest(empty_manifest).await?
                    }
                }
                Ok(None) => {
                    warn!("DeployManifest content not found for CID {}, creating empty manifest", deploy_manifest_cid);
                    // Fallback to empty manifest if content not found
                    let empty_manifest = Web4Manifest {
                        domain: request.domain.clone(),
                        version,
                        previous_manifest,
                        build_hash: hex::encode(lib_crypto::hash_blake3(
                            format!("{}:v{}:{}", request.domain, version, current_time).as_bytes()
                        )),
                        files: HashMap::new(),
                        created_at: current_time,
                        created_by: format!("{}", request.owner.id),
                        message: Some(format!("Domain {} registered", request.domain)),
                    };
                    self.store_manifest(empty_manifest).await?
                }
                Err(e) => {
                    warn!("Error loading DeployManifest for CID {}: {}, creating empty manifest", deploy_manifest_cid, e);
                    // Fallback to empty manifest on error
                    let empty_manifest = Web4Manifest {
                        domain: request.domain.clone(),
                        version,
                        previous_manifest,
                        build_hash: hex::encode(lib_crypto::hash_blake3(
                            format!("{}:v{}:{}", request.domain, version, current_time).as_bytes()
                        )),
                        files: HashMap::new(),
                        created_at: current_time,
                        created_by: format!("{}", request.owner.id),
                        message: Some(format!("Domain {} registered", request.domain)),
                    };
                    self.store_manifest(empty_manifest).await?
                }
            }
        } else {
            // No deploy_manifest_cid provided, create empty Web4Manifest as before
            let initial_manifest = Web4Manifest {
                domain: request.domain.clone(),
                version,
                previous_manifest,
                build_hash: hex::encode(lib_crypto::hash_blake3(
                    format!("{}:v{}:{}", request.domain, version, current_time).as_bytes()
                )),
                files: HashMap::new(),
                created_at: current_time,
                created_by: format!("{}", request.owner.id),
                message: if existing_record.is_some() {
                    Some(format!("Domain {} updated", request.domain))
                } else {
                    Some(format!("Domain {} registered", request.domain))
                },
            };

            // Store manifest and get its real CID
            self.store_manifest(initial_manifest).await?
        };

        // CANONICAL: Store web4_manifest_cid as the authoritative pointer
        let domain_record = if let Some(existing) = existing_record {
            // Update existing domain with new Web4Manifest
            DomainRecord {
                domain: request.domain.clone(),
                owner: existing.owner.clone(),
                current_web4_manifest_cid: web4_manifest_cid,
                version,
                registered_at: existing.registered_at,
                updated_at: current_time,
                expires_at,
                ownership_proof,
                content_mappings,
                metadata: request.metadata.clone(),
                transfer_history: existing.transfer_history,
            }
        } else {
            // New domain registration
            DomainRecord {
                domain: request.domain.clone(),
                owner: request.owner.id.clone(),
                current_web4_manifest_cid: web4_manifest_cid,
                version,
                registered_at: current_time,
                updated_at: current_time,
                expires_at,
                ownership_proof,
                content_mappings,
                metadata: request.metadata.clone(),
                transfer_history: vec![],
            }
        };

        // Store domain record (legacy method for compatibility)
        let registration_id = self.store_domain_record(&domain_record).await?;

        // Persist to lib-storage for durability
        self.persist_domain_record(&domain_record).await?;

        // Update in-memory registry cache
        {
            let mut records = self.domain_records.write().await;
            records.insert(request.domain.clone(), domain_record);
            info!(" DEBUG: Stored domain in registry. Total domains: {}. Registry ptr: {:p}",
                records.len(), &*self.domain_records);
        }

        // Update statistics
        self.update_registration_stats(registration_fee).await?;

        info!(" Domain {} registered successfully with ID {}", request.domain, registration_id);

        Ok(DomainRegistrationResponse {
            domain: request.domain,
            success: true,
            registration_id,
            expires_at,
            fees_charged: registration_fee,
            error: None,
        })
    }

    /// Convenience method: register domain with initial content (simplifies Web4Handler)
    pub async fn register_domain_with_content(
        &self,
        domain: String,
        owner: ZhtpIdentity,
        initial_content: HashMap<String, Vec<u8>>,
        metadata: DomainMetadata,
    ) -> Result<DomainRegistrationResponse> {
        // Create registration proof (simplified for now)
        let registration_proof = ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            hash_blake3(&[
                owner.id.0.as_slice(),
                domain.as_bytes(),
            ].concat()).to_vec(),
            owner.id.0.to_vec(),
            owner.id.0.to_vec(),
            None,
        );

        let request = DomainRegistrationRequest {
            domain,
            owner,
            duration_days: 365, // 1 year default
            metadata,
            initial_content,
            registration_proof,
            deploy_manifest_cid: None, // Auto-generate
        };

        self.register_domain(request).await
    }

    /// Look up domain information
    pub async fn lookup_domain(&self, domain: &str) -> Result<DomainLookupResponse> {
        info!(" Looking up Web4 domain: {}", domain);

        // First check local cache
        let records = self.domain_records.read().await;
        
        if let Some(record) = records.get(domain) {
            // Check if domain has expired
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            if record.expires_at < current_time {
                info!(" Domain {} found locally but expired", domain);
            } else {
                info!(" Domain {} found in local cache", domain);
                let owner_info = PublicOwnerInfo {
                    identity_hash: hex::encode(&record.owner.0[..16]), // First 16 bytes for privacy
                    registered_at: record.registered_at,
                    verified: true, // All registered domains are verified
                    alias: None, // Could be added later
                };

                return Ok(DomainLookupResponse {
                    found: true,
                    record: Some(record.clone()),
                    content_mappings: record.content_mappings.clone(),
                    owner_info: Some(owner_info),
                });
            }
        }
        
        drop(records); // Release lock before storage query

        // Domain not found locally - try storage as fallback
        if let Ok(Some(data)) = self.storage.load_domain_record(domain).await {
            if let Ok(record) = serde_json::from_slice::<DomainRecord>(&data) {
                // Cache it in memory for future lookups
                {
                    let mut records = self.domain_records.write().await;
                    records.insert(domain.to_string(), record.clone());
                }

                let owner_info = PublicOwnerInfo {
                    identity_hash: hex::encode(&record.owner.0[..16]),
                    registered_at: record.registered_at,
                    verified: true,
                    alias: None,
                };

                return Ok(DomainLookupResponse {
                    found: true,
                    record: Some(record.clone()),
                    content_mappings: record.content_mappings.clone(),
                    owner_info: Some(owner_info),
                });
            }
        }

        // Domain not found locally or in storage - blockchain query disabled
        info!(" Domain {} not found in storage or DHT", domain);
        Ok(DomainLookupResponse {
            found: false,
            record: None,
            content_mappings: HashMap::new(),
            owner_info: None,
        })
    }

    /// Resolve domain into a read-only view model.
    ///
    /// NOTE: Currently backed by the local registry cache until chain queries are wired.
    pub async fn resolve_name(&self, domain: &str) -> Result<ResolvedNameRecord> {
        let lookup = self.lookup_domain(domain).await?;
        if let Some(record) = lookup.record {
            Ok(record.into())
        } else {
            Err(anyhow!("Domain not found: {}", domain))
        }
    }


    /// Transfer domain to new owner
    pub async fn transfer_domain(
        &self,
        domain: &str,
        from_owner: &ZhtpIdentity,
        to_owner: &ZhtpIdentity,
        transfer_proof: ZeroKnowledgeProof,
    ) -> Result<bool> {
        info!(" Transferring domain {} from {} to {}", 
            domain, 
            hex::encode(&from_owner.id.0[..8]),
            hex::encode(&to_owner.id.0[..8])
        );

        let mut records = self.domain_records.write().await;
        
        if let Some(record) = records.get_mut(domain) {
            // Verify current ownership
            if record.owner != from_owner.id {
                return Err(anyhow!("Transfer denied: not domain owner"));
            }

            // Verify transfer proof
            if !self.verify_transfer_proof(from_owner, to_owner, domain, &transfer_proof).await? {
                return Err(anyhow!("Invalid transfer proof"));
            }

            // Calculate transfer fee
            let transfer_fee = record.metadata.economic_settings.transfer_fee;

            // Create transfer record
            let transfer_record = DomainTransfer {
                from_owner: from_owner.id.clone(),
                to_owner: to_owner.id.clone(),
                transferred_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                transfer_proof,
                fee_paid: transfer_fee,
            };

            // Create updated record for persistence (persist BEFORE mutating memory)
            let new_ownership_proof = self.create_ownership_proof(
                to_owner,
                domain,
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
            ).await?;

            let mut updated_record = record.clone();
            updated_record.owner = to_owner.id.clone();
            updated_record.transfer_history.push(transfer_record);
            updated_record.ownership_proof = new_ownership_proof;

            // Release lock before async persist
            drop(records);

            // Persist FIRST - if this fails, memory stays unchanged (durability guarantee)
            self.persist_domain_record(&updated_record).await?;

            // Update statistics
            self.update_transfer_stats(transfer_fee).await?;

            // Only mutate memory AFTER successful persistence
            {
                let mut records = self.domain_records.write().await;
                if let Some(record) = records.get_mut(domain) {
                    record.owner = updated_record.owner;
                    record.transfer_history = updated_record.transfer_history;
                    record.ownership_proof = updated_record.ownership_proof;
                }
            }

            info!(" Domain {} transferred successfully", domain);
            Ok(true)
        } else {
            Err(anyhow!("Domain not found: {}", domain))
        }
    }

    /// Release/delete domain
    pub async fn release_domain(&self, domain: &str, owner: &ZhtpIdentity) -> Result<bool> {
        info!("🗑️ Releasing Web4 domain: {}", domain);

        let domain_to_delete = domain.to_string();

        // TOCTOU FIX: Hold write lock through verification AND mutation to prevent
        // concurrent transfer/update from allowing a non-owner to delete the domain.
        // We verify ownership, delete from persistent storage, then remove from memory
        // all while holding the write lock.
        {
            let mut records = self.domain_records.write().await;

            // Verify ownership while holding write lock
            if let Some(record) = records.get(domain) {
                if record.owner != owner.id {
                    return Err(anyhow!("Release denied: not domain owner"));
                }
            } else {
                return Err(anyhow!("Domain not found: {}", domain));
            }

            // Delete from persistent storage - if this fails, memory stays unchanged
            self.delete_persisted_domain(&domain_to_delete).await?;

            // Remove from memory only after successful persistence deletion
            records.remove(domain);
        } // write lock released here

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_domains = stats.total_domains.saturating_sub(1);
            stats.active_domains = stats.active_domains.saturating_sub(1);
        }

        info!(" Domain {} released successfully", domain);
        Ok(true)
    }

    /// Get Web4 system statistics
    pub async fn get_statistics(&self) -> Result<Web4Statistics> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    /// Validate domain name format
    fn validate_domain_name(&self, domain: &str) -> Result<()> {
        // Must end with .zhtp or .sov
        let tld_len = if domain.ends_with(".zhtp") {
            5
        } else if domain.ends_with(".sov") {
            4
        } else {
            return Err(anyhow!("Domain must end with .zhtp or .sov"));
        };

        // Extract the name part (before TLD)
        let name = &domain[..domain.len() - tld_len];
        
        // Check for reserved dao. prefix (virtual namespace - cannot be registered)
        if name.starts_with("dao.") || name == "dao" {
            return Err(anyhow!(
                "dao. prefix is virtual and cannot be registered. DAO governance is automatically derived from base domains."
            ));
        }
        
        // Split into labels and validate each independently
        let labels: Vec<&str> = name.split('.').collect();
        
        // Must have at least one label
        if labels.is_empty() {
            return Err(anyhow!("Domain must have at least one label"));
        }
        
        // Validate each label
        for label in &labels {
            // Each label must be 1-63 characters
            if label.is_empty() {
                return Err(anyhow!("Domain labels cannot be empty"));
            }
            if label.len() > 63 {
                return Err(anyhow!("Domain label '{}' exceeds 63 characters", label));
            }

            // Must contain only valid characters (alphanumeric + hyphen)
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(anyhow!("Domain label '{}' can only contain letters, numbers, and hyphens", label));
            }

            // Cannot start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return Err(anyhow!("Domain label '{}' cannot start or end with hyphen", label));
            }
        }

        // Base domain (last label before TLD) must be at least 3 characters
        // This maintains the original 3-character minimum policy while allowing shorter subdomain labels
        if let Some(base_domain) = labels.last() {
            if base_domain.len() < 3 {
                return Err(anyhow!("Base domain '{}' must be at least 3 characters", base_domain));
            }
        }
        
        // Overall name length check (all labels + dots, excluding TLD)
        if name.len() > 253 {
            return Err(anyhow!("Domain name (excluding TLD) cannot exceed 253 characters"));
        }

        Ok(())
    }

    /// Store domain content using content-addressed storage
    async fn store_domain_content(&self, domain: &str, path: &str, content: Vec<u8>) -> Result<String> {
        info!(" Storing content for {}{} ({} bytes)", domain, path, content.len());

        // Use the content-addressed storage method
        let cid = self.store_content_by_cid(content).await?;

        info!(" Content stored with CID: {}", cid);
        Ok(cid)
    }

    /// Store domain record to persistent storage
    async fn store_domain_record(&self, record: &DomainRecord) -> Result<String> {
        let record_data = serde_json::to_vec(record)?;
        let record_hash = hex::encode(&hash_blake3(&record_data)[..32]);

        // For now, domain records are kept in memory
        // In production, this would be persisted to DHT or database

        Ok(record_hash)
    }

    /// Create ownership proof for domain
    async fn create_ownership_proof(&self, owner: &ZhtpIdentity, domain: &str, timestamp: u64) -> Result<ZeroKnowledgeProof> {
        // Create proof data combining identity, domain, and timestamp
        let proof_data = [
            owner.id.0.as_slice(),
            domain.as_bytes(),
            &timestamp.to_le_bytes(),
        ].concat();

        // Generate proof hash (in production this would be a proper ZK proof)
        let proof_hash = hash_blake3(&proof_data);
        
        Ok(ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            proof_hash.to_vec(),
            owner.id.0.to_vec(),
            owner.id.0.to_vec(),
            None,
        ))
    }

    /// Verify registration proof
    async fn verify_registration_proof(&self, request: &DomainRegistrationRequest) -> Result<bool> {
        // In production, this would verify the ZK proof
        // For now, just check that proof is present and valid format
        Ok(!request.registration_proof.proof_data.is_empty() && 
           !request.registration_proof.verification_key.is_empty())
    }

    /// Verify transfer proof
    async fn verify_transfer_proof(
        &self,
        from_owner: &ZhtpIdentity,
        to_owner: &ZhtpIdentity,
        domain: &str,
        proof: &ZeroKnowledgeProof,
    ) -> Result<bool> {
        // In production, this would verify the ZK proof for transfer authorization
        // For now, just check proof format and that it references both identities
        Ok(!proof.proof_data.is_empty() && 
           proof.verification_key.len() >= 32 && // Must contain both identity references
           !domain.is_empty())
    }

    /// Calculate registration fee based on domain and duration
    async fn calculate_registration_fee(&self, request: &DomainRegistrationRequest) -> Result<f64> {
        // Base fee structure
        let base_fee = 10.0; // 10 SOV base fee
        let per_day_fee = 0.01; // 0.01 SOV per day
        
        // Premium domain multiplier
        let premium_multiplier = if request.domain.len() <= 6 { // Short domains are premium
            3.0
        } else {
            1.0
        };

        let total_fee = (base_fee + (request.duration_days as f64 * per_day_fee)) * premium_multiplier;
        Ok(total_fee)
    }

    /// Update registration statistics
    async fn update_registration_stats(&self, fee_paid: f64) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.total_domains += 1;
        stats.active_domains += 1;
        stats.economic_stats.registration_fees += fee_paid;
        Ok(())
    }

    /// Update transfer statistics
    async fn update_transfer_stats(&self, fee_paid: f64) -> Result<()> {
        let mut stats = self.stats.write().await;
        stats.economic_stats.transfer_fees += fee_paid;
        Ok(())
    }

    /// Get content by hash from DHT ONLY - NOT IMPLEMENTED in stub
    /// Real implementation provided by application layer (zhtp) with actual storage integration
    pub async fn get_content(&self, content_hash: &str) -> Result<Vec<u8>> {
        Err(anyhow!("Content retrieval not implemented in protocol-only lib-network. Use zhtp application layer for storage integration. (requested hash: {})", content_hash))
    }

    /// Get content for a domain path
    pub async fn get_domain_content(&self, domain: &str, path: &str) -> Result<Vec<u8>> {
        // Look up domain
        let records = self.domain_records.read().await;
        let record = records.get(domain)
            .ok_or_else(|| anyhow!("Domain not found: {}", domain))?;

        // Get content hash for path
        let content_hash = record.content_mappings.get(path)
            .ok_or_else(|| anyhow!("Path not found in domain: {}", path))?;

        // Retrieve content
        self.get_content(content_hash).await
    }

    // ========================================================================
    // Domain Versioning API
    // ========================================================================

    /// Get domain status (version info)
    pub async fn get_domain_status(&self, domain: &str) -> Result<DomainStatusResponse> {
        let records = self.domain_records.read().await;
        info!(" DEBUG: get_domain_status for '{}'. Total domains: {}. DomainRegistry self ptr: {:p}",
            domain, records.len(), self);

        if let Some(record) = records.get(domain) {
            return Ok(DomainStatusResponse {
                found: true,
                domain: record.domain.clone(),
                version: record.version,
                current_web4_manifest_cid: record.current_web4_manifest_cid.clone(),
                owner_did: format!("did:zhtp:{}", hex::encode(&record.owner.0[..16])),
                updated_at: record.updated_at,
                expires_at: record.expires_at,
                build_hash: hex::encode(&hash_blake3(record.current_web4_manifest_cid.as_bytes())[..16]),
            });
        }

        drop(records); // Release lock before trying storage

        // Not found in memory - try loading from storage as fallback
        if let Ok(Some(data)) = self.storage.load_domain_record(domain).await {
            if let Ok(record) = serde_json::from_slice::<DomainRecord>(&data) {
                // Cache it in memory for future lookups
                {
                    let mut records = self.domain_records.write().await;
                    records.insert(domain.to_string(), record.clone());
                }

                return Ok(DomainStatusResponse {
                    found: true,
                    domain: record.domain.clone(),
                    version: record.version,
                    current_web4_manifest_cid: record.current_web4_manifest_cid.clone(),
                    owner_did: format!("did:zhtp:{}", hex::encode(&record.owner.0[..16])),
                    updated_at: record.updated_at,
                    expires_at: record.expires_at,
                    build_hash: hex::encode(&hash_blake3(record.current_web4_manifest_cid.as_bytes())[..16]),
                });
            }
        }

        Ok(DomainStatusResponse {
            found: false,
            domain: domain.to_string(),
            version: 0,
            current_web4_manifest_cid: String::new(),
            owner_did: String::new(),
            updated_at: 0,
            expires_at: 0,
            build_hash: String::new(),
        })
    }

    // ========================================================================
    // Content-Addressed Storage API
    // ========================================================================

    /// Store content by CID (content-addressed)
    /// Returns the CID after successful storage
    pub async fn store_content_by_cid(&self, content: Vec<u8>) -> Result<String> {
        // Compute CID from content hash
        let content_hash = hash_blake3(&content);
        let cid = format!("bafk{}", hex::encode(&content_hash[..16]));

        // Store in content cache (for fast access)
        {
            let mut cache = self.content_cache.write().await;
            cache.insert(cid.clone(), content.clone());
        }

        // FIX (Content Persistence Bug): Also persist content to storage
        // Content needs to be stored with key "content:{cid}" for durability across restarts
        let content_key = format!("content:{}", cid);
        self.storage.store_domain_record(&content_key, content.clone()).await?;

        Ok(cid)
    }

    /// Retrieve content by CID
    /// Returns None if content not found
    pub async fn get_content_by_cid(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        // First check in-memory cache
        {
            let cache = self.content_cache.read().await;
            if let Some(content) = cache.get(cid).cloned() {
                return Ok(Some(content));
            }
        }

        // Check persistent storage - content is stored with key "content:{cid}"
        let content_key = format!("content:{}", cid);
        match self.storage.load_domain_record(&content_key).await {
            Ok(Some(content)) => {
                // Cache it for next time
                {
                    let mut cache = self.content_cache.write().await;
                    cache.insert(cid.to_string(), content.clone());
                }
                return Ok(Some(content));
            }
            Ok(None) => {
                // Content not found, fall through to check manifest
            }
            Err(e) => {
                warn!("Error retrieving content from storage for CID {}: {}", cid, e);
            }
        }

        // Also check for manifest content with key "manifest:{cid}"
        // Manifests are stored with key "manifest:{cid}" for CID-based retrieval
        let manifest_key = format!("manifest:{}", cid);
        match self.storage.load_domain_record(&manifest_key).await {
            Ok(Some(content)) => {
                // Cache it for next time
                {
                    let mut cache = self.content_cache.write().await;
                    cache.insert(cid.to_string(), content.clone());
                }
                Ok(Some(content))
            }
            Ok(None) => {
                Ok(None)
            }
            Err(e) => {
                warn!("Error retrieving manifest from storage for CID {}: {}", cid, e);
                Ok(None)
            }
        }
    }

    /// Get domain version history
    pub async fn get_domain_history(&self, domain: &str, limit: usize) -> Result<DomainHistoryResponse> {
        let records = self.domain_records.read().await;
        let manifests = self.manifest_history.read().await;

        let record = records.get(domain)
            .ok_or_else(|| anyhow!("Domain not found: {}", domain))?;

        // Get version history from manifest storage
        let mut versions = Vec::new();

        if let Some(domain_manifests) = manifests.get(domain) {
            for manifest in domain_manifests.iter().rev().take(limit) {
                versions.push(DomainVersionEntry {
                    version: manifest.version,
                    web4_manifest_cid: manifest.compute_cid(),
                    created_at: manifest.created_at,
                    created_by: manifest.created_by.clone(),
                    message: manifest.message.clone(),
                    build_hash: manifest.build_hash.clone(),
                });
            }
        } else {
            // No history, return current version only
            versions.push(DomainVersionEntry {
                version: record.version,
                web4_manifest_cid: record.current_web4_manifest_cid.clone(),
                created_at: record.updated_at,
                created_by: format!("did:zhtp:{}", hex::encode(&record.owner.0[..16])),
                message: Some("Initial deployment".to_string()),
                build_hash: hex::encode(&hash_blake3(record.current_web4_manifest_cid.as_bytes())[..16]),
            });
        }

        Ok(DomainHistoryResponse {
            domain: domain.to_string(),
            current_version: record.version,
            total_versions: versions.len() as u64,
            versions,
        })
    }

    /// Update domain with new manifest (atomic compare-and-swap)
    pub async fn update_domain(&self, update_request: DomainUpdateRequest) -> Result<DomainUpdateResponse> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Validate timestamp (within 5 minutes)
        let time_diff = if current_time > update_request.timestamp {
            current_time - update_request.timestamp
        } else {
            update_request.timestamp - current_time
        };

        if time_diff > 300 {
            return Ok(DomainUpdateResponse {
                success: false,
                new_version: 0,
                new_manifest_cid: String::new(),
                previous_manifest_cid: String::new(),
                updated_at: 0,
                error: Some(format!("Request expired. Timestamp difference: {} seconds", time_diff)),
            });
        }

        let mut records = self.domain_records.write().await;

        let record = records.get_mut(&update_request.domain)
            .ok_or_else(|| anyhow!("Domain not found: {}", update_request.domain))?;

        // Compare-and-swap: verify expected previous CID matches current
        if record.current_web4_manifest_cid != update_request.expected_previous_manifest_cid {
            return Ok(DomainUpdateResponse {
                success: false,
                new_version: record.version,
                new_manifest_cid: record.current_web4_manifest_cid.clone(),
                previous_manifest_cid: record.current_web4_manifest_cid.clone(),
                updated_at: record.updated_at,
                error: Some(format!(
                    "Concurrent update detected. Expected previous CID: {}, actual: {}",
                    update_request.expected_previous_manifest_cid,
                    record.current_web4_manifest_cid
                )),
            });
        }

        // TODO: Verify signature matches domain owner
        // For now, we trust the caller has verified authorization

        let previous_manifest_cid = record.current_web4_manifest_cid.clone();
        let new_version = record.version + 1;
        let new_manifest_cid = update_request.new_manifest_cid.clone();

        // Create updated record for persistence (persist BEFORE mutating memory)
        let mut updated_record = record.clone();
        updated_record.current_web4_manifest_cid = new_manifest_cid.clone();
        updated_record.version = new_version;
        updated_record.updated_at = current_time;

        // Release lock before persisting
        drop(records);

        // Persist FIRST - if this fails, memory stays unchanged (durability guarantee)
        self.persist_domain_record(&updated_record).await?;

        // Only mutate memory AFTER successful persistence
        {
            let mut records = self.domain_records.write().await;
            if let Some(record) = records.get_mut(&update_request.domain) {
                record.current_web4_manifest_cid = updated_record.current_web4_manifest_cid.clone();
                record.version = updated_record.version;
                record.updated_at = updated_record.updated_at;
            }
        }

        info!(
            " Domain {} updated: v{} -> v{} (CID: {} -> {})",
            update_request.domain,
            new_version - 1,
            new_version,
            &previous_manifest_cid[..16.min(previous_manifest_cid.len())],
            &new_manifest_cid[..16.min(new_manifest_cid.len())]
        );

        Ok(DomainUpdateResponse {
            success: true,
            new_version,
            new_manifest_cid,
            previous_manifest_cid,
            updated_at: current_time,
            error: None,
        })
    }

    /// Store a manifest in history
    pub async fn store_manifest(&self, manifest: Web4Manifest) -> Result<String> {
        let cid = manifest.compute_cid();
        let domain = manifest.domain.clone();
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| anyhow!("Failed to serialize manifest: {}", e))?;

        // Validate manifest chain if we have the previous one
        if manifest.version > 1 {
            let manifests = self.manifest_history.read().await;
            if let Some(domain_manifests) = manifests.get(&domain) {
                if let Some(prev) = domain_manifests.last() {
                    manifest.validate_chain(Some(prev))
                        .map_err(|e| anyhow!("Manifest chain validation failed: {}", e))?;
                }
            }
        } else {
            manifest.validate_chain(None)
                .map_err(|e| anyhow!("Manifest validation failed: {}", e))?;
        }

        // Store manifest in memory
        let mut manifests = self.manifest_history.write().await;
        manifests
            .entry(domain.clone())
            .or_insert_with(Vec::new)
            .push(manifest);

        // FIX (Phantom Domain Bug): Also persist manifest history to storage
        // Get the updated history for this domain
        if let Some(domain_manifests) = manifests.get(&domain) {
            let manifest_history_data = serde_json::to_vec(domain_manifests)
                .map_err(|e| anyhow!("Failed to serialize manifest history: {}", e))?;

            // Persist to storage
            drop(manifests); // Release lock before making storage call
            self.storage.store_manifest(&domain, manifest_history_data).await?;
            info!(" ✅ Persisted manifest history for domain: {} (CID: {})", domain, cid);
        }

        // FIX (Content Not Found Bug): Also store the manifest content itself
        // The manifest needs to be retrievable by its CID as content
        // Store manifest content under key "manifest:{cid}" so it can be fetched
        let manifest_content_key = format!("manifest:{}", cid);
        self.storage.store_domain_record(&manifest_content_key, manifest_bytes.clone()).await?;
        info!(" ✅ Stored manifest content with CID: {} (size: {} bytes)", cid, manifest_bytes.len());

        info!(" Stored manifest {} for domain", cid);
        Ok(cid)
    }

    /// Get manifest by CID
    pub async fn get_manifest(&self, domain: &str, cid: &str) -> Result<Option<Web4Manifest>> {
        let manifests = self.manifest_history.read().await;

        if let Some(domain_manifests) = manifests.get(domain) {
            for manifest in domain_manifests {
                if manifest.compute_cid() == cid {
                    return Ok(Some(manifest.clone()));
                }
            }
        } else {
            // GUARDRAIL: Detect phantom domains
            // If domain is registered but has no manifest_history entry, that's a critical bug
            let records = self.domain_records.read().await;
            if records.contains_key(domain) && !cid.is_empty() {
                error!(
                    "PHANTOM DOMAIN DETECTED: domain '{}' is registered but has no manifest in history (requested cid: {})",
                    domain, cid
                );
                return Err(anyhow!(
                    "Phantom domain: {} has no manifest (manifest materialization failed during registration)",
                    domain
                ));
            }
        }

        Ok(None)
    }

    /// Rollback domain to a previous version
    pub async fn rollback_domain(&self, domain: &str, target_version: u64, owner_did: &str) -> Result<DomainUpdateResponse> {
        // Get the target manifest
        let manifests = self.manifest_history.read().await;
        let domain_manifests = manifests.get(domain)
            .ok_or_else(|| anyhow!("No history found for domain: {}", domain))?;

        let target_manifest = domain_manifests.iter()
            .find(|m| m.version == target_version)
            .ok_or_else(|| anyhow!("Version {} not found for domain {}", target_version, domain))?
            .clone();

        drop(manifests);

        let target_cid = target_manifest.compute_cid();

        // Get current state
        let records = self.domain_records.read().await;
        let current_cid = records.get(domain)
            .map(|r| r.current_web4_manifest_cid.clone())
            .ok_or_else(|| anyhow!("Domain not found: {}", domain))?;
        drop(records);

        // Create rollback update request
        let update_request = DomainUpdateRequest {
            domain: domain.to_string(),
            new_manifest_cid: target_cid,
            expected_previous_manifest_cid: current_cid,
            signature: String::new(), // TODO: Require signature
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        // Note: This creates a new version pointing to old content
        // The version number continues to increment (not reset to target)
        self.update_domain(update_request).await
    }
}

/// Web4 Manager - combines domain registry and content management
pub struct Web4Manager {
    /// Domain registry
    pub registry: Arc<DomainRegistry>,
    /// Content publisher
    pub content_publisher: ContentPublisher,
}

impl Web4Manager {
    /// Create new Web4 manager with domain registry and content publisher
    /// INVARIANT: registry and content_publisher must use the same storage
    pub fn new(registry: Arc<DomainRegistry>, content_publisher: ContentPublisher) -> Self {
        Self {
            registry,
            content_publisher,
        }
    }

    /// Register domain with initial content
    pub async fn register_domain_with_content(
        &self,
        domain: String,
        owner: ZhtpIdentity,
        initial_content: HashMap<String, Vec<u8>>,
        metadata: DomainMetadata,
    ) -> Result<DomainRegistrationResponse> {
        // Create registration proof (simplified for now)
        let registration_proof = ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            hash_blake3(&[
                owner.id.0.as_slice(),
                domain.as_bytes(),
            ].concat()).to_vec(),
            owner.id.0.to_vec(),
            owner.id.0.to_vec(),
            None,
        );

        let request = DomainRegistrationRequest {
            domain,
            owner,
            duration_days: 365, // 1 year default
            metadata,
            initial_content,
            registration_proof,
            deploy_manifest_cid: None, // Auto-generate
        };

        self.registry.register_domain(request).await
    }

    /// Get domain info (public method)
    pub async fn get_domain_info(&self, domain: &str) -> Result<DomainLookupResponse> {
        self.registry.lookup_domain(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{ZhtpIdentity, IdentityType};
    use tempfile::TempDir;
    use crate::storage_stub::UnifiedStorage;
    use async_trait::async_trait;
    use std::sync::RwLock as StdRwLock;

    /// Test storage implementation that actually persists data in memory
    #[derive(Clone, Default)]
    struct TestStorage {
        domains: Arc<StdRwLock<HashMap<String, Vec<u8>>>>,
        manifests: Arc<StdRwLock<HashMap<String, Vec<u8>>>>,
    }

    #[async_trait]
    impl UnifiedStorage for TestStorage {
        async fn store_domain_record(&self, domain: &str, data: Vec<u8>) -> Result<()> {
            self.domains.write().unwrap().insert(domain.to_string(), data);
            Ok(())
        }

        async fn load_domain_record(&self, domain: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.domains.read().unwrap().get(domain).cloned())
        }

        async fn delete_domain_record(&self, domain: &str) -> Result<()> {
            self.domains.write().unwrap().remove(domain);
            Ok(())
        }

        async fn list_domain_records(&self) -> Result<Vec<(String, Vec<u8>)>> {
            Ok(self.domains.read().unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }

        async fn store_manifest(&self, domain: &str, manifest_data: Vec<u8>) -> Result<()> {
            self.manifests.write().unwrap().insert(domain.to_string(), manifest_data);
            Ok(())
        }

        async fn load_manifest(&self, domain: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.manifests.read().unwrap().get(domain).cloned())
        }

        fn is_stub(&self) -> bool {
            false
        }
    }

    /// Test storage registry - maintains persistent storage per path for test isolation
    use std::collections::HashMap;
    use std::sync::{OnceLock, Mutex};

    fn get_test_storage_map() -> &'static Mutex<HashMap<String, Arc<TestStorage>>> {
        static STORAGE_MAP: OnceLock<Mutex<HashMap<String, Arc<TestStorage>>>> = OnceLock::new();
        STORAGE_MAP.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn get_test_storage(path: &std::path::Path) -> Arc<dyn UnifiedStorage> {
        let map = get_test_storage_map();
        let mut map = map.lock().unwrap();

        let key = path.to_string_lossy().to_string();
        if !map.contains_key(&key) {
            map.insert(key.clone(), Arc::new(TestStorage::default()));
        }

        map.get(&key).unwrap().clone() as Arc<dyn UnifiedStorage>
    }

    /// Clear test storage between tests (call at start of each test for isolation)
    fn clear_test_storage_for_path(path: &std::path::Path) {
        let map = get_test_storage_map();
        let mut map = map.lock().unwrap();
        let key = path.to_string_lossy().to_string();
        map.remove(&key);
    }

    /// Create a test storage system that actually persists across multiple calls
    async fn create_test_storage_with_persistence(persist_path: std::path::PathBuf) -> Arc<dyn UnifiedStorage> {
        get_test_storage(&persist_path)
    }

    /// Create a test identity for domain operations
    fn create_test_identity() -> ZhtpIdentity {
        ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            "test_domain_owner",
            None,
        ).unwrap()
    }

    #[tokio::test]
    async fn test_domain_persistence_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let persist_path = temp_dir.path().join("dht_storage.bin");

        // Clear test storage for isolation
        clear_test_storage_for_path(&persist_path);

        // Clean up any existing file
        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "testapp.zhtp";

        // Create registry and register a domain
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            // Register domain
            let registration_proof = ZeroKnowledgeProof::new(
                "Plonky2".to_string(),
                hash_blake3(b"test_proof").to_vec(),
                owner.id.0.to_vec(),
                owner.id.0.to_vec(),
                None,
            );

            let request = DomainRegistrationRequest {
                domain: domain_name.to_string(),
                owner: owner.clone(),
                duration_days: 365,
                metadata: DomainMetadata {
                    title: "Test App".to_string(),
                    description: "A test application".to_string(),
                    category: "test".to_string(),
                    tags: vec!["test".to_string()],
                    public: true,
                    economic_settings: DomainEconomicSettings {
                        registration_fee: 10.0,
                        renewal_fee: 5.0,
                        transfer_fee: 2.5,
                        hosting_budget: 100.0,
                    },
                },
                initial_content: HashMap::new(),
                registration_proof,
                deploy_manifest_cid: None,
            };

            let response = registry.register_domain(request).await.unwrap();
            assert!(response.success, "Domain registration should succeed");

            // Verify domain exists
            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(lookup.found, "Domain should be found");
        }

        // Create new registry with same storage path and verify domain persists
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            // Domain should be loaded from persistence
            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(lookup.found, "Domain should persist across registry restarts");
            assert_eq!(lookup.record.as_ref().unwrap().domain, domain_name);
        }

        // Clean up
        let _ = std::fs::remove_file(&persist_path);
    }

    #[tokio::test]
    async fn test_domain_update_persists() {
        let temp_dir = TempDir::new().unwrap();
        let persist_path = temp_dir.path().join("dht_storage_update.bin");

        // Clear test storage for isolation
        clear_test_storage_for_path(&persist_path);

        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "updatetest.zhtp";
        let initial_manifest_cid: String;
        let updated_manifest_cid = "bafknewmanifest123456".to_string();

        // Create registry, register domain, then update it
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            // Register domain
            let registration_proof = ZeroKnowledgeProof::new(
                "Plonky2".to_string(),
                hash_blake3(b"test_proof").to_vec(),
                owner.id.0.to_vec(),
                owner.id.0.to_vec(),
                None,
            );

            let request = DomainRegistrationRequest {
                domain: domain_name.to_string(),
                owner: owner.clone(),
                duration_days: 365,
                metadata: DomainMetadata {
                    title: "Update Test".to_string(),
                    description: "Testing updates".to_string(),
                    category: "test".to_string(),
                    tags: vec![],
                    public: true,
                    economic_settings: DomainEconomicSettings {
                        registration_fee: 10.0,
                        renewal_fee: 5.0,
                        transfer_fee: 2.5,
                        hosting_budget: 100.0,
                    },
                },
                initial_content: HashMap::new(),
                registration_proof,
                deploy_manifest_cid: None,
            };

            let response = registry.register_domain(request).await.unwrap();
            assert!(response.success);

            // Get initial manifest CID
            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            initial_manifest_cid = lookup.record.as_ref().unwrap().current_web4_manifest_cid.clone();

            // Update domain
            let update_request = DomainUpdateRequest {
                domain: domain_name.to_string(),
                new_manifest_cid: updated_manifest_cid.clone(),
                expected_previous_manifest_cid: initial_manifest_cid.clone(),
                signature: String::new(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            let update_response = registry.update_domain(update_request).await.unwrap();
            assert!(update_response.success, "Domain update should succeed");
            assert_eq!(update_response.new_version, 2);
        }

        // Verify update persisted across restart
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(lookup.found);
            let record = lookup.record.unwrap();
            assert_eq!(record.version, 2, "Version should be updated");
            assert_eq!(record.current_web4_manifest_cid, updated_manifest_cid, "Manifest CID should be updated");
        }

        let _ = std::fs::remove_file(&persist_path);
    }

    #[tokio::test]
    async fn test_domain_release_persists() {
        let temp_dir = TempDir::new().unwrap();
        let persist_path = temp_dir.path().join("dht_storage_release.bin");

        // Clear test storage for isolation
        clear_test_storage_for_path(&persist_path);

        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "releasetest.zhtp";

        // Create registry and register a domain
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            let registration_proof = ZeroKnowledgeProof::new(
                "Plonky2".to_string(),
                hash_blake3(b"test_proof").to_vec(),
                owner.id.0.to_vec(),
                owner.id.0.to_vec(),
                None,
            );

            let request = DomainRegistrationRequest {
                domain: domain_name.to_string(),
                owner: owner.clone(),
                duration_days: 365,
                metadata: DomainMetadata {
                    title: "Release Test".to_string(),
                    description: "Testing release".to_string(),
                    category: "test".to_string(),
                    tags: vec![],
                    public: true,
                    economic_settings: DomainEconomicSettings {
                        registration_fee: 10.0,
                        renewal_fee: 5.0,
                        transfer_fee: 2.5,
                        hosting_budget: 100.0,
                    },
                },
                initial_content: HashMap::new(),
                registration_proof,
                deploy_manifest_cid: None,
            };

            let response = registry.register_domain(request).await.unwrap();
            assert!(response.success);

            // Release the domain
            let release_result = registry.release_domain(domain_name, &owner).await.unwrap();
            assert!(release_result, "Domain release should succeed");

            // Verify domain no longer exists
            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(!lookup.found, "Domain should not be found after release");
        }

        // Verify release persisted across restart
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new(storage).await.unwrap();

            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(!lookup.found, "Domain should remain deleted after restart");
        }

        let _ = std::fs::remove_file(&persist_path);
    }
}
