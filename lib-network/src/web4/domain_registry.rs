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
use lib_storage::{UnifiedStorageSystem, UploadRequest, AccessControlSettings, ContentStorageRequirements};

use crate::dht::ZkDHTIntegration;
use super::types::*;
use super::content_publisher::ContentPublisher;
use lib_blockchain;

/// Web4 domain registry manager
pub struct DomainRegistry {
    /// Domain records storage
    domain_records: Arc<RwLock<HashMap<String, DomainRecord>>>,
    /// DHT client for direct storage
    dht_client: Arc<RwLock<Option<ZkDHTIntegration>>>,
    /// Storage backend for persistence
    storage_system: Arc<RwLock<UnifiedStorageSystem>>,
    /// Content cache (hash -> bytes)
    content_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Registry statistics
    stats: Arc<RwLock<Web4Statistics>>,
    /// Manifest history per domain (domain -> list of manifests, oldest first)
    manifest_history: Arc<RwLock<HashMap<String, Vec<Web4Manifest>>>>,
}

impl DomainRegistry {
    /// Create new domain registry
    pub async fn new() -> Result<Self> {
        Self::new_with_dht(None).await
    }

    /// Create new domain registry with existing storage system (avoids creating duplicates)
    pub async fn new_with_storage(storage: std::sync::Arc<tokio::sync::RwLock<lib_storage::UnifiedStorageSystem>>) -> Result<Self> {
        let registry = Self {
            domain_records: Arc::new(RwLock::new(HashMap::new())),
            dht_client: Arc::new(RwLock::new(None)), // No DHT client needed when using shared storage
            storage_system: storage,
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

        // Load persisted domain records from storage
        registry.load_persisted_domains().await?;

        Ok(registry)
    }

    /// Create new domain registry with optional existing DHT client
    pub async fn new_with_dht(dht_client: Option<ZkDHTIntegration>) -> Result<Self> {
        let storage_config = lib_storage::UnifiedStorageConfig::default();
        let storage_system = UnifiedStorageSystem::new(storage_config).await?;

        let registry = Self {
            domain_records: Arc::new(RwLock::new(HashMap::new())),
            dht_client: Arc::new(RwLock::new(dht_client)), // Use provided DHT client if available
            storage_system: Arc::new(RwLock::new(storage_system)),
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

        // Load persisted domain records from storage
        registry.load_persisted_domains().await?;

        Ok(registry)
    }

    // ========================================================================
    // Domain Persistence - Load and save domain records to lib-storage
    // ========================================================================

    /// Load all persisted domain records from lib-storage into the in-memory cache
    async fn load_persisted_domains(&self) -> Result<()> {
        // LOCK SAFETY: Acquire storage lock, do async work, release before acquiring other locks
        let records = {
            let mut storage = self.storage_system.write().await;
            storage.list_domain_records().await?
        }; // storage lock released here

        if records.is_empty() {
            info!("No persisted domain records found in storage");
            return Ok(());
        }

        // Parse records outside of any lock
        let mut parsed_records = Vec::new();
        for (domain, data) in records {
            match serde_json::from_slice::<DomainRecord>(&data) {
                Ok(record) => {
                    info!(" Loaded persisted domain: {} (v{})", record.domain, record.version);
                    parsed_records.push((domain, record));
                }
                Err(e) => {
                    warn!(" Failed to deserialize domain record: {}", e);
                }
            }
        }

        let loaded_count = parsed_records.len() as u64;

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

        info!(" Loaded {} persisted domain records from storage", loaded_count);
        Ok(())
    }

    /// Persist a domain record to lib-storage
    async fn persist_domain_record(&self, record: &DomainRecord) -> Result<()> {
        let data = serde_json::to_vec(record)
            .map_err(|e| anyhow!("Failed to serialize domain record: {}", e))?;

        let mut storage = self.storage_system.write().await;
        storage.store_domain_record(&record.domain, &data).await?;

        info!(" Persisted domain record: {} (v{})", record.domain, record.version);
        Ok(())
    }

    /// Delete a domain record from lib-storage
    async fn delete_persisted_domain(&self, domain: &str) -> Result<()> {
        let mut storage = self.storage_system.write().await;
        storage.delete_domain_record(domain).await?;

        info!(" Deleted persisted domain record: {}", domain);
        Ok(())
    }

    /// Register a new Web4 domain
    pub async fn register_domain(&self, request: DomainRegistrationRequest) -> Result<DomainRegistrationResponse> {
        info!("Registering Web4 domain: {}", request.domain);

        // Validate domain name
        self.validate_domain_name(&request.domain)?;

        // Check if domain is already registered
        {
            let records = self.domain_records.read().await;
            if records.contains_key(&request.domain) {
                return Ok(DomainRegistrationResponse {
                    domain: request.domain.clone(),
                    success: false,
                    registration_id: String::new(),
                    expires_at: 0,
                    fees_charged: 0.0,
                    error: Some("Domain already registered".to_string()),
                });
            }
        }

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

        // Use provided manifest CID or generate one
        let manifest_cid = request.manifest_cid.clone().unwrap_or_else(|| {
            format!(
                "bafk{}",
                hex::encode(&lib_crypto::hash_blake3(
                    format!("{}:v1:{}", request.domain, current_time).as_bytes()
                )[..16])
            )
        });

        let domain_record = DomainRecord {
            domain: request.domain.clone(),
            owner: request.owner.id.clone(),
            current_manifest_cid: manifest_cid,
            version: 1,
            registered_at: current_time,
            updated_at: current_time,
            expires_at,
            ownership_proof,
            content_mappings,
            metadata: request.metadata.clone(),
            transfer_history: vec![],
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
        
        drop(records); // Release lock before blockchain query
        
        // Domain not found locally or expired - query blockchain
        info!(" Domain {} not found locally, querying blockchain...", domain);
        match self.query_blockchain_for_domain(domain).await {
            Ok(Some(domain_record)) => {
                info!(" Domain {} found on blockchain, caching locally", domain);
                
                // Cache the domain record locally for future lookups
                {
                    let mut records = self.domain_records.write().await;
                    records.insert(domain.to_string(), domain_record.clone());
                }
                
                let owner_info = PublicOwnerInfo {
                    identity_hash: hex::encode(&domain_record.owner.0[..16]),
                    registered_at: domain_record.registered_at,
                    verified: true,
                    alias: None,
                };

                Ok(DomainLookupResponse {
                    found: true,
                    record: Some(domain_record.clone()),
                    content_mappings: domain_record.content_mappings.clone(),
                    owner_info: Some(owner_info),
                })
            }
            Ok(None) => {
                info!(" Domain {} not found on blockchain either", domain);
                Ok(DomainLookupResponse {
                    found: false,
                    record: None,
                    content_mappings: HashMap::new(),
                    owner_info: None,
                })
            }
            Err(e) => {
                warn!(" Failed to query blockchain for domain {}: {}", domain, e);
                // Return not found rather than error to maintain compatibility
                Ok(DomainLookupResponse {
                    found: false,
                    record: None,
                    content_mappings: HashMap::new(),
                    owner_info: None,
                })
            }
        }
    }

    /// Query blockchain for Web4Contract by domain name
    async fn query_blockchain_for_domain(&self, domain: &str) -> Result<Option<DomainRecord>> {
        // TODO: Blockchain query temporarily disabled during blockchain provider refactor
        // Web4 contracts are still recorded on blockchain via zhtp API, but cross-library
        // access needs to be refactored. For now, domains are discovered via DHT.
        warn!(" Blockchain query not available in lib-network - domains discovered via DHT only");
        Ok(None)
    }

    /// Convert Web4Contract from blockchain to DomainRecord for local use
    fn convert_web4_contract_to_domain_record(&self, web4_contract: &lib_blockchain::contracts::web4::Web4Contract) -> Result<DomainRecord> {
        // Convert Web4Contract routes to content_mappings
        let mut content_mappings: HashMap<String, String> = HashMap::new();
        
        for (path, content_route) in &web4_contract.routes {
            let path_str: String = path.clone();
            content_mappings.insert(path_str, content_route.content_hash.clone());
        }
        
        // Parse owner identity from string
        let owner = if web4_contract.owner.len() >= 32 {
            // If owner is hex string, decode it
            match hex::decode(&web4_contract.owner) {
                Ok(bytes) if bytes.len() >= 32 => {
                    let mut owner_bytes = [0u8; 32];
                    owner_bytes.copy_from_slice(&bytes[..32]);
                    lib_crypto::Hash(owner_bytes)
                }
                _ => {
                    // Fallback: hash the owner string
                    lib_crypto::Hash::from_bytes(&hash_blake3(web4_contract.owner.as_bytes())[..32])
                }
            }
        } else {
            // Hash short owner strings
            lib_crypto::Hash::from_bytes(&hash_blake3(web4_contract.owner.as_bytes())[..32])
        };

        // Convert WebsiteMetadata to DomainMetadata
        let domain_metadata = DomainMetadata {
            title: web4_contract.metadata.title.clone(),
            description: web4_contract.metadata.description.clone(),
            category: "web4".to_string(), // Default category for Web4 sites
            tags: web4_contract.metadata.tags.clone(),
            public: true, // Web4 contracts are publicly accessible
            economic_settings: DomainEconomicSettings {
                registration_fee: 1000.0, // Default registration fee
                renewal_fee: 500.0,       // Default renewal fee  
                transfer_fee: 250.0,      // Default transfer fee
                hosting_budget: 10000.0,  // Default hosting budget
            },
        };

        // Generate manifest CID from contract data
        let manifest_cid = format!(
            "bafk{}",
            hex::encode(&lib_crypto::hash_blake3(
                format!("{}:v1:{}", web4_contract.domain, web4_contract.created_at).as_bytes()
            )[..16])
        );

        Ok(DomainRecord {
            domain: web4_contract.domain.clone(),
            owner,
            current_manifest_cid: manifest_cid,
            version: 1, // Contracts imported from blockchain start at version 1
            registered_at: web4_contract.created_at,
            updated_at: web4_contract.created_at,
            expires_at: web4_contract.created_at + (365 * 24 * 60 * 60), // 1 year default
            content_mappings,
            metadata: domain_metadata,
            ownership_proof: ZeroKnowledgeProof::new(
                "Web4Contract".to_string(),
                web4_contract.contract_id.as_bytes().to_vec(),
                web4_contract.domain.as_bytes().to_vec(),
                web4_contract.owner.as_bytes().to_vec(),
                None,
            ),
            transfer_history: Vec::new(), // Not tracked in current contract version
        })
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

        // Verify ownership BEFORE any mutations
        {
            let records = self.domain_records.read().await;

            if let Some(record) = records.get(domain) {
                // Verify ownership
                if record.owner != owner.id {
                    return Err(anyhow!("Release denied: not domain owner"));
                }
            } else {
                return Err(anyhow!("Domain not found: {}", domain));
            }
        }

        // Delete from persistent storage FIRST - if this fails, memory stays unchanged (durability guarantee)
        self.delete_persisted_domain(&domain_to_delete).await?;

        // Only mutate memory AFTER successful persistence deletion
        {
            let mut records = self.domain_records.write().await;
            records.remove(domain);
        }

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
        
        // Must be 3-63 characters
        if name.len() < 3 || name.len() > 63 {
            return Err(anyhow!("Domain name must be 3-63 characters (excluding TLD)"));
        }

        // Must contain only valid characters
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(anyhow!("Domain name can only contain letters, numbers, and hyphens"));
        }

        // Cannot start or end with hyphen
        if name.starts_with('-') || name.ends_with('-') {
            return Err(anyhow!("Domain name cannot start or end with hyphen"));
        }

        Ok(())
    }

    /// Store domain content in DHT
    async fn store_domain_content(&self, domain: &str, path: &str, content: Vec<u8>) -> Result<String> {
        // Calculate original content hash for logging only
        let hash_bytes = hash_blake3(&content);
        let short_hash = hex::encode(&hash_bytes[..8]); // For logging only

        info!(" Storing content for domain {} at path {} (original hash: {}..., size: {} bytes)",
              domain, path, short_hash, content.len());

        // Prepare upload request and uploader identity OUTSIDE of lock
        let storage_requirements = ContentStorageRequirements {
            duration_days: 365, // 1 year storage
            quality_requirements: lib_storage::QualityRequirements {
                min_uptime: 0.99,
                max_response_time: 1000,
                min_replication: 2,
                geographic_distribution: None,
                required_certifications: vec![],
            },
            budget_constraints: lib_storage::BudgetConstraints {
                max_total_cost: 1000,
                max_cost_per_gb_day: 10,
                payment_schedule: lib_storage::types::economic_types::PaymentSchedule::Daily,
                max_price_volatility: 0.1,
            },
        };

        // Determine MIME type from path
        let mime_type = if path.ends_with(".css") {
            "text/css"
        } else if path.ends_with(".js") {
            "application/javascript"
        } else if path.ends_with(".json") {
            "application/json"
        } else if path.ends_with(".png") {
            "image/png"
        } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
            "image/jpeg"
        } else {
            "text/html"
        }.to_string();

        // Create upload request
        let upload_request = UploadRequest {
            content: content.clone(),
            filename: format!("{}:{}", domain, path),
            mime_type,
            description: format!("Web4 content for {} at {}", domain, path),
            tags: vec!["web4".to_string(), domain.to_string()],
            encrypt: false, // Web4 content is public
            compress: true,  // Compress for efficiency
            access_control: AccessControlSettings {
                public_read: true,
                read_permissions: vec![],
                write_permissions: vec![],
                expires_at: None,
            },
            storage_requirements,
        };

        // Create uploader identity (use domain owner or anonymous)
        let uploader = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::types::identity_types::IdentityType::Human,
            Some(25), // Default age
            Some("US".to_string()), // Default jurisdiction
            &format!("web4_publisher_{}", domain),
            None, // Random seed
        ).map_err(|e| anyhow!("Failed to create uploader identity: {}", e))?;

        // LOCK SAFETY: Acquire storage lock, do async work, release before acquiring other locks
        let actual_storage_hash = {
            let mut storage = self.storage_system.write().await;
            storage.upload_content(upload_request, uploader).await
                .map_err(|e| {
                    error!(" DHT storage FAILED (no cache fallback): {}", e);
                    anyhow!("Failed to store content in DHT: {}", e)
                })?
        }; // storage lock released here

        info!("  Stored in DHT successfully");
        info!("    Original hash: {}", short_hash);
        info!("    DHT storage hash: {}", hex::encode(actual_storage_hash.as_bytes()));
        info!("    (Different due to compression)");

        // Convert storage_hash to hex string for content_mappings
        let storage_hash_hex = hex::encode(actual_storage_hash.as_bytes());

        // LOCK SAFETY: Acquire cache lock separately
        {
            let mut cache = self.content_cache.write().await;
            cache.insert(storage_hash_hex.clone(), content);
            info!(" Cached content with DHT storage hash: {}", storage_hash_hex);
        } // cache lock released here

        // CRITICAL: Return the ACTUAL DHT storage hash (after compression/encryption)
        // This is the hash that can be used to retrieve the content from DHT
        Ok(storage_hash_hex)
    }

    /// Store domain record to persistent storage
    async fn store_domain_record(&self, record: &DomainRecord) -> Result<String> {
        let record_data = serde_json::to_vec(record)?;
        let record_hash = hex::encode(&hash_blake3(&record_data)[..32]);

        info!(" Storing domain record for {} (hash: {})", record.domain, &record_hash[..16]);

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
        let base_fee = 10.0; // 10 ZHTP base fee
        let per_day_fee = 0.01; // 0.01 ZHTP per day
        
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

    /// Get content by hash from DHT ONLY (cache disabled for testing)
    pub async fn get_content(&self, content_hash: &str) -> Result<Vec<u8>> {
        // CACHE DISABLED - Force DHT retrieval for testing
        info!(" TESTING MODE: Skipping cache, retrieving from DHT for content hash: {}", content_hash);

        // Note: Cache check disabled to test DHT functionality
        // {
        //     let cache = self.content_cache.read().await;
        //     if let Some(content) = cache.get(content_hash) {
        //         info!(" Cache hit for content hash: {}", content_hash);
        //         return Ok(content.clone());
        //     }
        // }

        // Prepare download request OUTSIDE of lock
        let hash_bytes = hex::decode(content_hash)
            .map_err(|e| anyhow!("Invalid content hash format: {}", e))?;

        if hash_bytes.len() != 32 {
            return Err(anyhow!("Content hash must be 32 bytes, got {}", hash_bytes.len()));
        }

        let content_hash_obj = lib_crypto::Hash(hash_bytes.try_into()
            .map_err(|_| anyhow!("Failed to convert hash to array"))?);

        // Create download request with anonymous requester
        let requester = lib_identity::ZhtpIdentity::new_unified(
            lib_identity::types::identity_types::IdentityType::Human,
            Some(25), // Default age
            Some("US".to_string()), // Default jurisdiction
            "web4_retriever",
            None, // Random seed
        ).map_err(|e| anyhow!("Failed to create requester identity: {}", e))?;

        let download_request = lib_storage::DownloadRequest {
            content_hash: content_hash_obj,
            requester,
            version: None,
        };

        // LOCK SAFETY: Acquire storage lock, do async work, release before acquiring other locks
        let content = {
            let mut storage = self.storage_system.write().await;
            storage.download_content(download_request).await
                .map_err(|e| {
                    error!(" Failed to retrieve content from DHT: {}", e);
                    anyhow!("Content not found for hash: {} (DHT error: {})", content_hash, e)
                })?
        }; // storage lock released here

        info!(" Retrieved {} bytes from DHT", content.len());

        // LOCK SAFETY: Acquire cache lock separately
        {
            let mut cache = self.content_cache.write().await;
            cache.insert(content_hash.to_string(), content.clone());
        } // cache lock released here

        Ok(content)
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
            Ok(DomainStatusResponse {
                found: true,
                domain: record.domain.clone(),
                version: record.version,
                current_manifest_cid: record.current_manifest_cid.clone(),
                owner_did: format!("did:zhtp:{}", hex::encode(&record.owner.0[..16])),
                updated_at: record.updated_at,
                expires_at: record.expires_at,
                build_hash: hex::encode(&hash_blake3(record.current_manifest_cid.as_bytes())[..16]),
            })
        } else {
            Ok(DomainStatusResponse {
                found: false,
                domain: domain.to_string(),
                version: 0,
                current_manifest_cid: String::new(),
                owner_did: String::new(),
                updated_at: 0,
                expires_at: 0,
                build_hash: String::new(),
            })
        }
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

        // Store in content cache
        {
            let mut cache = self.content_cache.write().await;
            cache.insert(cid.clone(), content);
            info!(" Stored content by CID: {} ({} bytes)", cid, cache.get(&cid).map(|c| c.len()).unwrap_or(0));
        }

        Ok(cid)
    }

    /// Retrieve content by CID
    /// Returns None if content not found
    pub async fn get_content_by_cid(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let cache = self.content_cache.read().await;
        let content = cache.get(cid).cloned();

        if content.is_some() {
            info!(" Retrieved content by CID: {}", cid);
        } else {
            info!(" Content not found for CID: {}", cid);
        }

        Ok(content)
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
                    manifest_cid: manifest.compute_cid(),
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
                manifest_cid: record.current_manifest_cid.clone(),
                created_at: record.updated_at,
                created_by: format!("did:zhtp:{}", hex::encode(&record.owner.0[..16])),
                message: Some("Initial deployment".to_string()),
                build_hash: hex::encode(&hash_blake3(record.current_manifest_cid.as_bytes())[..16]),
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
        if record.current_manifest_cid != update_request.expected_previous_manifest_cid {
            return Ok(DomainUpdateResponse {
                success: false,
                new_version: record.version,
                new_manifest_cid: record.current_manifest_cid.clone(),
                previous_manifest_cid: record.current_manifest_cid.clone(),
                updated_at: record.updated_at,
                error: Some(format!(
                    "Concurrent update detected. Expected previous CID: {}, actual: {}",
                    update_request.expected_previous_manifest_cid,
                    record.current_manifest_cid
                )),
            });
        }

        // TODO: Verify signature matches domain owner
        // For now, we trust the caller has verified authorization

        let previous_manifest_cid = record.current_manifest_cid.clone();
        let new_version = record.version + 1;
        let new_manifest_cid = update_request.new_manifest_cid.clone();

        // Create updated record for persistence (persist BEFORE mutating memory)
        let mut updated_record = record.clone();
        updated_record.current_manifest_cid = new_manifest_cid.clone();
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
                record.current_manifest_cid = updated_record.current_manifest_cid.clone();
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

        // Validate manifest chain if we have the previous one
        if manifest.version > 1 {
            let manifests = self.manifest_history.read().await;
            if let Some(domain_manifests) = manifests.get(&manifest.domain) {
                if let Some(prev) = domain_manifests.last() {
                    manifest.validate_chain(Some(prev))
                        .map_err(|e| anyhow!("Manifest chain validation failed: {}", e))?;
                }
            }
        } else {
            manifest.validate_chain(None)
                .map_err(|e| anyhow!("Manifest validation failed: {}", e))?;
        }

        // Store manifest in history
        let mut manifests = self.manifest_history.write().await;
        manifests
            .entry(manifest.domain.clone())
            .or_insert_with(Vec::new)
            .push(manifest);

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
            .map(|r| r.current_manifest_cid.clone())
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
    /// Create new Web4 manager
    pub async fn new() -> Result<Self> {
        Self::new_with_dht(None).await
    }

    /// Create new Web4 manager with existing storage system (avoids creating duplicates)
    pub async fn new_with_storage(storage: std::sync::Arc<tokio::sync::RwLock<lib_storage::UnifiedStorageSystem>>) -> Result<Self> {
        let registry = DomainRegistry::new_with_storage(storage.clone()).await?;
        let registry_arc = Arc::new(registry);
        let content_publisher = super::content_publisher::ContentPublisher::new_with_storage(registry_arc.clone(), storage).await?;
        
        Ok(Self {
            registry: registry_arc,
            content_publisher,
        })
    }

    /// Create new Web4 manager with optional existing DHT client
    pub async fn new_with_dht(dht_client: Option<ZkDHTIntegration>) -> Result<Self> {
        let registry = DomainRegistry::new_with_dht(dht_client).await?;
        let registry_arc = Arc::new(registry);
        let content_publisher = super::content_publisher::ContentPublisher::new(registry_arc.clone()).await?;

        Ok(Self {
            registry: registry_arc,
            content_publisher,
        })
    }

    /// Create new Web4 manager with existing domain registry (avoids duplicates)
    /// This is the preferred constructor when a DomainRegistry already exists
    pub async fn new_with_registry(
        registry: Arc<DomainRegistry>,
        storage: std::sync::Arc<tokio::sync::RwLock<lib_storage::UnifiedStorageSystem>>,
    ) -> Result<Self> {
        let content_publisher = super::content_publisher::ContentPublisher::new_with_storage(
            registry.clone(),
            storage
        ).await?;

        Ok(Self {
            registry,
            content_publisher,
        })
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
            manifest_cid: None, // Auto-generate
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

    /// Create a test storage system with persistence enabled
    async fn create_test_storage_with_persistence(persist_path: std::path::PathBuf) -> Arc<RwLock<UnifiedStorageSystem>> {
        let mut config = lib_storage::UnifiedStorageConfig::default();
        config.storage_config.dht_persist_path = Some(persist_path);
        let storage = UnifiedStorageSystem::new(config).await.unwrap();
        Arc::new(RwLock::new(storage))
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

        // Clean up any existing file
        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "testapp.zhtp";

        // Create registry and register a domain
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

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
                manifest_cid: None,
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
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

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

        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "updatetest.zhtp";
        let initial_manifest_cid: String;
        let updated_manifest_cid = "bafknewmanifest123456".to_string();

        // Create registry, register domain, then update it
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

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
                manifest_cid: None,
            };

            let response = registry.register_domain(request).await.unwrap();
            assert!(response.success);

            // Get initial manifest CID
            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            initial_manifest_cid = lookup.record.as_ref().unwrap().current_manifest_cid.clone();

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
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(lookup.found);
            let record = lookup.record.unwrap();
            assert_eq!(record.version, 2, "Version should be updated");
            assert_eq!(record.current_manifest_cid, updated_manifest_cid, "Manifest CID should be updated");
        }

        let _ = std::fs::remove_file(&persist_path);
    }

    #[tokio::test]
    async fn test_domain_release_persists() {
        let temp_dir = TempDir::new().unwrap();
        let persist_path = temp_dir.path().join("dht_storage_release.bin");

        let _ = std::fs::remove_file(&persist_path);

        let owner = create_test_identity();
        let domain_name = "releasetest.zhtp";

        // Create registry and register a domain
        {
            let storage = create_test_storage_with_persistence(persist_path.clone()).await;
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

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
                manifest_cid: None,
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
            let registry = DomainRegistry::new_with_storage(storage).await.unwrap();

            let lookup = registry.lookup_domain(domain_name).await.unwrap();
            assert!(!lookup.found, "Domain should remain deleted after restart");
        }

        let _ = std::fs::remove_file(&persist_path);
    }
}