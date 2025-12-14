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
        Ok(Self {
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
        })
    }

    /// Create new domain registry with optional existing DHT client
    pub async fn new_with_dht(dht_client: Option<ZkDHTIntegration>) -> Result<Self> {
        let storage_config = lib_storage::UnifiedStorageConfig::default();
        let storage_system = UnifiedStorageSystem::new(storage_config).await?;
        
        Ok(Self {
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
        })
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

        // Create initial manifest for version 1
        let initial_manifest_cid = format!(
            "bafk{}",
            hex::encode(&lib_crypto::hash_blake3(
                format!("{}:v1:{}", request.domain, current_time).as_bytes()
            )[..16])
        );

        let domain_record = DomainRecord {
            domain: request.domain.clone(),
            owner: request.owner.id.clone(),
            current_manifest_cid: initial_manifest_cid,
            version: 1,
            registered_at: current_time,
            updated_at: current_time,
            expires_at,
            ownership_proof,
            content_mappings,
            metadata: request.metadata.clone(),
            transfer_history: vec![],
        };

        // Store domain record
        let registration_id = self.store_domain_record(&domain_record).await?;

        // Update registry
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

            // Update domain record
            record.owner = to_owner.id.clone();
            record.transfer_history.push(transfer_record);

            // Update ownership proof
            record.ownership_proof = self.create_ownership_proof(
                to_owner, 
                domain, 
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
            ).await?;

            // Update statistics
            self.update_transfer_stats(transfer_fee).await?;

            info!(" Domain {} transferred successfully", domain);
            Ok(true)
        } else {
            Err(anyhow!("Domain not found: {}", domain))
        }
    }

    /// Release/delete domain
    pub async fn release_domain(&self, domain: &str, owner: &ZhtpIdentity) -> Result<bool> {
        info!("🗑️ Releasing Web4 domain: {}", domain);

        let mut records = self.domain_records.write().await;
        
        if let Some(record) = records.get(domain) {
            // Verify ownership
            if record.owner != owner.id {
                return Err(anyhow!("Release denied: not domain owner"));
            }

            // Remove domain record
            records.remove(domain);

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_domains = stats.total_domains.saturating_sub(1);
            }

            info!(" Domain {} released successfully", domain);
            Ok(true)
        } else {
            Err(anyhow!("Domain not found: {}", domain))
        }
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

        // Store content in DHT using UnifiedStorageSystem
        {
            let mut storage = self.storage_system.write().await;
            
            // Create storage requirements for the content
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
            // Use new_unified for simpler creation (generates keypair internally)
            let uploader = lib_identity::ZhtpIdentity::new_unified(
                lib_identity::types::identity_types::IdentityType::Human,
                Some(25), // Default age
                Some("US".to_string()), // Default jurisdiction
                &format!("web4_publisher_{}", domain),
                None, // Random seed
            ).map_err(|e| anyhow!("Failed to create uploader identity: {}", e))?;
            
            // Store in DHT via UnifiedStorageSystem (NO CACHE FALLBACK - DHT ONLY)
            let actual_storage_hash = match storage.upload_content(upload_request, uploader).await {
                Ok(storage_hash) => {
                    info!("  Stored in DHT successfully");
                    info!("    Original hash: {}", short_hash);
                    info!("    DHT storage hash: {}", hex::encode(storage_hash.as_bytes()));
                    info!("    (Different due to compression)");
                    storage_hash
                }
                Err(e) => {
                    error!(" DHT storage FAILED (no cache fallback): {}", e);
                    return Err(anyhow!("Failed to store content in DHT: {}", e));
                }
            };
            
            // Convert storage_hash to hex string for content_mappings
            let storage_hash_hex = hex::encode(actual_storage_hash.as_bytes());
            
            // Store in cache using the ACTUAL DHT STORAGE hash (compressed content hash)
            {
                let mut cache = self.content_cache.write().await;
                cache.insert(storage_hash_hex.clone(), content.clone());
                info!(" Cached content with DHT storage hash: {}", storage_hash_hex);
            }
            
            // CRITICAL: Return the ACTUAL DHT storage hash (after compression/encryption)
            // This is the hash that can be used to retrieve the content from DHT
            Ok(storage_hash_hex)
        }
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
        
        // Convert hex hash to Hash bytes (should be full 32 bytes now)
        let hash_bytes = hex::decode(content_hash)
            .map_err(|e| anyhow!("Invalid content hash format: {}", e))?;
        
        if hash_bytes.len() != 32 {
            return Err(anyhow!("Content hash must be 32 bytes, got {}", hash_bytes.len()));
        }
        
        let content_hash_obj = lib_crypto::Hash(hash_bytes.try_into()
            .map_err(|_| anyhow!("Failed to convert hash to array"))?);
        
        // Create download request with anonymous requester
        // Use new_unified for simpler creation (generates keypair internally)
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
        
        // Attempt DHT retrieval
        let mut storage = self.storage_system.write().await;
        match storage.download_content(download_request).await {
            Ok(content) => {
                info!(" Retrieved {} bytes from DHT", content.len());
                
                // Store in cache for next time
                let mut cache = self.content_cache.write().await;
                cache.insert(content_hash.to_string(), content.clone());
                
                Ok(content)
            }
            Err(e) => {
                error!(" Failed to retrieve content from DHT: {}", e);
                Err(anyhow!("Content not found for hash: {} (DHT error: {})", content_hash, e))
            }
        }
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
        info!(" DEBUG: get_domain_status for '{}'. Total domains: {}. Registry ptr: {:p}",
            domain, records.len(), &*self.domain_records);

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

        // Update record atomically
        record.current_manifest_cid = update_request.new_manifest_cid.clone();
        record.version = new_version;
        record.updated_at = current_time;

        info!(
            " Domain {} updated: v{} -> v{} (CID: {} -> {})",
            update_request.domain,
            new_version - 1,
            new_version,
            &previous_manifest_cid[..16.min(previous_manifest_cid.len())],
            &update_request.new_manifest_cid[..16.min(update_request.new_manifest_cid.len())]
        );

        Ok(DomainUpdateResponse {
            success: true,
            new_version,
            new_manifest_cid: update_request.new_manifest_cid,
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
        };

        self.registry.register_domain(request).await
    }

    /// Get domain info (public method)
    pub async fn get_domain_info(&self, domain: &str) -> Result<DomainLookupResponse> {
        self.registry.lookup_domain(domain).await
    }
}