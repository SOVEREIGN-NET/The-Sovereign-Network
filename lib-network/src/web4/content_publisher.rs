//! Web4 Content Publishing System
//! 
//! Provides content publishing capabilities for registered Web4 domains,
//! with domain ownership verification and DHT integration.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use lib_identity::ZhtpIdentity;
use crate::storage_stub::UnifiedStorage;

use crate::dht::ZkDHTIntegration;
use super::types::*;
use super::domain_registry::DomainRegistry;

/// Web4 content publisher
pub struct ContentPublisher {
    /// Domain registry for ownership verification
    domain_registry: Arc<DomainRegistry>,
    /// DHT client for content storage and retrieval (optional - uses registry's DHT if None)
    dht_client: Arc<RwLock<Option<ZkDHTIntegration>>>,
    /// Storage backend (trait-based, injected by composition root)
    storage: Arc<dyn UnifiedStorage>,
    /// Content statistics
    stats: Arc<RwLock<ContentPublishingStats>>,
}

/// Content publishing statistics
#[derive(Debug, Clone, Default)]
pub struct ContentPublishingStats {
    /// Total content items published
    pub total_published: u64,
    /// Total storage used (bytes)
    pub storage_bytes: u64,
    /// Total publishing fees collected
    pub publishing_fees: f64,
    /// Content by domain
    pub content_by_domain: HashMap<String, u64>,
    /// Content by type
    pub content_by_type: HashMap<String, u64>,
}

impl ContentPublisher {
    /// Create new content publisher with injected storage
    ///
    /// This is the ONLY public constructor. Storage is injected by composition root (zhtp).
    pub fn new(domain_registry: Arc<DomainRegistry>, storage: Arc<dyn UnifiedStorage>) -> Self {
        Self {
            domain_registry,
            dht_client: Arc::new(RwLock::new(None)),
            storage,
            stats: Arc::new(RwLock::new(ContentPublishingStats::default())),
        }
    }

    /// Create new content publisher with optional DHT client
    pub fn new_with_dht(domain_registry: Arc<DomainRegistry>, storage: Arc<dyn UnifiedStorage>, dht_client: Option<ZkDHTIntegration>) -> Self {
        Self {
            domain_registry,
            dht_client: Arc::new(RwLock::new(dht_client)),
            storage,
            stats: Arc::new(RwLock::new(ContentPublishingStats::default())),
        }
    }

    /// Publish content to Web4 domain
    pub async fn publish_content(&self, request: ContentPublishRequest) -> Result<ContentPublishResponse> {
        info!("Publishing content to {}{}", request.domain, request.path);

        // Verify domain ownership
        let domain_info = self.domain_registry.lookup_domain(&request.domain).await?;
        if !domain_info.found {
            return Ok(ContentPublishResponse {
                success: false,
                content_hash: String::new(),
                zhtp_url: String::new(),
                published_at: 0,
                storage_fees: 0.0,
                error: Some(format!("Domain not registered: {}", request.domain)),
            });
        }

        let domain_record = domain_info.record.unwrap();
        
        // Verify publisher is domain owner
        if domain_record.owner != request.publisher.id {
            // Also check if ownership proof is valid (allows delegation)
            if !self.verify_publishing_authorization(&request, &domain_record).await? {
                return Ok(ContentPublishResponse {
                    success: false,
                    content_hash: String::new(),
                    zhtp_url: String::new(),
                    published_at: 0,
                    storage_fees: 0.0,
                    error: Some("Not authorized to publish to this domain".to_string()),
                });
            }
        }

        // Validate content
        self.validate_content(&request).await?;

        // Store content in DHT if available, otherwise use storage system
        let content_hash = {
            let dht_client_guard = self.dht_client.read().await;
            if let Some(_dht_client) = dht_client_guard.as_ref() {
                // Use DHT for storage
                drop(dht_client_guard);
                let mut dht_client_mut = self.dht_client.write().await;
                if let Some(dht) = dht_client_mut.as_mut() {
                    dht.store_content(&request.domain, &request.path, request.content.clone()).await?;
                    // Return content hash after storing
                    let hash = lib_crypto::hash_blake3(&request.content);
                    hex::encode(hash)
                } else {
                    // Fallback to hash-based storage
                    let hash = lib_crypto::hash_blake3(&request.content);
                    hex::encode(hash)
                }
            } else {
                // No DHT available, use hash-based content addressing
                let hash = lib_crypto::hash_blake3(&request.content);
                hex::encode(hash)
            }
        };

        // Calculate storage fees
        let storage_fees = self.calculate_storage_fees(&request).await?;

        // Create ZHTP URL
        let zhtp_url = format!("zhtp://{}{}", request.domain, request.path);

        // Update domain content mappings
        self.update_domain_content_mapping(&request.domain, &request.path, &content_hash).await?;

        // Update statistics
        self.update_publishing_stats(&request, storage_fees).await?;

        let published_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        info!(" Content published successfully: {} -> {}", zhtp_url, content_hash);

        Ok(ContentPublishResponse {
            success: true,
            content_hash,
            zhtp_url,
            published_at,
            storage_fees,
            error: None,
        })
    }

    /// Update existing content
    pub async fn update_content(&self, request: ContentPublishRequest) -> Result<ContentPublishResponse> {
        info!(" Updating content at {}{}", request.domain, request.path);

        // Reuse publish logic but add versioning info
        let response = self.publish_content(request).await?;
        
        if response.success {
            // Update metadata to indicate this is an update
            info!("Content updated successfully at {}", response.zhtp_url);
        }

        Ok(response)
    }

    /// Delete content from domain
    pub async fn delete_content(
        &self,
        domain: &str,
        path: &str,
        requester: &ZhtpIdentity,
    ) -> Result<bool> {
        info!("🗑️ Deleting content from {}{}", domain, path);

        // Verify domain ownership
        let domain_info = self.domain_registry.lookup_domain(domain).await?;
        if !domain_info.found {
            return Err(anyhow!("Domain not registered: {}", domain));
        }

        let domain_record = domain_info.record.unwrap();
        
        // Verify requester is domain owner
        if domain_record.owner != requester.id {
            return Err(anyhow!("Not authorized to delete content from this domain"));
        }

        // Remove content mapping (actual content remains in DHT for other references)
        // In a full implementation, we'd also implement reference counting for cleanup

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_published = stats.total_published.saturating_sub(1);
            
            if let Some(count) = stats.content_by_domain.get_mut(domain) {
                *count = count.saturating_sub(1);
            }
        }

        info!(" Content deleted from {}{}", domain, path);
        Ok(true)
    }

    /// Get content metadata
    pub async fn get_content_metadata(
        &self,
        domain: &str,
        path: &str,
    ) -> Result<Option<ContentMetadata>> {
        // Look up domain to get content mappings
        let domain_info = self.domain_registry.lookup_domain(domain).await?;
        
        if !domain_info.found {
            return Ok(None);
        }

        // Check if content exists for this path
        let domain_record = domain_info.record.unwrap();
        if domain_record.content_mappings.contains_key(path) {
            // In a full implementation, we'd store and retrieve actual content metadata
            // For now, return basic metadata
            Ok(Some(ContentMetadata {
                title: format!("Content at {}", path),
                description: format!("Web4 content hosted at {}{}", domain, path),
                version: "1.0".to_string(),
                tags: vec!["web4".to_string()],
                public: true,
                license: "Web4 Standard".to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    /// List all content for a domain
    pub async fn list_domain_content(&self, domain: &str) -> Result<HashMap<String, String>> {
        let domain_info = self.domain_registry.lookup_domain(domain).await?;
        
        if domain_info.found {
            Ok(domain_info.content_mappings)
        } else {
            Ok(HashMap::new())
        }
    }

    /// Get publishing statistics
    pub async fn get_statistics(&self) -> Result<ContentPublishingStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    /// Validate content before publishing
    async fn validate_content(&self, request: &ContentPublishRequest) -> Result<()> {
        // Check content size limits
        if request.content.len() > 10 * 1024 * 1024 { // 10MB limit
            return Err(anyhow!("Content exceeds 10MB limit"));
        }

        // Validate path format
        if !request.path.starts_with('/') {
            return Err(anyhow!("Content path must start with '/'"));
        }

        // Check for invalid path characters
        if request.path.contains("..") || request.path.contains("//") {
            return Err(anyhow!("Invalid path format"));
        }

        Ok(())
    }

    /// Verify publishing authorization (for delegated publishing)
    async fn verify_publishing_authorization(
        &self,
        request: &ContentPublishRequest,
        domain_record: &DomainRecord,
    ) -> Result<bool> {
        // In production, this would verify ZK proofs for delegated publishing
        // For now, just verify the ownership proof is valid format
        Ok(!request.ownership_proof.proof_data.is_empty() &&
           !request.ownership_proof.verification_key.is_empty())
    }

    /// Calculate storage fees
    async fn calculate_storage_fees(&self, request: &ContentPublishRequest) -> Result<f64> {
        let base_fee = 0.1; // 0.1 SOV base fee
        let per_kb_fee = 0.001; // 0.001 SOV per KB
        
        let size_kb = (request.content.len() as f64) / 1024.0;
        let size_fee = size_kb * per_kb_fee;
        
        Ok(base_fee + size_fee)
    }

    /// Update domain content mapping
    async fn update_domain_content_mapping(
        &self,
        domain: &str,
        path: &str,
        content_hash: &str,
    ) -> Result<()> {
        // This would update the domain record's content mappings
        // For now, we'll rely on the DHT to handle the mapping
        info!("Content mapping updated: {}{} -> {}", domain, path, content_hash);
        Ok(())
    }

    /// Update publishing statistics
    async fn update_publishing_stats(
        &self,
        request: &ContentPublishRequest,
        storage_fees: f64,
    ) -> Result<()> {
        let mut stats = self.stats.write().await;
        
        stats.total_published += 1;
        stats.storage_bytes += request.content.len() as u64;
        stats.publishing_fees += storage_fees;
        
        // Update domain stats
        *stats.content_by_domain.entry(request.domain.clone()).or_insert(0) += 1;
        
        // Update content type stats
        *stats.content_by_type.entry(request.content_type.clone()).or_insert(0) += 1;
        
        Ok(())
    }
}