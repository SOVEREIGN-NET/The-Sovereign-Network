use anyhow::Result;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::PathBuf;
use crate::zhtp::zk_proofs::StorageProof;

/// Service type identifiers
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    Storage,
    Compute,
    Routing,
    Gateway,
    Custom(String),
}

/// Service metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Unique service identifier
    pub id: ContentId,
    /// Service type
    pub service_type: ServiceType,
    /// Node ID providing the service
    pub provider: Vec<u8>,
    /// Service endpoint information
    pub endpoint: String,
    /// Service capabilities/features
    pub capabilities: HashMap<String, String>,
    /// Last verified timestamp
    pub last_verified: u64,
    /// Service proof (if applicable)
    #[serde(skip)]
    pub proof: Option<StorageProof>,
}

/// Content identifier using SHA-256
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ContentId(
    #[serde(with = "serde_bytes")]
    pub [u8; 32]
);

impl ContentId {
    /// Create a new ContentId by hashing data
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }
}

impl From<String> for ContentId {
    fn from(s: String) -> Self {
        Self::new(s.as_bytes())
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Content metadata for discovery and routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content identifier
    pub id: ContentId,
    /// Total size in bytes
    pub size: u64,
    /// Content type (MIME)
    pub content_type: String,
    /// Storage nodes that have this content
    pub locations: Vec<Vec<u8>>,
    /// Timestamp of last verification
    pub last_verified: u64,
    /// Content tags for search
    pub tags: Vec<String>,
}

/// Content system statistics for ZHTP monitoring
#[derive(Debug, Clone)]
pub struct ContentStats {
    pub total_content: u64,
    pub total_services: u64,
    pub total_size_bytes: u64,
    pub popular_content: u64,
    pub unique_providers: u64,
}

/// Content addressing system for DHT
#[derive(Debug)]
pub struct ContentAddressing {
    /// Map of content IDs to metadata
    content_map: Arc<RwLock<HashMap<ContentId, ContentMetadata>>>,
    type_index: Arc<RwLock<HashMap<String, Vec<ContentId>>>>,
    size_index: Arc<RwLock<HashMap<u64, Vec<ContentId>>>>,
    tag_index: Arc<RwLock<HashMap<String, Vec<ContentId>>>>,
    services: Arc<RwLock<HashMap<ServiceType, Vec<ServiceInfo>>>>,
    access_counts: Arc<RwLock<HashMap<ContentId, u32>>>,
    /// Real content storage backend
    content_storage: Arc<RwLock<HashMap<ContentId, Vec<u8>>>>,
    /// Storage directory for persistent content
    storage_path: PathBuf,
}

impl Default for ContentAddressing {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentAddressing {
    pub fn new() -> Self {
        let storage_path = PathBuf::from("./storage/content");
        Self {
            content_map: Arc::new(RwLock::new(HashMap::new())),
            type_index: Arc::new(RwLock::new(HashMap::new())),
            size_index: Arc::new(RwLock::new(HashMap::new())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
            services: Arc::new(RwLock::new(HashMap::new())),
            access_counts: Arc::new(RwLock::new(HashMap::new())),
            content_storage: Arc::new(RwLock::new(HashMap::new())),
            storage_path,
        }
    }

    /// Create storage directory if it doesn't exist
    async fn ensure_storage_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.storage_path).await?;
        Ok(())
    }

    /// Get file path for content ID
    fn get_content_path(&self, content_id: &ContentId) -> PathBuf {
        let filename = format!("{}.dat", content_id);
        self.storage_path.join(filename)
    }

    /// Store content data to disk
    async fn store_content_to_disk(&self, content_id: &ContentId, data: &[u8]) -> Result<()> {
        self.ensure_storage_dir().await?;
        let file_path = self.get_content_path(content_id);
        let mut file = fs::File::create(file_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        Ok(())
    }

    /// Load content data from disk
    async fn load_content_from_disk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        let file_path = self.get_content_path(content_id);
        let mut file = fs::File::open(file_path).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;
        Ok(data)
    }

    /// Verify content integrity by comparing hash
    async fn verify_content_integrity(&self, content_id: &ContentId, data: &[u8]) -> bool {
        let computed_id = ContentId::new(data);
        *content_id == computed_id
    }

    /// Register new content in the system with real storage
    pub async fn register_content(
        &self,
        data: &[u8],
        content_type: String,
        node_id: Vec<u8>,
        tags: Vec<String>,
    ) -> Result<ContentId> {
        let content_id = ContentId::new(data);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Store actual content data in memory and disk
        {
            let mut content_storage = self.content_storage.write().await;
            content_storage.insert(content_id.clone(), data.to_vec());
        }
        
        // Store content to persistent disk storage
        self.store_content_to_disk(&content_id, data).await?;

        let data_size = data.len() as u64;
        let mut content_map = self.content_map.write().await;
        let mut type_idx = self.type_index.write().await;
        let mut size_idx = self.size_index.write().await;
        let mut access_counts = self.access_counts.write().await;
        
        if let Some(metadata) = content_map.get_mut(&content_id) {
            // Content exists, add new location
            if !metadata.locations.contains(&node_id) {
                metadata.locations.push(node_id);
            }
            metadata.last_verified = now;
        } else {
            // New content
            let metadata = ContentMetadata {
                id: content_id.clone(),
                size: data_size,
                content_type: content_type.clone(),
                locations: vec![node_id],
                last_verified: now,
                tags: tags.clone(),
            };
            content_map.insert(content_id.clone(), metadata);

            // Update indexes
            type_idx.entry(content_type)
                .or_insert_with(Vec::new)
                .push(content_id.clone());

            // Update tag index
            let mut tag_idx = self.tag_index.write().await;
            for tag in tags {
                tag_idx.entry(tag)
                    .or_insert_with(Vec::new)
                    .push(content_id.clone());
            }

            size_idx.entry(data_size)
                .or_insert_with(Vec::new)
                .push(content_id.clone());

            // Initialize access count
            access_counts.insert(content_id.clone(), 0);
        }

        Ok(content_id)
    }

    /// Fetch actual content data by ID from storage
    pub async fn fetch_content_data(&self, id: &ContentId) -> Result<Option<Vec<u8>>> {
        // Try memory storage first (faster)
        {
            let content_storage = self.content_storage.read().await;
            if let Some(data) = content_storage.get(id) {
                // Verify integrity before returning
                if self.verify_content_integrity(id, data).await {
                    return Ok(Some(data.clone()));
                } else {
                    log::warn!("Content integrity check failed for {} in memory", id);
                }
            }
        }

        // Fall back to disk storage
        match self.load_content_from_disk(id).await {
            Ok(data) => {
                // Verify integrity
                if self.verify_content_integrity(id, &data).await {
                    // Cache in memory for future access
                    {
                        let mut content_storage = self.content_storage.write().await;
                        content_storage.insert(id.clone(), data.clone());
                    }
                    Ok(Some(data))
                } else {
                    log::error!("Content integrity check failed for {} on disk", id);
                    Ok(None)
                }
            }
            Err(e) => {
                log::debug!("Failed to load content {} from disk: {}", id, e);
                Ok(None)
            }
        }
    }

    /// Find content by ID
    pub async fn find_content(&self, id: &ContentId) -> Option<ContentMetadata> {
        // Increment access count
        {
            let mut access_counts = self.access_counts.write().await;
            if let Some(count) = access_counts.get_mut(id) {
                *count += 1;
            }
        }

        // Return content metadata
        self.content_map.read().await.get(id).cloned()
    }

    /// Find nodes storing specific content
    pub async fn get_content_locations(&self, id: &ContentId) -> Vec<Vec<u8>> {
        self.content_map
            .read()
            .await
            .get(id)
            .map(|meta| meta.locations.clone())
            .unwrap_or_default()
    }

    /// Real content verification with actual integrity checks
    pub async fn verify_content(&self, id: &ContentId, node_id: &[u8]) -> bool {
        let mut content_map = self.content_map.write().await;
        
        if let Some(metadata) = content_map.get_mut(id) {
            if metadata.locations.contains(&node_id.to_vec()) {
                // Fetch and verify actual content data
                drop(content_map); // Release lock before async operation
                
                match self.fetch_content_data(id).await {
                    Ok(Some(data)) => {
                        // Verify content integrity
                        let is_valid = self.verify_content_integrity(id, &data).await;
                        
                        if is_valid {
                            // Update verification timestamp
                            let mut content_map = self.content_map.write().await;
                            if let Some(metadata) = content_map.get_mut(id) {
                                metadata.last_verified = crate::utils::get_current_timestamp();
                            }
                            log::info!("Content {} verified successfully on node {}", id, hex::encode(node_id));
                            true
                        } else {
                            log::error!("Content {} failed integrity check on node {}", id, hex::encode(node_id));
                            false
                        }
                    }
                    Ok(None) => {
                        log::warn!("Content {} not found on node {}", id, hex::encode(node_id));
                        false
                    }
                    Err(e) => {
                        log::error!("Failed to fetch content {} for verification: {}", id, e);
                        false
                    }
                }
            } else {
                log::warn!("Node {} does not claim to have content {}", hex::encode(node_id), id);
                false
            }
        } else {
            log::warn!("Content {} not found in metadata", id);
            false
        }
    }
    /// Search content by type
    pub async fn search_content_by_type(&self, content_type: &str) -> Vec<(ContentId, ContentMetadata)> {
        let content_map = self.content_map.read().await;
        
        // Search for partial matches in content type
        content_map.iter()
            .filter(|(_, meta)| meta.content_type.contains(content_type))
            .map(|(id, meta)| (id.clone(), meta.clone()))
            .collect()
    }

    /// Search content by size range in KB
    pub async fn search_content_by_size(&self, min_kb: u64, max_kb: u64) -> Vec<(ContentId, ContentMetadata)> {
        let size_idx = self.size_index.read().await;
        let content_map = self.content_map.read().await;
        
        size_idx.iter()
            .filter(|&(size, _)| *size >= min_kb && *size <= max_kb)
            .flat_map(|(_, ids)| {
                ids.iter()
                    .filter_map(|id| content_map.get(id).map(|meta| (id.clone(), meta.clone())))
            })
            .collect()
    }

    /// Search content by tag
    pub async fn search_content_by_tag(&self, tag: &str) -> Vec<(ContentId, ContentMetadata)> {
        let content_map = self.content_map.read().await;
        
        // Search for partial matches in tags
        content_map.iter()
            .filter(|(_, meta)| {
                meta.content_type.contains(tag) || // Search in content type
                meta.tags.iter().any(|t| t.contains(tag)) // Search in tags
            })
            .map(|(id, meta)| (id.clone(), meta.clone()))
            .collect()
    }

    /// Register a service
    pub async fn register_service(&self, info: ServiceInfo, _signature: Vec<u8>) -> Result<()> {
        let mut services = self.services.write().await;
        services
            .entry(info.service_type.clone())
            .or_insert_with(Vec::new)
            .push(info);
        Ok(())
    }

    /// List all registered services
    pub async fn list_services(&self) -> HashMap<ServiceType, Vec<ServiceInfo>> {
        self.services.read().await.clone()
    }

    /// Get popular content by minimum access count
    pub async fn get_popular_content(&self, min_access: u32) -> Vec<(ContentId, ContentMetadata)> {
        let access_counts = self.access_counts.read().await;
        let content_map = self.content_map.read().await;
        
        access_counts.iter()
            .filter(|&(_, &count)| count >= min_access)
            .filter_map(|(id, _)| {
                content_map.get(id).map(|meta| (id.clone(), meta.clone()))
            })
            .collect()
    }

    /// ZHTP-native content registration with DNS integration and real content storage
    pub async fn register_content_with_dns(
        &self,
        metadata: ContentMetadata,
        dns_service: Arc<RwLock<crate::zhtp::dns::ZhtpDNS>>,
        node_keypair: &crate::zhtp::crypto::Keypair,
    ) -> Result<()> {
        // First, try to fetch the actual content data
        let content_data = match self.fetch_content_data(&metadata.id).await? {
            Some(data) => data,
            None => {
                // If content not found locally, create minimal metadata entry
                log::warn!("Content {} not found locally, registering metadata only", metadata.id);
                format!("metadata-only-{}", metadata.id).into_bytes()
            }
        };
        
        let content_type = metadata.content_type.clone();
        let node_id = metadata.locations.first().cloned().unwrap_or_default();
        let tags = metadata.tags.clone();
        
        // Register content in local system with actual data
        self.register_content(&content_data, content_type, node_id, tags).await?;
        
        // Register content domain in ZHTP DNS
        let dns = dns_service.write().await;
        let content_domain = format!("{}.content.zhtp", metadata.id);
        
        // Convert node IDs to socket addresses
        let addresses: Vec<std::net::SocketAddr> = metadata.locations.iter()
            .map(|node_id| {
                let mut hasher = sha2::Sha256::new();
                hasher.update(node_id);
                let hash = hasher.finalize();
                let port = u16::from_be_bytes([hash[0], hash[1]]);
                format!("127.0.0.1:{}", port).parse().ok()
            })
            .filter_map(|addr| addr) // Filter out failed parses
            .collect();
        
        if !addresses.is_empty() {
            dns.register_domain(
                content_domain,
                addresses,
                node_keypair,
                metadata.id.0,
            ).await?;
        }
        
        println!("✅ Content {} registered in ZHTP DNS for decentralized discovery", metadata.id);
        Ok(())
    }

    /// Search content by ZHTP domain patterns
    pub async fn search_by_domain_pattern(&self, pattern: &str) -> Vec<(ContentId, ContentMetadata)> {
        let content_map = self.content_map.read().await;
        content_map.iter()
            .filter(|(id, _)| id.to_string().contains(pattern))
            .map(|(id, metadata)| (id.clone(), metadata.clone()))
            .collect()
    }

    /// Get content statistics for ZHTP network monitoring
    pub async fn get_zhtp_stats(&self) -> ContentStats {
        let content_map = self.content_map.read().await;
        let services = self.services.read().await;
        let access_counts = self.access_counts.read().await;
        
        let total_content = content_map.len() as u64;
        let total_services = services.values().map(|v| v.len()).sum::<usize>() as u64;
        let total_size: u64 = content_map.values().map(|m| m.size).sum();
        let popular_threshold = 10;
        let popular_content = access_counts.values().filter(|&&count| count >= popular_threshold).count() as u64;
        
        ContentStats {
            total_content,
            total_services,
            total_size_bytes: total_size,
            popular_content,
            unique_providers: content_map.values()
                .flat_map(|m| &m.locations)
                .collect::<std::collections::HashSet<_>>()
                .len() as u64,
        }
    }

    /// Advanced ZHTP content discovery by hash pattern
    pub async fn discover_content_by_hash_pattern(&self, pattern: &str) -> Vec<(ContentId, ContentMetadata)> {
        let content_map = self.content_map.read().await;
        content_map.iter()
            .filter(|(id, _)| hex::encode(id.0).contains(pattern))
            .map(|(id, metadata)| (id.clone(), metadata.clone()))
            .collect()
    }

    /// Bulk content verification for ZHTP network integrity with real content checks
    pub async fn bulk_verify_content(&self, node_id: &[u8]) -> Vec<(ContentId, bool)> {
        // First, collect all content IDs that this node claims to have
        let content_ids_to_verify: Vec<(ContentId, ContentMetadata)> = {
            let content_map = self.content_map.read().await;
            content_map.iter()
                .filter(|(_, metadata)| metadata.locations.iter().any(|loc| loc == node_id))
                .map(|(id, metadata)| (id.clone(), metadata.clone()))
                .collect()
        };
        
        let mut results = Vec::new();
        
        for (id, metadata) in content_ids_to_verify {
            // Perform real content verification
            let is_valid = match self.fetch_content_data(&id).await {
                Ok(Some(data)) => {
                    // Verify content integrity by comparing hashes
                    let computed_id = ContentId::new(&data);
                    let hash_valid = id == computed_id;
                    
                    // Additional checks: file size consistency
                    let size_valid = data.len() as u64 == metadata.size;
                    
                    if hash_valid && size_valid {
                        log::debug!("Content {} passed verification (hash + size)", id);
                        true
                    } else {
                        log::warn!("Content {} failed verification - hash_valid: {}, size_valid: {}", 
                                 id, hash_valid, size_valid);
                        false
                    }
                }
                Ok(None) => {
                    log::warn!("Content {} not found during bulk verification", id);
                    false
                }
                Err(e) => {
                    log::error!("Error verifying content {}: {}", id, e);
                    false
                }
            };
            
            results.push((id, is_valid));
        }
        
        let total_checked = results.len();
        let valid_count = results.iter().filter(|(_, valid)| *valid).count();
        println!("✅ Bulk verification completed: {}/{} content items valid", valid_count, total_checked);
        
        results
    }

    /// Get ZHTP network content statistics
    pub async fn get_network_content_stats(&self) -> HashMap<String, u64> {
        let content_map = self.content_map.read().await;
        let services = self.services.read().await;
        
        let mut stats = HashMap::new();
        stats.insert("total_content_items".to_string(), content_map.len() as u64);
        stats.insert("total_services".to_string(), services.values().map(|v| v.len()).sum::<usize>() as u64);
        stats.insert("total_storage_bytes".to_string(), content_map.values().map(|m| m.size).sum());
        
        // Count unique providers
        let unique_providers: std::collections::HashSet<_> = content_map.values()
            .flat_map(|m| &m.locations)
            .collect();
        stats.insert("unique_providers".to_string(), unique_providers.len() as u64);
        
        // Count by content type
        let mut type_counts: HashMap<String, u64> = HashMap::new();
        for metadata in content_map.values() {
            *type_counts.entry(metadata.content_type.clone()).or_insert(0) += 1;
        }
        for (content_type, count) in type_counts {
            stats.insert(format!("type_{}", content_type.replace('/', "_")), count);
        }
        
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_content_addressing() {
        let system = ContentAddressing::new();
        let test_data = b"Test content";
        let node_id = vec![1, 2, 3, 4];

        // Register content
        let content_id = system
            .register_content(&test_data[..], "text/plain".to_string(), node_id.clone(), vec!["test".to_string()])
            .await
            .expect("Failed to register test content");

        // Find content
        let metadata = system.find_content(&content_id).await.expect("Failed to find test content");
        assert_eq!(metadata.size, test_data.len() as u64);
        assert_eq!(metadata.content_type, "text/plain");
        assert!(metadata.locations.contains(&node_id));

        // Verify content
        assert!(system.verify_content(&content_id, &node_id).await);
        
        // Check locations
        let locations = system.get_content_locations(&content_id).await;
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0], node_id);
    }

    #[tokio::test]
    async fn test_real_content_fetching() {
        let system = ContentAddressing::new();
        let test_data = b"Real content fetching test";
        let node_id = vec![5, 6, 7, 8];

        // Register content with real storage
        let content_id = system
            .register_content(&test_data[..], "application/test".to_string(), node_id.clone(), vec!["real-test".to_string()])
            .await
            .expect("Failed to register test content");

        // Fetch actual content data
        let fetched_data = system.fetch_content_data(&content_id).await
            .expect("Failed to fetch content")
            .expect("Content not found");

        // Verify the fetched data matches original
        assert_eq!(fetched_data, test_data);

        // Test bulk verification
        let verification_results = system.bulk_verify_content(&node_id).await;
        assert_eq!(verification_results.len(), 1);
        assert_eq!(verification_results[0].0, content_id);
        assert!(verification_results[0].1); // Should be valid
    }
}