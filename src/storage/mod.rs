pub mod dht;
pub mod content;

pub use dht::{DhtNode, DhtNetwork};
pub use content::{ContentAddressing, ContentId, ContentMetadata};

use crate::zhtp::{dns::ZhtpDNS, crypto::Keypair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

/// ZHTP-native storage system configuration
#[derive(Debug)]
pub struct StorageConfig {
    /// Number of replicas for each piece of data across ZHTP network
    pub replication_factor: usize,
    /// Minimum number of ZK proofs required for verification
    pub min_proofs: usize,
    /// Maximum storage per node (in bytes)
    pub max_node_storage: u64,
    /// ZHTP DNS integration for content discovery
    pub dns_enabled: bool,
    /// Automatic content registration in ZHTP DNS
    pub auto_dns_registration: bool,
    /// Zero-knowledge proof requirements
    pub require_zk_proofs: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            min_proofs: 2,
            max_node_storage: 1024 * 1024 * 1024, // 1GB default
            dns_enabled: true,
            auto_dns_registration: true,
            require_zk_proofs: true,
        }
    }
}

/// ZHTP-native storage manager that integrates with DNS and networking
#[derive(Debug)]
pub struct ZhtpStorageManager {
    /// DHT network for distributed storage
    dht_network: Arc<DhtNetwork>,
    /// Content addressing system
    content_system: Arc<ContentAddressing>,
    /// ZHTP DNS for content discovery
    dns_service: Arc<RwLock<ZhtpDNS>>,
    /// Storage configuration
    config: StorageConfig,
    /// Node keypair for authentication
    node_keypair: Keypair,
}

impl ZhtpStorageManager {
    /// Create new ZHTP storage manager
    pub async fn new(
        dns_service: Arc<RwLock<ZhtpDNS>>,
        config: StorageConfig,
        node_keypair: Keypair,
    ) -> Self {
        let dht_network = Arc::new(DhtNetwork::new());
        let content_system = Arc::new(ContentAddressing::new());
        
        Self {
            dht_network,
            content_system,
            dns_service,
            config,
            node_keypair,
        }
    }

    /// Initialize DHT network and register with DNS
    pub async fn initialize_network(&self) -> anyhow::Result<()> {
        // Generate a shorter, hash-based node ID from keypair (compatible with DHT 64-char limit)
        let public_key_bytes = self.node_keypair.public_key();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, &public_key_bytes);
        let node_hash = std::hash::Hasher::finish(&hasher);
        let node_id = format!("zhtp-{:016x}", node_hash); // 21 chars total, well under 64 limit
        
        // Register this node in the DHT network with default storage capacity
        let default_capacity = self.config.max_node_storage;
        let registration_success = self.dht_network.register_node(node_id.clone(), default_capacity).await;
        
        if !registration_success {
            anyhow::bail!("Failed to register node {} in DHT network", node_id);
        }

        // Register node with ZHTP DNS for network discovery
        if self.config.dns_enabled {
            let dns = self.dns_service.write().await;
            
            // Create node domain for DNS registration
            let node_domain = format!("{}.node.zhtp", node_id);
            
            // Generate socket address for this node
            let mut hasher = Sha256::new();
            hasher.update(self.node_keypair.public_key());
            let hash = hasher.finalize();
            let port = u16::from_be_bytes([hash[0], hash[1]]);
            let node_addr = format!("127.0.0.1:{}", port).parse()?;
            
            // Register node domain in ZHTP DNS
            dns.register_domain(
                node_domain,
                vec![node_addr],
                &self.node_keypair,
                hash.into(),
            ).await?;
            
            println!("✅ Node {} registered in ZHTP DNS for network discovery", node_id);
        }

        println!("✅ ZHTP Storage Manager initialized - DHT network registration complete");
        println!("   Node ID: {}", node_id);
        println!("   Storage Capacity: {} bytes", default_capacity);
        println!("   DNS Registration: {}", if self.config.dns_enabled { "Enabled" } else { "Disabled" });
        
        Ok(())
    }

    /// Join an existing DHT network using bootstrap nodes
    pub async fn join_network(&self, bootstrap_nodes: Vec<String>) -> anyhow::Result<()> {
        // First ensure this node is initialized
        if !self.is_network_initialized().await {
            self.initialize_network().await?;
        }

        let node_id = hex::encode(self.node_keypair.public_key());
        let mut successful_connections = 0;

        // Attempt to connect to bootstrap nodes
        for bootstrap_node in bootstrap_nodes {
            // In a real implementation, this would:
            // 1. Parse the bootstrap node address
            // 2. Establish a connection using ZHTP protocols
            // 3. Exchange peer lists and routing information
            // 4. Update the local routing table
            
            // For now, we'll simulate the connection by registering bootstrap nodes
            if self.dht_network.register_node(bootstrap_node.clone(), self.config.max_node_storage).await {
                successful_connections += 1;
                println!("✅ Connected to bootstrap node: {}", bootstrap_node);
            } else {
                println!("⚠️ Failed to connect to bootstrap node: {}", bootstrap_node);
            }
        }

        if successful_connections == 0 {
            anyhow::bail!("Failed to connect to any bootstrap nodes");
        }

        println!("✅ Successfully joined DHT network - connected to {} bootstrap nodes", successful_connections);
        println!("   Node ID: {}", node_id);
        println!("   Total network nodes: {}", self.dht_network.get_node_count().await);
        
        Ok(())
    }

    /// Check if the node is properly registered in the DHT network
    pub async fn is_network_initialized(&self) -> bool {
        let node_id = hex::encode(self.node_keypair.public_key());
        self.dht_network.is_node_registered(&node_id).await
    }

    /// Get network status and peer information
    pub async fn get_network_status(&self) -> anyhow::Result<NetworkStatus> {
        let node_id = hex::encode(self.node_keypair.public_key());
        
        let is_registered = self.dht_network.is_node_registered(&node_id).await;
        let total_nodes = self.dht_network.get_node_count().await;
        let peer_count = self.dht_network.get_node_peer_count(&node_id).await;
        let available_capacity = self.dht_network.get_node_storage_capacity(&node_id).await.unwrap_or(0);
        
        Ok(NetworkStatus {
            node_id,
            is_registered,
            peer_count,
            total_network_nodes: total_nodes,
            available_storage_capacity: available_capacity,
            dns_enabled: self.config.dns_enabled,
        })
    }

    /// Store content and register in ZHTP DNS
    pub async fn store_content(
        &self,
        domain: String,
        data: Vec<u8>,
        content_type: String,
    ) -> anyhow::Result<ContentId> {
        // Store in DHT network with proper parameters
        let node_id = hex::encode(self.node_keypair.public_key());
        let content_id = self.dht_network.store_content(
            data.clone(),
            content_type.clone(),
            &node_id,
            Some(vec![domain.clone()]),
        ).await?;

        // Register in ZHTP DNS if enabled
        if self.config.auto_dns_registration {
            self.register_content_in_dns(domain, content_id.clone(), content_type).await?;
        }

        println!("✅ Content stored with ID: {} and registered in ZHTP DNS", content_id);
        Ok(content_id)
    }

    /// Store content with full ZHTP integration
    pub async fn store_content_with_metadata(
        &self,
        _domain: String,
        data: Vec<u8>,
        content_type: String,
        tags: Vec<String>,
    ) -> anyhow::Result<ContentId> {
        // Store in DHT network
        let node_id = hex::encode(self.node_keypair.public_key());
        let content_id = self.dht_network.store_content(
            data.clone(),
            content_type.clone(),
            &node_id,
            Some(tags.clone()),
        ).await?;

        // Create enhanced metadata
        let metadata = ContentMetadata {
            id: content_id.clone(),
            size: data.len() as u64,
            content_type: content_type.clone(),
            locations: vec![self.node_keypair.public_key().to_vec()],
            last_verified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            tags,
        };

        // Register with DNS integration
        if self.config.auto_dns_registration {
            self.content_system.register_content_with_dns(
                metadata,
                self.dns_service.clone(),
                &self.node_keypair,
            ).await?;
        }

        println!("✅ Content stored with metadata and registered in ZHTP network: {}", content_id);
        Ok(content_id)
    }

    /// Register content in ZHTP DNS for discovery
    async fn register_content_in_dns(
        &self,
        domain: String,
        content_id: ContentId,
        _content_type: String,
    ) -> anyhow::Result<()> {
        let dns = self.dns_service.write().await;
        
        // Create content-specific subdomain
        let content_domain = format!("{}.content.zhtp", domain);
        
        // Get storage locations from content system
        let locations = self.content_system.get_content_locations(&content_id).await;
        
        // Convert node IDs to socket addresses for DNS registration
        let mut socket_addrs = vec![];
        for node_id in locations {
            let mut hasher = Sha256::new();
            hasher.update(&node_id);
            let hash = hasher.finalize();
            let port = u16::from_be_bytes([hash[0], hash[1]]);
            let addr = format!("127.0.0.1:{}", port).parse()?;
            socket_addrs.push(addr);
        }

        // Register content domain with storage locations
        let content_hash = content_id.0;
        dns.register_domain(
            content_domain,
            socket_addrs,
            &self.node_keypair,
            content_hash,
        ).await?;

        println!("✅ Content {} registered in ZHTP DNS for decentralized discovery", content_id);
        Ok(())
    }

    /// Retrieve content by domain or content ID
    pub async fn get_content(&self, identifier: &str) -> anyhow::Result<Option<Vec<u8>>> {
        // Check if it's a domain or content ID
        if identifier.contains(".zhtp") {
            // Domain lookup via DNS
            self.get_content_by_domain(identifier).await
        } else {
            // Direct content ID lookup
            let content_id = ContentId::from(identifier.to_string());
            match self.dht_network.find_content(&content_id).await {
                Some((_, data)) => Ok(Some(data)),
                None => Ok(None),
            }
        }
    }

    /// Get content via ZHTP DNS domain lookup
    async fn get_content_by_domain(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
        use crate::zhtp::dns::{DnsQuery, QueryType};
        
        let dns = self.dns_service.read().await;
        
        // Create DNS query for the domain
        let query = DnsQuery {
            domain: domain.to_string(),
            query_type: QueryType::A,
            recursive: true,
        };

        // Resolve domain to get storage locations
        match dns.resolve(query).await {
            Ok(response) => {
                // Try to retrieve content from any of the addresses
                for addr in response.addresses {
                    if let Some(content) = self.dht_network.get_content_from_address(&addr).await {
                        return Ok(Some(content));
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    /// Search for content by type
    pub async fn search_by_type(&self, content_type: &str) -> Vec<(ContentId, ContentMetadata)> {
        self.content_system.search_content_by_type(content_type).await
    }

    /// Search for content by tags
    pub async fn search_by_tag(&self, tag: &str) -> Vec<(ContentId, ContentMetadata)> {
        self.content_system.search_content_by_tag(tag).await
    }

    /// Advanced ZHTP content search with DNS resolution
    pub async fn advanced_content_search(&self, query: &str) -> anyhow::Result<Vec<(ContentId, ContentMetadata)>> {
        // Search by tag first
        let mut results = self.search_by_tag(query).await;
        
        // Search by content type if no tag results
        if results.is_empty() {
            results = self.search_by_type(query).await;
        }
        
        // Search by domain pattern if still no results
        if results.is_empty() {
            results = self.content_system.discover_content_by_hash_pattern(query).await;
        }
        
        println!("✅ Advanced search for '{}' returned {} results", query, results.len());
        Ok(results)
    }

    /// Bulk content verification across the ZHTP network
    pub async fn verify_network_integrity(&self) -> anyhow::Result<Vec<(ContentId, bool)>> {
        let node_id = self.node_keypair.public_key().to_vec();
        let results = self.content_system.bulk_verify_content(&node_id).await;
        
        // Get detailed network statistics
        let network_stats = self.content_system.get_network_content_stats().await;
        println!("📊 Network integrity check complete:");
        for (key, value) in &network_stats {
            println!("   {}: {}", key, value);
        }
        
        Ok(results)
    }

    /// Content replication management for ZHTP resilience
    pub async fn manage_content_replication(&self, content_id: &ContentId, target_replicas: usize) -> anyhow::Result<()> {
        let current_locations = self.content_system.get_content_locations(content_id).await;
        
        if current_locations.len() < target_replicas {
            println!("📈 Content {} needs more replicas: {} < {}", content_id, current_locations.len(), target_replicas);
            
            // Step 1: Find available nodes with capacity
            let needed_replicas = target_replicas - current_locations.len();
            let available_nodes = self.find_available_nodes_with_capacity(content_id, needed_replicas).await?;
            
            if available_nodes.is_empty() {
                anyhow::bail!("No nodes available with sufficient capacity for replication");
            }
            
            // Step 2: Transfer content to new nodes
            let replication_results = self.transfer_content_to_nodes(content_id, &available_nodes).await?;
            
            // Step 3: Update DNS records with new locations
            self.update_dns_with_new_locations(content_id, &replication_results).await?;
            
            // Step 4: Verify replication success
            let verification_results = self.verify_replication_success(content_id, &replication_results).await?;
            
            // Log results
            let successful_replicas = verification_results.iter().filter(|(_, success)| *success).count();
            println!("✅ Replication completed: {}/{} new replicas successful", successful_replicas, needed_replicas);
            
            if successful_replicas < needed_replicas {
                println!("⚠️ Warning: Only {}/{} replicas were successfully created", successful_replicas, needed_replicas);
            }
        } else {
            println!("✅ Content {} has sufficient replicas: {}", content_id, current_locations.len());
        }
        
        Ok(())
    }

    /// Find available nodes with sufficient storage capacity
    async fn find_available_nodes_with_capacity(&self, content_id: &ContentId, needed_count: usize) -> anyhow::Result<Vec<NodeReplicationInfo>> {
        println!("🔍 Finding {} nodes with available capacity...", needed_count);
        
        let current_locations = self.content_system.get_content_locations(content_id).await;
        let current_node_ids: std::collections::HashSet<String> = current_locations.iter()
            .map(hex::encode)
            .collect();
        
        // Get content size to determine storage requirements
        let content_size = match self.dht_network.find_content(content_id).await {
            Some((metadata, data)) => {
                std::cmp::max(data.len() as u64, metadata.size)
            }
            None => {
                anyhow::bail!("Content not found for replication");
            }
        };
        
        // Query all network nodes for capacity
        let all_nodes = self.dht_network.get_all_network_nodes().await;
        let mut available_nodes = Vec::new();
        
        for node_id in all_nodes {
            // Skip nodes that already have the content
            if current_node_ids.contains(&node_id) {
                continue;
            }
            
            // Check node capacity
            let available_capacity = self.dht_network.get_node_storage_capacity(&node_id).await.unwrap_or(0);
            let node_reliability = self.dht_network.get_node_reliability_score(&node_id).await.unwrap_or(0.5);
            
            if available_capacity >= content_size && node_reliability > 0.6 {
                let node_addr = self.get_node_network_address(&node_id).await?;
                
                available_nodes.push(NodeReplicationInfo {
                    node_id: node_id.clone(),
                    network_address: node_addr,
                    available_capacity,
                    reliability_score: node_reliability,
                    estimated_transfer_time: self.estimate_transfer_time(&node_id, content_size).await,
                });
            }
        }
        
        // Sort by reliability and transfer time
        available_nodes.sort_by(|a, b| {
            let a_score = a.reliability_score - (a.estimated_transfer_time.as_secs() as f64 / 100.0);
            let b_score = b.reliability_score - (b.estimated_transfer_time.as_secs() as f64 / 100.0);
            b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Take the best nodes up to needed count
        available_nodes.truncate(needed_count);
        
        println!("✅ Found {} suitable nodes for replication", available_nodes.len());
        for node in &available_nodes {
            println!("   Node {}: reliability={:.3}, capacity={}MB", 
                    node.node_id, node.reliability_score, node.available_capacity / 1024 / 1024);
        }
        
        Ok(available_nodes)
    }

    /// Transfer content to selected nodes
    async fn transfer_content_to_nodes(&self, content_id: &ContentId, target_nodes: &[NodeReplicationInfo]) -> anyhow::Result<Vec<ReplicationResult>> {
        println!("📤 Transferring content {} to {} nodes...", content_id, target_nodes.len());
        
        // Get the content data and metadata
        let (metadata, content_data) = match self.dht_network.find_content(content_id).await {
            Some(data) => data,
            None => anyhow::bail!("Content not found for transfer"),
        };
        
        let mut replication_results = Vec::new();
        let mut successful_transfers = 0;
        
        // Transfer to each node
        for node_info in target_nodes {
            println!("📤 Transferring to node {}...", node_info.node_id);
            
            let transfer_start = std::time::Instant::now();
            
            // Perform the actual content transfer
            let transfer_result = self.perform_content_transfer(
                &node_info.node_id,
                &node_info.network_address,
                content_id,
                &content_data,
                &metadata,
            ).await;
            
            let transfer_duration = transfer_start.elapsed();
            
            match transfer_result {
                Ok(transfer_hash) => {
                    successful_transfers += 1;
                    println!("✅ Transfer to {} completed in {:?}", node_info.node_id, transfer_duration);
                    
                    replication_results.push(ReplicationResult {
                        node_id: node_info.node_id.clone(),
                        network_address: node_info.network_address,
                        transfer_success: true,
                        transfer_hash: Some(transfer_hash),
                        transfer_duration,
                        error_message: None,
                    });
                }
                Err(e) => {
                    println!("❌ Transfer to {} failed: {}", node_info.node_id, e);
                    
                    replication_results.push(ReplicationResult {
                        node_id: node_info.node_id.clone(),
                        network_address: node_info.network_address,
                        transfer_success: false,
                        transfer_hash: None,
                        transfer_duration,
                        error_message: Some(e.to_string()),
                    });
                }
            }
        }
        
        println!("📊 Transfer complete: {}/{} successful", successful_transfers, target_nodes.len());
        Ok(replication_results)
    }

    /// Update DNS records with new content locations
    async fn update_dns_with_new_locations(&self, content_id: &ContentId, replication_results: &[ReplicationResult]) -> anyhow::Result<()> {
        if !self.config.dns_enabled {
            println!("ℹ️ DNS updates skipped (DNS not enabled)");
            return Ok(());
        }
        
        println!("🌐 Updating DNS records with new content locations...");
        
        let successful_replications: Vec<_> = replication_results.iter()
            .filter(|r| r.transfer_success)
            .collect();
        
        if successful_replications.is_empty() {
            println!("⚠️ No successful replications to update in DNS");
            return Ok(());
        }
        
        let dns = self.dns_service.write().await;
        
        // Find existing DNS entries for this content
        let content_domain = format!("{}.content.zhtp", content_id);
        let existing_addresses = dns.resolve_domain_addresses(&content_domain).await.unwrap_or_default();
        
        // Add new addresses from successful replications
        let mut updated_addresses = existing_addresses;
        for replication in &successful_replications {
            if !updated_addresses.contains(&replication.network_address) {
                updated_addresses.push(replication.network_address);
            }
        }
        
        // Update DNS record with all locations
        let content_hash = content_id.0;
        dns.update_domain_addresses(
            content_domain.clone(),
            updated_addresses.clone(),
            &self.node_keypair,
        ).await?;
        
        println!("✅ DNS updated: {} now resolves to {} locations", content_domain, updated_addresses.len());
        
        // Also update individual node records
        for replication in &successful_replications {
            let node_domain = format!("{}.node.zhtp", replication.node_id);
            dns.register_domain(
                node_domain,
                vec![replication.network_address],
                &self.node_keypair,
                content_hash,
            ).await?;
        }
        
        println!("✅ Individual node DNS records updated for {} new replications", successful_replications.len());
        Ok(())
    }

    /// Verify replication success by checking content integrity
    async fn verify_replication_success(&self, content_id: &ContentId, replication_results: &[ReplicationResult]) -> anyhow::Result<Vec<(String, bool)>> {
        println!("🔍 Verifying replication integrity for {} replicas...", replication_results.len());
        
        let successful_replications: Vec<_> = replication_results.iter()
            .filter(|r| r.transfer_success)
            .collect();
        
        if successful_replications.is_empty() {
            return Ok(vec![]);
        }
        
        // Get original content hash for verification
        let original_hash = match self.dht_network.find_content(content_id).await {
            Some((_, data)) => {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                hex::encode(hasher.finalize())
            }
            None => anyhow::bail!("Original content not found for verification"),
        };
        
        let mut verification_results = Vec::new();
        
        // Verify each successful replication
        for replication in &successful_replications {
            println!("🔍 Verifying content on node {}...", replication.node_id);
            
            let verification_result = self.verify_node_content_integrity(
                &replication.node_id,
                &replication.network_address,
                content_id,
                &original_hash,
            ).await;
            
            match verification_result {
                Ok(is_valid) => {
                    if is_valid {
                        println!("✅ Content integrity verified on node {}", replication.node_id);
                    } else {
                        println!("❌ Content integrity check failed on node {}", replication.node_id);
                    }
                    verification_results.push((replication.node_id.clone(), is_valid));
                }
                Err(e) => {
                    println!("⚠️ Verification error for node {}: {}", replication.node_id, e);
                    verification_results.push((replication.node_id.clone(), false));
                }
            }
        }
        
        let successful_verifications = verification_results.iter().filter(|(_, success)| *success).count();
        println!("📊 Verification complete: {}/{} replicas verified successfully", 
                successful_verifications, verification_results.len());
        
        Ok(verification_results)
    }

    /// Helper: Get network address for a node
    async fn get_node_network_address(&self, node_id: &str) -> anyhow::Result<std::net::SocketAddr> {
        // Generate deterministic address from node ID
        let mut hasher = Sha256::new();
        hasher.update(node_id.as_bytes());
        let hash = hasher.finalize();
        let port = u16::from_be_bytes([hash[0], hash[1]]) % 10000 + 20000; // Port range 20000-30000
        Ok(format!("127.0.0.1:{}", port).parse()?)
    }

    /// Helper: Estimate transfer time for a node
    async fn estimate_transfer_time(&self, _node_id: &str, content_size: u64) -> std::time::Duration {
        // Simplified estimation: assume 10MB/s transfer rate
        let estimated_seconds = (content_size as f64 / (10.0 * 1024.0 * 1024.0)).max(1.0);
        std::time::Duration::from_secs(estimated_seconds as u64)
    }

    /// Helper: Perform actual content transfer to a node
    async fn perform_content_transfer(
        &self,
        node_id: &str,
        _node_address: &std::net::SocketAddr,
        content_id: &ContentId,
        content_data: &[u8],
        metadata: &ContentMetadata,
    ) -> anyhow::Result<String> {
        // In a real implementation, this would use ZHTP network protocols
        // For now, we'll simulate the transfer and register in DHT
        
        // Store content in the target node
        let stored_id = self.dht_network.store_content_on_node(
            node_id.to_string(),
            content_data.to_vec(),
            metadata.content_type.clone(),
            Some(metadata.tags.clone()),
        ).await?;
        
        // Verify the stored content ID matches
        if stored_id != *content_id {
            anyhow::bail!("Content ID mismatch after transfer: expected {}, got {}", content_id, stored_id);
        }
        
        // Generate transfer verification hash
        let mut hasher = Sha256::new();
        hasher.update(node_id.as_bytes());
        hasher.update(content_id.0);
        hasher.update(content_data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Helper: Verify content integrity on a specific node
    async fn verify_node_content_integrity(
        &self,
        node_id: &str,
        _node_address: &std::net::SocketAddr,
        content_id: &ContentId,
        expected_hash: &str,
    ) -> anyhow::Result<bool> {
        // Retrieve content from the specific node
        match self.dht_network.get_content_from_node(node_id, content_id).await {
            Some(data) => {
                // Compute hash of retrieved content
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let computed_hash = hex::encode(hasher.finalize());
                
                Ok(computed_hash == expected_hash)
            }
            None => Ok(false),
        }
    }

    /// Get comprehensive storage system health metrics
    pub async fn get_comprehensive_health_metrics(&self) -> anyhow::Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        
        // Get basic storage stats
        let stats = self.get_stats().await?;
        metrics.insert("total_content_items".to_string(), stats.total_content_items as f64);
        metrics.insert("total_dns_domains".to_string(), stats.total_dns_domains as f64);
        metrics.insert("storage_nodes".to_string(), stats.storage_nodes as f64);
        
        // Calculate storage efficiency
        let network_stats = self.content_system.get_network_content_stats().await;
        let total_bytes = network_stats.get("total_storage_bytes").copied().unwrap_or(0) as f64;
        let unique_providers = network_stats.get("unique_providers").copied().unwrap_or(1) as f64;
        let storage_efficiency = if unique_providers > 0.0 { total_bytes / unique_providers } else { 0.0 };
        metrics.insert("storage_efficiency_bytes_per_node".to_string(), storage_efficiency);
        
        // Calculate replication factor
        let total_content = network_stats.get("total_content_items").copied().unwrap_or(1) as f64;
        let total_replicas = stats.total_content_items as f64; // Simplified calculation
        let avg_replication = if total_content > 0.0 { total_replicas / total_content } else { 0.0 };
        metrics.insert("average_replication_factor".to_string(), avg_replication);
        
        // Network health score (0-100)
        let health_score = if storage_efficiency > 0.0 && avg_replication > 1.0 {
            ((avg_replication * 20.0).min(80.0) + (unique_providers * 2.0).min(20.0)).min(100.0)
        } else {
            0.0
        };
        metrics.insert("network_health_score".to_string(), health_score);
        
        println!("📊 Comprehensive health metrics calculated - Network health: {:.1}%", health_score);
        Ok(metrics)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> anyhow::Result<StorageStats> {
        let dns_stats = self.dns_service.read().await.get_stats().await;
        let network_stats = self.content_system.get_network_content_stats().await;
        let content_count = network_stats.get("total_content_items").copied().unwrap_or(0);
        
        Ok(StorageStats {
            total_content_items: content_count,
            total_dns_domains: dns_stats.get("total_domains").copied().unwrap_or(0),
            storage_nodes: dns_stats.get("total_certificates").copied().unwrap_or(0),
            network_bandwidth: self.calculate_network_bandwidth().await,
        })
    }

    /// Calculate current network bandwidth usage across all storage operations
    async fn calculate_network_bandwidth(&self) -> u64 {
        // Calculate bandwidth based on active storage operations
        let content_stats = self.content_system.get_network_content_stats().await;
        let content_count = content_stats.get("total_content_items").copied().unwrap_or(0);
        
        // Estimate bandwidth usage based on content activity
        // Average content size (1MB) * content items * activity factor
        let estimated_content_bandwidth = content_count * 1024 * 1024; // 1MB per content item
        
        // Add DNS resolution bandwidth (typically much smaller)
        let dns_stats = self.dns_service.read().await.get_stats().await;
        let dns_queries = dns_stats.get("total_domains").copied().unwrap_or(0);
        let dns_bandwidth = dns_queries * 512; // 512 bytes per DNS query
        
        // Add certificate validation bandwidth
        let cert_operations = dns_stats.get("total_certificates").copied().unwrap_or(0);
        let cert_bandwidth = cert_operations * 2048; // 2KB per certificate
        
        // Total network bandwidth in bytes
        estimated_content_bandwidth + dns_bandwidth + cert_bandwidth
    }
}

/// Storage system statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_content_items: u64,
    pub total_dns_domains: u64,
    pub storage_nodes: u64,
    pub network_bandwidth: u64,
}

/// Network initialization and connection status
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    pub node_id: String,
    pub is_registered: bool,
    pub peer_count: usize,
    pub total_network_nodes: usize,
    pub available_storage_capacity: u64,
    pub dns_enabled: bool,
}

/// Node information for replication planning
#[derive(Debug, Clone)]
pub struct NodeReplicationInfo {
    pub node_id: String,
    pub network_address: std::net::SocketAddr,
    pub available_capacity: u64,
    pub reliability_score: f64,
    pub estimated_transfer_time: std::time::Duration,
}

/// Result of content replication to a node
#[derive(Debug, Clone)]
pub struct ReplicationResult {
    pub node_id: String,
    pub network_address: std::net::SocketAddr,
    pub transfer_success: bool,
    pub transfer_hash: Option<String>,
    pub transfer_duration: std::time::Duration,
    pub error_message: Option<String>,
}
