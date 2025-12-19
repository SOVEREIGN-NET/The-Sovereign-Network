//! Peer discovery implementation for bootstrap

use anyhow::{Result, anyhow};
use crate::types::node_address::NodeAddress;
use lib_crypto::PublicKey;
use lib_identity::{NodeId, ZhtpIdentity};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::peer_registry::{
    SharedPeerRegistry, PeerEntry, PeerEndpoint, ConnectionMetrics, 
    NodeCapabilities, DiscoveryMethod, PeerTier
};
use crate::identity::unified_peer::UnifiedPeerId;

// SECURITY FIX: Add dirs crate for secure data directory
use dirs;

// SECURITY FIX: Bootstrap connection rate limiter
// Prevents DoS attacks via rapid connection attempts
struct BootstrapRateLimiter {
    connection_attempts: HashMap<String, (u32, std::time::Instant)>, // IP -> (count, first_attempt_time)
    max_attempts: u32,
    time_window_secs: u64,
}

impl BootstrapRateLimiter {
    fn new(max_attempts: u32, time_window_secs: u64) -> Self {
        Self {
            connection_attempts: HashMap::new(),
            max_attempts,
            time_window_secs,
        }
    }
    
    fn check_rate_limit(&mut self, ip_address: &str) -> Result<()> {
        let now = std::time::Instant::now();
        
        // Clean up old entries
        self.connection_attempts.retain(|_, (_, first_time)| {
            now.duration_since(*first_time).as_secs() < self.time_window_secs * 2
        });
        
        // Check current IP's attempt count
        if let Some((count, first_time)) = self.connection_attempts.get_mut(ip_address) {
            if now.duration_since(*first_time).as_secs() < self.time_window_secs {
                // Within time window
                if *count >= self.max_attempts {
                    return Err(anyhow!(
                        "Rate limit exceeded: {} attempts from {} in {} seconds",
                        count, ip_address, self.time_window_secs
                    ));
                }
                *count += 1;
            } else {
                // New time window
                *count = 1;
                *first_time = now;
            }
        } else {
            // First attempt from this IP
            self.connection_attempts.insert(ip_address.to_string(), (1, now));
        }
        
        Ok(())
    }
}

/// Discover peers through bootstrap process
/// 
/// **MIGRATION (Ticket #150):** Now adds discovered peers directly to unified peer_registry
/// 
/// # Arguments
/// * `bootstrap_addresses` - List of bootstrap peer addresses to connect to
/// * `local_identity` - Local identity for deriving NodeId and authentication
/// * `peer_registry` - Unified peer registry to add discovered peers
/// 
/// # Returns
/// Number of successfully discovered peers
/// 
/// # Security
/// - Implements rate limiting to prevent DoS attacks
/// - Validates all input addresses before connection attempts
/// - Uses secure nonce cache to prevent replay attacks
pub async fn discover_bootstrap_peers(
    bootstrap_addresses: &[String],
    local_identity: &ZhtpIdentity,
    peer_registry: crate::peer_registry::SharedPeerRegistry,
) -> Result<usize> {
    let mut discovered_count = 0;
    let mut failed_connections = Vec::new();

    // SECURITY FIX: Initialize rate limiter
    // Prevents DoS attacks via rapid connection attempts
    let rate_limiter = Arc::new(Mutex::new(BootstrapRateLimiter::new(5, 60))); // 5 attempts per minute per IP

    tracing::info!("Attempting to discover {} bootstrap peers", bootstrap_addresses.len());

    for address in bootstrap_addresses {
        // Extract IP address for rate limiting
        let ip_address = if let Ok(addr) = address.parse::<std::net::SocketAddr>() {
            addr.ip().to_string()
        } else {
            // If we can't parse the address yet, use the full address string
            address.clone()
        };
        
        // SECURITY FIX: Check rate limit before attempting connection
        {
            let mut limiter = rate_limiter.lock().await;
            if let Err(e) = limiter.check_rate_limit(&ip_address) {
                tracing::warn!("⚠️  Rate limit exceeded for {}: {}", address, e);
                failed_connections.push((address.clone(), e.to_string()));
                continue; // Skip this connection attempt
            }
        }
        
        match connect_to_bootstrap_peer(address, local_identity).await {
            Ok(peer_info) => {
                tracing::info!(
                    "✅ Successfully connected to bootstrap peer {} - NodeId: {}",
                    address,
                    peer_info.node_id.as_ref().map(|n| n.to_hex()).unwrap_or_else(|| "none".to_string())
                );
                // Ticket #150: Add peer directly to registry instead of collecting in Vec
                if let Err(e) = add_peer_to_registry(&peer_info, peer_registry.clone()).await {
                    tracing::warn!("Failed to add peer {} to registry: {}", address, e);
                } else {
                    discovered_count += 1;
                }
            }
            Err(e) => {
                tracing::warn!("❌ Failed to connect to bootstrap peer {}: {}", address, e);
                failed_connections.push((address.clone(), e.to_string()));
            }
        }
    }

    if discovered_count == 0 && !bootstrap_addresses.is_empty() {
        return Err(anyhow!(
            "Failed to connect to any bootstrap peers ({} attempted, {} failed): {:?}",
            bootstrap_addresses.len(),
            failed_connections.len(),
            failed_connections
        ));
    }

    tracing::info!(
        "Bootstrap discovery complete: {} successful, {} failed",
        discovered_count,
        failed_connections.len()
    );

    Ok(discovered_count)
}

/// Add a discovered peer to the unified peer registry
/// 
/// Converts PeerInfo from bootstrap discovery into PeerEntry format
/// and adds it to the registry with appropriate metadata.
/// 
/// **MIGRATION (Ticket #150):** Replaces the old pattern of accumulating
/// peers in a local Vec and returning them to callers. Now peers are
/// directly added to the registry so they're immediately visible to
/// DHT and mesh components.
/// 
/// # Arguments
/// * `peer_info` - Peer information from bootstrap handshake
/// * `peer_registry` - Shared registry to add the peer to
/// 
/// # Returns
/// Ok(()) if peer was successfully added to registry
async fn add_peer_to_registry(
    peer_info: &PeerInfo,
    peer_registry: SharedPeerRegistry,
) -> Result<()> {
    // Convert PeerInfo to UnifiedPeerId using legacy path
    // This creates an unverified "bootstrap mode" peer - appropriate for initial discovery
    // The peer can be verified later through the authentication handshake
    #[allow(deprecated)]
    let peer_id = UnifiedPeerId::from_public_key_legacy(peer_info.id.clone());

    // Convert addresses + protocols to PeerEndpoint list
    let endpoints: Vec<PeerEndpoint> = peer_info
        .addresses
        .iter()
        .map(|(protocol, address)| PeerEndpoint {
            address: NodeAddress::Domain(address.clone()),
            protocol: protocol.clone(),
            signal_strength: 1.0, // Bootstrap peers assumed to have good connectivity
            latency_ms: 50, // Default reasonable latency for bootstrap
        })
        .collect();

    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System time error: {}", e))?
        .as_secs();

    // Build ConnectionMetrics from PeerInfo data
    // SECURITY FIX: Use conservative estimates instead of hardcoded assumptions
    // Bootstrap peers should be verified before getting high scores
    let connection_metrics = ConnectionMetrics {
        signal_strength: 0.8, // Conservative estimate (was 1.0)
        bandwidth_capacity: peer_info.bandwidth_capacity,
        latency_ms: 100, // Conservative estimate (was 50)
        stability_score: 0.6, // Conservative estimate (was 0.8)
        connected_at: now,
    };

    // SECURITY FIX: Use conservative capability estimates
    // Bootstrap peers should be verified before getting high availability assumptions
    let capabilities = NodeCapabilities {
        protocols: peer_info.protocols.clone(),
        max_bandwidth: peer_info.bandwidth_capacity,
        available_bandwidth: (peer_info.bandwidth_capacity * 8) / 10, // 80% of max (conservative)
        routing_capacity: peer_info.compute_capacity as u32, // Convert u64 to u32
        energy_level: None, // Bootstrap nodes typically not battery-powered
        availability_percent: 85.0, // Conservative estimate (was 99.0)
    };

    // SECURITY FIX: Don't automatically trust bootstrap peers
    // Bootstrap peers should start with lower trust and be verified
    let initial_trust_score = 0.5; // Start with neutral trust, not 1.0
    let is_authenticated = false; // Require explicit authentication, don't assume
    
    // Create PeerEntry using constructor (struct has private fields)
    // **FIXED:** Use PeerEntry::new() instead of struct literal
    let peer_entry = PeerEntry::new(
        peer_id.clone(),               // peer_id
        endpoints,                      // endpoints
        peer_info.protocols.clone(),   // active_protocols
        connection_metrics,             // connection_metrics
        is_authenticated,               // authenticated (SECURITY FIX: false until verified)
        false,                          // quantum_secure (default for now)
        None,                           // next_hop (direct connection)
        1,                              // hop_count (direct connection)
        0.7,                            // route_quality (conservative estimate)
        capabilities,                   // capabilities
        None,                           // location (not typically known during bootstrap)
        0.7,                            // reliability_score (conservative estimate)
        None,                           // dht_info (will be populated later by DHT component)
        DiscoveryMethod::Bootstrap,     // discovery_method
        peer_info.last_seen,           // first_seen
        peer_info.last_seen,           // last_seen
        PeerTier::Tier3,               // tier (SECURITY FIX: Tier3 until verified, not Tier2)
        initial_trust_score,           // trust_score (SECURITY FIX: 0.5 until verified, not 1.0)
    );

    // Add to registry (upsert will update if already exists)
    let mut registry = peer_registry.write().await;
    registry.upsert(peer_entry).await?;
    
    tracing::debug!(
        "Added bootstrap peer {:?} to registry (DID: {}, device: {})",
        peer_id,
        peer_info.did,
        peer_info.device_name
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    
    /// Helper: Create test identity
    fn create_test_identity(device_name: &str) -> ZhtpIdentity {
        lib_identity::ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            device_name,
            None,
        ).unwrap()
    }
    
    /// Test bootstrap address validation
    #[tokio::test]
    async fn test_bootstrap_address_validation() {
        let identity = create_test_identity("test-device");
        
        // Test empty address
        let result = connect_to_bootstrap_peer("", &identity).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        
        // Test address with null byte
        let result = connect_to_bootstrap_peer("127.0.0.1\0:9333", &identity).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null byte"));
        
        // Test address with invalid characters
        let result = connect_to_bootstrap_peer("127.0.0.1;rm -rf /:9333", &identity).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid characters"));
        
        // Test address too long
        let long_address = "a".repeat(300);
        let result = connect_to_bootstrap_peer(&long_address, &identity).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }
    
    /// Test rate limiting
    #[tokio::test]
    async fn test_bootstrap_rate_limiting() {
        // This test would normally require mocking, but we can test the limiter directly
        let mut limiter = BootstrapRateLimiter::new(3, 60); // 3 attempts per 60 seconds
        
        // First 3 attempts should succeed
        assert!(limiter.check_rate_limit("192.168.1.1").is_ok());
        assert!(limiter.check_rate_limit("192.168.1.1").is_ok());
        assert!(limiter.check_rate_limit("192.168.1.1").is_ok());
        
        // 4th attempt should be rate limited
        let result = limiter.check_rate_limit("192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit exceeded"));
        
        // Different IP should not be rate limited
        assert!(limiter.check_rate_limit("192.168.1.2").is_ok());
    }
    
    /// Test peer registry integration with conservative trust
    #[tokio::test]
    async fn test_conservative_trust_scores() {
        let identity = create_test_identity("test-device");
        let registry = Arc::new(tokio::sync::RwLock::new(crate::peer_registry::PeerRegistry::new()));
        
        // Mock a peer info (this would normally come from a real connection)
        // Generate a keypair and use its public key
        let keypair = lib_crypto::KeyPair::generate().unwrap();
        let peer_public_key = keypair.public_key;
        let peer_node_id = NodeId::from_did_device("did:zhtp:test123", "test-device").unwrap();
        
        let peer_info = PeerInfo {
            id: peer_public_key,
            node_id: Some(peer_node_id),
            did: "did:zhtp:test123".to_string(),
            device_name: "test-device".to_string(),
            protocols: vec![crate::protocols::NetworkProtocol::TCP],
            addresses: [(
                crate::protocols::NetworkProtocol::TCP,
                "127.0.0.1:9333".to_string(),
            )]
            .iter()
            .cloned()
            .collect(),
            last_seen: 12345,
            reputation: 1.0, // This should be ignored in favor of conservative trust
            bandwidth_capacity: 1_000_000,
            storage_capacity: 1_000_000_000,
            compute_capacity: 100,
            connection_type: crate::protocols::NetworkProtocol::TCP,
        };
        
        // Add peer to registry
        add_peer_to_registry(&peer_info, registry.clone()).await.unwrap();

        // Verify conservative trust settings
        // Note: from_public_key_legacy creates a derived DID, not the original peer_info.did,
        // so we look up by public key instead
        let registry_read = registry.read().await;
        let peer_entry = registry_read.find_by_public_key(&peer_info.id);
        
        assert!(peer_entry.is_some());
        let entry = peer_entry.unwrap();
        
        // Verify conservative trust score (should be 0.5, not the peer_info.reputation of 1.0)
        assert_eq!(entry.trust_score, 0.5);
        
        // Verify not authenticated by default
        assert!(!entry.authenticated);
        
        // Verify conservative tier (should be Tier3, not Tier2)
        assert_eq!(entry.tier, crate::peer_registry::PeerTier::Tier3);
        
        // Verify conservative metrics
        assert_eq!(entry.connection_metrics.signal_strength, 0.8);
        assert_eq!(entry.connection_metrics.latency_ms, 100);
        assert_eq!(entry.connection_metrics.stability_score, 0.6);
    }
}

/// Connect to a bootstrap peer
/// 
/// # Arguments
/// * `address` - Bootstrap peer address to connect to
/// * `local_identity` - Local identity for deriving NodeId
/// 
/// # Returns
/// PeerInfo with identity-derived NodeId
/// 
/// # Security
/// - Validates address format before parsing
/// - Rejects addresses with null bytes or dangerous characters
/// - Validates IP/port format
async fn connect_to_bootstrap_peer(address: &str, local_identity: &ZhtpIdentity) -> Result<PeerInfo> {
    use tokio::net::TcpStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    // SECURITY FIX: Input validation for bootstrap address
    // Prevent injection attacks and malformed input
    if address.is_empty() {
        return Err(anyhow!("Bootstrap address cannot be empty"));
    }
    
    // Reject null bytes (security: prevent injection attacks)
    if address.contains('\0') {
        return Err(anyhow!("Bootstrap address contains null byte"));
    }
    
    // Reject potentially dangerous characters that could be used for injection
    // Allow only reasonable address characters: alphanumeric, . : [ ] - _
    if address.chars().any(|c| !c.is_ascii_alphanumeric() && !".:[]-_ ".contains(c)) {
        return Err(anyhow!("Bootstrap address contains invalid characters"));
    }
    
    // Maximum length check to prevent buffer overflows
    if address.len() > 256 {
        return Err(anyhow!("Bootstrap address too long (max 256 chars)"));
    }

    let addr: std::net::SocketAddr = address.parse()
        .map_err(|e| anyhow!("Invalid bootstrap address '{}': {}", address, e))?;

    let mut stream = TcpStream::connect(addr).await
        .map_err(|e| {
            tracing::warn!("Failed to connect to bootstrap peer {}: {}", address, e);
            anyhow!("Connection failed to {}: {}", address, e)
        })?;

    // SECURITY FIX: Use secure data directory for nonce cache
    // Prevents world-writable /tmp vulnerabilities
    let cache_dir = if let Some(data_dir) = dirs::data_dir() {
        data_dir.join("zhtp").join("bootstrap")
    } else {
        // Fallback to secure location if no standard data dir
        std::path::PathBuf::from("/var/lib/zhtp/bootstrap")
    };
    
    // Create directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        tracing::warn!("Failed to create secure cache directory: {}", e);
    } else {
        // Set secure permissions (read/write for owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)) {
                tracing::warn!("Failed to set secure permissions on cache directory: {}", e);
            }
        }
    }
    
    let cache_path = cache_dir.join("nonce_cache.db");
    
    // Use the standard open_default method for secure nonce cache
    let nonce_cache = crate::handshake::NonceCache::open_default(&cache_path, 300)
        .map_err(|e| {
            tracing::warn!("Failed to open secure nonce cache, bootstrap may be vulnerable to replay attacks: {}", e);
            anyhow!("Nonce cache initialization failed: {}", e)
        })?;
    
    let ctx = crate::handshake::HandshakeContext::new(nonce_cache);

    // Set up capabilities for bootstrap handshake
    // SECURITY: PQC enabled for post-quantum security (P1-2 fix)
    let capabilities = crate::handshake::HandshakeCapabilities {
        protocols: vec!["tcp".to_string(), "quic".to_string()],
        max_throughput: 10_000_000, // 10 MB/s
        max_message_size: 1024 * 1024, // 1 MB
        encryption_methods: vec!["chacha20-poly1305".to_string()],
        pqc_support: true, // Enable PQC for quantum resistance
        dht_capable: true,
        relay_capable: false,
        storage_capacity: 0,
        web4_capable: false,
        custom_features: vec![],
    };

    // Perform UHP authenticated handshake with bootstrap peer
    tracing::info!("Initiating UHP handshake with bootstrap peer {} (PQC enabled)", address);

    let result = crate::handshake::handshake_as_initiator(
        &mut stream,
        &ctx,
        local_identity,
        capabilities,
    ).await.map_err(|e| {
        tracing::error!("UHP handshake failed with bootstrap peer {}: {}", address, e);
        anyhow!("UHP handshake failed with {}: {}", address, e)
    })?;

    // Extract authenticated peer information from handshake result
    let peer_identity = &result.peer_identity;
    let peer_node_id = peer_identity.node_id.clone();
    let peer_did = peer_identity.did.clone();
    let peer_device = peer_identity.device_id.clone();
    let peer_public_key = peer_identity.public_key.clone();

    // Verify NodeId matches DID + device derivation
    let expected_node_id = NodeId::from_did_device(&peer_did, &peer_device)?;
    if peer_node_id.as_bytes() != expected_node_id.as_bytes() {
        return Err(anyhow!(
            "Bootstrap peer {} NodeId verification failed: claimed {} but expected {} from DID {} + device {}",
            address,
            peer_node_id.to_hex(),
            expected_node_id.to_hex(),
            peer_did,
            peer_device
        ));
    }

    let mut addresses = HashMap::new();
    addresses.insert(crate::protocols::NetworkProtocol::TCP, address.to_string());

    tracing::info!(
        "✅ Authenticated bootstrap peer {} - NodeId: {} (DID: {}, device: {})",
        address,
        peer_node_id.to_hex(),
        peer_did,
        peer_device
    );

    Ok(PeerInfo {
        id: peer_public_key,
        node_id: Some(peer_node_id),
        did: peer_did,
        device_name: peer_device,
        protocols: vec![crate::protocols::NetworkProtocol::TCP],
        addresses,
        last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        reputation: 1.0,
        bandwidth_capacity: 1_000_000,
        storage_capacity: 1_000_000_000,
        compute_capacity: 100,
        connection_type: crate::protocols::NetworkProtocol::TCP,
    })
}

/// Peer information structure with identity-based NodeId
/// 
/// Each peer is identified by:
/// - `id`: Cryptographic public key for verification
/// - `node_id`: Deterministically derived from DID + device name
/// - `did`: Decentralized identifier (did:zhtp:...)
/// - `device_name`: Device identifier used to derive NodeId
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: PublicKey,
    pub node_id: Option<NodeId>, // Identity-derived deterministic NodeId
    pub did: String, // Decentralized identifier
    pub device_name: String, // Device name for NodeId derivation
    pub protocols: Vec<crate::protocols::NetworkProtocol>,
    pub addresses: HashMap<crate::protocols::NetworkProtocol, String>,
    pub last_seen: u64,
    pub reputation: f64,
    pub bandwidth_capacity: u64,
    pub storage_capacity: u64,
    pub compute_capacity: u64,
    pub connection_type: crate::protocols::NetworkProtocol,
}

/// Validate that a peer's NodeId matches their DID + device derivation
/// 
/// # Arguments
/// * `peer_info` - Peer information to validate
/// 
/// # Returns
/// Ok(()) if NodeId is valid, Err if validation fails
/// 
/// # Example
/// ```ignore
/// let peer = discover_peer().await?;
/// validate_peer_node_id(&peer)?; // Ensures NodeId is properly derived
/// ```
pub fn validate_peer_node_id(peer_info: &PeerInfo) -> Result<()> {
    if let Some(claimed_node_id) = &peer_info.node_id {
        // Derive expected NodeId from DID + device
        let expected_node_id = NodeId::from_did_device(&peer_info.did, &peer_info.device_name)
            .map_err(|e| anyhow!("Failed to derive NodeId: {}", e))?;
        
        // Verify claimed NodeId matches derivation
        if claimed_node_id != &expected_node_id {
            return Err(anyhow!(
                "NodeId validation failed for peer {}:\n  Claimed:  {}\n  Expected: {} (from DID '{}' + device '{}')",
                hex::encode(&peer_info.id.as_bytes()[..8]),
                claimed_node_id.to_hex(),
                expected_node_id.to_hex(),
                peer_info.did,
                peer_info.device_name
            ));
        }
        
        tracing::debug!(
            "✓ Validated NodeId {} for peer {} (DID: {}, device: {})",
            claimed_node_id.to_hex(),
            hex::encode(&peer_info.id.as_bytes()[..8]),
            peer_info.did,
            peer_info.device_name
        );
    } else {
        return Err(anyhow!("Peer {} has no NodeId", hex::encode(&peer_info.id.as_bytes()[..8])));
    }
    
    Ok(())
}
