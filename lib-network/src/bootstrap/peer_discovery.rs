//! Peer discovery implementation for bootstrap

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use lib_identity::{NodeId, ZhtpIdentity, IdentityType, IdentityId};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::peer_registry::{
    SharedPeerRegistry, PeerEntry, PeerEndpoint, ConnectionMetrics, 
    NodeCapabilities, DiscoveryMethod, PeerTier
};
use crate::identity::unified_peer::UnifiedPeerId;

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
pub async fn discover_bootstrap_peers(
    bootstrap_addresses: &[String],
    local_identity: &ZhtpIdentity,
    peer_registry: crate::peer_registry::SharedPeerRegistry,
) -> Result<usize> {
    let mut discovered_count = 0;
    let mut failed_connections = Vec::new();

    tracing::info!("Attempting to discover {} bootstrap peers", bootstrap_addresses.len());

    for address in bootstrap_addresses {
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
    // Convert PeerInfo to ZhtpIdentity then to UnifiedPeerId
    let identity = ZhtpIdentity {
        id: IdentityId::new(), // Generate new identity ID
        identity_type: IdentityType::Device,
        did: peer_info.did.clone(),
        public_key: peer_info.id.clone(),
        node_id: peer_info.node_id.clone(),
        ..Default::default() // Set other fields to defaults
    };
    let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

    // Convert addresses + protocols to PeerEndpoint list
    let endpoints: Vec<PeerEndpoint> = peer_info
        .addresses
        .iter()
        .map(|(protocol, address)| PeerEndpoint {
            address: address.clone(),
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
    let connection_metrics = ConnectionMetrics {
        signal_strength: 1.0, // Bootstrap peers assumed reliable
        bandwidth_capacity: peer_info.bandwidth_capacity,
        latency_ms: 50, // Default for bootstrap
        stability_score: 0.8, // Bootstrap peers assumed stable
        connected_at: now,
    };

    // Build NodeCapabilities from PeerInfo
    let capabilities = NodeCapabilities {
        protocols: peer_info.protocols.clone(),
        max_bandwidth: peer_info.bandwidth_capacity,
        available_bandwidth: peer_info.bandwidth_capacity,
        routing_capacity: peer_info.compute_capacity,
        energy_level: None, // Bootstrap nodes typically not battery-powered
        availability_percent: 99.0, // Bootstrap nodes assumed highly available
    };

    // Create PeerEntry with all metadata
    let peer_entry = PeerEntry {
        peer_id: peer_id.clone(),
        
        // Connection metadata
        endpoints,
        active_protocols: peer_info.protocols.clone(),
        connection_metrics,
        authenticated: true, // Bootstrap handshake implies authentication
        quantum_secure: false, // Default for now
        
        // Routing metadata
        next_hop: None, // Direct connection to bootstrap peer
        hop_count: 1, // Direct connection
        route_quality: 0.9, // Bootstrap peers assumed high quality
        
        // Topology/capabilities
        capabilities,
        location: None, // Location not typically known during bootstrap
        reliability_score: 0.8, // Bootstrap peers assumed reliable
        
        // DHT metadata
        dht_info: None, // Will be populated later by DHT component
        
        // Discovery metadata
        discovery_method: DiscoveryMethod::Bootstrap,
        first_seen: peer_info.last_seen,
        last_seen: peer_info.last_seen,
        
        // Tiering and trust
        tier: PeerTier::Tier2, // Bootstrap peers typically Tier2 (relay/routing)
        trust_score: peer_info.reputation,
        
        // Statistics
        data_transferred: 0,
        tokens_earned: 0,
        traffic_routed: 0,
    };

    // Add to registry (upsert will update if already exists)
    let mut registry = peer_registry.write().await;
    registry.upsert(peer_entry)?;
    
    tracing::debug!(
        "Added bootstrap peer {} to registry (DID: {}, device: {})",
        peer_id.to_short_string(),
        peer_info.did,
        peer_info.device_name
    );

    Ok(())
}

/// Connect to a bootstrap peer
/// 
/// # Arguments
/// * `address` - Bootstrap peer address to connect to
/// * `local_identity` - Local identity for deriving NodeId
/// 
/// # Returns
/// PeerInfo with identity-derived NodeId
async fn connect_to_bootstrap_peer(address: &str, local_identity: &ZhtpIdentity) -> Result<PeerInfo> {
    use tokio::net::TcpStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    let addr: std::net::SocketAddr = address.parse()
        .map_err(|e| anyhow!("Invalid bootstrap address '{}': {}", address, e))?;

    let mut stream = TcpStream::connect(addr).await
        .map_err(|e| {
            tracing::warn!("Failed to connect to bootstrap peer {}: {}", address, e);
            anyhow!("Connection failed to {}: {}", address, e)
        })?;

    // Create handshake context with replay protection
    // Use temporary in-memory nonce cache for bootstrap (ephemeral session)
    let nonce_cache = crate::handshake::NonceCache::open_default(
        "/tmp/zhtp_bootstrap_nonce_cache",
        300 // 5 minute TTL for nonces
    ).map_err(|e| {
        tracing::warn!("Failed to open nonce cache, bootstrap may be vulnerable to replay attacks: {}", e);
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
