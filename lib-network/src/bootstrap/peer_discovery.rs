//! Peer discovery implementation for bootstrap

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use lib_identity::{NodeId, ZhtpIdentity};
use std::collections::HashMap;

/// Discover peers through bootstrap process
/// 
/// # Arguments
/// * `bootstrap_addresses` - List of bootstrap peer addresses to connect to
/// * `local_identity` - Local identity for deriving NodeId and authentication
/// 
/// # Returns
/// List of discovered peers with identity-derived NodeIds
pub async fn discover_bootstrap_peers(
    bootstrap_addresses: &[String],
    local_identity: &ZhtpIdentity,
) -> Result<Vec<PeerInfo>> {
    let mut discovered_peers = Vec::new();
    
    for address in bootstrap_addresses {
        if let Ok(peer_info) = connect_to_bootstrap_peer(address, local_identity).await {
            discovered_peers.push(peer_info);
        }
    }
    
    Ok(discovered_peers)
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

    let addr: std::net::SocketAddr = address.parse()?;
    let mut stream = TcpStream::connect(addr).await?;

    // Create handshake context with replay protection
    let ctx = crate::handshake::HandshakeContext::default();

    // Set up capabilities for bootstrap handshake
    let capabilities = crate::handshake::HandshakeCapabilities {
        supports_pqc: false, // Bootstrap can use classical crypto for speed
        max_message_size: 1024 * 1024, // 1 MB
        protocol_version: crate::handshake::UHP_VERSION,
        extensions: vec![],
    };

    // Perform UHP authenticated handshake with bootstrap peer
    tracing::info!("Initiating UHP handshake with bootstrap peer {}", address);

    let result = crate::handshake::handshake_as_initiator(
        &mut stream,
        &ctx,
        local_identity,
        capabilities,
    ).await.map_err(|e| anyhow!("UHP handshake failed with {}: {}", address, e))?;

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
