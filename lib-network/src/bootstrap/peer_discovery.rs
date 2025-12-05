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
    use tokio::io::AsyncWriteExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let addr: std::net::SocketAddr = address.parse()?;
    let mut stream = TcpStream::connect(addr).await?;
    
    // Send a mesh handshake to bootstrap peer with identity-derived NodeId
    // Note: Full MeshHandshake update with DID/device fields will be in next commit
    let handshake = crate::discovery::local_network::MeshHandshake {
        version: 1,
        node_id: uuid::Uuid::new_v4(), // TODO: Replace with identity.node_id in next commit
        public_key: local_identity.public_key.clone(),
        mesh_port: 9333, // Default mesh port
        protocols: vec!["zhtp".to_string(), "dht".to_string(), "tcp".to_string()],
        discovered_via: 4, // 4 = bootstrap peer
        capabilities: crate::discovery::local_network::HandshakeCapabilities::default(),
    };
    
    // Send handshake
    let handshake_bytes = bincode::serialize(&handshake)?;
    stream.write_all(&handshake_bytes).await?;
    
    // Keep connection alive for authentication
    // The bootstrap peer will now handle authentication
    tracing::info!("Sent handshake to bootstrap peer {}, awaiting auth...", address);
    
    // Read any response (acknowledgment or auth challenge)
    let mut response_buf = vec![0u8; 8192];
    use tokio::io::AsyncReadExt;
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read(&mut response_buf)
    ).await {
        Ok(Ok(n)) if n > 0 => {
            tracing::info!("Received {} bytes from bootstrap peer {}", n, address);
        }
        _ => {
            tracing::warn!("Bootstrap peer {} did not respond to handshake", address);
        }
    }
    
    // Create peer info for successful connection
    // Note: In production, we would parse the peer's identity from handshake response
    // For now, we derive a temporary NodeId for the bootstrap peer
    let bootstrap_did = format!("did:zhtp:bootstrap-{}", hex::encode(&lib_crypto::hash_blake3(address.as_bytes())));
    let bootstrap_device = "bootstrap-node";
    
    // Derive NodeId from bootstrap peer's synthetic identity
    let peer_node_id = NodeId::from_did_device(&bootstrap_did, bootstrap_device)
        .map_err(|e| anyhow!("Failed to derive bootstrap peer NodeId: {}", e))?;
    
    let peer_id = PublicKey::new(format!("bootstrap-{}", address).into_bytes());
    let mut addresses = HashMap::new();
    addresses.insert(crate::protocols::NetworkProtocol::TCP, address.to_string());
    
    tracing::info!(
        "✓ Bootstrap peer {} has NodeId: {} (derived from DID + device)",
        address,
        peer_node_id.to_hex()
    );
    
    Ok(PeerInfo {
        id: peer_id,
        node_id: Some(peer_node_id),
        did: bootstrap_did,
        device_name: bootstrap_device.to_string(),
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
