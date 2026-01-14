//! Unified Discovery Service Tests
//!
//! Tests for the consolidated discovery service that deduplicates peer announcements
//! across multiple discovery mechanisms (multicast, port scanning).

use anyhow::Result;
use lib_identity::{IdentityType, NodeId, ZhtpIdentity};
use lib_network::discovery::{
    DiscoveryProtocol, DiscoveryResult, UnifiedDiscoveryService,
};
use std::net::SocketAddr;
use uuid::Uuid;

/// Helper to create test identity with optional fixed seed for determinism
fn create_test_identity(device: &str, seed: Option<[u8; 64]>) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        seed,
    )
}

#[test]
fn test_discovery_protocol_priority() {
    // Multicast should have highest priority
    assert_eq!(DiscoveryProtocol::UdpMulticast.priority(), 1);
    assert_eq!(DiscoveryProtocol::PortScan.priority(), 2);

    // Lower number = higher priority
    assert!(DiscoveryProtocol::UdpMulticast.priority() < DiscoveryProtocol::PortScan.priority());
}

#[test]
fn test_discovery_result_creation() {
    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();

    let result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);

    assert_eq!(result.peer_id, peer_id);
    assert_eq!(result.addresses.len(), 1);
    assert_eq!(result.addresses[0], addr);
    assert_eq!(result.protocol, DiscoveryProtocol::UdpMulticast);
    assert_eq!(result.mesh_port, 9333);
    assert!(result.public_key.is_none());
}

#[test]
fn test_discovery_result_merge_addresses() {
    let peer_id = Uuid::new_v4();
    let addr1: SocketAddr = "192.168.1.100:9333".parse().unwrap();
    let addr2: SocketAddr = "10.0.0.50:9333".parse().unwrap();

    let mut result1 = DiscoveryResult::new(peer_id, addr1, DiscoveryProtocol::PortScan, 9333);
    let result2 = DiscoveryResult::new(peer_id, addr2, DiscoveryProtocol::UdpMulticast, 9333);

    result1.merge(result2);

    // Should have both addresses
    assert_eq!(result1.addresses.len(), 2);
    assert!(result1.addresses.contains(&addr1));
    assert!(result1.addresses.contains(&addr2));

    // Should prefer higher priority protocol (UdpMulticast)
    assert_eq!(result1.protocol, DiscoveryProtocol::UdpMulticast);
}

#[test]
fn test_discovery_result_merge_public_key() {
    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();
    
    // Create a test identity to get a public key
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed)).unwrap();
    let public_key = identity.public_key.clone();

    let mut result1 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::PortScan, 9333);
    let mut result2 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);
    result2.public_key = Some(public_key.clone());

    // result1 has no public key initially
    assert!(result1.public_key.is_none());

    result1.merge(result2);

    // Should now have public key from result2
    assert!(result1.public_key.is_some());
    assert_eq!(result1.public_key.unwrap().as_bytes(), public_key.as_bytes());
}

#[test]
fn test_discovery_result_merge_keeps_earliest_timestamp() {
    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();

    let mut result1 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::PortScan, 9333);
    result1.discovered_at = 1000;

    let mut result2 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);
    result2.discovered_at = 2000;

    result1.merge(result2);

    // Should keep earliest timestamp
    assert_eq!(result1.discovered_at, 1000);
}

#[test]
fn test_discovery_result_merge_no_duplicate_addresses() {
    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();

    let mut result1 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::PortScan, 9333);
    let result2 = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);

    result1.merge(result2);

    // Should not duplicate the same address
    assert_eq!(result1.addresses.len(), 1);
    assert_eq!(result1.addresses[0], addr);
}

#[tokio::test]
async fn test_unified_discovery_service_creation() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    // Should start with no discovered peers
    assert_eq!(service.peer_count().await, 0);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_register_peer() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();
    let result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);

    service.register_peer(result.clone()).await;

    // Should have one peer registered
    assert_eq!(service.peer_count().await, 1);

    // Should be able to retrieve the peer
    let retrieved = service.get_peer(&peer_id).await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().peer_id, peer_id);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_deduplication() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    let peer_id = Uuid::new_v4();
    let addr1: SocketAddr = "192.168.1.100:9333".parse().unwrap();
    let addr2: SocketAddr = "10.0.0.50:9333".parse().unwrap();

    // Register same peer discovered via different methods
    let result1 = DiscoveryResult::new(peer_id, addr1, DiscoveryProtocol::PortScan, 9333);
    service.register_peer(result1).await;

    let result2 = DiscoveryResult::new(peer_id, addr2, DiscoveryProtocol::UdpMulticast, 9333);
    service.register_peer(result2).await;

    // Should still have only one peer (deduplicated)
    assert_eq!(service.peer_count().await, 1);

    // Peer should have both addresses merged
    let peer = service.get_peer(&peer_id).await.unwrap();
    assert_eq!(peer.addresses.len(), 2);
    assert!(peer.addresses.contains(&addr1));
    assert!(peer.addresses.contains(&addr2));

    // Should prefer higher priority protocol (UdpMulticast)
    assert_eq!(peer.protocol, DiscoveryProtocol::UdpMulticast);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_multiple_peers() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    // Register three different peers
    let peer1 = Uuid::new_v4();
    let peer2 = Uuid::new_v4();
    let peer3 = Uuid::new_v4();

    let result1 = DiscoveryResult::new(
        peer1,
        "192.168.1.100:9333".parse().unwrap(),
        DiscoveryProtocol::UdpMulticast,
        9333,
    );
    let result2 = DiscoveryResult::new(
        peer2,
        "192.168.1.101:9333".parse().unwrap(),
        DiscoveryProtocol::PortScan,
        9333,
    );
    let result3 = DiscoveryResult::new(
        peer3,
        "192.168.1.102:9333".parse().unwrap(),
        DiscoveryProtocol::PortScan,
        9333,
    );

    service.register_peer(result1).await;
    service.register_peer(result2).await;
    service.register_peer(result3).await;

    // Should have three distinct peers
    assert_eq!(service.peer_count().await, 3);

    // Should be able to retrieve all peers
    let all_peers = service.get_discovered_peers().await;
    assert_eq!(all_peers.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_remove_peer() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    let peer_id = Uuid::new_v4();
    let result = DiscoveryResult::new(
        peer_id,
        "192.168.1.100:9333".parse().unwrap(),
        DiscoveryProtocol::UdpMulticast,
        9333,
    );

    service.register_peer(result).await;
    assert_eq!(service.peer_count().await, 1);

    // Remove the peer
    let removed = service.remove_peer(&peer_id).await;
    assert!(removed.is_some());
    assert_eq!(service.peer_count().await, 0);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_clear_peers() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    );

    // Register multiple peers
    for i in 0..5 {
        let peer_id = Uuid::new_v4();
        let addr = format!("192.168.1.{}:9333", 100 + i).parse().unwrap();
        let result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);
        service.register_peer(result).await;
    }

    assert_eq!(service.peer_count().await, 5);

    // Clear all peers
    service.clear_peers().await;
    assert_eq!(service.peer_count().await, 0);

    Ok(())
}

#[tokio::test]
async fn test_unified_discovery_service_with_callback() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_clone = Arc::clone(&callback_count);

    let service = UnifiedDiscoveryService::new(
        Uuid::new_v4(),
        9333,
        identity.public_key.clone(),
    )
    .with_callback(move |_result| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Register three different peers
    for i in 0..3 {
        let peer_id = Uuid::new_v4();
        let addr = format!("192.168.1.{}:9333", 100 + i).parse().unwrap();
        let result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);
        service.register_peer(result).await;
    }

    // Callback should be called 3 times (once per new peer)
    assert_eq!(callback_count.load(Ordering::SeqCst), 3);

    // Register same peer again (should not trigger callback)
    let peer_id = Uuid::new_v4();
    let result1 = DiscoveryResult::new(
        peer_id,
        "192.168.1.200:9333".parse().unwrap(),
        DiscoveryProtocol::PortScan,
        9333,
    );
    service.register_peer(result1).await;

    // Callback count should now be 4
    assert_eq!(callback_count.load(Ordering::SeqCst), 4);

    // Re-register same peer (deduplication, no new callback)
    let result2 = DiscoveryResult::new(
        peer_id,
        "10.0.0.50:9333".parse().unwrap(),
        DiscoveryProtocol::UdpMulticast,
        9333,
    );
    service.register_peer(result2).await;

    // Callback should still be 4 (no new peer, just merged)
    assert_eq!(callback_count.load(Ordering::SeqCst), 4);

    Ok(())
}

#[test]
fn test_discovery_result_to_unified_peer_id() -> Result<()> {
    let seed = [0x42u8; 64];
    // Use a unique device ID that meets entropy requirements
    let identity = create_test_identity("my-laptop-abc123def456", Some(seed))?;

    let peer_id = Uuid::new_v4();
    let addr: SocketAddr = "192.168.1.100:9333".parse().unwrap();
    let mut result = DiscoveryResult::new(peer_id, addr, DiscoveryProtocol::UdpMulticast, 9333);
    result.public_key = Some(identity.public_key.clone());

    // Convert to UnifiedPeerId
    let unified_peer = result.to_unified_peer_id(&identity)?;

    // Verify the conversion
    assert_eq!(unified_peer.did(), identity.did);
    assert_eq!(*unified_peer.node_id(), identity.node_id);
    assert_eq!(
        unified_peer.public_key().as_bytes(),
        identity.public_key.as_bytes()
    );

    Ok(())
}

#[test]
fn test_discovery_result_node_id_derivation() -> Result<()> {
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;

    // Verify NodeId is deterministically derived from DID + device
    let expected_node_id = NodeId::from_did_device(&identity.did, "laptop")?;
    assert_eq!(
        identity.node_id, expected_node_id,
        "NodeId should match DID + device derivation"
    );

    Ok(())
}
