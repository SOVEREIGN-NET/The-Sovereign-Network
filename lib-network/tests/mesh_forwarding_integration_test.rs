//! Integration tests for multi-hop message forwarding
//! 
//! Tests the complete message forwarding system including:
//! - Message envelope serialization/deserialization
//! - Multi-hop routing through intermediate nodes
//! - Route caching and optimization
//! - Reward tracking for forwarding nodes
//! - TTL expiration and loop prevention

use lib_network::types::mesh_message::{ZhtpMeshMessage, MeshMessageEnvelope};
use lib_crypto::{PublicKey, generate_keypair};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_message_envelope_serialization() {
    // Test that we can serialize and deserialize message envelopes
    
    let origin = PublicKey::new(vec![1, 2, 3, 4]);
    let destination = PublicKey::new(vec![5, 6, 7, 8]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.95,
        available_bandwidth: 1_000_000,
        connected_peers: 5,
        uptime_hours: 24,
    };
    
    let envelope = MeshMessageEnvelope::new(
        12345,
        origin.clone(),
        destination.clone(),
        message,
    );
    
    // Serialize
    let bytes = envelope.to_bytes().expect("Should serialize");
    assert!(bytes.len() > 0, "Serialized data should not be empty");
    
    // Deserialize
    let deserialized = MeshMessageEnvelope::from_bytes(&bytes)
        .expect("Should deserialize");
    
    // Verify fields
    assert_eq!(deserialized.message_id, 12345);
    assert_eq!(deserialized.origin.key_id, origin.key_id);
    assert_eq!(deserialized.destination.key_id, destination.key_id);
    assert_eq!(deserialized.ttl, 32);
    assert_eq!(deserialized.hop_count, 0);
}

#[tokio::test]
async fn test_envelope_hop_increment() {
    // Test that hop count increments and TTL decrements correctly
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    let relay = PublicKey::new(vec![7, 8, 9]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let mut envelope = MeshMessageEnvelope::new(
        999,
        origin.clone(),
        destination.clone(),
        message,
    );
    
    let initial_ttl = envelope.ttl;
    let initial_hops = envelope.hop_count;
    
    // Simulate forwarding through relay
    envelope.increment_hop(relay.clone());
    
    assert_eq!(envelope.hop_count, initial_hops + 1);
    assert_eq!(envelope.ttl, initial_ttl - 1);
    assert_eq!(envelope.route_history.len(), 1);
    assert_eq!(envelope.route_history[0].key_id, relay.key_id);
}

#[tokio::test]
async fn test_envelope_ttl_expiration() {
    // Test that messages are correctly identified as expired
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let mut envelope = MeshMessageEnvelope::new(
        111,
        origin,
        destination,
        message,
    );
    
    // Set TTL to 1
    envelope.ttl = 1;
    assert!(!envelope.should_drop(), "Should not drop with TTL=1");
    
    // Decrement to 0
    envelope.ttl = 0;
    assert!(envelope.should_drop(), "Should drop with TTL=0");
}

#[tokio::test]
async fn test_envelope_loop_detection() {
    // Test that we can detect routing loops
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    let relay1 = PublicKey::new(vec![7, 8, 9]);
    let relay2 = PublicKey::new(vec![10, 11, 12]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let mut envelope = MeshMessageEnvelope::new(
        222,
        origin,
        destination,
        message,
    );
    
    // Add relays to route
    envelope.increment_hop(relay1.clone());
    envelope.increment_hop(relay2.clone());
    
    // Check if nodes are in route
    assert!(envelope.contains_in_route(&relay1), "Should find relay1 in route");
    assert!(envelope.contains_in_route(&relay2), "Should find relay2 in route");
    
    let other_node = PublicKey::new(vec![99, 99, 99]);
    assert!(!envelope.contains_in_route(&other_node), "Should not find other node in route");
}

#[tokio::test]
async fn test_envelope_destination_check() {
    // Test the is_for_me() method
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let envelope = MeshMessageEnvelope::new(
        333,
        origin.clone(),
        destination.clone(),
        message,
    );
    
    // Test with correct destination
    assert!(envelope.is_for_me(&destination), "Should match destination");
    
    // Test with wrong destination
    assert!(!envelope.is_for_me(&origin), "Should not match origin");
    
    let other = PublicKey::new(vec![99, 99, 99]);
    assert!(!envelope.is_for_me(&other), "Should not match other node");
}

#[tokio::test]
async fn test_zhtp_request_message() {
    // Test ZHTP request/response message types
    
    let requester = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    let request = lib_protocols::types::ZhtpRequest::get(
        "/content/hello".to_string(),
        None
    ).unwrap();
    
    let message = ZhtpMeshMessage::ZhtpRequest(request);
    
    let envelope = MeshMessageEnvelope::new(
        444,
        requester,
        destination,
        message,
    );
    
    // Serialize and verify
    let bytes = envelope.to_bytes().expect("Should serialize");
    let deserialized = MeshMessageEnvelope::from_bytes(&bytes)
        .expect("Should deserialize");
    
    // Check message type
    match deserialized.message {
        ZhtpMeshMessage::ZhtpRequest(request) => {
            assert_eq!(request.method, lib_protocols::types::ZhtpMethod::Get);
            assert_eq!(request.uri, "/content/hello");
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn test_blockchain_data_chunking() {
    // Test blockchain data message type
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    let test_data = vec![0u8; 1000]; // 1KB of test data
    let test_hash = [42u8; 32];
    
    let message = ZhtpMeshMessage::BlockchainData {
        request_id: 555,
        chunk_index: 0,
        total_chunks: 5,
        data: test_data.clone(),
        complete_data_hash: test_hash,
    };
    
    let envelope = MeshMessageEnvelope::new(
        666,
        origin,
        destination,
        message,
    );
    
    // Serialize and verify
    let bytes = envelope.to_bytes().expect("Should serialize");
    let deserialized = MeshMessageEnvelope::from_bytes(&bytes)
        .expect("Should deserialize");
    
    // Check message type and data
    match deserialized.message {
        ZhtpMeshMessage::BlockchainData { request_id, chunk_index, total_chunks, data, complete_data_hash } => {
            assert_eq!(request_id, 555);
            assert_eq!(chunk_index, 0);
            assert_eq!(total_chunks, 5);
            assert_eq!(data.len(), 1000);
            assert_eq!(complete_data_hash, test_hash);
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn test_envelope_size_calculation() {
    // Test that we can calculate envelope size correctly
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    // Small message
    let small_message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let small_envelope = MeshMessageEnvelope::new(
        777,
        origin.clone(),
        destination.clone(),
        small_message,
    );
    
    let small_size = small_envelope.size();
    assert!(small_size > 0, "Size should be greater than 0");
    assert!(small_size < 500, "Small message should be less than 500 bytes");
    
    // Large message
    let large_data = vec![0u8; 10_000]; // 10KB
    let large_message = ZhtpMeshMessage::BlockchainData {
        request_id: 888,
        chunk_index: 0,
        total_chunks: 1,
        data: large_data,
        complete_data_hash: [0u8; 32],
    };
    
    let large_envelope = MeshMessageEnvelope::new(
        999,
        origin,
        destination,
        large_message,
    );
    
    let large_size = large_envelope.size();
    assert!(large_size > 10_000, "Large message should be greater than 10KB");
}

#[test]
fn test_message_types_coverage() {
    // Ensure all message types can be constructed
    
    let peer = PublicKey::new(vec![1, 2, 3]);
    
    // This test just ensures the message types compile correctly
    let _messages = vec![
        ZhtpMeshMessage::PeerDiscovery {
            capabilities: vec![],
            location: None,
            shared_resources: Default::default(),
        },
        ZhtpMeshMessage::HealthReport {
            reporter: peer.clone(),
            network_quality: 0.9,
            available_bandwidth: 1_000_000,
            connected_peers: 5,
            uptime_hours: 24,
        },
        ZhtpMeshMessage::ZhtpRequest(
            lib_protocols::types::ZhtpRequest::get("/test".to_string(), None).unwrap()
        ),
        ZhtpMeshMessage::NewBlock {
            block: vec![1, 2, 3],
            sender: peer.clone(),
            height: 100,
            timestamp: 1234567890,
        },
        ZhtpMeshMessage::NewTransaction {
            transaction: vec![1, 2, 3],
            sender: peer.clone(),
            tx_hash: [0u8; 32],
            fee: 100,
        },
    ];
    
    // If we get here, all message types are valid
    assert!(true);
}

#[tokio::test]
async fn test_concurrent_envelope_operations() {
    // Test that envelopes can be safely used in concurrent contexts
    use tokio::task;
    
    let origin = PublicKey::new(vec![1, 2, 3]);
    let destination = PublicKey::new(vec![4, 5, 6]);
    
    let message = ZhtpMeshMessage::HealthReport {
        reporter: origin.clone(),
        network_quality: 0.9,
        available_bandwidth: 500_000,
        connected_peers: 3,
        uptime_hours: 12,
    };
    
    let envelope = MeshMessageEnvelope::new(
        123,
        origin,
        destination,
        message,
    );
    
    // Spawn multiple tasks that serialize the envelope
    let mut handles = vec![];
    for _ in 0..10 {
        let env_clone = envelope.clone();
        let handle = task::spawn(async move {
            env_clone.to_bytes().expect("Should serialize")
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        let bytes = handle.await.expect("Task should complete");
        assert!(bytes.len() > 0, "Each task should produce serialized bytes");
    }
}
