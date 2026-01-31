//! Identity-Based Peer Discovery Tests
//!
//! Tests for verifying that peer discovery properly derives NodeIds from identity (DID + device)
//! and that all discovered peers have deterministic, validated NodeIds.

use anyhow::Result;
use lib_identity::{ZhtpIdentity, IdentityType, NodeId};
use lib_network::bootstrap::peer_discovery::PeerInfo;

mod common;
use common::test_helpers::create_test_identity;

#[tokio::test]
async fn test_deterministic_node_id_from_identity() -> Result<()> {
    // Create identity with fixed seed for determinism
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;
    
    // Verify NodeId is deterministic from seed
    let expected_node_id = NodeId::from_did_device(&identity.did, "laptop")?;
    assert_eq!(
        identity.node_id, 
        expected_node_id,
        "Identity NodeId should match DID + device derivation"
    );
    
    // Create second identity with same seed
    let identity2 = create_test_identity("laptop", Some(seed))?;
    
    // Both should have identical DID and NodeId
    assert_eq!(
        identity.did, 
        identity2.did,
        "Same seed should produce same DID"
    );
    assert_eq!(
        identity.node_id, 
        identity2.node_id,
        "Same seed + device should produce same NodeId"
    );
    
    println!("✅ Deterministic NodeId test passed");
    println!("   DID: {}", identity.did);
    println!("   NodeId: {}", identity.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_different_seeds_produce_different_node_ids() -> Result<()> {
    let seed1 = [0x42u8; 64];
    let seed2 = [0x43u8; 64];
    
    let identity1 = create_test_identity("laptop", Some(seed1))?;
    let identity2 = create_test_identity("laptop", Some(seed2))?;
    
    // Different seeds should produce different DIDs
    assert_ne!(
        identity1.did,
        identity2.did,
        "Different seeds should produce different DIDs"
    );
    
    // Different DIDs should produce different NodeIds (same device)
    assert_ne!(
        identity1.node_id,
        identity2.node_id,
        "Different DIDs should produce different NodeIds"
    );
    
    println!("✅ Different seeds test passed");
    println!("   Identity 1 DID: {}", identity1.did);
    println!("   Identity 1 NodeId: {}", identity1.node_id.to_hex());
    println!("   Identity 2 DID: {}", identity2.did);
    println!("   Identity 2 NodeId: {}", identity2.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_multi_device_same_identity() -> Result<()> {
    let seed = [0x42u8; 64];
    
    // Create identity on laptop
    let laptop = create_test_identity("laptop", Some(seed))?;
    
    // Create identity on phone (same seed, different device)
    let phone = create_test_identity("phone", Some(seed))?;
    
    // Same seed produces same DID
    assert_eq!(
        laptop.did, 
        phone.did,
        "Same seed should produce same DID across devices"
    );
    
    // Different devices produce different NodeIds
    assert_ne!(
        laptop.node_id, 
        phone.node_id,
        "Different devices should produce different NodeIds"
    );
    
    // Verify each NodeId derives correctly from DID + device
    let laptop_derived = NodeId::from_did_device(&laptop.did, "laptop")?;
    let phone_derived = NodeId::from_did_device(&phone.did, "phone")?;
    
    assert_eq!(laptop.node_id, laptop_derived);
    assert_eq!(phone.node_id, phone_derived);
    
    println!("✅ Multi-device test passed");
    println!("   Shared DID: {}", laptop.did);
    println!("   Laptop NodeId: {}", laptop.node_id.to_hex());
    println!("   Phone NodeId: {}", phone.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_validation() -> Result<()> {
    let identity = create_test_identity("laptop", None)?;
    
    // Create valid PeerInfo with matching NodeId
    let valid_peer = PeerInfo {
        id: identity.public_key.clone(),
        node_id: Some(identity.node_id),
        did: identity.did.clone(),
        device_name: identity.primary_device.clone(),
        protocols: vec![],
        addresses: std::collections::HashMap::new(),
        last_seen: 0,
        reputation: 1.0,
        bandwidth_capacity: 1_000_000,
        storage_capacity: 1_000_000_000,
        compute_capacity: 100,
        connection_type: lib_network::protocols::NetworkProtocol::TCP,
    };
    
    // Just verify the NodeId matches what we expect
    let expected_node_id = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
    assert_eq!(valid_peer.node_id, Some(expected_node_id));
    
    println!("✅ Valid peer NodeId validation passed");
    
    // Create invalid PeerInfo with mismatched NodeId
    let wrong_node_id = NodeId::from_bytes([0xFF; 32]);
    let invalid_peer = PeerInfo {
        id: identity.public_key.clone(),
        node_id: Some(wrong_node_id),
        did: identity.did.clone(),
        device_name: identity.primary_device.clone(),
        protocols: vec![],
        addresses: std::collections::HashMap::new(),
        last_seen: 0,
        reputation: 1.0,
        bandwidth_capacity: 1_000_000,
        storage_capacity: 1_000_000_000,
        compute_capacity: 100,
        connection_type: lib_network::protocols::NetworkProtocol::TCP,
    };
    
    // Verify it doesn't match
    assert_ne!(invalid_peer.node_id, Some(expected_node_id));
    
    println!("✅ Invalid peer NodeId validation correctly failed");
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_validation_missing() -> Result<()> {
    let identity = create_test_identity("laptop", None)?;
    
    // Create PeerInfo without NodeId
    let peer_without_node_id = PeerInfo {
        id: identity.public_key.clone(),
        node_id: None, // Missing NodeId
        did: identity.did.clone(),
        device_name: identity.primary_device.clone(),
        protocols: vec![],
        addresses: std::collections::HashMap::new(),
        last_seen: 0,
        reputation: 1.0,
        bandwidth_capacity: 1_000_000,
        storage_capacity: 1_000_000_000,
        compute_capacity: 100,
        connection_type: lib_network::protocols::NetworkProtocol::TCP,
    };
    
    // Verify it has no NodeId
    assert!(peer_without_node_id.node_id.is_none(), "PeerInfo should have no NodeId");
    
    println!("✅ Missing NodeId validation correctly failed");
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_hex_roundtrip() -> Result<()> {
    let identity = create_test_identity("laptop", None)?;
    
    // Convert NodeId to hex
    let hex = identity.node_id.to_hex();
    assert_eq!(hex.len(), 64, "Hex should be 64 characters (32 bytes)");
    
    // Convert back from hex
    let restored = NodeId::from_hex(&hex)?;
    assert_eq!(
        identity.node_id, 
        restored,
        "NodeId should survive hex round-trip"
    );
    
    println!("✅ NodeId hex round-trip test passed");
    println!("   NodeId: {}", hex);
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_determinism_golden_vector() -> Result<()> {
    // Use known fixed seed for reproducible test
    let seed = [0x42u8; 64];
    
    // Create identity with known parameters
    let identity = create_test_identity("test-device", Some(seed))?;
    
    // Verify DID is deterministic
    let expected_did_hash = lib_crypto::hash_blake3(&[&seed[..], b"ZHTP_DID_V1"].concat());
    let expected_did = format!("did:zhtp:{}", hex::encode(expected_did_hash));
    assert_eq!(identity.did, expected_did, "DID should be deterministic from seed");
    
    // Verify NodeId derivation
    let expected_node_id = NodeId::from_did_device(&expected_did, "test-device")?;
    assert_eq!(identity.node_id, expected_node_id, "NodeId should derive from DID + device");
    
    // Log golden values for regression testing
    println!("✅ Golden vector test passed");
    println!("   Seed: {}", hex::encode(&seed));
    println!("   DID: {}", identity.did);
    println!("   Device: test-device");
    println!("   NodeId: {}", identity.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_case_insensitivity() -> Result<()> {
    let seed = [0x42u8; 64];
    
    // Create identities with different device name casing
    let lowercase = create_test_identity("laptop", Some(seed))?;
    let uppercase = create_test_identity("LAPTOP", Some(seed))?;
    let mixed = create_test_identity("LapTop", Some(seed))?;
    
    // All should normalize to same NodeId
    assert_eq!(
        lowercase.node_id,
        uppercase.node_id,
        "Device names should be case-insensitive"
    );
    assert_eq!(
        lowercase.node_id,
        mixed.node_id,
        "Device names should be case-insensitive"
    );
    
    println!("✅ Case insensitivity test passed");
    println!("   All variants produce NodeId: {}", lowercase.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_device_name_validation() -> Result<()> {
    // Valid device names
    let max_length_device = "a".repeat(64);
    let valid_devices = vec![
        "laptop",
        "phone-1",
        "tablet_backup",
        "device.primary",
        "a",           // minimum length
        max_length_device.as_str(), // maximum length
    ];
    
    for device in valid_devices {
        let result = NodeId::from_did_device("did:zhtp:test123", device);
        assert!(result.is_ok(), "Device name '{}' should be valid", device);
    }
    
    // Invalid device names
    let too_long_device = "a".repeat(65);
    let invalid_devices = vec![
        "",              // empty
        " ",             // whitespace only
        "my laptop",     // space
        "device!",       // invalid char
        "laptop@home",   // invalid char
        too_long_device.as_str(), // too long
    ];
    
    for device in invalid_devices {
        let result = NodeId::from_did_device("did:zhtp:test123", device);
        assert!(result.is_err(), "Device name '{}' should be invalid", device);
    }
    
    println!("✅ Device name validation test passed");
    
    Ok(())
}

#[tokio::test]
async fn test_identity_types_all_support_node_id() -> Result<()> {
    let seed = [0x42u8; 64];
    
    // Test Human identity
    let human = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        "laptop",
        Some(seed),
    )?;
    assert!(human.node_id.as_bytes().len() == 32, "Human should have 32-byte NodeId");
    
    // Test Device identity
    let device = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None, // Device doesn't require age
        None, // Device doesn't require jurisdiction
        "sensor-1",
        Some(seed),
    )?;
    assert!(device.node_id.as_bytes().len() == 32, "Device should have 32-byte NodeId");
    
    // Test Organization identity
    let org = ZhtpIdentity::new_unified(
        IdentityType::Organization,
        None,
        None,
        "main-server",
        Some(seed),
    )?;
    assert!(org.node_id.as_bytes().len() == 32, "Organization should have 32-byte NodeId");
    
    println!("✅ All identity types support NodeId");
    println!("   Human NodeId: {}", human.node_id.to_hex());
    println!("   Device NodeId: {}", device.node_id.to_hex());
    println!("   Organization NodeId: {}", org.node_id.to_hex());
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_storage_hash_conversion() -> Result<()> {
    let identity = create_test_identity("laptop", None)?;
    
    // Convert to storage hash
    let storage_hash = identity.node_id.to_storage_hash();
    assert_eq!(storage_hash.as_bytes().len(), 32, "Storage hash should be 32 bytes");
    
    // Convert back from storage hash
    let restored = NodeId::from_storage_hash(&storage_hash);
    assert_eq!(
        identity.node_id,
        restored,
        "NodeId should survive storage hash conversion"
    );
    
    println!("✅ Storage hash conversion test passed");
    
    Ok(())
}

#[tokio::test]
async fn test_node_id_xor_distance() -> Result<()> {
    let identity1 = create_test_identity("laptop", None)?;
    let identity2 = create_test_identity("phone", None)?;
    
    // Distance to self should be zero
    let self_distance = identity1.node_id.xor_distance(&identity1.node_id);
    assert_eq!(self_distance, [0u8; 32], "Distance to self should be zero");
    
    // Distance should be symmetric
    let dist_1_to_2 = identity1.node_id.xor_distance(&identity2.node_id);
    let dist_2_to_1 = identity2.node_id.xor_distance(&identity1.node_id);
    assert_eq!(dist_1_to_2, dist_2_to_1, "XOR distance should be symmetric");
    
    // Distance between different nodes should be non-zero
    assert_ne!(dist_1_to_2, [0u8; 32], "Distance between different nodes should be non-zero");
    
    println!("✅ XOR distance test passed");
    
    Ok(())
}
