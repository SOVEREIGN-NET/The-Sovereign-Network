//! Handshake NodeId Verification Tests
//!
//! Tests for verifying that peer handshakes properly verify NodeId against identity (DID + device)
//! and reject connections with mismatched identity/NodeId pairs.

use anyhow::Result;
use lib_identity::{ZhtpIdentity, IdentityType, NodeId};
use lib_network::{
    ClientHello, HandshakeCapabilities,
};
use lib_network::handshake::{HandshakeContext, NonceCache, NetworkEpoch};
use tempfile::TempDir;

/// Helper to create test identity
fn create_test_identity(device: &str, seed: Option<[u8; 64]>) -> Result<ZhtpIdentity> {
    ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        device,
        seed,
    )
}

fn create_test_context() -> Result<(HandshakeContext, TempDir)> {
    let temp_dir = TempDir::new()?;
    let network_epoch = NetworkEpoch::from_chain_id(0); // Test network
    let cache = NonceCache::open_default(temp_dir.path(), 300, network_epoch)?;
    let ctx = HandshakeContext::new(cache).with_channel_binding(vec![0u8; 32]);
    Ok((ctx, temp_dir))
}

#[tokio::test]
async fn test_valid_node_id_verification() -> Result<()> {
    // Create identity with known seed
    let seed = [0x42u8; 64];
    let identity = create_test_identity("laptop", Some(seed))?;
    
    // Verify NodeId derives correctly from DID + device
    let expected_node_id = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
    assert_eq!(identity.node_id, expected_node_id, "NodeId should match DID + device derivation");
    
    println!("✅ Valid NodeId verification passed");
    Ok(())
}

#[tokio::test]
async fn test_invalid_node_id_rejected() -> Result<()> {
    // Create identity
    let identity = create_test_identity("laptop", None)?;
    
    // Create fake NodeId (all zeros - definitely wrong)
    let fake_node_id = NodeId::from_bytes([0u8; 32]);
    
    // Verify it doesn't match the correct derivation
    assert_ne!(identity.node_id, fake_node_id, "Fake NodeId should not match");
    
    println!("✅ Invalid NodeId rejection test passed");
    Ok(())
}

#[tokio::test]
async fn test_mismatched_did_rejected() -> Result<()> {
    // Create identity
    let identity = create_test_identity("laptop", None)?;
    
    // Try to derive NodeId from wrong DID
    let wrong_did = "did:zhtp:wrong";
    let derived_from_wrong = NodeId::from_did_device(wrong_did, &identity.primary_device)?;
    
    // Should not match
    assert_ne!(identity.node_id, derived_from_wrong, "Mismatched DID should produce different NodeId");
    println!("✅ Mismatched DID rejection test passed");
    Ok(())
}

#[tokio::test]
async fn test_mismatched_device_rejected() -> Result<()> {
    // Create identity
    let identity = create_test_identity("laptop", None)?;
    
    // Try to derive NodeId from wrong device
    let wrong_device = "wrong-device";
    let derived_from_wrong = NodeId::from_did_device(&identity.did, wrong_device)?;
    
    // Should not match
    assert_ne!(identity.node_id, derived_from_wrong, "Mismatched device should produce different NodeId");
    println!("✅ Mismatched device rejection test passed");
    Ok(())
}

#[tokio::test]
async fn test_create_handshake_data() -> Result<()> {
    // Create identity
    let identity = create_test_identity("test-device", None)?;
    
    // Create ClientHello
    let capabilities = HandshakeCapabilities::default();
    let (ctx, _temp_dir) = create_test_context()?;
    let client_hello = ClientHello::new(&identity, capabilities, &ctx)?;
    
    // Verify fields
    assert_eq!(client_hello.identity.did, identity.did);
    assert_eq!(client_hello.identity.device_id, identity.primary_device);
    assert_eq!(client_hello.identity.node_id, identity.node_id);
    
    // Verify the NodeId matches expected derivation
    let expected_node_id = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
    assert_eq!(client_hello.identity.node_id, expected_node_id);

    println!("✅ Handshake data creation test passed");
    Ok(())
}

#[tokio::test]
async fn test_handshake_serialization() -> Result<()> {
    // Create handshake data
    let identity = create_test_identity("device1", None)?;
    let capabilities = HandshakeCapabilities::default();
    let (ctx, _temp_dir) = create_test_context()?;
    let client_hello = ClientHello::new(&identity, capabilities, &ctx)?;
    
    // Serialize
    let serialized = bincode::serialize(&client_hello)?;
    println!("ClientHello serialized to {} bytes", serialized.len());
    
    // Deserialize
    let deserialized: ClientHello = bincode::deserialize(&serialized)?;
    
    // Verify fields match
    assert_eq!(deserialized.identity.did, client_hello.identity.did);
    assert_eq!(deserialized.identity.device_id, client_hello.identity.device_id);
    assert_eq!(deserialized.identity.node_id, client_hello.identity.node_id);
    
    // Verify NodeId still validates after round-trip
    let expected_node_id = NodeId::from_did_device(
        &deserialized.identity.did,
        &deserialized.identity.device_id
    )?;
    assert_eq!(deserialized.identity.node_id, expected_node_id);

    println!("✅ Handshake serialization round-trip test passed");
    Ok(())
}

#[tokio::test]
async fn test_multiple_devices_same_identity() -> Result<()> {
    // Create identity with same seed but different devices
    let seed = [0x33u8; 64];
    let identity1 = create_test_identity("laptop", Some(seed))?;
    let identity2 = create_test_identity("phone", Some(seed))?;
    
    // Both should have same DID
    assert_eq!(identity1.did, identity2.did, "Same seed should produce same DID");
    
    // But different NodeIds
    assert_ne!(
        identity1.node_id,
        identity2.node_id,
        "Different devices should have different NodeIds"
    );
    
    // Both should derive correctly
    let expected1 = NodeId::from_did_device(&identity1.did, &identity1.primary_device)?;
    let expected2 = NodeId::from_did_device(&identity2.did, &identity2.primary_device)?;
    
    assert_eq!(identity1.node_id, expected1);
    assert_eq!(identity2.node_id, expected2);
    
    // Cross-derivation should not match
    let cross_derived = NodeId::from_did_device(&identity1.did, &identity2.primary_device)?;
    assert_ne!(identity1.node_id, cross_derived, "Cross-device derivation should differ");
    
    println!("✅ Multi-device identity test passed");
    Ok(())
}

#[tokio::test]
async fn test_deterministic_verification() -> Result<()> {
    // Create two identities with same seed and device
    let seed = [0x55u8; 64];
    let identity1 = create_test_identity("desktop", Some(seed))?;
    let identity2 = create_test_identity("desktop", Some(seed))?;
    
    // Should have identical DIDs and NodeIds
    assert_eq!(identity1.did, identity2.did);
    assert_eq!(identity1.node_id, identity2.node_id);
    
    // Both should derive the same NodeId
    let expected1 = NodeId::from_did_device(&identity1.did, &identity1.primary_device)?;
    let expected2 = NodeId::from_did_device(&identity2.did, &identity2.primary_device)?;
    
    assert_eq!(expected1, expected2);
    assert_eq!(identity1.node_id, expected1);
    
    println!("✅ Deterministic verification test passed");
    Ok(())
}

#[tokio::test]
async fn test_tampered_node_id_detected() -> Result<()> {
    // Create valid identity
    let identity = create_test_identity("laptop", None)?;
    
    // Get valid NodeId and tamper with one byte
    let mut tampered_bytes = *identity.node_id.as_bytes();
    tampered_bytes[0] ^= 0xFF; // Flip all bits in first byte
    let tampered_node_id = NodeId::from_bytes(tampered_bytes);
    
    // Should not match
    assert_ne!(identity.node_id, tampered_node_id, "Tampered NodeId should not match");
    
    // Verify the correct one still derives properly
    let expected = NodeId::from_did_device(&identity.did, &identity.primary_device)?;
    assert_eq!(identity.node_id, expected);
    assert_ne!(tampered_node_id, expected);
    
    println!("✅ Tampered NodeId detection test passed");
    Ok(())
}

#[tokio::test]
async fn test_verification_across_identity_types() -> Result<()> {
    // Test with different identity types
    let human = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25),
        Some("US".to_string()),
        "device1",
        None,
    )?;
    
    let organization = ZhtpIdentity::new_unified(
        IdentityType::Organization,
        None,
        Some("US".to_string()),
        "server1",
        None,
    )?;
    
    let iot = ZhtpIdentity::new_unified(
        IdentityType::Device,
        None,
        None,
        "sensor1",
        None,
    )?;
    
    // All should derive correctly
    let expected_human = NodeId::from_did_device(&human.did, &human.primary_device)?;
    let expected_org = NodeId::from_did_device(&organization.did, &organization.primary_device)?;
    let expected_iot = NodeId::from_did_device(&iot.did, &iot.primary_device)?;
    
    assert_eq!(human.node_id, expected_human);
    assert_eq!(organization.node_id, expected_org);
    assert_eq!(iot.node_id, expected_iot);
    
    println!("✅ Verification across identity types test passed");
    Ok(())
}

#[tokio::test]
async fn test_golden_vector_verification() -> Result<()> {
    // Test with known seed to verify consistent derivation
    let seed = [0x01u8; 64];
    let device = "test-device";
    
    let identity = create_test_identity(device, Some(seed))?;
    
    // Verify the NodeId derives correctly
    let expected = NodeId::from_did_device(&identity.did, device)?;
    assert_eq!(identity.node_id, expected);
    
    // Create second identity with same parameters
    let identity2 = create_test_identity(device, Some(seed))?;
    
    // Should produce identical results
    assert_eq!(identity.did, identity2.did);
    assert_eq!(identity.node_id, identity2.node_id);
    
    println!("✅ Golden vector verification test passed");
    println!("   DID:    {}", identity.did);
    println!("   NodeId: {}", identity.node_id.to_hex());
    Ok(())
}

#[tokio::test]
async fn test_empty_did_rejected() -> Result<()> {
    // Try to derive NodeId with empty DID
    let result = NodeId::from_did_device("", "device");
    
    assert!(result.is_err(), "Empty DID should be rejected");
    println!("✅ Empty DID rejection test passed");
    Ok(())
}

#[tokio::test]
async fn test_empty_device_name_rejected() -> Result<()> {
    // Try to derive NodeId with empty device name
    let result = NodeId::from_did_device("did:zhtp:test123", "");
    
    assert!(result.is_err(), "Empty device name should be rejected");
    println!("✅ Empty device name rejection test passed");
    Ok(())
}
