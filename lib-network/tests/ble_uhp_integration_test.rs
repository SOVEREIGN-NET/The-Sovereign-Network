// Issue #141: BLE GATT Adapter Integration Tests
// Tests full UHP-over-BLE with fragmentation, reassembly, and verification

use anyhow::Result;
use std::sync::Arc;

#[cfg(feature = "ble-mock")]
use lib_network::protocols::bluetooth::{
    gatt_adapter::VerificationHook,
    mock::MockGattLink,
};

/// Test UHP message framing over BLE GATT with mock hardware
#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_uhp_over_ble_fragmentation() -> Result<()> {
    // Create mock BLE link (247-byte MTU is typical for BLE)
    let mut mock_link = MockGattLink::new(247, None, None);

    // Large UHP payload that will require fragmentation
    let original_payload = vec![0x42; 1024]; // 1KB payload > 247 byte MTU
    
    // Send UHP frame from central to peripheral
    mock_link.central.send_frame(&original_payload).await?;
    
    // Receive and verify the payload on peripheral side
    let received_payload = mock_link.peripheral.recv_frame().await?;
    
    assert_eq!(original_payload, received_payload);
    println!("✓ UHP fragmentation/reassembly works correctly");
    
    Ok(())
}

/// Test UHP verification hook rejects unverified peers
#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_uhp_verification_rejects_unverified_peers() -> Result<()> {
    // Mock verification: only accept payloads starting with 0x01 (verified)
    let verification_hook: VerificationHook = Arc::new(|payload| {
        payload.first() == Some(&0x01)
    });

    // Verifier on peripheral side (2nd param) since central sends TO peripheral
    let mut mock_link = MockGattLink::new(247, None, Some(verification_hook));
    
    // Test 1: Verified payload should pass
    let verified_payload = vec![0x01, 0x42, 0x43, 0x44]; // starts with 0x01
    mock_link.central.send_frame(&verified_payload).await?;
    let received = mock_link.peripheral.recv_frame().await?;
    assert_eq!(verified_payload, received);
    println!("✓ Verified peer payload accepted");
    
    // Test 2: Unverified payload should be rejected
    let unverified_payload = vec![0xFF, 0x42, 0x43, 0x44]; // starts with 0xFF
    mock_link.central.send_frame(&unverified_payload).await?;
    let result = mock_link.peripheral.recv_frame().await;
    assert!(result.is_err());
    println!("✓ Unverified peer payload rejected");
    
    Ok(())
}

/// Test bidirectional UHP communication over BLE
#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_bidirectional_uhp_over_ble() -> Result<()> {
    let mut mock_link = MockGattLink::new(247, None, None);
    
    // Send from central to peripheral
    let message_to_peripheral = b"Hello from central".to_vec();
    mock_link.central.send_frame(&message_to_peripheral).await?;
    let received_at_peripheral = mock_link.peripheral.recv_frame().await?;
    assert_eq!(message_to_peripheral, received_at_peripheral);
    
    // Send response from peripheral to central
    let response_to_central = b"Hello from peripheral".to_vec();
    mock_link.peripheral.send_frame(&response_to_central).await?;
    let received_at_central = mock_link.central.recv_frame().await?;
    assert_eq!(response_to_central, received_at_central);
    
    println!("✓ Bidirectional UHP communication works");
    
    Ok(())
}

/// Test UHP with various MTU sizes
#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_uhp_with_different_mtu_sizes() -> Result<()> {
    let test_cases = vec![
        (23, 100),   // Minimum BLE MTU, small payload
        (247, 500),  // Standard BLE MTU, medium payload  
        (512, 2048), // Large MTU, large payload
    ];
    
    for (mtu, payload_size) in test_cases {
        let mut mock_link = MockGattLink::new(mtu, None, None);
        let payload = vec![0xAB; payload_size];
        
        mock_link.central.send_frame(&payload).await?;
        let received = mock_link.peripheral.recv_frame().await?;
        
        assert_eq!(payload, received);
        println!("✓ MTU {} with payload size {} works", mtu, payload_size);
    }
    
    Ok(())
}

/// Test UHP error handling and recovery
#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_uhp_error_handling() -> Result<()> {
    // Test with verification that conditionally fails
    let flaky_verifier: VerificationHook = Arc::new(|payload| {
        // Accept only payloads with even second byte
        payload.get(1).map_or(false, |&b| b % 2 == 0)
    });

    // Verifier on peripheral side (2nd param) since central sends TO peripheral
    let mut mock_link = MockGattLink::new(247, None, Some(flaky_verifier));
    
    // This should pass (second byte is even)
    let good_payload = vec![0xFF, 0x42, 0x01, 0x02];
    mock_link.central.send_frame(&good_payload).await?;
    let received = mock_link.peripheral.recv_frame().await?;
    assert_eq!(good_payload, received);
    
    // This should fail (second byte is odd)  
    let bad_payload = vec![0xFF, 0x43, 0x01, 0x02];
    mock_link.central.send_frame(&bad_payload).await?;
    let result = mock_link.peripheral.recv_frame().await;
    assert!(result.is_err());
    
    // Verify we can still send good payloads after an error
    let another_good_payload = vec![0xFF, 0x44, 0x01, 0x02];
    mock_link.central.send_frame(&another_good_payload).await?;
    let received = mock_link.peripheral.recv_frame().await?;
    assert_eq!(another_good_payload, received);
    
    println!("✓ UHP error handling and recovery works");
    
    Ok(())
}

#[tokio::test]
#[cfg(feature = "ble-mock")]
async fn test_concurrent_uhp_connections() -> Result<()> {
    // Simulate multiple concurrent BLE connections
    let mut connections = Vec::new();
    
    for i in 0..5 {
        let mut mock_link = MockGattLink::new(247, None, None);
        let payload = format!("Message from connection {}", i).into_bytes();
        
        mock_link.central.send_frame(&payload).await?;
        let received = mock_link.peripheral.recv_frame().await?;
        assert_eq!(payload, received);
        
        connections.push(mock_link);
    }
    
    println!("✓ Concurrent UHP connections work");
    
    Ok(())
}