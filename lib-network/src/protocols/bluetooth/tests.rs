use super::BluetoothMeshProtocol;
use lib_crypto::KeyPair;

#[tokio::test]
async fn test_bluetooth_mesh_creation() {
    let node_id = [1u8; 32];
    let keypair = KeyPair::generate().unwrap();
    let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key.clone()).unwrap();

    assert_eq!(protocol.node_id, node_id);
    assert!(!protocol.discovery_active);
}

#[tokio::test]
async fn test_bluetooth_disabled_guard() {
    // RUNTIME ASSERTION TEST: Verify defensive guard prevents execution when disabled
    // This ensures that even if config filtering fails, Bluetooth still refuses to start

    let node_id = [1u8; 32];
    let keypair = KeyPair::generate().unwrap();
    let mut protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key.clone()).unwrap();

    // SETUP: Simulate config disabling Bluetooth (as would be done by mesh server)
    protocol.set_enabled(false);

    // ASSERTION: Attempting to start discovery should fail with clear error
    let result = protocol.start_discovery().await;

    assert!(
        result.is_err(),
        "start_discovery() should fail when enabled=false (defensive guard)"
    );

    // ASSERTION: Error message should indicate config reason
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("disabled in configuration"),
        "Error should mention config reason, got: {}",
        error_msg
    );
}

// TECH DEBT: This test is ignored due to macOS Core Bluetooth cleanup issue
//
// Problem: On macOS, initializing Core Bluetooth creates Objective-C objects and system
// threads that don't properly clean up when the test ends. This causes SIGABRT during
// test harness shutdown, failing the test suite with exit code 101 even though the
// test itself passes.
//
// Root Cause: start_discovery() -> init_corebluetooth() -> initialize_core_bluetooth()
// creates CBCentralManager and CBPeripheralManager which use dispatch queues and ARC.
//
// Solution Options:
// 1. Implement proper async shutdown/cleanup in BluetoothMeshProtocol::drop()
// 2. Add explicit shutdown() method and call it at end of test
// 3. Use #[cfg(not(target_os = "macos"))] to skip on macOS
//
// For now: Marked with #[ignore] to unblock CI/CD. Run manually with:
// cargo test --lib -p lib-network test_bluetooth_discovery -- --ignored
//
// Issue tracked in: [Add issue link when created]
#[tokio::test]
#[ignore = "macOS Core Bluetooth cleanup causes SIGABRT - see tech debt comment above"]
async fn test_bluetooth_discovery() {
    let node_id = [1u8; 32];
    let keypair = KeyPair::generate().unwrap();
    let mut protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

    let result = protocol.start_discovery().await;
    assert!(result.is_ok());
}
