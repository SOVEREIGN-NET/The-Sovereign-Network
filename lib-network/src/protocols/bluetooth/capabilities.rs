//! Capability helpers for Bluetooth mesh protocol.

use crate::protocols::zhtp_auth::NodeCapabilities;

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Get node capabilities for advertising
    pub fn get_node_capabilities(&self, has_dht: bool, reputation: u32) -> NodeCapabilities {
        NodeCapabilities {
            has_dht,
            can_relay: true,
            max_bandwidth: 250_000,
            protocols: vec!["bluetooth".to_string(), "zhtp".to_string()],
            reputation,
            quantum_secure: true,
        }
    }
}
