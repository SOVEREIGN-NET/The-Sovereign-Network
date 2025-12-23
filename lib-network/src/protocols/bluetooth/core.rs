//! Core (non-platform-specific) helpers for Bluetooth mesh protocol.

use anyhow::Result;
use tracing::info;

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Setup quantum-resistant zero-knowledge mesh protocols
    pub(crate) async fn setup_zk_mesh_protocols(&self) -> Result<()> {
        info!(" DEBUG: setup_zk_mesh_protocols() ENTRY POINT");
        info!("Setting up quantum-resistant ZK mesh protocols...");

        let lib_mesh_service = crate::constants::BLE_MESH_SERVICE_UUID;
        let zk_auth_char = crate::constants::BLE_ZK_AUTH_CHAR_UUID;
        let quantum_routing_char = crate::constants::BLE_QUANTUM_ROUTING_CHAR_UUID;
        let mesh_data_char = crate::constants::BLE_MESH_DATA_CHAR_UUID;
        let mesh_coord_char = crate::constants::BLE_MESH_COORD_CHAR_UUID;

        info!(" DEBUG: About to call register_mesh_gatt_service...");
        self.register_mesh_gatt_service(
            lib_mesh_service,
            vec![zk_auth_char, quantum_routing_char, mesh_data_char, mesh_coord_char],
        )
        .await?;
        info!(" DEBUG: register_mesh_gatt_service completed!");

        info!("Quantum-resistant mesh protocols ready for peer-to-peer communication");
        Ok(())
    }
}
