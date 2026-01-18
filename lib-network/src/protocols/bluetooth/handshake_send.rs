//! MeshHandshake send helpers for Bluetooth mesh protocol.

use anyhow::Result;
#[cfg(not(target_os = "macos"))]
use tracing::info;

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Send MeshHandshake to a connected BLE peer (non-macOS version)
    #[cfg(not(target_os = "macos"))]
    pub(crate) async fn send_mesh_handshake_to_peer(
        peer_address: &str,
        node_id: [u8; 32],
        public_key: &lib_crypto::PublicKey,
    ) -> Result<()> {
        let handshake_data = Self::build_mesh_handshake(node_id, public_key)?;
        info!(
            " Sending {} byte handshake to {}",
            handshake_data.len(),
            peer_address
        );

        let mesh_data_char = crate::constants::BLE_MESH_DATA_CHAR_UUID;

        #[cfg(target_os = "windows")]
        {
            Self::windows_write_handshake(peer_address, mesh_data_char, &handshake_data).await?;
        }

        #[cfg(target_os = "linux")]
        {
            Self::linux_write_handshake(peer_address, mesh_data_char, &handshake_data).await?;
        }

        info!(" MeshHandshake sent successfully to {}", peer_address);
        Ok(())
    }

    pub(crate) fn build_mesh_handshake(
        node_id: [u8; 32],
        public_key: &lib_crypto::PublicKey,
    ) -> Result<Vec<u8>> {
        use crate::handshake::{HandshakeCapabilities, PqcCapability};
        use uuid::Uuid;

        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&node_id[..16]);

        let handshake = super::MeshHandshake {
            version: 1,
            node_id: Uuid::from_bytes(uuid_bytes),
            public_key: public_key.clone(),
            mesh_port: 9333,
            protocols: vec!["ble".to_string(), "zhtp".to_string(), "relay".to_string()],
            discovered_via: 1,
            capabilities: HandshakeCapabilities {
                protocols: vec!["ble".to_string(), "zhtp".to_string()],
                max_throughput: 250_000,
                max_message_size: 512,
                encryption_methods: vec!["chacha20-poly1305".to_string()],
                pqc_capability: PqcCapability::Kyber1024Dilithium5,
                dht_capable: false,
                relay_capable: false,
                storage_capacity: 0,
                web4_capable: false,
                custom_features: vec![],
            },
        };

        let handshake_data = bincode::serialize(&handshake)
            .map_err(|e| anyhow::anyhow!("Failed to serialize handshake: {}", e))?;
        Ok(handshake_data)
    }
}
