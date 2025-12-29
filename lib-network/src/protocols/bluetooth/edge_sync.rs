//! Edge sync helpers for BLE transport.

use anyhow::Result;
use tracing::{debug, info};

use crate::network_output::{global_output_queue, NetworkOutput};

use super::{gatt, BluetoothMeshProtocol};

impl BluetoothMeshProtocol {
    /// Handle edge node sync message (headers/proof requests from lightweight clients)
    pub async fn handle_edge_sync_message(
        &self,
        message: &gatt::EdgeSyncMessage,
        peer_address: &str,
    ) -> Result<Option<gatt::EdgeSyncMessage>> {
        global_output_queue()
            .push(NetworkOutput::EdgeSyncRequest {
                peer: peer_address.to_string(),
                message: message.clone(),
            })
            .await;

        Ok(None)
    }

    /// Send edge sync message via BLE (with fragmentation if needed)
    pub async fn send_edge_sync_message(
        &self,
        peer_address: &str,
        message: &gatt::EdgeSyncMessage,
    ) -> Result<()> {
        let data = gatt::GattMessage::serialize_edge_sync(message)?;

        if data.len() > 500 {
            info!(" Message {} bytes, fragmenting for BLE MTU", data.len());
            let message_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            let fragments = gatt::fragment_large_message(message_id, &data, 512);
            info!("📤 Sending {} fragments to {}", fragments.len(), peer_address);

            for (i, fragment) in fragments.iter().enumerate() {
                self.write_gatt_characteristic_with_discovery(
                    peer_address,
                    crate::constants::BLE_MESH_DATA_CHAR_UUID,
                    fragment,
                )
                .await?;
                debug!(
                    "   Fragment {}/{} sent ({} bytes)",
                    i + 1,
                    fragments.len(),
                    fragment.len()
                );
            }

            info!(" All {} fragments sent to {}", fragments.len(), peer_address);
        } else {
            self.write_gatt_characteristic_with_discovery(
                peer_address,
                crate::constants::BLE_MESH_DATA_CHAR_UUID,
                &data,
            )
            .await?;
            info!(
                " Sent edge sync message ({} bytes) to {}",
                data.len(),
                peer_address
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[test]
    fn test_edge_sync_serialization_roundtrip() {
        let msg = gatt::EdgeSyncMessage::HeadersRequest {
            request_id: 1,
            start_height: 10,
            count: 5,
        };

        let data = gatt::GattMessage::serialize_edge_sync(&msg).unwrap();
        assert!(data.len() > 2);
    }

    #[tokio::test]
    async fn test_handle_edge_sync_message_returns_none() {
        let node_id = [9u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let msg = gatt::EdgeSyncMessage::HeadersRequest {
            request_id: 2,
            start_height: 0,
            count: 1,
        };

        let result = protocol
            .handle_edge_sync_message(&msg, "peer-x")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
