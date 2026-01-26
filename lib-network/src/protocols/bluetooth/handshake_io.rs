//! Platform-specific MeshHandshake writers.

#[cfg(any(target_os = "linux", target_os = "windows", any(test, feature = "ble-mock")))]
use anyhow::{anyhow, Result};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tracing::{info, warn};

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Windows: Write MeshHandshake to peer via WinRT GATT
    #[cfg(target_os = "windows")]
    pub(crate) async fn windows_write_handshake(
        peer_address: &str,
        char_uuid: &str,
        data: &[u8],
    ) -> Result<()> {
        use crate::protocols::bluetooth::windows_gatt::{GattEvent, WindowsGattManager};

        info!(" Windows: Writing handshake to {} via GATT", peer_address);

        let gatt_manager = WindowsGattManager::new()?;
        gatt_manager.initialize().await?;

        let (tx, mut rx) = WindowsGattManager::create_event_channel();
        gatt_manager.set_event_channel(tx).await?;

        gatt_manager.connect_device(peer_address).await?;

        let services = gatt_manager.discover_services(peer_address).await?;
        info!(
            " Windows: Discovered {} services on {}",
            services.len(),
            peer_address
        );

        let service_uuid = crate::constants::BLE_MESH_SERVICE_UUID;
        gatt_manager
            .write_characteristic(peer_address, service_uuid, char_uuid, data)
            .await?;

        info!(" Windows: Handshake written successfully");

        info!(
            " Windows: Enabling notifications on characteristic {}",
            char_uuid
        );

        let _ = gatt_manager.discover_services(peer_address).await;

        match gatt_manager.enable_notifications(peer_address, char_uuid).await {
            Ok(_) => {
                info!(
                    " Windows: Notifications enabled - handshake response will be received via ValueChanged events"
                );

                info!("⏳ Windows: Waiting for handshake ACK notification...");
                let timeout_duration = tokio::time::Duration::from_secs(5);

                match tokio::time::timeout(timeout_duration, async {
                    while let Some(event) = rx.recv().await {
                        match event {
                            GattEvent::CharacteristicValueChanged {
                                device_address,
                                char_uuid,
                                value,
                            } => {
                                info!(
                                    " Windows: Received notification from {} on char {}",
                                    device_address, char_uuid
                                );
                                info!("   Data: {} bytes: {:?}", value.len(), value);

                                if value.len() == 2 {
                                    let version = value[0];
                                    let status = value[1];
                                    match status {
                                        1 => {
                                            info!(
                                                " Handshake acknowledged by peer (version {}, status: Success)",
                                                version
                                            );
                                            return true;
                                        }
                                        _ => {
                                            warn!(
                                                " Handshake response: version {}, status: {}",
                                                version, status
                                            );
                                            return false;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    false
                })
                .await
                {
                    Ok(true) => info!(" Bidirectional handshake complete!"),
                    Ok(false) => warn!(" Handshake ACK received but status indicates failure"),
                    Err(_) => {
                        warn!("⏰ Timeout waiting for handshake ACK notification (peer may not have responded)");
                    }
                }
            }
            Err(e) => {
                warn!(
                    " Windows: Failed to enable notifications: {} (handshake sent, but response may not be received)",
                    e
                );
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        drop(gatt_manager);

        Ok(())
    }

    /// Linux: Write MeshHandshake to peer via BlueZ
    #[cfg(target_os = "linux")]
    pub(crate) async fn linux_write_handshake(
        peer_address: &str,
        char_uuid: &str,
        data: &[u8],
    ) -> Result<()> {
        use crate::protocols::bluetooth::linux_ops::LinuxBluetoothOps;
        use tokio::runtime::Handle;

        info!("🐧 Linux: Writing handshake to {} via BlueZ", peer_address);

        let peer_address = peer_address.to_string();
        let char_uuid = char_uuid.to_string();
        let data = data.to_vec();

        tokio::task::spawn_blocking(move || {
            Handle::current().block_on(async {
                let bt_ops = LinuxBluetoothOps::new();

                bt_ops.connect_device(&peer_address).await?;
                bt_ops
                    .write_gatt_characteristic(&peer_address, &char_uuid, &data)
                    .await?;

                info!(" Linux: Handshake written successfully");
                Ok(())
            })
        })
        .await
        .map_err(|e| anyhow!("Linux handshake task failed: {}", e))?
    }
}

#[cfg(any(test, feature = "ble-mock"))]
impl BluetoothMeshProtocol {
    async fn write_handshake_via_backend(
        &self,
        peer_address: &str,
        char_uuid: &str,
        data: &[u8],
    ) -> Result<()> {
        if let Some(backend) = self.gatt_backend().await {
            return backend
                .write_characteristic(peer_address, char_uuid, data)
                .await;
        }

        Err(anyhow!("No GATT backend configured"))
    }
}

#[cfg(test)]
mod tests {
    use super::BluetoothMeshProtocol;
    use crate::protocols::bluetooth::gatt_backend::GattBackend;
    use anyhow::Result;
    use async_trait::async_trait;
    use lib_crypto::KeyPair;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockBackend {
        writes: Arc<Mutex<Vec<(String, String, Vec<u8>)>>>,
    }

    #[async_trait]
    impl GattBackend for MockBackend {
        async fn read_characteristic(&self, _device_address: &str, _char_uuid: &str) -> Result<Vec<u8>> {
            Ok(vec![])
        }

        async fn write_characteristic(
            &self,
            device_address: &str,
            char_uuid: &str,
            data: &[u8],
        ) -> Result<()> {
            self.writes.lock().unwrap().push((
                device_address.to_string(),
                char_uuid.to_string(),
                data.to_vec(),
            ));
            Ok(())
        }

        async fn discover_services(&self, _device_address: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }

        async fn enable_notifications(&self, _device_address: &str, _char_uuid: &str) -> Result<()> {
            Ok(())
        }

        async fn disable_notifications(&self, _device_address: &str, _char_uuid: &str) -> Result<()> {
            Ok(())
        }

        async fn wait_for_notification(
            &self,
            _device_address: &str,
            _char_uuid: &str,
        ) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    fn protocol() -> BluetoothMeshProtocol {
        let node_id = [7u8; 32];
        let keypair = KeyPair::generate().unwrap();
        BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap()
    }

    #[tokio::test]
    async fn test_write_handshake_via_backend() {
        let backend = Arc::new(MockBackend::default());
        let protocol = protocol();
        protocol.set_gatt_backend(backend.clone()).await;

        let data = vec![1, 2];
        protocol
            .write_handshake_via_backend("peer", "char", &data)
            .await
            .unwrap();

        let writes = backend.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "peer");
        assert_eq!(writes[0].1, "char");
        assert_eq!(writes[0].2, data);
    }
}
