//! Mesh messaging over Bluetooth LE.

use anyhow::{anyhow, Result};
use tracing::info;

use crate::constants::{BLE_MESH_DATA_CHAR_UUID, BLE_MESH_SERVICE_UUID};

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Send mesh message via Bluetooth LE
    pub async fn send_mesh_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        info!(
            " Sending Bluetooth LE mesh message to {}: {} bytes",
            target_address,
            message.len()
        );

        let connections = self.current_connections.read().await;
        if !connections.contains_key(target_address) {
            return Err(anyhow!("Peer not connected: {}", target_address));
        }

        let connection = connections.get(target_address).unwrap();
        let ble_mtu = connection.mtu as usize;

        if message.len() <= ble_mtu {
            self.transmit_mesh_packet(message, target_address).await?;
        } else {
            let chunks: Vec<&[u8]> = message.chunks(ble_mtu).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                info!(
                    "Sending fragment {}/{} ({} bytes)",
                    i + 1,
                    chunks.len(),
                    chunk.len()
                );
                self.transmit_mesh_packet(chunk, target_address).await?;
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        }

        drop(connections);
        let mut connections_mut = self.current_connections.write().await;
        if let Some(conn) = connections_mut.get_mut(target_address) {
            conn.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        Ok(())
    }

    /// Transmit packet via mesh networking
    async fn transmit_mesh_packet(&self, data: &[u8], address: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.linux_transmit_gatt(data, address).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_transmit_ble(data, address).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_transmit_gatt(data, address).await?;
        }

        Ok(())
    }

    /// macOS GATT transmission
    #[cfg(target_os = "macos")]
    async fn macos_transmit_gatt(&self, data: &[u8], address: &str) -> Result<()> {
        info!(" macOS: Transmitting {} bytes via GATT to {}", data.len(), address);

        let core_bt = self.core_bluetooth.read().await;
        let manager = core_bt
            .as_ref()
            .ok_or_else(|| anyhow!("Core Bluetooth not initialized"))?;

        let identifier = address.strip_prefix("gatt://").unwrap_or(address);

        let service_uuid = BLE_MESH_SERVICE_UUID;
        let mesh_data_char = BLE_MESH_DATA_CHAR_UUID;

        let is_connected_central = manager.is_connected_central(identifier).await;

        if is_connected_central {
            info!(" macOS: Sending notification to connected central {}", identifier);
            manager.send_notification(mesh_data_char, data).await?;
        } else {
            info!(" macOS: Writing to discovered peripheral {}", identifier);
            manager
                .write_characteristic(identifier, service_uuid, mesh_data_char, data)
                .await?;
        }

        info!(" macOS: Successfully transmitted {} bytes to {}", data.len(), address);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn linux_transmit_gatt(&self, data: &[u8], address: &str) -> Result<()> {
        use std::process::Command;

        let hex_data = data.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let output = Command::new("gatttool")
            .args(&["-b", address, "--char-write-req", "-a", "0x0012", "-n", &hex_data])
            .output();

        if let Ok(result) = output {
            let output_str = String::from_utf8_lossy(&result.stdout);
            if !output_str.contains("successfully") {
                tracing::warn!("GATT write may have failed: {}", output_str);
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn windows_transmit_ble(&self, data: &[u8], address: &str) -> Result<()> {
        info!("Windows: Transmitting {} bytes via BLE to {}", data.len(), address);

        #[cfg(feature = "windows-gatt")]
        {
            use windows::{
                Devices::Bluetooth::BluetoothLEDevice,
                Devices::Bluetooth::GenericAttributeProfile::*,
                Storage::Streams::*,
            };

            let bluetooth_address = self.parse_windows_bluetooth_address(address)?;

            let device_async = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address)
                .map_err(|e| anyhow!("Failed to get BLE device: {:?}", e))?;
            let device = device_async
                .get()
                .map_err(|e| anyhow!("Failed to await BLE device: {:?}", e))?;

            let services_result_async = device
                .GetGattServicesAsync()
                .map_err(|e| anyhow!("Failed to get GATT services: {:?}", e))?;
            let services_result = services_result_async
                .get()
                .map_err(|e| anyhow!("Failed to await GATT services: {:?}", e))?;

            if services_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT services discovery failed"));
            }

            let services = services_result.Services()?;

            let zhtp_service_uuid = windows::core::GUID::from(BLE_MESH_SERVICE_UUID);
            let mesh_data_char_uuid = windows::core::GUID::from(BLE_MESH_DATA_CHAR_UUID);

            let mut zhtp_service = None;
            for i in 0..services.Size()? {
                let service = services.GetAt(i)?;
                if service.Uuid()? == zhtp_service_uuid {
                    zhtp_service = Some(service);
                    break;
                }
            }

            let zhtp_service =
                zhtp_service.ok_or_else(|| anyhow!("ZHTP mesh service not found"))?;

            let chars_result_async = zhtp_service
                .GetCharacteristicsAsync()
                .map_err(|e| anyhow!("Failed to get GATT characteristics: {:?}", e))?;
            let chars_result = chars_result_async
                .get()
                .map_err(|e| anyhow!("Failed to await GATT characteristics: {:?}", e))?;

            if chars_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT characteristic discovery failed"));
            }

            let chars = chars_result.Characteristics()?;

            let mut mesh_char = None;
            for i in 0..chars.Size()? {
                let chr = chars.GetAt(i)?;
                if chr.Uuid()? == mesh_data_char_uuid {
                    mesh_char = Some(chr);
                    break;
                }
            }

            let mesh_char = mesh_char.ok_or_else(|| anyhow!("Mesh data characteristic not found"))?;

            let mut writer = DataWriter::new()?;
            writer.WriteBytes(data)?;
            let data_buffer = writer.DetachBuffer()?;

            let write_result_async = mesh_char
                .WriteValueWithResultAsync(&data_buffer)
                .map_err(|e| anyhow!("Failed to write GATT value: {:?}", e))?;
            let write_result = write_result_async
                .get()
                .map_err(|e| anyhow!("Failed to await GATT write: {:?}", e))?;

            if write_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT write failed"));
            }
        }

        #[cfg(not(feature = "windows-gatt"))]
        {
            let _ = address;
            let _ = data;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[tokio::test]
    async fn test_send_mesh_message_requires_connection() {
        let node_id = [5u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let err = protocol
            .send_mesh_message("peer-missing", b"payload")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Peer not connected"));
    }
}
