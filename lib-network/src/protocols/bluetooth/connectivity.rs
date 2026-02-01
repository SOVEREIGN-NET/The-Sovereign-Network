//! Connectivity helpers for Bluetooth mesh protocol.

#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::anyhow;
use anyhow::Result;
use tracing::info;

use super::device::MeshPeer;
use super::{BluetoothConnection, BluetoothMeshProtocol};

#[cfg(target_os = "macos")]
use std::sync::Arc;

#[cfg(target_os = "macos")]
use tokio::sync::RwLock;

#[cfg(target_os = "macos")]
use super::macos_core::CoreBluetoothManager;

impl BluetoothMeshProtocol {
    #[cfg(target_os = "macos")]
    pub(crate) async fn connect_mesh_peer(
        peer: &MeshPeer,
        _device_id: [u8; 6],
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<BluetoothConnection> {
        info!(" Establishing mesh connection to: {}", peer.address);
        let connection = Self::macos_connect_mesh_peer(peer, core_bt).await?;
        info!(" BLE connection established to {}", peer.address);
        Ok(connection)
    }

    #[cfg(not(target_os = "macos"))]
    pub(crate) async fn connect_mesh_peer(
        peer: &MeshPeer,
        _device_id: [u8; 6],
    ) -> Result<BluetoothConnection> {
        info!(" Establishing mesh connection to: {}", peer.address);

        let connection = {
            #[cfg(target_os = "linux")]
            {
                Self::linux_connect_mesh_peer(peer).await?
            }

            #[cfg(target_os = "windows")]
            {
                Self::windows_connect_mesh_peer(peer).await?
            }

            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                return Err(anyhow!("Platform not supported for BLE connections"));
            }
        };

        info!(" BLE connection established to {}", peer.address);
        Ok(connection)
    }


    #[cfg(target_os = "linux")]
    async fn linux_connect_mesh_peer(peer: &MeshPeer) -> Result<BluetoothConnection> {
        use crate::protocols::bluetooth::linux_ops::LinuxBluetoothOps;
        use tokio::runtime::Handle;

        info!("Linux: Connecting to mesh peer {}", peer.address);

        let peer_clone = peer.clone();

        tokio::task::spawn_blocking(move || {
            Handle::current().block_on(async {
                let bt_ops = LinuxBluetoothOps::new();
                bt_ops.connect_device(&peer_clone.address).await?;

                Ok(BluetoothConnection {
                    peer_id: peer_clone.peer_id.clone(),
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    mtu: 247,
                    address: peer_clone.address.clone(),
                    last_seen: peer_clone.last_seen,
                    rssi: peer_clone.rssi,
                })
            })
        })
        .await
        .map_err(|e| anyhow!("Linux connect task failed: {}", e))?
    }

    #[cfg(target_os = "windows")]
    async fn windows_connect_mesh_peer(peer: &MeshPeer) -> Result<BluetoothConnection> {
        use crate::protocols::bluetooth::windows_gatt::WindowsGattManager;

        info!("Windows: Mesh connection to {}", peer.address);

        let gatt_manager = WindowsGattManager::new()?;
        gatt_manager.connect_device(&peer.address).await?;

        let services = gatt_manager.discover_services(&peer.address).await?;
        info!(" Windows: Connected to {} with {} services", peer.address, services.len());

        Ok(BluetoothConnection {
            peer_id: peer.peer_id.clone(),
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mtu: 247,
            address: peer.address.clone(),
            last_seen: peer.last_seen,
            rssi: peer.rssi,
        })
    }

    // macOS-specific connection wiring moved to bluetooth::macos module.

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_address: &str) -> Result<()> {
        info!(" Disconnecting from Bluetooth peer: {}", peer_address);

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let _ = Command::new("bluetoothctl")
                .args(&["disconnect", peer_address])
                .output();
        }

        #[cfg(target_os = "windows")]
        {
            #[cfg(feature = "windows-gatt")]
            {
                use windows::Devices::Bluetooth::BluetoothLEDevice;

                let bluetooth_address = self.parse_windows_bluetooth_address(peer_address)?;

                if let Ok(device_async) = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address) {
                    if let Ok(device) = device_async.get() {
                        drop(device);
                    }
                }
            }

            #[cfg(not(feature = "windows-gatt"))]
            {
                use std::process::Command;
                let _ = Command::new("powershell")
                    .args(&["-Command", &format!("Remove-NetRoute -DestinationPrefix '*{}*' -Confirm:$false", peer_address)])
                    .output();
                info!("Windows: Attempted disconnect via PowerShell");
            }
        }

        let mut connections = self.current_connections.write().await;
        connections.remove(peer_address);

        info!("Disconnected from Bluetooth peer: {}", peer_address);
        Ok(())
    }

    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        let connections = self.current_connections.read().await;
        connections.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::BluetoothMeshProtocol;
    use lib_crypto::KeyPair;

    #[tokio::test]
    async fn test_get_connected_peers_empty() {
        let node_id = [8u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let peers = protocol.get_connected_peers().await;
        assert!(peers.is_empty());
    }
}
