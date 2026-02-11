//! Discovery and mesh advertising for Bluetooth LE.

use anyhow::{anyhow, Result};
use tracing::{info, warn};

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::constants::BLE_MESH_SERVICE_UUID;

use super::device::{BleDevice, MeshPeer};
use super::BluetoothMeshProtocol;
use super::device;

use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
use super::macos_core::CoreBluetoothManager;

#[cfg(target_os = "windows")]
use super::windows_gatt::{GattEvent, WindowsGattManager};

impl BluetoothMeshProtocol {
    /// Generate ephemeral discovery address that rotates periodically
    #[allow(dead_code)]
    pub(crate) fn generate_ephemeral_address(&self, secure_node_id: &[u8; 32]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secure_node_id);
        hasher.update(b"ZHTP_EPHEMERAL");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        hasher.update(&(timestamp / 900).to_le_bytes());
        let hash = hasher.finalize();

        format!(
            "zhtp:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
        )
    }

    /// Verify if an ephemeral address belongs to a secure node ID
    fn verify_ephemeral_address(&self, address: &str, secure_node_id: &[u8; 32]) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for time_offset in [0, 900] {
            let check_time = (current_time - time_offset) / 900;
            let mut hasher = Sha256::new();
            hasher.update(secure_node_id);
            hasher.update(b"ZHTP_EPHEMERAL");
            hasher.update(&check_time.to_le_bytes());
            let hash = hasher.finalize();

            let expected = format!(
                "zhtp:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]
            );

            if address == expected {
                return true;
            }
        }
        false
    }

    /// Track a discovered device using secure identifiers
    pub(crate) async fn track_device(
        &self,
        _raw_mac: &[u8; 6],
        device_info: BleDevice,
    ) -> Result<()> {
        let mut devices = self.tracked_devices.write().await;
        let mut mapping = self.address_mapping.write().await;

        let secure_id_str = hex::encode(device_info.secure_node_id);

        devices.insert(secure_id_str.clone(), device_info.clone());
        mapping.insert(secure_id_str.clone(), device_info.ephemeral_address.clone());

        info!(
            " Tracking device with secure ID: {} -> {}",
            &secure_id_str[..16],
            device_info.ephemeral_address
        );
        Ok(())
    }

    /// Create secure tracked device from raw MAC (internal use only)
    #[allow(dead_code)]
    pub fn create_secure_tracked_device(
        &self,
        raw_mac: &[u8; 6],
        device_name: Option<String>,
    ) -> BleDevice {
        let secure_node_id = self.generate_secure_node_id(raw_mac);
        let encrypted_mac_hash = self.generate_encrypted_mac_hash(raw_mac);
        let ephemeral_address = self.generate_ephemeral_address(&secure_node_id);

        BleDevice {
            encrypted_mac_hash,
            secure_node_id,
            ephemeral_address,
            device_name,
            services: Vec::new(),
            characteristics: std::collections::HashMap::new(),
            connection_handle: None,
            connection_state: device::ConnectionState::Disconnected,
            signal_strength: -70,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Get device by secure node ID or ephemeral address
    pub(crate) async fn get_tracked_device(&self, identifier: &str) -> Option<BleDevice> {
        let devices = self.tracked_devices.read().await;

        if let Some(device) = devices.get(identifier) {
            return Some(device.clone());
        }

        for device in devices.values() {
            if device.ephemeral_address == identifier
                || self.verify_ephemeral_address(identifier, &device.secure_node_id)
            {
                return Some(device.clone());
            }
        }
        None
    }

    /// Resolve device address to D-Bus path using ephemeral address
    #[allow(dead_code)]
    pub async fn resolve_device_address(&self, identifier: &str) -> Result<String> {
        if let Some(device) = self.get_tracked_device(identifier).await {
            let ephemeral_parts: Vec<&str> = device.ephemeral_address.split(':').collect();
            let dbus_path = if ephemeral_parts.len() >= 6 {
                format!(
                    "dev_{}_{}_{}_{}_{}_{}",
                    ephemeral_parts[1],
                    ephemeral_parts[2],
                    ephemeral_parts[3],
                    ephemeral_parts[4],
                    ephemeral_parts[5],
                    ephemeral_parts[6]
                )
            } else {
                let node_id_hex = hex::encode(&device.secure_node_id[..6]);
                format!(
                    "dev_{}_{}_{}_{}_{}_{}",
                    &node_id_hex[0..2],
                    &node_id_hex[2..4],
                    &node_id_hex[4..6],
                    &node_id_hex[6..8],
                    &node_id_hex[8..10],
                    &node_id_hex[10..12]
                )
            };
            Ok(dbus_path)
        } else {
            self.discover_specific_device(identifier).await?;
            if let Some(device) = self.get_tracked_device(identifier).await {
                let node_id_hex = hex::encode(&device.secure_node_id[..6]);
                Ok(format!(
                    "dev_{}_{}_{}_{}_{}_{}",
                    &node_id_hex[0..2],
                    &node_id_hex[2..4],
                    &node_id_hex[4..6],
                    &node_id_hex[6..8],
                    &node_id_hex[8..10],
                    &node_id_hex[10..12]
                ))
            } else {
                Err(anyhow!("Device not found: {}", identifier))
            }
        }
    }

    /// Discover specific device by address
    #[allow(dead_code)]
    async fn discover_specific_device(&self, address: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.linux_discover_device(address).await
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_discover_device(address).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_discover_device(address).await
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_discover_device(address).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Err(anyhow!("Device discovery not supported on this platform"))
        }
    }

    /// Start Bluetooth LE discovery
    pub async fn start_discovery(&mut self) -> Result<()> {
        // DEFENSIVE GUARD: Check if Bluetooth is enabled (SAFETY LAYER)
        // This prevents accidental execution even if filtering misses it at the boundary
        if !self.enabled {
            return Err(anyhow!(
                "Bluetooth LE discovery refused: disabled in configuration (enable_bluetooth=false). \
                Defensive guard preventing disabled protocol from starting."
            ));
        }

        info!("Starting Bluetooth LE mesh discovery...");

        // Initialize Bluetooth stack for mesh networking
        info!(" DEBUG: About to initialize_bluetooth_stack...");
        self.initialize_bluetooth_stack().await?;
        info!(" DEBUG: Bluetooth stack initialized, now setting up ZK mesh protocols...");

        // Setup quantum-resistant ZK mesh protocols
        self.setup_zk_mesh_protocols().await?;
        info!(" DEBUG: ZK mesh protocols setup complete!");

        // Start advertising ZHTP mesh network
        self.start_real_mesh_advertising().await?;

        // Begin peer discovery and mesh routing
        self.start_mesh_peer_discovery().await?;

        self.discovery_active = true;
        info!("Bluetooth LE mesh discovery started");
        Ok(())
    }

    /// Start mesh advertising for peer-to-peer networking
    async fn start_real_mesh_advertising(&self) -> Result<()> {
        info!("Broadcasting ZHTP P2P mesh network...");

        #[cfg(target_os = "windows")]
        {
            info!(" Windows: Mesh advertising active via GATT service");
            info!("   GATT Service UUID: {}(v2)", BLE_MESH_SERVICE_UUID);
            info!("   Mesh capabilities available through GATT characteristics");
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mesh_adv_data = self.create_mesh_advertisement_data().await?;
            self.broadcast_mesh_advertisement(&mesh_adv_data).await?;
        }

        info!("P2P MESH broadcasting on Bluetooth LE");
        Ok(())
    }

    /// Create proper ZHTP mesh advertisement data
    async fn create_mesh_advertisement_data(&self) -> Result<Vec<u8>> {
        let mut adv_data = Vec::new();

        // 1. Flags
        adv_data.push(0x02);
        adv_data.push(0x01);
        adv_data.push(0x06);

        // 2. Complete Local Name: "ZHTP-MESH"
        let name = b"ZHTP-MESH";
        adv_data.push(name.len() as u8 + 1);
        adv_data.push(0x09);
        adv_data.extend_from_slice(name);

        // 3. 128-bit Service UUID: ZHTP Mesh Service
        adv_data.push(0x11);
        adv_data.push(0x07);
        let service_uuid = [
            0xca, 0x30, 0xd4, 0x30, 0xc0, 0x00, 0xb4, 0x80, 0xd1, 0x11, 0xad, 0x9d, 0x10,
            0xb8, 0xa7, 0x6b,
        ];
        adv_data.extend_from_slice(&service_uuid);

        // 4. Manufacturer Data: ZHTP Mesh Capabilities
        adv_data.push(0x07);
        adv_data.push(0xFF);
        adv_data.push(0xFF);
        adv_data.push(0xFF);
        adv_data.push(0x02);
        adv_data.push(0x01);
        adv_data.push(0x3F);
        adv_data.push(0x00);

        info!("Created ZHTP mesh advertisement: {} bytes", adv_data.len());
        Ok(adv_data)
    }

    /// Start mesh peer discovery for P2P networking
    async fn start_mesh_peer_discovery(&self) -> Result<()> {
        info!("Scanning for ZHTP mesh peers...");

        let connections = self.current_connections.clone();
        let device_id = self.device_id;
        let node_id = self.node_id;
        let public_key = self.public_key.clone();

        #[cfg(target_os = "macos")]
        let core_bt = self.core_bluetooth.clone();

        tokio::spawn(async move {
            let mut scan_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            scan_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                #[cfg(target_os = "macos")]
                let scan_result = Self::scan_for_mesh_peers(&core_bt).await;

                #[cfg(not(target_os = "macos"))]
                let scan_result = Self::scan_for_mesh_peers().await;

                if let Ok(peers) = scan_result {
                    info!(" DEBUG: Background scan found {} peers", peers.len());
                    let mut conns = connections.write().await;
                    info!(" DEBUG: Currently {} active connections", conns.len());

                    for peer in peers {
                        info!(
                            " DEBUG: Checking peer {} (already connected: {})",
                            peer.address,
                            conns.contains_key(&peer.address)
                        );
                        if !conns.contains_key(&peer.address) {
                            info!(" Attempting to connect to mesh peer: {}", peer.address);

                            #[cfg(target_os = "macos")]
                            let connect_result =
                                Self::connect_mesh_peer(&peer, device_id, &core_bt).await;

                            #[cfg(not(target_os = "macos"))]
                            let connect_result = Self::connect_mesh_peer(&peer, device_id).await;

                            if let Ok(connection) = connect_result {
                                conns.insert(peer.address.clone(), connection);
                                info!(" Connected to mesh peer: {}", peer.address);

                                drop(conns);

                                #[cfg(target_os = "macos")]
                                let handshake_result =
                                    Self::send_mesh_handshake_to_peer(
                                        &peer.address,
                                        node_id,
                                        &public_key,
                                        &core_bt,
                                    )
                                    .await;

                                #[cfg(not(target_os = "macos"))]
                                let handshake_result =
                                    Self::send_mesh_handshake_to_peer(
                                        &peer.address,
                                        node_id,
                                        &public_key,
                                    )
                                    .await;

                                if let Err(e) = handshake_result {
                                    warn!("Failed to send handshake to {}: {}", peer.address, e);
                                } else {
                                    info!("📤 Sent MeshHandshake to {}", peer.address);
                                }

                                conns = connections.write().await;
                            }
                        }
                    }
                }

                scan_interval.tick().await;
            }
        });

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn scan_for_mesh_peers(
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<Vec<MeshPeer>> {
        let mut peers = Vec::new();
        peers.extend(Self::macos_scan_mesh_peers(core_bt).await?);
        Ok(peers)
    }

    #[cfg(not(target_os = "macos"))]
    async fn scan_for_mesh_peers() -> Result<Vec<MeshPeer>> {
        let mut peers = Vec::new();

        #[cfg(target_os = "linux")]
        {
            peers.extend(Self::linux_scan_mesh_peers().await?);
        }

        #[cfg(target_os = "windows")]
        {
            peers.extend(Self::windows_scan_mesh_peers().await?);
        }

        Ok(peers)
    }

    #[cfg(target_os = "linux")]
    async fn linux_scan_mesh_peers() -> Result<Vec<MeshPeer>> {
        use crate::protocols::bluetooth::linux_ops::LinuxBluetoothOps;
        use tokio::runtime::Handle;

        info!("Linux: Scanning for ZHTP mesh peers...");

        tokio::task::spawn_blocking(move || {
            Handle::current().block_on(async {
                let bt_ops = LinuxBluetoothOps::new();
                let peers = bt_ops.scan_mesh_peers().await?;

                info!("Found {} SOV mesh peers on Linux", peers.len());
                Ok(peers)
            })
        })
        .await
        .map_err(|e| anyhow!("Linux scan task failed: {}", e))?
    }

    #[cfg(target_os = "windows")]
    async fn windows_scan_mesh_peers() -> Result<Vec<MeshPeer>> {
        info!("Windows: Scanning for ZHTP mesh peers using native GATT...");

        let gatt_manager = WindowsGattManager::new()?;
        gatt_manager.initialize().await?;

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        gatt_manager.set_event_channel(event_tx).await?;

        gatt_manager.start_discovery().await?;

        let mut peers = Vec::new();
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(15));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Some(GattEvent::DeviceDiscovered { address, name, rssi, advertisement_data: _ }) => {
                            let peer = MeshPeer {
                                peer_id: address.clone(),
                                address: address.clone(),
                                rssi,
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                mesh_capable: true,
                                services: vec![BLE_MESH_SERVICE_UUID.to_string()],
                                quantum_secure: true,
                            };
                            info!(
                                " Found ZHTP mesh peer: {} ({}) RSSI: {}",
                                name.as_deref().unwrap_or("Unknown"),
                                address,
                                rssi
                            );
                            peers.push(peer);
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = &mut timeout => break,
            }
        }

        gatt_manager.stop_discovery().await?;

        info!(" Found {} SOV mesh peers on Windows", peers.len());
        Ok(peers)
    }

    /// Check if advertisement data indicates ZHTP support
    #[allow(dead_code)]
    fn is_zhtp_advertisement(advertisement_data: &[u8]) -> bool {
        let zhtp_uuid_bytes = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f,
            0xd4, 0x30, 0xc8,
        ];

        if advertisement_data.len() >= 16 {
            for window in advertisement_data.windows(16) {
                if window == zhtp_uuid_bytes {
                    return true;
                }
            }
        }

        let ad_str = String::from_utf8_lossy(advertisement_data);
        ad_str.contains("ZHTP") || ad_str.contains("SOVNET")
    }

    /// Parse Windows PowerShell output for bypass peers
    #[allow(dead_code)]
    fn parse_windows_mesh_peer(line: &str) -> Option<MeshPeer> {
        if line.contains("ZHTP") {
            let address = format!("WIN-{:08X}", rand::random::<u32>());
            Some(MeshPeer {
                peer_id: address.clone(),
                address: address.clone(),
                rssi: -50,
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                mesh_capable: true,
                services: vec!["ZHTP-MESH".to_string()],
                quantum_secure: true,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[tokio::test]
    async fn test_create_mesh_advertisement_data() {
        let node_id = [7u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let data = protocol.create_mesh_advertisement_data().await.unwrap();
        assert!(data.len() >= 24);
        assert_eq!(data[0], 0x02);
        assert_eq!(data[1], 0x01);
        assert_eq!(data[2], 0x06);
        assert!(data.windows(9).any(|w| w == b"ZHTP-MESH"));
    }

    #[test]
    fn test_is_zhtp_advertisement() {
        let with_name = b"ZHTP-TEST";
        assert!(BluetoothMeshProtocol::is_zhtp_advertisement(with_name));

        let uuid_bytes = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f,
            0xd4, 0x30, 0xc8,
        ];
        assert!(BluetoothMeshProtocol::is_zhtp_advertisement(&uuid_bytes));
    }

    #[test]
    fn test_generate_and_verify_ephemeral_address() {
        let node_id = [3u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let secure_node_id = protocol.generate_secure_node_id(&[1, 2, 3, 4, 5, 6]);
        let ephemeral = protocol.generate_ephemeral_address(&secure_node_id);
        assert!(protocol.verify_ephemeral_address(&ephemeral, &secure_node_id));
    }
}
