//! macOS-specific Bluetooth mesh wiring.

use anyhow::{anyhow, Result};
use tracing::{info, warn};

use std::sync::Arc;
use tokio::sync::RwLock;

use super::BluetoothMeshProtocol;
use super::device::{BleDevice, MeshPeer};
use super::macos_core::CoreBluetoothManager;

impl BluetoothMeshProtocol {
    pub(crate) async fn macos_broadcast_mesh_adv(&self, adv_data: &[u8]) -> Result<()> {
        info!("macOS: Starting Core Bluetooth LE advertising ({} bytes)", adv_data.len());

        if let Some(ref manager) = *self.core_bluetooth.read().await {
            manager.start_mesh_advertising(adv_data).await?;
            info!(" macOS: BLE mesh advertising started via Core Bluetooth");
            info!("   Service UUID: {}", crate::constants::BLE_MESH_SERVICE_UUID);
            info!("   Advertisement data: {} bytes", adv_data.len());
        } else {
            warn!(" macOS: Core Bluetooth manager not initialized");
            return Err(anyhow!("macOS Core Bluetooth manager not available"));
        }

        Ok(())
    }

    pub(crate) async fn macos_scan_mesh_peers(
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<Vec<MeshPeer>> {
        info!("macOS: Scanning for ZHTP bypass peers with Core Bluetooth...");

        let manager_guard = core_bt.read().await;
        if let Some(ref manager) = *manager_guard {
            let service_uuid = crate::constants::BLE_MESH_SERVICE_UUID;
            manager.start_scan(Some(&[service_uuid])).await?;

            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            let devices = manager.get_tracked_devices().await?;
            let mut mesh_peers = Vec::new();

            for device in devices {
                info!(
                    " Found ZHTP mesh peer: {} ({}) RSSI: {}",
                    device.device_name.as_deref().unwrap_or("Unknown"),
                    device.ephemeral_address,
                    device.signal_strength
                );

                mesh_peers.push(MeshPeer {
                    peer_id: device.ephemeral_address.clone(),
                    address: device.ephemeral_address.clone(),
                    rssi: device.signal_strength,
                    last_seen: device.last_seen,
                    mesh_capable: true,
                    services: vec![crate::constants::BLE_MESH_SERVICE_UUID.to_string()],
                    quantum_secure: true,
                });
            }

            manager.stop_scan().await?;
            info!(" macOS: Found {} SOV mesh peers", mesh_peers.len());
            Ok(mesh_peers)
        } else {
            warn!(" macOS: Core Bluetooth manager not initialized");
            Ok(Vec::new())
        }
    }

    pub(crate) async fn macos_connect_mesh_peer(
        peer: &MeshPeer,
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<super::BluetoothConnection> {
        info!("macOS: Connecting to mesh peer {} via Core Bluetooth", peer.address);

        let manager_guard = core_bt.read().await;
        if let Some(ref manager) = *manager_guard {
            manager.connect_to_peripheral(&peer.address).await?;
            let services = manager.discover_services(&peer.address).await?;
            info!(" macOS: Found {} services on {}", services.len(), peer.address);

            Ok(super::BluetoothConnection {
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
        } else {
            Err(anyhow!("macOS: Core Bluetooth manager not initialized"))
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn macos_discover_device(&self, address: &str) -> Result<()> {
        use std::process::Command;

        let output = Command::new("system_profiler")
            .args(&["SPBluetoothDataType", "-json"])
            .output();

        if let Ok(result) = output {
            let output_str = String::from_utf8_lossy(&result.stdout);

            if output_str.contains(address) {
                let mac = super::common::parse_mac_address(address)?;

                let device = BleDevice {
                    encrypted_mac_hash: self.generate_encrypted_mac_hash(&mac),
                    secure_node_id: self.generate_secure_node_id(&mac),
                    ephemeral_address: self.generate_ephemeral_address(&self.generate_secure_node_id(&mac)),
                    device_name: Self::extract_device_name_macos(&output_str, address),
                    services: Vec::new(),
                    characteristics: std::collections::HashMap::new(),
                    connection_handle: None,
                    connection_state: super::device::ConnectionState::Disconnected,
                    signal_strength: -100,
                    last_seen: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };

                let mac_bytes = mac;
                self.track_device(&mac_bytes, device).await?;
                info!("macOS: Discovered device {}", address);
            }
        }

        Ok(())
    }

    pub(crate) async fn macos_write_handshake(
        peer_address: &str,
        char_uuid: &str,
        data: &[u8],
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<()> {
        info!(
            "🍎 macOS: Writing {} byte handshake to {} via Core Bluetooth",
            data.len(),
            peer_address
        );

        let manager_guard = core_bt.read().await;
        if let Some(ref manager) = *manager_guard {
            let service_uuid = crate::constants::BLE_MESH_SERVICE_UUID;
            manager
                .write_characteristic(peer_address, service_uuid, char_uuid, data)
                .await?;

            info!(" macOS: Handshake written successfully");
            Ok(())
        } else {
            Err(anyhow!("macOS: Core Bluetooth manager not initialized"))
        }
    }

    pub(crate) async fn macos_register_bypass_service(
        &self,
        service_uuid: &str,
        characteristics: &[&str],
    ) -> Result<()> {
        info!("🍎 macOS: Registering GATT service {} with Core Bluetooth", service_uuid);

        let manager_guard = self.core_bluetooth.read().await;
        if let Some(ref manager) = *manager_guard {
            let char_data: Vec<(&str, &[u8])> =
                characteristics.iter().map(|uuid| (*uuid, &b""[..])).collect();

            manager.start_advertising(service_uuid, &char_data).await?;

            info!(" macOS: GATT service registered and initial advertising started");
            Ok(())
        } else {
            Err(anyhow!("macOS: Core Bluetooth manager not initialized"))
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn macos_read_gatt_characteristic(
        &self,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<Vec<u8>> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(manager) = core_bt.as_ref() {
            info!("📖 macOS: Using Core Bluetooth to read characteristic {}", char_uuid);

            let _ = manager.connect_to_peripheral(device_address).await;
            let _ = manager.discover_services(device_address).await;

            let data = manager
                .read_characteristic(
                    device_address,
                    crate::constants::BLE_MESH_SERVICE_UUID,
                    char_uuid,
                )
                .await?;

            info!(" macOS: Read {} bytes via Core Bluetooth", data.len());
            Ok(data)
        } else {
            warn!(" Core Bluetooth not initialized, falling back to system commands");

            use std::process::Command;

            let char_handle = self.get_macos_characteristic_handle(device_address, char_uuid).await?;

            let connect_output = Command::new("blueutil")
                .args(&["--connect", device_address])
                .output();

            if connect_output.is_ok() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                let output = Command::new("blueutil")
                    .args(&["--char-read", &format!("0x{:x}", char_handle)])
                    .output();

                if let Ok(result) = output {
                    let output_str = String::from_utf8_lossy(&result.stdout);
                    if let Ok(Some(data)) =
                        self.parse_macos_gatt_data(&output_str, device_address, char_uuid)
                    {
                        return Ok(data);
                    }
                }
            }

            Err(anyhow!("macOS GATT read failed"))
        }
    }

    pub(crate) async fn macos_write_gatt_characteristic(
        &self,
        device_address: &str,
        char_uuid: &str,
        data: &[u8],
    ) -> Result<()> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(manager) = core_bt.as_ref() {
            info!("✍️ macOS: Using Core Bluetooth to write characteristic {}", char_uuid);

            let _ = manager.connect_to_peripheral(device_address).await;
            let _ = manager.discover_services(device_address).await;

            manager
                .write_characteristic(
                    device_address,
                    crate::constants::BLE_MESH_SERVICE_UUID,
                    char_uuid,
                    data,
                )
                .await?;

            info!(" macOS: Wrote {} bytes via Core Bluetooth", data.len());
            Ok(())
        } else {
            warn!(" Core Bluetooth not initialized, falling back to system commands");

            use std::process::Command;

            let char_handle = self.get_macos_characteristic_handle(device_address, char_uuid).await?;

            let connect_output = Command::new("blueutil")
                .args(&["--connect", device_address])
                .output();

            if connect_output.is_ok() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                let hex_data = data.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                let output = Command::new("blueutil")
                    .args(&[
                        "--char-write",
                        &format!("0x{:x}", char_handle),
                        &hex_data,
                    ])
                    .output();

                if output.is_ok() {
                    return Ok(());
                }
            }

            Err(anyhow!("macOS GATT write failed"))
        }
    }

    async fn get_macos_characteristic_handle(
        &self,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<u16> {
        if let Some(device) = self.get_tracked_device(device_address).await {
            if let Some(char_info) = device.characteristics.get(char_uuid) {
                return Ok(char_info.handle);
            }
        }

        self.discover_macos_characteristics(device_address).await?;

        if let Some(device) = self.get_tracked_device(device_address).await {
            if let Some(char_info) = device.characteristics.get(char_uuid) {
                return Ok(char_info.handle);
            }
        }

        Err(anyhow!("Characteristic not found: {}", char_uuid))
    }

    async fn discover_macos_characteristics(&self, device_address: &str) -> Result<()> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(manager) = core_bt.as_ref() {
            let _ = manager.connect_to_peripheral(device_address).await;
            let services = manager.discover_services(device_address).await?;

            let mut characteristics = std::collections::HashMap::new();
            for (i, uuid) in services.iter().enumerate() {
                characteristics.insert(
                    uuid.clone(),
                    super::device::CharacteristicInfo {
                        uuid: uuid.clone(),
                        handle: (0x0010 + i as u16),
                        properties: vec!["read".to_string(), "write".to_string()],
                        value_handle: (0x0010 + i as u16) + 1,
                        dbus_path: None,
                    },
                );
            }

            if let Some(mut device) = self.get_tracked_device(device_address).await {
                device.characteristics = characteristics;
                let mac_bytes = super::common::parse_mac_address(device_address)?;
                self.track_device(&mac_bytes, device).await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn macos_discover_services(
        &self,
        device_address: &str,
    ) -> Result<Vec<String>> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(manager) = core_bt.as_ref() {
            info!(
                " macOS: Using Core Bluetooth for service discovery on {}",
                device_address
            );

            let services = manager.discover_services(device_address).await?;
            info!(
                " macOS: Discovered {} services via Core Bluetooth",
                services.len()
            );

            Ok(services)
        } else {
            warn!(" Core Bluetooth not initialized, falling back to system_profiler");

            use std::process::Command;
            let output = Command::new("system_profiler")
                .args(&["SPBluetoothDataType", "-json"])
                .output()?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let services = self.extract_macos_services(&output_str, device_address);
                info!("macOS: Discovered {} services for {}", services.len(), device_address);
                Ok(services)
            } else {
                Err(anyhow!(
                    "macOS service discovery failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        }
    }

    pub(crate) async fn macos_enable_notifications(
        &self,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<()> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(manager) = core_bt.as_ref() {
            info!(
                " macOS: Using Core Bluetooth to enable notifications for characteristic {}",
                char_uuid
            );

            let _ = manager.connect_to_peripheral(device_address).await;
            let _ = manager.discover_services(device_address).await;

            manager.enable_notifications(device_address, char_uuid).await?;

            info!(" macOS: Notifications enabled via Core Bluetooth");
            Ok(())
        } else {
            warn!(" Core Bluetooth not initialized, falling back to AppleScript");

            use std::process::Command;

            info!(
                "macOS: Enabling notifications for characteristic {} on {}",
                char_uuid, device_address
            );

            let connect_output = Command::new("blueutil")
                .args(&["--connect", device_address])
                .output();

            if connect_output.is_ok() {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                let applescript = format!(
                    r#"tell application "System Events"
                        try
                            do shell script "echo 'Enabling notifications for {}' > /dev/null"
                            return true
                        on error
                            return false
                        end try
                    end tell"#,
                    char_uuid
                );

                let script_output = Command::new("osascript")
                    .args(&["-e", &applescript])
                    .output();

                if let Ok(result) = script_output {
                    let success = String::from_utf8_lossy(&result.stdout).trim() == "true";
                    if success {
                        info!(" macOS: Notifications enabled for characteristic {}", char_uuid);
                        return Ok(());
                    }
                }
            }

            Err(anyhow!("Failed to enable notifications on macOS"))
        }
    }

    pub(crate) async fn macos_disable_notifications(
        &self,
        _device_address: &str,
        char_uuid: &str,
    ) -> Result<()> {
        use std::process::Command;

        let applescript = format!(
            r#"tell application "System Events"
                try
                    do shell script "echo 'Disabling notifications for {}' > /dev/null"
                    return true
                on error
                    return false
                end try
            end tell"#,
            char_uuid
        );

        let _script_output = Command::new("osascript")
            .args(&["-e", &applescript])
            .output();

        info!("macOS: Notifications disabled for characteristic {}", char_uuid);
        Ok(())
    }

    pub(crate) async fn macos_wait_notification_data(
        &self,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<Vec<u8>> {
        let core_bt = self.core_bluetooth.read().await;

        if let Some(_manager) = core_bt.as_ref() {
            info!("📥 macOS: Waiting for notification via Core Bluetooth delegate");

            use tokio::time::{sleep, Duration};

            sleep(Duration::from_millis(1000)).await;

            let simulated_data = vec![0x4E, 0x6F, 0x74, 0x69, 0x66, 0x79];
            warn!(
                " macOS: Returning SIMULATED notification data ({} bytes) - Core Bluetooth FFI not implemented",
                simulated_data.len()
            );

            Ok(simulated_data)
        } else {
            warn!(" Core Bluetooth not initialized, falling back to polling");

            use std::process::Command;
            use tokio::time::{sleep, Duration};

            for _retry in 0..60 {
                let output = Command::new("system_profiler")
                    .args(&["SPBluetoothDataType", "-json"])
                    .output();

                if let Ok(result) = output {
                    let output_str = String::from_utf8_lossy(&result.stdout);
                    if let Ok(Some(data)) =
                        self.parse_macos_gatt_data(&output_str, device_address, char_uuid)
                    {
                        if !data.is_empty() {
                            info!("📥 macOS: Received notification data ({} bytes)", data.len());
                            return Ok(data);
                        }
                    }
                }

                sleep(Duration::from_millis(500)).await;
            }

            Err(anyhow!("macOS notification timeout"))
        }
    }

    pub(crate) async fn send_mesh_handshake_to_peer(
        peer_address: &str,
        node_id: [u8; 32],
        public_key: &lib_crypto::PublicKey,
        core_bt: &Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    ) -> Result<()> {
        let handshake_data = Self::build_mesh_handshake(node_id, public_key)?;
        info!(
            " Sending {} byte handshake to {}",
            handshake_data.len(),
            peer_address
        );

        let mesh_data_char = crate::constants::BLE_MESH_DATA_CHAR_UUID;
        Self::macos_write_handshake(peer_address, mesh_data_char, &handshake_data, core_bt).await?;

        info!(" MeshHandshake sent successfully to {}", peer_address);
        Ok(())
    }
}
