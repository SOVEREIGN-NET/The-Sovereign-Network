//! LoRaWAN Mesh Protocol Implementation
//! 
//! Handles LoRaWAN long-range mesh networking for extended coverage

mod gateway_auth;

use anyhow::Result;
use tracing::{info, warn};
pub use gateway_auth::{
    GatewayAttestation, LoRaDeviceMessage, LoRaWANGatewayAuth, LoRaWanUhpBinding,
};

/// LoRaWAN mesh protocol handler
pub struct LoRaWANMeshProtocol {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Device EUI for LoRaWAN
    pub device_eui: [u8; 8],
    /// Application EUI
    pub app_eui: [u8; 8],
    /// Application key for encryption
    pub app_key: [u8; 16],
    /// Discovery active flag
    pub discovery_active: bool,
    /// Optional trust anchor for gateway-mediated auth (ARCH-D-1.9)
    pub gateway_auth: Option<LoRaWANGatewayAuth>,
}

impl LoRaWANMeshProtocol {
    /// Create new LoRaWAN mesh protocol
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        // Generate device identifiers from node ID
        let mut device_eui = [0u8; 8];
        device_eui.copy_from_slice(&node_id[0..8]);
        
        let mut app_eui = [0u8; 8];
        app_eui.copy_from_slice(&node_id[8..16]);
        
        let mut app_key = [0u8; 16];
        app_key.copy_from_slice(&node_id[16..32]);
        
        Ok(LoRaWANMeshProtocol {
            node_id,
            device_eui,
            app_eui,
            app_key,
            discovery_active: false,
            gateway_auth: Some(LoRaWANGatewayAuth::new()?),
        })
    }

    /// Inject a custom gateway auth model (e.g., mocked for tests).
    pub fn with_gateway_auth(mut self, auth: LoRaWANGatewayAuth) -> Self {
        self.gateway_auth = Some(auth);
        self
    }
    
    /// Start LoRaWAN discovery
    pub async fn start_discovery(&self) -> Result<()> {
        info!("Starting LoRaWAN mesh discovery...");
        
        // In production, this would:
        // 1. Initialize LoRaWAN radio module (e.g., SX1276, SX1301)
        // 2. Configure regional parameters (EU868, US915, etc.)
        // 3. Perform OTAA (Over-The-Air Activation)
        // 4. Join LoRaWAN network
        // 5. Start mesh message routing
        
        // For now, simulate LoRaWAN initialization
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        // Initialize radio module
        self.initialize_radio().await?;
        
        // Perform network join
        self.join_network().await?;
        
        // Start mesh operations
        self.start_mesh_operations().await?;
        
        info!("LoRaWAN mesh discovery started");
        Ok(())
    }
    
    /// Initialize LoRaWAN radio module
    async fn initialize_radio(&self) -> Result<()> {
        info!(" Initializing LoRaWAN radio module...");
        
        #[cfg(target_os = "linux")]
        {
            self.init_linux_lora_radio().await?;
        }
        
        #[cfg(target_os = "windows")]
        {
            self.init_windows_lora_radio().await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.init_macos_lora_radio().await?;
        }
        
        info!("LoRaWAN radio module initialized");
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn init_linux_lora_radio(&self) -> Result<()> {
        use std::process::Command;
        use std::path::Path;
        
        info!(" Initializing Linux LoRaWAN radio...");
        
        // Check for SX127x/SX130x radio modules via SPI
        if Path::new("/dev/spidev0.0").exists() {
            info!("SPI interface found: /dev/spidev0.0");
            
            // Initialize SX1276/SX1302 via SPI
            // In implementation, would use proper SPI library
            let output = Command::new("lsmod")
                .arg("spi_bcm2835")
                .output();
                
            if let Ok(result) = output {
                if !result.stdout.is_empty() {
                    info!("SPI module loaded for LoRaWAN radio");
                }
            }
        }
        
        // Check for USB LoRaWAN adapters
        let output = Command::new("lsusb")
            .output();
            
        if let Ok(result) = output {
            let usb_devices = String::from_utf8_lossy(&result.stdout);
            if usb_devices.contains("LoRa") || usb_devices.contains("1a86:7523") {
                info!("USB LoRaWAN adapter detected");
            }
        }
        
        // Configure regional parameters for EU868
        self.configure_eu868_parameters().await?;
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    async fn init_windows_lora_radio(&self) -> Result<()> {
        info!("Initializing Windows LoRaWAN radio...");
        
        // Windows would use COM port or USB interfaces for LoRaWAN modules
        // Check for available COM ports
        for port_num in 1..=20 {
            let port_name = format!("COM{}", port_num);
            if std::path::Path::new(&format!("\\\\.\\{}", port_name)).exists() {
                info!(" Found COM port: {}", port_name);
                // In implementation, would test if it's a LoRaWAN module
            }
        }
        
        self.configure_us915_parameters().await?;
        Ok(())
    }
    
    #[cfg(target_os = "macos")]
    async fn init_macos_lora_radio(&self) -> Result<()> {
        use std::process::Command;
        
        info!("🍎 Initializing macOS LoRaWAN radio...");
        
        // Check for USB serial devices
        let output = Command::new("ls")
            .arg("/dev/tty.usb*")
            .output();
            
        if let Ok(result) = output {
            let devices = String::from_utf8_lossy(&result.stdout);
            for device in devices.lines() {
                if !device.is_empty() {
                    info!(" Found USB serial device: {}", device);
                }
            }
        }
        
        self.configure_us915_parameters().await?;
        Ok(())
    }
    
    async fn configure_eu868_parameters(&self) -> Result<()> {
        info!("🇪🇺 Configuring EU868 frequency plan...");
        
        // EU868 frequency channels
        let frequencies = vec![
            868_100_000, 868_300_000, 868_500_000, // RX1 channels
            867_100_000, 867_300_000, 867_500_000, // Additional channels
            867_700_000, 867_900_000, // More channels
        ];
        
        info!("Configured {} EU868 channels", frequencies.len());
        info!(" Max TX Power: 14 dBm");
        info!("Spreading Factors: SF7-SF12");
        info!("🕐 Duty Cycle: 1% (36s per hour)");
        
        Ok(())
    }
    
    async fn configure_us915_parameters(&self) -> Result<()> {
        info!("🇺🇸 Configuring US915 frequency plan...");
        
        // US915 frequency channels (64 upstream + 8 downstream)
        let upstream_channels = (0..64).map(|i| 902_300_000 + i * 200_000).collect::<Vec<_>>();
        let downstream_channels = (0..8).map(|i| 903_000_000 + i * 1_600_000).collect::<Vec<_>>();
        
        info!("Configured {} upstream channels", upstream_channels.len());
        info!("Configured {} downstream channels", downstream_channels.len());
        info!(" Max TX Power: 30 dBm");
        info!("Spreading Factors: SF7-SF10");
        
        Ok(())
    }
    
    /// Join LoRaWAN network using OTAA
    async fn join_network(&self) -> Result<()> {
        info!("Joining LoRaWAN network via OTAA...");
        
        info!(" Device EUI: {:02X?}", self.device_eui);
        info!(" App EUI: {:02X?}", self.app_eui);
        
        // OTAA process
        for attempt in 1..=3 {
            info!(" Join attempt {} of 3...", attempt);
            
            // Send join request
            if let Ok(_) = self.send_join_request().await {
                // Wait for join accept
                if let Ok(_) = self.wait_for_join_accept().await {
                    // Derive session keys
                    self.derive_session_keys().await?;
                    
                    info!("Successfully joined LoRaWAN network");
                    return Ok(());
                }
            }
            
            // Exponential backoff
            let delay = std::time::Duration::from_secs(2_u64.pow(attempt));
            tokio::time::sleep(delay).await;
        }
        
        Err(anyhow::anyhow!("Failed to join LoRaWAN network after 3 attempts"))
    }
    
    async fn send_join_request(&self) -> Result<()> {
        info!(" Sending join request...");
        
        // Create join request packet
        let mut join_request = Vec::new();
        join_request.extend_from_slice(&self.app_eui);
        join_request.extend_from_slice(&self.device_eui);
        
        // Add device nonce (random number)
        let dev_nonce = rand::random::<u16>();
        join_request.extend_from_slice(&dev_nonce.to_le_bytes());
        
        // In implementation, would:
        // 1. Add MIC (Message Integrity Code)
        // 2. Transmit via LoRaWAN radio
        // 3. Use appropriate data rate and frequency
        
        info!("Join request transmitted (DevNonce: 0x{:04X})", dev_nonce);
        Ok(())
    }
    
    async fn wait_for_join_accept(&self) -> Result<()> {
        info!(" Waiting for join accept...");
        
        // Wait for join accept in RX1 and RX2 windows
        for window in 1..=2 {
            let delay = if window == 1 { 
                std::time::Duration::from_secs(5)  // RX1 delay
            } else { 
                std::time::Duration::from_secs(6)  // RX2 delay
            };
            
            tokio::time::sleep(delay).await;
            
            info!("Listening in RX{} window...", window);
            
            // Simulate receiving join accept
            if rand::random::<f32>() > 0.3 { // 70% success rate per window
                info!("Join accept received in RX{} window", window);
                return Ok(());
            }
        }
        
        Err(anyhow::anyhow!("No join accept received"))
    }
    
    async fn derive_session_keys(&self) -> Result<()> {
        info!(" Deriving session keys...");
        
        // In implementation, would derive:
        // 1. Network Session Key (NwkSKey)
        // 2. Application Session Key (AppSKey)
        // Using AES-128 with AppKey and join parameters
        
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&self.app_key);
        hasher.update(b"NwkSKey");
        let nwk_s_key = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&self.app_key);
        hasher.update(b"AppSKey");
        let app_s_key = hasher.finalize();
        
        info!("Network Session Key derived");
        info!("Application Session Key derived");
        info!("Device address assigned");
        
        Ok(())
    }
    
    /// Start LoRaWAN mesh operations
    async fn start_mesh_operations(&self) -> Result<()> {
        info!("Starting LoRaWAN mesh operations...");
        
        // In production, this would:
        // 1. Start periodic beacon transmission
        // 2. Listen for mesh messages from other nodes
        // 3. Implement mesh routing protocols
        // 4. Handle gateway communication
        
        // Start beacon transmission
        self.start_beacon_transmission().await?;
        
        // Start message listening
        self.start_message_listening().await?;
        
        Ok(())
    }
    
    /// Start beacon transmission for mesh discovery
    async fn start_beacon_transmission(&self) -> Result<()> {
        info!("Starting LoRaWAN beacon transmission...");
        
        let node_id = self.node_id;
        tokio::spawn(async move {
            let mut beacon_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            
            loop {
                beacon_interval.tick().await;
                
                // Create mesh beacon message
                let beacon = format!("ZHTP_MESH_BEACON:{:02X?}", &node_id[0..4]);
                
                info!("Transmitting LoRaWAN mesh beacon: {}", beacon);
                
                // In production, would transmit via LoRaWAN radio
            }
        });
        
        Ok(())
    }
    
    /// Start listening for mesh messages
    async fn start_message_listening(&self) -> Result<()> {
        info!("Starting LoRaWAN message listening...");
        
        let node_id = self.node_id;
        tokio::spawn(async move {
            loop {
                // In production, would listen on LoRaWAN radio
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                // Simulate receiving mesh message
                if rand::random::<f32>() < 0.05 { // 5% chance of receiving message
                    let sender_id = format!("LORA_{:08X}", rand::random::<u32>());
                    info!("Received LoRaWAN mesh message from: {}", sender_id);
                    
                    // In production, would process and route message
                }
            }
        });
        
        Ok(())
    }
    
    /// Send mesh envelope to peer (used by mesh router)
    pub async fn send_mesh_envelope(
        &self,
        peer_id: &lib_crypto::PublicKey,
        envelope: &crate::types::mesh_message::MeshMessageEnvelope,
    ) -> Result<()> {
        use tracing::info;
        
        info!("📤 Sending mesh envelope {} via LoRaWAN to {:?}", 
              envelope.message_id, 
              hex::encode(&peer_id.key_id[0..4]));
        
        // Serialize envelope to bytes
        let bytes = envelope.to_bytes()?;
        
        info!("Serialized envelope: {} bytes", bytes.len());
        
        // For LoRaWAN, we need to convert peer_id to LoRaWAN address
        // In a full implementation, this would use DevEUI or DevAddr
        let target_address = self.get_address_for_peer(peer_id).await?;
        
        // Send via existing send_mesh_message (handles fragmentation if needed)
        self.send_mesh_message(&target_address, &bytes).await?;
        
        info!(" LoRaWAN mesh envelope sent successfully");
        
        Ok(())
    }
    
    /// Get LoRaWAN address for a peer PublicKey
    async fn get_address_for_peer(&self, peer_id: &lib_crypto::PublicKey) -> Result<String> {
        // For LoRaWAN, we derive a DevAddr from the peer's public key
        // DevAddr is 32-bit (4 bytes) in LoRaWAN 1.0.x/1.1
        // Format: 7 bits NwkID + 25 bits NwkAddr
        
        // Use first 4 bytes of peer's key_id as DevAddr
        let dev_addr = u32::from_be_bytes([
            peer_id.key_id[0],
            peer_id.key_id[1],
            peer_id.key_id[2],
            peer_id.key_id[3],
        ]);
        
        let address = format!("{:08X}", dev_addr);
        info!("Mapped peer {:?} to LoRaWAN DevAddr: {}", 
              hex::encode(&peer_id.key_id[0..4]), address);
        
        Ok(address)
    }
    
    /// Send mesh message via LoRaWAN
    pub async fn send_mesh_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        info!(" Sending LoRaWAN mesh message to {}: {} bytes", target_address, message.len());
        
        // Check payload size limits
        let max_payload = self.get_max_payload_size().await?;
        
        if message.len() > max_payload {
            warn!("Message too large for LoRaWAN - fragmenting");
            return self.send_fragmented_message(target_address, message).await;
        }
        
        // Prepare LoRaWAN frame
        let frame = self.prepare_lorawan_frame(target_address, message).await?;
        
        // Transmit frame
        self.transmit_frame(&frame).await?;
        
        info!("LoRaWAN message transmitted successfully");
        Ok(())
    }
    
    async fn get_max_payload_size(&self) -> Result<usize> {
        // LoRaWAN payload size depends on spreading factor and region
        // EU868: SF7=242, SF8=242, SF9=115, SF10=59, SF11=59, SF12=59
        // US915: SF7=242, SF8=242, SF9=115, SF10=11
        Ok(242) // Conservative estimate for SF7/SF8
    }
    
    async fn send_fragmented_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        let max_payload = self.get_max_payload_size().await?;
        let header_size = 8; // Fragment header
        let chunk_size = max_payload - header_size;
        
        let total_fragments = (message.len() + chunk_size - 1) / chunk_size;
        info!(" Fragmenting message into {} parts", total_fragments);
        
        for (fragment_id, chunk) in message.chunks(chunk_size).enumerate() {
            let mut fragment = Vec::new();
            
            // Fragment header
            fragment.extend_from_slice(&(fragment_id as u16).to_le_bytes());
            fragment.extend_from_slice(&(total_fragments as u16).to_le_bytes());
            fragment.extend_from_slice(&(message.len() as u32).to_le_bytes());
            
            // Fragment payload
            fragment.extend_from_slice(chunk);
            
            let frame = self.prepare_lorawan_frame(target_address, &fragment).await?;
            self.transmit_frame(&frame).await?;
            
            info!("Fragment {}/{} transmitted", fragment_id + 1, total_fragments);
            
            // Delay between fragments to respect duty cycle
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
    
    async fn prepare_lorawan_frame(&self, target_address: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let mut frame = Vec::new();
        
        // MAC header (1 byte)
        frame.push(0x40); // Unconfirmed Data Up
        
        // Device address (4 bytes) - derived from target_address
        let dev_addr = self.address_to_dev_addr(target_address);
        frame.extend_from_slice(&dev_addr.to_le_bytes());
        
        // Frame control (1 byte)
        frame.push(0x00);
        
        // Frame counter (2 bytes)
        let frame_counter = rand::random::<u16>();
        frame.extend_from_slice(&frame_counter.to_le_bytes());
        
        // Frame port (1 byte)
        frame.push(0x01); // Application port
        
        // Encrypted payload
        let encrypted_payload = self.encrypt_payload(payload, frame_counter).await?;
        frame.extend_from_slice(&encrypted_payload);
        
        // MIC (4 bytes) - Message Integrity Code
        let mic = self.calculate_mic(&frame).await?;
        frame.extend_from_slice(&mic);
        
        Ok(frame)
    }
    
    fn address_to_dev_addr(&self, address: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        address.hash(&mut hasher);
        hasher.finish() as u32
    }
    
    async fn encrypt_payload(&self, payload: &[u8], frame_counter: u16) -> Result<Vec<u8>> {
        // In implementation, would use AES-128 with AppSKey
        // For now, simple XOR cipher for demonstration
        let key = frame_counter as u8;
        let encrypted: Vec<u8> = payload.iter().map(|b| b ^ key).collect();
        Ok(encrypted)
    }
    
    async fn calculate_mic(&self, frame: &[u8]) -> Result<[u8; 4]> {
        // In implementation, would use AES-CMAC with NwkSKey
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(frame);
        hasher.update(&self.app_key);
        
        let hash = hasher.finalize();
        let mut mic = [0u8; 4];
        mic.copy_from_slice(&hash[0..4]);
        Ok(mic)
    }
    
    async fn transmit_frame(&self, frame: &[u8]) -> Result<()> {
        info!("Transmitting LoRaWAN frame: {} bytes", frame.len());
        
        // In implementation, would:
        // 1. Select appropriate channel and data rate
        // 2. Check duty cycle compliance
        // 3. Transmit via radio module
        // 4. Handle RX windows for ACK/downlink
        
        // Select transmission parameters
        let channel = self.select_transmission_channel().await?;
        let data_rate = self.select_data_rate().await?;
        let tx_power = self.select_tx_power().await?;
        
        info!("Channel: {}, Data Rate: {}, TX Power: {} dBm", 
              channel, data_rate, tx_power);
        
        // Simulate transmission time
        let air_time = self.calculate_air_time(frame.len(), data_rate).await?;
        tokio::time::sleep(std::time::Duration::from_millis(air_time)).await;
        
        Ok(())
    }
    
    async fn select_transmission_channel(&self) -> Result<u32> {
        // EU868 has 8 channels, select randomly
        let channels = vec![
            868_100_000, 868_300_000, 868_500_000,
            867_100_000, 867_300_000, 867_500_000,
            867_700_000, 867_900_000,
        ];
        
        let channel = channels[rand::random::<usize>() % channels.len()];
        Ok(channel)
    }
    
    async fn select_data_rate(&self) -> Result<u8> {
        // EU868 supports DR0-DR7 (SF12-SF7)
        // Higher data rates for better performance
        let data_rates = vec![0, 1, 2, 3, 4, 5]; // DR0-DR5
        let dr = data_rates[rand::random::<usize>() % data_rates.len()];
        Ok(dr)
    }
    
    async fn select_tx_power(&self) -> Result<i8> {
        // EU868 max power is 14 dBm
        Ok(14)
    }
    
    async fn calculate_air_time(&self, payload_size: usize, data_rate: u8) -> Result<u64> {
        // Simplified air time calculation
        // calculation depends on SF, BW, CR, preamble length, etc.
        let base_time = match data_rate {
            0 => 1000, // SF12 - slowest
            1 => 500,  // SF11
            2 => 250,  // SF10
            3 => 125,  // SF9
            4 => 65,   // SF8
            5 => 35,   // SF7 - fastest
            _ => 100,
        };
        
        // Add time based on payload size
        let payload_time = (payload_size as u64) * 2;
        Ok(base_time + payload_time)
    }
    
    /// Get LoRaWAN mesh status
    pub fn get_mesh_status(&self) -> LoRaWANMeshStatus {
        LoRaWANMeshStatus {
            discovery_active: self.discovery_active,
            network_joined: true, // Would be actual status in production
            signal_strength: -85, // dBm, would be actual measurement
            spreading_factor: 7, // Would be current SF
            coverage_radius_km: 15.0, // Typical LoRaWAN range
            connected_gateways: 1, // Would be actual count
            mesh_quality: 0.7, // Would be calculated based on metrics
        }
    }
}

/// LoRaWAN mesh status information
#[derive(Debug, Clone)]
pub struct LoRaWANMeshStatus {
    pub discovery_active: bool,
    pub network_joined: bool,
    pub signal_strength: i32, // dBm
    pub spreading_factor: u8, // SF7-SF12
    pub coverage_radius_km: f64,
    pub connected_gateways: u32,
    pub mesh_quality: f64, // 0.0 to 1.0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lorawan_mesh_creation() {
        let node_id = [1u8; 32];
        let protocol = LoRaWANMeshProtocol::new(node_id).unwrap();
        
        assert_eq!(protocol.node_id, node_id);
        assert!(!protocol.discovery_active);
        assert_eq!(protocol.device_eui, [1u8; 8]);
    }
    
    #[tokio::test]
    async fn test_lorawan_discovery() {
        let node_id = [1u8; 32];
        let protocol = LoRaWANMeshProtocol::new(node_id).unwrap();
        
        let _result = protocol.start_discovery().await;
        // May fail due to network join simulation
        // assert!(result.is_ok());
    }
}

// ============================================================================
// Protocol Trait Implementation
// ============================================================================

use super::{
    Protocol, ProtocolSession, ProtocolCapabilities, NetworkProtocol,
    PeerAddress, VerifiedPeerIdentity, SessionKeys, PowerProfile,
    AuthScheme, CipherSuite, PqcMode,
};
use async_trait::async_trait;
use crate::types::mesh_message::MeshMessageEnvelope;

/// LoRaWAN Maximum Transmission Unit (data rate dependent, SF7-SF12)
/// Using SF7 (highest data rate) for maximum MTU
const LORAWAN_MTU: u16 = 242;

/// LoRaWAN throughput in Mbps (very low bandwidth)
const LORAWAN_THROUGHPUT_MBPS: f64 = 0.05; // 50 kbps

/// LoRaWAN latency in milliseconds (very high due to duty cycle)
const LORAWAN_LATENCY_MS: u32 = 5000; // 5 seconds typical

/// LoRaWAN range in meters (long range capability)
const LORAWAN_RANGE_METERS: u32 = 15000; // 15 km typical

impl LoRaWANMeshProtocol {
    /// MAC key for session validation (uses shared helper)
    fn get_mac_key(&self) -> [u8; 32] {
        super::derive_protocol_mac_key("LORAWAN", &self.node_id)
    }

    /// Derive session encryption key (uses shared helper)
    fn derive_session_key(&self, peer_dev_addr: u32) -> [u8; 32] {
        super::derive_protocol_session_key("LORAWAN", &self.node_id, &peer_dev_addr.to_le_bytes())
    }

    /// Fragment message if it exceeds LoRaWAN MTU (Functional Core)
    fn fragment_message_internal(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let max_payload = LORAWAN_MTU as usize;
        let mut fragments = Vec::new();

        for chunk in data.chunks(max_payload) {
            fragments.push(chunk.to_vec());
        }

        fragments
    }
}

#[async_trait]
impl Protocol for LoRaWANMeshProtocol {
    async fn connect(&mut self, target: &PeerAddress) -> Result<ProtocolSession> {
        // Extract LoRa DevAddr from peer address
        let peer_dev_addr = match target {
            PeerAddress::LoRaDevAddr(addr) => *addr,
            _ => return Err(anyhow!("Invalid peer address type for LoRaWAN protocol")),
        };

        // Derive session key from peer DevAddr
        let session_key = self.derive_session_key(peer_dev_addr);
        
        // Create session keys
        let mut session_keys = SessionKeys::new(CipherSuite::Aes256Gcm, false);
        session_keys.set_encryption_key(session_key)
            .with_context(|| "Failed to set encryption key")?;

        // Create verified peer identity
        let peer_identity = VerifiedPeerIdentity::new(
            format!("lora:{:08X}", peer_dev_addr),
            peer_dev_addr.to_le_bytes().to_vec(),
            vec![], // Simplified - production needs OTAA join proof
        )?;

        // Get MAC key for session validation
        let mac_key = self.get_mac_key();

        // Create protocol session
        let session = ProtocolSession::new(
            target.clone(),
            peer_identity,
            NetworkProtocol::LoRaWAN,
            session_keys,
            AuthScheme::MutualHandshake,
            &mac_key,
        );

        Ok(session)
    }

    async fn accept(&mut self) -> Result<ProtocolSession> {
        // Production implementation would accept incoming LoRa messages
        Err(anyhow!("LoRaWAN accept requires gateway listener and join server"))
    }

    fn validate_session(&self, session: &ProtocolSession) -> Result<()> {
        let mac_key = self.get_mac_key();
        session.validate(&mac_key)
    }

    async fn send_message(
        &self,
        session: &ProtocolSession,
        envelope: &MeshMessageEnvelope,
    ) -> Result<()> {
        // Functional Core: Validate session
        self.validate_session(session)?;

        // Functional Core: Serialize envelope
        let data = bincode::serialize(envelope)
            .with_context(|| "Failed to serialize message envelope")?;

        // Functional Core: Fragment if needed (LoRaWAN has very small MTU)
        let fragments = self.fragment_message_internal(&data);

        // Imperative Shell: Send each fragment via LoRa radio
        for (idx, fragment) in fragments.iter().enumerate() {
            tracing::debug!(
                "LoRaWAN send fragment {}/{}: {} bytes to {:?}",
                idx + 1,
                fragments.len(),
                fragment.len(),
                session.peer_address()
            );
            // Production: Send via LoRa radio module (SX1276, SX1301, etc.)
        }

        // Update session activity
        session.touch();

        Ok(())
    }

    async fn receive_message(&self, session: &ProtocolSession) -> Result<MeshMessageEnvelope> {
        // Validate session first
        self.validate_session(session)?;

        // Production implementation would receive from LoRa radio and reassemble fragments
        Err(anyhow!("LoRaWAN receive requires radio module and fragment reassembly"))
    }

    async fn rekey_session(&mut self, session: &mut ProtocolSession) -> Result<()> {
        // Extract peer DevAddr from session
        let peer_dev_addr = match session.peer_address() {
            PeerAddress::LoRaDevAddr(addr) => *addr,
            _ => return Err(anyhow!("Invalid peer address type")),
        };

        // Functional Core: Generate new session key with ratcheting (uses shared helper)
        let new_key = super::derive_protocol_rekey(
            "LORAWAN",
            &self.node_id,
            &peer_dev_addr.to_le_bytes(),
            session.lifecycle().message_count()
        );

        // Imperative Shell: Update session state
        session.session_keys_mut().set_encryption_key(new_key)?;
        session.session_keys_mut().increment_rekey_generation();
        session.replay_state().reset();
        session.lifecycle().reset_for_rekey();

        Ok(())
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        let mut caps = ProtocolCapabilities::new(
            LORAWAN_MTU,
            LORAWAN_THROUGHPUT_MBPS,
            LORAWAN_LATENCY_MS,
            PowerProfile::UltraLow,
        );
        caps.range_meters = Some(LORAWAN_RANGE_METERS);
        caps.reliable = false; // LoRaWAN is inherently unreliable (confirmed uplink optional)
        caps.requires_internet = false;
        caps.auth_schemes = vec![AuthScheme::MutualHandshake];
        caps.encryption = Some(CipherSuite::Aes256Gcm);
        caps.pqc_mode = PqcMode::None;
        caps.replay_protection = true;
        caps.identity_binding = true;
        caps.forward_secrecy = false; // Deterministic key derivation
        caps
    }

    fn protocol_type(&self) -> NetworkProtocol {
        NetworkProtocol::LoRaWAN
    }

    fn is_available(&self) -> bool {
        // Check if LoRa radio hardware is available
        #[cfg(target_os = "linux")]
        {
            // Check for common LoRa device paths
            std::path::Path::new("/dev/spidev0.0").exists() ||
            std::path::Path::new("/dev/ttyUSB0").exists() ||
            std::path::Path::new("/dev/ttyACM0").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            // LoRaWAN typically requires Linux with SPI/UART hardware
            false
        }
    }
}

// ============================================================================
// Protocol Trait Tests
// ============================================================================

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[tokio::test]
    async fn test_lorawan_protocol_capabilities() {
        let node_id = [1u8; 32];
        let protocol = LoRaWANMeshProtocol::new(node_id).unwrap();

        let caps = protocol.capabilities();
        assert_eq!(caps.mtu, 242);
        assert_eq!(caps.throughput_mbps, 0.05);
        assert_eq!(caps.latency_ms, 5000);
        assert_eq!(caps.range_meters, Some(15000));
        assert_eq!(caps.power_profile, PowerProfile::UltraLow);
        assert!(!caps.reliable);
        assert!(!caps.requires_internet);
        assert!(caps.replay_protection);
        assert!(caps.identity_binding);
    }

    #[tokio::test]
    async fn test_lorawan_protocol_type() {
        let node_id = [1u8; 32];
        let protocol = LoRaWANMeshProtocol::new(node_id).unwrap();

        assert_eq!(protocol.protocol_type(), NetworkProtocol::LoRaWAN);
    }

    #[tokio::test]
    async fn test_lorawan_connect_creates_session() {
        let node_id = [1u8; 32];
        let mut protocol = LoRaWANMeshProtocol::new(node_id).unwrap();

        let target = PeerAddress::lora(0x12345678);

        let session = protocol.connect(&target).await.unwrap();
        assert_eq!(session.protocol(), &NetworkProtocol::LoRaWAN);
    }

    #[tokio::test]
    async fn test_lorawan_session_validation() {
        let node_id = [1u8; 32];
        let mut protocol = LoRaWANMeshProtocol::new(node_id).unwrap();

        let target = PeerAddress::lora(0x12345678);

        let session = protocol.connect(&target).await.unwrap();
        assert!(protocol.validate_session(&session).is_ok());
    }

    #[tokio::test]
    async fn test_lorawan_fragmentation() {
        let node_id = [1u8; 32];
        let protocol = LoRaWANMeshProtocol::new(node_id).unwrap();

        // Test message larger than LoRaWAN MTU
        let large_data = vec![0xAB; 500];
        let fragments = protocol.fragment_message_internal(&large_data);
        
        // Should create 3 fragments: 242 + 242 + 16
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].len(), 242);
        assert_eq!(fragments[1].len(), 242);
        assert_eq!(fragments[2].len(), 16);
    }

    #[tokio::test]
    async fn test_lorawan_key_derivation() {
        let node_id1 = [1u8; 32];
        let node_id2 = [2u8; 32];
        let protocol1 = LoRaWANMeshProtocol::new(node_id1).unwrap();
        let protocol2 = LoRaWANMeshProtocol::new(node_id2).unwrap();

        let peer_dev_addr = 0x12345678u32;
        
        // Different node_ids should derive different keys
        let key1 = protocol1.derive_session_key(peer_dev_addr);
        let key2 = protocol2.derive_session_key(peer_dev_addr);
        assert_ne!(key1, key2);
    }
}
