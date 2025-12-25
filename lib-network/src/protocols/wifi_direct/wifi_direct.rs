//! WiFi Direct Mesh Protocol Implementation
//!
//! Handles WiFi Direct mesh networking for medium-range peer connections

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use crate::protocols::wifi_direct_encryption::WiFiDirectEncryption;
use crate::network_utils::get_local_ip;

// Enhanced WiFi Direct implementations with cross-platform support
#[cfg(all(target_os = "macos", feature = "enhanced-wifi-direct"))]
use crate::protocols::enhanced_wifi_direct::{
    MacOSWiFiDirectManager, AdvancedWPSSecurity, MacOSWiFiInterface, MacOSP2PGroup
};

// WiFi Direct orchestrator for manager coordination
use crate::protocols::wifi_direct::orchestrator::WiFiDirectOrchestrator;

// Network and time imports removed - using system commands instead

/// P2P Group Owner negotiation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PGoNegotiation {
    /// Group Owner intent (0-15, higher = more likely to be GO)
    pub go_intent: u8,
    /// Tie-breaker bit for intent conflicts
    pub tie_breaker: bool,
    /// Device capabilities flags
    pub device_capability: DeviceCapability,
    /// Group capabilities flags  
    pub group_capability: GroupCapability,
    /// Operating channel preferences
    pub channel_list: Vec<u8>,
    /// Configuration timeout (negotiation)
    pub config_timeout: u16,
}

/// Device capability flags for P2P negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapability {
    pub service_discovery: bool,
    pub p2p_client_discoverability: bool,
    pub concurrent_operation: bool,
    pub p2p_infrastructure_managed: bool,
    pub p2p_device_limit: bool,
    pub p2p_invitation_procedure: bool,
}

/// Group capability flags for P2P negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCapability {
    pub p2p_group_owner: bool,
    pub persistent_p2p_group: bool,
    pub group_limit: bool,
    pub intra_bss_distribution: bool,
    pub cross_connection: bool,
    pub persistent_reconnect: bool,
    pub group_formation: bool,
    pub ip_address_allocation: bool,
}

/// WPS configuration methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WpsMethod {
    /// Push Button Configuration
    PBC,
    /// PIN display (device shows PIN)
    DisplayPin(String),
    /// PIN keypad (user enters PIN)
    KeypadPin(String),
    /// Near Field Communication
    NFC,
}

/// P2P Invitation request/response structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PInvitationRequest {
    /// Invitee device address
    pub invitee_address: String,
    /// Persistent group identifier
    pub persistent_group_id: String,
    /// Operating channel for the group
    pub operating_channel: u8,
    /// Group BSSID if known
    pub group_bssid: Option<String>,
    /// Invitation flags
    pub invitation_flags: InvitationFlags,
    /// Configuration timeout
    pub config_timeout: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PInvitationResponse {
    /// Status of the invitation (accepted/declined/failed)
    pub status: InvitationStatus,
    /// Configuration timeout
    pub config_timeout: u16,
    /// Operating channel if accepted
    pub operating_channel: Option<u8>,
    /// Group BSSID if joining existing group
    pub group_bssid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationFlags {
    pub invitation_type: InvitationType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvitationType {
    /// Join active group
    JoinActiveGroup,
    /// Reinvoke persistent group
    ReinvokePersistentGroup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvitationStatus {
    Success,
    InformationCurrentlyUnavailable,
    IncompatibleParameters,
    LimitReached,
    InvalidParameters,
    UnableToAccommodateRequest,
    PreviousProtocolError,
    NoCommonChannels,
    UnknownP2PGroup,
    BothGoIntentOfFifteen,
    IncompatibleProvisioningMethod,
    RejectedByUser,
}

/// WiFi Direct service information for mDNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiDirectService {
    pub service_name: String,
    pub service_type: String,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
}

/// WiFi Direct mesh protocol handler
#[derive(Clone)]
pub struct WiFiDirectMeshProtocol {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// SSID for WiFi Direct group
    pub ssid: String,
    /// Passphrase for WiFi Direct group
    pub passphrase: String,
    /// Operating channel
    pub channel: u8,
    /// Whether this device is group owner
    pub group_owner: bool,
    /// Connected devices
    pub connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
    /// Maximum number of devices in group
    pub max_devices: u8,
    /// Discovery active flag
    pub discovery_active: bool,
    /// P2P Group Owner negotiation parameters
    pub go_negotiation: P2PGoNegotiation,
    /// WPS configuration method
    pub wps_method: WpsMethod,
    /// mDNS service daemon for service discovery
    pub mdns_daemon: Option<ServiceDaemon>,
    /// Advertised services
    pub advertised_services: Arc<RwLock<Vec<WiFiDirectService>>>,
    /// Discovered peers with their capabilities
    pub discovered_peers: Arc<RwLock<HashMap<String, P2PGoNegotiation>>>,
    /// Active P2P invitations sent
    pub sent_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
    /// Received P2P invitations
    pub received_invitations: Arc<RwLock<HashMap<String, P2PInvitationRequest>>>,
    /// Persistent P2P groups
    pub persistent_groups: Arc<RwLock<HashMap<String, PersistentGroup>>>,
    /// Channel to notify when peers are discovered (for triggering blockchain sync)
    pub peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// WiFi Direct advertisement publisher (Windows only) - must be kept alive
    #[cfg(target_os = "windows")]
    pub wifi_direct_publisher: Arc<RwLock<Option<windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher>>>,
    /// ZHTP authentication manager for blockchain-based auth
    pub auth_manager: Arc<RwLock<Option<crate::protocols::zhtp_auth::ZhtpAuthManager>>>,
    /// Authenticated peers (device_id -> verification)
    pub authenticated_peers: Arc<RwLock<HashMap<String, crate::protocols::zhtp_auth::ZhtpAuthVerification>>>,
    /// Hidden SSID (don't broadcast publicly)
    pub hidden_ssid: bool,
    /// WiFi Direct enabled state (starts OFF by default for security)
    pub enabled: Arc<RwLock<bool>>,
    /// Orchestrator for coordinating all WiFi Direct managers (lazy initialized in enable())
    pub orchestrator: Arc<RwLock<Option<Arc<WiFiDirectOrchestrator>>>>,
}

/// Persistent P2P Group information
#[derive(Debug, Clone)]
pub struct PersistentGroup {
    pub group_id: String,
    pub ssid: String,
    pub passphrase: String,
    pub group_owner_address: String,
    pub operating_channel: u8,
    pub last_used: u64,
    pub member_devices: Vec<String>,
}

/// WiFi Direct peer connection (note: encryption field is not Clone)
pub struct WiFiDirectConnection {
    pub mac_address: String,
    pub ip_address: String,
    pub signal_strength: i8,
    pub connection_time: u64,
    pub data_rate: u64, // Mbps
    pub device_name: String,
    pub device_type: WiFiDirectDeviceType,
    /// Session key for ChaCha20Poly1305 app-layer encryption (from UHP handshake)
    pub session_key: Option<[u8; 32]>,
    /// WiFi Direct encryption adapter with E2E AEAD or link-layer fallback
    pub encryption: Option<WiFiDirectEncryption>,
}

impl std::fmt::Debug for WiFiDirectConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WiFiDirectConnection")
            .field("mac_address", &self.mac_address)
            .field("ip_address", &self.ip_address)
            .field("signal_strength", &self.signal_strength)
            .field("connection_time", &self.connection_time)
            .field("data_rate", &self.data_rate)
            .field("device_name", &self.device_name)
            .field("device_type", &self.device_type)
            .field("session_key", &self.session_key.as_ref().map(|_| "<secret>"))
            .field("encryption", &"<ChaCha20Poly1305>")
            .finish()
    }
}

impl Clone for WiFiDirectConnection {
    fn clone(&self) -> Self {
        WiFiDirectConnection {
            mac_address: self.mac_address.clone(),
            ip_address: self.ip_address.clone(),
            signal_strength: self.signal_strength,
            connection_time: self.connection_time,
            data_rate: self.data_rate,
            device_name: self.device_name.clone(),
            device_type: self.device_type.clone(),
            session_key: self.session_key,
            encryption: None, // Don't clone encryption state
        }
    }
}

impl Serialize for WiFiDirectConnection {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("WiFiDirectConnection", 8)?;
        state.serialize_field("mac_address", &self.mac_address)?;
        state.serialize_field("ip_address", &self.ip_address)?;
        state.serialize_field("signal_strength", &self.signal_strength)?;
        state.serialize_field("connection_time", &self.connection_time)?;
        state.serialize_field("data_rate", &self.data_rate)?;
        state.serialize_field("device_name", &self.device_name)?;
        state.serialize_field("device_type", &self.device_type)?;
        state.serialize_field("session_key", &self.session_key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WiFiDirectConnection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            MacAddress,
            IpAddress,
            SignalStrength,
            ConnectionTime,
            DataRate,
            DeviceName,
            DeviceType,
            SessionKey,
        }

        struct WiFiDirectConnectionVisitor;

        impl<'de> Visitor<'de> for WiFiDirectConnectionVisitor {
            type Value = WiFiDirectConnection;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct WiFiDirectConnection")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<WiFiDirectConnection, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut mac_address = None;
                let mut ip_address = None;
                let mut signal_strength = None;
                let mut connection_time = None;
                let mut data_rate = None;
                let mut device_name = None;
                let mut device_type = None;
                let mut session_key = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::MacAddress => {
                            mac_address = Some(map.next_value()?);
                        }
                        Field::IpAddress => {
                            ip_address = Some(map.next_value()?);
                        }
                        Field::SignalStrength => {
                            signal_strength = Some(map.next_value()?);
                        }
                        Field::ConnectionTime => {
                            connection_time = Some(map.next_value()?);
                        }
                        Field::DataRate => {
                            data_rate = Some(map.next_value()?);
                        }
                        Field::DeviceName => {
                            device_name = Some(map.next_value()?);
                        }
                        Field::DeviceType => {
                            device_type = Some(map.next_value()?);
                        }
                        Field::SessionKey => {
                            session_key = Some(map.next_value()?);
                        }
                    }
                }

                Ok(WiFiDirectConnection {
                    mac_address: mac_address.ok_or_else(|| de::Error::missing_field("mac_address"))?,
                    ip_address: ip_address.ok_or_else(|| de::Error::missing_field("ip_address"))?,
                    signal_strength: signal_strength
                        .ok_or_else(|| de::Error::missing_field("signal_strength"))?,
                    connection_time: connection_time
                        .ok_or_else(|| de::Error::missing_field("connection_time"))?,
                    data_rate: data_rate.ok_or_else(|| de::Error::missing_field("data_rate"))?,
                    device_name: device_name.ok_or_else(|| de::Error::missing_field("device_name"))?,
                    device_type: device_type.ok_or_else(|| de::Error::missing_field("device_type"))?,
                    session_key: session_key.ok_or_else(|| de::Error::missing_field("session_key"))?,
                    encryption: None,
                })
            }
        }

        deserializer.deserialize_struct(
            "WiFiDirectConnection",
            &[
                "mac_address",
                "ip_address",
                "signal_strength",
                "connection_time",
                "data_rate",
                "device_name",
                "device_type",
                "session_key",
            ],
            WiFiDirectConnectionVisitor,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WiFiDirectDeviceType {
    Computer,
    Phone,
    Tablet,
    Router,
    IoTDevice,
    P2P,
    Unknown,
}

impl WiFiDirectMeshProtocol {
    /// Create new WiFi Direct mesh protocol
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        Self::new_with_peer_notification(node_id, None)
    }
    
    /// Create new WiFi Direct mesh protocol with optional peer discovery notification channel
    pub fn new_with_peer_notification(
        node_id: [u8; 32], 
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>
    ) -> Result<Self> {
        let ssid = format!("ZHTP-MESH-{:08X}", rand::random::<u32>());
        let passphrase = format!("zhtp{:016X}", rand::random::<u64>());
        
        // Initialize P2P Group Owner negotiation parameters
        let go_negotiation = P2PGoNegotiation {
            go_intent: 7, // Moderate intent (0-15)
            tie_breaker: rand::random(),
            device_capability: DeviceCapability {
                service_discovery: true,
                p2p_client_discoverability: true,
                concurrent_operation: true,
                p2p_infrastructure_managed: false,
                p2p_device_limit: false,
                p2p_invitation_procedure: true,
            },
            group_capability: GroupCapability {
                p2p_group_owner: false,
                persistent_p2p_group: true,
                group_limit: false,
                intra_bss_distribution: true,
                cross_connection: true,
                persistent_reconnect: true,
                group_formation: true,
                ip_address_allocation: true,
            },
            channel_list: vec![1, 6, 11], // Common 2.4GHz channels
            config_timeout: 100, // 100ms negotiation timeout
        };
        
        // Initialize mDNS service daemon
        let mdns_daemon = match ServiceDaemon::new() {
            Ok(daemon) => Some(daemon),
            Err(e) => {
                warn!("Failed to initialize mDNS daemon: {}", e);
                None
            }
        };
        
        Ok(WiFiDirectMeshProtocol {
            node_id,
            ssid,
            passphrase,
            channel: 6, // Default channel
            group_owner: false,
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            max_devices: 8,
            discovery_active: false,
            go_negotiation,
            wps_method: WpsMethod::PBC, // Default to Push Button Configuration
            mdns_daemon,
            advertised_services: Arc::new(RwLock::new(Vec::new())),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            sent_invitations: Arc::new(RwLock::new(HashMap::new())),
            received_invitations: Arc::new(RwLock::new(HashMap::new())),
            persistent_groups: Arc::new(RwLock::new(HashMap::new())),
            peer_discovery_tx,
            #[cfg(target_os = "windows")]
            wifi_direct_publisher: Arc::new(RwLock::new(None)),
            auth_manager: Arc::new(RwLock::new(None)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            hidden_ssid: true, // SECURITY: Hidden SSID by default to prevent non-ZHTP connections
            enabled: Arc::new(RwLock::new(false)), // SECURITY: WiFi Direct starts OFF for privacy/security
            orchestrator: Arc::new(RwLock::new(None)), // Initialized lazily in enable()
        })
    }
    
    /// Enable WiFi Direct protocol
    /// SECURITY: WiFi Direct is disabled by default and must be explicitly enabled
    pub async fn enable(&self) -> Result<()> {
        let mut enabled = self.enabled.write().await;
        if *enabled {
            info!("  WiFi Direct already enabled");
            return Ok(());
        }

        info!("🔓 Enabling WiFi Direct protocol...");

        // Initialize orchestrator if not already initialized
        {
            let mut orchestrator = self.orchestrator.write().await;
            if orchestrator.is_none() {
                debug!("Initializing WiFi Direct orchestrator");
                let orch = Arc::new(WiFiDirectOrchestrator::new(self.node_id).await?);
                *orchestrator = Some(orch);
            }
        }

        *enabled = true;
        info!(" WiFi Direct protocol ENABLED");
        info!("    Hidden SSID mode active");
        info!("    ZHTP authentication required");

        Ok(())
    }
    
    /// Disable WiFi Direct protocol
    /// Stops all WiFi Direct activity and tears down connections
    pub async fn disable(&self) -> Result<()> {
        let mut enabled = self.enabled.write().await;
        if !*enabled {
            info!("  WiFi Direct already disabled");
            return Ok(());
        }
        
        info!(" Disabling WiFi Direct protocol...");
        
        // Stop Windows WiFi Direct publisher if active
        #[cfg(target_os = "windows")]
        {
            let mut publisher_guard = self.wifi_direct_publisher.write().await;
            if let Some(publisher) = publisher_guard.take() {
                use windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus;
                if publisher.Status().unwrap_or(WiFiDirectAdvertisementPublisherStatus::Aborted) 
                    == WiFiDirectAdvertisementPublisherStatus::Started {
                    publisher.Stop().ok();
                    info!("   Stopped WiFi Direct advertisement");
                }
            }
        }
        
        // Clear connected devices
        self.connected_devices.write().await.clear();
        
        // Clear discovered peers
        self.discovered_peers.write().await.clear();
        
        // Clear authenticated peers
        self.authenticated_peers.write().await.clear();

        // Stop orchestrator if running
        {
            let mut orchestrator = self.orchestrator.write().await;
            if let Some(orch) = orchestrator.take() {
                debug!("Stopping WiFi Direct orchestrator");
                orch.stop().await.ok();
            }
        }

        *enabled = false;
        info!(" WiFi Direct protocol DISABLED");
        info!("    No longer discoverable via WiFi Direct");
        info!("    All connections closed");

        Ok(())
    }
    
    /// Check if WiFi Direct is enabled
    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }
    
    /// Start WiFi Direct discovery
    pub async fn start_discovery(&mut self) -> Result<()> {
        // Check if WiFi Direct is enabled
        if !self.is_enabled().await {
            warn!("  WiFi Direct is DISABLED - cannot start discovery");
            warn!("   Call enable() first to activate WiFi Direct protocol");
            return Err(anyhow::anyhow!("WiFi Direct is disabled"));
        }

        info!("Starting WiFi Direct mesh discovery...");

        // Get orchestrator
        let orchestrator = {
            let orch_guard = self.orchestrator.read().await;
            if let Some(orch) = orch_guard.as_ref() {
                orch.clone()
            } else {
                return Err(anyhow::anyhow!("WiFi Direct orchestrator not initialized"));
            }
        };

        // Delegate to orchestrator
        orchestrator.start_discovery().await?;

        self.discovery_active = true;
        info!(" WiFi Direct discovery started");

        Ok(())
    }
    
    /// Initialize ZHTP authentication for WiFi Direct
    /// SECURITY: Prevents non-ZHTP nodes from connecting
    pub async fn initialize_auth(&self, blockchain_pubkey: lib_crypto::PublicKey) -> Result<()> {
        use crate::protocols::zhtp_auth::ZhtpAuthManager;
        
        info!(" Initializing ZHTP authentication for WiFi Direct");
        info!("   Post-quantum Dilithium2 signatures enabled");
        info!("   Only ZHTP nodes with blockchain identity can connect");
        
        let auth_manager = ZhtpAuthManager::new(blockchain_pubkey)?;
        *self.auth_manager.write().await = Some(auth_manager);
        
        info!(" WiFi Direct authentication initialized");
        info!("    Non-ZHTP devices will be rejected");
        
        Ok(())
    }
    
    /// Verify a connecting peer is a legitimate ZHTP node
    /// Returns true if authenticated, false otherwise
    pub async fn authenticate_peer(&self, device_id: &str, peer_data: &[u8]) -> Result<bool> {
        use crate::protocols::zhtp_auth::ZhtpAuthResponse;
        
        let auth_guard = self.auth_manager.read().await;
        let auth_manager = match auth_guard.as_ref() {
            Some(mgr) => mgr,
            None => {
                warn!("  WiFi Direct authentication not initialized - rejecting connection from {}", device_id);
                return Ok(false);
            }
        };
        
        // Try to parse peer data as auth response
        if let Ok(response) = serde_json::from_slice::<ZhtpAuthResponse>(peer_data) {
            info!(" Verifying ZHTP authentication from WiFi Direct peer {}", &device_id[..16.min(device_id.len())]);
            
            match auth_manager.verify_response(&response).await {
                Ok(verification) => {
                    if verification.authenticated {
                        info!(" WiFi Direct peer {} authenticated successfully", &device_id[..16.min(device_id.len())]);
                        info!("   Blockchain identity verified with Dilithium2 signature");
                        info!("   Trust score: {:.2}", verification.trust_score);
                        
                        // Store authenticated peer
                        self.authenticated_peers.write().await.insert(device_id.to_string(), verification);
                        
                        return Ok(true);
                    } else {
                        warn!(" WiFi Direct peer {} authentication FAILED", &device_id[..16.min(device_id.len())]);
                        warn!("   Invalid blockchain signature - rejecting connection");
                        return Ok(false);
                    }
                }
                Err(e) => {
                    warn!(" WiFi Direct peer {} authentication error: {}", &device_id[..16.min(device_id.len())], e);
                    return Ok(false);
                }
            }
        }
        
        // No valid auth response - reject
        warn!(" WiFi Direct device {} did not provide ZHTP authentication", &device_id[..16.min(device_id.len())]);
        warn!("   Rejecting non-ZHTP connection attempt");
        Ok(false)
    }

    /// Get list of discovered ZHTP services with enhanced information
    pub async fn get_discovered_services(&self) -> Vec<(String, HashMap<String, String>)> {
        let orchestrator = {
            let orch_guard = self.orchestrator.read().await;
            if let Some(orch) = orch_guard.as_ref() {
                orch.clone()
            } else {
                return Vec::new();
            }
        };

        orchestrator.get_discovered_services().await
    }

    /// Get list of discovered peer addresses (for bootstrap integration)
    pub async fn get_discovered_peer_addresses(&self) -> Vec<String> {
        let orchestrator = {
            let orch_guard = self.orchestrator.read().await;
            if let Some(orch) = orch_guard.as_ref() {
                orch.clone()
            } else {
                return Vec::new();
            }
        };

        orchestrator.get_discovered_peer_addresses().await
    }

    /// Send mesh message to a peer (delegates to mesh manager via orchestrator)
    pub async fn send_mesh_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        info!(" Sending WiFi Direct mesh message to {}: {} bytes", target_address, message.len());

        let orchestrator = {
            let orch_guard = self.orchestrator.read().await;
            if let Some(orch) = orch_guard.as_ref() {
                orch.clone()
            } else {
                return Err(anyhow::anyhow!("WiFi Direct orchestrator not initialized"));
            }
        };

        // Delegate to mesh manager
        orchestrator.mesh.send_message(target_address, message).await
    }
}

/// WiFi Direct mesh network status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiFiDirectMeshStatus {
    pub discovery_active: bool,
    pub group_owner: bool,
    pub connected_peers: u32,
    pub group_members: u32,
    pub signal_strength: i32, // dBm
    pub throughput_mbps: u32,
    pub mesh_quality: f64, // 0.0 to 1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wifi_direct_mesh_creation() {
        let node_id = [1u8; 32];
        let protocol = WiFiDirectMeshProtocol::new(node_id).unwrap();
        
        assert_eq!(protocol.node_id, node_id);
        assert!(!protocol.discovery_active);
        assert!(!protocol.group_owner); // Initially not group owner
    }
    
    #[tokio::test]
    #[ignore] // Ignore hardware-dependent test
    async fn test_wifi_direct_discovery() {
        let node_id = [1u8; 32];
        let mut protocol = WiFiDirectMeshProtocol::new(node_id).unwrap();

        // Enable WiFi Direct first (it's disabled by default for security)
        protocol.enable().await.unwrap();

        let result = protocol.start_discovery().await;
        assert!(result.is_ok());
    }
}
