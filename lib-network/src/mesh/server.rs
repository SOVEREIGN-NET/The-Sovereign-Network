use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use uuid::Uuid;
use tracing::{info, warn, error, debug};
use serde_json;

use lib_crypto::{PublicKey, Signature};
use crate::mesh::{MeshConnection, MeshProtocolStats};
use crate::protocols::NetworkProtocol;

// Port configuration for mesh networking protocols
// These are runtime/transport configuration, not node state
const QUIC_MESH_PORT: u16 = 9334;      // Node-to-node QUIC communication port
const MESH_BOOTSTRAP_PORT: u16 = 33444; // Bootstrap peer discovery port

/// Simple in-memory routing statistics (no blockchain state)
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Total number of messages routed through this node
    pub messages_routed: u64,
    /// Total bytes routed through this node
    pub bytes_routed: u64,
    /// Theoretical tokens that would be earned (for display only, not actual balance)
    pub theoretical_tokens_earned: u64,
    /// Number of successful routing operations
    pub successful_routes: u64,
    /// Number of failed routing operations
    pub failed_routes: u64,
    /// Protocol usage distribution (for bonus calculation)
    pub protocol_usage: HashMap<String, u64>,
}

/// Quality metrics for calculating quality bonuses
#[derive(Debug, Clone)]
pub struct QualityMetrics {
    /// When the node started
    pub start_time: Instant,
    /// Total successful operations
    pub successful_ops: u64,
    /// Total failed operations
    pub failed_ops: u64,
    /// Latency samples (in milliseconds)
    pub latency_samples: Vec<u64>,
    /// Maximum latency samples to keep
    pub max_samples: usize,
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            successful_ops: 0,
            failed_ops: 0,
            latency_samples: Vec::new(),
            max_samples: 1000, // Keep last 1000 samples
        }
    }
}

impl QualityMetrics {
    /// Calculate uptime percentage
    pub fn uptime_percentage(&self) -> f64 {
        // For now, assume 100% uptime if node is running
        // In production, this would track downtime periods
        100.0
    }
    
    /// Calculate success rate percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_ops + self.failed_ops;
        if total == 0 {
            return 100.0;
        }
        (self.successful_ops as f64 / total as f64) * 100.0
    }
    
    /// Calculate average latency in milliseconds
    pub fn average_latency(&self) -> f64 {
        if self.latency_samples.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.latency_samples.iter().sum();
        sum as f64 / self.latency_samples.len() as f64
    }
    
    /// Record a successful operation with latency
    pub fn record_success(&mut self, latency_ms: u64) {
        self.successful_ops += 1;
        self.latency_samples.push(latency_ms);
        
        // Keep only recent samples
        if self.latency_samples.len() > self.max_samples {
            self.latency_samples.remove(0);
        }
    }
    
    /// Record a failed operation
    pub fn record_failure(&mut self) {
        self.failed_ops += 1;
    }
    
    /// Calculate quality bonus multiplier based on metrics
    pub fn calculate_quality_multiplier(&self) -> f64 {
        let mut multiplier = 1.0;
        
        // Uptime bonus: +5% for >99% uptime
        let uptime = self.uptime_percentage();
        if uptime > 99.0 {
            multiplier += 0.05;
            debug!("Quality bonus: +5% for {}% uptime", uptime);
        }
        
        // Success rate bonus: +10% for >95% success
        let success = self.success_rate();
        if success > 95.0 {
            multiplier += 0.10;
            debug!("Quality bonus: +10% for {}% success rate", success);
        }
        
        // Latency bonus: +5% for <50ms average
        let latency = self.average_latency();
        if latency > 0.0 && latency < 50.0 {
            multiplier += 0.05;
            debug!("Quality bonus: +5% for {:.1}ms average latency", latency);
        }
        
        multiplier
    }
}

/// Storage statistics tracked by the mesh server
/// 
/// Tracks storage contributions for economic reward calculations
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total number of content items stored
    pub items_stored: u64,
    /// Total bytes stored (cumulative size of all content)
    pub bytes_stored: u64,
    /// Total number of content retrievals served
    pub retrievals_served: u64,
    /// Total storage duration in hours (sum of all content storage time)
    pub storage_duration_hours: u64,
    /// Theoretical tokens earned from storage (for display only)
    pub theoretical_tokens_earned: u64,
    /// Number of successful storage operations
    pub successful_storage_ops: u64,
    /// Number of failed storage operations
    pub failed_storage_ops: u64,
}

// use crate::types::*; // Removed - unused imports
use crate::types::mesh_message::ZhtpMeshMessage;
use crate::types::api_response::ZhtpApiResponse;
use crate::types::relay_type::LongRangeRelayType;
use crate::relays::LongRangeRelay;

/// Emergency halt policy governing kill-switch semantics (BFT-H, Issue #1007).
///
/// # Semantics
///
/// An emergency halt operates at **two distinct levels**:
///
/// 1. **Node-level halt** (`emergency_stop` on a single mesh server): stops
///    the local node from processing new connections.  This is always a
///    node-local effect; it does NOT alter the global consensus state.
///
/// 2. **Consensus-level halt**: a coordinated halt of the BFT protocol that
///    requires explicit agreement from ≥ 2/3 + 1 validators.  Without quorum,
///    uncoordinated halts create network partitions that break liveness and may
///    violate safety.
///
/// # Who can trigger
///
/// | Level | Trigger | Quorum required |
/// |---|---|---|
/// | Node-level | Owner or Admin wallet | No |
/// | Consensus-level | Governance vote / DAO proposal | Yes (2/3+1) |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyHaltPolicy {
    /// Whether this halt is coordinated across consensus validators.
    pub requires_consensus_quorum: bool,
    /// Minimum fraction of validators that must agree (numerator out of 3).
    pub quorum_numerator: u32,
    /// Denominator for quorum fraction (always 3 for BFT).
    pub quorum_denominator: u32,
}

impl Default for EmergencyHaltPolicy {
    fn default() -> Self {
        Self {
            requires_consensus_quorum: true,
            quorum_numerator: 2,
            quorum_denominator: 3,
        }
    }
}

impl EmergencyHaltPolicy {
    /// Returns whether the given validator count satisfies the quorum requirement.
    pub fn quorum_satisfied(&self, agreeing_validators: u32, total_validators: u32) -> bool {
        if total_validators == 0 {
            return false;
        }
        // require strictly more than 2/3: agreeing > 2/3 * total  ⟺  agreeing * 3 > 2 * total
        agreeing_validators * self.quorum_denominator > self.quorum_numerator * total_validators
    }

    /// Validates that a consensus-level halt has sufficient quorum.
    ///
    /// # Errors
    /// Returns `Err` if `requires_consensus_quorum` is `true` and quorum is not met.
    pub fn validate_consensus_halt(
        &self,
        agreeing_validators: u32,
        total_validators: u32,
    ) -> Result<(), String> {
        if self.requires_consensus_quorum && !self.quorum_satisfied(agreeing_validators, total_validators) {
            return Err(format!(
                "consensus halt requires 2/3+1 validator agreement \
                 ({agreeing_validators}/{total_validators} is insufficient)"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod emergency_halt_tests {
    use super::*;

    #[test]
    fn test_quorum_satisfied() {
        let policy = EmergencyHaltPolicy::default();
        assert!(policy.quorum_satisfied(7, 10));  // 7 > 6.67
        assert!(!policy.quorum_satisfied(6, 10)); // 6 ≤ 6.67
    }

    #[test]
    fn test_validate_consensus_halt_fails_without_quorum() {
        let policy = EmergencyHaltPolicy::default();
        assert!(policy.validate_consensus_halt(1, 10).is_err());
    }

    #[test]
    fn test_validate_consensus_halt_passes_with_quorum() {
        let policy = EmergencyHaltPolicy::default();
        assert!(policy.validate_consensus_halt(8, 10).is_ok());
    }
}

/// Security permission levels for network operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionLevel {
    /// Node owner - full control including emergency stop
    Owner,
    /// Network admin - can disconnect peers and manage connections
    Admin, 
    /// Regular user - can only disconnect own connections
    User,
    /// No permissions
    None,
}

/// Authentication credentials for secure operations
#[derive(Debug, Clone)]
pub struct SecurityCredentials {
    /// Caller's wallet public key
    pub wallet_key: PublicKey,
    /// Cryptographic signature of the operation
    pub signature: Vec<u8>,
    /// Timestamp to prevent replay attacks
    pub timestamp: u64,
    /// Operation nonce
    pub nonce: String,
}

/// Audit log entry for security operations
#[derive(Debug, Clone)]
pub struct SecurityAuditLog {
    pub timestamp: u64,
    pub operation: String,
    pub caller_key: String,
    pub target: Option<String>,
    pub permission_level: String,
    pub success: bool,
    pub reason: String,
}

// TCP/UDP bootstrap servers removed - using QUIC only
use crate::monitoring::health_monitoring::HealthMonitor;
use crate::dht::{ZkDHTIntegration, DHTNetworkStatus};
use crate::discovery::hardware::HardwareCapabilities;

// Import implementations from other packages
use lib_economy::EconomicModel;
use crate::storage_stub::UnifiedStorageSystem;

/// Network configuration for mesh node
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub node_id: [u8; 32],
    pub listen_port: u16,
    pub mesh_port: u16,
    pub max_peers: usize,
    pub protocols: Vec<NetworkProtocol>,
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
}

/// ZHTP Mesh Server - The New Internet
/// 
/// This replaces traditional internet infrastructure with a pure mesh network
/// that provides free internet access to everyone while paying users for participation
#[derive(Clone)]
pub struct ZhtpMeshServer {
    /// Server ID for this mesh node
    pub server_id: Uuid,
    /// Network configuration (ports, bootstrap peers, protocol settings)
    pub config: Arc<NetworkConfig>,
    /// Underlying mesh networking node with complete implementation
    pub mesh_node: Arc<RwLock<MeshNode>>,
    /// Economic incentive system
    pub economics: Arc<RwLock<EconomicModel>>,
    /// Distributed storage system
    pub storage: Arc<RwLock<UnifiedStorageSystem>>,
    /// Unified peer registry (Ticket #149: replaces separate mesh_connections)
    pub peer_registry: crate::peer_registry::SharedPeerRegistry,
    /// Long-range relay nodes (LoRaWAN gateways, satellite uplinks)
    pub long_range_relays: Arc<RwLock<HashMap<String, LongRangeRelay>>>,

    /// Revenue sharing pools for UBI distribution
    pub revenue_pools: Arc<RwLock<HashMap<String, u64>>>,
    /// Mesh protocol statistics
    pub stats: Arc<RwLock<MeshProtocolStats>>,
    /// Health monitoring system
    pub health_monitor: HealthMonitor,
    /// Zero-Knowledge DHT integration
    pub dht: Arc<RwLock<ZkDHTIntegration>>,
    /// Hardware capabilities detected on this system  
    pub hardware_capabilities: Option<HardwareCapabilities>,
    
    /// Routing statistics and performance metrics (in-memory counters)
    pub routing_stats: Arc<RwLock<RoutingStats>>,
    
    /// Storage statistics and performance metrics (in-memory counters)
    pub storage_stats: Arc<RwLock<StorageStats>>,
    
    /// Quality metrics for bonus calculation
    pub quality_metrics: Arc<RwLock<QualityMetrics>>,
    
    /// Active Bluetooth LE mesh protocol instance
    pub bluetooth_protocol: Option<Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>>,
    /// Active WiFi Direct mesh protocol instance
    pub wifi_direct_protocol: Option<Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>>,
    /// LoRaWAN mesh protocol instance
    pub lorawan_protocol: Option<Arc<RwLock<crate::protocols::lorawan::LoRaWANMeshProtocol>>>,
    /// Satellite mesh protocol instance
    pub satellite_protocol: Option<Arc<RwLock<crate::protocols::satellite::SatelliteMeshProtocol>>>,
    /// QUIC mesh protocol instance
    pub quic_protocol: Option<Arc<RwLock<crate::protocols::quic_mesh::QuicMeshProtocol>>>,
    /// Active protocol status tracking
    pub active_protocols: Arc<RwLock<HashMap<NetworkProtocol, bool>>>,
    
    // Message Routing and Handling (Phase 4)
    /// Message router for multi-hop forwarding
    pub message_router: Option<Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>>,
    /// Message handler for processing received messages
    pub message_handler: Option<Arc<RwLock<crate::messaging::message_handler::MeshMessageHandler>>>,
    
    // Blockchain Synchronization
    /// Sync coordinator to prevent duplicate syncs across multiple protocols
    pub sync_coordinator: Arc<crate::blockchain_sync::SyncCoordinator>,
    
    // Safety and Emergency Features
    /// Emergency stop flag for immediate shutdown
    pub emergency_stop: Arc<RwLock<bool>>,
    /// Maximum allowed connections (safety limit)  
    pub max_connections: Arc<RwLock<usize>>,
    /// Connection rate limiter to prevent abuse
    pub connection_attempts: Arc<RwLock<HashMap<String, u32>>>,
    
    // Security and Access Control
    /// Node owner's wallet public key (full permissions)
    pub owner_wallet_key: PublicKey,
    /// Authorized admin wallet keys (can disconnect peers)
    pub admin_wallet_keys: Arc<RwLock<Vec<PublicKey>>>,
    /// Security audit log for all operations
    pub security_audit_log: Arc<RwLock<Vec<SecurityAuditLog>>>,
}

/// MeshNode implementation for pure mesh networking
#[derive(Debug)]
pub struct MeshNode {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Supported protocols for mesh networking
    pub protocols: Vec<NetworkProtocol>,
    /// Maximum number of peers to connect to
    pub max_peers: usize,
    /// Bootstrap peers for initial discovery
    pub bootstrap_peers: Vec<String>,
    /// Current mesh connections
    pub active_connections: HashMap<PublicKey, MeshConnection>,
    /// Mesh discovery state
    pub discovery_active: bool,
    /// Hardware capabilities detected on this system
    pub hardware_capabilities: Option<HardwareCapabilities>,
}

impl MeshNode {
    /// Create new pure mesh node
    pub fn new_pure_mesh(config: NetworkConfig) -> Result<Self> {
        Ok(MeshNode {
            node_id: config.node_id,
            protocols: config.protocols,
            max_peers: config.max_peers,
            bootstrap_peers: config.bootstrap_peers,
            active_connections: HashMap::new(),
            discovery_active: false,
            hardware_capabilities: None,
        })
    }
    
    /// Create new pure mesh node with hardware detection
    pub async fn new_with_hardware_detection(config: NetworkConfig) -> Result<Self> {
        info!("Detecting available mesh networking hardware...");
        
        let hardware_capabilities = match HardwareCapabilities::detect().await {
            Ok(caps) => {
                info!("Hardware detection completed");
                Some(caps)
            },
            Err(e) => {
                warn!("Hardware detection failed: {}", e);
                None
            }
        };
        
        // Filter protocols based on hardware availability
        let filtered_protocols = if let Some(ref caps) = hardware_capabilities {
            filter_protocols_by_hardware(&config.protocols, caps)
        } else {
            // If hardware detection fails, use configured protocols as-is
            // The caller is responsible for configuring what they want
            warn!("Hardware detection failed - using configured protocols without hardware validation");
            config.protocols.clone()
        };
        
        info!(" Enabled protocols: {:?}", filtered_protocols);
        
        Ok(MeshNode {
            node_id: config.node_id,
            protocols: filtered_protocols,
            max_peers: config.max_peers,
            bootstrap_peers: config.bootstrap_peers,
            active_connections: HashMap::new(),
            discovery_active: false,
            hardware_capabilities,
        })
    }
    
    /// Start pure mesh networking - protocols are managed by ZhtpMeshServer
    pub async fn start_pure_mesh(&mut self) -> Result<()> {
        info!(" Mesh node ready - protocol management handled by server layer");
        
        self.discovery_active = true;
        info!("Mesh node initialized with {} configured protocols", self.protocols.len());
        
        Ok(())
    }
}

/// Filter protocols based on available hardware
fn filter_protocols_by_hardware(
    requested_protocols: &[NetworkProtocol], 
    hardware_caps: &HardwareCapabilities
) -> Vec<NetworkProtocol> {
    let mut enabled_protocols = Vec::new();
    
    for protocol in requested_protocols {
        match protocol {
            NetworkProtocol::BluetoothLE => {
                if hardware_caps.bluetooth_available {
                    info!("Bluetooth LE enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("Bluetooth LE disabled - no hardware detected");
                }
            },
            NetworkProtocol::WiFiDirect => {
                if hardware_caps.wifi_direct_available {
                    info!("WiFi Direct enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("WiFi Direct disabled - no hardware detected");
                }
            },
            NetworkProtocol::LoRaWAN => {
                if hardware_caps.lorawan_available() {
                    info!("LoRaWAN enabled - hardware detected");
                    enabled_protocols.push(protocol.clone());
                } else {
                    warn!("LoRaWAN disabled - no radio hardware detected");
                    info!("To enable LoRaWAN: Connect a LoRaWAN radio module (SX127x, USB adapter, etc.)");
                }
            },
            NetworkProtocol::Satellite => {
                // Satellite doesn't require special hardware detection for now
                info!("🛰️ Satellite protocol enabled (software-based)");
                enabled_protocols.push(protocol.clone());
            },
            _ => {
                // Enable other protocols by default
                enabled_protocols.push(protocol.clone());
            }
        }
    }
    
    if enabled_protocols.is_empty() {
        warn!("No protocols enabled based on requested config and available hardware");
        // Don't force Bluetooth - respect the user's configuration choice
        // Empty protocol list means the node will only use configured bootstrap peers
    }
    
    enabled_protocols
}

impl ZhtpMeshServer {
    /// Record routing activity when we forward a message with protocol and quality bonuses
    /// 
    /// # Arguments
    /// * `data_size` - Size of the routed data in bytes
    /// * `hop_count` - Number of hops in the route
    /// * `protocol` - Network protocol used (for protocol bonuses)
    /// * `latency_ms` - Latency of the operation in milliseconds (for quality bonuses)
    /// 
    /// # Bonuses
    /// * **Protocol Bonuses**:
    ///   - Bluetooth LE: 2.0x (mesh-first incentive)
    ///   - WiFi Direct: 1.5x (local mesh)
    ///   - LoRaWAN: 3.0x (rural/long-range)
    ///   - TCP: 1.0x (standard internet, no bonus)
    /// * **Quality Bonuses** (calculated separately):
    ///   - +5% for >99% uptime
    ///   - +10% for >95% success rate
    ///   - +5% for <50ms average latency
    pub async fn record_routing_activity(
        &self,
        data_size: usize,
        hop_count: u8,
        protocol: NetworkProtocol,
        latency_ms: u64,
    ) -> Result<()> {
        // Calculate base reward components
        let base_reward = 10; // 10 tokens per message routed
        let size_bonus = (data_size / 1024) as u64; // 1 token per KB
        let hop_bonus = hop_count as u64 * 5; // 5 tokens per hop
        
        // Sum base components
        let base_total = base_reward + size_bonus + hop_bonus;
        
        // Apply protocol multiplier (mesh incentive!)
        let protocol_multiplier = match protocol {
            NetworkProtocol::BluetoothLE => 2.0,      // 2x for true mesh
            NetworkProtocol::BluetoothClassic => 1.8, // 1.8x for BT classic
            NetworkProtocol::WiFiDirect => 1.5,       // 1.5x for local mesh
            NetworkProtocol::LoRaWAN => 3.0,          // 3x for rural/long-range
            NetworkProtocol::Satellite => 2.5,        // 2.5x for satellite
            NetworkProtocol::QUIC => 1.4,             // 1.4x for modern mesh transport
            NetworkProtocol::TCP => 1.0,              // Standard internet (no bonus)
            NetworkProtocol::UDP => 1.1,              // Slight bonus for UDP mesh
        };
        
        let reward_with_protocol = (base_total as f64 * protocol_multiplier) as u64;
        
        // Get quality multiplier
        let quality_multiplier = {
            let metrics = self.quality_metrics.read().await;
            metrics.calculate_quality_multiplier()
        };
        
        // Apply quality multiplier
        let final_reward = (reward_with_protocol as f64 * quality_multiplier) as u64;
        
        // Update quality metrics (record success with latency)
        {
            let mut metrics = self.quality_metrics.write().await;
            metrics.record_success(latency_ms);
        }
        
        // Update in-memory statistics
        {
            let mut stats = self.routing_stats.write().await;
            stats.messages_routed += 1;
            stats.bytes_routed += data_size as u64;
            stats.theoretical_tokens_earned += final_reward;
            stats.successful_routes += 1;
            
            // Track protocol usage for statistics
            let protocol_name = format!("{:?}", protocol);
            *stats.protocol_usage.entry(protocol_name).or_insert(0) += 1;
        }
        
        // Also update mesh protocol stats
        {
            let mut mesh_stats = self.stats.write().await;
            mesh_stats.total_data_routed += data_size as u64;
        }
        
        info!(
            "Routed {} bytes ({} hops) via {:?} - base: {}, protocol: {}x, quality: {:.2}x, final: {} tokens",
            data_size, hop_count, protocol, base_total, protocol_multiplier, quality_multiplier, final_reward
        );
        
        Ok(())
    }
    
    /// Record routing failure (for quality metrics)
    pub async fn record_routing_failure(&self) -> Result<()> {
        let mut metrics = self.quality_metrics.write().await;
        metrics.record_failure();
        
        let mut stats = self.routing_stats.write().await;
        stats.failed_routes += 1;
        
        Ok(())
    }
    
    /// Get quality metrics summary
    pub async fn get_quality_summary(&self) -> (f64, f64, f64, f64) {
        let metrics = self.quality_metrics.read().await;
        (
            metrics.uptime_percentage(),
            metrics.success_rate(),
            metrics.average_latency(),
            metrics.calculate_quality_multiplier(),
        )
    }
    
    /// Get node's routing statistics
    pub async fn get_routing_stats(&self) -> RoutingStats {
        self.routing_stats.read().await.clone()
    }
    
    /// Get theoretical tokens earned (for display only, not actual balance)
    pub async fn get_theoretical_earnings(&self) -> u64 {
        self.routing_stats.read().await.theoretical_tokens_earned
    }
    
    /// Verify node ownership using wallet public key
    pub async fn verify_node_ownership(&self, wallet_key: &PublicKey) -> bool {
        // Check if the wallet key matches the owner wallet key
        wallet_key.as_bytes() == self.owner_wallet_key.as_bytes()
    }
    
    /// Get permission level for a wallet (simplified)
    pub async fn get_permission_level(&self, wallet_key: &PublicKey) -> PermissionLevel {
        // Owner wallet has full control
        if self.verify_node_ownership(wallet_key).await {
            return PermissionLevel::Owner;
        }
        
        // Check admin wallets
        let admin_keys = self.admin_wallet_keys.read().await;
        if admin_keys.iter().any(|key| key.as_bytes() == wallet_key.as_bytes()) {
            return PermissionLevel::Admin;
        }
        
        // Everyone else is a regular user
        PermissionLevel::User
    }
    
    /// Add admin wallet (only owner can do this)
    pub async fn add_admin_wallet(&self, caller_wallet_key: &PublicKey, admin_wallet_key: PublicKey) -> Result<()> {
        // Verify caller is the owner
        if !self.verify_node_ownership(caller_wallet_key).await {
            return Err(anyhow!("Only node owner can add admin wallets"));
        }
        
        let mut admin_keys = self.admin_wallet_keys.write().await;
        admin_keys.push(admin_wallet_key.clone());
        
        // Log security operation
        self.log_security_operation(
            "add_admin_wallet".to_string(),
            caller_wallet_key.clone(),
            Some(format!("admin:{}", hex::encode(admin_wallet_key.as_bytes()))),
            "Owner".to_string(),
            true,
            "Admin wallet added successfully".to_string(),
        ).await;
        
        info!("Added admin wallet: {}", hex::encode(admin_wallet_key.as_bytes()));
        Ok(())
    }
    
    /// Emergency stop (owner or admin only).
    ///
    /// # BFT-H Emergency Halt Semantics (Issue #1007)
    ///
    /// **This is a NODE-LEVEL control only.**  It does NOT constitute a
    /// consensus-level halt.  Specifically:
    ///
    /// - Calling this on a single node stops that node from processing new
    ///   connections and messages, but it does NOT halt the consensus protocol
    ///   across the validator set.
    /// - A **consensus-level halt** (one that safely stops finality) requires
    ///   agreement from at least 2/3 + 1 validators.  Without quorum, an
    ///   uncoordinated halt partitions the validator set and risks breaking
    ///   liveness or, in extreme cases, safety.
    /// - Operators MUST coordinate out-of-band before triggering emergency stops
    ///   on multiple validators simultaneously.
    ///
    /// See [`EmergencyHaltPolicy`] for the governing rules.
    pub async fn emergency_stop(&self, caller_wallet_key: &PublicKey) -> Result<()> {
        let permission_level = self.get_permission_level(caller_wallet_key).await;
        
        match permission_level {
            PermissionLevel::Owner | PermissionLevel::Admin => {
                *self.emergency_stop.write().await = true;
                
                self.log_security_operation(
                    "emergency_stop".to_string(),
                    caller_wallet_key.clone(),
                    None,
                    format!("{:?}", permission_level),
                    true,
                    "Emergency stop activated".to_string(),
                ).await;
                
                warn!(" EMERGENCY STOP activated by wallet: {}", hex::encode(caller_wallet_key.as_bytes()));
                Ok(())
            }
            _ => {
                self.log_security_operation(
                    "emergency_stop".to_string(),
                    caller_wallet_key.clone(),
                    None,
                    format!("{:?}", permission_level),
                    false,
                    "Insufficient permissions".to_string(),
                ).await;
                
                Err(anyhow!("Only owner or admin wallets can trigger emergency stop"))
            }
        }
    }
    
    /// Log security operations for audit trail
    async fn log_security_operation(
        &self,
        operation: String,
        caller_key: PublicKey,
        target: Option<String>,
        permission_level: String,
        success: bool,
        reason: String,
    ) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let audit_entry = SecurityAuditLog {
            timestamp,
            operation,
            caller_key: hex::encode(caller_key.as_bytes()),
            target,
            permission_level,
            success,
            reason,
        };
        
        self.security_audit_log.write().await.push(audit_entry);
    }
    
    /// Start Bluetooth LE mesh discovery with persistent protocol instance
    async fn start_bluetooth_discovery(&mut self) -> Result<()> {
        use crate::protocols::bluetooth::BluetoothMeshProtocol;
        
        // Safety check: Emergency stop
        if *self.emergency_stop.read().await {
            return Err(anyhow!(" Cannot start discovery - emergency stop is active"));
        }
        
        // Safety check: Connection limit
        let stats = self.get_network_stats().await;
        let current_connections = stats.active_connections;
        let max_connections = *self.max_connections.read().await;
        let at_limit = (current_connections as usize) >= max_connections;
        if at_limit {
            warn!(" Connection limit reached ({}/{}), skipping Bluetooth discovery", 
                current_connections, max_connections);
            return Err(anyhow!("Connection limit reached"));
        }
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Create temporary PublicKey from node_id for Bluetooth initialization
        // Note: In production, the main zhtp application provides the real PublicKey
        let temp_public_key = lib_crypto::PublicKey::new(node_id.to_vec());
        
        // Initialize Bluetooth LE mesh protocol
        let bluetooth_protocol = BluetoothMeshProtocol::new(node_id, temp_public_key)?;
        let bluetooth_arc = Arc::new(RwLock::new(bluetooth_protocol));
        
        // Start discovery
        bluetooth_arc.write().await.start_discovery().await?;
        
        // Store the protocol instance for persistent management
        self.bluetooth_protocol = Some(bluetooth_arc.clone());
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::BluetoothLE, true);
        
        // Start background monitoring for this protocol
        self.start_bluetooth_monitoring(bluetooth_arc).await?;
        
        info!(" Bluetooth LE mesh discovery active with persistent management");
        Ok(())
    }
    
    /// Start WiFi Direct mesh connections with persistent protocol instance
    async fn start_wifi_direct_discovery(&mut self) -> Result<()> {
        use crate::protocols::wifi_direct::WiFiDirectMeshProtocol;
        
        // Safety check: Emergency stop
        if *self.emergency_stop.read().await {
            return Err(anyhow!(" Cannot start discovery - emergency stop is active"));
        }
        
        // Safety check: Connection limit
        let stats = self.get_network_stats().await;
        let current_connections = stats.active_connections;
        let max_connections = *self.max_connections.read().await;
        let at_limit = (current_connections as usize) >= max_connections;
        if at_limit {
            warn!(" Connection limit reached ({}/{}), skipping WiFi Direct discovery", 
                current_connections, max_connections);
            return Err(anyhow!("Connection limit reached"));
        }
        
        let node_id = self.mesh_node.read().await.node_id;
        
        // Initialize WiFi Direct mesh protocol
        let wifi_protocol = WiFiDirectMeshProtocol::new(node_id)?;
        let wifi_arc = Arc::new(RwLock::new(wifi_protocol));
        
        // Start discovery
        wifi_arc.write().await.start_discovery().await?;
        
        // Store the protocol instance for persistent management
        self.wifi_direct_protocol = Some(wifi_arc.clone());
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::WiFiDirect, true);
        
        // Start background monitoring for this protocol
        self.start_wifi_direct_monitoring(wifi_arc).await?;
        
        info!("WiFi Direct mesh discovery active with persistent management");
        Ok(())
    }
    
    /// Start QUIC mesh protocol with persistent instance
    ///
    /// Uses UHP v2 handshake for all connections (mutual authentication + PQC key exchange)
    async fn start_quic_discovery(&mut self) -> Result<()> {
        use crate::protocols::quic_mesh::QuicMeshProtocol;

        // Create server identity for UHP authentication
        // TODO: This should use a persistent server identity from config
        let identity = Arc::new(create_default_mesh_identity());

        // Bind to configured QUIC mesh port (PQC encrypted)
        let bind_addr = format!("0.0.0.0:{}", self.config.mesh_port).parse().unwrap();

        // Initialize QUIC mesh protocol with UHP v2 authentication
        let mut quic_protocol = QuicMeshProtocol::new(identity, bind_addr)?;
        
        // If message handler is already initialized, set it
        if let Some(handler) = &self.message_handler {
            quic_protocol.set_message_handler(handler.clone());
        }
        
        let quic_arc = Arc::new(RwLock::new(quic_protocol));
        
        // Start receiving
        quic_arc.read().await.start_receiving().await?;
        
        // Store the protocol instance
        self.quic_protocol = Some(quic_arc.clone());
        
        // Mark protocol as active
        self.active_protocols.write().await.insert(NetworkProtocol::QUIC, true);
        
        info!("🚀 QUIC mesh protocol active with PQC encryption on port {}", self.config.mesh_port);
        
        // Connect to bootstrap peers if configured
        // ARCHITECTURE NOTE: Bootstrap peers use QUIC exclusively because:
        // 1. QUIC is the required transport for mesh bootstrap (enable_quic: true in ProtocolsConfig)
        // 2. Mesh protocols (Bluetooth, WiFi, etc.) are optional and can be disabled
        // 3. Bootstrap must work even when other protocols are disabled
        // This means bootstrap_peers should always specify QUIC port (9334), but we support
        // automatic conversion from mesh port (33444) for backward compatibility with configs
        let bootstrap_peers = self.mesh_node.read().await.bootstrap_peers.clone();
        if !bootstrap_peers.is_empty() {
            info!("📡 Connecting to {} bootstrap peer(s) via QUIC...", bootstrap_peers.len());
            let quic = quic_arc.read().await;

            for peer_str in &bootstrap_peers {
                // Parse address - might be:
                // - "192.168.1.245:9334" (correct QUIC port)
                // - "192.168.1.245:33444" (legacy mesh port - converts to QUIC port for compatibility)
                // - "192.168.1.245" (IP only - uses QUIC default port)
                // - "zhtp://192.168.1.245:9334" (URL format)
                let addr_str = peer_str.trim_start_matches("zhtp://").trim_start_matches("http://");

                // Parse the address and fix port if needed
                let peer_addr = if let Some(colon_pos) = addr_str.rfind(':') {
                    let ip_part = &addr_str[..colon_pos];
                    let port_str = &addr_str[colon_pos + 1..];

                    // If port is legacy mesh port (33444), convert to configured QUIC port
                    let port = match port_str.parse::<u16>() {
                        Ok(p) if p == MESH_BOOTSTRAP_PORT => {
                            info!("   ⚠️  Peer has legacy mesh port {}, converting to configured QUIC port {}: {}", MESH_BOOTSTRAP_PORT, self.config.mesh_port, peer_str);
                            self.config.mesh_port
                        }
                        Ok(p) => p,
                        Err(_) => {
                            warn!("   Failed to parse port from bootstrap peer address '{}': invalid port", peer_str);
                            continue;
                        }
                    };

                    match format!("{}:{}", ip_part, port).parse::<std::net::SocketAddr>() {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!("   Failed to parse bootstrap peer address '{}': {}", peer_str, e);
                            continue;
                        }
                    }
                } else {
                    // No port specified - use configured QUIC mesh port
                    info!("   ℹ️  Peer has no port, using configured QUIC mesh port {}: {}", self.config.mesh_port, peer_str);
                    match format!("{}:{}", addr_str, self.config.mesh_port).parse::<std::net::SocketAddr>() {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!("   Failed to parse bootstrap peer address '{}': {}", peer_str, e);
                            continue;
                        }
                    }
                };

                info!("   Connecting to bootstrap peer: {}", peer_addr);
                if let Err(e) = quic.connect_to_peer(peer_addr).await {
                    warn!("   Failed to connect to bootstrap peer {}: {}", peer_addr, e);
                } else {
                    info!("   ✓ Connected to bootstrap peer {}", peer_addr);
                }
            }
        }
        
        Ok(())
    }

    /// Start all configured mesh protocols
    async fn start_mesh_protocols(&mut self) -> Result<()> {
        let protocols = {
            let node = self.mesh_node.read().await;
            node.protocols.clone()
        };

        for protocol in protocols {
            match protocol {
                NetworkProtocol::BluetoothLE => {
                    // BUGFIX: Skip Bluetooth discovery if not explicitly enabled in config
                    // This respects enable_bluetooth=false in config.toml
                    info!("Attempting to start Bluetooth LE discovery...");
                    if let Err(e) = self.start_bluetooth_discovery().await {
                        warn!("Failed to start Bluetooth discovery (expected if hardware unavailable): {}", e);
                    }
                },
                NetworkProtocol::WiFiDirect => {
                    if let Err(e) = self.start_wifi_direct_discovery().await {
                        warn!("Failed to start WiFi Direct discovery: {}", e);
                    }
                },
                NetworkProtocol::QUIC => {
                    if let Err(e) = self.start_quic_discovery().await {
                        warn!("Failed to start QUIC discovery: {}", e);
                    }
                },
                NetworkProtocol::LoRaWAN => {
                    // LoRaWAN is handled by long-range relay initialization
                },
                NetworkProtocol::Satellite => {
                    // Satellite is handled by long-range relay initialization
                },
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Start monitoring for Bluetooth protocol
    /// TODO (Ticket #149): Update to use peer_registry
    async fn start_bluetooth_monitoring(&self, protocol: Arc<RwLock<crate::protocols::bluetooth::BluetoothMeshProtocol>>) -> Result<()> {
        let peer_registry = self.peer_registry.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                
                let connected_peers = protocol.read().await.get_connected_peers().await;
                // Update connections map...
                // This is a simplified monitoring loop
            }
        });
        
        Ok(())
    }

    /// Start monitoring for WiFi Direct protocol
    /// TODO (Ticket #149): Update to use peer_registry
    async fn start_wifi_direct_monitoring(&self, protocol: Arc<RwLock<crate::protocols::wifi_direct::WiFiDirectMeshProtocol>>) -> Result<()> {
        let peer_registry = self.peer_registry.clone();
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                
                // Monitor WiFi connections
            }
        });
        
        Ok(())
    }

    /// Create a new ZHTP Mesh Server - The Internet
    pub async fn new(
        node_id: [u8; 32],
        owner_key: PublicKey,  // Owner key for security
        storage: UnifiedStorageSystem,
        protocols: Vec<NetworkProtocol>,
        bootstrap_peers: Vec<String>,
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        
        // Initialize mesh networking with capabilities
        let network_config = NetworkConfig {
            node_id,
            listen_port: 0, // No TCP port needed for pure mesh
            mesh_port: QUIC_MESH_PORT, // Configurable QUIC binding port
            max_peers: 1000, // Support many mesh connections
            protocols: protocols.clone(),
            listen_addresses: vec![], // No IP addresses needed
            bootstrap_peers,
        };
        
        let mesh_node = Arc::new(RwLock::new(MeshNode::new_with_hardware_detection(network_config.clone()).await?));

        // Extract hardware capabilities from the mesh node
        let hardware_capabilities = {
            let node = mesh_node.read().await;
            node.hardware_capabilities.clone()
        };

        let economics = Arc::new(RwLock::new(EconomicModel::new()));
        let storage = Arc::new(RwLock::new(storage));

        // Ticket #149: Use unified peer_registry instead of separate mesh_connections
        let peer_registry = Arc::new(RwLock::new(crate::peer_registry::PeerRegistry::new()));

        let long_range_relays = Arc::new(RwLock::new(HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(HashMap::new()));
        let stats = Arc::new(RwLock::new(MeshProtocolStats::default()));

        // Create participant tracking for UBI
        let ubi_participants = Arc::new(RwLock::new(HashMap::<String, String>::new()));

        // Initialize health monitor (Ticket #149: update to use peer_registry)
        let health_monitor = HealthMonitor::new(
            stats.clone(),
            peer_registry.clone(),
            long_range_relays.clone(),
        );

        // Initialize DHT integration
        let dht = Arc::new(RwLock::new(ZkDHTIntegration::new()));

        // Initialize routing statistics (in-memory counters only)
        let routing_stats = Arc::new(RwLock::new(RoutingStats::default()));

        // Initialize storage statistics (in-memory counters only)
        let storage_stats = Arc::new(RwLock::new(StorageStats::default()));

        // Initialize quality metrics for bonus calculation
        let quality_metrics = Arc::new(RwLock::new(QualityMetrics::default()));

        let server = ZhtpMeshServer {
            server_id,
            config: Arc::new(network_config),
            mesh_node,
            economics,
            storage,
            peer_registry, // Ticket #149: Using unified registry
            long_range_relays,
            revenue_pools,
            stats,
            health_monitor,
            dht,
            hardware_capabilities,
            
            // Simple routing statistics tracking (no wallets needed)
            routing_stats,
            
            // Simple storage statistics tracking (no wallets needed)
            storage_stats,
            
            // Quality metrics for bonus calculation
            quality_metrics,
            
            // Initialize protocol instances as None - will be created when protocols start
            bluetooth_protocol: None,
            wifi_direct_protocol: None,
            lorawan_protocol: None,
            satellite_protocol: None,
            quic_protocol: None,
            active_protocols: Arc::new(RwLock::new(HashMap::new())),
            
            // Initialize message routing and handling (Phase 4)
            message_router: None,
            message_handler: None,
            
            // Initialize blockchain sync coordinator
            sync_coordinator: Arc::new(crate::blockchain_sync::SyncCoordinator::new()),
            
            // Initialize safety features
            emergency_stop: Arc::new(RwLock::new(false)),
            max_connections: Arc::new(RwLock::new(100)), // Default safety limit
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            
            // Initialize security features
            owner_wallet_key: owner_key.clone(), // Owner wallet has full permissions
            admin_wallet_keys: Arc::new(RwLock::new(Vec::new())),
            security_audit_log: Arc::new(RwLock::new(Vec::new())),
        };
        
        Ok(server)
    }
    
    /// Start the mesh internet server
    pub async fn start(&mut self) -> Result<()> {
        println!(" STARTING ZHTP MESH SERVER - THE NEW INTERNET!");
        println!("===============================================");
        println!(" Network-Layer Stats Tracking (No Wallets)");
        
        // Display routing statistics
        {
            let stats = self.routing_stats.read().await;
            println!(" Messages Routed: {}", stats.messages_routed);
            println!(" Bytes Routed: {}", stats.bytes_routed);
            println!(" Successful Routes: {}", stats.successful_routes);
            println!(" Failed Routes: {}", stats.failed_routes);
            println!(" Theoretical Earnings: {} tokens (display only)", 
                stats.theoretical_tokens_earned);
        }
        
        println!("Initializing ISP-free mesh networking...");
        
        // Start the underlying mesh node protocols
        self.start_mesh_protocols().await?;
        
        // Initialize DHT for content distribution
        println!("Initializing zkDHT for Web4 content distribution...");
        
        // Create a default identity for DHT operations
        // TODO: This should use the server's actual identity
        let default_identity = create_default_mesh_identity();
        self.dht.write().await.initialize(default_identity).await?;
        
        // Initialize long-range communication capabilities
        if let Some(ref hardware_caps) = self.hardware_capabilities {
            self.initialize_long_range_relays(hardware_caps).await?;
        } else {
            warn!("Skipping long-range relay initialization - no hardware capabilities detected");
        }
        
        // WiFi sharing discovery disabled for legal compliance
        // self.start_wifi_sharing_discovery().await?;
        
        // Start mesh protocol message handling
        self.start_mesh_message_handler().await?;
        
        // TCP/UDP bootstrap removed - using QUIC only
        
        // Start network health monitoring
        self.start_health_monitoring().await?;
        
        println!("ZHTP MESH SERVER ONLINE!");
        println!(" FREE INTERNET FOR ALL - POWERED BY THE MESH!");
        println!("EARNING TOKENS FOR NETWORK PARTICIPATION!");
        
        Ok(())
    }
    
    /// Initialize long-range communication relays - GLOBAL internet replacement!
    async fn initialize_long_range_relays(&self, hardware_caps: &HardwareCapabilities) -> Result<()> {
        println!("Initializing GLOBAL long-range mesh relays...");
        println!("ZHTP Goal: Planet-wide internet replacement via mesh networking!");
        
        // Use the provided hardware capabilities (already detected)
        // Discover available LoRaWAN gateways (regional 15km coverage)
        self.discover_lorawan_gateways_with_capabilities(hardware_caps).await?;
        
        // Search for satellite uplink capabilities (GLOBAL coverage)
        self.discover_satellite_uplinks_with_capabilities(hardware_caps).await?;
        
        // Find high-power WiFi relays (internet bridge points)
        self.discover_wifi_relays_with_capabilities(hardware_caps).await?;
        
        let relay_count = self.long_range_relays.read().await.len();
        let relays = self.long_range_relays.read().await;
        
        // Calculate total global coverage
        let total_coverage_km: f64 = relays.values()
            .map(|relay| relay.coverage_radius_km)
            .sum();
        
        let has_satellite = relays.values()
            .any(|relay| matches!(relay.relay_type, LongRangeRelayType::Satellite));
        
        let has_internet_bridge = relays.values()
            .any(|relay| matches!(relay.relay_type, LongRangeRelayType::WiFiRelay));
        
        println!("GLOBAL MESH STATUS:");
        println!("   {} long-range relays discovered", relay_count);
        println!("   {:.0}km total coverage radius", total_coverage_km);
        println!("   🛰️ Satellite access: {}", if has_satellite { "GLOBAL" } else { "Regional only" });
        println!("   Internet bridges: {}", if has_internet_bridge { "WORLDWIDE" } else { "Mesh only" });
        
        if has_satellite && has_internet_bridge {
            println!(" ZHTP GLOBAL NETWORK ACTIVE - Unlimited worldwide reach!");
        } else if total_coverage_km > 1000.0 {
            println!("ZHTP CONTINENTAL NETWORK - Multi-country coverage active!");
        } else {
            println!("ZHTP REGIONAL NETWORK - Local area coverage established");
        }
        
        Ok(())
    }
    
    /// Discover LoRaWAN gateways with hardware capabilities
    async fn discover_lorawan_gateways_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::lorawan::discover_lorawan_gateways_with_capabilities;
        
        let discovered_gateways = discover_lorawan_gateways_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for gateway_info in discovered_gateways {
            let gateway_id = format!("lora_gateway_{}", gateway_info.gateway_eui);
            
            relays.insert(gateway_id.clone(), LongRangeRelay {
                relay_id: gateway_id.clone(),
                relay_type: LongRangeRelayType::LoRaWAN,
                coverage_radius_km: gateway_info.coverage_radius_km,
                max_throughput_mbps: 1, // LoRaWAN is low throughput
                cost_per_mb_tokens: 10,
                operator: gateway_info.operator_key,
                ubi_share_percentage: 20.0,
            });
            
            println!("LoRaWAN gateway discovered: {} - {} km range", 
                    gateway_id, gateway_info.coverage_radius_km);
        }
        
        Ok(())
    }
    
    /// Discover satellite uplinks for global coverage
    async fn discover_satellite_uplinks_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::satellite::discover_satellite_uplinks_with_capabilities;
        
        let discovered_satellites = discover_satellite_uplinks_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for satellite_info in discovered_satellites {
            let uplink_id = format!("satellite_{}_{}", 
                satellite_info.network_name.to_lowercase().replace(" ", "_"), 
                satellite_info.satellite_id);
            
            relays.insert(uplink_id.clone(), LongRangeRelay {
                relay_id: uplink_id.clone(),
                relay_type: LongRangeRelayType::Satellite,
                coverage_radius_km: satellite_info.coverage_radius_km,
                max_throughput_mbps: satellite_info.max_throughput_mbps,
                cost_per_mb_tokens: 100, // Satellites are more expensive
                operator: satellite_info.operator_key,
                ubi_share_percentage: 15.0,
            });
            
            println!("🛰️ Satellite uplink discovered: {} - GLOBAL coverage", uplink_id);
        }
        
        Ok(())
    }
    
    /// Discover WiFi relays for internet bridging
    async fn discover_wifi_relays_with_capabilities(&self, capabilities: &HardwareCapabilities) -> Result<()> {
        use crate::discovery::wifi::discover_wifi_relays_with_capabilities;
        
        let discovered_networks = discover_wifi_relays_with_capabilities(capabilities).await?;
        let mut relays = self.long_range_relays.write().await;
        
        for wifi_info in discovered_networks {
            let relay_id = format!("wifi_relay_{}", wifi_info.bssid.replace(":", "_"));
            
            relays.insert(relay_id.clone(), LongRangeRelay {
                relay_id: relay_id.clone(),
                relay_type: LongRangeRelayType::WiFiRelay,
                coverage_radius_km: 0.1, // WiFi has short range but high bandwidth
                max_throughput_mbps: wifi_info.bandwidth_estimate_mbps,
                cost_per_mb_tokens: 5, // P2P mesh relay cost
                operator: lib_crypto::PublicKey::new(vec![rand::random(), rand::random(), rand::random()]), // Random operator key
                ubi_share_percentage: 25.0,
            });
            
            println!("WiFi relay network discovered: {} - {} Mbps", 
                    wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
        }
        
        Ok(())
    }
    
    /// Start mesh protocol message handler (UPDATED - Phase 4)
    async fn start_mesh_message_handler(&self) -> Result<()> {
        info!(" Initializing mesh message forwarding system (Phase 4)...");
        
        // Initialize message forwarding components
        self.initialize_message_forwarding().await?;
        
        // UDP bootstrap removed - using QUIC only
        info!(" QUIC mesh protocol active on port 9334");
        
        Ok(())
    }
    
    /// Initialize message forwarding system (NEW - Phase 4)
    pub async fn initialize_message_forwarding(&self) -> Result<()> {
        info!(" Initializing message forwarding components...");
        
        // Create message handler (Ticket #149: using peer_registry)
        let message_handler = Arc::new(RwLock::new(
            crate::messaging::message_handler::MeshMessageHandler::new(
                self.peer_registry.clone(),
                self.long_range_relays.clone(),
                self.revenue_pools.clone(),
            )
        ));
        
        // Create message router (Ticket #149: using peer_registry)
        let message_router = Arc::new(RwLock::new(
            crate::routing::message_routing::MeshMessageRouter::new(
                self.peer_registry.clone(),
                self.long_range_relays.clone(),
            )
        ));
        
        // Set mesh server reference in router for reward tracking
        {
            let mut router_guard = message_router.write().await;
            router_guard.mesh_server = Some(Arc::new(RwLock::new(self.clone())));
        }
        
        // Set router reference in message handler
        {
            let mut handler_guard = message_handler.write().await;
            handler_guard.set_message_router(message_router.clone());
            
            // Set node ID in handler
            let node = self.mesh_node.read().await;
            let node_id = PublicKey::new(node.node_id.to_vec());
            handler_guard.set_node_id(node_id);
        }
        
        // Set protocol handlers in router
        {
            let router_guard = message_router.write().await;
            
            // TODO: Wire up protocol handlers when available
            // Currently the BluetoothMeshProtocol doesn't match the expected BluetoothClassicProtocol type
            // and WiFi/LoRa protocol modules don't exist yet
            
            // if let Some(bt_protocol) = &self.bluetooth_protocol {
            //     router_guard.bluetooth_handler = Some(bt_protocol.clone());
            // }
            
            // if let Some(wifi_protocol) = &self.wifi_direct_protocol {
            //     router_guard.wifi_handler = Some(wifi_protocol.clone());
            // }
            
            // if let Some(lora_protocol) = &self.lorawan_protocol {
            //     router_guard.lora_handler = Some(lora_protocol.clone());
            // }
        }
        
        // Set router and handler in protocol instances
        // TODO: Re-enable when protocol structure supports message_router and message_handler fields
        // if let Some(bt_protocol) = &self.bluetooth_protocol {
        //     let mut bt_guard = bt_protocol.write().await;
        //     bt_guard.message_router = Some(message_router.clone());
        //     bt_guard.message_handler = Some(message_handler.clone());
        // }
        
        if let Some(quic_protocol) = &self.quic_protocol {
            let mut quic_guard = quic_protocol.write().await;
            quic_guard.set_message_handler(message_handler.clone());
        }
        
        // Store in server (need to cast away const - this is during initialization)
        // We'll use unsafe here since we know initialization happens before concurrent access
        unsafe {
            let server_mut = self as *const Self as *mut Self;
            (*server_mut).message_router = Some(message_router);
            (*server_mut).message_handler = Some(message_handler);
        }
        
        info!(" Message forwarding system initialized successfully");
        
        Ok(())
    }
    
    /// Start network health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        info!("Starting network health monitoring...");
        self.health_monitor.start_monitoring().await
    }
    
    /// Handle incoming mesh message
    pub async fn handle_mesh_message(&self, message: ZhtpMeshMessage, _sender: PublicKey) -> Result<()> {
        // Message handling now done by unified_server in zhtp
        // This is just a pass-through for the API
        info!("Mesh message received: {:?}", message);
        Ok(())
    }
    
    /// Get current network statistics
    pub async fn get_network_stats(&self) -> MeshProtocolStats {
        self.stats.read().await.clone()
    }
    
    /// Get revenue pools (for UBI distribution)
    pub async fn get_revenue_pools(&self) -> HashMap<String, u64> {
        self.revenue_pools.read().await.clone()
    }
    
    /// Process native ZHTP request from browser/API clients
    pub async fn process_lib_request(
        &self,
        method: String,
        uri: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<ZhtpApiResponse> {
        info!("Processing native ZHTP request: {} {}", method, uri);
        
        // TODO: Implement ZHTP request handling
        Ok(ZhtpApiResponse {
            status: 200,
            status_message: "OK".to_string(),
            headers: HashMap::new(),
            body: b"Request processed by mesh server".to_vec(),
        })
    }
    
    // ===================
    // SECURITY SYSTEM
    // ===================
    
    /// Check permission level for a given public key (legacy method - use get_permission_level with wallet_key)
    pub async fn get_permission_level_legacy(&self, caller_key: &PublicKey) -> PermissionLevel {
        // Owner has full permissions
        if caller_key == &self.owner_wallet_key {
            return PermissionLevel::Owner;
        }
        
        // Check admin keys
        let admin_keys = self.admin_wallet_keys.read().await;
        if admin_keys.contains(caller_key) {
            return PermissionLevel::Admin;
        }
        
        // Check if it's a connected user (can only disconnect own connections)
        // MIGRATION (Ticket #149): Use peer_registry
        let registry = self.peer_registry.read().await;
        for peer_entry in registry.all_peers() {
            if peer_entry.peer_id.public_key() == caller_key {
                return PermissionLevel::User;
            }
        }
        
        PermissionLevel::None
    }
    
    /// Verify security credentials and signature
    pub async fn verify_credentials(&self, credentials: &SecurityCredentials, operation: &str) -> Result<bool> {
        // Check timestamp to prevent replay attacks (5 minute window)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if now > credentials.timestamp + 300 { // 5 minute expiry
            warn!(" Credential verification failed: timestamp expired (age: {} seconds)", now - credentials.timestamp);
            return Ok(false);
        }
        
        // Verify nonce is present
        if credentials.nonce.is_empty() {
            warn!(" Credential verification failed: empty nonce");
            return Ok(false);
        }
        
        // Verify signature is present
        if credentials.signature.is_empty() {
            warn!(" Credential verification failed: empty signature");
            return Ok(false);
        }
        
        // Create message to verify signature (matches what client should sign)
        let message = format!("{}:{}:{}:{}", 
            operation, 
            credentials.timestamp, 
            credentials.nonce,
            hex::encode(&self.server_id)
        );
        
        // Create Signature struct from credentials
        let signature = Signature {
            signature: credentials.signature.clone(),
            public_key: credentials.wallet_key.clone(),
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: credentials.timestamp,
        };
        
        // Perform actual cryptographic signature verification using lib-crypto
        match credentials.wallet_key.verify(message.as_bytes(), &signature) {
            Ok(is_valid) => {
                if is_valid {
                    info!(" Credential verification successful for operation: {}", operation);
                } else {
                    warn!(" Credential verification failed: invalid signature for operation: {}", operation);
                }
                Ok(is_valid)
            }
            Err(e) => {
                error!(" Credential verification error for operation {}: {}", operation, e);
                Ok(false) // Return false on verification error rather than propagating error
            }
        }
    }
    
    // LEGACY METHOD - COMMENTED OUT TO AVOID CONFLICTS WITH NEW WALLET-BASED SYSTEM
    /*
    /// Add security audit log entry (LEGACY)
    pub async fn log_security_operation_legacy(
        &self, 
        operation: &str, 
        caller_key: &PublicKey, 
        target: Option<&str>,
        permission_level: PermissionLevel,
        success: bool,
        reason: &str
    ) {
        let log_entry = SecurityAuditLog {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            operation: operation.to_string(),
            caller_key: hex::encode(&caller_key.key_id[..8]),
            target: target.map(|s| s.to_string()),
            permission_level: format!("{:?}", permission_level),
            success,
            reason: reason.to_string(),
        };
        
        self.security_audit_log.write().await.push(log_entry.clone());
        
        // Log to console for immediate visibility
        if success {
            info!(" Security: {} by {} ({:?}) - {}", 
                operation, 
                hex::encode(&caller_key.key_id[..8]), 
                permission_level, 
                reason
            );
        } else {
            warn!(" Security DENIED: {} by {} ({:?}) - {}", 
                operation, 
                hex::encode(&caller_key.key_id[..8]), 
                permission_level, 
                reason
            );
        }
    }
    */
    
    // LEGACY SECURITY METHODS - COMMENTED OUT TO AVOID CONFLICTS
    /*
    /// Add admin key (owner only) - LEGACY
    pub async fn add_admin_key(&self, credentials: &SecurityCredentials, new_admin_key: PublicKey) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        if permission_level != PermissionLevel::Owner {
            self.log_security_operation(
                "add_admin_key", 
                &credentials.caller_key, 
                Some(&hex::encode(&new_admin_key.key_id[..8])),
                permission_level, 
                false,
                "Insufficient permissions - only owner can add admins"
            ).await;
            return Err(anyhow!(" SECURITY: Only node owner can add admin keys"));
        }
        
        if !self.verify_credentials(credentials, "add_admin_key").await? {
            self.log_security_operation(
                "add_admin_key",
                &credentials.caller_key,
                Some(&hex::encode(&new_admin_key.key_id[..8])),
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        self.admin_keys.write().await.push(new_admin_key.clone());
        
        self.log_security_operation(
            "add_admin_key",
            &credentials.caller_key,
            Some(&hex::encode(&new_admin_key.key_id[..8])),
            permission_level,
            true,
            "Admin key added successfully"
        ).await;
        
        Ok(())
    }
    
    /// Get security audit log (admin+ only)
    pub async fn get_security_audit_log(&self, credentials: &SecurityCredentials) -> Result<Vec<SecurityAuditLog>> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        if matches!(permission_level, PermissionLevel::None | PermissionLevel::User) {
            self.log_security_operation(
                "get_audit_log",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Insufficient permissions - admin+ required"
            ).await;
            return Err(anyhow!(" SECURITY: Insufficient permissions to view audit log"));
        }
        
        Ok(self.security_audit_log.read().await.clone())
    }

    /// Graceful shutdown of the mesh server - signals shutdown but doesn't clear state immediately
    pub async fn initiate_shutdown(&self) -> Result<()> {
        info!("🛑 Stopping ZhtpMeshServer gracefully...");
        
        // Set emergency stop to prevent new operations
        *self.emergency_stop.write().await = true;
        
        // Stop protocols if available
        if let Some(bluetooth_protocol) = &self.bluetooth_protocol {
            let _ = bluetooth_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(wifi_direct_protocol) = &self.wifi_direct_protocol {
            let _ = wifi_direct_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(lorawan_protocol) = &self.lorawan_protocol {
            let _ = lorawan_protocol.stop_mesh_discovery().await;
        }
        
        if let Some(satellite_protocol) = &self.satellite_protocol {
            let _ = satellite_protocol.stop_mesh_discovery().await;
        }
        
        info!(" ZhtpMeshServer stopped gracefully");
        Ok(())
    }
    
    /// Emergency stop - immediate shutdown
    ///  SECURE: Emergency stop - immediate shutdown (OWNER ONLY)
    pub async fn emergency_stop(&mut self, credentials: &SecurityCredentials) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Only node owner can perform emergency stop
        if permission_level != PermissionLevel::Owner {
            self.log_security_operation(
                "emergency_stop", 
                &credentials.caller_key, 
                None,
                permission_level, 
                false,
                " CRITICAL: Unauthorized emergency stop attempt - only owner allowed"
            ).await;
            return Err(anyhow!(" SECURITY ALERT: Emergency stop DENIED - Only node owner can perform emergency stop"));
        }
        
        if !self.verify_credentials(credentials, "emergency_stop").await? {
            self.log_security_operation(
                "emergency_stop",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Invalid credentials for emergency stop"
            ).await;
            return Err(anyhow!("Invalid credentials for emergency stop"));
        }
        
        println!(" EMERGENCY STOP - Immediate shutdown initiated by OWNER!");
        
        // Set emergency flag
        *self.emergency_stop.write().await = true;
        
        // Force disconnect all protocols
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
            }
        }
        
        // Clear all connections immediately (Ticket #149: using peer_registry)
        self.peer_registry.write().await.clear();
        self.long_range_relays.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        // Stop health monitoring
        let health_monitor = &self.health_monitor;
        let _ = health_monitor.stop_monitoring().await;
        
        self.log_security_operation(
            "emergency_stop",
            &credentials.caller_key,
            None,
            permission_level,
            true,
            "Emergency stop completed successfully by owner"
        ).await;
        
        warn!(" Emergency stop complete - All connections terminated by owner");
        Ok(())
    }
    
    /// Stop the mesh server gracefully
    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping ZHTP Mesh Server...");
        
        // Check if emergency stop was triggered
        if *self.emergency_stop.read().await {
            println!("  Server was emergency stopped - performing cleanup");
            return Ok(());
        }
        
        // Gracefully disconnect all mesh connections (Ticket #149: using peer_registry)
        let registry = self.peer_registry.read().await;
        let peer_count = registry.all_peers().count();
        println!("Disconnecting {} mesh connections...", peer_count);
        drop(registry);
        
        // Disconnect protocols gracefully
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                info!("Gracefully disconnecting Bluetooth peer: {}", peer);
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
                tokio::time::sleep(Duration::from_millis(100)).await; // Small delay for graceful disconnect
            }
        }
        
        // Clear all in-memory state (Ticket #149: using peer_registry)
        self.peer_registry.write().await.clear();
        self.long_range_relays.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        // Stop health monitoring gracefully
        let health_monitor = &self.health_monitor;
        let _ = health_monitor.stop_monitoring().await;
        
        println!("ZHTP Mesh Server stopped gracefully");
        Ok(())
    }
    
    /// Check if emergency stop has been triggered
    pub async fn is_emergency_stopped(&self) -> bool {
        *self.emergency_stop.read().await
    }
    
    /// Set maximum connection limit for safety
    pub async fn set_max_connections(&self, max: usize) -> Result<()> {
        *self.max_connections.write().await = max;
        info!(" Maximum connection limit set to: {}", max);
        Ok(())
    }
    
    /// Get current connection count and limit status
    /// TODO (Ticket #149): Migrated to peer_registry
    pub async fn get_connection_status(&self) -> (usize, usize, bool) {
        let registry = self.peer_registry.read().await;
        let current = registry.all_peers().count();
        let max = *self.max_connections.read().await;
        let at_limit = current >= max;
        (current, max, at_limit)
    }
    
    ///  SECURE: Disconnect specific peer by address (Admin+ only, or User for own connections)
    pub async fn disconnect_peer_by_address(&self, credentials: &SecurityCredentials, address: &str) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Check permissions - Admin+ can disconnect any peer, Users can only disconnect themselves
        let can_disconnect = match permission_level {
            PermissionLevel::Owner | PermissionLevel::Admin => true,
            PermissionLevel::User => {
                // Users can only disconnect their own connections
                let caller_address = hex::encode(&credentials.caller_key.key_id[..8]);
                address.contains(&caller_address)
            },
            PermissionLevel::None => false,
        };
        
        if !can_disconnect {
            self.log_security_operation(
                "disconnect_peer_by_address", 
                &credentials.caller_key, 
                Some(address),
                permission_level, 
                false,
                "Insufficient permissions or attempting to disconnect other user's connection"
            ).await;
            return Err(anyhow!(" SECURITY: Insufficient permissions to disconnect peer"));
        }
        
        if !self.verify_credentials(credentials, "disconnect_peer_by_address").await? {
            self.log_security_operation(
                "disconnect_peer_by_address",
                &credentials.caller_key,
                Some(address),
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        info!(" Disconnecting peer: {} (authorized by {:?})", address, permission_level);
        
        // Try Bluetooth first
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            if connected_peers.contains(&address.to_string()) {
                let result = bt_protocol.read().await.disconnect_peer(address).await;
                self.log_security_operation(
                    "disconnect_peer_by_address",
                    &credentials.caller_key,
                    Some(address),
                    permission_level,
                    result.is_ok(),
                    if result.is_ok() { "Bluetooth peer disconnected" } else { "Failed to disconnect Bluetooth peer" }
                ).await;
                return result;
            }
        }
        
        // Remove from peer registry by address lookup (Ticket #149: using peer_registry)
        let registry = self.peer_registry.read().await;
        if let Some(key_to_remove) = registry.all_peers()
            .find(|entry| {
                // Try to match by peer DID or public key string representation
                format!("{:?}", entry.peer_id.public_key()).contains(address) ||
                entry.peer_id.did().contains(address)
            })
            .map(|entry| entry.peer_id.clone()) {
            drop(registry);
            let mut registry_write = self.peer_registry.write().await;
            registry_write.remove(&key_to_remove);
            self.log_security_operation(
                "disconnect_peer_by_address",
                &credentials.caller_key,
                Some(address),
                permission_level,
                true,
                "Mesh connection disconnected successfully"
            ).await;
            info!(" Disconnected peer from mesh connections: {}", address);
            return Ok(());
        }
        
        warn!("Could not find peer to disconnect: {}", address);
        Err(anyhow!("Peer not found: {}", address))
    }
    
    /// Get list of all connected peers across all protocols  
    pub async fn list_all_connected_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        
        // Add Bluetooth peers
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let bt_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in bt_peers {
                peers.push(format!("BT: {}", peer));
            }
        }
        
        // Add mesh connection peers (Ticket #149: using peer_registry)
        let registry = self.peer_registry.read().await;
        for peer_entry in registry.all_peers() {
            let endpoint = peer_entry.endpoints.first();
            peers.push(format!("MESH: {} ({:?})", 
                hex::encode(&peer_entry.peer_id.public_key().key_id[..8]), // First 8 bytes of key ID
                endpoint.map(|e| &e.protocol)
            ));
        }
        
        peers
    }
    
    ///  SECURE: Force disconnect all connections (Admin+ only)
    pub async fn disconnect_all_peers(&self, credentials: &SecurityCredentials) -> Result<()> {
        let permission_level = self.get_permission_level(&credentials.caller_key).await;
        
        // Only admin+ can disconnect all peers
        if matches!(permission_level, PermissionLevel::None | PermissionLevel::User) {
            self.log_security_operation(
                "disconnect_all_peers", 
                &credentials.caller_key, 
                None,
                permission_level, 
                false,
                "Insufficient permissions - admin+ required to disconnect all peers"
            ).await;
            return Err(anyhow!(" SECURITY: Only admins and owners can disconnect all peers"));
        }
        
        if !self.verify_credentials(credentials, "disconnect_all_peers").await? {
            self.log_security_operation(
                "disconnect_all_peers",
                &credentials.caller_key,
                None,
                permission_level,
                false,
                "Invalid credentials"
            ).await;
            return Err(anyhow!("Invalid credentials"));
        }
        
        warn!(" Force disconnecting ALL peers (authorized by {:?})", permission_level);
        
        // Disconnect all Bluetooth peers
        if let Some(ref bt_protocol) = self.bluetooth_protocol {
            let connected_peers = bt_protocol.read().await.get_connected_peers().await;
            for peer in connected_peers {
                let _ = bt_protocol.read().await.disconnect_peer(&peer).await;
            }
        }
        
        // Clear all mesh connections (Ticket #149: using peer_registry)
        self.peer_registry.write().await.clear();
        self.connection_attempts.write().await.clear();
        
        self.log_security_operation(
            "disconnect_all_peers",
            &credentials.caller_key,
            None,
            permission_level,
            true,
            "All peers disconnected successfully"
        ).await;
        
        info!(" All peers disconnected by authorized user");
        Ok(())
    }
    */
    // END OF LEGACY METHODS - CONFLICTS RESOLVED
    
    /// WiFi sharing discovery - DISABLED for legal compliance
    /// This function is kept for reference but should not be called
    #[allow(dead_code)]
    async fn start_wifi_sharing_discovery(&self) -> Result<()> {
        warn!("WiFi sharing discovery is disabled for legal compliance");
        
        // WiFi sharing removed for legal compliance
        let server_id = self.server_id;
        let hardware_caps = self.hardware_capabilities.clone();
        
        tokio::spawn(async move {
            loop {
                // Continuously discover WiFi sharing nodes using WiFi scanning
                tokio::time::sleep(Duration::from_secs(30)).await;
                
                // Use hardware-optimized WiFi discovery (avoid duplicate hardware detection)
                if let Some(ref caps) = hardware_caps {
                    match crate::discovery::wifi::discover_wifi_relays_with_capabilities(caps).await {
                        Ok(discovered_networks) => {
                            info!("Discovered {} WiFi relay networks for P2P mesh", discovered_networks.len());
                            
                            for wifi_info in discovered_networks {
                                info!("WiFi relay available: {} - {} Mbps capacity", 
                                      wifi_info.ssid, wifi_info.bandwidth_estimate_mbps);
                            }
                        },
                        Err(e) => {
                            warn!("WiFi relay discovery failed: {}", e);
                        }
                    }
                } else {
                    warn!("Skipping WiFi relay discovery - no hardware capabilities detected");
                }
            }
        });
        
        Ok(())
    }
    
    /// Serve Web4 content via zkDHT
    pub async fn serve_web4_content(&self, domain: &str, path: &str) -> Result<Vec<u8>> {
        info!("Serving Web4 content: {}{}", domain, path);
        
        // Resolve content hash via DHT
        let content_hash = self.dht.write().await
            .resolve_content(domain, path).await?;
        
        info!("Resolved content hash: {:?}", content_hash);
        
        // Use native binary DHT protocol instead of JavaScript
        let response = crate::dht::call_native_dht_client("loadPage", &serde_json::json!({
            "url": format!("zhtp://{}{}", domain, path)
        })).await?;
        
        // Extract content from response
        let content = response.get("content")
            .and_then(|c| c.get("html"))
            .and_then(|h| h.as_str())
            .unwrap_or("<h1>Content not found</h1>");
        
        Ok(content.as_bytes().to_vec())
    }
    
    /// Get DHT network status
    pub async fn get_dht_status(&self) -> DHTNetworkStatus {
        self.dht.read().await.get_network_status().await.unwrap_or(DHTNetworkStatus {
            total_nodes: 0,
            connected_nodes: 0,
            storage_used_bytes: 0,
            total_keys: 0,
        })
    }
    
    /// Clear DHT cache
    pub async fn clear_dht_cache(&self) {
        self.dht.write().await.clear_cache().await;
    }
}

/// Create a default identity for mesh server DHT operations
/// TODO: This should be replaced with proper server identity management
fn create_default_mesh_identity() -> lib_identity::ZhtpIdentity {
    use lib_identity::types::{IdentityType, AccessLevel, NodeId};
    use lib_identity::wallets::WalletManager;
    use lib_identity::{IdentityId, ZhtpIdentity};
    use lib_proofs::ZeroKnowledgeProof;
    use lib_crypto::PublicKey;
    use std::collections::HashMap;

    let identity_id = IdentityId::from_bytes(&[42u8; 32]); // Fixed ID for mesh server

    // Create mesh server DID
    let mesh_did = "did:zhtp:mesh-server".to_string();

    // Generate NodeId for mesh server
    let mesh_node_id = NodeId::from_did_device(&mesh_did, "mesh-device")
        .unwrap_or_else(|_| NodeId::from_bytes([42u8; 32]));

    let mut device_node_ids = HashMap::new();
    device_node_ids.insert("mesh-device".to_string(), mesh_node_id);

    ZhtpIdentity {
        id: identity_id.clone(),
        identity_type: IdentityType::Device, // Mesh server is a device/service
        did: mesh_did,
        public_key: PublicKey::new(vec![1, 2, 3, 4, 5]), // Placeholder public key
        private_key: None,
        node_id: mesh_node_id,
        device_node_ids,
        primary_device: "mesh-device".to_string(),
        ownership_proof: ZeroKnowledgeProof {
            proof_system: "mesh_server".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        },
        credentials: HashMap::new(),
        reputation: 100, // High reputation for mesh server
        age: None, // Services don't have age
        access_level: AccessLevel::FullCitizen, // Full access for mesh operations
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "mesh_server".to_string());
            metadata.insert("version".to_string(), "1.0".to_string());
            metadata
        },
        private_data_id: None,
        wallet_manager: WalletManager::new(identity_id.clone()),
        did_document_hash: None,
        attestations: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        last_active: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        recovery_keys: vec![],
        owner_identity_id: None,  // Mesh server is autonomous/system service
        reward_wallet_id: None,   // System service doesn't need reward wallet
        encrypted_master_seed: None,  // System services don't use seed-based HD wallets
        next_wallet_index: 0,
        password_hash: None,
        master_seed_phrase: None,
        zk_identity_secret: [0u8; 32], // Mesh server - zeroed secrets
        zk_credential_hash: [0u8; 32],
        wallet_master_seed: [0u8; 64],
        dao_member_id: "mesh-server".to_string(),
        dao_voting_power: 0, // System service has no voting power
        citizenship_verified: false,
        jurisdiction: None,
    }
}

// Additional methods for ZhtpMeshServer
impl ZhtpMeshServer {

    /// Get theoretical tokens earned from routing (for reward processing)
    /// 
    /// This returns the accumulated theoretical tokens that would be earned
    /// based on routing activity. Used by the routing reward processor to
    /// determine when to create reward transactions.
    pub async fn get_theoretical_tokens_earned(&self) -> u64 {
        let stats = self.routing_stats.read().await;
        stats.theoretical_tokens_earned
    }
    
    /// Get total bytes routed (for metrics and monitoring)
    pub async fn get_total_bytes_routed(&self) -> u64 {
        let stats = self.routing_stats.read().await;
        stats.bytes_routed
    }
    
    /// Get total messages routed (for metrics and monitoring)
    pub async fn get_total_messages_routed(&self) -> u64 {
        let stats = self.routing_stats.read().await;
        stats.messages_routed
    }
    
    /// Reset theoretical tokens counter after successful reward claim
    /// 
    /// This should be called after a reward transaction has been successfully
    /// created and added to the blockchain to prevent double-counting.
    /// 
    /// # Example
    /// ```ignore
    /// // After creating reward transaction
    /// mesh_server.reset_reward_counter().await;
    /// ```
    pub async fn reset_reward_counter(&self) {
        let mut stats = self.routing_stats.write().await;
        let previous = stats.theoretical_tokens_earned;
        stats.theoretical_tokens_earned = 0;
        
        if previous > 0 {
            info!(" Routing reward counter reset: {} SOV claimed", previous);
        }
    }
    
    /// Get complete routing statistics snapshot
    /// 
    /// Returns a complete snapshot of current routing statistics including:
    /// - Messages routed
    /// - Bytes routed
    /// - Theoretical tokens earned
    /// - Success/failure rates
    pub async fn get_routing_stats_snapshot(&self) -> RoutingStats {
        let stats = self.routing_stats.read().await;
        stats.clone()
    }
    
    /// Get the node's unique identifier as a 32-byte array
    /// 
    /// Converts the server's UUID to a 32-byte array for use in blockchain
    /// transactions and reward attribution. The UUID (16 bytes) is padded
    /// with zeros to create a 32-byte identifier.
    /// 
    /// # Returns
    /// A 32-byte array representing this node's unique identifier
    pub fn get_node_id(&self) -> [u8; 32] {
        let uuid_bytes = self.server_id.as_bytes();
        let mut node_id = [0u8; 32];
        node_id[..16].copy_from_slice(uuid_bytes);
        node_id
    }
    
    // ==================== Storage Statistics Methods ====================
    
    /// Update storage statistics when content is stored
    /// 
    /// This should be called by the storage system when new content is successfully stored.
    /// It updates the running totals for items stored, bytes stored, and storage duration.
    /// 
    /// # Arguments
    /// * `content_size` - Size in bytes of the stored content
    /// * `duration_hours` - Expected storage duration in hours
    /// * `tokens_earned` - Theoretical tokens earned for this storage operation
    pub async fn record_storage_operation(
        &self,
        content_size: u64,
        duration_hours: u64,
        tokens_earned: u64,
    ) {
        let mut stats = self.storage_stats.write().await;
        stats.items_stored += 1;
        stats.bytes_stored += content_size;
        stats.storage_duration_hours += duration_hours;
        stats.theoretical_tokens_earned += tokens_earned;
        stats.successful_storage_ops += 1;
        
        info!(
            " Storage recorded: {} bytes, {} hours, {} SOV earned",
            content_size, duration_hours, tokens_earned
        );
    }
    
    /// Update storage statistics when content is retrieved
    /// 
    /// This should be called by the storage system when content is successfully retrieved.
    pub async fn record_retrieval_operation(&self) {
        let mut stats = self.storage_stats.write().await;
        stats.retrievals_served += 1;
        
        info!("📤 Retrieval served: total retrievals = {}", stats.retrievals_served);
    }
    
    /// Record a failed storage operation
    pub async fn record_storage_failure(&self) {
        let mut stats = self.storage_stats.write().await;
        stats.failed_storage_ops += 1;
    }
    
    /// Reset theoretical tokens counter after successful reward claim
    /// 
    /// This should be called after a storage reward transaction has been successfully
    /// created and added to the blockchain to prevent double-counting.
    pub async fn reset_storage_reward_counter(&self) {
        let mut stats = self.storage_stats.write().await;
        let previous = stats.theoretical_tokens_earned;
        stats.theoretical_tokens_earned = 0;
        
        if previous > 0 {
            info!(" Storage reward counter reset: {} SOV claimed", previous);
        }
    }
    
    /// Get complete storage statistics snapshot
    /// 
    /// Returns a complete snapshot of current storage statistics including:
    /// - Items stored
    /// - Bytes stored
    /// - Retrievals served
    /// - Storage duration
    /// - Theoretical tokens earned
    /// - Success/failure rates
    pub async fn get_storage_stats_snapshot(&self) -> StorageStats {
        let stats = self.storage_stats.read().await;
        stats.clone()
    }
}
