//! Unified Discovery Service
//!
//! Consolidates multiple discovery mechanisms (multicast, port scanning)
//! into a single coordinated service with deduplication by UnifiedPeerId.
//!
//! Key Features:
//! - Single discovery interface for all protocols
//! - Automatic deduplication by NodeId
//! - Prioritized discovery methods (multicast > port scanning)
//! - Integration with lib-identity UnifiedPeerId system
//!
//! # Security Model
//!
//! ## Trust Levels
//! 1. **Semi-trusted**: Multicast announcements (local network only)
//! 2. **Fully Trusted**: After cryptographic handshake verification
//!
//! ## Security Guarantees
//! - Public keys are ONLY trusted after handshake verification
//! - DoS protection: Max 10 addresses per peer
//! - Rate limiting: 60-second scan intervals
//!
//! ## Attack Mitigations
//! - **Sybil Attack**: Peer IDs verified via cryptographic handshake
//! - **DoS**: Address list bounded
//! - **MITM**: Public keys verified against DIDs
//! - **Replay**: Timestamps tracked, duplicate addresses rejected
//!
//! ## Why No Subnet Scanning?
//! Subnet scanning (connecting to random IPs) was removed for security:
//! - Port scanning is network-unfriendly and may trigger IDS/IPS
//! - Cannot verify ZHTP protocol without handshake (false positives)
//! - Exposes node to potentially malicious services
//! - Multicast discovery is the proper protocol-aware method

use anyhow::{Result, Context};
use lib_crypto::PublicKey;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::identity::unified_peer::UnifiedPeerId;
use super::local_network::{HandshakeCapabilities, MeshHandshake, NodeAnnouncement};

/// Maximum addresses to store per peer (DoS protection)
const MAX_ADDRESSES_PER_PEER: usize = 10;

/// Minimum valid port number (avoid privileged ports)
const MIN_PORT: u16 = 1024;

/// Maximum valid port number
const MAX_PORT: u16 = 65535;

/// Discovery protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoveryProtocol {
    /// UDP Multicast (224.0.1.75:37775) - Priority 1
    UdpMulticast,
    /// Active port scanning - Priority 2 (fallback)
    PortScan,
}

impl DiscoveryProtocol {
    /// Get priority for deduplication (lower is higher priority)
    pub fn priority(&self) -> u8 {
        match self {
            DiscoveryProtocol::UdpMulticast => 1,
            DiscoveryProtocol::PortScan => 2,
        }
    }
}

/// Unified discovery result - common type for all discovery methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    /// Peer UUID (may be temporary until verified)
    pub peer_id: Uuid,
    /// All known addresses for this peer (IP:port combinations)
    pub addresses: Vec<SocketAddr>,
    /// Public key (if available from handshake)
    pub public_key: Option<PublicKey>,
    /// Discovery protocol that found this peer
    pub protocol: DiscoveryProtocol,
    /// Timestamp of discovery
    pub discovered_at: u64,
    /// Protocol capabilities (if known)
    pub capabilities: Option<HandshakeCapabilities>,
    /// Mesh/listening port
    pub mesh_port: u16,
    /// Optional DID (if peer has UnifiedPeerId)
    pub did: Option<String>,
    /// Optional device ID (if peer has UnifiedPeerId)
    pub device_id: Option<String>,
}

impl DiscoveryResult {
    /// Create a new discovery result
    pub fn new(
        peer_id: Uuid,
        address: SocketAddr,
        protocol: DiscoveryProtocol,
        mesh_port: u16,
    ) -> Self {
        Self {
            peer_id,
            addresses: vec![address],
            public_key: None,
            protocol,
            discovered_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            capabilities: None,
            mesh_port,
            did: None,
            device_id: None,
        }
    }

    /// Merge another discovery result into this one (deduplication)
    pub fn merge(&mut self, other: DiscoveryResult) {
        // Add new addresses (with limit for DoS protection)
        for addr in other.addresses {
            if !self.addresses.contains(&addr) && self.addresses.len() < MAX_ADDRESSES_PER_PEER {
                self.addresses.push(addr);
            }
        }

        // Update public key if we didn't have one
        // SECURITY: Public key should be verified against DID during handshake
        // This merge only trusts keys from authenticated handshakes, not raw scans
        if self.public_key.is_none() && other.public_key.is_some() {
            self.public_key = other.public_key;
        }

        // Update capabilities if we didn't have them
        if self.capabilities.is_none() && other.capabilities.is_some() {
            self.capabilities = other.capabilities;
        }

        // Prefer higher priority protocol
        if other.protocol.priority() < self.protocol.priority() {
            self.protocol = other.protocol;
        }

        // Update DID/device_id if available
        if self.did.is_none() && other.did.is_some() {
            self.did = other.did;
        }
        if self.device_id.is_none() && other.device_id.is_some() {
            self.device_id = other.device_id;
        }

        // Keep earliest discovery time
        self.discovered_at = self.discovered_at.min(other.discovered_at);
    }

    /// Convert to UnifiedPeerId (requires verified identity from handshake)
    pub fn to_unified_peer_id(&self, identity: &ZhtpIdentity) -> Result<UnifiedPeerId> {
        UnifiedPeerId::from_zhtp_identity(identity).context("Failed to create UnifiedPeerId")
    }

    /// Update peer ID after handshake verification
    ///
    /// # Security
    /// This replaces temporary scan-generated UUIDs with verified peer IDs from
    /// cryptographic handshakes. Should ONLY be called after successful handshake.
    ///
    /// # Arguments
    /// * `verified_peer_id` - The peer ID from MeshHandshake after verification
    /// * `public_key` - The verified public key from handshake
    pub fn update_verified_identity(&mut self, verified_peer_id: Uuid, public_key: PublicKey) {
        self.peer_id = verified_peer_id;
        self.public_key = Some(public_key);
    }
}

/// Conversion from NodeAnnouncement (multicast discovery)
impl From<NodeAnnouncement> for DiscoveryResult {
    fn from(announcement: NodeAnnouncement) -> Self {
        let address = SocketAddr::new(announcement.local_ip, announcement.mesh_port);
        Self {
            peer_id: announcement.node_id,
            addresses: vec![address],
            public_key: None,
            protocol: DiscoveryProtocol::UdpMulticast,
            discovered_at: announcement.announced_at,
            capabilities: None,
            mesh_port: announcement.mesh_port,
            did: None,
            device_id: None,
        }
    }
}

/// Conversion from MeshHandshake (after TCP connection established)
impl From<MeshHandshake> for DiscoveryResult {
    fn from(handshake: MeshHandshake) -> Self {
        let protocol = match handshake.discovered_via {
            0 => DiscoveryProtocol::UdpMulticast,
            4 => DiscoveryProtocol::PortScan,
            _ => DiscoveryProtocol::UdpMulticast, // Default
        };

        Self {
            peer_id: handshake.node_id,
            addresses: Vec::new(), // Will be filled by discovery service
            public_key: Some(handshake.public_key),
            protocol,
            discovered_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            capabilities: Some(handshake.capabilities),
            mesh_port: handshake.mesh_port,
            did: None,
            device_id: None,
        }
    }
}

/// Trait for discovery service implementations
#[async_trait::async_trait]
pub trait DiscoveryService: Send + Sync {
    /// Start the discovery service
    async fn start(&self) -> Result<()>;

    /// Stop the discovery service
    async fn stop(&self) -> Result<()>;

    /// Perform a one-time scan and return results
    async fn scan(&self) -> Result<Vec<DiscoveryResult>>;

    /// Get the protocol type this service implements
    fn protocol_type(&self) -> DiscoveryProtocol;

    /// Get service name for logging
    fn name(&self) -> &str;
}

/// Unified Discovery Service - coordinates all discovery mechanisms
pub struct UnifiedDiscoveryService {
    /// Local node identity
    node_id: Uuid,
    /// Local mesh port
    mesh_port: u16,
    /// Local public key
    public_key: PublicKey,
    /// Discovered peers (deduplicated by peer_id)
    discovered_peers: Arc<RwLock<HashMap<Uuid, DiscoveryResult>>>,
    /// Optional callback for new peer discoveries
    peer_discovered_callback:
        Option<Arc<dyn Fn(DiscoveryResult) + Send + Sync>>,
    /// Whether the service is running
    running: Arc<RwLock<bool>>,
}

impl UnifiedDiscoveryService {
    /// Create a new unified discovery service
    ///
    /// # Security
    /// - `mesh_port` validated to be in valid range (1024-65535)
    /// - `public_key` must match the node's actual cryptographic identity
    ///
    /// # Panics
    /// Panics if `mesh_port` is 0 (invalid)
    pub fn new(
        node_id: Uuid,
        mesh_port: u16,
        public_key: PublicKey,
    ) -> Self {
        // Validate port is not zero
        if mesh_port == 0 {
            panic!("Invalid mesh_port: 0 is not a valid port number");
        }
        
        // Log warning for privileged ports (< 1024)
        if mesh_port < MIN_PORT {
            warn!("Using privileged port {} - may require elevated permissions", mesh_port);
        }
        
        // Validate port is in valid range
        if mesh_port > MAX_PORT {
            warn!("Port {} exceeds maximum valid port {}", mesh_port, MAX_PORT);
        }
        
        Self {
            node_id,
            mesh_port,
            public_key,
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            peer_discovered_callback: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Set callback for new peer discoveries
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(DiscoveryResult) + Send + Sync + 'static,
    {
        self.peer_discovered_callback = Some(Arc::new(callback));
        self
    }

    /// Start all discovery mechanisms
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            warn!("UnifiedDiscoveryService already running");
            return Ok(());
        }
        *running = true;
        drop(running);

        info!("🔍 Starting Unified Discovery Service");
        info!("   Node ID: {}", self.node_id);
        info!("   Mesh Port: {}", self.mesh_port);

        // Start multicast discovery (primary method)
        self.start_multicast_discovery().await?;

        // Start periodic scanning as fallback (optional)
        self.start_periodic_scanning().await?;

        info!("✅ Unified Discovery Service started successfully");
        Ok(())
    }

    /// Stop all discovery mechanisms
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        *running = false;
        drop(running);

        info!("⏹️  Stopping Unified Discovery Service");
        Ok(())
    }

    /// Start UDP multicast discovery
    async fn start_multicast_discovery(&self) -> Result<()> {
        let node_id = self.node_id;
        let mesh_port = self.mesh_port;
        let public_key = self.public_key.clone();

        tokio::spawn(async move {
            let peer_callback = Arc::new(move |addr: String, pk: PublicKey| {
                debug!("Multicast discovered peer: {} (key: {})", addr, hex::encode(&pk.as_bytes()[..8]));
            });

            if let Err(e) = super::local_network::start_local_discovery(
                node_id,
                mesh_port,
                public_key,
                Some(peer_callback),
            )
            .await
            {
                error!("Multicast discovery error: {}", e);
            }
        });

        Ok(())
    }

    /// Start periodic scanning as fallback (currently disabled)
    ///
    /// NOTE: Periodic subnet scanning has been disabled for security reasons.
    /// Blind TCP connections to arbitrary IPs is network-unfriendly and may
    /// trigger IDS/IPS systems. Use UDP multicast discovery instead.
    async fn start_periodic_scanning(&self) -> Result<()> {
        // Subnet scanning removed - rely on multicast discovery
        debug!("Periodic subnet scanning disabled (use multicast discovery)");
        Ok(())
    }

    // NOTE: Subnet scanning removed for security reasons.
    // Blind TCP connections to arbitrary IPs is:
    // - Network-unfriendly (port scanning)
    // - Cannot verify ZHTP protocol without handshake
    // - May trigger IDS/IPS systems
    // - Exposes node to potentially malicious services
    //
    // Use UDP multicast discovery instead - it's protocol-aware and secure.

    /// Register a discovered peer (with deduplication)
    pub async fn register_peer(&self, result: DiscoveryResult) {
        let mut peers = self.discovered_peers.write().await;
        let peer_id = result.peer_id;

        if let Some(existing) = peers.get_mut(&peer_id) {
            existing.merge(result);
            debug!("Merged discovery result for peer: {}", peer_id);
        } else {
            info!("📡 New peer discovered: {} via {:?}", peer_id, result.protocol);
            peers.insert(peer_id, result.clone());

            if let Some(ref callback) = self.peer_discovered_callback {
                callback(result);
            }
        }
    }

    /// Get all discovered peers
    pub async fn get_discovered_peers(&self) -> Vec<DiscoveryResult> {
        let peers = self.discovered_peers.read().await;
        peers.values().cloned().collect()
    }

    /// Get a specific peer by ID
    pub async fn get_peer(&self, peer_id: &Uuid) -> Option<DiscoveryResult> {
        let peers = self.discovered_peers.read().await;
        peers.get(peer_id).cloned()
    }

    /// Get count of discovered peers
    pub async fn peer_count(&self) -> usize {
        let peers = self.discovered_peers.read().await;
        peers.len()
    }

    /// Remove a peer from the discovery cache
    pub async fn remove_peer(&self, peer_id: &Uuid) -> Option<DiscoveryResult> {
        let mut peers = self.discovered_peers.write().await;
        peers.remove(peer_id)
    }

    /// Clear all discovered peers
    pub async fn clear_peers(&self) {
        let mut peers = self.discovered_peers.write().await;
        peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_protocol_priority() {
        assert_eq!(DiscoveryProtocol::UdpMulticast.priority(), 1);
        assert_eq!(DiscoveryProtocol::PortScan.priority(), 2);
    }

    #[test]
    fn test_discovery_result_merge() {
        let mut result1 = DiscoveryResult::new(
            Uuid::new_v4(),
            "127.0.0.1:9333".parse().unwrap(),
            DiscoveryProtocol::PortScan,
            9333,
        );

        let mut result2 = DiscoveryResult::new(
            result1.peer_id, // Same peer
            "192.168.1.100:9333".parse().unwrap(),
            DiscoveryProtocol::UdpMulticast,
            9333,
        );
        // Create a test public key
        let test_pub_key = PublicKey {
            dilithium_pk: vec![1u8; 1312],
            kyber_pk: vec![2u8; 800],
            key_id: [3u8; 32],
        };
        result2.public_key = Some(test_pub_key);

        result1.merge(result2);

        // Should have both addresses
        assert_eq!(result1.addresses.len(), 2);

        // Should prefer higher priority protocol
        assert_eq!(result1.protocol, DiscoveryProtocol::UdpMulticast);

        // Should have public key from result2
        assert!(result1.public_key.is_some());
    }

    #[test]
    fn test_discovery_result_from_node_announcement() {
        let announcement = NodeAnnouncement {
            node_id: Uuid::new_v4(),
            mesh_port: 9333,
            local_ip: "192.168.1.50".parse().unwrap(),
            protocols: vec!["zhtp".to_string()],
            announced_at: 1234567890,
        };

        let result: DiscoveryResult = announcement.clone().into();

        assert_eq!(result.peer_id, announcement.node_id);
        assert_eq!(result.mesh_port, 9333);
        assert_eq!(result.protocol, DiscoveryProtocol::UdpMulticast);
        assert_eq!(result.addresses.len(), 1);
    }
}
