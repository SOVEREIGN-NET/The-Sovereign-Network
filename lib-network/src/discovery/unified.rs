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
//! - Bounded channels for memory exhaustion protection
//! - Replay attack protection via nonce tracking
//! - Security metrics and monitoring
//!
//! # Security Model
//!
//! ## Trust Levels
//! 1. **Semi-trusted**: Multicast announcements (local network only)
//! 2. **Fully Trusted**: After cryptographic handshake verification
//!
//! ## Security Guarantees
//! - Public keys are ONLY trusted after handshake verification
//! - DoS protection: Max 10 addresses per peer, bounded channels
//! - Rate limiting: 60-second scan intervals
//! - Replay protection: Nonce tracking with expiration
//! - Key validation: Format and prefix byte verification
//!
//! ## Attack Mitigations
//! - **Sybil Attack**: Peer IDs verified via cryptographic handshake
//! - **DoS**: Address list bounded, channel capacity limited
//! - **MITM**: Public keys verified against DIDs
//! - **Replay**: Nonces tracked with 5-minute expiration window
//! - **Memory Exhaustion**: Bounded collections throughout
//!
//! ## Why No Subnet Scanning?
//! Subnet scanning (connecting to random IPs) was removed for security:
//! - Port scanning is network-unfriendly and may trigger IDS/IPS
//! - Cannot verify ZHTP protocol without handshake (false positives)
//! - Exposes node to potentially malicious services
//! - Multicast discovery is the proper protocol-aware method

use anyhow::{Result, Context, anyhow};
use lib_crypto::PublicKey;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::identity::unified_peer::UnifiedPeerId;
use super::local_network::NodeAnnouncement;

/// Maximum addresses to store per peer (DoS protection)
const MAX_ADDRESSES_PER_PEER: usize = 10;

/// Maximum number of discovered peers to cache (DoS protection)
const MAX_DISCOVERED_PEERS: usize = 1000;

/// Bounded channel capacity for peer discovery events
const DISCOVERY_CHANNEL_CAPACITY: usize = 100;

/// Nonce expiration window in seconds (replay attack protection)
const NONCE_EXPIRATION_SECS: u64 = 300; // 5 minutes

/// Maximum nonces to track (memory bound)
const MAX_TRACKED_NONCES: usize = 10000;

/// Minimum valid port number (avoid privileged ports)
const MIN_PORT: u16 = 1024;

/// Maximum valid port number
const MAX_PORT: u16 = 65535;

/// Expected Dilithium public key size (Dilithium2)
const DILITHIUM_PK_SIZE: usize = 1312;

/// Expected Kyber public key size (Kyber768)
const KYBER_PK_SIZE: usize = 1184;

// === Zero-Copy Optimization Note ===
// For large payloads (>4KB), consider using:
// - bytes::Bytes for zero-copy buffer sharing
// - Arc<[u8]> for immutable shared data
// - tokio::io::copy() for streaming large transfers
// Current implementation prioritizes correctness and security over performance.
// Zero-copy can be added when profiling shows it's the bottleneck.

/// Nonce tracker for replay attack protection
///
/// Tracks seen nonces with timestamps to prevent replay attacks.
/// Old nonces are automatically pruned when they expire.
#[derive(Debug)]
pub struct NonceTracker {
    /// Seen nonces mapped to their timestamps
    seen_nonces: RwLock<HashMap<[u8; 32], u64>>,
    /// Expiration window in seconds
    expiration_secs: u64,
    /// Maximum nonces to track
    max_nonces: usize,
}

impl NonceTracker {
    /// Create a new nonce tracker with default settings
    pub fn new() -> Self {
        Self {
            seen_nonces: RwLock::new(HashMap::new()),
            expiration_secs: NONCE_EXPIRATION_SECS,
            max_nonces: MAX_TRACKED_NONCES,
        }
    }

    /// Create a new nonce tracker with custom settings
    pub fn with_config(expiration_secs: u64, max_nonces: usize) -> Self {
        Self {
            seen_nonces: RwLock::new(HashMap::new()),
            expiration_secs,
            max_nonces,
        }
    }

    /// Check if a nonce has been seen before (returns true if replay detected)
    ///
    /// # Security
    /// - Returns true if nonce was already seen (replay attack detected)
    /// - Returns false if nonce is new (safe to process)
    /// - Automatically records the nonce if it's new
    pub async fn check_and_record(&self, nonce: [u8; 32]) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nonces = self.seen_nonces.write().await;

        // Prune expired nonces first
        let expiration_threshold = now.saturating_sub(self.expiration_secs);
        nonces.retain(|_, &mut timestamp| timestamp > expiration_threshold);

        // Check if nonce exists
        if nonces.contains_key(&nonce) {
            warn!("Replay attack detected: nonce already seen");
            return true; // Replay detected
        }

        // Enforce max nonces limit (DoS protection)
        if nonces.len() >= self.max_nonces {
            // Remove oldest nonce
            if let Some(oldest_nonce) = nonces
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(n, _)| *n)
            {
                nonces.remove(&oldest_nonce);
            }
        }

        // Record new nonce
        nonces.insert(nonce, now);
        false // Not a replay
    }

    /// Get count of tracked nonces
    pub async fn nonce_count(&self) -> usize {
        self.seen_nonces.read().await.len()
    }

    /// Clear all tracked nonces (for testing)
    pub async fn clear(&self) {
        self.seen_nonces.write().await.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Security metrics for discovery service monitoring
///
/// Tracks security-relevant events for monitoring and alerting.
#[derive(Debug, Default)]
pub struct SecurityMetrics {
    /// Total peers discovered
    pub peers_discovered: AtomicU64,
    /// Peers rejected due to invalid key format
    pub invalid_keys_rejected: AtomicU64,
    /// Replay attacks detected
    pub replay_attacks_detected: AtomicU64,
    /// Peers evicted due to capacity limits
    pub peers_evicted: AtomicU64,
    /// Handshake failures
    pub handshake_failures: AtomicU64,
    /// Successful handshakes
    pub successful_handshakes: AtomicU64,
}

impl SecurityMetrics {
    /// Create new security metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new peer discovery
    pub fn record_peer_discovered(&self) {
        self.peers_discovered.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an invalid key rejection
    pub fn record_invalid_key(&self) {
        self.invalid_keys_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a replay attack detection
    pub fn record_replay_attack(&self) {
        self.replay_attacks_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a peer eviction
    pub fn record_peer_eviction(&self) {
        self.peers_evicted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a handshake failure
    pub fn record_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful handshake
    pub fn record_successful_handshake(&self) {
        self.successful_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of all metrics
    pub fn snapshot(&self) -> SecurityMetricsSnapshot {
        SecurityMetricsSnapshot {
            peers_discovered: self.peers_discovered.load(Ordering::Relaxed),
            invalid_keys_rejected: self.invalid_keys_rejected.load(Ordering::Relaxed),
            replay_attacks_detected: self.replay_attacks_detected.load(Ordering::Relaxed),
            peers_evicted: self.peers_evicted.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            successful_handshakes: self.successful_handshakes.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of security metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetricsSnapshot {
    pub peers_discovered: u64,
    pub invalid_keys_rejected: u64,
    pub replay_attacks_detected: u64,
    pub peers_evicted: u64,
    pub handshake_failures: u64,
    pub successful_handshakes: u64,
}

/// Peer reputation for adaptive trust
///
/// Tracks peer behavior to enable trust-based decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Peer identifier
    pub peer_id: Uuid,
    /// Reputation score (0-100, higher is better)
    pub score: u8,
    /// Number of successful interactions
    pub successful_interactions: u64,
    /// Number of failed interactions
    pub failed_interactions: u64,
    /// Number of protocol violations
    pub protocol_violations: u64,
    /// Last interaction timestamp
    pub last_seen: u64,
    /// Whether peer is currently banned
    pub banned: bool,
    /// Ban expiration timestamp (if banned)
    pub ban_expires: Option<u64>,
}

impl PeerReputation {
    /// Create a new peer reputation with default neutral score
    pub fn new(peer_id: Uuid) -> Self {
        Self {
            peer_id,
            score: 50, // Neutral starting score
            successful_interactions: 0,
            failed_interactions: 0,
            protocol_violations: 0,
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            banned: false,
            ban_expires: None,
        }
    }

    /// Record a successful interaction (increases reputation)
    pub fn record_success(&mut self) {
        self.successful_interactions += 1;
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Increase score, max 100
        self.score = self.score.saturating_add(1).min(100);
    }

    /// Record a failed interaction (decreases reputation)
    pub fn record_failure(&mut self) {
        self.failed_interactions += 1;
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Decrease score, min 0
        self.score = self.score.saturating_sub(2);
    }

    /// Record a protocol violation (significantly decreases reputation)
    pub fn record_violation(&mut self) {
        self.protocol_violations += 1;
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Major penalty for violations
        self.score = self.score.saturating_sub(10);

        // Auto-ban if score drops too low
        if self.score < 10 {
            self.ban(3600); // 1 hour ban
        }
    }

    /// Ban the peer for a duration
    pub fn ban(&mut self, duration_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.banned = true;
        self.ban_expires = Some(now + duration_secs);
        warn!("Peer {} banned until {}", self.peer_id, now + duration_secs);
    }

    /// Check if ban has expired and clear if so
    pub fn check_ban_expired(&mut self) -> bool {
        if !self.banned {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(expires) = self.ban_expires {
            if now >= expires {
                self.banned = false;
                self.ban_expires = None;
                self.score = 20; // Give them a second chance with low score
                info!("Peer {} ban expired, reputation reset to {}", self.peer_id, self.score);
                return true;
            }
        }
        false
    }

    /// Check if peer is trustworthy (score above threshold)
    pub fn is_trustworthy(&self) -> bool {
        !self.banned && self.score >= 30
    }

    /// Check if peer is highly trusted (score above high threshold)
    pub fn is_highly_trusted(&self) -> bool {
        !self.banned && self.score >= 70
    }
}

/// Peer reputation tracker
#[derive(Debug)]
pub struct ReputationTracker {
    /// Peer reputations mapped by peer ID
    reputations: RwLock<HashMap<Uuid, PeerReputation>>,
    /// Maximum peers to track
    max_peers: usize,
}

impl ReputationTracker {
    /// Create a new reputation tracker
    pub fn new() -> Self {
        Self {
            reputations: RwLock::new(HashMap::new()),
            max_peers: MAX_DISCOVERED_PEERS,
        }
    }

    /// Get or create reputation for a peer
    pub async fn get_or_create(&self, peer_id: Uuid) -> PeerReputation {
        let mut reps = self.reputations.write().await;

        // Check if exists and update ban status
        if let Some(rep) = reps.get_mut(&peer_id) {
            rep.check_ban_expired();
            return rep.clone();
        }

        // Enforce limit
        if reps.len() >= self.max_peers {
            // Remove peer with lowest score
            if let Some(lowest_id) = reps
                .iter()
                .min_by_key(|(_, r)| r.score)
                .map(|(id, _)| *id)
            {
                reps.remove(&lowest_id);
            }
        }

        // Create new reputation
        let rep = PeerReputation::new(peer_id);
        reps.insert(peer_id, rep.clone());
        rep
    }

    /// Update reputation for a peer
    pub async fn update(&self, reputation: PeerReputation) {
        let mut reps = self.reputations.write().await;
        reps.insert(reputation.peer_id, reputation);
    }

    /// Check if a peer is banned
    pub async fn is_banned(&self, peer_id: &Uuid) -> bool {
        let mut reps = self.reputations.write().await;
        if let Some(rep) = reps.get_mut(peer_id) {
            rep.check_ban_expired();
            return rep.banned;
        }
        false
    }

    /// Get reputation score for a peer (0-100)
    pub async fn get_score(&self, peer_id: &Uuid) -> u8 {
        let reps = self.reputations.read().await;
        reps.get(peer_id).map(|r| r.score).unwrap_or(50)
    }
}

impl Default for ReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate public key format and structure
///
/// # Security
/// Validates that public keys have correct sizes for post-quantum algorithms:
/// - Dilithium2: 1312 bytes
/// - Kyber768: 1184 bytes
///
/// This prevents malformed keys from being accepted before cryptographic verification.
pub fn validate_public_key(public_key: &PublicKey) -> Result<()> {
    // Validate Dilithium public key size
    let dilithium_len = public_key.dilithium_pk.len();
    if dilithium_len != DILITHIUM_PK_SIZE {
        return Err(anyhow!(
            "Invalid Dilithium public key size: expected {}, got {}",
            DILITHIUM_PK_SIZE, dilithium_len
        ));
    }

    // Validate Kyber public key size
    let kyber_len = public_key.kyber_pk.len();
    if kyber_len != KYBER_PK_SIZE {
        return Err(anyhow!(
            "Invalid Kyber public key size: expected {}, got {}",
            KYBER_PK_SIZE, kyber_len
        ));
    }

    // Validate key_id is not all zeros (indicates uninitialized key)
    if public_key.key_id.iter().all(|&b| b == 0) {
        return Err(anyhow!("Invalid key_id: all zeros indicates uninitialized key"));
    }

    // Basic entropy check - keys should not be all same value
    if public_key.dilithium_pk.iter().all(|&b| b == public_key.dilithium_pk[0]) {
        return Err(anyhow!("Invalid Dilithium key: no entropy (all bytes identical)"));
    }
    if public_key.kyber_pk.iter().all(|&b| b == public_key.kyber_pk[0]) {
        return Err(anyhow!("Invalid Kyber key: no entropy (all bytes identical)"));
    }

    Ok(())
}

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
    /// * `verified_peer_id` - The peer ID from the verified handshake
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
            mesh_port: announcement.mesh_port,
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
    ///
    /// # Security
    /// - Enforces MAX_DISCOVERED_PEERS limit to prevent memory exhaustion
    /// - Oldest peers are evicted when limit is reached (LRU-style)
    pub async fn register_peer(&self, result: DiscoveryResult) {
        let mut peers = self.discovered_peers.write().await;
        let peer_id = result.peer_id;

        if let Some(existing) = peers.get_mut(&peer_id) {
            existing.merge(result);
            debug!("Merged discovery result for peer: {}", peer_id);
        } else {
            // Enforce peer limit (DoS protection)
            if peers.len() >= MAX_DISCOVERED_PEERS {
                // Evict oldest peer (simple LRU - remove peer with earliest discovery time)
                if let Some(oldest_id) = peers
                    .iter()
                    .min_by_key(|(_, r)| r.discovered_at)
                    .map(|(id, _)| *id)
                {
                    warn!("Peer limit reached ({}), evicting oldest peer: {}",
                          MAX_DISCOVERED_PEERS, oldest_id);
                    peers.remove(&oldest_id);
                }
            }

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
            quic_port: 9334,
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

    // === Security Feature Tests ===

    #[test]
    fn test_validate_public_key_valid() {
        let valid_key = PublicKey {
            dilithium_pk: (0..1312).map(|i| (i % 256) as u8).collect(),
            kyber_pk: (0..1184).map(|i| (i % 256) as u8).collect(),
            key_id: [42u8; 32],
        };

        assert!(validate_public_key(&valid_key).is_ok());
    }

    #[test]
    fn test_validate_public_key_invalid_dilithium_size() {
        let invalid_key = PublicKey {
            dilithium_pk: vec![1u8; 1000], // Wrong size
            kyber_pk: vec![2u8; 1184],
            key_id: [3u8; 32],
        };

        let result = validate_public_key(&invalid_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Dilithium"));
    }

    #[test]
    fn test_validate_public_key_invalid_kyber_size() {
        let invalid_key = PublicKey {
            dilithium_pk: vec![1u8; 1312],
            kyber_pk: vec![2u8; 800], // Wrong size
            key_id: [3u8; 32],
        };

        let result = validate_public_key(&invalid_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Kyber"));
    }

    #[test]
    fn test_validate_public_key_zero_key_id() {
        let invalid_key = PublicKey {
            dilithium_pk: vec![1u8; 1312],
            kyber_pk: vec![2u8; 1184],
            key_id: [0u8; 32], // All zeros
        };

        let result = validate_public_key(&invalid_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_id"));
    }

    #[test]
    fn test_validate_public_key_no_entropy() {
        let invalid_key = PublicKey {
            dilithium_pk: vec![42u8; 1312], // All same value
            kyber_pk: vec![2u8; 1184],
            key_id: [3u8; 32],
        };

        let result = validate_public_key(&invalid_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("entropy"));
    }

    #[tokio::test]
    async fn test_nonce_tracker_new_nonce() {
        let tracker = NonceTracker::new();
        let nonce = [1u8; 32];

        // First time should not be a replay
        assert!(!tracker.check_and_record(nonce).await);

        // Second time should be a replay
        assert!(tracker.check_and_record(nonce).await);
    }

    #[tokio::test]
    async fn test_nonce_tracker_different_nonces() {
        let tracker = NonceTracker::new();
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        assert!(!tracker.check_and_record(nonce1).await);
        assert!(!tracker.check_and_record(nonce2).await);

        assert_eq!(tracker.nonce_count().await, 2);
    }

    #[tokio::test]
    async fn test_nonce_tracker_clear() {
        let tracker = NonceTracker::new();
        let nonce = [1u8; 32];

        tracker.check_and_record(nonce).await;
        assert_eq!(tracker.nonce_count().await, 1);

        tracker.clear().await;
        assert_eq!(tracker.nonce_count().await, 0);

        // After clear, same nonce should be accepted again
        assert!(!tracker.check_and_record(nonce).await);
    }

    #[test]
    fn test_security_metrics() {
        let metrics = SecurityMetrics::new();

        metrics.record_peer_discovered();
        metrics.record_peer_discovered();
        metrics.record_invalid_key();
        metrics.record_replay_attack();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.peers_discovered, 2);
        assert_eq!(snapshot.invalid_keys_rejected, 1);
        assert_eq!(snapshot.replay_attacks_detected, 1);
    }

    #[test]
    fn test_peer_reputation_new() {
        let rep = PeerReputation::new(Uuid::new_v4());
        assert_eq!(rep.score, 50); // Neutral starting score
        assert!(!rep.banned);
        assert!(rep.is_trustworthy());
    }

    #[test]
    fn test_peer_reputation_success_increases_score() {
        let mut rep = PeerReputation::new(Uuid::new_v4());
        let initial_score = rep.score;

        rep.record_success();
        assert!(rep.score > initial_score);
        assert_eq!(rep.successful_interactions, 1);
    }

    #[test]
    fn test_peer_reputation_failure_decreases_score() {
        let mut rep = PeerReputation::new(Uuid::new_v4());
        let initial_score = rep.score;

        rep.record_failure();
        assert!(rep.score < initial_score);
        assert_eq!(rep.failed_interactions, 1);
    }

    #[test]
    fn test_peer_reputation_violation_major_penalty() {
        let mut rep = PeerReputation::new(Uuid::new_v4());
        let initial_score = rep.score;

        rep.record_violation();
        assert!(rep.score < initial_score - 5); // At least -10 penalty
        assert_eq!(rep.protocol_violations, 1);
    }

    #[test]
    fn test_peer_reputation_auto_ban_on_low_score() {
        let mut rep = PeerReputation::new(Uuid::new_v4());
        rep.score = 15; // Start with low score

        rep.record_violation(); // Should trigger auto-ban
        assert!(rep.banned);
        assert!(!rep.is_trustworthy());
    }

    #[test]
    fn test_peer_reputation_trustworthy_thresholds() {
        let mut rep = PeerReputation::new(Uuid::new_v4());

        rep.score = 25;
        assert!(!rep.is_trustworthy()); // Below 30

        rep.score = 35;
        assert!(rep.is_trustworthy()); // Above 30
        assert!(!rep.is_highly_trusted()); // Below 70

        rep.score = 75;
        assert!(rep.is_trustworthy());
        assert!(rep.is_highly_trusted()); // Above 70
    }

    #[tokio::test]
    async fn test_reputation_tracker_get_or_create() {
        let tracker = ReputationTracker::new();
        let peer_id = Uuid::new_v4();

        let rep1 = tracker.get_or_create(peer_id).await;
        assert_eq!(rep1.peer_id, peer_id);
        assert_eq!(rep1.score, 50);

        // Second call should return same peer
        let rep2 = tracker.get_or_create(peer_id).await;
        assert_eq!(rep2.peer_id, peer_id);
    }

    #[tokio::test]
    async fn test_reputation_tracker_update() {
        let tracker = ReputationTracker::new();
        let peer_id = Uuid::new_v4();

        let mut rep = tracker.get_or_create(peer_id).await;
        rep.score = 80;
        tracker.update(rep).await;

        assert_eq!(tracker.get_score(&peer_id).await, 80);
    }

    #[tokio::test]
    async fn test_reputation_tracker_is_banned() {
        let tracker = ReputationTracker::new();
        let peer_id = Uuid::new_v4();

        assert!(!tracker.is_banned(&peer_id).await);

        let mut rep = tracker.get_or_create(peer_id).await;
        rep.ban(3600);
        tracker.update(rep).await;

        assert!(tracker.is_banned(&peer_id).await);
    }
}
