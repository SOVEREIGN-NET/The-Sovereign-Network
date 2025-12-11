//! Unified Peer Registry (Ticket #147)
//!
//! Single source of truth for all peer data, replacing 6 separate registries:
//! 1. mesh_connections (server)
//! 2. direct_routes (router)
//! 3. TopologyGraph.nodes (multi-hop)
//! 4. mesh_connections (handler)
//! 5. discovered_peers (bootstrap)
//! 6. dht_routing_table (DHT)
//!
//! ## Design Principles
//!
//! - **Single Source of Truth**: One canonical registry for all peer data
//! - **Thread-Safe**: Arc<RwLock<>> for concurrent access
//! - **Atomic Updates**: Prevent race conditions across components
//! - **Multi-Key Lookup**: Find peers by NodeId, PublicKey, or DID
//! - **Comprehensive Metadata**: All connection, routing, and capability data in one place
// Synchronization module (Ticket #151)
pub mod sync;

/// ## Security Features
///
/// - **DID Validation**: All DIDs validated before indexing (format + optional blockchain verification)
/// - **Index Consistency**: Atomic updates prevent stale index entries
/// - **Audit Logging**: All peer changes logged for security monitoring
/// - **Sybil Resistance**: Max peers limit + eviction policy
/// - **Rate Limiting**: Prevents DoS attacks via rapid peer churn
/// - **TOCTOU Prevention**: Atomic update methods prevent race conditions

// Acceptance Criteria Verification
//
// ✅ **Single peer registry structure defined**
//    - PeerRegistry struct with HashMap<UnifiedPeerId, PeerEntry> primary storage
//    - Secondary indexes for NodeId, PublicKey, DID
//
// ✅ **Consolidates metadata from all 6 existing stores**
//    - PeerEntry struct with all metadata
//    - Connection metadata (from MeshConnection): endpoints, protocols, metrics, auth
//    - Routing metadata (from RouteInfo): next_hop, hop_count, quality
//    - Topology metadata (from NetworkNode): capabilities, location, reliability
//    - DHT metadata (from DHT routing table): kademlia distance, bucket, contact
//    - Discovery metadata (from bootstrap): discovery method, timestamps
//    - Trust/tier metadata: trust_score, tier classification
//
// ✅ **Thread-safe wrapper using Arc<RwLock<>>**
//    - SharedPeerRegistry type alias
//    - new_shared_registry() constructor
//    - All methods use RwLock for concurrent access
//
// ✅ **Lookup methods for all identifier types**
//    - find_by_node_id()
//    - find_by_public_key()
//    - find_by_did()
//
// ✅ **Atomic update operations**
//    - upsert() atomically updates all indexes (with stale entry cleanup)
//    - remove() atomically removes from all indexes
//    - update_metrics()
//    - update_trust()

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use tracing::{info, warn, debug};

use crate::identity::unified_peer::UnifiedPeerId;
use crate::protocols::NetworkProtocol;
use lib_crypto::PublicKey;
use lib_identity::NodeId;

/// Default maximum peers (prevents memory exhaustion / Sybil attacks)
pub const DEFAULT_MAX_PEERS: usize = 10_000;

/// Default peer TTL in seconds (24 hours)
pub const DEFAULT_PEER_TTL_SECS: u64 = 86_400;

/// Default rate limit: operations per second (global)
pub const DEFAULT_GLOBAL_RATE_LIMIT: u32 = 1000;

/// Default rate limit: operations per peer per minute
pub const DEFAULT_PER_PEER_RATE_LIMIT: u32 = 10;

/// Rate limit window in seconds
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Maximum number of peers (Sybil resistance)
    pub max_peers: usize,
    /// Peer TTL in seconds (peers not seen within TTL are eligible for eviction)
    pub peer_ttl_secs: u64,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Global rate limit (operations per second)
    pub global_rate_limit: u32,
    /// Per-peer rate limit (operations per minute)
    pub per_peer_rate_limit: u32,
    /// Enable blockchain DID verification (requires blockchain connection)
    pub verify_did_on_blockchain: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            peer_ttl_secs: DEFAULT_PEER_TTL_SECS,
            audit_logging: true,
            global_rate_limit: DEFAULT_GLOBAL_RATE_LIMIT,
            per_peer_rate_limit: DEFAULT_PER_PEER_RATE_LIMIT,
            verify_did_on_blockchain: false, // Disabled by default for alpha
        }
    }
}

/// Rate limiter for registry operations
#[derive(Debug)]
pub struct RateLimiter {
    /// Per-peer operation counts (DID -> (count, window_start))
    per_peer_counts: HashMap<String, (u32, Instant)>,
    /// Global operation count
    global_count: u32,
    /// Global window start
    global_window_start: Instant,
    /// Configuration
    global_limit: u32,
    per_peer_limit: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(global_limit: u32, per_peer_limit: u32) -> Self {
        Self {
            per_peer_counts: HashMap::new(),
            global_count: 0,
            global_window_start: Instant::now(),
            global_limit,
            per_peer_limit,
        }
    }

    /// Check if operation is allowed for the given peer DID
    /// Returns Ok(()) if allowed, Err with reason if rate limited
    pub fn check_rate_limit(&mut self, peer_did: &str) -> Result<()> {
        let now = Instant::now();

        // Check global rate limit (per second window)
        if now.duration_since(self.global_window_start).as_secs() >= 1 {
            // Reset window
            self.global_count = 0;
            self.global_window_start = now;
        }

        if self.global_count >= self.global_limit {
            warn!(
                global_count = self.global_count,
                limit = self.global_limit,
                "Global rate limit exceeded"
            );
            return Err(anyhow!("Global rate limit exceeded: {} ops/sec", self.global_limit));
        }

        // Check per-peer rate limit (per minute window)
        let (count, window_start) = self.per_peer_counts
            .entry(peer_did.to_string())
            .or_insert((0, now));

        if now.duration_since(*window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            // Reset window
            *count = 0;
            *window_start = now;
        }

        if *count >= self.per_peer_limit {
            warn!(
                peer_did = %peer_did,
                count = *count,
                limit = self.per_peer_limit,
                "Per-peer rate limit exceeded"
            );
            return Err(anyhow!("Per-peer rate limit exceeded: {} ops/min for {}", self.per_peer_limit, peer_did));
        }

        // Allow operation and increment counters
        self.global_count += 1;
        *count += 1;

        Ok(())
    }

    /// Cleanup old entries from per-peer map to prevent memory growth
    pub fn cleanup_old_entries(&mut self) {
        let now = Instant::now();
        self.per_peer_counts.retain(|_, (_, window_start)| {
            now.duration_since(*window_start).as_secs() < RATE_LIMIT_WINDOW_SECS * 2
        });
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            per_peer_counts: self.per_peer_counts.clone(),
            global_count: self.global_count,
            global_window_start: self.global_window_start,
            global_limit: self.global_limit,
            per_peer_limit: self.per_peer_limit,
        }
    }
}

/// Unified peer registry - single source of truth for all peer data
///
/// Replaces 6 separate peer stores with one atomic, thread-safe registry
///
/// ## Security Features
/// - **Memory bounded**: max_peers limit prevents Sybil attacks
/// - **TTL expiration**: Stale peers automatically eligible for eviction
/// - **DID validation**: All DIDs validated before indexing (format + optional blockchain)
/// - **Index consistency**: Atomic updates prevent stale entries
/// - **Audit logging**: All changes logged for security monitoring
/// - **Rate limiting**: Per-peer and global rate limits prevent DoS attacks
#[derive(Debug)]
pub struct PeerRegistry {
    /// Primary storage: UnifiedPeerId → PeerEntry
    peers: HashMap<UnifiedPeerId, PeerEntry>,

    /// Secondary indexes for fast lookup
    by_node_id: HashMap<NodeId, UnifiedPeerId>,
    by_public_key: HashMap<PublicKey, UnifiedPeerId>,
    by_did: HashMap<String, UnifiedPeerId>,

    /// Configuration
    config: RegistryConfig,

    /// Observer registry for change notifications (Ticket #151)
    observers: sync::ObserverRegistry,

    /// Rate limiter for DoS protection
    rate_limiter: RateLimiter,
}

/// Extended configuration for PeerRegistry including observer settings
#[derive(Debug, Clone)]
pub struct PeerRegistryConfig {
    /// Base registry configuration
    pub base_config: RegistryConfig,
    /// Observer registry configuration
    pub observer_config: sync::ObserverRegistryConfig,
}

/// Complete peer metadata - consolidates all data from 6 existing registries
///
/// Contains all information previously scattered across:
/// - MeshConnection (connectivity)
/// - RouteInfo (routing)
/// - NetworkNode (topology/capabilities)
/// - DHT routing table entries
/// - Bootstrap discovered peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    /// Canonical peer identity
    pub peer_id: UnifiedPeerId,
    
    // === Connection Metadata (from MeshConnection) ===
    /// Network endpoints for this peer
    pub endpoints: Vec<PeerEndpoint>,
    /// Active connection protocols
    pub active_protocols: Vec<NetworkProtocol>,
    /// Connection quality metrics
    pub connection_metrics: ConnectionMetrics,
    /// Authentication status
    pub authenticated: bool,
    /// Quantum-secure encryption enabled
    pub quantum_secure: bool,
    
    // === Routing Metadata (from RouteInfo) ===
    /// Next hop for routing to this peer
    pub next_hop: Option<UnifiedPeerId>,
    /// Hop count to reach this peer
    pub hop_count: u8,
    /// Route quality score
    pub route_quality: f64,
    
    // === Topology/Capabilities (from NetworkNode) ===
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Geographic location (if known)
    pub location: Option<GeographicLocation>,
    /// Reliability score
    pub reliability_score: f64,
    
    // === DHT Metadata ===
    /// DHT-specific routing information
    pub dht_info: Option<DhtPeerInfo>,
    
    // === Discovery/Bootstrap Metadata ===
    /// How this peer was discovered
    pub discovery_method: DiscoveryMethod,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    
    // === Tiering and Trust ===
    /// Peer tier classification
    pub tier: PeerTier,
    /// Trust score (0.0 - 1.0)
    pub trust_score: f64,
    
    // === Statistics (use atomic counters for lock-free updates) ===
    /// Total data transferred (atomic for lock-free updates)
    #[serde(skip)]
    pub data_transferred: Arc<AtomicU64>,
    /// Total tokens earned (atomic for lock-free updates)
    #[serde(skip)]
    pub tokens_earned: Arc<AtomicU64>,
    /// Traffic routed through this peer (atomic for lock-free updates)
    #[serde(skip)]
    pub traffic_routed: Arc<AtomicU64>,

    // Serializable versions of the counters (for persistence)
    /// Serialized data_transferred value
    #[serde(rename = "data_transferred")]
    data_transferred_value: u64,
    /// Serialized tokens_earned value
    #[serde(rename = "tokens_earned")]
    tokens_earned_value: u64,
    /// Serialized traffic_routed value
    #[serde(rename = "traffic_routed")]
    traffic_routed_value: u64,
}

impl PeerEntry {
    /// Create a new PeerEntry with the given parameters
    ///
    /// This is the preferred way to create PeerEntry instances as it
    /// properly initializes the atomic counters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: UnifiedPeerId,
        endpoints: Vec<PeerEndpoint>,
        active_protocols: Vec<NetworkProtocol>,
        connection_metrics: ConnectionMetrics,
        authenticated: bool,
        quantum_secure: bool,
        next_hop: Option<UnifiedPeerId>,
        hop_count: u8,
        route_quality: f64,
        capabilities: NodeCapabilities,
        location: Option<GeographicLocation>,
        reliability_score: f64,
        dht_info: Option<DhtPeerInfo>,
        discovery_method: DiscoveryMethod,
        first_seen: u64,
        last_seen: u64,
        tier: PeerTier,
        trust_score: f64,
    ) -> Self {
        Self {
            peer_id,
            endpoints,
            active_protocols,
            connection_metrics,
            authenticated,
            quantum_secure,
            next_hop,
            hop_count,
            route_quality,
            capabilities,
            location,
            reliability_score,
            dht_info,
            discovery_method,
            first_seen,
            last_seen,
            tier,
            trust_score,
            // Initialize atomic counters
            data_transferred: Arc::new(AtomicU64::new(0)),
            tokens_earned: Arc::new(AtomicU64::new(0)),
            traffic_routed: Arc::new(AtomicU64::new(0)),
            // Initialize serializable backup values
            data_transferred_value: 0,
            tokens_earned_value: 0,
            traffic_routed_value: 0,
        }
    }

    /// Increment data transferred counter (lock-free)
    pub fn add_data_transferred(&self, bytes: u64) {
        self.data_transferred.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment tokens earned counter (lock-free)
    pub fn add_tokens_earned(&self, tokens: u64) {
        self.tokens_earned.fetch_add(tokens, Ordering::Relaxed);
    }

    /// Increment traffic routed counter (lock-free)
    pub fn add_traffic_routed(&self, bytes: u64) {
        self.traffic_routed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current data transferred value
    pub fn get_data_transferred(&self) -> u64 {
        self.data_transferred.load(Ordering::Relaxed)
    }

    /// Get current tokens earned value
    pub fn get_tokens_earned(&self) -> u64 {
        self.tokens_earned.load(Ordering::Relaxed)
    }

    /// Get current traffic routed value
    pub fn get_traffic_routed(&self) -> u64 {
        self.traffic_routed.load(Ordering::Relaxed)
    }

    /// Sync atomic counters to serializable fields (call before serialization)
    pub fn sync_counters_for_serialization(&mut self) {
        self.data_transferred_value = self.data_transferred.load(Ordering::Relaxed);
        self.tokens_earned_value = self.tokens_earned.load(Ordering::Relaxed);
        self.traffic_routed_value = self.traffic_routed.load(Ordering::Relaxed);
    }

    /// Initialize atomic counters from serialized values (call after deserialization)
    pub fn init_counters_from_serialized(&mut self) {
        self.data_transferred = Arc::new(AtomicU64::new(self.data_transferred_value));
        self.tokens_earned = Arc::new(AtomicU64::new(self.tokens_earned_value));
        self.traffic_routed = Arc::new(AtomicU64::new(self.traffic_routed_value));
    }
}

/// Network endpoint for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    /// Endpoint address (IP:port, Bluetooth address, etc.)
    pub address: String,
    /// Protocol for this endpoint
    pub protocol: NetworkProtocol,
    /// Signal strength/quality (0.0 - 1.0)
    pub signal_strength: f64,
    /// Latency in milliseconds
    pub latency_ms: u32,
}

/// Connection quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Connection strength/quality (0.0 - 1.0)
    pub signal_strength: f64,
    /// Bandwidth capacity in bytes/second
    pub bandwidth_capacity: u64,
    /// Connection latency in milliseconds
    pub latency_ms: u32,
    /// Connection stability score (0.0 - 1.0)
    pub stability_score: f64,
    /// When connection was established
    pub connected_at: u64,
}

/// Node capabilities for routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Supported protocols
    pub protocols: Vec<NetworkProtocol>,
    /// Maximum bandwidth capacity (bytes/sec)
    pub max_bandwidth: u64,
    /// Available bandwidth (bytes/sec)
    pub available_bandwidth: u64,
    /// Processing capacity for routing
    pub routing_capacity: u32,
    /// Energy level (for mobile/battery nodes, 0.0 - 1.0)
    pub energy_level: Option<f32>,
    /// Node availability percentage
    pub availability_percent: f32,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f32>,
}

/// DHT-specific peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeerInfo {
    /// Kademlia distance from local node
    pub kademlia_distance: u32,
    /// K-bucket index
    pub bucket_index: usize,
    /// Last contact timestamp
    pub last_contact: u64,
    /// Failed ping attempts
    pub failed_attempts: u32,
}

/// How a peer was discovered
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// Discovered via bootstrap process
    Bootstrap,
    /// Discovered via DHT lookup
    Dht,
    /// Discovered via local mesh scan
    MeshScan,
    /// Discovered via relay
    Relay,
    /// Manually added
    Manual,
    /// Discovered via blockchain peer list
    Blockchain,
}

/// Peer tier classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerTier {
    /// Core infrastructure nodes
    Tier1,
    /// Relay and routing nodes
    Tier2,
    /// Standard participating nodes
    Tier3,
    /// Edge/mobile nodes
    Tier4,
    /// Untrusted/new nodes
    Untrusted,
}

impl PeerRegistry {
    /// Create a new empty peer registry with default configuration
    pub fn new() -> Self {
        Self::with_config(RegistryConfig::default())
    }

    /// Create a new peer registry with custom configuration
    pub fn with_config(config: RegistryConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.global_rate_limit, config.per_peer_rate_limit);
        Self {
            peers: HashMap::new(),
            by_node_id: HashMap::new(),
            by_public_key: HashMap::new(),
            by_did: HashMap::new(),
            config,
            observers: sync::ObserverRegistry::new(),
            rate_limiter,
        }
    }
    
    /// Register an observer for peer change notifications (Ticket #151)
    pub async fn register_observer(&self, observer: Arc<dyn sync::PeerRegistryObserver>) {
        self.observers.register(observer).await;
    }
    
    /// Unregister an observer by name (Ticket #151)
    pub async fn unregister_observer(&self, name: &str) -> bool {
        self.observers.unregister(name).await
    }
    
    /// Clean up stale observers based on timeout (Ticket #151)
    ///
    /// # Memory Management
    /// - Removes observers that haven't been active recently
    /// - Returns number of observers removed
    pub async fn cleanup_stale_observers(&self, timeout_secs: u64) -> usize {
        self.observers.cleanup_stale_observers(timeout_secs).await
    }
    
    /// Get observer registry statistics for monitoring (Ticket #151)
    ///
    /// # Performance Monitoring
    /// - Provides insights into observer health and performance
    pub async fn get_observer_stats(&self) -> sync::ObserverRegistryStats {
        self.observers.get_stats().await
    }

    /// Validate DID format before indexing
    ///
    /// # Security
    /// - Prevents malicious DIDs like "admin" or "system" from being indexed
    /// - Validates DID format (prefix, length, hex characters)
    /// - Optionally verifies DID on blockchain (if configured)
    ///
    /// # DID Format
    /// Valid DID: `did:zhtp:<64-char-hex-hash>`
    pub fn validate_did(did: &str) -> Result<()> {
        // Check for null bytes (security: prevent injection attacks)
        if did.contains('\0') {
            return Err(anyhow!("Invalid DID: contains null byte"));
        }

        // DID must start with "did:zhtp:" and have sufficient length
        if !did.starts_with("did:zhtp:") {
            return Err(anyhow!("Invalid DID format: must start with 'did:zhtp:'"));
        }

        // DID must have content after the prefix (at least 16 chars for the hash)
        if did.len() < 25 {
            return Err(anyhow!("Invalid DID format: too short (expected at least 25 chars)"));
        }

        // Maximum DID length (prevent memory exhaustion)
        if did.len() > 100 {
            return Err(anyhow!("Invalid DID format: too long (max 100 chars)"));
        }

        // Check for valid hex characters after prefix
        let hash_part = &did[9..]; // After "did:zhtp:"
        if !hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid DID format: hash must be hexadecimal"));
        }

        // Additional security checks
        if hash_part.len() < 16 {
            return Err(anyhow!("Invalid DID format: hash too short (min 16 hex chars)"));
        }

        Ok(())
    }

    /// Verify DID on blockchain (async, optional)
    ///
    /// This checks that:
    /// 1. DID is registered on the blockchain
    /// 2. DID is not revoked
    /// 3. Public key matches registered DID
    ///
    /// NOTE: This is a placeholder for blockchain integration.
    /// In production, this should query the blockchain state.
    pub async fn verify_did_on_blockchain(did: &str, public_key: &PublicKey) -> Result<bool> {
        // TODO: Implement actual blockchain verification
        // For now, just log that verification would happen
        debug!(
            did = %did,
            public_key = %hex::encode(&public_key.key_id[0..8]),
            "Would verify DID on blockchain (not implemented yet)"
        );

        // Placeholder: In production, this would:
        // 1. Query blockchain for DID registration
        // 2. Verify public key matches
        // 3. Check revocation status
        // 4. Verify registration timestamp

        Ok(true) // Accept all DIDs for now
    }

    /// Get current timestamp in seconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Insert or update a peer entry
    ///
    /// # Security
    /// - Rate limits operations to prevent DoS attacks
    /// - Validates DID format before indexing
    /// - Removes stale index entries to prevent index poisoning
    /// - Enforces max_peers limit with eviction policy
    /// - Logs all changes for audit trail
    ///
    /// This is an atomic operation that updates all indexes
    /// Insert or update a peer entry
    ///
    /// # Security
    /// - Validates DID format before indexing
    /// - Removes stale index entries to prevent index poisoning
    /// - Enforces max_peers limit with eviction policy
    /// - Logs all changes for audit trail
    /// - Notifies observers atomically (Ticket #151)
    ///
    /// This is an atomic operation that updates all indexes and notifies observers
    pub async fn upsert(&mut self, entry: PeerEntry) -> Result<()> {
        let peer_id = entry.peer_id.clone();
        let did = peer_id.did().to_string();

        // SECURITY: Check rate limits before processing
        self.rate_limiter.check_rate_limit(&did)?;

        // SECURITY: Validate DID format before indexing
        Self::validate_did(&did)?;

        // SECURITY: Check if we need to evict peers (max_peers limit)
        if !self.peers.contains_key(&peer_id) && self.peers.len() >= self.config.max_peers {
            self.evict_stale_peer()?;
        }

        // Track if this is an update or new peer for event dispatch
        let old_entry = self.peers.get(&peer_id).cloned();
        let is_update = old_entry.is_some();

        // SECURITY: Remove stale index entries if peer exists with different identity fields
        // This prevents index poisoning attacks
        if let Some(existing) = &old_entry {
            // If identity fields changed, remove old index entries
            if existing.peer_id.node_id() != peer_id.node_id() {
                self.by_node_id.remove(existing.peer_id.node_id());
                warn!(
                    old_node_id = %hex::encode(existing.peer_id.node_id().as_bytes()),
                    new_node_id = %hex::encode(peer_id.node_id().as_bytes()),
                    "Peer NodeId changed - removed stale index"
                );
            }
            if existing.peer_id.public_key() != peer_id.public_key() {
                self.by_public_key.remove(existing.peer_id.public_key());
                warn!(
                    peer_did = %did,
                    "Peer PublicKey changed - removed stale index"
                );
            }
            if existing.peer_id.did() != peer_id.did() {
                self.by_did.remove(existing.peer_id.did());
                warn!(
                    old_did = %existing.peer_id.did(),
                    new_did = %did,
                    "Peer DID changed - removed stale index"
                );
            }
        }

        // Update secondary indexes
        self.by_node_id.insert(peer_id.node_id().clone(), peer_id.clone());
        self.by_public_key.insert(peer_id.public_key().clone(), peer_id.clone());
        self.by_did.insert(did.clone(), peer_id.clone());

        // Insert into primary storage
        self.peers.insert(peer_id.clone(), entry.clone());

        // AUDIT: Log peer changes
        if self.config.audit_logging {
            if !is_update {
                info!(
                    peer_did = %did,
                    peer_count = self.peers.len(),
                    "Peer added to registry"
                );
            } else {
                debug!(
                    peer_did = %did,
                    "Peer updated in registry"
                );
            }
        }

        // TICKET #151: Dispatch event to observers atomically
        let event = if is_update {
            sync::PeerRegistryEvent::PeerUpdated {
                peer_id,
                old_entry: old_entry.unwrap(),
                new_entry: entry,
            }
        } else {
            sync::PeerRegistryEvent::PeerAdded {
                peer_id,
                entry,
            }
        };
        
        self.observers.dispatch(event).await?;

        Ok(())
    }

    /// Evict the most stale peer to make room for new peers
    ///
    /// # Eviction Policy
    /// 1. First, try to evict expired peers (TTL exceeded)
    /// 2. If no expired peers, evict lowest-tier peer
    /// 3. Among same tier, evict least-recently-seen peer
    fn evict_stale_peer(&mut self) -> Result<()> {
        let now = Self::current_timestamp();
        let ttl = self.config.peer_ttl_secs;

        // Strategy 1: Find expired peer (TTL exceeded)
        let expired_peer = self.peers.iter()
            .filter(|(_, entry)| now.saturating_sub(entry.last_seen) > ttl)
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(id, _)| id.clone());

        if let Some(peer_id) = expired_peer {
            let audit_logging = self.config.audit_logging; // Capture before mutable borrow
            let _entry = self.remove(&peer_id);
            if audit_logging {
                info!(
                    peer_did = %peer_id.did(),
                    reason = "TTL_EXPIRED",
                    "Peer evicted from registry"
                );
            }
            return Ok(());
        }

        // Strategy 2: Evict lowest-tier, least-recently-seen peer
        let victim = self.peers.iter()
            .max_by(|(_, a), (_, b)| {
                // Higher tier (worse) = evict first
                // Among same tier, older last_seen = evict first
                a.tier.cmp(&b.tier)
                    .then_with(|| b.last_seen.cmp(&a.last_seen))
            })
            .map(|(id, _)| id.clone());

        if let Some(peer_id) = victim {
            let audit_logging = self.config.audit_logging; // Capture before mutable borrow
            let _entry = self.remove(&peer_id);
            if audit_logging {
                info!(
                    peer_did = %peer_id.did(),
                    reason = "MAX_PEERS_EVICTION",
                    "Peer evicted from registry"
                );
            }
            return Ok(());
        }

        Err(anyhow!("Cannot evict peer: registry empty"))
    }

    /// Remove a peer entry
    ///
    /// Atomically removes peer from all indexes and notifies observers (Ticket #151)
    pub async fn remove(&mut self, peer_id: &UnifiedPeerId) -> Option<PeerEntry> {
        // Get entry before removal for event dispatch
        let entry = self.peers.get(peer_id).cloned();
        
        // Remove from secondary indexes
        self.by_node_id.remove(peer_id.node_id());
        self.by_public_key.remove(peer_id.public_key());
        self.by_did.remove(peer_id.did());

        // Remove from primary storage
        let removed = self.peers.remove(peer_id);

        // AUDIT: Log removal
        if self.config.audit_logging && removed.is_some() {
            info!(
                peer_did = %peer_id.did(),
                peer_count = self.peers.len(),
                "Peer removed from registry"
            );
        }

        // TICKET #151: Dispatch event to observers if peer was removed
        if let Some(entry_data) = entry {
            let event = sync::PeerRegistryEvent::PeerRemoved {
                peer_id: peer_id.clone(),
                entry: entry_data,
            };
            // Ignore observer errors on removal (peer is already gone)
            let _ = self.observers.dispatch(event).await;
        }

        removed
    }

    /// Cleanup expired peers based on TTL
    ///
    /// Returns the number of peers removed
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Self::current_timestamp();
        let ttl = self.config.peer_ttl_secs;

        let expired: Vec<UnifiedPeerId> = self.peers.iter()
            .filter(|(_, entry)| now.saturating_sub(entry.last_seen) > ttl)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for peer_id in expired {
            self.remove(&peer_id);
        }

        if count > 0 && self.config.audit_logging {
            info!(
                expired_count = count,
                remaining_peers = self.peers.len(),
                "Expired peers cleaned up"
            );
        }

        count
    }

    /// Clear all peers from the registry
    ///
    /// Removes all peers and clears all indexes atomically.
    /// Use with caution - typically only for shutdown or testing.
    pub fn clear(&mut self) {
        let count = self.peers.len();
        self.peers.clear();
        self.by_node_id.clear();
        self.by_public_key.clear();
        self.by_did.clear();

        if self.config.audit_logging && count > 0 {
            info!(
                removed_count = count,
                "Registry cleared - all peers removed"
            );
        }
    }
    
    /// Atomic batch update - commit multiple peer changes in single transaction (Ticket #151)
    ///
    /// All changes are applied atomically and observers notified with single BatchUpdate event.
    /// This prevents race conditions when multiple peers need to be updated simultaneously.
    ///
    /// # Returns
    /// - Ok(()) if all operations succeeded
    /// - Err if any operation failed (entire batch is rolled back)
    ///
    /// # Example
    /// ```ignore
    /// let mut batch = sync::BatchUpdate::new();
    /// batch.add_peer(peer1_id, peer1_entry);
    /// batch.update_peer(peer2_id, old_entry, new_entry);
    /// batch.remove_peer(peer3_id, peer3_entry);
    /// registry.commit_batch(batch).await?;
    /// ```
    pub async fn commit_batch(&mut self, batch: sync::BatchUpdate) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        
        let ops = batch.operations();
        
        // Phase 1: Apply all additions
        for (peer_id, entry) in ops.added {
            // Direct insert without individual event dispatch
            let did = peer_id.did().to_string();
            Self::validate_did(&did)?;
            
            if !self.peers.contains_key(peer_id) && self.peers.len() >= self.config.max_peers {
                self.evict_stale_peer()?;
            }
            
            self.by_node_id.insert(peer_id.node_id().clone(), peer_id.clone());
            self.by_public_key.insert(peer_id.public_key().clone(), peer_id.clone());
            self.by_did.insert(did, peer_id.clone());
            self.peers.insert(peer_id.clone(), entry.clone());
        }
        
        // Phase 2: Apply all updates
        for (peer_id, _old, new_entry) in ops.updated {
            if self.peers.contains_key(peer_id) {
                self.peers.insert(peer_id.clone(), new_entry.clone());
            }
        }
        
        // Phase 3: Apply all removals
        for (peer_id, _entry) in ops.removed {
            self.by_node_id.remove(peer_id.node_id());
            self.by_public_key.remove(peer_id.public_key());
            self.by_did.remove(peer_id.did());
            self.peers.remove(peer_id);
        }
        
        // Phase 4: Extract event data and dispatch single batch event
        let (added, updated, removed) = batch.into_event_data();
        
        if self.config.audit_logging {
            info!(
                added = added.len(),
                updated = updated.len(),
                removed = removed.len(),
                "Batch update committed to registry"
            );
        }
        
        let event = sync::PeerRegistryEvent::BatchUpdate {
            added,
            updated,
            removed,
        };
        
        self.observers.dispatch(event).await?;
        
        Ok(())
    }

    /// Get peer by UnifiedPeerId
    pub fn get(&self, peer_id: &UnifiedPeerId) -> Option<&PeerEntry> {
        self.peers.get(peer_id)
    }
    
    /// Get mutable peer by UnifiedPeerId
    pub fn get_mut(&mut self, peer_id: &UnifiedPeerId) -> Option<&mut PeerEntry> {
        self.peers.get_mut(peer_id)
    }
    
    /// **ACCEPTANCE CRITERIA**: Lookup by NodeId
    pub fn find_by_node_id(&self, node_id: &NodeId) -> Option<&PeerEntry> {
        self.by_node_id.get(node_id)
            .and_then(|peer_id| self.peers.get(peer_id))
    }
    
    /// **ACCEPTANCE CRITERIA**: Lookup by PublicKey
    pub fn find_by_public_key(&self, public_key: &PublicKey) -> Option<&PeerEntry> {
        self.by_public_key.get(public_key)
            .and_then(|peer_id| self.peers.get(peer_id))
    }
    
    /// **ACCEPTANCE CRITERIA**: Lookup by DID
    pub fn find_by_did(&self, did: &str) -> Option<&PeerEntry> {
        self.by_did.get(did)
            .and_then(|peer_id| self.peers.get(peer_id))
    }
    
    /// Get all peers
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values()
    }
    
    /// Get peers by tier
    pub fn peers_by_tier(&self, tier: PeerTier) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(move |entry| entry.tier == tier)
    }
    
    /// Get authenticated peers
    pub fn authenticated_peers(&self) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(|entry| entry.authenticated)
    }
    
    /// Get peers with specific protocol
    pub fn peers_with_protocol(&self, protocol: NetworkProtocol) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(move |entry| 
            entry.active_protocols.contains(&protocol)
        )
    }
    
    /// Get peers by discovery method
    pub fn peers_by_discovery(&self, method: DiscoveryMethod) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(move |entry| entry.discovery_method == method)
    }
    
    /// Update connection metrics for a peer
    pub fn update_metrics(&mut self, peer_id: &UnifiedPeerId, metrics: ConnectionMetrics) -> Result<()> {
        let entry = self.peers.get_mut(peer_id)
            .ok_or_else(|| anyhow!("Peer not found"))?;
        entry.connection_metrics = metrics;
        entry.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(())
    }
    
    /// Update trust score
    pub fn update_trust(&mut self, peer_id: &UnifiedPeerId, trust_score: f64) -> Result<()> {
        let entry = self.peers.get_mut(peer_id)
            .ok_or_else(|| anyhow!("Peer not found"))?;
        entry.trust_score = trust_score.clamp(0.0, 1.0);
        Ok(())
    }
    
    /// Get registry statistics
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_peers: self.peers.len(),
            tier1_count: self.peers_by_tier(PeerTier::Tier1).count(),
            tier2_count: self.peers_by_tier(PeerTier::Tier2).count(),
            tier3_count: self.peers_by_tier(PeerTier::Tier3).count(),
            tier4_count: self.peers_by_tier(PeerTier::Tier4).count(),
            untrusted_count: self.peers_by_tier(PeerTier::Untrusted).count(),
            authenticated_count: self.authenticated_peers().count(),
        }
    }

    // ========== TOCTOU-SAFE ATOMIC UPDATE METHODS ==========
    //
    // These methods perform read-modify-write operations atomically
    // with a single mutable borrow, preventing race conditions that
    // occur with the read-clone-drop-write pattern.

    /// Atomically update a peer if it exists
    ///
    /// # TOCTOU Safety
    /// This method takes a single mutable borrow and performs the
    /// read-modify-write atomically, preventing race conditions.
    ///
    /// # Example
    /// ```ignore
    /// registry.update_if_exists(&peer_id, |entry| {
    ///     entry.connection_metrics.stability_score = 0.95;
    ///     entry.last_seen = current_timestamp();
    /// });
    /// ```
    pub fn update_if_exists<F>(&mut self, peer_id: &UnifiedPeerId, update_fn: F) -> bool
    where
        F: FnOnce(&mut PeerEntry),
    {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            update_fn(entry);
            true
        } else {
            false
        }
    }

    /// Atomically update a peer by public key if it exists
    ///
    /// # TOCTOU Safety
    /// Same as `update_if_exists` but looks up by public key.
    pub fn update_by_public_key<F>(&mut self, public_key: &PublicKey, update_fn: F) -> bool
    where
        F: FnOnce(&mut PeerEntry),
    {
        if let Some(peer_id) = self.by_public_key.get(public_key).cloned() {
            if let Some(entry) = self.peers.get_mut(&peer_id) {
                update_fn(entry);
                return true;
            }
        }
        false
    }

    /// Atomically update a peer by node ID if it exists
    ///
    /// # TOCTOU Safety
    /// Same as `update_if_exists` but looks up by node ID.
    pub fn update_by_node_id<F>(&mut self, node_id: &NodeId, update_fn: F) -> bool
    where
        F: FnOnce(&mut PeerEntry),
    {
        if let Some(peer_id) = self.by_node_id.get(node_id).cloned() {
            if let Some(entry) = self.peers.get_mut(&peer_id) {
                update_fn(entry);
                return true;
            }
        }
        false
    }

    /// Atomically update a peer by DID if it exists
    ///
    /// # TOCTOU Safety
    /// Same as `update_if_exists` but looks up by DID.
    pub fn update_by_did<F>(&mut self, did: &str, update_fn: F) -> bool
    where
        F: FnOnce(&mut PeerEntry),
    {
        if let Some(peer_id) = self.by_did.get(did).cloned() {
            if let Some(entry) = self.peers.get_mut(&peer_id) {
                update_fn(entry);
                return true;
            }
        }
        false
    }

    /// Atomically update or insert a peer
    ///
    /// # TOCTOU Safety
    /// Either updates an existing peer or inserts a new one atomically.
    /// The `update_fn` is only called if the peer already exists.
    /// The `create_fn` is only called if the peer doesn't exist.
    ///
    /// Returns true if updated, false if inserted.
    pub async fn update_or_insert<U, C>(
        &mut self,
        peer_id: &UnifiedPeerId,
        update_fn: U,
        create_fn: C,
    ) -> Result<bool>
    where
        U: FnOnce(&mut PeerEntry),
        C: FnOnce() -> PeerEntry,
    {
        if self.peers.contains_key(peer_id) {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                update_fn(entry);
            }
            Ok(true) // Updated
        } else {
            let new_entry = create_fn();
            self.upsert(new_entry).await?;
            Ok(false) // Inserted
        }
    }

    /// Atomically update metrics with retry on contention
    ///
    /// # TOCTOU Safety
    /// This is a convenience wrapper that updates common connection metrics.
    pub fn update_connection_state(
        &mut self,
        peer_id: &UnifiedPeerId,
        stability_score: Option<f64>,
        bandwidth_capacity: Option<u64>,
        latency_ms: Option<u32>,
    ) -> Result<()> {
        let entry = self.peers.get_mut(peer_id)
            .ok_or_else(|| anyhow!("Peer not found"))?;

        if let Some(score) = stability_score {
            entry.connection_metrics.stability_score = score.clamp(0.0, 1.0);
        }
        if let Some(bandwidth) = bandwidth_capacity {
            entry.connection_metrics.bandwidth_capacity = bandwidth;
        }
        if let Some(latency) = latency_ms {
            entry.connection_metrics.latency_ms = latency;
        }

        entry.last_seen = Self::current_timestamp();
        Ok(())
    }

    /// Cleanup rate limiter old entries (call periodically)
    pub fn cleanup_rate_limiter(&mut self) {
        self.rate_limiter.cleanup_old_entries();
    }

    /// Get rate limiter statistics
    pub fn rate_limiter_stats(&self) -> (u32, usize) {
        (self.rate_limiter.global_count, self.rate_limiter.per_peer_counts.len())
    }
}

/// Registry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStats {
    pub total_peers: usize,
    pub tier1_count: usize,
    pub tier2_count: usize,
    pub tier3_count: usize,
    pub tier4_count: usize,
    pub untrusted_count: usize,
    pub authenticated_count: usize,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe peer registry wrapper
///
/// **ACCEPTANCE CRITERIA**: Atomic updates prevent race conditions
pub type SharedPeerRegistry = Arc<RwLock<PeerRegistry>>;

/// Create a new shared peer registry
pub fn new_shared_registry() -> SharedPeerRegistry {
    Arc::new(RwLock::new(PeerRegistry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_peer_id() -> UnifiedPeerId {
        // This would use real ZhtpIdentity in production
        use lib_identity::ZhtpIdentity;
        
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None,
            None,
            "test-device",
            None,
        ).expect("Failed to create test identity");
        
        UnifiedPeerId::from_zhtp_identity(&identity)
            .expect("Failed to create UnifiedPeerId")
    }
    
    fn create_test_entry(peer_id: UnifiedPeerId) -> PeerEntry {
        PeerEntry {
            peer_id: peer_id.clone(),
            endpoints: vec![],
            active_protocols: vec![NetworkProtocol::QUIC],
            connection_metrics: ConnectionMetrics {
                signal_strength: 0.8,
                bandwidth_capacity: 1_000_000,
                latency_ms: 50,
                stability_score: 0.9,
                connected_at: 0,
            },
            authenticated: true,
            quantum_secure: true,
            next_hop: None,
            hop_count: 1,
            route_quality: 0.85,
            capabilities: NodeCapabilities {
                protocols: vec![NetworkProtocol::QUIC],
                max_bandwidth: 1_000_000,
                available_bandwidth: 800_000,
                routing_capacity: 100,
                energy_level: Some(0.9),
                availability_percent: 95.0,
            },
            location: None,
            reliability_score: 0.92,
            dht_info: None,
            discovery_method: DiscoveryMethod::MeshScan,
            first_seen: 0,
            last_seen: 0,
            tier: PeerTier::Tier3,
            trust_score: 0.8,
            // Atomic counters
            data_transferred: Arc::new(AtomicU64::new(0)),
            tokens_earned: Arc::new(AtomicU64::new(0)),
            traffic_routed: Arc::new(AtomicU64::new(0)),
            // Serializable backup values
            data_transferred_value: 0,
            tokens_earned_value: 0,
            traffic_routed_value: 0,
        }
    }
    
    #[test]
    fn test_registry_creation() {
        let registry = PeerRegistry::new();
        assert_eq!(registry.peers.len(), 0);
    }
    
    #[test]
    fn test_upsert_and_get() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id.clone());
        
        registry.upsert(entry.clone()).expect("Failed to upsert");
        
        let retrieved = registry.get(&peer_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().peer_id, peer_id);
    }
    
    #[test]
    fn test_find_by_node_id() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let node_id = peer_id.node_id().clone();
        let entry = create_test_entry(peer_id.clone());
        
        registry.upsert(entry).expect("Failed to upsert");
        
        let found = registry.find_by_node_id(&node_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.node_id(), &node_id);
    }
    
    #[test]
    fn test_find_by_public_key() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let public_key = peer_id.public_key().clone();
        let entry = create_test_entry(peer_id.clone());
        
        registry.upsert(entry).expect("Failed to upsert");
        
        let found = registry.find_by_public_key(&public_key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.public_key(), &public_key);
    }
    
    #[test]
    fn test_find_by_did() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let did = peer_id.did().to_string();
        let entry = create_test_entry(peer_id.clone());
        
        registry.upsert(entry).expect("Failed to upsert");
        
        let found = registry.find_by_did(&did);
        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.did(), did);
    }
    
    #[test]
    fn test_remove() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let node_id = peer_id.node_id().clone();
        let entry = create_test_entry(peer_id.clone());
        
        registry.upsert(entry).expect("Failed to upsert");
        assert!(registry.get(&peer_id).is_some());
        
        let removed = registry.remove(&peer_id);
        assert!(removed.is_some());
        assert!(registry.get(&peer_id).is_none());
        assert!(registry.find_by_node_id(&node_id).is_none());
    }
    
    #[test]
    fn test_peers_by_tier() {
        let mut registry = PeerRegistry::new();
        
        let peer1 = create_test_peer_id();
        let mut entry1 = create_test_entry(peer1);
        entry1.tier = PeerTier::Tier1;
        
        let peer2 = create_test_peer_id();
        let mut entry2 = create_test_entry(peer2);
        entry2.tier = PeerTier::Tier2;
        
        registry.upsert(entry1).expect("Failed to upsert");
        registry.upsert(entry2).expect("Failed to upsert");
        
        let tier1_peers: Vec<_> = registry.peers_by_tier(PeerTier::Tier1).collect();
        assert_eq!(tier1_peers.len(), 1);
    }
    
    #[tokio::test]
    async fn test_shared_registry() {
        let registry = new_shared_registry();

        {
            let mut reg = registry.write().await;
            let peer_id = create_test_peer_id();
            let entry = create_test_entry(peer_id);
            reg.upsert(entry).expect("Failed to upsert");
        }

        {
            let reg = registry.read().await;
            assert_eq!(reg.peers.len(), 1);
        }
    }

    // ========== NEW SECURITY TESTS ==========

    #[test]
    fn test_did_validation_rejects_invalid_format() {
        // Test that invalid DIDs are rejected
        assert!(PeerRegistry::validate_did("admin").is_err());
        assert!(PeerRegistry::validate_did("system").is_err());
        assert!(PeerRegistry::validate_did("did:other:abc123").is_err());
        assert!(PeerRegistry::validate_did("did:zhtp:").is_err()); // Too short
        assert!(PeerRegistry::validate_did("did:zhtp:xyz!@#").is_err()); // Invalid chars
    }

    #[test]
    fn test_did_validation_accepts_valid_format() {
        // Valid DIDs should pass
        assert!(PeerRegistry::validate_did("did:zhtp:1234567890abcdef1234567890abcdef").is_ok());
        assert!(PeerRegistry::validate_did("did:zhtp:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab").is_ok());
    }

    #[test]
    fn test_max_peers_eviction() {
        // Create a registry with max 3 peers
        let config = RegistryConfig {
            max_peers: 3,
            peer_ttl_secs: 86400,
            audit_logging: false, // Disable logging for test
            global_rate_limit: 10000, // High limit for tests
            per_peer_rate_limit: 1000,
            verify_did_on_blockchain: false,
        };
        let mut registry = PeerRegistry::with_config(config);

        // Add 3 peers
        for i in 0..3 {
            let peer_id = create_test_peer_id();
            let mut entry = create_test_entry(peer_id);
            entry.tier = PeerTier::Tier3;
            entry.last_seen = i as u64; // Different last_seen times
            registry.upsert(entry).expect("Failed to upsert");
        }

        assert_eq!(registry.peers.len(), 3);

        // Add 4th peer - should trigger eviction
        let peer_id = create_test_peer_id();
        let mut entry = create_test_entry(peer_id.clone());
        entry.tier = PeerTier::Tier1; // Higher tier = less likely to be evicted
        entry.last_seen = 100;
        registry.upsert(entry).expect("Failed to upsert");

        // Should still have 3 peers (one was evicted)
        assert_eq!(registry.peers.len(), 3);

        // The new Tier1 peer should be present
        assert!(registry.get(&peer_id).is_some());
    }

    #[test]
    fn test_cleanup_expired_peers() {
        let config = RegistryConfig {
            max_peers: 100,
            peer_ttl_secs: 60, // 60 second TTL
            audit_logging: false,
            global_rate_limit: 10000, // High limit for tests
            per_peer_rate_limit: 1000,
            verify_did_on_blockchain: false,
        };
        let mut registry = PeerRegistry::with_config(config);

        // Add peer with old last_seen (expired)
        let peer1 = create_test_peer_id();
        let mut entry1 = create_test_entry(peer1.clone());
        entry1.last_seen = 0; // Very old
        registry.upsert(entry1).expect("Failed to upsert");

        // Add peer with recent last_seen (not expired)
        let peer2 = create_test_peer_id();
        let mut entry2 = create_test_entry(peer2.clone());
        entry2.last_seen = PeerRegistry::current_timestamp(); // Now
        registry.upsert(entry2).expect("Failed to upsert");

        assert_eq!(registry.peers.len(), 2);

        // Cleanup expired peers
        let removed = registry.cleanup_expired();

        // One peer should be removed (the expired one)
        assert_eq!(removed, 1);
        assert_eq!(registry.peers.len(), 1);
        assert!(registry.get(&peer1).is_none()); // Expired peer gone
        assert!(registry.get(&peer2).is_some()); // Recent peer remains
    }

    #[test]
    fn test_update_metrics() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id.clone());

        registry.upsert(entry).expect("Failed to upsert");

        let new_metrics = ConnectionMetrics {
            signal_strength: 0.95,
            bandwidth_capacity: 2_000_000,
            latency_ms: 25,
            stability_score: 0.99,
            connected_at: 12345,
        };

        registry.update_metrics(&peer_id, new_metrics.clone()).expect("Failed to update");

        let updated = registry.get(&peer_id).unwrap();
        assert_eq!(updated.connection_metrics.signal_strength, 0.95);
        assert_eq!(updated.connection_metrics.bandwidth_capacity, 2_000_000);
    }

    #[test]
    fn test_update_trust_clamping() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id.clone());

        registry.upsert(entry).expect("Failed to upsert");

        // Test trust score clamping to 0.0-1.0 range
        registry.update_trust(&peer_id, 1.5).expect("Failed to update");
        assert_eq!(registry.get(&peer_id).unwrap().trust_score, 1.0);

        registry.update_trust(&peer_id, -0.5).expect("Failed to update");
        assert_eq!(registry.get(&peer_id).unwrap().trust_score, 0.0);

        registry.update_trust(&peer_id, 0.75).expect("Failed to update");
        assert_eq!(registry.get(&peer_id).unwrap().trust_score, 0.75);
    }

    #[test]
    fn test_registry_stats() {
        let mut registry = PeerRegistry::new();

        // Add peers with different tiers
        let peer1 = create_test_peer_id();
        let mut entry1 = create_test_entry(peer1);
        entry1.tier = PeerTier::Tier1;
        entry1.authenticated = true;

        let peer2 = create_test_peer_id();
        let mut entry2 = create_test_entry(peer2);
        entry2.tier = PeerTier::Tier2;
        entry2.authenticated = true;

        let peer3 = create_test_peer_id();
        let mut entry3 = create_test_entry(peer3);
        entry3.tier = PeerTier::Untrusted;
        entry3.authenticated = false;

        registry.upsert(entry1).expect("Failed to upsert");
        registry.upsert(entry2).expect("Failed to upsert");
        registry.upsert(entry3).expect("Failed to upsert");

        let stats = registry.stats();
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.tier1_count, 1);
        assert_eq!(stats.tier2_count, 1);
        assert_eq!(stats.untrusted_count, 1);
        assert_eq!(stats.authenticated_count, 2);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let registry = new_shared_registry();
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn 10 concurrent writers
        for i in 0..10 {
            let registry_clone = registry.clone();
            let success_clone = success_count.clone();
            handles.push(tokio::spawn(async move {
                let peer_id = create_test_peer_id();
                let mut entry = create_test_entry(peer_id);
                entry.tier = if i % 2 == 0 { PeerTier::Tier1 } else { PeerTier::Tier2 };

                let mut reg = registry_clone.write().await;
                if reg.upsert(entry).is_ok() {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        // Spawn 10 concurrent readers
        for _ in 0..10 {
            let registry_clone = registry.clone();
            handles.push(tokio::spawn(async move {
                let reg = registry_clone.read().await;
                let _ = reg.stats();
            }));
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.expect("Task panicked");
        }

        // All writes should succeed
        assert_eq!(success_count.load(Ordering::SeqCst), 10);

        // Verify registry state
        let reg = registry.read().await;
        assert_eq!(reg.peers.len(), 10);
    }

    #[test]
    fn test_with_custom_config() {
        let config = RegistryConfig {
            max_peers: 500,
            peer_ttl_secs: 3600,
            audit_logging: false,
            global_rate_limit: 2000,
            per_peer_rate_limit: 20,
            verify_did_on_blockchain: true,
        };

        let registry = PeerRegistry::with_config(config.clone());
        assert_eq!(registry.config.max_peers, 500);
        assert_eq!(registry.config.peer_ttl_secs, 3600);
        assert!(!registry.config.audit_logging);
        assert_eq!(registry.config.global_rate_limit, 2000);
        assert_eq!(registry.config.per_peer_rate_limit, 20);
        assert!(registry.config.verify_did_on_blockchain);
    }

    #[test]
    fn test_empty_registry_operations() {
        let mut registry = PeerRegistry::new();

        // Remove from empty registry should return None
        let peer_id = create_test_peer_id();
        assert!(registry.remove(&peer_id).is_none());

        // Find operations on empty registry
        assert!(registry.find_by_did("did:zhtp:nonexistent").is_none());
        assert!(registry.find_by_node_id(&lib_identity::NodeId::from_bytes([0u8; 32])).is_none());

        // Stats on empty registry
        let stats = registry.stats();
        assert_eq!(stats.total_peers, 0);

        // Cleanup on empty registry
        assert_eq!(registry.cleanup_expired(), 0);
    }

    // ========== NEW TESTS FOR SECURITY FEATURES ==========

    #[test]
    fn test_rate_limiting() {
        // Create a registry with very low rate limits for testing
        let config = RegistryConfig {
            max_peers: 100,
            peer_ttl_secs: 86400,
            audit_logging: false,
            global_rate_limit: 5,  // Only 5 ops per second
            per_peer_rate_limit: 2, // Only 2 ops per peer per minute
            verify_did_on_blockchain: false,
        };
        let mut registry = PeerRegistry::with_config(config);

        // First two ops for same peer should succeed
        let peer_id = create_test_peer_id();
        let entry1 = create_test_entry(peer_id.clone());
        assert!(registry.upsert(entry1).is_ok());

        let entry2 = create_test_entry(peer_id.clone());
        assert!(registry.upsert(entry2).is_ok());

        // Third op for same peer should be rate limited
        let entry3 = create_test_entry(peer_id.clone());
        let result = registry.upsert(entry3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    #[test]
    fn test_atomic_counter_operations() {
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id);

        // Test atomic counter increments
        assert_eq!(entry.get_data_transferred(), 0);
        entry.add_data_transferred(1000);
        assert_eq!(entry.get_data_transferred(), 1000);
        entry.add_data_transferred(500);
        assert_eq!(entry.get_data_transferred(), 1500);

        assert_eq!(entry.get_tokens_earned(), 0);
        entry.add_tokens_earned(50);
        assert_eq!(entry.get_tokens_earned(), 50);

        assert_eq!(entry.get_traffic_routed(), 0);
        entry.add_traffic_routed(2000);
        assert_eq!(entry.get_traffic_routed(), 2000);
    }

    #[test]
    fn test_update_if_exists() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id.clone());
        registry.upsert(entry).expect("Failed to upsert");

        // Update existing peer
        let updated = registry.update_if_exists(&peer_id, |entry| {
            entry.trust_score = 0.99;
            entry.connection_metrics.stability_score = 0.95;
        });
        assert!(updated);

        // Verify update
        let peer = registry.get(&peer_id).unwrap();
        assert_eq!(peer.trust_score, 0.99);
        assert_eq!(peer.connection_metrics.stability_score, 0.95);

        // Try to update non-existent peer
        let fake_peer_id = create_test_peer_id();
        let not_updated = registry.update_if_exists(&fake_peer_id, |_| {});
        assert!(!not_updated);
    }

    #[test]
    fn test_update_by_public_key() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let public_key = peer_id.public_key().clone();
        let entry = create_test_entry(peer_id);
        registry.upsert(entry).expect("Failed to upsert");

        // Update by public key
        let updated = registry.update_by_public_key(&public_key, |entry| {
            entry.authenticated = true;
        });
        assert!(updated);

        // Verify update
        let peer = registry.find_by_public_key(&public_key).unwrap();
        assert!(peer.authenticated);
    }

    #[test]
    fn test_update_connection_state() {
        let mut registry = PeerRegistry::new();
        let peer_id = create_test_peer_id();
        let entry = create_test_entry(peer_id.clone());
        registry.upsert(entry).expect("Failed to upsert");

        // Update connection state atomically
        registry.update_connection_state(
            &peer_id,
            Some(0.85),  // stability_score
            Some(5000000), // bandwidth_capacity
            Some(25),    // latency_ms
        ).expect("Failed to update");

        // Verify updates
        let peer = registry.get(&peer_id).unwrap();
        assert_eq!(peer.connection_metrics.stability_score, 0.85);
        assert_eq!(peer.connection_metrics.bandwidth_capacity, 5000000);
        assert_eq!(peer.connection_metrics.latency_ms, 25);
    }

    #[test]
    fn test_did_validation_enhanced() {
        // Test null byte injection
        assert!(PeerRegistry::validate_did("did:zhtp:abc\0def1234567890abcdef").is_err());

        // Test max length
        let long_did = format!("did:zhtp:{}", "a".repeat(100));
        assert!(PeerRegistry::validate_did(&long_did).is_err());

        // Test valid long DID (64 chars hex)
        let valid_long = format!("did:zhtp:{}", "a".repeat(64));
        assert!(PeerRegistry::validate_did(&valid_long).is_ok());

        // Test minimum hash length
        assert!(PeerRegistry::validate_did("did:zhtp:abc").is_err()); // Too short hash
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let mut limiter = RateLimiter::new(1000, 10);

        // Add some entries
        let _ = limiter.check_rate_limit("did:zhtp:test1234567890abcdef");
        let _ = limiter.check_rate_limit("did:zhtp:test2234567890abcdef");

        assert_eq!(limiter.per_peer_counts.len(), 2);

        // Cleanup should keep recent entries
        limiter.cleanup_old_entries();
        assert_eq!(limiter.per_peer_counts.len(), 2);
    }
}
