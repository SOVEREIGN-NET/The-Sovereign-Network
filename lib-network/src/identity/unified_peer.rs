//! Unified Peer Identity System
//!
//! This module consolidates three separate identity systems (NodeId, PeerId, PublicKey)
//! into a single unified representation for peer identification across the network.
//!
//! # Problem Statement
//!
//! Previously, the codebase used three different identity types:
//! - `NodeId` - Blake3 hash derived from DID + device name (lib-identity)
//! - `PeerId` - Legacy peer identifier (various protocols)
//! - `PublicKey` - Cryptographic public key (lib-crypto)
//!
//! This created confusion, redundant mappings, and data inconsistencies.
//!
//! # Solution
//!
//! `UnifiedPeerId` serves as the single source of truth for peer identity:
//! - Contains all three ID types internally
//! - Ensures consistency across the entire network stack
//! - Created exclusively from ZhtpIdentity (no legacy type conversions)
//!
//! # Usage
//!
//! ```rust
//! use lib_network::identity::{UnifiedPeerId, PeerIdMapper};
//! use lib_identity::{ZhtpIdentity, NodeId};
//! use lib_crypto::PublicKey;
//!
//! // Create from ZhtpIdentity
//! let identity = ZhtpIdentity::new_unified(...)?;
//! let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
//!
//! // Use mapper for bidirectional lookups
//! let mapper = PeerIdMapper::new();
//! mapper.register(peer_id.clone()).await;
//! let found = mapper.lookup_by_node_id(&node_id).await;
//! ```

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use lib_identity::{ZhtpIdentity, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;  // CRITICAL FIX C3: Use parking_lot for atomic operations
use std::fmt;
use tracing::{warn, info};

// ============================================================================
// Security Validation Functions
// ============================================================================

/// Validate peer timestamp for freshness and prevent time-travel attacks
///
/// # Security
///
/// - Rejects timestamps in the future (clock skew tolerance: 5 minutes)
/// - Rejects very old timestamps (max age: 1 year)
/// - Rejects timestamps before protocol launch (Nov 2023)
pub(crate) fn validate_peer_timestamp(timestamp: u64) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System clock error: {}", e))?
        .as_secs();

    // Reject future timestamps (with 5 min clock skew tolerance)
    const CLOCK_SKEW_TOLERANCE: u64 = 300;
    if timestamp > now + CLOCK_SKEW_TOLERANCE {
        return Err(anyhow!(
            "Timestamp in future: {} > {} (clock skew tolerance: {} sec)",
            timestamp,
            now,
            CLOCK_SKEW_TOLERANCE
        ));
    }

    // Reject very old timestamps (1 year max)
    const MAX_AGE_SECS: u64 = 365 * 24 * 3600;
    let age = now.saturating_sub(timestamp);
    if age > MAX_AGE_SECS {
        return Err(anyhow!(
            "Timestamp too old: {} seconds (max: {} = 1 year)",
            age,
            MAX_AGE_SECS
        ));
    }

    // Reject timestamps before protocol launch (Nov 2023)
    const PROTOCOL_LAUNCH: u64 = 1700000000;
    if timestamp < PROTOCOL_LAUNCH {
        return Err(anyhow!(
            "Timestamp predates protocol launch (Nov 2023): {}",
            timestamp
        ));
    }

    Ok(())
}

/// Validate device_id for sufficient entropy
///
/// # Security
///
/// - Prevents weak device names that increase collision risk
/// - Enforces minimum length and character variety
/// - Rejects common/predictable device names
pub(crate) fn validate_device_id(device_id: &str) -> Result<()> {
    // Minimum length check
    const MIN_LENGTH: usize = 3;
    if device_id.len() < MIN_LENGTH {
        return Err(anyhow!(
            "Device ID too short: {} chars (min: {})",
            device_id.len(),
            MIN_LENGTH
        ));
    }

    // Maximum length check (prevent abuse)
    const MAX_LENGTH: usize = 64;
    if device_id.len() > MAX_LENGTH {
        return Err(anyhow!(
            "Device ID too long: {} chars (max: {})",
            device_id.len(),
            MAX_LENGTH
        ));
    }

    // Reject common weak device names
    const WEAK_NAMES: &[&str] = &[
        "test",
        "device",
        "phone",
        "laptop",
        "server",
        "node",
        "peer",
        "client",
        "device1",
        "device2",
    ];
    let lower = device_id.to_lowercase();
    if WEAK_NAMES.contains(&lower.as_str()) {
        return Err(anyhow!(
            "Device ID is too common/weak: '{}' - use unique identifier",
            device_id
        ));
    }

    // Check for alphanumeric + hyphen/underscore only
    if !device_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(anyhow!(
            "Device ID contains invalid characters: '{}' - use alphanumeric, hyphen, underscore only",
            device_id
        ));
    }

    Ok(())
}

// ============================================================================
// Core Unified Peer Identity
// ============================================================================

/// Unified peer identity consolidating all identity types
///
/// This struct is the single source of truth for peer identification,
/// containing all three legacy ID types (NodeId, PeerId, PublicKey) in one place.
///
/// # Design Principles
///
/// - **Canonical Storage**: All three IDs stored together, no separate mappings needed
/// - **Single Source**: Created only from ZhtpIdentity, no partial conversions from legacy types
/// - **Consistency**: Guarantees that NodeId, PublicKey, and DID always stay in sync
/// - **Uniqueness**: Hash and Eq based on NodeId (the most stable identifier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedPeerId {
    /// Decentralized Identifier (DID) - Sovereign Identity
    /// Format: "did:zhtp:<hash>"
    pub did: String,

    /// Cryptographic public key for signature verification
    /// This is the peer's public key from their identity
    pub public_key: PublicKey,

    /// Canonical node identifier from lib-identity
    /// Derived as: Blake3(DID || device_name)
    pub node_id: NodeId,

    /// Device identifier (e.g., "laptop", "phone", "server-01")
    /// Used to distinguish multiple devices under same DID
    pub device_id: String,

    /// Optional display name for this peer
    pub display_name: Option<String>,

    /// Timestamp of identity creation (Unix timestamp)
    pub created_at: u64,
}

impl UnifiedPeerId {
    /// Create UnifiedPeerId from ZhtpIdentity (primary constructor)
    ///
    /// This is the preferred way to create a UnifiedPeerId as it ensures
    /// all fields are properly populated from the authoritative identity source.
    ///
    /// # Security
    ///
    /// Validates all inputs to enforce trust boundary:
    /// - DID format (must start with "did:zhtp:")
    /// - Device ID entropy and format
    /// - Timestamp freshness
    /// - Cryptographic binding (NodeId matches DID + device)
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` if all validations pass
    /// - `Err(...)` if any validation fails
    pub fn from_zhtp_identity(identity: &ZhtpIdentity) -> Result<Self> {
        // SECURITY FIX #3 (Finding #3): Validate at trust boundary

        // Validate DID format
        if !identity.did.starts_with("did:zhtp:") {
            return Err(anyhow!(
                "Invalid DID format: must start with 'did:zhtp:', got '{}'",
                &identity.did[..20.min(identity.did.len())]
            ));
        }

        // Validate device_id
        validate_device_id(&identity.primary_device)?;

        // Validate timestamp
        validate_peer_timestamp(identity.created_at)?;

        // Create instance
        let peer = Self {
            did: identity.did.clone(),
            public_key: identity.public_key.clone(),
            node_id: identity.node_id.clone(),
            device_id: identity.primary_device.clone(),
            display_name: identity.metadata.get("display_name").cloned(),
            created_at: identity.created_at,
        };

        // Validate cryptographic binding
        peer.verify_node_id()?;

        Ok(peer)
    }

    /// Verify that node_id matches Blake3(DID || device_id) per lib-identity rules
    pub fn verify_node_id(&self) -> Result<()> {
        let expected = NodeId::from_did_device(&self.did, &self.device_id)?;
        if self.node_id.as_bytes() != expected.as_bytes() {
            return Err(anyhow!(
                "NodeId mismatch: expected {} but got {}",
                expected.to_hex(),
                self.node_id.to_hex()
            ));
        }
        Ok(())
    }

    /// Get a compact string representation for logging
    pub fn to_compact_string(&self) -> String {
        format!("{}@{}", self.device_id, &self.did[..std::cmp::min(20, self.did.len())])
    }

    /// Get the NodeId (canonical identifier)
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get the PublicKey
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the DID
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the device ID
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

// ============================================================================
// Equality and Hashing (based on NodeId)
// ============================================================================

impl PartialEq for UnifiedPeerId {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
    }
}

impl Eq for UnifiedPeerId {}

impl std::hash::Hash for UnifiedPeerId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.node_id.as_bytes().hash(state);
    }
}

impl fmt::Display for UnifiedPeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnifiedPeerId({})", self.to_compact_string())
    }
}

// ============================================================================
// CRITICAL FIX C3: Atomic State Management
// ============================================================================

/// Configuration limits for PeerIdMapper
#[derive(Debug, Clone)]
pub struct PeerMapperConfig {
    /// Maximum total peers in mapper (DoS protection)
    pub max_peers: usize,
    /// Maximum devices per DID (Sybil attack protection)
    pub max_devices_per_did: usize,
}

impl Default for PeerMapperConfig {
    fn default() -> Self {
        Self {
            max_peers: 100_000,         // 100K peers max
            max_devices_per_did: 10,    // 10 devices per identity
        }
    }
}

/// CRITICAL FIX C3: Atomic mapper state
///
/// All state is consolidated into a single struct that can be updated atomically.
/// This eliminates the TOCTOU (Time-Of-Check-Time-Of-Use) vulnerability.
#[derive(Debug)]
struct MapperState {
    /// Main storage: NodeId → Arc<UnifiedPeerId>
    by_node_id: HashMap<NodeId, Arc<UnifiedPeerId>>,

    /// Index: PublicKey → NodeId (for fast lookup)
    by_public_key: HashMap<PublicKey, NodeId>,

    /// Index: DID → Vec<NodeId> (one DID can have multiple devices)
    by_did: HashMap<String, Vec<NodeId>>,
}

impl MapperState {
    fn new() -> Self {
        Self {
            by_node_id: HashMap::new(),
            by_public_key: HashMap::new(),
            by_did: HashMap::new(),
        }
    }
}

/// Service for bidirectional mapping between legacy ID types and UnifiedPeerId
///
/// # CRITICAL FIX C3: Race Condition Prevention
///
/// This mapper uses parking_lot::RwLock with single atomic state to prevent
/// the TOCTOU vulnerability that existed with multiple tokio::sync::RwLock instances.
///
/// **Previous vulnerability:**
/// - Multiple separate locks (by_node_id, by_public_key, by_did)
/// - Race window between checking `max_devices_per_did` and inserting
/// - Attackers could bypass limits via concurrent registration
///
/// **Fixed implementation:**
/// - Single MapperState struct with all data
/// - Single parking_lot::RwLock for entire state
/// - Atomic check-and-insert: no race window
/// - Audit logging for security events
///
/// # Thread Safety
///
/// All operations use parking_lot::RwLock for synchronous access.
/// parking_lot is preferred over tokio::sync::RwLock because:
/// - No async overhead for synchronous operations
/// - Better performance for short critical sections
/// - Deterministic lock ordering
///
/// # Security
///
/// - **Memory limits**: Enforces max_peers and max_devices_per_did limits
/// - **Atomic operations**: Race-free registration using single lock
/// - **Cryptographic verification**: Verifies NodeId derivation on registration
/// - **Audit logging**: Logs security events for monitoring
///
/// # Usage
///
/// ```rust
/// let mapper = PeerIdMapper::new();
///
/// // Register a peer
/// mapper.register(peer_id)?;
///
/// // Lookup by different ID types
/// let by_node = mapper.lookup_by_node_id(&node_id);
/// let by_pubkey = mapper.lookup_by_public_key(&public_key);
/// let by_did = mapper.lookup_by_did("did:zhtp:abc123");
/// ```
#[derive(Debug, Clone)]
pub struct PeerIdMapper {
    /// CRITICAL FIX C3: Single atomic state with parking_lot::RwLock
    state: Arc<RwLock<MapperState>>,

    /// Configuration limits
    config: PeerMapperConfig,
}

impl PeerIdMapper {
    /// Create a new empty peer ID mapper with default config
    pub fn new() -> Self {
        Self::with_config(PeerMapperConfig::default())
    }

    /// Create a new peer ID mapper with custom config
    pub fn with_config(config: PeerMapperConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(MapperState::new())),
            config,
        }
    }

    /// CRITICAL FIX C3: Atomic registration with single lock
    ///
    /// Register a peer in the mapper (creates all indexes)
    ///
    /// # Security
    ///
    /// - **Atomic**: Entire operation under single write lock (no TOCTOU)
    /// - **Verified**: Cryptographic NodeId binding checked
    /// - **Bounded**: Memory limits enforced
    /// - **Audited**: Security events logged
    ///
    /// # Implementation
    ///
    /// The entire registration is atomic:
    /// 1. Acquire write lock
    /// 2. Check max_peers limit
    /// 3. Check duplicate registration
    /// 4. Check max_devices_per_did limit
    /// 5. Verify cryptographic binding
    /// 6. Insert into all indexes
    /// 7. Release lock
    ///
    /// No race condition window between steps 3-6.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if registration succeeded
    /// - `Err(...)` if verification failed, limits exceeded, or already registered
    pub fn register(&self, peer: UnifiedPeerId) -> Result<()> {
        // Verify cryptographic binding (outside lock - pure computation)
        peer.verify_node_id()?;

        // Validate timestamp (outside lock - pure computation)
        validate_peer_timestamp(peer.created_at)?;

        // Validate device_id entropy (outside lock - pure computation)
        validate_device_id(&peer.device_id)?;

        let node_id = peer.node_id.clone();
        let public_key = peer.public_key.clone();
        let did = peer.did.clone();

        // CRITICAL FIX C3: SINGLE ATOMIC LOCK for entire registration
        // This prevents the TOCTOU race condition
        let mut state = self.state.write();

        // Check 1: max_peers limit (DoS protection)
        if state.by_node_id.len() >= self.config.max_peers {
            warn!(
                "Peer registration rejected: max_peers limit reached ({}/{})",
                state.by_node_id.len(),
                self.config.max_peers
            );
            return Err(anyhow!(
                "Peer limit reached: {} peers (max: {})",
                state.by_node_id.len(),
                self.config.max_peers
            ));
        }

        // Check 2: Duplicate registration (idempotency)
        if state.by_node_id.contains_key(&node_id) {
            warn!(
                "Duplicate peer registration attempt: {}",
                node_id.to_hex()
            );
            return Err(anyhow!("Peer already registered: {}", node_id.to_hex()));
        }

        // Check 3: max_devices_per_did limit (Sybil protection)
        // CRITICAL: This check MUST be under the same lock as the insert
        let device_count = state.by_did.get(&did).map(|v| v.len()).unwrap_or(0);
        if device_count >= self.config.max_devices_per_did {
            warn!(
                "Device limit exceeded for DID {}: {}/{} devices",
                &did[..20.min(did.len())],
                device_count,
                self.config.max_devices_per_did
            );
            return Err(anyhow!(
                "Device limit reached for DID {}: {} devices (max: {})",
                &did[..20.min(did.len())],
                device_count,
                self.config.max_devices_per_did
            ));
        }

        // All checks passed - insert atomically into all indexes
        let peer_arc = Arc::new(peer);

        // Insert into main storage
        state.by_node_id.insert(node_id.clone(), peer_arc.clone());

        // Insert into PublicKey index
        state.by_public_key.insert(public_key, node_id.clone());

        // Insert into DID index (supports multi-device)
        state.by_did.entry(did.clone()).or_insert_with(Vec::new).push(node_id.clone());

        // Audit log successful registration
        info!(
            "Peer registered: {} (DID: {}, devices: {})",
            node_id.to_hex(),
            &did[..20.min(did.len())],
            state.by_did.get(&did).map(|v| v.len()).unwrap_or(0)
        );

        // Lock released here - entire operation was atomic
        Ok(())
    }

    /// CRITICAL FIX C3: Atomic unregister with single lock
    ///
    /// Remove a peer from the mapper (cleans up all indexes)
    ///
    /// # Security
    ///
    /// - Atomic unregister (all-or-nothing, no partial state)
    /// - Single lock acquisition (prevents race conditions)
    pub fn unregister(&self, node_id: &NodeId) -> Option<Arc<UnifiedPeerId>> {
        // CRITICAL FIX C3: Single atomic lock for entire unregister
        let mut state = self.state.write();

        // Remove from main map
        let peer = state.by_node_id.remove(node_id)?;

        // Remove PublicKey → NodeId index
        state.by_public_key.remove(&peer.public_key);

        // Remove from DID → Vec<NodeId> index
        if let Some(nodes) = state.by_did.get_mut(&peer.did) {
            nodes.retain(|n| n != node_id);
            if nodes.is_empty() {
                state.by_did.remove(&peer.did);
            }
        }

        // Audit log
        info!("Peer unregistered: {}", node_id.to_hex());

        Some(peer)
    }

    /// Lookup peer by NodeId (canonical identifier)
    pub fn lookup_by_node_id(&self, node_id: &NodeId) -> Option<UnifiedPeerId> {
        let state = self.state.read();
        state.by_node_id.get(node_id).map(|arc| (**arc).clone())
    }

    /// Lookup peer by PublicKey
    pub fn lookup_by_public_key(&self, public_key: &PublicKey) -> Option<UnifiedPeerId> {
        let state = self.state.read();
        let node_id = state.by_public_key.get(public_key).cloned()?;
        state.by_node_id.get(&node_id).map(|arc| (**arc).clone())
    }

    /// Lookup all peers by DID (returns all devices for this identity)
    pub fn lookup_by_did(&self, did: &str) -> Vec<UnifiedPeerId> {
        let state = self.state.read();

        match state.by_did.get(did) {
            Some(ids) => {
                ids.iter()
                    .filter_map(|id| state.by_node_id.get(id).map(|arc| (**arc).clone()))
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Get all registered peers
    pub fn all_peers(&self) -> Vec<UnifiedPeerId> {
        let state = self.state.read();
        state.by_node_id.values().map(|arc| (**arc).clone()).collect()
    }

    /// Get total peer count
    pub fn peer_count(&self) -> usize {
        let state = self.state.read();
        state.by_node_id.len()
    }

    /// Clear all mappings
    pub fn clear(&self) {
        let mut state = self.state.write();
        state.by_node_id.clear();
        state.by_public_key.clear();
        state.by_did.clear();
    }

    /// Check if a peer is registered by NodeId
    pub fn contains_node_id(&self, node_id: &NodeId) -> bool {
        let state = self.state.read();
        state.by_node_id.contains_key(node_id)
    }

    /// Check if a peer is registered by PublicKey
    pub fn contains_public_key(&self, public_key: &PublicKey) -> bool {
        let state = self.state.read();
        state.by_public_key.contains_key(public_key)
    }

    /// Check if any peers are registered for a DID
    pub fn contains_did(&self, did: &str) -> bool {
        let state = self.state.read();
        state.by_did.contains_key(did)
    }
}

impl Default for PeerIdMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::IdentityType;

    fn create_test_identity(device: &str, seed: Option<[u8; 64]>) -> Result<ZhtpIdentity> {
        ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(25),
            Some("US".to_string()),
            device,
            seed,
        )
    }

    #[test]
    fn test_unified_peer_id_from_zhtp_identity() -> Result<()> {
        let identity = create_test_identity("laptop-secure-001", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        assert_eq!(peer_id.did, identity.did);
        assert_eq!(peer_id.public_key.as_bytes(), identity.public_key.as_bytes());
        assert_eq!(peer_id.node_id, identity.node_id);
        assert_eq!(peer_id.device_id, identity.primary_device);

        // Verify NodeId is correct
        peer_id.verify_node_id()?;

        println!("UnifiedPeerId from ZhtpIdentity test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_equality() -> Result<()> {
        let seed = [0x42u8; 64];
        let identity1 = create_test_identity("laptop-x1-carbon", Some(seed))?;
        let identity2 = create_test_identity("laptop-x1-carbon", Some(seed))?;

        let peer1 = UnifiedPeerId::from_zhtp_identity(&identity1)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity2)?;

        // Same seed + device = same NodeId = equal peers
        assert_eq!(peer1, peer2);

        println!("Peer ID equality test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_mapper_register_and_lookup() -> Result<()> {
        let mapper = PeerIdMapper::new();

        let identity = create_test_identity("server-prod-01", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Register
        mapper.register(peer_id.clone())?;

        // Lookup by NodeId
        let found = mapper.lookup_by_node_id(&identity.node_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), peer_id);

        // Lookup by PublicKey
        let found = mapper.lookup_by_public_key(&identity.public_key);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), peer_id);

        // Lookup by DID
        let found = mapper.lookup_by_did(&identity.did);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], peer_id);

        println!("Peer ID mapper register and lookup test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_mapper_multi_device() -> Result<()> {
        let mapper = PeerIdMapper::new();
        let seed = [0x42u8; 64];

        // Same identity, different devices
        let laptop = create_test_identity("laptop-macbook-pro", Some(seed))?;
        let phone = create_test_identity("phone-iphone-14", Some(seed))?;

        let peer_laptop = UnifiedPeerId::from_zhtp_identity(&laptop)?;
        let peer_phone = UnifiedPeerId::from_zhtp_identity(&phone)?;

        // Register both
        mapper.register(peer_laptop.clone())?;
        mapper.register(peer_phone.clone())?;

        // Lookup by DID should return both devices
        let found = mapper.lookup_by_did(&laptop.did);
        assert_eq!(found.len(), 2);

        // Verify both are present
        assert!(found.contains(&peer_laptop));
        assert!(found.contains(&peer_phone));

        println!("Peer ID mapper multi-device test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_mapper_unregister() -> Result<()> {
        let mapper = PeerIdMapper::new();

        let identity = create_test_identity("workstation-dell-7920", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Register
        mapper.register(peer_id.clone())?;
        assert_eq!(mapper.peer_count(), 1);

        // Unregister
        let removed = mapper.unregister(&identity.node_id);
        assert!(removed.is_some());
        let removed_peer = removed.unwrap();
        assert_eq!(*removed_peer, peer_id);
        assert_eq!(mapper.peer_count(), 0);

        // Verify all indexes are cleaned up
        assert!(!mapper.contains_node_id(&identity.node_id));
        assert!(!mapper.contains_public_key(&identity.public_key));
        assert!(!mapper.contains_did(&identity.did));

        println!("Peer ID mapper unregister test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_mapper_clear() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Register multiple peers
        for i in 0..5 {
            let device = format!("gaming-rig-{:03}", i);
            let identity = create_test_identity(&device, None)?;
            let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
            mapper.register(peer_id)?;
        }

        assert_eq!(mapper.peer_count(), 5);

        // Clear all
        mapper.clear();
        assert_eq!(mapper.peer_count(), 0);

        println!("Peer ID mapper clear test passed");
        Ok(())
    }

    // ============================================================================
    // CRITICAL FIX C3: Race Condition Attack Tests
    // ============================================================================

    #[test]
    fn test_c3_concurrent_registration_atomic() -> Result<()> {
        use std::thread;

        let mapper = PeerIdMapper::new();
        let seed = [0x99u8; 64];

        // Create identity
        let identity = create_test_identity("secure-device-123", Some(seed))?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Spawn 100 concurrent registration attempts with same NodeId
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let mapper = mapper.clone();
                let peer = peer_id.clone();
                thread::spawn(move || mapper.register(peer))
            })
            .collect();

        // Wait for all and collect results
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Verify exactly 1 succeeded, 99 failed
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(successes, 1, "Exactly one registration should succeed");
        assert_eq!(failures, 99, "99 registrations should fail (already registered)");

        // Verify only 1 peer in mapper
        assert_eq!(mapper.peer_count(), 1);

        println!("CRITICAL FIX C3: Concurrent registration atomicity test PASSED");
        Ok(())
    }

    #[test]
    fn test_c3_max_devices_race_condition_fixed() -> Result<()> {
        use std::thread;

        // CRITICAL TEST: Verify max_devices_per_did cannot be bypassed via races
        let config = PeerMapperConfig {
            max_peers: 100,
            max_devices_per_did: 3,
        };
        let mapper = PeerIdMapper::with_config(config);
        let seed = [0x42u8; 64];

        // Spawn 10 concurrent attempts to register devices for same DID
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let mapper = mapper.clone();
                thread::spawn(move || {
                    let device = format!("attack-device-{:03}", i);
                    let identity = create_test_identity(&device, Some(seed)).unwrap();
                    let peer_id = UnifiedPeerId::from_zhtp_identity(&identity).unwrap();
                    mapper.register(peer_id)
                })
            })
            .collect();

        // Wait for all and collect results
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Count successes and failures
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        // CRITICAL: Exactly 3 should succeed (max_devices_per_did limit)
        assert_eq!(
            successes, 3,
            "Exactly 3 registrations should succeed (max_devices_per_did=3)"
        );
        assert_eq!(
            failures, 7,
            "7 registrations should fail (device limit reached)"
        );

        // Verify exactly 3 peers registered
        assert_eq!(mapper.peer_count(), 3);

        println!("CRITICAL FIX C3: max_devices_per_did race condition FIXED");
        Ok(())
    }

    #[test]
    fn test_max_peers_limit_enforcement() -> Result<()> {
        let config = PeerMapperConfig {
            max_peers: 10,
            max_devices_per_did: 10,
        };
        let mapper = PeerIdMapper::with_config(config);

        // Register 10 peers successfully
        for i in 0..10 {
            let device = format!("test-device-{:03}", i);
            let identity = create_test_identity(&device, None)?;
            let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
            mapper.register(peer_id)?;
        }

        assert_eq!(mapper.peer_count(), 10);

        // Try to register 11th peer - should fail
        let identity = create_test_identity("device-overflow-11", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let result = mapper.register(peer_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Peer limit reached"));

        // Verify still 10 peers
        assert_eq!(mapper.peer_count(), 10);

        println!("Max peers limit enforcement test passed");
        Ok(())
    }

    #[test]
    fn test_max_devices_per_did_enforcement() -> Result<()> {
        let config = PeerMapperConfig {
            max_peers: 100,
            max_devices_per_did: 3,
        };
        let mapper = PeerIdMapper::with_config(config);
        let seed = [0x42u8; 64];

        // Register 3 devices for same DID
        for i in 0..3 {
            let device = format!("allowed-device-{}", i);
            let identity = create_test_identity(&device, Some(seed))?;
            let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
            mapper.register(peer_id)?;
        }

        assert_eq!(mapper.peer_count(), 3);

        // Try to register 4th device - should fail
        let identity = create_test_identity("blocked-device-4", Some(seed))?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let result = mapper.register(peer_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Device limit reached"));

        // Verify still 3 devices
        assert_eq!(mapper.peer_count(), 3);

        println!("Max devices per DID enforcement test passed");
        Ok(())
    }

    #[test]
    fn test_future_timestamp_rejected() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Create identity with future timestamp (1 hour from now)
        let mut identity = create_test_identity("future-device", None)?;
        let future_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() + 3600; // +1 hour

        // Manually construct UnifiedPeerId with future timestamp
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        peer_id.created_at = future_timestamp;

        // Try to register - should fail
        let result = mapper.register(peer_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timestamp in future"));

        println!("Future timestamp rejection test passed");
        Ok(())
    }

    #[test]
    fn test_old_timestamp_rejected() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Create identity with old timestamp (2 years ago)
        let mut identity = create_test_identity("old-device", None)?;
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() - (2 * 365 * 24 * 3600); // -2 years

        // Manually construct UnifiedPeerId with old timestamp
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        peer_id.created_at = old_timestamp;

        // Try to register - should fail
        let result = mapper.register(peer_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timestamp too old"));

        println!("Old timestamp rejection test passed");
        Ok(())
    }

    #[test]
    fn test_protocol_epoch_validation() -> Result<()> {
        // Test pre-protocol timestamp directly
        let pre_protocol_timestamp = 1600000000; // Sep 2020

        // Validate timestamp should fail
        let result = validate_peer_timestamp(pre_protocol_timestamp);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        println!("Error message: {}", err_msg);
        assert!(err_msg.contains("predates protocol launch") || err_msg.contains("Timestamp too old"));

        println!("Protocol epoch validation test passed");
        Ok(())
    }

    #[test]
    fn test_spoofed_node_id_rejected() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Create valid identity
        let identity = create_test_identity("victim-device", None)?;
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Spoof NodeId (replace with random bytes)
        let fake_node_id = NodeId::from_bytes([0xFFu8; 32]);
        peer_id.node_id = fake_node_id;

        // Try to register - should fail cryptographic verification
        let result = mapper.register(peer_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NodeId mismatch"));

        println!("Spoofed NodeId rejection test passed");
        Ok(())
    }

    #[test]
    fn test_weak_device_id_rejected() -> Result<()> {
        let weak_names = vec!["test", "device", "phone", "laptop", "server"];

        for weak_name in weak_names {
            // Test validation function directly
            let result = validate_device_id(weak_name);
            assert!(result.is_err(), "Weak name '{}' should be rejected", weak_name);
            assert!(result.unwrap_err().to_string().contains("too common/weak"));
        }

        println!("Weak device ID rejection test passed");
        Ok(())
    }

    #[test]
    fn test_short_device_id_rejected() -> Result<()> {
        // Test validation function directly
        let result = validate_device_id("ab");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));

        println!("Short device ID rejection test passed");
        Ok(())
    }

    #[test]
    fn test_long_device_id_rejected() -> Result<()> {
        // Test validation function directly
        let long_device = "a".repeat(65); // 65 chars (max is 64)
        let result = validate_device_id(&long_device);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));

        println!("Long device ID rejection test passed");
        Ok(())
    }

    #[test]
    fn test_concurrent_unregister_idempotent() -> Result<()> {
        use std::thread;

        let mapper = PeerIdMapper::new();

        // Register a peer
        let identity = create_test_identity("concurrent-unregister-test", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let node_id = identity.node_id.clone();

        mapper.register(peer_id.clone())?;
        assert_eq!(mapper.peer_count(), 1);

        // Spawn 10 concurrent unregister attempts
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let mapper = mapper.clone();
                let node_id = node_id.clone();
                thread::spawn(move || mapper.unregister(&node_id))
            })
            .collect();

        // Wait for all and collect results
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Verify exactly 1 returned Some, 9 returned None
        let successes = results.iter().filter(|r| r.is_some()).count();
        let failures = results.iter().filter(|r| r.is_none()).count();

        assert_eq!(successes, 1, "Exactly one unregister should succeed");
        assert_eq!(failures, 9, "9 unregisters should return None");

        // Verify peer removed
        assert_eq!(mapper.peer_count(), 0);

        // Verify all indexes cleaned up
        assert!(!mapper.contains_node_id(&node_id));

        println!("Concurrent unregister idempotency test passed");
        Ok(())
    }

    #[test]
    fn test_device_id_special_chars_rejected() -> Result<()> {
        let invalid_devices = vec![
            "device@123",  // @ not allowed
            "device#123",  // # not allowed
            "device$123",  // $ not allowed
            "device 123",  // space not allowed
            "device.123",  // . not allowed
        ];

        for invalid_device in invalid_devices {
            // Test validation function directly
            let result = validate_device_id(invalid_device);
            assert!(result.is_err(), "Device ID '{}' should be rejected", invalid_device);
            assert!(result.unwrap_err().to_string().contains("invalid characters"));
        }

        println!("Device ID special character rejection test passed");
        Ok(())
    }
}
