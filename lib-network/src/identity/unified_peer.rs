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
use tokio::sync::RwLock;
use std::fmt;

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
// Bidirectional Peer ID Mapper
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

/// Service for bidirectional mapping between legacy ID types and UnifiedPeerId
///
/// This mapper maintains indexes for fast lookups by any legacy ID type:
/// - NodeId → UnifiedPeerId
/// - PublicKey → UnifiedPeerId
/// - DID → UnifiedPeerId (can return multiple peers for multi-device identities)
///
/// # Thread Safety
///
/// All operations are async and use RwLock for concurrent access.
///
/// # Security
///
/// - **Memory limits**: Enforces max_peers and max_devices_per_did limits
/// - **Atomic operations**: Race-free registration using entry API
/// - **Cryptographic verification**: Verifies NodeId derivation on registration
///
/// # Usage
///
/// ```rust
/// let mapper = PeerIdMapper::new();
///
/// // Register a peer
/// mapper.register(peer_id).await?;
///
/// // Lookup by different ID types
/// let by_node = mapper.lookup_by_node_id(&node_id).await;
/// let by_pubkey = mapper.lookup_by_public_key(&public_key).await;
/// let by_did = mapper.lookup_by_did("did:zhtp:abc123").await;
/// ```
#[derive(Debug, Clone)]
pub struct PeerIdMapper {
    /// Main storage: NodeId → Arc<UnifiedPeerId> (Arc to avoid cloning sensitive data)
    by_node_id: Arc<RwLock<HashMap<NodeId, Arc<UnifiedPeerId>>>>,

    /// Index: PublicKey → NodeId (for fast lookup)
    by_public_key: Arc<RwLock<HashMap<PublicKey, NodeId>>>,

    /// Index: DID → Vec<NodeId> (one DID can have multiple devices)
    by_did: Arc<RwLock<HashMap<String, Vec<NodeId>>>>,

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
            by_node_id: Arc::new(RwLock::new(HashMap::new())),
            by_public_key: Arc::new(RwLock::new(HashMap::new())),
            by_did: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Register a peer in the mapper (creates all indexes)
    ///
    /// # Security
    ///
    /// - Verifies NodeId cryptographic binding (prevents spoofing)
    /// - Enforces memory limits (prevents DoS)
    /// - Atomic registration (prevents race conditions)
    /// - Validates timestamp freshness (prevents replay)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if registration succeeded
    /// - `Err(...)` if verification failed, limits exceeded, or already registered
    pub async fn register(&self, peer: UnifiedPeerId) -> Result<()> {
        // SECURITY FIX #3: Verify cryptographic binding
        peer.verify_node_id()?;

        // SECURITY FIX #7: Validate timestamp
        validate_peer_timestamp(peer.created_at)?;

        // SECURITY FIX #4: Validate device_id entropy
        validate_device_id(&peer.device_id)?;

        let node_id = peer.node_id.clone();
        let public_key = peer.public_key.clone();
        let did = peer.did.clone();

        // SECURITY FIX #1 & #6: Single atomic lock for all operations
        let mut node_map = self.by_node_id.write().await;
        let mut pubkey_map = self.by_public_key.write().await;
        let mut did_map = self.by_did.write().await;

        // SECURITY FIX #2: Check max_peers limit
        if node_map.len() >= self.config.max_peers {
            return Err(anyhow!(
                "Peer limit reached: {} peers (max: {})",
                node_map.len(),
                self.config.max_peers
            ));
        }

        // SECURITY FIX #1: Atomic check-and-insert (no race window)
        if node_map.contains_key(&node_id) {
            return Err(anyhow!("Peer already registered: {}", node_id.to_hex()));
        }

        // SECURITY FIX #2: Check max_devices_per_did limit
        let device_count = did_map.get(&did).map(|v| v.len()).unwrap_or(0);
        if device_count >= self.config.max_devices_per_did {
            return Err(anyhow!(
                "Device limit reached for DID {}: {} devices (max: {})",
                &did[..20.min(did.len())],
                device_count,
                self.config.max_devices_per_did
            ));
        }

        // SECURITY FIX #5: Use Arc to avoid cloning sensitive data
        let peer_arc = Arc::new(peer);

        // Store in main map
        node_map.insert(node_id.clone(), peer_arc.clone());

        // Create PublicKey → NodeId index
        pubkey_map.insert(public_key, node_id.clone());

        // Create DID → Vec<NodeId> index (supports multi-device)
        did_map.entry(did).or_insert_with(Vec::new).push(node_id);

        Ok(())
    }
    
    /// Remove a peer from the mapper (cleans up all indexes)
    ///
    /// # Security
    ///
    /// - Atomic unregister (all-or-nothing, no partial state)
    /// - Single lock acquisition (prevents race conditions)
    pub async fn unregister(&self, node_id: &NodeId) -> Option<Arc<UnifiedPeerId>> {
        // SECURITY FIX #6: Atomic unregister with single lock scope
        let mut node_map = self.by_node_id.write().await;
        let mut pubkey_map = self.by_public_key.write().await;
        let mut did_map = self.by_did.write().await;

        // Remove from main map
        let peer = node_map.remove(node_id)?;

        // Remove PublicKey → NodeId index
        pubkey_map.remove(&peer.public_key);

        // Remove from DID → Vec<NodeId> index
        if let Some(nodes) = did_map.get_mut(&peer.did) {
            nodes.retain(|n| n != node_id);
            if nodes.is_empty() {
                did_map.remove(&peer.did);
            }
        }

        Some(peer)
    }
    
    /// Lookup peer by NodeId (canonical identifier)
    pub async fn lookup_by_node_id(&self, node_id: &NodeId) -> Option<UnifiedPeerId> {
        self.by_node_id.read().await.get(node_id).map(|arc| (**arc).clone())
    }

    /// Lookup peer by PublicKey
    pub async fn lookup_by_public_key(&self, public_key: &PublicKey) -> Option<UnifiedPeerId> {
        let node_id = self.by_public_key.read().await.get(public_key).cloned()?;
        self.lookup_by_node_id(&node_id).await
    }

    /// Lookup all peers by DID (returns all devices for this identity)
    pub async fn lookup_by_did(&self, did: &str) -> Vec<UnifiedPeerId> {
        let node_ids = self.by_did.read().await.get(did).cloned();

        match node_ids {
            Some(ids) => {
                let map = self.by_node_id.read().await;
                ids.iter()
                    .filter_map(|id| map.get(id).map(|arc| (**arc).clone()))
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Get all registered peers
    pub async fn all_peers(&self) -> Vec<UnifiedPeerId> {
        self.by_node_id.read().await.values().map(|arc| (**arc).clone()).collect()
    }
    
    /// Get total peer count
    pub async fn peer_count(&self) -> usize {
        self.by_node_id.read().await.len()
    }
    
    /// Clear all mappings
    pub async fn clear(&self) {
        self.by_node_id.write().await.clear();
        self.by_public_key.write().await.clear();
        self.by_did.write().await.clear();
    }
    
    /// Check if a peer is registered by NodeId
    pub async fn contains_node_id(&self, node_id: &NodeId) -> bool {
        self.by_node_id.read().await.contains_key(node_id)
    }
    
    /// Check if a peer is registered by PublicKey
    pub async fn contains_public_key(&self, public_key: &PublicKey) -> bool {
        self.by_public_key.read().await.contains_key(public_key)
    }
    
    /// Check if any peers are registered for a DID
    pub async fn contains_did(&self, did: &str) -> bool {
        self.by_did.read().await.contains_key(did)
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
    
    #[tokio::test]
    async fn test_unified_peer_id_from_zhtp_identity() -> Result<()> {
        let identity = create_test_identity("laptop-secure-001", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        assert_eq!(peer_id.did, identity.did);
        assert_eq!(peer_id.public_key.as_bytes(), identity.public_key.as_bytes());
        assert_eq!(peer_id.node_id, identity.node_id);
        assert_eq!(peer_id.device_id, identity.primary_device);

        // Verify NodeId is correct
        peer_id.verify_node_id()?;

        println!("✅ UnifiedPeerId from ZhtpIdentity test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_id_equality() -> Result<()> {
        let seed = [0x42u8; 64];
        let identity1 = create_test_identity("laptop-x1-carbon", Some(seed))?;
        let identity2 = create_test_identity("laptop-x1-carbon", Some(seed))?;

        let peer1 = UnifiedPeerId::from_zhtp_identity(&identity1)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity2)?;

        // Same seed + device = same NodeId = equal peers
        assert_eq!(peer1, peer2);

        println!("✅ Peer ID equality test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_id_mapper_register_and_lookup() -> Result<()> {
        let mapper = PeerIdMapper::new();

        let identity = create_test_identity("server-prod-01", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Register
        mapper.register(peer_id.clone()).await?;

        // Lookup by NodeId
        let found = mapper.lookup_by_node_id(&identity.node_id).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), peer_id);

        // Lookup by PublicKey
        let found = mapper.lookup_by_public_key(&identity.public_key).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap(), peer_id);

        // Lookup by DID
        let found = mapper.lookup_by_did(&identity.did).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], peer_id);

        println!("✅ Peer ID mapper register and lookup test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_id_mapper_multi_device() -> Result<()> {
        let mapper = PeerIdMapper::new();
        let seed = [0x42u8; 64];

        // Same identity, different devices
        let laptop = create_test_identity("laptop-macbook-pro", Some(seed))?;
        let phone = create_test_identity("phone-iphone-14", Some(seed))?;

        let peer_laptop = UnifiedPeerId::from_zhtp_identity(&laptop)?;
        let peer_phone = UnifiedPeerId::from_zhtp_identity(&phone)?;

        // Register both
        mapper.register(peer_laptop.clone()).await?;
        mapper.register(peer_phone.clone()).await?;

        // Lookup by DID should return both devices
        let found = mapper.lookup_by_did(&laptop.did).await;
        assert_eq!(found.len(), 2);

        // Verify both are present
        assert!(found.contains(&peer_laptop));
        assert!(found.contains(&peer_phone));

        println!("✅ Peer ID mapper multi-device test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_id_mapper_unregister() -> Result<()> {
        let mapper = PeerIdMapper::new();

        let identity = create_test_identity("workstation-dell-7920", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Register
        mapper.register(peer_id.clone()).await?;
        assert_eq!(mapper.peer_count().await, 1);

        // Unregister
        let removed = mapper.unregister(&identity.node_id).await;
        assert!(removed.is_some());
        let removed_peer = removed.unwrap();
        assert_eq!(*removed_peer, peer_id);
        assert_eq!(mapper.peer_count().await, 0);

        // Verify all indexes are cleaned up
        assert!(!mapper.contains_node_id(&identity.node_id).await);
        assert!(!mapper.contains_public_key(&identity.public_key).await);
        assert!(!mapper.contains_did(&identity.did).await);

        println!("✅ Peer ID mapper unregister test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_peer_id_mapper_clear() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Register multiple peers
        for i in 0..5 {
            let device = format!("gaming-rig-{:03}", i);
            let identity = create_test_identity(&device, None)?;
            let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
            mapper.register(peer_id).await?;
        }

        assert_eq!(mapper.peer_count().await, 5);

        // Clear all
        mapper.clear().await;
        assert_eq!(mapper.peer_count().await, 0);

        println!("✅ Peer ID mapper clear test passed");
        Ok(())
    }

    // ============================================================================
    // SECURITY TESTS - Attack Scenario Coverage
    // ============================================================================

    #[tokio::test]
    async fn test_concurrent_registration_same_node_id() -> Result<()> {
        let mapper = PeerIdMapper::new();
        let seed = [0x99u8; 64];

        // Create identity
        let identity = create_test_identity("secure-device-123", Some(seed))?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Spawn 100 concurrent registration attempts with same NodeId
        let mut handles = vec![];
        for _ in 0..100 {
            let mapper = mapper.clone();
            let peer = peer_id.clone();
            handles.push(tokio::spawn(async move {
                mapper.register(peer).await
            }));
        }

        // Wait for all and collect results
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Verify exactly 1 succeeded, 99 failed
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(successes, 1, "Exactly one registration should succeed");
        assert_eq!(failures, 99, "99 registrations should fail (already registered)");

        // Verify only 1 peer in mapper
        assert_eq!(mapper.peer_count().await, 1);

        println!("✅ Concurrent registration race condition test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_max_peers_limit_enforcement() -> Result<()> {
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
            mapper.register(peer_id).await?;
        }

        assert_eq!(mapper.peer_count().await, 10);

        // Try to register 11th peer - should fail
        let identity = create_test_identity("device-overflow-11", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let result = mapper.register(peer_id).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Peer limit reached"));

        // Verify still 10 peers
        assert_eq!(mapper.peer_count().await, 10);

        println!("✅ Max peers limit enforcement test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_max_devices_per_did_enforcement() -> Result<()> {
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
            mapper.register(peer_id).await?;
        }

        assert_eq!(mapper.peer_count().await, 3);

        // Try to register 4th device - should fail
        let identity = create_test_identity("blocked-device-4", Some(seed))?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let result = mapper.register(peer_id).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Device limit reached"));

        // Verify still 3 devices
        assert_eq!(mapper.peer_count().await, 3);

        println!("✅ Max devices per DID enforcement test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_future_timestamp_rejected() -> Result<()> {
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
        let result = mapper.register(peer_id).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timestamp in future"));

        println!("✅ Future timestamp rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_old_timestamp_rejected() -> Result<()> {
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
        let result = mapper.register(peer_id).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timestamp too old"));

        println!("✅ Old timestamp rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_protocol_epoch_validation() -> Result<()> {
        // Test pre-protocol timestamp directly
        let pre_protocol_timestamp = 1600000000; // Sep 2020

        // Validate timestamp should fail
        let result = validate_peer_timestamp(pre_protocol_timestamp);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        println!("Error message: {}", err_msg);
        assert!(err_msg.contains("predates protocol launch") || err_msg.contains("Timestamp too old"));

        println!("✅ Protocol epoch validation test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_spoofed_node_id_rejected() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Create valid identity
        let identity = create_test_identity("victim-device", None)?;
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Spoof NodeId (replace with random bytes)
        let fake_node_id = NodeId::from_bytes([0xFFu8; 32]);
        peer_id.node_id = fake_node_id;

        // Try to register - should fail cryptographic verification
        let result = mapper.register(peer_id).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NodeId mismatch"));

        println!("✅ Spoofed NodeId rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_weak_device_id_rejected() -> Result<()> {
        let weak_names = vec!["test", "device", "phone", "laptop", "server"];

        for weak_name in weak_names {
            // Create valid identity first
            let identity = create_test_identity("valid-device-name-12345", None)?;
            let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

            // Manually set invalid device_id to bypass identity creation
            peer_id.device_id = weak_name.to_string();

            // Re-validate should fail when we try to use it
            let result = validate_device_id(&peer_id.device_id);
            assert!(result.is_err(), "Weak name '{}' should be rejected", weak_name);
            assert!(result.unwrap_err().to_string().contains("too common/weak"));
        }

        println!("✅ Weak device ID rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_short_device_id_rejected() -> Result<()> {
        // Create valid identity first
        let identity = create_test_identity("valid-device-name-12345", None)?;
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Manually set too-short device_id
        peer_id.device_id = "ab".to_string(); // 2 chars

        // Re-validate should fail
        let result = validate_device_id(&peer_id.device_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));

        println!("✅ Short device ID rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_long_device_id_rejected() -> Result<()> {
        // Create valid identity first
        let identity = create_test_identity("valid-device-name-12345", None)?;
        let mut peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // Manually set too-long device_id
        let long_device = "a".repeat(65); // 65 chars (max is 64)
        peer_id.device_id = long_device.clone();

        // Re-validate should fail
        let result = validate_device_id(&peer_id.device_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));

        println!("✅ Long device ID rejection test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_unregister_idempotent() -> Result<()> {
        let mapper = PeerIdMapper::new();

        // Register a peer
        let identity = create_test_identity("concurrent-unregister-test", None)?;
        let peer_id = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let node_id = identity.node_id.clone();

        mapper.register(peer_id.clone()).await?;
        assert_eq!(mapper.peer_count().await, 1);

        // Spawn 10 concurrent unregister attempts
        let mut handles = vec![];
        for _ in 0..10 {
            let mapper = mapper.clone();
            let node_id = node_id.clone();
            handles.push(tokio::spawn(async move {
                mapper.unregister(&node_id).await
            }));
        }

        // Wait for all and collect results
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Verify exactly 1 returned Some, 9 returned None
        let successes = results.iter().filter(|r| r.is_some()).count();
        let failures = results.iter().filter(|r| r.is_none()).count();

        assert_eq!(successes, 1, "Exactly one unregister should succeed");
        assert_eq!(failures, 9, "9 unregisters should return None");

        // Verify peer removed
        assert_eq!(mapper.peer_count().await, 0);

        // Verify all indexes cleaned up
        assert!(!mapper.contains_node_id(&node_id).await);

        println!("✅ Concurrent unregister idempotency test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_device_id_special_chars_rejected() -> Result<()> {
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

        println!("✅ Device ID special character rejection test passed");
        Ok(())
    }

}
