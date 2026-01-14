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
//! ```ignore
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
use lib_identity::{DhtPeerIdentity, ZhtpIdentity, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;  // CRITICAL FIX C3: Use parking_lot for atomic operations
use std::fmt;
use tracing::{warn, info, error};

// ============================================================================
// CRITICAL-1 FIX: Metrics for legacy path usage tracking
// ============================================================================

/// Global counter for legacy path usage (MEDIUM-2: Audit Trail)
static LEGACY_PATH_USAGE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Get the number of times the legacy path has been used
pub fn get_legacy_path_usage_count() -> u64 {
    LEGACY_PATH_USAGE_COUNT.load(Ordering::Relaxed)
}

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
/// - **Uniqueness**: Hash and Eq based on NodeId + PublicKey + DID (CRITICAL-2 fix)
///
/// # Security (CRITICAL-2 Fix)
///
/// Hash and Eq now include PublicKey and DID to prevent collision attacks where
/// an attacker crafts a NodeId that collides with a legitimate peer but has
/// a different PublicKey, allowing them to impersonate the peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedPeerId {
    /// Core peer identity fields shared across crates.
    pub core: DhtPeerIdentity,

    /// Optional display name for this peer
    pub display_name: Option<String>,

    /// Timestamp of identity creation (Unix timestamp)
    pub created_at: u64,

    /// CRITICAL-1 FIX: Bootstrap mode flag
    ///
    /// When true, this peer was created via legacy path (from_public_key_legacy)
    /// and has NOT been verified against the blockchain. Such peers:
    /// - CANNOT participate in consensus
    /// - CANNOT submit transactions
    /// - CANNOT access DHT content
    /// - CAN create blockchain identity
    /// - CAN query bootstrap nodes
    ///
    /// This flag MUST be checked before allowing security-critical operations.
    #[serde(default)]
    pub bootstrap_mode: bool,
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

        // Create instance with bootstrap_mode = false (verified identity)
        let peer = Self {
            core: DhtPeerIdentity::from_zhtp_identity_full(identity),
            display_name: identity.metadata.get("display_name").cloned(),
            created_at: identity.created_at,
            bootstrap_mode: false, // CRITICAL-1: Verified identity, NOT in bootstrap mode
        };

        // Validate cryptographic binding
        peer.verify_node_id()?;

        Ok(peer)
    }

    /// Check if this peer is in bootstrap mode (unverified identity)
    ///
    /// # Security
    ///
    /// Peers in bootstrap mode were created via `from_public_key_legacy` and
    /// have NOT been verified against the blockchain. They should be denied
    /// access to security-critical operations.
    pub fn is_bootstrap_mode(&self) -> bool {
        self.bootstrap_mode
    }

    /// Check if this peer is verified (NOT in bootstrap mode)
    pub fn is_verified(&self) -> bool {
        !self.bootstrap_mode
    }

    /// Verify that node_id matches Blake3(DID || device_id) per lib-identity rules
    pub fn verify_node_id(&self) -> Result<()> {
        let expected = NodeId::from_did_device(self.core.did(), self.core.device_id())?;
        if self.core.node_id().as_bytes() != expected.as_bytes() {
            return Err(anyhow!(
                "NodeId mismatch: expected {} but got {}",
                expected.to_hex(),
                self.core.node_id().to_hex()
            ));
        }
        Ok(())
    }

    /// Get a compact string representation for logging
    pub fn to_compact_string(&self) -> String {
        format!(
            "{}@{}",
            self.core.device_id(),
            &self.core.did()[..std::cmp::min(20, self.core.did().len())]
        )
    }

    /// Get the NodeId (canonical identifier)
    pub fn node_id(&self) -> &NodeId {
        self.core.node_id()
    }

    /// Get the PublicKey
    pub fn public_key(&self) -> &PublicKey {
        self.core.public_key()
    }

    /// Get the DID
    pub fn did(&self) -> &str {
        self.core.did()
    }

    /// Get the device ID
    pub fn device_id(&self) -> &str {
        self.core.device_id()
    }

    /// Create UnifiedPeerId from just a PublicKey (legacy compatibility)
    ///
    /// # DEPRECATED - Security Warning (CRITICAL-1 Fix)
    ///
    /// **⚠️ SECURITY WARNING:** This method bypasses blockchain identity verification.
    /// The resulting peer will be in `bootstrap_mode` and should be DENIED access to:
    /// - DHT content storage/retrieval
    /// - Transaction submission
    /// - Blockchain consensus participation
    /// - Mesh relay services
    ///
    /// The peer CAN:
    /// - Create blockchain identity via /api/v1/identity/create
    /// - Query bootstrap nodes
    ///
    /// **Prefer `from_zhtp_identity()` for all security-critical operations.**
    ///
    /// # Audit Trail (MEDIUM-2 Fix)
    ///
    /// This method logs a warning and increments a global counter for monitoring.
    /// Production deployments should alert on high usage of this path.
    ///
    /// # Device ID (MEDIUM-1 Fix)
    ///
    /// Generates a unique device_id using timestamp + random bytes to prevent
    /// collisions between legacy peers.
    #[deprecated(
        since = "0.2.0",
        note = "Use from_zhtp_identity() for verified peers. This method creates unverified bootstrap-mode peers."
    )]
    pub fn from_public_key_legacy(public_key: PublicKey) -> Self {
        // MEDIUM-2: Audit trail - log usage and increment counter
        LEGACY_PATH_USAGE_COUNT.fetch_add(1, Ordering::Relaxed);
        let usage_count = LEGACY_PATH_USAGE_COUNT.load(Ordering::Relaxed);

        warn!(
            "⚠️ SECURITY: from_public_key_legacy() called (usage #{}) - peer will be in bootstrap_mode",
            usage_count
        );

        // CRITICAL-1: Log caller context for security audit
        if usage_count > 100 {
            error!(
                "🚨 HIGH LEGACY PATH USAGE: {} calls to from_public_key_legacy(). \
                Consider migrating to from_zhtp_identity().",
                usage_count
            );
        }

        // Derive NodeId from public key hash
        let pk_hash = blake3::hash(&public_key.dilithium_pk);
        let node_id = NodeId::from_bytes(*pk_hash.as_bytes());

        // Create a derived DID (marked as unverified)
        let did = format!("did:zhtp:unverified:{}", hex::encode(&pk_hash.as_bytes()[..16]));

        // MEDIUM-1: Generate unique device_id with entropy
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let random_suffix = &pk_hash.as_bytes()[16..24];
        let device_id = format!(
            "bootstrap-{}-{}",
            timestamp % 1_000_000_000,
            hex::encode(random_suffix)
        );

        Self {
            core: DhtPeerIdentity {
                node_id,
                public_key,
                did,
                device_id,
            },
            display_name: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            bootstrap_mode: true, // CRITICAL-1: Mark as unverified bootstrap peer
        }
    }

    /// Create a verified UnifiedPeerId from PublicKey with blockchain verification
    ///
    /// This is the secure alternative to `from_public_key_legacy()`. It requires
    /// the caller to provide proof that the identity exists on the blockchain.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The peer's cryptographic public key
    /// * `did` - The peer's DID (must be verified to exist on blockchain)
    /// * `device_id` - The device identifier for this peer
    ///
    /// # Security
    ///
    /// The caller is responsible for verifying the DID exists on the blockchain
    /// before calling this method. The resulting peer will have `bootstrap_mode = false`.
    pub fn from_verified_public_key(
        public_key: PublicKey,
        did: String,
        device_id: String,
    ) -> Result<Self> {
        // Validate DID format
        if !did.starts_with("did:zhtp:") {
            return Err(anyhow!(
                "Invalid DID format: must start with 'did:zhtp:', got '{}'",
                &did[..20.min(did.len())]
            ));
        }

        // Reject unverified DIDs
        if did.contains("unverified") {
            return Err(anyhow!(
                "Cannot create verified peer from unverified DID: {}",
                &did[..30.min(did.len())]
            ));
        }

        // Validate device_id
        validate_device_id(&device_id)?;

        // Derive NodeId from DID + device_id
        let node_id = NodeId::from_did_device(&did, &device_id)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            core: DhtPeerIdentity {
                node_id,
                public_key,
                did,
                device_id,
            },
            display_name: None,
            created_at: now,
            bootstrap_mode: false, // Verified peer
        })
    }
}

// ============================================================================
// CRITICAL-2 FIX: Equality and Hashing (includes NodeId + PublicKey + DID)
// ============================================================================

impl PartialEq for UnifiedPeerId {
    /// CRITICAL-2 FIX: Compare NodeId, PublicKey, AND DID
    ///
    /// Previously only compared NodeId, allowing collision attacks where an attacker
    /// could craft a NodeId that collides with a legitimate peer but has a different
    /// PublicKey, enabling impersonation.
    ///
    /// Now we compare all three cryptographic identifiers to ensure full identity match.
    fn eq(&self, other: &Self) -> bool {
        // CRITICAL-2: Check for collision attack - log if NodeId matches but other fields don't
        if self.core.node_id == other.core.node_id {
            if self.core.public_key.dilithium_pk != other.core.public_key.dilithium_pk {
                error!(
                    "🚨 COLLISION ATTACK DETECTED: NodeId {} matches but PublicKey differs! \
                    This may be an impersonation attempt.",
                    self.core.node_id.to_hex()
                );
                return false; // Reject collision
            }
            if self.core.did != other.core.did {
                error!(
                    "🚨 COLLISION ATTACK DETECTED: NodeId {} matches but DID differs! \
                    Self DID: {}, Other DID: {}",
                    self.core.node_id.to_hex(),
                    &self.core.did[..30.min(self.core.did.len())],
                    &other.core.did[..30.min(other.core.did.len())]
                );
                return false; // Reject collision
            }
            true
        } else {
            false
        }
    }
}

impl Eq for UnifiedPeerId {}

impl std::hash::Hash for UnifiedPeerId {
    /// CRITICAL-2 FIX: Hash includes NodeId, PublicKey, AND DID
    ///
    /// Previously only hashed NodeId, making collision attacks easier.
    /// Now we hash all three cryptographic identifiers.
    ///
    /// Note: This changes the hash value and may affect existing stored data.
    /// Migration may be required for persistent peer storage.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Include all cryptographic identifiers in hash
        self.core.node_id.as_bytes().hash(state);
        self.core.public_key.dilithium_pk.hash(state);
        self.core.did.hash(state);
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
/// ```ignore
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
        validate_device_id(peer.device_id())?;

        let node_id = peer.node_id().clone();
        let public_key = peer.public_key().clone();
        let did = peer.did().to_string();

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
        state.by_public_key.remove(peer.public_key());

        // Remove from DID → Vec<NodeId> index
        if let Some(nodes) = state.by_did.get_mut(peer.did()) {
            nodes.retain(|n| n != node_id);
            if nodes.is_empty() {
                state.by_did.remove(peer.did());
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

        assert_eq!(peer_id.did(), identity.did);
        assert_eq!(peer_id.public_key().as_bytes(), identity.public_key.as_bytes());
        assert_eq!(peer_id.node_id(), &identity.node_id);
        assert_eq!(peer_id.device_id(), identity.primary_device);

        // Verify NodeId is correct
        peer_id.verify_node_id()?;

        println!("UnifiedPeerId from ZhtpIdentity test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_equality() -> Result<()> {
        let seed = [0x42u8; 64];
        let identity = create_test_identity("laptop-x1-carbon", Some(seed))?;

        // Create two peer IDs from the SAME identity
        let peer1 = UnifiedPeerId::from_zhtp_identity(&identity)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity)?;

        // CRITICAL-2: Same identity = same NodeId + same PublicKey + same DID = equal peers
        assert_eq!(peer1, peer2);

        // Also test that cloned peers are equal
        let peer3 = peer1.clone();
        assert_eq!(peer1, peer3);

        println!("Peer ID equality test passed");
        Ok(())
    }

    #[test]
    fn test_peer_id_inequality_different_keys() -> Result<()> {
        // Different seeds = different keys = NOT equal (even if device is same)
        let seed1 = [0x42u8; 64];
        let seed2 = [0x43u8; 64];

        let identity1 = create_test_identity("same-device-name", Some(seed1))?;
        let identity2 = create_test_identity("same-device-name", Some(seed2))?;

        let peer1 = UnifiedPeerId::from_zhtp_identity(&identity1)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity2)?;

        // CRITICAL-2: Different PublicKeys = NOT equal (prevents collision attacks)
        assert_ne!(peer1, peer2, "Peers with different keys should NOT be equal");

        println!("Peer ID inequality (different keys) test passed");
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
        peer_id.core.node_id = fake_node_id;

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

    // ============================================================================
    // CRITICAL-1 and CRITICAL-2 Security Fix Tests
    // ============================================================================

    #[test]
    fn test_critical1_legacy_peer_is_bootstrap_mode() -> Result<()> {
        // Test that from_public_key_legacy creates bootstrap-mode peers
        let seed = [0x42u8; 64];
        let identity = create_test_identity("test-device-001", Some(seed))?;

        // Legacy path should create bootstrap-mode peer
        #[allow(deprecated)]
        let legacy_peer = UnifiedPeerId::from_public_key_legacy(identity.public_key.clone());

        assert!(legacy_peer.bootstrap_mode, "Legacy peer should be in bootstrap mode");
        assert!(legacy_peer.is_bootstrap_mode(), "is_bootstrap_mode() should return true");
        assert!(!legacy_peer.is_verified(), "is_verified() should return false");

        // Verified path should NOT create bootstrap-mode peer
        let verified_peer = UnifiedPeerId::from_zhtp_identity(&identity)?;

        assert!(!verified_peer.bootstrap_mode, "Verified peer should NOT be in bootstrap mode");
        assert!(!verified_peer.is_bootstrap_mode(), "is_bootstrap_mode() should return false");
        assert!(verified_peer.is_verified(), "is_verified() should return true");

        println!("CRITICAL-1: Bootstrap mode flag test passed");
        Ok(())
    }

    #[test]
    fn test_critical1_legacy_path_audit_trail() -> Result<()> {
        // Test that legacy path increments usage counter
        let initial_count = get_legacy_path_usage_count();

        let seed = [0x77u8; 64];
        let identity = create_test_identity("audit-test-device", Some(seed))?;

        // Call legacy path
        #[allow(deprecated)]
        let _ = UnifiedPeerId::from_public_key_legacy(identity.public_key.clone());

        let new_count = get_legacy_path_usage_count();
        assert!(new_count > initial_count, "Legacy path usage counter should increment");

        println!("CRITICAL-1: Audit trail test passed (count: {} -> {})", initial_count, new_count);
        Ok(())
    }

    #[test]
    fn test_critical1_legacy_did_marked_unverified() -> Result<()> {
        let seed = [0x55u8; 64];
        let identity = create_test_identity("unverified-test-dev", Some(seed))?;

        #[allow(deprecated)]
        let legacy_peer = UnifiedPeerId::from_public_key_legacy(identity.public_key.clone());

        // DID should contain "unverified" marker
        assert!(
            legacy_peer.did().contains("unverified"),
            "Legacy peer DID should contain 'unverified' marker"
        );

        println!("CRITICAL-1: Unverified DID marker test passed");
        Ok(())
    }

    #[test]
    fn test_critical2_collision_attack_detection() -> Result<()> {
        let seed1 = [0x11u8; 64];
        let seed2 = [0x22u8; 64];

        let identity1 = create_test_identity("collision-device-1", Some(seed1))?;
        let identity2 = create_test_identity("collision-device-2", Some(seed2))?;

        let mut peer1 = UnifiedPeerId::from_zhtp_identity(&identity1)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity2)?;

        // Simulate collision attack: modify peer1's NodeId to match peer2's
        let original_node_id = peer1.core.node_id.clone();
        peer1.core.node_id = peer2.core.node_id.clone();

        // CRITICAL-2: Even though NodeId matches, peers should NOT be equal
        // because PublicKey and DID are different
        assert_ne!(
            peer1, peer2,
            "Peers with same NodeId but different PublicKey should NOT be equal (collision detected)"
        );

        // Restore original NodeId
        peer1.core.node_id = original_node_id;

        println!("CRITICAL-2: Collision attack detection test passed");
        Ok(())
    }

    #[test]
    fn test_critical2_hash_includes_pubkey_and_did() -> Result<()> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let seed1 = [0x33u8; 64];
        let seed2 = [0x44u8; 64];

        let identity1 = create_test_identity("hash-test-device-1", Some(seed1))?;
        let identity2 = create_test_identity("hash-test-device-2", Some(seed2))?;

        let peer1 = UnifiedPeerId::from_zhtp_identity(&identity1)?;
        let peer2 = UnifiedPeerId::from_zhtp_identity(&identity2)?;

        // Calculate hashes
        let mut hasher1 = DefaultHasher::new();
        peer1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        peer2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        // Different peers should have different hashes
        assert_ne!(hash1, hash2, "Different peers should have different hashes");

        // Same peer should have same hash
        let mut hasher1b = DefaultHasher::new();
        peer1.hash(&mut hasher1b);
        let hash1b = hasher1b.finish();

        assert_eq!(hash1, hash1b, "Same peer should have consistent hash");

        println!("CRITICAL-2: Hash includes PublicKey and DID test passed");
        Ok(())
    }

    #[test]
    fn test_medium1_legacy_device_id_has_entropy() -> Result<()> {
        let seed = [0x88u8; 64];
        let identity = create_test_identity("entropy-test-device", Some(seed))?;

        // Create multiple legacy peers and verify device_ids are unique
        let mut device_ids = std::collections::HashSet::new();

        for _ in 0..10 {
            #[allow(deprecated)]
            let peer = UnifiedPeerId::from_public_key_legacy(identity.public_key.clone());

            // Device ID should be unique
            assert!(
                device_ids.insert(peer.device_id().to_string()),
                "Legacy device_ids should be unique (got duplicate: {})",
                peer.device_id()
            );

            // Device ID should have bootstrap prefix
            assert!(
                peer.device_id().starts_with("bootstrap-"),
                "Legacy device_id should start with 'bootstrap-'"
            );
        }

        println!("MEDIUM-1: Device ID entropy test passed");
        Ok(())
    }

    #[test]
    fn test_from_verified_public_key() -> Result<()> {
        let seed = [0x99u8; 64];
        let identity = create_test_identity("verified-pk-test", Some(seed))?;

        // Create verified peer
        let peer = UnifiedPeerId::from_verified_public_key(
            identity.public_key.clone(),
            identity.did.clone(),
            identity.primary_device.clone(),
        )?;

        // Should NOT be in bootstrap mode
        assert!(!peer.bootstrap_mode, "from_verified_public_key should NOT create bootstrap-mode peer");
        assert!(peer.is_verified(), "Peer should be verified");

        println!("from_verified_public_key test passed");
        Ok(())
    }

    #[test]
    fn test_from_verified_public_key_rejects_unverified_did() -> Result<()> {
        let seed = [0xAAu8; 64];
        let identity = create_test_identity("reject-unverified", Some(seed))?;

        // Try to create "verified" peer with unverified DID
        let unverified_did = "did:zhtp:unverified:deadbeef12345678";

        let result = UnifiedPeerId::from_verified_public_key(
            identity.public_key.clone(),
            unverified_did.to_string(),
            "valid-device-001".to_string(),
        );

        assert!(result.is_err(), "Should reject unverified DID in from_verified_public_key");
        assert!(
            result.unwrap_err().to_string().contains("unverified"),
            "Error should mention unverified DID"
        );

        println!("from_verified_public_key rejects unverified DID test passed");
        Ok(())
    }
}
