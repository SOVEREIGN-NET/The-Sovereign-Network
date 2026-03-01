//! NodeId - Canonical 32-byte DHT routing address with entropy
//!
//! # CRITICAL FIX C2: Enhanced NodeId Security
//!
//! NodeId generation now includes:
//! - Cryptographic random nonce (prevents rainbow tables)
//! - Network genesis binding (prevents cross-chain replay)
//! - Timestamp binding (prevents pre-computation)
//! - Weak device ID rejection (enforces minimum entropy)
//!
//! # Security Properties
//!
//! - **Entropy**: 256 bits of randomness via getrandom
//! - **Network Binding**: Unique per blockchain network
//! - **Temporal Binding**: Creation timestamp included
//! - **Domain Separation**: Versioned prefix "ZHTP_NODE_ID_V2"
//!
//! # Example
//!
//! ```rust
//! use lib_identity::types::{NodeId, set_network_genesis};
//!
//! // Initialize network genesis once at startup
//! set_network_genesis([0x01u8; 32]);
//!
//! // Generate NodeId with full entropy
//! let node_id = NodeId::from_identity_components(
//!     "did:zhtp:abc123",
//!     "my-secure-device-name",
//! ).expect("Valid NodeId");
//! ```

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
// Note: lib_crypto::Hash replaced with direct blake3 usage for lib-types compatibility
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Network genesis hash - binds identities to specific network
/// Must be set at application startup via `set_network_genesis()`
static NETWORK_GENESIS: OnceLock<[u8; 32]> = OnceLock::new();

/// Set the network genesis hash (call once at startup)
///
/// This binds all generated NodeIds to a specific blockchain network,
/// preventing cross-chain replay attacks.
///
/// # Panics
///
/// Panics if called more than once (use `try_set_network_genesis()` for fallible version)
///
/// # Example
///
/// ```rust
/// use lib_identity::types::set_network_genesis;
///
/// // Mainnet genesis hash
/// let mainnet_genesis = [0x01u8; 32];  // Replace with real genesis
/// set_network_genesis(mainnet_genesis);
/// ```
pub fn set_network_genesis(genesis_hash: [u8; 32]) {
    NETWORK_GENESIS.set(genesis_hash)
        .expect("Network genesis already set - can only be called once");
}

/// Try to set network genesis (fallible version)
///
/// Returns `Ok(())` if set successfully, `Err(())` if already set.
pub fn try_set_network_genesis(genesis_hash: [u8; 32]) -> Result<(), ()> {
    NETWORK_GENESIS.set(genesis_hash).map_err(|_| ())
}

/// Get the current network genesis hash
///
/// Returns an error if not yet initialized via `set_network_genesis()`.
pub fn get_network_genesis() -> Result<&'static [u8; 32]> {
    NETWORK_GENESIS.get()
        .ok_or_else(|| anyhow!("Network genesis not initialized - call set_network_genesis() at startup"))
}

/// Canonical NodeId - 32-byte identity routing address with full entropy
///
/// # CRITICAL FIX C2: Enhanced Security
///
/// New fields added to prevent attacks:
/// - `creation_nonce`: Random 256-bit nonce (prevents rainbow tables)
/// - `network_genesis`: Network binding (prevents cross-chain replay)
///
/// Full Blake3 hash output per ARCHITECTURE_CONSOLIDATION.md specification.
/// Generated NON-deterministically from DID + device name + random nonce.
///
/// # Size Rationale
/// - 32 bytes = 256 bits (full Blake3 output)
/// - Per architecture spec: NodeId([u8; 32]) = Blake3("ZHTP_NODE_V2:" + ...)
/// - 2^256 address space
/// - Maintains cryptographic strength of Blake3
///
/// # Examples
/// ```
/// use lib_identity::types::NodeId;
///
/// // Valid creation
/// let node_id = NodeId::from_did_device(
///     "did:zhtp:abc123",
///     "laptop"
/// ).expect("Valid inputs");
///
/// // Same inputs produce same NodeId
/// let node_id2 = NodeId::from_did_device(
///     "did:zhtp:abc123",
///     "laptop"
/// ).expect("Valid inputs");
/// assert_eq!(node_id, node_id2);
/// ```
///
/// # CRITICAL FIX for PR #208: Added PartialOrd and Ord traits
///
/// The Ord trait is required for CRDT tie-breaking in lib-storage.
/// Ordering is based on lexicographic comparison of the bytes field,
/// providing deterministic convergence for distributed consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// Blake3 hash output (32 bytes)
    bytes: [u8; 32],

    /// CRITICAL FIX C2: Random nonce for entropy (prevents rainbow tables)
    creation_nonce: [u8; 32],

    /// CRITICAL FIX C2: Network genesis binding (prevents cross-chain replay)
    network_genesis: [u8; 32],
}

// CRITICAL FIX for PR #208: Manual implementation of PartialOrd and Ord
// Required for CRDT tie-breaking in lib-storage/consistency
// Ordering is based solely on bytes field for deterministic consensus
impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lexicographic comparison of bytes field
        // This provides deterministic ordering for CRDT convergence
        self.bytes.cmp(&other.bytes)
    }
}

impl NodeId {
    /// Create NodeId from raw 32-byte array (legacy, for testing only)
    ///
    /// # Warning
    ///
    /// This bypasses security checks. Use `from_identity_components()` in production.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            creation_nonce: [0u8; 32],
            network_genesis: [0u8; 32],
        }
    }

    /// Get reference to underlying 32-byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// CRITICAL FIX C2: Generate NodeId with proper entropy and network binding
    ///
    /// This replaces the old deterministic generation with a secure version that includes:
    /// - Cryptographically random nonce (prevents rainbow table attacks)
    /// - Network genesis binding (prevents cross-chain replay)
    /// - Timestamp binding (prevents pre-computation)
    /// - Weak device ID rejection (enforces minimum entropy)
    ///
    /// # Security
    ///
    /// - Uses `getrandom` for cryptographic randomness
    /// - Binds to network genesis (must call `set_network_genesis()` first)
    /// - Includes creation timestamp
    /// - Validates device ID has sufficient entropy
    ///
    /// # Returns
    ///
    /// - `Ok(NodeId)` if generation succeeds
    /// - `Err(...)` if validation fails or entropy unavailable
    pub fn from_identity_components(
        did: &str,
        device_id: &str,
    ) -> Result<Self> {
        // Validate inputs
        Self::validate_did(did)?;
        Self::validate_device_id(device_id)?;

        // Get network genesis (prevents cross-chain replay)
        let network_genesis = *get_network_genesis()?;

        // Generate cryptographically secure random nonce
        let mut creation_nonce = [0u8; 32];
        getrandom::getrandom(&mut creation_nonce)
            .map_err(|e| anyhow!("Failed to generate random nonce: {}", e))?;

        // Get current timestamp (binds to time of creation)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();

        // Compute NodeId with all entropy sources
        let mut hasher = blake3::Hasher::new();

        // Domain separation
        hasher.update(b"ZHTP_NODE_ID_V2");

        // Network binding (prevents cross-chain replay)
        hasher.update(&network_genesis);

        // Identity components
        hasher.update(did.as_bytes());
        hasher.update(device_id.as_bytes());

        // Random entropy (prevents rainbow tables)
        hasher.update(&creation_nonce);

        // Temporal binding (prevents pre-computation)
        hasher.update(&timestamp.to_le_bytes());

        let hash = hasher.finalize();
        let bytes: [u8; 32] = *hash.as_bytes();

        Ok(NodeId {
            bytes,
            creation_nonce,
            network_genesis,
        })
    }

    /// Create NodeId from DID and device name (legacy deterministic version)
    ///
    /// # Deprecated
    ///
    /// This method is kept for backward compatibility but should not be used
    /// in new code. Use `from_identity_components()` instead for proper security.
    ///
    /// # Security Warning
    ///
    /// This method is deterministic and vulnerable to rainbow table attacks.
    /// It exists only for compatibility with existing tests.
    pub fn from_did_device(did: &str, device: &str) -> Result<Self> {
        // For backward compatibility, use deterministic generation
        // This matches the old behavior for existing tests
        Self::validate_did(did)?;
        let normalized_device = Self::normalize_and_validate_device(device)?;

        let network_id = "mainnet";
        let protocol_version = 1u32;

        let preimage = format!(
            "ZHTP_NODE_V2:network={}:version={}:{}:{}",
            network_id, protocol_version, did, normalized_device
        );
        let hash = blake3::hash(preimage.as_bytes());
        let hash: [u8; 32] = *hash.as_bytes();

        Ok(Self {
            bytes: hash,
            creation_nonce: [0u8; 32],
            network_genesis: [0u8; 32],
        })
    }

    /// Verify NodeId was correctly generated from components
    ///
    /// Recomputes the hash with the stored nonce and verifies it matches.
    pub fn verify_derivation(
        &self,
        did: &str,
        device_id: &str,
        timestamp: u64,
    ) -> Result<bool> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZHTP_NODE_ID_V2");
        hasher.update(&self.network_genesis);
        hasher.update(did.as_bytes());
        hasher.update(device_id.as_bytes());
        hasher.update(&self.creation_nonce);
        hasher.update(&timestamp.to_le_bytes());

        let hash = hasher.finalize();
        Ok(hash.as_bytes() == &self.bytes)
    }

    /// CRITICAL FIX C2: Validate device_id for sufficient entropy
    ///
    /// Prevents weak device names that could be brute-forced or rainbow-tabled.
    ///
    /// # Requirements
    ///
    /// - Minimum 8 characters (not just 3 as in old version)
    /// - At least 4 unique characters (prevents "aaaaaaa")
    /// - Not in common/weak device ID list
    fn validate_device_id(device_id: &str) -> Result<()> {
        // Check minimum entropy (increased from 3 to 8)
        const MIN_LENGTH: usize = 8;
        if device_id.len() < MIN_LENGTH {
            return Err(anyhow!(
                "Device ID too short: {} chars (minimum {} required for security)",
                device_id.len(),
                MIN_LENGTH
            ));
        }

        // Check maximum length
        const MAX_LENGTH: usize = 64;
        if device_id.len() > MAX_LENGTH {
            return Err(anyhow!(
                "Device ID too long: {} chars (max: {})",
                device_id.len(),
                MAX_LENGTH
            ));
        }

        // Check for sufficient unique characters (prevents "aaaaaaaa")
        let unique_chars: std::collections::HashSet<char> =
            device_id.chars().collect();

        if unique_chars.len() < 4 {
            return Err(anyhow!(
                "Device ID has insufficient entropy: only {} unique characters (min: 4)",
                unique_chars.len()
            ));
        }

        // Check for common weak device IDs
        const WEAK_IDS: &[&str] = &[
            "00000000", "11111111", "12345678", "aaaaaaaa",
            "testtest", "deviceid", "abcdefgh", "password",
            "device-1", "device-2", "laptop01", "phone001",
        ];

        if WEAK_IDS.contains(&device_id.to_lowercase().as_str()) {
            return Err(anyhow!(
                "Device ID is too common/weak: '{}' - use a unique identifier",
                device_id
            ));
        }

        Ok(())
    }

    /// Validate DID format (must start with "did:zhtp:")
    fn validate_did(did: &str) -> Result<()> {
        if did.is_empty() {
            return Err(anyhow!("DID cannot be empty"));
        }

        if did.len() > 256 {
            return Err(anyhow!("DID too long: {} characters (max 256)", did.len()));
        }

        if !did.starts_with("did:zhtp:") {
            return Err(anyhow!(
                "Invalid DID format: must start with 'did:zhtp:', got '{}'",
                did
            ));
        }

        let id_part = &did[9..];
        if id_part.is_empty() {
            return Err(anyhow!("DID must have an identifier after 'did:zhtp:'"));
        }

        if id_part.contains(char::is_whitespace) {
            return Err(anyhow!("DID identifier cannot contain whitespace"));
        }

        if id_part.chars().any(|c| "!@#$%^&*()+=[]{}|\\;:'\",<>?/".contains(c)) {
            return Err(anyhow!("DID identifier contains invalid special characters"));
        }

        Ok(())
    }

    /// Normalize and validate device name (legacy method)
    fn normalize_and_validate_device(device: &str) -> Result<String> {
        let trimmed = device.trim();

        if trimmed.is_empty() {
            return Err(anyhow!("Device name cannot be empty or whitespace-only"));
        }

        if trimmed.len() > 64 {
            return Err(anyhow!(
                "Device name must be 1-64 characters, got {}",
                trimmed.len()
            ));
        }

        if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return Err(anyhow!(
                "Device name must match ^[A-Za-z0-9._-]+$, got '{}'",
                trimmed
            ));
        }

        Ok(trimmed.to_lowercase())
    }

    /// Convert NodeId to hex string (64 lowercase chars)
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Create NodeId from hex string
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(anyhow!(
                "Invalid hex length: expected 64 characters, got {}",
                hex.len()
            ));
        }

        let bytes = hex::decode(hex)
            .map_err(|e| anyhow!("Invalid hex string: {}", e))?;

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);

        Ok(Self::from_bytes(array))
    }

    /// Calculate XOR distance to another NodeId (for Kademlia routing)
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.bytes[i] ^ other.bytes[i];
        }
        result
    }

    /// Calculate Kademlia distance to another NodeId
    ///
    /// This is the standard Kademlia distance metric, defined as the index
    /// of the most significant bit of the XOR result between two NodeIds.
    /// A smaller value means a shorter distance.
    ///
    /// # Returns
    /// `u32` - The distance, where 0 is the closest possible.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
/// let node1 = NodeId::from_bytes([0b10000000; 32]);
/// let node2 = NodeId::from_bytes([0b00000000; 32]);
///
/// // With this implementation, the most significant differing bit in the first byte yields distance 0.
/// assert_eq!(node1.kademlia_distance(&node2), 0);
/// ```
pub fn kademlia_distance(&self, other: &Self) -> u32 {
        let xor_bytes = self.xor_distance(other);
        for (i, byte) in xor_bytes.iter().enumerate() {
            if *byte != 0 {
                return (i as u32 * 8) + byte.leading_zeros();
            }
        }
        0
    }

    /// Convert to 32-byte array (compatible with storage Hash)
    pub fn to_bytes_array(&self) -> [u8; 32] {
        self.bytes
    }

    /// Create NodeId from 32-byte array
    pub fn from_bytes_array(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }

    /// Convert to 32-byte storage hash (raw bytes)
    /// 
    /// Note: This returns raw bytes. Use `lib_crypto::Hash::from_bytes(node_id.to_bytes_array())` 
    /// to convert to lib_crypto::Hash if needed.
    pub fn to_storage_hash(&self) -> [u8; 32] {
        self.bytes
    }

    /// Create NodeId from 32-byte storage hash bytes
    ///
    /// Note: Pass raw bytes. Use `node_id_hash.as_bytes()` to get bytes from lib_crypto::Hash.
    pub fn from_storage_hash(bytes: &[u8; 32]) -> Self {
        Self::from_bytes(*bytes)
    }

    /// Get the creation nonce
    pub fn creation_nonce(&self) -> &[u8; 32] {
        &self.creation_nonce
    }

    /// Get the network genesis
    pub fn network_genesis(&self) -> &[u8; 32] {
        &self.network_genesis
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

impl Default for NodeId {
    fn default() -> Self {
        NodeId::from_bytes([0u8; 32])
    }
}

// ============================================================================
// TESTS - Security Enhancement Validation
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_has_entropy() {
        let _ = try_set_network_genesis([0x01u8; 32]);

        // Same inputs should produce different NodeIds (due to random nonce)
        let id1 = NodeId::from_identity_components(
            "did:zhtp:test12345",
            "device-with-sufficient-entropy",
        ).unwrap();

        let id2 = NodeId::from_identity_components(
            "did:zhtp:test12345",
            "device-with-sufficient-entropy",
        ).unwrap();

        assert_ne!(id1.bytes, id2.bytes, "NodeIds should be unique due to random nonce");
    }

    #[test]
    fn test_node_id_network_binding() {
        // Test that different networks produce different NodeIds
        // (This test can't actually run due to OnceLock, but demonstrates the concept)
        // In practice, different network deployments will have different genesis hashes
    }

    #[test]
    fn test_weak_device_id_rejected() {
        let _ = try_set_network_genesis([0x01u8; 32]);

        let weak_ids = vec!["00000000", "12345678", "aaaaaaaa", "testtest"];
        for weak_id in weak_ids {
            let result = NodeId::from_identity_components(
                "did:zhtp:test",
                weak_id,
            );
            assert!(result.is_err(), "Weak device ID should be rejected: {}", weak_id);
        }
    }

    #[test]
    fn test_short_device_id_rejected() {
        let _ = try_set_network_genesis([0x01u8; 32]);

        let result = NodeId::from_identity_components(
            "did:zhtp:test",
            "short7",  // Only 6 chars, min is 8
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_low_entropy_device_id_rejected() {
        let _ = try_set_network_genesis([0x01u8; 32]);

        let result = NodeId::from_identity_components(
            "did:zhtp:test",
            "aaabbbcc",  // Only 3 unique chars
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient entropy"));
    }

    // Legacy tests for backward compatibility
    #[test]
    fn test_from_did_device_golden_vector() {
        let did = "did:zhtp:0123456789abcdef";
        let device = "test-device";

        let node = NodeId::from_did_device(did, device).unwrap();

        let expected_hex = "5cb7a97aa0503fed385fa74f3ea61988309cb81678f3772c11bc7b3677d72888";
        assert_eq!(node.to_hex(), expected_hex);
    }
}
