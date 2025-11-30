//! NodeId - Canonical 32-byte DHT routing address
//!
//! NodeId is derived from a DID + device name combination, ensuring:
//! - Deterministic generation (same inputs → same NodeId)
//! - DHT compatibility (32 bytes per ARCHITECTURE_CONSOLIDATION.md)
//! - Multi-device support (one DID → many NodeIds)
//! - Strict validation (prevents malformed identities)

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use lib_crypto::Hash;

/// Canonical NodeId - 32-byte identity routing address
///
/// Full Blake3 hash output per ARCHITECTURE_CONSOLIDATION.md specification.
/// Generated deterministically from DID + device name.
///
/// # Size Rationale
/// - 32 bytes = 256 bits (full Blake3 output)
/// - Per architecture spec: NodeId([u8; 32]) = Blake3("ZHTP_NODE_V2:" + DID + ":" + device)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create NodeId from raw 32-byte array
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 32];
    /// let node_id = NodeId::from_bytes(bytes);
    /// assert_eq!(node_id.as_bytes(), &bytes);
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get reference to underlying 32-byte array
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 32];
    /// let node_id = NodeId::from_bytes(bytes);
    /// assert_eq!(node_id.as_bytes(), &bytes);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create NodeId from DID and device name
    ///
    /// Performs strict validation on both inputs and normalizes the device name
    /// (trimmed and lowercased) before hashing.
    ///
    /// # Validation Rules
    /// - DID must start with `did:zhtp:`
    /// - Device name must be 1-64 characters after trimming
    /// - Device name must match: `^[A-Za-z0-9._-]+$`
    ///
    /// # Errors
    /// Returns `Err` if validation fails. Never panics on invalid input.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// // Valid inputs
    /// let node_id = NodeId::from_did_device(
    ///     "did:zhtp:abc123",
    ///     "laptop"
    /// ).expect("Valid inputs");
    ///
    /// // Case-insensitive device names
    /// let upper = NodeId::from_did_device("did:zhtp:abc123", "LAPTOP").unwrap();
    /// let lower = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
    /// assert_eq!(upper, lower); // Same NodeId (normalized)
    ///
    /// // Invalid DID
    /// assert!(NodeId::from_did_device("invalid", "laptop").is_err());
    /// ```
    pub fn from_did_device(did: &str, device: &str) -> Result<Self> {
        // 1. Validate DID
        Self::validate_did(did)?;

        // 2. Normalize and validate device name
        let normalized_device = Self::normalize_and_validate_device(device)?;

        // 3. Derive NodeId using Blake3
        let preimage = format!("ZHTP_NODE_V2:{}:{}", did, normalized_device);
        let hash = lib_crypto::hash_blake3(preimage.as_bytes());

        // 4. Use full 32-byte Blake3 output (per ARCHITECTURE_CONSOLIDATION.md)
        Ok(Self(hash))
    }

    /// Validate DID format (must start with "did:zhtp:")
    fn validate_did(did: &str) -> Result<()> {
        // Check non-empty
        if did.is_empty() {
            return Err(anyhow!("DID cannot be empty"));
        }

        // Check reasonable length (max 256 characters)
        if did.len() > 256 {
            return Err(anyhow!("DID too long: {} characters (max 256)", did.len()));
        }

        // Check prefix
        if !did.starts_with("did:zhtp:") {
            return Err(anyhow!(
                "Invalid DID format: must start with 'did:zhtp:', got '{}'",
                did
            ));
        }

        // Check that there's content after prefix
        let id_part = &did[9..]; // Skip "did:zhtp:"
        if id_part.is_empty() {
            return Err(anyhow!("DID must have an identifier after 'did:zhtp:'"));
        }

        // Check for invalid characters (whitespace, special chars)
        if id_part.contains(char::is_whitespace) {
            return Err(anyhow!("DID identifier cannot contain whitespace"));
        }

        // Check for common invalid characters
        if id_part.chars().any(|c| "!@#$%^&*()+=[]{}|\\;:'\",<>?/".contains(c)) {
            return Err(anyhow!("DID identifier contains invalid special characters"));
        }

        Ok(())
    }

    /// Normalize and validate device name
    ///
    /// Returns normalized device name (trimmed + lowercased)
    fn normalize_and_validate_device(device: &str) -> Result<String> {
        // Trim whitespace
        let trimmed = device.trim();

        // Check non-empty after trim
        if trimmed.is_empty() {
            return Err(anyhow!(
                "Device name cannot be empty or whitespace-only"
            ));
        }

        // Check length (1-64 chars)
        if trimmed.len() > 64 {
            return Err(anyhow!(
                "Device name must be 1-64 characters, got {}",
                trimmed.len()
            ));
        }

        // Validate characters: a-z A-Z 0-9 . _ -
        if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return Err(anyhow!(
                "Device name must match ^[A-Za-z0-9._-]+$, got '{}'",
                trimmed
            ));
        }

        // Normalize to lowercase
        Ok(trimmed.to_lowercase())
    }

    /// Convert NodeId to hex string (64 lowercase chars)
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let bytes = [0x42; 32];
    /// let node_id = NodeId::from_bytes(bytes);
    /// let hex = node_id.to_hex();
    /// assert_eq!(hex.len(), 64);
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create NodeId from hex string
    ///
    /// Accepts exactly 64 hexadecimal characters (case-insensitive).
    /// Does not accept `0x` prefix.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// let node_id = NodeId::from_hex(hex).unwrap();
    /// assert_eq!(node_id.to_hex(), hex);
    /// ```
    ///
    /// # Errors
    /// Returns error if:
    /// - Length is not exactly 64 characters
    /// - Contains non-hexadecimal characters
    pub fn from_hex(hex: &str) -> Result<Self> {
        // Check length (must be exactly 64 chars = 32 bytes)
        if hex.len() != 64 {
            return Err(anyhow!(
                "Invalid hex length: expected 64 characters, got {}",
                hex.len()
            ));
        }

        // Decode hex to bytes
        let bytes = hex::decode(hex)
            .map_err(|e| anyhow!("Invalid hex string: {}", e))?;

        // Convert to fixed-size array
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);

        Ok(Self(array))
    }

    /// Calculate XOR distance to another NodeId (for Kademlia routing)
    ///
    /// Returns the bitwise XOR of two NodeIds, used as the distance metric
    /// in Kademlia DHT routing. Distance is symmetric: `d(a,b) = d(b,a)`.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let node1 = NodeId::from_did_device("did:zhtp:abc", "laptop").unwrap();
    /// let node2 = NodeId::from_did_device("did:zhtp:def", "phone").unwrap();
    ///
    /// let distance = node1.xor_distance(&node2);
    /// assert_eq!(distance, node2.xor_distance(&node1)); // Symmetric
    /// ```
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        result
    }

    /// Convert to 32-byte storage Hash
    ///
    /// Since NodeId is now 32 bytes (per ARCHITECTURE_CONSOLIDATION.md),
    /// this is a direct conversion to Hash with no padding needed.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    ///
    /// let node = NodeId::from_did_device("did:zhtp:abc", "laptop").unwrap();
    /// let hash = node.to_storage_hash();
    /// assert_eq!(hash.as_bytes().len(), 32);
    /// ```
    pub fn to_storage_hash(&self) -> Hash {
        Hash::from_bytes(&self.0)
    }

    /// Create NodeId from 32-byte storage Hash
    ///
    /// Since NodeId is now 32 bytes, this is a direct conversion from Hash.
    ///
    /// # Examples
    /// ```
    /// use lib_identity::types::NodeId;
    /// use lib_crypto::Hash;
    ///
    /// let node = NodeId::from_did_device("did:zhtp:abc", "laptop").unwrap();
    /// let hash = node.to_storage_hash();
    /// let restored = NodeId::from_storage_hash(&hash);
    /// assert_eq!(node, restored);
    /// ```
    pub fn from_storage_hash(hash: &Hash) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }

    // ========================================================================
    // Phase 2: DHT Integration (lib-dht)
    // ========================================================================
    //
    // TODO: Phase 2 - Add when lib-dht is integrated
    //
    // The following methods will be added in Phase 2 when lib-dht exists:
    //
    // /// Convert NodeId to lib-dht UID (zero-copy)
    // ///
    // /// Phase 2: Maps directly to lib-dht's 32-byte UID type.
    // /// This enables zero-copy conversion for DHT routing operations.
    // pub fn to_dht_uid(&self) -> lib_dht::UID {
    //     lib_dht::UID::from_bytes(self.0)
    // }
    //
    // /// Create NodeId from lib-dht UID (zero-copy)
    // ///
    // /// Phase 2: Direct conversion from DHT's native UID type.
    // pub fn from_dht_uid(uid: &lib_dht::UID) -> Self {
    //     Self(*uid.as_bytes())
    // }
    //
    // Note: lib-dht does not exist yet in the codebase. When it's added:
    // 1. Uncomment these methods
    // 2. Add lib-dht dependency to Cargo.toml
    // 3. Add integration tests in lib-dht's test suite
    // 4. Verify zero-copy conversion works as expected
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Default for NodeId {
    fn default() -> Self {
        NodeId([0u8; 32])
    }
}

// ============================================================================
// TESTS - Written FIRST to define the contract (TDD)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // GIVEN valid DID and device name
    // WHEN NodeId::from_did_device() is called
    // THEN a deterministic 32-byte NodeId is generated
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_valid_inputs() {
        // GIVEN: Valid DID and device name
        let did = "did:zhtp:abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, device);

        // THEN: Success with 32-byte NodeId
        assert!(result.is_ok(), "Should succeed with valid inputs");
        let node_id = result.unwrap();
        assert_eq!(node_id.as_bytes().len(), 32, "NodeId must be 32 bytes");
    }

    #[test]
    fn test_from_did_device_deterministic() {
        // GIVEN: Same DID and device name
        let did = "did:zhtp:abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId twice
        let node_id1 = NodeId::from_did_device(did, device).unwrap();
        let node_id2 = NodeId::from_did_device(did, device).unwrap();

        // THEN: Both NodeIds are identical
        assert_eq!(node_id1, node_id2, "Same inputs must produce same NodeId");
    }

    #[test]
    fn test_from_did_device_different_devices_different_nodeids() {
        // GIVEN: Same DID, different devices
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds for different devices
        let laptop = NodeId::from_did_device(did, "laptop").unwrap();
        let phone = NodeId::from_did_device(did, "phone").unwrap();

        // THEN: NodeIds are different
        assert_ne!(laptop, phone, "Different devices must have different NodeIds");
    }

    #[test]
    fn test_from_did_device_different_dids_different_nodeids() {
        // GIVEN: Different DIDs, same device
        let device = "laptop";

        // WHEN: Creating NodeIds for different DIDs
        let node1 = NodeId::from_did_device("did:zhtp:abc123", device).unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", device).unwrap();

        // THEN: NodeIds are different (proves DID is included in derivation)
        assert_ne!(node1, node2, "Different DIDs must produce different NodeIds");
    }

    #[test]
    fn test_from_did_device_golden_vector() {
        // GIVEN: Known DID and device (golden test vector)
        let did = "did:zhtp:0123456789abcdef";
        let device = "test-device";

        // WHEN: Creating NodeId
        let node = NodeId::from_did_device(did, device).unwrap();

        // THEN: Produces expected hex output (locks derivation algorithm)
        // This is Blake3("ZHTP_NODE_V2:did:zhtp:0123456789abcdef:test-device") - FULL 32 bytes
        // Pre-computed golden vector to prevent algorithm drift
        let expected_hex = "b5e3496b8b72b2fa70614d54b32dcb94e9e0fc4574f7ab7530a8af6a795bcafc";
        let expected_bytes: [u8; 32] = [181, 227, 73, 107, 139, 114, 178, 250,
                                         112, 97, 77, 84, 179, 45, 203, 148,
                                         233, 224, 252, 69, 116, 247, 171, 117,
                                         48, 168, 175, 106, 121, 91, 202, 252];

        // Verify exact match (regression protection)
        assert_eq!(node.to_hex(), expected_hex,
            "Golden vector must match pre-computed Blake3 hash");
        assert_eq!(node.as_bytes(), &expected_bytes,
            "Golden vector bytes must match exactly");

        // Verify determinism by recreating
        let node2 = NodeId::from_did_device(did, device).unwrap();
        assert_eq!(node, node2,
            "Same inputs must always produce identical NodeId");
    }

    // ------------------------------------------------------------------------
    // GIVEN invalid DID (missing prefix, wrong format)
    // WHEN NodeId::from_did_device() is called
    // THEN it returns Err with descriptive message
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_invalid_did_missing_prefix() {
        // GIVEN: DID without "did:zhtp:" prefix
        let invalid_did = "abc123def456";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(invalid_did, device);

        // THEN: Error with clear message
        assert!(result.is_err(), "Should fail with invalid DID");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("did:zhtp:"), "Error should mention required prefix");
    }

    #[test]
    fn test_from_did_device_invalid_did_empty() {
        // GIVEN: Empty DID
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device("", device);

        // THEN: Error
        assert!(result.is_err(), "Should fail with empty DID");
    }

    #[test]
    fn test_from_did_device_invalid_did_wrong_prefix() {
        // GIVEN: Wrong DID prefix
        let invalid_did = "did:web:abc123";
        let device = "laptop";

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(invalid_did, device);

        // THEN: Error mentioning "did:zhtp:"
        assert!(result.is_err(), "Should fail with wrong DID method");
    }

    #[test]
    fn test_from_did_device_invalid_did_malformed() {
        // GIVEN: Malformed DIDs (various invalid formats)
        let device = "laptop";
        let malformed_dids: Vec<String> = vec![
            "did:zhtp:".to_string(),                    // Missing ID part
            "did:zhtp: abc".to_string(),                // Whitespace in ID
            "did:zhtp:abc def".to_string(),             // Space in ID
            "did:zhtp:abc!@#".to_string(),              // Special chars in ID
            format!("did:zhtp:{}", "a".repeat(500)),    // Extremely long ID
        ];

        for invalid_did in &malformed_dids {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(invalid_did, device);

            // THEN: Error
            assert!(result.is_err(), "Should fail with malformed DID: {}", invalid_did);
        }
    }

    // ------------------------------------------------------------------------
    // GIVEN invalid device name
    // WHEN NodeId::from_did_device() is called
    // THEN it returns Err with descriptive message
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_did_device_invalid_device_empty() {
        // GIVEN: Valid DID, empty device
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeId with empty device
        let result = NodeId::from_did_device(did, "");

        // THEN: Error
        assert!(result.is_err(), "Should fail with empty device name");
    }

    #[test]
    fn test_from_did_device_invalid_device_too_long() {
        // GIVEN: Device name > 64 characters
        let did = "did:zhtp:abc123def456";
        let long_device = "a".repeat(65);

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, &long_device);

        // THEN: Error mentioning length limit
        assert!(result.is_err(), "Should fail with device name > 64 chars");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("64"), "Error should mention max length");
    }

    #[test]
    fn test_from_did_device_valid_device_exactly_64_chars() {
        // GIVEN: Device name exactly 64 characters (boundary test)
        let did = "did:zhtp:abc123def456";
        let device_64 = "a".repeat(64);

        // WHEN: Creating NodeId
        let result = NodeId::from_did_device(did, &device_64);

        // THEN: Success (64 is valid, 65 is not)
        assert!(result.is_ok(), "Should accept device name of exactly 64 chars");
    }

    #[test]
    fn test_from_did_device_invalid_device_invalid_chars() {
        // GIVEN: Device with invalid characters
        let did = "did:zhtp:abc123def456";
        let invalid_devices = vec![
            "my laptop",      // space
            "phone!",         // exclamation
            "device@home",    // @
            "laptop#1",       // #
        ];

        for device in invalid_devices {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(did, device);

            // THEN: Error
            assert!(result.is_err(), "Should fail with invalid char in: {}", device);
        }
    }

    #[test]
    fn test_from_did_device_device_normalization_lowercase() {
        // GIVEN: Device names with different casing
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds with different cases
        let upper = NodeId::from_did_device(did, "LAPTOP").unwrap();
        let lower = NodeId::from_did_device(did, "laptop").unwrap();
        let mixed = NodeId::from_did_device(did, "LaPtOp").unwrap();

        // THEN: All produce same NodeId (normalized to lowercase)
        assert_eq!(upper, lower, "Uppercase should normalize to lowercase");
        assert_eq!(lower, mixed, "Mixed case should normalize to lowercase");
    }

    #[test]
    fn test_from_did_device_device_normalization_trim() {
        // GIVEN: Device names with leading/trailing spaces
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeIds
        let trimmed = NodeId::from_did_device(did, "laptop").unwrap();
        let with_spaces = NodeId::from_did_device(did, "  laptop  ").unwrap();

        // THEN: Spaces are trimmed, same NodeId
        assert_eq!(trimmed, with_spaces, "Should trim leading/trailing spaces");
    }

    #[test]
    fn test_from_did_device_invalid_device_whitespace_only() {
        // GIVEN: Device name with only whitespace
        let did = "did:zhtp:abc123def456";

        // WHEN: Creating NodeId with whitespace-only device
        let result = NodeId::from_did_device(did, "   ");

        // THEN: Error (trimmed to empty)
        assert!(result.is_err(), "Should fail when device trims to empty");
    }

    #[test]
    fn test_from_did_device_valid_special_chars() {
        // GIVEN: Device names with allowed special chars
        let did = "did:zhtp:abc123def456";
        let valid_devices = vec![
            "my-laptop",
            "device_1",
            "phone.backup",
            "test-device_2.primary",
        ];

        for device in valid_devices {
            // WHEN: Creating NodeId
            let result = NodeId::from_did_device(did, device);

            // THEN: Success
            assert!(result.is_ok(), "Should accept valid chars in: {}", device);
        }
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN hex conversion methods are called
    // THEN proper hex encoding/decoding works
    // ------------------------------------------------------------------------

    #[test]
    fn test_hex_conversion_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to hex and back
        let hex = original.to_hex();
        let decoded = NodeId::from_hex(&hex);

        // THEN: Round-trip succeeds
        assert!(decoded.is_ok(), "Hex decoding should succeed");
        assert_eq!(original, decoded.unwrap(), "Round-trip must preserve NodeId");
    }

    #[test]
    fn test_from_hex_valid_64_chars() {
        // GIVEN: Valid 64-character hex string (32 bytes)
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // WHEN: Creating NodeId from hex
        let result = NodeId::from_hex(hex);

        // THEN: Success
        assert!(result.is_ok(), "Should accept 64 hex chars");
    }

    #[test]
    fn test_from_hex_invalid_length() {
        // GIVEN: Hex strings of wrong length
        let invalid_hexes = vec![
            "abc",                    // too short
            "0123456789abcdef0123",   // 20 chars (10 bytes)
            "0123456789abcdef0123456789abcdef0123456789", // 42 chars (21 bytes)
        ];

        for hex in invalid_hexes {
            // WHEN: Creating NodeId
            let result = NodeId::from_hex(hex);

            // THEN: Error mentioning expected length
            assert!(result.is_err(), "Should fail with wrong length: {}", hex);
            let err = result.unwrap_err().to_string();
            assert!(err.contains("64"), "Error should mention expected 64 chars");
        }
    }

    #[test]
    fn test_from_hex_invalid_characters() {
        // GIVEN: Invalid hex strings (exactly 64 chars with invalid characters)
        let invalid_hexes = vec![
            "0123456789abcdeg0123456789abcdef0123456789abcdef0123456789abcdef", // 'g' not hex (pos 16, length 64)
            "0123456789abcde 0123456789abcdef0123456789abcdef0123456789abcdef", // space (pos 16, length 64)
            "zzzz456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 'z' not hex (pos 0-3, length 64)
        ];

        for hex in invalid_hexes {
            // WHEN: Creating NodeId
            let result = NodeId::from_hex(hex);

            // THEN: Error due to invalid characters (not length)
            assert_eq!(hex.len(), 64, "Test string should be exactly 64 chars");
            assert!(result.is_err(), "Should fail with invalid hex: {}", hex);
        }
    }

    #[test]
    fn test_from_hex_canonical_form_lowercase() {
        // GIVEN: Uppercase hex string (64 chars)
        let uppercase = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        // WHEN: Creating NodeId
        let result = NodeId::from_hex(uppercase);

        // THEN: Should accept and normalize to lowercase
        assert!(result.is_ok(), "Should accept uppercase hex");
        let node = result.unwrap();
        let output_hex = node.to_hex();

        // Verify output is lowercase
        assert!(output_hex.chars().all(|c| !c.is_uppercase()),
            "to_hex() must output lowercase");
        assert_eq!(output_hex, uppercase.to_lowercase(),
            "Hex should normalize to lowercase");
    }

    #[test]
    fn test_from_hex_rejects_0x_prefix() {
        // GIVEN: Hex with 0x prefix (66 chars total: "0x" + 64 hex chars)
        let hex_with_prefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // WHEN: Creating NodeId
        let result = NodeId::from_hex(hex_with_prefix);

        // THEN: Should reject (66 chars with prefix, not 64)
        assert!(result.is_err(), "Should reject 0x prefix");
    }

    #[test]
    fn test_from_hex_rejects_odd_length() {
        // GIVEN: Odd-length hex strings (would cause decode errors if length wasn't checked)
        let odd_hexes = vec![
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",   // 63 chars (odd)
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // 65 chars (odd)
        ];

        for odd_hex in odd_hexes {
            // WHEN: Creating NodeId
            let result = NodeId::from_hex(odd_hex);

            // THEN: Should reject (caught by length check, which also prevents odd-length decode errors)
            assert!(result.is_err(), "Should reject odd-length hex: {} chars", odd_hex.len());
        }
    }

    // ------------------------------------------------------------------------
    // GIVEN two NodeIds
    // WHEN xor_distance() is called
    // THEN correct Kademlia distance is returned
    // ------------------------------------------------------------------------

    #[test]
    fn test_xor_distance_self_is_zero() {
        // GIVEN: Same NodeId
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Calculating distance to self
        let distance = node.xor_distance(&node);

        // THEN: Distance is all zeros
        assert_eq!(distance, [0u8; 32], "Distance to self must be zero");
    }

    #[test]
    fn test_xor_distance_symmetric() {
        // GIVEN: Two different NodeIds
        let node1 = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", "phone").unwrap();

        // WHEN: Calculating distance both ways
        let dist_1_to_2 = node1.xor_distance(&node2);
        let dist_2_to_1 = node2.xor_distance(&node1);

        // THEN: Distance is symmetric
        assert_eq!(dist_1_to_2, dist_2_to_1, "XOR distance must be symmetric");
    }

    #[test]
    fn test_xor_distance_different_nodes() {
        // GIVEN: Two different NodeIds
        let node1 = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();
        let node2 = NodeId::from_did_device("did:zhtp:def456", "phone").unwrap();

        // WHEN: Calculating distance
        let distance = node1.xor_distance(&node2);

        // THEN: Distance is non-zero
        assert_ne!(distance, [0u8; 32], "Distance between different nodes must be non-zero");
    }

    #[test]
    fn test_xor_distance_known_values() {
        // GIVEN: Two NodeIds with known byte values
        let bytes1 = [0xAA; 32]; // All bits 10101010
        let bytes2 = [0x55; 32]; // All bits 01010101
        let node1 = NodeId::from_bytes(bytes1);
        let node2 = NodeId::from_bytes(bytes2);

        // WHEN: Calculating XOR distance
        let distance = node1.xor_distance(&node2);

        // THEN: XOR of 0xAA and 0x55 is 0xFF (all bits 1)
        let expected = [0xFF; 32];
        assert_eq!(distance, expected,
            "XOR distance must be bitwise XOR: 0xAA ^ 0x55 = 0xFF");
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN storage hash conversion is used
    // THEN proper 32-byte conversion works (no padding needed)
    // ------------------------------------------------------------------------

    #[test]
    fn test_storage_hash_conversion_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to Hash and back
        let hash = original.to_storage_hash();
        let restored = NodeId::from_storage_hash(&hash);

        // THEN: Round-trip preserves NodeId
        assert_eq!(original, restored, "NodeId → Hash → NodeId must preserve value");
    }

    #[test]
    fn test_to_storage_hash_32_bytes() {
        // GIVEN: A NodeId (32 bytes)
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to storage hash
        let hash = node.to_storage_hash();

        // THEN: Hash is 32 bytes (same as NodeId, no padding)
        assert_eq!(hash.as_bytes().len(), 32, "Storage Hash must be 32 bytes");

        // All 32 bytes match NodeId exactly
        assert_eq!(hash.as_bytes(), node.as_bytes());
    }

    #[test]
    fn test_from_storage_hash_exact_conversion() {
        // GIVEN: A Hash with all 32 bytes set
        let hash_bytes = [0xAB; 32];
        let hash = Hash::from_bytes(&hash_bytes);

        // WHEN: Converting to NodeId
        let node = NodeId::from_storage_hash(&hash);

        // THEN: All 32 bytes are preserved
        assert_eq!(node.as_bytes(), &hash_bytes);
    }

    // ------------------------------------------------------------------------
    // GIVEN a NodeId
    // WHEN Display trait is used
    // THEN hex representation is shown
    // ------------------------------------------------------------------------

    #[test]
    fn test_display_shows_hex() {
        // GIVEN: A NodeId
        let node = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Using Display trait
        let display = format!("{}", node);

        // THEN: Shows hex (64 chars)
        assert_eq!(display.len(), 64, "Display should show 64 hex chars");
        assert_eq!(display, node.to_hex(), "Display should match to_hex()");
    }

    // ------------------------------------------------------------------------
    // Property Tests - Additional invariants
    // ------------------------------------------------------------------------

    #[test]
    fn test_property_bytes_round_trip() {
        // GIVEN: A NodeId
        let original = NodeId::from_did_device("did:zhtp:abc123", "laptop").unwrap();

        // WHEN: Converting to bytes and back
        let bytes = *original.as_bytes();
        let restored = NodeId::from_bytes(bytes);

        // THEN: Round-trip preserves value
        assert_eq!(original, restored);
    }
}
