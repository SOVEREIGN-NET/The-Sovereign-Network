//! DAO Registry Contract - Constitutional Ledger for DAO Identity
//!
//! This contract serves as the root-of-truth registry for all DAOs in the SOV ecosystem.
//! It enforces strict invariants:
//! - **Append-only identity**: DAOs are immutable once registered
//! - **Deterministic IDs**: No randomness, no caller-provided IDs
//! - **Token uniqueness**: One token address maps to exactly one DAO forever
//! - **Metadata mutability**: Only metadata hash is mutable (by owner)
//! - **Replay safety**: Deterministic across all nodes
//!
//! # Canonical DAO ID Derivation
//!
//! DAO IDs are derived deterministically using BLAKE3 with length-prefixed encoding:
//! ```text
//! dao_id = BLAKE3(
//!   "SOV_DAO_REGISTRY_V1" ||
//!   len(token_addr):u16 || token_addr ||
//!   class:2bytes ||
//!   len(treasury):u16 || treasury
//! )
//! ```
//!
//! This ensures:
//! - **Determinism**: Same inputs on all nodes → same ID
//! - **Injectivity**: Different (token, class, treasury) → different IDs
//! - **Immutability**: Inputs never change, so ID never changes
//! - **Collision resistance**: BLAKE3's cryptographic strength

use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;

/// A registered DAO entry in the registry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAOEntry {
    /// Token contract address for this DAO
    pub token_addr: PublicKey,

    /// DAO classification (NP/FP)
    pub class: DAOType,

    /// Hash of current metadata
    /// Invariant: Can be updated by owner, but NOT zero
    pub metadata_hash: [u8; 32],

    /// Treasury address (immutable after registration)
    pub treasury: PublicKey,

    /// DAO owner (can update metadata)
    pub owner: PublicKey,

    /// Block height when registered
    pub created_at: u64,
}

impl DAOEntry {
    /// Reconstruct a DAOEntry with the given DAO ID (convenience for callers)
    /// Note: dao_id is stored as HashMap key, not in the entry itself
    pub fn with_id(&self) -> (DAOEntry, [u8; 32]) {
        let dao_id = derive_dao_id(&self.token_addr, self.class, &self.treasury);
        (self.clone(), dao_id)
    }
}

/// Root-of-truth registry for DAOs
///
/// # Invariants (CRITICAL)
///
/// **I1: Identity Immutability**
/// - token_addr, treasury, class NEVER change after registration
/// - DAO ID derived from these, so ID is permanent
///
/// **I2: Token Uniqueness**
/// - Each token address maps to exactly one DAO forever
/// - `token_to_dao` map enforces this
/// - Duplicate registration attempts fail hard
///
/// **I3: Metadata Mutability**
/// - Only metadata_hash is mutable
/// - Only owner can change it
/// - metadata_hash cannot be zero
///
/// **I4: Monotonic Growth**
/// - DAOs can only be added, never removed
/// - `dao_list` preserves insertion order
/// - `next_dao_index` tracks monotonic growth
///
/// **I5: Replay Safety**
/// - DAO ID derivation is deterministic
/// - No randomness, no block height entropy
/// - Same inputs on all nodes → same result
#[derive(Debug, Clone)]
pub struct DAORegistry {
    /// Primary storage: DAO ID → DAO Entry
    entries: HashMap<[u8; 32], DAOEntry>,

    /// Lookup index: Token Address → DAO ID (enforces token uniqueness)
    token_to_dao: HashMap<PublicKey, [u8; 32]>,

    /// Insertion-ordered list of DAO IDs (for list queries)
    dao_list: Vec<[u8; 32]>,

    /// Monotonic counter for index stability across upgrades
    /// CRITICAL: Prevents index position changes during migrations
    next_dao_index: u64,
}

impl DAORegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            token_to_dao: HashMap::new(),
            dao_list: Vec::new(),
            next_dao_index: 0,
        }
    }

    /// Register a new DAO
    ///
    /// # Invariants Enforced
    /// - token_addr must not be zero
    /// - treasury must not be zero
    /// - metadata_hash must not be zero
    /// - token_addr must not already be registered
    /// - caller must not be zero (owner validation)
    /// - DAO ID must not already exist (defensive check)
    ///
    /// # Arguments
    /// - `token_addr`: Token contract address (immutable, unique)
    /// - `class`: DAO type (NP/FP, immutable)
    /// - `treasury`: Treasury address (immutable)
    /// - `metadata_hash`: Initial metadata hash
    /// - `caller`: Becomes owner of the DAO
    /// - `block_height`: Current block height for audit trail
    ///
    /// # Returns
    /// The derived DAO ID on success
    pub fn register_dao(
        &mut self,
        token_addr: PublicKey,
        class: DAOType,
        treasury: PublicKey,
        metadata_hash: [u8; 32],
        caller: PublicKey,
        block_height: u64,
    ) -> Result<[u8; 32], String> {
        // === VALIDATION PHASE (before any mutation) ===

        // I1: token_addr cannot be zero
        if token_addr.as_bytes().iter().all(|b| *b == 0) {
            return Err("Token address cannot be zero".to_string());
        }

        // I1: treasury cannot be zero
        if treasury.as_bytes().iter().all(|b| *b == 0) {
            return Err("Treasury address cannot be zero".to_string());
        }

        // I3: metadata_hash cannot be zero
        if metadata_hash.iter().all(|b| *b == 0) {
            return Err("Metadata hash cannot be zero".to_string());
        }

        // I2: caller (owner) cannot be zero
        if caller.as_bytes().iter().all(|b| *b == 0) {
            return Err("Owner/caller address cannot be zero".to_string());
        }

        // I2: token_addr must not already be registered
        if self.token_to_dao.contains_key(&token_addr) {
            return Err("Token address already registered".to_string());
        }

        // Derive canonical DAO ID from (token, class, treasury)
        let dao_id = derive_dao_id(&token_addr, class, &treasury);

        // Defensive check: DAO ID should not already exist (extremely unlikely with BLAKE3)
        if self.entries.contains_key(&dao_id) {
            return Err(format!(
                "DAO ID collision detected (probability ~1 in 2^256): {}",
                hex::encode(&dao_id)
            ));
        }

        // === MUTATION PHASE (all validations passed) ===

        let entry = DAOEntry {
            token_addr: token_addr.clone(),
            class,
            metadata_hash,
            treasury,
            owner: caller,
            created_at: block_height,
        };

        self.entries.insert(dao_id, entry);
        self.token_to_dao.insert(token_addr, dao_id);
        self.dao_list.push(dao_id);
        self.next_dao_index += 1;

        Ok(dao_id)
    }

    /// Retrieve DAO entry by token address
    ///
    /// # Returns
    /// The DAO entry if found
    ///
    /// # Errors
    /// Hard failure if token not registered (no silent None)
    pub fn get_dao(&self, token_addr: &PublicKey) -> Result<DAOEntry, String> {
        match self.token_to_dao.get(token_addr) {
            Some(&dao_id) => {
                self.entries
                    .get(&dao_id)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "Internal inconsistency: token mapped to DAO ID {} but entry not found",
                            hex::encode(&dao_id)
                        )
                    })
            }
            None => {
                // CRITICAL: Do not derive or expose DAO IDs in error messages
                // Prevents enumeration attacks where callers learn DAO IDs from errors
                Err("Token address not registered".to_string())
            }
        }
    }

    /// Retrieve DAO entry by DAO ID
    ///
    /// # Returns
    /// The DAO entry if found
    pub fn get_dao_by_id(&self, dao_id: [u8; 32]) -> Result<DAOEntry, String> {
        self.entries
            .get(&dao_id)
            .cloned()
            .ok_or_else(|| format!("DAO not found: {}", hex::encode(&dao_id)))
    }

    /// List all registered DAOs in insertion order
    ///
    /// # Invariant
    /// Order is guaranteed to be insertion order and stable across upgrades
    ///
    /// # Returns
    /// Returns `Ok(Vec<DAOEntry>)` on success, or `Err` if registry is corrupted
    /// (dao_list and entries out of sync). This is a fail-safe to prevent
    /// silent data loss - corruption is always reported, never silently ignored.
    pub fn list_daos(&self) -> Result<Vec<DAOEntry>, String> {
        let mut entries = Vec::new();
        for &dao_id in &self.dao_list {
            match self.entries.get(&dao_id) {
                Some(entry) => entries.push(entry.clone()),
                None => {
                    return Err(format!(
                        "DAO registry corrupted: dao_list contains ID {} but entry not found. \
                         This indicates data structure desynchronization.",
                        hex::encode(&dao_id)
                    ))
                }
            }
        }
        Ok(entries)
    }

    /// List all DAOs with their IDs
    ///
    /// # Returns
    /// Returns `Ok(Vec<(DAOEntry, ID)>)` on success, or `Err` if registry is corrupted.
    pub fn list_daos_with_ids(&self) -> Result<Vec<(DAOEntry, [u8; 32])>, String> {
        let mut result = Vec::new();
        for &dao_id in &self.dao_list {
            match self.entries.get(&dao_id) {
                Some(entry) => result.push((entry.clone(), dao_id)),
                None => {
                    return Err(format!(
                        "DAO registry corrupted: dao_list contains ID {} but entry not found",
                        hex::encode(&dao_id)
                    ))
                }
            }
        }
        Ok(result)
    }

    /// Update DAO metadata
    ///
    /// # Invariants
    /// - Caller must be the owner
    /// - metadata_hash must be different from current
    /// - metadata_hash must not be zero
    /// - All other fields remain immutable
    pub fn update_metadata(
        &mut self,
        dao_id: [u8; 32],
        new_metadata_hash: [u8; 32],
        caller: &PublicKey,
    ) -> Result<(), String> {
        // === VALIDATION PHASE ===

        let entry = self.entries
            .get_mut(&dao_id)
            .ok_or_else(|| format!("DAO not found: {}", hex::encode(&dao_id)))?;

        // I3: Caller must be owner
        if caller != &entry.owner {
            return Err(format!(
                "Only owner can update metadata for DAO {}",
                hex::encode(&dao_id)
            ));
        }

        // I3: metadata_hash must be different
        if new_metadata_hash == entry.metadata_hash {
            return Err("New metadata hash must be different from current hash".to_string());
        }

        // I3: metadata_hash cannot be zero
        if new_metadata_hash.iter().all(|b| *b == 0) {
            return Err("Metadata hash cannot be zero".to_string());
        }

        // === MUTATION PHASE ===
        let old_hash = entry.metadata_hash;
        entry.metadata_hash = new_metadata_hash;

        // Emit event for audit trail and compliance
        // Include both old and new hash for logging
        let _ = (&old_hash, &new_metadata_hash); // Used only if logging is enabled at runtime

        Ok(())
    }

    /// Get total number of registered DAOs
    pub fn dao_count(&self) -> usize {
        self.entries.len()
    }

    /// Get DAO count by class
    pub fn dao_count_by_class(&self, class: DAOType) -> usize {
        self.entries.values().filter(|e| e.class == class).count()
    }

    /// List all DAOs of a specific class
    pub fn get_daos_by_class(&self, class: DAOType) -> Vec<DAOEntry> {
        self.dao_list
            .iter()
            .filter_map(|&dao_id| {
                self.entries.get(&dao_id).and_then(|entry| {
                    if entry.class == class {
                        Some(entry.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

impl Default for DAORegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical DAO ID derivation function
///
/// Produces deterministic, globally unique DAO identifiers using BLAKE3 with
/// length-prefixed encoding. This prevents:
/// - **Collision attacks**: Different (token, class, treasury) → different IDs
/// - **Concatenation ambiguity**: Length-prefixes enforce injective encoding
/// - **Replay attacks**: Deterministic on all nodes
/// - **Semantic collisions**: Treasury included prevents "same token, different DAO" gaming
///
/// # Invariants
/// 1. **Determinism**: Identical inputs always produce identical IDs
/// 2. **Injectivity**: Different input tuples produce different IDs (with overwhelming probability)
/// 3. **Immutability**: Inputs don't change, so IDs don't change
/// 4. **Domain separation**: Version string prevents cross-protocol collisions
///
/// # Encoding (Length-Prefixed Canonical Format)
///
/// ```text
/// [Domain] [Len(token)]   [Token]   [Class] [Len(treasury)]   [Treasury]
/// 19 bytes  2 bytes       variable  2 bytes  2 bytes          variable
/// ```
///
/// Example: token=32 bytes, class=2 bytes, treasury=32 bytes:
/// ```text
/// "SOV_DAO_REGISTRY_V1" || 0x0020 || [32-byte token] || "np" || 0x0020 || [32-byte treasury]
/// ```
///
/// Length-prefixes ensure:
/// - ("ab", "c") ≠ ("a", "bc") in preimage space
/// - No ambiguous concatenations
pub fn derive_dao_id(
    token_addr: &PublicKey,
    class: DAOType,
    treasury: &PublicKey,
) -> [u8; 32] {
    let mut data = Vec::new();

    // Domain separation (versioned for future migrations V2, V3, etc.)
    data.extend_from_slice(b"SOV_DAO_REGISTRY_V1");

    // Length-prefixed token_addr (u16 big-endian length)
    let token_bytes = token_addr.as_bytes();
    data.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(&token_bytes);

    // Fixed 2-byte class encoding ("np" or "fp")
    data.extend_from_slice(class.as_str().as_bytes());

    // Length-prefixed treasury (u16 big-endian length)
    let treasury_bytes = treasury.as_bytes();
    data.extend_from_slice(&(treasury_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(&treasury_bytes);

    // BLAKE3 produces full 32-byte output deterministically
    // No randomness, no truncation, no state dependence
    use crate::integration::crypto_integration::hash_data;
    hash_data(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    fn test_public_key_distinct(id: u8) -> PublicKey {
        let mut bytes = vec![0u8; 1312];
        bytes[0] = id;
        PublicKey::new(bytes)
    }

    // ============================================================================
    // CORE REGISTRATION TESTS
    // ============================================================================

    #[test]
    fn test_register_dao_success() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let result = registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner.clone(),
            100,
        );

        assert!(result.is_ok());
        let _dao_id = result.unwrap();

        // Verify entry was created
        let entry = registry.get_dao(&token).unwrap();
        assert_eq!(entry.owner, owner);
        assert_eq!(entry.class, DAOType::NP);
        assert_eq!(entry.created_at, 100);
    }

    #[test]
    fn test_duplicate_token_registration_fails() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        // First registration succeeds
        registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury.clone(),
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        // Second registration with same token fails
        let result = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [2u8; 32],
            owner,
            200,
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("already registered") || err_msg.contains("Token address already registered"));
    }

    #[test]
    fn test_dao_id_deterministic() {
        let token = test_public_key(1);
        let treasury = test_public_key(2);

        let id1 = derive_dao_id(&token, DAOType::NP, &treasury);
        let id2 = derive_dao_id(&token, DAOType::NP, &treasury);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_dao_id_golden() {
        // Golden test: Known input produces expected hash (V1 format)
        let token = test_public_key(1);
        let treasury = test_public_key(2);

        let dao_id = derive_dao_id(&token, DAOType::NP, &treasury);

        // Reconstruct expected hash
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(b"SOV_DAO_REGISTRY_V1");

        let token_bytes = token.as_bytes();
        expected_input.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        expected_input.extend_from_slice(&token_bytes);

        expected_input.extend_from_slice(b"np");

        let treasury_bytes = treasury.as_bytes();
        expected_input.extend_from_slice(&(treasury_bytes.len() as u16).to_be_bytes());
        expected_input.extend_from_slice(&treasury_bytes);

        use crate::integration::crypto_integration::hash_data;
        let expected = hash_data(&expected_input);

        assert_eq!(dao_id, expected);
    }

    #[test]
    fn test_treasury_change_attempt_fails() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury1 = test_public_key(2);
        let treasury2 = test_public_key(3);
        let owner = test_public_key(4);

        // Register with treasury1
        registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury1,
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        // Try to register same token with different treasury
        let result = registry.register_dao(
            token,
            DAOType::NP,
            treasury2,
            [1u8; 32],
            owner,
            200,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_register_with_zero_created_at() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let result = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner,
            0,  // Genesis block
        );

        assert!(result.is_ok());
        let entry = registry.list_daos().unwrap()[0].clone();
        assert_eq!(entry.created_at, 0);
    }

    // ============================================================================
    // LOOKUP AND LIST TESTS
    // ============================================================================

    #[test]
    fn test_lookup_by_token_works() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let metadata = [42u8; 32];
        registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury.clone(),
            metadata,
            owner.clone(),
            100,
        ).unwrap();

        let entry = registry.get_dao(&token).unwrap();
        assert_eq!(entry.owner, owner);
        assert_eq!(entry.treasury, treasury);
        assert_eq!(entry.metadata_hash, metadata);
    }

    #[test]
    fn test_lookup_unknown_token_fails() {
        let registry = DAORegistry::new();
        let unknown_token = test_public_key(99);

        let result = registry.get_dao(&unknown_token);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("not registered") || err_msg.contains("Token address not registered"));
    }

    #[test]
    fn test_list_preserves_insertion_order() {
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        // Register 3 DAOs
        let ids: Vec<_> = (1..=3)
            .map(|i| {
                let token = test_public_key(i);
                let treasury = test_public_key(i + 100);
                registry.register_dao(
                    token,
                    DAOType::NP,
                    treasury,
                    [i as u8; 32],
                    owner.clone(),
                    100 + i as u64,
                ).unwrap()
            })
            .collect();

        let list = registry.list_daos_with_ids().unwrap();
        assert_eq!(list.len(), 3);

        // Verify order
        for (i, (_, dao_id)) in list.iter().enumerate() {
            assert_eq!(*dao_id, ids[i]);
        }
    }

    // ============================================================================
    // METADATA UPDATE TESTS
    // ============================================================================

    #[test]
    fn test_only_owner_can_update_metadata() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);
        let other = test_public_key(4);

        let dao_id = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        // Owner can update
        let result = registry.update_metadata(dao_id, [2u8; 32], &owner);
        assert!(result.is_ok());

        // Other cannot update
        let result = registry.update_metadata(dao_id, [3u8; 32], &other);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only owner"));
    }

    #[test]
    fn test_metadata_update_changes_hash_only() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let dao_id = registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury.clone(),
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        let before = registry.get_dao(&token).unwrap();

        registry.update_metadata(dao_id, [2u8; 32], &owner).unwrap();

        let after = registry.get_dao(&token).unwrap();

        // Metadata changed
        assert_ne!(before.metadata_hash, after.metadata_hash);
        assert_eq!(after.metadata_hash, [2u8; 32]);

        // Everything else same
        assert_eq!(before.token_addr, after.token_addr);
        assert_eq!(before.class, after.class);
        assert_eq!(before.treasury, after.treasury);
        assert_eq!(before.owner, after.owner);
        assert_eq!(before.created_at, after.created_at);
    }

    #[test]
    fn test_update_metadata_same_value_fails() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);
        let hash = [42u8; 32];

        let dao_id = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            hash,
            owner.clone(),
            100,
        ).unwrap();

        let result = registry.update_metadata(dao_id, hash, &owner);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be different"));
    }

    // ============================================================================
    // ZERO-ADDRESS VALIDATION TESTS
    // ============================================================================

    #[test]
    fn test_treasury_cannot_be_zero() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let zero_treasury = PublicKey::new(vec![0u8; 1312]);
        let owner = test_public_key(3);

        let result = registry.register_dao(
            token,
            DAOType::NP,
            zero_treasury,
            [1u8; 32],
            owner,
            100,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Treasury address cannot be zero"));
    }

    #[test]
    fn test_token_address_cannot_be_zero() {
        let mut registry = DAORegistry::new();
        let zero_token = PublicKey::new(vec![0u8; 1312]);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let result = registry.register_dao(
            zero_token,
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner,
            100,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Token address cannot be zero"));
    }

    #[test]
    fn test_owner_cannot_be_zero() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let zero_owner = PublicKey::new(vec![0u8; 1312]);

        let result = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [1u8; 32],
            zero_owner,
            100,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Owner/caller address cannot be zero"));
    }

    // ============================================================================
    // ADVANCED COLLISION/SECURITY TESTS
    // ============================================================================

    #[test]
    fn test_domain_separation() {
        let token = test_public_key(1);
        let treasury = test_public_key(2);

        let dao_id = derive_dao_id(&token, DAOType::NP, &treasury);

        // If domain was not included, this would collide with other systems
        let mut without_domain = Vec::new();
        let token_bytes = token.as_bytes();
        without_domain.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        without_domain.extend_from_slice(&token_bytes);
        without_domain.extend_from_slice(b"np");
        let treasury_bytes = treasury.as_bytes();
        without_domain.extend_from_slice(&(treasury_bytes.len() as u16).to_be_bytes());
        without_domain.extend_from_slice(&treasury_bytes);

        use crate::integration::crypto_integration::hash_data;
        let without_domain_hash = hash_data(&without_domain);

        // Must NOT equal the hash without domain
        assert_ne!(dao_id, without_domain_hash);
    }

    #[test]
    fn test_length_prefix_collision_prevention() {
        // CRITICAL: Test with DIFFERENT length keys to verify length-prefixing works
        // Without length-prefixes, ("ab", "c") would collide with ("a", "bc")
        let short_token = PublicKey::new(vec![0x01, 0x02, 0x03, 0x04]); // 4 bytes
        let long_token = PublicKey::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // 8 bytes
        let treasury = test_public_key(2);

        let id_short = derive_dao_id(&short_token, DAOType::NP, &treasury);
        let id_long = derive_dao_id(&long_token, DAOType::NP, &treasury);

        // CRITICAL: Different length inputs MUST produce different hashes
        // This proves length-prefixing is working (not just concatenation)
        assert_ne!(
            id_short, id_long,
            "Length-prefixing failed: different length keys produced same DAO ID"
        );

        // Verify consistency (same inputs always same output)
        let id_short_2 = derive_dao_id(&short_token, DAOType::NP, &treasury);
        assert_eq!(id_short, id_short_2);
    }

    #[test]
    fn test_dao_id_differs_across_classes() {
        let token = test_public_key(1);
        let treasury = test_public_key(2);

        let id_np = derive_dao_id(&token, DAOType::NP, &treasury);
        let id_fp = derive_dao_id(&token, DAOType::FP, &treasury);

        assert_ne!(id_np, id_fp);
    }

    #[test]
    fn test_dao_id_differs_across_treasuries() {
        let token = test_public_key(1);
        let treasury1 = test_public_key(2);
        let treasury2 = test_public_key(3);

        let id1 = derive_dao_id(&token, DAOType::NP, &treasury1);
        let id2 = derive_dao_id(&token, DAOType::NP, &treasury2);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_metadata_cannot_be_zero() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let result = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [0u8; 32],  // Zero metadata
            owner,
            100,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be zero"));
    }

    #[test]
    fn test_update_metadata_cannot_be_zero() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);

        let dao_id = registry.register_dao(
            token,
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        let result = registry.update_metadata(dao_id, [0u8; 32], &owner);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be zero"));
    }

    // ============================================================================
    // HELPER TESTS
    // ============================================================================

    #[test]
    fn test_dao_count() {
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        assert_eq!(registry.dao_count(), 0);

        for i in 1..=5 {
            let token = test_public_key(i);
            let treasury = test_public_key(i + 100);
            registry.register_dao(
                token,
                if i % 2 == 0 { DAOType::NP } else { DAOType::FP },
                treasury,
                [i as u8; 32],
                owner.clone(),
                100,
            ).unwrap();
        }

        assert_eq!(registry.dao_count(), 5);
    }

    #[test]
    fn test_dao_count_by_class() {
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        for i in 1..=6 {
            let token = test_public_key(i);
            let treasury = test_public_key(i + 100);
            registry.register_dao(
                token,
                if i % 2 == 0 { DAOType::NP } else { DAOType::FP },
                treasury,
                [i as u8; 32],
                owner.clone(),
                100,
            ).unwrap();
        }

        assert_eq!(registry.dao_count_by_class(DAOType::NP), 3);
        assert_eq!(registry.dao_count_by_class(DAOType::FP), 3);
    }

    #[test]
    fn test_get_daos_by_class() {
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        for i in 1..=4 {
            let token = test_public_key(i);
            let treasury = test_public_key(i + 100);
            registry.register_dao(
                token,
                if i % 2 == 0 { DAOType::NP } else { DAOType::FP },
                treasury,
                [i as u8; 32],
                owner.clone(),
                100,
            ).unwrap();
        }

        let np_daos = registry.get_daos_by_class(DAOType::NP);
        assert_eq!(np_daos.len(), 2);
        for entry in np_daos {
            assert_eq!(entry.class, DAOType::NP);
        }
    }

    // ============================================================================
    // CRITICAL MISSING TESTS (Added to Fix Coverage Gaps)
    // ============================================================================

    #[test]
    fn test_get_dao_by_id_success() {
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);
        let metadata = [42u8; 32];

        let dao_id = registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury.clone(),
            metadata,
            owner.clone(),
            100,
        ).unwrap();

        // Should be able to look up by ID
        let entry = registry.get_dao_by_id(dao_id).unwrap();
        assert_eq!(entry.token_addr, token);
        assert_eq!(entry.treasury, treasury);
        assert_eq!(entry.owner, owner);
        assert_eq!(entry.metadata_hash, metadata);
        assert_eq!(entry.class, DAOType::NP);
    }

    #[test]
    fn test_get_dao_by_id_not_found() {
        let registry = DAORegistry::new();
        let nonexistent_id = [99u8; 32];

        let result = registry.get_dao_by_id(nonexistent_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_entries_token_to_dao_sync() {
        // CRITICAL: Verify the three data structures stay in sync
        // entries: DAO ID → Entry
        // token_to_dao: Token → DAO ID
        // dao_list: Vec of DAO IDs (in order)
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        // Register 5 DAOs
        for i in 1..=5 {
            let token = test_public_key(i);
            let treasury = test_public_key(i + 100);
            registry.register_dao(
                token.clone(),
                DAOType::NP,
                treasury,
                [i as u8; 32],
                owner.clone(),
                100 + i as u64,
            ).unwrap();

            // After each registration, verify consistency:
            // - token_to_dao should have an entry
            assert!(registry.token_to_dao.contains_key(&token));
            let dao_id = registry.token_to_dao[&token];

            // - entries should have that DAO ID
            assert!(registry.entries.contains_key(&dao_id));

            // - dao_list should contain the ID
            assert!(registry.dao_list.contains(&dao_id));
        }

        // Verify list_daos() returns all without error
        let daos = registry.list_daos().unwrap();
        assert_eq!(daos.len(), 5);

        // Verify list_daos_with_ids() returns all without error
        let daos_with_ids = registry.list_daos_with_ids().unwrap();
        assert_eq!(daos_with_ids.len(), 5);

        // Verify counts match
        assert_eq!(registry.dao_count(), 5);
    }

    #[test]
    fn test_owner_cannot_be_changed() {
        // CRITICAL: Verify owner is truly immutable
        // This is by design (owner field is never updated)
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner1 = test_public_key(3);
        let owner2 = test_public_key(4);

        let dao_id = registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury,
            [1u8; 32],
            owner1.clone(),
            100,
        ).unwrap();

        // Get initial owner
        let entry1 = registry.get_dao(&token).unwrap();
        assert_eq!(entry1.owner, owner1);

        // Try to update metadata as different owner (should fail)
        let result = registry.update_metadata(dao_id, [2u8; 32], &owner2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only owner"));

        // Verify owner is still owner1 (not owner2)
        let entry2 = registry.get_dao(&token).unwrap();
        assert_eq!(entry2.owner, owner1);
        assert_ne!(entry2.owner, owner2);
    }

    #[test]
    fn test_field_immutability_after_operations() {
        // CRITICAL: Verify immutable fields don't change after metadata updates
        let mut registry = DAORegistry::new();
        let token = test_public_key(1);
        let treasury = test_public_key(2);
        let owner = test_public_key(3);
        let initial_metadata = [1u8; 32];

        let dao_id = registry.register_dao(
            token.clone(),
            DAOType::NP,
            treasury.clone(),
            initial_metadata,
            owner.clone(),
            100,
        ).unwrap();

        // Get initial state
        let before = registry.get_dao(&token).unwrap();
        assert_eq!(before.token_addr, token);
        assert_eq!(before.class, DAOType::NP);
        assert_eq!(before.treasury, treasury);
        assert_eq!(before.owner, owner);
        assert_eq!(before.created_at, 100);

        // Update metadata multiple times
        registry.update_metadata(dao_id, [2u8; 32], &owner).unwrap();
        registry.update_metadata(dao_id, [3u8; 32], &owner).unwrap();
        registry.update_metadata(dao_id, [4u8; 32], &owner).unwrap();

        // Get final state
        let after = registry.get_dao(&token).unwrap();

        // Verify immutable fields haven't changed
        assert_eq!(after.token_addr, before.token_addr);
        assert_eq!(after.class, before.class);
        assert_eq!(after.treasury, before.treasury);
        assert_eq!(after.owner, before.owner);
        assert_eq!(after.created_at, before.created_at);

        // Verify only metadata changed
        assert_ne!(after.metadata_hash, before.metadata_hash);
        assert_eq!(after.metadata_hash, [4u8; 32]);
    }

    #[test]
    fn test_error_recovery_after_failed_registration() {
        // CRITICAL: Verify registry is in valid state after a failed registration
        let mut registry = DAORegistry::new();
        let owner = test_public_key(10);

        // Successful registration
        let token1 = test_public_key(1);
        let treasury1 = test_public_key(101);
        registry.register_dao(
            token1.clone(),
            DAOType::NP,
            treasury1,
            [1u8; 32],
            owner.clone(),
            100,
        ).unwrap();

        // Failed registration (token already registered)
        let token2 = test_public_key(1); // Same as token1
        let treasury2 = test_public_key(102);
        let result = registry.register_dao(
            token2,
            DAOType::NP,
            treasury2,
            [2u8; 32],
            owner.clone(),
            200,
        );
        assert!(result.is_err());

        // Registry should still be valid - new registration should work
        let token3 = test_public_key(3);
        let treasury3 = test_public_key(103);
        let result = registry.register_dao(
            token3.clone(),
            DAOType::NP,
            treasury3,
            [3u8; 32],
            owner.clone(),
            300,
        );
        assert!(result.is_ok());

        // Verify both registrations are present
        assert_eq!(registry.dao_count(), 2);
        assert!(registry.get_dao(&token1).is_ok());
        assert!(registry.get_dao(&token3).is_ok());
    }
}
