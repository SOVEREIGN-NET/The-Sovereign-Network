//! DaoPrefixRouter - Enforces dao. prefix semantics (Issue #657)
//!
//! This module implements Phase 2 of Domain Reservation Enforcement,
//! specifically the virtual `dao.X` resolution and registration rejection.
//!
//! # Invariants
//!
//! 1. **No Materialization**: `dao.X` is NEVER stored as a `NameRecord`
//! 2. **Virtual Resolution**: `dao.X` resolution is ALWAYS derived from `X.governance_pointer`
//! 3. **Registration Rejection**: `dao.` prefix at registration is ALWAYS rejected
//! 4. **Locality**: `dao.<name>` always binds to `<name>`, not to higher ancestors
//!
//! # Resolution Rules
//!
//! | Query | Resolution |
//! |-------|------------|
//! | `shoes.sov` | Normal domain record |
//! | `dao.shoes.sov` | GovernanceResolution from `shoes.sov` |
//! | `dao.dao.sov` | Invalid (dao.sov is reserved meta-governance) |
//! | `dao.food.dao.sov` | GovernanceResolution from `food.dao.sov` |
//! | `dao.sub.shoes.sov` | Controlled by `sub.shoes.sov`, not `shoes.sov` |
//!
//! # Special Reservations
//!
//! - `dao.sov` is reserved for meta-governance purposes and represents the root
//!   governance layer of the Sovereign Network itself.
//! - Any attempt to resolve `dao.dao.sov` is explicitly invalid because it would
//!   create a circular reference (dao.sov cannot govern itself through the dao prefix).
//! - This reservation ensures the integrity of the root governance structure.
//!
//! # Transfer Semantics
//!
//! When domain `X` is transferred:
//! - Default governance authority moves to new owner
//! - Existing delegations PERSIST across transfer
//! - New owner must explicitly revoke to change delegation

use super::types::{
    hash_name, normalize_name, DelegateTarget, GovernanceDelegation, GovernancePointer,
    GovernanceResolution, GovernanceStatus, NameHash, NameRecord, NameStatus, ResolutionResult,
    Timestamp,
};

/// DaoPrefixRouter - Enforces dao. prefix semantics
///
/// This is a stateless utility struct that provides:
/// - Registration validation (reject all dao.* names)
/// - Virtual resolution for dao.* queries
/// - Governance status derivation from parent state
pub struct DaoPrefixRouter;

/// Error type for dao prefix registration attempts
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaoPrefixRegistrationError {
    /// The name that was attempted to register
    pub attempted: String,
    /// Reason for rejection
    pub reason: &'static str,
}

impl std::fmt::Display for DaoPrefixRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cannot register '{}': {}",
            self.attempted, self.reason
        )
    }
}

impl std::error::Error for DaoPrefixRegistrationError {}

impl DaoPrefixRouter {
    // ========================================================================
    // Detection and Parsing
    // ========================================================================

    /// Check if a name is a dao-prefixed name (pre-check)
    ///
    /// This is a string-based pre-check. Authoritative logic should use
    /// `NameClass::DaoPrefixed` from the classification system.
    ///
    /// # Examples
    /// ```
    /// assert!(DaoPrefixRouter::is_dao_prefixed("dao.shoes.sov"));
    /// assert!(!DaoPrefixRouter::is_dao_prefixed("shoes.sov"));
    /// assert!(!DaoPrefixRouter::is_dao_prefixed("mydao.sov"));
    /// ```
    pub fn is_dao_prefixed(name: &str) -> bool {
        normalize_name(name).starts_with("dao.")
    }

    /// Extract the parent name from a dao-prefixed name
    ///
    /// Returns `None` if the name is not dao-prefixed.
    ///
    /// # Examples
    /// ```
    /// assert_eq!(DaoPrefixRouter::extract_parent("dao.shoes.sov"), Some("shoes.sov"));
    /// assert_eq!(DaoPrefixRouter::extract_parent("shoes.sov"), None);
    /// ```
    pub fn extract_parent(name: &str) -> Option<String> {
        let normalized = normalize_name(name);
        normalized.strip_prefix("dao.").map(|s| s.to_string())
    }

    /// Compute the parent hash for a dao-prefixed name
    ///
    /// Returns `None` if the name is not dao-prefixed.
    pub fn parent_hash(name: &str) -> Option<NameHash> {
        Self::extract_parent(name).map(|parent| hash_name(&parent))
    }

    // ========================================================================
    // Registration Validation
    // ========================================================================

    /// Validate a registration attempt
    ///
    /// Returns `Err` if attempting to register a `dao.*` name.
    /// `dao.*` names are virtual and cannot be registered.
    ///
    /// # Arguments
    /// * `name` - The name being registered
    ///
    /// # Returns
    /// * `Ok(())` - Name is not dao-prefixed, registration can proceed
    /// * `Err(DaoPrefixRegistrationError)` - Name is dao-prefixed, reject
    pub fn validate_registration(name: &str) -> Result<(), DaoPrefixRegistrationError> {
        if Self::is_dao_prefixed(name) {
            return Err(DaoPrefixRegistrationError {
                attempted: name.to_string(),
                reason: "dao.* names are virtual and cannot be registered. Governance is accessed via resolution, not registration.",
            });
        }
        Ok(())
    }

    // ========================================================================
    // Resolution
    // ========================================================================

    /// Check if a dao-prefixed resolution is valid
    ///
    /// `dao.dao.sov` is invalid because `dao.sov` is reserved meta-governance.
    pub fn is_valid_dao_prefix_resolution(name: &str) -> bool {
        if !Self::is_dao_prefixed(name) {
            return false;
        }

        let parent = match Self::extract_parent(name) {
            Some(p) => p,
            None => return false,
        };

        // dao.dao.sov is invalid - dao.sov is reserved meta-governance
        if parent == "dao.sov" {
            return false;
        }

        true
    }

    /// Derive governance status from parent record state
    pub fn derive_governance_status(parent: &NameRecord) -> GovernanceStatus {
        match &parent.status {
            NameStatus::Active => GovernanceStatus::Active,
            NameStatus::Suspended { .. } | NameStatus::SuspendedByParent => {
                GovernanceStatus::Suspended
            }
            NameStatus::RevocationPending { .. } | NameStatus::Revoked { .. } => {
                GovernanceStatus::Revoked
            }
            NameStatus::Expired { .. } | NameStatus::Released => GovernanceStatus::ParentExpired,
        }
    }

    /// Resolve governance for a dao.X query
    ///
    /// This is the core resolution function. Given a parent record,
    /// it constructs the `GovernanceResolution` that represents `dao.X`.
    ///
    /// # Arguments
    /// * `parent` - The parent domain record (X, not dao.X)
    /// * `governance_pointer` - The governance pointer from X
    /// * `governance_delegate` - Optional delegation from X
    /// * `current_time` - Current timestamp for delegation expiry check
    ///
    /// # Returns
    /// A `GovernanceResolution` representing the virtual dao.X record
    pub fn resolve_governance(
        parent: &NameRecord,
        governance_pointer: &GovernancePointer,
        governance_delegate: Option<&GovernanceDelegation>,
        current_time: Timestamp,
    ) -> GovernanceResolution {
        // Determine active delegate (if any and not expired)
        let delegate = governance_delegate.and_then(|d| {
            d.active_delegate(current_time)
                .map(|target| target.clone())
        });

        GovernanceResolution {
            parent_domain: parent.name.clone(),
            parent_hash: parent.name_hash,
            governance_contract: governance_pointer.contract,
            governance_did: governance_pointer.did.clone(),
            delegate,
            status: Self::derive_governance_status(parent),
        }
    }

    /// Full resolution flow for a name that might be dao-prefixed
    ///
    /// This is the high-level resolution function that handles both
    /// normal domains and dao.* queries.
    ///
    /// # Arguments
    /// * `name` - The name to resolve
    /// * `lookup_fn` - Function to look up a NameRecord by hash
    /// * `get_governance_fn` - Function to get governance config for a record
    /// * `current_time` - Current timestamp
    ///
    /// # Returns
    /// * `ResolutionResult::Domain` - For normal domain resolution
    /// * `ResolutionResult::Governance` - For dao.* resolution
    /// * `ResolutionResult::NotFound` - If parent doesn't exist
    /// * `ResolutionResult::Invalid` - If resolution is invalid (e.g., dao.dao.sov)
    pub fn resolve<F, G>(
        name: &str,
        lookup_fn: F,
        get_governance_fn: G,
        current_time: Timestamp,
    ) -> ResolutionResult
    where
        F: FnOnce(NameHash) -> Option<NameRecord>,
        G: FnOnce(&NameRecord) -> (GovernancePointer, Option<GovernanceDelegation>),
    {
        let normalized = normalize_name(name);

        // Check if this is a dao-prefixed query
        if !Self::is_dao_prefixed(&normalized) {
            // Not a dao.* query - this function shouldn't be called
            // Return Invalid to signal misuse
            return ResolutionResult::Invalid {
                reason: "Not a dao-prefixed name".to_string(),
            };
        }

        // Validate the dao prefix resolution
        if !Self::is_valid_dao_prefix_resolution(&normalized) {
            return ResolutionResult::Invalid {
                reason: "dao.dao.sov is invalid - dao.sov is reserved meta-governance".to_string(),
            };
        }

        // Extract parent name and compute hash
        let parent_name = match Self::extract_parent(&normalized) {
            Some(p) => p,
            None => {
                return ResolutionResult::Invalid {
                    reason: "Could not extract parent from dao-prefixed name".to_string(),
                }
            }
        };

        let parent_hash = hash_name(&parent_name);

        // Look up the parent record
        let parent_record = match lookup_fn(parent_hash) {
            Some(record) => record,
            None => return ResolutionResult::NotFound,
        };

        // Get governance configuration
        let (governance_pointer, governance_delegate) = get_governance_fn(&parent_record);

        // Resolve governance
        let resolution = Self::resolve_governance(
            &parent_record,
            &governance_pointer,
            governance_delegate.as_ref(),
            current_time,
        );

        ResolutionResult::Governance(resolution)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::root_registry::types::{
        NameClassification, NameStatus, SuspensionReason, VerificationLevel, timing,
    };

    fn make_test_record(name: &str, status: NameStatus) -> NameRecord {
        let expires_at_height = 1000000u64;
        #[allow(deprecated)]
        NameRecord {
            name: name.to_string(),
            name_hash: hash_name(name),
            owner: [1u8; 32],
            controller: None,
            zone_controller: None,
            parent: None,
            depth: 0,
            classification: NameClassification::Commercial,
            verification_level: VerificationLevel::L2VerifiedEntity,
            verification_proof: None,
            issuer: [1u8; 32],
            governance_pointer: None,
            governance_config: None,
            governance_delegate: None,
            status,
            registered_at: 100,
            // Phase 6: Block height fields
            expires_at_height,
            renewal_window_start_height: expires_at_height.saturating_sub(timing::RENEWAL_WINDOW_BLOCKS),
            renew_grace_until_height: expires_at_height + timing::EXPIRATION_GRACE_BLOCKS,
            revoke_grace_until_height: None,
            // Legacy fields (deprecated)
            expires_at: 1000000,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            custodian: None,
            transfer_lock_until: None,
            transfer_history: vec![],
            renewal_history: vec![],
        }
    }

    // ========================================================================
    // Detection Tests
    // ========================================================================

    #[test]
    fn test_is_dao_prefixed() {
        assert!(DaoPrefixRouter::is_dao_prefixed("dao.shoes.sov"));
        assert!(DaoPrefixRouter::is_dao_prefixed("DAO.SHOES.SOV")); // case insensitive
        assert!(DaoPrefixRouter::is_dao_prefixed("dao.food.dao.sov"));
        assert!(DaoPrefixRouter::is_dao_prefixed("dao.sub.shoes.sov"));

        assert!(!DaoPrefixRouter::is_dao_prefixed("shoes.sov"));
        assert!(!DaoPrefixRouter::is_dao_prefixed("mydao.sov"));
        assert!(!DaoPrefixRouter::is_dao_prefixed("food.dao.sov"));
        assert!(!DaoPrefixRouter::is_dao_prefixed("notdao.shoes.sov"));
    }

    #[test]
    fn test_extract_parent() {
        assert_eq!(
            DaoPrefixRouter::extract_parent("dao.shoes.sov"),
            Some("shoes.sov".to_string())
        );
        assert_eq!(
            DaoPrefixRouter::extract_parent("dao.food.dao.sov"),
            Some("food.dao.sov".to_string())
        );
        assert_eq!(
            DaoPrefixRouter::extract_parent("dao.sub.shoes.sov"),
            Some("sub.shoes.sov".to_string())
        );

        assert_eq!(DaoPrefixRouter::extract_parent("shoes.sov"), None);
        assert_eq!(DaoPrefixRouter::extract_parent("mydao.sov"), None);
    }

    #[test]
    fn test_parent_hash() {
        let parent_hash = DaoPrefixRouter::parent_hash("dao.shoes.sov");
        assert!(parent_hash.is_some());
        assert_eq!(parent_hash.unwrap(), hash_name("shoes.sov"));

        assert!(DaoPrefixRouter::parent_hash("shoes.sov").is_none());
    }

    // ========================================================================
    // Registration Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_registration_rejects_dao_prefix() {
        let result = DaoPrefixRouter::validate_registration("dao.shoes.sov");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.attempted, "dao.shoes.sov");
        assert!(err.reason.contains("virtual"));
    }

    #[test]
    fn test_validate_registration_allows_non_dao_prefix() {
        assert!(DaoPrefixRouter::validate_registration("shoes.sov").is_ok());
        assert!(DaoPrefixRouter::validate_registration("mydao.sov").is_ok());
        assert!(DaoPrefixRouter::validate_registration("food.dao.sov").is_ok());
    }

    #[test]
    fn test_validate_registration_rejects_even_with_ownership() {
        // Key test: Even if you own shoes.sov, you cannot register dao.shoes.sov
        let result = DaoPrefixRouter::validate_registration("dao.shoes.sov");
        assert!(result.is_err());
    }

    // ========================================================================
    // Resolution Validity Tests
    // ========================================================================

    #[test]
    fn test_dao_dao_sov_is_invalid() {
        assert!(!DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.dao.sov"));
    }

    #[test]
    fn test_dao_food_dao_sov_is_valid() {
        assert!(DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.food.dao.sov"));
    }

    #[test]
    fn test_dao_shoes_sov_is_valid() {
        assert!(DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.shoes.sov"));
    }

    #[test]
    fn test_dao_sub_shoes_sov_is_valid() {
        assert!(DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.sub.shoes.sov"));
    }

    // ========================================================================
    // Governance Status Derivation Tests
    // ========================================================================

    #[test]
    fn test_derive_governance_status_active() {
        let record = make_test_record("shoes.sov", NameStatus::Active);
        assert_eq!(
            DaoPrefixRouter::derive_governance_status(&record),
            GovernanceStatus::Active
        );
    }

    #[test]
    fn test_derive_governance_status_suspended() {
        let record = make_test_record(
            "shoes.sov",
            NameStatus::Suspended {
                reason: SuspensionReason::Emergency {
                    reason: "test".to_string(),
                },
            },
        );
        assert_eq!(
            DaoPrefixRouter::derive_governance_status(&record),
            GovernanceStatus::Suspended
        );
    }

    #[test]
    fn test_derive_governance_status_suspended_by_parent() {
        let record = make_test_record("shoes.sov", NameStatus::SuspendedByParent);
        assert_eq!(
            DaoPrefixRouter::derive_governance_status(&record),
            GovernanceStatus::Suspended
        );
    }

    #[test]
    fn test_derive_governance_status_expired() {
        let record = make_test_record(
            "shoes.sov",
            NameStatus::Expired {
                grace_ends: 2000000,
            },
        );
        assert_eq!(
            DaoPrefixRouter::derive_governance_status(&record),
            GovernanceStatus::ParentExpired
        );
    }

    // ========================================================================
    // Governance Resolution Tests
    // ========================================================================

    #[test]
    fn test_resolve_governance_basic() {
        let record = make_test_record("shoes.sov", NameStatus::Active);
        let pointer = GovernancePointer {
            contract: Some([42u8; 32]),
            did: Some("did:example:governance".to_string()),
        };

        let resolution =
            DaoPrefixRouter::resolve_governance(&record, &pointer, None, 1000);

        assert_eq!(resolution.parent_domain, "shoes.sov");
        assert_eq!(resolution.parent_hash, hash_name("shoes.sov"));
        assert_eq!(resolution.governance_contract, Some([42u8; 32]));
        assert_eq!(
            resolution.governance_did,
            Some("did:example:governance".to_string())
        );
        assert!(resolution.delegate.is_none());
        assert_eq!(resolution.status, GovernanceStatus::Active);
    }

    #[test]
    fn test_resolve_governance_with_active_delegation() {
        let record = make_test_record("shoes.sov", NameStatus::Active);
        let pointer = GovernancePointer::default();
        let delegation = GovernanceDelegation {
            delegate: DelegateTarget::Contract([99u8; 32]),
            expires_at: Some(2000), // Not expired at time 1000
        };

        let resolution =
            DaoPrefixRouter::resolve_governance(&record, &pointer, Some(&delegation), 1000);

        assert!(resolution.delegate.is_some());
        match resolution.delegate {
            Some(DelegateTarget::Contract(addr)) => assert_eq!(addr, [99u8; 32]),
            _ => panic!("Expected Contract delegate"),
        }
    }

    #[test]
    fn test_resolve_governance_with_expired_delegation() {
        let record = make_test_record("shoes.sov", NameStatus::Active);
        let pointer = GovernancePointer::default();
        let delegation = GovernanceDelegation {
            delegate: DelegateTarget::Contract([99u8; 32]),
            expires_at: Some(500), // Expired at time 1000
        };

        let resolution =
            DaoPrefixRouter::resolve_governance(&record, &pointer, Some(&delegation), 1000);

        // Delegation should not be active because it's expired
        assert!(resolution.delegate.is_none());
    }

    // ========================================================================
    // Full Resolution Flow Tests
    // ========================================================================

    #[test]
    fn test_resolve_dao_shoes_sov_parent_exists() {
        let shoes_record = make_test_record("shoes.sov", NameStatus::Active);
        let pointer = GovernancePointer {
            contract: Some([42u8; 32]),
            did: None,
        };

        let result = DaoPrefixRouter::resolve(
            "dao.shoes.sov",
            |_hash| Some(shoes_record.clone()),
            |_record| (pointer.clone(), None),
            1000,
        );

        match result {
            ResolutionResult::Governance(res) => {
                assert_eq!(res.parent_domain, "shoes.sov");
                assert_eq!(res.governance_contract, Some([42u8; 32]));
                assert_eq!(res.status, GovernanceStatus::Active);
            }
            _ => panic!("Expected Governance resolution"),
        }
    }

    #[test]
    fn test_resolve_dao_shoes_sov_parent_not_found() {
        let result = DaoPrefixRouter::resolve(
            "dao.shoes.sov",
            |_hash| None, // Parent doesn't exist
            |_record| (GovernancePointer::default(), None),
            1000,
        );

        assert_eq!(result, ResolutionResult::NotFound);
    }

    #[test]
    fn test_resolve_dao_dao_sov_invalid() {
        let result = DaoPrefixRouter::resolve(
            "dao.dao.sov",
            |_hash| Some(make_test_record("dao.sov", NameStatus::Active)),
            |_record| (GovernancePointer::default(), None),
            1000,
        );

        match result {
            ResolutionResult::Invalid { reason } => {
                assert!(reason.contains("dao.dao.sov"));
                assert!(reason.contains("invalid"));
            }
            _ => panic!("Expected Invalid resolution for dao.dao.sov"),
        }
    }

    #[test]
    fn test_resolve_dao_food_dao_sov_valid() {
        let food_record = make_test_record("food.dao.sov", NameStatus::Active);
        let pointer = GovernancePointer {
            contract: Some([88u8; 32]),
            did: None,
        };

        let result = DaoPrefixRouter::resolve(
            "dao.food.dao.sov",
            |_hash| Some(food_record.clone()),
            |_record| (pointer.clone(), None),
            1000,
        );

        match result {
            ResolutionResult::Governance(res) => {
                assert_eq!(res.parent_domain, "food.dao.sov");
                assert_eq!(res.governance_contract, Some([88u8; 32]));
            }
            _ => panic!("Expected Governance resolution for dao.food.dao.sov"),
        }
    }

    #[test]
    fn test_resolve_non_dao_prefix_returns_invalid() {
        let result = DaoPrefixRouter::resolve(
            "shoes.sov", // Not a dao.* query
            |_hash| Some(make_test_record("shoes.sov", NameStatus::Active)),
            |_record| (GovernancePointer::default(), None),
            1000,
        );

        match result {
            ResolutionResult::Invalid { reason } => {
                assert!(reason.contains("Not a dao-prefixed"));
            }
            _ => panic!("Expected Invalid for non-dao-prefixed query"),
        }
    }

    // ========================================================================
    // Delegation Tests
    // ========================================================================

    #[test]
    fn test_governance_delegation_is_active() {
        let delegation = GovernanceDelegation {
            delegate: DelegateTarget::Contract([1u8; 32]),
            expires_at: Some(2000),
        };

        assert!(delegation.is_active(1000)); // Before expiry
        assert!(delegation.is_active(1999)); // Just before expiry
        assert!(!delegation.is_active(2000)); // At expiry
        assert!(!delegation.is_active(3000)); // After expiry
    }

    #[test]
    fn test_governance_delegation_permanent() {
        let delegation = GovernanceDelegation {
            delegate: DelegateTarget::Did("did:example:delegate".to_string()),
            expires_at: None, // Permanent
        };

        assert!(delegation.is_active(1000));
        assert!(delegation.is_active(1000000));
        assert!(delegation.is_active(u64::MAX - 1));
    }

    #[test]
    fn test_governance_pointer_is_configured() {
        let empty = GovernancePointer::empty();
        assert!(!empty.is_configured());

        let with_contract = GovernancePointer {
            contract: Some([1u8; 32]),
            did: None,
        };
        assert!(with_contract.is_configured());

        let with_did = GovernancePointer {
            contract: None,
            did: Some("did:example:gov".to_string()),
        };
        assert!(with_did.is_configured());

        let with_both = GovernancePointer {
            contract: Some([1u8; 32]),
            did: Some("did:example:gov".to_string()),
        };
        assert!(with_both.is_configured());
    }
}
