//! Domain Operations and Invariant Guards
//!
//! [Issue #655] Phase 0: Domain Reservation Enforcement - Operation Invariants
//!
//! Implements the operation pre/postconditions from the specification:
//! - K1: register(name, owner, verification_proof)
//! - K2: renew(name, duration)
//! - K3: transfer(name, new_owner)
//! - K4: delegate(parent_name, child_label, delegate_to, duration?)
//! - K5: revoke(name, authority, reason)
//! - K6: resolve(name)

use super::types::*;
use super::validation::{ParsedName, ValidationError, ValidationResult};
use thiserror::Error;

// ============================================================================
// Operation Errors
// ============================================================================

/// Errors that can occur during domain operations
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationError {
    /// Validation failed
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Domain already exists
    #[error("Domain '{name}' already exists")]
    AlreadyExists { name: String },

    /// Domain not found
    #[error("Domain '{name}' not found")]
    NotFound { name: String },

    /// Domain is not in active state
    #[error("Domain '{name}' is not active (status: {status})")]
    NotActive { name: String, status: String },

    /// Not authorized for this operation
    #[error("Not authorized: {reason}")]
    Unauthorized { reason: String },

    /// Transfer lock is active
    #[error("Domain '{name}' has an active transfer lock until {lock_until}")]
    TransferLocked { name: String, lock_until: Timestamp },

    /// Domain is in grace period
    #[error("Domain '{name}' is in grace period")]
    InGracePeriod { name: String },

    /// Domain is suspended
    #[error("Domain '{name}' is suspended")]
    Suspended { name: String },

    /// Cannot renew in current state
    #[error("Cannot renew domain '{name}' in current state")]
    CannotRenew { name: String },

    /// Parent domain not found
    #[error("Parent domain '{parent}' not found")]
    ParentNotFound { parent: String },

    /// Parent domain not active
    #[error("Parent domain '{parent}' is not active")]
    ParentNotActive { parent: String },

    /// Delegation depth exceeded
    #[error("Delegation depth exceeded (max: {max}, requested: {requested})")]
    DepthExceeded { max: usize, requested: usize },

    /// Fee not paid
    #[error("Required fee not paid: {required} (paid: {paid})")]
    FeeNotPaid { required: u64, paid: u64 },

    /// Welfare DAO approval required
    #[error("Welfare DAO approval required for '{name}'")]
    WelfareApprovalRequired { name: String },

    /// Invalid revocation authority
    #[error("Invalid revocation authority for this operation")]
    InvalidRevocationAuthority,

    /// Appeal already filed
    #[error("Appeal already filed for domain '{name}'")]
    AppealAlreadyFiled { name: String },

    /// No appeal exists
    #[error("No appeal exists for domain '{name}'")]
    NoAppealExists { name: String },

    /// Invalid state transition
    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    /// Duration invalid
    #[error("Invalid duration: {reason}")]
    InvalidDuration { reason: String },
}

/// Result type for operations
pub type OperationResult<T> = Result<T, OperationError>;

// ============================================================================
// Registration Guards (K1)
// ============================================================================

/// Guard checks for the register operation
///
/// # Preconditions (from spec K1)
/// - Name passes classification validation
/// - Name not already registered (or in Released state)
/// - Caller has authority to register in target namespace
/// - Verification level meets minimum for classification
/// - Fee paid and routed through FeeRouter
/// - For welfare delegated: issuing DAO has approved
pub struct RegisterGuard;

impl RegisterGuard {
    /// Check all preconditions for registration
    pub fn check_preconditions(
        parsed: &ParsedName,
        owner_verification: VerificationLevel,
        existing_record: Option<&NameRecord>,
        fee_paid: u64,
        required_fee: u64,
        has_welfare_approval: bool,
    ) -> OperationResult<()> {
        // Precondition 1: Name passes classification validation
        // (Already validated in ParsedName creation)

        // Precondition 2: Name not already registered (or in Released state)
        if let Some(record) = existing_record {
            if !record.status.is_available() {
                return Err(OperationError::AlreadyExists {
                    name: parsed.full_name.clone(),
                });
            }
        }

        // Precondition 3: Caller has authority to register in target namespace
        // (Checked by classification - commercial requires L2, welfare requires DAO approval)

        // Precondition 4: Verification level meets minimum for classification
        super::validation::validate_verification_level(
            parsed.classification,
            owner_verification,
        )?;

        // Precondition 5: Fee paid and routed through FeeRouter
        if fee_paid < required_fee {
            return Err(OperationError::FeeNotPaid {
                required: required_fee,
                paid: fee_paid,
            });
        }

        // Precondition 6: For welfare delegated: issuing DAO has approved
        if parsed.classification == NameClassification::WelfareDelegated && !has_welfare_approval {
            return Err(OperationError::WelfareApprovalRequired {
                name: parsed.full_name.clone(),
            });
        }

        Ok(())
    }

    /// Create the initial NameRecord after successful registration
    ///
    /// # Postconditions (from spec K1)
    /// - NameRecord created with status=Active
    /// - expires_at set based on registration duration
    /// - transfer_lock active for 24 hours
    /// - If has children scope: zone_controller set
    /// - dao.{name} automatically reserved for owner
    /// - Fee distribution completed atomically
    pub fn create_record(
        parsed: &ParsedName,
        owner: PublicKey,
        verification_level: VerificationLevel,
        verification_proof: Option<VCReference>,
        issuer: PublicKey,
        current_block: BlockHeight,
        current_time: Timestamp,
        duration_secs: u64,
        parent_hash: Option<NameHash>,
    ) -> NameRecord {
        let name_hash = super::validation::compute_name_hash(&parsed.full_name);
        let expires_at = current_time + duration_secs;
        let transfer_lock_until = current_time + timing::TRANSFER_LOCK_SECS;

        NameRecord {
            name: parsed.full_name.clone(),
            name_hash,
            owner,
            controller: None,
            zone_controller: None, // Set separately if zone delegation needed
            parent: parent_hash,
            classification: parsed.classification,
            verification_level,
            verification_proof,
            issuer,
            governance_pointer: None, // Set separately for dao.X
            status: NameStatus::Active,
            registered_at: current_block,
            expires_at,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            transfer_lock_until: Some(transfer_lock_until),
            transfer_history: vec![],
            renewal_history: vec![],
        }
    }
}

// ============================================================================
// Renewal Guards (K2)
// ============================================================================

/// Guard checks for the renew operation
///
/// # Preconditions (from spec K2)
/// - Name exists and caller is owner
/// - Status is Active OR (Expired AND within grace period)
/// - Status is NOT Suspended or RevocationPending
/// - Renewal fee paid
pub struct RenewGuard;

impl RenewGuard {
    /// Check all preconditions for renewal
    pub fn check_preconditions(
        record: &NameRecord,
        caller: &PublicKey,
        current_time: Timestamp,
        fee_paid: u64,
        required_fee: u64,
    ) -> OperationResult<()> {
        // Precondition 1: Caller is owner
        if &record.owner != caller {
            return Err(OperationError::Unauthorized {
                reason: "Only owner can renew".to_string(),
            });
        }

        // Precondition 2 & 3: Status check
        match &record.status {
            NameStatus::Active => {
                // Check if within renewal window (90 days before expiry)
                // This is optional - could allow renewal anytime when active
            }
            NameStatus::Expired { grace_ends } => {
                // Can renew if within grace period
                if current_time >= *grace_ends {
                    return Err(OperationError::CannotRenew {
                        name: record.name.clone(),
                    });
                }
            }
            NameStatus::Suspended { .. }
            | NameStatus::SuspendedByParent
            | NameStatus::RevocationPending { .. } => {
                return Err(OperationError::Suspended {
                    name: record.name.clone(),
                });
            }
            NameStatus::Revoked { .. } | NameStatus::Released => {
                return Err(OperationError::CannotRenew {
                    name: record.name.clone(),
                });
            }
        }

        // Precondition 4: Fee paid
        if fee_paid < required_fee {
            return Err(OperationError::FeeNotPaid {
                required: required_fee,
                paid: fee_paid,
            });
        }

        Ok(())
    }

    /// Apply renewal to record
    ///
    /// # Postconditions (from spec K2)
    /// - expires_at extended by duration
    /// - If was Expired: status returns to Active
    /// - transfer_lock active for 24 hours
    /// - Fee distribution completed
    pub fn apply_renewal(
        record: &mut NameRecord,
        duration_secs: u64,
        current_time: Timestamp,
        current_block: BlockHeight,
        fee_paid: u64,
    ) {
        let previous_expiry = record.expires_at;
        let new_expiry = record.expires_at.max(current_time) + duration_secs;

        record.expires_at = new_expiry;
        record.status = NameStatus::Active;
        record.grace_ends_at = None;
        record.transfer_lock_until = Some(current_time + timing::TRANSFER_LOCK_SECS);

        record.renewal_history.push(RenewalRecord {
            renewed_by: record.owner,
            renewed_at: current_block,
            previous_expiry,
            new_expiry,
            fee_paid,
        });
    }
}

// ============================================================================
// Transfer Guards (K3)
// ============================================================================

/// Guard checks for the transfer operation
///
/// # Preconditions (from spec K3)
/// - Name exists and caller is owner
/// - Status is Active
/// - transfer_lock has expired (24h since registration/renewal)
/// - NOT in expiration grace period
/// - new_owner meets verification requirements for classification
pub struct TransferGuard;

impl TransferGuard {
    /// Check all preconditions for transfer
    pub fn check_preconditions(
        record: &NameRecord,
        caller: &PublicKey,
        new_owner_verification: VerificationLevel,
        current_time: Timestamp,
    ) -> OperationResult<()> {
        // Precondition 1: Caller is owner
        if &record.owner != caller {
            return Err(OperationError::Unauthorized {
                reason: "Only owner can transfer".to_string(),
            });
        }

        // Precondition 2: Status is Active
        if !record.status.is_active() {
            return Err(OperationError::NotActive {
                name: record.name.clone(),
                status: format!("{:?}", record.status),
            });
        }

        // Precondition 3: Transfer lock expired
        if record.has_transfer_lock(current_time) {
            return Err(OperationError::TransferLocked {
                name: record.name.clone(),
                lock_until: record.transfer_lock_until.unwrap_or(0),
            });
        }

        // Precondition 4: NOT in expiration grace period
        if record.is_in_grace_period(current_time) {
            return Err(OperationError::InGracePeriod {
                name: record.name.clone(),
            });
        }

        // Precondition 5: new_owner meets verification requirements
        super::validation::validate_verification_level(
            record.classification,
            new_owner_verification,
        )?;

        Ok(())
    }

    /// Apply transfer to record
    ///
    /// # Postconditions (from spec K3)
    /// - owner updated to new_owner
    /// - controller reset to None (new owner must re-delegate)
    /// - governance_pointer reset to new_owner default
    /// - transfer_history appended
    /// - All children retain current state (no automatic transfer)
    pub fn apply_transfer(
        record: &mut NameRecord,
        new_owner: PublicKey,
        current_block: BlockHeight,
        tx_hash: [u8; 32],
    ) {
        let from = record.owner;

        record.transfer_history.push(TransferRecord {
            from,
            to: new_owner,
            transferred_at: current_block,
            tx_hash,
        });

        record.owner = new_owner;
        record.controller = None; // Reset controller
        record.governance_pointer = None; // Reset governance pointer
    }
}

// ============================================================================
// Delegation Guards (K4)
// ============================================================================

/// Guard checks for the delegate operation
///
/// # Preconditions (from spec K4)
/// - Parent exists and caller is owner or zone_controller
/// - Child name doesn't exist
/// - Child label is valid (not reserved, proper format)
/// - Delegation depth <= max_depth (8)
/// - For welfare: delegate_to meets sector verification floor
pub struct DelegateGuard;

impl DelegateGuard {
    /// Check all preconditions for delegation
    pub fn check_preconditions(
        parent: &NameRecord,
        child_parsed: &ParsedName,
        caller: &PublicKey,
        delegate_verification: VerificationLevel,
        child_exists: bool,
    ) -> OperationResult<()> {
        // Precondition 1: Caller is owner or zone_controller
        let is_owner = &parent.owner == caller;
        let is_zone_controller = parent
            .zone_controller
            .as_ref()
            .map(|zc| zc == caller)
            .unwrap_or(false);

        if !is_owner && !is_zone_controller {
            return Err(OperationError::Unauthorized {
                reason: "Must be owner or zone controller to delegate".to_string(),
            });
        }

        // Precondition 2: Child doesn't exist
        if child_exists {
            return Err(OperationError::AlreadyExists {
                name: child_parsed.full_name.clone(),
            });
        }

        // Precondition 3: Parent is active
        if !parent.status.is_active() {
            return Err(OperationError::ParentNotActive {
                parent: parent.name.clone(),
            });
        }

        // Precondition 4: Depth check
        if child_parsed.depth > limits::MAX_DEPTH {
            return Err(OperationError::DepthExceeded {
                max: limits::MAX_DEPTH,
                requested: child_parsed.depth,
            });
        }

        // Precondition 5: Verification level for welfare
        super::validation::validate_verification_level(
            child_parsed.classification,
            delegate_verification,
        )?;

        Ok(())
    }

    /// Calculate child expiry based on parent and requested duration
    ///
    /// Child expires_at = min(duration, parent.expires_at)
    pub fn calculate_child_expiry(
        parent: &NameRecord,
        requested_duration: Option<u64>,
        current_time: Timestamp,
    ) -> Timestamp {
        match requested_duration {
            Some(duration) => {
                let requested_expiry = current_time + duration;
                requested_expiry.min(parent.expires_at)
            }
            None => parent.expires_at,
        }
    }
}

// ============================================================================
// Revocation Guards (K5)
// ============================================================================

/// Guard checks for the revoke operation
///
/// # Preconditions (from spec K5)
/// - Name exists
/// - Caller is authorized revoker for this name/reason
/// - If owner voluntary: immediate
/// - If governance/dispute: proper process followed
pub struct RevokeGuard;

/// Authority requesting revocation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationRequester {
    /// Owner voluntarily releasing
    Owner(PublicKey),
    /// Root governance action
    RootGovernance { proposal_id: [u8; 32] },
    /// Emergency multisig
    EmergencyMultisig { signers: Vec<PublicKey> },
    /// Dispute module
    DisputeModule { dispute_id: [u8; 32] },
    /// Issuing welfare DAO
    WelfareDao { dao_id: [u8; 32] },
}

impl RevokeGuard {
    /// Check all preconditions for revocation
    pub fn check_preconditions(
        record: &NameRecord,
        requester: &RevocationRequester,
    ) -> OperationResult<()> {
        // Check authorization based on requester type
        match requester {
            RevocationRequester::Owner(owner) => {
                if &record.owner != owner {
                    return Err(OperationError::Unauthorized {
                        reason: "Only owner can voluntarily release".to_string(),
                    });
                }
            }
            RevocationRequester::RootGovernance { .. } => {
                // Root governance can revoke any domain (with timelock)
                // Actual governance validation would happen in the governance module
            }
            RevocationRequester::EmergencyMultisig { .. } => {
                // Emergency can only suspend, not fully revoke immediately
                // This is handled in state transitions
            }
            RevocationRequester::DisputeModule { .. } => {
                // Dispute module outcome - validation done in dispute module
            }
            RevocationRequester::WelfareDao { .. } => {
                // Only for welfare delegated domains
                if !matches!(
                    record.classification,
                    NameClassification::WelfareDelegated
                ) {
                    return Err(OperationError::InvalidRevocationAuthority);
                }
            }
        }

        Ok(())
    }

    /// Determine the new status based on revocation type
    ///
    /// # Postconditions (from spec K5)
    /// - If owner voluntary: status = Revoked immediately
    /// - If governance: status = Suspended (immediate), then RevocationPending after process
    /// - All children: status = SuspendedByParent
    /// - governance_pointer resolves to RevokedRecord (tombstone)
    /// - grace_ends_at set if dispute revocation (7 days)
    pub fn determine_new_status(
        requester: &RevocationRequester,
        current_time: Timestamp,
    ) -> NameStatus {
        match requester {
            RevocationRequester::Owner(_) => NameStatus::Revoked {
                tombstone: RevokedRecord {
                    revoked_at: current_time,
                    reason_code: ReasonCode::OwnerVoluntary,
                    revoking_authority: [0u8; 32], // Owner's key would go here
                    appeal_status: None,
                },
            },
            RevocationRequester::RootGovernance { .. } => NameStatus::RevocationPending {
                grace_ends: current_time + timing::REVOCATION_GRACE_SECS,
                appeal_id: None,
            },
            RevocationRequester::EmergencyMultisig { .. } => NameStatus::Suspended {
                reason: SuspensionReason::Emergency {
                    reason: "Emergency action".to_string(),
                },
            },
            RevocationRequester::DisputeModule { dispute_id } => NameStatus::RevocationPending {
                grace_ends: current_time + timing::REVOCATION_GRACE_SECS,
                appeal_id: Some(*dispute_id),
            },
            RevocationRequester::WelfareDao { .. } => NameStatus::RevocationPending {
                grace_ends: current_time + timing::REVOCATION_GRACE_SECS,
                appeal_id: None,
            },
        }
    }
}

// ============================================================================
// Resolution (K6)
// ============================================================================

/// Resolution result for name queries
///
/// # Postconditions (from spec K6)
/// - If Active: returns full NameRecord
/// - If Suspended/RevocationPending: returns record with status indicator
/// - If Revoked: returns RevokedRecord tombstone
/// - If Expired (in grace): returns record with grace_ends_at
/// - If Released/NotFound: returns None
/// - For dao.{name}: returns governance_pointer or tombstone
#[derive(Debug, Clone)]
pub enum ResolutionResult {
    /// Active record (full access)
    Active(NameRecord),
    /// Suspended record (limited access)
    Suspended {
        record: NameRecord,
        reason: SuspensionReason,
    },
    /// Pending revocation (in grace period)
    RevocationPending {
        record: NameRecord,
        grace_ends: Timestamp,
        appeal_id: Option<[u8; 32]>,
    },
    /// Revoked (tombstone only)
    Revoked(RevokedRecord),
    /// Expired but in grace period
    Expired {
        record: NameRecord,
        grace_ends: Timestamp,
    },
    /// Not found or released
    NotFound,
}

impl ResolutionResult {
    /// Create resolution result from a name record
    pub fn from_record(record: NameRecord) -> Self {
        match &record.status {
            NameStatus::Active => ResolutionResult::Active(record),
            NameStatus::Suspended { reason } => ResolutionResult::Suspended {
                reason: reason.clone(),
                record,
            },
            NameStatus::SuspendedByParent => ResolutionResult::Suspended {
                reason: SuspensionReason::Emergency {
                    reason: "Parent suspended".to_string(),
                },
                record,
            },
            NameStatus::RevocationPending {
                grace_ends,
                appeal_id,
            } => ResolutionResult::RevocationPending {
                grace_ends: *grace_ends,
                appeal_id: *appeal_id,
                record,
            },
            NameStatus::Revoked { tombstone } => ResolutionResult::Revoked(tombstone.clone()),
            NameStatus::Expired { grace_ends } => ResolutionResult::Expired {
                grace_ends: *grace_ends,
                record,
            },
            NameStatus::Released => ResolutionResult::NotFound,
        }
    }

    /// Check if resolution returned an active/usable record
    pub fn is_active(&self) -> bool {
        matches!(self, ResolutionResult::Active(_))
    }

    /// Get the governance pointer if available
    pub fn governance_pointer(&self) -> Option<&GovernanceRecord> {
        match self {
            ResolutionResult::Active(r) => r.governance_pointer.as_ref(),
            ResolutionResult::Suspended { record, .. } => record.governance_pointer.as_ref(),
            ResolutionResult::Expired { record, .. } => record.governance_pointer.as_ref(),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::root_registry::validation::parse_and_validate;

    fn test_owner() -> PublicKey {
        [1u8; 32]
    }

    fn other_owner() -> PublicKey {
        [2u8; 32]
    }

    fn create_test_record(name: &str) -> NameRecord {
        let parsed = parse_and_validate(name).unwrap();
        RegisterGuard::create_record(
            &parsed,
            test_owner(),
            VerificationLevel::L2VerifiedEntity,
            None,
            test_owner(),
            1000,
            1000,
            365 * 24 * 60 * 60, // 1 year
            None,
        )
    }

    #[test]
    fn test_register_preconditions() {
        let parsed = parse_and_validate("mystore.sov").unwrap();

        // Should succeed with proper verification and fee
        let result = RegisterGuard::check_preconditions(
            &parsed,
            VerificationLevel::L2VerifiedEntity,
            None,
            100,
            100,
            false,
        );
        assert!(result.is_ok());

        // Should fail with insufficient verification
        let result = RegisterGuard::check_preconditions(
            &parsed,
            VerificationLevel::L1BasicDID,
            None,
            100,
            100,
            false,
        );
        assert!(matches!(
            result,
            Err(OperationError::Validation(
                ValidationError::InsufficientVerification { .. }
            ))
        ));

        // Should fail with insufficient fee
        let result = RegisterGuard::check_preconditions(
            &parsed,
            VerificationLevel::L2VerifiedEntity,
            None,
            50,
            100,
            false,
        );
        assert!(matches!(result, Err(OperationError::FeeNotPaid { .. })));
    }

    #[test]
    fn test_register_welfare_requires_approval() {
        let parsed = parse_and_validate("kitchen.food.sov").unwrap();

        // Should fail without welfare approval
        let result = RegisterGuard::check_preconditions(
            &parsed,
            VerificationLevel::L1BasicDID,
            None,
            100,
            100,
            false,
        );
        assert!(matches!(
            result,
            Err(OperationError::WelfareApprovalRequired { .. })
        ));

        // Should succeed with approval
        let result = RegisterGuard::check_preconditions(
            &parsed,
            VerificationLevel::L1BasicDID,
            None,
            100,
            100,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_renew_preconditions() {
        let record = create_test_record("mystore.sov");

        // Should succeed for owner with fee
        let result = RenewGuard::check_preconditions(&record, &test_owner(), 2000, 100, 100);
        assert!(result.is_ok());

        // Should fail for non-owner
        let result = RenewGuard::check_preconditions(&record, &other_owner(), 2000, 100, 100);
        assert!(matches!(result, Err(OperationError::Unauthorized { .. })));

        // Should fail with insufficient fee
        let result = RenewGuard::check_preconditions(&record, &test_owner(), 2000, 50, 100);
        assert!(matches!(result, Err(OperationError::FeeNotPaid { .. })));
    }

    #[test]
    fn test_transfer_preconditions() {
        let mut record = create_test_record("mystore.sov");

        // Should fail during transfer lock
        let result = TransferGuard::check_preconditions(
            &record,
            &test_owner(),
            VerificationLevel::L2VerifiedEntity,
            1500, // Still in lock period
        );
        assert!(matches!(result, Err(OperationError::TransferLocked { .. })));

        // Should succeed after lock expires
        record.transfer_lock_until = Some(1000);
        let result = TransferGuard::check_preconditions(
            &record,
            &test_owner(),
            VerificationLevel::L2VerifiedEntity,
            2000, // After lock
        );
        assert!(result.is_ok());

        // Should fail for non-owner
        let result = TransferGuard::check_preconditions(
            &record,
            &other_owner(),
            VerificationLevel::L2VerifiedEntity,
            2000,
        );
        assert!(matches!(result, Err(OperationError::Unauthorized { .. })));
    }

    #[test]
    fn test_revocation_by_owner() {
        let record = create_test_record("mystore.sov");

        let requester = RevocationRequester::Owner(test_owner());
        assert!(RevokeGuard::check_preconditions(&record, &requester).is_ok());

        let status = RevokeGuard::determine_new_status(&requester, 5000);
        assert!(matches!(status, NameStatus::Revoked { .. }));
    }

    #[test]
    fn test_revocation_by_non_owner_fails() {
        let record = create_test_record("mystore.sov");

        let requester = RevocationRequester::Owner(other_owner());
        let result = RevokeGuard::check_preconditions(&record, &requester);
        assert!(matches!(result, Err(OperationError::Unauthorized { .. })));
    }

    #[test]
    fn test_resolution_result() {
        let record = create_test_record("mystore.sov");
        let result = ResolutionResult::from_record(record);
        assert!(result.is_active());

        // Test revoked resolution
        let mut record = create_test_record("revoked.sov");
        record.status = NameStatus::Revoked {
            tombstone: RevokedRecord {
                revoked_at: 1000,
                reason_code: ReasonCode::OwnerVoluntary,
                revoking_authority: [0u8; 32],
                appeal_status: None,
            },
        };
        let result = ResolutionResult::from_record(record);
        assert!(matches!(result, ResolutionResult::Revoked(_)));
    }

    #[test]
    fn test_child_expiry_calculation() {
        let mut parent = create_test_record("parent.sov");
        parent.expires_at = 100000;

        // Without duration, inherit parent expiry
        let expiry = DelegateGuard::calculate_child_expiry(&parent, None, 1000);
        assert_eq!(expiry, 100000);

        // With shorter duration
        let expiry = DelegateGuard::calculate_child_expiry(&parent, Some(10000), 1000);
        assert_eq!(expiry, 11000);

        // With longer duration (capped at parent)
        let expiry = DelegateGuard::calculate_child_expiry(&parent, Some(200000), 1000);
        assert_eq!(expiry, 100000);
    }
}
