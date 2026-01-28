//! Role Registry Types - Immutable Entitlement Binding
//!
//! Defines types for the Role Registry system which binds:
//! people -> roles -> entitlement ceilings
//!
//! Key principle: When an assignment is created, caps are SNAPSHOTTED.
//! Future governance changes don't affect existing commitments.
//!
//! # Consensus-Critical
//! All types use deterministic serialization (BTreeMap, not HashMap).
//! Integer math only - no floating point.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a role (32-byte hash)
pub type RoleId = [u8; 32];

/// Unique identifier for an assignment (32-byte hash)
pub type AssignmentId = [u8; 32];

/// Unique identifier for a person/identity (32-byte hash)
pub type IdentityId = [u8; 32];

/// Role definition with compensation ceilings
///
/// Roles define the maximum compensation parameters. When someone is
/// assigned to a role, these values are SNAPSHOTTED into the assignment.
/// Subsequent changes to role caps only affect NEW assignments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// Unique role identifier
    pub role_id: RoleId,

    /// Human-readable role name
    pub name: String,

    /// Role description
    pub description: String,

    /// Maximum compensation per year (in base units)
    pub annual_cap: u64,

    /// Maximum lifetime compensation (optional)
    pub lifetime_cap: Option<u64>,

    /// Maximum compensation per epoch
    pub per_epoch_cap: u64,

    /// Epoch when this role was created
    pub created_at_epoch: u64,

    /// Whether this role is currently active for new assignments
    pub is_active: bool,

    /// Whether assignments to this role require attestation
    pub requires_attestation: bool,
}

impl RoleDefinition {
    /// Create a new role definition
    ///
    /// # Arguments
    /// * `role_id` - Unique identifier
    /// * `name` - Human-readable name
    /// * `description` - Role description
    /// * `annual_cap` - Maximum annual compensation
    /// * `per_epoch_cap` - Maximum per-epoch compensation
    /// * `current_epoch` - Current epoch for timestamp
    ///
    /// # Returns
    /// New RoleDefinition with is_active=true
    pub fn new(
        role_id: RoleId,
        name: String,
        description: String,
        annual_cap: u64,
        per_epoch_cap: u64,
        current_epoch: u64,
    ) -> Self {
        Self {
            role_id,
            name,
            description,
            annual_cap,
            lifetime_cap: None,
            per_epoch_cap,
            created_at_epoch: current_epoch,
            is_active: true,
            requires_attestation: false,
        }
    }

    /// Create a role with lifetime cap
    pub fn with_lifetime_cap(mut self, lifetime_cap: u64) -> Self {
        self.lifetime_cap = Some(lifetime_cap);
        self
    }

    /// Set attestation requirement
    pub fn with_attestation_required(mut self) -> Self {
        self.requires_attestation = true;
        self
    }
}

/// Assignment status
///
/// - Active: Can receive compensation
/// - Suspended: Temporarily paused (accrued entitlement preserved)
/// - Terminated: Permanently ended
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentStatus {
    /// Active - can receive compensation
    Active,
    /// Suspended - temporarily paused, accrued entitlement preserved
    Suspended,
    /// Terminated - permanently ended
    Terminated,
}

impl fmt::Display for AssignmentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Assignment with snapshotted caps
///
/// When an assignment is created, the role's current caps are SNAPSHOTTED
/// into snap_* fields. These fields are IMMUTABLE after creation.
///
/// This ensures:
/// - Worker knows their max compensation at assignment time
/// - Governance changes apply only to NEW assignments
/// - No retroactive punishment possible
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    /// Unique assignment identifier
    pub assignment_id: AssignmentId,

    /// Person receiving this assignment
    pub person_id: IdentityId,

    /// Role being assigned
    pub role_id: RoleId,

    // ─── SNAPSHOTS - IMMUTABLE AFTER CREATION ───────────────────────────
    /// Snapshotted annual cap at assignment time (private to enforce immutability)
    snap_annual_cap: u64,

    /// Snapshotted lifetime cap at assignment time (private to enforce immutability)
    snap_lifetime_cap: Option<u64>,

    /// Snapshotted per-epoch cap at assignment time (private to enforce immutability)
    snap_per_epoch_cap: u64,

    // ─── STATE TRACKING ─────────────────────────────────────────────────
    /// Total amount paid across all time
    pub total_paid: u64,

    /// Amount paid in current year
    pub current_year_paid: u64,

    /// Current epoch's paid amount (resets each epoch)
    pub current_epoch_paid: u64,

    /// Last epoch when payment was recorded (for epoch reset)
    pub last_payment_epoch: Option<u64>,

    /// Current assignment status
    pub status: AssignmentStatus,

    // ─── TIMESTAMPS ─────────────────────────────────────────────────────
    /// Epoch when assignment was created
    pub assigned_at_epoch: u64,

    /// Year when assignment was created (for annual cap tracking)
    pub assigned_in_year: u64,

    /// Current year being tracked (for annual cap reset)
    pub current_year: u64,

    /// Epoch when suspended (if applicable)
    pub suspended_at_epoch: Option<u64>,

    /// Epoch when terminated (if applicable)
    pub terminated_at_epoch: Option<u64>,
}

impl Assignment {
    /// Create a new assignment with snapshotted caps
    ///
    /// # Arguments
    /// * `assignment_id` - Unique identifier
    /// * `person_id` - Person receiving assignment
    /// * `role` - Role definition (caps will be snapshotted)
    /// * `current_epoch` - Current epoch
    /// * `current_year` - Current year (for annual cap tracking)
    ///
    /// # Returns
    /// New Assignment with caps snapshotted from role
    pub fn new(
        assignment_id: AssignmentId,
        person_id: IdentityId,
        role: &RoleDefinition,
        current_epoch: u64,
        current_year: u64,
    ) -> Self {
        Self {
            assignment_id,
            person_id,
            role_id: role.role_id,

            // SNAPSHOT caps at creation time - these are IMMUTABLE
            snap_annual_cap: role.annual_cap,
            snap_lifetime_cap: role.lifetime_cap,
            snap_per_epoch_cap: role.per_epoch_cap,

            // State tracking starts at zero
            total_paid: 0,
            current_year_paid: 0,
            current_epoch_paid: 0,
            last_payment_epoch: None,
            status: AssignmentStatus::Active,

            // Timestamps
            assigned_at_epoch: current_epoch,
            assigned_in_year: current_year,
            current_year,
            suspended_at_epoch: None,
            terminated_at_epoch: None,
        }
    }

    // ─── SNAPSHOT ACCESSORS (Read-Only) ────────────────────────────────────

    /// Get snapshotted annual cap
    pub fn snap_annual_cap(&self) -> u64 {
        self.snap_annual_cap
    }

    /// Get snapshotted lifetime cap
    pub fn snap_lifetime_cap(&self) -> Option<u64> {
        self.snap_lifetime_cap
    }

    /// Get snapshotted per-epoch cap
    pub fn snap_per_epoch_cap(&self) -> u64 {
        self.snap_per_epoch_cap
    }

    // ─── STATE QUERY METHODS ───────────────────────────────────────────────

    /// Check if assignment can receive payment
    pub fn can_receive_payment(&self) -> bool {
        self.status == AssignmentStatus::Active
    }

    /// Get remaining annual cap
    pub fn remaining_annual_cap(&self) -> u64 {
        self.snap_annual_cap.saturating_sub(self.current_year_paid)
    }

    /// Get remaining lifetime cap (if applicable)
    pub fn remaining_lifetime_cap(&self) -> Option<u64> {
        self.snap_lifetime_cap
            .map(|cap| cap.saturating_sub(self.total_paid))
    }

    /// Get remaining epoch cap for given epoch
    pub fn remaining_epoch_cap(&self, current_epoch: u64) -> u64 {
        // Reset epoch tracking if we're in a new epoch
        if self.last_payment_epoch != Some(current_epoch) {
            self.snap_per_epoch_cap
        } else {
            self.snap_per_epoch_cap.saturating_sub(self.current_epoch_paid)
        }
    }

    /// Calculate maximum payable amount considering all caps
    ///
    /// Returns the minimum of:
    /// - Remaining annual cap
    /// - Remaining lifetime cap (if set)
    /// - Remaining epoch cap
    pub fn max_payable(&self, current_epoch: u64) -> u64 {
        let mut max = self.remaining_annual_cap();

        if let Some(lifetime_remaining) = self.remaining_lifetime_cap() {
            max = max.min(lifetime_remaining);
        }

        max.min(self.remaining_epoch_cap(current_epoch))
    }

    /// Record a payment
    ///
    /// # Arguments
    /// * `amount` - Amount to record
    /// * `current_epoch` - Current epoch
    /// * `current_year` - Current year
    ///
    /// # Returns
    /// Ok(()) if successful, Err if would exceed caps
    pub fn record_payment(
        &mut self,
        amount: u64,
        current_epoch: u64,
        current_year: u64,
    ) -> Result<(), AssignmentError> {
        if !self.can_receive_payment() {
            return Err(AssignmentError::NotActive);
        }

        // Reset year tracking if needed
        if current_year > self.current_year {
            self.current_year = current_year;
            self.current_year_paid = 0;
        }

        // Reset epoch tracking if needed
        if self.last_payment_epoch != Some(current_epoch) {
            self.current_epoch_paid = 0;
            self.last_payment_epoch = Some(current_epoch);
        }

        // Check caps
        if self.current_year_paid.saturating_add(amount) > self.snap_annual_cap {
            return Err(AssignmentError::ExceedsAnnualCap);
        }

        if let Some(lifetime_cap) = self.snap_lifetime_cap {
            if self.total_paid.saturating_add(amount) > lifetime_cap {
                return Err(AssignmentError::ExceedsLifetimeCap);
            }
        }

        if self.current_epoch_paid.saturating_add(amount) > self.snap_per_epoch_cap {
            return Err(AssignmentError::ExceedsEpochCap);
        }

        // Record payment
        self.total_paid = self.total_paid.saturating_add(amount);
        self.current_year_paid = self.current_year_paid.saturating_add(amount);
        self.current_epoch_paid = self.current_epoch_paid.saturating_add(amount);

        Ok(())
    }

    /// Suspend assignment (preserves accrued entitlement)
    pub fn suspend(&mut self, current_epoch: u64) -> Result<(), AssignmentError> {
        if self.status == AssignmentStatus::Terminated {
            return Err(AssignmentError::AlreadyTerminated);
        }
        if self.status == AssignmentStatus::Suspended {
            return Err(AssignmentError::AlreadySuspended);
        }

        self.status = AssignmentStatus::Suspended;
        self.suspended_at_epoch = Some(current_epoch);
        Ok(())
    }

    /// Reactivate a suspended assignment
    pub fn reactivate(&mut self) -> Result<(), AssignmentError> {
        if self.status != AssignmentStatus::Suspended {
            return Err(AssignmentError::NotSuspended);
        }

        self.status = AssignmentStatus::Active;
        self.suspended_at_epoch = None;
        Ok(())
    }

    /// Terminate assignment permanently
    pub fn terminate(&mut self, current_epoch: u64) -> Result<(), AssignmentError> {
        if self.status == AssignmentStatus::Terminated {
            return Err(AssignmentError::AlreadyTerminated);
        }

        self.status = AssignmentStatus::Terminated;
        self.terminated_at_epoch = Some(current_epoch);
        Ok(())
    }
}

/// Assignment operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    /// Assignment is not active
    NotActive,
    /// Payment would exceed annual cap
    ExceedsAnnualCap,
    /// Payment would exceed lifetime cap
    ExceedsLifetimeCap,
    /// Payment would exceed epoch cap
    ExceedsEpochCap,
    /// Assignment is already terminated
    AlreadyTerminated,
    /// Assignment is already suspended
    AlreadySuspended,
    /// Assignment is not suspended (can't reactivate)
    NotSuspended,
}

impl fmt::Display for AssignmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotActive => write!(f, "Assignment is not active"),
            Self::ExceedsAnnualCap => write!(f, "Payment would exceed annual cap"),
            Self::ExceedsLifetimeCap => write!(f, "Payment would exceed lifetime cap"),
            Self::ExceedsEpochCap => write!(f, "Payment would exceed epoch cap"),
            Self::AlreadyTerminated => write!(f, "Assignment is already terminated"),
            Self::AlreadySuspended => write!(f, "Assignment is already suspended"),
            Self::NotSuspended => write!(f, "Assignment is not suspended"),
        }
    }
}

impl std::error::Error for AssignmentError {}

/// Role registry operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleRegistryError {
    /// Role not found
    RoleNotFound(RoleId),
    /// Role is not active
    RoleNotActive(RoleId),
    /// Assignment not found
    AssignmentNotFound(AssignmentId),
    /// Person already has this role
    DuplicateAssignment {
        person_id: IdentityId,
        role_id: RoleId,
    },
    /// Prohibited role combination
    ProhibitedCombination {
        role_a: RoleId,
        role_b: RoleId,
    },
    /// Unauthorized operation
    Unauthorized,
    /// Assignment error
    AssignmentError(AssignmentError),
    /// Role already exists
    RoleAlreadyExists(RoleId),
}

impl fmt::Display for RoleRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleNotFound(id) => write!(f, "Role not found: {:?}", &id[..4]),
            Self::RoleNotActive(id) => write!(f, "Role not active: {:?}", &id[..4]),
            Self::AssignmentNotFound(id) => write!(f, "Assignment not found: {:?}", &id[..4]),
            Self::DuplicateAssignment { person_id, role_id } => {
                write!(
                    f,
                    "Person {:?} already has role {:?}",
                    &person_id[..4],
                    &role_id[..4]
                )
            }
            Self::ProhibitedCombination { role_a, role_b } => {
                write!(
                    f,
                    "Prohibited role combination: {:?} and {:?}",
                    &role_a[..4],
                    &role_b[..4]
                )
            }
            Self::Unauthorized => write!(f, "Unauthorized operation"),
            Self::AssignmentError(e) => write!(f, "Assignment error: {}", e),
            Self::RoleAlreadyExists(id) => write!(f, "Role already exists: {:?}", &id[..4]),
        }
    }
}

impl std::error::Error for RoleRegistryError {}

impl From<AssignmentError> for RoleRegistryError {
    fn from(e: AssignmentError) -> Self {
        Self::AssignmentError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_role_id() -> RoleId {
        [1u8; 32]
    }

    fn test_person_id() -> IdentityId {
        [2u8; 32]
    }

    fn test_assignment_id() -> AssignmentId {
        [3u8; 32]
    }

    fn test_role() -> RoleDefinition {
        RoleDefinition::new(
            test_role_id(),
            "Engineer".to_string(),
            "Software Engineer".to_string(),
            100_000, // annual cap
            10_000,  // per epoch cap
            100,     // current epoch
        )
    }

    #[test]
    fn test_role_definition_new() {
        let role = test_role();
        assert_eq!(role.role_id, test_role_id());
        assert_eq!(role.name, "Engineer");
        assert_eq!(role.annual_cap, 100_000);
        assert_eq!(role.per_epoch_cap, 10_000);
        assert!(role.is_active);
        assert!(!role.requires_attestation);
        assert!(role.lifetime_cap.is_none());
    }

    #[test]
    fn test_role_definition_with_lifetime_cap() {
        let role = test_role().with_lifetime_cap(500_000);
        assert_eq!(role.lifetime_cap, Some(500_000));
    }

    #[test]
    fn test_assignment_new_snapshots_caps() {
        let role = test_role().with_lifetime_cap(500_000);
        let assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100, // current epoch
            2024, // current year
        );

        // Verify caps are snapshotted
        assert_eq!(assignment.snap_annual_cap(), 100_000);
        assert_eq!(assignment.snap_lifetime_cap(), Some(500_000));
        assert_eq!(assignment.snap_per_epoch_cap(), 10_000);

        // Verify initial state
        assert_eq!(assignment.total_paid, 0);
        assert_eq!(assignment.current_year_paid, 0);
        assert_eq!(assignment.status, AssignmentStatus::Active);
    }

    #[test]
    fn test_assignment_record_payment() {
        let role = test_role();
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Record payment
        assert!(assignment.record_payment(5_000, 100, 2024).is_ok());
        assert_eq!(assignment.total_paid, 5_000);
        assert_eq!(assignment.current_year_paid, 5_000);
        assert_eq!(assignment.current_epoch_paid, 5_000);
    }

    #[test]
    fn test_assignment_exceeds_annual_cap() {
        let role = test_role(); // 100k annual cap
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Try to exceed annual cap
        let result = assignment.record_payment(100_001, 100, 2024);
        assert_eq!(result, Err(AssignmentError::ExceedsAnnualCap));
    }

    #[test]
    fn test_assignment_exceeds_epoch_cap() {
        let role = test_role(); // 10k per epoch cap
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Try to exceed epoch cap
        let result = assignment.record_payment(10_001, 100, 2024);
        assert_eq!(result, Err(AssignmentError::ExceedsEpochCap));
    }

    #[test]
    fn test_assignment_exceeds_lifetime_cap() {
        let role = test_role().with_lifetime_cap(50_000);
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Pay up to lifetime cap over multiple epochs
        assert!(assignment.record_payment(10_000, 100, 2024).is_ok());
        assert!(assignment.record_payment(10_000, 101, 2024).is_ok());
        assert!(assignment.record_payment(10_000, 102, 2024).is_ok());
        assert!(assignment.record_payment(10_000, 103, 2024).is_ok());
        assert!(assignment.record_payment(10_000, 104, 2024).is_ok());

        // Now at 50k - next payment should fail
        let result = assignment.record_payment(1, 105, 2024);
        assert_eq!(result, Err(AssignmentError::ExceedsLifetimeCap));
    }

    #[test]
    fn test_assignment_epoch_reset() {
        let role = test_role(); // 10k per epoch cap
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Fill epoch cap
        assert!(assignment.record_payment(10_000, 100, 2024).is_ok());

        // Can't pay more in same epoch
        assert!(assignment.record_payment(1, 100, 2024).is_err());

        // New epoch resets
        assert!(assignment.record_payment(10_000, 101, 2024).is_ok());
    }

    #[test]
    fn test_assignment_year_reset() {
        let role = test_role(); // 100k annual cap
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Pay full annual amount over epochs
        for i in 0..10 {
            assert!(assignment.record_payment(10_000, 100 + i, 2024).is_ok());
        }
        assert_eq!(assignment.current_year_paid, 100_000);

        // Can't pay more in same year
        assert!(assignment.record_payment(1, 110, 2024).is_err());

        // New year resets
        assert!(assignment.record_payment(10_000, 111, 2025).is_ok());
        assert_eq!(assignment.current_year_paid, 10_000);
        assert_eq!(assignment.total_paid, 110_000);
    }

    #[test]
    fn test_assignment_suspend_and_reactivate() {
        let role = test_role();
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Pay some amount
        assert!(assignment.record_payment(5_000, 100, 2024).is_ok());

        // Suspend
        assert!(assignment.suspend(101).is_ok());
        assert_eq!(assignment.status, AssignmentStatus::Suspended);
        assert_eq!(assignment.suspended_at_epoch, Some(101));

        // Can't pay while suspended
        assert!(assignment.record_payment(1_000, 102, 2024).is_err());

        // Accrued entitlement preserved
        assert_eq!(assignment.total_paid, 5_000);
        assert_eq!(assignment.snap_annual_cap(), 100_000);

        // Reactivate
        assert!(assignment.reactivate().is_ok());
        assert_eq!(assignment.status, AssignmentStatus::Active);

        // Can pay again
        assert!(assignment.record_payment(1_000, 103, 2024).is_ok());
    }

    #[test]
    fn test_assignment_terminate() {
        let role = test_role();
        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Terminate
        assert!(assignment.terminate(101).is_ok());
        assert_eq!(assignment.status, AssignmentStatus::Terminated);

        // Can't pay after termination
        assert!(assignment.record_payment(1_000, 102, 2024).is_err());

        // Can't terminate again
        assert!(assignment.terminate(103).is_err());

        // Can't suspend after termination
        assert!(assignment.suspend(104).is_err());
    }

    #[test]
    fn test_max_payable_calculation() {
        let role = RoleDefinition::new(
            test_role_id(),
            "Test".to_string(),
            "Test role".to_string(),
            100_000, // annual
            5_000,   // per epoch
            100,
        ).with_lifetime_cap(200_000);

        let mut assignment = Assignment::new(
            test_assignment_id(),
            test_person_id(),
            &role,
            100,
            2024,
        );

        // Initially limited by epoch cap (5k is smallest)
        assert_eq!(assignment.max_payable(100), 5_000);

        // After paying 3k this epoch, limited to 2k remaining in epoch
        assignment.record_payment(3_000, 100, 2024).unwrap();
        assert_eq!(assignment.max_payable(100), 2_000);

        // New epoch resets to 5k
        assert_eq!(assignment.max_payable(101), 5_000);
    }
}
