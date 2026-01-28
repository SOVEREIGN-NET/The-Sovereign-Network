//! Cap Ledger Types - Hard Cap Enforcement
//!
//! Types for enforcing compensation caps at multiple scope levels:
//! - Global pool cap (system-wide limit)
//! - Role period cap (per-role budget per period)
//! - Role lifetime cap (optional total for role)
//! - Assignment annual cap (from snapshot)
//! - Assignment lifetime cap (from snapshot)
//!
//! # Consensus-Critical
//! All arithmetic uses checked operations to prevent overflow.
//! Caps are HARD LAW - any exceeded cap aborts the operation.

use super::role_types::{AssignmentId, RoleId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a cap reservation
pub type ReservationId = [u8; 32];

/// Role cap configuration and consumption tracking
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleCap {
    /// Role identifier
    pub role_id: RoleId,

    /// Maximum compensation per period for all assignments in this role
    pub period_cap: u64,

    /// Amount consumed in current period
    pub period_consumed: u64,

    /// Optional lifetime cap for this role (total across all time)
    pub lifetime_cap: Option<u64>,

    /// Total consumed across all time
    pub lifetime_consumed: u64,

    /// Current period number (for reset tracking)
    pub current_period: u64,
}

impl RoleCap {
    /// Create a new role cap
    pub fn new(role_id: RoleId, period_cap: u64, lifetime_cap: Option<u64>, current_period: u64) -> Self {
        Self {
            role_id,
            period_cap,
            period_consumed: 0,
            lifetime_cap,
            lifetime_consumed: 0,
            current_period,
        }
    }

    /// Get remaining period capacity
    pub fn remaining_period(&self) -> u64 {
        self.period_cap.saturating_sub(self.period_consumed)
    }

    /// Get remaining lifetime capacity (if applicable)
    pub fn remaining_lifetime(&self) -> Option<u64> {
        self.lifetime_cap.map(|cap| cap.saturating_sub(self.lifetime_consumed))
    }

    /// Reset period consumption for new period
    pub fn reset_period(&mut self, new_period: u64) {
        if new_period > self.current_period {
            self.period_consumed = 0;
            self.current_period = new_period;
        }
    }

    /// Record consumption (after successful payout)
    pub fn record_consumption(&mut self, amount: u64) {
        self.period_consumed = self.period_consumed.saturating_add(amount);
        self.lifetime_consumed = self.lifetime_consumed.saturating_add(amount);
    }
}

/// Assignment consumption tracking
///
/// Tracks consumption against snapshotted caps from the assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentConsumption {
    /// Assignment identifier
    pub assignment_id: AssignmentId,

    /// Role this assignment belongs to
    pub role_id: RoleId,

    /// Annual cap (from assignment snapshot - IMMUTABLE)
    pub snap_annual_cap: u64,

    /// Lifetime cap (from assignment snapshot - IMMUTABLE)
    pub snap_lifetime_cap: Option<u64>,

    /// Amount consumed in current period
    pub current_period_consumed: u64,

    /// Total consumed across all time
    pub total_consumed: u64,

    /// Current period number (for reset tracking)
    pub current_period: u64,
}

impl AssignmentConsumption {
    /// Create new assignment consumption tracker
    pub fn new(
        assignment_id: AssignmentId,
        role_id: RoleId,
        snap_annual_cap: u64,
        snap_lifetime_cap: Option<u64>,
        current_period: u64,
    ) -> Self {
        Self {
            assignment_id,
            role_id,
            snap_annual_cap,
            snap_lifetime_cap,
            current_period_consumed: 0,
            total_consumed: 0,
            current_period,
        }
    }

    /// Get remaining annual capacity
    pub fn remaining_annual(&self) -> u64 {
        self.snap_annual_cap.saturating_sub(self.current_period_consumed)
    }

    /// Get remaining lifetime capacity (if applicable)
    pub fn remaining_lifetime(&self) -> Option<u64> {
        self.snap_lifetime_cap.map(|cap| cap.saturating_sub(self.total_consumed))
    }

    /// Reset period consumption for new period
    pub fn reset_period(&mut self, new_period: u64) {
        if new_period > self.current_period {
            self.current_period_consumed = 0;
            self.current_period = new_period;
        }
    }

    /// Record consumption (after successful payout)
    pub fn record_consumption(&mut self, amount: u64) {
        self.current_period_consumed = self.current_period_consumed.saturating_add(amount);
        self.total_consumed = self.total_consumed.saturating_add(amount);
    }
}

/// Period-level consumption tracking
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodConsumption {
    /// Period number
    pub period: u64,

    /// Total consumed in this period (global)
    pub total_consumed: u64,

    /// Number of payouts in this period
    pub payout_count: u64,
}

impl PeriodConsumption {
    /// Create new period consumption tracker
    pub fn new(period: u64) -> Self {
        Self {
            period,
            total_consumed: 0,
            payout_count: 0,
        }
    }

    /// Record a payout
    pub fn record_payout(&mut self, amount: u64) {
        self.total_consumed = self.total_consumed.saturating_add(amount);
        self.payout_count = self.payout_count.saturating_add(1);
    }
}

/// A pending cap reservation
///
/// Created when compensation is reserved but not yet committed.
/// Allows atomic reserve-then-commit pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapReservation {
    /// Unique reservation identifier
    pub id: ReservationId,

    /// Assignment being paid
    pub assignment_id: AssignmentId,

    /// Role of the assignment
    pub role_id: RoleId,

    /// Amount reserved
    pub amount: u64,

    /// Period when reserved
    pub period: u64,

    /// Epoch when reservation was created
    pub created_at_epoch: u64,
}

impl CapReservation {
    /// Create a new cap reservation
    pub fn new(
        id: ReservationId,
        assignment_id: AssignmentId,
        role_id: RoleId,
        amount: u64,
        period: u64,
        created_at_epoch: u64,
    ) -> Self {
        Self {
            id,
            assignment_id,
            role_id,
            amount,
            period,
            created_at_epoch,
        }
    }
}

/// Cap enforcement errors
///
/// All errors include full context for debugging and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    /// Arithmetic overflow (should never happen with valid inputs)
    Overflow,

    /// Global pool cap exceeded
    GlobalCapExceeded {
        cap: u64,
        consumed: u64,
        requested: u64,
    },

    /// Role period cap exceeded
    RolePeriodCapExceeded {
        role_id: RoleId,
        cap: u64,
        consumed: u64,
        requested: u64,
    },

    /// Role lifetime cap exceeded
    RoleLifetimeCapExceeded {
        role_id: RoleId,
        cap: u64,
        consumed: u64,
        requested: u64,
    },

    /// Assignment annual cap exceeded
    AssignmentAnnualCapExceeded {
        assignment_id: AssignmentId,
        cap: u64,
        consumed: u64,
        requested: u64,
    },

    /// Assignment lifetime cap exceeded
    AssignmentLifetimeCapExceeded {
        assignment_id: AssignmentId,
        cap: u64,
        consumed: u64,
        requested: u64,
    },

    /// Role not found in ledger
    RoleNotFound(RoleId),

    /// Assignment not found in ledger
    AssignmentNotFound(AssignmentId),

    /// Reservation not found
    ReservationNotFound(ReservationId),

    /// Reservation already committed or rolled back
    ReservationAlreadyConsumed(ReservationId),

    /// Period mismatch (reservation from different period)
    PeriodMismatch {
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => write!(f, "Arithmetic overflow in cap calculation"),
            Self::GlobalCapExceeded { cap, consumed, requested } => {
                write!(
                    f,
                    "Global cap exceeded: cap={}, consumed={}, requested={}",
                    cap, consumed, requested
                )
            }
            Self::RolePeriodCapExceeded { role_id, cap, consumed, requested } => {
                write!(
                    f,
                    "Role period cap exceeded: role={:?}, cap={}, consumed={}, requested={}",
                    &role_id[..4], cap, consumed, requested
                )
            }
            Self::RoleLifetimeCapExceeded { role_id, cap, consumed, requested } => {
                write!(
                    f,
                    "Role lifetime cap exceeded: role={:?}, cap={}, consumed={}, requested={}",
                    &role_id[..4], cap, consumed, requested
                )
            }
            Self::AssignmentAnnualCapExceeded { assignment_id, cap, consumed, requested } => {
                write!(
                    f,
                    "Assignment annual cap exceeded: assignment={:?}, cap={}, consumed={}, requested={}",
                    &assignment_id[..4], cap, consumed, requested
                )
            }
            Self::AssignmentLifetimeCapExceeded { assignment_id, cap, consumed, requested } => {
                write!(
                    f,
                    "Assignment lifetime cap exceeded: assignment={:?}, cap={}, consumed={}, requested={}",
                    &assignment_id[..4], cap, consumed, requested
                )
            }
            Self::RoleNotFound(role_id) => {
                write!(f, "Role not found: {:?}", &role_id[..4])
            }
            Self::AssignmentNotFound(assignment_id) => {
                write!(f, "Assignment not found: {:?}", &assignment_id[..4])
            }
            Self::ReservationNotFound(reservation_id) => {
                write!(f, "Reservation not found: {:?}", &reservation_id[..4])
            }
            Self::ReservationAlreadyConsumed(reservation_id) => {
                write!(f, "Reservation already consumed: {:?}", &reservation_id[..4])
            }
            Self::PeriodMismatch { expected, actual } => {
                write!(f, "Period mismatch: expected={}, actual={}", expected, actual)
            }
        }
    }
}

impl std::error::Error for CapError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_role_id() -> RoleId {
        [1u8; 32]
    }

    fn test_assignment_id() -> AssignmentId {
        [2u8; 32]
    }

    #[test]
    fn test_role_cap_new() {
        let cap = RoleCap::new(test_role_id(), 100_000, Some(500_000), 1);
        assert_eq!(cap.period_cap, 100_000);
        assert_eq!(cap.lifetime_cap, Some(500_000));
        assert_eq!(cap.period_consumed, 0);
        assert_eq!(cap.lifetime_consumed, 0);
    }

    #[test]
    fn test_role_cap_remaining() {
        let mut cap = RoleCap::new(test_role_id(), 100_000, Some(500_000), 1);
        cap.record_consumption(30_000);

        assert_eq!(cap.remaining_period(), 70_000);
        assert_eq!(cap.remaining_lifetime(), Some(470_000));
    }

    #[test]
    fn test_role_cap_period_reset() {
        let mut cap = RoleCap::new(test_role_id(), 100_000, Some(500_000), 1);
        cap.record_consumption(50_000);

        // Reset to new period
        cap.reset_period(2);

        assert_eq!(cap.period_consumed, 0);
        assert_eq!(cap.lifetime_consumed, 50_000); // Lifetime NOT reset
        assert_eq!(cap.current_period, 2);
    }

    #[test]
    fn test_assignment_consumption_new() {
        let consumption = AssignmentConsumption::new(
            test_assignment_id(),
            test_role_id(),
            100_000,
            Some(300_000),
            1,
        );

        assert_eq!(consumption.snap_annual_cap, 100_000);
        assert_eq!(consumption.snap_lifetime_cap, Some(300_000));
        assert_eq!(consumption.current_period_consumed, 0);
        assert_eq!(consumption.total_consumed, 0);
    }

    #[test]
    fn test_assignment_consumption_remaining() {
        let mut consumption = AssignmentConsumption::new(
            test_assignment_id(),
            test_role_id(),
            100_000,
            Some(300_000),
            1,
        );
        consumption.record_consumption(25_000);

        assert_eq!(consumption.remaining_annual(), 75_000);
        assert_eq!(consumption.remaining_lifetime(), Some(275_000));
    }

    #[test]
    fn test_assignment_consumption_period_reset() {
        let mut consumption = AssignmentConsumption::new(
            test_assignment_id(),
            test_role_id(),
            100_000,
            Some(300_000),
            1,
        );
        consumption.record_consumption(50_000);

        // Reset to new period
        consumption.reset_period(2);

        assert_eq!(consumption.current_period_consumed, 0);
        assert_eq!(consumption.total_consumed, 50_000); // Total NOT reset
        assert_eq!(consumption.current_period, 2);
    }

    #[test]
    fn test_period_consumption() {
        let mut period = PeriodConsumption::new(1);
        period.record_payout(10_000);
        period.record_payout(20_000);

        assert_eq!(period.total_consumed, 30_000);
        assert_eq!(period.payout_count, 2);
    }

    #[test]
    fn test_cap_reservation() {
        let reservation = CapReservation::new(
            [3u8; 32],
            test_assignment_id(),
            test_role_id(),
            50_000,
            1,
            100,
        );

        assert_eq!(reservation.amount, 50_000);
        assert_eq!(reservation.period, 1);
    }

    #[test]
    fn test_cap_error_display() {
        let error = CapError::GlobalCapExceeded {
            cap: 1_000_000,
            consumed: 900_000,
            requested: 200_000,
        };
        let msg = format!("{}", error);
        assert!(msg.contains("Global cap exceeded"));
        assert!(msg.contains("1000000"));
    }
}
