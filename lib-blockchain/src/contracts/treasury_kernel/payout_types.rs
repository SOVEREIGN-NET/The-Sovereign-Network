//! Payout Types - Compensation Calculation and Payment Tracking
//!
//! Types for deterministic compensation computation and double-payment prevention.
//!
//! # Key Principles
//!
//! 1. **Deterministic**: Same inputs MUST produce same output
//! 2. **No Discretion**: Engine computes, does not decide
//! 3. **Reconstructable**: Every payout can be recalculated from stored inputs
//!
//! # Consensus-Critical
//! All types use deterministic serialization. Integer math only (no floating point).

use super::metric_types::MetricKey;
use super::role_types::{AssignmentId, RoleId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Hash of a computation (32 bytes)
pub type ComputationHash = [u8; 32];

/// Transaction identifier (32 bytes)
pub type TransactionId = [u8; 32];

/// Result of a payout computation
///
/// Contains all information needed to verify and execute a payout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutCalculation {
    /// Assignment receiving the payout
    pub assignment_id: AssignmentId,
    /// Epoch for which compensation is calculated
    pub epoch: u64,
    /// Base amount before multipliers
    pub base_amount: u64,
    /// Amount after applying multipliers
    pub multiplied_amount: u64,
    /// Final amount after applying caps
    pub final_amount: u64,
    /// Hash of computation inputs (for verification/replay)
    pub computation_hash: ComputationHash,
    /// Detailed breakdown of how amount was calculated
    pub breakdown: PayoutBreakdown,
}

/// Detailed breakdown of payout calculation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutBreakdown {
    /// Base rate applied (per unit)
    pub base_rate: u64,
    /// Total units of work (e.g., hours, tasks)
    pub total_units: u64,
    /// Multipliers applied (name -> factor in basis points, 10000 = 1.0)
    pub multipliers: Vec<(String, u64)>,
    /// Cap that was applied (if any)
    pub cap_applied: Option<CapApplication>,
}

impl PayoutBreakdown {
    /// Create a new breakdown
    pub fn new(base_rate: u64, total_units: u64) -> Self {
        Self {
            base_rate,
            total_units,
            multipliers: Vec::new(),
            cap_applied: None,
        }
    }

    /// Add a multiplier
    pub fn with_multiplier(mut self, name: &str, factor_bps: u64) -> Self {
        self.multipliers.push((name.to_string(), factor_bps));
        self
    }

    /// Set cap application
    pub fn with_cap(mut self, cap: CapApplication) -> Self {
        self.cap_applied = Some(cap);
        self
    }
}

/// Information about which cap was applied
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapApplication {
    /// Type of cap that was applied
    pub cap_type: CapType,
    /// Original amount before cap
    pub original_amount: u64,
    /// Cap value
    pub cap_value: u64,
    /// Amount after applying cap
    pub capped_amount: u64,
}

/// Types of caps that can be applied
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapType {
    /// Assignment annual cap (from snapshot)
    AssignmentAnnual,
    /// Assignment lifetime cap (from snapshot)
    AssignmentLifetime,
    /// Assignment epoch cap (from snapshot)
    AssignmentEpoch,
    /// Role period cap
    RolePeriod,
    /// Role lifetime cap
    RoleLifetime,
    /// Global pool cap
    Global,
}

impl fmt::Display for CapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssignmentAnnual => write!(f, "AssignmentAnnual"),
            Self::AssignmentLifetime => write!(f, "AssignmentLifetime"),
            Self::AssignmentEpoch => write!(f, "AssignmentEpoch"),
            Self::RolePeriod => write!(f, "RolePeriod"),
            Self::RoleLifetime => write!(f, "RoleLifetime"),
            Self::Global => write!(f, "Global"),
        }
    }
}

/// Record of a completed payment
///
/// Stored in PaidLedger to prevent double-payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// Epoch of the payment
    pub epoch: u64,
    /// Assignment that was paid
    pub assignment_id: AssignmentId,
    /// Amount paid
    pub amount: u64,
    /// Hash of the computation (for verification)
    pub computation_hash: ComputationHash,
    /// When payment was recorded
    pub paid_at_epoch: u64,
    /// Transaction ID of the credit operation
    pub transaction_id: TransactionId,
}

impl PaymentRecord {
    /// Create a new payment record
    pub fn new(
        epoch: u64,
        assignment_id: AssignmentId,
        amount: u64,
        computation_hash: ComputationHash,
        paid_at_epoch: u64,
        transaction_id: TransactionId,
    ) -> Self {
        Self {
            epoch,
            assignment_id,
            amount,
            computation_hash,
            paid_at_epoch,
            transaction_id,
        }
    }
}

/// Configuration for compensation calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensationConfig {
    /// Base rates per role (in smallest unit per work unit)
    pub base_rates: std::collections::BTreeMap<RoleId, u64>,
    /// Default base rate for roles not explicitly configured
    pub default_base_rate: u64,
}

impl CompensationConfig {
    /// Create a new config with default rate
    pub fn new(default_base_rate: u64) -> Self {
        Self {
            base_rates: std::collections::BTreeMap::new(),
            default_base_rate,
        }
    }

    /// Set rate for a specific role
    pub fn with_role_rate(mut self, role_id: RoleId, rate: u64) -> Self {
        self.base_rates.insert(role_id, rate);
        self
    }

    /// Get rate for a role
    pub fn get_rate(&self, role_id: &RoleId) -> u64 {
        self.base_rates.get(role_id).copied().unwrap_or(self.default_base_rate)
    }
}

impl Default for CompensationConfig {
    fn default() -> Self {
        Self::new(1000) // Default: 1000 units per work unit
    }
}

/// Economic constants for payout calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConstants {
    /// Maximum payout per epoch per assignment (hard limit)
    pub max_epoch_payout: u64,
    /// Minimum payout threshold (below this, no payout)
    pub min_payout_threshold: u64,
    /// Basis points denominator (10000 = 100%)
    pub basis_points_denominator: u64,
}

impl Default for EconomicConstants {
    fn default() -> Self {
        Self {
            max_epoch_payout: 100_000,
            min_payout_threshold: 1,
            basis_points_denominator: 10_000,
        }
    }
}

/// Compensation engine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompensationError {
    /// Metric is not finalized
    UnfinalizedMetric { key: MetricKey },
    /// Epoch mismatch in metric
    EpochMismatch { expected: u64, found: u64 },
    /// Epoch not closed yet
    EpochNotClosed { epoch: u64 },
    /// Already paid for this epoch
    AlreadyPaid {
        epoch: u64,
        assignment_id: AssignmentId,
        existing_tx: TransactionId,
    },
    /// No metrics found for compensation
    NoMetrics {
        epoch: u64,
        assignment_id: AssignmentId,
    },
    /// Insufficient attestations on metric
    InsufficientAttestations { metric_key: MetricKey },
    /// Assignment not found
    AssignmentNotFound(AssignmentId),
    /// Role not found
    RoleNotFound(RoleId),
    /// Payout would exceed cap
    CapExceeded {
        cap_type: CapType,
        amount: u64,
        cap: u64,
    },
    /// Computation mismatch (verification failed)
    ComputationMismatch {
        expected_hash: ComputationHash,
        actual_hash: ComputationHash,
    },
    /// Below minimum threshold
    BelowMinimumThreshold { amount: u64, threshold: u64 },
}

impl fmt::Display for CompensationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnfinalizedMetric { key } => {
                write!(f, "Metric not finalized: epoch={}, type={}", key.epoch, key.metric_type)
            }
            Self::EpochMismatch { expected, found } => {
                write!(f, "Epoch mismatch: expected={}, found={}", expected, found)
            }
            Self::EpochNotClosed { epoch } => {
                write!(f, "Epoch {} is not closed", epoch)
            }
            Self::AlreadyPaid { epoch, assignment_id, existing_tx } => {
                write!(
                    f,
                    "Already paid for epoch={}, assignment={:?}, tx={:?}",
                    epoch, &assignment_id[..4], &existing_tx[..4]
                )
            }
            Self::NoMetrics { epoch, assignment_id } => {
                write!(
                    f,
                    "No metrics for epoch={}, assignment={:?}",
                    epoch, &assignment_id[..4]
                )
            }
            Self::InsufficientAttestations { metric_key } => {
                write!(f, "Insufficient attestations for metric: epoch={}", metric_key.epoch)
            }
            Self::AssignmentNotFound(id) => {
                write!(f, "Assignment not found: {:?}", &id[..4])
            }
            Self::RoleNotFound(id) => {
                write!(f, "Role not found: {:?}", &id[..4])
            }
            Self::CapExceeded { cap_type, amount, cap } => {
                write!(f, "{} cap exceeded: amount={}, cap={}", cap_type, amount, cap)
            }
            Self::ComputationMismatch { expected_hash, actual_hash } => {
                write!(
                    f,
                    "Computation mismatch: expected={:?}, actual={:?}",
                    &expected_hash[..4], &actual_hash[..4]
                )
            }
            Self::BelowMinimumThreshold { amount, threshold } => {
                write!(f, "Amount {} below minimum threshold {}", amount, threshold)
            }
        }
    }
}

impl std::error::Error for CompensationError {}

/// Payment error for PaidLedger
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    /// Already paid for this epoch/assignment
    AlreadyPaid {
        epoch: u64,
        assignment_id: AssignmentId,
        existing_tx: TransactionId,
    },
    /// Payment not found
    PaymentNotFound {
        epoch: u64,
        assignment_id: AssignmentId,
    },
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPaid { epoch, assignment_id, existing_tx } => {
                write!(
                    f,
                    "Already paid for epoch={}, assignment={:?}, tx={:?}",
                    epoch, &assignment_id[..4], &existing_tx[..4]
                )
            }
            Self::PaymentNotFound { epoch, assignment_id } => {
                write!(
                    f,
                    "Payment not found for epoch={}, assignment={:?}",
                    epoch, &assignment_id[..4]
                )
            }
        }
    }
}

impl std::error::Error for PaymentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payout_breakdown() {
        let breakdown = PayoutBreakdown::new(100, 40)
            .with_multiplier("performance", 11000) // 110%
            .with_multiplier("seniority", 10500);  // 105%

        assert_eq!(breakdown.base_rate, 100);
        assert_eq!(breakdown.total_units, 40);
        assert_eq!(breakdown.multipliers.len(), 2);
    }

    #[test]
    fn test_compensation_config() {
        let role_id = [1u8; 32];
        let config = CompensationConfig::new(1000)
            .with_role_rate(role_id, 1500);

        assert_eq!(config.get_rate(&role_id), 1500);
        assert_eq!(config.get_rate(&[2u8; 32]), 1000); // Default
    }

    #[test]
    fn test_payment_record() {
        let record = PaymentRecord::new(
            1,
            [1u8; 32],
            50_000,
            [2u8; 32],
            2,
            [3u8; 32],
        );

        assert_eq!(record.epoch, 1);
        assert_eq!(record.amount, 50_000);
    }

    #[test]
    fn test_economic_constants_default() {
        let constants = EconomicConstants::default();
        assert_eq!(constants.basis_points_denominator, 10_000);
    }
}
