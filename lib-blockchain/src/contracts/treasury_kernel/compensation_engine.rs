//! Compensation Engine - Deterministic, Mechanical Payouts
//!
//! The Compensation Engine is a PURE COMPUTE function. Given the same inputs,
//! it MUST produce the same payout. No discretion, no override.
//!
//! # What the Engine Does
//! - Reads metrics (immutable after finalization)
//! - Reads role definitions
//! - Reads assignment snapshots
//! - Computes payout amount
//! - Returns calculation result
//!
//! # What the Engine Does NOT Do
//! - Hold mutable state
//! - Mutate balances directly
//! - Skip attestation checks
//! - Override caps
//! - Apply discretionary adjustments
//!
//! # Consensus-Critical
//! All computation uses integer math. Same inputs = same output.

use super::metric_types::{MetricRecord, MetricType};
use super::payout_types::{
    CapApplication, CapType, CompensationConfig, CompensationError, ComputationHash,
    EconomicConstants, PayoutBreakdown, PayoutCalculation,
};
use super::role_types::{Assignment, RoleDefinition};
use serde::{Deserialize, Serialize};

/// Compensation Engine - pure compute, no state mutation
///
/// # Thread Safety
/// The engine holds only configuration (immutable after creation).
/// All methods take inputs by reference and return computed values.
///
/// # Determinism Guarantee
/// `compute_payout()` is a pure function. Given identical inputs,
/// it will ALWAYS return identical outputs. This is enforced by:
/// - Using only integer arithmetic
/// - Sorting inputs deterministically before hashing
/// - No external state or randomness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensationEngine {
    /// Configuration (immutable after creation)
    config: CompensationConfig,
}

impl CompensationEngine {
    /// Create a new compensation engine
    pub fn new(config: CompensationConfig) -> Self {
        Self { config }
    }

    /// Compute payout from inputs (PURE FUNCTION)
    ///
    /// # Arguments
    /// * `metrics` - Finalized metrics for this assignment/epoch
    /// * `role` - Role definition
    /// * `assignment` - Assignment with snapshotted caps
    /// * `epoch` - Epoch for which to compute
    /// * `constants` - Economic constants
    ///
    /// # Returns
    /// PayoutCalculation with deterministic result
    ///
    /// # Determinism
    /// Same inputs ALWAYS produce same output. The computation hash
    /// can be used to verify this.
    pub fn compute_payout(
        &self,
        metrics: &[MetricRecord],
        role: &RoleDefinition,
        assignment: &Assignment,
        epoch: u64,
        constants: &EconomicConstants,
    ) -> Result<PayoutCalculation, CompensationError> {
        // Validate all inputs
        self.validate_inputs(metrics, epoch)?;

        // Compute base amount from metrics
        let (base_amount, total_units) = self.compute_base_amount(metrics, role)?;

        // Apply multipliers (none for now - can be extended)
        let multiplied_amount = base_amount;

        // Apply caps from assignment snapshot
        let (final_amount, cap_applied) =
            self.apply_caps(multiplied_amount, assignment, epoch, constants)?;

        // Check minimum threshold
        if final_amount < constants.min_payout_threshold && final_amount > 0 {
            return Err(CompensationError::BelowMinimumThreshold {
                amount: final_amount,
                threshold: constants.min_payout_threshold,
            });
        }

        // Build breakdown
        let breakdown = PayoutBreakdown::new(self.config.get_rate(&role.role_id), total_units)
            .with_cap_if(cap_applied);

        // Compute deterministic hash of inputs
        let computation_hash = self.hash_computation(metrics, role, assignment, epoch);

        Ok(PayoutCalculation {
            assignment_id: assignment.assignment_id,
            epoch,
            base_amount,
            multiplied_amount,
            final_amount,
            computation_hash,
            breakdown,
        })
    }

    /// Validate all input metrics
    fn validate_inputs(&self, metrics: &[MetricRecord], epoch: u64) -> Result<(), CompensationError> {
        for metric in metrics {
            // Check finalized
            if !metric.finalized {
                return Err(CompensationError::UnfinalizedMetric {
                    key: metric.key.clone(),
                });
            }

            // Check epoch match
            if metric.key.epoch != epoch {
                return Err(CompensationError::EpochMismatch {
                    expected: epoch,
                    found: metric.key.epoch,
                });
            }
        }
        Ok(())
    }

    /// Compute base amount from metrics
    ///
    /// Uses integer arithmetic only. No floating point.
    fn compute_base_amount(
        &self,
        metrics: &[MetricRecord],
        role: &RoleDefinition,
    ) -> Result<(u64, u64), CompensationError> {
        let rate = self.config.get_rate(&role.role_id);

        // Sum up work units (primarily hours, but could be other types)
        let total_units: u64 = metrics
            .iter()
            .filter(|m| matches!(m.key.metric_type, MetricType::HoursWorked))
            .map(|m| m.value)
            .sum();

        // Base calculation: rate * units
        // Use saturating arithmetic so overflow deterministically clamps to u64::MAX
        let base_amount = rate.saturating_mul(total_units);

        Ok((base_amount, total_units))
    }

    /// Apply caps from assignment snapshot
    ///
    /// Returns (capped_amount, cap_applied_if_any)
    fn apply_caps(
        &self,
        amount: u64,
        assignment: &Assignment,
        _epoch: u64,
        constants: &EconomicConstants,
    ) -> Result<(u64, Option<CapApplication>), CompensationError> {
        let mut result = amount;
        let mut cap_applied = None;

        // Check against hard global epoch cap (from EconomicConstants)
        // This is the absolute maximum per epoch per assignment
        if result > constants.max_epoch_payout {
            cap_applied = Some(CapApplication {
                cap_type: CapType::AssignmentEpoch,
                original_amount: result,
                cap_value: constants.max_epoch_payout,
                capped_amount: constants.max_epoch_payout,
            });
            result = constants.max_epoch_payout;
        }

        // Check against snapshotted per-epoch cap (from assignment snapshot)
        // This is the role-specific cap snapshotted at assignment time
        if result > assignment.snap_per_epoch_cap {
            cap_applied = Some(CapApplication {
                cap_type: CapType::AssignmentEpoch,
                original_amount: result,
                cap_value: assignment.snap_per_epoch_cap,
                capped_amount: assignment.snap_per_epoch_cap,
            });
            result = assignment.snap_per_epoch_cap;
        }

        // Check against remaining annual cap
        let remaining_annual = assignment.snap_annual_cap.saturating_sub(assignment.current_year_paid);
        if result > remaining_annual {
            cap_applied = Some(CapApplication {
                cap_type: CapType::AssignmentAnnual,
                original_amount: result,
                cap_value: remaining_annual,
                capped_amount: remaining_annual,
            });
            result = remaining_annual;
        }

        // Check against remaining lifetime cap (if set)
        if let Some(lifetime_cap) = assignment.snap_lifetime_cap {
            let remaining_lifetime = lifetime_cap.saturating_sub(assignment.total_paid);
            if result > remaining_lifetime {
                cap_applied = Some(CapApplication {
                    cap_type: CapType::AssignmentLifetime,
                    original_amount: result,
                    cap_value: remaining_lifetime,
                    capped_amount: remaining_lifetime,
                });
                result = remaining_lifetime;
            }
        }

        Ok((result, cap_applied))
    }

    /// Hash computation inputs for verification/replay
    ///
    /// Uses deterministic ordering (sorted by metric key).
    fn hash_computation(
        &self,
        metrics: &[MetricRecord],
        role: &RoleDefinition,
        assignment: &Assignment,
        epoch: u64,
    ) -> ComputationHash {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Hash metrics in deterministic order (sorted by key)
        let mut sorted_metrics: Vec<_> = metrics.iter().collect();
        sorted_metrics.sort_by(|a, b| a.key.cmp(&b.key));

        for metric in sorted_metrics {
            hasher.update(&metric.key.epoch.to_le_bytes());
            hasher.update(&metric.key.assignment_id);
            // Use bincode for deterministic serialization instead of Debug formatting
            if let Ok(serialized) = bincode::serialize(&metric.key.metric_type) {
                hasher.update(&serialized);
            }
            hasher.update(&metric.value.to_le_bytes());
        }

        // Hash role
        hasher.update(&role.role_id);
        hasher.update(&role.annual_cap.to_le_bytes());

        // Hash assignment
        hasher.update(&assignment.assignment_id);
        hasher.update(&assignment.snap_annual_cap.to_le_bytes());
        // Hash lifetime cap - use 0 for None to maintain determinism
        let lifetime_cap_value = assignment.snap_lifetime_cap.unwrap_or(0);
        hasher.update(&lifetime_cap_value.to_le_bytes());

        // Hash epoch
        hasher.update(&epoch.to_le_bytes());

        // Finalize hash - Blake3 provides full 32 bytes
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Verify a computation matches expected hash
    pub fn verify_computation(
        &self,
        metrics: &[MetricRecord],
        role: &RoleDefinition,
        assignment: &Assignment,
        epoch: u64,
        expected_hash: &ComputationHash,
    ) -> Result<(), CompensationError> {
        let actual_hash = self.hash_computation(metrics, role, assignment, epoch);
        if &actual_hash != expected_hash {
            return Err(CompensationError::ComputationMismatch {
                expected_hash: *expected_hash,
                actual_hash,
            });
        }
        Ok(())
    }
}

impl Default for CompensationEngine {
    fn default() -> Self {
        Self::new(CompensationConfig::default())
    }
}

/// Helper trait for PayoutBreakdown
trait PayoutBreakdownExt {
    fn with_cap_if(self, cap: Option<CapApplication>) -> Self;
}

impl PayoutBreakdownExt for PayoutBreakdown {
    fn with_cap_if(self, cap: Option<CapApplication>) -> Self {
        match cap {
            Some(c) => self.with_cap(c),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::treasury_kernel::metric_types::{MetricKey, MetricType};
    use crate::contracts::treasury_kernel::role_types::AssignmentStatus;

    fn test_role_id() -> [u8; 32] {
        [1u8; 32]
    }

    fn test_assignment_id() -> [u8; 32] {
        [2u8; 32]
    }

    fn test_person_id() -> [u8; 32] {
        [3u8; 32]
    }

    fn test_role() -> RoleDefinition {
        RoleDefinition {
            role_id: test_role_id(),
            name: "Engineer".to_string(),
            description: "Software Engineer".to_string(),
            annual_cap: 100_000,
            lifetime_cap: None,
            per_epoch_cap: 10_000,
            created_at_epoch: 1,
            is_active: true,
            requires_attestation: false,
        }
    }

    fn test_assignment() -> Assignment {
        Assignment {
            assignment_id: test_assignment_id(),
            person_id: test_person_id(),
            role_id: test_role_id(),
            snap_annual_cap: 100_000,
            snap_lifetime_cap: None,
            snap_per_epoch_cap: 10_000,
            total_paid: 0,
            current_year_paid: 0,
            current_epoch_paid: 0,
            last_payment_epoch: None,
            status: AssignmentStatus::Active,
            assigned_at_epoch: 1,
            assigned_in_year: 2024,
            current_year: 2024,
            suspended_at_epoch: None,
            terminated_at_epoch: None,
        }
    }

    fn test_metric(hours: u64, finalized: bool) -> MetricRecord {
        let mut record = MetricRecord::new(
            MetricKey::new(1, test_assignment_id(), MetricType::HoursWorked),
            hours,
            1,
            [50u8; 32],
        );
        if finalized {
            record.finalize(1);
        }
        record
    }

    fn test_constants() -> EconomicConstants {
        EconomicConstants {
            max_epoch_payout: 100_000,
            min_payout_threshold: 1,
            basis_points_denominator: 10_000,
        }
    }

    #[test]
    fn test_same_inputs_produce_same_payout() {
        let engine = CompensationEngine::new(CompensationConfig::new(100));
        let metrics = vec![test_metric(40, true)];
        let role = test_role();
        let assignment = test_assignment();
        let constants = test_constants();

        // First computation
        let calc1 = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // Second computation with same inputs
        let calc2 = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // MUST be identical
        assert_eq!(calc1.final_amount, calc2.final_amount);
        assert_eq!(calc1.computation_hash, calc2.computation_hash);
    }

    #[test]
    fn test_unfinalized_metric_fails() {
        let engine = CompensationEngine::default();
        let metrics = vec![test_metric(40, false)]; // Not finalized
        let role = test_role();
        let assignment = test_assignment();
        let constants = test_constants();

        let result = engine.compute_payout(&metrics, &role, &assignment, 1, &constants);

        assert!(matches!(
            result,
            Err(CompensationError::UnfinalizedMetric { .. })
        ));
    }

    #[test]
    fn test_epoch_mismatch_fails() {
        let engine = CompensationEngine::default();
        let metrics = vec![test_metric(40, true)]; // Epoch 1
        let role = test_role();
        let assignment = test_assignment();
        let constants = test_constants();

        // Request computation for epoch 2, but metric is from epoch 1
        let result = engine.compute_payout(&metrics, &role, &assignment, 2, &constants);

        assert!(matches!(
            result,
            Err(CompensationError::EpochMismatch { expected: 2, found: 1 })
        ));
    }

    #[test]
    fn test_cap_applied() {
        let engine = CompensationEngine::new(CompensationConfig::new(1000)); // High rate
        let metrics = vec![test_metric(100, true)]; // 100 hours = 100,000 base
        let role = test_role();
        let mut assignment = test_assignment();
        assignment.snap_per_epoch_cap = 50_000; // Cap at 50k per epoch
        let constants = test_constants();

        let calc = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // Should be capped at 50k
        assert_eq!(calc.final_amount, 50_000);
        assert!(calc.breakdown.cap_applied.is_some());
    }

    #[test]
    fn test_computation_hash_deterministic() {
        let engine = CompensationEngine::default();
        let metrics = vec![test_metric(40, true)];
        let role = test_role();
        let assignment = test_assignment();

        let hash1 = engine.hash_computation(&metrics, &role, &assignment, 1);
        let hash2 = engine.hash_computation(&metrics, &role, &assignment, 1);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_computation() {
        let engine = CompensationEngine::default();
        let metrics = vec![test_metric(40, true)];
        let role = test_role();
        let assignment = test_assignment();
        let constants = test_constants();

        let calc = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // Verification should pass
        assert!(engine
            .verify_computation(&metrics, &role, &assignment, 1, &calc.computation_hash)
            .is_ok());

        // Wrong hash should fail
        let wrong_hash = [99u8; 32];
        assert!(matches!(
            engine.verify_computation(&metrics, &role, &assignment, 1, &wrong_hash),
            Err(CompensationError::ComputationMismatch { .. })
        ));
    }

    #[test]
    fn test_empty_metrics_zero_payout() {
        let engine = CompensationEngine::default();
        let metrics: Vec<MetricRecord> = vec![]; // No metrics
        let role = test_role();
        let assignment = test_assignment();
        let constants = test_constants();

        let calc = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        assert_eq!(calc.final_amount, 0);
    }

    #[test]
    fn test_annual_cap_respected() {
        let engine = CompensationEngine::new(CompensationConfig::new(1000));
        let metrics = vec![test_metric(40, true)]; // 40,000 base
        let role = test_role();
        let mut assignment = test_assignment();
        assignment.current_year_paid = 90_000; // Already paid 90k this year
        assignment.snap_annual_cap = 100_000; // 100k annual cap
        let constants = test_constants();

        let calc = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // Only 10k remaining in annual cap
        assert_eq!(calc.final_amount, 10_000);
    }

    #[test]
    fn test_lifetime_cap_respected() {
        let engine = CompensationEngine::new(CompensationConfig::new(1000));
        let metrics = vec![test_metric(40, true)]; // 40,000 base
        let role = test_role();
        let mut assignment = test_assignment();
        assignment.snap_lifetime_cap = Some(50_000);
        assignment.total_paid = 30_000; // Already paid 30k lifetime
        assignment.snap_per_epoch_cap = 100_000; // High per-epoch cap so lifetime cap is the limiting factor
        let constants = test_constants();

        let calc = engine
            .compute_payout(&metrics, &role, &assignment, 1, &constants)
            .unwrap();

        // Only 20k remaining in lifetime cap
        assert_eq!(calc.final_amount, 20_000);
    }
}
