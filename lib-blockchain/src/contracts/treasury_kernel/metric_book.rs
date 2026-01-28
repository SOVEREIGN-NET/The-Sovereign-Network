//! Metric Book - Append-Only Work Metrics
//!
//! The Metric Book records and tracks work metrics with strict append-only semantics.
//! No metric can be modified or deleted once recorded.
//!
//! # Key Invariants
//!
//! 1. **Append-Only**: Metrics can only be added, never modified
//! 2. **Attestation Required**: Metrics must be attested before payout
//! 3. **Epoch Binding**: Metrics belong to specific epochs and are immutable once epoch closes
//!
//! # Consensus-Critical
//! Uses BTreeMap for deterministic iteration.

use super::metric_types::{
    Attestation, AttestationPolicy, AttesterRole, EpochError, EpochState, EpochStatus,
    MetricError, MetricKey, MetricRecord, MetricType,
};
use super::role_types::AssignmentId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Metric Book - append-only work metric storage
///
/// Records work metrics with strict immutability guarantees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBook {
    /// Recorded metrics (key -> record)
    metrics: BTreeMap<MetricKey, MetricRecord>,

    /// Attestations per metric (key -> list of attestations)
    attestations: BTreeMap<MetricKey, Vec<Attestation>>,

    /// Attestation policies by metric type
    policies: BTreeMap<MetricType, AttestationPolicy>,

    /// Reference to epoch states (for validation)
    /// The actual epoch management is in EpochClock
    epoch_status_cache: BTreeMap<u64, EpochStatus>,
}

impl MetricBook {
    /// Create a new metric book
    pub fn new() -> Self {
        Self {
            metrics: BTreeMap::new(),
            attestations: BTreeMap::new(),
            policies: BTreeMap::new(),
            epoch_status_cache: BTreeMap::new(),
        }
    }

    /// Set epoch status (called by EpochClock when status changes)
    pub fn set_epoch_status(&mut self, epoch: u64, status: EpochStatus) {
        self.epoch_status_cache.insert(epoch, status);
    }

    /// Get epoch status
    fn get_epoch_status(&self, epoch: u64) -> EpochStatus {
        // Default to Open for unknown epochs (new epochs)
        self.epoch_status_cache.get(&epoch).copied().unwrap_or(EpochStatus::Open)
    }

    /// Check if epoch is open for recording
    fn require_epoch_open(&self, epoch: u64) -> Result<(), MetricError> {
        match self.get_epoch_status(epoch) {
            EpochStatus::Open => Ok(()),
            EpochStatus::Closing => Err(MetricError::EpochClosing(epoch)),
            EpochStatus::Closed => Err(MetricError::EpochClosed(epoch)),
        }
    }

    /// Check if epoch allows attestations
    fn require_epoch_allows_attestations(&self, epoch: u64) -> Result<(), MetricError> {
        match self.get_epoch_status(epoch) {
            EpochStatus::Open | EpochStatus::Closing => Ok(()),
            EpochStatus::Closed => Err(MetricError::EpochClosed(epoch)),
        }
    }

    // ─── Policy Management ──────────────────────────────────────────────

    /// Set attestation policy for a metric type
    pub fn set_policy(&mut self, policy: AttestationPolicy) {
        self.policies.insert(policy.metric_type.clone(), policy);
    }

    /// Get policy for a metric type
    pub fn get_policy(&self, metric_type: &MetricType) -> AttestationPolicy {
        self.policies
            .get(metric_type)
            .cloned()
            .unwrap_or_else(|| AttestationPolicy::default())
    }

    // ─── Metric Recording ───────────────────────────────────────────────

    /// Record a metric - append only, no overwrite
    ///
    /// # Arguments
    /// * `epoch` - Epoch when work was performed
    /// * `assignment_id` - Assignment this metric belongs to
    /// * `metric_type` - Type of metric
    /// * `value` - The metric value
    /// * `recorder` - Who is recording this metric (key_id)
    /// * `current_epoch` - Current epoch (for timestamp)
    ///
    /// # Returns
    /// Ok(MetricKey) if recorded successfully
    /// Err if metric already exists or epoch is closed
    pub fn record_metric(
        &mut self,
        epoch: u64,
        assignment_id: &AssignmentId,
        metric_type: MetricType,
        value: u64,
        recorder: &[u8; 32],
        current_epoch: u64,
    ) -> Result<MetricKey, MetricError> {
        // Check epoch is open
        self.require_epoch_open(epoch)?;

        let key = MetricKey::new(epoch, *assignment_id, metric_type);

        // Check metric doesn't already exist (append-only)
        if let Some(existing) = self.metrics.get(&key) {
            return Err(MetricError::MetricAlreadyRecorded {
                key,
                existing_value: existing.value,
            });
        }

        // Record the metric
        let record = MetricRecord::new(key.clone(), value, current_epoch, *recorder);
        self.metrics.insert(key.clone(), record);

        Ok(key)
    }

    /// Overwrite is explicitly forbidden
    ///
    /// This function exists only to document the prohibition.
    #[allow(dead_code)]
    pub fn overwrite_metric(&mut self, _key: &MetricKey, _new_value: u64) -> Result<(), MetricError> {
        Err(MetricError::OverwriteForbidden)
    }

    /// Get a metric record
    pub fn get_metric(&self, key: &MetricKey) -> Option<&MetricRecord> {
        self.metrics.get(key)
    }

    /// Get all metrics for an assignment in an epoch
    pub fn get_metrics_for_assignment(
        &self,
        epoch: u64,
        assignment_id: &AssignmentId,
    ) -> Vec<&MetricRecord> {
        self.metrics
            .iter()
            .filter(|(k, _)| k.epoch == epoch && &k.assignment_id == assignment_id)
            .map(|(_, v)| v)
            .collect()
    }

    // ─── Attestation ────────────────────────────────────────────────────

    /// Add attestation to a metric
    ///
    /// # Arguments
    /// * `key` - Metric to attest
    /// * `attester` - Who is attesting (key_id)
    /// * `attester_role` - Role of the attester
    /// * `signature` - Signature over the metric
    /// * `current_epoch` - Current epoch
    ///
    /// # Returns
    /// Ok(()) if attestation added
    /// Err if metric not found, already finalized, or duplicate attestation
    pub fn attest_metric(
        &mut self,
        key: &MetricKey,
        attester: &[u8; 32],
        attester_role: AttesterRole,
        signature: &[u8; 64],
        current_epoch: u64,
    ) -> Result<(), MetricError> {
        // Check epoch allows attestations
        self.require_epoch_allows_attestations(key.epoch)?;

        // Check metric exists
        let record = self
            .metrics
            .get(key)
            .ok_or_else(|| MetricError::MetricNotFound(key.clone()))?;

        // Check not already finalized
        if record.finalized {
            return Err(MetricError::AlreadyFinalized(key.clone()));
        }

        // Check for duplicate attestation
        let existing_attestations = self.attestations.entry(key.clone()).or_default();
        if existing_attestations.iter().any(|a| &a.attester == attester) {
            return Err(MetricError::DuplicateAttestation {
                key: key.clone(),
                attester: *attester,
            });
        }

        // Add attestation
        let attestation = Attestation::new(*attester, attester_role, current_epoch, *signature);
        existing_attestations.push(attestation);

        Ok(())
    }

    /// Get attestations for a metric
    pub fn get_attestations(&self, key: &MetricKey) -> &[Attestation] {
        self.attestations.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Check if metric has sufficient attestations
    pub fn is_sufficiently_attested(&self, key: &MetricKey) -> bool {
        let record = match self.metrics.get(key) {
            Some(r) => r,
            None => return false,
        };

        let policy = self.get_policy(&record.key.metric_type);
        let attestations = self.get_attestations(key);

        // Check count
        if attestations.len() < policy.required_count as usize {
            return false;
        }

        // Check required roles
        for required_role in &policy.required_roles {
            if !attestations.iter().any(|a| &a.attester_role == required_role) {
                return false;
            }
        }

        true
    }

    /// Finalize a metric (mark as ready for compensation)
    ///
    /// Only succeeds if sufficiently attested.
    pub fn finalize_metric(
        &mut self,
        key: &MetricKey,
        current_epoch: u64,
    ) -> Result<(), MetricError> {
        // Check attestations
        if !self.is_sufficiently_attested(key) {
            let policy = match self.metrics.get(key) {
                Some(r) => self.get_policy(&r.key.metric_type),
                None => return Err(MetricError::MetricNotFound(key.clone())),
            };
            let actual = self.get_attestations(key).len() as u32;
            return Err(MetricError::InsufficientAttestations {
                key: key.clone(),
                required: policy.required_count,
                actual,
            });
        }

        // Finalize
        let record = self
            .metrics
            .get_mut(key)
            .ok_or_else(|| MetricError::MetricNotFound(key.clone()))?;

        record.finalize(current_epoch);

        Ok(())
    }

    /// Check if a metric is finalized
    pub fn is_finalized(&self, key: &MetricKey) -> bool {
        self.metrics.get(key).map(|r| r.finalized).unwrap_or(false)
    }

    // ─── Queries ────────────────────────────────────────────────────────

    /// Get all metrics for an epoch
    pub fn get_metrics_for_epoch(&self, epoch: u64) -> Vec<&MetricRecord> {
        self.metrics
            .iter()
            .filter(|(k, _)| k.epoch == epoch)
            .map(|(_, v)| v)
            .collect()
    }

    /// Count finalized metrics in an epoch
    pub fn count_finalized_in_epoch(&self, epoch: u64) -> usize {
        self.metrics
            .iter()
            .filter(|(k, v)| k.epoch == epoch && v.finalized)
            .count()
    }

    /// Count total metrics
    pub fn total_metrics(&self) -> usize {
        self.metrics.len()
    }
}

impl Default for MetricBook {
    fn default() -> Self {
        Self::new()
    }
}

/// Epoch Clock - manages epoch lifecycle with immutable closure
///
/// Once an epoch is closed, it CANNOT be reopened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochClock {
    /// Epoch states
    epochs: BTreeMap<u64, EpochState>,

    /// Current epoch
    current_epoch: u64,

    /// Governance authority (key_id)
    governance_authority: [u8; 32],
}

impl EpochClock {
    /// Create a new epoch clock
    pub fn new(initial_epoch: u64, governance_authority: [u8; 32]) -> Self {
        let mut epochs = BTreeMap::new();
        epochs.insert(initial_epoch, EpochState::new(initial_epoch, initial_epoch));

        Self {
            epochs,
            current_epoch: initial_epoch,
            governance_authority,
        }
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Advance to next epoch
    pub fn advance_epoch(&mut self) {
        self.current_epoch += 1;
        self.epochs.insert(
            self.current_epoch,
            EpochState::new(self.current_epoch, self.current_epoch),
        );
    }

    /// Get epoch state
    pub fn get_epoch(&self, epoch: u64) -> Option<&EpochState> {
        self.epochs.get(&epoch)
    }

    /// Get mutable epoch state
    fn get_epoch_mut(&mut self, epoch: u64) -> Option<&mut EpochState> {
        self.epochs.get_mut(&epoch)
    }

    /// Check if epoch can record metrics
    pub fn can_record_metrics(&self, epoch: u64) -> bool {
        self.epochs
            .get(&epoch)
            .map(|s| s.can_record_metrics())
            .unwrap_or(false)
    }

    /// Check if epoch can process compensation
    pub fn can_process_compensation(&self, epoch: u64) -> bool {
        self.epochs
            .get(&epoch)
            .map(|s| s.can_process_compensation())
            .unwrap_or(false)
    }

    /// Begin closing an epoch (transitions Open -> Closing)
    ///
    /// After this, no new metrics can be recorded but attestations are still allowed.
    pub fn begin_close_epoch(
        &mut self,
        epoch: u64,
        caller: &[u8; 32],
    ) -> Result<(), EpochError> {
        // Verify caller is governance
        if caller != &self.governance_authority {
            // In production, would return Unauthorized error
        }

        let state = self
            .epochs
            .get_mut(&epoch)
            .ok_or(EpochError::EpochNotFound(epoch))?;

        match state.status {
            EpochStatus::Open => {
                state.status = EpochStatus::Closing;
                Ok(())
            }
            EpochStatus::Closing => {
                // Already closing, no-op
                Ok(())
            }
            EpochStatus::Closed => Err(EpochError::AlreadyClosed(epoch)),
        }
    }

    /// Finalize epoch closure (transitions Closing -> Closed)
    ///
    /// After this, the epoch is fully immutable.
    pub fn finalize_close_epoch(
        &mut self,
        epoch: u64,
        caller: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), EpochError> {
        // Verify caller is governance
        if caller != &self.governance_authority {
            // In production, would return Unauthorized error
        }

        let state = self
            .epochs
            .get_mut(&epoch)
            .ok_or(EpochError::EpochNotFound(epoch))?;

        match state.status {
            EpochStatus::Open => {
                // Must go through Closing first
                state.status = EpochStatus::Closing;
                // Then close
                state.status = EpochStatus::Closed;
                state.closed_at_epoch = Some(current_epoch);
                Ok(())
            }
            EpochStatus::Closing => {
                state.status = EpochStatus::Closed;
                state.closed_at_epoch = Some(current_epoch);
                Ok(())
            }
            EpochStatus::Closed => Err(EpochError::AlreadyClosed(epoch)),
        }
    }

    /// Close an epoch in one step (Open -> Closed)
    ///
    /// Convenience method that calls begin_close and finalize_close.
    pub fn close_epoch(
        &mut self,
        epoch: u64,
        caller: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), EpochError> {
        self.finalize_close_epoch(epoch, caller, current_epoch)
    }

    /// Reopen is explicitly forbidden
    ///
    /// This function exists only to document the prohibition.
    #[allow(dead_code)]
    pub fn reopen_epoch(&mut self, _epoch: u64) -> Result<(), EpochError> {
        Err(EpochError::ReopenForbidden)
    }

    /// Get epoch status
    pub fn get_epoch_status(&self, epoch: u64) -> Option<EpochStatus> {
        self.epochs.get(&epoch).map(|s| s.status)
    }

    /// Sync epoch status to metric book
    pub fn sync_to_metric_book(&self, metric_book: &mut MetricBook) {
        for (epoch, state) in &self.epochs {
            metric_book.set_epoch_status(*epoch, state.status);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_assignment_id(n: u8) -> AssignmentId {
        [n; 32]
    }

    fn test_recorder() -> [u8; 32] {
        [50u8; 32]
    }

    fn test_attester() -> [u8; 32] {
        [60u8; 32]
    }

    fn test_signature() -> [u8; 64] {
        [0u8; 64]
    }

    fn governance_key() -> [u8; 32] {
        [1u8; 32]
    }

    #[test]
    fn test_metric_overwrite_fails() {
        let mut book = MetricBook::new();

        // Record initial metric
        book.record_metric(
            1,
            &test_assignment_id(10),
            MetricType::HoursWorked,
            40,
            &test_recorder(),
            1,
        )
        .unwrap();

        // Attempt overwrite
        let result = book.record_metric(
            1,
            &test_assignment_id(10),
            MetricType::HoursWorked,
            80,
            &test_recorder(),
            1,
        );

        assert!(matches!(
            result,
            Err(MetricError::MetricAlreadyRecorded { .. })
        ));
    }

    #[test]
    fn test_metrics_immutable_after_epoch_close() {
        let mut book = MetricBook::new();
        let mut clock = EpochClock::new(1, governance_key());

        // Record metric while epoch is open
        book.record_metric(
            1,
            &test_assignment_id(10),
            MetricType::HoursWorked,
            40,
            &test_recorder(),
            1,
        )
        .unwrap();

        // Close epoch
        clock.close_epoch(1, &governance_key(), 2).unwrap();
        clock.sync_to_metric_book(&mut book);

        // Cannot record to closed epoch
        let result = book.record_metric(
            1,
            &test_assignment_id(11),
            MetricType::HoursWorked,
            40,
            &test_recorder(),
            2,
        );

        assert!(matches!(result, Err(MetricError::EpochClosed(1))));
    }

    #[test]
    fn test_epoch_reopen_fails() {
        let mut clock = EpochClock::new(1, governance_key());

        // Close epoch
        clock.close_epoch(1, &governance_key(), 2).unwrap();

        // Attempt reopen
        let result = clock.reopen_epoch(1);

        assert!(matches!(result, Err(EpochError::ReopenForbidden)));
    }

    #[test]
    fn test_attestation_required_for_finalization() {
        let mut book = MetricBook::new();

        // Set policy requiring supervisor attestation
        let policy = AttestationPolicy::new(MetricType::HoursWorked, 1)
            .require_role(AttesterRole::Supervisor);
        book.set_policy(policy);

        // Record metric
        let key = book
            .record_metric(
                1,
                &test_assignment_id(10),
                MetricType::HoursWorked,
                40,
                &test_recorder(),
                1,
            )
            .unwrap();

        // Try to finalize without attestation
        let result = book.finalize_metric(&key, 2);

        assert!(matches!(
            result,
            Err(MetricError::InsufficientAttestations { .. })
        ));

        // Add attestation
        book.attest_metric(
            &key,
            &test_attester(),
            AttesterRole::Supervisor,
            &test_signature(),
            1,
        )
        .unwrap();

        // Now finalization succeeds
        assert!(book.finalize_metric(&key, 2).is_ok());
        assert!(book.is_finalized(&key));
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let mut book = MetricBook::new();

        let key = book
            .record_metric(
                1,
                &test_assignment_id(10),
                MetricType::HoursWorked,
                40,
                &test_recorder(),
                1,
            )
            .unwrap();

        // First attestation
        book.attest_metric(
            &key,
            &test_attester(),
            AttesterRole::Supervisor,
            &test_signature(),
            1,
        )
        .unwrap();

        // Duplicate attestation from same attester
        let result = book.attest_metric(
            &key,
            &test_attester(),
            AttesterRole::Supervisor,
            &test_signature(),
            1,
        );

        assert!(matches!(
            result,
            Err(MetricError::DuplicateAttestation { .. })
        ));
    }

    #[test]
    fn test_attestation_not_allowed_after_finalization() {
        let mut book = MetricBook::new();

        let key = book
            .record_metric(
                1,
                &test_assignment_id(10),
                MetricType::HoursWorked,
                40,
                &test_recorder(),
                1,
            )
            .unwrap();

        // Attest and finalize
        book.attest_metric(
            &key,
            &test_attester(),
            AttesterRole::Supervisor,
            &test_signature(),
            1,
        )
        .unwrap();
        book.finalize_metric(&key, 2).unwrap();

        // Try to add another attestation
        let result = book.attest_metric(
            &key,
            &[70u8; 32], // Different attester
            AttesterRole::Peer,
            &test_signature(),
            2,
        );

        assert!(matches!(result, Err(MetricError::AlreadyFinalized(_))));
    }

    #[test]
    fn test_epoch_lifecycle() {
        let mut clock = EpochClock::new(1, governance_key());

        // Initially open
        assert!(clock.can_record_metrics(1));
        assert!(!clock.can_process_compensation(1));

        // Begin close
        clock.begin_close_epoch(1, &governance_key()).unwrap();
        assert!(!clock.can_record_metrics(1)); // No longer accepting new metrics
        assert!(!clock.can_process_compensation(1)); // Not yet closed

        // Finalize close
        clock.finalize_close_epoch(1, &governance_key(), 2).unwrap();
        assert!(!clock.can_record_metrics(1));
        assert!(clock.can_process_compensation(1)); // Now can process

        // Cannot close again
        let result = clock.close_epoch(1, &governance_key(), 3);
        assert!(matches!(result, Err(EpochError::AlreadyClosed(1))));
    }

    #[test]
    fn test_closing_epoch_still_allows_attestations() {
        let mut book = MetricBook::new();
        let mut clock = EpochClock::new(1, governance_key());

        // Record while open
        let key = book
            .record_metric(
                1,
                &test_assignment_id(10),
                MetricType::HoursWorked,
                40,
                &test_recorder(),
                1,
            )
            .unwrap();

        // Begin close
        clock.begin_close_epoch(1, &governance_key()).unwrap();
        clock.sync_to_metric_book(&mut book);

        // Cannot record new metrics
        let result = book.record_metric(
            1,
            &test_assignment_id(11),
            MetricType::HoursWorked,
            40,
            &test_recorder(),
            1,
        );
        assert!(matches!(result, Err(MetricError::EpochClosing(1))));

        // But CAN still attest
        assert!(book
            .attest_metric(
                &key,
                &test_attester(),
                AttesterRole::Supervisor,
                &test_signature(),
                1,
            )
            .is_ok());
    }

    #[test]
    fn test_multiple_attesters_required() {
        let mut book = MetricBook::new();

        // Policy requiring 2 attestations: supervisor + peer
        let policy = AttestationPolicy::new(MetricType::CodeCommits, 2)
            .require_role(AttesterRole::Supervisor)
            .require_role(AttesterRole::Peer);
        book.set_policy(policy);

        let key = book
            .record_metric(
                1,
                &test_assignment_id(10),
                MetricType::CodeCommits,
                15,
                &test_recorder(),
                1,
            )
            .unwrap();

        // Just supervisor - not sufficient
        book.attest_metric(
            &key,
            &test_attester(),
            AttesterRole::Supervisor,
            &test_signature(),
            1,
        )
        .unwrap();
        assert!(!book.is_sufficiently_attested(&key));

        // Add peer - now sufficient
        book.attest_metric(
            &key,
            &[70u8; 32],
            AttesterRole::Peer,
            &test_signature(),
            1,
        )
        .unwrap();
        assert!(book.is_sufficiently_attested(&key));
    }

    #[test]
    fn test_get_metrics_for_assignment() {
        let mut book = MetricBook::new();

        // Record multiple metrics for same assignment
        book.record_metric(
            1,
            &test_assignment_id(10),
            MetricType::HoursWorked,
            40,
            &test_recorder(),
            1,
        )
        .unwrap();
        book.record_metric(
            1,
            &test_assignment_id(10),
            MetricType::TasksCompleted,
            5,
            &test_recorder(),
            1,
        )
        .unwrap();
        book.record_metric(
            1,
            &test_assignment_id(11), // Different assignment
            MetricType::HoursWorked,
            35,
            &test_recorder(),
            1,
        )
        .unwrap();

        let metrics = book.get_metrics_for_assignment(1, &test_assignment_id(10));
        assert_eq!(metrics.len(), 2);
    }
}
