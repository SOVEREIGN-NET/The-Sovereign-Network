//! Metric Book Types - Finalized Work Tracking
//!
//! Types for recording, attesting, and finalizing work metrics.
//!
//! # Key Principles
//!
//! 1. **Append-Only**: Metrics can only be added, never modified or deleted
//! 2. **Attestation Required**: Metrics must be attested before compensation
//! 3. **Epoch Finality**: Once an epoch closes, it cannot be reopened
//!
//! # Consensus-Critical
//! All types use deterministic serialization. Integer math only.

use super::role_types::AssignmentId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique key for a metric record
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MetricKey {
    /// Epoch when work was performed
    pub epoch: u64,
    /// Assignment this metric belongs to
    pub assignment_id: AssignmentId,
    /// Type of metric
    pub metric_type: MetricType,
}

impl MetricKey {
    /// Create a new metric key
    pub fn new(epoch: u64, assignment_id: AssignmentId, metric_type: MetricType) -> Self {
        Self {
            epoch,
            assignment_id,
            metric_type,
        }
    }
}

/// Types of work metrics that can be recorded
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MetricType {
    /// Hours worked in the period
    HoursWorked,
    /// Number of tasks completed
    TasksCompleted,
    /// Code commits made
    CodeCommits,
    /// Code reviews performed
    ReviewsPerformed,
    /// Milestones achieved
    MilestonesAchieved,
    /// Documents written/reviewed
    DocumentsProduced,
    /// Support tickets resolved
    TicketsResolved,
    /// Custom metric with identifier
    Custom(String),
}

impl MetricType {
    /// Get the default unit for this metric type
    pub fn default_unit(&self) -> MetricUnit {
        match self {
            Self::HoursWorked => MetricUnit::Hours,
            Self::TasksCompleted => MetricUnit::Count,
            Self::CodeCommits => MetricUnit::Count,
            Self::ReviewsPerformed => MetricUnit::Count,
            Self::MilestonesAchieved => MetricUnit::Count,
            Self::DocumentsProduced => MetricUnit::Count,
            Self::TicketsResolved => MetricUnit::Count,
            Self::Custom(_) => MetricUnit::Count,
        }
    }
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HoursWorked => write!(f, "HoursWorked"),
            Self::TasksCompleted => write!(f, "TasksCompleted"),
            Self::CodeCommits => write!(f, "CodeCommits"),
            Self::ReviewsPerformed => write!(f, "ReviewsPerformed"),
            Self::MilestonesAchieved => write!(f, "MilestonesAchieved"),
            Self::DocumentsProduced => write!(f, "DocumentsProduced"),
            Self::TicketsResolved => write!(f, "TicketsResolved"),
            Self::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

/// Unit of measurement for metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricUnit {
    /// Hours (for time-based metrics)
    Hours,
    /// Simple count
    Count,
    /// Percentage (0-100)
    Percentage,
    /// Points (arbitrary scoring)
    Points,
}

impl fmt::Display for MetricUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hours => write!(f, "hours"),
            Self::Count => write!(f, "count"),
            Self::Percentage => write!(f, "%"),
            Self::Points => write!(f, "points"),
        }
    }
}

/// A recorded metric value
///
/// Once created, the value CANNOT be modified (append-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricRecord {
    /// Unique key for this metric
    pub key: MetricKey,
    /// The recorded value
    pub value: u64,
    /// Unit of measurement
    pub unit: MetricUnit,
    /// Epoch when recorded
    pub recorded_at_epoch: u64,
    /// Who recorded this metric (key_id)
    pub recorded_by: [u8; 32],
    /// Whether this metric has been finalized (sufficient attestations)
    pub finalized: bool,
    /// Epoch when finalized (if applicable)
    pub finalized_at_epoch: Option<u64>,
}

impl MetricRecord {
    /// Create a new metric record
    pub fn new(
        key: MetricKey,
        value: u64,
        recorded_at_epoch: u64,
        recorded_by: [u8; 32],
    ) -> Self {
        let unit = key.metric_type.default_unit();
        Self {
            key,
            value,
            unit,
            recorded_at_epoch,
            recorded_by,
            finalized: false,
            finalized_at_epoch: None,
        }
    }

    /// Mark as finalized
    pub fn finalize(&mut self, epoch: u64) {
        self.finalized = true;
        self.finalized_at_epoch = Some(epoch);
    }
}

/// Role of an attester
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttesterRole {
    /// Direct supervisor
    Supervisor,
    /// Peer reviewer
    Peer,
    /// Automated system (CI/CD, etc.)
    Automated,
    /// Governance authority
    Governance,
}

impl fmt::Display for AttesterRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supervisor => write!(f, "Supervisor"),
            Self::Peer => write!(f, "Peer"),
            Self::Automated => write!(f, "Automated"),
            Self::Governance => write!(f, "Governance"),
        }
    }
}

/// An attestation for a metric
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Who attested (key_id)
    pub attester: [u8; 32],
    /// Role of the attester
    pub attester_role: AttesterRole,
    /// Epoch when attested
    pub attested_at_epoch: u64,
    /// Signature over the metric (stored as Vec for serde compatibility)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

/// Serde helper for [u8; 64] arrays
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        data.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

impl Attestation {
    /// Create a new attestation
    pub fn new(
        attester: [u8; 32],
        attester_role: AttesterRole,
        attested_at_epoch: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            attester,
            attester_role,
            attested_at_epoch,
            signature,
        }
    }
}

/// Policy for attestation requirements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPolicy {
    /// Metric type this policy applies to
    pub metric_type: MetricType,
    /// Minimum number of attestations required
    pub required_count: u32,
    /// Required attester roles (at least one from each)
    pub required_roles: Vec<AttesterRole>,
    /// Epochs before auto-rejection if not attested
    /// NOTE: Timeout enforcement is not yet implemented - this is a reserved field for future use
    pub timeout_epochs: u64,
}

impl AttestationPolicy {
    /// Create a new attestation policy
    pub fn new(metric_type: MetricType, required_count: u32) -> Self {
        Self {
            metric_type,
            required_count,
            required_roles: Vec::new(),
            timeout_epochs: 10, // Default 10 epochs
        }
    }

    /// Require a specific role
    pub fn require_role(mut self, role: AttesterRole) -> Self {
        if !self.required_roles.contains(&role) {
            self.required_roles.push(role);
        }
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, epochs: u64) -> Self {
        self.timeout_epochs = epochs;
        self
    }
}

/// Default policy: 1 supervisor attestation
impl Default for AttestationPolicy {
    fn default() -> Self {
        Self::new(MetricType::HoursWorked, 1).require_role(AttesterRole::Supervisor)
    }
}

/// Epoch status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochStatus {
    /// Open - metrics can be recorded
    Open,
    /// Closing - no new metrics, attestations still allowed
    Closing,
    /// Closed - fully immutable
    Closed,
}

impl fmt::Display for EpochStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

/// State of an epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochState {
    /// Epoch identifier
    pub epoch_id: u64,
    /// When the epoch started
    pub started_at_epoch: u64,
    /// When closed (if applicable)
    pub closed_at_epoch: Option<u64>,
    /// Current status
    pub status: EpochStatus,
    /// Count of finalized metrics in this epoch
    pub finalized_metrics_count: u64,
    /// Total compensation processed in this epoch
    pub total_compensation_processed: u64,
}

impl EpochState {
    /// Create a new open epoch
    pub fn new(epoch_id: u64, started_at: u64) -> Self {
        Self {
            epoch_id,
            started_at_epoch: started_at,
            closed_at_epoch: None,
            status: EpochStatus::Open,
            finalized_metrics_count: 0,
            total_compensation_processed: 0,
        }
    }

    /// Check if metrics can be recorded
    pub fn can_record_metrics(&self) -> bool {
        self.status == EpochStatus::Open
    }

    /// Check if attestations can be added
    pub fn can_add_attestations(&self) -> bool {
        self.status == EpochStatus::Open || self.status == EpochStatus::Closing
    }

    /// Check if compensation can be processed
    pub fn can_process_compensation(&self) -> bool {
        self.status == EpochStatus::Closed
    }
}

/// Metric book errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricError {
    /// Metric already recorded (append-only violation)
    MetricAlreadyRecorded {
        key: MetricKey,
        existing_value: u64,
    },
    /// Metric not found
    MetricNotFound(MetricKey),
    /// Epoch is closed, cannot record
    EpochClosed(u64),
    /// Epoch is closing, cannot record new metrics
    EpochClosing(u64),
    /// Epoch not registered/unknown (must be explicitly opened via EpochClock)
    EpochNotRegistered(u64),
    /// Metric already finalized
    AlreadyFinalized(MetricKey),
    /// Overwrite forbidden (explicit prohibition)
    OverwriteForbidden,
    /// Insufficient attestations
    InsufficientAttestations {
        key: MetricKey,
        required: u32,
        actual: u32,
    },
    /// Missing required attester role
    MissingRequiredRole {
        key: MetricKey,
        missing_role: AttesterRole,
    },
    /// Duplicate attestation from same attester
    DuplicateAttestation {
        key: MetricKey,
        attester: [u8; 32],
    },
    /// Attestation timeout expired (reserved for future use, not yet enforced)
    AttestationTimeout {
        key: MetricKey,
        timeout_epoch: u64,
    },
}

impl fmt::Display for MetricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetricAlreadyRecorded { key, existing_value } => {
                write!(
                    f,
                    "Metric already recorded: epoch={}, type={}, value={}",
                    key.epoch, key.metric_type, existing_value
                )
            }
            Self::MetricNotFound(key) => {
                write!(f, "Metric not found: epoch={}, type={}", key.epoch, key.metric_type)
            }
            Self::EpochClosed(epoch) => write!(f, "Epoch {} is closed", epoch),
            Self::EpochClosing(epoch) => write!(f, "Epoch {} is closing, no new metrics", epoch),
            Self::EpochNotRegistered(epoch) => {
                write!(f, "Epoch {} not registered - must be explicitly opened via EpochClock", epoch)
            }
            Self::AlreadyFinalized(key) => {
                write!(f, "Metric already finalized: epoch={}", key.epoch)
            }
            Self::OverwriteForbidden => write!(f, "Metric overwrite is forbidden"),
            Self::InsufficientAttestations { key, required, actual } => {
                write!(
                    f,
                    "Insufficient attestations for epoch={}: required={}, actual={}",
                    key.epoch, required, actual
                )
            }
            Self::MissingRequiredRole { key, missing_role } => {
                write!(
                    f,
                    "Missing required attester role for epoch={}: {}",
                    key.epoch, missing_role
                )
            }
            Self::DuplicateAttestation { key, attester } => {
                write!(
                    f,
                    "Duplicate attestation for epoch={} from {:?}",
                    key.epoch, &attester[..4]
                )
            }
            Self::AttestationTimeout { key, timeout_epoch } => {
                write!(
                    f,
                    "Attestation timeout for epoch={}, expired at epoch {}",
                    key.epoch, timeout_epoch
                )
            }
        }
    }
}

impl std::error::Error for MetricError {}

/// Epoch clock errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochError {
    /// Epoch not found
    EpochNotFound(u64),
    /// Epoch already closed
    AlreadyClosed(u64),
    /// Epoch reopen forbidden (explicit prohibition)
    ReopenForbidden,
    /// Cannot close future epoch
    CannotCloseFutureEpoch(u64),
    /// Epoch not yet closeable (still in grace period)
    NotYetCloseable(u64),
    /// Unauthorized caller attempted epoch state transition
    Unauthorized,
}

impl fmt::Display for EpochError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochNotFound(epoch) => write!(f, "Epoch {} not found", epoch),
            Self::AlreadyClosed(epoch) => write!(f, "Epoch {} is already closed", epoch),
            Self::ReopenForbidden => write!(f, "Epoch reopen is forbidden"),
            Self::CannotCloseFutureEpoch(epoch) => {
                write!(f, "Cannot close future epoch {}", epoch)
            }
            Self::NotYetCloseable(epoch) => {
                write!(f, "Epoch {} is not yet closeable", epoch)
            }
            Self::Unauthorized => write!(f, "Unauthorized: only governance can modify epoch state"),
        }
    }
}

impl std::error::Error for EpochError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_assignment_id() -> AssignmentId {
        [1u8; 32]
    }

    #[test]
    fn test_metric_key_creation() {
        let key = MetricKey::new(1, test_assignment_id(), MetricType::HoursWorked);
        assert_eq!(key.epoch, 1);
        assert_eq!(key.metric_type, MetricType::HoursWorked);
    }

    #[test]
    fn test_metric_record_creation() {
        let key = MetricKey::new(1, test_assignment_id(), MetricType::HoursWorked);
        let record = MetricRecord::new(key, 40, 1, [2u8; 32]);

        assert_eq!(record.value, 40);
        assert_eq!(record.unit, MetricUnit::Hours);
        assert!(!record.finalized);
    }

    #[test]
    fn test_metric_record_finalize() {
        let key = MetricKey::new(1, test_assignment_id(), MetricType::HoursWorked);
        let mut record = MetricRecord::new(key, 40, 1, [2u8; 32]);

        record.finalize(5);

        assert!(record.finalized);
        assert_eq!(record.finalized_at_epoch, Some(5));
    }

    #[test]
    fn test_attestation_policy() {
        let policy = AttestationPolicy::new(MetricType::HoursWorked, 2)
            .require_role(AttesterRole::Supervisor)
            .require_role(AttesterRole::Peer)
            .with_timeout(5);

        assert_eq!(policy.required_count, 2);
        assert!(policy.required_roles.contains(&AttesterRole::Supervisor));
        assert!(policy.required_roles.contains(&AttesterRole::Peer));
        assert_eq!(policy.timeout_epochs, 5);
    }

    #[test]
    fn test_epoch_state_creation() {
        let state = EpochState::new(1, 100);

        assert_eq!(state.epoch_id, 1);
        assert_eq!(state.status, EpochStatus::Open);
        assert!(state.can_record_metrics());
        assert!(state.can_add_attestations());
        assert!(!state.can_process_compensation());
    }

    #[test]
    fn test_metric_type_default_units() {
        assert_eq!(MetricType::HoursWorked.default_unit(), MetricUnit::Hours);
        assert_eq!(MetricType::TasksCompleted.default_unit(), MetricUnit::Count);
        assert_eq!(MetricType::CodeCommits.default_unit(), MetricUnit::Count);
    }
}
